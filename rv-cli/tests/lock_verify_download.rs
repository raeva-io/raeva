//! Regression tests for `rv lock verify --download`.
//!
//! Spin up an in-process HTTP stub, point a tempdir-rooted rv install at it,
//! and run the binary under test. The fix being guarded here routes downloads
//! through `RepoClient::fetch_artifact_to_store_and_index` so the artifact
//! key → blob index commit happens under the same `StoreLock` as the blob
//! persist (the GC race that the legacy two-step
//! `fetch_artifact_to_store` → `Store::add_artifact` reopened).

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering};

use hex::ToHex;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn spawn_stub<F>(handler: F, expected_requests: u32) -> std::net::SocketAddr
where
    F: Fn(&str) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handler = Arc::new(handler);
    let served = Arc::new(AtomicU32::new(0));
    tokio::spawn(async move {
        while served.load(Ordering::SeqCst) < expected_requests {
            let (mut sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let handler = handler.clone();
            let served = served.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut total = Vec::new();
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    if n == 0 {
                        return;
                    }
                    total.extend_from_slice(&buf[..n]);
                    if total.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let request_line = std::str::from_utf8(&total)
                    .ok()
                    .and_then(|s| s.lines().next())
                    .unwrap_or("")
                    .to_string();
                let response = handler(&request_line);
                let _ = sock.write_all(&response).await;
                let _ = sock.shutdown().await;
                served.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    addr
}

fn http_ok(body: &[u8]) -> Vec<u8> {
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body);
    resp
}

fn http_404() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

fn write_project_sha1(project: &Path, repo_url: &str, sha1: &str) {
    fs::write(
        project.join("rv.toml"),
        format!(
            r#"
[[repositories]]
id = "stub"
url = "{repo_url}"
"#
        ),
    )
    .expect("write rv.toml");

    fs::write(
        project.join("pom.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
</project>
"#,
    )
    .expect("write pom.xml");

    let lockfile = format!(
        r#"schema_version = 1

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "{repo_url}"
checksum = {{ algorithm = "sha1", digest = "{sha1}" }}
"#
    );
    fs::write(project.join("rv.lock"), lockfile).expect("write rv.lock");
}

fn write_project(project: &Path, repo_url: &str, sha256: &str) {
    fs::write(
        project.join("rv.toml"),
        format!(
            r#"
[[repositories]]
id = "stub"
url = "{repo_url}"
"#
        ),
    )
    .expect("write rv.toml");

    fs::write(
        project.join("pom.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
</project>
"#,
    )
    .expect("write pom.xml");

    let lockfile = format!(
        r#"schema_version = 1

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "{repo_url}"
checksum = {{ algorithm = "sha256", digest = "{sha256}" }}
"#
    );
    fs::write(project.join("rv.lock"), lockfile).expect("write rv.lock");
}

/// Regression: `rv lock verify --download` must use the atomic
/// `fetch_artifact_to_store_and_index` path, so the artifact-key → blob
/// mapping is recorded under the same store lock as the blob persist. The
/// legacy two-step sequence reopened the GC race window.
///
/// We assert the externally-observable effect: after a successful download,
/// the SQLite index has a row mapping the artifact key to the blob. With the
/// old code path the row landed in a separate `Store::add_artifact` call;
/// with the new path it lands inside `put_stream_and_index`. Either way the
/// row must be present; the test confirms the new code did not silently
/// drop the index step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_verify_download_indexes_artifact() {
    ensure_crypto_provider();

    let artifact_body: &[u8] = b"hello-jar-bytes-from-the-stub-server";
    let sha256_hex: String = Sha256::digest(artifact_body).encode_hex();

    let body_clone = artifact_body.to_vec();
    let sha256_clone = sha256_hex.clone();
    let addr = spawn_stub(
        move |request_line| {
            if request_line.contains(".sha256") {
                http_ok(sha256_clone.as_bytes())
            } else if request_line.contains(".sha1") || request_line.contains(".md5") {
                http_404()
            } else if request_line.contains(".jar") {
                http_ok(&body_clone)
            } else {
                http_404()
            }
        },
        32,
    )
    .await;

    let project = tempdir().expect("temp project");
    let home = tempdir().expect("temp raeva home");
    let repo_url = format!("http://{addr}/");
    write_project(project.path(), &repo_url, &sha256_hex);

    // Run `rv lock verify --download` as a subprocess so we exercise the
    // real binary end to end (the same surface a user runs).
    let bin = env!("CARGO_BIN_EXE_rv");
    let output = tokio::task::spawn_blocking({
        let project = project.path().to_path_buf();
        let home = home.path().to_path_buf();
        let bin = bin.to_string();
        move || {
            std::process::Command::new(&bin)
                .arg("-C")
                .arg(&project)
                .arg("lock")
                .arg("verify")
                .arg("--download")
                .env("RAEVA_HOME", &home)
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env_remove("RUST_LOG")
                .output()
                .expect("spawn rv")
        }
    })
    .await
    .expect("join");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "lock verify --download should succeed\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The artifact-key → blob mapping must be present in the store index.
    // With the fixed atomic API, this row is written under the same lock as
    // the blob persist. Query the rv-store index directly via the public
    // `lookup_artifact` API so the test exercises the same surface that
    // downstream consumers (e.g. `rv export-m2`) rely on.
    let store_dir = find_store_dir(home.path()).unwrap_or_else(|| {
        panic!(
            "store dir not found under RAEVA_HOME\nstdout: {stdout}\nstderr: {stderr}\nhome listing: {:?}",
            list_recursive(home.path())
        );
    });
    let store = rv_store::Store::open(&store_dir).expect("open store");
    let key = rv_store::ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    let mapped = store.lookup_artifact(&key).await.expect("lookup_artifact");
    assert!(
        mapped.is_some(),
        "artifact-key → blob mapping must exist after --download \
         (the atomic fetch_artifact_to_store_and_index path commits the \
         index row under the same store lock as the blob persist)"
    );
}

/// Regression: a lockfile with a SHA-1 pin (legitimately produced by
/// `rv sync`'s default SHA-1-sidecar fallback against a SHA-1-only
/// repository) must verify cleanly. The old verify path bailed with
/// "unsupported checksum sha1" before even consulting the store, falsely
/// rejecting a lockfile the sync path produced.
///
/// We pre-populate a real `Store` with the artifact and its index entry,
/// then run `rv lock verify` (no `--download`, no network) against a
/// SHA-1-pinned lockfile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_verify_accepts_sha1_pin() {
    let artifact_body: &[u8] = b"sha1-only-repo-jar-bytes";
    let mut sha1_hasher = Sha1::new();
    sha1::Digest::update(&mut sha1_hasher, artifact_body);
    let sha1_hex: String = sha1::Digest::finalize(sha1_hasher).encode_hex();

    let project = tempdir().expect("temp project");
    let home = tempdir().expect("temp raeva home");
    // Pretend the lockfile came from a sha1-only repo. The URL is never
    // hit because `verify` (without `--download`) does not touch network.
    let repo_url = "https://repo.example/sha1-only/";
    write_project_sha1(project.path(), repo_url, &sha1_hex);

    // Seed the store with the artifact and its key→blob mapping, the
    // exact post-condition `rv sync` would leave behind.
    let store_dir = home.path().join("store");
    fs::create_dir_all(&store_dir).expect("mkdir store");
    let store = rv_store::Store::open(&store_dir).expect("open store");
    let blob_id = store
        .put_bytes(artifact_body)
        .await
        .expect("put artifact bytes");
    let key = rv_store::ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    store
        .add_artifact(&key, &blob_id)
        .await
        .expect("index artifact");
    // Drop the connection so the subprocess can open its own.
    drop(store);

    let bin = env!("CARGO_BIN_EXE_rv");
    let output = tokio::task::spawn_blocking({
        let project = project.path().to_path_buf();
        let home = home.path().to_path_buf();
        let bin = bin.to_string();
        move || {
            std::process::Command::new(&bin)
                .arg("-C")
                .arg(&project)
                .arg("lock")
                .arg("verify")
                .env("RAEVA_HOME", &home)
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env_remove("RUST_LOG")
                .output()
                .expect("spawn rv")
        }
    })
    .await
    .expect("join");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "lock verify must accept a sha1-pinned lockfile when the blob \
         is in the store\nstdout: {stdout}\nstderr: {stderr}"
    );
    // Negative control: the old code would have rejected with a message
    // mentioning "sha1" as unsupported. Make sure that string is gone.
    assert!(
        !stderr
            .to_ascii_lowercase()
            .contains("unsupported checksum sha1"),
        "verify rejected sha1 with the old error message: {stderr}"
    );
}

/// Locate the rv-store directory under a tempdir-rooted `RAEVA_HOME`.
/// The layout has historically used `~/.raeva/store` and `~/store` at
/// different points in the M-series, so walk for `index.db` rather than
/// hardcoding the path.
fn list_recursive(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(read) = fs::read_dir(&p) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            out.push(path);
        }
    }
    out
}

fn find_store_dir(home: &Path) -> Option<std::path::PathBuf> {
    let mut stack = vec![home.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(read) = fs::read_dir(&p) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if matches!(
                path.file_name().and_then(|s| s.to_str()),
                Some("index.sqlite") | Some("index.db")
            ) {
                return path.parent().map(|p| p.to_path_buf());
            }
        }
    }
    None
}
