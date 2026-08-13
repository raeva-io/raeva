//! Regression tests for `rv lock verify --download`.
//!
//! Spin up an in-process HTTP stub, point a tempdir-rooted rv install at it,
//! and run the binary under test. What these guard is the repair path's
//! trust boundary: which origins it will contact, and which bytes it will
//! let the shared content store's coordinate index point at.

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
    spawn_stub_counted(handler, expected_requests).await.0
}

/// `spawn_stub` plus a counter of accepted connections, for tests that must
/// prove the origin was *never* contacted. The count is bumped on accept
/// rather than after the response so a connection the client opens and drops
/// still registers as a hit.
async fn spawn_stub_counted<F>(
    handler: F,
    expected_requests: u32,
) -> (std::net::SocketAddr, Arc<AtomicU32>)
where
    F: Fn(&str) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handler = Arc::new(handler);
    let served = Arc::new(AtomicU32::new(0));
    let hits = Arc::new(AtomicU32::new(0));
    let hits_out = hits.clone();
    tokio::spawn(async move {
        while served.load(Ordering::SeqCst) < expected_requests {
            let (mut sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            hits.fetch_add(1, Ordering::SeqCst);
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
    (addr, hits_out)
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
    write_project_split(project, repo_url, repo_url, sha256);
}

/// Like [`write_project`], but the origin `rv.toml` declares and the origin
/// `rv.lock` records are set independently, so a test can model a tampered
/// lockfile that points at a repository the project never trusted.
fn write_project_split(project: &Path, config_repo_url: &str, lock_repo_url: &str, sha256: &str) {
    fs::write(
        project.join("rv.toml"),
        format!(
            r#"
[[repositories]]
id = "stub"
url = "{config_repo_url}"
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
repo_url = "{lock_repo_url}"
checksum = {{ algorithm = "sha256", digest = "{sha256}" }}
"#
    );
    fs::write(project.join("rv.lock"), lockfile).expect("write rv.lock");
}

/// Happy path: a configured origin serving bytes that match the recorded pin
/// must still be downloaded *and* indexed.
///
/// We assert the externally-observable effect: after a successful download,
/// the SQLite index has a row mapping the artifact key to the blob. Holding
/// the index write back until the pin check passes must not lose it — the
/// row is what downstream consumers (e.g. `rv export-m2`) follow.
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

/// Run the real binary against `project` with `RAEVA_HOME` pointed at `home`.
async fn run_rv(project: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_rv").to_string();
    let project = project.to_path_buf();
    let home = home.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(&bin)
            .arg("-C")
            .arg(&project)
            .args(&args)
            .env("RAEVA_HOME", &home)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("RUST_LOG")
            .output()
            .expect("spawn rv")
    })
    .await
    .expect("join")
}

/// Serve a jar plus a matching `.sha256` sidecar; 404 everything else.
fn jar_routes(body: Vec<u8>, sha256: String) -> impl Fn(&str) -> Vec<u8> + Send + Sync + 'static {
    move |request_line: &str| {
        if request_line.contains(".sha256") {
            http_ok(sha256.as_bytes())
        } else if request_line.contains(".jar") {
            http_ok(&body)
        } else {
            http_404()
        }
    }
}

/// Security regression: `rv lock verify --download` must apply the same trust
/// policy as `rv sync`. A tampered `rv.lock` that names a `repo_url` the
/// project's `rv.toml` never declared must be refused as a verify finding,
/// and the attacker origin must not be contacted at all — verify used to
/// synthesize a `Repository` for whatever URL the lockfile carried, so
/// `--download` would happily fetch from it (`rv sync` refuses the very same
/// lockfile with `UntrustedRepoUrl` before any I/O).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_verify_download_refuses_untrusted_lockfile_origin() {
    ensure_crypto_provider();

    // The attacker rewrote both halves of the lockfile row: the origin *and*
    // the pin, so the pin check alone would wave these bytes through.
    let attacker_body: &[u8] = b"attacker-controlled-jar-bytes";
    let attacker_sha256: String = Sha256::digest(attacker_body).encode_hex();

    let (addr, hits) = spawn_stub_counted(
        jar_routes(attacker_body.to_vec(), attacker_sha256.clone()),
        32,
    )
    .await;

    let project = tempdir().expect("temp project");
    let home = tempdir().expect("temp raeva home");
    let attacker_url = format!("http://{addr}/");
    // `rv.toml` trusts an unrelated repository; the lockfile points at the
    // attacker's stub.
    write_project_split(
        project.path(),
        "https://repo.example/m2/",
        &attacker_url,
        &attacker_sha256,
    );

    let output = run_rv(
        project.path(),
        home.path(),
        &["--json", "lock", "verify", "--download"],
    )
    .await;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !output.status.success(),
        "verify must fail on a lockfile whose origin is not a trust root\nstdout: {stdout}\nstderr: {stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
        panic!("stdout must be a single JSON envelope: {err}\nstdout: {stdout}\nstderr: {stderr}")
    });
    assert_eq!(
        parsed["data"]["untrusted_origin"],
        serde_json::json!(1),
        "the untrusted origin must surface as its own finding: {parsed}"
    );
    assert_eq!(
        parsed["data"]["untrusted_origin_artifacts"][0]["repo_url"],
        serde_json::json!(attacker_url),
        "the finding must name the refused origin: {parsed}"
    );
    assert_eq!(
        parsed["data"]["downloaded"],
        serde_json::json!(0),
        "nothing may be downloaded from an untrusted origin: {parsed}"
    );

    // The load-bearing assertion: the attacker origin was never contacted.
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "verify must not open a connection to an origin outside the trust roots"
    );

    // ...and nothing was indexed for the coordinate.
    let store_dir = home.path().join("store");
    if store_dir.exists() {
        let store = rv_store::Store::open(&store_dir).expect("open store");
        let key = rv_store::ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        assert!(
            store
                .lookup_artifact(&key)
                .await
                .expect("lookup_artifact")
                .is_none(),
            "a refused download must leave the artifact index untouched"
        );
    }
}

/// Security regression: bytes that fail the lockfile pin must never be
/// indexed. `--download` used to route through
/// `fetch_artifact_to_store_and_index`, which repointed the artifact key at
/// the fetched blob *before* comparing it to the pin — so a failed pin check
/// still left the shared store's coordinate index aimed at whatever the
/// origin served.
///
/// Here the origin is declared in `rv.toml` (so the trust gate passes and a
/// fetch really happens) but serves bytes that do not match the recorded
/// pin. The coordinate must still resolve to the blob it resolved to before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_verify_download_leaves_index_alone_when_the_pin_fails() {
    ensure_crypto_provider();

    // What the origin serves, with a self-consistent sidecar so the fetch
    // itself succeeds and only the lockfile pin comparison can reject it.
    let served_body: &[u8] = b"bytes-the-origin-actually-serves";
    let served_sha256: String = Sha256::digest(served_body).encode_hex();
    // What the lockfile pins: something else entirely.
    let pinned_sha256: String = Sha256::digest(b"the-bytes-the-lockfile-pins").encode_hex();

    let (addr, hits) =
        spawn_stub_counted(jar_routes(served_body.to_vec(), served_sha256.clone()), 32).await;

    let project = tempdir().expect("temp project");
    let home = tempdir().expect("temp raeva home");
    let repo_url = format!("http://{addr}/");
    write_project(project.path(), &repo_url, &pinned_sha256);

    // Seed the store so the coordinate already maps to a known blob; that
    // mapping is what a redirect would overwrite.
    let store_dir = home.path().join("store");
    fs::create_dir_all(&store_dir).expect("mkdir store");
    let key = rv_store::ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    let store = rv_store::Store::open(&store_dir).expect("open store");
    let original_blob = store
        .put_bytes(b"the-blob-the-store-already-had")
        .await
        .expect("put original bytes");
    store
        .add_artifact(&key, &original_blob)
        .await
        .expect("index original");
    drop(store);

    let output = run_rv(
        project.path(),
        home.path(),
        &["--json", "lock", "verify", "--download"],
    )
    .await;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !output.status.success(),
        "verify must fail when the downloaded bytes miss the pin\nstdout: {stdout}\nstderr: {stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
        panic!("stdout must be a single JSON envelope: {err}\nstdout: {stdout}\nstderr: {stderr}")
    });
    assert_eq!(
        parsed["data"]["pin_mismatch"],
        serde_json::json!(1),
        "the mismatched download must surface as its own finding: {parsed}"
    );
    assert_eq!(
        parsed["data"]["downloaded"],
        serde_json::json!(0),
        "a download that fails the pin must not count as a repair: {parsed}"
    );

    // The origin really was contacted: this test exercises the pin gate, not
    // the trust gate.
    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "the configured origin should have been fetched from"
    );

    // The load-bearing assertion: the coordinate still maps to the blob it
    // mapped to before, not to the bytes the origin served.
    let store = rv_store::Store::open(&store_dir).expect("reopen store");
    let mapped = store
        .lookup_artifact(&key)
        .await
        .expect("lookup_artifact")
        .expect("the seeded mapping must survive a failed download");
    assert_eq!(
        mapped, original_blob,
        "a download that fails the lockfile pin must not repoint the artifact index"
    );
    assert_ne!(
        mapped.as_str(),
        served_sha256,
        "the index must not point at the bytes the origin served"
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
