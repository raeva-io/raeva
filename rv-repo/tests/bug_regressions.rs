//! Regression tests for `rv-repo` bug fixes.
//!
//! These tests spin up tiny in-process HTTP servers so they run hermetically
//! (no `#[ignore]` / no network access). They guard behaviour that is hard to
//! cover from inside the source module because it crosses `Store`, `Config`,
//! and `RepoClient` boundaries.

use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering};

/// rustls 0.23 requires a process-level `CryptoProvider`. The integration
/// tests live outside the binary that normally installs it, so seed it here
/// exactly once per test process.
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

use rv_config::{Config, RepoConfig, ResolvedPaths};
use rv_repo::{ArtifactRequest, RepoClient, Repository};
use rv_store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Tiny one-shot HTTP/1.1 stub. The handler closure inspects the request line
/// (e.g. `GET /path HTTP/1.1`) and returns an HTTP response body. Listens until
/// `expected_requests` connections have been served, then drops.
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

fn build_config(temp: &tempfile::TempDir, url: String) -> Config {
    let paths = ResolvedPaths::discover().expect("paths");
    let repo_config = RepoConfig {
        id: Some("stub".to_string()),
        url,
        releases: Some(true),
        snapshots: Some(false),
        snapshots_update_policy: None,
    };
    Config::for_testing_with_repos(temp.path().to_path_buf(), paths, vec![repo_config])
}

fn count_files_recursively(dir: &std::path::Path) -> usize {
    use std::fs;
    let mut count = 0;
    if let Ok(read) = fs::read_dir(dir) {
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += count_files_recursively(&path);
            } else if path.is_file() {
                count += 1;
            }
        }
    }
    count
}

/// Regression: when `require_checksums` is true and the server has no
/// sidecar (.sha256/.sha1), `fetch_artifact_to_store` must return
/// `MissingChecksum` WITHOUT first writing an unverified blob into CAS.
#[tokio::test]
async fn missing_checksum_does_not_orphan_blob_in_store() {
    ensure_crypto_provider();
    let temp = tempfile::tempdir().expect("temp dir");
    let store_dir = temp.path().join("store");
    let store = Store::open(&store_dir).expect("open store");

    // Stub: 200 OK for the .jar GET; 404 for any .sha256/.sha1 request.
    // The artifact bytes are arbitrary — the test will fail if the bytes
    // ever hit CAS, regardless of content.
    let addr = spawn_stub(
        |request_line| {
            if request_line.contains(".sha256") || request_line.contains(".sha1") {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            } else {
                let body = b"unverified-jar-bytes-must-not-land-in-cas";
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                resp.extend_from_slice(body);
                resp
            }
        },
        // Worst case: 1x .jar + 1x .sha256 + 1x .sha1.
        8,
    )
    .await;

    let config = build_config(&temp, format!("http://{addr}/"));
    let client = RepoClient::new(&config).await.expect("client");

    let repo_config = config.repositories().first().expect("repo").clone();
    let repo = Repository::from(&repo_config);
    let req =
        ArtifactRequest::new("com.example", "demo", "1.0.0").with_packaging("jar".to_string());

    let blob_dir = store_dir.join("blobs");
    let blobs_before = count_files_recursively(&blob_dir);

    let result = client.fetch_artifact_to_store(&repo, &req, &store).await;

    assert!(
        matches!(result, Err(rv_repo::RepoError::MissingChecksum(_))),
        "expected MissingChecksum, got {result:?}"
    );

    let blobs_after = count_files_recursively(&blob_dir);
    assert_eq!(
        blobs_before, blobs_after,
        "CAS must not have grown when checksum sidecar was missing; \
         before={blobs_before}, after={blobs_after}"
    );
}

/// Regression: `maven-metadata.xml` must be sidecar-verified. A stub that
/// serves a valid-looking metadata body together with a bogus `.sha256`
/// sidecar must produce `ChecksumMismatch`, not a parsed metadata document.
#[tokio::test]
async fn metadata_with_bad_sidecar_is_rejected() {
    use rv_version::{Coord, Version};

    ensure_crypto_provider();
    let temp = tempfile::tempdir().expect("temp dir");

    // Minimal valid maven-metadata.xml body.
    const METADATA_BODY: &str = r#"<?xml version="1.0"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <versioning>
    <latest>1.0.0</latest>
    <release>1.0.0</release>
    <versions><version>1.0.0</version></versions>
  </versioning>
</metadata>"#;
    // Deliberately wrong SHA-256: all zeros. The real SHA-256 of the body
    // above is nothing like this string, so verification must fail.
    const BAD_SIDECAR: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    let addr = spawn_stub(
        |request_line| {
            if request_line.contains(".sha256") {
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    BAD_SIDECAR.len()
                )
                .into_bytes();
                resp.extend_from_slice(BAD_SIDECAR.as_bytes());
                resp
            } else if request_line.contains(".sha1") {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            } else {
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    METADATA_BODY.len()
                )
                .into_bytes();
                resp.extend_from_slice(METADATA_BODY.as_bytes());
                resp
            }
        },
        8,
    )
    .await;

    let config = build_config(&temp, format!("http://{addr}/"));
    let client = RepoClient::new(&config).await.expect("client");

    let repo_config = config.repositories().first().expect("repo").clone();
    let repo = Repository::from(&repo_config);
    let coord = Coord {
        group_id: "com.example".into(),
        artifact_id: "demo".into(),
        version: Version::parse("1.0.0").expect("version"),
        packaging: Some("jar".to_string()),
        classifier: None,
    };

    let result = client.fetch_metadata(&repo, &coord).await;

    assert!(
        matches!(result, Err(rv_repo::RepoError::ChecksumMismatch { .. })),
        "expected ChecksumMismatch on bad metadata sidecar, got {result:?}"
    );
}

/// Records per-path GET counts so the test can assert that the dedup map
/// collapsed concurrent fetches of the shared companion POM coordinate down
/// to a single network round trip.
type PathHits = Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>;

/// Long-lived HTTP/1.1 stub. Unlike `spawn_stub`, this one keeps accepting
/// connections until the returned handle is dropped, so a slow client that
/// re-uses the connection or fans out many requests is not racing the
/// listener's "served N then exit" loop.
async fn spawn_recording_stub<F>(handler: F, hits: PathHits) -> std::net::SocketAddr
where
    F: Fn(&str) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let handler = handler.clone();
            let hits = hits.clone();
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
                if let Some(path) = request_line
                    .split_whitespace()
                    .nth(1)
                    .map(|s| s.to_string())
                {
                    let mut map = hits.lock().expect("hits map");
                    *map.entry(path).or_insert(0) += 1;
                }
                let response = handler(&request_line);
                let _ = sock.write_all(&response).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

/// `ensure_artifacts` must collapse concurrent fetches for the same Maven
/// coordinate down to a single GET. Two lockfile entries with different
/// classifiers (`jar` and `jar:sources`) share the same companion POM
/// coordinate `(com.example, demo, 1.0.0, pom, None)`. Without the OnceCell
/// dedup map both `ensure_package_artifacts` futures race to GET the POM,
/// duplicating the network round trip even though the CAS layer would
/// eventually dedupe the write. With the dedup map exactly one GET fires.
#[tokio::test]
async fn ensure_artifacts_dedupes_concurrent_fetches_of_shared_coordinate() {
    use sha2::{Digest, Sha256};

    ensure_crypto_provider();
    let temp = tempfile::tempdir().expect("temp dir");
    let store_dir = temp.path().join("store");
    let store = Store::open(&store_dir).expect("open store");

    let jar_body: &[u8] = b"jar-bytes-main";
    let sources_body: &[u8] = b"jar-bytes-sources";
    let pom_body: &[u8] = b"<project>pom</project>";

    let jar_sha256 = hex::encode(Sha256::digest(jar_body));
    let sources_sha256 = hex::encode(Sha256::digest(sources_body));
    let pom_sha256 = hex::encode(Sha256::digest(pom_body));

    let hits: PathHits = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    let jar_sha_for_handler = jar_sha256.clone();
    let sources_sha_for_handler = sources_sha256.clone();
    let pom_sha_for_handler = pom_sha256.clone();
    let addr = spawn_recording_stub(
        move |request_line| {
            // `request_line` looks like "GET /path HTTP/1.1".
            let path = request_line.split_whitespace().nth(1).unwrap_or("");
            // Stall long enough that both `ensure_package_artifacts` futures
            // get past their `needs_download_unpinned` check (which short-
            // circuits once the first POM has landed in the index) and into
            // the actual fetch call. Without the dedup map the second future
            // would then fire its own GET.
            std::thread::sleep(std::time::Duration::from_millis(150));

            let body: Option<Vec<u8>> = if path.ends_with(".sha256") {
                if path.contains("demo-1.0.0.jar.sha256") {
                    Some(jar_sha_for_handler.as_bytes().to_vec())
                } else if path.contains("demo-1.0.0-sources.jar.sha256") {
                    Some(sources_sha_for_handler.as_bytes().to_vec())
                } else if path.contains("demo-1.0.0.pom.sha256") {
                    Some(pom_sha_for_handler.as_bytes().to_vec())
                } else {
                    None
                }
            } else if path.ends_with(".sha1") {
                None
            } else if path.ends_with("demo-1.0.0.jar") {
                Some(jar_body.to_vec())
            } else if path.ends_with("demo-1.0.0-sources.jar") {
                Some(sources_body.to_vec())
            } else if path.ends_with("demo-1.0.0.pom") {
                Some(pom_body.to_vec())
            } else {
                None
            };

            match body {
                Some(b) => {
                    let mut resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        b.len()
                    )
                    .into_bytes();
                    resp.extend_from_slice(&b);
                    resp
                }
                None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            }
        },
        hits.clone(),
    )
    .await;

    let config = build_config(&temp, format!("http://{addr}/"));
    let client = RepoClient::new(&config).await.expect("client");

    let repo_url = config.repositories().first().expect("repo").url.clone();

    let platform = rv_config::Platform::current().expect("current platform");
    let lock_platform = rv_config::LockPlatform {
        platform: platform.clone(),
        packages: vec![
            rv_config::LockPackage {
                group_id: "com.example".into(),
                artifact_id: "demo".into(),
                version: "1.0.0".into(),
                snapshot_timestamp: None,
                packaging: "jar".into(),
                classifier: None,
                repo_url: repo_url.clone(),
                checksum: Some(rv_config::Checksum::new("sha256", jar_sha256.clone())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            },
            rv_config::LockPackage {
                group_id: "com.example".into(),
                artifact_id: "demo".into(),
                version: "1.0.0".into(),
                snapshot_timestamp: None,
                packaging: "jar".into(),
                classifier: Some("sources".into()),
                repo_url: repo_url.clone(),
                checksum: Some(rv_config::Checksum::new("sha256", sources_sha256.clone())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            },
        ],
        edges: Vec::new(),
        extra: Default::default(),
    };
    let mut lock = rv_config::Lockfile::new();
    lock.platforms.push(lock_platform);

    let results = rv_repo::sync::ensure_artifacts(&client, &store, &lock, &config, &[platform])
        .await
        .expect("ensure_artifacts");
    for r in &results {
        assert!(r.result.is_ok(), "{}: {:?}", r.package, r.result);
    }

    let map = hits.lock().expect("hits");
    let pom_hits = *map
        .get("/com/example/demo/1.0.0/demo-1.0.0.pom")
        .unwrap_or(&0);
    assert_eq!(
        pom_hits, 1,
        "shared companion POM must be fetched exactly once across concurrent workers; \
         got {pom_hits} hits. full path map: {map:?}"
    );
    // Sanity: each main artifact still hit the network once.
    assert_eq!(
        *map.get("/com/example/demo/1.0.0/demo-1.0.0.jar")
            .unwrap_or(&0),
        1,
        "main jar should be fetched once"
    );
    assert_eq!(
        *map.get("/com/example/demo/1.0.0/demo-1.0.0-sources.jar")
            .unwrap_or(&0),
        1,
        "sources jar should be fetched once"
    );
}
