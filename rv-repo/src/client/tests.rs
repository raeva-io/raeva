use super::*;
use crate::artifact::ArtifactRequest;
use crate::auth::AuthStore;
use crate::fetch::FetchConfig;
use crate::mirror::MirrorSelector;
use crate::routing::{Router, cache_scope_key};
use crate::transport::{ClientSet, same_origin_redirect_policy};
use rv_config::{ChecksumPolicy, MirrorConfig, UpdatePolicy};
use rv_maven_types::layout::metadata_path;
use rv_maven_types::{ArtifactCoord, Coord, HashAlgorithm};
use rv_store::Store;
use rv_store::metadata_cache::{CacheTable, MetadataCache};
use rv_test_support::http::{Response, StubServer};
use rv_test_support::tls::{BAD_CERTIFICATE, fatal_alert, reject_handshake};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;
use tokio::net::TcpListener;
use url::Url;

const RELEASE_METADATA: &[u8] =
    b"<metadata><versioning><versions><version>1</version></versions></versioning></metadata>";

fn sha256_hex(body: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(body))
}

fn mirror(id: &str, url: &str, of: &str) -> MirrorConfig {
    let mut mirror = MirrorConfig::new(Some(id), url);
    mirror.mirror_of = vec![of.to_string()];
    mirror
}

fn token_auth(token: &str) -> AuthStore {
    let mut auth = rv_config::AuthConfig::new(None);
    auth.token = Some(SecretString::from(token.to_string()));
    AuthStore::from_auth_configs(&[auth]).expect("auth")
}

fn router(mirrors: Vec<MirrorConfig>, auth: AuthStore) -> Router {
    Router::new(MirrorSelector::from_mirrors(mirrors), auth)
}

/// The returned `TempDir` holds the SQLite cache and must outlive the client.
fn client_for(router: Router) -> (RepoClient, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
    let http = rv_http::client_builder()
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .build()
        .expect("client");
    let client = RepoClient::for_test(ClientSet::unscreened(http), router, cache);
    (client, tmp)
}

fn test_client() -> (RepoClient, tempfile::TempDir) {
    client_for(router(Vec::new(), AuthStore::default()))
}

fn mirrored_client(mirrors: Vec<MirrorConfig>) -> (RepoClient, tempfile::TempDir) {
    let (mut client, tmp) = client_for(router(mirrors, AuthStore::default()));
    client.fetch = FetchConfig {
        retries: 0,
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    (client, tmp)
}

fn http_repo(server: &StubServer) -> Repository {
    Repository::new(None, format!("http://{}/", server.addr()), true, true)
}

fn file_repo(dir: &std::path::Path) -> Repository {
    Repository::new(None, Url::from_directory_path(dir).unwrap(), true, true)
}

fn store_in(dir: &tempfile::TempDir) -> Store {
    Store::open(dir.path()).expect("store")
}

/// Serves `body` at every path, with a matching `.sha256` sidecar.
fn body_stub(body: &'static [u8]) -> (Repository, StubServer) {
    let server = StubServer::start(move |request| {
        if request.path.ends_with(".sha256") {
            Response::new(200, sha256_hex(body))
        } else {
            Response::new(200, body)
        }
    });
    (http_repo(&server), server)
}

/// Serves any POM and `maven-metadata.xml`, with `.sha256` sidecars only
/// while `checksums` is set.
fn model_stub(checksums: Arc<AtomicBool>) -> StubServer {
    const POM: &str = "<project><modelVersion>4.0.0</modelVersion></project>";
    const METADATA: &str = "<metadata><version>1.0-SNAPSHOT</version><versioning><versions><version>1.0</version></versions></versioning></metadata>";
    StubServer::start(move |request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        let body = if path.ends_with(".pom") {
            POM
        } else if path.ends_with("/maven-metadata.xml") {
            METADATA
        } else {
            return Response::new(404, "");
        };
        match (sidecar, checksums.load(Ordering::SeqCst)) {
            (false, _) => Response::new(200, body),
            (true, true) => Response::new(200, sha256_hex(body)),
            (true, false) => Response::new(404, ""),
        }
    })
}

fn offline_miss<T: std::fmt::Debug>(result: Result<T>) -> bool {
    matches!(result, Err(RepoError::OfflineNotCached(_)))
}

fn coord(raw: &str) -> Coord {
    raw.parse().unwrap()
}

/// A POM or `maven-metadata.xml` cached under `--allow-missing-checksums`
/// is not served to a run that requires checksums: it is fetched again,
/// refused while no sidecar exists, and replaced once one does. Offline, the
/// strict run reports the unverified copy as unusable.
#[tokio::test]
async fn a_strict_run_does_not_trust_an_unverified_cache_row() {
    let checksums = Arc::new(AtomicBool::new(false));
    let server = model_stub(Arc::clone(&checksums));
    let (client, _tmp) = test_client();
    let repo = Repository::new(None, format!("http://{}/", server.addr()), true, false);
    let req = ArtifactRequest::new("test", "demo", "1.0");
    let release = coord("test:demo:1.0");
    let scope = cache_scope_key(&repo.url, &repo);
    let rows = |client: &RepoClient| {
        [
            (CacheTable::Pom, scope.clone(), req.pom().to_path()),
            (
                CacheTable::VersionList,
                RepoClient::metadata_scope(&repo, &scope, "1.0"),
                metadata_path("test", "demo", None),
            ),
        ]
        .map(|(table, scope, path)| {
            let entry = client.cache.get(table, &scope, &path).unwrap().unwrap();
            entry.checksum_checked
        })
    };
    let read_both = |client: RepoClient| {
        let (req, release, repo) = (&req, &release, &repo);
        async move {
            client.fetch_pom(repo, req).await?;
            client.fetch_metadata(repo, release).await.map(|_| ())
        }
    };

    let lenient = client.clone().with_allow_missing_checksums(true);
    read_both(lenient.clone()).await.unwrap();
    assert_eq!(rows(&client), [false, false]);
    let answered = server.answered();
    read_both(lenient.clone()).await.unwrap();
    assert_eq!(server.answered(), answered, "a lenient run reuses its rows");

    assert!(matches!(
        client.fetch_pom(&repo, &req).await,
        Err(RepoError::MissingChecksum(_))
    ));
    assert!(matches!(
        client.fetch_metadata(&repo, &release).await,
        Err(RepoError::MissingChecksum(_))
    ));

    let offline = client.clone().with_offline(true);
    let answered = server.answered();
    for error in [
        offline.fetch_pom(&repo, &req).await.unwrap_err(),
        offline.fetch_metadata(&repo, &release).await.unwrap_err(),
    ] {
        let message = error.to_string();
        assert!(
            message.starts_with("offline mode: a checked copy of "),
            "{message}"
        );
        assert!(
            message.contains("the cached one has no checksum file"),
            "{message}"
        );
    }
    assert_eq!(server.answered(), answered, "offline never connects");
    let lenient_offline = offline.clone().with_allow_missing_checksums(true);
    lenient_offline.fetch_pom(&repo, &req).await.unwrap();

    checksums.store(true, Ordering::SeqCst);
    read_both(client.clone()).await.unwrap();
    assert_eq!(rows(&client), [true, true]);
    let answered = server.answered();
    for run in [client.clone(), lenient, offline] {
        read_both(run).await.unwrap();
    }
    assert_eq!(
        server.answered(),
        answered,
        "every run reuses verified rows"
    );
}

/// Serves snapshot metadata whose first pair of requests carries build 1
/// and later ones build 2, with a wrong sidecar unless `repaired`, which
/// fixes the second pair. This catches retrying only the sidecar or
/// accepting the first body.
fn metadata_checksum_stub(repaired: bool) -> (Repository, StubServer) {
    let index = AtomicU32::new(0);
    let server = StubServer::start(move |request| {
        let index = index.fetch_add(1, Ordering::SeqCst);
        let build = if index < 2 { 1 } else { 2 };
        let body = format!(
            "<metadata><version>1.0-SNAPSHOT</version><versioning><latest>{build}</latest><snapshot><timestamp>20261011.010101</timestamp><buildNumber>{build}</buildNumber></snapshot></versioning></metadata>"
        );
        if !request.path.ends_with(".sha256") {
            Response::new(200, body)
        } else if repaired && index >= 2 {
            Response::new(200, sha256_hex(body))
        } else {
            Response::new(200, "0".repeat(64))
        }
    });
    (http_repo(&server), server)
}

fn capture_warn_output(body: impl std::future::Future<Output = ()>) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rv_test_support::capture_warnings(|| runtime.block_on(body))
}

/// A metadata checksum mismatch refetches both files once, then warns and
/// uses the metadata under `warn`, without secrets in the warning. The row
/// is not reused once the update or checksum policy tightens, and a
/// mismatch cannot stretch the update policy. A retry that matches warns
/// nothing, under either policy.
#[test]
fn metadata_checksum_mismatch_warns_after_retry_and_respects_cache_policy() {
    let output = capture_warn_output(async {
        for version in ["1.0", "1.0-SNAPSHOT"] {
            let (client, _cache) = test_client();
            let (mut repo, server) = metadata_checksum_stub(false);
            repo.url = repo.url.replacen("http://", "http://user:secret@", 1);
            repo.url.push_str("?token=secret-query");
            repo.snapshots_update_policy = UpdatePolicy::Daily;
            let metadata_coord = coord(&format!("com.example:demo:{version}"));
            let metadata = client.fetch_metadata(&repo, &metadata_coord).await.unwrap();
            assert_eq!(metadata.latest.as_deref(), Some("2"));
            assert_eq!(server.connections(), 4, "both files are fetched twice");
            client.fetch_metadata(&repo, &metadata_coord).await.unwrap();
            assert_eq!(server.connections(), 4, "the daily cache applies");
            repo.releases_update_policy = UpdatePolicy::Always;
            repo.snapshots_update_policy = UpdatePolicy::Always;
            client.fetch_metadata(&repo, &metadata_coord).await.unwrap();
            assert_eq!(server.connections(), 8, "a shorter update policy refetches");
            repo.releases_checksum_policy = ChecksumPolicy::Fail;
            repo.snapshots_checksum_policy = ChecksumPolicy::Fail;
            assert!(matches!(
                client.fetch_metadata(&repo, &metadata_coord).await,
                Err(RepoError::ChecksumMismatch { .. })
            ));
            assert_eq!(server.connections(), 12);
        }
        let (client, _cache) = test_client();
        let (mut repo, server) = metadata_checksum_stub(false);
        repo.snapshots_update_policy = UpdatePolicy::Always;
        for _ in 0..2 {
            let snapshot = coord("com.example:demo:1.0-SNAPSHOT");
            let resolved = client
                .resolve_snapshot_version(&repo, &snapshot)
                .await
                .unwrap();
            assert_eq!(resolved.version, "1.0-20261011.010101-2");
        }
        assert_eq!(
            server.connections(),
            8,
            "a mismatch cannot extend the policy"
        );

        for policy in [ChecksumPolicy::Warn, ChecksumPolicy::Fail] {
            let (client, _cache) = test_client();
            let (mut repo, server) = metadata_checksum_stub(true);
            repo.snapshots_checksum_policy = policy;
            let snapshot = coord("com.example:demo:1.0-SNAPSHOT");
            let resolved = client
                .resolve_snapshot_version(&repo, &snapshot)
                .await
                .unwrap();
            assert_eq!(resolved.version, "1.0-20261011.010101-2");
            assert_eq!(server.connections(), 4);
        }
    });
    assert_eq!(output.matches("METADATA_CHECKSUM_MISMATCH").count(), 6);
    assert!(output.contains("repository_url=http://127.0.0.1:"));
    assert!(output.contains("com/example/demo/maven-metadata.xml"));
    assert!(output.contains("com/example/demo/1.0-SNAPSHOT/maven-metadata.xml"));
    assert!(!output.contains("secret"));
    assert!(!output.contains("user:"));
}

#[tokio::test]
async fn metadata_warn_policy_does_not_relax_artifact_or_pom_checksums() {
    for policy in [ChecksumPolicy::Warn, ChecksumPolicy::Ignore] {
        let (client, _cache) = test_client();
        let (mut repo, server) = metadata_checksum_stub(false);
        repo.releases_checksum_policy = policy;
        let request = ArtifactRequest::new("com.example", "demo", "1.0");
        assert!(matches!(
            client.fetch_pom(&repo, &request).await,
            Err(RepoError::ChecksumMismatch { .. })
        ));
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            client
                .fetch_artifact_to_store(&repo, &request, &store_in(&dir))
                .await,
            Err(RepoError::ChecksumMismatch { .. })
        ));
        assert_eq!(
            server.connections(),
            4,
            "only metadata gets a checksum retry"
        );
    }
}

/// A local repository's sidecars are checked as a remote's are, offline
/// too, and a local metadata mismatch is fatal whatever the policy.
#[tokio::test]
async fn local_repository_checksum_mismatches_are_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let version_dir = dir.path().join("com/example/demo/1");
    std::fs::create_dir_all(&version_dir).unwrap();
    for file in ["demo-1.pom", "demo-1.jar", "../maven-metadata.xml"] {
        std::fs::write(version_dir.join(file), b"<metadata/>").unwrap();
        std::fs::write(version_dir.join(format!("{file}.sha256")), "0".repeat(64)).unwrap();
    }
    let repo = file_repo(dir.path());
    let req = ArtifactRequest::new("com.example", "demo", "1");
    let key = ArtifactCoord::new("com.example", "demo", "1", "jar", None);
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let (client, _cache) = test_client();
    let mismatch = |result: Result<_>| matches!(result, Err(RepoError::ChecksumMismatch { .. }));
    assert!(mismatch(
        client
            .fetch_metadata(&repo, &coord("com.example:demo:1"))
            .await
            .map(|_| ())
    ));
    let client = client.with_offline(true);
    assert!(mismatch(client.fetch_pom(&repo, &req).await.map(|_| ())));
    assert!(mismatch(
        client
            .fetch_artifact_to_store(&repo, &req, &store)
            .await
            .map(|_| ())
    ));
    let indexed = client
        .fetch_artifact_to_store_and_index(&repo, &req, &store, &key)
        .await;
    assert!(mismatch(indexed.map(|_| ())));
}

#[tokio::test]
async fn a_pin_does_not_count_as_a_repository_checksum() {
    let repository = tempfile::tempdir().unwrap();
    let dir = repository.path().join("com/example/demo/1");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("demo-1.jar"), b"pinned jar").unwrap();
    let repo = file_repo(repository.path());
    let req = ArtifactRequest::new("com.example", "demo", "1");
    let key = ArtifactCoord::new("com.example", "demo", "1", "jar", None);
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let (client, _cache) = test_client();
    let pin = rv_maven_types::Digest::Sha256(rv_maven_types::BlobId::from_bytes(b"pinned jar"));
    let fetched = client
        .fetch_artifact(
            &repo,
            &req,
            &store,
            FetchArtifact {
                pin: Some(&pin),
                index: Some(&key),
            },
        )
        .await
        .unwrap();
    assert!(!fetched.checksum_verified);
    assert_eq!(
        store
            .lookup_artifact_from(&key, &repo.url, &repo.url, false, false)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .lookup_artifact_from(&key, &repo.url, &repo.url, true, false)
            .await
            .unwrap(),
        Some(fetched.blob)
    );
}

/// A mirror that fails the handshake, answers 503 or 404, or serves bytes
/// that fail their checksum stops the fetch, as in Maven. Retrying the
/// origin would route the build around a mirror that policy may require.
#[tokio::test]
async fn mirror_failures_do_not_fall_back_to_origin() {
    let origin_server = StubServer::start(|_| Response::new(200, ""));
    let tls = StdTcpListener::bind("127.0.0.1:0").expect("bind");
    let tls_url = format!("https://{}/", tls.local_addr().unwrap());
    thread::spawn(move || {
        for mut stream in tls.incoming().flatten() {
            reject_handshake(&mut stream, BAD_CERTIFICATE);
        }
    });
    let unavailable = StubServer::start(|_| Response::new(503, ""));
    let missing = StubServer::start(|_| Response::new(404, ""));
    let mismatched = StubServer::start(|request| {
        if request.path.ends_with(".sha256") {
            Response::new(200, "0".repeat(64))
        } else if request.path.ends_with(".sha1") {
            Response::new(404, "")
        } else {
            Response::new(200, RELEASE_METADATA)
        }
    });
    let at = |server: &StubServer| format!("http://{}/", server.addr());
    type Check = fn(&RepoError) -> bool;
    let cases: [(_, Check); 4] = [
        (tls_url, |err| err.tls_cause().is_some()),
        (at(&unavailable), |err| err.status_code() == Some(503)),
        (at(&missing), |err| matches!(err, RepoError::NotFound(_))),
        (at(&mismatched), |err| {
            matches!(err, RepoError::ChecksumMismatch { .. })
        }),
    ];
    let mut origin = Repository::new(Some("central".into()), at(&origin_server), true, false);
    origin.releases_checksum_policy = ChecksumPolicy::Fail;
    let req = ArtifactRequest::new("com.example", "demo", "1");
    for (mirror_url, expected) in cases {
        let (client, _cache) = mirrored_client(vec![mirror("corp", &mirror_url, "*")]);
        let err = client
            .fetch_metadata(&origin, &coord("com.example:demo:1"))
            .await
            .unwrap_err();
        assert!(expected(&err), "{mirror_url}: {err:?}");
        let dir = tempfile::tempdir().unwrap();
        let fetched = client
            .fetch_artifact_to_store(&origin, &req, &store_in(&dir))
            .await;
        assert!(fetched.is_err(), "{mirror_url}");
    }
    assert!(unavailable.answered() > 0 && missing.answered() > 0 && mismatched.answered() > 0);
    assert_eq!(origin_server.connections(), 0, "the origin is never asked");
}

/// A blocked mirror's stored files answer for it no more than it does.
#[tokio::test]
async fn a_blocked_mirror_answers_nothing_from_the_store() {
    let origin = Repository::new(None, "https://repo.example/maven2/".to_string(), true, true);
    let mirror_url = "https://mirror.example/maven2/";
    let key = ArtifactCoord::new("g", "a", "1", "jar", None);
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&dir);
    let blob = rv_maven_types::BlobId::from_bytes(b"jar");
    let origin_row = rv_store::Origin {
        repo_url: origin.url.clone(),
        endpoint_url: mirror_url.to_string(),
        checksum_verified: true,
        served: true,
    };
    let row = vec![(key.clone(), blob.clone(), origin_row)];
    store.record_origins(row).await.unwrap();
    for blocked in [false, true] {
        let mut corp = mirror("corp", mirror_url, "*");
        corp.blocked = blocked;
        let (client, _cache) = mirrored_client(vec![corp]);
        let served = client.served_artifact(&store, &origin, &key).await.unwrap();
        let stored = client.stored_artifact(&store, &origin, &key).await.unwrap();
        let expected = (!blocked).then(|| blob.clone());
        assert_eq!(served.map(|(blob, _)| blob), expected, "{blocked}");
        assert_eq!(stored, expected, "{blocked}");
    }
}

/// Maven's `<blocked>` mirror gets no request, and neither does the
/// repository it would serve.
#[tokio::test]
async fn a_blocked_mirror_sends_no_request() {
    let mirror_server = StubServer::start(|_| Response::new(200, RELEASE_METADATA));
    let origin_server = StubServer::start(|_| Response::new(200, RELEASE_METADATA));
    let mut blocked = mirror("corp", &format!("http://{}/", mirror_server.addr()), "*");
    blocked.blocked = true;
    let (client, _cache) = mirrored_client(vec![blocked]);
    let origin = http_repo(&origin_server);
    let err = client
        .fetch_metadata(&origin, &coord("com.example:demo:1"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, RepoError::BlockedMirror(id) if id == "corp"),
        "{err:?}"
    );
    assert!(err.moves_to_next_repository());
    let dir = tempfile::tempdir().unwrap();
    let req = ArtifactRequest::new("com.example", "demo", "1");
    let fetched = client
        .fetch_artifact_to_store(&origin, &req, &store_in(&dir))
        .await;
    assert!(
        matches!(fetched, Err(RepoError::BlockedMirror(_))),
        "{fetched:?}"
    );
    assert_eq!(mirror_server.connections() + origin_server.connections(), 0);
}

/// The checksum probe prefers SHA-256 and falls back to SHA-1 when the
/// `.sha256` is missing, refused (as an object store answers for a missing
/// key) or holds no digest. A sidecar holding no digest counts as missing, so
/// the lock pin or the checksum policy decides. The probe stops at a rejected
/// certificate instead of handshaking again for the `.sha1`.
#[tokio::test]
async fn checksum_probe_falls_back_to_sha1_only_when_sha256_is_unusable() {
    const SHA1: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    const GARBAGE: &str = "<html><body>404 not found</body></html>";
    const PATH: &str = "com/example/demo/1.0/demo-1.0.jar";
    for (sha256, sha1) in [
        ((404, ""), (200, SHA1)),
        ((403, ""), (200, SHA1)),
        ((401, ""), (200, SHA1)),
        ((200, GARBAGE), (200, SHA1)),
        ((200, GARBAGE), (200, GARBAGE)),
        ((403, ""), (403, "")),
    ] {
        let server = StubServer::start(move |request| {
            let (status, body) = if request.path.ends_with(".sha256") {
                sha256
            } else {
                sha1
            };
            Response::new(status, body)
        });
        let (client, _tmp) = test_client();
        let checksum = client
            .fetch_checksum(&client.router.route(&http_repo(&server)), PATH)
            .await
            .unwrap();
        if sha1.1 == SHA1 {
            let checksum = checksum.expect("the sha1 sidecar is used");
            assert_eq!(
                (checksum.algorithm(), checksum.hex()),
                (HashAlgorithm::Sha1, SHA1)
            );
        } else {
            assert_eq!(checksum, None, "{sha256:?} {sha1:?}");
        }
    }

    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&accepted);
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            reject_handshake(&mut stream, BAD_CERTIFICATE);
        }
    });
    let repo = Repository::new(None, format!("https://{address}/"), true, false);
    let (client, _tmp) = test_client();
    let err = client
        .fetch_checksum(&client.router.route(&repo), PATH)
        .await
        .unwrap_err();
    assert!(err.tls_cause().is_some(), "{err:?}");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

/// A repository that publishes only `.md5` sidecars, as Central does for a
/// few POMs, verifies POMs and artifacts with MD5, as Maven does, with a
/// weak-hash warning. A file that does not match its `.md5` is refused.
#[test]
fn md5_only_sidecars_verify_poms_and_artifacts() {
    const POM: &[u8] = b"<project><version>1</version></project>";
    const JAR: &[u8] = b"jar bytes";
    let md5 = |bytes: &[u8]| {
        let digest = rv_maven_types::Digest::of_bytes(HashAlgorithm::Md5, bytes);
        Response::new(200, format!("{}  a-1.pom\n", digest.hex()))
    };
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/a/1/a-1.pom" => Response::new(200, POM),
        "/g/a/1/a-1.pom.md5" => md5(POM),
        "/g/a/1/a-1.jar" | "/g/bad/1/bad-1.jar" => Response::new(200, JAR),
        "/g/a/1/a-1.jar.md5" => md5(JAR),
        "/g/bad/1/bad-1.jar.md5" => md5(b"other bytes"),
        _ => Response::new(404, ""),
    });
    let (client, _cache) = test_client();
    let repo = http_repo(&server);
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut results = None;
    let log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            let jar = ArtifactRequest::new("g", "a", "1");
            let pom = client.fetch_pom(&repo, &jar).await;
            let good = client.fetch_artifact_to_store(&repo, &jar, &store).await;
            let bad = ArtifactRequest::new("g", "bad", "1");
            let bad = client.fetch_artifact_to_store(&repo, &bad, &store).await;
            results = Some((pom, good, bad));
        });
    });
    let (pom, good, bad) = results.unwrap();
    assert_eq!(pom.unwrap().as_ref(), POM);
    assert_eq!(good.unwrap(), rv_maven_types::BlobId::from_bytes(JAR));
    match bad {
        Err(RepoError::ChecksumMismatch { expected, .. }) => {
            assert_eq!(expected.algorithm(), HashAlgorithm::Md5);
        }
        other => panic!("expected an md5 mismatch, got {other:?}"),
    }
    assert_eq!(
        log.matches("falling back to MD5 checksum").count(),
        3,
        "{log}"
    );
}

/// A release POM or artifact a repository lacks, refuses to a request
/// without credentials, or stays busy for, is asked for once per client,
/// however many children name it as their parent: Maven asks for a missing
/// one once per build.
#[tokio::test]
async fn a_missing_or_refused_file_is_asked_for_once() {
    for status in [404, 401, 403, 503] {
        let server = StubServer::start(move |_| Response::new(status, ""));
        let repo = http_repo(&server);
        let (mut client, _tmp) = test_client();
        client.fetch.retries = 0;
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let parent = ArtifactRequest::new("com.example", "parent", "1.0.0");
        for _ in 0..3 {
            let pom = client.fetch_pom(&repo, &parent).await.map(|_| ());
            let jar = client
                .fetch_artifact(&repo, &parent, &store, FetchArtifact::default())
                .await
                .map(|_| ());
            for result in [pom, jar] {
                let err = result.unwrap_err();
                assert_eq!(err.status_code(), Some(status), "{err}");
            }
        }
        for file in ["parent-1.0.0.pom", "parent-1.0.0.jar"] {
            let asked = server
                .requests()
                .iter()
                .filter(|request| request.path.ends_with(file))
                .count();
            assert_eq!(asked, 1, "{status} {file}");
        }
    }
}

/// A busy answer read again from the memo keeps its Retry-After and the
/// attempts the first read made.
#[tokio::test]
async fn a_kept_busy_answer_keeps_its_retries() {
    let server = StubServer::start(|_| Response::new(503, "").header("Retry-After", "1"));
    let repo = http_repo(&server);
    let (mut client, _tmp) = test_client();
    client.fetch.retries = 1;
    let parent = ArtifactRequest::new("com.example", "parent", "1.0.0");
    let first = client.fetch_pom(&repo, &parent).await.unwrap_err();
    let asked = server.requests().len();
    let kept = client.fetch_pom(&repo, &parent).await.unwrap_err();
    assert_eq!(server.requests().len(), asked);
    assert!(
        matches!(&kept, RepoError::Retried { attempts: 2, error }
            if matches!(**error, RepoError::HttpStatus { retry_after: Some(_), .. })),
        "{kept:?}"
    );
    assert_eq!(kept.to_string(), first.to_string());
}

/// A POM or artifact with no sidecar is refused by default, so a hostile
/// mirror cannot inject unverified bytes, and nothing reaches the store. An
/// artifact that is missing too is reported as not found.
#[tokio::test]
async fn missing_sidecars_refuse_poms_and_artifacts_without_storing_them() {
    let server = StubServer::start(|request| {
        if request.path.contains(".sha") || request.path.contains("absent") {
            Response::new(404, "")
        } else {
            Response::new(
                200,
                "<project><dependencies><dependency><groupId>evil</groupId></dependency></dependencies></project>",
            )
        }
    });
    let repo = http_repo(&server);
    let (client, _tmp) = test_client();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&dir);
    let jar = ArtifactRequest::new("com.example", "demo", "1.0.0");
    let missing = |result: Result<_>| matches!(result, Err(RepoError::MissingChecksum(_)));
    assert!(missing(client.fetch_pom(&repo, &jar).await.map(|_| ())));
    assert!(missing(
        client
            .fetch_artifact_to_store(&repo, &jar.pom(), &store)
            .await
            .map(|_| ())
    ));
    let fetched = client
        .fetch_artifact(&repo, &jar, &store, FetchArtifact::default())
        .await;
    assert!(missing(fetched.map(|_| ())));
    let absent = ArtifactRequest::new("com.example", "absent", "1.0.0");
    let fetched = client
        .fetch_artifact(&repo, &absent, &store, FetchArtifact::default())
        .await;
    assert!(
        matches!(fetched, Err(RepoError::NotFound(_))),
        "{fetched:?}"
    );
    fn files_under(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| {
                let path = entry.path();
                if path.is_dir() { files_under(&path) } else { 1 }
            })
            .sum()
    }
    assert_eq!(files_under(&dir.path().join("blobs")), 0);
}

/// A wildcard mirror on another host does not receive the default (no-id)
/// credential, on any request of a snapshot POM fetch, including the
/// metadata sub-fetch, or of a release POM.
#[tokio::test]
async fn cross_host_mirror_never_receives_the_default_credential() {
    let server = StubServer::start(|request| {
        let metadata = "<metadata><versioning><snapshotVersions><snapshotVersion><extension>pom</extension><value>1.0-20240101.010101-7</value></snapshotVersion></snapshotVersions></versioning></metadata>";
        let pom = "<project><modelVersion>4.0.0</modelVersion></project>";
        let body = if request.path.contains("maven-metadata.xml") {
            metadata
        } else {
            pom
        };
        if request.path.ends_with(".sha256") {
            Response::new(200, sha256_hex(body))
        } else {
            Response::new(200, body)
        }
    });
    let mirrors = vec![mirror(
        "hostile",
        &format!("http://{}/", server.addr()),
        "*",
    )];
    let (client, _tmp) = client_for(router(mirrors, token_auth("hostile-cdn-token")));
    let repo = Repository::new(None, "https://repo.example/maven2/", true, true);
    assert!(client.router.route(&repo).cross_origin);
    for version in ["1.0-SNAPSHOT", "1.0"] {
        let req = ArtifactRequest::new("com.example", "demo", version);
        client.fetch_pom(&repo, &req).await.unwrap();
    }
    let requests = server.requests();
    assert!(
        requests
            .iter()
            .any(|request| request.path.contains("maven-metadata.xml"))
    );
    for request in requests {
        let raw = request.raw.to_ascii_lowercase();
        assert!(
            !raw.contains("authorization") && !raw.contains("hostile-cdn-token"),
            "{raw}"
        );
    }
}

/// Coordinates are checked before they reach a URL path.
#[test]
fn coordinate_components_that_could_escape_the_path_are_refused() {
    for (group, version) in [
        ("com.example", Some("../../etc/shadow")),
        ("com/evil", Some("1.0.0")),
    ] {
        let err = validate_coord_components(group, "demo", version).unwrap_err();
        assert!(matches!(err, RepoError::InvalidCoord(_)), "{err:?}");
    }
    validate_coord_components("com.example", "demo", Some("1.0.0-SNAPSHOT")).unwrap();
    validate_coord_components("org.springframework.boot", "spring-boot", None).unwrap();
}

/// Offline, nothing remote is asked, through any entry point or a mirror,
/// and the miss names the repository without its credentials or query.
#[tokio::test]
async fn offline_remote_reads_never_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_url = format!("http://{}/", listener.local_addr().unwrap());
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let req = ArtifactRequest::new("com.example", "demo", "1");
    let key = ArtifactCoord::new("com.example", "demo", "1", "jar", None);
    for mirrored in [false, true] {
        let mirrors = if mirrored {
            vec![mirror("remote", &remote_url, "*")]
        } else {
            vec![]
        };
        let (client, _cache) = mirrored_client(mirrors);
        let client = client.with_offline(true);
        let repo = Repository::new(
            None,
            if mirrored {
                "file:///unused/"
            } else {
                &remote_url
            },
            true,
            true,
        );
        assert!(offline_miss(client.fetch_pom(&repo, &req).await));
        assert!(offline_miss(
            client.fetch_artifact_to_store(&repo, &req, &store).await
        ));
        let indexed = client
            .fetch_artifact_to_store_and_index(&repo, &req, &store, &key)
            .await;
        assert!(offline_miss(indexed));
        let remote = Repository::new(None, &remote_url, true, true);
        assert!(offline_miss(
            client
                .fetch_metadata(&remote, &coord("com.example:demo:1"))
                .await
        ));
        let snapshot = coord("com.example:demo:1.0-SNAPSHOT");
        assert!(offline_miss(
            client.resolve_snapshot_version(&remote, &snapshot).await
        ));
        assert!(client.prefetch_pom(&remote, &req).await.unwrap().is_none());
        client.prefetch_artifact(&remote, &req, &store).await;
        // Each attempt guards its own endpoint too.
        let route = client.router.route(&remote);
        let path = req.to_path();
        for index in [None, Some(&key)] {
            let options = FetchArtifact { pin: None, index };
            let attempt = client.fetch_artifact_attempt(&route, &path, &store, options);
            assert!(offline_miss(attempt.await));
        }
    }
    let (client, _cache) = test_client();
    let secret = Repository::new(
        None,
        "https://alice:s3cret@repo.example/m2/?token=t0k",
        true,
        false,
    );
    let rendered = client
        .with_offline(true)
        .fetch_metadata(&secret, &coord("com.example:demo:1"))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        rendered.contains("(repo: https://repo.example/m2/?***)"),
        "{rendered}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

/// A rejected certificate fails the fetch at once: the retry loop does not
/// spend the configured retries reconnecting to it.
#[tokio::test]
async fn rejected_tls_certificate_is_not_retried() {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let accepted = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&accepted);
    thread::spawn(move || {
        // Metadata and its checksum are requested together, and a failed
        // metadata request cancels the probe, so both connections are taken
        // before either is refused.
        let mut pending = Vec::new();
        for mut stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = stream.read(&mut [0u8; 512]);
            pending.push(stream);
            if pending.len() == 2 {
                for mut stream in pending.drain(..) {
                    let _ = stream.write_all(&fatal_alert(BAD_CERTIFICATE));
                }
            }
        }
    });
    let (mut client, _cache) = test_client();
    client.fetch.retries = 2;
    let repo = Repository::new(None, format!("https://{address}/"), true, false);
    let err = client
        .fetch_metadata(&repo, &coord("org.example:lib:1.0"))
        .await
        .unwrap_err();
    assert!(err.tls_cause().is_some(), "{err:?}");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "a retry would be a third connection"
    );
}

/// A snapshot `<value>` that is not a valid version is refused before it
/// reaches a URL, and the error names its size, not the server's text.
#[tokio::test]
async fn an_unusable_snapshot_value_is_not_echoed() {
    const METADATA: &[u8] = b"<metadata><version>1.0-SNAPSHOT</version><versioning>\
        <snapshotVersions><snapshotVersion><extension>jar</extension>\
        <value>../../\x1b[31mevil</value></snapshotVersion></snapshotVersions>\
        </versioning></metadata>";
    let (client, _tmp) = test_client();
    let (repo, _server) = body_stub(METADATA);
    let error = client
        .resolve_snapshot_version(&repo, &coord("test:demo:1.0-SNAPSHOT"))
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(matches!(error, RepoError::InvalidMetadata(_)), "{message}");
    assert!(
        !message.contains("evil") && !message.contains('\x1b'),
        "{message}"
    );
    assert!(message.contains("(15 bytes)"), "{message}");
}

/// A prefetched version list is requested once, and its warnings are
/// logged by the read that uses it; a missing one is not asked for again.
#[test]
fn prefetched_metadata_is_logged_by_its_read() {
    const LIST: &[u8] = b"<metadata><groupId>g</groupId><artifactId>a</artifactId>\
        <versioning><versions><version>1</version></versions></versioning></metadata>";
    let sha1 = |bytes: &[u8]| Response::new(200, hex::encode(sha1::Sha1::digest(bytes)));
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/a/maven-metadata.xml" | "/g/b/maven-metadata.xml" => Response::new(200, LIST),
        "/g/a/maven-metadata.xml.sha1" | "/g/b/maven-metadata.xml.sha1" => sha1(LIST),
        _ => Response::new(404, ""),
    });
    let (client, _cache) = test_client();
    let repo = http_repo(&server);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let prefetch_log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            for (artifact, found) in [("a", true), ("b", true), ("missing", false)] {
                let wanted = coord(&format!("g:{artifact}:1"));
                let listed = client.prefetch_metadata(&repo, &wanted).await;
                assert_eq!(listed.is_some(), found, "{artifact}");
            }
        });
    });
    assert!(
        !prefetch_log.contains("WEAK_HASH_FALLBACK"),
        "{prefetch_log}"
    );
    let read_log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            for _ in 0..2 {
                let listed = client.fetch_metadata(&repo, &coord("g:a:1")).await.unwrap();
                assert_eq!(listed.versions, ["1"]);
            }
            let missing = client.fetch_metadata(&repo, &coord("g:missing:1")).await;
            assert!(
                matches!(missing, Err(RepoError::NotFound(_))),
                "{missing:?}"
            );
        });
    });
    assert_eq!(
        read_log.matches("WEAK_HASH_FALLBACK").count(),
        1,
        "{read_log}"
    );
    assert!(!read_log.contains("g/b/"), "{read_log}");
    for (path, count) in [
        ("/g/a/maven-metadata.xml", 1),
        ("/g/missing/maven-metadata.xml", 1),
    ] {
        let requests = server.requests().iter().filter(|r| r.path == path).count();
        assert_eq!(requests, count, "{path}");
    }
}

/// A prefetched POM or artifact is requested once and checked, and its
/// warnings are logged, by the read that uses it, as that read's own
/// download would be. A POM never read leaves nothing in the metadata cache.
/// A prefetch's credential warning waits for the read that uses what it
/// fetched, so a file no read uses gives none. A miss a prefetch met gives
/// it to the read that meets the miss.
#[test]
fn a_prefetch_leaves_its_credential_warning_to_the_read() {
    const POM: &[u8] = b"<project><version>1</version></project>";
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/a/1/a-1.pom" => Response::new(200, POM),
        "/g/a/1/a-1.pom.sha1" => Response::new(200, hex::encode(sha1::Sha1::digest(POM))),
        _ => Response::new(404, ""),
    });
    let repo = http_repo(&server);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (artifact, found) in [("a", true), ("missing", false)] {
        let auth = token_auth("t").with_configured_urls(&["https://nexus.corp/maven/"]);
        let (client, _cache) = client_for(router(Vec::new(), auth));
        let req = ArtifactRequest::new("g", artifact, "1");
        let prefetch_log = rv_test_support::capture_warnings(|| {
            runtime.block_on(async {
                let prefetched = client.prefetch_pom(&repo, &req).await;
                assert_eq!(prefetched.is_ok(), found, "{artifact}");
            });
        });
        assert!(
            !prefetch_log.contains("DEFAULT_CREDENTIAL_WITHHELD"),
            "{artifact}: {prefetch_log}"
        );
        let read_log = rv_test_support::capture_warnings(|| {
            runtime.block_on(async {
                for _ in 0..2 {
                    let read = client.fetch_pom(&repo, &req).await;
                    assert_eq!(read.is_ok(), found, "{artifact}");
                }
            });
        });
        assert_eq!(
            read_log.matches("DEFAULT_CREDENTIAL_WITHHELD").count(),
            1,
            "{artifact}: {read_log}"
        );
    }
}

/// A prefetch's warning shown inside another hold goes to that hold: when
/// the hold is dropped unshown, the next read that needs it gives it.
#[test]
fn a_prefetch_warning_shown_into_a_dropped_hold_is_given_again() {
    const POM: &[u8] = b"<project><version>1</version></project>";
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/a/1/a-1.pom" | "/g/b/1/b-1.pom" => Response::new(200, POM),
        "/g/a/1/a-1.pom.sha1" | "/g/b/1/b-1.pom.sha1" => {
            Response::new(200, hex::encode(sha1::Sha1::digest(POM)))
        }
        _ => Response::new(404, ""),
    });
    let repo = http_repo(&server);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let auth = token_auth("t").with_configured_urls(&["https://nexus.corp/maven/"]);
    let (client, _cache) = client_for(router(Vec::new(), auth));
    let (a, b) = (
        ArtifactRequest::new("g", "a", "1"),
        ArtifactRequest::new("g", "b", "1"),
    );
    let log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            client.prefetch_pom(&repo, &a).await.unwrap();
            let holds = rv_maven_model::held::Holds::default();
            let (read, dropped) = holds.hold(client.fetch_pom(&repo, &a)).await;
            read.unwrap();
            drop(dropped);
            client.fetch_pom(&repo, &b).await.unwrap();
        });
    });
    assert_eq!(
        log.matches("DEFAULT_CREDENTIAL_WITHHELD").count(),
        1,
        "{log}"
    );
}

#[test]
fn prefetches_are_checked_and_logged_by_their_reads() {
    const POM: &[u8] = b"<project><version>1</version></project>";
    const UNUSED: &[u8] = b"<project><version>2</version></project>";
    const JAR: &[u8] = b"prefetched jar bytes";
    let sha1 = |bytes: &[u8]| Response::new(200, hex::encode(sha1::Sha1::digest(bytes)));
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/a/1/a-1.pom" => Response::new(200, POM),
        "/g/a/1/a-1.pom.sha1" => sha1(POM),
        "/g/b/2/b-2.pom" => Response::new(200, UNUSED),
        "/g/b/2/b-2.pom.sha1" => sha1(UNUSED),
        "/g/a/1/a-1.jar" | "/g/bad/1/bad-1.jar" | "/g/pinned/1/pinned-1.jar" => {
            Response::new(200, JAR)
        }
        "/g/a/1/a-1.jar.sha1" | "/g/pinned/1/pinned-1.jar.sha1" => sha1(JAR),
        "/g/bad/1/bad-1.jar.sha1" => sha1(b"other bytes"),
        _ => Response::new(404, ""),
    });
    let (client, _cache) = test_client();
    let repo = http_repo(&server);
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let used = ArtifactRequest::new("g", "a", "1");
    let unused = ArtifactRequest::new("g", "b", "2");
    let bad = ArtifactRequest::new("g", "bad", "1");
    let pinned = ArtifactRequest::new("g", "pinned", "1");
    let prefetch_log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            assert_eq!(
                client.prefetch_pom(&repo, &used).await.unwrap().as_deref(),
                Some(POM)
            );
            assert_eq!(
                client
                    .prefetch_pom(&repo, &unused)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(UNUSED)
            );
            for req in [&used, &bad, &pinned] {
                client.prefetch_artifact(&repo, req, &store).await;
            }
        });
    });
    assert!(
        !prefetch_log.contains("WEAK_HASH_FALLBACK"),
        "{prefetch_log}"
    );

    let read_log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            for _ in 0..2 {
                assert_eq!(client.fetch_pom(&repo, &used).await.unwrap().as_ref(), POM);
            }
        });
    });
    assert_eq!(
        read_log.matches("WEAK_HASH_FALLBACK").count(),
        1,
        "{read_log}"
    );
    assert!(read_log.contains("a-1.pom") && !read_log.contains("b-2.pom"));
    let scope = cache_scope_key(&repo.url, &repo);
    for (path, cached) in [("g/a/1/a-1.pom", true), ("g/b/2/b-2.pom", false)] {
        let row = client.cache.get(CacheTable::Pom, &scope, path).unwrap();
        assert_eq!(row.is_some(), cached, "{path}");
    }

    let wrong_pin =
        rv_maven_types::Digest::of_bytes(rv_maven_types::HashAlgorithm::Sha256, b"other bytes");
    let mut fetched = None;
    let fetch_log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            let good = client.fetch_artifact_to_store(&repo, &used, &store).await;
            let bad = client.fetch_artifact_to_store(&repo, &bad, &store).await;
            let options = FetchArtifact {
                pin: Some(&wrong_pin),
                index: None,
            };
            let pinned = client.fetch_artifact(&repo, &pinned, &store, options).await;
            let pinned = pinned.map(|fetched| fetched.blob);
            fetched = Some((good, bad, pinned));
        });
    });
    let (good, bad, pinned) = fetched.unwrap();
    assert_eq!(good.unwrap(), rv_maven_types::BlobId::from_bytes(JAR));
    for refused in [bad, pinned] {
        assert!(
            matches!(refused, Err(RepoError::ChecksumMismatch { .. })),
            "{refused:?}"
        );
    }
    assert!(
        fetch_log.contains("a-1.jar") && fetch_log.contains("WEAK_HASH_FALLBACK"),
        "{fetch_log}"
    );
    for path in [
        "/g/a/1/a-1.pom",
        "/g/a/1/a-1.jar",
        "/g/bad/1/bad-1.jar",
        "/g/pinned/1/pinned-1.jar",
    ] {
        let requests = server.requests().iter().filter(|r| r.path == path).count();
        assert_eq!(requests, 1, "{path}");
    }
    let staging = std::fs::read_dir(store_dir.path().join("tmp"))
        .unwrap()
        .count();
    assert_eq!(staging, 0, "refused bytes stay out of the store");
}

#[test]
fn a_prefetched_file_answers_its_read_when_the_sidecar_failed() {
    let server = StubServer::start(|request| match request.path.as_str() {
        "/g/a/1/a-1.jar" => Response::new(200, "jar bytes"),
        "/g/a/1/a-1.jar.sha256" => Response::new(500, ""),
        _ => Response::new(404, ""),
    });
    let (client, _cache) = test_client();
    let repo = http_repo(&server);
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let req = ArtifactRequest::new("g", "a", "1");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fetched = runtime.block_on(async {
        client.prefetch_artifact(&repo, &req, &store).await;
        client.fetch_artifact_to_store(&repo, &req, &store).await
    });
    assert!(fetched.is_err(), "{fetched:?}");
    let downloads = (server.requests().iter())
        .filter(|request| request.path == "/g/a/1/a-1.jar")
        .count();
    assert_eq!(downloads, 1);
}

#[tokio::test]
async fn snapshot_requests_report_the_path_actually_served() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = file_repo(tmp.path());
    let dir = tmp.path().join("g/a/1-SNAPSHOT");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("maven-metadata.xml"), "<metadata><version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20261011.010101</timestamp><buildNumber>1</buildNumber></snapshot></versioning></metadata>").unwrap();
    std::fs::write(dir.join("a-1-20261011.010101-1.pom"), b"pom bytes").unwrap();
    let (client, _cache) = test_client();
    let store_tmp = tempfile::tempdir().unwrap();
    let store = store_in(&store_tmp);
    for version in ["1-SNAPSHOT", "1-20261011.010101-1"] {
        let request = ArtifactRequest::new("g", "a", version).with_packaging("pom");
        let (bytes, path) = client.fetch_pom_with_path(&repo, &request).await.unwrap();
        assert_eq!(bytes.as_ref(), b"pom bytes");
        assert_eq!(path, "g/a/1-SNAPSHOT/a-1-20261011.010101-1.pom");
        let fetched = client
            .fetch_artifact(&repo, &request, &store, FetchArtifact::default())
            .await
            .unwrap();
        assert_eq!(fetched.path, path);
    }
}

/// Only POM bytes are announced, not the metadata a SNAPSHOT POM read
/// resolves first.
#[tokio::test]
async fn only_poms_are_announced() {
    let server = model_stub(Arc::new(AtomicBool::new(true)));
    let (client, _tmp) = test_client();
    let announced = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&announced);
    let arrival: PomArrival = Arc::new(move |bytes: &bytes::Bytes| {
        record.lock().expect("announced").push(bytes.clone());
    });
    let snapshot = ArtifactRequest::new("test", "demo", "1.0-SNAPSHOT");
    let pom = announcing_poms(arrival, client.fetch_pom(&http_repo(&server), &snapshot))
        .await
        .expect("pom");
    assert_eq!(*announced.lock().expect("announced"), [pom]);
}

/// As `mvn -U` does, `--update` fetches cached metadata and a non-unique
/// SNAPSHOT POM again once per run, and reuses a release POM. Offline,
/// the cache still serves them all.
#[tokio::test]
async fn update_refetches_mutable_rows_cached_before_the_run() {
    let server = model_stub(Arc::new(AtomicBool::new(true)));
    let (client, tmp) = test_client();
    let repo = http_repo(&server);
    let release = ArtifactRequest::new("test", "demo", "1.0");
    let snapshot = ArtifactRequest::new("test", "demo", "1.0-SNAPSHOT");
    let metadata = coord("test:demo:1.0");
    // Each run is a new process over the same metadata.db.
    let run = || {
        let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
        let http = rv_http::client_builder()
            .no_proxy()
            .build()
            .expect("client");
        RepoClient::for_test(
            ClientSet::unscreened(http),
            router(Vec::new(), AuthStore::default()),
            cache,
        )
    };
    let read_all = |client: RepoClient| {
        let (release, snapshot, metadata, repo) = (&release, &snapshot, &metadata, &repo);
        async move {
            client.fetch_pom(repo, release).await.unwrap();
            client.fetch_pom(repo, snapshot).await.unwrap();
            client.fetch_metadata(repo, metadata).await.unwrap();
        }
    };
    read_all(client).await;
    let answered = server.answered();
    read_all(run()).await;
    assert_eq!(server.answered(), answered, "the cache serves a plain run");

    // Rows record whole seconds; a row written in the second the run
    // starts counts as written by it.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    read_all(run().with_update(true).with_offline(true)).await;
    assert_eq!(server.answered(), answered, "offline uses the cache");
    let updating = run().with_update(true);
    read_all(updating.clone()).await;
    let requests = server.requests();
    let refetched: Vec<&str> = requests[answered..]
        .iter()
        .map(|request| request.path.as_str())
        .filter(|path| !path.ends_with(".sha256"))
        .collect();
    assert_eq!(
        refetched,
        [
            "/test/demo/1.0-SNAPSHOT/maven-metadata.xml",
            "/test/demo/1.0-SNAPSHOT/demo-1.0-SNAPSHOT.pom",
            "/test/demo/maven-metadata.xml",
        ]
    );
    let answered = server.answered();
    read_all(updating).await;
    read_all(run()).await;
    assert_eq!(
        server.answered(),
        answered,
        "rows this run wrote are reused"
    );
}

/// A POM or version list a repository lacks or refuses is not asked for
/// again by a later run that sends the same credential while the update
/// policy keeps the answer, as Maven does not ask again for a POM it holds,
/// and the kept answer reads as the live one did. A run that sends another
/// credential, or one where none was sent, asks again and gets the file,
/// and so do `--update` and a run whose raeva.lock records the repository
/// as serving the file. A lock pin alone does not. Under `always` nothing
/// is kept. Without the `cache-key` file the misses kept for a credential
/// no longer match.
#[tokio::test]
async fn a_miss_is_kept_across_runs_for_the_credential_sent() {
    for status in [404, 401, 403] {
        a_miss_is_kept_across_runs(status).await;
    }
}

async fn a_miss_is_kept_across_runs(status: u16) {
    const POM: &[u8] = b"<project/>";
    let server = StubServer::start(move |request| {
        if request.header("authorization") != Some("Bearer good") {
            return Response::new(status, "");
        }
        let body: &[u8] = match request.path.trim_end_matches(".sha256") {
            "/g/a/1/a-1.pom" => POM,
            "/g/a/maven-metadata.xml" => RELEASE_METADATA,
            _ => return Response::new(404, ""),
        };
        if request.path.ends_with(".sha256") {
            Response::new(200, sha256_hex(body))
        } else {
            Response::new(200, body)
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    // Each run is a new process over the same metadata.db.
    let run = |auth: AuthStore| {
        let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
        let http = rv_http::client_builder().no_proxy().build().unwrap();
        RepoClient::for_test(ClientSet::unscreened(http), router(Vec::new(), auth), cache)
    };
    let read = |client: RepoClient, repo: Repository, artifact: &'static str| async move {
        let request = ArtifactRequest::new("g", artifact, "1");
        let pom = client.fetch_pom(&repo, &request).await.map(|_| ());
        let listed = (client.fetch_metadata(&repo, &coord(&format!("g:{artifact}:1")))).await;
        [pom, listed.map(|_| ())].map(|result| match result {
            Ok(()) => "ok".to_string(),
            Err(err) => {
                assert_eq!(err.status_code(), Some(status), "{err}");
                err.to_string()
            }
        })
    };
    let anonymous = || run(AuthStore::default());
    let asked = || server.requests().len();
    let mut repo = http_repo(&server);
    let pom_path = "g/a/1/a-1.pom".to_string();
    let pin = rv_maven_types::Digest::Sha256(rv_maven_types::Sha256::from_bytes(POM));

    let live = read(anonymous(), repo.clone(), "a").await;
    assert!(live.iter().all(|answer| answer != "ok"), "{live:?}");
    let before = asked();
    // raeva.lock pins the POM another repository served.
    let mut pinned = anonymous();
    pinned.lock_pins = unserved_pins([(pom_path.clone(), pin.clone())]);
    assert_eq!(read(pinned, repo.clone(), "a").await, live);
    assert_eq!(asked(), before, "{status}: a later run reads the kept miss");

    let mut served = anonymous();
    let origin = std::collections::BTreeSet::from([repo.url.clone()]);
    served.lock_pins = Arc::new([(pom_path, (pin, origin))].into());
    assert_eq!(read(served, repo.clone(), "a").await, live);
    assert!(asked() > before, "{status}: the lock's origin asks again");
    let before = asked();
    assert_eq!(
        read(anonymous().with_update(true), repo.clone(), "a").await,
        live
    );
    assert!(asked() > before, "{status}: --update asks again");

    let refused = || async {
        let request = ArtifactRequest::new("g", "a", "1");
        run(token_auth("bad"))
            .fetch_pom(&repo, &request)
            .await
            .unwrap_err()
    };
    let before = asked();
    let err = refused().await;
    assert!(asked() > before, "{status}: another credential asks again");
    let before = asked();
    let kept = refused().await;
    assert_eq!(
        asked(),
        before,
        "{status}: the same credential reads its miss"
    );
    assert_eq!(kept.to_string(), err.to_string());
    assert!(
        status == 404 || matches!(kept, RepoError::Unauthorized { sent: Some(_), .. }),
        "{kept:?}"
    );
    std::fs::remove_file(tmp.path().join("cache-key")).unwrap();
    let before = asked();
    refused().await;
    assert!(asked() > before, "{status}: a new cache key asks again");
    let before = asked();
    refused().await;
    assert_eq!(asked(), before, "{status}: the new key keeps the miss");
    let found = read(run(token_auth("good")), repo.clone(), "a").await;
    assert_eq!(found, ["ok", "ok"]);

    repo.releases_update_policy = UpdatePolicy::Always;
    read(anonymous(), repo.clone(), "b").await;
    let before = asked();
    read(anonymous(), repo, "b").await;
    assert!(asked() > before, "{status}: nothing is kept under always");
}

/// Maven reads any version ending in `SNAPSHOT` as a snapshot, so a
/// non-unique `1.0SNAPSHOT` POM is fetched again under `--update` too.
#[tokio::test]
async fn update_refetches_a_snapshot_pom_spelled_without_a_hyphen() {
    const METADATA: &str = "<metadata><version>1.0SNAPSHOT</version></metadata>";
    const POM: &str = "<project><modelVersion>4.0.0</modelVersion></project>";
    let server = StubServer::start(|request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        let body = if path.ends_with(".pom") {
            POM
        } else {
            METADATA
        };
        Response::new(
            200,
            if sidecar {
                sha256_hex(body)
            } else {
                body.to_string()
            },
        )
    });
    let (client, _tmp) = test_client();
    let repo = http_repo(&server);
    let snapshot = ArtifactRequest::new("test", "demo", "1.0SNAPSHOT");
    client.fetch_pom(&repo, &snapshot).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let answered = server.answered();
    let mut updating = client.with_update(true);
    updating.pom_memo = Arc::default();
    updating.metadata_memo = MetadataMemo::default();
    updating.fetch_pom(&repo, &snapshot).await.unwrap();
    let requests = server.requests();
    assert!(
        requests[answered..]
            .iter()
            .any(|request| request.path == "/test/demo/1.0SNAPSHOT/demo-1.0SNAPSHOT.pom"),
        "{requests:?}"
    );
}

/// Maven Resolver files a resolved snapshot under the base version of the
/// resolved version, which for `1.0SNAPSHOT` at a timestamped build is that
/// build itself.
#[tokio::test]
async fn a_timestamped_snapshot_spelled_without_a_hyphen_is_read_from_its_build() {
    const METADATA: &str = "<metadata><version>1.0SNAPSHOT</version><versioning><snapshot>\
        <timestamp>20240101.010101</timestamp><buildNumber>7</buildNumber></snapshot>\
        </versioning></metadata>";
    const POM: &str = "<project><modelVersion>4.0.0</modelVersion></project>";
    const PATH: &str = "/test/demo/1.020240101.010101-7/demo-1.020240101.010101-7.pom";
    let server = StubServer::start(|request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        let body = match path {
            PATH => POM,
            "/test/demo/1.0SNAPSHOT/maven-metadata.xml" => METADATA,
            _ => return Response::new(404, ""),
        };
        Response::new(
            200,
            if sidecar {
                sha256_hex(body)
            } else {
                body.to_string()
            },
        )
    });
    let (client, _tmp) = test_client();
    let repo = http_repo(&server);
    let snapshot = ArtifactRequest::new("test", "demo", "1.0SNAPSHOT");
    let (bytes, path) = client.fetch_pom_with_path(&repo, &snapshot).await.unwrap();
    assert_eq!(&bytes[..], POM.as_bytes());
    assert_eq!(format!("/{path}"), PATH);
}

/// A cached POM other than the one raeva.lock pins is a miss: it is fetched
/// again rather than served or reported as a mismatch from the cache.
#[tokio::test]
async fn a_cached_pom_that_differs_from_the_pin_is_fetched_again() {
    let server = model_stub(Arc::new(AtomicBool::new(true)));
    let (mut client, _tmp) = test_client();
    let repo = http_repo(&server);
    let req = ArtifactRequest::new("test", "demo", "1.0");
    client.fetch_pom(&repo, &req).await.unwrap();
    let answered = server.answered();
    client.lock_pins = unserved_pins([(
        req.pom().to_path(),
        rv_maven_types::Digest::Sha256(rv_maven_types::Sha256::from_bytes(b"other")),
    )]);
    client.pom_memo = Arc::default();
    client.fetch_pom(&repo, &req).await.unwrap();
    assert!(
        server.answered() > answered,
        "the differing row is not served"
    );
}

/// A repeat fetch with a SHA-1 pin reuses the stored file that matches it.
#[tokio::test]
async fn a_sha1_pinned_file_is_downloaded_once() {
    const JAR: &[u8] = b"sha1 pinned jar";
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/a/1/a-1.jar" => Response::new(200, JAR),
        _ => Response::new(404, "missing"),
    });
    let repo = http_repo(&server);
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let (client, _cache) = test_client();
    let pin = rv_maven_types::Digest::of_bytes(rv_maven_types::HashAlgorithm::Sha1, JAR);
    let options = FetchArtifact {
        pin: Some(&pin),
        index: None,
    };
    let a = ArtifactRequest::new("g", "a", "1");
    for _ in 0..2 {
        let fetched = client.fetch_artifact(&repo, &a, &store, options).await;
        assert_eq!(
            fetched.unwrap().blob,
            rv_maven_types::BlobId::from_bytes(JAR)
        );
    }
    let jars = (server.requests().iter())
        .filter(|r| r.path == "/g/a/1/a-1.jar")
        .count();
    assert_eq!(jars, 1);
}

/// A file raeva.lock pins is checked against the pin alone: its sidecars are
/// not requested unless the bytes differ from a lock pin. A later fetch of a
/// stored file reuses it when its checks accept it, so platforms resolved
/// together download each file once. A sidecar holding no digest counts as
/// missing, so the pin or `--allow-missing-checksums` decides.
#[tokio::test]
async fn pins_skip_sidecars_and_stored_files_are_not_downloaded_again() {
    const JAR: &[u8] = b"pinned jar";
    const POM: &[u8] = b"<project><version>1</version></project>";
    const OTHER: &[u8] = b"other jar";
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/a/1/a-1.jar" => Response::new(200, JAR),
        "/g/a/1/a-1.pom" => Response::new(200, POM),
        "/g/b/1/b-1.jar" => Response::new(200, OTHER),
        "/g/b/1/b-1.jar.sha256" => Response::new(200, sha256_hex(OTHER)),
        "/g/c/1/c-1.jar" => Response::new(200, OTHER),
        _ => Response::new(200, "<html><body>Not Found</body></html>"),
    });
    let repo = http_repo(&server);
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let (mut client, _cache) = test_client();
    let pin =
        |bytes: &[u8]| rv_maven_types::Digest::Sha256(rv_maven_types::BlobId::from_bytes(bytes));
    client.lock_pins = unserved_pins([
        ("g/a/1/a-1.pom".to_string(), pin(POM)),
        ("g/b/1/b-1.jar".to_string(), pin(b"stale pin")),
    ]);
    let (a, b, c) = (
        ArtifactRequest::new("g", "a", "1"),
        ArtifactRequest::new("g", "b", "1"),
        ArtifactRequest::new("g", "c", "1"),
    );
    let key = ArtifactCoord::new("g", "a", "1", "jar", None);

    assert_eq!(client.fetch_pom(&repo, &a).await.unwrap().as_ref(), POM);
    let options = FetchArtifact {
        pin: Some(&pin(JAR)),
        index: Some(&key),
    };
    let fetched = client.fetch_artifact(&repo, &a, &store, options).await;
    assert!(!fetched.unwrap().checksum_verified);
    let again = client.fetch_artifact(&repo, &a, &store, options).await;
    assert_eq!(again.unwrap().blob, rv_maven_types::BlobId::from_bytes(JAR));
    // Without the pin, a strict run neither takes the stored file nor finds
    // a checksum for it.
    let unpinned = client.fetch_artifact_to_store(&repo, &a, &store).await;
    assert!(
        matches!(unpinned, Err(RepoError::MissingChecksum(_))),
        "{unpinned:?}"
    );
    assert_eq!(
        client.stored_artifact(&store, &repo, &key).await.unwrap(),
        None
    );
    let mut pinned = client.clone();
    pinned.lock_pins = unserved_pins([("g/a/1/a-1.jar".to_string(), pin(JAR))]);
    assert_eq!(
        pinned.stored_artifact(&store, &repo, &key).await.unwrap(),
        Some(rv_maven_types::BlobId::from_bytes(JAR))
    );
    // Bytes that differ from a stale lock pin are checked against the
    // sidecar instead.
    let verified = client.fetch_artifact(&repo, &b, &store, FetchArtifact::default());
    assert!(verified.await.unwrap().checksum_verified);
    let lenient = client.clone().with_allow_missing_checksums(true);
    assert!(
        lenient
            .fetch_artifact_to_store(&repo, &c, &store)
            .await
            .is_ok()
    );

    let requests = server.requests();
    let count = |path: &str| requests.iter().filter(|r| r.path == path).count();
    for path in ["/g/a/1/a-1.pom", "/g/b/1/b-1.jar", "/g/b/1/b-1.jar.sha256"] {
        assert_eq!(count(path), 1, "{path}");
    }
    // The pinned fetch and its repeat download once; the strict fetch
    // without the pin downloads again and finds no checksum.
    assert_eq!(count("/g/a/1/a-1.jar"), 2);
    for path in ["/g/a/1/a-1.pom.sha256", "/g/a/1/a-1.pom.sha1"] {
        assert_eq!(count(path), 0, "{path}");
    }

    // A clone with another lock does not take bytes only this lock's pin
    // admitted.
    let mut repinned = client.clone();
    repinned.lock_pins = unserved_pins([("g/a/1/a-1.pom".to_string(), pin(b"another pom"))]);
    let refused = repinned.fetch_pom(&repo, &a).await;
    assert!(refused.is_err(), "{refused:?}");
}

/// A POM's external HTTP repository is fetched through a user mirror that
/// matches it, and a loopback one directly.
#[tokio::test]
async fn pom_http_repositories_fetch_through_user_mirrors_or_loopback() {
    let (loopback, server) = body_stub(b"artifact bytes");
    let tmp = tempfile::tempdir().unwrap();
    let config = Config::for_testing(
        tmp.path().into(),
        rv_config::ResolvedPaths::from_raeva_home(tmp.path().join("home")),
    )
    .with_mirrors(vec![mirror("safe", &loopback.url, "external:http:*")]);
    let client = RepoClient::new(&config).await.unwrap();
    let legacy = Repository::new(None, "http://repo.example/", true, false);
    for declared in [legacy, loopback.clone()] {
        let admitted = client
            .policy()
            .admit([declared], crate::Declaration::LocalPom);
        let repo = &admitted.admitted[0];
        assert_eq!(client.effective_repository(repo).url, loopback.url);
        let fetched = client
            .fetch_pom(repo, &ArtifactRequest::new("g", "a", "1"))
            .await
            .unwrap();
        assert_eq!(fetched.as_ref(), b"artifact bytes");
    }
    assert!(
        server
            .requests()
            .iter()
            .any(|request| request.path == "/g/a/1/a-1.pom")
    );
}

/// One URL under two ids is two repositories: a miss or a download under
/// one id, whose credential the server may answer differently, is not
/// reused for the other.
#[tokio::test]
async fn one_url_answers_each_repository_id_on_its_own() {
    const JAR: &[u8] = b"private jar";
    const POM: &[u8] = b"<project/>";
    const PUBLIC: &[u8] = b"<project><!-- public --></project>";
    let server = StubServer::start(|request| {
        let authorized = request.header("authorization").is_some();
        match (request.path.as_str(), authorized) {
            ("/g/b/1/b-1.pom", false) => return Response::new(200, PUBLIC),
            ("/g/b/1/b-1.pom.sha256", false) => return Response::new(200, sha256_hex(PUBLIC)),
            (_, false) => return Response::new(404, ""),
            _ => {}
        }
        match request.path.as_str() {
            "/g/b/1/b-1.pom" => Response::new(200, POM),
            "/g/b/1/b-1.pom.sha256" => Response::new(200, sha256_hex(POM)),
            "/g/a/1/a-1.pom" => Response::new(200, POM),
            "/g/a/1/a-1.pom.sha256" => Response::new(200, sha256_hex(POM)),
            "/g/a/1/a-1.jar" => Response::new(200, JAR),
            "/g/a/1/a-1.jar.sha256" => Response::new(200, sha256_hex(JAR)),
            _ => Response::new(404, ""),
        }
    });
    let mut auth = rv_config::AuthConfig::new(Some("private"));
    auth.token = Some(SecretString::from("dummy-token".to_string()));
    let auth = AuthStore::from_auth_configs(&[auth]).expect("auth");
    let (client, _cache) = client_for(router(Vec::new(), auth));
    let url = format!("http://{}/", server.addr());
    let public = Repository::new(Some("public".into()), url.clone(), true, true);
    let private = Repository::new(Some("private".into()), url, true, true);
    let request = ArtifactRequest::new("g", "a", "1");
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);

    let missed = client.fetch_pom(&public, &request).await;
    assert!(matches!(missed, Err(RepoError::NotFound(_))), "{missed:?}");
    assert!(client.fetch_pom(&private, &request).await.is_ok());
    let missed = client
        .fetch_artifact_to_store(&public, &request, &store)
        .await;
    assert!(matches!(missed, Err(RepoError::NotFound(_))), "{missed:?}");
    let fetched = client
        .fetch_artifact_to_store(&private, &request, &store)
        .await;
    assert_eq!(fetched.unwrap(), rv_maven_types::BlobId::from_bytes(JAR));
    let other = ArtifactRequest::new("g", "b", "1");
    for (repo, bytes) in [(&public, PUBLIC), (&private, POM)] {
        assert_eq!(
            client.fetch_pom(repo, &other).await.unwrap().as_ref(),
            bytes
        );
    }
}

/// A fetched POM's repository gets its id credential once the project's own
/// POM declares that origin, so a miss it got without the credential is
/// asked again.
#[tokio::test]
async fn a_miss_without_the_credential_is_asked_again_once_it_follows() {
    for status in [404, 401] {
        a_miss_without_the_credential_is_asked_again(status).await;
    }
}

async fn a_miss_without_the_credential_is_asked_again(status: u16) {
    const JAR: &[u8] = b"private jar";
    const POM: &[u8] = b"<project/>";
    let server = StubServer::start(move |request| {
        if request.header("authorization").is_none() {
            return Response::new(status, "");
        }
        match request.path.as_str() {
            "/g/a/1/a-1.pom" => Response::new(200, POM),
            "/g/a/1/a-1.pom.sha256" => Response::new(200, sha256_hex(POM)),
            "/g/a/1/a-1.jar" => Response::new(200, JAR),
            "/g/a/1/a-1.jar.sha256" => Response::new(200, sha256_hex(JAR)),
            _ => Response::new(404, ""),
        }
    });
    let mut auth = rv_config::AuthConfig::new(Some("corp"));
    auth.token = Some(SecretString::from("dummy-token".to_string()));
    let auth = AuthStore::from_auth_configs(&[auth])
        .expect("auth")
        .with_configured_urls(&[]);
    let (client, _cache) = client_for(router(Vec::new(), auth));
    let url = format!("http://{}/", server.addr());
    let mut fetched = Repository::new(Some("corp".into()), url.clone(), true, true);
    fetched.set_provenance(crate::Provenance::FetchedPom);
    let request = ArtifactRequest::new("g", "a", "1");
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);

    let missed = client.fetch_pom(&fetched, &request).await.map(|_| ());
    assert_eq!(missed.unwrap_err().status_code(), Some(status));
    let missed = client
        .fetch_artifact_to_store(&fetched, &request, &store)
        .await;
    assert_eq!(missed.unwrap_err().status_code(), Some(status));

    let declared = Repository::new(Some("corp".into()), url, true, true);
    client
        .policy()
        .admit([declared], crate::Declaration::LocalPom);
    assert_eq!(
        client.fetch_pom(&fetched, &request).await.unwrap().as_ref(),
        POM
    );
    let jar = client
        .fetch_artifact_to_store(&fetched, &request, &store)
        .await;
    assert_eq!(jar.unwrap(), rv_maven_types::BlobId::from_bytes(JAR));
}

/// A miss answered after the credential began to follow counts as one
/// without it: the request was sent before.
#[tokio::test]
async fn a_miss_sent_before_the_credential_follows_is_asked_again() {
    use std::sync::atomic::{AtomicBool, Ordering};
    const POM: &[u8] = b"<project/>";
    let started = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let (on_start, on_release) = (Arc::clone(&started), Arc::clone(&release));
    let server = StubServer::start(move |request| {
        if request.header("authorization").is_none() {
            if request.path == "/g/a/1/a-1.pom" {
                on_start.store(true, Ordering::SeqCst);
                while !on_release.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            return Response::new(404, "");
        }
        match request.path.as_str() {
            "/g/a/1/a-1.pom" => Response::new(200, POM),
            "/g/a/1/a-1.pom.sha256" => Response::new(200, sha256_hex(POM)),
            _ => Response::new(404, ""),
        }
    });
    let mut auth = rv_config::AuthConfig::new(Some("corp"));
    auth.token = Some(SecretString::from("dummy-token".to_string()));
    let auth = AuthStore::from_auth_configs(&[auth])
        .expect("auth")
        .with_configured_urls(&[]);
    let (client, _cache) = client_for(router(Vec::new(), auth));
    let url = format!("http://{}/", server.addr());
    let mut fetched = Repository::new(Some("corp".into()), url.clone(), true, true);
    fetched.set_provenance(crate::Provenance::FetchedPom);
    let request = ArtifactRequest::new("g", "a", "1");

    let anonymous = tokio::spawn({
        let (client, fetched, request) = (client.clone(), fetched.clone(), request.clone());
        async move { client.fetch_pom(&fetched, &request).await }
    });
    while !started.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let declared = Repository::new(Some("corp".into()), url, true, true);
    client
        .policy()
        .admit([declared], crate::Declaration::LocalPom);
    release.store(true, Ordering::SeqCst);
    let missed = anonymous.await.unwrap();
    assert!(matches!(missed, Err(RepoError::NotFound(_))), "{missed:?}");
    assert_eq!(
        client.fetch_pom(&fetched, &request).await.unwrap().as_ref(),
        POM
    );
}

/// A checksum probe that ran out of retries on one sidecar reports that
/// failure over another sidecar's, so the repository search ends there. A
/// read with a lock pin, which needs no sidecar, still gets the POM.
#[tokio::test]
async fn a_retried_sidecar_failure_decides_the_probe() {
    for (sha256, sha1) in [(500, 503), (503, 407)] {
        let server = StubServer::start(move |request| match request.path.rsplit('.').next() {
            Some("pom") => Response::new(200, "<project/>"),
            Some("sha256") => Response::new(sha256, ""),
            Some("sha1") => Response::new(sha1, ""),
            _ => Response::new(404, ""),
        });
        let repo = http_repo(&server);
        let (mut client, _tmp) = test_client();
        client.fetch.retries = 0;
        let err = client
            .fetch_pom(&repo, &ArtifactRequest::new("g", "a", "1"))
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), Some(503), "{sha256} {sha1}: {err}");
        assert!(!err.moves_to_next_repository());
        let req = ArtifactRequest::new("g", "a", "1");
        let mut pinned = client.clone();
        pinned.lock_pins = unserved_pins([(
            req.pom().to_path(),
            rv_maven_types::Digest::Sha256(rv_maven_types::BlobId::from_bytes(b"<project/>")),
        )]);
        pinned.fetch_pom(&repo, &req).await.unwrap();
    }
}

/// A refusal of a request whose route picked its credential before the
/// credential began to follow counts as one without it, however late the
/// request goes out.
#[tokio::test]
async fn a_refusal_counts_from_when_its_route_picked_the_credential() {
    const POM: &[u8] = b"<project/>";
    let server = StubServer::start(|request| {
        if request.header("authorization").is_none() {
            return Response::new(401, "");
        }
        match request.path.as_str() {
            "/g/a/1/a-1.pom" => Response::new(200, POM),
            "/g/a/1/a-1.pom.sha256" => Response::new(200, sha256_hex(POM)),
            _ => Response::new(404, ""),
        }
    });
    let mut auth = rv_config::AuthConfig::new(Some("corp"));
    auth.token = Some(SecretString::from("dummy-token".to_string()));
    let auth = AuthStore::from_auth_configs(&[auth])
        .expect("auth")
        .with_configured_urls(&[]);
    let (client, _cache) = client_for(router(Vec::new(), auth));
    let url = format!("http://{}/", server.addr());
    let mut fetched = Repository::new(Some("corp".into()), url.clone(), true, true);
    fetched.set_provenance(crate::Provenance::FetchedPom);
    let route = client.router.route(&fetched);
    assert!(route.auth().unwrap().is_none());
    let declared = Repository::new(Some("corp".into()), url, true, true);
    client
        .policy()
        .admit([declared], crate::Declaration::LocalPom);
    let refused = client
        .fetch_model_bytes(
            &route,
            "g/a/1/a-1.pom",
            "1",
            &mut super::requests::DeferredWarnings::default(),
        )
        .await;
    assert_eq!(refused.unwrap_err().status_code(), Some(401));
    let request = ArtifactRequest::new("g", "a", "1");
    assert_eq!(
        client.fetch_pom(&fetched, &request).await.unwrap().as_ref(),
        POM
    );
}

/// A missing file has no checksum file either: the miss is answered while
/// its sidecar probe still waits, on a download and on a prefetch.
#[tokio::test]
async fn a_missing_file_does_not_wait_for_its_sidecars() {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    let release = Arc::new(AtomicBool::new(false));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let held = Arc::clone(&release);
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let held = Arc::clone(&held);
            std::thread::spawn(move || {
                while let Some(head) =
                    rv_test_support::http::read_request_head_blocking(&mut stream)
                {
                    let line = String::from_utf8_lossy(&head);
                    let path = line.split_whitespace().nth(1).unwrap_or_default();
                    if path.ends_with(".sha256") || path.ends_with(".sha1") {
                        while !held.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                    let reply = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";
                    if stream.write_all(reply).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let (client, _cache) = mirrored_client(Vec::new());
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let repo = Repository::new(None, format!("http://{addr}/"), true, true);
    let started = std::time::Instant::now();
    client
        .prefetch_artifact(&repo, &ArtifactRequest::new("g", "b", "1"), &store)
        .await;
    let prefetched = started.elapsed();
    let started = std::time::Instant::now();
    let fetched = client
        .fetch_artifact_to_store(&repo, &ArtifactRequest::new("g", "a", "1"), &store)
        .await;
    let downloaded = started.elapsed();
    release.store(true, Ordering::SeqCst);
    // The sidecars would answer only when the client's timeout ends them.
    let bound = Duration::from_secs(2);
    assert!(prefetched < bound, "the prefetch waited {prefetched:?}");
    assert!(downloaded < bound, "the download waited {downloaded:?}");
    assert!(
        matches!(fetched, Err(RepoError::NotFound(_))),
        "{fetched:?}"
    );
}

/// A refused download reports its own status, not the failure of a sidecar
/// probed beside it, so the resolver treats it as the refusal it is.
#[tokio::test]
async fn a_refused_file_reports_its_status_before_its_sidecars() {
    let server = StubServer::start(|request| match request.path.as_str() {
        "/g/a/1/a-1.jar" | "/g/a/1/a-1.jar.sha256" => Response::new(403, ""),
        "/g/a/1/a-1.jar.sha1" => Response::new(400, ""),
        _ => Response::new(404, ""),
    });
    let (client, _cache) = mirrored_client(Vec::new());
    let store_dir = tempfile::tempdir().unwrap();
    let request = ArtifactRequest::new("g", "a", "1");
    let fetched = client
        .fetch_artifact_to_store(&http_repo(&server), &request, &store_in(&store_dir))
        .await;
    assert!(
        matches!(&fetched, Err(RepoError::Unauthorized { status, .. }) if status.as_u16() == 403),
        "{fetched:?}"
    );
}

/// Lock pins for `files`, with no origin recorded as serving them.
fn unserved_pins<const N: usize>(
    files: [(String, rv_maven_types::Digest); N],
) -> Arc<HashMap<String, (rv_maven_types::Digest, std::collections::BTreeSet<String>)>> {
    Arc::new(
        files
            .into_iter()
            .map(|(path, pin)| (path, (pin, Default::default())))
            .collect(),
    )
}
