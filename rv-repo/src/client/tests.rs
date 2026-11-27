use super::*;
use crate::artifact::ArtifactRequest;
use crate::auth::AuthStore;
use crate::error::IntegritySource;
use crate::fetch::FetchConfig;
use crate::mirror::MirrorSelector;
use crate::routing::{Router, cache_scope_key};
use crate::transport::ClientSet;
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
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let client = RepoClient::for_test(ClientSet::unscreened(http), router, cache);
    (client, tmp)
}

fn test_client() -> (RepoClient, tempfile::TempDir) {
    client_for(router(Vec::new(), AuthStore::default()))
}

/// No retries, and the default timeout: under load macOS can hold a new
/// loopback connection for several seconds before its handshake completes.
fn mirrored_client(mirrors: Vec<MirrorConfig>) -> (RepoClient, tempfile::TempDir) {
    let (mut client, tmp) = client_for(router(mirrors, AuthStore::default()));
    client.fetch = FetchConfig {
        retries: 0,
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

/// A cached POM without a checksum file that matches a SHA-1 lock pin is
/// verified by it, offline too, as one that matches a SHA-256 pin is.
#[tokio::test]
async fn a_cached_pom_matching_a_sha1_pin_needs_no_checksum_file() {
    let server = model_stub(Arc::new(AtomicBool::new(false)));
    let (mut client, _tmp) = test_client();
    let repo = http_repo(&server);
    let req = ArtifactRequest::new("test", "demo", "1.0");
    let bytes = (client.clone().with_allow_missing_checksums(true))
        .fetch_pom(&repo, &req)
        .await
        .unwrap();
    let pin = rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, &bytes);
    client.lock_pins = unserved_pins([(req.pom().to_path(), pin)]);
    let offline = client.with_offline(true);
    assert_eq!(offline.fetch_pom(&repo, &req).await.unwrap(), bytes);
}

/// A SHA-1 lock pin decides a fetched POM before its checksum file does: it
/// needs none, and other bytes are refused as differing from the pin even
/// when the repository's checksum file matches them.
#[tokio::test]
async fn a_sha1_pin_decides_a_fetched_pom_before_its_checksum_file() {
    for checksums in [false, true] {
        let server = model_stub(Arc::new(AtomicBool::new(checksums)));
        let repo = http_repo(&server);
        let req = ArtifactRequest::new("test", "demo", "1.0");
        let (lenient, _lenient_home) = test_client();
        let bytes = (lenient.with_allow_missing_checksums(true))
            .fetch_pom(&repo, &req)
            .await
            .unwrap();
        let pin = rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, &bytes);
        let (mut client, _home) = test_client();
        client.lock_pins = unserved_pins([(req.pom().to_path(), pin)]);
        assert_eq!(client.fetch_pom(&repo, &req).await.unwrap(), bytes);

        let other = rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, b"other");
        let (mut client, _home) = test_client();
        client.lock_pins = unserved_pins([(req.pom().to_path(), other)]);
        assert!(matches!(
            client.fetch_pom(&repo, &req).await,
            Err(RepoError::ChecksumMismatch {
                check: IntegritySource::LockPin,
                ..
            })
        ));
    }
}

/// Metadata without a sidecar from a repository whose checksum policy is
/// `fail` names that policy, with or without `--allow-missing-checksums`,
/// since the flag cannot lift it; a POM there is a plain missing checksum.
#[tokio::test]
async fn a_fail_policy_on_metadata_without_a_sidecar_names_the_policy() {
    let server = model_stub(Arc::new(AtomicBool::new(false)));
    let (client, _tmp) = test_client();
    let mut repo = Repository::new(None, format!("http://{}/", server.addr()), true, false);
    repo.releases_checksum_policy = ChecksumPolicy::Fail;
    let release = coord("test:demo:1.0");
    for run in [
        client.clone(),
        client.clone().with_allow_missing_checksums(true),
    ] {
        let err = run.fetch_metadata(&repo, &release).await.unwrap_err();
        assert!(
            matches!(err, RepoError::MissingMetadataChecksum(_)),
            "{err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("checksum policy is fail, which no flag lifts"),
            "{message}"
        );
    }
    let req = ArtifactRequest::new("test", "demo", "1.0");
    let err = client.fetch_pom(&repo, &req).await.unwrap_err();
    assert!(matches!(err, RepoError::MissingChecksum(_)), "{err}");
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
/// mismatch cannot stretch the update policy past the run that fetched it. A retry that matches warns
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
            assert_eq!(
                server.answered(),
                6,
                "both files are fetched twice, then the .sha1 and .md5 hold no digest"
            );
            client.fetch_metadata(&repo, &metadata_coord).await.unwrap();
            assert_eq!(server.answered(), 6, "the daily cache applies");
            repo.releases_update_policy = UpdatePolicy::Always;
            repo.snapshots_update_policy = UpdatePolicy::Always;
            client.fetch_metadata(&repo, &metadata_coord).await.unwrap();
            assert_eq!(server.answered(), 12, "a shorter update policy refetches");
            repo.releases_checksum_policy = ChecksumPolicy::Fail;
            repo.snapshots_checksum_policy = ChecksumPolicy::Fail;
            assert!(matches!(
                client.fetch_metadata(&repo, &metadata_coord).await,
                Err(RepoError::ChecksumMismatch { .. })
            ));
            assert_eq!(server.answered(), 18);
        }
        let (client, cache) = test_client();
        let (mut repo, server) = metadata_checksum_stub(false);
        repo.snapshots_update_policy = UpdatePolicy::Always;
        let later = || {
            let http = rv_http::client_builder().no_proxy().build().unwrap();
            let cache = MetadataCache::new(&cache.path().join("metadata.db")).unwrap();
            RepoClient::for_test(
                ClientSet::unscreened(http),
                router(Vec::new(), AuthStore::default()),
                cache,
            )
        };
        for (run, answered) in [(client.clone(), 6), (client, 6), (later(), 12)] {
            let snapshot = coord("com.example:demo:1.0-SNAPSHOT");
            let resolved = run.resolve_snapshot_version(&repo, &snapshot).await;
            assert_eq!(resolved.unwrap().version, "1.0-20261011.010101-2");
            assert_eq!(
                server.answered(),
                answered,
                "a run reads what it fetched, and a mismatch cannot extend the policy"
            );
        }

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
            assert_eq!(server.answered(), 4);
        }
    });
    assert_eq!(output.matches("METADATA_CHECKSUM_MISMATCH").count(), 6);
    assert!(output.contains("repository_url=http://127.0.0.1:"));
    assert!(output.contains("com/example/demo/maven-metadata.xml"));
    assert!(output.contains("com/example/demo/1.0-SNAPSHOT/maven-metadata.xml"));
    assert!(!output.contains("secret"));
    assert!(!output.contains("user:"));
}

/// Metadata whose `.sha256` is stale while its `.sha1` matches, as on
/// Central's snapshot repository for publishers that deploy only Maven's
/// default checksums: Maven checks the `.sha1` and takes it under either
/// policy, and so does raeva, with a warning that names the `.sha256`. A
/// `.sha1` that disagrees too leaves the policy to decide.
#[test]
fn metadata_with_a_stale_sha256_and_a_matching_sha1_is_used() {
    let body = "<metadata><version>1.0-SNAPSHOT</version><versioning><snapshot>\
                <timestamp>20261011.010101</timestamp><buildNumber>3</buildNumber>\
                </snapshot></versioning></metadata>";
    let stub = |sha1: String| {
        StubServer::start(move |request| match request.path.rsplit_once('.') {
            Some((_, "sha256")) => Response::new(200, "0".repeat(64)),
            Some((_, "sha1")) => Response::new(200, sha1.clone()),
            Some((_, "md5")) => Response::new(404, ""),
            _ => Response::new(200, body),
        })
    };
    let sha1 = hex::encode(<sha1::Sha1 as sha1::Digest>::digest(body));
    let snapshot = coord("com.example:demo:1.0-SNAPSHOT");
    let output = capture_warn_output(async {
        for policy in [ChecksumPolicy::Warn, ChecksumPolicy::Fail] {
            let (client, _cache) = test_client();
            let server = stub(sha1.clone());
            let mut repo = http_repo(&server);
            repo.snapshots_checksum_policy = policy;
            let resolved = client.resolve_snapshot_version(&repo, &snapshot).await;
            assert_eq!(resolved.unwrap().version, "1.0-20261011.010101-3");
            assert_eq!(
                server.answered(),
                5,
                "file and .sha256 twice, then the .sha1"
            );
        }
        let (client, _cache) = test_client();
        let server = stub("1".repeat(40));
        let mut repo = http_repo(&server);
        repo.snapshots_checksum_policy = ChecksumPolicy::Fail;
        let refused = client.resolve_snapshot_version(&repo, &snapshot).await;
        assert!(
            matches!(&refused, Err(RepoError::ChecksumMismatch { expected, .. })
                if expected.algorithm() == HashAlgorithm::Sha256),
            "{refused:?}"
        );
    });
    assert_eq!(
        output.matches("SHA256_FILE_MISMATCH").count(),
        2,
        "{output}"
    );
    assert!(output.contains("matches its .sha1 file"), "{output}");
    assert!(!output.contains("METADATA_CHECKSUM_MISMATCH"), "{output}");
}

/// A POM or jar whose `.sha256` is wrong is used, with a warning that names
/// the repository, when its `.sha1` matches, as Maven checks only that one,
/// under either policy. When the `.sha1` is wrong too, the `.sha256`
/// mismatch is the error.
#[test]
fn a_wrong_sha256_leaves_a_pom_and_a_jar_to_their_sha1() {
    let body = "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                <artifactId>demo</artifactId><version>1.0</version></project>";
    for sha1 in [
        hex::encode(<sha1::Sha1 as sha1::Digest>::digest(body)),
        "0".repeat(40),
    ] {
        let sha1_answer = sha1.clone();
        let server = StubServer::start(move |request| match request.path.rsplit_once('.') {
            Some((_, "sha256")) => Response::new(200, "0".repeat(64)),
            Some((_, "sha1")) => Response::new(200, sha1_answer.clone()),
            Some((_, "md5")) => Response::new(404, ""),
            _ => Response::new(200, body),
        });
        let matches = sha1 != "0".repeat(40);
        for policy in [ChecksumPolicy::Warn, ChecksumPolicy::Fail] {
            let (client, _cache) = test_client();
            let mut repo = http_repo(&server);
            repo.id = Some("corp".to_string());
            repo.releases_checksum_policy = policy;
            let request = ArtifactRequest::new("com.example", "demo", "1.0");
            let dir = tempfile::tempdir().unwrap();
            let store = store_in(&dir);
            let output = capture_warn_output(async {
                let pom = client.fetch_pom(&repo, &request).await;
                let jar = client
                    .fetch_artifact_to_store(&repo, &request, &store)
                    .await;
                for result in [pom.map(|_| ()), jar.map(|_| ())] {
                    match result {
                        Ok(()) => assert!(matches, "{policy:?}"),
                        Err(RepoError::ChecksumMismatch { expected, .. }) => {
                            assert!(!matches, "{policy:?}");
                            assert_eq!(expected.algorithm(), HashAlgorithm::Sha256);
                        }
                        Err(err) => panic!("{policy:?}: {err}"),
                    }
                }
            });
            let warned = output.matches("SHA256_FILE_MISMATCH").count();
            assert_eq!(warned, if matches { 2 } else { 0 }, "{output}");
            if matches {
                assert!(
                    output.contains("the repository 'corp'")
                        && output.contains("com/example/demo/1.0/demo-1.0.jar")
                        && output.contains(".sha1 file"),
                    "{output}"
                );
            }
        }
    }
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
        // The POM and the jar each: the file, its `.sha256`, then the
        // `.sha1` and `.md5` Maven checks, which hold no digest here.
        assert_eq!(server.answered(), 8, "only metadata gets a checksum retry");
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

fn group_filter(rules: &'static [u8]) -> Arc<rv_config::RepositoryFilters> {
    let on = [("aether.remoteRepositoryFilter.groupId", "true")];
    let files: &[(&str, &str, &[u8])] = &[("groupId", "groupId-r1.txt", rules)];
    Arc::new(
        rv_config::RepositoryFilters::from_files(rv_maven_types::MavenMode::Maven39, &on, files)
            .unwrap(),
    )
}

/// A group the groupId filter keeps from a repository is not asked of it,
/// for a POM, metadata, an artifact or a prefetch, nor answered from the
/// cache or the store; the miss is not kept, so a run without the filter
/// asks. A mirror's id names its rule file, as in Maven.
#[tokio::test]
async fn a_filtered_repository_is_not_asked_for_what_its_rules_leave_out() {
    let (_, server) = body_stub(b"<project><modelVersion>4.0.0</modelVersion></project>");
    let url = format!("http://{}/", server.addr());
    let r1 = Repository::new(Some("r1".to_string()), url.clone(), true, true);
    let cache_dir = tempfile::tempdir().unwrap();
    let client_with = |filters: Option<Arc<rv_config::RepositoryFilters>>, mirrors| {
        let cache = MetadataCache::new(&cache_dir.path().join("metadata.db")).unwrap();
        let http = rv_http::client_builder().no_proxy().build().unwrap();
        let mut client = RepoClient::for_test(
            ClientSet::unscreened(http),
            router(mirrors, AuthStore::default()),
            cache,
        );
        if let Some(filters) = filters {
            client.filters = filters;
        }
        client
    };
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&dir);
    let key = ArtifactCoord::new("org.ex.a", "a1", "1.0", "jar", None);
    let row = rv_store::Origin {
        repo_url: url.clone(),
        endpoint_url: url.clone(),
        checksum_verified: true,
        served: true,
    };
    let blob = rv_maven_types::BlobId::from_bytes(b"jar");
    store
        .record_origins(vec![(key.clone(), blob.clone(), row)])
        .await
        .unwrap();

    let client = client_with(Some(group_filter(b"org.ex.b\n")), Vec::new());
    let req = ArtifactRequest::new("org.ex.a", "a1", "1.0");
    let pom = client.fetch_pom(&r1, &req).await.unwrap_err();
    assert!(
        pom.is_filtered() && pom.to_string().contains("groupId filter"),
        "{pom}"
    );
    assert!(client.prefetch_pom(&r1, &req).await.is_err());
    let metadata = client
        .fetch_metadata(&r1, &coord("org.ex.a:a1:[1,2)"))
        .await;
    assert!(
        matches!(metadata, Err(RepoError::NotFound(_))),
        "{metadata:?}"
    );
    let group = client.fetch_group_metadata(&r1, "org.ex.a").await;
    assert!(matches!(group, Err(RepoError::NotFound(_))), "{group:?}");
    let jar = client.fetch_artifact_to_store(&r1, &req, &store).await;
    assert!(matches!(jar, Err(RepoError::NotFound(_))), "{jar:?}");
    client.prefetch_artifact(&r1, &req, &store, ()).await;
    assert_eq!(
        client.stored_artifact(&store, &r1, &key).await.unwrap(),
        None
    );
    assert_eq!(
        client.served_artifact(&store, &r1, &key).await.unwrap(),
        None
    );
    assert_eq!(server.connections(), 0, "{:?}", server.requests());

    let allowed = ArtifactRequest::new("org.ex.b", "b1", "1.0");
    client.fetch_pom(&r1, &allowed).await.unwrap();
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|r| r.path.ends_with(".pom"))
            .count(),
        1
    );

    let unfiltered = client_with(None, Vec::new());
    unfiltered.fetch_pom(&r1, &req).await.unwrap();
    assert_eq!(
        unfiltered.stored_artifact(&store, &r1, &key).await.unwrap(),
        Some(blob)
    );

    let mirrored = client_with(
        Some(group_filter(b"org.ex.b\n")),
        vec![mirror("m1", &url, "r1")],
    );
    let other = ArtifactRequest::new("org.ex.c", "c1", "1.0");
    mirrored.fetch_pom(&r1, &other).await.unwrap();
}

/// Offline, a snapshot build raeva.lock pins does not resolve through a
/// repository the filters refuse it from, so the search goes on to one
/// they let serve it.
#[tokio::test]
async fn an_offline_pinned_snapshot_does_not_resolve_through_a_filtered_repository() {
    let r1 = Repository::new(Some("r1".to_string()), "https://r1.invalid/", true, true);
    let pom = ArtifactRequest::new("org.ex.s", "s1", "1.0-20240101.010101-1")
        .pom()
        .to_path_with_versions("1.0-SNAPSHOT", "1.0-20240101.010101-1");
    let gav = rv_maven_types::Gav::new("org.ex.s", "s1", "1.0-SNAPSHOT");
    let pin = rv_lock::PinnedSnapshot {
        build: rv_maven_types::SnapshotStamp::of_version("1.0-20240101.010101-1"),
        pom: rv_maven_types::SnapshotStamp::of_version("1.0-20240101.010101-1"),
        file_origins: vec!["https://r1.invalid/".to_string()],
        pom_origins: Vec::new(),
        file: None,
    };
    let coord = Coord {
        packaging: Some("pom".to_string()),
        ..coord("org.ex.s:s1:1.0-SNAPSHOT")
    };
    for rules in [&b"org.ex.s\n"[..], b"org.other\n"] {
        let (mut client, _cache) = test_client();
        client.offline = true;
        client.lock_snapshots = Arc::new(HashMap::from([(
            gav.clone(),
            std::collections::BTreeSet::from([pin.clone()]),
        )]));
        client.lock_missing_poms = Arc::new(std::collections::HashSet::from([pom.clone()]));
        // r1 served the build's jar and answered 404 for its POM.
        let absent = RepoClient::absence_scope(&client.router.route(&r1));
        let checked = super::models::Checked::Verified;
        let kept = client.cache_insert_bytes(
            CacheTable::Miss,
            &absent,
            &pom,
            b"404",
            rv_store::metadata_cache::Expiry::After(3600),
            checked,
        );
        assert!(kept.await);
        let on = [("aether.remoteRepositoryFilter.groupId", "true")];
        let files: &[(&str, &str, &[u8])] = &[("groupId", "groupId-r1.txt", rules)];
        client.filters = Arc::new(
            rv_config::RepositoryFilters::from_files(
                rv_maven_types::MavenMode::Maven39,
                &on,
                files,
            )
            .unwrap(),
        );
        let resolved = client.resolve_snapshot_version(&r1, &coord).await;
        if rules == b"org.ex.s\n" {
            assert_eq!(resolved.unwrap().version, "1.0-20240101.010101-1");
        } else {
            assert!(
                matches!(resolved, Err(RepoError::NotFound(_))),
                "{resolved:?}"
            );
        }
    }
}

/// The prefixes filter judges a snapshot by the path Maven's layout gives
/// it: a timestamped build in its base version's directory, and a
/// `-SNAPSHOT` request by the build its metadata resolves to.
#[tokio::test]
async fn the_prefixes_filter_judges_a_snapshot_by_its_layout_path() {
    let server = StubServer::start(|request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        let body = if path.ends_with("/maven-metadata.xml") {
            "<metadata><groupId>org.ex.s</groupId><artifactId>s1</artifactId>\
             <version>1.0-SNAPSHOT</version><versioning><snapshot>\
             <timestamp>20240101.010101</timestamp><buildNumber>1</buildNumber>\
             </snapshot></versioning></metadata>"
        } else if path.ends_with(".pom") {
            "<project><modelVersion>4.0.0</modelVersion></project>"
        } else {
            return Response::new(404, "");
        };
        if sidecar {
            Response::new(200, sha256_hex(body))
        } else {
            Response::new(200, body)
        }
    });
    let url = format!("http://{}/", server.addr());
    let r1 = Repository::new(Some("r1".to_string()), url, true, true);
    let client_with = |rules: &'static [u8]| {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = MetadataCache::new(&cache_dir.path().join("metadata.db")).unwrap();
        let http = rv_http::client_builder().no_proxy().build().unwrap();
        let mut client = RepoClient::for_test(
            ClientSet::unscreened(http),
            router(Vec::new(), AuthStore::default()),
            cache,
        );
        let on = [("aether.remoteRepositoryFilter.prefixes", "true")];
        let files: &[(&str, &str, &[u8])] = &[("prefixes", "prefixes-r1.txt", rules)];
        client.filters = Arc::new(
            rv_config::RepositoryFilters::from_files(
                rv_maven_types::MavenMode::Maven39,
                &on,
                files,
            )
            .unwrap(),
        );
        (client, cache_dir)
    };
    let poms = || {
        (server.requests().iter())
            .filter(|request| request.path.ends_with(".pom"))
            .count()
    };

    let (client, _cache) = client_with(b"/org/ex/s/s1/1.0-SNAPSHOT\n");
    let build = ArtifactRequest::new("org.ex.s", "s1", "1.0-20240101.010101-1");
    client.fetch_pom(&r1, &build).await.unwrap();
    assert_eq!(poms(), 1, "{:?}", server.requests());

    let (client, _cache) = client_with(
        b"/org/ex/s/s1/1.0-SNAPSHOT/maven-metadata.xml\n/org/ex/s/s1/1.0-SNAPSHOT/s1-1.0-SNAPSHOT.pom\n",
    );
    let snapshot = ArtifactRequest::new("org.ex.s", "s1", "1.0-SNAPSHOT");
    let refused = client.fetch_pom(&r1, &snapshot).await.unwrap_err();
    assert!(
        refused.is_filtered() && refused.to_string().contains("prefixes filter"),
        "{refused}"
    );
    assert_eq!(poms(), 1, "{:?}", server.requests());
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
    // Maven reads the first token only, which is no digest here.
    const HEX_PAGE: &str = "<html><body>Not found request \
        abababababababababababababababababababababababababababababababab extra</body></html>";
    const PATH: &str = "com/example/demo/1.0/demo-1.0.jar";
    for (sha256, sha1) in [
        ((404, ""), (200, SHA1)),
        ((403, ""), (200, SHA1)),
        ((401, ""), (200, SHA1)),
        ((200, GARBAGE), (200, SHA1)),
        ((200, HEX_PAGE), (200, SHA1)),
        ((200, GARBAGE), (200, GARBAGE)),
        ((200, HEX_PAGE), (200, HEX_PAGE)),
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

/// A client that checks `.sha256` answers late takes a POM on a `.sha1`
/// that matches its bytes, once the repository has lacked another
/// `.sha256` and the POM's release has not served one, and [`RepoClient::settle_checksums`] waits for its `.sha256`:
/// a missing one gives the weak-hash warning then, one that holds another
/// digest leaves the POM to the `.sha1` with a warning, and one the
/// repository refuses fails the check and keeps the POM out of the cache. A
/// `.sha1` that does not match waits for the `.sha256`, as does every read
/// of a client that does not check late.
#[test]
fn a_late_sha256_is_checked_before_the_reads_are_settled() {
    const HELD: std::time::Duration = std::time::Duration::from_secs(2);
    let pom = |artifact: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t.x</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version></project>"
        )
    };
    let sha1 = |body: &str| rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, body.as_bytes());
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = path.rsplit_once(".pom").unwrap_or((path, ""));
        let artifact = file.rsplit('/').next().unwrap_or("").trim_end_matches("-1");
        let body = pom(artifact);
        match (artifact, sidecar) {
            (_, "") => Response::new(200, body),
            ("first", ".sha256") => Response::new(404, ""),
            ("stale" | "broken", ".sha1") => Response::new(200, "0".repeat(40)),
            (_, ".sha1") => Response::new(200, sha1(&body).hex().to_string()),
            ("stale" | "vouched", ".sha256") => Response::new(200, sha256_hex(&body)).delayed(HELD),
            ("wrong", ".sha256") => Response::new(200, "0".repeat(64)).delayed(HELD),
            ("refused", ".sha256") => Response::new(407, "").delayed(HELD),
            (_, ".sha256") => Response::new(404, "").delayed(HELD),
            _ => Response::new(404, ""),
        }
    });
    let repo = http_repo(&server);
    let (plain, _tmp) = test_client();
    let late = plain.clone().checking_sha256_late();
    // Each in a release of its own: one that served a `.sha256` is waited
    // for.
    let timed = |client: &RepoClient, artifact: &'static str| {
        let (client, repo) = (client.clone(), repo.clone());
        async move {
            let started = std::time::Instant::now();
            let request = ArtifactRequest::new(format!("t.{artifact}"), artifact, "1");
            let fetched = client.fetch_pom(&repo, &request).await;
            (fetched, started.elapsed())
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            timed(&late, "first").await.0.unwrap();
            late.settle_checksums().await.unwrap();

            for artifact in ["matched", "vouched"] {
                let (read, waited) = timed(&late, artifact).await;
                assert_eq!(read.unwrap(), pom(artifact).as_bytes());
                assert!(
                    waited < HELD,
                    "{artifact} waited {waited:?} for its .sha256"
                );
            }
            let started = std::time::Instant::now();
            late.settle_checksums().await.unwrap();
            assert!(
                started.elapsed() > HELD / 2,
                "settled before the .sha256 answered"
            );
            let (cached, waited) = timed(&plain, "matched").await;
            assert_eq!(cached.unwrap(), pom("matched").as_bytes());
            assert!(waited < HELD, "matched was not cached once checked");

            let (wrong, waited) = timed(&late, "wrong").await;
            assert_eq!(wrong.unwrap(), pom("wrong").as_bytes());
            assert!(waited < HELD, "wrong waited {waited:?} for its .sha256");
            late.settle_checksums().await.unwrap();

            let (refused, waited) = timed(&late, "refused").await;
            assert_eq!(refused.unwrap(), pom("refused").as_bytes());
            assert!(waited < HELD, "refused waited {waited:?} for its .sha256");
            let failed = late.settle_checksums().await;
            assert!(
                matches!(failed, Err(RepoError::Unauthorized { .. })),
                "{failed:?}"
            );
            let (refused, waited) = timed(&plain, "refused").await;
            assert!(
                matches!(refused, Err(RepoError::Unauthorized { .. })),
                "a refused POM was kept: {refused:?}"
            );
            assert!(waited >= HELD, "failed after {waited:?}");

            let (broken, waited) = timed(&late, "broken").await;
            assert!(
                matches!(broken, Err(RepoError::ChecksumMismatch { .. })),
                "{broken:?}"
            );
            assert!(waited >= HELD, "failed on the .sha1 after {waited:?}");
            let (stale, waited) = timed(&late, "stale").await;
            assert_eq!(stale.unwrap(), pom("stale").as_bytes());
            assert!(waited >= HELD, "took the stale .sha1 after {waited:?}");

            let (plain_read, waited) = timed(&plain, "other").await;
            plain_read.unwrap();
            assert!(
                waited >= HELD,
                "a plain client took the .sha1 after {waited:?}"
            );
            let failed = late.settle_checksums().await;
            assert!(
                matches!(failed, Err(RepoError::Unauthorized { .. })),
                "a failed client settled: {failed:?}"
            );
        });
    });
    let weak = |artifact: &str| {
        (log.lines())
            .filter(|line| line.contains("falling back to SHA-1"))
            .any(|line| line.contains(&format!("{artifact}-1.pom")))
    };
    assert!(weak("matched") && weak("other"), "{log}");
    assert!(
        !weak("vouched") && !weak("wrong") && !weak("refused"),
        "{log}"
    );
    let wrong: Vec<_> = (log.lines())
        .filter(|line| line.contains("SHA256_FILE_MISMATCH"))
        .collect();
    assert!(
        wrong.len() == 1 && wrong[0].contains("wrong-1.pom") && wrong[0].contains(".sha1 file"),
        "{log}"
    );
}

/// Every read of a POM taken on its `.sha1` shares its `.sha256` check:
/// another late client that reads the held bytes fails to settle too, and a
/// client that waits for checksum files fails its read. A failed check
/// waits for the others, which still log their warnings and cache their
/// POMs.
#[test]
fn every_read_of_a_late_pom_shares_its_check() {
    const HELD: std::time::Duration = std::time::Duration::from_secs(1);
    let pom = |artifact: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t.x</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version></project>"
        )
    };
    let sha1 = |body: &str| rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, body.as_bytes());
    let slow_asked = std::sync::Arc::new(std::sync::Mutex::new(None));
    let asked = slow_asked.clone();
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = path.rsplit_once(".pom").unwrap_or((path, ""));
        let artifact = file.rsplit('/').next().unwrap_or("").trim_end_matches("-1");
        let body = pom(artifact);
        match (artifact, sidecar) {
            (_, "") => Response::new(200, body),
            ("first", ".sha256") => Response::new(404, ""),
            (_, ".sha1") => Response::new(200, sha1(&body).hex().to_string()),
            ("refused", ".sha256") => Response::new(407, "").delayed(HELD),
            ("slow", ".sha256") => {
                *asked.lock().unwrap() = Some(std::time::Instant::now());
                Response::new(404, "").delayed(HELD * 3)
            }
            (_, ".sha256") => Response::new(404, "").delayed(HELD),
            _ => Response::new(404, ""),
        }
    });
    let repo = http_repo(&server);
    let (plain, _tmp) = test_client();
    let (late, other) = (
        plain.clone().checking_sha256_late(),
        plain.clone().checking_sha256_late(),
    );
    let read = |client: &RepoClient, artifact: &'static str| {
        let (client, repo) = (client.clone(), repo.clone());
        async move {
            let started = std::time::Instant::now();
            let request = ArtifactRequest::new(format!("t.{artifact}"), artifact, "1");
            let fetched = client.fetch_pom(&repo, &request).await;
            (fetched, started.elapsed())
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            read(&late, "first").await.0.unwrap();
            for artifact in ["refused", "slow"] {
                let (fetched, waited) = read(&late, artifact).await;
                assert_eq!(fetched.unwrap(), pom(artifact).as_bytes());
                assert!(waited < HELD, "{artifact} waited {waited:?}");
            }
            let (held, waited) = read(&other, "refused").await;
            assert_eq!(held.unwrap(), pom("refused").as_bytes());
            assert!(waited < HELD, "the held POM waited {waited:?}");
            let (waiting, _) = read(&plain, "refused").await;
            assert!(
                matches!(waiting, Err(RepoError::Unauthorized { .. })),
                "a client that waits took a refused POM: {waiting:?}"
            );
            let failed = other.settle_checksums().await;
            assert!(
                matches!(failed, Err(RepoError::Unauthorized { .. })),
                "{failed:?}"
            );
            let failed = late.settle_checksums().await;
            assert!(
                matches!(failed, Err(RepoError::Unauthorized { .. })),
                "{failed:?}"
            );
            assert!(late.late_check_failed());
            // Measured from the slow check's request, not from the settle, so
            // a loaded host that delays the steps above cannot fail it.
            let asked = slow_asked
                .lock()
                .unwrap()
                .expect("the slow check was asked");
            assert!(
                asked.elapsed() >= HELD * 3,
                "a failed check did not wait for the slow one"
            );
            let (cached, waited) = read(&plain, "slow").await;
            assert_eq!(cached.unwrap(), pom("slow").as_bytes());
            assert!(waited < HELD, "slow was not cached once checked");
            let (refused, _) = read(&plain, "refused").await;
            assert!(
                matches!(refused, Err(RepoError::Unauthorized { .. })),
                "a refused POM was kept: {refused:?}"
            );
        });
    });
    let weak = |artifact: &str| {
        (log.lines())
            .filter(|line| line.contains("falling back to SHA-1"))
            .any(|line| line.contains(&format!("{artifact}-1.pom")))
    };
    assert!(weak("slow") && !weak("refused"), "{log}");
}

/// The POM [`late_server`] serves for `{artifact}`.
fn late_pom(artifact: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>t.x</groupId>\
         <artifactId>{artifact}</artifactId><version>1</version></project>"
    )
}

/// A repository of [`late_pom`]s with their `.sha1` and no `.sha256`;
/// `answer` answers first, by artifact and sidecar suffix (empty for the
/// POM itself).
fn late_server(
    answer: impl Fn(&str, &str) -> Option<Response> + Send + Sync + 'static,
) -> StubServer {
    StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = path.rsplit_once(".pom").unwrap_or((path, ""));
        let artifact = file.rsplit('/').next().unwrap_or("").trim_end_matches("-1");
        let body = late_pom(artifact);
        if let Some(response) = answer(artifact, sidecar) {
            return response;
        }
        match (artifact, sidecar) {
            (_, "") => Response::new(200, body),
            (_, ".sha1") => {
                let sha1 = rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, body.as_bytes());
                Response::new(200, sha1.hex().to_string())
            }
            _ => Response::new(404, ""),
        }
    })
}

/// A client that checks `.sha256` answers late, once `first` has shown
/// that `server` lacks one, on a runtime of its own.
fn late_client(
    server: &StubServer,
) -> (
    RepoClient,
    Repository,
    tempfile::TempDir,
    tokio::runtime::Runtime,
) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (plain, tmp) = test_client();
    let late = plain.checking_sha256_late();
    let repo = http_repo(server);
    runtime.block_on(async {
        let first = ArtifactRequest::new("t.first", "first", "1");
        late.fetch_pom(&repo, &first).await.unwrap();
        late.settle_checksums().await.unwrap();
    });
    (late, repo, tmp, runtime)
}

fn late_request(artifact: &str) -> ArtifactRequest {
    ArtifactRequest::new(format!("t.{artifact}"), artifact, "1")
}

/// Each read of a failed late check gets an error of the class the check
/// failed with, a TLS failure included, and a copy where one can be made.
#[tokio::test]
async fn every_read_of_a_failed_late_check_keeps_its_class() {
    let client = rv_http::client_builder().build().expect("client");
    let (address, server) = rv_test_support::tls::reject_one_handshake(BAD_CERTIFICATE);
    let tls = client
        .get(format!("https://{address}/"))
        .send()
        .await
        .expect_err("rejected");
    server.join().expect("server");
    let mismatch = RepoError::ChecksumMismatch {
        subject: "t/a/1/a-1.pom".into(),
        artifact: None,
        expected: rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha256, b"a"),
        actual: rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha256, b"b"),
        check: IntegritySource::Sidecar,
    };
    let retried = RepoError::Retried {
        attempts: 3,
        error: Box::new(RepoError::Transfer(
            std::io::ErrorKind::UnexpectedEof.into(),
        )),
    };
    for failure in [RepoError::Http(tls), retried, mismatch] {
        let (class, shown) = (failure.class(), failure.to_string());
        let shared = Arc::new(failure);
        for read in [
            requests::unshared(shared.clone()),
            requests::unshared(shared.clone()),
        ] {
            assert_eq!(read.class(), class, "{read:?}");
            assert_eq!(read.to_string(), shown);
        }
    }
    let copied = requests::unshared(Arc::new(RepoError::AuthSetup("no key".to_string())));
    assert!(matches!(copied, RepoError::AuthSetup(_)), "{copied:?}");
}

/// A `.sha1` sent beside a `.sha256` that answers is one no read needed,
/// and a busy answer to it changes no later read: `target`'s `.sha1` is
/// sent early only once `held` has shown a `.sha256` missing, so whether it
/// is asked for depends on the order of the reads and on a prefetch of
/// `target`, and the outcome must not.
#[test]
fn a_busy_answer_to_a_sidecar_no_read_needed_refuses_no_later_read() {
    let server = late_server(|artifact, sidecar| match (artifact, sidecar) {
        ("target", ".sha256") => Some(
            Response::new(200, sha256_hex(late_pom("target")))
                .delayed(std::time::Duration::from_millis(300)),
        ),
        ("target", ".sha1") => Some(Response::new(429, "").header("Retry-After", "600")),
        _ => None,
    });
    let mut outcomes = Vec::new();
    for late in [true, false] {
        for prefetch in [false, true] {
            for order in [["held", "target"], ["target", "held"]] {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let (client, _tmp) = test_client();
                let client = if late {
                    client.checking_sha256_late()
                } else {
                    client
                };
                let repo = http_repo(&server);
                let outcome = runtime.block_on(async {
                    if prefetch {
                        client
                            .prefetch_pom(&repo, &late_request("target"))
                            .await
                            .unwrap();
                    }
                    let mut reads = Vec::new();
                    for artifact in order.into_iter().chain(["after"]) {
                        let read = client.fetch_pom(&repo, &late_request(artifact)).await;
                        reads.push(format!("{artifact} {:?}", read.map(|_| ())));
                    }
                    reads.sort();
                    format!("{reads:?} {:?}", client.settle_checksums().await)
                });
                outcomes.push((late, prefetch, order, outcome));
            }
        }
    }
    let expected = r#"["after Ok(())", "held Ok(())", "target Ok(())"] Ok(())"#;
    for (late, prefetch, order, outcome) in outcomes {
        assert_eq!(
            outcome, expected,
            "late {late}, prefetch {prefetch}, {order:?}"
        );
    }
}

/// A busy answer after a redirect is kept for the run as one without, so a
/// later read of the file does not wait out the retries again.
#[test]
fn a_busy_answer_after_a_redirect_is_kept_for_the_run() {
    use reqwest::StatusCode;
    let path = "g/a/1/a-1.jar";
    let busy = |redirected_to: Option<&str>| RepoError::Retried {
        attempts: 3,
        error: Box::new(RepoError::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            url: format!("https://repo.example/{path}"),
            redirected_to: redirected_to.map(str::to_string),
            retry_after: None,
        }),
    };
    for redirected_to in [None, Some("https://cdn.example")] {
        let miss = super::models::Miss::of(&busy(redirected_to), path);
        assert!(
            matches!(miss, Some(super::models::Miss::Busy { .. })),
            "{redirected_to:?}"
        );
    }
}

/// A needed `.sha1` takes the early one's refusal while it is in force, for
/// every request, and once it is over is asked for again: one asked for then
/// would meet the server's refusal afresh, so a `.md5` asked for after it
/// does not decide the read only because the `.sha1` went out early.
#[tokio::test(start_paused = true)]
async fn a_needed_sidecar_whose_early_refusal_is_over_is_asked_again() {
    use crate::fetch::OptionalAnswer;
    use reqwest::StatusCode;
    use std::time::Duration;

    let url = Url::parse("https://repo.example/g/a/1/a-1.pom.sha1").unwrap();
    let refused = || {
        let refusal = OptionalAnswer::Refused {
            status: StatusCode::TOO_MANY_REQUESTS,
            retry_after: Duration::from_secs(301),
            answered: tokio::time::Instant::now(),
        };
        let error = RepoError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            url: url.to_string(),
            redirected_to: None,
            retry_after: Some(Duration::from_secs(301)),
        };
        (Err(error), refusal)
    };
    let fetch = FetchConfig::default();
    let in_force = requests::needed_sha1(Some(refused()), &fetch, Some(&url));
    assert!(
        matches!(in_force, Some(Err(RepoError::HttpStatus { .. }))),
        "{in_force:?}"
    );
    assert!(fetch.cooldowns.of(&url).refusal().is_some());
    let other = url.join("b-1.pom").unwrap();
    let held = fetch
        .refusers
        .refused(&other, StatusCode::SERVICE_UNAVAILABLE, Duration::ZERO);
    assert!(
        matches!(&held, RepoError::HttpStatus { status, url: named, .. }
            if status.as_u16() == 429 && *named == url.to_string()),
        "{held:?}"
    );

    let fetch = FetchConfig::default();
    let early = refused();
    tokio::time::advance(Duration::from_secs(301)).await;
    let over = requests::needed_sha1(Some(early), &fetch, Some(&url));
    assert!(over.is_none(), "{over:?}");
    assert!(fetch.cooldowns.of(&url).refusal().is_none());

    let unsent = (Ok(String::new()), OptionalAnswer::Unsent);
    assert!(requests::needed_sha1(Some(unsent), &fetch, None).is_none());
}

/// Whether a refusal on an unneeded `.sha1` keeps the next `.sha1` from
/// going out early changes nothing either: a refusal on `next`'s `.sha256`,
/// which Maven never reads, holds back only other optional requests, so
/// `next` is read on its `.sha1`, whether that went out beside the
/// `.sha256` or after it.
#[test]
fn an_unneeded_refusal_fails_no_later_pair() {
    let server = late_server(|artifact, sidecar| match (artifact, sidecar) {
        ("unused", ".sha256") => Some(
            Response::new(200, sha256_hex(late_pom("unused")))
                .delayed(std::time::Duration::from_millis(300)),
        ),
        ("unused", ".sha1") | ("next", ".sha256") => {
            Some(Response::new(429, "").header("Retry-After", "600"))
        }
        _ => None,
    });
    for late in [true, false] {
        for order in [["seed", "unused"], ["unused", "seed"]] {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let (client, _tmp) = test_client();
            let client = if late {
                client.checking_sha256_late()
            } else {
                client
            };
            let repo = http_repo(&server);
            let failures = runtime.block_on(async {
                let mut failures = Vec::new();
                for artifact in order.into_iter().chain(["next"]) {
                    if let Err(err) = client.fetch_pom(&repo, &late_request(artifact)).await {
                        failures.push(format!("{artifact}: {err:?}"));
                    }
                }
                if let Err(err) = client.settle_checksums().await {
                    failures.push(format!("settled: {err:?}"));
                }
                failures
            });
            assert!(failures.is_empty(), "late {late}, {order:?}: {failures:?}");
        }
    }
}

/// A read fails with the same message whether it met the refusing answer
/// itself or a prefetch of its POM met it first and the read was refused
/// unsent: the error names the answer, not the request kept unsent.
#[test]
fn a_read_a_refusal_kept_unsent_names_the_refusing_answer() {
    let server = late_server(|artifact, sidecar| match (artifact, sidecar) {
        ("busy", ".sha1") => Some(Response::new(429, "").header("Retry-After", "600")),
        ("busy", ".sha256") => Some(Response::new(404, "")),
        _ => None,
    });
    for late in [true, false] {
        for prefetch in [true, false] {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let (client, _tmp) = test_client();
            let client = if late {
                client.checking_sha256_late()
            } else {
                client
            };
            let repo = http_repo(&server);
            let read = runtime.block_on(async {
                if prefetch {
                    let prefetched = client.prefetch_pom(&repo, &late_request("busy")).await;
                    assert!(prefetched.is_err(), "{prefetched:?}");
                }
                client.fetch_pom(&repo, &late_request("busy")).await
            });
            assert!(
                matches!(&read, Err(RepoError::HttpStatus { status, url, .. })
                    if status.as_u16() == 429 && url.ends_with("/busy-1.pom.sha1")),
                "late {late}, prefetch {prefetch}: {:?}",
                read.map(|_| ())
            );
        }
    }
}

/// A `.sha1` that a missing `.sha256` makes needed fails the read when it
/// answers with a `Retry-After` longer than raeva waits, and refuses every
/// later request to the server, whether it was sent beside the `.sha256`
/// or after it.
#[test]
fn a_needed_sidecar_that_is_refused_refuses_the_server() {
    let server = late_server(|artifact, sidecar| {
        (artifact == "busy" && sidecar == ".sha1")
            .then(|| Response::new(429, "").header("Retry-After", "600"))
    });
    for late in [true, false] {
        for early in [true, false] {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let (client, _tmp) = test_client();
            let client = if late {
                client.checking_sha256_late()
            } else {
                client
            };
            let repo = http_repo(&server);
            let before = server.requests().len();
            let (read, after) = runtime.block_on(async {
                if early {
                    client
                        .fetch_pom(&repo, &late_request("first"))
                        .await
                        .unwrap();
                    client.settle_checksums().await.unwrap();
                }
                let read = client.fetch_pom(&repo, &late_request("busy")).await;
                let after = client.fetch_pom(&repo, &late_request("after")).await;
                (read.map(|_| ()), after.map(|_| ()))
            });
            let case = format!("late {late}, early {early}");
            let refused = |read: &Result<()>, artifact: &str| {
                matches!(read, Err(RepoError::HttpStatus { status, url, .. })
                    if status.as_u16() == 429 && url.contains(artifact))
            };
            assert!(refused(&read, "busy-1.pom.sha1"), "{case}: {read:?}");
            assert!(refused(&after, "busy-1.pom.sha1"), "{case}: {after:?}");
            let paths: Vec<_> = server.requests()[before..]
                .iter()
                .map(|r| r.path.clone())
                .collect();
            assert!(
                !paths.iter().any(|path| path.contains("after")),
                "{case}: {paths:?}"
            );
        }
    }
}

/// An early `.sha1` that an optional request's refusal kept from its retry
/// is sent again once the `.sha256` proves missing: `slow`'s `.sha1` is
/// busy once, late, and `other`'s, sent beside a `.sha256` that answers,
/// refuses the optional requests before the retry.
#[test]
fn a_needed_sidecar_an_optional_refusal_kept_unsent_goes_out() {
    let slow_sha1 = Arc::new(AtomicU32::new(0));
    let asked = Arc::clone(&slow_sha1);
    let server = late_server(move |artifact, sidecar| match (artifact, sidecar) {
        ("slow", ".sha1") if asked.fetch_add(1, Ordering::SeqCst) == 0 => Some(
            Response::new(503, "")
                .header("Retry-After", "0")
                .delayed(std::time::Duration::from_millis(400)),
        ),
        ("other", ".sha256") => Some(
            Response::new(200, sha256_hex(late_pom("other")))
                .delayed(std::time::Duration::from_millis(200)),
        ),
        ("other", ".sha1") => Some(Response::new(429, "").header("Retry-After", "600")),
        _ => None,
    });
    let (late, repo, _tmp, runtime) = late_client(&server);
    let (slow, other) = runtime.block_on(async {
        let (slow, other) = (late_request("slow"), late_request("other"));
        let (slow, other) = (late.fetch_pom(&repo, &slow), late.fetch_pom(&repo, &other));
        let (slow, other) = tokio::join!(slow, other);
        (slow.map(|_| ()), other.map(|_| ()))
    });
    assert!(
        matches!((&slow, &other), (Ok(()), Ok(()))),
        "{slow:?} {other:?}"
    );
    assert_eq!(slow_sha1.load(Ordering::SeqCst), 2);
}

/// Once a `.sha256` has been missing, the `.sha1` is sent beside the next
/// one, and a `Retry-After` longer than raeva waits on either fails no
/// read, whichever answers first: on the `.sha1`, which no read needs once
/// the `.sha256` matches, and on the `.sha256`, which Maven never reads, as
/// when it answers late. Each read is a client's first after `first`,
/// which shows the `.sha256` missing, and checks the `.sha256` late or not.
#[test]
fn a_busy_answer_to_a_sidecar_of_a_pair_fails_no_read_whichever_comes_first() {
    fn refused() -> Response {
        Response::new(429, "").header("Retry-After", "600")
    }
    let cases: [fn(&str, &str) -> Option<Response>; 3] = [
        |artifact, sidecar| match (artifact, sidecar) {
            ("busy", ".sha1") => Some(refused()),
            ("busy", ".sha256") => Some(Response::new(200, sha256_hex(late_pom("busy")))),
            _ => None,
        },
        |artifact, sidecar| (artifact == "busy" && sidecar == ".sha256").then(refused),
        |artifact, sidecar| {
            (artifact == "busy" && sidecar == ".sha256")
                .then(|| refused().delayed(std::time::Duration::from_millis(300)))
        },
    ];
    for (case, answer) in cases.into_iter().enumerate() {
        let server = late_server(answer);
        for late in [true, false].repeat(16) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let (client, _tmp) = test_client();
            let client = if late {
                client.checking_sha256_late()
            } else {
                client
            };
            let repo = http_repo(&server);
            let read = runtime.block_on(async {
                client
                    .fetch_pom(&repo, &late_request("first"))
                    .await
                    .unwrap();
                client.settle_checksums().await.unwrap();
                let read = client.fetch_pom(&repo, &late_request("busy")).await;
                (read.map(|_| ()), client.settle_checksums().await)
            });
            let failed = match &read {
                (Ok(()), Ok(())) => None,
                (Err(err), Ok(())) | (Ok(()), Err(err)) => Some(format!("{err:?}")),
                (Err(_), Err(_)) => panic!("case {case} late {late}: {read:?}"),
            };
            assert!(failed.is_none(), "case {case} late {late}: {read:?}");
        }
    }
}

/// A POM a prefetch took on its `.sha1` that no read went on to use has
/// its `.sha256` answered before [`RepoClient::settle_checksums`] returns,
/// so a settled resolution leaves no request running.
#[test]
fn settling_waits_for_the_check_of_a_pom_only_prefetched() {
    const HELD: std::time::Duration = std::time::Duration::from_secs(1);
    let server = late_server(|artifact, sidecar| {
        (artifact == "spec" && sidecar == ".sha256").then(|| Response::new(404, "").delayed(HELD))
    });
    let (late, repo, _tmp, runtime) = late_client(&server);
    runtime.block_on(async {
        let started = std::time::Instant::now();
        let prefetched = late.prefetch_pom(&repo, &late_request("spec")).await;
        assert!(prefetched.unwrap().is_some());
        assert!(
            started.elapsed() < HELD,
            "the prefetch waited for the .sha256"
        );
        late.settle_checksums().await.unwrap();
        assert!(
            started.elapsed() > HELD / 2,
            "settled before the .sha256 answered"
        );
        assert_eq!(server.answered(), server.requests().len());
    });
}

/// A settlement that is cancelled keeps the checks it had not finished, so
/// the next one still fails on a `.sha256` the repository refuses.
#[test]
fn a_cancelled_settlement_keeps_its_checks() {
    const HELD: std::time::Duration = std::time::Duration::from_secs(1);
    let server = late_server(|artifact, sidecar| {
        (artifact == "refused" && sidecar == ".sha256")
            .then(|| Response::new(407, "").delayed(HELD))
    });
    let (late, repo, _tmp, runtime) = late_client(&server);
    runtime.block_on(async {
        late.fetch_pom(&repo, &late_request("refused"))
            .await
            .unwrap();
        let cancelled = tokio::time::timeout(HELD / 4, late.settle_checksums()).await;
        assert!(cancelled.is_err(), "settled before the .sha256 answered");
        let settled = late.settle_checksums().await;
        assert!(
            matches!(settled, Err(RepoError::Unauthorized { .. })),
            "{settled:?}"
        );
        assert!(late.late_check_failed());
    });
}

/// A check that another client relies on outlives the client that started
/// it: dropping that one unsettled leaves the other the check's own answer.
#[test]
fn a_check_another_client_relies_on_outlives_the_client_that_started_it() {
    const HELD: std::time::Duration = std::time::Duration::from_millis(500);
    let server = late_server(|artifact, sidecar| {
        (artifact == "refused" && sidecar == ".sha256")
            .then(|| Response::new(407, "").delayed(HELD))
    });
    let (late, repo, _tmp, runtime) = late_client(&server);
    let other = late.clone().checking_sha256_late();
    runtime.block_on(async {
        late.fetch_pom(&repo, &late_request("refused"))
            .await
            .unwrap();
        other
            .fetch_pom(&repo, &late_request("refused"))
            .await
            .unwrap();
        drop(late);
        let settled = other.settle_checksums().await;
        assert!(
            matches!(settled, Err(RepoError::Unauthorized { .. })),
            "{settled:?}"
        );
    });
}

/// A client made while a `.sha256` another one left running waits to be
/// retried after a busy answer hears of that wait, as it may rely on the
/// check.
#[test]
fn a_client_made_during_a_retry_wait_hears_of_it() {
    let server = late_server(|artifact, sidecar| {
        (artifact == "busy" && sidecar == ".sha256").then(|| Response::new(503, ""))
    });
    let (late, repo, _tmp, runtime) = late_client(&server);
    let quiet = Arc::new(std::sync::Mutex::new(std::time::Duration::ZERO));
    runtime.block_on(async {
        late.fetch_pom(&repo, &late_request("busy")).await.unwrap();
        while server.answered() < server.requests().len()
            || !(server.requests().iter())
                .any(|request| request.path.ends_with("busy-1.pom.sha256"))
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let other = late.clone().checking_sha256_late();
        let heard = Arc::clone(&quiet);
        other.report_late_checks(move |quiet| *heard.lock().unwrap() = quiet);
    });
    let heard = *quiet.lock().unwrap();
    assert!(heard > std::time::Duration::from_secs(1), "{heard:?}");
}

/// A `.sha256` asked for late that fails as a read waiting for it would,
/// here a proxy that refuses it, fails the settlement with the same kind of
/// error as that read, while another client still shares the check.
#[test]
fn a_late_sha256_fails_the_settlement_as_its_read_would() {
    const HELD: std::time::Duration = std::time::Duration::from_millis(500);
    let server = late_server(|artifact, sidecar| {
        (artifact == "refused" && sidecar == ".sha256")
            .then(|| Response::new(407, "").delayed(HELD))
    });
    let (late, repo, _tmp, runtime) = late_client(&server);
    let other = late.clone().checking_sha256_late();
    runtime.block_on(async {
        late.fetch_pom(&repo, &late_request("refused"))
            .await
            .unwrap();
        other
            .fetch_pom(&repo, &late_request("refused"))
            .await
            .unwrap();
        let settled = late.settle_checksums().await.unwrap_err();
        let (plain, _plain_tmp) = test_client();
        let read = plain
            .fetch_pom(&repo, &late_request("refused"))
            .await
            .unwrap_err();
        assert!(
            !matches!(settled, RepoError::Internal(_)),
            "{settled:?}, a read gives {read:?}"
        );
        assert_eq!(settled.to_string(), read.to_string());
    });
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

/// Maven Central's two names under one id share their files, as Maven's
/// local repository tracks them by the id that served them: a POM and a jar
/// fetched for `central` at repo1 are not asked for again for `central` at
/// repo.maven.apache.org, nor prefetched. Under another mirror id, at the
/// same URL, they are.
#[tokio::test]
async fn centrals_two_names_under_one_id_fetch_a_file_once() {
    let (_, server) = body_stub(b"<project/>");
    let url = format!("http://{}/", server.addr());
    let mirrors = vec![
        mirror("stub", &url, "central"),
        mirror("other", &url, "other"),
    ];
    let (client, _tmp) = mirrored_client(mirrors);
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&dir);
    let central = |id: &str, url: &str| Repository::new(Some(id.into()), url, true, false);
    let req = ArtifactRequest::new("com.example", "lib", "1.0.0");
    let asked = |file: &str| {
        let requests = server.requests();
        requests
            .iter()
            .filter(|request| request.path.ends_with(file))
            .count()
    };
    for (repo, asked_for) in [
        (central("central", "https://repo1.maven.org/maven2/"), 1),
        (
            central("central", "https://repo.maven.apache.org/maven2/"),
            1,
        ),
        (central("other", "https://repo.maven.apache.org/maven2/"), 2),
    ] {
        client.fetch_pom(&repo, &req).await.unwrap();
        client.prefetch_artifact(&repo, &req, &store, ()).await;
        let fetched = client.fetch_artifact(&repo, &req, &store, FetchArtifact::default());
        fetched.await.unwrap();
        for file in ["lib-1.0.0.pom", "lib-1.0.0.jar"] {
            assert_eq!(asked(file), asked_for, "{} {file}", repo.url);
        }
    }
}

/// A pinned POM fetched as a file is taken from the POM cache a model read
/// filled for the same repository, or for Central's other name under one
/// id, not asked for again. Under another mirror id it is.
#[tokio::test]
async fn a_pinned_pom_fetched_as_a_file_reads_the_pom_cache() {
    let body = b"<project/>";
    let central = |id: &str, url: &str| Repository::new(Some(id.into()), url, true, false);
    let (repo1, rma) = (
        "https://repo1.maven.org/maven2/",
        "https://repo.maven.apache.org/maven2/",
    );
    let req = ArtifactRequest::new("com.example", "lib", "1.0.0").pom();
    let pin = rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha256, body);
    let options = FetchArtifact {
        pin: Some(&pin),
        index: None,
    };
    for fetched_at in [repo1, rma] {
        let (_, server) = body_stub(body);
        let url = format!("http://{}/", server.addr());
        let mirrors = vec![
            mirror("stub", &url, "central"),
            mirror("other", &url, "other"),
        ];
        let (client, _tmp) = mirrored_client(mirrors);
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        client
            .fetch_pinned_pom_with_path(&central("central", repo1), &req, &pin)
            .await
            .unwrap();
        for (repo, asked_for) in [
            (central("central", fetched_at), 1),
            (central("other", rma), 2),
        ] {
            let fetched = client.fetch_artifact(&repo, &req, &store, options).await;
            assert_eq!(fetched.unwrap().blob, *pin.as_sha256().unwrap());
            let asked = (server.requests().iter())
                .filter(|request| request.path.ends_with("lib-1.0.0.pom"))
                .count();
            assert_eq!(
                asked,
                asked_for,
                "{} {}",
                repo.id.as_deref().unwrap(),
                repo.url
            );
        }
    }
}

/// A busy answer read again from the memo keeps its Retry-After and the
/// attempts the first read made, and nothing is asked again. The answer is
/// recorded as a fetch that outlasted its retries records it, so the test
/// does not wait out a busy retry or race the sidecar a cancelled probe
/// may still send.
#[tokio::test]
async fn a_kept_busy_answer_keeps_its_retries() {
    let server = StubServer::start(|_| Response::new(503, ""));
    let repo = http_repo(&server);
    let (client, _tmp) = test_client();
    let parent = ArtifactRequest::new("com.example", "parent", "1.0.0");
    let path = "com/example/parent/1.0.0/parent-1.0.0.pom";
    let busy = RepoError::Retried {
        attempts: 2,
        error: Box::new(RepoError::HttpStatus {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            url: format!("{}{path}", repo.url),
            redirected_to: None,
            retry_after: Some(Duration::from_secs(1)),
        }),
    };
    let route = client.router.route(&repo);
    let key = client.miss_key(&route, path).expect("a remote path");
    client.record_miss(&route, key, &busy, client.credential_generation(), false);
    let kept = client.fetch_pom(&repo, &parent).await.unwrap_err();
    assert!(server.requests().is_empty());
    assert!(
        matches!(&kept, RepoError::Retried { attempts: 2, error }
            if matches!(**error, RepoError::HttpStatus { retry_after: Some(_), .. })),
        "{kept:?}"
    );
    assert_eq!(kept.to_string(), busy.to_string());
}

/// After a `Retry-After` longer than raeva waits, the other requests to
/// that server fail at once with the same answer, without being sent, and
/// name the request it answered.
#[tokio::test]
async fn a_retry_after_past_the_cap_holds_back_the_other_requests() {
    let server = StubServer::start(|_| Response::new(429, "").header("Retry-After", "600"));
    let repo = http_repo(&server);
    let (mut client, _tmp) = test_client();
    client.fetch.retries = 3;
    let first = ArtifactRequest::new("com.example", "first", "1.0.0");
    let second = ArtifactRequest::new("com.example", "second", "1.0.0");
    client.fetch_pom(&repo, &first).await.unwrap_err();
    let paths: Vec<_> = server.requests().iter().map(|r| r.path.clone()).collect();
    let asked = paths.len();
    // The POM and its sidecar may go out together, but neither is retried.
    assert!(
        paths.iter().all(|path| path.contains("/first-"))
            && paths.iter().collect::<std::collections::HashSet<_>>().len() == asked,
        "{paths:?}"
    );
    let held = client.fetch_pom(&repo, &second).await.unwrap_err();
    // The first POM's sidecar can still land after `fetch_pom` returns, so
    // the log is checked again as a whole: nothing for the second POM, and
    // nothing retried.
    let sent: Vec<_> = server.requests().into_iter().map(|r| r.path).collect();
    assert!(
        sent.iter().all(|path| path.contains("/first-"))
            && sent.iter().collect::<std::collections::HashSet<_>>().len() == sent.len(),
        "{sent:?}"
    );
    assert!(
        matches!(&held, RepoError::HttpStatus { status, url, retry_after: Some(wait), .. }
            if status.as_u16() == 429
                && url.ends_with("/first-1.0.0.pom")
                && *wait > rv_http::retry::MAX_BUSY_WAIT
                && *wait <= Duration::from_secs(600)),
        "{held:?}"
    );
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

/// A checksum file asked for beside an artifact that then fails to download
/// logs nothing, however far its probe got: a weak hash the repository
/// published for a file it does not serve is no warning.
#[test]
fn a_failed_download_logs_nothing_of_its_checksum_probe() {
    let server = StubServer::start(|request| {
        let path = request.path.as_str();
        if path.ends_with(".sha1") {
            Response::new(200, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        } else if path.ends_with(".jar") {
            Response::new(404, "").delayed(Duration::from_millis(300))
        } else {
            Response::new(404, "")
        }
    });
    let repo = http_repo(&server);
    let (client, _tmp) = test_client();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&dir);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut result = None;
    let log = rv_test_support::capture_warnings(|| {
        runtime.block_on(async {
            let jar = ArtifactRequest::new("g", "a", "1");
            result =
                Some((client.fetch_artifact(&repo, &jar, &store, FetchArtifact::default())).await);
        });
    });
    let result = result.unwrap();
    assert!(matches!(result, Err(RepoError::NotFound(_))), "{result:?}");
    assert!(
        server
            .requests()
            .iter()
            .any(|r| r.path.ends_with(".jar.sha1")),
        "the probe ran beside the file"
    );
    assert!(!log.contains("falling back"), "{log}");
}

/// A repository that has answered more file requests with a miss than with
/// the file, as one listed before the repository that serves most files
/// does, is asked for a file before its checksum file, so a miss sends no
/// sidecar request. What it does serve is still checked against its
/// checksum file: a missing or mismatched one still fails.
#[tokio::test]
async fn an_origin_that_mostly_misses_is_asked_for_the_file_first() {
    const POM: &str = "<project><modelVersion>4.0.0</modelVersion></project>";
    let server = StubServer::start(|request| {
        let path = request.path.as_str();
        let (file, sidecar) = match path.rsplit_once('.') {
            Some((file, "sha256" | "sha1" | "md5")) => (file, true),
            _ => (path, false),
        };
        match (file.contains("/served/"), sidecar) {
            (true, false) => Response::new(200, POM),
            (true, true) if file.contains("/served/1/") && path.ends_with(".sha256") => {
                Response::new(200, sha256_hex(POM))
            }
            (true, true)
                if (file.contains("/served/2/") || file.contains("/served/4/"))
                    && path.ends_with(".sha256") =>
            {
                Response::new(200, sha256_hex("other bytes"))
            }
            (true, true) => Response::new(404, ""),
            // A miss answers late, so a sidecar asked for beside it is sent.
            (false, false) => Response::new(404, "").delayed(Duration::from_millis(300)),
            (false, true) => Response::new(404, ""),
        }
    });
    let repo = http_repo(&server);
    let (client, _tmp) = test_client();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&dir);
    for artifact in ["a", "b", "c"] {
        let missing = ArtifactRequest::new("g", artifact, "1");
        let pom = client.fetch_pom(&repo, &missing).await;
        assert!(matches!(pom, Err(RepoError::NotFound(_))), "{pom:?}");
        let jar = client
            .fetch_artifact(&repo, &missing, &store, FetchArtifact::default())
            .await;
        assert!(matches!(jar, Err(RepoError::NotFound(_))), "{jar:?}");
    }
    let sidecars = |artifact: &str| {
        (server.requests().iter())
            .filter(|request| request.path.starts_with(&format!("/g/{artifact}/")))
            .filter(|request| request.path.contains(".pom.") || request.path.contains(".jar."))
            .count()
    };
    // The first miss was asked for with its sidecar, before the origin
    // had answered anything.
    assert!(sidecars("a") > 0, "{:?}", server.requests());
    assert_eq!(sidecars("b") + sidecars("c"), 0, "{:?}", server.requests());

    let served = ArtifactRequest::new("g", "served", "1");
    assert_eq!(
        client.fetch_pom(&repo, &served).await.unwrap().as_ref(),
        POM.as_bytes()
    );
    let fetched = client
        .fetch_artifact(&repo, &served, &store, FetchArtifact::default())
        .await
        .unwrap();
    assert!(fetched.checksum_verified);
    let tampered = ArtifactRequest::new("g", "served", "2");
    let pom = client.fetch_pom(&repo, &tampered).await;
    assert!(
        matches!(pom, Err(RepoError::ChecksumMismatch { .. })),
        "{pom:?}"
    );
    let jar = client
        .fetch_artifact(&repo, &tampered, &store, FetchArtifact::default())
        .await;
    assert!(
        matches!(jar, Err(RepoError::ChecksumMismatch { .. })),
        "{jar:?}"
    );
    // A pin that is not a SHA-256 checks the bytes beside their checksum
    // file, which is still asked for.
    let sha1 = rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, POM.as_bytes());
    let pinned = FetchArtifact {
        pin: Some(&sha1),
        index: None,
    };
    let jar = (client.fetch_artifact(
        &repo,
        &ArtifactRequest::new("g", "served", "4"),
        &store,
        pinned,
    ))
    .await;
    assert!(
        matches!(jar, Err(RepoError::ChecksumMismatch { .. })),
        "{jar:?}"
    );
    let unchecked = ArtifactRequest::new("g", "served", "3");
    let pom = client.fetch_pom(&repo, &unchecked).await;
    assert!(matches!(pom, Err(RepoError::MissingChecksum(_))), "{pom:?}");
    let jar = client
        .fetch_artifact(&repo, &unchecked, &store, FetchArtifact::default())
        .await;
    assert!(matches!(jar, Err(RepoError::MissingChecksum(_))), "{jar:?}");
}

/// Once an origin lacks a `.sha256`, the `.sha1` is asked for together with
/// the `.sha256`, except for a file of a release whose last `.sha256` the
/// origin served: the files of one release are published together. The
/// `.sha256` still decides whenever it is served, and a file of that
/// release without one still falls back to its `.sha1`.
#[tokio::test]
async fn a_release_that_serves_sha256_is_not_asked_for_sha1_beside_it() {
    const BODY: &str = "<project><modelVersion>4.0.0</modelVersion></project>";
    let sha1 = rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, BODY.as_bytes());
    let sha1_hex = sha1.hex().to_string();
    let server = StubServer::start(move |request| {
        let path = request.path.as_str();
        if let Some(file) = path.strip_suffix(".sha256") {
            if file.starts_with("/g/new/") && !file.ends_with("lone-2.jar") {
                // Late, so a `.sha1` asked for beside it is sent.
                return Response::new(200, sha256_hex(BODY)).delayed(Duration::from_millis(300));
            }
            return Response::new(404, "");
        }
        if path.ends_with(".sha1") {
            return Response::new(200, sha1_hex.clone());
        }
        Response::new(200, BODY)
    });
    let repo = http_repo(&server);
    let (client, _tmp) = test_client();
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(&dir);
    client
        .fetch_pom(&repo, &ArtifactRequest::new("g.old", "x", "1"))
        .await
        .unwrap();
    let first = ArtifactRequest::new("g.new", "a", "2");
    client.fetch_pom(&repo, &first).await.unwrap();
    let jar = client
        .fetch_artifact(&repo, &first, &store, FetchArtifact::default())
        .await
        .unwrap();
    assert!(jar.checksum_verified);
    client
        .fetch_pom(&repo, &ArtifactRequest::new("g.new", "b", "2"))
        .await
        .unwrap();
    let lone = client
        .fetch_artifact(
            &repo,
            &ArtifactRequest::new("g.new", "lone", "2"),
            &store,
            FetchArtifact::default(),
        )
        .await
        .unwrap();
    assert!(lone.checksum_verified);
    let asked = |path: &str| {
        (server.requests().iter())
            .filter(|r| r.path == path)
            .count()
    };
    assert_eq!(asked("/g/old/x/1/x-1.pom.sha1"), 1);
    // A release asked about for the first time keeps the origin's hedge.
    assert_eq!(asked("/g/new/a/2/a-2.pom.sha1"), 1);
    assert_eq!(
        asked("/g/new/a/2/a-2.jar.sha1"),
        0,
        "{:?}",
        server.requests()
    );
    assert_eq!(
        asked("/g/new/b/2/b-2.pom.sha1"),
        0,
        "{:?}",
        server.requests()
    );
    assert_eq!(asked("/g/new/lone/2/lone-2.jar.sha1"), 1);
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
        client.prefetch_artifact(&remote, &req, &store, ()).await;
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
        rendered.contains("offline mode")
            && !rendered.contains("s3cret")
            && !rendered.contains("t0k"),
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

/// Maven 3.10 takes snapshot metadata whose timestamp is no path component
/// for invalid, so the repository names no build and the base version
/// stands, with a warning; Maven 3.9 reads the snapshot versions.
#[test]
fn maven_310_ignores_snapshot_metadata_with_an_invalid_token() {
    const METADATA: &[u8] = b"<metadata><version>1.0-SNAPSHOT</version><versioning>\
        <snapshot><timestamp>20240101:010101</timestamp><buildNumber>7</buildNumber></snapshot>\
        <snapshotVersions><snapshotVersion><extension>jar</extension>\
        <value>1.0-20240101.010101-7</value></snapshotVersion></snapshotVersions>\
        </versioning></metadata>";
    use rv_maven_types::MavenMode;
    let mut warnings = Vec::new();
    for (mode, version, candidate) in [
        (
            MavenMode::Maven39,
            "1.0-20240101.010101-7",
            SnapshotCandidate::Specific,
        ),
        (
            MavenMode::Maven310,
            "1.0-SNAPSHOT",
            SnapshotCandidate::Absent,
        ),
    ] {
        let output = capture_warn_output(async {
            let (mut client, _tmp) = test_client();
            client.maven_mode = mode;
            let (repo, _server) = body_stub(METADATA);
            let resolved = client
                .resolve_snapshot_version(&repo, &coord("test:demo:1.0-SNAPSHOT"))
                .await
                .unwrap();
            // The metadata was served, though Maven 3.10 reads it as empty.
            assert_eq!(
                (
                    resolved.version.as_str(),
                    resolved.candidate,
                    resolved.metadata_served
                ),
                (version, candidate, true)
            );
        });
        warnings.push(output.matches("POM_PROBLEM").count());
    }
    assert_eq!(warnings, [0, 1]);
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

/// A `-SNAPSHOT` POM is prefetched through its `maven-metadata.xml`, both
/// held for the read, which then asks nothing and caches both; a parent or
/// BOM chain of snapshots, as spring-cloud-gateway's, was read one hop of
/// two round trips after another. Nothing reaches the metadata cache before
/// that read.
#[tokio::test]
async fn a_snapshot_pom_prefetch_leaves_its_metadata_and_build_to_the_read() {
    const POM: &[u8] = b"<project><version>1.0-SNAPSHOT</version></project>";
    const METADATA: &[u8] = b"<metadata><versioning><snapshotVersions><snapshotVersion>\
        <extension>pom</extension><value>1.0-20240101.010101-7</value>\
        </snapshotVersion></snapshotVersions></versioning></metadata>";
    let sha1 = |bytes: &[u8]| Response::new(200, hex::encode(sha1::Sha1::digest(bytes)));
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/s/1.0-SNAPSHOT/maven-metadata.xml" => Response::new(200, METADATA),
        "/g/s/1.0-SNAPSHOT/maven-metadata.xml.sha1" => sha1(METADATA),
        "/g/s/1.0-SNAPSHOT/s-1.0-20240101.010101-7.pom" => Response::new(200, POM),
        "/g/s/1.0-SNAPSHOT/s-1.0-20240101.010101-7.pom.sha1" => sha1(POM),
        _ => Response::new(404, ""),
    });
    let (client, _cache) = test_client();
    let repo = http_repo(&server);
    let req = ArtifactRequest::new("g", "s", "1.0-SNAPSHOT");
    let prefetched = client.prefetch_pom(&repo, &req).await.unwrap();
    assert_eq!(prefetched.as_deref(), Some(POM));
    let scope = cache_scope_key(&repo.url, &repo);
    let metadata = "g/s/1.0-SNAPSHOT/maven-metadata.xml";
    let pom = "g/s/1.0-SNAPSHOT/s-1.0-20240101.010101-7.pom";
    let listed = RepoClient::metadata_scope(&repo, &scope, &req.version);
    let cached = |table, path| {
        let scope = if matches!(table, CacheTable::Pom) {
            &scope
        } else {
            &listed
        };
        client.cache.get(table, scope, path).unwrap().is_some()
    };
    assert!(!cached(CacheTable::VersionList, metadata) && !cached(CacheTable::Pom, pom));
    let asked = server.requests().len();
    let (bytes, path) = client.fetch_pom_with_path(&repo, &req).await.unwrap();
    assert_eq!((bytes.as_ref(), path.as_str()), (POM, pom));
    assert_eq!(server.requests().len(), asked);
    assert!(cached(CacheTable::VersionList, metadata) && cached(CacheTable::Pom, pom));
}

#[tokio::test]
async fn a_snapshot_artifact_prefetch_downloads_the_build_its_read_takes() {
    const JAR: &[u8] = b"snapshot jar bytes";
    const METADATA: &[u8] = b"<metadata><versioning><snapshotVersions><snapshotVersion>\
        <extension>jar</extension><value>1.0-20240101.010101-7</value>\
        </snapshotVersion></snapshotVersions></versioning></metadata>";
    const BUILD: &str = "g/s/1.0-SNAPSHOT/s-1.0-20240101.010101-7.jar";
    let sha1 = |bytes: &[u8]| Response::new(200, hex::encode(sha1::Sha1::digest(bytes)));
    let server = StubServer::start(move |request| match request.path.as_str() {
        "/g/s/1.0-SNAPSHOT/maven-metadata.xml" => Response::new(200, METADATA),
        "/g/s/1.0-SNAPSHOT/maven-metadata.xml.sha1" => sha1(METADATA),
        "/g/s/1.0-SNAPSHOT/s-1.0-20240101.010101-7.jar" => Response::new(200, JAR),
        "/g/s/1.0-SNAPSHOT/s-1.0-20240101.010101-7.jar.sha1" => sha1(JAR),
        _ => Response::new(404, ""),
    });
    let (client, _cache) = test_client();
    let repo = http_repo(&server);
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let req = ArtifactRequest::new("g", "s", "1.0-SNAPSHOT");
    client.prefetch_artifact(&repo, &req, &store, ()).await;
    let asked = server.requests();
    assert!(asked.iter().any(|request| request.path[1..] == *BUILD));
    let fetched = (client.fetch_artifact(&repo, &req, &store, FetchArtifact::default()))
        .await
        .unwrap();
    assert_eq!(fetched.path, BUILD);
    assert_eq!(server.requests().len(), asked.len());
}

/// A prefetch asks repositories the read may never reach. Whether a
/// checksum file admitted a POM is the read's: here the read takes the
/// first repository's copy, which has none, not the second's, downloaded
/// or cached by an earlier run.
#[tokio::test]
async fn a_pom_is_admitted_as_its_read_found_it() {
    const POM: &[u8] = b"<project/>";
    let bare = StubServer::start(|request| match request.path.as_str() {
        "/g/a/1/a-1.pom" => Response::new(200, POM),
        _ => Response::new(404, ""),
    });
    let checked = StubServer::start(|request| match request.path.as_str() {
        "/g/a/1/a-1.pom" => Response::new(200, POM),
        "/g/a/1/a-1.pom.sha256" => Response::new(200, sha256_hex(POM)),
        _ => Response::new(404, ""),
    });
    let req = ArtifactRequest::new("g", "a", "1");
    for cached in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        // Each run is a new process over the same metadata.db.
        let run = || {
            let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
            let http = rv_http::client_builder().no_proxy().build().unwrap();
            let router = router(Vec::new(), AuthStore::default());
            RepoClient::for_test(ClientSet::unscreened(http), router, cache)
                .with_allow_missing_checksums(true)
        };
        if cached {
            run().fetch_pom(&http_repo(&checked), &req).await.unwrap();
        }
        let client = run();
        client
            .prefetch_pom(&http_repo(&checked), &req)
            .await
            .unwrap();
        client.fetch_pom(&http_repo(&bare), &req).await.unwrap();
        let admitted = client.admissions().get("g/a/1/a-1.pom").copied();
        assert_eq!(admitted, Some(false), "cached: {cached}");
    }
}

/// A file or POM a prefetch fetched before the credential changed is
/// fetched again under the new one, as the read would have: here the
/// checksum file answers only to the credential. A -SNAPSHOT jar counts
/// under the credential its metadata read picked, here before the change
/// that lands while the metadata is on its way; b's metadata names a build
/// only the credential sees.
#[tokio::test]
async fn a_prefetched_file_is_not_taken_under_another_credential() {
    const JAR: &[u8] = b"jar";
    const POM: &[u8] = b"<project><version>1</version></project>";
    let server = StubServer::start(|request| {
        let path = request.path.as_str();
        let authorized = request.header("authorization").is_some();
        let build = if authorized && path.starts_with("/g/b/") {
            2
        } else {
            1
        };
        let metadata = format!(
            "<metadata><versioning><snapshotVersions><snapshotVersion><extension>jar\
             </extension><value>1.0-20240101.010101-{build}</value></snapshotVersion>\
             <snapshotVersion><extension>pom</extension><value>1.0-20240101.010101-{build}\
             </value></snapshotVersion></snapshotVersions></versioning></metadata>"
        );
        let body = match path.split_once(".sha256").map_or(path, |(file, _)| file) {
            file if file.ends_with(".pom") => POM,
            file if file.ends_with(".xml") => metadata.as_bytes(),
            _ => JAR,
        };
        match path {
            _ if path.ends_with("/maven-metadata.xml") => {
                std::thread::sleep(std::time::Duration::from_millis(200));
                Response::new(200, body)
            }
            _ if path.ends_with(".xml.sha256") => Response::new(200, sha256_hex(body)),
            _ if path.ends_with(".sha256") && authorized => Response::new(200, sha256_hex(body)),
            _ if path.ends_with(".sha256") => Response::new(401, ""),
            "/g/a/1/a-1.pom"
            | "/g/a/1/a-1.jar"
            | "/g/a/1.0-SNAPSHOT/a-1.0-20240101.010101-1.jar"
            | "/g/a/1.0-SNAPSHOT/a-1.0-20240101.010101-1.pom"
            | "/g/b/1.0-SNAPSHOT/b-1.0-20240101.010101-2.jar" => Response::new(200, body),
            _ => Response::new(404, ""),
        }
    });
    let url = format!("http://{}/", server.addr());
    let snapshot = "1.0-SNAPSHOT";
    for (artifact, version, pom) in [
        ("a", "1", false),
        ("a", "1", true),
        ("a", snapshot, false),
        ("b", snapshot, false),
        ("a", snapshot, true),
    ] {
        let mut auth = rv_config::AuthConfig::new(Some("corp"));
        auth.token = Some(SecretString::from("dummy-token".to_string()));
        let auth = AuthStore::from_auth_configs(&[auth])
            .expect("auth")
            .with_configured_urls(&[]);
        let (client, _cache) = client_for(router(Vec::new(), auth));
        let client = client.with_allow_missing_checksums(pom);
        let mut fetched = Repository::new(Some("corp".into()), url.clone(), true, true);
        fetched.set_provenance(crate::Provenance::FetchedPom);
        let request = ArtifactRequest::new("g", artifact, version);
        let store_dir = tempfile::tempdir().unwrap();
        let store = store_in(&store_dir);
        let admit = async {
            if version == snapshot {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let declared = Repository::new(Some("corp".into()), url.clone(), true, true);
            (client.policy()).admit([declared], crate::Declaration::LocalPom);
        };
        if pom {
            let (prefetched, ()) = tokio::join!(client.prefetch_pom(&fetched, &request), admit);
            assert!(prefetched.unwrap().is_some());
            assert_eq!(client.fetch_pom(&fetched, &request).await.unwrap(), POM);
            let dir = format!("/g/a/{version}/");
            let sidecar = |r: &rv_test_support::http::Request| {
                r.path.starts_with(&dir) && r.path.ends_with(".pom.sha256")
            };
            let mut asked = server.requests().into_iter().filter(sidecar);
            assert!(
                asked.any(|r| r.header("authorization").is_some()),
                "{version}"
            );
            continue;
        }
        tokio::join!(
            client.prefetch_artifact(&fetched, &request, &store, ()),
            admit
        );
        let jar = client
            .fetch_artifact_to_store(&fetched, &request, &store)
            .await;
        assert_eq!(
            jar.unwrap(),
            rv_maven_types::BlobId::from_bytes(JAR),
            "{artifact}"
        );
    }
}

/// A miss a prefetch met is kept for later runs only once a read uses it,
/// as the read would have kept it had it asked, also when the read joins
/// the prefetch's request.
#[tokio::test]
async fn a_prefetched_miss_is_kept_by_its_read() {
    let server = StubServer::start(|_| {
        std::thread::sleep(std::time::Duration::from_millis(200));
        Response::new(404, "")
    });
    let (repo, req) = (http_repo(&server), ArtifactRequest::new("g", "a", "1"));
    // A checksum probe the miss cancels may or may not reach the server.
    let asked = || {
        (server.requests().iter())
            .filter(|r| r.path.ends_with(".pom"))
            .count()
    };
    for (read, joined) in [(false, false), (true, false), (true, true)] {
        let tmp = tempfile::tempdir().unwrap();
        // Each run is a new process over the same metadata.db.
        let run = || {
            let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
            let http = rv_http::client_builder().no_proxy().build().unwrap();
            let router = router(Vec::new(), AuthStore::default());
            RepoClient::for_test(ClientSet::unscreened(http), router, cache)
        };
        let client = run();
        let before = asked();
        let joining = async {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert!(client.fetch_pom(&repo, &req).await.is_err());
        };
        if joined {
            tokio::join!(client.prefetch_pom(&repo, &req), joining)
                .0
                .unwrap_err();
        } else {
            assert!(client.prefetch_pom(&repo, &req).await.is_err());
            if read {
                joining.await;
            }
        }
        assert_eq!(asked() - before, 1, "the read takes the prefetch's miss");
        let before = asked();
        assert!(run().fetch_pom(&repo, &req).await.is_err());
        assert_eq!(
            asked() == before,
            read,
            "a later run asks again unless the read kept it"
        );
    }
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
                client.prefetch_artifact(&repo, req, &store, ()).await;
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
        client.prefetch_artifact(&repo, &req, &store, ()).await;
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

    // No pause: rows record whole seconds, and those an earlier run wrote
    // in the second this one starts are still fetched again.
    read_all(
        run()
            .with_freshness(Freshness::update_from_now())
            .with_offline(true),
    )
    .await;
    assert_eq!(server.answered(), answered, "offline uses the cache");
    let update = Freshness::update_from_now();
    let updating = run().with_freshness(update);
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
    read_all(run().with_freshness(update)).await;
    read_all(run()).await;
    assert_eq!(
        server.answered(),
        answered,
        "rows this run wrote are reused, by another client of it too"
    );
}

/// A row dated in the future, as a clock that ran ahead leaves it, is
/// fetched again, with `--update` and without, instead of staying fresh
/// until that clock's time.
#[tokio::test]
async fn rows_dated_in_the_future_are_fetched_again() {
    let server = model_stub(Arc::new(AtomicBool::new(true)));
    let (client, tmp) = test_client();
    let repo = http_repo(&server);
    let release = ArtifactRequest::new("test", "demo", "1.0");
    let snapshot = ArtifactRequest::new("test", "demo", "1.0-SNAPSHOT");
    let metadata = coord("test:demo:1.0");
    let db = tmp.path().join("metadata.db");
    let run = || {
        let http = rv_http::client_builder()
            .no_proxy()
            .build()
            .expect("client");
        RepoClient::for_test(
            ClientSet::unscreened(http),
            router(Vec::new(), AuthStore::default()),
            MetadataCache::new(&db).expect("cache"),
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
    for update in [true, false] {
        let conn = rusqlite::Connection::open(&db).expect("metadata.db");
        for table in ["pom_cache_v5", "version_list_cache_v4"] {
            let sql = format!("UPDATE {table} SET fetched_at = unixepoch() + 3600");
            conn.execute(&sql, []).expect("date rows ahead");
        }
        drop(conn);
        let answered = server.answered();
        read_all(run().with_freshness(if update {
            Freshness::update_from_now()
        } else {
            Freshness::Policy
        }))
        .await;
        let requests = server.requests();
        let mut refetched: Vec<&str> = requests[answered..]
            .iter()
            .map(|request| request.path.as_str())
            .filter(|path| !path.ends_with(".sha256"))
            .collect();
        refetched.sort_unstable();
        assert_eq!(
            refetched,
            [
                "/test/demo/1.0-SNAPSHOT/demo-1.0-SNAPSHOT.pom",
                "/test/demo/1.0-SNAPSHOT/maven-metadata.xml",
                "/test/demo/1.0/demo-1.0.pom",
                "/test/demo/maven-metadata.xml",
            ],
            "update: {update}"
        );
    }
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
        read(
            anonymous().with_freshness(Freshness::update_from_now()),
            repo.clone(),
            "a"
        )
        .await,
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

/// The `maven-metadata.xml` of `t:s:1.0-SNAPSHOT` at build `n`.
fn snapshot_metadata(n: usize) -> String {
    format!(
        "<metadata><groupId>t</groupId><artifactId>s</artifactId><version>1.0-SNAPSHOT</version>\
         <versioning><snapshot><timestamp>20260101.12000{n}</timestamp>\
         <buildNumber>{n}</buildNumber></snapshot></versioning></metadata>"
    )
}

/// A process that shares the store can write the metadata it fetched
/// before a deploy over the row this one wrote after it. A run still
/// resolves the SNAPSHOT from the metadata it fetched, plain or under
/// `--update`, and another client of an update fetches the file again
/// rather than take the replacement for this run's.
#[tokio::test]
async fn a_run_resolves_from_the_metadata_it_fetched_when_another_process_replaces_it() {
    let server = StubServer::start(|request| {
        let body = match request.path.trim_end_matches(".sha256") {
            "/t/s/1.0-SNAPSHOT/maven-metadata.xml" => snapshot_metadata(2),
            path if path.ends_with(".pom") => {
                "<project><modelVersion>4.0.0</modelVersion></project>".to_string()
            }
            _ => return Response::new(404, ""),
        };
        if request.path.ends_with(".sha256") {
            Response::new(200, sha256_hex(body))
        } else {
            Response::new(200, body)
        }
    });
    let repo = http_repo(&server);
    let snapshot = coord("t:s:1.0-SNAPSHOT");
    let build_2 = "1.0-20260101.120002-2";
    for update in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let freshness = if update {
            Freshness::update_from_now()
        } else {
            Freshness::Policy
        };
        let run = || {
            let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
            let http = rv_http::client_builder().no_proxy().build().unwrap();
            RepoClient::for_test(
                ClientSet::unscreened(http),
                router(Vec::new(), AuthStore::default()),
                cache,
            )
            .with_freshness(freshness)
        };
        let client = run();
        let request = ArtifactRequest::new("t", "s", "1.0-SNAPSHOT");
        let (_, pom) = client.fetch_pom_with_path(&repo, &request).await.unwrap();
        assert!(pom.ends_with(&format!("s-{build_2}.pom")), "{pom}");
        let older = snapshot_metadata(1);
        let replaced = rusqlite::Connection::open(tmp.path().join("metadata.db"))
            .unwrap()
            .execute(
                "UPDATE version_list_cache_v4 SET content = ?1, sha256 = ?2 WHERE path = ?3",
                rusqlite::params![
                    older.as_bytes(),
                    sha256_hex(&older),
                    "t/s/1.0-SNAPSHOT/maven-metadata.xml"
                ],
            )
            .unwrap();
        assert_eq!(replaced, 1);
        let answered = server.answered();
        let jar = client.resolve_snapshot_version(&repo, &snapshot).await;
        assert_eq!(jar.unwrap().version, build_2, "update: {update}");
        assert_eq!(server.answered(), answered, "update: {update}");
        if update {
            let other = run().resolve_snapshot_version(&repo, &snapshot).await;
            assert_eq!(other.unwrap().version, build_2);
            assert!(server.answered() > answered, "another client fetches again");
        }
    }
}

/// A run reads each metadata file once: a cached row that expires between
/// two reads of a client, while the repository deploys a new build, still
/// gives the second read what the first found, for a SNAPSHOT's metadata
/// and a group's alike. The next run fetches the new build.
#[tokio::test]
async fn a_run_keeps_the_metadata_it_read_when_the_row_expires_meanwhile() {
    let build = Arc::new(AtomicU32::new(1));
    let served = Arc::clone(&build);
    let server = StubServer::start(move |request| {
        let n = served.load(Ordering::SeqCst) as usize;
        let body = match request.path.trim_end_matches(".sha256") {
            "/t/s/1.0-SNAPSHOT/maven-metadata.xml" => snapshot_metadata(n),
            "/t/maven-metadata.xml" => {
                format!(
                    "<metadata><versioning><versions><version>{n}</version></versions></versioning></metadata>"
                )
            }
            _ => return Response::new(404, ""),
        };
        if request.path.ends_with(".sha256") {
            Response::new(200, sha256_hex(body))
        } else {
            Response::new(200, body)
        }
    });
    let repo = http_repo(&server);
    let snapshot = coord("t:s:1.0-SNAPSHOT");
    let tmp = tempfile::tempdir().unwrap();
    let run = || {
        let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
        let http = rv_http::client_builder().no_proxy().build().unwrap();
        RepoClient::for_test(
            ClientSet::unscreened(http),
            router(Vec::new(), AuthStore::default()),
            cache,
        )
    };
    let read = |client: RepoClient| {
        let (repo, snapshot) = (&repo, &snapshot);
        async move {
            let resolved = client.resolve_snapshot_version(repo, snapshot).await;
            let group = client.fetch_group_metadata(repo, "t").await.unwrap();
            (resolved.unwrap().version, group.versions)
        }
    };
    let first = ("1.0-20260101.120001-1".to_string(), vec!["1".to_string()]);
    assert_eq!(read(run()).await, first, "an earlier run caches build 1");
    rusqlite::Connection::open(tmp.path().join("metadata.db"))
        .unwrap()
        .execute(
            "UPDATE version_list_cache_v4 SET expires_at = unixepoch() + 1",
            [],
        )
        .unwrap();
    let client = run();
    let answered = server.answered();
    assert_eq!(read(client.clone()).await, first);
    assert_eq!(server.answered(), answered, "the run reads the cached rows");
    build.store(2, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(read(client).await, first, "the run keeps what it read");
    assert_eq!(server.answered(), answered);
    let next = ("1.0-20260101.120002-2".to_string(), vec!["2".to_string()]);
    assert_eq!(read(run()).await, next, "the next run fetches build 2");
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
    let mut updating = client.with_freshness(Freshness::update_from_now());
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
/// again rather than served from the cache, and the fetched bytes are then
/// held to the pin whichever repository serves them.
#[tokio::test]
async fn a_cached_pom_that_differs_from_the_pin_is_fetched_again() {
    for pin in [
        rv_maven_types::Digest::Sha256(rv_maven_types::Sha256::from_bytes(b"other")),
        rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha1, b"other"),
    ] {
        let server = model_stub(Arc::new(AtomicBool::new(true)));
        let (mut client, _tmp) = test_client();
        let repo = http_repo(&server);
        let req = ArtifactRequest::new("test", "demo", "1.0");
        client.fetch_pom(&repo, &req).await.unwrap();
        let answered = server.answered();
        client.lock_pins = unserved_pins([(req.pom().to_path(), pin.clone())]);
        client.pom_memo = Arc::default();
        let err = client.fetch_pom(&repo, &req).await.unwrap_err();
        assert!(
            matches!(err, RepoError::ChecksumMismatch { .. }),
            "{pin}: {err:?}"
        );
        assert!(
            server.answered() > answered,
            "{pin}: the differing row is not served"
        );
    }
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
    // Bytes that differ from a release file's lock pin are refused before
    // the store keeps them; an update checks them against the sidecar.
    let refused = client.fetch_artifact(&repo, &b, &store, FetchArtifact::default());
    let refused = refused.await;
    assert!(
        matches!(
            refused,
            Err(RepoError::ChecksumMismatch {
                check: IntegritySource::LockPin,
                ..
            })
        ),
        "{refused:?}"
    );
    assert!(
        !store
            .get_path(&rv_maven_types::BlobId::from_bytes(OTHER))
            .exists()
    );
    let updating = client.clone().with_freshness(Freshness::update_from_now());
    let verified = updating.fetch_artifact(&repo, &b, &store, FetchArtifact::default());
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
    for path in ["/g/a/1/a-1.pom", "/g/b/1/b-1.jar.sha256"] {
        assert_eq!(count(path), 1, "{path}");
    }
    assert_eq!(count("/g/b/1/b-1.jar"), 2);
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

/// A checksum probe that ran out of retries on the `.sha1` reports that
/// failure over the `.md5`'s, so the repository search ends there; a failed
/// `.sha256`, which Maven never reads, counts as none. A read with a lock
/// pin, which needs no sidecar, still gets the POM.
#[tokio::test]
async fn a_retried_sidecar_failure_decides_the_probe() {
    for (sha256, sha1, md5) in [(503, 500, 503), (500, 503, 407)] {
        let server = StubServer::start(move |request| match request.path.rsplit('.').next() {
            Some("pom") => Response::new(200, "<project/>"),
            Some("sha256") => Response::new(sha256, ""),
            Some("sha1") => Response::new(sha1, ""),
            Some("md5") => Response::new(md5, ""),
            _ => Response::new(404, ""),
        });
        let repo = http_repo(&server);
        let (mut client, _tmp) = test_client();
        client.fetch.retries = 0;
        let err = client
            .fetch_pom(&repo, &ArtifactRequest::new("g", "a", "1"))
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), Some(503), "{sha256} {sha1} {md5}: {err}");
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
            None,
            &mut super::requests::DeferredWarnings::default(),
            super::models::PomRead::Use,
        )
        .await;
    let Err(refused) = refused else {
        panic!("the repository refused the credential")
    };
    assert_eq!(refused.status_code(), Some(401));
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
        .prefetch_artifact(&repo, &ArtifactRequest::new("g", "b", "1"), &store, ())
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

#[test]
fn release_file_pins_include_timestamped_snapshots() {
    let (mut client, _tmp) = test_client();
    let pin = rv_maven_types::Digest::of_bytes(HashAlgorithm::Sha256, b"pinned");
    for (version, fixed) in [
        ("1", true),
        ("1-20260101.010101-1", true),
        ("1-SNAPSHOT", false),
        ("1SNAPSHOT", false),
        ("SNAPSHOT", false),
    ] {
        for classifier in [None, Some("sources")] {
            let key = ArtifactCoord::new("g", "a", version, "jar", classifier);
            let path = file_path(&key);
            client.lock_pins = unserved_pins([(path.clone(), pin.clone())]);
            assert_eq!(
                client.release_file_pin(&path),
                fixed.then_some(&pin),
                "{path}"
            );
        }
    }
}

#[tokio::test]
async fn stored_fixed_files_must_match_lock_pins_under_update_too() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = store_in(&store_dir);
    let blob = store.put_bytes(b"stored").await.unwrap();
    let repo = Repository::new(None, "https://repo.example/", true, true);
    for (version, fixed) in [
        ("1", true),
        ("1-20260101.010101-1", true),
        ("1-SNAPSHOT", false),
    ] {
        let key = ArtifactCoord::new("g", "a", version, "jar", None);
        let origin = rv_store::Origin {
            repo_url: repo.url.clone(),
            endpoint_url: repo.url.clone(),
            checksum_verified: true,
            served: true,
        };
        store
            .record_origins(vec![(key.clone(), blob.clone(), origin)])
            .await
            .unwrap();
        for update in [false, true] {
            for bytes in [b"stored".as_slice(), b"other"] {
                for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha1] {
                    let (mut client, _tmp) = test_client();
                    let pin = rv_maven_types::Digest::of_bytes(algorithm, bytes);
                    client.lock_pins = unserved_pins([(file_path(&key), pin)]);
                    let client = client.with_freshness(if update {
                        Freshness::update_from_now()
                    } else {
                        Freshness::Policy
                    });
                    let accepted = !fixed || bytes == b"stored";
                    assert_eq!(
                        client.stored_artifact(&store, &repo, &key).await.unwrap(),
                        accepted.then(|| blob.clone()),
                        "{version}, update={update}, {algorithm:?}"
                    );
                    assert_eq!(
                        client.served_artifact(&store, &repo, &key).await.unwrap(),
                        accepted.then(|| (blob.clone(), true)),
                        "{version}, update={update}, {algorithm:?}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn explicit_pom_pins_filter_cached_bytes() {
    const POM: &[u8] = b"<project/>";
    for version in ["1", "1-20260101.010101-1"] {
        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha1] {
            let (client, _tmp) = test_client();
            let repo = Repository::new(None, "https://repo.example/", true, true);
            let request = ArtifactRequest::new("g", "a", version);
            let path = request
                .pom()
                .to_path_with_versions(&super::models::resolved_directory(version), version);
            let scope = client.router.route(&repo).scope;
            client
                .cache
                .insert(
                    CacheTable::Pom,
                    &scope,
                    &path,
                    POM,
                    rv_store::metadata_cache::Expiry::NEVER,
                    true,
                )
                .unwrap();
            let client = client.with_offline(true);
            assert_eq!(
                client.fetch_pom(&repo, &request).await.unwrap().as_ref(),
                POM
            );
            let wrong = rv_maven_types::Digest::of_bytes(algorithm, b"other pom");
            let result = client
                .fetch_pinned_pom_with_path(&repo, &request, &wrong)
                .await;
            assert!(
                matches!(result, Err(RepoError::OfflineNotCached(_))),
                "{result:?}"
            );
            let correct = rv_maven_types::Digest::of_bytes(algorithm, POM);
            assert_eq!(
                client
                    .fetch_pinned_pom_with_path(&repo, &request, &correct)
                    .await
                    .unwrap()
                    .0
                    .as_ref(),
                POM,
            );
        }
    }
}

#[tokio::test]
async fn mismatching_explicit_pom_pins_are_not_cached() {
    const POM: &[u8] = b"<project/>";
    const OTHER: &[u8] = b"<project><!-- changed --></project>";
    for version in ["1", "1-20260101.010101-1"] {
        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha1] {
            let tampered = Arc::new(AtomicBool::new(true));
            let serving = Arc::clone(&tampered);
            let server = StubServer::start(move |request| {
                let body = if serving.load(Ordering::SeqCst) {
                    OTHER
                } else {
                    POM
                };
                if request.path.ends_with(".sha256") {
                    Response::new(200, sha256_hex(body))
                } else {
                    Response::new(200, body)
                }
            });
            let repo = http_repo(&server);
            let (client, _tmp) = test_client();
            assert!(client.lock_pins.is_empty());
            let request = ArtifactRequest::new("g", "a", version);
            let pin = rv_maven_types::Digest::of_bytes(algorithm, POM);
            let result = client
                .fetch_pinned_pom_with_path(&repo, &request, &pin)
                .await;
            assert!(matches!(result, Err(RepoError::ChecksumMismatch {
                check: IntegritySource::LockPin, expected, actual, ..
            }) if expected == pin && actual == rv_maven_types::Digest::of_bytes(algorithm, OTHER)));
            let path = request
                .pom()
                .to_path_with_versions(&super::models::resolved_directory(version), version);
            let scope = client.router.route(&repo).scope;
            assert!(
                client
                    .cache
                    .get(CacheTable::Pom, &scope, &path)
                    .unwrap()
                    .is_none()
            );
            tampered.store(false, Ordering::SeqCst);
            assert_eq!(
                client
                    .fetch_pinned_pom_with_path(&repo, &request, &pin)
                    .await
                    .unwrap()
                    .0
                    .as_ref(),
                POM,
            );
            assert_eq!(
                server
                    .requests()
                    .iter()
                    .filter(|r| r.path == format!("/{path}"))
                    .count(),
                2
            );
        }
    }
}

#[tokio::test]
async fn explicit_pom_pins_check_local_bytes() {
    const POM: &[u8] = b"<project/>";
    const OTHER: &[u8] = b"<project><!-- changed --></project>";
    for version in ["1", "1-20260101.010101-1"] {
        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha1] {
            let repository = tempfile::tempdir().unwrap();
            let repo = file_repo(repository.path());
            let (client, _tmp) = test_client();
            let request = ArtifactRequest::new("g", "a", version);
            let path = request
                .pom()
                .to_path_with_versions(&super::models::resolved_directory(version), version);
            let file = repository.path().join(&path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, OTHER).unwrap();
            std::fs::write(
                repository.path().join(format!("{path}.sha256")),
                sha256_hex(OTHER),
            )
            .unwrap();
            let pin = rv_maven_types::Digest::of_bytes(algorithm, POM);
            let result = client
                .fetch_pinned_pom_with_path(&repo, &request, &pin)
                .await;
            assert!(matches!(result, Err(RepoError::ChecksumMismatch {
                check: IntegritySource::LockPin, expected, actual, ..
            }) if expected == pin && actual == rv_maven_types::Digest::of_bytes(algorithm, OTHER)));
            std::fs::write(&file, POM).unwrap();
            std::fs::write(
                repository.path().join(format!("{path}.sha256")),
                sha256_hex(POM),
            )
            .unwrap();
            assert_eq!(
                client
                    .fetch_pinned_pom_with_path(&repo, &request, &pin)
                    .await
                    .unwrap()
                    .0
                    .as_ref(),
                POM,
            );
        }
    }
}

/// Offline, a version list or group listing an online run found missing is
/// missing, as a POM is, so a search goes on to the next repository rather
/// than fail as not downloaded.
#[tokio::test]
async fn offline_a_kept_metadata_miss_is_not_found() {
    let server = StubServer::start(|_| Response::new(404, ""));
    let repo = http_repo(&server);
    let tmp = tempfile::tempdir().unwrap();
    let run = || {
        let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
        let http = rv_http::client_builder().no_proxy().build().unwrap();
        let router = router(Vec::new(), AuthStore::default());
        RepoClient::for_test(ClientSet::unscreened(http), router, cache)
    };
    let reads = |client: RepoClient| {
        let repo = repo.clone();
        async move {
            [
                client.fetch_metadata(&repo, &coord("g:a:1")).await.err(),
                client.fetch_group_metadata(&repo, "g").await.err(),
            ]
            .map(Option::unwrap)
        }
    };
    for err in reads(run()).await {
        assert!(matches!(err, RepoError::NotFound(_)), "{err:?}");
    }
    let asked = server.requests().len();
    for err in reads(run().with_offline(true)).await {
        assert!(matches!(err, RepoError::NotFound(_)), "{err:?}");
    }
    assert_eq!(server.requests().len(), asked);
    let (client, _tmp) = test_client();
    for err in reads(client.with_offline(true)).await {
        assert!(matches!(err, RepoError::OfflineNotCached(_)), "{err:?}");
    }
}

/// A cached row of a SNAPSHOT version that a read takes is counted, so the
/// SNAPSHOT check knows when it falls due; a release row is not.
#[tokio::test]
async fn a_cached_snapshot_row_a_read_takes_is_counted() {
    use rv_store::metadata_cache::{Expiry, RowsDue};
    let (client, _cache) = test_client();
    let scope = "https://r.example/";
    let now = rv_store::metadata_cache::now_epoch_seconds();
    let rows = [
        ("g/a/1-SNAPSHOT/maven-metadata.xml", Expiry::After(600)),
        ("g/b/1-SNAPSHOT/maven-metadata.xml", Expiry::Daily),
        ("g/c/1/maven-metadata.xml", Expiry::After(60)),
    ];
    for (path, expiry) in rows {
        (client.cache)
            .insert_fetched_at(
                CacheTable::VersionList,
                scope,
                path,
                b"<metadata/>",
                expiry,
                now,
                true,
            )
            .unwrap();
    }
    assert_eq!(*client.snapshot_rows.lock().unwrap(), RowsDue::default());
    for (path, _) in rows {
        let read = client.cache_get_bytes(CacheTable::VersionList, scope, path);
        assert!(read.await.unwrap().is_some(), "{path}");
    }
    let expected = RowsDue {
        expire_at: Some(now + 600),
        daily_from: Some(now),
    };
    assert_eq!(*client.snapshot_rows.lock().unwrap(), expected);
}

/// A refusal is kept across runs only when the credential the route sends
/// went with it, as the run that reads it back reports that credential: not
/// one whose redirect chain left the repository's origin, which withheld
/// the credential, and came back to the URL asked for.
#[test]
fn a_refusal_without_the_routes_credential_is_not_kept() {
    let mut auth = rv_config::AuthConfig::new(Some("corp"));
    auth.token = Some(SecretString::from("dummy-token".to_string()));
    let auth = AuthStore::from_auth_configs(&[auth])
        .expect("auth")
        .with_configured_urls(&[]);
    let (client, _cache) = client_for(router(Vec::new(), auth));
    let repo = Repository::new(
        Some("corp".into()),
        "https://repo.example/".to_string(),
        true,
        true,
    );
    let route = client.router.route(&repo);
    let configured = route.auth().unwrap().expect("credential").sent.clone();
    let path = "g/a/1/a-1.pom";
    let kept = |sent: Option<crate::auth::SentCredential>| {
        let refusal = RepoError::Unauthorized {
            status: reqwest::StatusCode::UNAUTHORIZED,
            url: format!("https://repo.example/{path}"),
            redirected_to: None,
            sent: sent.map(Box::new),
        };
        super::models::Miss::of(&refusal, path).and_then(|miss| miss.kept_status(&route, path))
    };
    assert_eq!(kept(Some(configured)), Some(401));
    assert_eq!(kept(None), None);
}
