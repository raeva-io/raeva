use super::*;
use super::{metadata_path, snapshot_dir_version, snapshot_timestamp_from_version};
use crate::auth::AuthStore;
use crate::cache::MetadataCache;
use crate::mirror::MirrorSelector;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rv_test_support::http::{Response, StubServer};
use secrecy::Secret;
use std::io::{Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn plain_test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .user_agent(USER_AGENT)
        .build()
        .expect("client")
}

/// Build a minimal in-process `RepoClient`, skipping `Config` so tests can
/// isolate fetch/checksum/mirror logic. The returned `TempDir` must outlive
/// the `RepoClient`: dropping it deletes the on-disk SQLite cache that
/// `MetadataCache` holds open.
fn test_client() -> (RepoClient, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
    let client = RepoClient {
        root_redirects: Arc::default(),
        client: plain_test_client(),
        runtime_client: plain_test_client(),
        auth: AuthStore::without_os_credentials(),
        mirrors: MirrorSelector::default(),
        fetch: FetchConfig::default(),
        progress: None,
        cache,
        offline: false,
        require_checksums: true,
        mirror_failures: Arc::new(MirrorFailureTracker::default()),
        pom_inflight: PomInflight::default(),
        absent_snapshots: AbsentSnapshots::default(),
        configured_hosts: ConfiguredHosts::default(),
        trusted_hosts: TrustedHosts::default(),
    };
    (client, tmp)
}

fn test_client_with_mirrors(
    mirrors: Vec<rv_config::MirrorConfig>,
) -> (RepoClient, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
    let client = RepoClient {
        root_redirects: Arc::default(),
        client: plain_test_client(),
        runtime_client: plain_test_client(),
        auth: AuthStore::without_os_credentials(),
        mirrors: MirrorSelector::from_mirrors(mirrors),
        fetch: FetchConfig {
            retries: 0,
            timeout: Duration::from_secs(5),
            ..Default::default()
        },
        progress: None,
        cache,
        offline: false,
        require_checksums: true,
        mirror_failures: Arc::new(MirrorFailureTracker::default()),
        pom_inflight: PomInflight::default(),
        absent_snapshots: AbsentSnapshots::default(),
        configured_hosts: ConfiguredHosts::default(),
        trusted_hosts: TrustedHosts::default(),
    };
    (client, tmp)
}

type StubHandler = Box<dyn Fn(&str) -> Response + Send + Sync>;

fn spawn_stub_seq(responses: Vec<StubHandler>) -> (std::net::SocketAddr, StubServer) {
    let index = AtomicU32::new(0);
    let server = StubServer::start(move |request| {
        responses[index.fetch_add(1, Ordering::SeqCst) as usize](&request.raw)
    });
    (server.addr(), server)
}

async fn verified_body_stub(body: &'static [u8]) -> (Repository, StubServer) {
    use sha2::{Digest, Sha256};

    let responses = (0..16)
        .map(|_| {
            Box::new(move |request: &str| {
                if request.lines().next().unwrap().contains(".sha256") {
                    Response::new(200, hex::encode(Sha256::digest(body)).as_bytes())
                } else {
                    Response::new(200, body)
                }
            }) as StubHandler
        })
        .collect();
    let (addr, hits) = spawn_stub_seq(responses);
    (
        Repository::new(None, format!("http://{addr}/"), true, true),
        hits,
    )
}

fn insert_expired_cache_entry(
    cache_dir: &std::path::Path,
    table: &str,
    scope: &str,
    path: &str,
    content: &[u8],
) {
    let conn = rusqlite::Connection::open(cache_dir.join("metadata.db")).unwrap();
    conn.execute(
        &format!(
            "INSERT OR REPLACE INTO {table} (repo_url, path, content, fetched_at, expires_at)
             VALUES (?1, ?2, ?3, 1, 2)"
        ),
        rusqlite::params![scope, path, content],
    )
    .unwrap();
}

#[tokio::test]
async fn expired_snapshot_metadata_and_timestamped_pom_resolve_offline() {
    const METADATA: &[u8] = b"<metadata><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20261011.010101</timestamp><buildNumber>7</buildNumber></snapshot></versioning></metadata>";
    const POM: &[u8] = b"<project><version>1.0-SNAPSHOT</version></project>";
    let server = StubServer::start(|_| Response::new(500, "unexpected request"));
    for policy in [
        rv_config::UpdatePolicy::Daily,
        rv_config::UpdatePolicy::Always,
    ] {
        let (client, tmp) = test_client();
        let client = client.with_offline(true);
        let mut repo = Repository::new(None, format!("http://{}/", server.addr()), true, true);
        repo.snapshots_update_policy = policy;
        let req = ArtifactRequest::new("test", "demo", "1.0-SNAPSHOT");
        let coord = "test:demo:1.0-SNAPSHOT".parse::<Coord>().unwrap();
        let scope = RepoClient::cache_scope_key(&repo.url, &repo.url);
        insert_expired_cache_entry(
            tmp.path(),
            "version_list_cache",
            &RepoClient::metadata_cache_scope(&repo, &scope, &req.version),
            "test/demo/1.0-SNAPSHOT/maven-metadata.xml",
            METADATA,
        );
        insert_expired_cache_entry(
            tmp.path(),
            "pom_cache",
            &scope,
            "test/demo/1.0-SNAPSHOT/demo-1.0-20261011.010101-7.pom",
            POM,
        );
        assert_eq!(
            client.fetch_metadata(&repo, &coord).await.unwrap(),
            Metadata::from_bytes(METADATA).unwrap()
        );
        assert_eq!(
            client.resolve_snapshot(&repo, &coord).await.unwrap(),
            "1.0-20261011.010101-7"
        );
        assert_eq!(client.fetch_pom(&repo, &req).await.unwrap().as_ref(), POM);
        let conn = rusqlite::Connection::open(tmp.path().join("metadata.db")).unwrap();
        for table in ["pom_cache", "version_list_cache"] {
            let timestamps: (i64, i64) = conn
                .query_row(
                    &format!("SELECT fetched_at, expires_at FROM {table}"),
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                timestamps,
                (1, 2),
                "offline reads must not renew timestamps"
            );
        }
    }
    assert!(server.requests().is_empty());
    assert_eq!(server.connections(), 0);
}

#[tokio::test]
async fn expired_rows_survive_unrelated_online_cache_reads_and_inserts() {
    const POM: &[u8] = b"<project><version>1</version></project>";
    let (client, tmp) = test_client();
    let (repo, server) = verified_body_stub(POM).await;
    for table in ["pom_cache", "version_list_cache"] {
        insert_expired_cache_entry(tmp.path(), table, "other-project", "cached", b"old");
    }
    let req = ArtifactRequest::new("unrelated", "project", "1");
    assert_eq!(client.fetch_pom(&repo, &req).await.unwrap().as_ref(), POM);
    // Each path exceeds the former 100-operation cleanup interval on its own.
    for _ in 0..201 {
        client.fetch_pom(&repo, &req).await.unwrap();
    }
    for _ in 0..201 {
        client
            .cache_insert_bytes_with_ttl(CacheTable::Pom, &repo.url, "another", POM, 3600)
            .await;
    }
    for table in [CacheTable::Pom, CacheTable::VersionList] {
        let entry = client
            .cache
            .get(table, "other-project", "cached")
            .unwrap()
            .unwrap();
        assert_eq!(entry.content, b"old");
        assert_eq!(entry.expires_at, 2);
    }
    assert_eq!(
        server.requests().len(),
        2,
        "only the unrelated POM and its checksum are fetched"
    );
}

#[tokio::test]
async fn online_refetches_expired_release_and_snapshot_poms() {
    const POM: &[u8] = b"<project><!-- republished --></project>";
    for version in ["1.0", "1.0-20261011.010101-7"] {
        let (client, tmp) = test_client();
        let (repo, server) = verified_body_stub(POM).await;
        let req = ArtifactRequest::new("test", "demo", version);
        let path = if req.is_snapshot() {
            req.pom().to_path_with_versions("1.0-SNAPSHOT", version)
        } else {
            req.pom().to_path()
        };
        let scope = RepoClient::cache_scope_key(&repo.url, &repo.url);
        insert_expired_cache_entry(tmp.path(), "pom_cache", &scope, &path, b"old POM");
        assert_eq!(client.fetch_pom(&repo, &req).await.unwrap().as_ref(), POM);
        assert!(
            server
                .requests()
                .iter()
                .any(|request| request.path == format!("/{path}"))
        );
        let entry = client
            .cache
            .get(CacheTable::Pom, &scope, &path)
            .unwrap()
            .unwrap();
        assert_eq!(entry.content, POM);
        assert!(entry.expires_at > 2);
    }
}

#[tokio::test]
async fn online_refetches_expired_version_lists_and_snapshot_metadata() {
    const METADATA: &[u8] = b"<metadata><version>1.0-SNAPSHOT</version><versioning><versions><version>1.0</version></versions><snapshot><timestamp>20261011.010101</timestamp><buildNumber>7</buildNumber></snapshot></versioning></metadata>";
    for (version, snapshot_resolution) in [
        ("1.0", false),
        ("1.0-SNAPSHOT", false),
        ("1.0-SNAPSHOT", true),
    ] {
        let (client, tmp) = test_client();
        let (repo, server) = verified_body_stub(METADATA).await;
        let coord = format!("test:demo:{version}").parse::<Coord>().unwrap();
        let path = metadata_path(
            "test",
            "demo",
            is_snapshot_version(version).then_some(version),
        );
        let scope = RepoClient::metadata_cache_scope(
            &repo,
            &RepoClient::cache_scope_key(&repo.url, &repo.url),
            version,
        );
        insert_expired_cache_entry(
            tmp.path(),
            "version_list_cache",
            &scope,
            &path,
            b"old metadata",
        );
        if snapshot_resolution {
            assert_eq!(
                client.resolve_snapshot(&repo, &coord).await.unwrap(),
                "1.0-20261011.010101-7"
            );
        } else {
            assert_eq!(
                client.fetch_metadata(&repo, &coord).await.unwrap(),
                Metadata::from_bytes(METADATA).unwrap()
            );
        }
        assert!(
            server
                .requests()
                .iter()
                .any(|request| request.path == format!("/{path}"))
        );
        let entry = client
            .cache
            .get(CacheTable::VersionList, &scope, &path)
            .unwrap()
            .unwrap();
        assert_eq!(entry.content, METADATA);
        assert!(entry.expires_at > 2);
    }
}

#[tokio::test]
async fn expired_offline_rows_preserve_origin_mirror_and_policy_isolation() {
    const METADATA: &[u8] =
        b"<metadata><versioning><versions><version>1</version></versions></versioning></metadata>";
    let server = StubServer::start(|_| Response::new(500, "unexpected request"));
    let mirror = format!("http://{}/", server.addr());
    let (client, tmp) = test_client_with_mirrors(vec![rv_config::MirrorConfig {
        id: Some("mirror".into()),
        url: mirror.clone(),
        mirror_of: vec!["*".into()],
    }]);
    let client = client.with_offline(true);
    let origin = Repository::new(None, "https://origin.invalid/", true, false);
    let req = ArtifactRequest::new("test", "demo", "1");
    let coord = "test:demo:1".parse::<Coord>().unwrap();
    let scope = RepoClient::cache_scope_key(&origin.url, &mirror);
    insert_expired_cache_entry(
        tmp.path(),
        "pom_cache",
        &scope,
        &req.pom().to_path(),
        b"cached POM",
    );
    insert_expired_cache_entry(
        tmp.path(),
        "version_list_cache",
        &RepoClient::metadata_cache_scope(&origin, &scope, "1"),
        "test/demo/maven-metadata.xml",
        METADATA,
    );
    assert_eq!(
        client.fetch_pom(&origin, &req).await.unwrap().as_ref(),
        b"cached POM"
    );
    client.fetch_metadata(&origin, &coord).await.unwrap();

    let other = Repository::new(None, "https://other.invalid/", true, false);
    assert!(matches!(
        client.fetch_pom(&other, &req).await,
        Err(RepoError::OfflineNotCached(_))
    ));
    assert!(matches!(
        client.fetch_metadata(&other, &coord).await,
        Err(RepoError::OfflineNotCached(_))
    ));
    let mut strict = origin.clone();
    strict.releases_checksum_policy = rv_config::ChecksumPolicy::Fail;
    assert!(matches!(
        client.fetch_metadata(&strict, &coord).await,
        Err(RepoError::OfflineNotCached(_))
    ));
    let mut always = origin.clone();
    always.releases_update_policy = rv_config::UpdatePolicy::Always;
    assert!(matches!(
        client.fetch_metadata(&always, &coord).await,
        Err(RepoError::OfflineNotCached(_))
    ));
    let mut changed_mirror = client.clone();
    changed_mirror.mirrors = MirrorSelector::from_mirrors(vec![rv_config::MirrorConfig {
        id: Some("mirror".into()),
        url: format!("{mirror}other/"),
        mirror_of: vec!["*".into()],
    }]);
    assert!(matches!(
        changed_mirror.fetch_pom(&origin, &req).await,
        Err(RepoError::OfflineNotCached(_))
    ));
    assert!(matches!(
        changed_mirror.fetch_metadata(&origin, &coord).await,
        Err(RepoError::OfflineNotCached(_))
    ));
    let missing = ArtifactRequest::new("test", "missing", "1");
    assert!(matches!(
        client.fetch_pom(&origin, &missing).await,
        Err(RepoError::OfflineNotCached(_))
    ));
    let missing = "test:missing:1".parse::<Coord>().unwrap();
    assert!(matches!(
        client.fetch_metadata(&origin, &missing).await,
        Err(RepoError::OfflineNotCached(_))
    ));
    assert!(server.requests().is_empty());
    assert_eq!(server.connections(), 0);
}

// Triggers reject actual SQLite writes without depending on filesystem
// permissions (which root can bypass) or making each test wait five seconds.
fn reject_cache_inserts(path: &std::path::Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_pom BEFORE INSERT ON pom_cache
         BEGIN SELECT RAISE(ABORT, 'injected cache write failure'); END;
         CREATE TRIGGER reject_versions BEFORE INSERT ON version_list_cache
         BEGIN SELECT RAISE(ABORT, 'injected cache write failure'); END;",
    )
    .unwrap();
    conn
}

#[tokio::test]
async fn cache_write_failure_does_not_discard_fetched_pom() {
    const BODY: &[u8] = b"<project><modelVersion>4.0.0</modelVersion></project>";
    let (client, tmp) = test_client();
    let conn = reject_cache_inserts(&tmp.path().join("metadata.db"));
    let (repo, hits) = verified_body_stub(BODY).await;
    let req = ArtifactRequest::new("com.example", "demo", "1.0");
    let scope = RepoClient::cache_scope_key(&repo.url, &repo.url);
    let path = req.clone().pom().to_path();

    // Prove the injection fails and retains the underlying SQLite class.
    let err = client
        .cache
        .insert_with_ttl(CacheTable::Pom, &scope, &path, BODY, 60)
        .expect_err("trigger rejects inserts");
    assert!(matches!(err, RepoError::DbError(ref err)
        if err.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation)));

    for fetcher in [&client, &client.clone()] {
        assert_eq!(fetcher.fetch_pom(&repo, &req).await.unwrap().as_ref(), BODY);
        assert!(
            client
                .cache
                .get(CacheTable::Pom, &scope, &path)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        hits.connections(),
        4,
        "uncached bytes must be fetched again"
    );

    conn.execute_batch("DROP TRIGGER reject_pom;").unwrap();
    assert_eq!(client.fetch_pom(&repo, &req).await.unwrap().as_ref(), BODY);
    assert_eq!(
        client
            .cache
            .get(CacheTable::Pom, &scope, &path)
            .unwrap()
            .unwrap()
            .content,
        BODY
    );
}

#[tokio::test]
async fn cache_write_failure_does_not_discard_fetched_metadata() {
    const BODY: &[u8] = b"<metadata><version>1.0-SNAPSHOT</version><versioning><latest>1.0</latest><versions><version>1.0</version></versions><snapshot><timestamp>20261011.010101</timestamp><buildNumber>2</buildNumber></snapshot></versioning></metadata>";
    let (client, tmp) = test_client();
    let conn = reject_cache_inserts(&tmp.path().join("metadata.db"));
    let (repo, hits) = verified_body_stub(BODY).await;
    let expected = Metadata::from_bytes(BODY).unwrap();
    for version in ["1.0", "1.0-SNAPSHOT"] {
        let coord = Coord::parse(&format!("com.example:demo:{version}")).unwrap();
        assert_eq!(
            client.fetch_metadata(&repo, &coord).await.unwrap(),
            expected
        );
    }
    // Snapshot resolution has its own fetch/insert call site.
    let coord = Coord::parse("com.example:demo:1.0-SNAPSHOT").unwrap();
    assert_eq!(
        client.resolve_snapshot(&repo, &coord).await.unwrap(),
        "1.0-20261011.010101-2"
    );
    assert_eq!(hits.connections(), 6);
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM version_list_cache", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0, "failed writes must leave the cache empty");
}

#[tokio::test]
async fn artifact_store_write_failures_remain_fatal() {
    let (client, _tmp) = test_client();
    let (repo, _server) = verified_body_stub(b"artifact bytes").await;
    let req = ArtifactRequest::new("com.example", "demo", "1.0");
    let key = rv_config::ArtifactKey::new("com.example", "demo", "1.0", "jar", None);

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let staging = dir.path().join("tmp");
    std::fs::remove_dir_all(&staging).unwrap();
    std::fs::write(&staging, b"not a directory").unwrap();
    let err = client
        .fetch_artifact_to_store(&repo, &req, &store)
        .await
        .unwrap_err();
    assert!(matches!(err, RepoError::Store(_)), "{err:?}");

    std::fs::remove_file(&staging).unwrap();
    std::fs::create_dir(&staging).unwrap();
    let conn = rusqlite::Connection::open(dir.path().join("index.sqlite")).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_artifact BEFORE INSERT ON artifacts
         BEGIN SELECT RAISE(ABORT, 'injected artifact index failure'); END;",
    )
    .unwrap();
    let err = client
        .fetch_artifact_to_store_and_index(&repo, &req, &store, &key)
        .await
        .unwrap_err();
    assert!(matches!(err, RepoError::Store(_)), "{err:?}");
    assert!(store.lookup_artifact(&key).await.unwrap().is_none());
}

// The first and second pairs deliberately serve different metadata bodies.
// This catches retrying only the sidecar or accepting the first body.
async fn metadata_checksum_stub(repaired: bool) -> (Repository, StubServer) {
    use sha2::{Digest, Sha256};
    let responses = (0..12).map(|index| {
        Box::new(move |request: &str| {
            let build = if index < 2 { 1 } else { 2 };
            let body = format!("<metadata><version>1.0-SNAPSHOT</version><versioning><latest>{build}</latest><snapshot><timestamp>20261011.010101</timestamp><buildNumber>{build}</buildNumber></snapshot></versioning></metadata>");
            if request.lines().next().unwrap().contains(".sha256") {
                let digest = if repaired && index >= 2 {
                    hex::encode(Sha256::digest(body.as_bytes()))
                } else {
                    "0".repeat(64)
                };
                Response::new(200, digest.as_bytes())
            } else {
                Response::new(200, body.as_bytes())
            }
        }) as StubHandler
    }).collect();
    let (addr, hits) = spawn_stub_seq(responses);
    (
        Repository::new(None, format!("http://{addr}/"), true, true),
        hits,
    )
}

fn capture_metadata_warnings(body: impl std::future::Future<Output = ()>) -> String {
    #[derive(Clone)]
    struct Writer(Arc<Mutex<Vec<u8>>>);
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Writer {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(Writer(output.clone()))
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .without_time()
        .finish();
    rv_test_support::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(body);
    });
    let bytes = output.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn metadata_checksum_mismatch_warns_after_retry_and_respects_cache_policy() {
    let output = capture_metadata_warnings(async {
        for version in ["1.0", "1.0-SNAPSHOT"] {
            let (client, _cache) = test_client();
            let (mut repo, hits) = metadata_checksum_stub(false).await;
            // Secrets in URL userinfo and query must never reach the warning.
            repo.url = repo.url.replacen("http://", "http://user:secret@", 1);
            repo.url.push_str("?token=secret-query");
            repo.snapshots_update_policy = rv_config::UpdatePolicy::Daily;
            let coord = Coord::parse(&format!("com.example:demo:{version}")).unwrap();
            let metadata = client.fetch_metadata(&repo, &coord).await.unwrap();
            assert_eq!(metadata.latest.as_deref(), Some("2"));
            assert_eq!(hits.connections(), 4, "both files must be fetched twice");
            client.fetch_metadata(&repo, &coord).await.unwrap();
            assert_eq!(hits.connections(), 4, "normal daily cache applies");
            repo.releases_update_policy = rv_config::UpdatePolicy::Always;
            repo.snapshots_update_policy = rv_config::UpdatePolicy::Always;
            client.fetch_metadata(&repo, &coord).await.unwrap();
            assert_eq!(
                hits.connections(),
                8,
                "shortening update policy must refetch"
            );
            // Tightening the policy must not reuse accepted mismatched bytes.
            repo.releases_checksum_policy = rv_config::ChecksumPolicy::Fail;
            repo.snapshots_checksum_policy = rv_config::ChecksumPolicy::Fail;
            assert!(matches!(
                client.fetch_metadata(&repo, &coord).await,
                Err(RepoError::ChecksumMismatch { .. })
            ));
            assert_eq!(hits.connections(), 12);
        }
        let (client, _cache) = test_client();
        let (mut repo, hits) = metadata_checksum_stub(false).await;
        repo.snapshots_update_policy = rv_config::UpdatePolicy::Always;
        let coord = Coord::parse("com.example:demo:1.0-SNAPSHOT").unwrap();
        for _ in 0..2 {
            let resolved = client
                .resolve_snapshot_version(&repo, &coord)
                .await
                .unwrap();
            assert_eq!(resolved.version, "1.0-20261011.010101-2");
        }
        assert_eq!(
            hits.connections(),
            8,
            "mismatch cannot extend update policy"
        );
    });
    assert_eq!(output.matches("METADATA_CHECKSUM_MISMATCH").count(), 6);
    assert!(output.contains("repository_url=http://127.0.0.1:"));
    assert!(output.contains("com/example/demo/maven-metadata.xml"));
    assert!(output.contains("com/example/demo/1.0-SNAPSHOT/maven-metadata.xml"));
    assert!(!output.contains("secret"));
    assert!(!output.contains("user:"));
}

#[test]
fn metadata_checksum_retry_then_success_emits_no_mismatch_warning() {
    let output = capture_metadata_warnings(async {
        for policy in [
            rv_config::ChecksumPolicy::Warn,
            rv_config::ChecksumPolicy::Fail,
        ] {
            let (client, _cache) = test_client();
            let (mut repo, hits) = metadata_checksum_stub(true).await;
            repo.snapshots_checksum_policy = policy;
            let coord = Coord::parse("com.example:demo:1.0-SNAPSHOT").unwrap();
            let resolved = client
                .resolve_snapshot_version(&repo, &coord)
                .await
                .unwrap();
            assert_eq!(resolved.version, "1.0-20261011.010101-2");
            assert_eq!(hits.connections(), 4);
        }
    });
    assert!(!output.contains("METADATA_CHECKSUM_MISMATCH"));
}

#[tokio::test]
async fn metadata_checksum_fail_policy_from_pom_and_config_is_fatal() {
    let (client, _cache) = test_client();
    let (repo, hits) = metadata_checksum_stub(false).await;
    let policies = "<releases><checksumPolicy>fail</checksumPolicy></releases><snapshots><enabled>true</enabled><checksumPolicy>fail</checksumPolicy></snapshots>";
    let xml = format!("<repository><url>{}</url>{policies}</repository>", repo.url);
    let pom_repo: rv_maven_model::Repository = quick_xml::de::from_str(&xml).unwrap();
    let mut config_repo = rv_config::RepoConfig::maven_central();
    config_repo.url = repo.url.clone();
    config_repo.snapshots = Some(true);
    config_repo.releases_checksum_policy = Some(rv_config::ChecksumPolicy::Fail);
    config_repo.snapshots_checksum_policy = Some(rv_config::ChecksumPolicy::Fail);
    for repo in [Repository::from(pom_repo), Repository::from(config_repo)] {
        assert_eq!(
            repo.releases_checksum_policy,
            rv_config::ChecksumPolicy::Fail
        );
        assert_eq!(
            repo.snapshots_checksum_policy,
            rv_config::ChecksumPolicy::Fail
        );
        let coord = Coord::parse("com.example:demo:1.0-SNAPSHOT").unwrap();
        assert!(matches!(
            client.fetch_metadata(&repo, &coord).await,
            Err(RepoError::ChecksumMismatch { .. })
        ));
    }
    assert_eq!(hits.connections(), 8);
}

#[tokio::test]
async fn metadata_warn_policy_does_not_relax_artifact_or_pom_checksums() {
    for policy in [
        rv_config::ChecksumPolicy::Warn,
        rv_config::ChecksumPolicy::Ignore,
    ] {
        let (client, _cache) = test_client();
        let (mut repo, hits) = metadata_checksum_stub(false).await;
        repo.releases_checksum_policy = policy;
        let request = ArtifactRequest::new("com.example", "demo", "1.0");
        assert!(matches!(
            client.fetch_pom(&repo, &request).await,
            Err(RepoError::ChecksumMismatch { .. })
        ));
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert!(matches!(
            client
                .fetch_artifact_to_store(&repo, &request, &store)
                .await,
            Err(RepoError::ChecksumMismatch { .. })
        ));
        assert_eq!(hits.connections(), 4, "only metadata gets a checksum retry");
    }
}

#[tokio::test]
async fn local_metadata_checksum_mismatch_remains_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("com/example/demo");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("maven-metadata.xml"), b"<metadata/>").unwrap();
    std::fs::write(path.join("maven-metadata.xml.sha256"), "0".repeat(64)).unwrap();
    let repo = Repository::new(
        None,
        Url::from_directory_path(dir.path()).unwrap(),
        true,
        true,
    );
    let (client, _cache) = test_client();
    let coord = Coord::parse("com.example:demo:1.0").unwrap();
    assert!(matches!(
        client.fetch_metadata(&repo, &coord).await,
        Err(RepoError::ChecksumMismatch { .. })
    ));
}

// Self-signed localhost certificate used only by the in-process redirect
// stubs. The reqwest clients below opt into accepting it.
const TEST_CERT_DER: &str = "308201993082013fa00302010202142edbe5ec174441664b0b0f3b828a97fe31e81747300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3236303732343233343131335a170d3336303732313233343131335a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004325fb4c3e179b836c763009e555ff7709191f1fec299a00a5cfb7a34d99fe02e9c346670096f9bd5c4a8b3d2acf3b1894646cb99f04584a20f3492fd8e99cc4ba36f306d301d0603551d0e04160414730484bd1929ef7f056e4256368807a07197a43c301f0603551d23041830168014730484bd1929ef7f056e4256368807a07197a43c300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300a06082a8648ce3d040302034800304502210099131112ae00cf55f0d34b1283ced2c520d4d9c029dfe2ccafc327456953de66022029cbd4d385d2d1d11fd11550073ccfaf8a1c6d2e6febe89f9439c928b33c78fe";
const TEST_KEY_DER: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104200e9f9cb30589ef41f37a668cc1928b38f76ca3c443feb73aef12380ccac2f9a9a14403420004325fb4c3e179b836c763009e555ff7709191f1fec299a00a5cfb7a34d99fe02e9c346670096f9bd5c4a8b3d2acf3b1894646cb99f04584a20f3492fd8e99cc4b";

struct HttpsStub {
    addr: std::net::SocketAddr,
    request: Arc<Mutex<Option<String>>>,
}

fn spawn_https_stub(handler: impl Fn(&str) -> Vec<u8> + Send + 'static) -> HttpsStub {
    spawn_https_stub_requests(1, handler)
}

fn spawn_https_stub_requests(
    count: usize,
    handler: impl Fn(&str) -> Vec<u8> + Send + 'static,
) -> HttpsStub {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = CertificateDer::from(hex::decode(TEST_CERT_DER).expect("test certificate"));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        hex::decode(TEST_KEY_DER).expect("test private key"),
    ));
    let tls = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("test TLS config"),
    );
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind HTTPS stub");
    let addr = listener.local_addr().expect("HTTPS stub address");
    let request = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&request);
    thread::spawn(move || {
        for _ in 0..count {
            let (stream, _) = listener.accept().expect("accept HTTPS stub");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let connection =
                rustls::ServerConnection::new(tls.clone()).expect("create TLS server connection");
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).expect("read HTTPS request");
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..read]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let raw_request = String::from_utf8_lossy(&bytes).into_owned();
            *captured.lock().expect("capture HTTPS request") = Some(raw_request.clone());
            stream
                .write_all(&handler(&raw_request))
                .expect("write HTTPS response");
            stream.flush().expect("flush HTTPS response");
        }
    });
    HttpsStub { addr, request }
}

fn redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// A guard for a configuration that named exactly these origins. Mirrors
/// `redirect_guard`: naming an origin also exempts its host from the
/// address screen.
fn origins_guard(origins: HashSet<String>) -> RedirectGuard {
    let exempt_hosts: Vec<String> = origins
        .iter()
        .filter_map(|origin| Url::parse(origin).ok())
        .filter_map(|origin| origin.host_str().map(str::to_string))
        .collect();
    RedirectGuard {
        origins,
        root_issuer: None,
        exempt_hosts: ConfiguredHosts::new(exempt_hosts),
        proxy_active: false,
    }
}

fn redirect_test_client(trusted_origins: HashSet<String>) -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .redirect(trusted_redirect_policy(origins_guard(trusted_origins)))
        .build()
        .expect("redirect test client")
}

fn url(raw: &str) -> Url {
    Url::parse(raw).expect("test URL")
}

fn origin_set<const N: usize>(raw: [&str; N]) -> HashSet<String> {
    raw.iter()
        .map(|value| url(value).origin().ascii_serialization())
        .collect()
}

/// A runtime (growable) exemption set, as `trust_repositories` builds one.
fn host_set<const N: usize>(raw: [&str; N]) -> TrustedHosts {
    let hosts = TrustedHosts::default();
    for host in raw {
        hosts.insert(host);
    }
    hosts
}

/// A configured (frozen) exemption set, as `redirect_guard` builds one.
fn frozen_hosts<const N: usize>(raw: [&str; N]) -> ConfiguredHosts {
    ConfiguredHosts::new(raw.iter().map(|host| host.to_string()))
}

async fn fetch_redirect_test(client: &reqwest::Client, url: &Url) -> Result<Bytes> {
    fetch_bytes(
        client,
        url,
        None,
        None,
        &FetchConfig {
            retries: 0,
            timeout: Duration::from_secs(5),
            ..Default::default()
        },
        None,
    )
    .await
}

/// The stubs live on loopback, which the address guard rejects unless the
/// target origin is configured too — so this configures both, the shape a
/// user gets from an on-prem registry pair.
#[tokio::test]
async fn trusted_https_cross_origin_redirect_strips_sensitive_headers() {
    assert_redirect_strips_sensitive_headers(false).await;
}

#[tokio::test]
async fn root_https_cross_origin_redirect_strips_sensitive_headers() {
    assert_redirect_strips_sensitive_headers(true).await;
}

#[tokio::test]
async fn root_redirect_pom_is_cached_for_a_fresh_offline_client() {
    use sha2::{Digest, Sha256};

    const POM: &[u8] = b"<project><groupId>test</groupId><artifactId>parent</artifactId><version>1</version></project>";
    let target = spawn_https_stub_requests(2, |request| {
        if request
            .split_whitespace()
            .nth(1)
            .unwrap()
            .ends_with(".sha256")
        {
            ok_response(hex::encode(Sha256::digest(POM)).as_bytes())
        } else {
            ok_response(POM)
        }
    });
    let target_url = format!("https://127.0.0.1:{}", target.addr.port());
    let destination = target_url.clone();
    let source = spawn_https_stub_requests(2, move |request| {
        redirect_response(&format!(
            "{destination}{}",
            request.split_whitespace().nth(1).unwrap()
        ))
    });
    let repo = Repository::new(
        None,
        format!("https://127.0.0.1:{}/repo/", source.addr.port()),
        true,
        false,
    );
    // Configure only the loopback target to permit the TLS fixture. The
    // issuing origin obtains redirect authority from the root POM grant.
    let (online, cache_dir) = screened_test_client(origins_guard(origin_set([&target_url])));
    online.trust_root_repositories(std::slice::from_ref(&repo));
    let req = ArtifactRequest::new("test", "parent", "1");
    assert_eq!(online.fetch_pom(&repo, &req).await.unwrap().as_ref(), POM);
    assert!(source.request.lock().unwrap().is_some());
    assert!(target.request.lock().unwrap().is_some());
    drop(online);

    let (mut offline, _tmp) = test_client();
    offline.cache = MetadataCache::new(&cache_dir.path().join("metadata.db")).unwrap();
    let offline = offline.with_offline(true);
    assert_eq!(offline.fetch_pom(&repo, &req).await.unwrap().as_ref(), POM);
}

#[tokio::test]
async fn snapshot_metadata_policy_cache_survives_a_fresh_offline_client() {
    use sha2::{Digest, Sha256};

    const METADATA: &[u8] = b"<metadata><version>1-SNAPSHOT</version><versioning><snapshot><timestamp>20261011.010101</timestamp><buildNumber>7</buildNumber></snapshot></versioning></metadata>";
    let responses = (0..2)
        .map(|_| {
            Box::new(|request: &str| {
                if request
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .ends_with(".sha256")
                {
                    Response::new(200, hex::encode(Sha256::digest(METADATA)).as_bytes())
                } else {
                    Response::new(200, METADATA)
                }
            }) as StubHandler
        })
        .collect();
    let (addr, hits) = spawn_stub_seq(responses);
    let mut repo = Repository::new(None, format!("http://{addr}/"), true, true);
    repo.snapshots_update_policy = rv_config::UpdatePolicy::Interval(17);
    repo.snapshots_checksum_policy = rv_config::ChecksumPolicy::Fail;
    let coord = Coord::parse("test:bom:1-SNAPSHOT").unwrap();
    let (online, cache_dir) = test_client();
    online.fetch_metadata(&repo, &coord).await.unwrap();
    assert_eq!(hits.connections(), 2);
    drop(online);

    let (mut offline, _tmp) = test_client();
    offline.cache = MetadataCache::new(&cache_dir.path().join("metadata.db")).unwrap();
    let offline = offline.with_offline(true);
    offline.fetch_metadata(&repo, &coord).await.unwrap();
    assert_eq!(
        offline.resolve_snapshot(&repo, &coord).await.unwrap(),
        "1-20261011.010101-7"
    );
    assert_eq!(hits.connections(), 2, "offline must not make HTTP requests");
}

async fn assert_redirect_strips_sensitive_headers(root: bool) {
    let target = spawn_https_stub(|_| ok_response(b"artifact bytes"));
    let target_url = format!("https://127.0.0.1:{}/artifact", target.addr.port());
    let source_location = target_url.clone();
    let source = spawn_https_stub(move |_| redirect_response(&source_location));
    let source_url =
        Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
    let trusted = HashSet::from([
        source_url.origin().ascii_serialization(),
        Url::parse(&target_url)
            .unwrap()
            .origin()
            .ascii_serialization(),
    ]);
    let client = if root {
        let (client, _tmp) = screened_test_client(origins_guard(HashSet::from([url(&target_url)
            .origin()
            .ascii_serialization()])));
        client.trust_root_repositories(&[Repository::new(None, source_url.as_str(), true, false)]);
        client.http_client_for(&source_url).unwrap().into_owned()
    } else {
        redirect_test_client(trusted)
    };

    let response = client
        .get(source_url)
        .bearer_auth("registry-secret")
        .header(reqwest::header::COOKIE, "session=private")
        .send()
        .await
        .expect("trusted HTTPS redirect should succeed");
    assert_eq!(
        response.bytes().await.expect("response bytes"),
        Bytes::from_static(b"artifact bytes")
    );

    let source_request = source
        .request
        .lock()
        .expect("source request")
        .clone()
        .expect("source contacted");
    let target_request = target
        .request
        .lock()
        .expect("target request")
        .clone()
        .expect("target contacted");
    assert!(
        source_request
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-secret"),
        "configured source must receive its Authorization header"
    );
    let target_request = target_request.to_ascii_lowercase();
    assert!(
        !target_request.contains("authorization:"),
        "redirect target must not receive Authorization"
    );
    assert!(
        !target_request.contains("cookie:"),
        "redirect target must not receive Cookie"
    );
}

#[tokio::test]
async fn root_redirect_to_unauthorized_target_reports_auth_error() {
    let target = spawn_https_stub(|_| {
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    });
    let target_url = loopback_name_url(target.addr.port(), "/login");
    let location = target_url.to_string();
    let source = spawn_https_stub(move |_| redirect_response(&location));
    let source_url = url(&format!("https://127.0.0.1:{}/repo/", source.addr.port()));
    let (client, _tmp) = screened_test_client(origins_guard(HashSet::from([target_url
        .origin()
        .ascii_serialization()])));
    client.trust_root_repositories(&[Repository::new(None, source_url.as_str(), true, false)]);
    let error = fetch_redirect_test(
        client.http_client_for(&source_url).unwrap().as_ref(),
        &source_url,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, RepoError::AuthError(message) if message.contains("401")),
        "{error}"
    );
}

#[test]
fn root_issuer_policy_keeps_transport_hop_and_target_limits() {
    let source = url("https://root.example/repository/artifact");
    let target = url("https://storage.example/artifact");
    let mut guard = origins_guard(HashSet::new());
    guard.root_issuer = Some(source.origin().ascii_serialization());
    guard
        .evaluate(std::slice::from_ref(&source), &target)
        .unwrap();
    for (previous, target, expected) in [
        (
            vec![url("https://dependency.example/artifact")],
            target.clone(),
            RedirectRejectionKind::OriginNotConfigured,
        ),
        (
            vec![url("https://root.example:8443/artifact")],
            target.clone(),
            RedirectRejectionKind::OriginNotConfigured,
        ),
        (
            vec![source.clone()],
            url("http://storage.example/artifact"),
            RedirectRejectionKind::HttpsDowngrade,
        ),
        (
            vec![source.clone(), target.clone()],
            url("https://another.example/artifact"),
            RedirectRejectionKind::SecondCrossOriginHop,
        ),
        (
            vec![source.clone()],
            url("https://127.0.0.1/secret"),
            RedirectRejectionKind::NonGlobalTarget,
        ),
    ] {
        assert_eq!(
            guard.evaluate(&previous, &target).unwrap_err().kind,
            expected
        );
    }
    guard.root_issuer = Some("http://root.example".into());
    assert_eq!(
        guard
            .evaluate(&[url("http://root.example/artifact")], &target)
            .unwrap_err()
            .kind,
        RedirectRejectionKind::InsecureOrigin
    );
}

#[tokio::test]
async fn transitive_grant_does_not_authorize_redirects_but_root_grant_does() {
    for root in [false, true] {
        let target = spawn_https_stub(|_| ok_response(b"artifact bytes"));
        let target_url = loopback_name_url(target.addr.port(), "/artifact");
        let location = target_url.to_string();
        let source = spawn_https_stub(move |_| redirect_response(&location));
        let source_url = url(&format!("https://127.0.0.1:{}/repo/", source.addr.port()));
        let (client, _tmp) = screened_test_client(origins_guard(HashSet::from([target_url
            .origin()
            .ascii_serialization()])));
        let repo = Repository::new(None, source_url.as_str(), true, false);
        // A transitive declaration encountered first must not prevent a
        // later root declaration from granting trust to the same endpoint.
        client.trust_repositories(std::slice::from_ref(&repo));
        if root {
            client.trust_root_repositories(&[repo]);
        }
        let result = fetch_redirect_test(
            client.http_client_for(&source_url).unwrap().as_ref(),
            &source_url,
        )
        .await;
        if root {
            assert_eq!(result.unwrap(), Bytes::from_static(b"artifact bytes"));
        } else {
            assert!(matches!(
                result,
                Err(RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::OriginNotConfigured,
                    ..
                })
            ));
            assert!(target.request.lock().unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn root_grant_does_not_widen_an_existing_redirect_clients_dns_screen() {
    let (client, _tmp) = screened_test_client(origins_guard(HashSet::new()));
    let source = url("https://root.example/repository/");
    client.trust_root_repositories(&[Repository::new(None, source.as_str(), true, false)]);
    let http = client.http_client_for(&source).unwrap();
    let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let target_url = loopback_name_url(target.addr.port(), "/secret");
    client.trust_root_repositories(&[Repository::new(None, target_url.as_str(), true, false)]);
    // Existing root clients must not acquire the new host's DNS exemption.
    let error = fetch_redirect_test(&http, &target_url).await.unwrap_err();
    assert!(matches!(
        error,
        RepoError::RedirectRejected {
            kind: RedirectRejectionKind::NonGlobalTarget,
            ..
        }
    ));
    assert!(target.request.lock().unwrap().is_none());
}

#[tokio::test]
async fn trusted_origin_rejects_loopback_target() {
    let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let target_url = format!("https://127.0.0.1:{}/artifact", target.addr.port());
    let source = spawn_https_stub(move |_| redirect_response(&target_url));
    let source_url =
        Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
    let trusted = HashSet::from([source_url.origin().ascii_serialization()]);
    let client = redirect_test_client(trusted);

    let error = fetch_redirect_test(&client, &source_url)
        .await
        .expect_err("loopback redirect target must be rejected");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::NonGlobalTarget,
                ..
            }
        ),
        "expected explicit non-global rejection, got {error:?}"
    );
    assert!(
        target.request.lock().expect("target request").is_none(),
        "loopback target must not be contacted"
    );
}

#[tokio::test]
async fn trusted_origin_rejects_non_global_literal_targets() {
    for target_url in [
        "https://127.0.0.1/artifact",
        "https://10.0.0.1/artifact",
        "https://172.16.0.1/artifact",
        "https://192.168.1.10/artifact",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/artifact",
        "https://[::ffff:10.0.0.1]/artifact",
        "https://[fd00::1]/artifact",
    ] {
        let source = spawn_https_stub(move |_| redirect_response(target_url));
        let source_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
        let trusted = HashSet::from([source_url.origin().ascii_serialization()]);
        let client = redirect_test_client(trusted);

        let error = fetch_redirect_test(&client, &source_url)
            .await
            .err()
            .unwrap_or_else(|| panic!("{target_url} must be rejected"));
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::NonGlobalTarget,
                    ..
                }
            ),
            "expected non-global rejection for {target_url}, got {error:?}"
        );
    }
}

#[tokio::test]
async fn trusted_origin_rejects_https_to_http_downgrade() {
    let (target_addr, target_hits) = spawn_stub_seq(vec![Box::new(|_| Response::new(200, b"no"))]);
    let target_url = format!("http://{target_addr}/artifact");
    let source = spawn_https_stub(move |_| redirect_response(&target_url));
    let source_url =
        Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
    let trusted = HashSet::from([source_url.origin().ascii_serialization()]);
    let client = redirect_test_client(trusted);

    let error = fetch_redirect_test(&client, &source_url)
        .await
        .expect_err("HTTPS downgrade must be rejected");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::HttpsDowngrade,
                ..
            }
        ),
        "expected explicit HTTPS downgrade rejection, got {error:?}"
    );
    assert!(
        error.to_string().contains("target is not HTTPS"),
        "rendered error must name the downgrade: {error}"
    );
    assert_eq!(
        target_hits.connections(),
        0,
        "downgrade target must not be contacted"
    );
}

#[tokio::test]
async fn redirect_policy_rejects_second_cross_origin_hop() {
    let final_target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let final_url = format!("https://127.0.0.1:{}/artifact", final_target.addr.port());
    let middle = spawn_https_stub(move |_| redirect_response(&final_url));
    let middle_url = format!("https://127.0.0.1:{}/middle", middle.addr.port());
    let middle_origin = middle_url.clone();
    let first = spawn_https_stub(move |_| redirect_response(&middle_url));
    let first_url = Url::parse(&format!("https://127.0.0.1:{}/start", first.addr.port())).unwrap();
    // The middle origin is configured so the first hop clears the address
    // guard and the second hop is what fails.
    let trusted = HashSet::from([
        first_url.origin().ascii_serialization(),
        Url::parse(&middle_origin)
            .unwrap()
            .origin()
            .ascii_serialization(),
    ]);
    let client = redirect_test_client(trusted);

    let error = fetch_redirect_test(&client, &first_url)
        .await
        .expect_err("second cross-origin hop must be rejected");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::SecondCrossOriginHop,
                ..
            }
        ),
        "expected explicit second-hop rejection, got {error:?}"
    );
    assert!(
        error.to_string().contains("second cross-origin hop"),
        "rendered error must name the second hop: {error}"
    );
    assert!(
        middle.request.lock().expect("middle request").is_some(),
        "first cross-origin target should be contacted"
    );
    assert!(
        final_target
            .request
            .lock()
            .expect("final request")
            .is_none(),
        "second cross-origin target must not be contacted"
    );
}

#[tokio::test]
async fn redirect_policy_names_unconfigured_issuing_origin() {
    let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let target_url = format!("https://127.0.0.1:{}/artifact", target.addr.port());
    let source = spawn_https_stub(move |_| redirect_response(&target_url));
    let source_url =
        Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
    let source_origin = source_url.origin().ascii_serialization();
    let client = redirect_test_client(HashSet::new());

    let error = fetch_redirect_test(&client, &source_url)
        .await
        .expect_err("unconfigured redirect issuer must be rejected");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::OriginNotConfigured,
                ..
            }
        ),
        "expected explicit unconfigured-origin rejection, got {error:?}"
    );
    assert!(
        error.to_string().contains(&source_origin),
        "rendered error must name untrusted origin {source_origin}: {error}"
    );
    assert!(
        target.request.lock().expect("target request").is_none(),
        "target of an untrusted redirect must not be contacted"
    );
}

/// Minimal CONNECT-capable stub proxy. Records the request line of every
/// connection it accepts, so a test can assert exactly which authorities
/// the client asked it to reach, and tunnels CONNECT through to the real
/// (loopback) address so a permitted hop can still complete.
async fn spawn_stub_proxy() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("proxy address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut downstream, _)) = listener.accept().await else {
                return;
            };
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                let mut head = Vec::new();
                loop {
                    let Ok(read) = downstream.read(&mut buffer).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&buffer[..read]);
                    if head.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&head).into_owned();
                let request_line = request.lines().next().unwrap_or_default().to_string();
                recorder
                    .lock()
                    .expect("proxy log")
                    .push(request_line.clone());

                let authority = request_line
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split_whitespace().next())
                    .map(str::to_string);
                let Some(authority) = authority else {
                    // Absolute-form GET: answer directly, no upstream.
                    let _ = downstream.write_all(&ok_response(b"proxied")).await;
                    return;
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(&authority).await else {
                    let _ = downstream
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        .await;
                    return;
                };
                if downstream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_ok()
                {
                    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                }
            });
        }
    });
    (addr, seen)
}

fn proxied_test_client(
    proxy_url: &str,
    guard: RedirectGuard,
    resolver_exempt: ConfiguredHosts,
) -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .proxy(reqwest::Proxy::all(proxy_url).expect("stub proxy"))
        .dns_resolver(Arc::new(GlobalOnlyResolver {
            exempt_hosts: resolver_exempt,
        }))
        .redirect(trusted_redirect_policy(guard))
        .build()
        .expect("proxied test client")
}

/// The proxy-bypass blocker. A proxied request never resolves its target
/// locally, so [`GlobalOnlyResolver`] cannot screen it: without the
/// proxy-aware branch in the policy, `Location: https://admin.internal/`
/// becomes a `CONNECT admin.internal:443` that the corporate proxy happily
/// completes on rv's behalf. The proxy log is the assertion: the internal
/// name must never be handed to it.
#[tokio::test]
async fn proxied_redirect_to_internal_hostname_never_reaches_the_proxy() {
    let (proxy_addr, proxy_log) = spawn_stub_proxy().await;
    let source = spawn_https_stub(|_| redirect_response("https://admin.internal/secret"));
    let source_url =
        Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
    let guard = RedirectGuard {
        root_issuer: None,
        origins: HashSet::from([source_url.origin().ascii_serialization()]),
        exempt_hosts: ConfiguredHosts::default(),
        proxy_active: true,
    };
    let client = proxied_test_client(
        &format!("http://{proxy_addr}"),
        guard,
        frozen_hosts(["127.0.0.1"]),
    );

    let error = fetch_redirect_test(&client, &source_url)
        .await
        .expect_err("internal-hostname redirect must be rejected");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::ProxiedTargetNotConfigured,
                ..
            }
        ),
        "expected a proxied-target rejection, got {error:?}"
    );

    let log = proxy_log.lock().expect("proxy log").clone();
    assert_eq!(
        log,
        vec![format!("CONNECT 127.0.0.1:{} HTTP/1.1", source.addr.port())],
        "the proxy must see the configured source and nothing else"
    );
    assert!(
        !log.iter().any(|line| line.contains("admin.internal")),
        "the internal name must never be handed to the proxy: {log:?}"
    );
}

/// The other half of the proxy story: a configured target origin is still
/// followed through the proxy, so the guard does not simply break proxied
/// redirects.
#[tokio::test]
async fn proxied_redirect_to_configured_origin_is_followed() {
    let (proxy_addr, proxy_log) = spawn_stub_proxy().await;
    let target = spawn_https_stub(|_| ok_response(b"artifact bytes"));
    let target_url = format!("https://127.0.0.1:{}/artifact", target.addr.port());
    let redirect_to = target_url.clone();
    let source = spawn_https_stub(move |_| redirect_response(&redirect_to));
    let source_url =
        Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
    let guard = RedirectGuard {
        root_issuer: None,
        origins: HashSet::from([
            source_url.origin().ascii_serialization(),
            Url::parse(&target_url)
                .unwrap()
                .origin()
                .ascii_serialization(),
        ]),
        exempt_hosts: ConfiguredHosts::default(),
        proxy_active: true,
    };
    let client = proxied_test_client(
        &format!("http://{proxy_addr}"),
        guard,
        frozen_hosts(["127.0.0.1"]),
    );

    let bytes = fetch_redirect_test(&client, &source_url)
        .await
        .expect("configured target must still be reachable through the proxy");
    assert_eq!(bytes, Bytes::from_static(b"artifact bytes"));
    let log = proxy_log.lock().expect("proxy log").clone();
    assert!(
        log.iter()
            .any(|line| line.contains(&format!("CONNECT 127.0.0.1:{}", target.addr.port()))),
        "the permitted hop must reach the proxy: {log:?}"
    );
}

/// A corporate proxy named by hostname that resolves onto RFC1918 must be
/// dialable: its host is exempt from the address screen. That exemption is
/// scoped to the resolver, so the redirect target arriving from behind it
/// is screened exactly as before.
#[tokio::test]
async fn private_hostname_proxy_connects_while_target_stays_screened() {
    let (proxy_addr, proxy_log) = spawn_stub_proxy().await;
    let source = spawn_https_stub(|_| redirect_response("https://admin.internal/secret"));
    let source_url =
        Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
    let guard = RedirectGuard {
        root_issuer: None,
        origins: HashSet::from([source_url.origin().ascii_serialization()]),
        // `localhost` stands in for `proxy.corp`: a proxy named by hostname
        // that resolves to an address the screen would otherwise reject.
        exempt_hosts: frozen_hosts(["localhost", "127.0.0.1"]),
        proxy_active: true,
    };
    let proxy_url = format!("http://localhost:{}", proxy_addr.port());
    let client = proxied_test_client(&proxy_url, guard.clone(), guard.exempt_hosts.clone());

    let error = fetch_redirect_test(&client, &source_url)
        .await
        .expect_err("internal-hostname redirect must be rejected");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::ProxiedTargetNotConfigured,
                ..
            }
        ),
        "expected a proxied-target rejection, got {error:?}"
    );
    let log = proxy_log.lock().expect("proxy log").clone();
    assert_eq!(
        log,
        vec![format!("CONNECT 127.0.0.1:{} HTTP/1.1", source.addr.port())],
        "the private-address proxy must have been reachable, and only for the source"
    );

    // Drop the proxy host from the resolver exemption and the same client
    // cannot even reach its proxy, which is what finding 4 was about.
    let unexempt = proxied_test_client(&proxy_url, guard, ConfiguredHosts::default());
    let error = fetch_redirect_test(&unexempt, &source_url)
        .await
        .expect_err("an unexempt private proxy host must not resolve");
    assert!(
        error.to_string().contains("localhost"),
        "rejection must name the host it refused to resolve: {error}"
    );
    assert_eq!(
        proxy_log.lock().expect("proxy log").len(),
        1,
        "no further connection may reach the proxy"
    );
}

/// The DNS exemption is host-level, so authorisation must not be.
/// Configuring `https://nexus.corp` (port 443) exempts the *name* from the
/// address screen; letting that exemption carry a redirect to
/// `https://nexus.corp:8443` would hand a hostile mirror a port scanner
/// pointed at a private host the user only meant to fetch artifacts from.
#[test]
fn redirect_to_exempt_host_requires_the_configured_origin() {
    let guard = RedirectGuard {
        root_issuer: None,
        origins: origin_set(["https://mirror.example", "https://nexus.corp"]),
        exempt_hosts: frozen_hosts(["mirror.example", "nexus.corp"]),
        proxy_active: false,
    };
    let previous = [url("https://mirror.example/demo-1.0.jar")];

    let rejection = guard
        .evaluate(&previous, &url("https://nexus.corp:8443/demo-1.0.jar"))
        .expect_err("a different port is a different service");
    assert_eq!(
        rejection.kind,
        RedirectRejectionKind::ExemptHostOriginMismatch
    );
    assert!(
        rejection.details.contains("nexus.corp:8443"),
        "rejection must name the origin it refused: {}",
        rejection.details
    );

    guard
        .evaluate(&previous, &url("https://nexus.corp/demo-1.0.jar"))
        .expect("the configured origin is still followed");
    // An unexempt name carries no address here and no exemption later, so
    // the policy defers to the resolver rather than second-guessing it.
    guard
        .evaluate(&previous, &url("https://cdn.example/demo-1.0.jar"))
        .expect("unexempt hostname is screened by the resolver");
}

/// With a proxy in play the proxy resolves hostnames, so
/// [`GlobalOnlyResolver`] never sees the target and a hostname hop is
/// followed only to an origin the user configured.
#[test]
fn proxied_redirect_requires_a_configured_target_origin() {
    let guard = RedirectGuard {
        root_issuer: None,
        origins: origin_set(["https://mirror.example", "https://cdn.example"]),
        exempt_hosts: frozen_hosts(["mirror.example", "cdn.example", "proxy.corp"]),
        proxy_active: true,
    };
    let previous = [url("https://mirror.example/demo-1.0.jar")];

    for target in [
        "https://admin.internal/",
        "https://cdn.example:8443/demo-1.0.jar",
        "https://elsewhere.example/demo-1.0.jar",
        // Finding 4's exemption must not become authority: the proxy host
        // is connectable, not a legitimate redirect target.
        "https://proxy.corp/demo-1.0.jar",
    ] {
        let Err(rejection) = guard.evaluate(&previous, &url(target)) else {
            panic!("{target} must not be followed through a proxy");
        };
        assert_eq!(
            rejection.kind,
            RedirectRejectionKind::ProxiedTargetNotConfigured,
            "unexpected rejection for {target}: {rejection}"
        );
    }

    guard
        .evaluate(&previous, &url("https://cdn.example/demo-1.0.jar"))
        .expect("a configured origin is still reachable through the proxy");
    // IP literals still carry their address, so the literal screen decides.
    guard
        .evaluate(&previous, &url("https://93.184.216.34/demo-1.0.jar"))
        .expect("global literal target stays followable");
    let rejection = guard
        .evaluate(&previous, &url("https://169.254.169.254/latest/meta-data"))
        .expect_err("non-global literal stays rejected under a proxy");
    assert_eq!(rejection.kind, RedirectRejectionKind::NonGlobalTarget);
}

/// A proxy host is exempt from the address screen so it can be dialled, and
/// nothing more: with no proxy active the same host is still refused as a
/// redirect target because no configured origin matches it.
#[test]
fn exempt_proxy_host_is_not_a_redirect_target() {
    let guard = RedirectGuard {
        root_issuer: None,
        origins: origin_set(["https://mirror.example"]),
        exempt_hosts: frozen_hosts(["mirror.example", "proxy.corp"]),
        proxy_active: false,
    };
    let previous = [url("https://mirror.example/demo-1.0.jar")];

    let rejection = guard
        .evaluate(&previous, &url("https://proxy.corp/demo-1.0.jar"))
        .expect_err("proxy host must not be a redirect target");
    assert_eq!(
        rejection.kind,
        RedirectRejectionKind::ExemptHostOriginMismatch
    );
}

/// Repository and mirror URLs must land in both sets, and a configuration
/// with no proxy must leave the policy in its unproxied mode.
#[test]
fn redirect_guard_reads_repository_endpoints() {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = rv_config::ResolvedPaths::for_testing().expect("paths");
    let config = rv_config::Config::for_testing_with_repos(
        temp.path().to_path_buf(),
        paths,
        vec![rv_config::RepoConfig {
            id: Some("internal".to_string()),
            url: "https://nexus.corp:8443/repository/maven/".to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: None,
            releases_update_policy: None,
            releases_checksum_policy: None,
            snapshots_checksum_policy: None,
        }],
    );

    let guard = redirect_guard(&config).expect("guard");
    assert!(guard.origins.contains("https://nexus.corp:8443"));
    assert!(guard.exempt_hosts.contains("nexus.corp"));
    assert!(
        !guard.proxy_active,
        "no configured proxy must leave the proxy screen off"
    );
}

/// Every IPv4 special-purpose block this screen excludes, at both edges,
/// paired with the routable addresses immediately outside it. The
/// neighbours are the point: an off-by-one in a mask silently either opens
/// a private range or blackholes a public one.
#[test]
fn ipv4_special_purpose_blocks_are_excluded() {
    let cases: &[(&str, &str, [&str; 2], &[&str])] = &[
        (
            "0.0.0.0/8",
            "this network",
            ["0.0.0.0", "0.255.255.255"],
            &["1.0.0.0"],
        ),
        (
            "10.0.0.0/8",
            "private",
            ["10.0.0.0", "10.255.255.255"],
            &["9.255.255.255", "11.0.0.0"],
        ),
        (
            "100.64.0.0/10",
            "shared address space",
            ["100.64.0.0", "100.127.255.255"],
            &["100.63.255.255", "100.128.0.0"],
        ),
        (
            "127.0.0.0/8",
            "loopback",
            ["127.0.0.0", "127.255.255.255"],
            &["126.255.255.255", "128.0.0.1"],
        ),
        (
            "169.254.0.0/16",
            "link local",
            ["169.254.0.0", "169.254.169.254"],
            &["169.253.255.255", "169.255.0.0"],
        ),
        (
            "172.16.0.0/12",
            "private",
            ["172.16.0.0", "172.31.255.255"],
            &["172.15.255.255", "172.32.0.0"],
        ),
        (
            "192.0.0.0/24",
            "IETF protocol assignments",
            ["192.0.0.0", "192.0.0.255"],
            // The two globally-reachable /32s inside the block are
            // excluded with it, deliberately.
            &["191.255.255.255", "192.0.1.0"],
        ),
        (
            "192.0.2.0/24",
            "documentation TEST-NET-1",
            ["192.0.2.0", "192.0.2.255"],
            &["192.0.1.255", "192.0.3.0"],
        ),
        (
            "192.88.99.0/24",
            "deprecated 6to4 relay anycast",
            ["192.88.99.0", "192.88.99.255"],
            &["192.88.98.255", "192.88.100.0"],
        ),
        (
            "192.168.0.0/16",
            "private",
            ["192.168.0.0", "192.168.255.255"],
            &["192.167.255.255", "192.169.0.0"],
        ),
        (
            "198.18.0.0/15",
            "benchmarking",
            ["198.18.0.0", "198.19.255.255"],
            &["198.17.255.255", "198.20.0.0"],
        ),
        (
            "198.51.100.0/24",
            "documentation TEST-NET-2",
            ["198.51.100.0", "198.51.100.255"],
            &["198.51.99.255", "198.51.101.0"],
        ),
        (
            "203.0.113.0/24",
            "documentation TEST-NET-3",
            ["203.0.113.0", "203.0.113.255"],
            &["203.0.112.255", "203.0.114.0"],
        ),
        (
            "224.0.0.0/4",
            "multicast",
            ["224.0.0.0", "239.255.255.255"],
            &["223.255.255.255"],
        ),
        (
            "240.0.0.0/4",
            "reserved, including the broadcast address",
            ["240.0.0.0", "255.255.255.255"],
            // Nothing routable borders this block: 239.255.255.255 below it
            // is multicast, and above it is the end of the address space.
            &[],
        ),
    ];

    for (block, description, excluded, neighbours) in cases {
        for address in excluded {
            let addr: IpAddr = address.parse().expect("address");
            assert!(
                !is_globally_routable(addr),
                "{address} is in {block} ({description}) and must be non-global"
            );
        }
        for neighbour in *neighbours {
            let addr: IpAddr = neighbour.parse().expect("address");
            assert!(
                is_globally_routable(addr),
                "{neighbour} sits outside {block} ({description}) and must stay global"
            );
        }
    }

    for public in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "223.255.255.255"] {
        let addr: IpAddr = public.parse().expect("address");
        assert!(is_globally_routable(addr), "{public} should be global");
    }
}

/// The IPv6 half of the same table, plus the embedded-IPv4 forms that would
/// otherwise launder an RFC1918 destination through a v6 literal.
#[test]
fn ipv6_special_purpose_blocks_are_excluded() {
    let cases: &[(&str, &str, &[&str], &[&str])] = &[
        ("::/128", "unspecified", &["::"], &[]),
        ("::1/128", "loopback", &["::1"], &[]),
        (
            "100::/64",
            "discard only",
            &["100::", "100::ffff:ffff:ffff:ffff"],
            // The block immediately above is the dummy prefix, also
            // excluded, so the nearest routable neighbour is one /64 further
            // out.
            &["100:0:0:2::1", "101::1"],
        ),
        (
            "100:0:0:1::/64",
            "dummy prefix",
            &["100:0:0:1::", "100:0:0:1:ffff:ffff:ffff:ffff"],
            // Below it sits the discard-only prefix, also excluded.
            &["100:0:0:2::1"],
        ),
        (
            "64:ff9b:1::/48",
            "local-use IPv4/IPv6 translation",
            &["64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff"],
            &["64:ff9b:2::1"],
        ),
        (
            "2001::/23",
            "IETF protocol assignments (Teredo, benchmarking, ORCHIDv2)",
            &[
                "2001::",
                "2001:1::1",
                "2001:2::1",
                "2001:20::1",
                "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            &["2000::1", "2001:200::1"],
        ),
        (
            "2001:db8::/32",
            "documentation",
            &["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"],
            &["2001:db7::1", "2001:db9::1"],
        ),
        (
            "2002::/16",
            "6to4, which embeds an arbitrary IPv4 destination",
            &[
                "2002::",
                "2002:a00:1::1",
                "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            &["2003::1"],
        ),
        (
            "3fff::/20",
            "documentation",
            &["3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"],
            &["3ffe::1", "3fff:1000::1"],
        ),
        (
            "5f00::/16",
            "segment routing SIDs",
            &["5f00::", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            &["5eff:ffff::1", "5f01::1"],
        ),
        (
            "fc00::/7",
            "unique local",
            &[
                "fc00::1",
                "fd00::1",
                "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            &["fbff:ffff::1"],
        ),
        (
            "fe80::/10",
            "link local",
            &["fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            &[],
        ),
        (
            "fec0::/10",
            "deprecated site local",
            &["fec0::1", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            &[],
        ),
        ("ff00::/8", "multicast", &["ff02::1", "ff05::1:3"], &[]),
    ];

    for (block, description, excluded, neighbours) in cases {
        for address in *excluded {
            let addr: IpAddr = address.parse().expect("address");
            assert!(
                !is_globally_routable(addr),
                "{address} is in {block} ({description}) and must be non-global"
            );
        }
        for neighbour in *neighbours {
            let addr: IpAddr = neighbour.parse().expect("address");
            assert!(
                is_globally_routable(addr),
                "{neighbour} sits outside {block} ({description}) and must stay global"
            );
        }
    }

    for embedded in [
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:0.0.0.1",
        // Deprecated IPv4-compatible form of 10.0.0.1.
        "::10.0.0.1",
        // Well-known NAT64 prefix carrying a private destination.
        "64:ff9b::10.0.0.1",
        "64:ff9b::169.254.169.254",
    ] {
        let addr: IpAddr = embedded.parse().expect("address");
        assert!(
            !is_globally_routable(addr),
            "{embedded} embeds a non-global IPv4 address and must be rejected"
        );
    }

    for public in [
        "2606:4700:4700::1111",
        "2a00:1450:4001:80e::200e",
        // A DNS64 network answers with these for every public destination,
        // so the well-known NAT64 prefix must stay usable.
        "64:ff9b::8.8.8.8",
        "::ffff:8.8.8.8",
    ] {
        let addr: IpAddr = public.parse().expect("address");
        assert!(is_globally_routable(addr), "{public} should be global");
    }
}

#[test]
fn dns_screen_accepts_public_answer() {
    let addrs = vec![
        "8.8.8.8:443".parse().expect("socket address"),
        "[2606:4700:4700::1111]:443"
            .parse()
            .expect("socket address"),
    ];
    let screened =
        screen_resolved_addrs("cdn.example.com", false, addrs.clone()).expect("public answer");
    assert_eq!(screened, addrs);
}

/// A rebinding answer that mixes a public and a private address must be
/// rejected wholesale: the connector uses the addresses returned here, so
/// keeping the public one would still leave the private one reachable.
#[test]
fn dns_screen_rejects_mixed_answer() {
    let addrs = vec![
        "8.8.8.8:443".parse().expect("socket address"),
        "169.254.169.254:443".parse().expect("socket address"),
    ];
    let error = screen_resolved_addrs("rebind.example.com", false, addrs)
        .expect_err("mixed answer must be rejected");
    assert_eq!(error.kind, RedirectRejectionKind::NonGlobalTarget);
    assert!(
        error.details.contains("169.254.169.254"),
        "rejection must name the offending address: {}",
        error.details
    );
}

#[test]
fn dns_screen_exempts_configured_host() {
    let addrs = vec!["10.1.2.3:8443".parse().expect("socket address")];
    let screened = screen_resolved_addrs("nexus.corp.internal", true, addrs.clone())
        .expect("configured host may be private");
    assert_eq!(screened, addrs);
}

#[tokio::test]
async fn resolver_rejects_loopback_name_unless_configured() {
    let resolver = GlobalOnlyResolver {
        exempt_hosts: TrustedHosts::default(),
    };
    let error = resolver
        .resolve("localhost".parse().expect("name"))
        .await
        .err()
        .expect("localhost must not resolve for an unconfigured host");
    assert!(
        error.to_string().contains("not globally routable"),
        "resolver rejection must explain itself: {error}"
    );

    let resolver = GlobalOnlyResolver {
        exempt_hosts: host_set(["localhost"]),
    };
    let addrs = resolver
        .resolve("localhost".parse().expect("name"))
        .await
        .expect("configured host resolves");
    assert!(
        addrs.count() > 0,
        "configured loopback host must still resolve"
    );
}

/// A `RepoClient` wired the way [`RepoClient::new`] wires one: a
/// redirect-capable client screening against the frozen configured set, and
/// a same-origin-only client screening against the live runtime set that
/// `trust_repositories` grows. Requests pick between them exactly as
/// production does, through `http_client_for`.
fn screened_test_client(guard: RedirectGuard) -> (RepoClient, tempfile::TempDir) {
    let (mut client, tmp) = test_client();
    let trusted_hosts = guard.exempt_hosts.to_runtime_set();
    client.client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .redirect(trusted_redirect_policy(guard.clone()))
        .dns_resolver(Arc::new(GlobalOnlyResolver {
            exempt_hosts: guard.exempt_hosts.clone(),
        }))
        .build()
        .expect("screened test client");
    client.runtime_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .dns_resolver(Arc::new(GlobalOnlyResolver {
            exempt_hosts: trusted_hosts.clone(),
        }))
        .build()
        .expect("runtime test client");
    client.fetch = FetchConfig {
        retries: 0,
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    client.root_redirects = Arc::new(RootRedirectClients {
        guard: guard.clone(),
        accept_invalid_certs: true,
        ..Default::default()
    });
    client.configured_hosts = guard.exempt_hosts;
    client.trusted_hosts = trusted_hosts;
    (client, tmp)
}

/// `localhost` stands in for `nexus.corp.internal`: a *name* that resolves
/// onto an address the screen rejects. Only a name exercises the resolver
/// at all — an IP literal never reaches one, which is why the mock servers
/// elsewhere in this file cannot see this class of failure.
fn loopback_name_url(port: u16, path: &str) -> Url {
    url(&format!("https://localhost:{port}{path}"))
}

/// The routing rule the split rests on: only a host `rv.toml` named is
/// served by the redirect-capable client, and no trust grant can move a
/// host onto it afterwards.
#[test]
fn only_configured_hosts_reach_the_redirect_capable_client() {
    let (client, _tmp) =
        screened_test_client(origins_guard(origin_set(["https://mirror.example"])));

    assert!(
        std::ptr::eq(
            client
                .http_client_for(&url("https://mirror.example/demo-1.0.jar"))
                .unwrap()
                .as_ref(),
            &client.client
        ),
        "a configured host is served by the redirect-capable client"
    );
    let runtime_url = url("https://nexus.corp.internal/demo-1.0.jar");
    for stage in ["before the grant", "after the grant"] {
        assert!(
            std::ptr::eq(
                client.http_client_for(&runtime_url).unwrap().as_ref(),
                &client.runtime_client
            ),
            "an unconfigured host must stay on the same-origin-only client {stage}"
        );
        client.trust_repositories(&[Repository::new(
            None,
            "https://nexus.corp.internal/repo/".to_string(),
            true,
            false,
        )]);
    }
    assert!(client.trusts_host("nexus.corp.internal"));
}

/// A hostname nothing has trusted still fails the address screen when it
/// resolves onto a private network, and fails before any connection.
#[tokio::test]
async fn untrusted_private_hostname_fails_the_address_screen() {
    let repo = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let (client, _tmp) = screened_test_client(origins_guard(HashSet::new()));

    let repo_url = loopback_name_url(repo.addr.port(), "/demo-1.0.jar");
    let error = fetch_redirect_test(
        client.http_client_for(&repo_url).unwrap().as_ref(),
        &repo_url,
    )
    .await
    .expect_err("an untrusted private hostname must not be dialled");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::NonGlobalTarget,
                ..
            }
        ),
        "expected a non-global rejection, got {error:?}"
    );
    assert!(
        repo.request.lock().expect("repo request").is_none(),
        "the screened host must not be contacted"
    );
}

/// The regression: a repository the root POM declares becomes trusted
/// part-way through a resolve, and the client that is already running the
/// resolve has to honour that without being rebuilt. Freezing the exempt
/// set at construction left every such fetch failing the address screen —
/// the normal shape of an on-prem registry named only in the project's POM.
#[tokio::test]
async fn runtime_trusted_repository_host_fetches_without_a_client_rebuild() {
    let repo = spawn_https_stub(|_| ok_response(b"artifact bytes"));
    let repo_url = loopback_name_url(repo.addr.port(), "/demo-1.0.jar");
    let (client, _tmp) = screened_test_client(origins_guard(HashSet::new()));

    // Routing sends an unconfigured host to the same-origin-only client.
    assert!(
        std::ptr::eq(
            client.http_client_for(&repo_url).unwrap().as_ref(),
            &client.runtime_client
        ),
        "an unconfigured repository host must not be served by the redirect-capable client"
    );
    let error = fetch_redirect_test(
        client.http_client_for(&repo_url).unwrap().as_ref(),
        &repo_url,
    )
    .await
    .expect_err("the host is not trusted yet");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::NonGlobalTarget,
                ..
            }
        ),
        "expected a non-global rejection before the grant, got {error:?}"
    );

    // What `RepoBackend::extend_repos_trusted` does when the root POM
    // declares a repository the configuration never named.
    client.trust_repositories(&[Repository::new(
        Some("internal".to_string()),
        loopback_name_url(repo.addr.port(), "/repo/").to_string(),
        true,
        false,
    )]);
    assert!(client.trusts_host("LOCALHOST"), "the grant is case-blind");

    let bytes = fetch_redirect_test(
        client.http_client_for(&repo_url).unwrap().as_ref(),
        &repo_url,
    )
    .await
    .expect("a trusted repository host must resolve and fetch");
    assert_eq!(bytes, Bytes::from_static(b"artifact bytes"));
}

/// Runtime trust buys a direct connection and nothing else: a hostile
/// mirror bouncing `rv` at another port of a private host the root POM
/// happened to name is the SSRF this whole screen exists to stop.
///
/// The redirect-capable client's resolver never sees the grant, so the
/// target is screened on its addresses and the connection dies there.
#[tokio::test]
async fn runtime_trusted_host_is_still_not_a_redirect_target() {
    let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let target_url = loopback_name_url(target.addr.port(), "/secret").to_string();
    let source = spawn_https_stub(move |_| redirect_response(&target_url));
    let source_url = url(&format!("https://127.0.0.1:{}/start", source.addr.port()));
    // Only the source is configured in `rv.toml`; the target host is
    // trusted at runtime, the way a root-POM repository is.
    let configured = HashSet::from([source_url.origin().ascii_serialization()]);
    let (client, _tmp) = screened_test_client(origins_guard(configured));
    client.trust_repositories(&[Repository::new(
        None,
        loopback_name_url(target.addr.port(), "/repo/").to_string(),
        true,
        false,
    )]);

    let error = fetch_redirect_test(
        client.http_client_for(&source_url).unwrap().as_ref(),
        &source_url,
    )
    .await
    .expect_err("a runtime-trusted host is not a redirect target");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::NonGlobalTarget,
                ..
            }
        ),
        "expected a non-global rejection, got {error:?}"
    );
    assert!(
        target.request.lock().expect("target request").is_none(),
        "the redirect target must not be contacted"
    );
}

/// The interleaving the port-blind exemption made possible: a hostile
/// configured mirror redirects to a host nothing trusts yet, the policy
/// permits the hop *because* the resolver is expected to screen it, and a
/// concurrent reactor task then trusts a direct repository on that same
/// host. A redirect target that was not exempt at policy-evaluation time
/// must be DNS-screened at connect time, regardless of concurrent trust
/// grants — otherwise the grant retroactively licenses the hop, at any
/// port, on a private machine the user only meant to fetch artifacts from.
///
/// Driven in order rather than raced: the three steps are the ones the two
/// tasks interleave, and the assertion is that step 3 cannot change what
/// step 4 decides.
#[tokio::test]
async fn trust_granted_after_policy_evaluation_leaves_the_target_screened() {
    let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
    let target_url = loopback_name_url(target.addr.port(), "/secret");
    let redirect_to = target_url.to_string();
    let source = spawn_https_stub(move |_| redirect_response(&redirect_to));
    let source_url = url(&format!("https://127.0.0.1:{}/start", source.addr.port()));
    let guard = origins_guard(HashSet::from([source_url.origin().ascii_serialization()]));
    let (client, _tmp) = screened_test_client(guard.clone());

    // (1) and (2): the hop is evaluated while nothing trusts the target
    // host, and permitted on the expectation that the resolver screens the
    // addresses the name answers with.
    guard
        .evaluate(std::slice::from_ref(&source_url), &target_url)
        .expect("an unexempt hostname target is left to the resolver");

    // (3) a concurrent task grants the host direct-connection trust, the
    // way a root-POM repository on the same machine would.
    client.trust_repositories(&[Repository::new(
        None,
        loopback_name_url(target.addr.port(), "/repo/").to_string(),
        true,
        false,
    )]);
    assert!(
        client.trusts_host("localhost"),
        "the grant must have landed"
    );

    // (4) the redirect-capable client screens the target anyway: its
    // resolver reads the frozen configured set, which runtime trust cannot
    // reach. `configured_hosts` is the same handle that client's resolver
    // holds, so this is the state the connection would see.
    assert!(
        !client.configured_hosts.contains("localhost"),
        "runtime trust must never reach the configured set"
    );
    let resolver = GlobalOnlyResolver {
        exempt_hosts: client.configured_hosts.clone(),
    };
    let error = resolver
        .resolve("localhost".parse().expect("name"))
        .await
        .err()
        .expect("the permitted redirect target must still be screened");
    assert!(
        error.to_string().contains("non-global address"),
        "resolver rejection must explain itself: {error}"
    );

    // And end to end, with the grant already in place before the request
    // runs: the hop is followed no further than the address screen.
    let error = fetch_redirect_test(
        client.http_client_for(&source_url).unwrap().as_ref(),
        &source_url,
    )
    .await
    .expect_err("a grant taken mid-flight must not unscreen the target");
    assert!(
        matches!(
            error,
            RepoError::RedirectRejected {
                kind: RedirectRejectionKind::NonGlobalTarget,
                ..
            }
        ),
        "expected a non-global rejection, got {error:?}"
    );
    assert!(
        target.request.lock().expect("target request").is_none(),
        "the redirect target must not be contacted"
    );
}

/// A redirect that switches origin (e.g. attacker mirror sends
/// `302 Location: http://other-host/`) must be rejected
/// even when the redirect chain is short. Otherwise a hostile mirror
/// can bypass TLS and the per-repository origin check by replying with
/// a redirect to a malicious server.
#[tokio::test]
async fn redirect_policy_rejects_cross_origin() {
    let target = StubServer::start(|_| Response::new(200, "hello"));
    let addr_b = target.addr();
    let source = StubServer::start(move |_| {
        Response::new(302, "").header("Location", format!("http://{addr_b}/jar"))
    });
    let addr_a = source.addr();

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .build()
        .expect("client");
    let result = client.get(format!("http://{addr_a}/jar")).send().await;

    assert!(
        result.is_err(),
        "cross-origin redirect must surface as an error, got {result:?}"
    );
    assert_eq!(
        target.connections(),
        0,
        "cross-origin redirect target must NOT have been contacted"
    );
}

/// Same-origin redirects are still allowed (servers that bounce
/// /foo -> /foo/ within the same host must keep working).
#[tokio::test]
async fn redirect_policy_allows_same_origin() {
    let counter = AtomicU32::new(0);
    let server = StubServer::start(move |_| {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            Response::new(302, "").header("Location", "/target")
        } else {
            Response::new(200, "ok")
        }
    });
    let addr = server.addr();

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .build()
        .expect("client");
    let response = client
        .get(format!("http://{addr}/start"))
        .send()
        .await
        .expect("same-origin redirect should be followed");
    assert!(response.status().is_success());
}

/// Long redirect chains on the same origin are still capped
/// (defence against denial-of-service or loops).
#[tokio::test]
async fn redirect_policy_caps_chain_length() {
    let server = StubServer::start(|_| Response::new(302, "").header("Location", "/loop"));
    let addr = server.addr();

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .build()
        .expect("client");
    let url = Url::parse(&format!("http://{addr}/loop")).expect("loop URL");
    let result = fetch_redirect_test(&client, &url).await;
    assert!(
        matches!(
            result,
            Err(RepoError::RedirectRejected {
                kind: RedirectRejectionKind::ChainLimit,
                ..
            })
        ),
        "redirect chain over the cap must name the chain limit, got {result:?}"
    );
}

#[test]
fn repeated_mirror_redirect_failures_emit_one_summary_warning() {
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct VecWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for VecWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("warning output")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for VecWriter {
        type Writer = VecWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let tracker = MirrorFailureTracker::default();
    let mirror = Repository::new(
        Some("object-store-mirror".to_string()),
        "https://registry.example/maven/".to_string(),
        true,
        false,
    );
    let error = RepoError::RedirectRejected {
        kind: RedirectRejectionKind::HttpsDowngrade,
        details: "test redirect".to_string(),
    };
    for _ in 0..MIRROR_FAILURE_SUMMARY_THRESHOLD {
        tracker.record(&mirror, &error);
    }

    let output = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(VecWriter(Arc::clone(&output)))
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .without_time()
        .finish();
    rv_test_support::with_default(subscriber, || tracker.report());

    let rendered =
        String::from_utf8(output.lock().expect("warning output").clone()).expect("UTF-8 warning");
    assert!(
        rendered.contains(
            "mirror object-store-mirror (https://registry.example/maven/) failed 3 fetches"
        ),
        "summary must name the mirror and failure count: {rendered}"
    );
    assert!(
        rendered.contains("cross-origin redirect rejected: target is not HTTPS"),
        "summary must name the rejection class: {rendered}"
    );
    assert!(
        rendered.contains("results came from origin repositories"),
        "summary must disclose origin fallback: {rendered}"
    );
    assert_eq!(
        rendered
            .matches("results came from origin repositories")
            .count(),
        1,
        "repeated failures must collapse into one summary: {rendered}"
    );
}

#[tokio::test]
async fn artifact_fetch_reports_successful_mirror_as_provenance() {
    use rv_config::{ArtifactKey, MirrorConfig};
    use rv_store::Store;
    use sha2::{Digest, Sha256};

    let body = b"mirror artifact";
    let digest = hex::encode(Sha256::digest(body));
    let checksum: StubHandler = Box::new(move |request| {
        assert!(request.contains(".sha256"), "first request is checksum");
        Response::new(200, digest.as_bytes())
    });
    let artifact: StubHandler = Box::new(move |request| {
        assert!(!request.contains(".sha"), "second request is artifact");
        Response::new(200, body)
    });
    let (mirror_addr, mirror_hits) = spawn_stub_seq(vec![checksum, artifact]);
    let mirror_url = format!("http://{mirror_addr}/");
    let (client, _cache) = test_client_with_mirrors(vec![MirrorConfig {
        id: Some("serving-mirror".to_string()),
        url: mirror_url.clone(),
        mirror_of: vec!["central".to_string()],
    }]);
    let origin = Repository::new(
        Some("central".to_string()),
        "http://127.0.0.1:9/".to_string(),
        true,
        false,
    );
    let request = ArtifactRequest::new("com.example", "demo", "1.0.0");
    let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    let store_dir = tempfile::tempdir().expect("store tempdir");
    let store = Store::open(store_dir.path()).expect("store");

    let (_, serving_repository) = client
        .fetch_artifact_to_store_and_index_with_repository(&origin, &request, &store, &key)
        .await
        .expect("mirror artifact fetch");
    assert_eq!(serving_repository, mirror_url);
    assert_eq!(mirror_hits.connections(), 2);
}

#[tokio::test]
async fn file_mirror_bypasses_pom_and_metadata_cache() {
    let dir = tempfile::tempdir().unwrap();
    let mirror_url = Url::from_directory_path(dir.path()).unwrap().to_string();
    let (client, _cache) = test_client_with_mirrors(vec![rv_config::MirrorConfig {
        id: Some("local".into()),
        url: mirror_url.clone(),
        mirror_of: vec!["origin".into()],
    }]);
    let origin = Repository::new(
        Some("origin".into()),
        "https://origin.invalid/",
        true,
        false,
    );
    let request = ArtifactRequest::new("test", "a", "1");
    let coord = "test:a:1".parse::<Coord>().unwrap();
    let pom_path = request.pom().to_path();
    let metadata_path = "test/a/maven-metadata.xml";
    std::fs::create_dir_all(dir.path().join("test/a/1")).unwrap();
    let scope = RepoClient::cache_scope_key(&origin.url, &mirror_url);
    let metadata_scope =
        RepoClient::metadata_cache_scope(&client.effective_repository(&origin), &scope, "1");
    for version in ["1", "2"] {
        let pom = format!("<project><version>{version}</version></project>");
        let metadata = format!(
            "<metadata><versioning><versions><version>{version}</version></versions></versioning></metadata>"
        );
        std::fs::write(dir.path().join(&pom_path), &pom).unwrap();
        std::fs::write(dir.path().join(metadata_path), metadata).unwrap();
        for offline in [false, true] {
            let client = client.clone().with_offline(offline);
            assert_eq!(
                client.fetch_pom(&origin, &request).await.unwrap(),
                pom.as_bytes()
            );
            assert_eq!(
                client
                    .fetch_metadata(&origin, &coord)
                    .await
                    .unwrap()
                    .versions,
                vec![version]
            );
        }
        assert!(
            client
                .cache
                .get(CacheTable::Pom, &scope, &pom_path)
                .unwrap()
                .is_none()
        );
        assert!(
            client
                .cache
                .get(CacheTable::VersionList, &metadata_scope, metadata_path)
                .unwrap()
                .is_none()
        );
    }
    client
        .cache
        .insert_with_ttl(CacheTable::Pom, &scope, &pom_path, b"stale", 3600)
        .unwrap();
    client
        .cache
        .insert_with_ttl(
            CacheTable::VersionList,
            &metadata_scope,
            metadata_path,
            b"stale",
            3600,
        )
        .unwrap();
    std::fs::remove_file(dir.path().join(pom_path)).unwrap();
    std::fs::remove_file(dir.path().join(metadata_path)).unwrap();
    for offline in [false, true] {
        let client = client.clone().with_offline(offline);
        assert!(matches!(
            client.fetch_pom(&origin, &request).await,
            Err(RepoError::NotFound(_))
        ));
        assert!(matches!(
            client.fetch_metadata(&origin, &coord).await,
            Err(RepoError::NotFound(_))
        ));
    }
}

#[tokio::test]
async fn file_repository_serves_pom_and_artifact_from_disk() {
    use rv_config::ArtifactKey;
    use rv_store::Store;

    let repo_dir = tempfile::tempdir().expect("repo dir");
    let version_dir = repo_dir.path().join("com/example/demo/1.0.0");
    std::fs::create_dir_all(&version_dir).unwrap();
    let pom = b"<project><modelVersion>4.0.0</modelVersion></project>";
    std::fs::write(version_dir.join("demo-1.0.0.pom"), pom).unwrap();
    std::fs::write(
        version_dir.join("demo-1.0.0.pom.sha1"),
        crate::fetch::sha1_hex(pom),
    )
    .unwrap();
    std::fs::write(version_dir.join("demo-1.0.0.jar"), b"jar bytes").unwrap();

    let url = Url::from_directory_path(repo_dir.path())
        .unwrap()
        .to_string();
    let repo = Repository::new(Some("local".to_string()), url, true, false);
    let (client, _cache) = test_client();
    let client = client.with_allow_missing_checksums(true);
    let request = ArtifactRequest::new("com.example", "demo", "1.0.0");

    let bytes = client.fetch_pom(&repo, &request).await.expect("pom");
    assert_eq!(bytes.as_ref(), pom);

    let store_dir = tempfile::tempdir().expect("store dir");
    let store = Store::open(store_dir.path()).expect("store");
    let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    client
        .fetch_artifact_to_store_and_index_with_repository(&repo, &request, &store, &key)
        .await
        .expect("jar from a file repository");

    let missing = ArtifactRequest::new("com.example", "absent", "1.0.0");
    assert!(matches!(
        client.fetch_pom(&repo, &missing).await,
        Err(RepoError::NotFound(_))
    ));
}

#[tokio::test]
async fn file_repository_reads_plain_snapshot_layout_without_sidecars() {
    let repo_dir = tempfile::tempdir().expect("repo dir");
    let version_dir = repo_dir.path().join("com/example/demo/9-SNAPSHOT");
    std::fs::create_dir_all(&version_dir).unwrap();
    let pom = b"<project><modelVersion>4.0.0</modelVersion></project>";
    std::fs::write(version_dir.join("demo-9-SNAPSHOT.pom"), pom).unwrap();

    let url = Url::from_directory_path(repo_dir.path())
        .unwrap()
        .to_string();
    let repo = Repository::new(Some("local".to_string()), url, true, true);
    let (client, _cache) = test_client();
    let request = ArtifactRequest::new("com.example", "demo", "9-SNAPSHOT");

    for offline in [false, true] {
        let bytes = client
            .clone()
            .with_offline(offline)
            .fetch_pom(&repo, &request)
            .await
            .expect("plain -SNAPSHOT pom with no metadata or checksum files");
        assert_eq!(bytes.as_ref(), pom);
    }
}

#[test]
fn effective_repository_takes_the_mirror_id() {
    let (client, _cache) = test_client_with_mirrors(vec![rv_config::MirrorConfig {
        id: Some("registry".to_string()),
        url: "https://registry.example/maven/".to_string(),
        mirror_of: vec!["central".to_string()],
    }]);
    let origin = Repository::new(
        Some("central".to_string()),
        "https://repo1.maven.org/maven2/",
        true,
        false,
    );
    assert_eq!(
        client.effective_repository(&origin).id.as_deref(),
        Some("registry")
    );
    let other = Repository::new(Some("other".to_string()), "https://o.example/", true, false);
    assert_eq!(
        client.effective_repository(&other).id.as_deref(),
        Some("other")
    );
}

#[test]
fn effective_repository_url_applies_mirror_without_network_fetch() {
    let mirror_url = "https://registry.example/maven/";
    let (client, _cache) = test_client_with_mirrors(vec![rv_config::MirrorConfig {
        id: Some("registry".to_string()),
        url: mirror_url.to_string(),
        mirror_of: vec!["central".to_string()],
    }]);
    let origin = Repository::new(
        Some("central".to_string()),
        "https://repo1.maven.org/maven2/",
        true,
        false,
    );

    assert_eq!(client.effective_repository_url(&origin), mirror_url);
}

#[tokio::test]
async fn artifact_fetch_reports_origin_after_mirror_fallback() {
    use rv_config::{ArtifactKey, MirrorConfig};
    use rv_store::Store;
    use sha2::{Digest, Sha256};

    let unavailable: StubHandler = Box::new(|_| Response::new(503, ""));
    let unavailable_again: StubHandler = Box::new(|_| Response::new(503, ""));
    let (mirror_addr, mirror_hits) = spawn_stub_seq(vec![unavailable, unavailable_again]);

    let body = b"origin artifact";
    let digest = hex::encode(Sha256::digest(body));
    let checksum: StubHandler = Box::new(move |_| Response::new(200, digest.as_bytes()));
    let artifact: StubHandler = Box::new(move |_| Response::new(200, body));
    let (origin_addr, origin_hits) = spawn_stub_seq(vec![checksum, artifact]);
    let origin_url = format!("http://{origin_addr}/");
    let (client, _cache) = test_client_with_mirrors(vec![MirrorConfig {
        id: Some("broken-mirror".to_string()),
        url: format!("http://{mirror_addr}/"),
        mirror_of: vec!["central".to_string()],
    }]);
    let origin = Repository::new(Some("central".to_string()), origin_url.clone(), true, false);
    let request = ArtifactRequest::new("com.example", "demo", "1.0.0");
    let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
    let store_dir = tempfile::tempdir().expect("store tempdir");
    let store = Store::open(store_dir.path()).expect("store");

    let (_, serving_repository) = client
        .fetch_artifact_to_store_and_index_with_repository(&origin, &request, &store, &key)
        .await
        .expect("origin fallback artifact fetch");
    assert_eq!(serving_repository, origin_url);
    assert_eq!(mirror_hits.connections(), 2);
    assert_eq!(origin_hits.connections(), 2);
}

/// THE launch-blocker fix: a repo (like Maven Central) that serves only a
/// SHA-1 sidecar, no SHA-256, must resolve by DEFAULT. The client prefers
/// SHA-256, finds it 404, falls back to the `.sha1` sidecar (emitting the
/// `WEAK_HASH_FALLBACK` warning), and returns it. The durable rv.lock pin
/// is the locally-computed SHA-256 of the downloaded bytes, recorded
/// independently of which sidecar gated the fetch (see the resolver), so
/// the SHA-1 fallback never weakens the lockfile.
#[tokio::test]
async fn fetch_checksum_default_accepts_sha1_only_repo() {
    use crate::fetch::ChecksumAlgorithm;
    use crate::repository::Repository;

    // Stub: SHA-256 -> 404; SHA-1 -> 200. Default config must probe both
    // and accept the SHA-1 sidecar.
    let sha1_hits = Arc::new(AtomicU32::new(0));
    let sha1_hits_clone = sha1_hits.clone();
    let server = StubServer::start(move |request| {
        if request.path.contains(".sha256") {
            Response::new(404, "")
        } else if request.path.contains(".sha1") {
            sha1_hits_clone.fetch_add(1, Ordering::SeqCst);
            Response::new(200, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        } else {
            Response::new(404, "")
        }
    });
    let addr = server.addr();

    let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
    let (client, _tmp) = test_client();

    let result = client
        .fetch_checksum(&repo, "com/example/demo/1.0/demo-1.0.jar", false)
        .await
        .expect("fetch_checksum");
    let checksum = result.expect("sha1 sidecar must be accepted by default");
    assert_eq!(
        checksum.algorithm,
        ChecksumAlgorithm::Sha1,
        "default config must fall back to the .sha1 sidecar when sha256 is absent"
    );
    assert_eq!(checksum.value, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    assert_eq!(
        sha1_hits.load(Ordering::SeqCst),
        1,
        "the .sha1 sidecar must be fetched as the fallback"
    );
}

/// Spawn a stub that answers every `.sha256` request with `sha256_body`
/// and every `.sha1` request with `sha1_body`, both as 200 OK. Used by
/// the garbage-sidecar fallback tests below.
fn spawn_sidecar_stub(sha256_body: &'static str, sha1_body: &'static str) -> StubServer {
    StubServer::start(move |request| {
        Response::new(
            200,
            if request.path.contains(".sha256") {
                sha256_body
            } else {
                sha1_body
            },
        )
    })
}

/// A server that answers the `.sha256` probe with 200 + an HTML "not
/// found" page (no hex token) must not abort the probe loop: the `.sha1`
/// sidecar is still tried and accepted.
#[tokio::test]
async fn fetch_checksum_falls_back_when_sha256_body_is_garbage() {
    use crate::fetch::ChecksumAlgorithm;
    use crate::repository::Repository;

    let server = spawn_sidecar_stub(
        "<html><body>404 not found</body></html>",
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    );
    let addr = server.addr();

    let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
    let (client, _tmp) = test_client();

    let checksum = client
        .fetch_checksum(&repo, "com/example/demo/1.0/demo-1.0.jar", false)
        .await
        .expect("fetch_checksum")
        .expect("sha1 fallback must be used");
    assert_eq!(
        checksum.algorithm,
        ChecksumAlgorithm::Sha1,
        "garbage sha256 body must fall through to the .sha1 sidecar"
    );
    assert_eq!(checksum.value, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
}

/// When EVERY probed sidecar serves an unparseable body, the probe loop
/// must surface an error (the first concrete failure), not silently
/// return `Ok(None)` as if the repo published no sidecars at all.
#[tokio::test]
async fn fetch_checksum_errors_when_all_sidecar_bodies_are_garbage() {
    use crate::repository::Repository;

    let server = spawn_sidecar_stub(
        "<html><body>404 not found</body></html>",
        "<html><body>404 not found</body></html>",
    );
    let addr = server.addr();

    let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
    let (client, _tmp) = test_client();

    let result = client
        .fetch_checksum(&repo, "com/example/demo/1.0/demo-1.0.jar", false)
        .await;
    match result {
        Err(RepoError::MissingChecksum(_)) => {}
        other => panic!("expected the first parse failure to surface, got {other:?}"),
    }
}

/// Companion POMs fetched alongside a JAR must go through the
/// sidecar-verification path. A repo that serves the POM body but no
/// `.sha256`/`.sha1` sidecar must be rejected (in the
/// `require_checksums=true` default), so a hostile mirror cannot inject
/// a tampered POM with malicious `<dependency>` rows. The runtime
/// mitigation is what this test pins down; lockfile-level POM pinning
/// is the deeper fix.
#[tokio::test]
async fn pom_without_sidecar_is_refused_in_default_config() {
    use crate::artifact::ArtifactRequest;
    use crate::repository::Repository;
    use rv_store::Store;

    // Stub: POM body served, but both sidecars (.sha256 and .sha1) 404.
    let server = StubServer::start(|request| {
        if request.path.contains(".sha256") || request.path.contains(".sha1") {
            Response::new(404, "")
        } else {
            Response::new(
                200,
                "<project><dependencies><dependency><groupId>evil</groupId><artifactId>x</artifactId><version>1.0</version></dependency></dependencies></project>",
            )
        }
    });
    let addr = server.addr();

    let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
    let (client, _tmp) = test_client();
    let store_dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(store_dir.path()).expect("store");

    let pom_req = ArtifactRequest::new("com.example", "demo", "1.0.0").pom();
    let result = client
        .fetch_artifact_to_store(&repo, &pom_req, &store)
        .await;

    match result {
        Err(RepoError::MissingChecksum(_)) => {}
        other => {
            panic!("POM without sidecar must be refused with MissingChecksum, got {other:?}")
        }
    }
}

/// Concurrent POM requests must share one download, including shared parents and BOMs.
#[tokio::test]
async fn concurrent_pom_fetches_share_one_download() {
    use crate::artifact::ArtifactRequest;
    use crate::repository::Repository;
    use sha1::{Digest, Sha1};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BODY: &[u8] = b"<project><modelVersion>4.0.0</modelVersion></project>";
    let sha1 = hex::encode(Sha1::digest(BODY));
    let pom_gets = Arc::new(AtomicUsize::new(0));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let counter = Arc::clone(&pom_gets);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            let sha1 = sha1.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut total = Vec::new();
                while !total.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total.extend_from_slice(&buf[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&total).into_owned();
                // Keep the download open until all concurrent callers can join it.
                tokio::time::sleep(Duration::from_millis(150)).await;
                let (status, body): (&str, Vec<u8>) = if request.contains(".pom.sha256") {
                    ("404 Not Found", Vec::new())
                } else if request.contains(".pom.sha1") {
                    ("200 OK", sha1.into_bytes())
                } else {
                    counter.fetch_add(1, Ordering::SeqCst);
                    ("200 OK", BODY.to_vec())
                };
                let mut out = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                out.extend_from_slice(&body);
                let _ = sock.write_all(&out).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
    let (client, _tmp) = test_client();
    let req = ArtifactRequest::new("com.example", "shared-parent", "1.0.0");

    let results = futures::future::join_all((0..8).map(|_| client.fetch_pom(&repo, &req))).await;

    for result in results {
        assert_eq!(result.expect("pom fetch").as_ref(), BODY);
    }
    assert_eq!(
        pom_gets.load(Ordering::SeqCst),
        1,
        "eight concurrent callers must share a single POM download"
    );
}

/// Every outbound HTTP request must carry a
/// `User-Agent: raeva/<version>` header. Some private repos block
/// UA-less requests; reqwest's default sends nothing. Verify by
/// capturing the raw request from a stub server.
#[tokio::test]
async fn user_agent_header_is_present_on_requests() {
    let captured = Arc::new(std::sync::Mutex::new(String::new()));
    let captured_clone = captured.clone();
    let r: StubHandler = Box::new(move |req| {
        let mut guard = captured_clone.lock().expect("lock");
        *guard = req.to_string();
        Response::new(200, "ok")
    });
    let (addr, _server) = spawn_stub_seq(vec![r]);

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .user_agent(USER_AGENT)
        .build()
        .expect("client");
    let _ = client
        .get(format!("http://{addr}/jar"))
        .send()
        .await
        .expect("send");

    let request = captured.lock().expect("lock").clone();
    let expected = format!("user-agent: {USER_AGENT}");
    assert!(
        request.to_ascii_lowercase().contains(&expected),
        "request must carry raeva User-Agent, got: {request}"
    );
}

/// A wildcard mirror that substitutes the original
/// `central` repo URL with a third-party host MUST cause the default
/// (no-id) `AuthConfig` to be suppressed when the client issues a real
/// outbound request. The wiring is `MirrorSelector::resolve_with_host_change`
/// → `host_changed` → `AuthStore::for_repository_with_policy`, and this
/// test exercises the composition end-to-end through `fetch_path`.
#[tokio::test]
async fn cross_host_wildcard_mirror_suppresses_default_auth() {
    use crate::repository::Repository;
    use rv_config::{AuthConfig, MirrorConfig};

    // Server captures the raw request bytes so we can assert the
    // presence/absence of the Authorization header.
    let captured = Arc::new(std::sync::Mutex::new(String::new()));
    let captured_clone = captured.clone();
    let r: StubHandler = Box::new(move |req| {
        *captured_clone.lock().expect("lock") = req.to_string();
        Response::new(200, "ok")
    });
    let (addr, _server) = spawn_stub_seq(vec![r]);

    // Default (no-id) bearer token configured globally. Without
    // host-change suppression this would be attached to every request.
    let auth = AuthStore::from_auth_configs(&[AuthConfig {
        id: None,
        username: None,
        password: None,
        token: Some(Secret::new("hostile-cdn-token".to_string())),
    }])
    .expect("auth store");

    // Wildcard mirror replacing every repo with the stub on a different
    // host (loopback 127.0.0.1:<port>); this triggers `origins_differ`.
    let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
        id: Some("hostile".to_string()),
        url: format!("http://{addr}/"),
        mirror_of: vec!["*".to_string()],
    }]);

    let _tmp = tempfile::tempdir().expect("tempdir");
    let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
    // _tmp stays bound for the rest of the test; dropping it would
    // delete the SQLite cache file MetadataCache still holds open.
    let client = RepoClient {
        root_redirects: Arc::default(),
        client: plain_test_client(),
        runtime_client: plain_test_client(),
        auth,
        mirrors,
        fetch: FetchConfig::default(),
        progress: None,
        cache,
        offline: false,
        require_checksums: false,
        mirror_failures: Arc::new(MirrorFailureTracker::default()),
        pom_inflight: PomInflight::default(),
        absent_snapshots: AbsentSnapshots::default(),
        configured_hosts: ConfiguredHosts::default(),
        trusted_hosts: TrustedHosts::default(),
    };

    // Original repo is "https://repo.example/" (different host from the
    // stub). The mirror substitutes the URL but the host change must
    // make `for_repository_with_policy` return `None`.
    let original = Repository::new(None, "https://repo.example/maven2/", true, false);
    let (resolved, host_changed, _fallback) = client.resolve_repo_with_fallback(&original);
    assert!(
        host_changed,
        "test precondition: mirror substitution must cross hosts"
    );

    // Issue the actual GET through the mirror-resolved repo (which is
    // how production code paths reach `fetch_path` after the
    // resolve_repo+host_changed pair is computed at the entry point).
    let _ = client
        .fetch_path(&resolved, "com/example/demo/1.0/demo-1.0.jar", host_changed)
        .await
        .expect("fetch");

    let request = captured.lock().expect("lock").clone();
    let lc = request.to_ascii_lowercase();
    assert!(
        !lc.contains("authorization: bearer"),
        "default bearer token must NOT be forwarded across a wildcard mirror host change; got request:\n{request}"
    );
    assert!(
        !lc.contains("hostile-cdn-token"),
        "default credential value must not appear in the request line; got:\n{request}"
    );
}

type ModelHits = Arc<Mutex<HashMap<String, u32>>>;

/// Serve mutable repository responses with valid checksum sidecars.
/// Miss-cache tests therefore use the normal checksum policy.
async fn model_repository(status: Arc<AtomicU32>) -> (Repository, ModelHits) {
    model_repository_gated(status, None).await
}

async fn model_repository_gated(
    status: Arc<AtomicU32>,
    gate: Option<tokio::sync::watch::Receiver<bool>>,
) -> (Repository, ModelHits) {
    use sha2::{Digest, Sha256};

    let hits = ModelHits::default();
    let request_hits = Arc::clone(&hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let hits = Arc::clone(&request_hits);
            let status = Arc::clone(&status);
            let gate = gate.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut total = Vec::new();
                while !total.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total.extend_from_slice(&buf[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&total);
                let path = request.split_whitespace().nth(1).expect("path");
                if !path.contains(".sha") {
                    *hits.lock().unwrap().entry(path.to_string()).or_default() += 1;
                }
                if let Some(mut gate) = gate {
                    gate.wait_for(|released| *released).await.unwrap();
                }
                let body = if path.contains("maven-metadata.xml") {
                    br#"<metadata><versioning><snapshotVersions><snapshotVersion>
                      <extension>pom</extension><value>1.0-20261010.000000-1</value>
                    </snapshotVersion></snapshotVersions></versioning></metadata>"#
                        .as_slice()
                } else {
                    b"<project><modelVersion>4.0.0</modelVersion></project>".as_slice()
                };
                let status = status.load(Ordering::SeqCst);
                let body = if status != 200 {
                    Vec::new()
                } else if path.ends_with(".sha256") {
                    hex::encode(Sha256::digest(body)).into_bytes()
                } else {
                    body.to_vec()
                };
                let mut response = format!(
                    "HTTP/1.1 {status} Stub\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                response.extend_from_slice(&body);
                let _ = sock.write_all(&response).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (
        Repository::new(None, format!("http://{addr}/"), true, true),
        hits,
    )
}

#[tokio::test]
async fn concurrent_pom_errors_reach_all_callers_and_allow_retry() {
    let status = Arc::new(AtomicU32::new(401));
    let (repo, _) = model_repository(Arc::clone(&status)).await;
    let (client, _tmp) = test_client();
    let req = ArtifactRequest::new("com.example", "shared", "1");
    let results = tokio::time::timeout(
        Duration::from_secs(5),
        futures::future::join_all((0..8).map(|_| client.fetch_pom(&repo, &req))),
    )
    .await
    .expect("all failed waiters must complete");
    for result in results {
        assert!(matches!(result, Err(RepoError::AuthError(_))), "{result:?}");
    }
    status.store(200, Ordering::SeqCst);
    client
        .fetch_pom(&repo, &req)
        .await
        .expect("failed POM initialization must be retryable");
}

#[tokio::test]
async fn cancelled_pom_initializer_releases_waiters() {
    use futures::FutureExt;

    let (release, gate) = tokio::sync::watch::channel(false);
    let (repo, hits) = model_repository_gated(Arc::new(AtomicU32::new(200)), Some(gate)).await;
    let (client, _tmp) = test_client();
    let req = ArtifactRequest::new("com.example", "shared", "1");
    let mut first = Box::pin(client.fetch_pom(&repo, &req));
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut first => panic!("server must hold the first download: {result:?}"),
            _ = async {
                while hits.lock().unwrap().is_empty() {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
    })
    .await
    .expect("first download must start");
    let mut waiters = Box::pin(futures::future::join_all(
        (0..4).map(|_| client.fetch_pom(&repo, &req)),
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(waiters.as_mut().now_or_never().is_none());
            // Map + initializer + four waiting futures all own the cell.
            if client
                .pom_inflight
                .lock()
                .unwrap()
                .values()
                .any(|cell| Arc::strong_count(cell) == 6)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("siblings must join the in-flight POM");
    drop(first);
    release.send_replace(true);
    let results = tokio::time::timeout(Duration::from_secs(5), waiters)
        .await
        .expect("cancelling the initializer must release its waiters");
    for result in results {
        assert!(result.is_ok(), "{result:?}");
    }
}

/// Repeated module imports and concurrent POM callers share authoritative
/// misses; a new client retries them even when it reuses the disk cache.
#[tokio::test]
async fn snapshot_not_found_is_not_requested_twice() {
    let (repo, hits) = model_repository(Arc::new(AtomicU32::new(404))).await;
    let (client, _tmp) = test_client();
    let req = ArtifactRequest::new("com.example", "demo", "1.0-SNAPSHOT");
    let first = client.fetch_pom(&repo, &req).await.expect_err("404");
    for _ in 0..3 {
        let err = client
            .clone()
            .fetch_pom(&repo, &req)
            .await
            .expect_err("404");
        assert!(matches!(err, RepoError::NotFound(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            first.to_string(),
            "preserve the diagnostic"
        );
    }
    // The generic metadata API must see the same miss as snapshot resolution.
    let coord = Coord::parse("com.example:demo:1.0-SNAPSHOT").unwrap();
    assert!(matches!(
        client.fetch_metadata(&repo, &coord).await,
        Err(RepoError::NotFound(_))
    ));
    let pinned = ArtifactRequest::new("com.example", "demo", "1.0-20261010.000000-1");
    let results = futures::future::join_all((0..8).map(|_| client.fetch_pom(&repo, &pinned))).await;
    assert!(
        results
            .iter()
            .all(|r| matches!(r, Err(RepoError::NotFound(_))))
    );
    assert_eq!(
        hits.lock().unwrap().len(),
        2,
        "metadata and timestamped POM"
    );
    assert!(hits.lock().unwrap().values().all(|&count| count == 1));
    assert!(matches!(
        client
            .clone()
            .with_offline(true)
            .fetch_pom(&repo, &pinned)
            .await,
        Err(RepoError::OfflineNotCached(_))
    ));

    let (mut fresh, _fresh_tmp) = test_client();
    fresh.cache = client.cache.clone();
    assert!(matches!(
        fresh.fetch_pom(&repo, &req).await,
        Err(RepoError::NotFound(_))
    ));
    let metadata = "/com/example/demo/1.0-SNAPSHOT/maven-metadata.xml";
    assert_eq!(
        hits.lock().unwrap()[metadata],
        2,
        "misses must not persist across clients"
    );
}

#[tokio::test]
async fn snapshot_misses_are_scoped_to_origin_and_repository() {
    let (mirror, hits) = model_repository(Arc::new(AtomicU32::new(404))).await;
    let (mut client, _tmp) = test_client_with_mirrors(vec![rv_config::MirrorConfig {
        id: Some("mirror".into()),
        url: mirror.url.clone(),
        mirror_of: vec!["*".into()],
    }]);
    let req = ArtifactRequest::new("com.example", "demo", "1.0-SNAPSHOT");
    for url in ["https://one.invalid/", "https://two.invalid/"] {
        let origin = Repository::new(None, url.to_string(), true, true);
        for _ in 0..2 {
            assert!(matches!(
                client.fetch_pom(&origin, &req).await,
                Err(RepoError::NotFound(_))
            ));
        }
    }
    assert_eq!(hits.lock().unwrap().values().sum::<u32>(), 2);
    client.mirrors = MirrorSelector::default();
    let (other, _) = model_repository(Arc::new(AtomicU32::new(200))).await;
    client
        .fetch_pom(&other, &req)
        .await
        .expect("another repository can serve the snapshot");
}

/// An origin 404 after a transient mirror failure must not cache a mirror miss.
/// This applies to both snapshot metadata and POM fallback.
#[tokio::test]
async fn snapshot_origin_miss_does_not_poison_a_recovering_mirror() {
    for version in ["1.0-SNAPSHOT", "1.0-20261010.000000-1"] {
        let status = Arc::new(AtomicU32::new(500));
        let (mirror, _) = model_repository(Arc::clone(&status)).await;
        let (origin, hits) = model_repository(Arc::new(AtomicU32::new(404))).await;
        let (client, _tmp) = test_client_with_mirrors(vec![rv_config::MirrorConfig {
            id: Some("mirror".into()),
            url: mirror.url,
            mirror_of: vec!["*".into()],
        }]);
        let req = ArtifactRequest::new("com.example", "demo", version);
        for _ in 0..2 {
            assert!(matches!(
                client.fetch_pom(&origin, &req).await,
                Err(RepoError::NotFound(_))
            ));
        }
        assert_eq!(
            hits.lock().unwrap().values().sum::<u32>(),
            1,
            "cache the fallback's own miss"
        );
        status.store(200, Ordering::SeqCst);
        client
            .fetch_pom(&origin, &req)
            .await
            .expect("retry the recovered mirror");
    }
}

#[tokio::test]
async fn snapshot_miss_cache_does_not_cover_releases_or_local_files() {
    let status = Arc::new(AtomicU32::new(404));
    let (repo, _) = model_repository(Arc::clone(&status)).await;
    let (client, _tmp) = test_client();
    let release = ArtifactRequest::new("com.example", "demo", "1.0");
    assert!(matches!(
        client.fetch_pom(&repo, &release).await,
        Err(RepoError::NotFound(_))
    ));
    status.store(200, Ordering::SeqCst);
    client
        .fetch_pom(&repo, &release)
        .await
        .expect("release misses are not cached");

    let dir = tempfile::tempdir().unwrap();
    let local = Repository::new(
        None,
        Url::from_directory_path(dir.path()).unwrap().to_string(),
        true,
        true,
    );
    let req = ArtifactRequest::new("com.example", "demo", "1.0-SNAPSHOT");
    assert!(matches!(
        client.fetch_pom(&local, &req).await,
        Err(RepoError::NotFound(_))
    ));
    let path = dir.path().join(req.pom().to_path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"<project/>").unwrap();
    client
        .fetch_pom(&local, &req)
        .await
        .expect("new local snapshot is visible");
}

/// The SNAPSHOT-metadata sub-fetch must keep the cross-host
/// credential suppression. A `-SNAPSHOT` POM fetch routed through a
/// cross-host wildcard mirror resolves the snapshot metadata as a
/// sub-request. Re-resolving the already-mirrored repo inside
/// `resolve_snapshot_version` would recompute `host_changed=false` and
/// re-attach the default credential to the third-party mirror host.
/// Every request issued during the whole snapshot POM fetch must be free
/// of the default bearer token.
#[tokio::test]
async fn snapshot_metadata_subfetch_preserves_cross_host_suppression() {
    use crate::artifact::ArtifactRequest;
    use crate::repository::Repository;
    use rv_config::{AuthConfig, MirrorConfig};
    use sha2::Digest;

    // Capture every raw request across all connections so we can assert
    // the credential never leaks on the metadata, sidecar, or POM GET.
    let server = StubServer::start(|request| {
        let snapshot_meta = "<metadata><groupId>com.example</groupId>\
                    <artifactId>demo</artifactId><version>1.0-SNAPSHOT</version>\
                    <versioning><snapshot><timestamp>20240101.010101</timestamp>\
                    <buildNumber>7</buildNumber></snapshot>\
                    <snapshotVersions><snapshotVersion><extension>pom</extension>\
                    <value>1.0-20240101.010101-7</value></snapshotVersion>\
                    </snapshotVersions></versioning></metadata>";
        let pom_body = "<project><modelVersion>4.0.0</modelVersion>\
                    <groupId>com.example</groupId><artifactId>demo</artifactId>\
                    <version>1.0-SNAPSHOT</version></project>";

        if request.path.contains("maven-metadata.xml.sha256")
            || request.path.contains(".pom.sha256")
        {
            let target = if request.path.contains("maven-metadata.xml.sha256") {
                snapshot_meta.as_bytes()
            } else {
                pom_body.as_bytes()
            };
            Response::new(200, hex::encode(sha2::Sha256::digest(target)))
        } else if request.path.contains(".sha1") {
            Response::new(404, "")
        } else if request.path.contains("maven-metadata.xml") {
            Response::new(200, snapshot_meta)
        } else {
            Response::new(200, pom_body)
        }
    });
    let addr = server.addr();

    // Default (no-id) bearer token configured globally.
    let auth = AuthStore::from_auth_configs(&[AuthConfig {
        id: None,
        username: None,
        password: None,
        token: Some(Secret::new("hostile-cdn-token".to_string())),
    }])
    .expect("auth store");

    // Wildcard mirror replacing every repo with the stub on a different
    // host than the configured origin.
    let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
        id: Some("hostile".to_string()),
        url: format!("http://{addr}/"),
        mirror_of: vec!["*".to_string()],
    }]);

    let _tmp = tempfile::tempdir().expect("tempdir");
    let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
    let client = RepoClient {
        root_redirects: Arc::default(),
        client: plain_test_client(),
        runtime_client: plain_test_client(),
        auth,
        mirrors,
        fetch: FetchConfig::default(),
        progress: None,
        cache,
        offline: false,
        require_checksums: true,
        mirror_failures: Arc::new(MirrorFailureTracker::default()),
        pom_inflight: PomInflight::default(),
        absent_snapshots: AbsentSnapshots::default(),
        configured_hosts: ConfiguredHosts::default(),
        trusted_hosts: TrustedHosts::default(),
    };

    // Original repo lives on a different host (repo.example) than the
    // stub, so the mirror substitution crosses hosts.
    let repo = Repository::new(
        None,
        "https://repo.example/maven2/".to_string(),
        true,
        true, // snapshots enabled
    );
    let req = ArtifactRequest::new("com.example", "demo", "1.0-SNAPSHOT");

    // Drives resolve_snapshot_for_request -> resolve_snapshot_version_resolved
    // -> fetch_snapshot_metadata, then the POM body fetch.
    let _ = client
        .fetch_pom(&repo, &req)
        .await
        .expect("snapshot pom fetch should succeed against the stub");

    let requests: Vec<_> = server
        .requests()
        .into_iter()
        .map(|request| request.raw)
        .collect();
    assert!(
        requests.iter().any(|r| r.contains("maven-metadata.xml")),
        "test precondition: the snapshot metadata sub-fetch must have run; saw {requests:?}"
    );
    for request in &requests {
        let lc = request.to_ascii_lowercase();
        assert!(
            !lc.contains("authorization: bearer"),
            "default bearer token leaked across the cross-host mirror on a snapshot sub-fetch; got:\n{request}"
        );
        assert!(
            !lc.contains("hostile-cdn-token"),
            "default credential value leaked on a snapshot sub-fetch request; got:\n{request}"
        );
    }
}

/// When a mirror returns 503 (or any non-404 5xx), the client must
/// retry the fetch against the ORIGINAL repo, mirroring
/// Maven's "next mirror in the list, then origin" behavior. Substituting
/// the mirror URL once with no fallback would let a broken mirror take the
/// whole sync down.
#[tokio::test]
async fn mirror_503_falls_back_to_origin() {
    use crate::repository::Repository;
    use rv_config::MirrorConfig;
    use sha2::{Digest, Sha256};

    let body =
        b"<metadata><versioning><versions><version>1.0.0</version></versions></versioning></metadata>"
            .to_vec();
    let sha256 = hex::encode(Sha256::digest(&body));

    // Mirror always 503s. Track that we did hit it.
    let mirror = StubServer::start(|_| Response::new(503, ""));
    let mirror_addr = mirror.addr();
    let origin_server = StubServer::start(move |request| {
        if request.path.contains(".sha256") {
            Response::new(200, sha256.clone())
        } else if request.path.contains(".sha1") {
            Response::new(404, "")
        } else {
            Response::new(200, body.clone())
        }
    });
    let origin_addr = origin_server.addr();

    // Mirror substitutes the origin's URL with the mirror URL.
    let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
        id: Some("broken-mirror".to_string()),
        url: format!("http://{mirror_addr}/"),
        mirror_of: vec!["*".to_string()],
    }]);

    let _tmp = tempfile::tempdir().expect("tempdir");
    let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
    // _tmp stays bound for the rest of the test; dropping it would
    // delete the SQLite cache file MetadataCache still holds open.
    let client = RepoClient {
        root_redirects: Arc::default(),
        client: plain_test_client(),
        runtime_client: plain_test_client(),
        auth: AuthStore::without_os_credentials(),
        mirrors,
        // Speed the retry loop up so the test doesn't wait on backoff.
        fetch: FetchConfig {
            retries: 0,
            timeout: Duration::from_secs(5),
            ..Default::default()
        },
        progress: None,
        cache,
        offline: false,
        require_checksums: true,
        mirror_failures: Arc::new(MirrorFailureTracker::default()),
        pom_inflight: PomInflight::default(),
        absent_snapshots: AbsentSnapshots::default(),
        configured_hosts: ConfiguredHosts::default(),
        trusted_hosts: TrustedHosts::default(),
    };

    let origin = Repository::new(
        Some("central".to_string()),
        format!("http://{origin_addr}/"),
        true,
        false,
    );
    let coord = rv_version::Coord {
        group_id: "com.example".into(),
        artifact_id: "demo".into(),
        version: "1.0.0".parse().expect("version"),
        packaging: Some("jar".to_string()),
        classifier: None,
    };

    let metadata = client
        .fetch_metadata(&origin, &coord)
        .await
        .expect("origin fallback must succeed when mirror 503s");
    // Quick sanity check that we actually got the origin-served payload.
    assert!(
        metadata.versions.contains(&"1.0.0".to_string()),
        "metadata from origin must contain version 1.0.0"
    );
    assert!(
        mirror.answered() >= 1,
        "mirror must be hit first (got {} hits)",
        mirror.answered()
    );
    assert!(
        origin_server.answered() >= 1,
        "origin must be retried after mirror 503 (got {} hits)",
        origin_server.answered()
    );
}

/// A mirror 404 must NOT trigger the origin fallback. 404 means
/// "the artifact genuinely does not exist at this coordinate"; retrying
/// the origin only adds latency and reissues the same authoritative
/// negative answer. Maven matches this behavior.
#[tokio::test]
async fn mirror_404_does_not_fall_back_to_origin() {
    use crate::repository::Repository;
    use rv_config::MirrorConfig;

    let mirror = StubServer::start(|_| Response::new(404, ""));
    let mirror_addr = mirror.addr();
    let origin_server = StubServer::start(|_| Response::new(200, ""));
    let origin_addr = origin_server.addr();

    let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
        id: Some("404-mirror".to_string()),
        url: format!("http://{mirror_addr}/"),
        mirror_of: vec!["*".to_string()],
    }]);

    let _tmp = tempfile::tempdir().expect("tempdir");
    let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
    // _tmp stays bound for the rest of the test; dropping it would
    // delete the SQLite cache file MetadataCache still holds open.
    let client = RepoClient {
        root_redirects: Arc::default(),
        client: plain_test_client(),
        runtime_client: plain_test_client(),
        auth: AuthStore::without_os_credentials(),
        mirrors,
        fetch: FetchConfig {
            retries: 0,
            timeout: Duration::from_secs(5),
            ..Default::default()
        },
        progress: None,
        cache,
        offline: false,
        require_checksums: true,
        mirror_failures: Arc::new(MirrorFailureTracker::default()),
        pom_inflight: PomInflight::default(),
        absent_snapshots: AbsentSnapshots::default(),
        configured_hosts: ConfiguredHosts::default(),
        trusted_hosts: TrustedHosts::default(),
    };

    let origin = Repository::new(
        Some("central".to_string()),
        format!("http://{origin_addr}/"),
        true,
        false,
    );
    let coord = rv_version::Coord {
        group_id: "com.example".into(),
        artifact_id: "demo".into(),
        version: "1.0.0".parse().expect("version"),
        packaging: Some("jar".to_string()),
        classifier: None,
    };

    let result = client.fetch_metadata(&origin, &coord).await;
    assert!(
        matches!(result, Err(RepoError::NotFound(_))),
        "404 from mirror must surface as NotFound, got {result:?}"
    );
    assert!(mirror.answered() >= 1, "mirror must be hit at least once");
    assert_eq!(
        origin_server.connections(),
        0,
        "origin must NOT be retried on a mirror 404 (Maven parity)"
    );
}

/// The metadata/POM cache scope key must distinguish two different
/// origins that resolve through the same mirror, and also distinguish the
/// same origin across a mirror change, so neither cross-origin reuse nor
/// stale-after-mirror-swap reuse can occur.
#[test]
fn cache_scope_key_isolates_origin_and_mirror() {
    let mirror = "https://mirror.corp/";
    let origin_a = "https://repo.maven.apache.org/maven2/";
    let origin_b = "https://nexus.corp/releases/";

    // Two distinct origins behind one mirror must not collide.
    assert_ne!(
        RepoClient::cache_scope_key(origin_a, mirror),
        RepoClient::cache_scope_key(origin_b, mirror),
        "distinct origins routed through one mirror must not share a cache scope"
    );

    // The same origin across two different mirrors must not collide either,
    // so swapping a repo's mirror cannot reuse the previous mirror's entry.
    let mirror_2 = "https://mirror2.corp/";
    assert_ne!(
        RepoClient::cache_scope_key(origin_a, mirror),
        RepoClient::cache_scope_key(origin_a, mirror_2),
        "a mirror change for one origin must not reuse the previous mirror's entry"
    );

    // Deterministic for identical inputs.
    assert_eq!(
        RepoClient::cache_scope_key(origin_a, mirror),
        RepoClient::cache_scope_key(origin_a, mirror),
    );
}

#[test]
fn metadata_path_for_release() {
    let path = metadata_path("com.example", "demo", None);
    assert_eq!(path, "com/example/demo/maven-metadata.xml");
}

#[test]
fn metadata_path_for_snapshot() {
    let path = metadata_path("com.example", "demo", Some("1.0-SNAPSHOT"));
    assert_eq!(path, "com/example/demo/1.0-SNAPSHOT/maven-metadata.xml");
}

#[test]
fn extracts_snapshot_timestamp() {
    let version = "1.0-20240101.010101-7";
    assert_eq!(
        snapshot_timestamp_from_version(version),
        Some("20240101.010101".to_string())
    );
}

#[test]
fn derives_snapshot_directory_version() {
    let version = "1.0-20240101.010101-7";
    assert_eq!(
        snapshot_dir_version(version),
        Some("1.0-SNAPSHOT".to_string())
    );
}

// -------------------------------------------------------------------------
// validate_coord_components / metadata_path traversal guard
// -------------------------------------------------------------------------

/// A version string containing `../` must be rejected before any URL is
/// built, preventing path-traversal / SSRF from hostile maven-metadata.xml.
#[test]
fn validate_coord_rejects_path_traversal_in_version() {
    let err = validate_coord_components("com.example", "demo", Some("../../etc/shadow"))
        .expect_err("traversal version must be rejected");
    assert!(
        matches!(err, RepoError::InvalidCoord(_)),
        "expected InvalidCoord, got {err:?}"
    );
}

/// A group ID containing a forward slash is also rejected.
#[test]
fn validate_coord_rejects_slash_in_group_id() {
    let err = validate_coord_components("com/evil", "demo", Some("1.0.0"))
        .expect_err("slash in group_id must be rejected");
    assert!(matches!(err, RepoError::InvalidCoord(_)));
}

/// Normal Maven coordinates must pass validation.
#[test]
fn validate_coord_accepts_normal_coordinates() {
    validate_coord_components("com.example", "demo", Some("1.0.0-SNAPSHOT"))
        .expect("normal coordinate must be accepted");
    validate_coord_components("org.springframework.boot", "spring-boot", None)
        .expect("no-version path must be accepted");
}

// -------------------------------------------------------------------------
// ChecksumMismatch must not trigger mirror->origin fallback
// -------------------------------------------------------------------------

/// A `ChecksumMismatch` error returned by a mirror must NOT cause a
/// fallback to the origin. It is an integrity violation, not a transient
/// failure; retrying the origin would let a hostile mirror exploit the
/// retry path.
#[test]
fn checksum_mismatch_does_not_trigger_fallback() {
    let err = RepoError::ChecksumMismatch {
        path: "com/example/demo/1.0/demo-1.0.jar".to_string(),
        expected: "deadbeef".to_string(),
        actual: "cafebabe".to_string(),
    };
    assert!(
        !should_fallback_to_origin(&err),
        "ChecksumMismatch must not trigger origin fallback"
    );
}

/// A mirror returning a mismatched checksum on `fetch_metadata` must NOT
/// cause an origin retry; the error must propagate as-is.
#[tokio::test]
async fn mirror_checksum_mismatch_does_not_fall_back_to_origin() {
    use crate::repository::Repository;
    use rv_config::MirrorConfig;

    // Mirror serves a valid body but a deliberately wrong SHA-256 sidecar.
    let body =
        b"<metadata><versioning><versions><version>1.0.0</version></versions></versioning></metadata>"
            .to_vec();
    let wrong_sha256 = "0".repeat(64);

    let mirror = StubServer::start(move |request| {
        if request.path.contains(".sha256") {
            Response::new(200, wrong_sha256.clone())
        } else if request.path.contains(".sha1") {
            Response::new(404, "")
        } else {
            Response::new(200, body.clone())
        }
    });
    let mirror_addr = mirror.addr();
    let origin_server = StubServer::start(|_| Response::new(200, ""));
    let origin_addr = origin_server.addr();

    let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
        id: Some("mismatch-mirror".to_string()),
        url: format!("http://{mirror_addr}/"),
        mirror_of: vec!["*".to_string()],
    }]);

    let _tmp = tempfile::tempdir().expect("tempdir");
    let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
    let client = RepoClient {
        root_redirects: Arc::default(),
        client: plain_test_client(),
        runtime_client: plain_test_client(),
        auth: AuthStore::without_os_credentials(),
        mirrors,
        fetch: FetchConfig {
            retries: 0,
            timeout: Duration::from_secs(5),
            ..Default::default()
        },
        progress: None,
        cache,
        offline: false,
        require_checksums: true,
        mirror_failures: Arc::new(MirrorFailureTracker::default()),
        pom_inflight: PomInflight::default(),
        absent_snapshots: AbsentSnapshots::default(),
        configured_hosts: ConfiguredHosts::default(),
        trusted_hosts: TrustedHosts::default(),
    };

    let mut origin = Repository::new(
        Some("central".to_string()),
        format!("http://{origin_addr}/"),
        true,
        false,
    );
    origin.releases_checksum_policy = rv_config::ChecksumPolicy::Fail;
    let coord = rv_version::Coord {
        group_id: "com.example".into(),
        artifact_id: "demo".into(),
        version: "1.0.0".parse().expect("version"),
        packaging: Some("jar".to_string()),
        classifier: None,
    };

    let result = client.fetch_metadata(&origin, &coord).await;
    assert!(
        matches!(result, Err(RepoError::ChecksumMismatch { .. })),
        "ChecksumMismatch from mirror must propagate, got {result:?}"
    );
    assert!(mirror.answered() >= 1, "mirror must have been contacted");
    assert_eq!(
        origin_server.connections(),
        0,
        "origin must NOT be retried on a mirror ChecksumMismatch"
    );
}

#[tokio::test]
async fn offline_file_repository_reads_models_and_artifacts_after_mirror_selection() {
    let repo_dir = tempfile::tempdir().unwrap();
    let version_dir = repo_dir.path().join("com/example/demo/1.0-SNAPSHOT");
    std::fs::create_dir_all(&version_dir).unwrap();
    let metadata = b"<metadata><groupId>com.example</groupId><artifactId>demo</artifactId>\
        <version>1.0-SNAPSHOT</version><versioning><snapshot>\
        <timestamp>20261010.000000</timestamp><buildNumber>1</buildNumber>\
        </snapshot></versioning></metadata>";
    std::fs::write(version_dir.join("maven-metadata.xml"), metadata).unwrap();
    let pom = b"<project><modelVersion>4.0.0</modelVersion></project>";
    std::fs::write(version_dir.join("demo-1.0-20261010.000000-1.pom"), pom).unwrap();
    std::fs::write(version_dir.join("demo-1.0-20261010.000000-1.jar"), b"jar").unwrap();
    let local_url = Url::from_directory_path(repo_dir.path())
        .unwrap()
        .to_string();
    // Exercise both direct file access with an external mirror and a remote
    // origin routed to a file mirror. Each starts with a cold metadata cache.
    for mirrored in [false, true] {
        let (url, mirror_url, pattern) = if mirrored {
            ("https://origin.invalid/", local_url.as_str(), "*")
        } else {
            (local_url.as_str(), "https://mirror.invalid/", "external:*")
        };
        let (client, _cache) = test_client_with_mirrors(vec![rv_config::MirrorConfig {
            id: Some("mirror".into()),
            url: mirror_url.into(),
            mirror_of: vec![pattern.into()],
        }]);
        let client = client.with_offline(true);
        let repo = Repository::new(Some("origin".into()), url, true, true);
        let coord = Coord::parse("com.example:demo:1.0-SNAPSHOT").unwrap();
        assert_eq!(
            client
                .resolve_snapshot_version(&repo, &coord)
                .await
                .unwrap()
                .version,
            "1.0-20261010.000000-1"
        );
        let req = ArtifactRequest::new("com.example", "demo", "1.0-SNAPSHOT");
        assert_eq!(client.fetch_pom(&repo, &req).await.unwrap().as_ref(), pom);
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path()).unwrap();
        let blob = client
            .fetch_artifact_to_store(&repo, &req, &store)
            .await
            .unwrap();
        let key = rv_config::ArtifactKey::new("com.example", "demo", "1.0-SNAPSHOT", "jar", None);
        let (indexed_blob, serving_repo) = client
            .fetch_artifact_to_store_and_index_with_repository(&repo, &req, &store, &key)
            .await
            .unwrap();
        assert_eq!(indexed_blob, blob);
        assert_eq!(serving_repo, local_url);

        let (mut fresh, _fresh_cache) = test_client();
        fresh.mirrors = client.mirrors.clone();
        let fresh = fresh.with_offline(true);
        fresh.fetch_metadata(&repo, &coord).await.unwrap();
    }
}

#[tokio::test]
async fn offline_file_repository_still_verifies_checksum_sidecars() {
    let repo_dir = tempfile::tempdir().unwrap();
    let version_dir = repo_dir.path().join("com/example/demo/1");
    std::fs::create_dir_all(&version_dir).unwrap();
    for extension in ["pom", "jar"] {
        std::fs::write(version_dir.join(format!("demo-1.{extension}")), b"content").unwrap();
        std::fs::write(
            version_dir.join(format!("demo-1.{extension}.sha256")),
            "0".repeat(64),
        )
        .unwrap();
    }
    let repo = Repository::new(
        None,
        Url::from_directory_path(repo_dir.path()).unwrap(),
        true,
        true,
    );
    let (client, _cache) = test_client();
    let client = client.with_offline(true);
    let req = ArtifactRequest::new("com.example", "demo", "1");
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    let key = rv_config::ArtifactKey::new("com.example", "demo", "1", "jar", None);
    assert!(matches!(
        client.fetch_pom(&repo, &req).await,
        Err(RepoError::ChecksumMismatch { .. })
    ));
    assert!(matches!(
        client.fetch_artifact_to_store(&repo, &req, &store).await,
        Err(RepoError::ChecksumMismatch { .. })
    ));
    assert!(matches!(
        client
            .fetch_artifact_to_store_and_index(&repo, &req, &store, &key)
            .await,
        Err(RepoError::ChecksumMismatch { .. })
    ));
}

#[tokio::test]
async fn offline_remote_pom_and_artifact_reads_never_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_url = format!("http://{}/", listener.local_addr().unwrap());
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    let req = ArtifactRequest::new("com.example", "demo", "1");
    let key = rv_config::ArtifactKey::new("com.example", "demo", "1", "jar", None);
    for mirrored in [false, true] {
        let (client, _cache) = test_client_with_mirrors(if mirrored {
            vec![rv_config::MirrorConfig {
                id: Some("remote".into()),
                url: remote_url.clone(),
                mirror_of: vec!["*".into()],
            }]
        } else {
            vec![]
        });
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
        assert!(matches!(
            client.fetch_pom(&repo, &req).await,
            Err(RepoError::OfflineNotCached(_))
        ));
        assert!(matches!(
            client.fetch_artifact_to_store(&repo, &req, &store).await,
            Err(RepoError::OfflineNotCached(_))
        ));
        assert!(matches!(
            client
                .fetch_artifact_to_store_and_index(&repo, &req, &store, &key)
                .await,
            Err(RepoError::OfflineNotCached(_))
        ));
        // Fallback attempts also guard their own effective endpoint before
        // checksum policy or streaming can bypass the public entry point.
        let remote = Repository::new(None, &remote_url, true, true);
        assert!(matches!(
            client
                .fetch_artifact_to_store_attempt(&remote, &req.to_path(), false, &store)
                .await,
            Err(RepoError::OfflineNotCached(_))
        ));
        assert!(matches!(
            client
                .fetch_artifact_to_store_and_index_attempt(
                    &remote,
                    &req.to_path(),
                    false,
                    &store,
                    &key
                )
                .await,
            Err(RepoError::OfflineNotCached(_))
        ));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

// -------------------------------------------------------------------------
// offline guard for fetch_metadata and fetch_snapshot_metadata
// -------------------------------------------------------------------------

/// Calling `fetch_metadata` in offline mode with a cold cache must return
/// `OfflineNotCached` without making any network connection.
#[tokio::test]
async fn fetch_metadata_offline_cold_cache_returns_offline_error() {
    use crate::repository::Repository;

    // Bind a listener on a random port so we can detect any accidental
    // network contact from the offline client.
    let server = StubServer::start(|_| Response::new(200, ""));
    let addr = server.addr();

    let (client, _tmp) = test_client();
    let client = client.with_offline(true);
    let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, false);
    let coord = rv_version::Coord {
        group_id: "com.example".into(),
        artifact_id: "demo".into(),
        version: "1.0.0".parse().expect("version"),
        packaging: None,
        classifier: None,
    };

    let result = client.fetch_metadata(&repo, &coord).await;
    assert!(
        matches!(result, Err(RepoError::OfflineNotCached(_))),
        "offline + cold cache must return OfflineNotCached, got {result:?}"
    );
    assert_eq!(
        server.connections(),
        0,
        "no network connection must be made in offline mode"
    );
}

/// Calling `resolve_snapshot_version` in offline mode with a cold cache
/// must return `OfflineNotCached` without making any network connection.
#[tokio::test]
async fn fetch_snapshot_metadata_offline_cold_cache_returns_offline_error() {
    use crate::repository::Repository;

    let server = StubServer::start(|_| Response::new(200, ""));
    let addr = server.addr();

    let (client, _tmp) = test_client();
    let client = client.with_offline(true);
    let repo = Repository::new(
        Some("stub".into()),
        format!("http://{addr}/"),
        true,
        true, // snapshots enabled
    );
    let coord = rv_version::Coord {
        group_id: "com.example".into(),
        artifact_id: "demo".into(),
        version: "1.0-SNAPSHOT".parse().expect("version"),
        packaging: None,
        classifier: None,
    };

    let result = client.resolve_snapshot_version(&repo, &coord).await;
    assert!(
        matches!(result, Err(RepoError::OfflineNotCached(_))),
        "offline + cold cache must return OfflineNotCached for snapshot metadata, got {result:?}"
    );
    assert_eq!(
        server.connections(),
        0,
        "no network connection must be made in offline mode"
    );
}
