//! Credential handling when a lockfile row records a mirror-substituted URL.
//!
//! Resolution rewrites a repository URL through `[[mirrors]]` and records the
//! *substituted* URL as the package's origin. A later `rv sync` therefore hands
//! the mirror's own URL back to the fetch path, where mirror selection matches
//! it against the very entry that produced it and short-circuits as a
//! self-reference — so the cross-host flag it would otherwise raise never
//! appears. These tests pin the outbound `Authorization` header for both sides
//! of that decision.
//!
//! They live in their own integration binary because they mutate `HOME` /
//! `RAEVA_HOME` to make `Config::load` hermetic.

use std::sync::{Mutex, Once};

use rv_config::{
    Checksum, Config, LOCKFILE_SCHEMA_VERSION, LockGav, LockPackage, LockPlatform, Lockfile,
    Platform,
};
use rv_repo::{RepoClient, sync};
use rv_store::Store;
use rv_test_support::http::{Response, StubServer};

/// rustls 0.23 requires a process-level `CryptoProvider`; the integration
/// binary has to seed it itself.
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// `temp_env` mutates process-wide state, so the two scenarios take turns.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const JAR_BYTES: &[u8] = b"demo jar bytes";
const POM_BYTES: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
    <groupId>com.example</groupId><artifactId>demo</artifactId>\
    <version>1.0</version></project>";

fn response_for(path: &str) -> Response {
    let body: Option<Vec<u8>> = match path {
        "/maven/com/example/demo/1.0/demo-1.0.jar" => Some(JAR_BYTES.to_vec()),
        "/maven/com/example/demo/1.0/demo-1.0.jar.sha256" => {
            Some(sha256_hex(JAR_BYTES).into_bytes())
        }
        "/maven/com/example/demo/1.0/demo-1.0.pom" => Some(POM_BYTES.to_vec()),
        "/maven/com/example/demo/1.0/demo-1.0.pom.sha256" => {
            Some(sha256_hex(POM_BYTES).into_bytes())
        }
        _ => None,
    };
    match body {
        Some(body) => Response::new(200, body),
        None => Response::new(404, ""),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Load a `Config` from a project `rv.toml` with `HOME`/`RAEVA_HOME` pointed at
/// a scratch directory, so no developer `settings.xml` or user config leaks in.
///
/// Synchronous, and the env lock is confined to it: the scenarios only need
/// serializing while the process environment is swapped.
fn load_config(home: &std::path::Path, rv_toml: &str) -> Config {
    let _serialized = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let project = home.join("project");
    std::fs::create_dir_all(&project).expect("project dir");
    std::fs::write(project.join("rv.toml"), rv_toml).expect("rv.toml");
    let home_string = home.to_string_lossy().into_owned();
    let raeva_home = home.join("raeva").to_string_lossy().into_owned();
    temp_env::with_vars(
        [
            ("HOME", Some(home_string.as_str())),
            ("USERPROFILE", Some(home_string.as_str())),
            ("RAEVA_HOME", Some(raeva_home.as_str())),
        ],
        || {
            Config::load(&project)
                .expect("config")
                .without_os_credentials()
        },
    )
}

fn single_package_lock(mirror_url: &str) -> (Lockfile, Vec<Platform>) {
    let platform = Platform::current().expect("platform");
    let package = LockPackage {
        group_id: "com.example".to_string(),
        artifact_id: "demo".to_string(),
        version: "1.0".to_string(),
        snapshot_timestamp: None,
        packaging: "jar".to_string(),
        classifier: None,
        // What resolution records: the mirror URL, not the origin repository.
        repo_url: mirror_url.to_string(),
        checksum: Some(Checksum::new("sha256", sha256_hex(JAR_BYTES))),
        system_path: None,
        direct_scope: None,
        extra: Default::default(),
    };
    let lock = Lockfile {
        schema_version: LOCKFILE_SCHEMA_VERSION,
        config_hash: None,
        resolution: None,
        platforms: vec![LockPlatform::single_module(
            platform.clone(),
            "",
            "pom.xml",
            LockGav::new("com.example", "root", "1"),
            "pom",
            vec![package],
            Vec::new(),
        )],
        metadata: Default::default(),
        extra: Default::default(),
    };
    (lock, vec![platform])
}

fn authorization_headers(server: &StubServer) -> Vec<String> {
    server
        .requests()
        .iter()
        .flat_map(|request| request.raw.lines())
        .filter(|line| {
            line.split(':')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("authorization"))
        })
        .map(str::to_string)
        .collect()
}

/// The leak: a wildcard mirror on a third-party host plus a default (no-id)
/// corp token. Resolution withheld the token from the mirror and recorded the
/// mirror URL; syncing that lockfile must withhold it too.
#[tokio::test]
async fn syncing_a_mirror_recorded_row_does_not_leak_the_default_token() {
    ensure_crypto_provider();
    let home = tempfile::tempdir().expect("home");
    let server = StubServer::start(|request| response_for(&request.path));
    let addr = server.addr();
    let mirror_url = format!("http://{addr}/maven/");

    let config = load_config(
        home.path(),
        &format!(
            r#"[[repositories]]
id = "central"
url = "https://repo1.maven.org/maven2/"

[[mirrors]]
id = "cdn"
url = "{mirror_url}"
mirror_of = ["*"]

[[auth]]
token = "corp-secret-token"
"#
        ),
    );

    let store_dir = home.path().join("store");
    let store = Store::open(&store_dir).expect("store");
    let client = RepoClient::new(&config).await.expect("client");
    let (lock, platforms) = single_package_lock(&mirror_url);

    let results = sync::ensure_artifacts(&client, &store, &lock, &config, &platforms, &[])
        .await
        .expect("sync");
    for result in &results {
        result
            .result
            .as_ref()
            .expect("the mirror serves the artifact anonymously");
    }

    assert!(
        !server.requests().is_empty(),
        "the stub must have been contacted"
    );
    let sent = authorization_headers(&server);
    assert!(
        sent.is_empty(),
        "the default corp token must never reach a cross-host mirror: {sent:?}"
    );
}

/// Control: a mirror sharing an origin with a configured repository is not a
/// cross-host substitution, so the default credential still applies. The token
/// already reaches that origin through the repository itself.
#[tokio::test]
async fn syncing_a_same_host_mirror_row_still_sends_the_default_token() {
    ensure_crypto_provider();
    let home = tempfile::tempdir().expect("home");
    let server = StubServer::start(|request| response_for(&request.path));
    let addr = server.addr();
    let mirror_url = format!("http://{addr}/maven/");

    let config = load_config(
        home.path(),
        &format!(
            r#"[[repositories]]
id = "internal"
url = "http://{addr}/repo/"

[[mirrors]]
id = "internal-mirror"
url = "{mirror_url}"
mirror_of = ["*"]

[[auth]]
token = "corp-secret-token"
"#
        ),
    );

    let store_dir = home.path().join("store");
    let store = Store::open(&store_dir).expect("store");
    let client = RepoClient::new(&config).await.expect("client");
    let (lock, platforms) = single_package_lock(&mirror_url);

    let results = sync::ensure_artifacts(&client, &store, &lock, &config, &platforms, &[])
        .await
        .expect("sync");
    for result in &results {
        result
            .result
            .as_ref()
            .expect("the mirror serves the artifact");
    }

    let sent = authorization_headers(&server);
    assert!(
        !sent.is_empty(),
        "a same-origin mirror must still receive the configured default credential"
    );
}
