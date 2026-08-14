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

use std::sync::{Arc, Mutex, Once};

use rv_config::{
    Checksum, Config, LOCKFILE_SCHEMA_VERSION, LockGav, LockPackage, LockPlatform, Lockfile,
    Platform,
};
use rv_repo::{RepoClient, sync};
use rv_store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

/// Every request the stub received, verbatim (request line plus headers).
type RequestLog = Arc<Mutex<Vec<String>>>;

/// A Maven-shaped stub serving `demo-1.0.jar`/`.pom` plus their `.sha256`
/// sidecars under `/maven/`, recording each request it answers.
async fn spawn_recording_stub() -> (std::net::SocketAddr, RequestLog) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let log: RequestLog = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let sink = sink.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let mut total = Vec::new();
                loop {
                    let Ok(read) = sock.read(&mut buf).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    total.extend_from_slice(&buf[..read]);
                    if total.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&total).into_owned();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                sink.lock().expect("log").push(request);
                let _ = sock.write_all(&response_for(&path)).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, log)
}

fn response_for(path: &str) -> Vec<u8> {
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
        Some(body) => {
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            response
        }
        None => {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        }
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
        || Config::load(&project).expect("config"),
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

fn authorization_headers(log: &RequestLog) -> Vec<String> {
    log.lock()
        .expect("log")
        .iter()
        .flat_map(|request| request.lines())
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
    let (addr, log) = spawn_recording_stub().await;
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
        !log.lock().expect("log").is_empty(),
        "the stub must have been contacted"
    );
    let sent = authorization_headers(&log);
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
    let (addr, log) = spawn_recording_stub().await;
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

    let sent = authorization_headers(&log);
    assert!(
        !sent.is_empty(),
        "a same-origin mirror must still receive the configured default credential"
    );
}
