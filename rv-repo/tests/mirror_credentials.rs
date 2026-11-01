//! Credential handling when a lockfile row is restored through a mirror.
//!
//! A row records the repository a configuration or POM declares, never the
//! mirror that served it, so the mirror configured now decides the endpoint
//! and the credentials, as in Maven. These tests pin the outbound
//! `Authorization` header. They mutate `HOME` and `RAEVA_HOME` to make
//! `Config::load` hermetic, so they live in their own binary.

use std::sync::Mutex;

use rv_config::Config;
use rv_lock::{LockArtifact, LockPlatform, Lockfile, Platform};
use rv_maven_types::{ArtifactCoord, Gav};
use rv_repo::{RepoClient, RepoError};
use rv_store::Store;
use rv_test_support::http::{Response, StubServer};
use sha2::{Digest, Sha256};

static ENV_LOCK: Mutex<()> = Mutex::new(());

const JAR: &[u8] = b"demo jar bytes";
const POM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
    <groupId>com.example</groupId><artifactId>demo</artifactId>\
    <version>1.0</version></project>";
const CENTRAL: &str = "https://repo1.maven.org/maven2/";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn mirror_stub() -> StubServer {
    let _ = rustls::crypto::ring::default_provider().install_default();
    StubServer::start(|request| {
        let base = "/maven/com/example/demo/1.0/demo-1.0";
        match request.path.strip_prefix(base) {
            Some(".jar") => Response::new(200, JAR),
            Some(".jar.sha256") => Response::new(200, sha256_hex(JAR)),
            Some(".pom") => Response::new(200, POM),
            Some(".pom.sha256") => Response::new(200, sha256_hex(POM)),
            _ => Response::new(404, ""),
        }
    })
}

fn load_config(home: &std::path::Path, config_toml: &str) -> Config {
    let _serialized = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(home.join("raeva")).unwrap();
    std::fs::write(home.join("raeva/config.toml"), config_toml).unwrap();
    let raeva_home = home.join("raeva");
    temp_env::with_vars(
        [
            ("HOME", Some(home.as_os_str())),
            ("USERPROFILE", Some(home.as_os_str())),
            ("RAEVA_HOME", Some(raeva_home.as_os_str())),
        ],
        || Config::load(&project).unwrap(),
    )
}

#[tokio::test]
async fn project_configuration_allows_its_http_repository_in_a_pom() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("project")).unwrap();
    std::fs::write(
        home.path().join("project/raeva.toml"),
        "[[repositories]]\nid = \"configured\"\nurl = \"http://repo.example\"\n",
    )
    .unwrap();
    let config = load_config(home.path(), "");
    let client = RepoClient::new(&config).await.unwrap();
    let declared =
        rv_repo::Repository::new(Some("pom".into()), "http://repo.example/", true, false);
    for from in [
        rv_repo::Declaration::LocalPom,
        rv_repo::Declaration::RemoteParent,
    ] {
        let admitted = client.policy().admit([declared.clone()], from).admitted;
        assert_eq!(admitted, std::slice::from_ref(&declared));
        assert_eq!(client.effective_repository(&admitted[0]).url, declared.url);
    }
}

/// Restores one jar row naming `row_url` through the configuration
/// `config_toml`, returning the results and the stub's `Authorization`
/// headers.
async fn restore(
    server: &StubServer,
    row_url: &str,
    config_toml: &str,
) -> (Vec<rv_repo::DownloadResult>, Vec<String>) {
    let home = tempfile::tempdir().unwrap();
    let config = load_config(home.path(), config_toml);
    let store = Store::open(&home.path().join("store")).unwrap();
    let client = RepoClient::new(&config).await.unwrap();
    let platform = Platform::current().unwrap();
    let mut package = LockArtifact::new(
        ArtifactCoord::new("com.example", "demo", "1.0", "jar", None),
        row_url,
    );
    package.checksums = vec![rv_maven_types::Digest::parse("sha256", &sha256_hex(JAR)).unwrap()];
    let mut lock = Lockfile::new();
    let root = Gav::new("com.example", "root", "1");
    lock.platforms = vec![LockPlatform::single_module(
        platform.clone(),
        root,
        "pom",
        vec![package],
    )];
    let results = rv_repo::ensure_artifacts(
        &store,
        &lock,
        &[rv_repo::RestoreContext {
            config: &config,
            client: &client,
            platforms: &[platform],
            trusted_repositories: &[],
        }],
    )
    .await
    .unwrap();
    let headers = server
        .requests()
        .iter()
        .flat_map(|request| request.raw.lines().map(str::to_string).collect::<Vec<_>>())
        .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .collect();
    (results, headers)
}

/// The default (id-less) token does not cross to a mirror on another host,
/// but still reaches a mirror on the origin of a configured repository; and
/// the mirror's id, not the mirrored repository's, selects an id-scoped
/// credential.
#[tokio::test]
async fn mirror_credentials_follow_the_mirror() {
    let default_token = "[[auth]]\ntoken = \"corp-secret-token\"\n";
    let by_id = "[[auth]]\nid = \"central\"\ntoken = \"central-token\"\n\n\
                 [[auth]]\nid = \"cdn\"\ntoken = \"cdn-token\"\n";
    for (same_host, auth, expected) in [
        (false, default_token, None),
        (true, default_token, Some("corp-secret-token")),
        (false, by_id, Some("cdn-token")),
    ] {
        let server = mirror_stub();
        let addr = server.addr();
        let repo_url = if same_host {
            format!("http://{addr}/repo/")
        } else {
            CENTRAL.to_string()
        };
        let config = format!(
            "[[repositories]]\nid = \"central\"\nurl = \"{repo_url}\"\n\n\
             [[mirrors]]\nid = \"cdn\"\nurl = \"http://{addr}/maven/\"\nmirror_of = [\"*\"]\n\n{auth}"
        );
        let (results, headers) = restore(&server, &repo_url, &config).await;
        for result in &results {
            result.result.as_ref().unwrap();
        }
        let requests = server.requests();
        assert!(!requests.is_empty());
        assert!(
            requests
                .iter()
                .all(|request| request.path.starts_with("/maven/"))
        );
        match expected {
            None => assert!(headers.is_empty(), "{headers:?}"),
            Some(token) => {
                assert!(!headers.is_empty());
                assert!(
                    headers.iter().all(|header| header.contains(token)),
                    "{headers:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_row_naming_the_mirror_url_is_refused() {
    let server = mirror_stub();
    let mirror_url = format!("http://{}/maven/", server.addr());
    let config = format!(
        "[[repositories]]\nid = \"central\"\nurl = \"{CENTRAL}\"\n\n\
         [[mirrors]]\nid = \"cdn\"\nurl = \"{mirror_url}\"\nmirror_of = [\"central\"]\n"
    );
    let (results, _) = restore(&server, &mirror_url, &config).await;
    let error = results[0].result.as_ref().unwrap_err();
    assert!(matches!(error, RepoError::UntrustedRepoUrl(_)), "{error:?}");
    assert!(server.requests().is_empty());
}
