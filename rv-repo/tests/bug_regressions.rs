//! `ensure_artifacts` regressions that cross `Store`, `Config` and
//! `RepoClient`, against an in-process HTTP stub.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use rv_config::{Config, RepoConfig, ResolvedPaths};
use rv_lock::{LockArtifact, LockPlatform, Lockfile, Platform};
use rv_maven_types::{ArtifactCoord, Gav};
use rv_repo::RepoClient;
use rv_store::Store;
use rv_test_support::http::{Response, StubServer};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn ensure_artifacts_repairs_deleted_explicit_pom_dependency() {
    const POM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
        <groupId>com.example</groupId><artifactId>pom-dep</artifactId>\
        <version>1.0.0</version><packaging>pom</packaging></project>";
    const PATH: &str = "/com/example/pom-dep/1.0.0/pom-dep-1.0.0.pom";
    let _ = rustls::crypto::ring::default_provider().install_default();
    let sha256 = hex::encode(Sha256::digest(POM));
    let pom_gets = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&pom_gets);
    let checksum = sha256.clone();
    let server = StubServer::start(move |request| match request.path.strip_prefix(PATH) {
        Some("") => {
            counter.fetch_add(1, Ordering::SeqCst);
            Response::new(200, POM)
        }
        Some(".sha256") => Response::new(200, checksum.as_str()),
        _ => Response::new(404, ""),
    });

    let temp = tempfile::tempdir().unwrap();
    let mut repo = RepoConfig::new(Some("stub"), &format!("http://{}/", server.addr()));
    repo.releases = Some(true);
    repo.snapshots = Some(false);
    let paths = ResolvedPaths::for_testing().unwrap();
    let config = Config::for_testing_with_repos(temp.path().to_path_buf(), paths, vec![repo]);
    let client = RepoClient::new(&config).await.unwrap();
    let store = Store::open(&temp.path().join("store")).unwrap();
    let key = ArtifactCoord::new("com.example", "pom-dep", "1.0.0", "pom", None);
    let mut artifact = LockArtifact::new(key.clone(), &config.repositories()[0].url);
    artifact.checksums = vec![rv_maven_types::Digest::parse("sha256", &sha256).unwrap()];
    let platform = Platform::current().unwrap();
    let mut lock = Lockfile::new();
    let root = Gav::new("com.example", "root", "1");
    lock.platforms = vec![LockPlatform::single_module(
        platform.clone(),
        root,
        "pom",
        vec![artifact],
    )];
    let sync = || async {
        let platforms = std::slice::from_ref(&platform);
        let results = rv_repo::ensure_artifacts(
            &store,
            &lock,
            &[rv_repo::RestoreContext {
                config: &config,
                client: &client,
                platforms,
                trusted_repositories: &[],
            }],
        )
        .await
        .unwrap();
        assert_eq!(results.len(), 1, "the pom row is synced, not filtered");
        assert!(results[0].result.is_ok(), "{:?}", results[0].result);
    };

    sync().await;
    let blob = store.lookup_artifact(&key).await.unwrap().unwrap();
    let blob_path = store.get_path(&blob);
    std::fs::remove_file(&blob_path).unwrap();
    sync().await;
    assert_eq!(std::fs::read(&blob_path).unwrap(), POM);
    // The verified POM the first restore read stays in the POM cache.
    assert_eq!(pom_gets.load(Ordering::SeqCst), 1);
}
