use rv_config::{Config, RepoConfig, ResolvedPaths, UpdatePolicy};
use rv_repo::{RepoClient, Repository};
use rv_version::{Coord, Version};

#[tokio::test]
#[ignore] // Requires network access to the Spring snapshot repository.
async fn resolves_snapshot_version_from_remote_repo() {
    let temp = tempfile::tempdir().expect("temp dir");
    let paths = ResolvedPaths::discover().expect("paths");
    let repo_config = RepoConfig {
        id: Some("spring-snapshot".to_string()),
        url: "https://repo.spring.io/snapshot/".to_string(),
        releases: Some(false),
        snapshots: Some(true),
        snapshots_update_policy: Some(UpdatePolicy::Always),
    };

    let config =
        Config::for_testing_with_repos(temp.path().to_path_buf(), paths, vec![repo_config.clone()]);
    let client = RepoClient::new(&config).await.expect("repo client");

    let repo = Repository::from(&repo_config);
    let coord = Coord {
        group_id: "org.springframework.boot".into(),
        artifact_id: "spring-boot-dependencies".into(),
        version: Version::parse("3.3.0-SNAPSHOT").expect("version"),
        packaging: Some("pom".to_string()),
        classifier: None,
    };

    let resolution = client
        .resolve_snapshot_version(&repo, &coord)
        .await
        .expect("resolve snapshot version");

    assert!(
        !resolution.version.ends_with("-SNAPSHOT"),
        "expected timestamped snapshot, got {}",
        resolution.version
    );
    assert!(
        resolution.snapshot_timestamp.is_some(),
        "expected snapshot timestamp from metadata"
    );
}
