use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rv_config::{Config, RepoConfig, ResolvedPaths, UpdatePolicy};
use rv_maven_types::Coord;
use rv_repo::{RepoClient, Repository};
use rv_test_support::http::StubServer;
use tempfile::TempDir;

use crate::common::{assert_success, run_raeva, with_sha1};

#[tokio::test]
async fn a_parent_range_refreshes_metadata_after_a_cached_release_lookup() {
    let updated = Arc::new(AtomicBool::new(false));
    let remote = Arc::clone(&updated);
    let server = StubServer::start(move |request| {
        let (release, newer) = if remote.load(Ordering::SeqCst) {
            ("1.1", "<version>1.1</version>")
        } else {
            ("1.0", "")
        };
        let metadata = format!(
            "<metadata><groupId>org.example</groupId><artifactId>lib</artifactId>\
             <versioning><release>{release}</release><versions><version>1.0</version>\
             {newer}</versions></versioning></metadata>"
        );
        with_sha1(
            &request.path,
            [
                ("/org/example/lib/maven-metadata.xml", metadata.as_str()),
                (
                    "/org/example/lib/1.0/lib-1.0.pom",
                    "<project><modelVersion>4.0.0</modelVersion><parent>\
                     <groupId>org.example</groupId><artifactId>lib</artifactId>\
                     <version>[1.1,2.0)</version><relativePath/></parent>\
                     <artifactId>lib</artifactId><version>1.0</version></project>",
                ),
                ("/org/example/lib/1.0/lib-1.0.jar", "lib jar"),
                (
                    "/org/example/lib/1.1/lib-1.1.pom",
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
                     <artifactId>lib</artifactId><version>1.1</version><packaging>pom</packaging>\
                     </project>",
                ),
            ],
        )
    });
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let url = format!("http://{}/", server.addr());
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"central\"\nurl = \"{url}\"\nsnapshots = true\n\
             releases-update-policy = \"never\"\nsnapshots-update-policy = \"always\"\n"
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>org.example</groupId><artifactId>lib</artifactId><version>RELEASE</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();

    let config = Config::for_testing_with_repos(
        project.path().to_owned(),
        ResolvedPaths::from_raeva_home(home.path()),
        vec![RepoConfig::new(Some("central"), &url)],
    );
    let mut repo = Repository::new(Some("central".into()), &url, true, true);
    repo.releases_update_policy = UpdatePolicy::Never;
    repo.snapshots_update_policy = UpdatePolicy::Always;
    let client = RepoClient::new(&config).await.unwrap();
    let cached = client
        .fetch_metadata(&repo, &Coord::parse("org.example:lib:1.0").unwrap())
        .await
        .unwrap();
    assert_eq!(cached.versions, ["1.0"]);
    drop(client);
    updated.store(true, Ordering::SeqCst);

    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "resolve RELEASE and its parent range",
    );
    let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).unwrap();
    assert_eq!(lock.platforms[0].artifacts[0].coordinate.version(), "1.0");
    assert!(lock.support_poms().contains_key("org.example:lib:1.1"));
}
