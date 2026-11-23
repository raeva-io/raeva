use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rv_config::{Config, RepoConfig, ResolvedPaths, UpdatePolicy};
use rv_maven_types::Coord;
use rv_repo::{RepoClient, Repository};
use rv_test_support::http::StubServer;
use tempfile::TempDir;

use crate::common::{assert_success, pom, run_raeva, with_sha1, with_sha256};

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

/// A repository that serves `t:s:1.0-SNAPSHOT` at build `build`, with a
/// jar of its own bytes for each build.
fn snapshot_repository(build: Arc<AtomicUsize>) -> StubServer {
    StubServer::start(move |request| {
        let n = build.load(Ordering::SeqCst);
        let value = snapshot_build(n);
        let metadata = format!(
            "<metadata><groupId>t</groupId><artifactId>s</artifactId>\
             <version>1.0-SNAPSHOT</version><versioning><snapshot>\
             <timestamp>20260101.12000{n}</timestamp><buildNumber>{n}</buildNumber>\
             </snapshot><lastUpdated>2026010112000{n}</lastUpdated><snapshotVersions>\
             <snapshotVersion><extension>jar</extension><value>{value}</value>\
             </snapshotVersion><snapshotVersion><extension>pom</extension>\
             <value>{value}</value></snapshotVersion></snapshotVersions></versioning>\
             </metadata>"
        );
        let dir = "/t/s/1.0-SNAPSHOT";
        with_sha256(
            &request.path,
            [
                (format!("{dir}/maven-metadata.xml"), metadata),
                (
                    format!("{dir}/s-{value}.pom"),
                    "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                     <artifactId>s</artifactId><version>1.0-SNAPSHOT</version></project>"
                        .to_string(),
                ),
                (format!("{dir}/s-{value}.jar"), format!("snapshot jar {n}")),
            ],
        )
    })
}

fn snapshot_build(n: usize) -> String {
    format!("1.0-20260101.12000{n}-{n}")
}

/// A project of Maven `maven` that depends on `t:s:1.0-SNAPSHOT` from
/// `server`.
fn snapshot_project(server: &StubServer, maven: &str) -> TempDir {
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[lock]\nmaven = \"{maven}\"\n\n[[repositories]]\nid = \"central\"\n\
             url = \"http://{}/\"\nsnapshots = true\n",
            server.addr()
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>s</artifactId>\
             <version>1.0-SNAPSHOT</version></dependency></dependencies>",
        ),
    )
    .unwrap();
    project
}

/// Wait for the start of the next wall-clock second, so the commands that
/// follow run within one second, as `fetched_at` counts them.
fn at_the_next_second() {
    let into = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    std::thread::sleep(
        Duration::from_millis(1010) - Duration::from_nanos(into.subsec_nanos().into()),
    );
}

fn locks_build(project: &TempDir, n: usize) -> bool {
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    lock.contains(&format!("timestamp = \"20260101.12000{n}\""))
}

/// `sync --update` run at once after a sync, in the same second, still asks
/// for the SNAPSHOT's metadata and locks the build deployed since, in both
/// Maven modes.
#[test]
fn an_update_in_the_second_of_the_last_sync_finds_a_new_snapshot_build() {
    for maven in ["3.9", "3.10"] {
        let build = Arc::new(AtomicUsize::new(1));
        let server = snapshot_repository(Arc::clone(&build));
        let project = snapshot_project(&server, maven);
        let home = TempDir::new().unwrap();
        at_the_next_second();
        assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
        assert!(locks_build(&project, 1), "Maven {maven}");
        build.store(2, Ordering::SeqCst);
        let update = run_raeva(project.path(), home.path(), &["sync", "--update"]);
        assert_success(&update, "sync --update");
        assert!(
            locks_build(&project, 2) && !locks_build(&project, 1),
            "Maven {maven}: {}",
            String::from_utf8_lossy(&update.stderr)
        );
    }
}

/// `sync --update` run at once after `seed restore` asks for the metadata the
/// seed restored and locks the build deployed since, in both Maven modes.
#[test]
fn an_update_at_once_after_a_seed_restore_finds_a_new_snapshot_build() {
    for maven in ["3.9", "3.10"] {
        let build = Arc::new(AtomicUsize::new(1));
        let server = snapshot_repository(Arc::clone(&build));
        let project = snapshot_project(&server, maven);
        let (saved, restored) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let seed = saved.path().join("seed");
        let seed = seed.to_str().unwrap();
        assert_success(&run_raeva(project.path(), saved.path(), &["sync"]), "sync");
        assert_success(
            &run_raeva(project.path(), saved.path(), &["seed", "save", seed]),
            "seed save",
        );
        build.store(2, Ordering::SeqCst);
        at_the_next_second();
        assert_success(
            &run_raeva(project.path(), restored.path(), &["seed", "restore", seed]),
            "seed restore",
        );
        let update = run_raeva(project.path(), restored.path(), &["sync", "--update"]);
        assert_success(&update, "sync --update");
        assert!(
            locks_build(&project, 2) && !locks_build(&project, 1),
            "Maven {maven}: {}",
            String::from_utf8_lossy(&update.stderr)
        );
    }
}
