use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rv_test_support::fixtures;
use rv_test_support::http::{Response, StubServer};
use serde_json::Value;
use tempfile::TempDir;

use crate::schemas;

use crate::common::{
    assert_status, assert_success, pom, raeva_command, run_raeva, serve_sha256, sha1_hex,
    sha256_hex, sha256_repository, write_repo_toml, write_with_sha256,
};
use schemas::{assert_schema_valid, cyclonedx_validator};

fn basic_repository() -> PathBuf {
    fixtures::path("reactor-cli/basic-repository")
}

/// Directories under `reactor-cli/` a `fixtures::path` call below opens. A
/// new directory must fail here until a test names it.
fn reactor_cli_dirs() -> Vec<String> {
    let mut names: Vec<String> =
        fixtures::quoted_after(include_str!("reactor_sync.rs"), concat!("path", "("))
            .into_iter()
            .filter_map(|path| path.strip_prefix("reactor-cli/").map(str::to_string))
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .collect();
    names.sort();
    names.dedup();
    names
}

#[test]
fn every_reactor_cli_directory_is_used() {
    let names = reactor_cli_dirs();
    let dirs: Vec<&str> = names.iter().map(String::as_str).collect();
    let root = fixtures::path("reactor-cli");
    fixtures::assert_children(&root, &dirs, &[]);
    for name in &names {
        if name.ends_with("-repository") {
            continue;
        }
        assert!(
            root.join(name).join("pom.xml").is_file(),
            "{name}: pom.xml is missing"
        );
    }
}

fn spawn_repository(root: PathBuf) -> (String, StubServer) {
    let server = StubServer::start(move |request| {
        serve_sha256(&request.path, |path| fs::read(root.join(&path[1..])).ok())
    });
    (format!("http://{}/", server.addr()), server)
}

fn snapshot_publication(advanced: bool) -> (&'static str, u32) {
    if advanced {
        ("20240202.020202", 9)
    } else {
        ("20240101.010101", 7)
    }
}

pub(crate) fn snapshot_route(path: &str, advanced: bool) -> Option<Vec<u8>> {
    let (timestamp, build_number) = snapshot_publication(advanced);
    let resolved = format!("1.0-{timestamp}-{build_number}");
    match path {
        "/org/test/zz-release/1.0/zz-release-1.0.pom" => Some(
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>zz-release</artifactId><version>1.0</version>
</project>"#
                .to_vec(),
        ),
        "/org/test/zz-release/1.0/zz-release-1.0.jar" => Some(b"release artifact bytes".to_vec()),
        "/org/test/snapshot/1.0-SNAPSHOT/maven-metadata.xml" => Some(
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>snapshot</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><snapshot>\
                 <timestamp>{timestamp}</timestamp><buildNumber>{build_number}</buildNumber>\
                 </snapshot><snapshotVersions><snapshotVersion><extension>jar</extension>\
                 <value>{resolved}</value></snapshotVersion><snapshotVersion>\
                 <extension>pom</extension><value>{resolved}</value></snapshotVersion>\
                 </snapshotVersions></versioning></metadata>"
            )
            .into_bytes(),
        ),
        _ if path == format!("/org/test/snapshot/1.0-SNAPSHOT/snapshot-{resolved}.pom") => Some(
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>snapshot</artifactId>
  <version>1.0-SNAPSHOT</version>
</project>"#
                .to_vec(),
        ),
        _ if path == format!("/org/test/snapshot/1.0-SNAPSHOT/snapshot-{resolved}.jar") => {
            Some(format!("snapshot artifact bytes {resolved}").into_bytes())
        }
        _ => None,
    }
}

fn spawn_snapshot_repository() -> (String, Arc<AtomicBool>, StubServer) {
    let advanced = Arc::new(AtomicBool::new(false));
    let server_state = advanced.clone();
    let server = StubServer::start(move |request| {
        let advanced = server_state.load(Ordering::SeqCst);
        serve_sha256(&request.path, |path| snapshot_route(path, advanced))
    });
    (format!("http://{}/", server.addr()), advanced, server)
}

fn spawn_osv(routes: Vec<(&'static str, &'static str)>) -> (String, StubServer) {
    let routes = Mutex::new(routes.into_iter().fold(
        HashMap::<String, VecDeque<&'static str>>::new(),
        |mut routes, (path, body)| {
            routes.entry(path.to_string()).or_default().push_back(body);
            routes
        },
    ));
    let server = StubServer::start(move |request| {
        let body = routes
            .lock()
            .expect("routes")
            .get_mut(&request.path)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| panic!("unexpected OSV request path {}", request.path));
        Response::new(200, body).header("Content-Type", "application/json")
    });
    (format!("http://{}/v1", server.addr()), server)
}

fn write_snapshot_project(project: &Path, repo_url: &str) {
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"snapshot-fixture\"\nurl = \"{repo_url}\"\n\
             releases = true\nsnapshots = true\nsnapshots-update-policy = \"always\"\n"
        ),
    )
    .expect("write snapshot raeva.toml");
    fs::write(
        project.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.test</groupId><artifactId>snapshot-root</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.test</groupId><artifactId>zz-release</artifactId><version>1.0</version>
    </dependency>
    <dependency>
      <groupId>org.test</groupId><artifactId>snapshot</artifactId>
      <version>1.0-SNAPSHOT</version>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .expect("write snapshot pom.xml");
}

fn m2_path(root: &Path, group: &str, artifact: &str, version: &str, extension: &str) -> PathBuf {
    root.join(group.replace('.', "/"))
        .join(artifact)
        .join(version)
        .join(format!("{artifact}-{version}.{extension}"))
}

pub(crate) const TWO_DAYS: i64 = 2 * 24 * 60 * 60;

/// Move the last SNAPSHOT check of every project, and every row of the
/// metadata cache under `home`, `secs` into the past, with raeva.lock's
/// modification time.
pub(crate) fn age_snapshot_checks(home: &Path, lock_path: &Path, secs: i64) {
    use std::time::{Duration, SystemTime};
    fs::File::options()
        .write(true)
        .open(lock_path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(secs as u64))
        .unwrap();
    let cache = rusqlite::Connection::open(home.join("metadata.db")).unwrap();
    let tables: Vec<(String, String)> = cache
        .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (table, sql) in tables {
        let update = if sql.contains("expires_at") {
            "fetched_at = fetched_at - ?1, expires_at = expires_at - ?1"
        } else if sql.contains("checked_at") {
            "checked_at = checked_at - ?1"
        } else {
            continue;
        };
        cache
            .execute(&format!("UPDATE {table} SET {update}"), [secs])
            .unwrap();
    }
}

/// Give the empty home `to` the SNAPSHOT checks `from` recorded, so a
/// plain sync there restores a lock whose SNAPSHOT check is not due.
fn copy_snapshot_checks(from: &Path, to: &Path) {
    let cache = rusqlite::Connection::open(to.join("metadata.db")).unwrap();
    let source = from.join("metadata.db");
    cache
        .execute("ATTACH DATABASE ?1 AS source", [source.to_str().unwrap()])
        .unwrap();
    let schema: String = cache
        .query_row(
            "SELECT sql FROM source.sqlite_master WHERE name = 'snapshot_checks_v3'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    cache.execute_batch(&schema).unwrap();
    cache
        .execute_batch("INSERT INTO snapshot_checks_v3 SELECT * FROM source.snapshot_checks_v3")
        .unwrap();
}

/// `--frozen` and the freshness checks restore the locked SNAPSHOT build
/// whatever the update policy or the time of the last check, also when a
/// POM edit makes them resolve again. A plain sync looks for a newer build
/// once the policy expires.
#[test]
fn frozen_keeps_locked_snapshot_builds_and_plain_sync_follows_the_update_policy() {
    for policy in ["daily", "always"] {
        let project = TempDir::new().expect("project");
        let home = TempDir::new().expect("home");
        let repository = TempDir::new().expect("repository");
        publish_snapshot_repository(repository.path(), false);
        let repo_url = url::Url::from_directory_path(repository.path()).unwrap();
        write_snapshot_project(project.path(), repo_url.as_str());
        let config_path = project.path().join("raeva.toml");
        let config = fs::read_to_string(&config_path).unwrap().replace(
            "snapshots-update-policy = \"always\"",
            &format!("snapshots-update-policy = \"{policy}\""),
        );
        fs::write(config_path, config).unwrap();

        let initial = run_raeva(project.path(), home.path(), &["sync"]);
        assert_success(&initial, "initial snapshot sync");
        let lock_path = project.path().join("raeva.lock");
        let before = fs::read(&lock_path).expect("read initial snapshot lock");
        publish_snapshot_repository(repository.path(), true);
        age_snapshot_checks(home.path(), &lock_path, TWO_DAYS);

        let pom_path = project.path().join("pom.xml");
        let pom = fs::read_to_string(&pom_path).unwrap();
        for edited in [false, true] {
            if edited {
                fs::write(
                    &pom_path,
                    pom.replace("</project>", "<!-- edit --></project>"),
                )
                .unwrap();
            }
            for args in [
                &["sync", "--frozen"][..],
                &["sync", "--frozen", "--offline"],
                &["export-m2", "--dry-run"],
                &["export-m2", "--offline", "--dry-run"],
            ] {
                assert_success(
                    &run_raeva(project.path(), home.path(), args),
                    &format!("{policy} {args:?} edited={edited}"),
                );
                assert_eq!(fs::read(&lock_path).unwrap(), before, "{args:?}");
            }
        }
        fs::write(&pom_path, &pom).unwrap();

        let sync = run_raeva(project.path(), home.path(), &["sync"]);
        assert_success(&sync, "plain sync after the policy expired");
        let stderr = String::from_utf8_lossy(&sync.stderr);
        assert!(
            stderr.contains("1.0-20240101.010101-7 -> 1.0-20240202.020202-9"),
            "{policy}: {stderr}"
        );
    }
}

#[test]
fn only_sync_update_finds_a_snapshot_build_within_its_update_policy() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let repository = TempDir::new().expect("repository");
    publish_snapshot_repository(repository.path(), false);
    let repo_url = url::Url::from_directory_path(repository.path()).unwrap();
    write_snapshot_project(project.path(), repo_url.as_str());
    let config_path = project.path().join("raeva.toml");
    let config = fs::read_to_string(&config_path).unwrap().replace(
        "snapshots-update-policy = \"always\"",
        "snapshots-update-policy = \"daily\"",
    );
    fs::write(config_path, config).unwrap();
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "initial snapshot sync",
    );
    let lock_path = project.path().join("raeva.lock");
    let before = fs::read(&lock_path).unwrap();
    publish_snapshot_repository(repository.path(), true);
    for args in [&["sync"][..], &["sync", "--frozen"]] {
        assert_success(&run_raeva(project.path(), home.path(), args), "keep");
        assert_eq!(fs::read(&lock_path).unwrap(), before, "{args:?}");
    }
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--update"]),
        "sync --update",
    );
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock.contains("timestamp = \"20240202.020202\""), "{lock}");
}

fn platform_profile(os: &str, repositories: &str, dependencies: &str) -> String {
    format!(
        "<profile><id>{os}</id><activation><os><family>{os}</family></os></activation>\
         {repositories}{dependencies}</profile>"
    )
}

fn profile_repository(url: &str, releases: bool, snapshot_policy: &str) -> String {
    format!(
        "<repositories><repository><id>platform</id><url>{url}</url>\
         <releases><enabled>{releases}</enabled></releases>\
         <snapshots><enabled>true</enabled><updatePolicy>{snapshot_policy}</updatePolicy>\
         </snapshots></repository></repositories>"
    )
}

fn profile_dependency(artifact: &str, version: &str) -> String {
    format!(
        "<dependencies><dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
         <version>{version}</version></dependency></dependencies>"
    )
}

fn write_profile_project(project: &Path, profiles: &str) {
    fs::write(
        project.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><profiles>{profiles}</profiles></project>"
        ),
    )
    .unwrap();
}

fn snapshot_platform_project(project: &Path, linux: &Path, windows: &Path) {
    let linux = url::Url::from_directory_path(linux).unwrap();
    let windows = url::Url::from_directory_path(windows).unwrap();
    // Leave repository policies to each platform's POM profile.
    fs::write(project.join("raeva.toml"), "repositories = []\n").unwrap();
    let dependency = profile_dependency("snapshot", "1.0-SNAPSHOT");
    write_profile_project(
        project,
        &(platform_profile(
            "unix",
            &profile_repository(linux.as_str(), true, "daily"),
            &dependency,
        ) + &platform_profile(
            "windows",
            &profile_repository(windows.as_str(), true, "always"),
            &dependency,
        )),
    );
}

fn snapshot_and_bom_platform_project(project: &Path, linux: &Path, windows: &Path, policy: &str) {
    publish_snapshot_repository(linux, false);
    let bom = windows.join("org/test/bom/1/bom-1.pom");
    fs::create_dir_all(bom.parent().unwrap()).unwrap();
    fs::write(
        bom,
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>bom</artifactId><version>1</version><packaging>pom</packaging></project>",
    )
    .unwrap();
    fs::write(project.join("raeva.toml"), "repositories = []\n").unwrap();
    write_profile_project(
        project,
        &(platform_profile(
            "unix",
            &profile_repository(
                url::Url::from_directory_path(linux).unwrap().as_str(),
                true,
                policy,
            ),
            &profile_dependency("snapshot", "1.0-SNAPSHOT"),
        ) + &platform_profile(
            "windows",
            &profile_repository(
                url::Url::from_directory_path(windows).unwrap().as_str(),
                true,
                "daily",
            )
            .replace("<id>platform</id>", "<id>windows</id>"),
            "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope>\
             </dependency></dependencies></dependencyManagement>",
        )),
    );
}

#[test]
fn frozen_partial_resolution_downloads_only_resolved_support_poms() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let linux = TempDir::new().unwrap();
    let windows = TempDir::new().unwrap();
    snapshot_and_bom_platform_project(project.path(), linux.path(), windows.path(), "always");
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64,windows-x86_64"],
        ),
        "initial platforms",
    );
    let lock_path = project.path().join("raeva.lock");
    let before = fs::read(&lock_path).unwrap();
    for args in [
        &["sync", "--platforms", "linux-x86_64"][..],
        &["sync", "--frozen", "--platforms", "linux-x86_64"],
    ] {
        let cold = TempDir::new().unwrap();
        assert_success(
            &run_raeva(project.path(), cold.path(), args),
            "cold partial resolution",
        );
        assert_eq!(fs::read(&lock_path).unwrap(), before);
    }
}

#[test]
fn support_pom_trust_uses_all_restoration_contexts() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let linux = TempDir::new().unwrap();
    let windows = TempDir::new().unwrap();
    snapshot_and_bom_platform_project(project.path(), linux.path(), windows.path(), "daily");
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64,windows-x86_64"],
        ),
        "initial platforms",
    );
    let lock_path = project.path().join("raeva.lock");
    let before = fs::read(&lock_path).unwrap();
    publish_snapshot_repository(linux.path(), true);
    let advanced = linux
        .path()
        .join("org/test/snapshot/1.0-SNAPSHOT/snapshot-1.0-20240202.020202-9.pom");
    let pom = fs::read_to_string(&advanced).unwrap().replace(
        "</project>",
        &(profile_dependency("missing", "1") + "</project>"),
    );
    fs::write(advanced, pom).unwrap();
    for args in [
        &["sync", "--platforms", "linux-x86_64,windows-x86_64"][..],
        &[
            "sync",
            "--frozen",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ],
    ] {
        let cold = TempDir::new().unwrap();
        copy_snapshot_checks(home.path(), cold.path());
        assert_success(
            &run_raeva(project.path(), cold.path(), args),
            "restore without refreshing daily snapshot",
        );
        assert_eq!(fs::read(&lock_path).unwrap(), before);
    }
}

#[test]
fn frozen_partial_sync_ignores_other_platforms_snapshot_expiry() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let linux = TempDir::new().unwrap();
    let windows = TempDir::new().unwrap();
    publish_snapshot_repository(linux.path(), false);
    publish_snapshot_repository(windows.path(), false);
    snapshot_platform_project(project.path(), linux.path(), windows.path());
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64,windows-x86_64"],
        ),
        "initial platforms",
    );
    let lock_path = project.path().join("raeva.lock");
    let before = fs::read(&lock_path).unwrap();
    publish_snapshot_repository(linux.path(), true);
    for args in [
        &["sync", "--platforms", "linux-x86_64"][..],
        &["sync", "--frozen", "--platforms", "linux-x86_64"],
    ] {
        assert_success(&run_raeva(project.path(), home.path(), args), "reuse Linux");
        assert_eq!(fs::read(&lock_path).unwrap(), before);
    }
}

#[test]
fn plain_sync_refreshes_recorded_platforms_and_frozen_keeps_their_builds() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let linux = TempDir::new().unwrap();
    let windows = TempDir::new().unwrap();
    publish_snapshot_repository(linux.path(), false);
    publish_snapshot_repository(windows.path(), false);
    snapshot_platform_project(project.path(), linux.path(), windows.path());
    // Only Windows depends on the SNAPSHOT, avoiding a cross-platform pin conflict.
    let pom_path = project.path().join("pom.xml");
    let pom = fs::read_to_string(&pom_path).unwrap();
    fs::write(
        &pom_path,
        pom.replacen(&profile_dependency("snapshot", "1.0-SNAPSHOT"), "", 1),
    )
    .unwrap();
    let platforms = format!(
        "linux-x86_64,windows-x86_64,{}",
        rv_lock::Platform::current().unwrap()
    );
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", &platforms],
        ),
        "initial platforms",
    );
    let lock_path = project.path().join("raeva.lock");
    let before = fs::read(&lock_path).unwrap();
    publish_snapshot_repository(windows.path(), true);
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
        "frozen keeps the Windows SNAPSHOT build",
    );
    assert_eq!(fs::read(&lock_path).unwrap(), before);
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "refresh Windows",
    );
    let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    assert!(lock.contains("20240202.020202"), "{lock}");
}

#[test]
fn frozen_restore_uses_the_selected_platforms_release_policy() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let repository = TempDir::new().unwrap();
    publish_snapshot_repository(repository.path(), false);
    fs::write(project.path().join("raeva.toml"), "repositories = []\n").unwrap();
    let url = url::Url::from_directory_path(repository.path()).unwrap();
    write_profile_project(
        project.path(),
        &(platform_profile(
            "unix",
            &profile_repository(url.as_str(), false, "daily"),
            "",
        ) + &platform_profile(
            "windows",
            &profile_repository(url.as_str(), true, "daily"),
            &profile_dependency("zz-release", "1.0"),
        )),
    );
    let current = rv_lock::Platform::current().unwrap().to_string();
    for platforms in ["windows-x86_64", "linux-x86_64", &current] {
        assert_success(
            &run_raeva(
                project.path(),
                home.path(),
                &["sync", "--platforms", platforms],
            ),
            "lock platform",
        );
    }
    for args in [
        &["sync", "--platforms", "windows-x86_64"][..],
        &["sync", "--frozen", "--platforms", "windows-x86_64"],
        &["sync", "--frozen"],
        &["sync"],
    ] {
        let cold = TempDir::new().unwrap();
        assert_success(
            &run_raeva(project.path(), cold.path(), args),
            "cold Windows restoration",
        );
    }
}

#[test]
fn frozen_origin_authorization_uses_each_platforms_settings() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    for repository in [&a, &b] {
        publish_snapshot_repository(repository.path(), false);
    }
    let a_url = url::Url::from_directory_path(a.path()).unwrap().to_string();
    let b_url = url::Url::from_directory_path(b.path()).unwrap().to_string();
    fs::write(project.path().join("raeva.toml"), "repositories = []\n").unwrap();
    let settings = format!(
        "<settings><profiles>{}{}</profiles></settings>",
        platform_profile(
            "unix",
            &profile_repository(&a_url, true, "daily")
                .replace("<id>platform</id>", "<id>linux</id>"),
            ""
        ),
        platform_profile(
            "windows",
            &profile_repository(&b_url, true, "daily")
                .replace("<id>platform</id>", "<id>windows</id>"),
            ""
        )
    );
    fs::create_dir(home.path().join(".m2")).unwrap();
    fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
    write_profile_project(
        project.path(),
        &platform_profile("unix", "", &profile_dependency("zz-release", "1.0")),
    );
    let platforms = format!(
        "linux-x86_64,windows-x86_64,{}",
        rv_lock::Platform::current().unwrap()
    );
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", &platforms],
        ),
        "initial platforms",
    );
    let lock_path = project.path().join("raeva.lock");
    let mut lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    lock.platforms
        .iter_mut()
        .find(|p| p.platform.os() == "linux")
        .unwrap()
        .artifacts[0]
        .repo_url = crate::common::recorded_origin(project.path(), &b_url);
    let tampered = lock.to_toml().unwrap();
    for platforms in [Some("linux-x86_64"), None] {
        fs::write(&lock_path, &tampered).unwrap();
        let cold = TempDir::new().unwrap();
        fs::create_dir(cold.path().join(".m2")).unwrap();
        fs::write(cold.path().join(".m2/settings.xml"), &settings).unwrap();
        let mut args = vec!["sync", "--frozen"];
        if let Some(platforms) = platforms {
            args.extend(["--platforms", platforms]);
        }
        let frozen = run_raeva(project.path(), cold.path(), &args);
        assert_status(&frozen, 7, "frozen refuses the tampered origin");
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), tampered);
        args.remove(1);
        assert_success(
            &run_raeva(project.path(), home.path(), &args),
            "repair origin",
        );
        let repaired = rv_lock::Lockfile::read(&lock_path).unwrap();
        assert_eq!(
            repaired
                .platforms
                .iter()
                .find(|p| p.platform.os() == "linux")
                .unwrap()
                .artifacts[0]
                .repo_url,
            crate::common::recorded_origin(project.path(), &a_url)
        );
    }
}

#[test]
fn frozen_partial_resolution_resolves_a_changed_unselected_platform() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::write(project.path().join("raeva.toml"), "repositories = []\n").unwrap();
    write_profile_project(
        project.path(),
        &platform_profile(
            "windows",
            "",
            "<properties><changed>false</changed></properties>",
        ),
    );
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64,windows-x86_64"],
        ),
        "initial platforms",
    );
    // Plain partial sync drops Windows because its recorded model changed;
    // frozen resolves it instead, and its graph is the same.
    write_profile_project(
        project.path(),
        &platform_profile(
            "windows",
            "",
            "<properties><changed>true</changed></properties>",
        ),
    );
    for offline in [&[][..], &["--offline"]] {
        let args = [
            &["sync", "--frozen", "--platforms", "linux-x86_64"],
            offline,
        ]
        .concat();
        let frozen = run_raeva(project.path(), home.path(), &args);
        assert_success(&frozen, &format!("{args:?} resolves the Windows model"));
    }
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64"],
        ),
        "drop stale Windows model",
    );
    let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).unwrap();
    assert_eq!(lock.platforms.len(), 1);
}

/// The other platforms a changed model makes frozen resolve use the
/// repositories their own settings profiles declare.
#[test]
fn frozen_resolves_a_changed_unselected_platform_through_its_settings() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let windows = TempDir::new().unwrap();
    publish_snapshot_repository(windows.path(), false);
    let (windows_url, _server) = spawn_repository(windows.path().to_path_buf());
    fs::write(project.path().join("raeva.toml"), "repositories = []\n").unwrap();
    let settings = format!(
        "<settings><profiles>{}</profiles></settings>",
        platform_profile(
            "windows",
            &profile_repository(&windows_url, true, "daily")
                .replace("<id>platform</id>", "<id>windows</id>"),
            ""
        )
    );
    fs::create_dir(home.path().join(".m2")).unwrap();
    fs::write(home.path().join(".m2/settings.xml"), &settings).unwrap();
    write_profile_project(
        project.path(),
        &platform_profile("windows", "", &profile_dependency("zz-release", "1.0")),
    );
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", "linux-x86_64,windows-x86_64"],
        ),
        "initial platforms",
    );
    let pom = project.path().join("pom.xml");
    let text = fs::read_to_string(&pom).unwrap();
    fs::write(&pom, text.replace("</project>", "<!-- edit --></project>")).unwrap();
    let cold = TempDir::new().unwrap();
    fs::create_dir(cold.path().join(".m2")).unwrap();
    fs::write(cold.path().join(".m2/settings.xml"), &settings).unwrap();
    assert_success(
        &run_raeva(
            project.path(),
            cold.path(),
            &["sync", "--frozen", "--platforms", "linux-x86_64"],
        ),
        "frozen resolves Windows through its settings repository",
    );
}

/// A repository only the POM declares renews a locked SNAPSHOT by its own
/// update policy, so a plain sync resolves again instead of reusing the lock.
#[test]
fn a_pom_declared_snapshot_policy_renews_the_lock() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let (repo_url, advanced, _server) = spawn_snapshot_repository();
    let empty = StubServer::start(|_| Response::new(404, ""));
    write_snapshot_project(project.path(), &format!("http://{}/", empty.addr()));
    let pom_path = project.path().join("pom.xml");
    let pom = fs::read_to_string(&pom_path)
        .expect("read pom.xml")
        .replace(
            "  <dependencies>",
            &format!(
                "  <repositories><repository><id>pom-snapshots</id><url>{repo_url}</url>\
             <snapshots><enabled>true</enabled><updatePolicy>always</updatePolicy></snapshots>\
             </repository></repositories>\n  <dependencies>"
            ),
        );
    fs::write(&pom_path, pom).expect("write pom.xml");

    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "initial snapshot sync",
    );
    advanced.store(true, Ordering::SeqCst);
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "sync after a new snapshot build",
    );
    let lock = fs::read_to_string(project.path().join("raeva.lock")).expect("read lock");
    assert!(lock.contains("timestamp = \"20240202.020202\""), "{lock}");
}

#[test]
fn frozen_downloads_use_each_platforms_settings_client() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let cold = TempDir::new().expect("cold home");
    let cold_after_edit = TempDir::new().expect("cold home after edit");
    let (repo_url, _server) = spawn_repository(basic_repository());
    let empty = StubServer::start(|_| Response::new(404, ""));
    let empty_url = format!("http://{}/", empty.addr());
    write_repo_toml(project.path(), "fixture", &empty_url);
    let (family, other, checked_family) = if cfg!(windows) {
        ("unix", "linux-x86_64", "windows")
    } else {
        ("windows", "windows-x86_64", "unix")
    };
    let settings = format!(
        "<settings><profiles>\
         <profile><id>other</id><activation><os><family>{family}</family></os></activation>\
         <repositories><repository><id>platform</id><url>{repo_url}</url></repository>\
         </repositories></profile>\
         <profile><id>checked</id><activation><os><family>{checked_family}</family></os></activation>\
         <repositories><repository><id>platform</id><url>{empty_url}</url></repository>\
         </repositories></profile></profiles></settings>"
    );
    for home in [&home, &cold, &cold_after_edit] {
        fs::create_dir(home.path().join(".m2")).expect("isolated Maven home");
        fs::write(home.path().join(".m2/settings.xml"), &settings).expect("settings");
    }
    fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><profiles><profile>\
             <id>other</id><activation><os><family>{family}</family></os></activation>\
             <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope>\
             </dependency></dependencies></dependencyManagement><dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>app-only</artifactId><version>1</version>\
             </dependency></dependencies></profile></profiles></project>"
        ),
    )
    .expect("pom.xml");
    let current = rv_lock::Platform::current().unwrap().to_string();
    assert_success(
        &run_raeva(
            project.path(),
            home.path(),
            &["sync", "--platforms", &format!("{current},{other}")],
        ),
        "initial two-platform sync",
    );
    let lock_path = project.path().join("raeva.lock");
    let before = fs::read(&lock_path).unwrap();
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert!(
        lock.platforms
            .iter()
            .any(|entry| entry.platform.to_string() == other && !entry.artifacts.is_empty())
    );
    assert!(lock.support_poms().contains_key("org.test:bom:1"));
    assert_success(
        &run_raeva(project.path(), cold.path(), &["sync", "--frozen"]),
        "cold frozen sync",
    );
    assert_eq!(fs::read(&lock_path).unwrap(), before);
    let pom_path = project.path().join("pom.xml");
    let pom = fs::read_to_string(&pom_path).unwrap();
    fs::write(
        &pom_path,
        pom.replace("</project>", "<!-- edit --></project>"),
    )
    .unwrap();
    assert_success(
        &run_raeva(
            project.path(),
            cold_after_edit.path(),
            &["sync", "--frozen"],
        ),
        "cold frozen resolution uses every recorded platform's settings",
    );
    assert_eq!(fs::read(&lock_path).unwrap(), before);
    let m2 = project.path().join("export");
    assert_success(
        &run_raeva(
            project.path(),
            cold.path(),
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        ),
        "export all platforms",
    );
    for (artifact, extension) in [
        ("app-only", "jar"),
        ("app-only", "pom"),
        ("bom", "pom"),
        ("bom-parent", "pom"),
    ] {
        assert!(
            m2_path(&m2, "org.test", artifact, "1", extension).is_file(),
            "{artifact}.{extension}"
        );
    }
}

fn publish_snapshot_repository(root: &Path, advanced: bool) {
    let (timestamp, build) = snapshot_publication(advanced);
    for path in [
        "/org/test/zz-release/1.0/zz-release-1.0.pom".to_string(),
        "/org/test/zz-release/1.0/zz-release-1.0.jar".to_string(),
        "/org/test/snapshot/1.0-SNAPSHOT/maven-metadata.xml".to_string(),
        format!("/org/test/snapshot/1.0-SNAPSHOT/snapshot-1.0-{timestamp}-{build}.pom"),
        format!("/org/test/snapshot/1.0-SNAPSHOT/snapshot-1.0-{timestamp}-{build}.jar"),
    ] {
        let file = root.join(&path[1..]);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, snapshot_route(&path, advanced).unwrap()).unwrap();
    }
}

#[test]
fn remote_parent_snapshot_policy_prevents_stale_lock_reuse() {
    for snapshots in [
        "<enabled>true</enabled><updatePolicy>${snapshot.policy}</updatePolicy>",
        "<enabled>${snapshot.enabled}</enabled><updatePolicy>always</updatePolicy>",
    ] {
        let project = TempDir::new().expect("project");
        let home = TempDir::new().expect("home");
        let repository = TempDir::new().expect("repository");
        publish_snapshot_repository(repository.path(), false);
        let parent = repository.path().join("org/test/parent/1/parent-1.pom");
        fs::create_dir_all(parent.parent().unwrap()).unwrap();
        fs::write(
            parent,
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
             <properties><snapshot.policy>always</snapshot.policy>\
             <snapshot.enabled>true</snapshot.enabled></properties></project>",
        )
        .unwrap();
        let url = url::Url::from_directory_path(repository.path()).unwrap();
        let empty = TempDir::new().expect("unused repository");
        let unused = url::Url::from_directory_path(empty.path()).unwrap();
        write_snapshot_project(project.path(), unused.as_str());
        write_repo_toml(project.path(), "fixture", unused.as_str());
        let pom_path = project.path().join("pom.xml");
        let pom = fs::read_to_string(&pom_path).unwrap().replace(
            "  <dependencies>",
            &format!(
                "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
                 <version>1</version><relativePath/></parent><repositories><repository>\
                 <id>pom-snapshots</id><url>{url}</url><snapshots>{snapshots}</snapshots>\
                 </repository></repositories><dependencies>"
            ),
        );
        fs::write(pom_path, pom).unwrap();
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync"]),
            "initial sync",
        );
        publish_snapshot_repository(repository.path(), true);
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync"]),
            "renew snapshot",
        );
        let lock = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
        assert!(
            lock.contains("timestamp = \"20240202.020202\""),
            "{snapshots}: {lock}"
        );
    }
}

/// A POM repository with the id of a configured one is superseded by it,
/// policy included; under another id at the same URL it is a repository of
/// its own, whose `always` policy refreshes the SNAPSHOT.
#[test]
fn superseded_pom_snapshot_policy_keeps_warm_sync_local() {
    // The POM's declaration under the configured id is superseded, at the
    // same URL or another one, and a blocked one counts for nothing. One
    // under the id of built-in Central replaces it.
    for (id, elsewhere, superseded) in [
        ("snapshot-fixture", "", true),
        ("snapshot-fixture", "other", true),
        ("pom", "http", true),
        ("pom", "", false),
        ("central", "unconfigured", false),
    ] {
        let project = TempDir::new().expect("project");
        let other = TempDir::new().expect("other repository");
        let home = TempDir::new().expect("home");
        let repository = TempDir::new().expect("repository");
        publish_snapshot_repository(repository.path(), false);
        let repo_url = url::Url::from_directory_path(repository.path()).unwrap();
        write_snapshot_project(project.path(), repo_url.as_str());
        let config_path = project.path().join("raeva.toml");
        let config = fs::read_to_string(&config_path).unwrap().replace(
            "snapshots-update-policy = \"always\"",
            "snapshots-update-policy = \"never\"\nreleases-update-policy = \"always\"",
        );
        let config = if elsewhere == "unconfigured" {
            String::new()
        } else {
            config
        };
        fs::write(config_path, config).unwrap();
        let pom_url = match elsewhere {
            "other" => url::Url::from_directory_path(other.path()).unwrap(),
            "http" => url::Url::parse("http://repo.invalid/").unwrap(),
            _ => repo_url.clone(),
        };
        let pom_path = project.path().join("pom.xml");
        let pom = fs::read_to_string(&pom_path).unwrap().replace(
            "  <dependencies>",
            &format!(
                "<repositories><repository><id>{id}</id><url>{pom_url}</url><snapshots>\
                 <enabled>true</enabled><updatePolicy>always</updatePolicy></snapshots>\
                 </repository></repositories><dependencies>"
            ),
        );
        fs::write(pom_path, pom).unwrap();
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync"]),
            "initial sync",
        );
        let lock_path = project.path().join("raeva.lock");
        let before = fs::read(&lock_path).unwrap();
        publish_snapshot_repository(repository.path(), true);
        let sync = run_raeva(project.path(), home.path(), &["sync"]);
        assert_success(&sync, "warm sync");
        let stderr = String::from_utf8_lossy(&sync.stderr);
        assert_eq!(
            stderr.contains("Checked"),
            superseded,
            "{id} {elsewhere}: {stderr}"
        );
        assert_eq!(
            fs::read(lock_path).unwrap() == before,
            superseded,
            "{id} {elsewhere}"
        );
    }
}

#[test]
fn reactor_json_tree_and_why_use_module_results() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    fixtures::copy_tree_lf(&fixtures::path("reactor-cli/basic"), project.path());
    let repo_url = url::Url::from_directory_path(basic_repository()).unwrap();
    write_repo_toml(project.path(), "fixture", repo_url.as_str());
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--offline"]),
        "reactor sync",
    );

    let why = run_raeva(
        project.path(),
        home.path(),
        &["--json", "why", "org.test:shared"],
    );
    assert_success(&why, "reactor JSON why");
    let why: Value = serde_json::from_slice(&why.stdout).expect("why JSON");
    assert!(why["data"].get("paths").is_none(), "{why}");
    let modules = why["data"]["modules"].as_array().expect("why modules");
    assert_eq!(
        modules
            .iter()
            .map(|module| &module["module"])
            .collect::<Vec<_>>(),
        ["app/pom.xml", "lib/pom.xml", "pom.xml"]
    );
    assert_eq!(
        modules[0]["paths"],
        serde_json::json!([
            ["org.test:shared:1:jar"],
            ["com.example:lib:1:jar", "org.test:shared:1:jar"]
        ])
    );
    assert_eq!(
        modules[1]["paths"],
        serde_json::json!([["org.test:shared:1:jar"]])
    );
    assert_eq!(modules[2]["paths"], serde_json::json!([]));
    for module in modules {
        for path in module["paths"].as_array().expect("module paths") {
            let path = path.as_array().expect("path");
            assert_eq!(path.last().unwrap(), "org.test:shared:1:jar");
            for step in path {
                assert!(!step.as_str().expect("coordinate").contains("(workspace)"));
            }
        }
    }

    let tree = run_raeva(project.path(), home.path(), &["--json", "tree"]);
    assert_success(&tree, "reactor JSON tree");
    let tree: Value = serde_json::from_slice(&tree.stdout).expect("tree JSON");
    assert!(tree["data"].get("dependencies").is_none(), "{tree}");
    let modules = tree["data"]["modules"].as_array().expect("tree modules");
    assert_eq!(
        modules
            .iter()
            .map(|module| &module["module"])
            .collect::<Vec<_>>(),
        ["app/pom.xml", "lib/pom.xml", "pom.xml"]
    );
    assert_eq!(
        modules[0]["dependencies"][0]["coordinate"],
        "com.example:lib:1:jar"
    );
    assert_eq!(modules[0]["dependencies"][0]["workspace"], true);
    assert_eq!(
        modules[1]["dependencies"][0]["coordinate"],
        "org.test:shared:1:jar"
    );
    assert_eq!(modules[2]["dependencies"], serde_json::json!([]));
}

#[test]
fn reactor_sync_frozen_diff_and_exports_are_module_aware() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    fixtures::copy_tree_lf(&fixtures::path("reactor-cli/basic"), project.path());
    let (repo_url, _repo_url_server) = spawn_repository(basic_repository());
    write_repo_toml(project.path(), "fixture", &repo_url);

    let first = run_raeva(project.path(), home.path(), &["sync"]);
    assert_success(&first, "initial reactor sync");
    let lock_path = project.path().join("raeva.lock");
    let first_bytes = fs::read(&lock_path).expect("read first lock");
    let lock = rv_lock::Lockfile::read(&lock_path).expect("parse reactor lock");
    assert!(first_bytes.starts_with(
        b"# This file is automatically @generated by raeva.\n\
          # It is not intended for manual editing.\n\
          schema_version = 9\n"
    ));
    let platform = lock.platforms.first().expect("platform");
    assert_eq!(
        platform
            .modules
            .iter()
            .map(|module| module.path.as_str())
            .collect::<Vec<_>>(),
        ["app/pom.xml", "lib/pom.xml", "pom.xml"]
    );
    assert_eq!(
        platform
            .artifacts
            .iter()
            .filter(|artifact| artifact.coordinate.artifact_id() == "shared")
            .count(),
        1,
        "shared external must be deduplicated in the artifact union"
    );

    let app = platform
        .modules
        .iter()
        .find(|module| module.path == "app/pom.xml")
        .expect("app module");
    let sibling_index = app
        .packages
        .iter()
        .position(|package| package.workspace_module.as_deref() == Some("lib/pom.xml"))
        .expect("workspace sibling marker");
    let shared_index = app
        .packages
        .iter()
        .position(|package| package.coordinate.artifact_id() == "shared")
        .expect("shared package");
    assert!(
        app.edges
            .iter()
            .any(|edge| edge.from == sibling_index && edge.to == shared_index),
        "workspace sibling must retain its edge to the shared external"
    );

    let aggregate_verify = run_raeva(project.path(), home.path(), &["--json", "lock", "verify"]);
    assert_success(&aggregate_verify, "aggregate reactor lock verify");
    let aggregate_verify: Value =
        serde_json::from_slice(&aggregate_verify.stdout).expect("aggregate verify JSON");
    assert_eq!(
        aggregate_verify["data"]["verified"], 7,
        "two jars, their POMs, a parent, a BOM and its parent"
    );
    assert_eq!(aggregate_verify["data"]["workspace_skipped"], 1);
    assert_eq!(
        aggregate_verify["data"]["workspace_entries"][0]["workspace_module"],
        "lib/pom.xml"
    );

    let shared_digest = platform
        .artifacts
        .iter()
        .find(|artifact| artifact.coordinate.artifact_id() == "shared")
        .and_then(|artifact| {
            artifact
                .checksums
                .iter()
                .find_map(rv_maven_types::Digest::as_sha256)
        })
        .expect("shared SHA-256")
        .to_string();
    let shared_blob = home
        .path()
        .join("store/blobs")
        .join(&shared_digest[0..2])
        .join(&shared_digest[2..4])
        .join(&shared_digest);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&shared_blob)
            .expect("shared blob metadata")
            .permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&shared_blob, permissions).expect("make shared blob writable");
    }
    fs::write(&shared_blob, b"corrupt shared artifact").expect("corrupt shared blob");
    let corrupt_verify = run_raeva(project.path(), home.path(), &["--json", "lock", "verify"]);
    assert_status(&corrupt_verify, 7, "verify corrupt shared blob");
    let corrupt_verify: Value =
        serde_json::from_slice(&corrupt_verify.stdout).expect("corrupt verify JSON");
    assert_eq!(corrupt_verify["data"]["corrupt"], 1);
    assert_eq!(
        corrupt_verify["data"]["corrupt_artifacts"][0]["affected_modules"],
        serde_json::json!(["app/pom.xml", "lib/pom.xml"])
    );
    fs::write(&shared_blob, b"shared artifact bytes").expect("restore shared blob");

    let tree = run_raeva(project.path(), home.path(), &["tree"]);
    assert_success(&tree, "aggregate reactor tree");
    let tree = String::from_utf8(tree.stdout).expect("tree output");
    for module in ["app/pom.xml", "lib/pom.xml", "pom.xml"] {
        assert!(
            tree.contains(&format!("Module: {module}")),
            "aggregate tree must contain a section for {module}: {tree}"
        );
    }
    assert!(
        tree.contains("com.example:lib:1 (compile, workspace)"),
        "workspace sibling must render distinctly: {tree}"
    );

    let why = run_raeva(project.path(), home.path(), &["why", "org.test:shared"]);
    assert_success(&why, "aggregate reactor why");
    let why = String::from_utf8(why.stdout).expect("why output");
    assert!(why.contains("Module: app/pom.xml"));
    assert!(why.contains("Module: lib/pom.xml"));
    assert!(
        why.contains("com.example:lib:1 (workspace) -> org.test:shared:1"),
        "why must trace through the workspace sibling: {why}"
    );

    let (osv_url, osv) = spawn_osv(vec![(
        "/v1/querybatch",
        r#"{"results":[{"vulns":[]},{"vulns":[]}]}"#,
    )]);
    let aggregate_vuln = raeva_command(project.path(), home.path())
        .arg("vuln")
        .env("RAEVA_OSV_BASE_URL", osv_url)
        .output()
        .expect("run aggregate vuln");
    assert_success(&aggregate_vuln, "aggregate reactor vuln");
    let requests: Vec<_> = osv
        .requests()
        .into_iter()
        .map(|request| request.raw)
        .collect();
    osv.stop();
    assert_eq!(requests.len(), 1, "aggregate scan uses one OSV query set");
    let request = &requests[0];
    assert!(request.contains("pkg:maven/org.test/app-only@1"));
    assert!(request.contains("pkg:maven/org.test/shared@1"));
    assert_eq!(
        request.matches("pkg:maven/org.test/shared@1").count(),
        1,
        "shared external must be queried once across modules: {request}"
    );
    assert!(
        !request.contains("pkg:maven/com.example/lib@1"),
        "workspace modules must never be queried: {request}"
    );

    let (osv_url, osv) = spawn_osv(vec![
        (
            "/v1/querybatch",
            r#"{"results":[{"vulns":[]},{"vulns":[{"id":"OSV-SHARED"}]}]}"#,
        ),
        (
            "/v1/vulns/OSV-SHARED",
            r#"{"id":"OSV-SHARED","summary":"shared finding","severity":[{"type":"CVSS_V3","score":"7.5"}],"affected":[]}"#,
        ),
    ]);
    let findings = raeva_command(project.path(), home.path())
        .args(["--json", "vuln"])
        .env("RAEVA_OSV_BASE_URL", osv_url)
        .output()
        .expect("run aggregate vuln findings");
    assert_status(&findings, 1, "aggregate vuln findings");
    let findings: serde_json::Value =
        serde_json::from_slice(&findings.stdout).expect("vuln findings JSON");
    assert_eq!(
        findings["data"]["results"][0]["affected_modules"],
        serde_json::json!(["app/pom.xml", "lib/pom.xml"])
    );
    assert_eq!(osv.requests().len(), 2);
    osv.stop();

    let cyclonedx_first = run_raeva(project.path(), home.path(), &["sbom"]);
    let cyclonedx_second = run_raeva(project.path(), home.path(), &["sbom"]);
    assert_success(&cyclonedx_first, "aggregate CycloneDX");
    assert_success(&cyclonedx_second, "repeat aggregate CycloneDX");
    assert_eq!(
        cyclonedx_first.stdout, cyclonedx_second.stdout,
        "aggregate CycloneDX must be byte-identical"
    );
    let cyclonedx: Value =
        serde_json::from_slice(&cyclonedx_first.stdout).expect("aggregate CycloneDX JSON");
    assert_schema_valid(&cyclonedx_validator(), &cyclonedx);
    let components = cyclonedx["components"].as_array().expect("components");
    let first_party_components = components
        .iter()
        .filter(|component| component["group"] == "com.example")
        .count()
        + usize::from(cyclonedx["metadata"]["component"]["group"] == "com.example");
    assert_eq!(
        first_party_components, 3,
        "all reactor modules, including the metadata root, are first-party components"
    );
    for module in ["reactor", "app", "lib"] {
        let component = if module == "reactor" {
            &cyclonedx["metadata"]["component"]
        } else {
            components
                .iter()
                .find(|component| component["name"] == module)
                .unwrap_or_else(|| panic!("missing first-party component {module}"))
        };
        assert!(
            component.get("hashes").is_none(),
            "first-party module {module} must not have download hashes"
        );
    }
    for command in [
        vec!["tree", "--module", "missing/pom.xml"],
        vec!["why", "org.test:shared", "--module", "missing/pom.xml"],
        vec!["vuln", "--module", "missing/pom.xml"],
        vec!["sbom", "--module", "missing/pom.xml"],
        vec!["lock", "verify", "--module", "missing/pom.xml"],
    ] {
        let output = run_raeva(project.path(), home.path(), &command);
        assert_status(&output, 2, &command.join(" "));
        let error = String::from_utf8(output.stderr).expect("selector error");
        assert!(error.contains("matches no module"), "{error}");
        assert!(error.contains("app/pom.xml"), "{error}");
        assert!(error.contains("lib/pom.xml"), "{error}");
        assert!(error.contains("pom.xml"), "{error}");
    }

    let second = run_raeva(project.path(), home.path(), &["sync"]);
    assert_success(&second, "idempotent reactor sync");
    assert_eq!(
        first_bytes,
        fs::read(&lock_path).expect("read second lock"),
        "unchanged re-sync must be byte-identical"
    );
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--frozen"]),
        "frozen reactor sync",
    );

    let m2 = project.path().join("m2-export");
    let exported = run_raeva(
        project.path(),
        home.path(),
        &["export-m2", "--m2-path", m2.to_str().expect("m2 path")],
    );
    assert_success(&exported, "reactor export-m2");
    assert!(m2_path(&m2, "org.test", "shared", "1", "jar").is_file());
    assert!(m2_path(&m2, "org.test", "app-only", "1", "jar").is_file());
    assert!(
        !m2_path(&m2, "com.example", "lib", "1", "jar").exists(),
        "workspace sibling must never be exported"
    );
    for support in ["external-parent", "bom", "bom-parent"] {
        assert!(
            m2_path(&m2, "org.test", support, "1", "pom").is_file(),
            "support POM {support} must be exported"
        );
    }

    let checksums = run_raeva(project.path(), home.path(), &["export-checksums"]);
    assert_success(&checksums, "reactor export-checksums");
    let checksum_text = fs::read_to_string(project.path().join(".mvn/checksums/checksums.sha256"))
        .expect("read checksums");
    assert_eq!(checksum_text.matches("shared-1.jar").count(), 1);
    assert!(!checksum_text.contains("lib-1.jar"));
}

/// `raeva sync` must pin the bytes of every POM it exports later: the companion
/// POM of each locked artifact (on the artifact row) and each support POM
/// (parent / imported BOM, in the recorded provenance). The store's coordinate
/// index is last-writer-wins, so without these digests a later sync of another
/// project sharing the store can silently substitute the POM `raeva export-m2`
/// ships for this lockfile.
#[test]
fn sync_pins_companion_and_support_pom_bytes() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    fixtures::copy_tree_lf(&fixtures::path("reactor-cli/basic"), project.path());
    let (repo_url, _repo_url_server) = spawn_repository(basic_repository());
    write_repo_toml(project.path(), "fixture", &repo_url);

    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "initial sync",
    );

    let lock_path = project.path().join("raeva.lock");
    let lock = rv_lock::Lockfile::read(&lock_path).expect("read lock");
    let platform = lock.platforms.first().expect("platform");

    let served_digest =
        |path: &str| sha256_hex(&fs::read(basic_repository().join(&path[1..])).expect(path));

    for artifact in &platform.artifacts {
        let coord = &artifact.coordinate;
        assert_eq!(
            artifact.pom_sha256.as_ref().map(ToString::to_string),
            Some(served_digest(&format!(
                "/org/test/{0}/{1}/{0}-{1}.pom",
                coord.artifact_id(),
                coord.version()
            ))),
            "artifact {}:{} must pin the companion POM bytes the repository served",
            coord.artifact_id(),
            coord.version()
        );
    }

    let support = &lock.support_poms();
    assert!(!support.is_empty(), "support-POM provenance");
    let bom = support
        .get("org.test:bom:1")
        .expect("the imported BOM must be recorded");
    assert_eq!(
        bom.sha256.to_string(),
        served_digest("/org/test/bom/1/bom-1.pom"),
        "the imported BOM must pin the bytes the repository served"
    );
    let parent = support
        .get("org.test:external-parent:1")
        .expect("the external parent must be recorded");
    assert_eq!(
        parent.sha256.to_string(),
        served_digest("/org/test/external-parent/1/external-parent-1.pom"),
        "the external parent must pin the bytes the repository served"
    );
}

/// As in Maven, the repositories an active settings.xml profile adds and
/// those the POM declares are searched before Maven Central, not instead of
/// it, so a private coordinate is not asked of Central first. A mirror keeps
/// Central on loopback.
#[test]
fn settings_and_pom_repositories_are_searched_before_central() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let (repo_url, server) = spawn_repository(basic_repository());
    fs::write(
        project.path().join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories><repository>\
             <id>pom</id><url>{repo_url}pom/</url></repository></repositories>\
             <dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>app-only</artifactId><version>1</version></dependency>\
             </dependencies></project>"
        ),
    )
    .expect("write pom.xml");
    fs::create_dir(home.path().join(".m2")).expect("m2 dir");
    fs::write(
        home.path().join(".m2").join("settings.xml"),
        format!(
            "<settings><mirrors>\
             <mirror><id>central-mirror</id><mirrorOf>central</mirrorOf><url>{repo_url}</url></mirror>\
             </mirrors><profiles><profile><id>corp</id>\
             <activation><activeByDefault>true</activeByDefault></activation><repositories>\
             <repository><id>corp</id><url>{repo_url}corp/</url></repository>\
             </repositories></profile></profiles></settings>"
        ),
    )
    .expect("write settings.xml");

    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let paths: Vec<String> = server.requests().into_iter().map(|r| r.path).collect();
    let first = |prefix: &str| {
        let pom = format!("{prefix}org/test/app-only/1/app-only-1.pom");
        paths.iter().position(|path| *path == pom)
    };
    let (corp, pom, central) = (first("/corp/"), first("/pom/"), first("/"));
    assert!(corp.is_some() && corp < pom && pom < central, "{paths:?}");
}

/// A fresh store downloads every locked file again and checks it against
/// its raeva.lock pin: a file the repository replaced fails as a lock mismatch
/// that names both digests.
#[test]
fn a_download_refuses_bytes_that_differ_from_the_lock_pins() {
    let (project, repository) = (
        TempDir::new().expect("project"),
        TempDir::new().expect("repo"),
    );
    fixtures::copy_tree_lf(&fixtures::path("reactor-cli/basic"), project.path());
    fixtures::copy_tree_lf(&basic_repository(), repository.path());
    let (repo_url, _server) = spawn_repository(repository.path().to_path_buf());
    write_repo_toml(project.path(), "fixture", &repo_url);
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");

    let jar = repository.path().join("org/test/shared/1/shared-1.jar");
    let locked = sha256_hex(&fs::read(&jar).expect("read jar"));
    fs::write(&jar, b"replaced").expect("replace jar");
    fs::remove_file(repository.path().join("org/test/app-only/1/app-only-1.jar")).expect("rm");
    let fresh = TempDir::new().expect("fresh home");
    let output = run_raeva(project.path(), fresh.path(), &["sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_status(&output, 7, "replaced jar");
    let replaced = sha256_hex(b"replaced");
    for expected in [
        "1 downloaded file(s) do not match their checksums in raeva.lock",
        "org.test:shared:1:jar from ",
        "shared-1.jar: expected sha256 ",
        &format!("{locked}, got {replaced}"),
        "and 1 other download failure(s):\norg.test:app-only:1",
    ] {
        assert!(stderr.contains(expected), "{expected}: {stderr}");
    }
}

/// A conflicted lock keeps the pins of both its sides, so the regeneration
/// a plain sync runs refuses a release file the repository replaced, and
/// two sides that pin other bytes for one file. A lock or a side of the
/// previous schema keeps its pins the same way, and `--frozen` refuses it.
/// Only `--update` or deleting the lock starts again from the bytes served
/// now.
#[test]
fn a_conflicted_lock_keeps_its_pins() {
    let tampered = Arc::new(AtomicBool::new(false));
    let state = tampered.clone();
    let server = StubServer::start(move |request| {
        let tampered = state.load(Ordering::SeqCst);
        serve_sha256(&request.path, |path| match path {
            "/org/test/zz-release/1.0/zz-release-1.0.jar" if tampered => {
                Some(b"tampered bytes".to_vec())
            }
            _ => snapshot_route(path, false),
        })
    });
    let project = TempDir::new().unwrap();
    write_repo_toml(
        project.path(),
        "fixture",
        &format!("http://{}/", server.addr()),
    );
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "root",
            "<dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>zz-release</artifactId><version>1.0</version></dependency>\
             </dependencies>",
        ),
    )
    .unwrap();
    let sync = |args: &[&str]| run_raeva(project.path(), TempDir::new().unwrap().path(), args);
    assert_success(&sync(&["sync"]), "initial");
    let lock_path = project.path().join("raeva.lock");
    let lock = fs::read_to_string(&lock_path).unwrap();
    let (good, bad) = (
        sha256_hex(b"release artifact bytes"),
        sha256_hex(b"tampered bytes"),
    );
    assert!(lock.contains(&good), "{lock}");
    tampered.store(true, Ordering::SeqCst);
    let conflict = |line: &str, theirs: &str| {
        lock.replacen(
            line,
            &format!("<<<<<<<<< ours\n{line}\n=========\n{theirs}\n>>>>>>>>> theirs"),
            1,
        )
    };
    let hash = lock.lines().find(|l| l.starts_with("config_hash")).unwrap();
    let digest = format!("digest = \"{good}\"");
    let schema = format!("schema_version = {}", rv_lock::LOCKFILE_SCHEMA_VERSION);
    let older = format!("schema_version = {}", rv_lock::LOCKFILE_SCHEMA_VERSION - 1);
    let pinned = format!("expected sha256:{good}, got sha256:{bad} (the raeva.lock pin)");
    // Our side pins the jar by SHA-1 alone and theirs by SHA-256 of the
    // bytes served now: the SHA-1 pin still holds.
    let algorithm = format!("algorithm = \"sha256\"\n{digest}");
    let sha1_good = sha1_hex(b"release artifact bytes");
    let sha1_side = conflict(
        &algorithm,
        &format!("algorithm = \"sha256\"\ndigest = \"{bad}\""),
    )
    .replacen(
        &algorithm,
        &format!("algorithm = \"sha1\"\ndigest = \"{sha1_good}\""),
        1,
    );
    fs::write(&lock_path, lock.replacen(&schema, &older, 1)).unwrap();
    let frozen = sync(&["sync", "--frozen"]);
    assert_status(&frozen, 3, "frozen on the previous schema");
    assert!(
        String::from_utf8_lossy(&frozen.stderr).contains("without --frozen to regenerate"),
        "{}",
        String::from_utf8_lossy(&frozen.stderr)
    );
    // Sides that pin other bytes stop a plain sync too.
    fs::write(
        &lock_path,
        conflict(&digest, &format!("digest = \"{bad}\"")),
    )
    .unwrap();
    let frozen = sync(&["sync", "--frozen"]);
    assert!(
        String::from_utf8_lossy(&frozen.stderr).contains("'raeva sync --update' to regenerate"),
        "{}",
        String::from_utf8_lossy(&frozen.stderr)
    );
    for (conflicted, status, expected) in [
        (lock.replacen(&schema, &older, 1), 7, pinned.clone()),
        (conflict(&schema, &older), 7, pinned.clone()),
        (conflict(hash, hash), 7, pinned),
        (
            conflict(&digest, &format!("digest = \"{bad}\"")),
            7,
            format!("sha256 {good} in our side, sha256 {bad} in their side"),
        ),
        (
            sha1_side,
            7,
            format!("zz-release-1.0.jar: expected sha1 {sha1_good}, got "),
        ),
        (
            conflict(hash, "config_hash ="),
            3,
            "their side of its merge conflict does not read".to_string(),
        ),
    ] {
        fs::write(&lock_path, &conflicted).unwrap();
        let output = sync(&["sync"]);
        assert_status(&output, status, &expected);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&expected), "{expected}: {stderr}");
        assert_eq!(
            status == 3,
            stderr.contains("Resolve the conflict or take one side's lock"),
            "{stderr}"
        );
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), conflicted);
    }
    assert_success(&sync(&["sync", "--update"]), "update");
    assert!(fs::read_to_string(&lock_path).unwrap().contains(&bad));
    fs::remove_file(&lock_path).unwrap();
    assert_success(&sync(&["sync"]), "start again");
    assert!(fs::read_to_string(&lock_path).unwrap().contains(&bad));
}

const FIXTURE_PLATFORMS: &str = "linux-x86_64,windows-x86_64";

/// Copy the `line-endings` fixture with CRLF line endings in every project
/// input when `crlf` is set, LF otherwise.
fn line_endings_project(crlf: bool) -> TempDir {
    let project = TempDir::new().expect("project");
    fixtures::copy_tree_lf(&fixtures::path("reactor-cli/line-endings"), project.path());
    if crlf {
        for rel in fixtures::sorted_relative_files(project.path()) {
            let path = project.path().join(&rel);
            let text = fs::read_to_string(&path).expect("read fixture input");
            fs::write(&path, text.replace('\n', "\r\n")).expect("write fixture input");
        }
    }
    project
}

/// A Git checkout with `core.autocrlf=true` gives the project inputs CRLF
/// line endings. Both checkouts write the same lock, and a lock written on
/// one side passes `--frozen` on the other.
#[test]
fn crlf_and_lf_checkouts_write_the_same_lock() {
    let home = TempDir::new().expect("home");
    let lf = line_endings_project(false);
    let crlf = line_endings_project(true);
    for project in [&lf, &crlf] {
        assert_success(
            &run_raeva(
                project.path(),
                home.path(),
                &["sync", "--platforms", FIXTURE_PLATFORMS],
            ),
            "sync",
        );
    }
    let lf_lock = fs::read(lf.path().join("raeva.lock")).expect("read LF lock");
    assert_eq!(
        String::from_utf8(fs::read(crlf.path().join("raeva.lock")).expect("read CRLF lock"))
            .unwrap(),
        String::from_utf8(lf_lock.clone()).unwrap()
    );

    fs::write(crlf.path().join("raeva.lock"), &lf_lock).expect("copy LF lock");
    for args in [
        &["sync", "--frozen", "--platforms", FIXTURE_PLATFORMS][..],
        &[
            "sync",
            "--frozen",
            "--offline",
            "--platforms",
            FIXTURE_PLATFORMS,
        ][..],
    ] {
        assert_success(&run_raeva(crlf.path(), home.path(), args), &args.join(" "));
    }
    assert_eq!(
        fs::read(crlf.path().join("raeva.lock")).expect("read lock"),
        lf_lock
    );
}

/// `--frozen` and `raeva lock verify` refuse a lock that reads the same but
/// is not the text raeva writes, apart from CRLF line endings, and a plain
/// sync rewrites it.
#[test]
fn a_lock_in_other_text_fails_frozen_until_a_sync_rewrites_it() {
    let home = TempDir::new().expect("home");
    let project = line_endings_project(false);
    let raeva = |args: &[&str]| run_raeva(project.path(), home.path(), args);
    let platforms = ["--platforms", FIXTURE_PLATFORMS];
    let frozen = ["sync", "--frozen", platforms[0], platforms[1]];
    assert_success(&raeva(&["sync", platforms[0], platforms[1]]), "sync");
    let lock_path = project.path().join("raeva.lock");
    let written = fs::read_to_string(&lock_path).expect("read lock");
    fs::write(&lock_path, written.replace('\n', "\r\n")).expect("write CRLF lock");
    assert_success(&raeva(&frozen), "frozen with CRLF");
    assert_success(&raeva(&["lock", "verify"]), "verify with CRLF");
    let edits = [
        format!("{written}# reviewed\n"),
        written.replacen("schema_version = 9", "schema_version  =  9", 1),
    ];
    for edited in edits {
        assert_ne!(edited, written);
        fs::write(&lock_path, &edited).expect("write edited lock");
        for args in [&frozen[..], &["lock", "verify"]] {
            let output = raeva(args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(7), "{stderr}");
            assert!(stderr.contains("not the text raeva writes"), "{stderr}");
        }
        assert_success(
            &raeva(&["sync", platforms[0], platforms[1]]),
            "sync rewrites",
        );
        assert_eq!(fs::read_to_string(&lock_path).expect("read lock"), written);
        assert_success(&raeva(&frozen), "frozen after the rewrite");
    }
}

/// A reactor that cannot be discovered is invalid project input: `raeva sync`
/// exits 3 and names the POM, as the resolver does for a POM it cannot use.
#[test]
fn an_invalid_reactor_pom_exits_with_the_project_input_status() {
    let cases = [
        (
            "broken XML",
            "<project><modelVersion>4.0.0</modelVersion>",
            "",
        ),
        (
            "escaping module",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>../outside</module></modules></project>",
            "escapes",
        ),
        (
            "missing module",
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>gone</module></modules></project>",
            "gone",
        ),
    ];
    for (label, pom, expected) in cases {
        let base = TempDir::new().expect("base");
        let home = TempDir::new().expect("home");
        let project = base.path().join("project");
        fs::create_dir_all(&project).expect("mkdir project");
        fs::create_dir_all(base.path().join("outside")).expect("mkdir outside");
        fs::write(
            base.path().join("outside/pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>outside</artifactId><version>1</version></project>",
        )
        .expect("write outside pom.xml");
        fs::write(project.join("pom.xml"), pom).expect("write pom.xml");
        let output = run_raeva(&project, home.path(), &["sync", "--offline"]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_status(&output, 3, label);
        assert!(stderr.contains("pom.xml"), "{label}: {stderr}");
        assert!(stderr.contains(expected), "{label}: {stderr}");
    }
}

/// A project's dependency, a module's on a sibling, or a build plugin's,
/// plugins locked or not, that still has no version after management, or a
/// build plugin's dependency in `test` scope, fails as Maven 3.9.12 and
/// 3.10.0 fail it: exit 3 with `INVALID_POM`, naming the module's file, and
/// no lock.
#[test]
fn a_dependency_without_a_version_exits_with_the_project_input_status() {
    let project = |artifact: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
        )
    };
    let module = |artifact: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version></parent>\
             <artifactId>{artifact}</artifactId>{body}</project>"
        )
    };
    let sibling = "<dependencies><dependency><groupId>org.test</groupId>\
                   <artifactId>m1</artifactId></dependency></dependencies>";
    let plugin = "<build><plugins><plugin><groupId>org.test</groupId><artifactId>p</artifactId>\
                  <version>1</version><dependencies><dependency><groupId>org.test</groupId>\
                  <artifactId>x</artifactId></dependency></dependencies></plugin></plugins>\
                  </build>";
    let reactor = project(
        "root",
        "<packaging>pom</packaging><modules><module>m1</module><module>m2</module></modules>",
    );
    let cases = [
        (
            vec![("pom.xml", project("app", &sibling.replace("m1", "lib")))],
            "pom.xml",
            "'dependencies.dependency.version' for org.test:lib:jar is missing",
        ),
        (
            vec![
                ("pom.xml", reactor.clone()),
                ("m1/pom.xml", module("m1", "")),
                ("m2/pom.xml", module("m2", sibling)),
            ],
            "m2",
            "'dependencies.dependency.version' for org.test:m1:jar is missing",
        ),
    ];
    let plugin_missing = "'build.plugins.plugin[org.test:p].dependencies.dependency.version' \
                          for org.test:x:jar is missing";
    let scoped_x = "<artifactId>x</artifactId><version>1</version><scope>test</scope>";
    let cases = cases.into_iter().chain([
        (
            vec![("pom.xml", project("app", plugin))],
            "pom.xml",
            plugin_missing,
        ),
        (
            vec![
                ("pom.xml", project("app", plugin)),
                ("raeva.toml", "[plugins]\nlock = true\n".to_string()),
            ],
            "pom.xml",
            plugin_missing,
        ),
        (
            vec![(
                "pom.xml",
                project(
                    "app",
                    &plugin.replace("<artifactId>x</artifactId>", scoped_x),
                ),
            )],
            "pom.xml",
            "'build.plugins.plugin[org.test:p].dependencies.dependency.scope' for \
             org.test:x:jar must be one of [compile, runtime, system] but is 'test'",
        ),
    ]);
    for (files, path, message) in cases {
        let project = TempDir::new().expect("project");
        let home = TempDir::new().expect("home");
        for (name, content) in files {
            let file = project.path().join(name);
            fs::create_dir_all(file.parent().expect("parent")).expect("mkdir module");
            fs::write(file, content).expect("write pom.xml");
        }
        let output = raeva_command(project.path(), home.path())
            .args(["--json", "sync", "--offline"])
            .output()
            .expect("run raeva sync");
        let envelope: Value = serde_json::from_slice(&output.stdout).expect("one JSON envelope");
        assert_status(&output, 3, message);
        assert_eq!(envelope["code"], "INVALID_POM", "{envelope}");
        let error = envelope["error"].as_str().unwrap_or_default();
        assert!(
            error.contains(message) && error.contains(path),
            "{message}: {envelope}"
        );
        assert!(!project.path().join("raeva.lock").exists(), "{message}");
    }
}

/// One module's graph failing ends the sync before any artifact is checked,
/// so a damaged store copy in another module goes unreported.
#[test]
fn a_failed_module_graph_comes_before_any_artifact_check() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    fixtures::copy_tree_lf(&fixtures::path("reactor-cli/basic"), project.path());
    let (repo_url, _repo_url_server) = spawn_repository(basic_repository());
    write_repo_toml(project.path(), "fixture", &repo_url);
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "initial sync",
    );

    let digest = sha256_hex(
        &fs::read(basic_repository().join("org/test/shared/1/shared-1.jar")).expect("shared jar"),
    );
    let blob = (home.path().join("store/blobs"))
        .join(&digest[0..2])
        .join(&digest[2..4])
        .join(&digest);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&blob, fs::Permissions::from_mode(0o644)).expect("writable blob");
    }
    fs::write(&blob, b"corrupt shared artifact").expect("corrupt shared blob");

    let app = project.path().join("app/pom.xml");
    let pom = fs::read_to_string(&app).expect("app POM").replace(
        "  </dependencies>",
        "    <dependency>\n      <groupId>org.test</groupId>\n      \
         <artifactId>absent</artifactId>\n      <version>[5,6)</version>\n    \
         </dependency>\n  </dependencies>",
    );
    fs::write(&app, pom).expect("write app POM");

    let sync = run_raeva(project.path(), home.path(), &["sync", "--offline"]);
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(
        !sync.status.success(),
        "the absent range must fail: {stderr}"
    );
    assert!(stderr.contains("absent"), "{stderr}");
    assert!(!stderr.contains("downloading it again"), "{stderr}");
}

/// A locked SNAPSHOT build its repository no longer serves is reported as
/// missing there, not refused by a repository that disables snapshots.
#[test]
fn a_purged_snapshot_build_is_reported_as_missing_from_its_repository() {
    let project = TempDir::new().expect("project");
    let repository = TempDir::new().expect("repository");
    publish_snapshot_repository(repository.path(), false);
    let (repo_url, _server) = spawn_repository(repository.path().to_path_buf());
    write_snapshot_project(project.path(), &repo_url);
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let (timestamp, build) = snapshot_publication(false);
    fs::remove_file(repository.path().join(format!(
        "org/test/snapshot/1.0-SNAPSHOT/snapshot-1.0-{timestamp}-{build}.jar"
    )))
    .unwrap();
    let home = TempDir::new().expect("fresh home");
    let frozen = run_raeva(project.path(), home.path(), &["sync", "--frozen"]);
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(!frozen.status.success(), "{stderr}");
    assert!(!stderr.contains("snapshots disabled"), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "not found: {repo_url}org/test/snapshot/1.0-SNAPSHOT/snapshot-1.0-{timestamp}-{build}.jar (HTTP 404)"
        )),
        "{stderr}"
    );
}

/// A fallback repository's refusal does not stand in for the miss of the
/// repository the lock records.
#[test]
fn a_purged_release_is_reported_as_missing_from_its_repository() {
    let project = TempDir::new().expect("project");
    let repository = TempDir::new().expect("repository");
    publish_snapshot_repository(repository.path(), false);
    let (repo_url, _server) = spawn_repository(repository.path().to_path_buf());
    let refuse = Arc::new(AtomicBool::new(false));
    let refusing = refuse.clone();
    let private = StubServer::start(move |_| {
        Response::new(
            if refusing.load(Ordering::SeqCst) {
                401
            } else {
                404
            },
            "",
        )
    });
    let (_central, central) = crate::common::local_central();
    write_snapshot_project(project.path(), &repo_url);
    let toml = fs::read_to_string(project.path().join("raeva.toml")).unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "{toml}[[repositories]]\nid = \"private\"\nurl = \"http://{}/\"\n{central}",
            private.addr()
        ),
    )
    .unwrap();
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    fs::remove_file(
        repository
            .path()
            .join("org/test/zz-release/1.0/zz-release-1.0.jar"),
    )
    .unwrap();
    refuse.store(true, Ordering::SeqCst);
    let home = TempDir::new().expect("fresh home");
    let frozen = run_raeva(project.path(), home.path(), &["sync", "--frozen"]);
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert!(!frozen.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "not found: {repo_url}org/test/zz-release/1.0/zz-release-1.0.jar (HTTP 404)"
        )),
        "{stderr}"
    );
}

/// A resolution error names the module that declares the dependency, in
/// text and JSON.
#[test]
fn a_resolution_error_names_its_module() {
    let (project, home) = crate::common::temp_project();
    let server = StubServer::start(|_| Response::new(404, ""));
    write_repo_toml(
        project.path(),
        "central",
        &format!("http://{}/", server.addr()),
    );
    let module = |artifact: &str, body: &str| {
        crate::common::pom(
            artifact,
            &format!(
                "<parent><groupId>t</groupId><artifactId>root</artifactId><version>1</version></parent>{body}"
            ),
        )
    };
    fs::write(
        project.path().join("pom.xml"),
        crate::common::pom(
            "root",
            "<packaging>pom</packaging><modules><module>core</module><module>app</module></modules>",
        ),
    )
    .expect("write root pom.xml");
    for (name, body) in [
        ("core", ""),
        (
            "app",
            "<dependencies><dependency><groupId>t</groupId><artifactId>core</artifactId>\
<version>1</version></dependency><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
<version>[2,3)</version></dependency></dependencies>",
        ),
    ] {
        fs::create_dir(project.path().join(name)).expect("module dir");
        fs::write(
            project.path().join(name).join("pom.xml"),
            module(name, body),
        )
        .expect("write module pom.xml");
    }

    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_status(&output, 5, "range without a version");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("t:lib") && stderr.contains("\n  In app/pom.xml\n"),
        "{stderr}"
    );

    let output = run_raeva(project.path(), home.path(), &["--json", "sync"]);
    let envelope = crate::common::envelope(&output);
    assert_eq!(
        envelope["location"],
        serde_json::json!({"module": "app/pom.xml", "via": []}),
        "{envelope}"
    );
}

/// A repository serving `lib:x:1` with `jar` as its jar, or only its POM.
fn spawn_lib_repository(jar: Option<&'static [u8]>) -> (String, StubServer) {
    let server = StubServer::start(move |request| {
        serve_sha256(&request.path, |path| match path {
            "/lib/x/1/x-1.pom" => Some(
                b"<project><modelVersion>4.0.0</modelVersion><groupId>lib</groupId>\
                  <artifactId>x</artifactId><version>1</version></project>"
                    .to_vec(),
            ),
            "/lib/x/1/x-1.jar" => jar.map(<[u8]>::to_vec),
            _ => None,
        })
    });
    (format!("http://{}/", server.addr()), server)
}

/// A reactor whose module `a` reaches `lib:x:1` through Central, mirrored to
/// `central`, and module `b` through `declared`, which its POM lists before
/// Central. The project and the Raeva home it returns.
fn two_repository_reactor(central: &str, declared: &str) -> (TempDir, TempDir) {
    let (project, home) = (
        TempDir::new().expect("project"),
        TempDir::new().expect("home"),
    );
    let dependency = "<dependencies><dependency><groupId>lib</groupId>\
                      <artifactId>x</artifactId><version>1</version></dependency></dependencies>";
    let declared = format!(
        "<repositories><repository><id>declared</id><url>{declared}</url></repository>\
         </repositories>{dependency}"
    );
    let settings = format!(
        "<settings><mirrors><mirror><id>central-mirror</id><mirrorOf>central</mirrorOf>\
         <url>{central}</url></mirror></mirrors></settings>"
    );
    for (root, path, text) in [
        (
            project.path(),
            "pom.xml",
            pom(
                "root",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
            ),
        ),
        (project.path(), "a/pom.xml", pom("a", dependency)),
        (project.path(), "b/pom.xml", pom("b", &declared)),
        (home.path(), ".m2/settings.xml", settings),
    ] {
        let path = root.join(path);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, text).expect("write file");
    }
    (project, home)
}

/// A module whose first repository is not the one another module took a
/// coordinate from reuses what the store holds from its own repository, so a
/// lock-less offline sync on a warm store writes the same lock.
#[test]
fn offline_sync_reuses_a_coordinate_each_modules_repository_served() {
    let (central, central_server) = spawn_lib_repository(Some(b"lib jar"));
    let (declared, declared_server) = spawn_lib_repository(Some(b"lib jar"));
    let (project, home) = two_repository_reactor(&central, &declared);
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let lock_path = project.path().join("raeva.lock");
    let lock = fs::read(&lock_path).expect("read lock");
    let requests = (
        central_server.requests().len(),
        declared_server.requests().len(),
    );
    fs::remove_file(&lock_path).expect("remove lock");

    let offline = run_raeva(project.path(), home.path(), &["sync", "--offline"]);
    assert_success(&offline, "offline sync");
    assert_eq!(fs::read(&lock_path).expect("read lock"), lock);
    assert_eq!(
        (
            central_server.requests().len(),
            declared_server.requests().len()
        ),
        requests
    );
}

/// Two repositories that serve different bytes for one coordinate fail the
/// sync, online and from the store offline alike.
#[test]
fn different_bytes_from_two_repositories_fail_online_and_offline() {
    let (central, _central_server) = spawn_lib_repository(Some(b"central jar"));
    let (declared, _declared_server) = spawn_lib_repository(Some(b"declared jar"));
    let (project, home) = two_repository_reactor(&central, &declared);
    for args in [&["sync"][..], &["sync", "--offline"]] {
        let output = run_raeva(project.path(), home.path(), args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_status(&output, 5, &format!("{args:?}"));
        assert!(
            stderr.contains("artifact lib:x:1:jar resolved to different bytes in reactor modules"),
            "{args:?}: {stderr}"
        );
        assert!(!project.path().join("raeva.lock").exists());
    }
}

/// Offline, a file the first repository never served comes from the store
/// as a later repository served it, as the download that wrote the lock
/// found it there.
#[test]
fn offline_sync_takes_a_file_a_later_repository_served() {
    let (central, _central_server) = spawn_lib_repository(Some(b"lib jar"));
    let (declared, _declared_server) = spawn_lib_repository(None);
    let (project, home) = two_repository_reactor(&central, &declared);
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let lock_path = project.path().join("raeva.lock");
    let lock = fs::read(&lock_path).expect("read lock");
    fs::remove_file(&lock_path).expect("remove lock");

    let offline = run_raeva(project.path(), home.path(), &["sync", "--offline"]);
    assert_success(&offline, "offline sync");
    assert_eq!(fs::read(&lock_path).expect("read lock"), lock);
}

/// Offline, the repositories are searched in the order an online sync
/// searches them: a `file:` repository is read in its turn, and a remote one
/// answers with the bytes the store holds from it, here Central's from
/// another project.
#[test]
fn offline_sync_searches_a_file_repository_in_its_turn() {
    let (central, _central_server) = spawn_lib_repository(Some(b"lib jar"));
    let (pom_only, _pom_only_server) = spawn_lib_repository(None);
    // The store gets Central's jar and the POM-only repository's POM.
    let (other, home) = two_repository_reactor(&central, &pom_only);
    assert_success(&run_raeva(other.path(), home.path(), &["sync"]), "sync");

    let local_jar: &[u8] = b"local jar";
    let file = "<repository><id>local</id>\
                <url>file://${project.basedir}/repository/</url></repository>";
    let remote = format!("<repository><id>declared</id><url>{pom_only}</url></repository>");
    for (repositories, with_jar, expected) in [
        (file.to_string(), true, local_jar),
        (file.to_string(), false, b"lib jar".as_slice()),
        (format!("{remote}{file}"), true, local_jar),
    ] {
        let project = TempDir::new().expect("project");
        let local = project.path().join("repository/lib/x/1");
        fs::create_dir_all(&local).expect("mkdir");
        let pom: &[u8] = b"<project><modelVersion>4.0.0</modelVersion><groupId>lib</groupId>\
              <artifactId>x</artifactId><version>1</version></project>";
        let files = [("x-1.pom", pom), ("x-1.jar", local_jar)];
        for (name, bytes) in &files[..if with_jar { 2 } else { 1 }] {
            write_with_sha256(&local.join(name), bytes);
        }
        fs::write(
            project.path().join("pom.xml"),
            crate::common::pom(
                "app",
                &format!(
                    "<repositories>{repositories}</repositories><dependencies><dependency>\
                     <groupId>lib</groupId><artifactId>x</artifactId><version>1</version>\
                     </dependency></dependencies>"
                ),
            ),
        )
        .expect("write pom");
        let lock_path = project.path().join("raeva.lock");
        let offline = run_raeva(project.path(), home.path(), &["sync", "--offline"]);
        assert_success(&offline, &format!("offline sync {repositories} {with_jar}"));
        let lock = fs::read_to_string(&lock_path).expect("read lock");
        assert!(lock.contains(&sha256_hex(expected)), "{lock}");
        fs::remove_file(&lock_path).expect("remove lock");
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync"]),
            "online sync",
        );
        assert_eq!(fs::read_to_string(&lock_path).expect("read lock"), lock);
    }
}

/// A sync that resolves again takes a file a later repository served from
/// the store once the repositories before it miss, and does not download it
/// again.
#[test]
fn a_warm_sync_takes_a_later_repositorys_file_from_the_store() {
    let (central, central_server) = spawn_lib_repository(Some(b"lib jar"));
    let (declared, _declared_server) = spawn_lib_repository(None);
    let (project, home) = two_repository_reactor(&central, &declared);
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let lock_path = project.path().join("raeva.lock");
    let lock = fs::read(&lock_path).expect("read lock");
    let jar_requests = || {
        let requests = central_server.requests();
        requests
            .iter()
            .filter(|request| request.path.starts_with("/lib/x/1/x-1.jar"))
            .count()
    };
    let downloads = jar_requests();
    fs::remove_file(&lock_path).expect("remove lock");

    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "warm sync",
    );
    assert_eq!(fs::read(&lock_path).expect("read lock"), lock);
    assert_eq!(jar_requests(), downloads);
}

/// A dependency whose POM no repository has resolves without it, as in
/// Maven, and offline too: the misses the online sync recorded stand.
#[test]
fn offline_sync_resolves_a_dependency_without_a_pom() {
    let server = StubServer::start(|request| {
        serve_sha256(&request.path, |path| {
            (path == "/lib/x/1/x-1.jar").then(|| b"jar only".to_vec())
        })
    });
    let central = format!("http://{}/", server.addr());
    let (project, home) = two_repository_reactor(&central, &central);
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "sync");
    let lock_path = project.path().join("raeva.lock");
    let lock = fs::read(&lock_path).expect("read lock");
    for args in [
        &["sync", "--offline"][..],
        &["sync", "--offline", "--update"],
    ] {
        fs::remove_file(&lock_path).expect("remove lock");
        let offline = run_raeva(project.path(), home.path(), args);
        assert_success(&offline, &format!("{args:?}"));
        let stderr = String::from_utf8_lossy(&offline.stderr);
        assert!(stderr.contains("POM_PROBLEM"), "{stderr}");
        assert_eq!(fs::read(&lock_path).expect("read lock"), lock);
    }
}

/// A failure that turns a module's resolved graph into lock rows, here a
/// SNAPSHOT build number raeva.lock cannot record, names the module.
#[test]
fn a_failure_completing_a_module_names_it() {
    const VERSION: &str = "1.0-20260720.123253-4294967296";
    let base = "/maven/com/example/demo/1.0-SNAPSHOT/demo";
    let demo_pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
         <artifactId>demo</artifactId><version>{VERSION}</version></project>"
    );
    let server = sha256_repository([
        (format!("{base}-{VERSION}.pom"), demo_pom.into_bytes()),
        (format!("{base}-{VERSION}.jar"), b"demo jar".to_vec()),
    ]);
    let project = tempfile::tempdir().expect("project");
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "root",
            "<packaging>pom</packaging><modules><module>app</module></modules>",
        ),
    )
    .expect("root pom");
    fs::create_dir(project.path().join("app")).expect("mkdir app");
    fs::write(
        project.path().join("app/pom.xml"),
        pom(
            "app",
            &format!(
                "<dependencies><dependency><groupId>com.example</groupId>\
                 <artifactId>demo</artifactId><version>{VERSION}</version></dependency>\
                 </dependencies>"
            ),
        ),
    )
    .expect("app pom");
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"central\"\nurl = \"http://{}/maven/\"\n\
             snapshots = true\n",
            server.addr()
        ),
    )
    .expect("raeva.toml");
    let home = tempfile::tempdir().expect("home");
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .expect("run raeva sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("which raeva.lock cannot record"),
        "{stderr}"
    );
    assert!(stderr.contains("In app/pom.xml"), "{stderr}");
}

/// A plain sync that restores the lock on one platform keeps its SNAPSHOT
/// builds, as on several: the resolution that establishes the trust of a
/// repository only a remote parent declares reads no SNAPSHOT metadata.
#[test]
fn a_restore_with_trust_discovery_keeps_the_locked_snapshot_builds() {
    let advanced = Arc::new(AtomicBool::new(false));
    let state = advanced.clone();
    let own_addr = Arc::new(std::sync::OnceLock::<String>::new());
    let addr = own_addr.clone();
    let server = StubServer::start(move |request| {
        let advanced = state.load(Ordering::SeqCst);
        serve_sha256(&request.path, |path| {
            if let Some(path) = path.strip_prefix("/maven") {
                if path == "/com/example/corp-parent/1.0/corp-parent-1.0.pom" {
                    return Some(
                        format!(
                            "<project><modelVersion>4.0.0</modelVersion>\
                             <groupId>com.example</groupId><artifactId>corp-parent</artifactId>\
                             <version>1.0</version><packaging>pom</packaging><repositories>\
                             <repository><id>declared</id><url>http://{}/fallback/</url>\
                             </repository></repositories></project>",
                            addr.get().expect("address")
                        )
                        .into_bytes(),
                    );
                }
                // Both builds stay published; the metadata names the latest.
                return (snapshot_route(path, advanced))
                    .or_else(|| snapshot_route(path, false))
                    .filter(|_| path.starts_with("/org/test/snapshot/"));
            }
            match path.strip_prefix("/fallback")? {
                "/org/example/lib/1.0/lib-1.0.pom" => Some(
                    b"<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
                      <artifactId>lib</artifactId><version>1.0</version></project>"
                        .to_vec(),
                ),
                "/org/example/lib/1.0/lib-1.0.jar" => Some(b"lib jar".to_vec()),
                _ => None,
            }
        })
    });
    own_addr.set(server.addr().to_string()).expect("address");
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"configured\"\nurl = \"http://{}/maven/\"\n\
             snapshots = true\nsnapshots-update-policy = \"never\"\n",
            server.addr()
        ),
    )
    .unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
         <artifactId>corp-parent</artifactId><version>1.0</version><relativePath/></parent>\
         <artifactId>app</artifactId><dependencies>\
         <dependency><groupId>org.example</groupId><artifactId>lib</artifactId>\
         <version>1.0</version></dependency>\
         <dependency><groupId>org.test</groupId><artifactId>snapshot</artifactId>\
         <version>1.0-SNAPSHOT</version></dependency></dependencies></project>",
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "initial",
    );
    let lock_path = project.path().join("raeva.lock");
    let lock = fs::read(&lock_path).unwrap();

    // A newer build, a store without the locked files and a cache without
    // the metadata: the restore resolves to trust the parent's repository.
    advanced.store(true, Ordering::SeqCst);
    fs::remove_dir_all(home.path().join("store")).unwrap();
    let cache = rusqlite::Connection::open(home.path().join("metadata.db")).unwrap();
    for table in ["pom_cache_v5", "version_list_cache_v4", "miss_cache_v4"] {
        cache.execute(&format!("DELETE FROM {table}"), []).unwrap();
    }
    drop(cache);
    let before = server.requests().len();
    let restored = run_raeva(project.path(), home.path(), &["sync"]);
    assert_success(&restored, "restore");
    assert_eq!(fs::read(&lock_path).unwrap(), lock);
    let metadata: Vec<_> = server.requests()[before..]
        .iter()
        .map(|request| request.path.clone())
        .filter(|path| path.starts_with("/maven/") && path.ends_with("maven-metadata.xml"))
        .collect();
    assert!(metadata.is_empty(), "{metadata:?}");
    assert!(
        home.path().join("store").is_dir(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
}

/// Only a run that asked the repositories counts as a SNAPSHOT check: an
/// offline sync, an offline update or a sync of other platforms leaves the
/// check of a platform due, and the next plain sync makes it.
#[test]
fn a_sync_that_checked_no_repository_leaves_the_snapshot_check_due() {
    let host = rv_lock::Platform::current().unwrap().to_string();
    let other = if host == "linux-x86_64" {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    };
    let central = StubServer::start(|_| Response::new(404, ""));
    for middle in [
        &["sync", "--offline"][..],
        &["sync", "--update", "--offline"],
        &["sync", "--platforms", &host],
    ] {
        let (url, advanced, _server) = spawn_snapshot_repository();
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        write_snapshot_project(project.path(), &url);
        let config = project.path().join("raeva.toml");
        let text = fs::read_to_string(&config)
            .unwrap()
            .replace("\"always\"", "\"daily\"")
            + &format!(
                "\n[[repositories]]\nid = \"central\"\nurl = \"http://{}/\"\n",
                central.addr()
            );
        fs::write(&config, text).unwrap();
        let both = format!("{host},{other}");
        assert_success(
            &run_raeva(project.path(), home.path(), &["sync", "--platforms", &both]),
            "initial",
        );
        let lock_path = project.path().join("raeva.lock");
        advanced.store(true, Ordering::SeqCst);
        age_snapshot_checks(home.path(), &lock_path, TWO_DAYS);

        let output = run_raeva(project.path(), home.path(), middle);
        assert_success(&output, &format!("{middle:?}"));
        let output = run_raeva(project.path(), home.path(), &["sync"]);
        assert_success(&output, &format!("plain sync after {middle:?}"));
        let lock = fs::read_to_string(&lock_path).unwrap();
        assert!(
            lock.contains("20240202.020202") && !lock.contains("20240101.010101"),
            "{middle:?}: {}\n{lock}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// A resolution for a POM edit within the update interval reads the
/// metadata cached by the last check and leaves that check's time: the
/// next plain sync after the interval looks for newer builds.
#[test]
fn a_resolution_within_the_update_interval_keeps_the_last_check() {
    const HOURS: i64 = 60 * 60;
    let (url, advanced, _server) = spawn_snapshot_repository();
    let central = StubServer::start(|_| Response::new(404, ""));
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    write_snapshot_project(project.path(), &url);
    let config = project.path().join("raeva.toml");
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("\"always\"", "\"interval:1440\"")
        + &format!(
            "\n[[repositories]]\nid = \"central\"\nurl = \"http://{}/\"\n",
            central.addr()
        );
    fs::write(&config, text).unwrap();
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "initial",
    );
    let lock_path = project.path().join("raeva.lock");
    advanced.store(true, Ordering::SeqCst);
    age_snapshot_checks(home.path(), &lock_path, 12 * HOURS);

    let pom_path = project.path().join("pom.xml");
    let pom = fs::read_to_string(&pom_path).unwrap();
    fs::write(
        &pom_path,
        pom.replace("</project>", "<!-- edit --></project>"),
    )
    .unwrap();
    assert_success(&run_raeva(project.path(), home.path(), &["sync"]), "edit");
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(lock.contains("20240101.010101"), "{lock}");

    age_snapshot_checks(home.path(), &lock_path, 13 * HOURS);
    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_success(&output, "after the interval");
    let lock = fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.contains("20240202.020202"),
        "{}\n{lock}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A resolution that adds the first SNAPSHOT dependency of a platform
/// records the check it made, so the next sync keeps the lock.
#[test]
fn a_resolution_that_adds_a_snapshot_records_its_check() {
    let (url, _advanced, _server) = spawn_snapshot_repository();
    let central = StubServer::start(|_| Response::new(404, ""));
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    write_snapshot_project(project.path(), &url);
    let config = project.path().join("raeva.toml");
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("\"always\"", "\"interval:1440\"")
        + &format!(
            "\n[[repositories]]\nid = \"central\"\nurl = \"http://{}/\"\n",
            central.addr()
        );
    fs::write(&config, text).unwrap();
    let pom_path = project.path().join("pom.xml");
    let pom = fs::read_to_string(&pom_path).unwrap();
    let snapshot = pom
        .find(
            "    <dependency>\n      <groupId>org.test</groupId><artifactId>snapshot</artifactId>",
        )
        .unwrap();
    let end = snapshot + pom[snapshot..].find("</dependency>\n").unwrap() + "</dependency>\n".len();
    fs::write(&pom_path, format!("{}{}", &pom[..snapshot], &pom[end..])).unwrap();
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "release only",
    );
    // A home that never checked this project, as after a clone.
    rusqlite::Connection::open(home.path().join("metadata.db"))
        .unwrap()
        .execute("DELETE FROM snapshot_checks_v3", [])
        .unwrap();

    fs::write(&pom_path, &pom).unwrap();
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "add the SNAPSHOT",
    );
    let output = run_raeva(project.path(), home.path(), &["sync"]);
    assert_success(&output, "again");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.lines().any(|line| line.starts_with("Checked")),
        "{stderr}"
    );
}

/// Offline, a plain sync that keeps the lock fails on a pinned file the
/// store lacks and only a remote repository serves, as one that resolves
/// does.
#[test]
fn an_offline_sync_that_keeps_the_lock_fails_on_a_file_the_store_lacks() {
    let server = StubServer::start(|request| {
        serve_sha256(&request.path, |path| match path {
            "/org/test/zz-release/1.0/zz-release-1.0.pom"
            | "/org/test/zz-release/1.0/zz-release-1.0.jar" => snapshot_route(path, false),
            _ => None,
        })
    });
    let project = TempDir::new().unwrap();
    write_repo_toml(
        project.path(),
        "fixture",
        &format!("http://{}/", server.addr()),
    );
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><dependencies><dependency>\
         <groupId>org.test</groupId><artifactId>zz-release</artifactId><version>1.0</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();
    let home = TempDir::new().unwrap();
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "initial",
    );
    drop(server);
    let removed = remove_stored(&home.path().join("store"), b"release artifact bytes");
    assert_eq!(removed, 1);

    let output = run_raeva(
        project.path(),
        home.path(),
        &["--json", "sync", "--offline"],
    );
    assert_status(&output, 5, "offline sync with a pinned file missing");
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["code"], "OFFLINE_NOT_CACHED", "{envelope}");
}

/// Remove the files under `dir` that hold `bytes`, read-only or not, and
/// count them.
fn remove_stored(dir: &Path, bytes: &[u8]) -> usize {
    let mut removed = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            removed += remove_stored(&path, bytes);
        } else if fs::read(&path).is_ok_and(|held| held == bytes) {
            for writable in [path.as_path(), dir] {
                let mut permissions = fs::metadata(writable).unwrap().permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                permissions.set_readonly(false);
                fs::set_permissions(writable, permissions).unwrap();
            }
            fs::remove_file(&path).unwrap();
            removed += 1;
        }
    }
    removed
}

/// A module's `always` snapshot policy renews only the SNAPSHOTs that
/// module reads: another module's SNAPSHOT BOM keeps its own repository's
/// daily policy, so a plain sync reuses the lock.
#[test]
fn a_modules_snapshot_policy_leaves_another_modules_bom() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let repository = TempDir::new().expect("repository");
    let unused = TempDir::new().expect("unused repository");
    publish_snapshot_repository(repository.path(), false);
    let url = url::Url::from_directory_path(repository.path()).unwrap();
    let unused = url::Url::from_directory_path(unused.path()).unwrap();
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"snapshot-fixture\"\nurl = \"{url}\"\nreleases = true\n\
             snapshots = true\nsnapshots-update-policy = \"daily\"\n"
        ),
    )
    .unwrap();
    let module = |name: &str, body: &str| {
        fs::create_dir_all(root.join(name)).unwrap();
        fs::write(
            root.join(name).join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>{name}</artifactId><version>1</version>{body}<dependencies>\
                 <dependency><groupId>org.test</groupId><artifactId>zz-release</artifactId>\
                 <version>1.0</version></dependency></dependencies></project>"
            ),
        )
        .unwrap();
    };
    module(
        "a",
        &format!(
            "<repositories><repository><id>pom-always</id><url>{unused}</url><snapshots>\
             <enabled>true</enabled><updatePolicy>always</updatePolicy></snapshots>\
             </repository></repositories>"
        ),
    );
    module(
        "b",
        "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>snapshot</artifactId><version>1.0-SNAPSHOT</version><type>pom</type>\
         <scope>import</scope></dependency></dependencies></dependencyManagement>",
    );
    fs::write(
        root.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules><module>a</module><module>b</module></modules></project>",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "initial sync");
    let lock_path = root.join("raeva.lock");
    let before = fs::read_to_string(&lock_path).unwrap();
    assert!(
        before.contains("org.test:snapshot:1.0-SNAPSHOT"),
        "{before}"
    );
    publish_snapshot_repository(repository.path(), true);
    assert_success(&run_raeva(root, home.path(), &["sync"]), "warm sync");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), before);
}

/// A module's dependency on the reactor module `snapshot`, which takes its
/// own SNAPSHOT jar from a repository, reads no repository file: the
/// module's `always` policy leaves that jar to `snapshot`'s daily policy, so
/// a plain sync reuses the lock.
#[test]
fn a_reactor_dependency_leaves_the_modules_own_snapshot_jar_to_its_policy() {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let repository = TempDir::new().expect("repository");
    let unused = TempDir::new().expect("unused repository");
    publish_snapshot_repository(repository.path(), false);
    let url = url::Url::from_directory_path(repository.path()).unwrap();
    let unused = url::Url::from_directory_path(unused.path()).unwrap();
    let root = project.path();
    fs::write(
        root.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"snapshot-fixture\"\nurl = \"{url}\"\nreleases = true\n\
             snapshots = true\nsnapshots-update-policy = \"daily\"\n"
        ),
    )
    .unwrap();
    let module = |name: &str, version: &str, wanted: &str, body: &str| {
        fs::create_dir_all(root.join(name)).unwrap();
        fs::write(
            root.join(name).join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>{name}</artifactId><version>{version}</version>{body}\
                 <dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>snapshot</artifactId><version>{wanted}</version>\
                 </dependency></dependencies></project>"
            ),
        )
        .unwrap();
    };
    module("snapshot", "1.0-SNAPSHOT", "[1.0-SNAPSHOT]", "");
    module(
        "app",
        "1",
        "1.0-SNAPSHOT",
        &format!(
            "<repositories><repository><id>pom-always</id><url>{unused}</url><snapshots>\
             <enabled>true</enabled><updatePolicy>always</updatePolicy></snapshots>\
             </repository></repositories>"
        ),
    );
    fs::write(
        root.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules><module>snapshot</module><module>app</module></modules></project>",
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "initial sync");
    let before = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(before.contains("compile\\t\\tsnapshot/pom.xml"), "{before}");
    let warm = run_raeva(root, home.path(), &["sync"]);
    assert_success(&warm, "warm sync");
    let said = String::from_utf8_lossy(&warm.stderr);
    assert!(!said.contains("Resolving dependencies"), "{said}");
}

/// Module a reads `t:shared:1` from repository A, which has the jar but no
/// POM; module b reads its tests jar and POM from B. Maven builds both,
/// online and offline, and its local repository holds the one POM, under
/// B. The lock pins that POM for both files from B, `--frozen` and a second
/// sync keep it, and the export labels it as Maven does.
#[test]
fn a_pom_one_module_reads_none_of_is_pinned_from_the_module_that_read_it() {
    let (project, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let root = project.path();
    let pom_text = |artifact: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
        )
    };
    let shared = root.join("repos/A/t/shared/1/shared-1.jar");
    write_with_sha256(&shared, b"shared jar");
    let shared = root.join("repos/B/t/shared/1/shared-1");
    write_with_sha256(
        &shared.with_extension("pom"),
        pom_text("shared", "").as_bytes(),
    );
    write_with_sha256(
        &root.join("repos/B/t/shared/1/shared-1-tests.jar"),
        b"tests",
    );
    fs::write(
        root.join("pom.xml"),
        pom_text(
            "app",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module></modules>",
        ),
    )
    .unwrap();
    for (module, repo, extra) in [("a", "A", ""), ("b", "B", "<type>test-jar</type>")] {
        let url = format!("file://{}/repos/{repo}/", root.display());
        fs::create_dir_all(root.join(module)).unwrap();
        fs::write(
            root.join(format!("{module}/pom.xml")),
            pom_text(
                module,
                &format!(
                    "<repositories><repository><id>{repo}</id><url>{url}</url></repository>\
                     </repositories><dependencies><dependency><groupId>t</groupId>\
                     <artifactId>shared</artifactId><version>1</version>{extra}</dependency>\
                     </dependencies>"
                ),
            ),
        )
        .unwrap();
    }
    let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&raeva(&["sync"]), "sync");
    let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert_success(&raeva(&["sync", "--frozen"]), "frozen sync");
    assert_success(&raeva(&["sync"]), "second sync");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), lock);
    let m2 = home.path().join("m2");
    let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
    assert_success(&raeva(&export), "export");
    let markers = fs::read_to_string(m2.join("t/shared/1/_remote.repositories")).unwrap();
    let lines: Vec<_> = markers
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    for line in [
        "shared-1.pom>B=",
        "shared-1.jar>A=",
        "shared-1-tests.jar>B=",
    ] {
        assert!(lines.contains(&line), "{lines:?} {lock}");
    }
    assert!(!lines.contains(&"shared-1.pom>A="), "{lines:?} {lock}");
}

/// Modules a and b read one jar, a from a repository without its POM and b
/// from one with it. Whichever repository the merged row names, the lock
/// pins b's POM, under b's repository only.
#[test]
fn one_jar_read_with_and_without_its_pom_keeps_the_pom() {
    for lacking in ["A", "B"] {
        let (project, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let root = project.path();
        let pom_text = |artifact: &str, body: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
            )
        };
        let serving = if lacking == "A" { "B" } else { "A" };
        for repo in ["A", "B"] {
            write_with_sha256(
                &root.join(format!("repos/{repo}/t/shared/1/shared-1.jar")),
                b"shared jar",
            );
        }
        write_with_sha256(
            &root.join(format!("repos/{serving}/t/shared/1/shared-1.pom")),
            pom_text("shared", "").as_bytes(),
        );
        fs::write(
            root.join("pom.xml"),
            pom_text(
                "app",
                "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                 </modules>",
            ),
        )
        .unwrap();
        for (module, repo) in [("a", lacking), ("b", serving)] {
            let url = format!("file://{}/repos/{repo}/", root.display());
            fs::create_dir_all(root.join(module)).unwrap();
            fs::write(
                root.join(format!("{module}/pom.xml")),
                pom_text(
                    module,
                    &format!(
                        "<repositories><repository><id>{repo}</id><url>{url}</url>\
                         </repository></repositories><dependencies><dependency>\
                         <groupId>t</groupId><artifactId>shared</artifactId>\
                         <version>1</version></dependency></dependencies>"
                    ),
                ),
            )
            .unwrap();
        }
        let raeva = |args: &[&str]| run_raeva(root, home.path(), args);
        assert_success(&raeva(&["sync"]), "sync");
        let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(lock.contains("pom_sha256"), "lacking {lacking}: {lock}");
        let m2 = home.path().join("m2");
        let export = ["export-m2", "--m2-path", m2.to_str().unwrap()];
        assert_success(&raeva(&export), "export");
        let markers = fs::read_to_string(m2.join("t/shared/1/_remote.repositories")).unwrap();
        assert!(
            markers.contains(&format!("shared-1.pom>{serving}="))
                && !markers.contains(&format!("shared-1.pom>{lacking}=")),
            "lacking {lacking}: {markers} {lock}"
        );
    }
}

/// Writes a reactor of modules a and b, listed in `modules` order, each
/// with its own repository: A serves `t:shared:1` without its POM, beside
/// `t:shared:2` and `t:wrapper:1`, which depends on `t:shared:1`; B serves
/// the POM of `t:shared:1` with `shared_body`, its `tests` jar, `t:x:1`
/// and `t:moved:1`. Each module declares its `dependencies`.
fn shared_descriptor_reactor(
    root: &Path,
    modules: [&str; 2],
    dependencies: [&str; 2],
    shared_body: &str,
    maven: &str,
) {
    let pom_text = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let shared_1 = "<dependencies><dependency><groupId>t</groupId><artifactId>shared</artifactId>\
                    <version>1</version></dependency></dependencies>";
    for (repo, artifact, version, file, bytes) in [
        ("A", "shared", "1", "shared-1.jar", b"shared".to_vec()),
        ("A", "shared", "2", "shared-2.jar", b"shared 2".to_vec()),
        (
            "A",
            "shared",
            "2",
            "shared-2.pom",
            pom_text("shared", "2", "").into_bytes(),
        ),
        ("A", "wrapper", "1", "wrapper-1.jar", b"wrapper".to_vec()),
        (
            "A",
            "wrapper",
            "1",
            "wrapper-1.pom",
            pom_text("wrapper", "1", shared_1).into_bytes(),
        ),
        ("B", "shared", "1", "shared-1.jar", b"shared".to_vec()),
        ("B", "shared", "1", "shared-1-tests.jar", b"tests".to_vec()),
        (
            "B",
            "shared",
            "1",
            "shared-1.pom",
            pom_text("shared", "1", shared_body).into_bytes(),
        ),
        ("B", "x", "1", "x-1.jar", b"x".to_vec()),
        (
            "B",
            "x",
            "1",
            "x-1.pom",
            pom_text("x", "1", "").into_bytes(),
        ),
        ("B", "moved", "1", "moved-1.jar", b"moved".to_vec()),
        (
            "B",
            "moved",
            "1",
            "moved-1.pom",
            pom_text("moved", "1", "").into_bytes(),
        ),
    ] {
        write_with_sha256(
            &root.join(format!("repos/{repo}/t/{artifact}/{version}/{file}")),
            &bytes,
        );
    }
    let listed: String = (modules.iter())
        .map(|module| format!("<module>{module}</module>"))
        .collect();
    fs::write(
        root.join("pom.xml"),
        pom_text(
            "app",
            "1",
            &format!("<packaging>pom</packaging><modules>{listed}</modules>"),
        ),
    )
    .unwrap();
    fs::write(
        root.join("raeva.toml"),
        format!("[lock]\nmaven = \"{maven}\"\n"),
    )
    .unwrap();
    for ((module, repo), dependencies) in [("a", "A"), ("b", "B")].into_iter().zip(dependencies) {
        let url = format!("file://{}/repos/{repo}/", root.display());
        fs::create_dir_all(root.join(module)).unwrap();
        fs::write(
            root.join(format!("{module}/pom.xml")),
            pom_text(
                module,
                "1",
                &format!(
                    "<repositories><repository><id>{repo}</id><url>{url}</url>\
                     </repository></repositories><dependencies>{dependencies}</dependencies>"
                ),
            ),
        )
        .unwrap();
    }
}

/// A dependency on `t:{artifact}:{version}` with `extra` inside it.
fn t_dependency(artifact: &str, version: &str, extra: &str) -> String {
    format!(
        "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
         <version>{version}</version>{extra}</dependency>"
    )
}

/// Asserts the Maven 3.9 mode's refusal of a descriptor modules a and b
/// read apart: exit 5 naming `coord` and both modules, no URL, no lock.
fn assert_shared_descriptor_refused(
    root: &Path,
    output: &std::process::Output,
    coord: &str,
    case: &str,
) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(5), "{case}: {stderr}");
    for part in [coord, "a/pom.xml", "b/pom.xml", "maven = \"3.10\""] {
        assert!(stderr.contains(part), "{case}: {stderr}");
    }
    assert!(!stderr.contains("repos/"), "{case}: {stderr}");
    assert!(!root.join("raeva.lock").exists(), "{case}");
}

const EXCLUDES_X: &str = "<exclusions><exclusion><groupId>t</groupId><artifactId>x</artifactId></exclusion></exclusions>";

/// Module a reads `t:shared:1` from a repository without its POM, and
/// module b reads the POM, which depends on `t:x:1`. Maven 3.9.12 keeps one
/// descriptor per artifact for the build: built in turn, b gets no `t:x`
/// after a, and a fails after b, while `-T 2` and `-pl b` give b `t:x`. The
/// Maven 3.9 mode refuses the project in either module order without a
/// URL, also when b excludes `t:x`; it locks a POM without dependencies,
/// which reads as none does, one read for another classifier, and in the
/// Maven 3.10 mode, which reads each module's own, `t:x` for b only.
#[test]
fn a_pom_one_module_lacks_that_gives_another_dependencies_is_refused_in_maven_39() {
    let x = "<dependencies><dependency><groupId>t</groupId><artifactId>x</artifactId>\
             <version>1</version></dependency></dependencies>";
    let tests = "<classifier>tests</classifier>";
    for (modules, shared_body, b_extra, maven, refused) in [
        (["a", "b"], x, "", "3.9", true),
        (["b", "a"], x, "", "3.9", true),
        (["b", "a"], x, EXCLUDES_X, "3.9", true),
        (["a", "b"], "", "", "3.9", false),
        // Another classifier is another descriptor.
        (["a", "b"], x, tests, "3.9", false),
        (["a", "b"], x, "", "3.10", false),
    ] {
        let (project, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let root = project.path();
        let dependencies = [
            t_dependency("shared", "1", ""),
            t_dependency("shared", "1", b_extra),
        ];
        shared_descriptor_reactor(
            root,
            modules,
            dependencies.each_ref().map(String::as_str),
            shared_body,
            maven,
        );
        let output = run_raeva(root, home.path(), &["sync"]);
        let case = format!("{modules:?} {maven} {shared_body:?} {b_extra:?}");
        if !refused {
            assert_success(&output, &case);
            let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert_eq!(
                lock.contains("t:x:1"),
                !shared_body.is_empty(),
                "{case}: {lock}"
            );
            continue;
        }
        assert_shared_descriptor_refused(root, &output, "t:shared:1", &case);
    }
}

/// Two more readings Maven 3.9 pools: a losing SNAPSHOT build, under its
/// base version, whose POM lists other dependencies in A than in B, and B's POM relocating
/// `t:shared:1` to the reactor module `t:moved:1` where A has none. Both
/// are refused in either module order.
#[test]
fn a_snapshot_build_or_a_relocation_into_the_reactor_must_read_alike_in_maven_39() {
    let pom_text = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let x = "<dependencies><dependency><groupId>t</groupId><artifactId>x</artifactId>\
             <version>1</version></dependency></dependencies>";
    let moved = "<distributionManagement><relocation><artifactId>moved</artifactId>\
                 </relocation></distributionManagement>";
    let build = "1-20260101.000000-1";
    let metadata = format!(
        "<metadata><groupId>t</groupId><artifactId>snap</artifactId><version>1-SNAPSHOT</version>\
         <versioning><snapshot><timestamp>20260101.000000</timestamp><buildNumber>1</buildNumber>\
         </snapshot><snapshotVersions><snapshotVersion><extension>jar</extension>\
         <value>{build}</value></snapshotVersion><snapshotVersion><extension>pom</extension>\
         <value>{build}</value></snapshotVersion></snapshotVersions></versioning></metadata>"
    );
    for (case, coord) in [("snapshot", "t:snap:1-SNAPSHOT"), ("reactor", "t:shared:1")] {
        for modules in [["a", "b"], ["b", "a"]] {
            let (project, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
            let root = project.path();
            // a's SNAPSHOT build loses to `t:snap:2`, which the existing
            // check of the locked POMs' bytes leaves out.
            let (shared_body, a_dependencies, b_dependency) = match case {
                "snapshot" => (
                    x,
                    t_dependency("snap", "2", "") + &t_dependency("snapwrap", "1", ""),
                    t_dependency("snap", "1-SNAPSHOT", ""),
                ),
                _ => (
                    moved,
                    t_dependency("shared", "1", ""),
                    t_dependency("shared", "1", ""),
                ),
            };
            shared_descriptor_reactor(
                root,
                modules,
                [&a_dependencies, &b_dependency],
                shared_body,
                "3.9",
            );
            let snapwrap = format!(
                "<dependencies>{}</dependencies>",
                t_dependency("snap", "1-SNAPSHOT", "")
            );
            for (artifact, version, body) in
                [("snap", "2", ""), ("snapwrap", "1", snapwrap.as_str())]
            {
                let file = |extension: &str| {
                    root.join(format!(
                        "repos/A/t/{artifact}/{version}/{artifact}-{version}.{extension}"
                    ))
                };
                write_with_sha256(&file("pom"), pom_text(artifact, version, body).as_bytes());
                write_with_sha256(&file("jar"), artifact.as_bytes());
            }
            let snap = |repo: &str, file: &str| {
                root.join(format!("repos/{repo}/t/snap/1-SNAPSHOT/{file}"))
            };
            let shared_2 = format!(
                "<dependencies>{}</dependencies>",
                t_dependency("shared", "2", "")
            );
            for (repo, body) in [("A", shared_2.as_str()), ("B", x)] {
                write_with_sha256(&snap(repo, "maven-metadata.xml"), metadata.as_bytes());
                write_with_sha256(
                    &snap(repo, &format!("snap-{build}.pom")),
                    pom_text("snap", "1-SNAPSHOT", body).as_bytes(),
                );
                write_with_sha256(&snap(repo, &format!("snap-{build}.jar")), b"snap");
            }
            if case == "reactor" {
                fs::create_dir_all(root.join("moved")).unwrap();
                fs::write(root.join("moved/pom.xml"), pom_text("moved", "1", "")).unwrap();
                let parent = fs::read_to_string(root.join("pom.xml")).unwrap();
                let parent = parent.replace("</modules>", "<module>moved</module></modules>");
                fs::write(root.join("pom.xml"), parent).unwrap();
            }
            let output = run_raeva(root, home.path(), &["sync"]);
            assert_shared_descriptor_refused(root, &output, coord, &format!("{case} {modules:?}"));
        }
    }
}

/// A relocation Maven 3.9 pools with every POM along it. a's
/// `t:shared:1` loses in both cases, which leaves the check of locked POM
/// bytes out:
/// - A lacks `t:shared:1`'s POM, and B's relocates it to the SNAPSHOT
///   `t:moved:1-SNAPSHOT`.
/// - Both serve one POM relocating `t:shared:1` to `t:mid:1`; A lacks
///   `t:mid:1`'s, and B's relocates on to `t:end:1`, whose POM B lacks.
///
/// Both are refused in either module order.
#[test]
fn a_relocation_maven_39_reads_once_must_read_alike_along_its_chain() {
    let pom_text = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let relocate = |artifact: &str, version: &str| {
        format!(
            "<distributionManagement><relocation><artifactId>{artifact}</artifactId>\
             {version}</relocation></distributionManagement>"
        )
    };
    let build = "1-20260101.000000-1";
    let metadata = format!(
        "<metadata><groupId>t</groupId><artifactId>moved</artifactId><version>1-SNAPSHOT</version>\
         <versioning><snapshot><timestamp>20260101.000000</timestamp><buildNumber>1</buildNumber>\
         </snapshot><snapshotVersions><snapshotVersion><extension>jar</extension>\
         <value>{build}</value></snapshotVersion><snapshotVersion><extension>pom</extension>\
         <value>{build}</value></snapshotVersion></snapshotVersions></versioning></metadata>"
    );
    let a_dependencies = t_dependency("shared", "2", "") + &t_dependency("wrapper", "1", "");
    let b_dependency = t_dependency("shared", "1", "");
    for case in ["snapshot target", "chain"] {
        for modules in [["a", "b"], ["b", "a"]] {
            let (project, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
            let root = project.path();
            let shared_body = match case {
                "snapshot target" => relocate("moved", "<version>1-SNAPSHOT</version>"),
                _ => relocate("mid", ""),
            };
            shared_descriptor_reactor(
                root,
                modules,
                [&a_dependencies, &b_dependency],
                &shared_body,
                "3.9",
            );
            let file = |repo: &str, artifact: &str, version: &str, name: &str| {
                root.join(format!("repos/{repo}/t/{artifact}/{version}/{name}"))
            };
            if case == "snapshot target" {
                let moved = |name: &str| file("B", "moved", "1-SNAPSHOT", name);
                write_with_sha256(&moved("maven-metadata.xml"), metadata.as_bytes());
                let pom = pom_text("moved", "1-SNAPSHOT", "");
                write_with_sha256(&moved(&format!("moved-{build}.pom")), pom.as_bytes());
                write_with_sha256(&moved(&format!("moved-{build}.jar")), b"moved");
            } else {
                let shared = pom_text("shared", "1", &shared_body);
                write_with_sha256(&file("A", "shared", "1", "shared-1.pom"), shared.as_bytes());
                write_with_sha256(&file("A", "mid", "1", "mid-1.jar"), b"mid");
                let mid = pom_text("mid", "1", &relocate("end", ""));
                write_with_sha256(&file("B", "mid", "1", "mid-1.pom"), mid.as_bytes());
                write_with_sha256(&file("B", "end", "1", "end-1.jar"), b"end");
            }
            let output = run_raeva(root, home.path(), &["sync"]);
            assert_shared_descriptor_refused(
                root,
                &output,
                "t:shared:1",
                &format!("{case} {modules:?}"),
            );
        }
    }
}

/// A relocation that names the SNAPSHOT version it moves to reads the
/// target's own build, not the one it moved from: B relocates
/// `t:old:1-SNAPSHOT`, at one build, to `t:mid:1-SNAPSHOT`, at another,
/// and on to `t:end:1`. a's `t:old:1-SNAPSHOT`, which A lacks, loses to
/// `t:old:2`. Refused in either module order.
#[test]
fn a_relocation_to_a_named_snapshot_reads_that_snapshot_s_own_build_in_maven_39() {
    let pom_text = |artifact: &str, version: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>"
        )
    };
    let relocate = |artifact: &str, version: &str| {
        format!(
            "<distributionManagement><relocation><artifactId>{artifact}</artifactId>\
             <version>{version}</version></relocation></distributionManagement>"
        )
    };
    let metadata = |artifact: &str, stamp: &str, number: &str| {
        let build = format!("1-{stamp}-{number}");
        let text = format!(
            "<metadata><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>1-SNAPSHOT</version><versioning><snapshot><timestamp>{stamp}</timestamp>\
             <buildNumber>{number}</buildNumber></snapshot><snapshotVersions><snapshotVersion>\
             <extension>jar</extension><value>{build}</value></snapshotVersion><snapshotVersion>\
             <extension>pom</extension><value>{build}</value></snapshotVersion>\
             </snapshotVersions></versioning></metadata>"
        );
        (build, text)
    };
    let a_dependencies = t_dependency("old", "2", "") + &t_dependency("oldwrap", "1", "");
    let b_dependency = t_dependency("old", "1-SNAPSHOT", "");
    for modules in [["a", "b"], ["b", "a"]] {
        let (project, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let root = project.path();
        shared_descriptor_reactor(root, modules, [&a_dependencies, &b_dependency], "", "3.9");
        let file = |repo: &str, artifact: &str, version: &str, name: &str| {
            root.join(format!("repos/{repo}/t/{artifact}/{version}/{name}"))
        };
        let oldwrap = format!(
            "<dependencies>{}</dependencies>",
            t_dependency("old", "1-SNAPSHOT", "")
        );
        for (artifact, version, body) in [("old", "2", ""), ("oldwrap", "1", oldwrap.as_str())] {
            let name = |extension: &str| format!("{artifact}-{version}.{extension}");
            let pom = pom_text(artifact, version, body);
            write_with_sha256(&file("A", artifact, version, &name("pom")), pom.as_bytes());
            write_with_sha256(
                &file("A", artifact, version, &name("jar")),
                artifact.as_bytes(),
            );
        }
        for (artifact, stamp, number, body) in [
            ("old", "20260101.000000", "1", relocate("mid", "1-SNAPSHOT")),
            ("mid", "20260202.000000", "2", relocate("end", "1")),
        ] {
            let (build, text) = metadata(artifact, stamp, number);
            write_with_sha256(
                &file("B", artifact, "1-SNAPSHOT", "maven-metadata.xml"),
                text.as_bytes(),
            );
            write_with_sha256(
                &file(
                    "B",
                    artifact,
                    "1-SNAPSHOT",
                    &format!("{artifact}-{build}.pom"),
                ),
                pom_text(artifact, "1-SNAPSHOT", &body).as_bytes(),
            );
        }
        write_with_sha256(
            &file("B", "end", "1", "end-1.pom"),
            pom_text("end", "1", "").as_bytes(),
        );
        write_with_sha256(&file("B", "end", "1", "end-1.jar"), b"end");
        let output = run_raeva(root, home.path(), &["sync"]);
        assert_shared_descriptor_refused(
            root,
            &output,
            "t:old:1-SNAPSHOT",
            &format!("{modules:?}"),
        );
    }
}

/// Maven 3.9 keeps the first module's reading of a POM for the whole
/// build, so the Maven 3.9 mode refuses any two that differ, whatever
/// either changes (verify/missing-pom.md has Maven 3.9.12's runs):
/// - a reads `t:shared:1` for a losing node below `t:wrapper:1`, as
///   `t:shared:2` wins, without its POM or with other bytes than b's.
/// - B's POM relocates `t:shared:1` to `t:moved:1`.
/// - Both modules exclude `t:x`, which only B's POM lists.
///
/// b asking for `t:shared:1` as a `maven-plugin` is another artifact than
/// a's `jar`, with its own reading: b gets `t:x` in either order.
#[test]
fn a_pom_maven_39_reads_once_must_read_alike_in_every_module() {
    let x = "<dependencies><dependency><groupId>t</groupId><artifactId>x</artifactId>\
             <version>1</version></dependency></dependencies>";
    let other_x = format!("<name>A</name>{x}");
    let moved = "<distributionManagement><relocation><artifactId>moved</artifactId>\
                 </relocation></distributionManagement>";
    let shared = t_dependency("shared", "1", "");
    let losing = t_dependency("shared", "2", "") + &t_dependency("wrapper", "1", "");
    let excluding = t_dependency("shared", "1", EXCLUDES_X);
    let plugin = t_dependency("shared", "1", "<type>maven-plugin</type>");
    for (name, shared_body, a_pom, a_dependencies, b_dependencies, x_locked) in [
        ("losing", x, None, &losing, &shared, None),
        (
            "losing, other bytes",
            x,
            Some(&other_x),
            &losing,
            &shared,
            None,
        ),
        ("relocated", moved, None, &shared, &shared, None),
        ("excluded", x, None, &excluding, &excluding, None),
        ("maven-plugin", x, None, &shared, &plugin, Some(true)),
    ] {
        for modules in [["a", "b"], ["b", "a"]] {
            let (project, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
            let root = project.path();
            shared_descriptor_reactor(
                root,
                modules,
                [a_dependencies, b_dependencies],
                shared_body,
                "3.9",
            );
            if let Some(body) = a_pom {
                write_with_sha256(
                    &root.join("repos/A/t/shared/1/shared-1.pom"),
                    format!(
                        "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                         <artifactId>shared</artifactId><version>1</version>{body}</project>"
                    )
                    .as_bytes(),
                );
            }
            let output = run_raeva(root, home.path(), &["sync"]);
            let case = format!("{name} {modules:?}");
            let Some(x_locked) = x_locked else {
                assert_shared_descriptor_refused(root, &output, "t:shared:1", &case);
                continue;
            };
            assert_success(&output, &case);
            let lock = fs::read_to_string(root.join("raeva.lock")).unwrap();
            assert_eq!(lock.contains("t:x:1"), x_locked, "{case}: {lock}");
        }
    }
}

/// A `<module>` entry may name the module's POM file under any name, as
/// Maven 3.9.12 and 3.10.0 read it, also beside another module's POM in one
/// directory. raeva.lock records the file's path, a sibling depends on the
/// module through the reactor, `--module` selects it, and an edit of the
/// file that changes the graph fails `--frozen`.
#[test]
fn a_module_entry_may_name_its_pom_file() {
    for maven in ["3.9", "3.10"] {
        let temp = TempDir::new().expect("project");
        let root = temp.path().join("project");
        let repo = temp.path().join("repo");
        crate::common::publish(&repo, "org.test:lib:1", "");
        let module = |artifact: &str, packaging: &str, body: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>{artifact}</artifactId><version>1</version>\
                 <packaging>{packaging}</packaging>{body}</project>"
            )
        };
        let child_dependency = "<dependencies><dependency><groupId>org.test</groupId>\
                                <artifactId>child</artifactId><version>1</version>\
                                </dependency></dependencies>";
        fs::create_dir_all(root.join("child")).expect("mkdir");
        fs::write(
            root.join("pom.xml"),
            module(
                "root",
                "pom",
                "<modules><module>child/custom.xml</module><module>other.xml</module>\
                 </modules>",
            ),
        )
        .expect("root pom");
        fs::write(root.join("child/custom.xml"), module("child", "jar", "")).expect("child");
        fs::write(
            root.join("other.xml"),
            module("other", "jar", child_dependency),
        )
        .expect("other");
        let url = url::Url::from_directory_path(&repo).unwrap().to_string();
        write_repo_toml(&root, "fixture", &url);
        let toml = fs::read_to_string(root.join("raeva.toml")).expect("raeva.toml");
        fs::write(
            root.join("raeva.toml"),
            format!("{toml}\n[lock]\nmaven = \"{maven}\"\n"),
        )
        .expect("raeva.toml");
        let home = TempDir::new().expect("home");
        let output = run_raeva(&root, home.path(), &["sync"]);
        assert_success(&output, &format!("{maven} sync"));
        let lock: toml::Value =
            toml::from_str(&fs::read_to_string(root.join("raeva.lock")).expect("lock"))
                .expect("parse lock");
        let paths: Vec<&str> = (lock["platforms"][0]["modules"].as_array().expect("modules"))
            .iter()
            .map(|module| module["path"].as_str().expect("path"))
            .collect();
        assert_eq!(
            paths,
            ["child/custom.xml", "other.xml", "pom.xml"],
            "{maven}"
        );
        let output = run_raeva(&root, home.path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{maven} frozen"));
        let output = run_raeva(
            &root,
            home.path(),
            &["tree", "--module", "child/custom.xml"],
        );
        assert_success(&output, &format!("{maven} tree"));
        let lib = "<dependencies><dependency><groupId>org.test</groupId>\
                   <artifactId>lib</artifactId><version>1</version></dependency></dependencies>";
        fs::write(root.join("child/custom.xml"), module("child", "jar", lib)).expect("child");
        let output = run_raeva(&root, home.path(), &["sync", "--frozen"]);
        assert_status(&output, 7, &format!("{maven} frozen after the edit"));
        assert_success(&run_raeva(&root, home.path(), &["sync"]), "sync again");
        let output = run_raeva(&root, home.path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{maven} frozen after the sync"));
    }
}
