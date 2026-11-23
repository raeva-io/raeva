//! A lock written behind one mirror setup and checked by `sync --frozen`
//! behind another, as a CI home often is. Behind a `<mirrorOf>*</mirrorOf>`
//! mirror every request reaches one server, so the lock records the first
//! repository searched for each file and every repository a range listed.
//! The check passes where Maven builds the same thing and fails where the
//! bytes or the versions differ.

use std::fs;
use std::path::Path;

use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{assert_status, assert_success, publish, run_raeva, write_with_sha256};

/// Serves the files below `root`, each with its `.sha256` file.
fn serve(root: &Path) -> (StubServer, String) {
    let root = root.to_path_buf();
    let server = StubServer::start(move |request| {
        match fs::read(root.join(request.path.trim_start_matches('/'))) {
            Ok(bytes) => Response::new(200, bytes),
            Err(_) => Response::new(404, ""),
        }
    });
    let url = format!("http://{}/", server.addr());
    (server, url)
}

fn list(repository: &Path, group: &str, artifact: &str, versions: &[&str]) {
    let versions: String = (versions.iter())
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    let body = format!(
        "<metadata><groupId>{group}</groupId><artifactId>{artifact}</artifactId>\
         <versioning><versions>{versions}</versions></versioning></metadata>"
    );
    let path = repository.join(group.replace('.', "/")).join(artifact);
    write_with_sha256(&path.join("maven-metadata.xml"), body.as_bytes());
}

/// A user home whose settings.xml has one mirror of `mirror_of` at `url`,
/// with `config` as its config.toml.
fn home(mirror_of: &str, url: &str, config: &str) -> TempDir {
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>m</id><mirrorOf>{mirror_of}</mirrorOf>\
             <url>{url}</url></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    fs::write(home.path().join("config.toml"), config).unwrap();
    home
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The exit code of `sync --frozen` behind `ci` for a lock `sync` wrote
/// behind `locked`, each a mirror's `mirrorOf` and URL. A check that passes
/// passes offline after it too.
fn frozen_after(project: &Path, config: &str, locked: (&str, &str), ci: (&str, &str)) -> i32 {
    let lock_home = home(locked.0, locked.1, config);
    assert_success(&run_raeva(project, lock_home.path(), &["sync"]), "sync");
    let ci_home = home(ci.0, ci.1, config);
    let frozen = run_raeva(project, ci_home.path(), &["sync", "--frozen"]);
    let code = frozen.status.code().unwrap();
    if code == 0 {
        let offline = ["--offline", "sync", "--frozen"];
        let offline = run_raeva(project, ci_home.path(), &offline);
        assert_success(&offline, "offline sync --frozen after the frozen check");
        // An offline Maven reads what the export writes from this lock.
        let m2 = ci_home.path().join("exported");
        let export = run_raeva(
            project,
            ci_home.path(),
            &["--offline", "export-m2", "--m2-path", m2.to_str().unwrap()],
        );
        assert_success(&export, "export-m2");
    } else {
        assert_status(&frozen, 7, "sync --frozen");
    }
    code
}

/// How the servers the two homes reach differ.
#[derive(Clone, Copy, PartialEq)]
enum Manager {
    Same,
    /// A file has other bytes.
    OtherBytes,
    /// Only the lock home's server lists `x:lib` 1.7, which CI's servers
    /// hold unlisted, so Maven takes 1.5 there. A version listed only in
    /// CI is no drift: the lock caps a range at its version.
    HigherVersion,
}

/// An imported BOM declares repository `first`, which alone holds the
/// BOM's parent. Written with a Central-only mirror, the lock records the
/// parent from `first`; behind a `*` mirror to a manager that has
/// everything, Maven reads it there for the BOM's build.
/// With `reactor`, two modules import the BOM, and the second reuses the
/// first one's build of it.
fn bom_parent_from_its_own_repository(manager: Manager, reactor: bool) -> i32 {
    let repos = TempDir::new().unwrap();
    let (central, first, all) = (
        repos.path().join("central"),
        repos.path().join("first"),
        repos.path().join("all"),
    );
    let (_first, first_url) = serve(&first);
    let bom = format!(
        "<packaging>pom</packaging><parent><groupId>d</groupId>\
         <artifactId>bom-parent</artifactId><version>1.0</version><relativePath/></parent>\
         <repositories><repository><id>first</id><url>{first_url}</url></repository>\
         </repositories><dependencyManagement><dependencies><dependency><groupId>c</groupId>\
         <artifactId>common</artifactId><version>1.0</version></dependency></dependencies>\
         </dependencyManagement>"
    );
    publish(&central, "d:bom:1.0", &bom);
    publish(&central, "c:common:1.0", "");
    publish(&first, "d:bom-parent:1.0", "<packaging>pom</packaging>");
    fs::create_dir_all(&all).unwrap();
    copy_tree(&central, &all);
    copy_tree(&first, &all);
    if manager == Manager::OtherBytes {
        publish(
            &all,
            "d:bom-parent:1.0",
            "<packaging>pom</packaging><description>other</description>",
        );
    }
    let (_central, central_url) = serve(&central);
    let (_all, all_url) = serve(&all);
    let project = TempDir::new().unwrap();
    let module = |artifact: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>app</groupId>\
             <artifactId>{artifact}</artifactId><version>1</version><dependencyManagement>\
             <dependencies><dependency><groupId>d</groupId><artifactId>bom</artifactId>\
             <version>1.0</version><type>pom</type><scope>import</scope></dependency>\
             </dependencies></dependencyManagement><dependencies><dependency>\
             <groupId>c</groupId><artifactId>common</artifactId></dependency></dependencies>\
             </project>"
        )
    };
    if reactor {
        fs::write(
            project.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>app</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>a</module><module>b</module></modules></project>",
        )
        .unwrap();
        for artifact in ["a", "b"] {
            fs::create_dir_all(project.path().join(artifact)).unwrap();
            fs::write(
                project.path().join(artifact).join("pom.xml"),
                module(artifact),
            )
            .unwrap();
        }
    } else {
        fs::write(project.path().join("pom.xml"), module("app")).unwrap();
    }
    frozen_after(
        project.path(),
        "[security]\nallow_transitive_repositories = true\n",
        ("central", &central_url),
        ("*", &all_url),
    )
}

#[test]
fn a_bom_parent_from_the_boms_own_repository_passes_behind_a_star_mirror() {
    for reactor in [false, true] {
        assert_eq!(
            bom_parent_from_its_own_repository(Manager::Same, reactor),
            0,
            "reactor: {reactor}"
        );
    }
}

#[test]
fn a_bom_parent_with_other_bytes_behind_a_star_mirror_is_drift() {
    for reactor in [false, true] {
        assert_eq!(
            bom_parent_from_its_own_repository(Manager::OtherBytes, reactor),
            7,
            "reactor: {reactor}"
        );
    }
}

/// A `file:` repository in the project holds `x:lib` 1.0 and 1.5, which
/// `[1.0,2.0)` reads; `c:common` comes from Central. The lock home's mirror
/// of `mirror_of` reaches a manager that has everything; CI mirrors Central
/// to a server that has only `c:common`. Maven takes 1.5 from the file
/// repository either way, unless the manager lists a higher version.
fn file_repository_range(mirror_of: &str, manager: Manager) -> i32 {
    let repos = TempDir::new().unwrap();
    let (central, all) = (repos.path().join("central"), repos.path().join("all"));
    let project = TempDir::new().unwrap();
    let local = project.path().join("repo");
    for version in ["1.0", "1.5"] {
        publish(&local, &format!("x:lib:{version}"), "");
        publish(&all, &format!("x:lib:{version}"), "");
    }
    list(&local, "x", "lib", &["1.0", "1.5"]);
    list(&all, "x", "lib", &["1.0", "1.5"]);
    publish(&central, "c:common:1.0", "");
    match manager {
        Manager::Same => publish(&all, "c:common:1.0", ""),
        Manager::OtherBytes => publish(&all, "c:common:1.0", "<description>other</description>"),
        Manager::HigherVersion => {
            publish(&all, "c:common:1.0", "");
            publish(&all, "x:lib:1.7", "");
            publish(&central, "x:lib:1.7", "");
            list(&all, "x", "lib", &["1.0", "1.5", "1.7"]);
        }
    }
    let (_central, central_url) = serve(&central);
    let (_all, all_url) = serve(&all);
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>app</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>shared</id><url>file://${project.basedir}/repo</url></repository></repositories>\
         <dependencies><dependency><groupId>c</groupId><artifactId>common</artifactId>\
         <version>1.0</version></dependency><dependency><groupId>x</groupId>\
         <artifactId>lib</artifactId><version>[1.0,2.0)</version></dependency></dependencies>\
         </project>",
    )
    .unwrap();
    frozen_after(
        project.path(),
        "",
        (mirror_of, &all_url),
        ("central", &central_url),
    )
}

#[test]
fn a_file_repository_range_locked_behind_a_star_mirror_passes_behind_a_central_one() {
    assert_eq!(file_repository_range("*", Manager::Same), 0);
}

#[test]
fn a_range_listed_by_central_only_where_the_lock_was_written_passes() {
    assert_eq!(file_repository_range("central", Manager::Same), 0);
}

#[test]
fn a_listing_that_changes_the_pick_is_drift() {
    assert_eq!(file_repository_range("*", Manager::HigherVersion), 7);
    assert_eq!(file_repository_range("central", Manager::HigherVersion), 7);
}

#[test]
fn a_file_with_other_bytes_through_the_star_mirror_is_drift() {
    assert_eq!(file_repository_range("*", Manager::OtherBytes), 7);
}

/// `y:mid` from Central asks `x:lib` `[1.0,2.0)`, which loses to the
/// project's own `x:lib` 1.0 from its `file:` repository. Behind the star
/// mirror both repositories list the losing range's versions; behind the
/// Central one only the `file:` repository does, and Maven builds the same.
#[test]
fn a_range_that_lost_locked_behind_a_star_mirror_passes_behind_a_central_one() {
    let repos = TempDir::new().unwrap();
    let (central, all) = (repos.path().join("central"), repos.path().join("all"));
    let project = TempDir::new().unwrap();
    let local = project.path().join("repo");
    for repository in [&local, &all] {
        publish(repository, "x:lib:1.0", "");
        publish(repository, "x:lib:1.5", "");
        list(repository, "x", "lib", &["1.0", "1.5"]);
    }
    let mid = "<dependencies><dependency><groupId>x</groupId><artifactId>lib</artifactId>\
               <version>[1.0,2.0)</version></dependency></dependencies>";
    for repository in [&central, &all] {
        publish(repository, "c:common:1.0", "");
        publish(repository, "y:mid:1.0", mid);
    }
    let (_central, central_url) = serve(&central);
    let (_all, all_url) = serve(&all);
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>app</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories><repository>\
         <id>shared</id><url>file://${project.basedir}/repo</url></repository></repositories>\
         <dependencies><dependency><groupId>x</groupId><artifactId>lib</artifactId>\
         <version>1.0</version></dependency><dependency><groupId>y</groupId>\
         <artifactId>mid</artifactId><version>1.0</version></dependency></dependencies>\
         </project>",
    )
    .unwrap();
    let code = frozen_after(
        project.path(),
        "",
        ("*", &all_url),
        ("central", &central_url),
    );
    assert_eq!(code, 0);
}

/// The remote parent declares an empty repository `first`, which the
/// allowlist admits. Behind a `*` mirror the lock records `first` for each
/// file and for the range's list; CI mirrors Central alone, asks `first`
/// itself, and takes everything from Central.
fn remote_parent_repository_range(ci: Manager) -> i32 {
    let repos = TempDir::new().unwrap();
    let (first, locked, checked) = (
        repos.path().join("first"),
        repos.path().join("locked"),
        repos.path().join("checked"),
    );
    fs::create_dir_all(&first).unwrap();
    let (_first, first_url) = serve(&first);
    let higher = ci == Manager::HigherVersion;
    for repository in [&locked, &checked] {
        publish(
            repository,
            "p:parent:1.0",
            &format!(
                "<packaging>pom</packaging><repositories><repository><id>first</id>\
                 <url>{first_url}</url></repository></repositories>"
            ),
        );
        publish(repository, "c:common:1.0", "");
        publish(repository, "x:lib:1.0", "");
        publish(repository, "x:lib:1.5", "");
        list(repository, "x", "lib", &["1.0", "1.5"]);
        if higher {
            publish(repository, "x:lib:1.7", "");
        }
    }
    match ci {
        Manager::Same => {}
        Manager::OtherBytes => publish(&checked, "x:lib:1.5", "<description>other</description>"),
        Manager::HigherVersion => list(&locked, "x", "lib", &["1.0", "1.5", "1.7"]),
    }
    let (_locked, locked_url) = serve(&locked);
    let (_checked, checked_url) = serve(&checked);
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
         <artifactId>parent</artifactId><version>1.0</version><relativePath/></parent>\
         <groupId>app</groupId><artifactId>app</artifactId><version>1</version><dependencies>\
         <dependency><groupId>c</groupId><artifactId>common</artifactId><version>1.0</version>\
         </dependency><dependency><groupId>x</groupId><artifactId>lib</artifactId>\
         <version>[1.0,2.0)</version></dependency></dependencies></project>",
    )
    .unwrap();
    frozen_after(
        project.path(),
        &format!("[security]\ntransitive_repository_allowlist = [\"{first_url}\"]\n"),
        ("*", &locked_url),
        ("central", &checked_url),
    )
}

#[test]
fn a_range_through_a_remote_parents_repository_passes_without_the_star_mirror() {
    assert_eq!(remote_parent_repository_range(Manager::Same), 0);
}

#[test]
fn a_range_through_a_remote_parents_repository_with_other_bytes_or_versions_is_drift() {
    assert_eq!(remote_parent_repository_range(Manager::OtherBytes), 7);
    assert_eq!(remote_parent_repository_range(Manager::HigherVersion), 7);
}

/// The lock took `x:lib` 1.5. CI's mirror also lists 1.7, which a fresh
/// resolution takes, and fails to serve 1.5's POM: that is the server's
/// failure, not a locked version no longer listed, so it is no drift.
#[test]
fn a_replay_the_server_fails_keeps_its_error() {
    let repos = TempDir::new().unwrap();
    let (locked, ci) = (repos.path().join("locked"), repos.path().join("ci"));
    for version in ["1.0", "1.5"] {
        publish(&locked, &format!("x:lib:{version}"), "");
    }
    list(&locked, "x", "lib", &["1.0", "1.5"]);
    copy_tree(&locked, &ci);
    publish(&ci, "x:lib:1.7", "");
    list(&ci, "x", "lib", &["1.0", "1.5", "1.7"]);
    let (_locked, locked_url) = serve(&locked);
    let ci_root = ci.clone();
    let ci_server = StubServer::start(move |request| {
        if request.path == "/x/lib/1.5/lib-1.5.pom" {
            return Response::new(503, "");
        }
        match fs::read(ci_root.join(request.path.trim_start_matches('/'))) {
            Ok(bytes) => Response::new(200, bytes),
            Err(_) => Response::new(404, ""),
        }
    });
    let ci_url = format!("http://{}/", ci_server.addr());
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>app</groupId>\
         <artifactId>app</artifactId><version>1</version><dependencies><dependency>\
         <groupId>x</groupId><artifactId>lib</artifactId><version>[1.0,2.0)</version>\
         </dependency></dependencies></project>",
    )
    .unwrap();
    let config = "[network]\nretries = 0\n";
    let lock_home = home("central", &locked_url, config);
    assert_success(
        &run_raeva(project.path(), lock_home.path(), &["sync"]),
        "sync",
    );
    let ci_home = home("central", &ci_url, config);
    let frozen = run_raeva(project.path(), ci_home.path(), &["sync", "--frozen"]);
    let stderr = String::from_utf8_lossy(&frozen.stderr);
    assert_ne!(frozen.status.code(), Some(7), "{stderr}");
    assert_ne!(frozen.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("503"), "{stderr}");
}
