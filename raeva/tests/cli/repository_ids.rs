//! Maven keys repositories by id: one URL declared under two ids is two
//! repositories, each with its own policies, and `_remote.repositories`
//! names every repository a file was resolved from.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rv_maven_types::BlobId;
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{assert_success, raeva_command, run_raeva, stderr};

const SNAPSHOT: &str = "1.0-20240101.010101-1";

fn publish(repository: &Path, artifact: &str, version: &str) {
    let dir = repository.join(format!("org/test/{artifact}/{version}"));
    fs::create_dir_all(&dir).expect("create repository");
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>{artifact}</artifactId><version>{version}</version></project>"
    );
    let file = |extension: &str| {
        let file_version = if version.ends_with("-SNAPSHOT") {
            SNAPSHOT
        } else {
            version
        };
        dir.join(format!("{artifact}-{file_version}.{extension}"))
    };
    fs::write(file("pom"), pom).expect("write pom");
    fs::write(file("jar"), format!("{artifact} bytes")).expect("write jar");
    if version.ends_with("-SNAPSHOT") {
        let entries: String = ["jar", "pom"]
            .map(|extension| {
                format!(
                    "<snapshotVersion><extension>{extension}</extension>\
                     <value>{SNAPSHOT}</value><updated>20240101010101</updated>\
                     </snapshotVersion>"
                )
            })
            .concat();
        let metadata = format!(
            "<metadata><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version><versioning><snapshot>\
             <timestamp>20240101.010101</timestamp><buildNumber>1</buildNumber></snapshot>\
             <lastUpdated>20240101010101</lastUpdated><snapshotVersions>{entries}\
             </snapshotVersions></versioning></metadata>"
        );
        fs::write(dir.join("maven-metadata.xml"), metadata).expect("write metadata");
    }
}

fn file_url(dir: &Path) -> String {
    url::Url::from_directory_path(dir).unwrap().to_string()
}

fn repository(id: &str, url: &str, releases: bool, snapshots: bool) -> String {
    format!(
        "<repository><id>{id}</id><url>{url}</url>\
         <releases><enabled>{releases}</enabled></releases>\
         <snapshots><enabled>{snapshots}</enabled></snapshots></repository>"
    )
}

fn dependency(artifact: &str, version: &str) -> String {
    format!(
        "<dependency><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
         <version>{version}</version></dependency>"
    )
}

fn module_pom(artifact: &str, parent: bool, repositories: &str, dependencies: &str) -> String {
    let parent = if parent {
        "<parent><groupId>org.test</groupId><artifactId>root</artifactId>\
         <version>1</version></parent>"
    } else {
        "<groupId>org.test</groupId><version>1</version>"
    };
    format!(
        "<project><modelVersion>4.0.0</modelVersion>{parent}<artifactId>{artifact}</artifactId>\
         <repositories>{repositories}</repositories>\
         <dependencies>{dependencies}</dependencies></project>"
    )
}

/// A project in `base/project` whose configured repository is an empty
/// directory, so resolution reaches only what its POMs declare.
fn write_project(base: &Path, pom: &str) -> std::path::PathBuf {
    let project = base.join("project");
    let empty = base.join("empty");
    fs::create_dir_all(&project).expect("create project");
    fs::create_dir_all(&empty).expect("create empty repository");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"empty\"\nurl = \"{}\"\n",
            file_url(&empty)
        ),
    )
    .expect("write raeva.toml");
    fs::write(project.join("pom.xml"), pom).expect("write pom.xml");
    project
}

fn markers(m2: &Path, artifact: &str, version: &str) -> String {
    let dir = m2.join(format!("org/test/{artifact}/{version}"));
    fs::read_to_string(dir.join("_remote.repositories")).expect("read markers")
}

fn export(project: &Path, home: &Path, m2: &Path) {
    let output = run_raeva(
        project,
        home,
        &["export-m2", "--m2-path", m2.to_str().unwrap()],
    );
    assert_success(&output, "export");
}

/// Serves the files below `root` over HTTP, each with a `.sha256` sidecar.
/// A missing key below `/a/` is refused, as an object store refuses it.
fn file_server(root: &Path) -> StubServer {
    let root = root.to_path_buf();
    StubServer::start(move |request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        match fs::read(root.join(path.trim_start_matches('/'))) {
            Ok(bytes) if sidecar => Response::new(200, BlobId::from_bytes(&bytes).to_string()),
            Ok(bytes) => Response::new(200, bytes),
            Err(_) if path.starts_with("/a/") => Response::new(403, ""),
            Err(_) => Response::new(404, ""),
        }
    })
}

/// Writes `org.test:snap:1.0-SNAPSHOT` into `repository` with metadata
/// listing `entries` as (extension, classifier, build) and dated `updated`;
/// `files` maps each file name suffix after `snap-` to its bytes.
fn publish_snapshot(
    repository: &Path,
    updated: &str,
    entries: &[(&str, Option<&str>, &str)],
    files: &[(String, &str)],
) {
    let dir = repository.join("org/test/snap/1.0-SNAPSHOT");
    fs::create_dir_all(&dir).expect("create repository");
    for (name, bytes) in files {
        fs::write(dir.join(format!("snap-{name}")), bytes).expect("write file");
    }
    let entries: String = entries
        .iter()
        .map(|(extension, classifier, value)| {
            let classifier = classifier
                .map(|classifier| format!("<classifier>{classifier}</classifier>"))
                .unwrap_or_default();
            format!(
                "<snapshotVersion><extension>{extension}</extension>{classifier}\
                 <value>{value}</value><updated>{updated}</updated></snapshotVersion>"
            )
        })
        .collect();
    let metadata = format!(
        "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
         <version>1.0-SNAPSHOT</version><versioning><lastUpdated>{updated}</lastUpdated>\
         <snapshotVersions>{entries}</snapshotVersions></versioning></metadata>"
    );
    fs::write(dir.join("maven-metadata.xml"), metadata).expect("write metadata");
}

const SNAP_POM: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
     <artifactId>snap</artifactId><version>1.0-SNAPSHOT</version></project>";

fn pinned_digests(lock: &str) -> Vec<String> {
    lock.split("[[inputs]]")
        .next()
        .unwrap()
        .lines()
        .filter(|line| line.contains("sha256") || line.contains("timestamp"))
        .map(str::to_string)
        .collect()
}

/// A release repository and a snapshot repository on one URL, a common
/// corporate layout, serve a release and a snapshot whichever is declared
/// first, also to a cold restore that picks the declaration by version.
#[test]
fn one_url_serves_releases_and_snapshots_under_two_ids() {
    let base = TempDir::new().expect("base");
    let corp = base.path().join("corp");
    publish(&corp, "rel", "1");
    publish(&corp, "snap", "1.0-SNAPSHOT");
    let url = file_url(&corp);
    let dependencies = dependency("rel", "1") + &dependency("snap", "1.0-SNAPSHOT");
    for releases_first in [false, true] {
        let mut declared = [
            repository("corp-snapshots", &url, false, true),
            repository("corp-releases", &url, true, false),
        ];
        if releases_first {
            declared.reverse();
        }
        let pom = module_pom("app", false, &declared.concat(), &dependencies);
        let project = write_project(&base.path().join(releases_first.to_string()), &pom);
        let home = TempDir::new().expect("home");
        assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");

        let lock = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("lock");
        let origin = crate::common::recorded_origin(&project, &url);
        let ids: Vec<_> = lock.repo_ids[&origin].iter().map(String::as_str).collect();
        assert_eq!(ids, ["corp-releases", "corp-snapshots"]);

        let cold = TempDir::new().expect("cold home");
        let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
        assert_success(&frozen, "cold frozen sync");
        let m2 = base.path().join(format!("m2-{releases_first}"));
        export(&project, cold.path(), &m2);
        let snap = markers(&m2, "snap", "1.0-SNAPSHOT");
        assert!(
            snap.contains("snap-1.0-20240101.010101-1.jar>corp-snapshots="),
            "{snap}"
        );
        assert!(markers(&m2, "rel", "1").contains("rel-1.jar>corp-releases="));
    }
}

/// A parent pinned to a SNAPSHOT build restores into a cold store and
/// exports: restore and export key its evidence by the build read.
#[test]
fn a_snapshot_parent_restored_cold_exports() {
    let base = TempDir::new().expect("base");
    let corp = base.path().join("corp");
    publish(&corp, "parent", "1.0-SNAPSHOT");
    let dir = corp.join("org/test/parent/1.0-SNAPSHOT");
    fs::write(
        dir.join(format!("parent-{SNAPSHOT}.pom")),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>parent</artifactId><version>1.0-SNAPSHOT</version>\
         <packaging>pom</packaging></project>",
    )
    .expect("parent pom");
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
         <artifactId>parent</artifactId><version>1.0-SNAPSHOT</version></parent>\
         <artifactId>app</artifactId><repositories>{}</repositories></project>",
        repository("corp", &file_url(&corp), true, true)
    );
    let project = write_project(base.path(), &pom);
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(lock.contains("timestamp = \"20240101.010101\""), "{lock}");

    let cold = TempDir::new().expect("cold home");
    let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "cold frozen sync");
    let m2 = base.path().join("m2");
    export(&project, cold.path(), &m2);
    let exported = m2.join("org/test/parent/1.0-SNAPSHOT");
    assert!(exported.join(format!("parent-{SNAPSHOT}.pom")).is_file());
}

/// Each module of a reactor resolves through its own repositories, so a file
/// is labelled with every id it was resolved under: one URL that two modules
/// declare under different ids, and identical bytes two repositories serve.
/// `mvn -o` accepts a file for a module only when it is labelled with one of
/// that module's repository ids.
#[test]
fn modules_label_files_with_every_repository_that_served_them() {
    let base = TempDir::new().expect("base");
    let (shared_dir, other_dir) = (base.path().join("shared"), base.path().join("other"));
    for artifact in ["common", "only-a", "only-b"] {
        publish(&shared_dir, artifact, "1");
    }
    publish(&other_dir, "common", "1");
    let (shared, other) = (file_url(&shared_dir), file_url(&other_dir));

    let root = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                <modules><module>a</module><module>b</module><module>c</module></modules>\
                </project>";
    let project = write_project(base.path(), root);
    let modules = [
        (
            "a",
            repository("id-a", &shared, true, false),
            dependency("common", "1") + &dependency("only-a", "1"),
        ),
        (
            "b",
            repository("id-b", &shared, true, false),
            dependency("only-b", "1"),
        ),
        (
            "c",
            repository("id-c", &other, true, false),
            dependency("common", "1"),
        ),
    ];
    for (name, repositories, dependencies) in &modules {
        fs::create_dir_all(project.join(name)).expect("create module");
        fs::write(
            project.join(name).join("pom.xml"),
            module_pom(name, true, repositories, dependencies),
        )
        .expect("write module pom");
    }
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let m2 = base.path().join("m2");
    export(&project, home.path(), &m2);

    let only_b = markers(&m2, "only-b", "1");
    assert!(only_b.contains("only-b-1.jar>id-b="), "{only_b}");
    let common = markers(&m2, "common", "1");
    for id in ["id-a", "id-c"] {
        assert!(common.contains(&format!("common-1.jar>{id}=")), "{common}");
        assert!(common.contains(&format!("common-1.pom>{id}=")), "{common}");
    }
}

/// Maven picks each file's SNAPSHOT build across repositories by `updated`,
/// so a jar and its POM may come from different repositories, with different
/// builds or the same one; a cold restore and `lock verify --download` find
/// the POM the lock pins in whichever repository serves it, also past one
/// that refuses it.
#[test]
fn a_snapshot_pom_restores_from_the_repository_that_serves_its_build() {
    let older = "1.0-20240101.010101-1";
    let newer = "1.0-20240102.010101-2";
    // Per repository: the jar build and `updated`, and the POM's, if any.
    type Layout<'a> = [(&'a str, &'a str, &'a str, Option<(&'a str, &'a str)>); 2];
    let layouts: [(Layout<'_>, Option<&str>); 3] = [
        (
            [
                (
                    "a",
                    older,
                    "20240103010101",
                    Some((older, "20240101010101")),
                ),
                (
                    "b",
                    newer,
                    "20240102010101",
                    Some((newer, "20240102010101")),
                ),
            ],
            Some("20240102.010101"),
        ),
        (
            [
                ("a", older, "20240101010101", None),
                (
                    "b",
                    older,
                    "20240101010101",
                    Some((older, "20240101010101")),
                ),
            ],
            None,
        ),
        // A repository without a POM entry or `<snapshot>` offers no POM
        // build, however recent its jar.
        (
            [
                ("a", newer, "20240102010101", None),
                (
                    "b",
                    older,
                    "20240101010101",
                    Some((older, "20240101010101")),
                ),
            ],
            Some("20240101.010101"),
        ),
    ];
    // Per layout, whether a also holds other bytes at the POM's path, which
    // its metadata does not list.
    let layouts = layouts
        .into_iter()
        .zip([false, false, false])
        .chain([(layouts[2], true)]);
    // Repository b is configured, or declared only in the project POM.
    let cases = layouts.flat_map(|layout| [(layout, false), (layout, true)]);
    for (((layout, pom_build), stray), b_in_pom) in cases {
        let base = TempDir::new().expect("base");
        let mut toml = String::new();
        let mut declared = String::new();
        // One origin serves both repositories, so b passes the address
        // screen when only the project POM declares it. The jar's
        // repository a is an object store that refuses a missing key.
        let server = file_server(base.path());
        for (name, jar, jar_updated, pom) in layout {
            let repository = base.path().join(name);
            let dir = repository.join("org/test/snap/1.0-SNAPSHOT");
            fs::create_dir_all(&dir).expect("create repository");
            fs::write(dir.join(format!("snap-{jar}.jar")), format!("{name} jar")).expect("jar");
            if stray && name == "a" {
                fs::write(dir.join(format!("snap-{older}.pom")), "<project/>").expect("pom");
            }
            let entry = |extension: &str, value: &str, updated: &str| {
                format!(
                    "<snapshotVersion><extension>{extension}</extension><value>{value}</value>\
                     <updated>{updated}</updated></snapshotVersion>"
                )
            };
            let mut entries = entry("jar", jar, jar_updated);
            if let Some((pom, pom_updated)) = pom {
                fs::write(
                    dir.join(format!("snap-{pom}.pom")),
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>snap</artifactId><version>1.0-SNAPSHOT</version></project>",
                )
                .expect("pom");
                entries += &entry("pom", pom, pom_updated);
            }
            let metadata = format!(
                "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><lastUpdated>{jar_updated}\
                 </lastUpdated><snapshotVersions>{entries}</snapshotVersions></versioning>\
                 </metadata>"
            );
            fs::write(dir.join("maven-metadata.xml"), metadata).expect("metadata");
            let url = format!("http://{}/{name}/", server.addr());
            if name == "b" && b_in_pom {
                declared += &self::repository(name, &url, true, true);
            } else {
                toml += &format!(
                    "[[repositories]]\nid = \"{name}\"\nurl = \"{url}\"\nsnapshots = true\n"
                );
            }
        }
        let project = base.path().join("project");
        fs::create_dir_all(&project).expect("create project");
        fs::write(project.join("raeva.toml"), toml).expect("write raeva.toml");
        fs::write(
            project.join("pom.xml"),
            module_pom("app", false, &declared, &dependency("snap", "1.0-SNAPSHOT")),
        )
        .expect("write pom.xml");
        let home = TempDir::new().expect("home");
        assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
        match pom_build {
            Some(timestamp) => {
                let recorded =
                    format!("[platforms.artifacts.pom_snapshot]\ntimestamp = \"{timestamp}\"");
                assert!(lock.contains(&recorded), "{lock}");
            }
            None => assert!(!lock.contains("pom_snapshot"), "{lock}"),
        }

        let cold = TempDir::new().expect("cold home");
        let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
        assert_success(&frozen, "cold frozen sync");
        let verify_home = TempDir::new().expect("cold home");
        let verify = run_raeva(
            &project,
            verify_home.path(),
            &["lock", "verify", "--download"],
        );
        assert_success(&verify, "cold lock verify --download");

        // The restored home resolves offline again after a model change,
        // with the jar and POM builds the lock pins.
        let pom_xml = fs::read_to_string(project.join("pom.xml")).expect("pom.xml");
        let touched = pom_xml.replacen(
            "<dependencies>",
            "<properties><touched>1</touched></properties><dependencies>",
            1,
        );
        assert_ne!(touched, pom_xml);
        fs::write(project.join("pom.xml"), touched).expect("write pom.xml");
        let offline = run_raeva(&project, cold.path(), &["sync", "--offline"]);
        assert_success(&offline, "offline re-resolution");
        let relocked = fs::read_to_string(project.join("raeva.lock")).expect("lock");
        let rows = |lock: &str| {
            lock.lines()
                .filter(|line| line.contains("pom_sha256") || line.contains("timestamp"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(rows(&relocked), rows(&lock), "{relocked}");
    }
}

/// Metadata that lists a jar build and no POM gives the timestamped jar the
/// base `-SNAPSHOT.pom`, or no POM when the repository has none, as Maven
/// reads it; the timestamped POM is never read. The lock records the base
/// POM, and a cold restore, `lock verify --download`, an offline
/// re-resolution and `export-m2` keep to it.
#[test]
fn a_snapshot_pom_missing_from_snapshot_versions_is_the_base_pom() {
    for base_pom in [true, false] {
        let base = TempDir::new().expect("base");
        let server = file_server(base.path());
        let repository = base.path().join("s");
        publish(&repository, "right", "1");
        publish(&repository, "wrong", "1");
        let dir = repository.join("org/test/snap/1.0-SNAPSHOT");
        fs::create_dir_all(&dir).expect("create repository");
        let pom = |artifact: &str| {
            SNAP_POM.replace(
                "</project>",
                &format!(
                    "<dependencies>{}</dependencies></project>",
                    dependency(artifact, "1")
                ),
            )
        };
        fs::write(dir.join(format!("snap-{SNAPSHOT}.jar")), "snap jar").expect("jar");
        fs::write(dir.join(format!("snap-{SNAPSHOT}.pom")), pom("wrong")).expect("pom");
        if base_pom {
            fs::write(dir.join("snap-1.0-SNAPSHOT.pom"), pom("right")).expect("base pom");
        }
        fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><snapshot>\
                 <timestamp>20240101.010101</timestamp><buildNumber>1</buildNumber></snapshot>\
                 <lastUpdated>20240101010101</lastUpdated><snapshotVersions>\
                 <snapshotVersion><extension>jar</extension><value>{SNAPSHOT}</value>\
                 <updated>20240101010101</updated></snapshotVersion>\
                 </snapshotVersions></versioning></metadata>"
            ),
        )
        .expect("metadata");
        let project = base.path().join("project");
        fs::create_dir_all(&project).expect("create project");
        fs::write(
            project.join("raeva.toml"),
            format!(
                "[[repositories]]\nid = \"s\"\nurl = \"http://{}/s/\"\nsnapshots = true\n",
                server.addr()
            ),
        )
        .expect("write raeva.toml");
        fs::write(
            project.join("pom.xml"),
            module_pom("app", false, "", &dependency("snap", "1.0-SNAPSHOT")),
        )
        .expect("write pom.xml");
        let home = TempDir::new().expect("home");
        assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
        assert!(lock.contains("pom_base = true"), "{lock}");
        assert!(!lock.contains("pom_snapshot"), "{lock}");
        assert!(!lock.contains("\"wrong\""), "{lock}");
        assert_eq!(lock.contains("\"right\""), base_pom, "{lock}");
        // The snap row pins its POM only when the base POM exists, as does
        // the right row it brings.
        assert_eq!(
            lock.matches("pom_sha256").count(),
            2 * usize::from(base_pom),
            "{lock}"
        );

        let cold = TempDir::new().expect("cold home");
        let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
        assert_success(&frozen, "cold frozen sync");
        let verify_home = TempDir::new().expect("verify home");
        let verify = run_raeva(
            &project,
            verify_home.path(),
            &["lock", "verify", "--download"],
        );
        assert_success(&verify, "cold lock verify --download");

        // Offline, a POM the lock records as missing is missing rather than
        // not downloaded, in the home that read the metadata and in a cold
        // restore alike.
        let rows = |lock: &str| {
            lock.lines()
                .filter(|line| {
                    ["pom_sha256", "pom_base", "timestamp", "artifact ="]
                        .iter()
                        .any(|key| line.contains(key))
                })
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let pom_xml = fs::read_to_string(project.join("pom.xml")).expect("pom.xml");
        for (touch, offline_home) in [home.path(), cold.path()].into_iter().enumerate() {
            let touched = pom_xml.replacen(
                "<dependencies>",
                &format!("<properties><touched>{touch}</touched></properties><dependencies>"),
                1,
            );
            fs::write(project.join("pom.xml"), touched).expect("write pom.xml");
            let offline = run_raeva(&project, offline_home, &["sync", "--offline"]);
            assert_success(
                &offline,
                &format!("offline sync {touch}, base POM {base_pom}"),
            );
            let relocked = fs::read_to_string(project.join("raeva.lock")).expect("lock");
            assert_eq!(rows(&relocked), rows(&lock), "{relocked}");
        }

        // Metadata an earlier export left that names the timestamped POM
        // loses that entry.
        let m2 = base.path().join("m2");
        let exported = m2.join("org/test/snap/1.0-SNAPSHOT");
        fs::create_dir_all(&exported).expect("create m2");
        fs::write(
            exported.join("maven-metadata-s.xml"),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><snapshot>\
                 <timestamp>20240101.010101</timestamp><buildNumber>1</buildNumber></snapshot>\
                 <lastUpdated>20240101010101</lastUpdated><snapshotVersions>\
                 <snapshotVersion><extension>pom</extension><value>{SNAPSHOT}</value>\
                 <updated>20240101010101</updated></snapshotVersion>\
                 </snapshotVersions></versioning></metadata>"
            ),
        )
        .expect("earlier metadata");
        export(&project, cold.path(), &m2);
        assert!(exported.join(format!("snap-{SNAPSHOT}.jar")).is_file());
        assert!(!exported.join(format!("snap-{SNAPSHOT}.pom")).exists());
        assert_eq!(
            fs::read_to_string(exported.join("snap-1.0-SNAPSHOT.pom")).ok(),
            base_pom.then(|| pom("right"))
        );
        let metadata = fs::read_dir(&exported)
            .expect("exported directory")
            .filter_map(|entry| {
                let name = entry.ok()?.file_name().into_string().ok()?;
                name.starts_with("maven-metadata").then_some(name)
            })
            .map(|name| fs::read_to_string(exported.join(name)).expect("metadata"))
            .collect::<String>();
        assert!(metadata.contains(SNAPSHOT), "{metadata}");
        assert!(
            !metadata.contains("<extension>pom</extension>"),
            "{metadata}"
        );

        // Each JDK section records the base POM, and a cold restore under
        // either JDK keeps to it.
        let toml = fs::read_to_string(project.join("raeva.toml")).expect("raeva.toml");
        fs::write(
            project.join("raeva.toml"),
            format!("{toml}[lock]\njdks = [\"17\", \"21\"]\n"),
        )
        .expect("write raeva.toml");
        let on_jdk = |home: &Path, jdk: &str, args: &[&str]| {
            raeva_command(&project, home)
                .env("JAVA_HOME", base.path().join("no-java-home"))
                .env("JAVA_VERSION", jdk)
                .args(args)
                .output()
                .expect("run raeva")
        };
        assert_success(&on_jdk(home.path(), "17", &["sync"]), "sync with jdks");
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
        assert_eq!(
            rv_lock::Lockfile::from_toml(&lock).unwrap().platforms.len(),
            2,
            "{lock}"
        );
        assert_eq!(lock.matches("pom_base = true").count(), 1, "{lock}");
        assert!(!lock.contains("\"wrong\""), "{lock}");
        for jdk in ["17", "21"] {
            let cold = TempDir::new().expect("cold home");
            let frozen = on_jdk(cold.path(), jdk, &["sync", "--frozen"]);
            assert_success(&frozen, &format!("cold frozen sync under {jdk}"));
        }
    }
}

/// A SNAPSHOT POM from a repository only a remote parent declares: the lock
/// names that repository among the row's origins, so a cold restore and
/// `lock verify --download` trust it and fetch the pinned POM from it.
#[test]
fn a_snapshot_pom_restores_from_a_repository_a_remote_parent_declares() {
    let base = TempDir::new().expect("base");
    let root = base.path().join("repos");
    let served = root.clone();
    // One origin serves both repositories, so the parent's declaration
    // passes the address screen as its configured sibling does.
    let server = StubServer::start(move |request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        match fs::read(served.join(path.trim_start_matches('/'))) {
            Ok(bytes) if sidecar => Response::new(200, BlobId::from_bytes(&bytes).to_string()),
            Ok(bytes) => Response::new(200, bytes),
            Err(_) => Response::new(403, ""),
        }
    });
    let url = |name: &str| format!("http://{}/{name}/", server.addr());
    let build = "1.0-20240101.010101-1";
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
               <artifactId>snap</artifactId><version>1.0-SNAPSHOT</version></project>";
    for name in ["a", "b"] {
        let dir = root.join(name).join("org/test/snap/1.0-SNAPSHOT");
        fs::create_dir_all(&dir).expect("create repository");
        fs::write(dir.join(format!("snap-{build}.jar")), format!("{name} jar")).expect("jar");
        let entry = |extension: &str| {
            format!(
                "<snapshotVersion><extension>{extension}</extension><value>{build}</value>\
                 <updated>20240101010101</updated></snapshotVersion>"
            )
        };
        let mut entries = entry("jar");
        if name == "b" {
            fs::write(dir.join(format!("snap-{build}.pom")), pom).expect("pom");
            entries += &entry("pom");
        }
        fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><lastUpdated>20240101010101\
                 </lastUpdated><snapshotVersions>{entries}</snapshotVersions></versioning>\
                 </metadata>"
            ),
        )
        .expect("metadata");
    }
    let parent = root.join("a/org/test/root/1");
    fs::create_dir_all(&parent).expect("create parent");
    fs::write(
        parent.join("root-1.pom"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <repositories>{}</repositories></project>",
            repository("b", &url("b"), true, true)
        ),
    )
    .expect("parent");
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"a\"\nurl = \"{}\"\nsnapshots = true\n",
            url("a")
        ),
    )
    .expect("write raeva.toml");
    fs::write(
        project.join("pom.xml"),
        module_pom("app", true, "", &dependency("snap", "1.0-SNAPSHOT")),
    )
    .expect("write pom.xml");
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(
        !lock.contains("other_repo_urls")
            && lock.contains(&format!("pom_repo_urls = [\"{}\"]", url("b"))),
        "{lock}"
    );

    // With only the POM missing, the repair still reaches b.
    let blob = BlobId::from_bytes(pom.as_bytes()).to_string();
    let path = home
        .path()
        .join("store/blobs")
        .join(&blob[..2])
        .join(&blob[2..4])
        .join(&blob);
    fs::remove_file(&path).expect("remove the POM blob");
    let verify = run_raeva(&project, home.path(), &["lock", "verify", "--download"]);
    assert_success(&verify, "lock verify --download of the POM");
    assert!(path.is_file(), "the POM blob is restored");

    let cold = TempDir::new().expect("cold home");
    let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "cold frozen sync");
    let cold = TempDir::new().expect("cold home");
    let verify = run_raeva(&project, cold.path(), &["lock", "verify", "--download"]);
    assert_success(&verify, "cold lock verify --download");

    // A newer build in both repositories does not move a frozen check that
    // resolves again after a POM edit, on a home that never saw the sync.
    let newer = "1.0-20240202.020202-2";
    for name in ["a", "b"] {
        let dir = root.join(name).join("org/test/snap/1.0-SNAPSHOT");
        fs::write(dir.join(format!("snap-{newer}.jar")), "newer jar").expect("jar");
        let mut extensions = vec!["jar"];
        if name == "b" {
            fs::write(dir.join(format!("snap-{newer}.pom")), pom).expect("pom");
            extensions.push("pom");
        }
        let entries: String = (extensions.iter())
            .map(|extension| {
                format!(
                    "<snapshotVersion><extension>{extension}</extension><value>{newer}</value>\
                     <updated>20240202020202</updated></snapshotVersion>"
                )
            })
            .collect();
        fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><lastUpdated>20240202020202\
                 </lastUpdated><snapshotVersions>{entries}</snapshotVersions></versioning>\
                 </metadata>"
            ),
        )
        .expect("metadata");
    }
    let pom_path = project.join("pom.xml");
    let edited = fs::read_to_string(&pom_path).expect("pom") + "<!-- edited -->\n";
    fs::write(&pom_path, edited).expect("edit pom.xml");
    let cold = TempDir::new().expect("cold home");
    let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "cold frozen sync after a newer build");
    assert_eq!(
        fs::read_to_string(project.join("raeva.lock")).expect("lock"),
        lock
    );
}

/// `lock verify --download` asks each origin a SNAPSHOT POM records, so the
/// refusal of the one that served it is not hidden by the jar's miss, and
/// a refusal of the jar's repository, which never served the POM, is not
/// reported for it.
#[test]
fn a_snapshot_pom_download_reports_its_own_repository_refusal() {
    assert_snapshot_pom_download_reports("b", "returned HTTP 401");
    assert_snapshot_pom_download_reports("a", "not found");
}

fn assert_snapshot_pom_download_reports(refused: &str, expected: &str) {
    let refused = format!("/{refused}/");
    let base = TempDir::new().expect("base");
    let root = base.path().join("repos");
    let served = root.clone();
    let refuse = Arc::new(AtomicBool::new(false));
    let refusing = refuse.clone();
    let server = StubServer::start(move |request| {
        let (path, sidecar) = match request.path.strip_suffix(".sha256") {
            Some(path) => (path, true),
            None => (request.path.as_str(), false),
        };
        match fs::read(served.join(path.trim_start_matches('/'))) {
            Ok(bytes) if sidecar => Response::new(200, BlobId::from_bytes(&bytes).to_string()),
            Ok(bytes) => Response::new(200, bytes),
            Err(_) if path.starts_with(&refused) && refusing.load(Ordering::SeqCst) => {
                Response::new(401, "")
            }
            Err(_) => Response::new(404, ""),
        }
    });
    let url = |name: &str| format!("http://{}/{name}/", server.addr());
    let build = "1.0-20240101.010101-1";
    for name in ["a", "b"] {
        let dir = root.join(name).join("org/test/snap/1.0-SNAPSHOT");
        fs::create_dir_all(&dir).expect("create repository");
        fs::write(dir.join(format!("snap-{build}.jar")), format!("{name} jar")).expect("jar");
        let entry = |extension: &str| {
            format!(
                "<snapshotVersion><extension>{extension}</extension><value>{build}</value>\
                 <updated>20240101010101</updated></snapshotVersion>"
            )
        };
        let mut entries = entry("jar");
        if name == "b" {
            fs::write(dir.join(format!("snap-{build}.pom")), SNAP_POM).expect("pom");
            entries += &entry("pom");
        }
        fs::write(
            dir.join("maven-metadata.xml"),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
                 <version>1.0-SNAPSHOT</version><versioning><lastUpdated>20240101010101\
                 </lastUpdated><snapshotVersions>{entries}</snapshotVersions></versioning>\
                 </metadata>"
            ),
        )
        .expect("metadata");
    }
    let mut toml = String::new();
    for name in ["a", "b"] {
        toml += &format!(
            "[[repositories]]\nid = \"{name}\"\nurl = \"{}\"\nsnapshots = true\n",
            url(name)
        );
    }
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(project.join("raeva.toml"), toml).expect("write raeva.toml");
    fs::write(
        project.join("pom.xml"),
        module_pom("app", false, "", &dependency("snap", "1.0-SNAPSHOT")),
    )
    .expect("write pom.xml");
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(
        lock.contains(&format!("pom_repo_urls = [\"{}\"]", url("b"))),
        "{lock}"
    );

    fs::remove_file(root.join(format!("b/org/test/snap/1.0-SNAPSHOT/snap-{build}.pom")))
        .expect("remove the POM");
    refuse.store(true, Ordering::SeqCst);
    let cold = TempDir::new().expect("cold home");
    let verify = run_raeva(&project, cold.path(), &["lock", "verify", "--download"]);
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(!verify.status.success(), "{stderr}");
    assert!(stderr.contains(expected), "{stderr}");
}

/// Two modules take one SNAPSHOT jar from two repositories, and both its
/// POM from the first: the lock records where the POM came from, so a
/// frozen check that resolves again after a POM edit takes the pinned POM
/// build from there and not from the repository that has only the jar.
#[test]
fn a_frozen_check_takes_a_snapshot_pom_from_the_repository_that_served_it() {
    let base = TempDir::new().expect("base");
    let (a, b) = (base.path().join("a"), base.path().join("b"));
    let jar = format!("{SNAPSHOT}.jar");
    publish_snapshot(
        &a,
        "20240101010101",
        &[("jar", None, SNAPSHOT), ("pom", None, SNAPSHOT)],
        &[(jar.clone(), "jar"), (format!("{SNAPSHOT}.pom"), SNAP_POM)],
    );
    publish_snapshot(
        &b,
        "20240101010101",
        &[("jar", None, SNAPSHOT)],
        &[(jar, "jar")],
    );
    let root = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                <modules><module>m1</module><module>m2</module></modules></project>";
    let project = write_project(base.path(), root);
    let modules = [
        ("m1", repository("a", &file_url(&a), false, true)),
        (
            "m2",
            repository("b", &file_url(&b), false, true)
                + &repository("a", &file_url(&a), false, true),
        ),
    ];
    for (name, repositories) in &modules {
        fs::create_dir_all(project.join(name)).expect("create module");
        fs::write(
            project.join(name).join("pom.xml"),
            module_pom(
                name,
                true,
                repositories,
                &dependency("snap", "1.0-SNAPSHOT"),
            ),
        )
        .expect("write module pom");
    }
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(lock.contains("other_repo_urls = ["), "{lock}");

    let pom = project.join("pom.xml");
    fs::write(&pom, format!("{root}<!-- edited -->\n")).expect("edit pom.xml");
    for args in [
        &["sync", "--frozen"][..],
        &["sync", "--frozen", "--offline"],
    ] {
        assert_success(
            &run_raeva(&project, home.path(), args),
            &format!("{args:?}"),
        );
        assert_eq!(
            fs::read_to_string(project.join("raeva.lock")).expect("lock"),
            lock
        );
    }
    let cold = TempDir::new().expect("cold home");
    assert_success(
        &run_raeva(&project, cold.path(), &["sync", "--frozen"]),
        "cold frozen",
    );

    // A newer build in both, the old files kept, moves neither module.
    let newer = "1.0-20240202.020202-2";
    let jar = format!("{newer}.jar");
    publish_snapshot(
        &a,
        "20240202020202",
        &[("jar", None, newer), ("pom", None, newer)],
        &[
            (jar.clone(), "newer jar"),
            (format!("{newer}.pom"), SNAP_POM),
        ],
    );
    publish_snapshot(
        &b,
        "20240202020202",
        &[("jar", None, newer)],
        &[(jar, "newer jar")],
    );
    let cold = TempDir::new().expect("cold home");
    assert_success(
        &run_raeva(&project, cold.path(), &["sync", "--frozen"]),
        "cold frozen after a newer build",
    );
    assert_eq!(
        fs::read_to_string(project.join("raeva.lock")).expect("lock"),
        lock
    );
}

/// One repository serves a SNAPSHOT jar to one module, another serves it to
/// both and serves both their POMs: newer builds in both, the old files
/// kept, move neither module's jar or POM.
#[test]
fn a_frozen_check_keeps_snapshot_builds_from_overlapping_origins() {
    let base = TempDir::new().expect("base");
    let (a, b) = (base.path().join("a"), base.path().join("b"));
    let publish = |newer: &str, updated: &str, jar_bytes: &'static str| {
        let jar = format!("{newer}.jar");
        publish_snapshot(
            &a,
            updated,
            &[("jar", None, newer)],
            &[(jar.clone(), jar_bytes)],
        );
        publish_snapshot(
            &b,
            updated,
            &[("jar", None, newer), ("pom", None, newer)],
            &[(jar, jar_bytes), (format!("{newer}.pom"), SNAP_POM)],
        );
    };
    publish(SNAPSHOT, "20240101010101", "jar");
    let root = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                <modules><module>m1</module><module>m2</module></modules></project>";
    let project = write_project(base.path(), root);
    let modules = [
        (
            "m1",
            repository("a", &file_url(&a), false, true)
                + &repository("b", &file_url(&b), false, true),
        ),
        ("m2", repository("b", &file_url(&b), false, true)),
    ];
    for (name, repositories) in &modules {
        fs::create_dir_all(project.join(name)).expect("create module");
        fs::write(
            project.join(name).join("pom.xml"),
            module_pom(
                name,
                true,
                repositories,
                &dependency("snap", "1.0-SNAPSHOT"),
            ),
        )
        .expect("write module pom");
    }
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(lock.contains("pom_repo_urls = ["), "{lock}");

    publish("1.0-20240202.020202-2", "20240202020202", "newer jar");
    let pom = project.join("pom.xml");
    fs::write(&pom, format!("{root}<!-- edited -->\n")).expect("edit pom.xml");
    let cold = TempDir::new().expect("cold home");
    assert_success(
        &run_raeva(&project, cold.path(), &["sync", "--frozen"]),
        "cold frozen after newer builds",
    );
    assert_eq!(
        fs::read_to_string(project.join("raeva.lock")).expect("lock"),
        lock
    );
}

/// A plain `-SNAPSHOT` jar in one repository and its POM in another: the
/// lock records the POM's origin, reads back, and passes a frozen check.
#[test]
fn a_non_unique_snapshot_pom_from_another_repository_round_trips() {
    let base = TempDir::new().expect("base");
    let project = write_project(
        base.path(),
        &module_pom(
            "app",
            false,
            &(repository("a", "file://${project.basedir}/a/", false, true)
                + &repository("b", "file://${project.basedir}/b/", false, true)),
            &dependency("snap", "1.0-SNAPSHOT"),
        ),
    );
    for (repository, name, bytes) in [("a", "jar", "jar"), ("b", "pom", SNAP_POM)] {
        let dir = project.join(repository).join("org/test/snap/1.0-SNAPSHOT");
        fs::create_dir_all(&dir).expect("create repository");
        fs::write(dir.join(format!("snap-1.0-SNAPSHOT.{name}")), bytes).expect("write file");
    }
    let home = TempDir::new().expect("home");
    assert_success(
        &run_raeva(&project, home.path(), &["sync", "--offline"]),
        "sync",
    );
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(lock.contains("pom_repo_urls = [\"./b/\"]"), "{lock}");
    let pom = project.join("pom.xml");
    let edited = fs::read_to_string(&pom).expect("pom") + "<!-- edited -->\n";
    fs::write(&pom, edited).expect("edit pom.xml");
    for args in [
        &["sync", "--frozen", "--offline"][..],
        &["sync", "--frozen"],
    ] {
        assert_success(
            &run_raeva(&project, home.path(), args),
            &format!("{args:?}"),
        );
        assert_eq!(
            fs::read_to_string(project.join("raeva.lock")).expect("lock"),
            lock
        );
    }

    // Timestamped builds published later leave the plain files locked.
    let newer = "1.0-20240202.020202-2";
    publish_snapshot(
        &project.join("a"),
        "20240202020202",
        &[("jar", None, newer)],
        &[(format!("{newer}.jar"), "newer jar")],
    );
    publish_snapshot(
        &project.join("b"),
        "20240202020202",
        &[("pom", None, newer)],
        &[(format!("{newer}.pom"), SNAP_POM)],
    );
    for args in [
        &["sync", "--frozen", "--offline"][..],
        &["sync", "--frozen"],
    ] {
        assert_success(
            &run_raeva(&project, home.path(), args),
            &format!("{args:?} after timestamped builds"),
        );
        assert_eq!(
            fs::read_to_string(project.join("raeva.lock")).expect("lock"),
            lock
        );
    }
}

/// The path that wins mediation read a release POM from a repository
/// another path cannot see; the losing path's miss keeps the winner's
/// origin, so the lock still names the repository that served the POM.
#[test]
fn a_losing_path_without_the_pom_keeps_its_origin() {
    let base = TempDir::new().expect("base");
    let (main, r) = (base.path().join("main"), base.path().join("r"));
    let write = |repository: &Path, path: &str, text: &str| {
        let file = repository.join("org/test").join(path);
        fs::create_dir_all(file.parent().unwrap()).expect("create repository");
        fs::write(file, text).expect("write file");
    };
    let declaring = |artifact: &str, repositories: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version>\
             <repositories>{repositories}</repositories>\
             <dependencies>{}</dependencies></project>",
            dependency("x", "1.0")
        )
    };
    // A dependency POM may not declare a file: repository.
    let server = file_server(base.path());
    let r_url = format!("http://{}/r/", server.addr());
    let only_r = repository("r", &r_url, true, false);
    write(&main, "a/1.0/a-1.0.pom", &declaring("a", &only_r));
    write(&main, "b/1.0/b-1.0.pom", &declaring("b", ""));
    for artifact in ["a", "b", "x"] {
        write(
            &main,
            &format!("{artifact}/1.0/{artifact}-1.0.jar"),
            artifact,
        );
    }
    write(
        &r,
        "x/1.0/x-1.0.pom",
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>x</artifactId><version>1.0</version></project>",
    );
    let project = write_project(
        base.path(),
        &module_pom(
            "app",
            false,
            &repository("main", &file_url(&main), true, false),
            &(dependency("a", "1.0") + &dependency("b", "1.0")),
        ),
    );
    // Central is main too, so the path that cannot see r asks no network.
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"central\"\nurl = \"{}\"\n",
            file_url(&main)
        ),
    )
    .expect("write raeva.toml");
    let home = TempDir::new().expect("home");
    fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .expect("config.toml");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(
        lock.contains(&format!("pom_repo_urls = [\"{r_url}\"]")),
        "{lock}"
    );
}

/// A release POM from one repository and its jar from another, as camel
/// reads jakarta.jms-api's POM from a stub repository and its jar from
/// Central: the lock records the POM's origin and a cold frozen check
/// fetches it there. Other bytes fail the pin check; without a lock, modules
/// that read different bytes fail naming the repository that served each.
#[test]
fn a_release_pom_from_another_repository_is_named_as_its_origin() {
    let base = TempDir::new().expect("base");
    let (a, b) = (base.path().join("a"), base.path().join("b"));
    publish(&a, "lib", "1.0");
    let stub = b.join("org/test/lib/1.0");
    fs::create_dir_all(&stub).expect("create repository");
    fs::write(
        stub.join("lib-1.0.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>lib</artifactId><version>1.0</version><name>stub</name></project>",
    )
    .expect("write stub pom");
    let both =
        repository("b", &file_url(&b), true, false) + &repository("a", &file_url(&a), true, false);
    let project = write_project(
        base.path(),
        &module_pom("app", false, &both, &dependency("lib", "1.0")),
    );
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(
        lock.contains(&format!(
            "pom_repo_urls = [\"{}\"]",
            crate::common::recorded_origin(&project, &file_url(&b))
        )),
        "{lock}"
    );
    let cold = TempDir::new().expect("cold home");
    assert_success(
        &run_raeva(&project, cold.path(), &["sync", "--frozen"]),
        "cold frozen",
    );

    let root = "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
                <modules><module>m1</module><module>m2</module></modules></project>";
    fs::write(project.join("pom.xml"), root).expect("write root");
    for (name, repositories) in [
        ("m1", both.clone()),
        ("m2", repository("a", &file_url(&a), true, false)),
    ] {
        fs::create_dir_all(project.join(name)).expect("create module");
        fs::write(
            project.join(name).join("pom.xml"),
            module_pom(name, true, &repositories, &dependency("lib", "1.0")),
        )
        .expect("write module pom");
    }
    let output = run_raeva(&project, home.path(), &["sync"]);
    assert_eq!(output.status.code(), Some(7), "pinned POM bytes");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("checksum mismatch") && stderr.contains(&file_url(&a)),
        "{stderr}"
    );
    fs::remove_file(project.join("raeva.lock")).expect("remove lock");
    let output = run_raeva(&project, home.path(), &["sync"]);
    assert_eq!(output.status.code(), Some(5), "conflicting POM bytes");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("m1/pom.xml from {}", file_url(&b)))
            && stderr.contains(&format!("m2/pom.xml from {}", file_url(&a))),
        "{stderr}"
    );
}

/// An active profile's repository under the id of one the POM declares
/// replaces it, for the parent lookup too: the superseded URL is never asked.
#[test]
fn a_profile_repository_replaces_the_one_its_pom_declares_under_its_id() {
    let base = TempDir::new().expect("base");
    let old = StubServer::start(|_| Response::new(404, ""));
    let new = base.path().join("new");
    let parent = new.join("org/test/root/1");
    fs::create_dir_all(&parent).expect("create parent");
    fs::write(
        parent.join("root-1.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging></project>",
    )
    .expect("parent");
    publish(&new, "lib", "1");
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version></parent><artifactId>app</artifactId>\
         <repositories>{}</repositories><profiles><profile><id>moved</id><activation>\
         <activeByDefault>true</activeByDefault></activation><repositories>{}</repositories>\
         </profile></profiles><dependencies>{}</dependencies></project>",
        repository("corp", &format!("http://{}/", old.addr()), true, false),
        repository("corp", &file_url(&new), true, false),
        dependency("lib", "1"),
    );
    let project = write_project(base.path(), &pom);
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    assert!(old.requests().is_empty(), "{:?}", old.requests().len());
}

/// As Maven's artifact resolver does, a SNAPSHOT build's jar is asked only
/// of the repository whose metadata named the build: when it lacks the jar,
/// another repository's file of the same name does not stand in.
#[test]
fn a_snapshot_jar_comes_only_from_the_repository_that_names_its_build() {
    let build = "1.0-20240102.010101-2";
    let entries = [("jar", None, build), ("pom", None, build)];
    for winner_has_jar in [false, true] {
        let base = TempDir::new().expect("base");
        let mut files = vec![(format!("{build}.pom"), SNAP_POM)];
        if winner_has_jar {
            files.push((format!("{build}.jar"), "a jar"));
        }
        publish_snapshot(&base.path().join("a"), "20240103010101", &entries, &files);
        files.truncate(1);
        files.push((format!("{build}.jar"), "b jar"));
        publish_snapshot(&base.path().join("b"), "20240102010101", &entries, &files);
        let server = file_server(base.path());
        let toml: String = ["a", "b"]
            .map(|name| {
                format!(
                    "[[repositories]]\nid = \"{name}\"\nurl = \"http://{}/{name}/\"\n\
                     snapshots = true\n",
                    server.addr()
                )
            })
            .concat();
        let project = base.path().join("project");
        fs::create_dir_all(&project).expect("create project");
        fs::write(project.join("raeva.toml"), toml).expect("write raeva.toml");
        fs::write(
            project.join("pom.xml"),
            module_pom("app", false, "", &dependency("snap", "1.0-SNAPSHOT")),
        )
        .expect("write pom.xml");
        let home = TempDir::new().expect("home");
        let output = run_raeva(&project, home.path(), &["sync"]);
        let asked_b = server.requests().iter().any(|request| {
            request
                .path
                .starts_with(&format!("/b/org/test/snap/1.0-SNAPSHOT/snap-{build}.jar"))
        });
        assert!(!asked_b, "the jar was asked of b");
        if winner_has_jar {
            assert_success(&output, "sync");
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
            let digest = BlobId::from_bytes(b"a jar").to_string();
            assert!(lock.contains(&digest), "{lock}");
        } else {
            assert!(
                !output.status.success(),
                "sync took another repository's build"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("org.test:snap"), "{stderr}");
        }
    }
}

/// Maven narrows a SNAPSHOT's jar to the repository whose metadata named the
/// build, but asks for the timestamped POM by its build string, which every
/// repository may serve: it reads the POM from the first one that does, here
/// one with older metadata, also when the winner has another POM or none.
#[test]
fn a_snapshot_pom_comes_from_the_first_repository_that_serves_its_build() {
    let build = "1.0-20240102.010101-2";
    let entries = [("jar", None, build), ("pom", None, build)];
    let first_pom = SNAP_POM.replace("</project>", "<description>a</description></project>");
    let winner_pom = SNAP_POM.replace("</project>", "<description>b</description></project>");
    for winner_has_pom in [true, false] {
        let base = TempDir::new().expect("base");
        let files = [(format!("{build}.pom"), first_pom.as_str())];
        publish_snapshot(&base.path().join("a"), "20240101010101", &entries, &files);
        let mut files = vec![(format!("{build}.jar"), "b jar")];
        if winner_has_pom {
            files.push((format!("{build}.pom"), winner_pom.as_str()));
        }
        publish_snapshot(&base.path().join("b"), "20240102010101", &entries, &files);
        let server = file_server(base.path());
        let toml: String = ["a", "b"]
            .map(|name| {
                format!(
                    "[[repositories]]\nid = \"{name}\"\nurl = \"http://{}/{name}/\"\n\
                     snapshots = true\n",
                    server.addr()
                )
            })
            .concat();
        let project = base.path().join("project");
        fs::create_dir_all(&project).expect("create project");
        fs::write(project.join("raeva.toml"), toml).expect("write raeva.toml");
        fs::write(
            project.join("pom.xml"),
            module_pom("app", false, "", &dependency("snap", "1.0-SNAPSHOT")),
        )
        .expect("write pom.xml");
        let home = TempDir::new().expect("home");
        assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
        let asked_b = server.requests().iter().any(|request| {
            (request.path).starts_with(&format!("/b/org/test/snap/1.0-SNAPSHOT/snap-{build}.pom"))
        });
        assert!(!asked_b, "the POM was asked of b");
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
        let pinned = |bytes: &str| lock.contains(&BlobId::from_bytes(bytes.as_bytes()).to_string());
        assert!(pinned(&first_pom), "{lock}");
        assert!(!pinned(&winner_pom), "{lock}");
        assert!(pinned("b jar"), "{lock}");

        let cold = TempDir::new().expect("cold home");
        let frozen = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
        assert_success(&frozen, "cold frozen sync");
    }
}

/// One URL declared under two ids is two repositories: a mirror of one id
/// serves its newer build, so that build's jar comes through the mirror and
/// not from the URL the other id reaches directly, and so does its POM,
/// which the direct URL lacks.
#[test]
fn a_snapshot_build_comes_through_the_mirror_of_the_id_that_names_it() {
    let older = "1.0-20240101.010101-1";
    let newer = "1.0-20240102.010101-2";
    let base = TempDir::new().expect("base");
    let direct = [("jar", None, older), ("pom", None, older)];
    // The direct URL also holds a stale copy of the newer build's jar.
    publish_snapshot(
        &base.path().join("x"),
        "20240101010101",
        &direct,
        &[
            (format!("{older}.pom"), SNAP_POM),
            (format!("{older}.jar"), "old jar"),
            (format!("{newer}.jar"), "stale jar"),
        ],
    );
    let mirrored = [("jar", None, newer), ("pom", None, newer)];
    publish_snapshot(
        &base.path().join("m"),
        "20240102010101",
        &mirrored,
        &[
            (format!("{newer}.pom"), SNAP_POM),
            (format!("{newer}.jar"), "mirror jar"),
        ],
    );
    let server = file_server(base.path());
    let url = format!("http://{}/x/", server.addr());
    let toml = format!(
        "[[repositories]]\nid = \"direct\"\nurl = \"{url}\"\nsnapshots = true\n\
         [[repositories]]\nid = \"mirrored\"\nurl = \"{url}\"\nsnapshots = true\n"
    );
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(project.join("raeva.toml"), toml).expect("write raeva.toml");
    fs::write(
        project.join("pom.xml"),
        module_pom("app", false, "", &dependency("snap", "1.0-SNAPSHOT")),
    )
    .expect("write pom.xml");
    let home = TempDir::new().expect("home");
    fs::write(
        home.path().join("config.toml"),
        format!(
            "[[mirrors]]\nid = \"m\"\nurl = \"http://{}/m/\"\nmirror_of = [\"mirrored\"]\n",
            server.addr()
        ),
    )
    .expect("write config.toml");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    for bytes in [SNAP_POM.as_bytes(), b"mirror jar"] {
        let digest = BlobId::from_bytes(bytes).to_string();
        assert!(lock.contains(&digest), "{lock}");
    }
    let stale = server.requests().iter().any(|request| {
        request
            .path
            .starts_with(&format!("/x/org/test/snap/1.0-SNAPSHOT/snap-{newer}.jar"))
    });
    assert!(!stale, "the newer jar was asked of the direct URL");
}

/// A classified jar can pin another build than the main jar of its
/// version. Offline, each file keeps the build its own row pins.
#[test]
fn a_classified_snapshot_keeps_its_own_build_offline() {
    let older = "1.0-20240101.010101-1";
    let newer = "1.0-20240102.010101-2";
    let base = TempDir::new().expect("base");
    publish_snapshot(
        &base.path().join("r"),
        "20240102010101",
        &[
            ("pom", None, older),
            ("jar", None, older),
            ("jar", Some("linux"), newer),
        ],
        &[
            (format!("{older}.pom"), SNAP_POM),
            (format!("{older}.jar"), "main jar"),
            (format!("{newer}-linux.jar"), "linux jar"),
        ],
    );
    let server = file_server(base.path());
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"r\"\nurl = \"http://{}/r/\"\nsnapshots = true\n",
            server.addr()
        ),
    )
    .expect("write raeva.toml");
    let linux = "<dependency><groupId>org.test</groupId><artifactId>snap</artifactId>\
                 <version>1.0-SNAPSHOT</version><classifier>linux</classifier></dependency>";
    let dependencies = dependency("snap", "1.0-SNAPSHOT") + linux;
    fs::write(
        project.join("pom.xml"),
        module_pom("app", false, "", &dependencies),
    )
    .expect("write pom.xml");
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    for bytes in [b"main jar".as_slice(), b"linux jar"] {
        let digest = BlobId::from_bytes(bytes).to_string();
        assert!(lock.contains(&digest), "{lock}");
    }

    let cold = TempDir::new().expect("cold home");
    assert_success(
        &run_raeva(&project, cold.path(), &["sync", "--frozen"]),
        "cold frozen sync",
    );
    let pom_xml = fs::read_to_string(project.join("pom.xml")).expect("pom.xml");
    let touched = pom_xml.replacen(
        "<dependencies>",
        "<properties><touched>1</touched></properties><dependencies>",
        1,
    );
    fs::write(project.join("pom.xml"), touched).expect("write pom.xml");
    assert_success(
        &run_raeva(&project, cold.path(), &["sync", "--offline"]),
        "offline re-resolution",
    );
    let relocked = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert_eq!(
        pinned_digests(&relocked),
        pinned_digests(&lock),
        "{relocked}"
    );
}

/// A `maven-metadata.xml` in `repository` that lists `org.test:lib:1`, which
/// the range `[1,2)` takes.
fn list_lib(repository: &Path) {
    fs::write(
        repository.join("org/test/lib/maven-metadata.xml"),
        "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId>\
         <versioning><versions><version>1</version></versions></versioning></metadata>",
    )
    .expect("write the listing");
}

/// The versions a `maven-metadata-*.xml` lists, or `None` without one.
fn listed(m2: &Path, artifact: &str, id: &str) -> Option<Vec<String>> {
    let path = m2.join(format!("org/test/{artifact}/maven-metadata-{id}.xml"));
    let text = fs::read_to_string(path).ok()?;
    Some(
        (text.split("<version>").skip(1))
            .map(|rest| rest.split('<').next().expect("version").to_string())
            .collect(),
    )
}

/// Maven labels a file with the id of the settings.xml mirror it came
/// through, but `mvn -o` without that mirror reads the declared id. The
/// export labels the file under both, and lists the version a range took
/// there under both.
#[test]
fn a_mirrored_file_is_labelled_with_the_mirror_and_the_declared_id() {
    let base = TempDir::new().expect("base");
    let (direct, mirror) = (base.path().join("direct"), base.path().join("mirror"));
    publish(&direct, "lib", "1");
    publish(&mirror, "lib", "1");
    list_lib(&direct);
    list_lib(&mirror);
    let pom = module_pom(
        "app",
        false,
        &repository("corp", &file_url(&direct), true, false),
        &dependency("lib", "[1,2)"),
    );
    let project = write_project(base.path(), &pom);
    let home = TempDir::new().expect("home");
    fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>corp-mirror</id><mirrorOf>corp</mirrorOf>\
             <url>{}</url></mirror></mirrors></settings>",
            file_url(&mirror)
        ),
    )
    .expect("write settings.xml");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let m2 = base.path().join("m2");
    export(&project, home.path(), &m2);

    let lib = markers(&m2, "lib", "1");
    for id in ["corp", "corp-mirror"] {
        assert!(lib.contains(&format!("lib-1.jar>{id}=")), "{lib}");
        assert!(lib.contains(&format!("lib-1.pom>{id}=")), "{lib}");
        assert_eq!(listed(&m2, "lib", id), Some(vec!["1".to_string()]), "{id}");
    }
}

/// A repository that only a settings.xml profile active on another locked
/// platform declares serves that platform's files through a `*` mirror.
/// The export trusts it as the freshness check did, and labels the files
/// with its id.
#[test]
fn a_settings_profile_repository_of_another_platform_is_exported() {
    let base = TempDir::new().expect("base");
    let mirror = base.path().join("mirror");
    publish(&mirror, "lib", "1");
    publish(&mirror, "other", "1");
    fs::write(
        mirror.join("org/test/other/1/other-1-sources.jar"),
        "sources",
    )
    .unwrap();
    let host = rv_lock::Platform::current().expect("host platform");
    let (other, family) = if host.os() == "windows" {
        ("linux-x86_64", "unix")
    } else {
        ("windows-x86_64", "windows")
    };
    let activation = format!("<activation><os><family>{family}</family></os></activation>");
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(
        project.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version>\
             <dependencies>{}</dependencies><profiles><profile><id>p</id>{activation}\
             <dependencies>{}</dependencies></profile></profiles></project>",
            dependency("lib", "1"),
            dependency("other", "1"),
        ),
    )
    .expect("write pom.xml");
    let home = TempDir::new().expect("home");
    fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>all</id><mirrorOf>*</mirrorOf><url>{}</url>\
             </mirror></mirrors><profiles><profile><id>s</id>{activation}<repositories>\
             <repository><id>platform-repo</id><url>{}</url></repository></repositories>\
             </profile></profiles></settings>",
            file_url(&mirror),
            file_url(&base.path().join("platform-repo")),
        ),
    )
    .expect("write settings.xml");
    let platforms = format!("{},{other}", host.os_arch());
    let sync = run_raeva(&project, home.path(), &["sync", "--platforms", &platforms]);
    assert_success(&sync, "sync");
    let m2 = base.path().join("m2");
    let export = [
        "export-m2",
        "--with-sources",
        "--m2-path",
        m2.to_str().unwrap(),
    ];
    let output = run_raeva(&project, home.path(), &export);
    assert_success(&output, "export");
    assert!(
        !stderr(&output).contains("UNTRUSTED"),
        "{}",
        stderr(&output)
    );

    let other = markers(&m2, "other", "1");
    for id in ["all", "platform-repo"] {
        assert!(other.contains(&format!("other-1.jar>{id}=")), "{other}");
    }
    assert!(m2.join("org/test/other/1/other-1-sources.jar").is_file());
}

/// One URL that the settings profiles of two platforms declare under their
/// own ids, each id with its own mirror: a classifier jar of a dependency
/// only the host's platform takes comes through the host's mirror, as its
/// build reads it, not through the one the other platform's id names.
#[test]
fn a_classifier_jar_comes_through_its_own_platforms_mirror() {
    let base = TempDir::new().expect("base");
    let (own, foreign) = (base.path().join("own"), base.path().join("foreign"));
    for (mirror, sources) in [(&own, "own sources"), (&foreign, "foreign sources")] {
        publish(mirror, "lib", "1");
        fs::write(mirror.join("org/test/lib/1/lib-1-sources.jar"), sources).unwrap();
    }
    let host = rv_lock::Platform::current().expect("host platform");
    let (other, host_family, other_family) = if host.os() == "windows" {
        ("linux-x86_64", "windows", "unix")
    } else {
        ("windows-x86_64", "unix", "windows")
    };
    let activation =
        |family: &str| format!("<activation><os><family>{family}</family></os></activation>");
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(
        project.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><profiles><profile><id>p</id>\
             {}<dependencies>{}</dependencies></profile></profiles></project>",
            activation(host_family),
            dependency("lib", "1"),
        ),
    )
    .expect("write pom.xml");
    let url = "https://repo.corp.invalid/maven/";
    let profile = |id: &str, family: &str| {
        format!(
            "<profile><id>{id}</id>{}<repositories><repository><id>{id}</id><url>{url}</url>\
             </repository></repositories></profile>",
            activation(family)
        )
    };
    let mirror = |id: &str, dir: &Path| {
        format!(
            "<mirror><id>{id}-mirror</id><mirrorOf>{id}</mirrorOf><url>{}</url></mirror>",
            file_url(dir)
        )
    };
    let home = TempDir::new().expect("home");
    fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors>{}{}</mirrors><profiles>{}{}</profiles></settings>",
            mirror("own", &own),
            mirror("foreign", &foreign),
            profile("own", host_family),
            profile("foreign", other_family),
        ),
    )
    .expect("write settings.xml");
    let platforms = format!("{},{other}", host.os_arch());
    let sync = run_raeva(&project, home.path(), &["sync", "--platforms", &platforms]);
    assert_success(&sync, "sync");
    let m2 = base.path().join("m2");
    let export = [
        "export-m2",
        "--with-sources",
        "--m2-path",
        m2.to_str().unwrap(),
    ];
    assert_success(&run_raeva(&project, home.path(), &export), "export");
    assert_eq!(
        fs::read_to_string(m2.join("org/test/lib/1/lib-1-sources.jar")).unwrap(),
        "own sources"
    );
}

/// One repository id that the settings profiles of two platforms declare at
/// two URLs, both behind a `*` mirror: each platform's files come from its
/// own URL, and the export takes both, as the freshness check did, though
/// the merged configuration keeps one URL for the id.
#[test]
fn one_id_at_each_platforms_own_url_exports_through_a_mirror() {
    let base = TempDir::new().expect("base");
    let mirror = base.path().join("mirror");
    publish(&mirror, "host-native", "1");
    publish(&mirror, "other-native", "1");
    let host = rv_lock::Platform::current().expect("host platform");
    let (other, host_family, other_family) = if host.os() == "windows" {
        ("linux-x86_64", "windows", "unix")
    } else {
        ("windows-x86_64", "unix", "windows")
    };
    let activation =
        |family: &str| format!("<activation><os><family>{family}</family></os></activation>");
    let pom_profile = |id: &str, family: &str, artifact: &str| {
        format!(
            "<profile><id>{id}</id>{}<dependencies>{}</dependencies></profile>",
            activation(family),
            dependency(artifact, "1")
        )
    };
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(
        project.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><profiles>{}{}</profiles>\
             </project>",
            pom_profile("host", host_family, "host-native"),
            pom_profile("other", other_family, "other-native"),
        ),
    )
    .expect("write pom.xml");
    let profile = |id: &str, family: &str| {
        format!(
            "<profile><id>{id}</id>{}<repositories><repository><id>corp</id>\
             <url>https://{family}.corp.invalid/m2/</url></repository></repositories>\
             </profile>",
            activation(family)
        )
    };
    let home = TempDir::new().expect("home");
    fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>all</id><mirrorOf>*</mirrorOf><url>{}</url>\
             </mirror></mirrors><profiles>{}{}</profiles></settings>",
            file_url(&mirror),
            profile("h", host_family),
            profile("o", other_family),
        ),
    )
    .expect("write settings.xml");
    let platforms = format!("{},{other}", host.os_arch());
    let sync = run_raeva(&project, home.path(), &["sync", "--platforms", &platforms]);
    assert_success(&sync, "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("read raeva.lock");
    for family in [host_family, other_family] {
        assert!(
            lock.contains(&format!("https://{family}.corp.invalid/m2/")),
            "{lock}"
        );
    }
    let m2 = base.path().join("m2");
    export(&project, home.path(), &m2);
    for artifact in ["host-native", "other-native"] {
        let labels = markers(&m2, artifact, "1");
        for id in ["all", "corp"] {
            assert!(
                labels.contains(&format!("{artifact}-1.jar>{id}=")),
                "{labels}"
            );
        }
    }
}

/// An origin raeva.lock records no id for is labelled `central`, and a
/// repository id a reactor POM's profile declares gets an empty list, as
/// `mvn -P` with that profile reads it, with the POM's properties and
/// coordinates interpolated. Both the label and an id the export cannot write a list
/// under are reported.
#[test]
fn unrecorded_and_unusable_repository_ids_are_reported() {
    let base = TempDir::new().expect("base");
    let repository_dir = base.path().join("repository");
    publish(&repository_dir, "lib", "1");
    list_lib(&repository_dir);
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nurl = \"{}\"\n",
            file_url(&repository_dir)
        ),
    )
    .expect("write raeva.toml");
    let profiles = format!(
        "<profiles><profile><id>extra</id><properties><named.id>named</named.id></properties>\
         <repositories>{}{}{}{}</repositories></profile></profiles>",
        repository("extra", "https://extra.invalid/", true, true),
        repository("${extra.id}", "https://extra.invalid/", true, true),
        repository("${named.id}", "https://extra.invalid/", true, true),
        repository(
            "${project.artifactId}-repo",
            "https://extra.invalid/",
            true,
            true
        ),
    );
    let pom = module_pom("app", false, "", &dependency("lib", "[1,2)"))
        .replace("</project>", &format!("{profiles}</project>"));
    fs::write(project.join("pom.xml"), pom).expect("write pom.xml");
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let m2 = base.path().join("m2");
    let output = run_raeva(
        &project,
        home.path(),
        &["--json", "export-m2", "--m2-path", m2.to_str().unwrap()],
    );
    assert_success(&output, "export");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let context = |code: &str| {
        (envelope["data"]["warnings"]
            .as_array()
            .expect("warnings")
            .iter())
        .find(|warning| warning["code"] == code)
        .unwrap_or_else(|| panic!("{code}: {envelope}"))["context"]
            .clone()
    };
    assert_eq!(
        context("EXPORT_REPOSITORY_ID_GUESSED")["origins"],
        crate::common::recorded_origin(&project, &file_url(&repository_dir))
    );
    assert_eq!(
        context("EXPORT_REPOSITORY_ID_UNUSABLE")["ids"],
        "${extra.id}"
    );

    let lib = markers(&m2, "lib", "1");
    assert!(lib.contains("lib-1.jar>central="), "{lib}");
    assert_eq!(listed(&m2, "lib", "central"), Some(vec!["1".to_string()]));
    for id in ["extra", "named", "app-repo"] {
        assert_eq!(listed(&m2, "lib", id), Some(Vec::new()), "{id}");
    }
}

/// `mvn -P` may also activate a profile of a parent outside the reactor:
/// a remote parent, here pinned through a parent version range, or a
/// parent on disk that is no module. The export writes empty lists under
/// the ids their repositories and plugin repositories declare, read in the
/// reactor POM's model as Maven reads them: a profile's property beats its
/// POM's and loses to a POM below it, and `project.*`, `pom.*` and the
/// unprefixed coordinates name the reactor POM.
#[test]
fn the_profiles_of_parents_outside_the_reactor_get_lists() {
    let base = TempDir::new().expect("base");
    let repository_dir = base.path().join("repository");
    publish(&repository_dir, "lib", "1");
    list_lib(&repository_dir);
    let corp = repository_dir.join("org/test/corp-parent/1");
    fs::create_dir_all(&corp).expect("create corp-parent");
    let plugin_repositories = |ids: &[&str]| {
        let repositories: String = (ids.iter())
            .map(|id| {
                format!("<pluginRepository><id>{id}</id><url>https://extra.invalid/</url></pluginRepository>")
            })
            .collect();
        format!("<pluginRepositories>{repositories}</pluginRepositories>")
    };
    let profile = |id: &str, properties: &str, repositories: &[&str], plugins: &[&str]| {
        let repositories: String = (repositories.iter())
            .map(|id| repository(id, "https://extra.invalid/", true, true))
            .collect();
        format!(
            "<profiles><profile><id>{id}</id><properties>{properties}</properties>\
             <repositories>{repositories}</repositories>{}</profile></profiles>",
            plugin_repositories(plugins)
        )
    };
    fs::write(
        corp.join("corp-parent-1.pom"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>corp-parent</artifactId><version>1</version><packaging>pom</packaging>\
             <properties><corp.id>corp-props</corp.id><site.id>parent</site.id></properties>{}</project>",
            profile(
                "corp",
                "<corp.id>corp-profile</corp.id><site.id>profile</site.id><over.id>profile</over.id>",
                &[
                    "corp-snapshots",
                    "${corp.id}",
                    "${project.artifactId}-corp",
                    "${site.id}-site",
                    "${over.id}-over",
                    "${pom.artifactId}-pom",
                    "${artifactId}-plain",
                ],
                &["corp-plugins"],
            )
        ),
    )
    .expect("write corp-parent");
    fs::write(
        repository_dir.join("org/test/corp-parent/maven-metadata.xml"),
        "<metadata><groupId>org.test</groupId><artifactId>corp-parent</artifactId>\
         <versioning><versions><version>1</version></versions></versioning></metadata>",
    )
    .expect("write corp-parent listing");
    let project = base.path().join("project");
    fs::create_dir_all(project.join("parent")).expect("create project");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"corp-repo\"\nurl = \"{}\"\n",
            file_url(&repository_dir)
        ),
    )
    .expect("write raeva.toml");
    fs::write(
        project.join("parent/pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
             <parent><groupId>org.test</groupId><artifactId>corp-parent</artifactId>\
             <version>[1,2)</version><relativePath/></parent>\
             <artifactId>local-parent</artifactId><version>1</version><packaging>pom</packaging>\
             <properties><over.id>local</over.id></properties>{}</project>",
            profile("local", "", &["local-extra"], &[])
        ),
    )
    .expect("write local parent");
    fs::write(
        project.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion>\
             <parent><groupId>org.test</groupId><artifactId>local-parent</artifactId>\
             <version>1</version><relativePath>parent/pom.xml</relativePath></parent>\
             <artifactId>app</artifactId><properties><site.id>child</site.id></properties>{}\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             <version>[1,2)</version></dependency></dependencies></project>",
            plugin_repositories(&["app-plugins"])
        ),
    )
    .expect("write pom.xml");
    let home = TempDir::new().expect("home");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let m2 = base.path().join("m2");
    export(&project, home.path(), &m2);

    assert_eq!(listed(&m2, "lib", "corp-repo"), Some(vec!["1".to_string()]));
    for id in [
        "corp-snapshots",
        "corp-profile",
        "app-corp",
        "child-site",
        "local-over",
        "app-pom",
        "app-plain",
        "corp-plugins",
        "app-plugins",
        "local-extra",
    ] {
        assert_eq!(listed(&m2, "lib", id), Some(Vec::new()), "{id}");
    }
    for id in ["corp-props", "parent-site", "profile-site", "profile-over"] {
        assert_eq!(listed(&m2, "lib", id), None, "{id}");
    }
}

/// A non-unique `-SNAPSHOT` replaced in place stays as stored, its POM with
/// its jar, as Maven keeps both whatever the update policy, until
/// `--update` fetches both again: the lock never pairs the new POM with the
/// old jar.
#[test]
fn a_snapshot_replaced_in_place_keeps_its_jar_and_pom_until_update() {
    let base = TempDir::new().expect("base");
    let server = file_server(base.path());
    let dir = base.path().join("s/org/test/snap/1.0-SNAPSHOT");
    fs::create_dir_all(&dir).expect("create repository");
    fs::write(
        dir.join("maven-metadata.xml"),
        "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
         <version>1.0-SNAPSHOT</version><versioning><snapshot><localCopy>true</localCopy>\
         </snapshot><lastUpdated>20240101010101</lastUpdated></versioning></metadata>",
    )
    .expect("metadata");
    let publish = |build: &str| {
        let pom = SNAP_POM.replace("</project>", &format!("<name>{build}</name></project>"));
        fs::write(dir.join("snap-1.0-SNAPSHOT.pom"), pom).expect("pom");
        fs::write(dir.join("snap-1.0-SNAPSHOT.jar"), build).expect("jar");
    };
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"s\"\nurl = \"http://{}/s/\"\nsnapshots = true\n\
             snapshots-update-policy = \"always\"\n",
            server.addr()
        ),
    )
    .expect("write raeva.toml");
    fs::write(
        project.join("pom.xml"),
        module_pom("app", false, "", &dependency("snap", "1.0-SNAPSHOT")),
    )
    .expect("write pom.xml");
    let home = TempDir::new().expect("home");
    publish("first");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let first = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(
        first.contains(BlobId::from_bytes(b"first").as_str()),
        "{first}"
    );
    publish("second");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
    let kept = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert_eq!(kept, first);
    let update = run_raeva(&project, home.path(), &["sync", "--update"]);
    assert_success(&update, "sync --update");
    let updated = fs::read_to_string(project.join("raeva.lock")).expect("lock");
    assert!(
        updated.contains(BlobId::from_bytes(b"second").as_str()),
        "{updated}"
    );
    assert_eq!(pinned_digests(&updated).len(), pinned_digests(&first).len());
    assert!(
        !updated.contains(BlobId::from_bytes(b"first").as_str()),
        "{updated}"
    );
}

/// A non-unique `-SNAPSHOT` replaced in place whose POM the metadata cache
/// no longer holds pairs the POM it reads with the jar of the same build,
/// whether raeva.lock pins the old POM or there is no lock, so a clean
/// machine resolves the lock again.
#[test]
fn a_snapshot_replaced_in_place_pairs_its_pom_and_jar_without_the_metadata_cache() {
    let base = TempDir::new().expect("base");
    let server = file_server(base.path());
    let dir = base.path().join("s/org/test/snap/1.0-SNAPSHOT");
    fs::create_dir_all(&dir).expect("create repository");
    fs::write(
        dir.join("maven-metadata.xml"),
        "<metadata><groupId>org.test</groupId><artifactId>snap</artifactId>\
         <version>1.0-SNAPSHOT</version><versioning><snapshot><localCopy>true</localCopy>\
         </snapshot><lastUpdated>20240101010101</lastUpdated></versioning></metadata>",
    )
    .expect("metadata");
    let pom =
        |build: &str| SNAP_POM.replace("</project>", &format!("<name>{build}</name></project>"));
    let publish = |build: &str| {
        fs::write(dir.join("snap-1.0-SNAPSHOT.pom"), pom(build)).expect("pom");
        fs::write(dir.join("snap-1.0-SNAPSHOT.jar"), build).expect("jar");
    };
    // The build whose POM and jar the lock pins, never one's POM with
    // another's jar.
    let build = |lock: &str| {
        let pins = |build: &str| {
            let pom = BlobId::from_bytes(pom(build).as_bytes());
            let jar = BlobId::from_bytes(build.as_bytes());
            (lock.contains(pom.as_str()), lock.contains(jar.as_str()))
        };
        match (pins("first"), pins("second")) {
            ((true, true), (false, false)) => "first",
            ((false, false), (true, true)) => "second",
            pins => panic!("{pins:?}: {lock}"),
        }
    };
    let project = base.path().join("project");
    fs::create_dir_all(&project).expect("create project");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"s\"\nurl = \"http://{}/s/\"\nsnapshots = true\n\
             snapshots-update-policy = \"always\"\n",
            server.addr()
        ),
    )
    .expect("write raeva.toml");
    fs::write(
        project.join("pom.xml"),
        module_pom("app", false, "", &dependency("snap", "1.0-SNAPSHOT")),
    )
    .expect("write pom.xml");
    let forget_metadata = |home: &Path| {
        for entry in fs::read_dir(home).expect("home") {
            let path = entry.expect("entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with("metadata.db") {
                fs::remove_file(path).expect("remove metadata.db");
            }
        }
    };
    for keep_lock in [true, false] {
        let home = TempDir::new().expect("home");
        let _ = fs::remove_file(project.join("raeva.lock"));
        publish("first");
        assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
        let first = fs::read_to_string(project.join("raeva.lock")).expect("lock");
        assert_eq!(build(&first), "first");
        publish("second");
        forget_metadata(home.path());
        if !keep_lock {
            fs::remove_file(project.join("raeva.lock")).expect("remove lock");
        }
        assert_success(&run_raeva(&project, home.path(), &["sync"]), "sync");
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("lock");
        build(&lock);
        let clean = TempDir::new().expect("clean home");
        let frozen = run_raeva(&project, clean.path(), &["sync", "--frozen"]);
        assert_success(
            &frozen,
            &format!("frozen on a clean home, lock kept {keep_lock}"),
        );
    }
}

/// Writes the version list of `org.test:{artifact}` into `repository`, its
/// last version as `<release>`, updated at `stamp`.
fn publish_listing(repository: &Path, artifact: &str, versions: &[&str], stamp: &str) {
    let dir = repository.join(format!("org/test/{artifact}"));
    fs::create_dir_all(&dir).expect("create repository");
    let release = versions.last().expect("a version");
    let versions: String = (versions.iter())
        .map(|version| format!("<version>{version}</version>"))
        .collect();
    let metadata = format!(
        "<metadata><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
         <versioning><release>{release}</release><versions>{versions}</versions>\
         <lastUpdated>{stamp}</lastUpdated></versioning></metadata>"
    );
    fs::write(dir.join("maven-metadata.xml"), metadata).expect("write metadata");
}

/// A reactor whose module `a` declares id `r` at `u1` and module `b` at
/// `u2`, listed in `order`, each depending on `org.test:lib:{version}` when
/// it reads it.
fn same_id_project(
    base: &Path,
    name: &str,
    order: [&str; 2],
    version: &str,
    b_reads: bool,
) -> PathBuf {
    let project = base.join(name);
    let empty = base.join("empty");
    fs::create_dir_all(&empty).expect("create empty repository");
    let modules: String = (order.iter())
        .map(|module| format!("<module>{module}</module>"))
        .collect();
    let root = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
         <modules>{modules}</modules></project>"
    );
    fs::create_dir_all(&project).expect("create project");
    fs::write(project.join("pom.xml"), root).expect("write pom.xml");
    fs::write(
        project.join("raeva.toml"),
        format!(
            "[[repositories]]\nid = \"empty\"\nurl = \"{}\"\n",
            file_url(&empty)
        ),
    )
    .expect("write raeva.toml");
    for (module, url, reads) in [("a", "u1", true), ("b", "u2", b_reads)] {
        let repositories = repository("r", &file_url(&base.join(url)), true, false);
        let dependencies = if reads {
            dependency("lib", version)
        } else {
            String::new()
        };
        fs::create_dir_all(project.join(module)).expect("create module");
        fs::write(
            project.join(module).join("pom.xml"),
            module_pom(module, true, &repositories, &dependencies),
        )
        .expect("write module pom");
    }
    project
}

/// Writes `u1` listing `org.test:lib` `u1_versions` updated at `u1_stamp`,
/// and `u2` listing 1 and 2 updated at `20240101000000`.
fn publish_same_id(base: &Path, u1_versions: &[&str], u1_stamp: &str) {
    let (u1, u2) = (base.join("u1"), base.join("u2"));
    for version in ["1", "2"] {
        publish(&u1, "lib", version);
        publish(&u2, "lib", version);
    }
    publish_listing(&u1, "lib", u1_versions, u1_stamp);
    publish_listing(&u2, "lib", &["1", "2"], "20240101000000");
}

const STAMP: &str = "20240101000000";

/// Maven keeps one version list per repository id, which the module it
/// reads first fixes for the others, whatever their own URL. With one id
/// at two URLs whose lists a range or `RELEASE` takes differently, raeva
/// cannot lock Maven's choice, so it refuses with the same message in
/// either reactor order.
#[test]
fn one_id_listing_other_versions_at_two_urls_is_refused() {
    let base = TempDir::new().expect("base");
    publish_same_id(base.path(), &["1"], STAMP);
    for version in ["[1,3)", "RELEASE"] {
        let mut errors = Vec::new();
        for (name, order) in [("ab", ["a", "b"]), ("ba", ["b", "a"])] {
            let name = format!("{name}-{}", version.len());
            let project = same_id_project(base.path(), &name, order, version, true);
            let home = TempDir::new().expect("home");
            let output = run_raeva(&project, home.path(), &["sync"]);
            assert_eq!(output.status.code(), Some(5), "{output:?}");
            assert!(!project.join("raeva.lock").exists(), "{name} wrote a lock");
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            for expected in [
                "repository id r",
                "org.test:lib",
                &file_url(&base.path().join("u1")),
                &file_url(&base.path().join("u2")),
                "distinct ids",
            ] {
                assert!(stderr.contains(expected), "{expected}: {stderr}");
            }
            errors.push(stderr);
        }
        assert_eq!(errors[0], errors[1]);
    }
}

/// Maven records a 404 for the version list under the repository id, so
/// the module that reads the id first fixes the list for the other whether
/// its URL answered 404 or listed versions. With `u1` answering 404 and
/// `u2` listing 1 and 2, raeva refuses as for an empty list at `u1`, in
/// either reactor order and Maven line, where it locked `a` on 1 and `b` on
/// 2, a pair no Maven build resolves. A reactor whose second module reads
/// no list still syncs.
#[test]
fn one_id_without_a_listing_at_one_url_is_refused() {
    for maven in ["3.9", "3.10"] {
        for (name, order, b_reads) in [
            ("ab", ["a", "b"], true),
            ("ba", ["b", "a"], true),
            ("one-reader", ["a", "b"], false),
        ] {
            let base = TempDir::new().expect("base");
            let u2 = base.path().join("u2");
            for version in ["1", "2"] {
                publish(&u2, "lib", version);
            }
            publish_listing(&u2, "lib", &["1", "2"], STAMP);
            fs::create_dir_all(base.path().join("u1")).expect("create u1");
            let empty = base.path().join("empty");
            publish(&empty, "lib", "1");
            publish_listing(&empty, "lib", &["1"], STAMP);
            let project = same_id_project(base.path(), name, order, "[1,3)", b_reads);
            let config = project.join("raeva.toml");
            let text = fs::read_to_string(&config).expect("read raeva.toml");
            fs::write(&config, format!("[lock]\nmaven = \"{maven}\"\n\n{text}"))
                .expect("write raeva.toml");
            let home = TempDir::new().expect("home");
            let output = run_raeva(&project, home.path(), &["sync"]);
            let what = format!("{maven} {name}");
            if !b_reads {
                assert_success(&output, &what);
                continue;
            }
            assert_eq!(output.status.code(), Some(5), "{what}: {output:?}");
            assert!(!project.join("raeva.lock").exists(), "{what} wrote a lock");
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            for expected in [
                "repository id r",
                "org.test:lib",
                &file_url(&base.path().join("u1")),
                &file_url(&u2),
            ] {
                assert!(stderr.contains(expected), "{what}: {expected}: {stderr}");
            }
        }
    }
}

/// The same reactor syncs when both URLs list the same versions, also
/// updated at other times for a range or a lone `RELEASE`, which pick by no
/// `lastUpdated`; when only one module reads the list; and when a mirror
/// serves both declarations from one URL.
#[test]
fn one_id_at_two_urls_syncs_when_maven_reads_one_list() {
    let later = "20250101000000";
    for (name, u1, stamp, version, b_reads, mirror) in [
        ("equal", &["1", "2"][..], STAMP, "[1,3)", true, false),
        ("range-stamp", &["1", "2"], later, "[1,3)", true, false),
        ("release-stamp", &["1", "2"], later, "RELEASE", true, false),
        ("one-reader", &["1"], STAMP, "[1,3)", false, false),
        ("mirrored", &["1"], STAMP, "[1,3)", true, true),
    ] {
        let base = TempDir::new().expect("base");
        publish_same_id(base.path(), u1, stamp);
        let project = same_id_project(base.path(), "project", ["a", "b"], version, b_reads);
        let home = TempDir::new().expect("home");
        if mirror {
            fs::write(
                home.path().join("config.toml"),
                format!(
                    "[[mirrors]]\nid = \"m\"\nurl = \"{}\"\nmirror_of = [\"r\"]\n",
                    file_url(&base.path().join("u2"))
                ),
            )
            .expect("write config.toml");
        }
        assert_success(&run_raeva(&project, home.path(), &["sync"]), name);
    }
}

/// A repository whose own URL does not parse, which a settings.xml mirror
/// serves, resolves through the mirror, as in Maven 3.9 and 3.10. raeva.lock
/// records no origin for its files, neither that URL nor the mirror's, and
/// the export labels them with the mirror's id and the repository's.
#[test]
fn a_mirrored_repository_whose_url_does_not_parse_resolves_through_the_mirror() {
    let base = TempDir::new().expect("tempdir");
    let served = base.path().join("served");
    publish(&served, "lpar", "1");
    publish(&served, "lib", "1.0");
    fs::write(
        served.join("org/test/lib/1.0/lib-1.0.pom"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
         <artifactId>lpar</artifactId><version>1</version></parent>\
         <artifactId>lib</artifactId><version>1.0</version></project>",
    )
    .expect("write lib pom");
    // `split`'s POM comes from the mirror, its jar from `good`, which has
    // another POM.
    let good = base.path().join("good");
    publish(&good, "split", "1.0");
    fs::write(good.join("org/test/split/1.0/split-1.0.pom"), "<project/>").expect("pom");
    let split = served.join("org/test/split/1.0");
    fs::create_dir_all(&split).expect("create split");
    fs::write(
        split.join("split-1.0.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>split</artifactId><version>1.0</version></project>",
    )
    .expect("write split pom");
    let server = file_server(&served);
    let good_server = file_server(&good);
    let pom = module_pom(
        "app",
        false,
        &(repository("bad", "http://[::1", true, false)
            + &repository(
                "good",
                &format!("http://{}/", good_server.addr()),
                true,
                false,
            )),
        &(dependency("lib", "1.0") + &dependency("split", "1.0")),
    );
    let project = write_project(base.path(), &pom);
    let mirror = format!("http://{}/", server.addr());
    let settings = format!(
        "<settings><mirrors><mirror><id>mm</id><mirrorOf>bad</mirrorOf><url>{mirror}</url>\
         </mirror></mirrors></settings>"
    );
    let homes: Vec<TempDir> = (0..3).map(|_| TempDir::new().expect("home")).collect();
    for home in &homes {
        fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
        fs::write(home.path().join(".m2/settings.xml"), &settings).expect("write settings");
    }

    let output = run_raeva(&project, homes[0].path(), &["sync"]);
    assert_success(&output, "sync");
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
    assert!(!lock.contains("[::1") && !lock.contains(&mirror), "{lock}");
    assert!(
        lock.contains("pom_repo_urls") && lock.contains("lpar"),
        "{lock}"
    );
    assert!(!stderr(&output).contains("[::1"), "{}", stderr(&output));
    let output = run_raeva(&project, homes[0].path(), &["sync"]);
    assert_success(&output, "second sync");
    let again = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
    assert_eq!(again, lock);

    let output = run_raeva(&project, homes[1].path(), &["sync", "--frozen"]);
    assert_success(&output, "cold frozen sync");
    let m2 = base.path().join("m2");
    export(&project, homes[1].path(), &m2);
    let markers = markers(&m2, "lib", "1.0");
    for line in ["lib-1.0.jar>mm=", "lib-1.0.jar>bad=", "lib-1.0.pom>mm="] {
        assert!(markers.contains(line), "{markers}");
    }
    let split = self::markers(&m2, "split", "1.0");
    assert!(
        split.contains("split-1.0.pom>mm=") && split.contains("split-1.0.jar>good="),
        "{split}"
    );
    let output = run_raeva(&project, homes[2].path(), &["lock", "verify", "--download"]);
    assert_success(&output, "lock verify --download");
}

/// Two repositories whose URLs do not parse that mirrors serve, which the
/// empty origin raeva.lock records could not tell apart, are refused (exit
/// 3), never shown, for a file and for a version list read through them.
#[test]
fn what_the_lock_cannot_record_of_an_unparsable_mirrored_repository_is_refused() {
    let base = TempDir::new().expect("tempdir");
    let served = base.path().join("served");
    publish(&served, "lib", "1.0");
    fs::write(
        served.join("org/test/lib/maven-metadata.xml"),
        "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
         <versions><version>1.0</version></versions></versioning></metadata>",
    )
    .expect("write metadata");
    let server = file_server(&served);
    let mirror = format!("http://{}/", server.addr());
    for (repositories, version, refusal) in [
        (
            repository("bad", "http://[::1", true, false)
                + &repository("bad2", "http://[::2", true, false),
            "1.0",
            "several repositories whose URLs do not parse or have a scheme raeva cannot fetch",
        ),
        (
            repository("bad", "http://[::1", true, false)
                + &repository("bad2", "./x/", true, false),
            "[1.0,2.0)",
            "several repositories whose URLs do not parse",
        ),
        (
            repository("bad", "ftp://host/x/", true, false)
                + &repository("bad2", "http://[::1", true, false),
            "[1.0,2.0)",
            "several repositories whose URLs do not parse or have a scheme raeva cannot fetch",
        ),
    ] {
        let case = TempDir::new_in(base.path()).expect("case");
        let pom = module_pom("app", false, &repositories, &dependency("lib", version));
        let project = write_project(case.path(), &pom);
        let home = TempDir::new().expect("home");
        fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>mm</id><mirrorOf>bad,bad2</mirrorOf>\
                 <url>{mirror}</url></mirror></mirrors></settings>"
            ),
        )
        .expect("write settings");
        let output = run_raeva(&project, home.path(), &["sync"]);
        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(3), "{version}: {text}");
        assert!(text.contains(refusal) && !text.contains("[::"), "{text}");
        assert!(!project.join("raeva.lock").exists(), "{version}");
        // The configuration is at fault, and there is no lockfile.
        let output = run_raeva(&project, home.path(), &["--json", "sync"]);
        let json = String::from_utf8_lossy(&output.stdout);
        let envelope: serde_json::Value = serde_json::from_str(&json).expect("sync JSON");
        assert_eq!(envelope["code"], "REPOSITORY_CONFIG", "{json}");
        assert!(!json.contains("invalid lockfile"), "{json}");
    }
}

/// A range read through a repository whose URL raeva.lock cannot record,
/// which a settings.xml mirror serves, resolves as in Maven 3.9.12 and
/// 3.10.0, and its range_versions and evicted_ranges lines record the empty
/// origin, as the rows do. A cold `--frozen`, a seed restored into a fresh
/// home and an offline `--frozen` there, and export-m2's version lists all
/// take that origin for the mirror's route. An `external:*,!central` mirror
/// serves a `symlink+file:` URL in both modes: 3.9 has no transport for it,
/// and 3.10 reads it as a directory, which the lock records.
#[test]
fn a_range_through_a_mirrored_repository_url_raeva_cannot_record_locks() {
    let base = TempDir::new().expect("tempdir");
    let served = base.path().join("served");
    publish(&served, "lib", "1.0");
    publish(&served, "lib2", "1.0");
    publish(&served, "lib2", "1.5");
    let listing = |artifact: &str, versions: &[&str]| {
        let versions: String = versions
            .iter()
            .map(|v| format!("<version>{v}</version>"))
            .collect();
        fs::write(
            served.join(format!("org/test/{artifact}/maven-metadata.xml")),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
                 <versioning><versions>{versions}</versions></versioning></metadata>"
            ),
        )
        .expect("write metadata");
    };
    listing("lib", &["1.0"]);
    listing("lib2", &["1.0", "1.5"]);
    // mid's range on lib2 loses to the project's own lib2 1.0.
    let mid = served.join("org/test/mid/1");
    fs::create_dir_all(&mid).expect("mid");
    fs::write(
        mid.join("mid-1.pom"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>mid</artifactId><version>1</version><dependencies>{}</dependencies>\
             </project>",
            dependency("lib2", "[1.0,2.0)")
        ),
    )
    .expect("mid pom");
    fs::write(mid.join("mid-1.jar"), "mid bytes").expect("mid jar");
    let server = file_server(&served);
    let settings = |mirror_of: &str| {
        format!(
            "<settings><mirrors><mirror><id>mm</id><mirrorOf>{mirror_of}</mirrorOf>\
             <url>http://{}/</url></mirror></mirrors></settings>",
            server.addr()
        )
    };
    let dependencies =
        dependency("lib", "[1.0,2.0)") + &dependency("lib2", "1.0") + &dependency("mid", "1");
    let linked = format!(
        "symlink+{}",
        url::Url::from_directory_path(base.path().join("elsewhere")).unwrap()
    );
    // Maven 3.10 reads a URL without a scheme as a directory under the
    // project, which raeva.lock records.
    let cases = [
        ("http://[::1", "3.9", "bad"),
        ("http://[::1", "3.10", "bad"),
        ("ftp://host/x/", "3.9", "bad"),
        ("ftp://host/x/", "3.10", "bad"),
        ("./x/", "3.9", "bad"),
        ("http://[::1", "3.9", "external:*,!central"),
        (&linked, "3.9", "external:*,!central"),
        (&linked, "3.10", "external:*,!central"),
    ];
    for (url, maven, mirror_of) in cases {
        let case = format!("{url} {maven} {mirror_of}");
        let dir = TempDir::new_in(base.path()).expect("case");
        let pom = module_pom(
            "app",
            false,
            &repository("bad", url, true, false),
            &dependencies,
        );
        let project = write_project(dir.path(), &pom);
        let toml = fs::read_to_string(project.join("raeva.toml")).expect("raeva.toml");
        fs::write(
            project.join("raeva.toml"),
            format!("{toml}\n[lock]\nmaven = \"{maven}\"\n"),
        )
        .expect("raeva.toml");
        let homes: Vec<TempDir> = (0..3).map(|_| TempDir::new().expect("home")).collect();
        for home in &homes {
            fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
            fs::write(home.path().join(".m2/settings.xml"), settings(mirror_of)).expect("settings");
        }
        assert_success(&run_raeva(&project, homes[0].path(), &["sync"]), &case);
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
        let read = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("lock");
        let origin = &read.platforms[0].artifacts[0].repo_url;
        let recorded = url == linked && maven == "3.10";
        assert_eq!(origin.is_empty(), !recorded, "{case}: {lock}");
        assert!(
            lock.contains(&format!(
                "range_versions = \"org.test:lib\\t1.0\\t{origin}\""
            )),
            "{case}: {lock}"
        );
        assert!(
            lock.contains(&format!(
                "evicted_ranges = \"org.test:lib2\\t[1.0,2.0)\\t{origin}\\t1.0 1.5\""
            )),
            "{case}: {lock}"
        );
        assert!(!lock.contains(url.trim_end_matches('/')), "{case}: {lock}");
        let output = run_raeva(&project, homes[1].path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{case} cold frozen"));
        let seed = dir.path().join("seed");
        let seed = seed.to_str().unwrap();
        assert_success(
            &run_raeva(&project, homes[1].path(), &["seed", "save", seed]),
            &case,
        );
        let output = run_raeva(&project, homes[2].path(), &["seed", "restore", seed]);
        assert_success(&output, &format!("{case} seed restore"));
        let output = run_raeva(
            &project,
            homes[2].path(),
            &["--offline", "sync", "--frozen"],
        );
        assert_success(&output, &format!("{case} offline frozen from the seed"));
        let m2 = dir.path().join("m2");
        let output = run_raeva(
            &project,
            homes[0].path(),
            &["export-m2", "--m2-path", m2.to_str().unwrap()],
        );
        assert_success(&output, &format!("{case} export"));
        for (artifact, version) in [("lib", "1.0"), ("lib2", "1.0")] {
            let lists =
                fs::read_to_string(m2.join(format!("org/test/{artifact}/maven-metadata-mm.xml")))
                    .expect("the mirror's list");
            assert!(
                lists.contains(&format!("<version>{version}</version>")),
                "{case}: {lists}"
            );
        }
    }
}

/// A file only the mirror of a repository whose URL raeva.lock cannot record
/// served, recorded with the empty origin, serves every reader as through a
/// URL it records: `seed save`, a fresh home's `--frozen` after a newer
/// SNAPSHOT build is deployed, an offline `sbom` without the metadata cache,
/// `export-m2 --plan-json`, which lists it without a url, and the sources jar
/// `--with-sources` adds.
#[test]
fn the_empty_origin_names_the_mirror_route_for_every_reader() {
    let base = TempDir::new().expect("tempdir");
    let served = base.path().join("served");
    publish(&served, "lib", "1.0");
    fs::write(
        served.join("org/test/lib/1.0/lib-1.0-sources.jar"),
        "sources",
    )
    .expect("sources");
    publish(&served, "snap", "1.0-SNAPSHOT");
    let server = file_server(&served);
    let settings = format!(
        "<settings><mirrors><mirror><id>mm</id><mirrorOf>rel</mirrorOf>\
         <url>http://{}/</url></mirror></mirrors></settings>",
        server.addr()
    );
    let dependencies = dependency("lib", "1.0") + &dependency("snap", "1.0-SNAPSHOT");
    for maven in ["3.9", "3.10"] {
        let dir = TempDir::new_in(base.path()).expect("case");
        let repositories = repository("rel", "ftp://placeholder/", true, true);
        let pom = module_pom("app", false, &repositories, &dependencies);
        let project = write_project(dir.path(), &pom);
        let toml = fs::read_to_string(project.join("raeva.toml")).expect("raeva.toml");
        fs::write(
            project.join("raeva.toml"),
            format!("{toml}\n[lock]\nmaven = \"{maven}\"\n"),
        )
        .expect("raeva.toml");
        let homes: Vec<TempDir> = (0..2).map(|_| TempDir::new().expect("home")).collect();
        for home in &homes {
            fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
            fs::write(home.path().join(".m2/settings.xml"), &settings).expect("settings");
        }
        let home = homes[0].path();
        assert_success(&run_raeva(&project, home, &["sync"]), maven);
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
        assert!(lock.contains("repo_url = \"\""), "{maven}: {lock}");
        let seed = dir.path().join("seed");
        let output = run_raeva(&project, home, &["seed", "save", seed.to_str().unwrap()]);
        assert_success(&output, &format!("{maven} seed save"));
        let plan = run_raeva(&project, home, &["export-m2", "--plan-json"]);
        assert_success(&plan, &format!("{maven} plan"));
        let plan: serde_json::Value = serde_json::from_slice(&plan.stdout).expect("plan");
        let files = plan["files"].as_array().expect("files");
        assert!(
            !files.is_empty() && files.iter().all(|file| file.get("url").is_none()),
            "{plan}"
        );
        let m2 = dir.path().join("m2");
        let output = run_raeva(
            &project,
            home,
            &[
                "export-m2",
                "--with-sources",
                "--m2-path",
                m2.to_str().unwrap(),
            ],
        );
        assert_success(&output, &format!("{maven} sources"));
        assert!(
            m2.join("org/test/lib/1.0/lib-1.0-sources.jar").is_file(),
            "{maven}"
        );
        // Offline, without the metadata cache, from the store alone.
        for name in ["metadata.db", "metadata.db-wal", "metadata.db-shm"] {
            let _ = fs::remove_file(home.join(name));
        }
        let output = run_raeva(&project, home, &["--offline", "sbom"]);
        assert_success(&output, &format!("{maven} offline sbom"));
        // A fresh home's frozen check keeps the locked SNAPSHOT build.
        let snap = served.join("org/test/snap/1.0-SNAPSHOT");
        let metadata = fs::read_to_string(snap.join("maven-metadata.xml")).expect("metadata");
        let newer = "1.0-20240102.010101-2";
        for extension in ["pom", "jar"] {
            let first = fs::read(snap.join(format!("snap-{SNAPSHOT}.{extension}"))).expect("build");
            fs::write(snap.join(format!("snap-{newer}.{extension}")), first).expect("newer build");
        }
        let updated = metadata
            .replace(SNAPSHOT, newer)
            .replace("20240101.010101", "20240102.010101")
            .replace("<buildNumber>1<", "<buildNumber>2<")
            .replace("20240101010101", "20240102010101");
        fs::write(snap.join("maven-metadata.xml"), updated).expect("newer metadata");
        let output = run_raeva(&project, homes[1].path(), &["sync", "--frozen"]);
        assert_success(
            &output,
            &format!("{maven} fresh frozen after a newer build"),
        );
        let after = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
        assert_eq!(after, lock, "{maven}");
        fs::write(snap.join("maven-metadata.xml"), metadata).expect("restore metadata");
    }
}

/// A POM repository whose URL is a relative path, which a settings.xml
/// mirror serves, resolves through the mirror as Maven 3.9.12 and 3.10.0
/// do, and a cold `--frozen` restores it. Maven 3.9.12 reads no directory
/// for the URL, so raeva.lock records the empty origin for it; Maven 3.10.0
/// reads the directory relative to the project, which raeva.lock records
/// relative to it.
#[test]
fn a_mirrored_repository_with_a_relative_url_restores() {
    let base = TempDir::new().expect("tempdir");
    let served = base.path().join("served");
    publish(&served, "lib", "1.0");
    let server = file_server(&served);
    let settings = format!(
        "<settings><mirrors><mirror><id>mm</id><mirrorOf>rel</mirrorOf>\
         <url>http://{}/</url></mirror></mirrors></settings>",
        server.addr()
    );
    let cases = ["./x/", "./x", "x/", "../x/"].into_iter();
    for (url, maven) in cases.flat_map(|url| [(url, "3.9"), (url, "3.10")]) {
        let case = TempDir::new_in(base.path()).expect("case");
        let pom = module_pom(
            "app",
            false,
            &repository("rel", url, true, false),
            &dependency("lib", "1.0"),
        );
        let project = write_project(case.path(), &pom);
        let toml = fs::read_to_string(project.join("raeva.toml")).expect("raeva.toml");
        let toml = format!("{toml}\n[lock]\nmaven = \"{maven}\"\n");
        fs::write(project.join("raeva.toml"), toml).expect("raeva.toml");
        let homes: Vec<TempDir> = (0..2).map(|_| TempDir::new().expect("home")).collect();
        for home in &homes {
            fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
            fs::write(home.path().join(".m2/settings.xml"), &settings).expect("settings");
        }
        let output = run_raeva(&project, homes[0].path(), &["sync"]);
        assert_success(&output, &format!("{url} {maven}"));
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
        let origin = match (maven, url) {
            ("3.9", _) => String::new(),
            (_, "../x/") => url.to_string(),
            _ => "./x/".to_string(),
        };
        let recorded = format!("repo_url = \"{origin}\"");
        assert!(lock.contains(&recorded), "{url} {maven}: {lock}");
        let output = run_raeva(&project, homes[1].path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{url} {maven} cold frozen"));
    }
}

/// The warning on metadata Maven 3.10 reads as empty does not show the URL
/// of a repository that does not parse, which a mirror serves.
#[test]
fn a_metadata_warning_hides_a_mirrored_url_that_does_not_parse() {
    let base = TempDir::new().expect("tempdir");
    let served = base.path().join("served");
    publish(&served, "lib", "1.0");
    fs::write(
        served.join("org/test/lib/maven-metadata.xml"),
        "<metadata><groupId>org.test</groupId><artifactId>lib</artifactId><versioning>\
         <versions><version>1.0</version><version>..</version></versions></versioning>\
         </metadata>",
    )
    .expect("write metadata");
    let server = file_server(&served);
    let pom = module_pom(
        "app",
        false,
        &repository("bad", "https://[hostsentinel", true, false),
        &dependency("lib", "[1.0,2.0)"),
    );
    let project = write_project(base.path(), &pom);
    let toml = fs::read_to_string(project.join("raeva.toml")).expect("raeva.toml");
    fs::write(
        project.join("raeva.toml"),
        format!("{toml}\n[lock]\nmaven = \"3.10\"\n"),
    )
    .expect("raeva.toml");
    let home = TempDir::new().expect("home");
    fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>mm</id><mirrorOf>bad</mirrorOf>\
             <url>http://{}/</url></mirror></mirrors></settings>",
            server.addr()
        ),
    )
    .expect("write settings");
    let output = run_raeva(&project, home.path(), &["--json", "-v", "sync"]);
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert!(shown.contains("invalid version token"), "{shown}");
    assert!(!shown.contains("hostsentinel"), "{shown}");
}

/// Writes the POM `org.test:{artifact}:1.0` holding `body` into `repository`.
fn publish_pom(repository: &Path, artifact: &str, body: &str) {
    let dir = repository.join(format!("org/test/{artifact}/1.0"));
    fs::create_dir_all(&dir).expect("create repository");
    fs::write(
        dir.join(format!("{artifact}-1.0.pom")),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version>\
             <packaging>pom</packaging>{body}</project>"
        ),
    )
    .expect("write pom");
}

/// A home whose settings.xml sends Central to `central` and the
/// repositories `mirror_of` names to `mirror`.
fn mirror_home(central: &StubServer, mirror_of: &str, mirror: &StubServer) -> TempDir {
    let home = TempDir::new().expect("home");
    fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>cm</id><mirrorOf>central</mirrorOf>\
             <url>http://{}/</url></mirror><mirror><id>m</id><mirrorOf>{mirror_of}</mirrorOf>\
             <url>http://{}/</url></mirror></mirrors></settings>",
            central.addr(),
            mirror.addr()
        ),
    )
    .expect("write settings");
    home
}

/// A project in `dir` built as Maven `maven` builds it, from `pom`.
fn maven_project(dir: &Path, maven: &str, pom: &str) -> PathBuf {
    fs::create_dir_all(dir).expect("create project");
    fs::write(dir.join("pom.xml"), pom).expect("write pom.xml");
    fs::write(
        dir.join("raeva.toml"),
        format!("[lock]\nmaven = \"{maven}\"\n"),
    )
    .expect("write raeva.toml");
    dir.to_path_buf()
}

/// Maven 3.9.12 and 3.10.0 look the parent up in the POM's repositories as
/// written, so a repository whose URL holds an expression is served there
/// by a mirror that matches it, by id or as `external:*` matches a URL
/// without a scheme. Central's other parent of those coordinates, which
/// declares `evil`, is never read, and with no other parent the build
/// still finds it. A property the POM sets makes the URL the lock records.
#[test]
fn a_mirrored_repository_whose_url_holds_an_expression_serves_the_parent() {
    let base = TempDir::new().expect("tempdir");
    let corp = base.path().join("corp");
    publish_pom(&corp, "parent", "");
    publish(&corp, "lib", "1.0");
    let central = base.path().join("central");
    publish_pom(
        &central,
        "parent",
        &format!("<dependencies>{}</dependencies>", dependency("evil", "1.0")),
    );
    publish(&central, "evil", "1.0");
    publish(&central, "lib", "1.0");
    let bare = base.path().join("bare");
    publish(&bare, "lib", "1.0");
    let corp_server = file_server(&corp);
    let central_server = file_server(&central);
    let bare_server = file_server(&bare);
    let pom = |url: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>parent</artifactId><version>1.0</version><relativePath/></parent>\
             <artifactId>app</artifactId><properties><corp.url>http://corp.invalid\
             </corp.url></properties><repositories>{}</repositories><dependencies>{}\
             </dependencies></project>",
            repository("corp", url, true, false),
            dependency("lib", "1.0")
        )
    };
    for (url, mirror_of, recorded) in [
        ("${undefined.prop}/x", "corp", ""),
        ("${undefined.prop}/x", "external:*,!central", ""),
        (
            "${corp.url}/releases",
            "corp",
            "http://corp.invalid/releases/",
        ),
        (
            "${corp.url}/releases",
            "*,!central",
            "http://corp.invalid/releases/",
        ),
    ] {
        for maven in ["3.9", "3.10"] {
            for central in [&central_server, &bare_server] {
                let case = format!("{url} {mirror_of} {maven} {}", central.addr());
                let dir = TempDir::new_in(base.path()).expect("case");
                let project = maven_project(&dir.path().join("p"), maven, &pom(url));
                let home = mirror_home(central, mirror_of, &corp_server);
                assert_success(&run_raeva(&project, home.path(), &["sync"]), &case);
                let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
                assert!(!lock.contains("evil"), "{case}: {lock}");
                let read = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("lock");
                let parent = &read.platforms[0].support_poms["org.test:parent:1.0"];
                // Maven 3.10 reads a URL without a scheme as a directory.
                let recorded = match (recorded, maven) {
                    ("", "3.10") => "./${undefined.prop}/x/",
                    (recorded, _) => recorded,
                };
                assert_eq!(parent.repo_url, recorded, "{case}: {lock}");
                let cold = mirror_home(central, mirror_of, &corp_server);
                let output = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
                assert_success(&output, &format!("{case} cold frozen"));
                let seed = dir.path().join("seed");
                let seed = seed.to_str().unwrap();
                assert_success(
                    &run_raeva(&project, home.path(), &["seed", "save", seed]),
                    &case,
                );
                let restored = mirror_home(central, mirror_of, &corp_server);
                let output = run_raeva(&project, restored.path(), &["seed", "restore", seed]);
                assert_success(&output, &format!("{case} seed restore"));
                let output = run_raeva(
                    &project,
                    restored.path(),
                    &["--offline", "sync", "--frozen"],
                );
                assert_success(&output, &format!("{case} offline frozen from the seed"));
                let m2 = dir.path().join("m2");
                export(&project, restored.path(), &m2);
                assert!(
                    m2.join("org/test/parent/1.0/parent-1.0.pom").exists(),
                    "{case}"
                );
            }
        }
    }
}

/// A fetched parent's and an imported BOM's repository whose URL Maven
/// reads as no http or https URL serves their parents through the mirror
/// that matches it, as in Maven 3.9.12 and 3.10.0, never Central's other
/// POMs of those coordinates.
#[test]
fn a_fetched_poms_mirrored_repository_serves_its_parent() {
    let base = TempDir::new().expect("tempdir");
    let corp = base.path().join("corp");
    let corp2 = base.path().join("corp2");
    let central = base.path().join("central");
    publish(&corp, "lib", "1.0");
    publish(&central, "lib", "1.0");
    publish(&central, "lib", "2.0");
    publish(&central, "evil", "1.0");
    let managed = |version: &str| {
        format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dependency("lib", version)
        )
    };
    publish_pom(&corp2, "top", "");
    publish_pom(&corp2, "bomtop", &managed("1.0"));
    publish_pom(
        &central,
        "top",
        &format!("<dependencies>{}</dependencies>", dependency("evil", "1.0")),
    );
    publish_pom(&central, "bomtop", &managed("2.0"));
    let corp_server = file_server(&corp);
    let corp2_server = file_server(&corp2);
    let central_server = file_server(&central);
    for (url, maven, recorded) in [
        ("${undefined.prop}/y", "3.9", ""),
        ("${undefined.prop}/y", "3.10", "./${undefined.prop}/y/"),
        ("y/", "3.9", ""),
        ("y/", "3.10", "./y/"),
        ("ftp://h.invalid/y/", "3.9", ""),
        ("file:///nonexistent/y/", "3.10", "file:///nonexistent/y/"),
    ] {
        let case = format!("{url} {maven}");
        let parent = |artifact: &str| {
            format!(
                "<parent><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
                 <version>1.0</version></parent><repositories>{}</repositories>",
                repository("corp2", url, true, false)
            )
        };
        publish_pom(&corp, "mid", &parent("top"));
        publish_pom(&corp, "bom", &parent("bomtop"));
        let dir = TempDir::new_in(base.path()).expect("case");
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>mid</artifactId><version>1.0</version><relativePath/></parent>\
             <artifactId>app</artifactId><repositories>{}</repositories>\
             <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>bom</artifactId><version>1.0</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>lib</artifactId>\
             </dependency></dependencies></project>",
            repository("corp", "http://corp.invalid/", true, false)
        );
        let project = maven_project(&dir.path().join("p"), maven, &pom);
        let home = TempDir::new().expect("home");
        fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
        fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>cm</id><mirrorOf>central</mirrorOf>\
                 <url>http://{}/</url></mirror><mirror><id>m</id><mirrorOf>corp</mirrorOf>\
                 <url>http://{}/</url></mirror><mirror><id>m2</id><mirrorOf>corp2</mirrorOf>\
                 <url>http://{}/</url></mirror></mirrors></settings>",
                central_server.addr(),
                corp_server.addr(),
                corp2_server.addr()
            ),
        )
        .expect("write settings");
        assert_success(&run_raeva(&project, home.path(), &["sync"]), &case);
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
        assert!(!lock.contains("evil"), "{case}: {lock}");
        assert!(lock.contains("org.test:lib:1.0\\tjar"), "{case}: {lock}");
        let read = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("lock");
        for pom in ["org.test:top:1.0", "org.test:bomtop:1.0"] {
            let pin = &read.platforms[0].support_poms[pom];
            assert_eq!(pin.repo_url, recorded, "{case} {pom}: {lock}");
        }
        let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{case} frozen"));
    }
}

/// A settings.xml profile repository goes through `external:*` and
/// `external:http:*` mirrors as Maven 3.9.12 and 3.10.0 send it: by
/// Resolver's URL pattern, as for a POM's, not by the `java.net.URL` check
/// maven-core makes first. `./x` and `x/` are external without a scheme,
/// and `http://[::1` reads as `http`. Maven 3.9.12 fails on `http://[::1`
/// in its transport; 3.10.0 takes the mirror. A URL that still holds a
/// `${...}` no project fills in is refused.
#[test]
fn a_settings_repository_meets_external_mirrors_as_in_maven() {
    let base = TempDir::new().expect("tempdir");
    let mirror = base.path().join("mirror");
    let central = base.path().join("central");
    for (repository, versions) in [(&mirror, ["1.0", "1.5"]), (&central, ["1.0", "1.2"])] {
        for version in versions {
            publish(repository, "ranged", version);
        }
        let listed: String = (versions.iter())
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        fs::write(
            repository.join("org/test/ranged/maven-metadata.xml"),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>ranged</artifactId>\
                 <versioning><versions>{listed}</versions></versioning></metadata>"
            ),
        )
        .expect("write metadata");
    }
    let mirror_server = file_server(&mirror);
    let central_server = file_server(&central);
    for (url, external, http) in [
        ("./x", true, false),
        ("x/", true, false),
        ("${undefined.prop}/x", true, false),
        ("http://[::1", true, true),
    ] {
        for (pattern, mirrored) in [("external:*", external), ("external:http:*", http)] {
            for maven in ["3.9", "3.10"] {
                let case = format!("{url} {pattern} {maven}");
                let dir = TempDir::new_in(base.path()).expect("case");
                let pom = module_pom("app", false, "", &dependency("ranged", "[1.0,2.0)"));
                let project = maven_project(&dir.path().join("p"), maven, &pom);
                let home = TempDir::new().expect("home");
                fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
                fs::write(
                    home.path().join(".m2/settings.xml"),
                    format!(
                        "<settings><mirrors><mirror><id>cm</id><mirrorOf>central</mirrorOf>\
                         <url>http://{}/</url></mirror><mirror><id>m</id>\
                         <mirrorOf>{pattern}</mirrorOf><url>http://{}/</url></mirror>\
                         </mirrors><profiles><profile><id>sp</id><repositories><repository>\
                         <id>srepo</id><url>{url}</url></repository></repositories>\
                         </profile></profiles><activeProfiles><activeProfile>sp\
                         </activeProfile></activeProfiles></settings>",
                        central_server.addr(),
                        mirror_server.addr()
                    ),
                )
                .expect("write settings");
                let output = run_raeva(&project, home.path(), &["sync"]);
                // No project fills the expression in.
                if url.contains("${") {
                    crate::common::assert_status(&output, 3, &case);
                    let err = stderr(&output);
                    assert!(err.contains("leaves unfilled"), "{case}: {err}");
                    continue;
                }
                assert_success(&output, &case);
                let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
                let version = if mirrored { "1.5" } else { "1.2" };
                assert!(
                    lock.contains(&format!("org.test:ranged:{version}\\tjar")),
                    "{case}: {lock}"
                );
                let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
                assert_success(&output, &format!("{case} frozen"));
            }
        }
    }
}

/// An `external:http:*` mirror serves only what Resolver's URL pattern reads
/// as `http` on a host that is not local. `./x`, `x/` and a URL holding an
/// expression have no scheme there, so the mirror passes over them and the
/// range resolves from Central, as in Maven 3.9.12 and 3.10.0; `http://[::1`
/// reads as `http` on the host `[`, which the mirror serves.
#[test]
fn an_external_http_mirror_reads_the_scheme_as_resolver_does() {
    let base = TempDir::new().expect("tempdir");
    let mirror = base.path().join("mirror");
    let central = base.path().join("central");
    for (repository, versions) in [(&mirror, ["1.0", "1.5"]), (&central, ["1.0", "1.2"])] {
        for version in versions {
            publish(repository, "ranged", version);
        }
        let listed: String = (versions.iter())
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        fs::write(
            repository.join("org/test/ranged/maven-metadata.xml"),
            format!(
                "<metadata><groupId>org.test</groupId><artifactId>ranged</artifactId>\
                 <versioning><versions>{listed}</versions></versioning></metadata>"
            ),
        )
        .expect("write metadata");
    }
    let mirror_server = file_server(&mirror);
    let central_server = file_server(&central);
    for (url, mirrored) in [
        ("./x", false),
        ("x/", false),
        ("${undefined.prop}/x", false),
        ("http://[::1", true),
    ] {
        for maven in ["3.9", "3.10"] {
            let case = format!("{url} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let pom = module_pom(
                "app",
                false,
                &repository("corp", url, true, false),
                &dependency("ranged", "[1.0,2.0)"),
            );
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            let home = mirror_home(&central_server, "external:http:*,!central", &mirror_server);
            assert_success(&run_raeva(&project, home.path(), &["sync"]), &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            let version = if mirrored { "1.5" } else { "1.2" };
            assert!(
                lock.contains(&format!("org.test:ranged:{version}\\tjar")),
                "{case}: {lock}"
            );
            let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
            assert_success(&output, &format!("{case} frozen"));
        }
    }
}

/// Maven reads a dependency's repository without an id as one with an empty
/// id, which a mirror of `*` or of an empty entry serves and one of
/// `external:*` does not when it is on this machine, as Maven 3.9.12 and
/// 3.10.0 do. Where the transitive
/// policy ignores it, it stays ignored.
#[test]
fn a_dependency_repository_without_an_id_meets_mirrors_as_in_maven() {
    let base = TempDir::new().expect("tempdir");
    let (mirror, central, declared) = (
        base.path().join("mirror"),
        base.path().join("central"),
        base.path().join("declared"),
    );
    publish(&mirror, "inner", "1.0");
    publish(&declared, "inner", "1.0");
    fs::write(
        declared.join("org/test/inner/1.0/inner-1.0.jar"),
        "declared bytes",
    )
    .expect("write jar");
    let mirror_server = file_server(&mirror);
    let central_server = file_server(&central);
    let declared_server = file_server(&declared);
    let declared_url = format!("http://{}/", declared_server.addr());
    let dir = central.join("org/test/lib/1.0");
    fs::create_dir_all(&dir).expect("create repository");
    fs::write(
        dir.join("lib-1.0.pom"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>lib</artifactId><version>1.0</version><repositories><repository>\
             <url>{declared_url}</url></repository></repositories>\
             <dependencies>{}</dependencies></project>",
            dependency("inner", "1.0")
        ),
    )
    .expect("write pom");
    fs::write(dir.join("lib-1.0.jar"), "lib").expect("write jar");
    let inner = |bytes: &str| BlobId::from_bytes(bytes.as_bytes()).to_string();
    for (security, mirror_of, served) in [
        ("", "*,!central", None),
        (
            "allow_transitive_repositories = true\n",
            "*,!central",
            Some("inner bytes"),
        ),
        (
            "allow_transitive_repositories = true\n",
            "external:*,!central",
            Some("declared bytes"),
        ),
        (
            "allow_transitive_repositories = true\n",
            "external:*,,!central",
            Some("inner bytes"),
        ),
    ] {
        let case = format!("{security}{mirror_of}");
        let dir = TempDir::new_in(base.path()).expect("case");
        let pom = module_pom("app", false, "", &dependency("lib", "1.0"));
        let project = maven_project(&dir.path().join("p"), "3.9", &pom);
        let home = mirror_home(&central_server, mirror_of, &mirror_server);
        fs::write(
            home.path().join("config.toml"),
            format!("[security]\n{security}"),
        )
        .expect("write config.toml");
        let output = run_raeva(&project, home.path(), &["sync"]);
        let lock = fs::read_to_string(project.join("raeva.lock")).unwrap_or_default();
        match served {
            None => {
                assert!(!output.status.success(), "{case}");
                assert!(stderr(&output).contains("org.test:inner:1.0"), "{case}");
            }
            Some(bytes) => {
                assert_success(&output, &case);
                assert!(lock.contains(&inner(bytes)), "{case}: {lock}");
            }
        }
    }
}

/// Maven 3.9.12 and 3.10.0 read parents and imported BOMs through the
/// mirror the repository's URL as written matches, which stays in the
/// model resolver's list under the mirror's id when the interpolated URL,
/// which the dependencies use, goes to no mirror or another, even one at
/// the same URL. raeva refuses such a build in both modes, naming the
/// repository but not its URL, also where it does not read the
/// interpolated URL, as Maven searches the mirror before Central. With one
/// route for both URLs, a mirror of the repository's own id, which the
/// interpolated declaration replaces before any BOM import, though not
/// before the parent lookup, or a split repository that only dependencies
/// use, the build locks what Maven reads.
#[test]
fn a_repository_split_between_mirror_routes_refuses_the_model_build() {
    let base = TempDir::new().expect("tempdir");
    let bom = |repository: &Path, managed: &str| {
        publish_pom(
            repository,
            "bom",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dependency("managed", managed)
            ),
        );
    };
    let mirror = base.path().join("mirror");
    bom(&mirror, "2.0");
    publish_pom(&mirror, "parent", "");
    publish(&mirror, "managed", "2.0");
    let direct = base.path().join("direct");
    bom(&direct, "3.0");
    for version in ["2.0", "3.0"] {
        publish(&direct, "managed", version);
    }
    let central = base.path().join("central");
    bom(&central, "3.0");
    publish(&central, "managed", "3.0");
    let (mirror_server, direct_server) = (file_server(&mirror), file_server(&direct));
    let central_server = file_server(&central);
    let direct_url = format!("http://{}", direct_server.addr());
    let unreachable = format!("http://127.0.0.2:{}", direct_server.addr().port());
    let import = |artifact: &str| {
        format!(
            "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>"
        )
    };
    // Its own declaration of `corp`, as written, is one the importer's
    // reserved id makes Maven ignore.
    let boma = format!(
        "<properties><base>{direct_url}</base></properties><repositories>{}\
         </repositories>{}",
        repository("corp", "${base}", true, false),
        import("bom")
    );
    publish_pom(&direct, "boma", &boma);
    // A repository without the BOM, beside a parent whose repository is
    // `file:` once interpolated, which raeva does not read from a fetched
    // POM, and a mirror's as written, which Maven searches before Central.
    let plain = base.path().join("plain");
    publish_pom(&plain, "boma", &boma);
    publish_pom(
        &plain,
        "parentx",
        &format!(
            "<properties><px.base>file:///nonexistent-splitroute</px.base></properties>\
             <repositories>{}</repositories>",
            repository("pr", "${px.base}/r", true, false)
        ),
    );
    for version in ["2.0", "3.0"] {
        publish(&plain, "managed", version);
    }
    let plain_server = file_server(&plain);
    let plain_url = format!("http://{}", plain_server.addr());
    let refused = "Maven reads parents and imported BOMs through the mirror of the URL as written";
    #[derive(Clone, Copy, PartialEq)]
    enum Use {
        Bom,
        Parent,
        Dependency,
        /// A BOM import below a local parent that declares `corp` too,
        /// which Maven ignores.
        RedeclaringParent,
        /// A BOM import of a BOM that imports one.
        Nested,
        /// A BOM import below a fetched parent.
        FetchedParent,
    }
    for (url, repo_base, mirrors, used, locked) in [
        (
            "${repo.base}",
            &direct_url,
            &[("m", "external:*,!central")][..],
            Use::Bom,
            None,
        ),
        (
            "${project.baseUri}repo",
            &direct_url,
            &[("m", "external:*,!central")][..],
            Use::Bom,
            None,
        ),
        (
            "${project.baseUri}repo",
            &direct_url,
            &[("m", "external:*,!central")][..],
            Use::Parent,
            None,
        ),
        (
            "${repo.base}",
            &direct_url,
            &[("m", "*,!central")][..],
            Use::Bom,
            Some("2.0"),
        ),
        (
            "${project.baseUri}repo",
            &direct_url,
            &[("m", "*,!central")][..],
            Use::Bom,
            Some("2.0"),
        ),
        (
            "${repo.base}",
            &unreachable,
            &[("m", "external:http:*,!central")][..],
            Use::Bom,
            Some("2.0"),
        ),
        (
            "${repo.base}",
            &direct_url,
            &[("m", "nothing")][..],
            Use::Bom,
            Some("3.0"),
        ),
        (
            "${repo.base}",
            &direct_url,
            &[("m", "external:*,!central")][..],
            Use::Dependency,
            Some("3.0"),
        ),
        (
            "${project.baseUri}repo",
            &direct_url,
            &[("m", "external:*,!central")][..],
            Use::Dependency,
            Some("3.0"),
        ),
        (
            "${repo.base}",
            &direct_url,
            &[("corp", "external:*,!central")][..],
            Use::Bom,
            Some("3.0"),
        ),
        (
            "${repo.base}",
            &direct_url,
            &[("m1", "external:*,!central"), ("m", "*,!central")][..],
            Use::Bom,
            Some("2.0"),
        ),
        (
            "${repo.base}",
            &direct_url,
            &[("m", "external:http:*,!central")][..],
            Use::RedeclaringParent,
            Some("3.0"),
        ),
        (
            &plain_url,
            &direct_url,
            &[("m", "external:*,!central")][..],
            Use::Nested,
            Some("3.0"),
        ),
        (
            &plain_url,
            &direct_url,
            &[("m", "external:*,!central")][..],
            Use::FetchedParent,
            None,
        ),
        (
            "${project.baseUri}repo",
            &direct_url,
            &[("corp", "external:*,!central")][..],
            Use::Parent,
            None,
        ),
    ] {
        let head = match used {
            Use::Parent => {
                "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
                            <version>1.0</version><relativePath/></parent>"
            }
            Use::RedeclaringParent => {
                "<parent><groupId>org.test</groupId><artifactId>lp</artifactId>\
                 <version>1</version><relativePath>../lp/pom.xml</relativePath></parent>"
            }
            Use::FetchedParent => {
                "<parent><groupId>org.test</groupId><artifactId>parentx</artifactId>\
                 <version>1.0</version><relativePath/></parent>"
            }
            _ => "<groupId>org.test</groupId>",
        };
        let unversioned = "<dependency><groupId>org.test</groupId>\
                           <artifactId>managed</artifactId></dependency>"
            .to_string();
        let (management, managed) = match used {
            Use::Bom | Use::RedeclaringParent | Use::FetchedParent => (import("bom"), unversioned),
            Use::Nested => (import("boma"), unversioned),
            Use::Parent | Use::Dependency => (String::new(), dependency("managed", "3.0")),
        };
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion>{head}<artifactId>app</artifactId>\
             <version>1</version><properties><repo.base>{repo_base}</repo.base></properties>\
             <repositories>{}</repositories>{management}<dependencies>{managed}</dependencies>\
             </project>",
            repository("corp", url, true, false),
        );
        for maven in ["3.9", "3.10"] {
            let case = format!("{url} {mirrors:?} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            fs::create_dir_all(dir.path().join("lp")).expect("create parent");
            fs::write(
                dir.path().join("lp/pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>lp</artifactId><version>1</version><packaging>pom\
                     </packaging><repositories>{}</repositories></project>",
                    repository("corp", "http://corp.invalid/repo", true, false)
                ),
            )
            .expect("write parent");
            copy_dir(&direct, &project.join("repo"));
            let home = settings_home(&central_server, mirrors, &mirror_server);
            let output = run_raeva(&project, home.path(), &["sync"]);
            let Some(locked) = locked else {
                crate::common::assert_status(&output, 3, &case);
                let err = stderr(&output);
                let id = if used == Use::FetchedParent {
                    "pr"
                } else {
                    "corp"
                };
                assert!(err.contains(&format!("repository '{id}'")), "{case}: {err}");
                assert!(err.contains(refused), "{case}: {err}");
                assert!(
                    !err.contains(&direct_server.addr().to_string()),
                    "{case}: {err}"
                );
                assert!(!project.join("raeva.lock").exists(), "{case}");
                let cold = settings_home(&central_server, mirrors, &mirror_server);
                let output = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
                crate::common::assert_status(&output, 3, &format!("{case} fresh frozen"));
                continue;
            };
            assert_success(&output, &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            assert!(
                lock.contains(&format!("org.test:managed:{locked}")),
                "{case}: {lock}"
            );
            if !matches!(used, Use::Parent | Use::Dependency) {
                let served = if locked == "2.0" { &mirror } else { &direct };
                assert!(lock.contains(&pom_sha256(served, "bom")), "{case}: {lock}");
            }
            let cold = settings_home(&central_server, mirrors, &mirror_server);
            let output = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
            assert_success(&output, &format!("{case} cold frozen"));
        }
    }
}

/// A dependency's POM whose repository splits between mirror routes is
/// refused only where Maven's lookup reaches the mirror entry the URL as
/// written left. That entry comes after the repositories the dependency
/// was resolved through, so a BOM or parent one of those holds locks, from
/// the project's repository or from Central; a BOM only the mirror holds
/// is refused, and a parent only it holds is not found, naming the mirror
/// Maven also looks it up through. In Maven 3.9.12 a dependency that
/// redeclares a request repository's id replaces it before the BOM import,
/// so only Central comes ahead of the mirror; Maven 3.10.0 keeps it.
/// Without `allow_transitive_repositories` raeva reads neither.
#[test]
fn a_dependency_pom_split_between_mirror_routes_refuses_only_where_maven_reaches_it() {
    let base = TempDir::new().expect("tempdir");
    let bom = |repository: &Path, managed: &str, artifact: &str| {
        publish_pom(
            repository,
            artifact,
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dependency("managed", managed)
            ),
        );
    };
    let (mirror, direct, plain) = (
        base.path().join("mirror"),
        base.path().join("direct"),
        base.path().join("plain"),
    );
    let (central, central_bom) = (base.path().join("central"), base.path().join("cbom"));
    bom(&mirror, "2.0", "bom");
    bom(&mirror, "2.0", "bomx");
    publish_pom(&mirror, "mparent", "");
    bom(&direct, "3.0", "bom");
    bom(&direct, "3.0", "bomx");
    fs::create_dir_all(&central).expect("create central");
    publish_pom(
        &central_bom,
        "bom",
        &format!(
            "<!-- central --><dependencyManagement><dependencies>{}</dependencies>\
             </dependencyManagement>",
            dependency("managed", "3.0")
        ),
    );
    publish_pom(&plain, "pparent", "");
    for repository in [&mirror, &direct, &plain] {
        for version in ["2.0", "3.0"] {
            publish(repository, "managed", version);
        }
    }
    let direct_server = file_server(&direct);
    let mirror_server = file_server(&mirror);
    let import = |artifact: &str| {
        format!(
            "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>managed\
             </artifactId></dependency></dependencies>"
        )
    };
    let parent = |artifact: &str| {
        format!(
            "<parent><groupId>org.test</groupId><artifactId>{artifact}</artifactId>\
             <version>1.0</version></parent>"
        )
    };
    for (artifact, head, body) in [
        ("lib", String::new(), import("bom")),
        ("libx", String::new(), import("bomx")),
        ("libp", parent("pparent"), String::new()),
        ("libm", parent("mparent"), String::new()),
        ("libr", String::new(), import("bom")),
    ] {
        // `libr` redeclares the project's `corp`, which replaces that entry.
        let id = if artifact == "libr" { "corp" } else { "libs" };
        for served in [&direct, &plain] {
            let dir = served.join(format!("org/test/{artifact}/1.0"));
            fs::create_dir_all(&dir).expect("create lib");
            fs::write(
                dir.join(format!("{artifact}-1.0.pom")),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion>{head}<groupId>org.test\
                     </groupId><artifactId>{artifact}</artifactId><version>1.0</version>\
                     <properties><lib.base>http://{}</lib.base></properties><repositories>\
                     {}</repositories>{body}</project>",
                    direct_server.addr(),
                    repository(id, "${lib.base}", true, false),
                ),
            )
            .expect("write lib");
            fs::write(dir.join(format!("{artifact}-1.0.jar")), "lib bytes").expect("write jar");
        }
    }
    let plain_server = file_server(&plain);
    let (central_server, central_bom_server) = (file_server(&central), file_server(&central_bom));
    // The BOM each case locks: `Some` with the repository that serves it.
    for (corp, from_central, artifact, trusted, served) in [
        (&direct_server, false, "lib", false, Some(&direct)),
        (&direct_server, false, "lib", true, Some(&direct)),
        (&plain_server, true, "lib", true, Some(&central_bom)),
        (&plain_server, false, "lib", true, None),
        (&plain_server, false, "libx", true, None),
        (&plain_server, false, "libp", true, Some(&plain)),
        (&plain_server, false, "libm", true, None),
        (&direct_server, false, "libr", true, None),
        (&direct_server, true, "libr", true, Some(&central_bom)),
    ] {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories>{}</repositories>\
             <dependencies>{}</dependencies></project>",
            repository("corp", &format!("http://{}", corp.addr()), true, false),
            dependency(artifact, "1.0"),
        );
        let central = if from_central {
            &central_bom_server
        } else {
            &central_server
        };
        for maven in ["3.9", "3.10"] {
            let case = format!(
                "{artifact} {} central={from_central} trusted={trusted} {maven}",
                corp.addr()
            );
            let served = match (artifact, maven) {
                ("libr", "3.10") => Some(&direct),
                _ => served,
            };
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            let home_for = || {
                let home = mirror_home(central, "external:*,!central", &mirror_server);
                if trusted {
                    fs::write(
                        home.path().join("config.toml"),
                        "[security]\nallow_transitive_repositories = true\n",
                    )
                    .expect("write config");
                }
                home
            };
            let output = run_raeva(&project, home_for().path(), &["sync"]);
            let Some(served) = served else {
                let refused = if artifact == "libm" { 5 } else { 3 };
                crate::common::assert_status(&output, refused, &case);
                if artifact == "libm" {
                    let err = stderr(&output);
                    assert!(
                        err.contains(
                            "Parent POM not found: org.test:mparent:1.0; Maven also looks it up \
                             through mirror 'm', where the URL of repository 'libs' as written goes"
                        ),
                        "{case}: {err}"
                    );
                    assert!(!project.join("raeva.lock").exists(), "{case}");
                    continue;
                }
                let err = stderr(&output);
                let id = if artifact == "libr" { "corp" } else { "libs" };
                assert!(err.contains(&format!("repository '{id}'")), "{case}: {err}");
                assert!(!project.join("raeva.lock").exists(), "{case}");
                continue;
            };
            assert_success(&output, &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            if artifact == "libp" {
                assert!(
                    lock.contains(&pom_sha256(served, "pparent")),
                    "{case}: {lock}"
                );
            } else {
                assert!(lock.contains("org.test:managed:3.0"), "{case}: {lock}");
                assert!(lock.contains(&pom_sha256(served, "bom")), "{case}: {lock}");
            }
            let output = run_raeva(&project, home_for().path(), &["sync", "--frozen"]);
            assert_success(&output, &format!("{case} cold frozen"));
        }
    }
    // A parent no repository holds, where the dependency's repository is
    // written out, is only not found: raeva searches its mirror.
    let dir = mirror.join("org/test/libn/1.0");
    fs::create_dir_all(&dir).expect("create libn");
    fs::write(
        dir.join("libn-1.0.pom"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>nparent</artifactId><version>1.0</version></parent>\
             <artifactId>libn</artifactId><repositories>{}</repositories></project>",
            repository(
                "libs",
                &format!("http://{}", direct_server.addr()),
                true,
                false
            )
        ),
    )
    .expect("write libn");
    fs::write(dir.join("libn-1.0.jar"), "lib bytes").expect("write jar");
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><repositories>{}</repositories>\
         <dependencies>{}</dependencies></project>",
        repository(
            "corp",
            &format!("http://{}", direct_server.addr()),
            true,
            false
        ),
        dependency("libn", "1.0"),
    );
    let dir = TempDir::new_in(base.path()).expect("case");
    let project = maven_project(&dir.path().join("p"), "3.9", &pom);
    let home = mirror_home(&central_server, "*", &mirror_server);
    fs::write(
        home.path().join("config.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .expect("write config");
    let output = run_raeva(&project, home.path(), &["sync"]);
    crate::common::assert_status(&output, 5, "libn");
    let err = stderr(&output);
    assert!(
        err.contains("Parent POM not found: org.test:nparent:1.0"),
        "{err}"
    );
    assert!(!err.contains("Maven also looks it up"), "{err}");
}

/// Two mirrors at one URL are one route only when neither is blocked and
/// neither has a `<server>` with more than a username and password: Maven
/// sends each mirror's headers and other settings with every request, but
/// a password only once challenged. A project
/// build re-adds each repository once interpolated, behind the mirror entry
/// a split one left, so a repository declared before it does not serve the
/// BOM first.
#[test]
fn a_split_project_repository_locks_only_where_maven_reads_one_route() {
    let base = TempDir::new().expect("tempdir");
    let (mirror, direct) = (base.path().join("mirror"), base.path().join("direct"));
    for (repository, managed) in [(&mirror, "2.0"), (&direct, "3.0")] {
        publish_pom(
            repository,
            "bom",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dependency("managed", managed)
            ),
        );
        for version in ["2.0", "3.0"] {
            publish(repository, "managed", version);
        }
    }
    let (mirror_server, direct_server) = (file_server(&mirror), file_server(&direct));
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let direct_url = format!("http://{}", direct_server.addr());
    let early = repository("early", &direct_url, true, false);
    let header = "<configuration><httpHeaders><property><name>X-Tenant</name>\
                  <value>tenant-one</value></property></httpHeaders></configuration>";
    let credentials = "<username>deployer</username><password>idref-fixture-pass</password>";
    let configured = format!(
        "{credentials}<configuration><preemptiveAuth>true</preemptiveAuth></configuration>"
    );
    let keyed = format!("{credentials}<privateKey>/idref/key</privateKey>");
    for (earlier, mirrors, server, locked) in [
        ("", "m1:external:*,!central m:*,!central", "", true),
        ("", "m1:external:*,!central m:*,!central", credentials, true),
        (
            "",
            "m1:external:*,!central m:*,!central",
            &configured,
            false,
        ),
        ("", "m1:external:*,!central m:*,!central", &keyed, false),
        ("", "m1:external:*,!central m:*,!central", header, false),
        ("", "m1:external:*,!central m:*,!central", "blocked", false),
        (early.as_str(), "m:external:*,!central", "", false),
    ] {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><properties><repo.base>\
             {direct_url}</repo.base></properties><repositories>{earlier}{}</repositories>\
             <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>bom</artifactId><version>1.0</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>managed\
             </artifactId></dependency></dependencies></project>",
            repository("corp", "${repo.base}", true, false),
        );
        let mirrors: Vec<(&str, &str)> = (mirrors.split(' '))
            .map(|entry| entry.split_once(':').expect("id:mirrorOf"))
            .collect();
        for maven in ["3.9", "3.10"] {
            let case = format!("{earlier} {mirrors:?} server={} {maven}", server.len());
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            let home_for = || {
                let home = settings_home(&central_server, &mirrors, &mirror_server);
                let settings = home.path().join(".m2/settings.xml");
                let xml = fs::read_to_string(&settings).expect("read settings");
                let xml = match server {
                    "" => xml,
                    "blocked" => xml.replace("<id>m</id>", "<id>m</id><blocked>true</blocked>"),
                    server => xml.replace(
                        "<settings>",
                        &format!(
                            "<settings><servers><server><id>m1</id>{server}</server></servers>"
                        ),
                    ),
                };
                fs::write(&settings, xml).expect("write settings");
                home
            };
            let output = run_raeva(&project, home_for().path(), &["sync"]);
            if !locked {
                crate::common::assert_status(&output, 3, &case);
                let err = stderr(&output);
                assert!(err.contains("repository 'corp'"), "{case}: {err}");
                assert!(!err.contains("idref-fixture-pass"), "{case}: {err}");
                assert!(!project.join("raeva.lock").exists(), "{case}");
                continue;
            }
            assert_success(&output, &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            assert!(lock.contains("org.test:managed:2.0"), "{case}: {lock}");
            assert!(lock.contains(&pom_sha256(&mirror, "bom")), "{case}: {lock}");
            let output = run_raeva(&project, home_for().path(), &["sync", "--frozen"]);
            assert_success(&output, &format!("{case} cold frozen"));
        }
    }
}

/// Maven sends a `<server>` password only once a request is challenged, so
/// where the mirror of the URL as written has one and that of the URL once
/// interpolated, at the same URL, has none, it reads the anonymous BOM
/// even where a credentialed request would get another, as raeva does
/// without sending it. A BOM that is challenged Maven reads with the
/// password, which raeva never sends there, and refuses.
#[test]
fn a_password_maven_sends_only_when_challenged_leaves_two_mirrors_one_route() {
    let base = TempDir::new().expect("tempdir");
    let (anonymous, credentialed, direct) = (
        base.path().join("anonymous"),
        base.path().join("credentialed"),
        base.path().join("direct"),
    );
    for (repository, managed) in [
        (&anonymous, "3.0"),
        (&credentialed, "2.0"),
        (&direct, "3.0"),
    ] {
        publish_pom(
            repository,
            "bom",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dependency("managed", managed)
            ),
        );
        for version in ["2.0", "3.0"] {
            publish(repository, "managed", version);
        }
    }
    let direct_server = file_server(&direct);
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let direct_url = format!("http://{}", direct_server.addr());
    let pom = format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
         <artifactId>app</artifactId><version>1</version><properties><repo.base>\
         {direct_url}</repo.base></properties><repositories>{}</repositories>\
         <dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>bom</artifactId><version>1.0</version><type>pom</type>\
         <scope>import</scope></dependency></dependencies></dependencyManagement>\
         <dependencies><dependency><groupId>org.test</groupId><artifactId>managed\
         </artifactId></dependency></dependencies></project>",
        repository("corp", "${repo.base}", true, false),
    );
    for challenged in [false, true] {
        let roots = (anonymous.clone(), credentialed.clone());
        let mirror_server = StubServer::start(move |request| {
            let path = request.path.trim_start_matches('/');
            let root = match request.header("authorization") {
                Some(_) => &roots.1,
                None if challenged && path.contains("/bom/") => {
                    return Response::new(401, "")
                        .header("WWW-Authenticate", "Basic realm=\"idref\"");
                }
                None => &roots.0,
            };
            let (file, sidecar) = match path.strip_suffix(".sha256") {
                Some(file) => (file, true),
                None => (path, false),
            };
            match fs::read(root.join(file)) {
                Ok(bytes) if sidecar => Response::new(200, BlobId::from_bytes(&bytes).to_string()),
                Ok(bytes) => Response::new(200, bytes),
                Err(_) => Response::new(404, ""),
            }
        });
        for maven in ["3.9", "3.10"] {
            let case = format!("challenged={challenged} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            let home_for = || {
                let mirrors = [("m1", "external:*,!central"), ("m", "*,!central")];
                let home = settings_home(&central_server, &mirrors, &mirror_server);
                let settings = home.path().join(".m2/settings.xml");
                let xml = fs::read_to_string(&settings).expect("read settings");
                let xml = xml.replace(
                    "<settings>",
                    "<settings><servers><server><id>m1</id><username>deployer</username>\
                     <password>idref-fixture-pass</password></server></servers>",
                );
                fs::write(&settings, xml).expect("write settings");
                home
            };
            let output = run_raeva(&project, home_for().path(), &["sync"]);
            let err = stderr(&output);
            assert!(!err.contains("idref-fixture-pass"), "{case}: {err}");
            if challenged {
                crate::common::assert_status(&output, 3, &case);
                assert!(
                    err.contains("g:bom:1.0") || err.contains("org.test:bom:1.0"),
                    "{case}: {err}"
                );
                assert!(err.contains("401"), "{case}: {err}");
                assert!(!project.join("raeva.lock").exists(), "{case}");
            } else {
                assert_success(&output, &case);
                let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
                assert!(lock.contains("org.test:managed:3.0"), "{case}: {lock}");
                assert!(
                    lock.contains(&pom_sha256(&anonymous, "bom")),
                    "{case}: {lock}"
                );
                let output = run_raeva(&project, home_for().path(), &["sync", "--frozen"]);
                assert_success(&output, &format!("{case} cold frozen"));
            }
        }
        let sent = (mirror_server.requests().iter())
            .any(|request| request.header("authorization").is_some());
        assert!(!sent, "challenged={challenged}: a password was sent");
    }
}

/// An active settings.xml profile's repository whose `<id>` or `<layout>`
/// still holds a `${...}` once the file is interpolated, or whose literal
/// `<layout>` is not `default`, is refused, mirrored or not. One whose
/// `<url>` does is the project's, as in Maven, which fills it in with the
/// POM's properties or the profile's own; one that `-D` or the environment
/// fills in, and a plain one, resolve.
#[test]
fn a_settings_repository_id_or_layout_that_takes_project_properties_is_refused() {
    let base = TempDir::new().expect("tempdir");
    let (mirror, direct) = (base.path().join("mirror"), base.path().join("direct"));
    for repository in [&mirror, &direct] {
        publish(repository, "managed", "3.0");
    }
    let (mirror_server, direct_server) = (file_server(&mirror), file_server(&direct));
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let direct_url = format!("http://{}", direct_server.addr());
    let corp = |id: &str, url: &str, layout: &str| {
        format!("<repository><id>{id}</id><url>{url}</url>{layout}</repository>")
    };
    let properties =
        |value: &str| format!("<properties><repo.base>{value}</repo.base></properties>");
    let in_pom = properties(&direct_url);
    let legacy = "<layout>legacy</layout>";
    let default = "<layout>default</layout>";
    // (repository, profile properties, POM head, POM properties, -D, refused)
    for (repository, profile, head, own, define, refused) in [
        (
            corp("corp", "${repo.base}", ""),
            "",
            "",
            in_pom.as_str(),
            false,
            None,
        ),
        (
            corp("corp", "${repo.base}", ""),
            in_pom.as_str(),
            "",
            "",
            false,
            None,
        ),
        (
            corp("${rid}", &direct_url, ""),
            "",
            "",
            "<properties><rid>corp</rid></properties>",
            false,
            Some("<id>"),
        ),
        (
            corp("corp", "${repo.base}", "<layout>${lay}</layout>"),
            "",
            "",
            "<properties><lay>default</lay></properties>",
            true,
            Some("<layout>"),
        ),
        (
            corp("corp", &direct_url, legacy),
            "",
            "",
            "",
            false,
            Some("<layout>"),
        ),
        (corp("corp", &direct_url, ""), "", "", "", false, None),
        (corp("corp", &direct_url, default), "", "", "", false, None),
        (corp("corp", "${repo.base}", ""), "", "", "", true, None),
        (
            corp("corp", "${env.RV_IDREF_BASE}", ""),
            "",
            "",
            "",
            false,
            None,
        ),
        (
            corp("${env.RV_IDREF_ID}", &direct_url, ""),
            "",
            "",
            "",
            false,
            None,
        ),
    ] {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion>{head}<groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version>{own}<dependencies>{}\
             </dependencies></project>",
            dependency("managed", "3.0")
        );
        for mirrored in [false, true] {
            for maven in ["3.9", "3.10"] {
                let case = format!("{repository} {profile} {head} mirrored={mirrored} {maven}");
                let dir = TempDir::new_in(base.path()).expect("case");
                let project = maven_project(&dir.path().join("p"), maven, &pom);
                let mirrors: &[(&str, &str)] = if mirrored {
                    &[("m", "external:*,!central")]
                } else {
                    &[]
                };
                let home = settings_home(&central_server, mirrors, &mirror_server);
                let settings = home.path().join(".m2/settings.xml");
                let xml = fs::read_to_string(&settings).expect("read settings");
                let xml = xml.replace(
                    "</settings>",
                    &format!(
                        "<profiles><profile><id>sp</id>{profile}<repositories>{repository}\
                         </repositories></profile></profiles><activeProfiles>\
                         <activeProfile>sp</activeProfile></activeProfiles></settings>"
                    ),
                );
                fs::write(&settings, xml).expect("write settings");
                let mut command = raeva_command(&project, home.path());
                command
                    .env("RV_IDREF_BASE", &direct_url)
                    .env("RV_IDREF_ID", "corp")
                    .arg("sync");
                if define {
                    command.arg(format!("-Drepo.base={direct_url}"));
                }
                let output = command.output().expect("run raeva");
                if let Some(element) = refused {
                    crate::common::assert_status(&output, 3, &case);
                    let err = stderr(&output);
                    assert!(err.contains("in the active profile 'sp'"), "{case}: {err}");
                    assert!(err.contains(&format!("the {element} of ")), "{case}: {err}");
                    assert!(!project.join("raeva.lock").exists(), "{case}");
                    continue;
                }
                assert_success(&output, &case);
                let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
                assert!(lock.contains("org.test:managed:3.0"), "{case}: {lock}");
            }
        }
    }
    // A mirror of another layout is refused too; one of `default` serves.
    for (layout, refused) in [
        ("<layout>legacy</layout>", true),
        ("<layout>default</layout>", false),
    ] {
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories>{}</repositories>\
             <dependencies>{}</dependencies></project>",
            corp("corp", &direct_url, ""),
            dependency("managed", "3.0")
        );
        let dir = TempDir::new_in(base.path()).expect("case");
        let project = maven_project(&dir.path().join("p"), "3.9", &pom);
        let home = settings_home(&central_server, &[("m", "corp")], &mirror_server);
        let settings = home.path().join(".m2/settings.xml");
        let xml = fs::read_to_string(&settings).expect("read settings");
        let xml = xml.replace(
            "<mirrorOf>corp</mirrorOf>",
            &format!("<mirrorOf>corp</mirrorOf>{layout}"),
        );
        fs::write(&settings, xml).expect("write settings");
        let output = run_raeva(&project, home.path(), &["sync"]);
        if refused {
            crate::common::assert_status(&output, 3, layout);
            let err = stderr(&output);
            assert!(
                err.contains("the <layout> of mirror 'm' is 'legacy'"),
                "{err}"
            );
        } else {
            assert_success(&output, layout);
        }
    }
}

/// A settings.xml plugin repository raeva cannot read, through an
/// undefined or POM property in its URL, a layout expression, a `legacy`
/// layout or an id expression, and a POM plugin repository whose id takes
/// a `${...}`, serve only the plugins, as in Maven: a dependency lock
/// resolves past them, and only a sync that `[plugins]` makes lock the
/// plugins refuses the settings.xml one.
#[test]
fn a_plugin_repository_raeva_cannot_read_refuses_only_a_plugin_lock() {
    let base = TempDir::new().expect("tempdir");
    let direct = base.path().join("direct");
    publish(&direct, "a1", "1.0");
    let direct_server = file_server(&direct);
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let direct_url = format!("http://{}", direct_server.addr());
    let plugin = |body: &str| {
        format!(
            "<pluginRepositories><pluginRepository>{body}</pluginRepository></pluginRepositories>"
        )
    };
    let project_pom = |plugins: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><properties><pp>{direct_url}\
             </pp><lay>default</lay><pid>zz</pid></properties><repositories>{}</repositories>\
             {plugins}<dependencies>{}</dependencies></project>",
            repository("corp", &direct_url, true, false),
            dependency("a1", "1.0")
        )
    };
    let settings = [
        "<id>pr</id><url>${undefined}/</url>",
        "<id>pr</id><url>${pp}/</url>",
        "<id>pr</id><url>https://x.invalid/</url><layout>${lay}</layout>",
        "<id>pr</id><url>https://x.invalid/</url><layout>legacy</layout>",
        "<id>${pid}</id><url>https://x.invalid/</url>",
    ];
    let rows = (settings.iter().map(|body| (plugin(body), String::new())))
        .chain([(String::new(), plugin("<id>${pid}</id><url>${pp}/</url>"))]);
    for ((settings_plugin, pom_plugin), maven) in
        rows.flat_map(|row| [(row.clone(), "3.9"), (row, "3.10")])
    {
        let case = format!("{settings_plugin}{pom_plugin} {maven}");
        let dir = TempDir::new_in(base.path()).expect("case");
        let project = maven_project(&dir.path().join("p"), maven, &project_pom(&pom_plugin));
        let home = settings_home(&central_server, &[], &central_server);
        let settings = home.path().join(".m2/settings.xml");
        let xml = fs::read_to_string(&settings).expect("read settings");
        let xml = xml.replace(
            "</settings>",
            &format!(
                "<profiles><profile><id>sp</id>{settings_plugin}</profile></profiles>\
                 <activeProfiles><activeProfile>sp</activeProfile></activeProfiles></settings>"
            ),
        );
        fs::write(&settings, xml).expect("write settings");
        assert_success(&run_raeva(&project, home.path(), &["sync"]), &case);
        let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{case} frozen"));
        if settings_plugin.is_empty() {
            continue;
        }
        let toml = project.join("raeva.toml");
        let text = fs::read_to_string(&toml).expect("read raeva.toml");
        fs::write(&toml, format!("{text}[plugins]\nlock = true\n")).expect("write raeva.toml");
        let output = run_raeva(&project, home.path(), &["sync"]);
        crate::common::assert_status(&output, 3, &format!("{case} plugins"));
        let err = stderr(&output);
        assert!(
            err.contains("in the active profile 'sp', the <")
                && err.contains("of plugin repository"),
            "{case}: {err}"
        );
    }
}

/// A POM repository `<id>` that raeva fills in as Maven does resolves as
/// in Maven, whether the project, a project profile, a fetched parent or a
/// dependency declares it: the parent lookup matches mirrors against the id
/// as written and the rest against the id once interpolated, so with a
/// mirror of the filled id the parent comes from the declared URL and the
/// dependencies through the mirror. A dependency's such repository serves
/// its range once the transitive policy admits it, and its artifact too.
#[test]
fn a_pom_repository_id_raeva_fills_in_resolves_as_in_maven() {
    let base = TempDir::new().expect("tempdir");
    let (mirror, direct) = (base.path().join("mirror"), base.path().join("direct"));
    let other = direct.join("other");
    for (repository, label) in [(&direct, "direct"), (&mirror, "mirror"), (&other, "other")] {
        let dir = repository.join("org/test/a1/1.0");
        fs::create_dir_all(&dir).expect("create a1");
        fs::write(
            dir.join("a1-1.0.pom"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>a1</artifactId><version>1.0</version>\
                 <description>{label}</description></project>"
            ),
        )
        .expect("write a1");
        fs::write(dir.join("a1-1.0.jar"), label).expect("write jar");
    }
    publish_pom(&direct, "idpar", "");
    publish_pom(&other, "lpar", "");
    for (repository, label) in [(&mirror, "mirror"), (&other, "other")] {
        let dir = repository.join("org/test/a3/1.0");
        fs::create_dir_all(&dir).expect("create a3");
        fs::write(
            dir.join("a3-1.0.pom"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>a3</artifactId><version>1.0</version>\
                 <description>{label}</description></project>"
            ),
        )
        .expect("write a3");
        fs::write(dir.join("a3-1.0.jar"), label).expect("write jar");
    }
    publish(&direct, "both", "1.0");
    publish(&other, "both", "2.0");
    publish_listing(&direct, "both", &["1.0"], STAMP);
    publish_listing(&other, "both", &["2.0"], STAMP);
    let (mirror_server, direct_server) = (file_server(&mirror), file_server(&direct));
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let direct_url = format!("http://{}", direct_server.addr());
    let other_url = format!("{direct_url}/other");
    let declares_pp = |name: &str, head: &str, dependencies: &str| {
        let dir = direct.join(format!("org/test/{name}/1.0"));
        fs::create_dir_all(&dir).expect("create lib");
        fs::write(
            dir.join(format!("{name}-1.0.pom")),
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{head}<groupId>org.test</groupId>\
                 <artifactId>{name}</artifactId><version>1.0</version><properties><p>pp</p>\
                 </properties><repositories>{}</repositories><dependencies>{dependencies}\
                 </dependencies></project>",
                repository("${p}", &other_url, true, false)
            ),
        )
        .expect("write lib");
        fs::write(dir.join(format!("{name}-1.0.jar")), name).expect("write jar");
    };
    declares_pp(
        "libx",
        "<parent><groupId>org.test</groupId><artifactId>lpar</artifactId>\
         <version>1.0</version><relativePath/></parent>",
        &dependency("a3", "1.0"),
    );
    declares_pp("libre", "", &dependency("both", "[1.0,3.0)"));
    let rid = repository("${rid}", &direct_url, true, false);
    let project_pom = |head: &str, body: &str, dependencies: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{head}<groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><properties><rid>x</rid>\
             </properties>{body}<dependencies>{dependencies}</dependencies></project>"
        )
    };
    let repositories = |list: &str| format!("<repositories>{list}</repositories>");
    let idpar = "<parent><groupId>org.test</groupId><artifactId>idpar</artifactId>\
                 <version>1.0</version><relativePath/></parent>";
    let corp = repositories(&repository("corp", &direct_url, true, false));
    let transitive = "[security]\nallow_transitive_repositories = true\n";
    let a1 = dependency("a1", "1.0");
    // (case, pom, mirror of, user config, (artifact, repository) whose POM
    // the lock holds)
    type Held<'a> = &'a [(&'a str, &'a Path)];
    let cases: [(&str, String, &str, &str, Held<'_>); 5] = [
        (
            "project id, mirror of the filled id, remote parent",
            project_pom(idpar, &repositories(&rid), &a1),
            "x",
            "",
            &[("idpar", &direct), ("a1", &mirror)],
        ),
        (
            "project profile id",
            project_pom(
                "",
                &format!(
                    "<profiles><profile><id>pp</id><activation><activeByDefault>true\
                     </activeByDefault></activation>{}</profile></profiles>",
                    repositories(&rid)
                ),
                &a1,
            ),
            "nothing",
            "",
            &[("a1", &direct)],
        ),
        (
            "fetched parent id",
            project_pom(
                "<parent><groupId>org.test</groupId><artifactId>fpar</artifactId>\
                 <version>1.0</version><relativePath/></parent>",
                &corp,
                &dependency("a1", "1.0"),
            ),
            "nothing",
            transitive,
            &[("a1", &direct)],
        ),
        (
            "dependency id, mirror of the filled id, its parent at the declared URL",
            project_pom("", &corp, &dependency("libx", "1.0")),
            "pp",
            transitive,
            &[("lpar", &other), ("a3", &mirror)],
        ),
        (
            "dependency id serving a range",
            project_pom("", &corp, &dependency("libre", "1.0")),
            "nothing",
            transitive,
            &[("both", &other)],
        ),
    ];
    publish_pom(
        &direct,
        "fpar",
        &format!(
            "<properties><fid>fp</fid></properties>{}",
            repositories(&repository("${fid}", &direct_url, true, false))
        ),
    );
    for ((case, pom, mirror_of, config, held), maven) in cases
        .iter()
        .flat_map(|case| [(case, "3.9"), (case, "3.10")])
    {
        let case = format!("{case} {maven}");
        let dir = TempDir::new_in(base.path()).expect("case");
        let project = maven_project(&dir.path().join("p"), maven, pom);
        let home = settings_home(&central_server, &[("m", mirror_of)], &mirror_server);
        fs::write(home.path().join("config.toml"), config).expect("config.toml");
        assert_success(&run_raeva(&project, home.path(), &["sync"]), &case);
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
        for (artifact, repository) in held.iter() {
            let path = repository.join(format!("org/test/{artifact}"));
            let version = if *artifact == "both" { "2.0" } else { "1.0" };
            let pom = path.join(format!("{version}/{artifact}-{version}.pom"));
            let sha = BlobId::from_bytes(&fs::read(&pom).expect("read pom")).to_string();
            let sha = sha.rsplit(':').next().unwrap_or_default().to_string();
            assert!(lock.contains(&sha), "{case}: {artifact}: {lock}");
        }
        let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{case} frozen"));
    }
}

/// A POM that redeclares the request repository `corp` at another URL has
/// the BOMs imported after it read there in Maven 3.9.12, after the other
/// repositories, for a dependency whether the redeclaration is its own, its
/// parent's or a BOM's, while 3.10.0 keeps the request's `corp` for a
/// dependency. A BOM the project imports that redeclares `corp` has its
/// nested imports read there in both. Central, searched first, and a BOM
/// another build read before, which Maven 3.9.12 keeps, answer before the
/// redeclared URL. Where raeva does not read that URL, a dependency's
/// import Maven 3.9.12 reads there is refused. A redeclared `central` at
/// Central's other name reads the same files.
#[test]
fn a_redeclared_repository_id_serves_the_imports_after_it_as_in_maven() {
    let base = TempDir::new().expect("tempdir");
    let direct = base.path().join("direct");
    let (maven, other) = (direct.join("maven"), direct.join("other"));
    let direct_server = file_server(&direct);
    let url = |path: &str| format!("http://{}/{path}", direct_server.addr());
    let import = |artifact: &str| {
        format!(
            "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>"
        )
    };
    let managed = "<dependencies><dependency><groupId>org.test</groupId>\
                   <artifactId>managed</artifactId></dependency></dependencies>";
    let redeclare = format!(
        "<repositories>{}</repositories>",
        repository("corp", &url("other"), true, false)
    );
    for (repository, version) in [(&maven, "3.0"), (&other, "4.0")] {
        for artifact in ["bom", "bom2"] {
            publish_pom(
                repository,
                artifact,
                &format!(
                    "<dependencyManagement><dependencies>{}</dependencies>\
                     </dependencyManagement>",
                    dependency("managed", version)
                ),
            );
        }
        for version in ["3.0", "4.0"] {
            publish(repository, "managed", version);
        }
    }
    publish_pom(&maven, "rparent", &redeclare);
    publish_pom(&maven, "bomr", &format!("{redeclare}{}", import("bom2")));
    let lib = |artifact: &str, head: &str, body: &str| {
        let dir = maven.join(format!("org/test/{artifact}/1.0"));
        fs::create_dir_all(&dir).expect("create lib");
        fs::write(
            dir.join(format!("{artifact}-1.0.pom")),
            format!(
                "<project><modelVersion>4.0.0</modelVersion>{head}<groupId>org.test</groupId>\
                 <artifactId>{artifact}</artifactId><version>1.0</version>{body}{managed}\
                 </project>"
            ),
        )
        .expect("write lib");
        fs::write(dir.join(format!("{artifact}-1.0.jar")), artifact).expect("write jar");
    };
    lib("libr", "", &format!("{redeclare}{}", import("bom")));
    lib(
        "librp",
        "<parent><groupId>org.test</groupId><artifactId>rparent</artifactId>\
         <version>1.0</version></parent>",
        &import("bom"),
    );
    lib("librb", "", &import("bomr"));
    lib("libplain", "", &import("bom"));
    lib(
        "libre",
        "",
        &format!(
            "<properties><o.base>http://{}</o.base></properties><repositories>{}\
             </repositories>{}",
            direct_server.addr(),
            repository("corp", "${o.base}/other", true, false),
            import("bom")
        ),
    );
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let held = base.path().join("held");
    for artifact in ["bom", "bom2"] {
        publish_pom(
            &held,
            artifact,
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dependency("managed", "2.0")
            ),
        );
    }
    publish(&maven, "managed", "2.0");
    let held_server = file_server(&held);
    let project = |body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories>{}</repositories>\
             {body}</project>",
            repository("corp", &url("maven"), true, false)
        )
    };
    let managed_version = |lock: &str| {
        (lock.split("[[platforms.artifacts]]"))
            .find(|row| row.contains("artifact = \"managed\""))
            .and_then(|row| row.split("version = \"").nth(1))
            .and_then(|rest| rest.split('"').next())
            .map(str::to_string)
    };
    let transitive = "[security]\nallow_transitive_repositories = true\n";
    let depends = |artifacts: &[&str]| {
        let dependencies: String = (artifacts.iter())
            .map(|artifact| dependency(artifact, "1.0"))
            .collect();
        project(&format!("<dependencies>{dependencies}</dependencies>"))
    };
    // (case, pom, user config, whether Central holds the BOMs, (Maven
    // 3.9.12, Maven 3.10.0)), `None` for a refusal.
    let mut cases = Vec::new();
    for artifact in ["libr", "librp", "librb", "libre"] {
        let pom = depends(&[artifact]);
        cases.push((
            artifact,
            pom.clone(),
            transitive,
            false,
            (Some("4.0"), Some("3.0")),
        ));
        cases.push((artifact, pom, "", false, (None, Some("3.0"))));
    }
    let bomr = project(&format!("{}{managed}", import("bomr")));
    cases.push((
        "proj-bomr",
        bomr.clone(),
        "",
        false,
        (Some("4.0"), Some("4.0")),
    ));
    for config in [transitive, ""] {
        let libr = depends(&["libr"]);
        cases.push((
            "libr, Central",
            libr,
            config,
            true,
            (Some("2.0"), Some("3.0")),
        ));
        let plain_first = depends(&["libplain", "libr"]);
        let pair = (Some("3.0"), Some("3.0"));
        cases.push((
            "plain first, Central",
            plain_first.clone(),
            config,
            true,
            pair,
        ));
        cases.push(("plain first", plain_first, config, false, pair));
        let libr_first = depends(&["libr", "libplain"]);
        let pair = (Some("2.0"), Some("3.0"));
        cases.push(("libr first, Central", libr_first, config, true, pair));
    }
    cases.push((
        "proj-bomr, Central",
        bomr,
        "",
        true,
        (Some("2.0"), Some("2.0")),
    ));
    for (case, pom, config, held, (in_39, in_310)) in &cases {
        for (maven, expected) in [("3.9", in_39), ("3.10", in_310)] {
            let case = format!("{case} {maven} {config:?}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, pom);
            let central = if *held { &held_server } else { &central_server };
            let home = settings_home(central, &[], central);
            fs::write(home.path().join("config.toml"), config).expect("config.toml");
            let output = run_raeva(&project, home.path(), &["sync"]);
            let Some(expected) = expected else {
                assert_eq!(output.status.code(), Some(3), "{case}: {}", stderr(&output));
                assert!(
                    stderr(&output)
                        .contains("redeclares repository 'corp' at a URL raeva does not read"),
                    "{case}: {}",
                    stderr(&output)
                );
                continue;
            };
            assert_success(&output, &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            assert_eq!(
                managed_version(&lock).as_deref(),
                Some(*expected),
                "{case}: {lock}"
            );
            let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
            assert_success(&output, &format!("{case} frozen"));
        }
    }
    // A dependency that redeclares `central` at Central's other name, with
    // no mirror of Central, in the default configuration. Central's
    // requests keep their path.
    let alias = base.path().join("alias");
    publish_pom(
        &alias.join("maven2"),
        "bomc",
        &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dependency("managed", "2.0")
        ),
    );
    let alias_server = file_server(&alias);
    lib(
        "libc",
        "",
        &format!(
            "<repositories>{}</repositories>{}",
            repository(
                "central",
                "https://repo.maven.apache.org/maven2",
                true,
                false
            ),
            import("bomc")
        ),
    );
    for maven in ["3.9", "3.10"] {
        let dir = TempDir::new_in(base.path()).expect("case");
        let project = maven_project(&dir.path().join("p"), maven, &depends(&["libc"]));
        let home = TempDir::new().expect("home");
        fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
        fs::write(home.path().join(".m2/settings.xml"), "<settings/>").expect("settings");
        let sync = |args: &[&str]| {
            (raeva_command(&project, home.path()))
                .env(rv_repo::CENTRAL_TEST_ENV, alias_server.addr().to_string())
                .args(args)
                .output()
                .expect("run raeva")
        };
        assert_success(&sync(&["sync"]), &format!("central alias {maven}"));
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
        assert_eq!(
            managed_version(&lock).as_deref(),
            Some("2.0"),
            "{maven}: {lock}"
        );
        assert_success(
            &sync(&["sync", "--frozen"]),
            &format!("central alias {maven} frozen"),
        );
    }
}

/// A dependency's BOM that declares a copy of Central raeva does not read,
/// then Central, has its nested imports searched in that copy first in
/// Maven 3.9.12, whose super POM `central` moves the request's Central
/// behind the BOM's repositories. A release on Central is the copy's too,
/// so raeva reads it from Central; one a repository raeva reads holds
/// before Central is refused, as the copy may hold another. Maven 3.10.0
/// keeps Central ahead and reads it there.
#[test]
fn a_release_past_a_copy_of_central_is_read_from_central() {
    let base = TempDir::new().expect("tempdir");
    let direct = base.path().join("direct");
    let direct_server = file_server(&direct);
    let url = |path: &str| format!("http://{}/{path}", direct_server.addr());
    let central = base.path().join("central");
    let central_server = file_server(&central);
    let maven = direct.join("maven");
    let import = |artifact: &str| {
        format!(
            "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>"
        )
    };
    let managing = |version: &str| {
        format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            dependency("managed", version)
        )
    };
    publish_pom(&central.join("maven2"), "bomn", &managing("2.0"));
    publish_pom(&direct.join("copy"), "bomn", &managing("2.0"));
    publish_pom(&direct.join("third"), "bomn", &managing("4.0"));
    for version in ["2.0", "4.0"] {
        publish(&maven, "managed", version);
    }
    let repositories = |ids: &[&str]| {
        let declared: String = (ids.iter())
            .map(|id| match *id {
                "maven-central" => repository(id, "https://repo1.maven.org/maven2", true, false),
                _ => repository(id, &url(id), true, false),
            })
            .collect();
        format!("<repositories>{declared}</repositories>")
    };
    let managed = "<dependencies><dependency><groupId>org.test</groupId>\
                   <artifactId>managed</artifactId></dependency></dependencies>";
    for (bom, lib, ids) in [
        ("bomg", "libg", &["copy", "maven-central"][..]),
        ("bomt", "libt", &["copy", "third", "maven-central"][..]),
    ] {
        publish_pom(
            &maven,
            bom,
            &format!("{}{}", repositories(ids), import("bomn")),
        );
        publish_pom(
            &maven,
            lib,
            &format!("{}{}{managed}", repositories(ids), import(bom)),
        );
        publish(&maven, "managed", "2.0");
        fs::write(maven.join(format!("org/test/{lib}/1.0/{lib}-1.0.jar")), lib).expect("jar");
    }
    let allow_third = format!(
        "[security]\ntransitive_repository_allowlist = [\"{}\"]\n",
        url("third/")
    );
    // (dependency, user config, (Maven 3.9.12, Maven 3.10.0)), `None` for a
    // refusal.
    let cases = [
        ("libg", String::new(), (Some("2.0"), Some("2.0"))),
        ("libt", allow_third, (None, Some("2.0"))),
    ];
    for (lib, config, (in_39, in_310)) in &cases {
        for (maven_version, expected) in [("3.9", in_39), ("3.10", in_310)] {
            let case = format!("{lib} {maven_version}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let pom = format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>app</artifactId><version>1</version><repositories>{}\
                 </repositories><dependencies>{}</dependencies></project>",
                repository("corp", &url("maven"), true, false),
                dependency(lib, "1.0")
            );
            let project = maven_project(&dir.path().join("p"), maven_version, &pom);
            let home = TempDir::new().expect("home");
            fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
            fs::write(home.path().join(".m2/settings.xml"), "<settings/>").expect("settings");
            fs::write(home.path().join("config.toml"), config).expect("config.toml");
            let sync = |args: &[&str]| {
                (raeva_command(&project, home.path()))
                    .env(rv_repo::CENTRAL_TEST_ENV, central_server.addr().to_string())
                    .args(args)
                    .output()
                    .expect("run raeva")
            };
            let output = sync(&["sync"]);
            let Some(expected) = expected else {
                assert_eq!(output.status.code(), Some(3), "{case}: {}", stderr(&output));
                assert!(
                    stderr(&output).contains(
                        "org.test:bomn:1.0:pom is in none of the repositories Maven 3.9.12 \
                         searches before repository 'copy', which raeva does not read"
                    ),
                    "{case}: {}",
                    stderr(&output)
                );
                continue;
            };
            assert_success(&output, &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            let managed_row = (lock.split("[[platforms.artifacts]]"))
                .find(|row| row.contains("artifact = \"managed\""))
                .unwrap_or_default();
            assert!(
                managed_row.contains(&format!("version = \"{expected}\"")),
                "{case}: {lock}"
            );
            assert_success(&sync(&["sync", "--frozen"]), &format!("{case} frozen"));
        }
    }
}

/// A BOM the project imports declares `old`, and its nested BOM comes
/// through the mirror of `old`, as in Maven. The lock would record `old`,
/// which no one but the BOM declares, so the sync is refused and names the
/// POM, the repository and the mirror; once the project declares `old`
/// too, it locks. A nested BOM the project's own repository holds is read
/// there first, and nothing is refused. A BOM, or a dependency, that
/// declares `central` at any of Central's URLs behind the mirror of
/// `central` reads Central there, as the project does, and locks.
#[test]
fn a_nested_bom_through_a_mirror_of_an_imported_boms_repository() {
    let base = TempDir::new().expect("tempdir");
    let (direct, mirror) = (base.path().join("direct"), base.path().join("mirror"));
    let (maven, old) = (direct.join("maven"), direct.join("old"));
    let direct_server = file_server(&direct);
    let mirror_server = file_server(&mirror);
    let url = |path: &str| format!("http://{}/{path}", direct_server.addr());
    let import = |artifact: &str| {
        format!(
            "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>{artifact}</artifactId><version>1.0</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>"
        )
    };
    let bom = |repository: &Path, artifact: &str, version: &str| {
        publish_pom(
            repository,
            artifact,
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dependency("managed", version)
            ),
        );
    };
    bom(&old, "bomn", "3.0");
    bom(&mirror, "bomn", "2.0");
    bom(&maven, "bomc", "4.0");
    bom(&mirror, "bomc", "2.0");
    let old_repository = repository("old", &url("old"), true, false);
    for (artifact, nested) in [("boml", "bomn"), ("bomlc", "bomc")] {
        publish_pom(
            &maven,
            artifact,
            &format!(
                "<repositories>{old_repository}</repositories>{}",
                import(nested)
            ),
        );
    }
    for version in ["2.0", "3.0", "4.0"] {
        publish(&maven, "managed", version);
    }
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    bom(&central, "bomk", "2.0");
    let central_urls = [
        "https://repo.maven.apache.org/maven2",
        "https://repo1.maven.org/maven2",
        "http://repo1.maven.org/maven2",
        "http://repo.maven.apache.org/maven2",
    ];
    for (index, central_url) in central_urls.iter().enumerate() {
        let declares = format!(
            "<repositories>{}</repositories>{}",
            repository("central", central_url, true, false),
            import("bomk")
        );
        publish_pom(&maven, &format!("bomcen{index}"), &declares);
        publish_pom(
            &maven,
            &format!("libcen{index}"),
            &format!(
                "{declares}<dependencies><dependency><groupId>org.test</groupId>\
                 <artifactId>managed</artifactId></dependency></dependencies>"
            ),
        );
    }
    let project = |repositories: &str, bom: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories>{}{repositories}\
             </repositories>{}<dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>managed</artifactId></dependency></dependencies></project>",
            repository("corp", &url("maven"), true, false),
            import(bom)
        )
    };
    // (case, pom, the managed version, `None` for the refusal)
    let mut cases = vec![
        ("bom repository only".to_string(), project("", "boml"), None),
        (
            "project declares it too".to_string(),
            project(&old_repository, "boml"),
            Some("2.0"),
        ),
        (
            "nested BOM in corp".to_string(),
            project("", "bomlc"),
            Some("4.0"),
        ),
    ];
    for (index, central_url) in central_urls.iter().enumerate() {
        let bom = format!("bomcen{index}");
        cases.push((
            format!("BOM declares central at {central_url}"),
            project("", &bom),
            Some("2.0"),
        ));
        let dependency = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><repositories>{}</repositories>\
             <dependencies><dependency><groupId>org.test</groupId>\
             <artifactId>libcen{index}</artifactId><version>1.0</version><type>pom</type>\
             </dependency></dependencies></project>",
            repository("corp", &url("maven"), true, false)
        );
        cases.push((
            format!("dependency declares central at {central_url}"),
            dependency,
            Some("2.0"),
        ));
    }
    for ((case, pom, expected), maven) in cases
        .iter()
        .flat_map(|case| [(case, "3.9"), (case, "3.10")])
    {
        let case = format!("{case} {maven}");
        let dir = TempDir::new_in(base.path()).expect("case");
        let project = maven_project(&dir.path().join("p"), maven, pom);
        let home = settings_home(&central_server, &[("m", "old")], &mirror_server);
        let output = run_raeva(&project, home.path(), &["sync"]);
        let Some(expected) = expected else {
            assert_eq!(output.status.code(), Some(3), "{case}: {}", stderr(&output));
            assert!(
                stderr(&output).contains(
                    "org.test:bomn:1.0 comes from repository 'old', which only the imported \
                     BOM org.test:boml:1.0 declares, through mirror 'm'"
                ),
                "{case}: {}",
                stderr(&output)
            );
            continue;
        };
        assert_success(&output, &case);
        let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
        let row = (lock.split("[[platforms.artifacts]]"))
            .find(|row| row.contains("artifact = \"managed\""))
            .unwrap_or_default();
        assert!(
            row.contains(&format!("version = \"{expected}\"")),
            "{case}: {lock}"
        );
        let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{case} frozen"));
        let cold = settings_home(&central_server, &[("m", "old")], &mirror_server);
        let output = run_raeva(&project, cold.path(), &["sync", "--frozen"]);
        assert_success(&output, &format!("{case} frozen from an empty store"));
    }
}

/// A POM repository whose `<id>` takes an environment variable raeva
/// treats as unset is refused where the project or a parent, local or
/// fetched, declares it and a mirror names an id: Maven matches the mirrors
/// against the value raeva does not know. A dependency's POM's is dropped
/// in the default configuration.
/// A layout other than `default` once interpolated is ignored in any POM
/// unless a mirror serves it, through which Maven reaches it; one that
/// takes a `${...}` serves a parent lookup, which reads it as written,
/// only through a mirror of every layout.
#[test]
fn a_pom_repository_id_or_layout_raeva_cannot_follow_is_refused_or_ignored() {
    let base = TempDir::new().expect("tempdir");
    let (mirror, direct) = (base.path().join("mirror"), base.path().join("direct"));
    for repository in [&mirror, &direct] {
        publish(repository, "managed", "3.0");
    }
    publish(&mirror, "onlyold", "1.0");
    publish(&direct.join("old"), "onlyold", "1.0");
    publish_pom(&mirror, "mparent", "");
    publish_pom(&direct, "parent", "");
    let (mirror_server, direct_server) = (file_server(&mirror), file_server(&direct));
    publish_pom(
        &direct,
        "rparent",
        &format!(
            "<repositories>{}</repositories>",
            repository(
                "${env.RV_TEST_RID}",
                &format!("http://{}", direct_server.addr()),
                true,
                false
            )
        ),
    );
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let direct_url = format!("http://{}", direct_server.addr());
    let old = |id: &str, layout: &str| {
        format!("<repository><id>{id}</id><url>{direct_url}/old</url>{layout}</repository>")
    };
    let lib_of = |layout: &str| match layout {
        "" => "libid",
        "<layout>legacy</layout>" => "liblegacy",
        _ => "libexpr",
    };
    for (id, layout) in [
        ("${rid}", ""),
        ("old", "<layout>legacy</layout>"),
        ("old", "<layout>${lay}</layout>"),
    ] {
        let name = lib_of(layout);
        let lib = direct.join(format!("org/test/{name}/1.0"));
        fs::create_dir_all(&lib).expect("create lib");
        fs::write(
            lib.join(format!("{name}-1.0.pom")),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                 <artifactId>{name}</artifactId><version>1.0</version><properties>\
                 <rid>old</rid><lay>default</lay></properties><repositories>{}</repositories>\
                 <dependencies>{}</dependencies></project>",
                old(id, layout),
                dependency("onlyold", "1.0"),
            ),
        )
        .expect("write lib");
        fs::write(lib.join(format!("{name}-1.0.jar")), "lib").expect("write jar");
    }
    let corp = repository("corp", &direct_url, true, false);
    let project_pom = |head: &str, repositories: &str, dependencies: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{head}<groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version><properties><rid>corp</rid>\
             <lay>default</lay><lay2>canarylayout</lay2></properties><repositories>{corp}\
             {repositories}</repositories>\
             <dependencies>{dependencies}</dependencies></project>"
        )
    };
    let parent = "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
                  <version>1.0</version><relativePath/></parent>";
    let fetched_parent = "<parent><groupId>org.test</groupId><artifactId>rparent</artifactId>\
                          <version>1.0</version><relativePath/></parent>";
    let local_parent = "<parent><groupId>org.test</groupId><artifactId>lp</artifactId>\
                        <version>1</version><relativePath>../lp/pom.xml</relativePath></parent>";
    let managed = dependency("managed", "3.0");
    for (head, repositories, refused) in [
        (
            fetched_parent,
            String::new(),
            "the <id> of repository '${env.RV_TEST_RID}', which a fetched parent",
        ),
        (local_parent, String::new(), "the id of a repository"),
        (
            "",
            repository("${env.RV_TEST_RID}", &direct_url, true, false),
            "the id of a repository",
        ),
        (
            parent,
            repository("${env.RV_TEST_RID}", &direct_url, true, false),
            "the id of a repository",
        ),
    ] {
        let pom = project_pom(head, &repositories, &managed);
        for maven in ["3.9", "3.10"] {
            let case = format!("{head} {repositories} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            fs::create_dir_all(dir.path().join("lp")).expect("create parent");
            fs::write(
                dir.path().join("lp/pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
                     <artifactId>lp</artifactId><version>1</version><packaging>pom\
                     </packaging><repositories>{}</repositories></project>",
                    repository("${env.RV_TEST_RID}", &direct_url, true, false)
                ),
            )
            .expect("write parent");
            let home = mirror_home(&central_server, "*,!corp,!central", &mirror_server);
            let output = raeva_command(&project, home.path())
                .env("RV_TEST_RID", "corp")
                .arg("sync")
                .output()
                .expect("run raeva");
            crate::common::assert_status(&output, 3, &case);
            let err = stderr(&output);
            assert!(err.contains(refused), "{case}: {err}");
            assert!(!project.join("raeva.lock").exists(), "{case}");
        }
    }
    // Only `old` holds `onlyold`, unmirrored.
    for layout in ["<layout>default</layout>", "<layout>${lay}</layout>"] {
        let pom = project_pom("", &old("old", layout), &dependency("onlyold", "1.0"));
        for maven in ["3.9", "3.10"] {
            let case = format!("{layout} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            let home = mirror_home(&central_server, "nothing", &mirror_server);
            assert_success(&run_raeva(&project, home.path(), &["sync"]), &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            assert!(
                lock.contains(&format!("{direct_url}/old")),
                "{case}: {lock}"
            );
            let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
            assert_success(&output, &format!("{case} frozen"));
        }
    }
    // The parent lookup reads `${lay}` as written, which only a mirror of
    // every layout serves.
    let pom = project_pom(
        "<parent><groupId>org.test</groupId><artifactId>mparent</artifactId>\
         <version>1.0</version><relativePath/></parent>",
        &old("old", "<layout>${lay}</layout>"),
        &managed,
    );
    for ((layouts, found), maven) in [("*", true), ("default,legacy", false)]
        .into_iter()
        .flat_map(|row| [(row, "3.9"), (row, "3.10")])
    {
        let dir = TempDir::new_in(base.path()).expect("case");
        let project = maven_project(&dir.path().join("p"), maven, &pom);
        let home = mirror_home(&central_server, "*,!corp,!central", &mirror_server);
        let settings = home.path().join(".m2/settings.xml");
        let xml = fs::read_to_string(&settings).expect("read settings");
        let xml = xml.replace(
            "<mirrorOf>*,!corp,!central</mirrorOf>",
            &format!(
                "<mirrorOf>*,!corp,!central</mirrorOf><mirrorOfLayouts>{layouts}\
                 </mirrorOfLayouts>"
            ),
        );
        fs::write(&settings, xml).expect("write settings");
        let output = run_raeva(&project, home.path(), &["sync"]);
        if found {
            assert_success(&output, layouts);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            assert!(lock.contains(&pom_sha256(&mirror, "mparent")), "{lock}");
        } else {
            crate::common::assert_status(&output, 5, layouts);
            let err = stderr(&output);
            assert!(
                err.contains("Parent POM not found: org.test:mparent:1.0"),
                "{err}"
            );
        }
    }
    // An imported BOM's is ignored, as a dependency's is.
    publish_pom(
        &direct,
        "ibom",
        &format!(
            "<properties><rid>corp</rid></properties><repositories>{}</repositories>\
             <dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
            repository("${rid}", &direct_url, true, false),
            dependency("managed", "3.0")
        ),
    );
    let pom = project_pom("", "", "").replace(
        "<dependencies></dependencies>",
        "<dependencyManagement><dependencies><dependency><groupId>org.test</groupId>\
         <artifactId>ibom</artifactId><version>1.0</version><type>pom</type><scope>import\
         </scope></dependency></dependencies></dependencyManagement><dependencies>\
         <dependency><groupId>org.test</groupId><artifactId>managed</artifactId>\
         </dependency></dependencies>",
    );
    let dir = TempDir::new_in(base.path()).expect("case");
    let project = maven_project(&dir.path().join("p"), "3.9", &pom);
    let home = mirror_home(&central_server, "*,!corp,!central", &mirror_server);
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "imported BOM");
    // The project's legacy repository, or one whose layout the POM fills
    // in, serves `onlyold` through a mirror, and is ignored without one; a
    // layout left as `${nolay}` names none, which no mirror serves.
    for (layout, mirror_of, ignored) in [
        ("legacy", "*,!corp,!central", None),
        ("legacy", "nothing", Some("<layout> is 'legacy'")),
        ("${lay}", "*,!corp,!central", None),
        (
            "${nolay}",
            "*,!corp,!central",
            Some("<layout> is '${nolay}', which names no"),
        ),
        (
            "${lay2}",
            "nothing",
            Some("<layout> takes '${lay2}', which is not 'default' once interpolated"),
        ),
    ] {
        let pom = project_pom(
            "",
            &old("old", &format!("<layout>{layout}</layout>")),
            &dependency("onlyold", "1.0"),
        );
        let case = format!("{layout} {mirror_of}");
        let dir = TempDir::new_in(base.path()).expect("case");
        let project = maven_project(&dir.path().join("p"), "3.9", &pom);
        let home = mirror_home(&central_server, mirror_of, &mirror_server);
        let output = run_raeva(&project, home.path(), &["sync"]);
        let err = stderr(&output);
        let Some(ignored) = ignored else {
            assert_success(&output, &case);
            continue;
        };
        assert!(!output.status.success(), "{case}: {err}");
        assert!(
            err.contains(&format!(
                "ignoring repository 'old' that the project declares because its {ignored}"
            )),
            "{case}: {err}"
        );
        assert!(!err.contains("canarylayout"), "{case}: {err}");
    }
    // The repository whose id the POM fills in serves `onlyold` through the
    // mirror, as does the legacy one; unmirrored, the legacy one is ignored
    // and nothing else holds it.
    for (layout, mirror_of, served) in [
        ("", "*,!corp,!central", true),
        ("<layout>legacy</layout>", "*,!corp,!central", true),
        ("<layout>legacy</layout>", "nothing", false),
        ("<layout>${lay}</layout>", "*,!corp,!central", true),
    ] {
        let pom = project_pom("", "", &dependency(lib_of(layout), "1.0"));
        for maven in ["3.9", "3.10"] {
            let case = format!("fetched {layout} {mirror_of} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            let home = mirror_home(&central_server, mirror_of, &mirror_server);
            fs::write(
                home.path().join("config.toml"),
                "[security]\nallow_transitive_repositories = true\n",
            )
            .expect("write config");
            let output = run_raeva(&project, home.path(), &["sync"]);
            let err = stderr(&output);
            if served {
                assert_success(&output, &case);
                let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
                assert!(lock.contains("onlyold"), "{case}: {lock}");
                continue;
            }
            assert!(!output.status.success(), "{case}: {err}");
            assert!(
                err.contains("ignoring repository") && err.contains("that a fetched POM declares"),
                "{case}: {err}"
            );
            assert!(!project.join("raeva.lock").exists(), "{case}");
        }
    }
}

/// Maven injects an active settings.xml profile into the project's model,
/// so a repository URL the file leaves as `${repo.base}/maven` takes the
/// profile's own property, which wins over the POM's, and replaces a POM
/// repository of its id. As with a POM's, the project's parent and
/// imported BOMs go through the mirror of the URL as written and its
/// dependencies through that of the URL once interpolated: one `*` mirror
/// serves both, no mirror leaves both to the URL filled in, and a mirror
/// of only the URL as written splits them and is refused. The versions
/// are those Maven 3.9.12 and 3.10.0 lock. Maven fills it in once for the
/// whole build, so raeva answers it only beside no other repository of an
/// active profile.
#[test]
fn a_settings_repository_the_project_fills_in_resolves_as_in_maven() {
    let base = TempDir::new().expect("tempdir");
    let (mirror, direct) = (base.path().join("mirror"), base.path().join("direct"));
    let maven_repo = direct.join("maven");
    for (repository, managed) in [(&mirror, "2.0"), (&maven_repo, "3.0")] {
        publish_pom(
            repository,
            "bom",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dependency("managed", managed)
            ),
        );
        for version in ["2.0", "3.0"] {
            publish(repository, "managed", version);
        }
    }
    publish_pom(&mirror, "parent", "");
    let (mirror_server, direct_server) = (file_server(&mirror), file_server(&direct));
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let (direct_url, mirror_url) = (
        format!("http://{}", direct_server.addr()),
        format!("http://{}", mirror_server.addr()),
    );
    let parent = "<parent><groupId>org.test</groupId><artifactId>parent</artifactId>\
                  <version>1.0</version><relativePath/></parent>";
    let pom_property = format!("<properties><repo.base>{mirror_url}</repo.base></properties>");
    let pom_repository = format!(
        "<repositories>{}</repositories>",
        repository("corp", &format!("{mirror_url}/"), true, false)
    );
    let pom_of = |head: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{head}<groupId>org.test</groupId>\
             <artifactId>app</artifactId><version>1</version>{body}<dependencyManagement>\
             <dependencies><dependency><groupId>org.test</groupId><artifactId>bom\
             </artifactId><version>1.0</version><type>pom</type><scope>import</scope>\
             </dependency></dependencies></dependencyManagement><dependencies>\
             <dependency><groupId>org.test</groupId><artifactId>managed</artifactId>\
             </dependency></dependencies></project>"
        )
    };
    let home_with = |mirror_of: Option<&str>, base: &str, path: &str| {
        let mirrors: Vec<(&str, &str)> = mirror_of.map(|of| ("m", of)).into_iter().collect();
        let home = settings_home(&central_server, &mirrors, &mirror_server);
        let settings = home.path().join(".m2/settings.xml");
        let xml = fs::read_to_string(&settings).expect("read settings");
        let xml = xml.replace(
            "</settings>",
            &format!(
                "<profiles><profile><id>sp</id><properties><repo.base>{base}</repo.base>\
                 </properties><repositories><repository><id>corp</id>\
                 <url>${{repo.base}}/{path}</url></repository></repositories></profile>\
                 </profiles><activeProfiles><activeProfile>sp</activeProfile>\
                 </activeProfiles></settings>"
            ),
        );
        fs::write(&settings, xml).expect("write settings");
        home
    };
    // (mirrorOf, POM head, POM body, the managed version locked)
    for (mirror_of, head, body, locked) in [
        (Some("*"), "", "", Some("2.0")),
        (None, "", "", Some("3.0")),
        (None, "", pom_property.as_str(), Some("3.0")),
        (None, "", pom_repository.as_str(), Some("3.0")),
        (Some("*"), parent, "", Some("2.0")),
        (Some("external:*,!central"), "", "", None),
    ] {
        let pom = pom_of(head, body);
        for maven in ["3.9", "3.10"] {
            let case = format!("{mirror_of:?} {head} {body} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom);
            let home_for = || home_with(mirror_of, &direct_url, "maven");
            let output = run_raeva(&project, home_for().path(), &["sync"]);
            let Some(locked) = locked else {
                crate::common::assert_status(&output, 3, &case);
                let err = stderr(&output);
                assert!(err.contains("repository 'corp'"), "{case}: {err}");
                assert!(!project.join("raeva.lock").exists(), "{case}");
                continue;
            };
            assert_success(&output, &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            assert!(
                lock.contains(&format!("org.test:managed:{locked}")),
                "{case}: {lock}"
            );
            let served = if mirror_of.is_some() {
                &mirror
            } else {
                &maven_repo
            };
            assert!(lock.contains(&pom_sha256(served, "bom")), "{case}: {lock}");
            if !head.is_empty() {
                assert!(
                    lock.contains(&pom_sha256(&mirror, "parent")),
                    "{case}: {lock}"
                );
            }
            let output = run_raeva(&project, home_for().path(), &["sync", "--frozen"]);
            assert_success(&output, &format!("{case} cold frozen"));
        }
    }
    // The lock covers the URL as written and the property that fills it
    // in; a secret the property carries is refused and kept out of sight.
    let dir = TempDir::new_in(base.path()).expect("case");
    let project = maven_project(&dir.path().join("p"), "3.9", &pom_of("", ""));
    let home = home_with(None, &direct_url, "maven");
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "lock");
    for (base, path) in [
        (mirror_url.as_str(), "maven"),
        (direct_url.as_str(), "other"),
    ] {
        let output = run_raeva(
            &project,
            home_with(None, base, path).path(),
            &["sync", "--frozen"],
        );
        crate::common::assert_status(&output, 7, &format!("{base}/{path}"));
    }
    fs::remove_file(project.join("raeva.lock")).expect("remove lock");
    let secret = direct_url.replace("http://", "http://u:idref-secret@");
    let output = run_raeva(
        &project,
        home_with(None, &secret, "maven").path(),
        &["sync"],
    );
    crate::common::assert_status(&output, 3, "userinfo");
    assert!(
        !stderr(&output).contains("idref-secret"),
        "{}",
        stderr(&output)
    );
    assert!(!project.join("raeva.lock").exists());
    let home_profiles = |mirrors: &[(&str, &str)], profiles: &str, active: &[&str]| {
        let home = settings_home(&central_server, mirrors, &mirror_server);
        let settings = home.path().join(".m2/settings.xml");
        let xml = fs::read_to_string(&settings).expect("read settings");
        let active: String = (active.iter())
            .map(|id| format!("<activeProfile>{id}</activeProfile>"))
            .collect();
        let xml = xml.replace(
            "</settings>",
            &format!(
                "<profiles>{profiles}</profiles><activeProfiles>{active}</activeProfiles>\
                 </settings>"
            ),
        );
        fs::write(&settings, xml).expect("write settings");
        home
    };
    let literal = format!(
        "<profile><id>sp1</id><repositories><repository><id>corp</id><url>{mirror_url}/</url>\
         </repository></repositories></profile>"
    );
    let model = |id: &str, activation: &str, policy: &str| {
        format!(
            "<profile><id>{id}</id>{activation}<properties><repo.base>{direct_url}</repo.base>\
             </properties><repositories><repository><id>corp</id>\
             <url>${{repo.base}}/maven</url>{policy}</repository></repositories></profile>"
        )
    };
    // A profile `<activeProfiles>` names but `-P` turns off leaves Maven's
    // request copy, as written, which a mirror of its id serves.
    let dir = TempDir::new_in(base.path()).expect("case");
    let project = maven_project(&dir.path().join("p"), "3.9", &pom_of("", ""));
    let home = home_profiles(&[("m", "corp")], &model("sp2", "", ""), &["sp2"]);
    assert_success(
        &run_raeva(&project, home.path(), &["-P!sp2", "sync"]),
        "deactivated",
    );
    let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
    assert!(
        lock.contains(&pom_sha256(&mirror, "bom")),
        "deactivated: {lock}"
    );
    // Maven orders the active profiles' repositories by profile, which
    // raeva does not follow for one each project fills in: it refuses one
    // that shares its id with another, or comes beside a literal one, and
    // a request copy whose layout holds a `${...}`.
    let other = format!(
        "<profile><id>sp1</id><repositories><repository><id>other</id>\
         <url>{mirror_url}/</url></repository></repositories></profile>"
    );
    let expression_layout = "<profile><id>sp2</id><properties><lay>default</lay></properties>\
                             <repositories><repository><id>corp</id><url>http://unused.invalid/\
                             </url><layout>${lay}</layout></repository></repositories></profile>";
    for (case, profiles, args, refused) in [
        (
            "later",
            format!("{literal}{}", model("sp2", "", "")),
            &["sync"][..],
            "another repository of an active profile has its id",
        ),
        (
            "earlier",
            format!("{}{literal}", model("sp2", "", "")),
            &["sync"],
            "another repository of an active profile has its id",
        ),
        (
            "beside a literal",
            format!("{other}{}", model("sp2", "", "")),
            &["-Psp1,sp2", "sync"],
            "declares the literal repository 'other'",
        ),
        (
            "request copy layout",
            expression_layout.to_string(),
            &["-P!sp2", "sync"],
            "in the profile 'sp2' that <activeProfiles> names, the <layout> of repository 'corp'",
        ),
    ] {
        for maven in ["3.9", "3.10"] {
            let case = format!("{case} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = maven_project(&dir.path().join("p"), maven, &pom_of("", ""));
            let home = home_profiles(&[("m", "corp")], &profiles, &["sp1", "sp2"]);
            let output = run_raeva(&project, home.path(), args);
            crate::common::assert_status(&output, 3, &case);
            let err = stderr(&output);
            assert!(err.contains(refused), "{case}: {err}");
            assert!(!project.join("raeva.lock").exists(), "{case}");
        }
    }
    // The lock covers the repository's policies too.
    let dir = TempDir::new_in(base.path()).expect("case");
    let project = maven_project(&dir.path().join("p"), "3.9", &pom_of("", ""));
    let home = home_profiles(&[], &model("sp2", "", ""), &["sp2"]);
    assert_success(&run_raeva(&project, home.path(), &["sync"]), "policy lock");
    let policy = "<snapshots><enabled>false</enabled></snapshots>";
    let home = home_profiles(&[], &model("sp2", "", policy), &["sp2"]);
    let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
    crate::common::assert_status(&output, 7, "policy");
    // A profile that only such a repository makes relevant is not left
    // inactive where its activation reads what raeva does not.
    let activation = "<activation><property><name>java.vendor</name><value>Nobody</value>\
                      </property></activation>";
    let home = home_profiles(&[], &model("sp2", activation, ""), &[]);
    let output = run_raeva(&project, home.path(), &["sync"]);
    let err = stderr(&output);
    assert!(!output.status.success(), "{err}");
    assert!(err.contains("settings.xml profile sp2"), "{err}");
}

/// Maven fills a settings.xml repository's `${repo.base}` in once for the
/// whole reactor, from the first project that sets it, and every project
/// reads that one. A reactor whose projects fill it in alike, as from the
/// profile's own property, locks what Maven 3.9.12 and 3.10.0 do; one whose
/// modules fill it in apart, whichever comes first, or whose root leaves it
/// unfilled, is refused, as is one where only one module's URL would split
/// between mirror routes.
#[test]
fn a_settings_repository_a_reactor_fills_in_locks_only_when_every_project_fills_it_alike() {
    let base = TempDir::new().expect("tempdir");
    let (mirror, direct) = (base.path().join("mirror"), base.path().join("direct"));
    let maven_repo = direct.join("maven");
    for (repository, managed) in [(&mirror, "2.0"), (&maven_repo, "3.0")] {
        publish_pom(
            repository,
            "bom",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dependency("managed", managed)
            ),
        );
        for version in ["2.0", "3.0"] {
            publish(repository, "managed", version);
        }
    }
    let (mirror_server, direct_server) = (file_server(&mirror), file_server(&direct));
    let central = base.path().join("central");
    fs::create_dir_all(&central).expect("create central");
    let central_server = file_server(&central);
    let direct_url = format!("http://{}", direct_server.addr());
    let property = |value: &str| format!("<properties><repo.base>{value}</repo.base></properties>");
    let module = |name: &str, body: &str| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version></parent>\
             <artifactId>{name}</artifactId>{body}<dependencyManagement><dependencies>\
             <dependency><groupId>org.test</groupId><artifactId>bom</artifactId>\
             <version>1.0</version><type>pom</type><scope>import</scope></dependency>\
             </dependencies></dependencyManagement><dependencies><dependency>\
             <groupId>org.test</groupId><artifactId>managed</artifactId></dependency>\
             </dependencies></project>"
        )
    };
    let reactor = |dir: &Path, maven: &str, order: [&str; 2], root: &str, a: &str, b: &str| {
        let modules: String = (order.iter())
            .map(|name| format!("<module>{name}</module>"))
            .collect();
        let root = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.test</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules>{modules}</modules>{root}</project>"
        );
        let project = maven_project(&dir.join("p"), maven, &root);
        for (name, body) in [("a", a), ("b", b)] {
            fs::create_dir_all(project.join(name)).expect("create module");
            fs::write(project.join(name).join("pom.xml"), module(name, body))
                .expect("write module");
        }
        project
    };
    let home_with = |mirror_of: Option<&str>, profile: &str| {
        let mirrors: Vec<(&str, &str)> = mirror_of.map(|of| ("m", of)).into_iter().collect();
        let home = settings_home(&central_server, &mirrors, &mirror_server);
        let settings = home.path().join(".m2/settings.xml");
        let xml = fs::read_to_string(&settings).expect("read settings");
        let xml = xml.replace(
            "</settings>",
            &format!(
                "<profiles><profile><id>sp</id>{profile}<repositories><repository>\
                 <id>corp</id><url>${{repo.base}}/maven</url></repository></repositories>\
                 </profile></profiles><activeProfiles><activeProfile>sp</activeProfile>\
                 </activeProfiles></settings>"
            ),
        );
        fs::write(&settings, xml).expect("write settings");
        home
    };
    let own = property(&direct_url);
    for (mirror_of, locked) in [(None, "3.0"), (Some("*"), "2.0")] {
        for maven in ["3.9", "3.10"] {
            let case = format!("{mirror_of:?} {maven}");
            let dir = TempDir::new_in(base.path()).expect("case");
            let project = reactor(dir.path(), maven, ["a", "b"], "", "", "");
            let home = home_with(mirror_of, &own);
            assert_success(&run_raeva(&project, home.path(), &["sync"]), &case);
            let lock = fs::read_to_string(project.join("raeva.lock")).expect("read lock");
            assert_eq!(
                lock.matches(&format!("org.test:managed:{locked}")).count(),
                2,
                "{case}: {lock}"
            );
            let served = if locked == "2.0" {
                &mirror
            } else {
                &maven_repo
            };
            assert!(lock.contains(&pom_sha256(served, "bom")), "{case}: {lock}");
            let output = run_raeva(&project, home.path(), &["sync", "--frozen"]);
            assert_success(&output, &format!("{case} frozen"));
        }
    }
    let other = property("http://127.0.0.1:9");
    let apart = property("http://127.0.0.2:9");
    // (mirrorOf, root, a, b, refused)
    for (mirror_of, root, a, b, refused) in [
        (None, "", own.as_str(), other.as_str(), "leaves unfilled"),
        (None, own.as_str(), "", other.as_str(), "fills in otherwise"),
        (
            Some("external:*,!central"),
            apart.as_str(),
            "",
            own.as_str(),
            "fills in otherwise",
        ),
    ] {
        for order in [["a", "b"], ["b", "a"]] {
            for maven in ["3.9", "3.10"] {
                let case = format!("{root} {a} {b} {order:?} {maven}");
                let dir = TempDir::new_in(base.path()).expect("case");
                let project = reactor(dir.path(), maven, order, root, a, b);
                let home = home_with(mirror_of, "");
                let output = run_raeva(&project, home.path(), &["sync"]);
                crate::common::assert_status(&output, 3, &case);
                let err = stderr(&output);
                assert!(
                    err.contains("the settings.xml repository 'corp'"),
                    "{case}: {err}"
                );
                assert!(err.contains(refused), "{case}: {err}");
                assert!(!project.join("raeva.lock").exists(), "{case}");
            }
        }
    }
}

/// The sha256 raeva.lock records for `artifact`'s 1.0 POM in `repository`.
fn pom_sha256(repository: &Path, artifact: &str) -> String {
    let path = repository.join(format!("org/test/{artifact}/1.0/{artifact}-1.0.pom"));
    let blob = BlobId::from_bytes(&fs::read(&path).expect("read pom")).to_string();
    format!(
        "sha256 = \"{}\"",
        blob.rsplit(':').next().unwrap_or_default()
    )
}

/// A home whose settings.xml sends Central to `central` and each
/// `(id, mirrorOf)` mirror to `mirror`.
fn settings_home(central: &StubServer, mirrors: &[(&str, &str)], mirror: &StubServer) -> TempDir {
    let home = TempDir::new().expect("home");
    fs::create_dir_all(home.path().join(".m2")).expect("create .m2");
    let mirrors: String = (mirrors.iter())
        .map(|(id, mirror_of)| {
            format!(
                "<mirror><id>{id}</id><mirrorOf>{mirror_of}</mirrorOf>\
                 <url>http://{}/</url></mirror>",
                mirror.addr()
            )
        })
        .collect();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>cm</id><mirrorOf>central</mirrorOf>\
             <url>http://{}/</url></mirror>{mirrors}</mirrors></settings>",
            central.addr()
        ),
    )
    .expect("write settings");
    home
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create dir");
    for entry in fs::read_dir(from).expect("read dir") {
        let path = entry.expect("dir entry").path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            fs::copy(&path, &target).expect("copy file");
        }
    }
}
