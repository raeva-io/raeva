//! Maven keys repositories by id: one URL declared under two ids is two
//! repositories, each with its own policies, and `_remote.repositories`
//! names every repository a file was resolved from.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rv_maven_types::BlobId;
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{assert_success, raeva_command, run_raeva};

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
        let ids: Vec<_> = lock.repo_ids[&url].iter().map(String::as_str).collect();
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
/// fetches it there, and a module that read other bytes for that POM fails
/// naming the repository that served each.
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
        lock.contains(&format!("pom_repo_urls = [\"{}\"]", file_url(&b))),
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

/// One URL declared under two ids is two repositories: a mirror of one id
/// serves its newer build, so that build's POM and jar come through the
/// mirror and not from the URL the other id reaches directly.
#[test]
fn a_snapshot_build_comes_through_the_mirror_of_the_id_that_names_it() {
    let older = "1.0-20240101.010101-1";
    let newer = "1.0-20240102.010101-2";
    let base = TempDir::new().expect("base");
    let direct = [("jar", None, older), ("pom", None, older)];
    // The direct URL also holds a stale copy of the newer build's files.
    publish_snapshot(
        &base.path().join("x"),
        "20240101010101",
        &direct,
        &[
            (format!("{older}.pom"), SNAP_POM),
            (format!("{older}.jar"), "old jar"),
            (format!("{newer}.pom"), "<project/>"),
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
            .starts_with(&format!("/x/org/test/snap/1.0-SNAPSHOT/snap-{newer}"))
    });
    assert!(!stale, "the newer build was asked of the direct URL");
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
