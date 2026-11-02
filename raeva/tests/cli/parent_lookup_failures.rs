//! A dependency's parent POM that a repository fails to serve fails the
//! sync with the exit status of that failure, not as a missing parent, and
//! one that does not parse costs the dependency its transitive
//! dependencies, as in Maven.

use crate::common::{
    assert_status, assert_success, raeva_command, sha1_hex, with_sha1, write_repo_toml,
};
use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

const LIB_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>org.example</groupId><artifactId>lib-parent</artifactId><version>1.0</version></parent>\
<artifactId>lib</artifactId></project>";
const LIB_PARENT_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>lib-parent</artifactId><version>1.0</version>\
<packaging>pom</packaging></project>";
const LIB_JAR: &str = "lib jar";

/// Serves `lib` with its checksums, and answers every request for
/// `lib-parent` through `parent`.
fn spawn_repository(lib_pom: &'static str, parent: fn(&str) -> Response) -> (String, StubServer) {
    let server = StubServer::start(move |request| {
        let path = request.path.as_str();
        if let Some(rest) = path.strip_prefix("/maven/org/example/")
            && rest.starts_with("lib-parent/")
        {
            return parent(rest);
        }
        with_sha1(
            path,
            [
                ("/maven/org/example/lib/1.0/lib-1.0.pom", lib_pom),
                ("/maven/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
            ],
        )
    });
    (format!("http://{}/maven/", server.addr()), server)
}

fn project(repository: &str) -> TempDir {
    let dir = tempfile::tempdir().expect("project dir");
    std::fs::write(
        dir.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>app</artifactId><version>1.0</version><dependencies><dependency>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>\
</dependency></dependencies></project>",
    )
    .expect("write pom.xml");
    write_repo_toml(dir.path(), "fixture", repository);
    dir
}

fn sync_lib(lib_pom: &'static str, parent: fn(&str) -> Response) -> std::process::Output {
    let (repository, _server) = spawn_repository(lib_pom, parent);
    let project = project(&repository);
    let home = tempfile::tempdir().expect("home");
    raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .expect("run raeva sync")
}

#[test]
fn a_refused_parent_is_an_authentication_failure() {
    let output = sync_lib(LIB_POM, |_| Response::new(401, ""));
    assert_status(&output, 3, "refused parent");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HTTP 401"), "{stderr}");
    assert!(stderr.contains("<server>"), "{stderr}");
}

#[test]
fn an_unavailable_parent_is_a_network_failure() {
    let output = sync_lib(LIB_POM, |_| Response::new(503, ""));
    assert_status(&output, 4, "unavailable parent");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("lib-parent-1.0.pom"), "{stderr}");
}

#[test]
fn a_parent_failing_its_sidecar_is_an_integrity_failure() {
    let output = sync_lib(LIB_POM, |rest| {
        if rest.ends_with(".pom.sha1") {
            Response::new(200, "0".repeat(40))
        } else if rest.ends_with(".pom") {
            Response::new(200, LIB_PARENT_POM)
        } else {
            Response::new(404, "")
        }
    });
    assert_status(&output, 9, "parent sidecar mismatch");
}

/// A parent with no checksum file needs `--allow-missing-checksums`, which
/// warns `CHECKSUM_MISSING`. From then on its raeva.lock pin verifies it:
/// `--frozen` and a plain sync, with a warm or an empty raeva home, need
/// neither the flag nor a warning.
#[test]
fn a_locked_parent_needs_no_checksum_file() {
    let (repository, _server) = spawn_repository(LIB_POM, |rest| {
        if rest.ends_with(".pom") {
            Response::new(200, LIB_PARENT_POM)
        } else {
            Response::new(404, "")
        }
    });
    let project = project(&repository);
    let sync = |home: &TempDir, args: &[&str]| {
        raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .arg("sync")
            .args(args)
            .output()
            .expect("run raeva sync")
    };
    let home = tempfile::tempdir().expect("home");
    let output = sync(&home, &[]);
    assert_status(&output, 5, "missing parent checksum");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing checksum"), "{stderr}");
    let output = sync(&home, &["--allow-missing-checksums"]);
    assert_success(&output, "allow missing parent checksum");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CHECKSUM_MISSING"), "{stderr}");

    let empty = tempfile::tempdir().expect("empty home");
    for (home, args) in [
        (&home, &["--frozen"][..]),
        (&home, &[]),
        (&empty, &["--frozen"]),
        (&empty, &[]),
    ] {
        let output = sync(home, args);
        assert_success(&output, &format!("{args:?}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("CHECKSUM_MISSING"), "{args:?}: {stderr}");
    }
}

#[test]
fn fresh_commands_use_the_locked_parent_pin_after_a_pom_edit() {
    let (repository, _server) = spawn_repository(LIB_POM, |rest| {
        if rest.ends_with(".pom") {
            Response::new(200, LIB_PARENT_POM)
        } else {
            Response::new(404, "")
        }
    });
    let project = project(&repository);
    let home = tempfile::tempdir().expect("home");
    let run = |args: &[&str]| {
        raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva")
    };
    assert_success(
        &run(&["sync", "--allow-missing-checksums"]),
        "pin unchecked parent",
    );
    let lock_path = project.path().join("raeva.lock");
    let locked = std::fs::read(&lock_path).unwrap();
    let pom = project.path().join("pom.xml");
    let original = std::fs::read_to_string(&pom).unwrap();
    std::fs::write(
        &pom,
        original.replace("</project>", "<!-- edit --></project>"),
    )
    .unwrap();

    // Fresh commands run first, while the cached parent still has no
    // repository checksum evidence. Offline validation must use its lock pin.
    for offline in [true, false] {
        for mut args in [
            vec!["export-m2", "--dry-run"],
            vec!["export-checksums"],
            vec!["sbom"],
            vec!["sync", "--frozen"],
        ] {
            if offline {
                args.push("--offline");
            }
            let output = run(&args);
            assert_success(&output, &format!("{args:?}"));
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!stderr.contains("CHECKSUM_MISSING"), "{args:?}: {stderr}");
            assert_eq!(std::fs::read(&lock_path).unwrap(), locked);
        }
    }
}

#[test]
fn a_parent_no_repository_has_fails_the_sync() {
    let output = sync_lib(LIB_POM, |_| Response::new(404, ""));
    assert_status(&output, 5, "missing parent");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("org.example:lib-parent:1.0"), "{stderr}");
    // The parent is lib's, which the error names.
    assert!(
        stderr.contains("In pom.xml, through org.example:lib:1.0\n"),
        "{stderr}"
    );
}

#[test]
fn an_unparseable_parent_drops_only_the_transitive_dependencies() {
    let output = sync_lib(LIB_POM, |rest| {
        let body = "<project><modelVersion>4.0.0</modelVersion><artifactId>lib-parent";
        with_sha1(rest, [("lib-parent/1.0/lib-parent-1.0.pom", body)])
    });
    assert_success(&output, "unparseable parent");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("POM is invalid"), "{stderr}");
    assert!(stderr.contains("POM_PROBLEM"), "{stderr}");
}

/// Maven may read a POM in an encoding such as Big5, which `raeva` does not,
/// so `raeva` reports it instead of dropping what the POM declares, and does
/// not blame the repository for serving something other than a POM.
#[test]
fn a_pom_raeva_cannot_read_but_maven_can_fails_the_sync() {
    const LIB_IN_BIG5: &str = "<?xml version=\"1.0\" encoding=\"Big5\"?>\
<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version></project>";
    let output = sync_lib(LIB_IN_BIG5, |_| Response::new(404, ""));
    assert_status(&output, 5, "Big5 POM");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("org.example:lib:1.0"), "{stderr}");
    assert!(stderr.contains("declares encoding Big5"), "{stderr}");
    assert!(!stderr.contains("POM is invalid"), "{stderr}");
    assert!(!stderr.contains("error page"), "{stderr}");
}

/// Maven's model reader knows the XHTML entities, such as `&copy;`.
#[test]
fn a_pom_with_an_xhtml_entity_is_read() {
    const LIB_WITH_ENTITY: &str = "<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>\
<description>&copy; Example</description></project>";
    let output = sync_lib(LIB_WITH_ENTITY, |_| Response::new(404, ""));
    assert_success(&output, "XHTML entity POM");
}

/// A jar no repository has a POM for is locked without dependencies and
/// without a POM pin, as Maven uses it with a warning, and every command
/// that reads the lock accepts that row.
#[test]
fn a_dependency_without_a_pom_is_locked_without_one() {
    use crate::common::assert_success;
    let server = StubServer::start(|request| match request.path.as_str() {
        "/maven/org/example/lib/1.0/lib-1.0.jar" => Response::new(200, LIB_JAR),
        "/maven/org/example/lib/1.0/lib-1.0.jar.sha1" => {
            Response::new(200, sha1_hex(LIB_JAR.as_bytes()))
        }
        _ => Response::new(404, ""),
    });
    let project = project(&format!("http://{}/maven/", server.addr()));
    let home = tempfile::tempdir().expect("home");
    let empty = tempfile::tempdir().expect("empty home");
    let run = |home: &TempDir, args: &[&str]| {
        raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva")
    };
    let output = run(&home, &["sync"]);
    assert_success(&output, "sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("POM is missing"), "{stderr}");
    let lock_path = project.path().join("raeva.lock");
    let locked = std::fs::read_to_string(&lock_path).unwrap();
    assert!(locked.contains("artifact = \"lib\""), "{locked}");
    assert!(!locked.contains("pom_sha256"), "{locked}");
    let document: toml::Value = toml::from_str(&locked).expect("parse raeva.lock");
    crate::schemas::assert_schema_valid(
        &crate::schemas::validator(crate::schemas::RAEVA_LOCK_SCHEMA),
        &serde_json::to_value(document).expect("convert raeva.lock"),
    );
    for (home, args) in [
        (&home, &["sync", "--frozen"][..]),
        (&home, &["sync", "--frozen", "--offline"]),
        (&home, &["export-m2", "--dry-run"]),
        (&home, &["export-checksums"]),
        (&home, &["sbom"]),
        (&empty, &["sync", "--frozen"]),
    ] {
        let output = run(home, args);
        assert_success(&output, &format!("{args:?}"));
        assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), locked);
    }
}

/// A SNAPSHOT whose metadata names a build with no POM is locked without
/// one too.
#[test]
fn a_snapshot_without_a_pom_is_locked_without_one() {
    const METADATA: &str = "<metadata><groupId>org.example</groupId><artifactId>lib</artifactId>\
<version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20240101.120000</timestamp>\
<buildNumber>1</buildNumber></snapshot><lastUpdated>20240101120000</lastUpdated></versioning></metadata>";
    let server = StubServer::start(|request| {
        with_sha1(
            &request.path,
            [
                (
                    "/maven/org/example/lib/1.0-SNAPSHOT/maven-metadata.xml",
                    METADATA,
                ),
                (
                    "/maven/org/example/lib/1.0-SNAPSHOT/lib-1.0-20240101.120000-1.jar",
                    LIB_JAR,
                ),
            ],
        )
    });
    let project = project(&format!("http://{}/maven/", server.addr()));
    let pom = project.path().join("pom.xml");
    let xml = std::fs::read_to_string(&pom).unwrap();
    std::fs::write(
        &pom,
        xml.replace(
            "<version>1.0</version></dependency>",
            "<version>1.0-SNAPSHOT</version></dependency>",
        ),
    )
    .unwrap();
    let config = project.path().join("raeva.toml");
    let toml = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, toml + "snapshots = true\n").unwrap();
    let home = tempfile::tempdir().expect("home");
    let empty = tempfile::tempdir().expect("empty home");
    for (home, args) in [(&home, &["sync"][..]), (&empty, &["sync", "--frozen"])] {
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "0")
            .args(args)
            .output()
            .expect("run raeva");
        assert_success(&output, &format!("{args:?}"));
    }
    let locked = std::fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    assert!(locked.contains("build_number = 1"), "{locked}");
    assert!(!locked.contains("pom_sha256"), "{locked}");
}

/// A dependency whose parent is a reactor module, versioned by a remote
/// parent's `${revision}`, exports without that module's POM: Maven takes
/// it from the reactor, by the coordinates sync recorded. The module names
/// the version itself or inherits the remote parent's.
#[test]
fn a_dependency_with_a_reactor_parent_exports_by_the_recorded_coordinates() {
    use crate::common::assert_success;
    const EXT_POM: &str = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
<artifactId>root</artifactId><version>1.2</version><relativePath/></parent><groupId>ext</groupId>\
<artifactId>lib</artifactId><version>1</version></project>";
    for (corp_version, corp_revision, root_version, app_parent) in [
        ("1", "1.2", "<version>${revision}</version>", "${revision}"),
        (
            "${revision}",
            "1",
            "<properties><revision>1.2</revision></properties>",
            "1",
        ),
    ] {
        let corp_pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>corp</groupId>\
             <artifactId>parent</artifactId><version>{corp_version}</version>\
             <packaging>pom</packaging><properties><revision>{corp_revision}</revision>\
             </properties></project>"
        );
        let server = StubServer::start(move |request| {
            let body = match request.path.as_str().strip_prefix("/maven/") {
                Some("corp/parent/1/parent-1.pom") => corp_pom.as_str(),
                Some("ext/lib/1/lib-1.pom") => EXT_POM,
                Some("ext/lib/1/lib-1.jar") => LIB_JAR,
                Some(other) => match other.strip_suffix(".sha1") {
                    Some("corp/parent/1/parent-1.pom") => {
                        return Response::new(200, sha1_hex(corp_pom.as_bytes()));
                    }
                    Some("ext/lib/1/lib-1.pom") => {
                        return Response::new(200, sha1_hex(EXT_POM.as_bytes()));
                    }
                    Some("ext/lib/1/lib-1.jar") => {
                        return Response::new(200, sha1_hex(LIB_JAR.as_bytes()));
                    }
                    _ => return Response::new(404, ""),
                },
                None => return Response::new(404, ""),
            };
            Response::new(200, body)
        });
        let project = tempfile::tempdir().expect("project dir");
        let write = |path: &str, contents: &str| {
            let path = project.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
            std::fs::write(path, contents).expect("write");
        };
        write(
            "pom.xml",
            &format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>corp</groupId>\
                 <artifactId>parent</artifactId><version>1</version><relativePath/></parent>\
                 <groupId>p</groupId><artifactId>root</artifactId>{root_version}\
                 <packaging>pom</packaging><modules><module>app</module></modules></project>"
            ),
        );
        write(
            "app/pom.xml",
            &format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>p</groupId>\
                 <artifactId>root</artifactId><version>{app_parent}</version></parent>\
                 <artifactId>app</artifactId><dependencies><dependency><groupId>ext</groupId>\
                 <artifactId>lib</artifactId><version>1</version></dependency></dependencies>\
                 </project>"
            ),
        );
        let (_central, central) = crate::common::local_central();
        write(
            "raeva.toml",
            &format!(
                "[[repositories]]\nid = \"fixture\"\nurl = \"http://{}/maven/\"\n{central}",
                server.addr()
            ),
        );
        let home = tempfile::tempdir().expect("home");
        let m2 = tempfile::tempdir().expect("m2");
        let run = |args: &[&str]| {
            raeva_command(project.path(), home.path())
                .env("RAEVA_RETRIES", "0")
                .args(args)
                .output()
                .expect("run raeva")
        };
        assert_success(&run(&["sync"]), "sync");
        let output = run(&["export-m2", "--m2-path", m2.path().to_str().unwrap()]);
        assert_success(&output, "export-m2");
        assert!(m2.path().join("ext/lib/1/lib-1.jar").is_file());
        assert!(m2.path().join("corp/parent/1/parent-1.pom").is_file());
        assert!(!m2.path().join("p/root").exists());
    }
}

/// A lone module reads its `../pom.xml` parent also when a dependency names
/// the module itself, as Maven's reactor serves the project's own model for
/// that edge.
#[test]
fn a_lone_module_a_dependency_names_reads_the_parent_above_it() {
    const LIB: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
<artifactId>lib</artifactId><version>1.0</version><dependencies><dependency>\
<groupId>com.example</groupId><artifactId>app</artifactId><version>2.5.0</version>\
</dependency></dependencies></project>";
    let server = StubServer::start(|request| {
        with_sha1(
            &request.path,
            [
                ("/org/example/lib/1.0/lib-1.0.pom", LIB),
                ("/org/example/lib/1.0/lib-1.0.jar", LIB_JAR),
            ],
        )
    });
    let dir = tempfile::tempdir().expect("checkout");
    std::fs::write(
        dir.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>\
<properties><revision>2.5.0</revision></properties></project>",
    )
    .expect("write parent pom.xml");
    let module = dir.path().join("app");
    std::fs::create_dir(&module).expect("module dir");
    std::fs::write(
        module.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
<artifactId>parent</artifactId><version>1</version></parent><artifactId>app</artifactId>\
<version>${revision}</version><dependencies><dependency><groupId>org.example</groupId>\
<artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>",
    )
    .expect("write module pom.xml");
    write_repo_toml(&module, "fixture", &format!("http://{}/", server.addr()));
    let home = tempfile::tempdir().expect("home");
    let output = raeva_command(&module, home.path())
        .arg("sync")
        .output()
        .expect("run raeva sync");
    assert_success(&output, "lone module sync");
    let lock = std::fs::read_to_string(module.join("raeva.lock")).expect("read raeva.lock");
    assert!(lock.contains("1 0 compile"), "{lock}");
}

/// A relocation target whose parent is missing is named after the
/// dependency that relocates to it.
#[test]
fn a_relocation_target_with_a_missing_parent_is_named() {
    const OLD_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>old</artifactId><version>1.0</version>\
<distributionManagement><relocation><artifactId>lib</artifactId></relocation>\
</distributionManagement></project>";
    let server = StubServer::start(|request| {
        with_sha1(
            request.path.as_str(),
            [
                ("/maven/org/example/old/1.0/old-1.0.pom", OLD_POM),
                ("/maven/org/example/lib/1.0/lib-1.0.pom", LIB_POM),
            ],
        )
    });
    let repository = format!("http://{}/maven/", server.addr());
    let project = project(&repository);
    let pom = project.path().join("pom.xml");
    let text = std::fs::read_to_string(&pom).expect("pom.xml");
    std::fs::write(
        &pom,
        text.replace(
            "<artifactId>lib</artifactId>",
            "<artifactId>old</artifactId>",
        ),
    )
    .expect("write pom.xml");
    let home = tempfile::tempdir().expect("home");
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .expect("run raeva sync");
    assert_status(&output, 5, "relocated missing parent");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("In pom.xml, through org.example:old:1.0 -> org.example:lib:1.0\n"),
        "{stderr}"
    );
}

/// A relocation target that management moves to another version, whose
/// parent is missing, is named as well.
#[test]
fn a_managed_relocation_target_with_a_missing_parent_is_named() {
    const MID_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>mid</artifactId><version>1.0</version>\
<dependencies><dependency><groupId>org.example</groupId><artifactId>old</artifactId>\
<version>1.0</version></dependency></dependencies></project>";
    const OLD_POM: &str = "<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>old</artifactId><version>1.0</version>\
<distributionManagement><relocation><artifactId>lib</artifactId></relocation>\
</distributionManagement></project>";
    const LIB_1: &str = "<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version></project>";
    const LIB_2: &str = "<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>org.example</groupId><artifactId>lib-parent</artifactId><version>1.0</version></parent>\
<artifactId>lib</artifactId><version>2.0</version></project>";
    let server = StubServer::start(|request| {
        with_sha1(
            request.path.as_str(),
            [
                ("/maven/org/example/mid/1.0/mid-1.0.pom", MID_POM),
                ("/maven/org/example/old/1.0/old-1.0.pom", OLD_POM),
                ("/maven/org/example/lib/1.0/lib-1.0.pom", LIB_1),
                ("/maven/org/example/lib/2.0/lib-2.0.pom", LIB_2),
            ],
        )
    });
    let repository = format!("http://{}/maven/", server.addr());
    let project = project(&repository);
    let pom = project.path().join("pom.xml");
    let text = std::fs::read_to_string(&pom).expect("pom.xml");
    let text = text
        .replace(
            "<artifactId>lib</artifactId>",
            "<artifactId>mid</artifactId>",
        )
        .replace(
            "<dependencies>",
            "<dependencyManagement><dependencies><dependency><groupId>org.example</groupId>\
             <artifactId>lib</artifactId><version>2.0</version></dependency></dependencies>\
             </dependencyManagement><dependencies>",
        );
    std::fs::write(&pom, text).expect("write pom.xml");
    let home = tempfile::tempdir().expect("home");
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .expect("run raeva sync");
    assert_status(&output, 5, "managed relocated missing parent");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "In pom.xml, through org.example:mid:1.0 -> org.example:old:1.0 -> org.example:lib:2.0\n"
        ),
        "{stderr}"
    );
}

/// A reactor module that takes its version from a remote parent fails
/// before dependency resolution when no repository has that parent, and
/// the error names the module.
#[test]
fn a_module_s_missing_remote_parent_names_the_module() {
    let (repository, _server) = spawn_repository(LIB_POM, |_| Response::new(404, ""));
    let project = tempfile::tempdir().expect("project dir");
    std::fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>root</artifactId><version>1.0</version><packaging>pom</packaging>\
<modules><module>core</module></modules></project>",
    )
    .expect("write pom.xml");
    std::fs::create_dir(project.path().join("core")).expect("mkdir core");
    std::fs::write(
        project.path().join("core/pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.example</groupId>\
<artifactId>lib-parent</artifactId><version>1.0</version><relativePath/></parent>\
<artifactId>core</artifactId></project>",
    )
    .expect("write core/pom.xml");
    write_repo_toml(project.path(), "fixture", &repository);
    let home = tempfile::tempdir().expect("home");
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "0")
        .arg("sync")
        .output()
        .expect("run raeva sync");
    assert_status(&output, 5, "missing remote parent of a module");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("org.example:lib-parent:1.0"), "{stderr}");
    assert!(stderr.contains("In core/pom.xml"), "{stderr}");
}
