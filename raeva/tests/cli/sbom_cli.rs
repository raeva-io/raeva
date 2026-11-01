use crate::common::{assert_success, raeva_command, temp_project, write_demo_lock};
use rv_lock::{LockEdge, Scope};
use std::fs;
use std::path::Path;

use crate::schemas::{assert_schema_valid, cyclonedx_validator};

#[test]
fn sbom_defaults_to_reproducible_cyclonedx_on_stdout() {
    let (project, home) = temp_project();
    // `zeta` (row 1, as raeva.lock sorts them) depends on `alpha`.
    write_demo_lock(
        project.path(),
        home.path(),
        &[
            ("alpha", "jar", None, Scope::Compile),
            ("zeta", "test-jar", Some("tests"), Scope::Compile),
        ],
        vec![LockEdge::new(1, 0, Some(Scope::Compile), false)],
    );

    let first = raeva_command(project.path(), home.path())
        .arg("sbom")
        .output()
        .expect("run raeva sbom");
    let second = raeva_command(project.path(), home.path())
        .arg("sbom")
        .output()
        .expect("run raeva sbom again");
    assert_success(&first, "sbom");
    assert_success(&second, "sbom again");
    assert_eq!(first.stdout, second.stdout);

    let first: serde_json::Value = serde_json::from_slice(&first.stdout).expect("CycloneDX JSON");
    assert_eq!(first["bomFormat"], "CycloneDX");
    assert_eq!(first["specVersion"], "1.5");
    assert_eq!(first["metadata"]["component"]["group"], "com.example");
    assert_eq!(first["metadata"]["component"]["name"], "demo");
    assert_eq!(first["metadata"]["component"]["version"], "1.0.0");
    assert_eq!(
        first["metadata"]["tools"]["components"][0]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        first["metadata"]["component"]["purl"],
        "pkg:maven/com.example/demo@1.0.0"
    );
    assert!(first["metadata"].get("timestamp").is_none());

    let components = first["components"].as_array().expect("components");
    assert_eq!(components.len(), 2);
    assert_eq!(components[0]["name"], "alpha");
    assert_eq!(components[1]["name"], "zeta");
    assert_eq!(
        components[1]["purl"],
        "pkg:maven/org.example/zeta@2.0.0?classifier=tests&type=test-jar"
    );
    for component in components {
        assert!(component.get("licenses").is_none());
        assert_eq!(component["hashes"][0]["alg"], "SHA-256");
    }
}

fn license_project() -> (tempfile::TempDir, tempfile::TempDir) {
    let (project, home) = temp_project();
    let write_pom = |artifact: &str, body: &str| {
        let dir = project
            .path()
            .join("repository/org/example")
            .join(artifact)
            .join("1");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{artifact}-1.pom")), format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
        )).unwrap();
        fs::write(dir.join(format!("{artifact}-1.jar")), b"jar").unwrap();
    };
    write_pom(
        "parent",
        "<packaging>pom</packaging><properties><license.name>Apache-2.0</license.name></properties><licenses><license><name>${license.name}</name></license></licenses>",
    );
    let parent = "<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1</version><relativePath/></parent>";
    write_pom(
        "bom",
        "<packaging>pom</packaging><licenses><license><name>ISC</name></license></licenses>",
    );
    write_pom(
        "inherited",
        &format!(
            "{parent}<properties><license.name>MIT</license.name></properties><dependencyManagement><dependencies><dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>"
        ),
    );
    write_pom(
        "overridden",
        &format!(
            "{parent}<licenses><license><name>A private license</name></license><license><name>Unicode-3.0</name></license><license><name>BSD</name><url>https://opensource.org/licenses/BSD-3-Clause</url></license></licenses>"
        ),
    );
    write_pom("absent", "");
    fs::create_dir_all(project.path().join("build-parent")).unwrap();
    fs::write(project.path().join("build-parent/pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging><licenses><license><name>Apache License, Version 2.0</name></license></licenses></project>").unwrap();
    let url = url::Url::from_directory_path(project.path().join("repository")).unwrap();
    let dependencies: String = ["inherited", "overridden", "absent"].iter().map(|artifact| format!("<dependency><groupId>org.example</groupId><artifactId>{artifact}</artifactId><version>1</version></dependency>")).collect();
    fs::write(project.path().join("pom.xml"), format!("<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1</version><relativePath>build-parent/pom.xml</relativePath></parent><artifactId>demo</artifactId><repositories><repository><id>fixture</id><url>{url}</url></repository></repositories><dependencies>{dependencies}</dependencies></project>")).unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync license fixture");
    (project, home)
}

fn sbom(project: &Path, home: &Path) -> std::process::Output {
    raeva_command(project, home)
        .args(["sbom", "--offline"])
        .output()
        .unwrap()
}

#[test]
fn sbom_emits_effective_licenses_offline_from_locked_bytes() {
    let (project, home) = license_project();
    let lock_bytes = fs::read(project.path().join("raeva.lock")).unwrap();
    let first = sbom(project.path(), home.path());
    assert_success(&first, "licensed SBOM");
    let document: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_schema_valid(&cyclonedx_validator(), &document);
    assert_eq!(
        document["metadata"]["component"]["licenses"],
        serde_json::json!([{"license": {"id": "Apache-2.0"}}])
    );
    let components = document["components"].as_array().unwrap();
    let find = |name| {
        components
            .iter()
            .find(|component| component["name"] == name)
            .unwrap()
    };
    assert_eq!(
        find("inherited")["licenses"],
        serde_json::json!([{"license": {"id": "MIT"}}])
    );
    assert_eq!(
        find("overridden")["licenses"],
        serde_json::json!([{"license": {"name": "A private license"}}, {"license": {"name": "Unicode-3.0"}}, {"license": {"id": "BSD-3-Clause"}}])
    );
    assert!(find("absent").get("licenses").is_none());

    let file = project.path().join("bom.json");
    let written = raeva_command(project.path(), home.path())
        .args(["sbom", "--offline", "-o"])
        .arg(&file)
        .output()
        .unwrap();
    assert_success(&written, "write licensed SBOM");
    assert_eq!(fs::read(file).unwrap(), first.stdout);

    let store = rv_store::Store::open(&home.path().join("store")).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let changed = store.put_bytes(b"<project><groupId>org.example</groupId><artifactId>inherited</artifactId><version>1</version><licenses><license><name>ISC</name></license></licenses></project>").await.unwrap();
        store.add_artifact(&rv_maven_types::ArtifactCoord::new("org.example", "inherited", "1", "pom", None), &changed).await.unwrap();
    });
    fs::remove_dir_all(project.path().join("repository")).unwrap();
    let second = sbom(project.path(), home.path());
    assert_success(&second, "SBOM ignores changed coordinate index");
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(
        lock_bytes,
        fs::read(project.path().join("raeva.lock")).unwrap()
    );
}

#[test]
fn sbom_license_metadata_does_not_require_imported_boms() {
    let (project, home) = license_project();
    let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).unwrap();
    let pin = &lock.platforms[0].support_poms["org.example:bom:1"].sha256;
    let store = rv_store::Store::open(&home.path().join("store")).unwrap();
    fs::remove_file(store.get_path(&pin.to_string().parse().unwrap())).unwrap();
    let result = sbom(project.path(), home.path());
    assert_success(&result, "SBOM needs parent metadata but no dependency BOMs");
    let document: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let inherited = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["name"] == "inherited")
        .unwrap();
    assert_eq!(
        inherited["licenses"],
        serde_json::json!([{"license": {"id": "MIT"}}])
    );
}

#[test]
fn sbom_uses_reactor_licenses_and_root_user_properties() {
    let (project, home) = temp_project();
    fs::write(project.path().join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><properties><license.name>MIT</license.name></properties><licenses><license><name>${license.name}</name></license></licenses><modules><module>inherited</module><module>overridden</module></modules></project>").unwrap();
    for (module, licenses) in [
        ("inherited", ""),
        (
            "overridden",
            "<licenses><license><name>Private ${project.artifactId}</name></license></licenses>",
        ),
    ] {
        fs::create_dir(project.path().join(module)).unwrap();
        fs::write(project.path().join(module).join("pom.xml"), format!("<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1</version></parent><artifactId>{module}</artifactId><properties><license.name>BSD-2-Clause</license.name></properties>{licenses}</project>")).unwrap();
    }
    fs::create_dir(project.path().join(".mvn")).unwrap();
    fs::write(
        project.path().join(".mvn/maven.config"),
        "-Dlicense.name=ISC\n",
    )
    .unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync reactor licenses");
    let result = sbom(project.path(), home.path());
    assert_success(&result, "reactor licenses");
    let document: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        document["metadata"]["component"]["licenses"],
        serde_json::json!([{"license": {"id": "ISC"}}])
    );
    let components = document["components"].as_array().unwrap();
    assert_eq!(
        components[0]["licenses"],
        serde_json::json!([{"license": {"id": "ISC"}}])
    );
    assert_eq!(
        components[1]["licenses"],
        serde_json::json!([{"license": {"name": "Private overridden"}}])
    );
    let selected = raeva_command(project.path(), home.path())
        .args(["sbom", "--offline", "--module", "inherited/pom.xml"])
        .output()
        .unwrap();
    assert_success(&selected, "selected module licenses");
    let selected: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
    assert_eq!(
        selected["metadata"]["component"]["licenses"],
        components[0]["licenses"]
    );
}

fn range_parent_project(
    lower_only: bool,
    shared_dependency: bool,
) -> (tempfile::TempDir, tempfile::TempDir) {
    let (project, home) = temp_project();
    let parent = |artifact: &str, version: &str| {
        format!(
            "<parent><groupId>g</groupId><artifactId>{artifact}</artifactId><version>{version}</version><relativePath/></parent>"
        )
    };
    for (repo, versions) in [("both", vec!["1", "2"]), ("low", vec!["1"])] {
        let repository = project.path().join(repo);
        for artifact in ["parent", "grand"] {
            let dir = repository.join("g").join(artifact);
            fs::create_dir_all(&dir).unwrap();
            let versions_xml: String = versions
                .iter()
                .map(|v| format!("<version>{v}</version>"))
                .collect();
            fs::write(dir.join("maven-metadata.xml"), format!("<metadata><groupId>g</groupId><artifactId>{artifact}</artifactId><versioning><versions>{versions_xml}</versions></versioning></metadata>")).unwrap();
            for version in &versions {
                let body = if artifact == "grand" {
                    format!(
                        "<properties><license.name>{}</license.name></properties>",
                        if *version == "1" {
                            "MIT"
                        } else {
                            "BSD-2-Clause"
                        }
                    )
                } else {
                    format!(
                        "{}<licenses><license><name>{}</name></license></licenses>",
                        parent("grand", "[1,3)"),
                        if *version == "1" {
                            "${license.name}"
                        } else {
                            "Apache-2.0"
                        }
                    )
                };
                write_range_pom(
                    &repository,
                    artifact,
                    version,
                    version,
                    &format!("<packaging>pom</packaging>{body}"),
                );
            }
        }
        if shared_dependency {
            write_range_pom(&repository, "lib", "1", "1", &parent("parent", "[1,3)"));
            fs::write(repository.join("g/lib/1/lib-1.jar"), b"jar").unwrap();
        }
    }
    fs::write(project.path().join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><modules><module>a</module><module>b</module></modules></project>").unwrap();
    for (module, version, repo) in [
        ("a", "[1,3)", if lower_only { "low" } else { "both" }),
        ("b", if lower_only { "2" } else { "1" }, "both"),
    ] {
        let dir = project.path().join(module);
        fs::create_dir_all(&dir).unwrap();
        let url = url::Url::from_directory_path(project.path().join(repo)).unwrap();
        let dependencies = if shared_dependency {
            "<dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>1</version></dependency></dependencies>"
        } else {
            ""
        };
        fs::write(dir.join("pom.xml"), format!("<project><modelVersion>4.0.0</modelVersion>{}<artifactId>{module}</artifactId><version>1</version><repositories><repository><id>fixture</id><url>{url}</url></repository></repositories>{dependencies}</project>", parent("parent", version))).unwrap();
    }
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync repository-scoped parent ranges");
    (project, home)
}

fn write_range_pom(repo: &Path, artifact: &str, version: &str, file_version: &str, body: &str) {
    let dir = repo.join("g").join(artifact).join(version);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(format!("{artifact}-{file_version}.pom")), format!("<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>{artifact}</artifactId><version>{version}</version>{body}</project>")).unwrap();
}

fn assert_selected_license(
    project: &Path,
    home: &Path,
    module: &str,
    license: &str,
) -> serde_json::Value {
    let result = raeva_command(project, home)
        .args(["sbom", "--offline", "--module", module])
        .output()
        .unwrap();
    assert_success(&result, "SBOM with a selected parent range");
    let document: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        document["metadata"]["component"]["licenses"],
        serde_json::json!([{"license": {"id": license}}])
    );
    document
}

#[test]
fn sbom_parent_ranges_keep_repository_scoped_selections_and_restore_offline() {
    for lower_only in [false, true] {
        let (project, home) = range_parent_project(lower_only, false);
        let expected_a = if lower_only { "MIT" } else { "Apache-2.0" };
        let expected_b = if lower_only {
            "Apache-2.0"
        } else {
            "BSD-2-Clause"
        };
        let lock_path = project.path().join("raeva.lock");
        let bytes = fs::read(&lock_path).unwrap();
        let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
        let document: toml::Value = toml::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_schema_valid(
            &crate::schemas::validator(crate::schemas::RAEVA_LOCK_SCHEMA),
            &serde_json::to_value(document).unwrap(),
        );
        assert_eq!(
            lock.platforms[0].support_poms.len(),
            2 + if lower_only { 2 } else { 1 }
        );
        let module = lock.platforms[0]
            .modules
            .iter()
            .find(|m| m.path == "a/pom.xml")
            .unwrap();
        assert!(
            module
                .parent_ranges
                .iter()
                .any(|selection| selection.model == "g:a:1"
                    && selection.parent == "g:parent:[1,3)"
                    && selection.selected
                        == if lower_only {
                            "g:parent:1"
                        } else {
                            "g:parent:2"
                        })
        );
        assert_selected_license(project.path(), home.path(), "a/pom.xml", expected_a);
        assert_selected_license(project.path(), home.path(), "b/pom.xml", expected_b);
        assert_success(
            &sbom(project.path(), home.path()),
            "whole reactor with different parent versions",
        );

        let mut missing = lock.clone();
        missing.platforms[0]
            .modules
            .iter_mut()
            .find(|m| m.path == "a/pom.xml")
            .unwrap()
            .parent_ranges
            .clear();
        missing.write_atomic(&lock_path).unwrap();
        let absent = raeva_command(project.path(), home.path())
            .args(["sbom", "--offline", "--module", "a/pom.xml"])
            .output()
            .unwrap();
        assert!(!absent.status.success());
        assert!(String::from_utf8_lossy(&absent.stderr).contains("no locked range selection"));
        fs::write(&lock_path, &bytes).unwrap();

        let store = rv_store::Store::open(&home.path().join("store")).unwrap();
        let pin = &lock.platforms[0].support_poms[if lower_only {
            "g:parent:1"
        } else {
            "g:parent:2"
        }]
        .sha256;
        let blob = store.get_path(&pin.to_string().parse().unwrap());
        for damage in [false, true] {
            fs::remove_file(&blob).unwrap();
            if damage {
                fs::write(&blob, b"damaged parent").unwrap();
            }
            let result = raeva_command(project.path(), home.path())
                .args(["sbom", "--offline", "--module", "a/pom.xml"])
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(7),
                "a store miss is lock mismatch"
            );
            assert!(result.stdout.is_empty());
            let error = String::from_utf8_lossy(&result.stderr);
            assert!(
                error.contains(if damage {
                    "does not match its locked SHA-256"
                } else {
                    "unavailable in the content store"
                }),
                "{error}"
            );
            let restore = raeva_command(project.path(), home.path())
                .args(["sync", "--frozen"])
                .output()
                .unwrap();
            assert_success(&restore, "restore pinned range parents");
        }
        fs::remove_dir_all(project.path().join("both")).unwrap();
        fs::remove_dir_all(project.path().join("low")).unwrap();
        assert_selected_license(project.path(), home.path(), "a/pom.xml", expected_a);
        assert_success(
            &sbom(project.path(), home.path()),
            "offline SBOM after pinned restore",
        );
        assert_eq!(fs::read(lock_path).unwrap(), bytes);
    }
}

#[test]
fn sbom_parent_ranges_are_scoped_to_each_dependency_model() {
    let (project, home) = range_parent_project(true, true);
    for (module, license) in [("a/pom.xml", "MIT"), ("b/pom.xml", "Apache-2.0")] {
        let document = assert_selected_license(project.path(), home.path(), module, license);
        let lib = document["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "lib")
            .unwrap();
        assert_eq!(
            lib["licenses"],
            serde_json::json!([{"license": {"id": license}}])
        );
    }
    let combined = sbom(project.path(), home.path());
    assert!(!combined.status.success());
    assert!(
        String::from_utf8_lossy(&combined.stderr)
            .contains("g/lib@1 has different effective licenses")
    );
}

#[test]
fn sbom_fails_without_required_pinned_parent_evidence() {
    let (project, home) = license_project();
    let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).unwrap();
    let pin = &lock.platforms[0].support_poms["org.example:parent:1"].sha256;
    let store = rv_store::Store::open(&home.path().join("store")).unwrap();
    let blob = store.get_path(&pin.to_string().parse().unwrap());
    fs::remove_file(blob).unwrap();
    let result = raeva_command(project.path(), home.path())
        .args(["--json", "sbom", "--offline"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(7));
    let error: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(error["code"], "LOCKFILE_MISMATCH");
    let error = error.to_string();
    assert!(
        error.contains("cannot read SBOM license evidence"),
        "{error}"
    );
    assert!(error.contains("org.example:parent:1"), "{error}");
    assert!(error.contains("content store"), "{error}");
}

#[test]
fn sbom_omits_absent_pom_licenses_and_rejects_damaged_evidence() {
    for damage in [false, true] {
        let (project, home) = temp_project();
        write_demo_lock(
            project.path(),
            home.path(),
            &[("alpha", "jar", None, Scope::Compile)],
            vec![],
        );
        let lock_path = project.path().join("raeva.lock");
        let mut lock = rv_lock::Lockfile::read(&lock_path).unwrap();
        if damage {
            let store = rv_store::Store::open(&home.path().join("store")).unwrap();
            let id = lock.platforms[0].artifacts[0]
                .pom_sha256
                .as_ref()
                .unwrap()
                .to_string()
                .parse()
                .unwrap();
            let path = store.get_path(&id);
            fs::remove_file(&path).unwrap();
            fs::write(path, b"damaged").unwrap();
        } else {
            lock.platforms[0].artifacts[0].pom_sha256 = None;
            lock.write_atomic(&lock_path).unwrap();
        }
        let result = sbom(project.path(), home.path());
        if damage {
            assert_eq!(result.status.code(), Some(7));
            assert!(result.stdout.is_empty());
            let error = String::from_utf8_lossy(&result.stderr);
            assert!(
                error.contains("does not match its locked SHA-256"),
                "{error}"
            );
        } else {
            assert_success(&result, "SBOM of a dependency without a POM");
            let document: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert!(document["components"][0].get("licenses").is_none());
        }
    }
}

#[test]
fn sbom_rejects_a_lock_without_a_parent_range_selection() {
    let (project, home) = range_parent_project(true, false);
    let lock_path = project.path().join("raeva.lock");
    let mut lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    for module in &mut lock.platforms[0].modules {
        module.parent_ranges.clear();
    }
    lock.write_atomic(&lock_path).unwrap();
    let result = raeva_command(project.path(), home.path())
        .args(["sbom", "--offline", "--module", "a/pom.xml"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("has no locked range selection"), "{error}");
}

fn target_project(body: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let (project, home) = temp_project();
    fs::write(project.path().join("pom.xml"), format!("<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>demo</artifactId><version>1</version>{body}</project>")).unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        "[lock]\njdks = [\"17\", \"21\"]\n",
    )
    .unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args([
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,macos-aarch64",
        ])
        .output()
        .unwrap();
    assert_success(&sync, "sync recorded targets");
    (project, home)
}

#[test]
fn sbom_covers_identical_targets_and_selects_without_fallback() {
    let (project, home) = target_project("");
    let all = sbom(project.path(), home.path());
    assert_success(&all, "all targets");
    let all_document: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    assert_schema_valid(&cyclonedx_validator(), &all_document);
    let coverage = &all_document["metadata"]["properties"];
    assert_eq!(coverage.as_array().unwrap().len(), 4);
    for property in coverage.as_array().unwrap() {
        assert_eq!(property["name"], "raeva:target");
        assert!(String::from_utf8_lossy(&all.stderr).contains(property["value"].as_str().unwrap()));
    }
    for (flags, count) in [
        (vec!["--platform", "linux-x86_64"], 2),
        (vec!["--jdk", "21"], 2),
        (vec!["--platform", "linux-x86_64", "--jdk", "21"], 1),
    ] {
        let selected = raeva_command(project.path(), home.path())
            .arg("sbom")
            .args(flags)
            .output()
            .unwrap();
        assert_success(&selected, "selected targets");
        let document: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
        assert_eq!(
            document["metadata"]["properties"].as_array().unwrap().len(),
            count
        );
        assert_ne!(document["serialNumber"], all_document["serialNumber"]);
        assert_eq!(document["components"], all_document["components"]);
    }
    for flags in [["--platform", "windows-x86_64"], ["--jdk", "22"]] {
        let missing = raeva_command(project.path(), home.path())
            .arg("sbom")
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(missing.status.code(), Some(2));
        let error = String::from_utf8_lossy(&missing.stderr);
        // Only the flag given is named, not the other as "all".
        let asked = format!("no recorded target matches {} {};", flags[0], flags[1]);
        assert!(
            error.contains(&asked) && error.contains("available targets"),
            "{error}"
        );
        assert!(!error.contains("PLATFORM_FALLBACK"));
    }
    let path = project.path().join("bom.json");
    let written = raeva_command(project.path(), home.path())
        .args(["--json", "sbom", "--jdk", "21", "-o"])
        .arg(&path)
        .output()
        .unwrap();
    assert_success(&written, "JSON file response");
    let response: serde_json::Value = serde_json::from_slice(&written.stdout).unwrap();
    assert_eq!(
        response["data"]["targets"],
        serde_json::json!([
            {"platform": "linux-x86_64", "jdk": "21"},
            {"platform": "macos-aarch64", "jdk": "21"}
        ])
    );
    let before = all.stdout;
    let lock_path = project.path().join("raeva.lock");
    let mut lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    lock.platforms.reverse();
    lock.write_atomic(&lock_path).unwrap();
    let reordered = sbom(project.path(), home.path());
    assert_success(&reordered, "reordered targets");
    assert_eq!(reordered.stdout, before);
}

#[test]
fn sbom_rejects_target_specific_root_licenses() {
    let (project, home) = target_project(
        "<licenses><license><name>Private JDK ${java.version}</name></license></licenses>",
    );
    let combined = sbom(project.path(), home.path());
    assert_eq!(combined.status.code(), Some(2));
    let error = String::from_utf8_lossy(&combined.stderr);
    assert!(
        error.contains("demo@1 has different effective licenses")
            && error.contains("--platform and --jdk"),
        "{error}"
    );
    let mut identities = Vec::new();
    for jdk in ["17", "21"] {
        let selected = raeva_command(project.path(), home.path())
            .args(["sbom", "--jdk", jdk])
            .output()
            .unwrap();
        assert_success(&selected, "selected license environment");
        let document: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
        assert_eq!(
            document["metadata"]["component"]["licenses"][0]["license"]["name"],
            format!("Private JDK {jdk}")
        );
        identities.push(document["serialNumber"].clone());
    }
    assert_ne!(identities[0], identities[1]);
}

#[test]
fn sbom_applies_module_selection_before_target_ambiguity() {
    let (project, home) = temp_project();
    fs::write(project.path().join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><modules><module>stable</module><module>varying</module></modules></project>").unwrap();
    for module in ["stable", "varying"] {
        fs::create_dir(project.path().join(module)).unwrap();
        let profile = if module == "varying" {
            "<profiles><profile><id>jdk21</id><activation><jdk>21</jdk></activation><dependencies><dependency><groupId>com.example</groupId><artifactId>stable</artifactId><version>1</version></dependency></dependencies></profile></profiles>"
        } else {
            ""
        };
        fs::write(project.path().join(module).join("pom.xml"), format!("<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>{module}</artifactId><version>1</version>{profile}</project>")).unwrap();
    }
    fs::write(
        project.path().join("raeva.toml"),
        "[lock]\njdks = [\"17\", \"21\"]\n",
    )
    .unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline", "--platforms", "linux-x86_64"])
        .output()
        .unwrap();
    assert_success(&sync, "sync module graphs");
    let combined = sbom(project.path(), home.path());
    assert_eq!(combined.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&combined.stderr)
            .contains("different identities or dependency graphs")
    );
    for selector in ["stable/pom.xml", "com.example:stable"] {
        let selected = raeva_command(project.path(), home.path())
            .args(["sbom", "--module", selector])
            .output()
            .unwrap();
        assert_success(&selected, "unrelated graph is excluded");
        let document: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
        assert_eq!(document["metadata"]["component"]["name"], "stable");
        assert_eq!(
            document["metadata"]["properties"].as_array().unwrap().len(),
            2
        );
    }
    for jdk in ["17", "21"] {
        let selected = raeva_command(project.path(), home.path())
            .args(["sbom", "--jdk", jdk])
            .output()
            .unwrap();
        assert_success(&selected, "explicit graph target");
        let unknown = raeva_command(project.path(), home.path())
            .args(["sbom", "--jdk", jdk, "--module", "missing/pom.xml"])
            .output()
            .unwrap();
        assert_eq!(unknown.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&unknown.stderr).contains("SBOM of raeva.lock"));
    }
    // Each JDK builds another module set; no module differs between them.
    fs::write(project.path().join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><profiles><profile><id>jdk17</id><activation><jdk>17</jdk></activation><modules><module>stable</module></modules></profile><profile><id>jdk21</id><activation><jdk>21</jdk></activation><modules><module>varying</module></modules></profile></profiles></project>").unwrap();
    fs::write(project.path().join("varying/pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>varying</artifactId><version>1</version></project>").unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline", "--platforms", "linux-x86_64"])
        .output()
        .unwrap();
    assert_success(&sync, "sync disjoint module sets");
    let disjoint = sbom(project.path(), home.path());
    assert_success(&disjoint, "disjoint module graphs");
    let document: serde_json::Value = serde_json::from_slice(&disjoint.stdout).unwrap();
    assert_eq!(document["metadata"]["component"]["name"], "root");
    let names: Vec<_> = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| component["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["stable", "varying"]);
}

#[test]
fn sbom_rejects_target_specific_dependency_licenses_from_identical_pins() {
    let (project, home) = license_project();
    let pom_path = project
        .path()
        .join("repository/org/example/inherited/1/inherited-1.pom");
    let pom = fs::read_to_string(&pom_path).unwrap().replace(
        "<license.name>MIT</license.name>",
        "<license.name>Private JDK ${java.version}</license.name>",
    );
    fs::write(pom_path, pom).unwrap();
    fs::write(
        project.path().join("raeva.toml"),
        "[lock]\njdks = [\"17\", \"21\"]\n",
    )
    .unwrap();
    fs::remove_file(project.path().join("raeva.lock")).unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline", "--platforms", "linux-x86_64"])
        .output()
        .unwrap();
    assert_success(&sync, "sync target-specific dependency license");
    let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).unwrap();
    assert_eq!(lock.platforms[0].artifacts, lock.platforms[1].artifacts);
    assert_eq!(lock.platforms[0].modules, lock.platforms[1].modules);
    let combined = sbom(project.path(), home.path());
    assert_eq!(combined.status.code(), Some(2));
    let error = String::from_utf8_lossy(&combined.stderr);
    assert!(
        error.contains("inherited@1 has different effective licenses"),
        "{error}"
    );
    for jdk in ["17", "21"] {
        let selected = raeva_command(project.path(), home.path())
            .args(["sbom", "--jdk", jdk])
            .output()
            .unwrap();
        assert_success(&selected, "dependency license environment");
        let document: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
        let inherited = document["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "inherited")
            .unwrap();
        assert_eq!(
            inherited["licenses"][0]["license"]["name"],
            format!("Private JDK {jdk}")
        );
    }
}

#[test]
fn sbom_parent_ranges_use_snapshot_model_and_parent_aliases() {
    let (project, home) = range_parent_project(true, false);
    for repo in ["both", "low"] {
        let repository = project.path().join(repo);
        for (artifact, timestamp, build, body) in [
            (
                "snap-parent",
                "20240101.010101",
                3,
                "<packaging>pom</packaging><parent><groupId>g</groupId><artifactId>grand</artifactId><version>[1,3)</version><relativePath/></parent><licenses><license><name>${license.name}</name></license></licenses>",
            ),
            (
                "snap-lib",
                "20240101.010102",
                2,
                "<parent><groupId>g</groupId><artifactId>snap-parent</artifactId><version>[1-SNAPSHOT]</version><relativePath/></parent>",
            ),
        ] {
            let dir = repository.join("g").join(artifact).join("1-SNAPSHOT");
            let file_version = format!("1-{timestamp}-{build}");
            write_range_pom(&repository, artifact, "1-SNAPSHOT", &file_version, body);
            let jar = if artifact == "snap-lib" {
                fs::write(dir.join("snap-lib-1-20240101.010101-1.jar"), b"jar").unwrap();
                "<snapshotVersion><extension>jar</extension><value>1-20240101.010101-1</value><updated>20240101010101</updated></snapshotVersion>"
            } else {
                ""
            };
            fs::write(dir.join("maven-metadata.xml"), format!("<metadata><groupId>g</groupId><artifactId>{artifact}</artifactId><version>1-SNAPSHOT</version><versioning><snapshotVersions>{jar}<snapshotVersion><extension>pom</extension><value>{file_version}</value><updated>20240101010102</updated></snapshotVersion></snapshotVersions></versioning></metadata>")).unwrap();
        }
    }
    for module in ["a", "b"] {
        let path = project.path().join(module).join("pom.xml");
        let xml = fs::read_to_string(&path).unwrap().replace("</project>", "<dependencies><dependency><groupId>g</groupId><artifactId>snap-lib</artifactId><version>1-SNAPSHOT</version></dependency></dependencies></project>");
        fs::write(path, xml).unwrap();
    }
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync snapshot range aliases");
    let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).unwrap();
    assert!(lock.platforms[0].artifacts[0].pom_snapshot.is_some());
    assert!(
        lock.platforms[0].support_poms["g:snap-parent:1-SNAPSHOT"]
            .snapshot
            .is_some()
    );
    fs::remove_dir_all(project.path().join("both")).unwrap();
    fs::remove_dir_all(project.path().join("low")).unwrap();
    for (module, root_license, dep_license) in [
        ("a/pom.xml", "MIT", "MIT"),
        ("b/pom.xml", "Apache-2.0", "BSD-2-Clause"),
    ] {
        let document = assert_selected_license(project.path(), home.path(), module, root_license);
        let lib = document["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "snap-lib")
            .unwrap();
        assert_eq!(lib["version"], "1-SNAPSHOT");
        assert_eq!(
            lib["licenses"],
            serde_json::json!([{"license": {"id": dep_license}}])
        );
    }
}

#[test]
fn sbom_parent_ranges_survive_reactor_version_only_changes_without_rewriting_lock() {
    for reactor_dependency in [false, true] {
        let (project, home) = range_parent_project(false, false);
        let b_path = project.path().join("b/pom.xml");
        if reactor_dependency {
            let xml = fs::read_to_string(&b_path).unwrap().replace("</project>", "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies></project>");
            fs::write(&b_path, xml).unwrap();
            let sync = raeva_command(project.path(), home.path())
                .args(["sync", "--offline"])
                .output()
                .unwrap();
            assert_success(&sync, "sync reactor dependency with a parent range");
        }
        let lock_path = project.path().join("raeva.lock");
        let lock_bytes = fs::read(&lock_path).unwrap();
        let a_path = project.path().join("a/pom.xml");
        let bump = |path: &Path| {
            let xml = fs::read_to_string(path).unwrap().replace(
                "<artifactId>a</artifactId><version>1</version>",
                "<artifactId>a</artifactId><version>9</version>",
            );
            fs::write(path, xml).unwrap();
        };
        bump(&a_path);
        if reactor_dependency {
            bump(&b_path);
        }
        let frozen = raeva_command(project.path(), home.path())
            .args(["sync", "--frozen", "--offline"])
            .output()
            .unwrap();
        assert_success(
            &frozen,
            "frozen accepts reactor version changes with parent ranges",
        );
        let selected =
            assert_selected_license(project.path(), home.path(), "a/pom.xml", "Apache-2.0");
        assert_eq!(selected["metadata"]["component"]["version"], "9");
        let whole = sbom(project.path(), home.path());
        assert_success(&whole, "whole SBOM after a reactor version change");
        if reactor_dependency {
            let b =
                assert_selected_license(project.path(), home.path(), "b/pom.xml", "BSD-2-Clause");
            let a = b["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == "a")
                .unwrap();
            assert_eq!(a["version"], "9");
            assert_eq!(
                a["licenses"],
                serde_json::json!([{"license": {"id": "Apache-2.0"}}])
            );
        }
        assert_eq!(fs::read(lock_path).unwrap(), lock_bytes);
    }
}

#[test]
fn sbom_parent_range_changes_drift_even_with_identical_support_pom_union() {
    let (project, home) = range_parent_project(true, false);
    let a_path = project.path().join("a/pom.xml");
    let a = fs::read_to_string(&a_path).unwrap();
    fs::create_dir(project.path().join("c")).unwrap();
    fs::write(
        project.path().join("c/pom.xml"),
        a.replace("<artifactId>a</artifactId>", "<artifactId>c</artifactId>")
            .replace("<version>[1,3)</version>", "<version>1</version>"),
    )
    .unwrap();
    let root_path = project.path().join("pom.xml");
    fs::write(
        &root_path,
        fs::read_to_string(&root_path)
            .unwrap()
            .replace("</modules>", "<module>c</module></modules>"),
    )
    .unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync pins both parent lineages");
    let lock_path = project.path().join("raeva.lock");
    let old = rv_lock::Lockfile::read(&lock_path).unwrap();
    fs::copy(&lock_path, project.path().join("old.lock")).unwrap();
    fs::write(&a_path, a.replace("/low/", "/both/")).unwrap();
    let frozen = raeva_command(project.path(), home.path())
        .args(["sync", "--frozen", "--offline"])
        .output()
        .unwrap();
    assert_eq!(frozen.status.code(), Some(7));
    let error = String::from_utf8_lossy(&frozen.stderr);
    assert!(
        error.contains(
            "parent range g:parent:[1,3) for g:a:1 in a/pom.xml: g:parent:1 -> g:parent:2"
        ),
        "{error}"
    );
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync records the changed parent selection");
    let new = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert_eq!(old.platforms[0].support_poms, new.platforms[0].support_poms);
    let diff = raeva_command(project.path(), home.path())
        .current_dir(project.path())
        .args(["--json", "lock", "diff", "old.lock"])
        .output()
        .unwrap();
    assert_success(&diff, "lock diff includes selected parent changes");
    let diff: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert_eq!(diff["data"]["changed"], true);
    let changes = diff["data"]["pom_changes"].as_array().unwrap();
    assert!(
        changes
            .iter()
            .any(|change| change["change"] == "parent_range"
                && change["module"] == "a/pom.xml"
                && change["model"] == "g:a:1"
                && change["coordinate"] == "g:parent:[1,3)"
                && change["old"] == "g:parent:1"
                && change["new"] == "g:parent:2")
    );
    assert_selected_license(project.path(), home.path(), "a/pom.xml", "Apache-2.0");
}

#[test]
fn sbom_parent_ranges_keep_the_winning_model_repository_context() {
    let (project, home) = range_parent_project(true, true);
    fs::write(
        project.path().join("raeva.toml"),
        "[security]\nallow_transitive_repositories = true\n",
    )
    .unwrap();
    for (artifact, repo, version) in [("left", "low", "1"), ("right", "both", "[1]")] {
        let url = url::Url::from_directory_path(project.path().join(repo)).unwrap();
        let body = format!(
            "<repositories><repository><id>choice</id><url>{url}</url></repository></repositories><dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>{version}</version></dependency></dependencies>"
        );
        write_range_pom(&project.path().join("low"), artifact, "1", "1", &body);
        fs::write(
            project
                .path()
                .join("low/g")
                .join(artifact)
                .join("1")
                .join(format!("{artifact}-1.jar")),
            b"jar",
        )
        .unwrap();
    }
    let path = project.path().join("a/pom.xml");
    fs::write(&path, fs::read_to_string(&path).unwrap().replace("<artifactId>lib</artifactId><version>1</version></dependency>", "<artifactId>left</artifactId><version>1</version></dependency><dependency><groupId>g</groupId><artifactId>right</artifactId><version>1</version></dependency>")).unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync competing model repository contexts");
    let lock = rv_lock::Lockfile::read(&project.path().join("raeva.lock")).unwrap();
    let a = lock.platforms[0]
        .modules
        .iter()
        .find(|m| m.path == "a/pom.xml")
        .unwrap();
    let ranges: Vec<_> = a
        .parent_ranges
        .iter()
        .filter(|s| s.model == "g:lib:1" && s.parent == "g:parent:[1,3)")
        .collect();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].selected, "g:parent:1");
    let selected = assert_selected_license(project.path(), home.path(), "a/pom.xml", "MIT");
    let lib = selected["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "lib")
        .unwrap();
    assert_eq!(
        lib["licenses"],
        serde_json::json!([{"license": {"id": "MIT"}}])
    );
}

#[test]
fn sbom_local_parent_ranges_need_no_remote_selection_record() {
    let (project, home) = temp_project();
    fs::write(project.path().join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><licenses><license><name>MIT</name></license></licenses><modules><module>a</module></modules></project>").unwrap();
    fs::create_dir(project.path().join("a")).unwrap();
    fs::write(project.path().join("a/pom.xml"), "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId><artifactId>root</artifactId><version>[1,3)</version></parent><artifactId>a</artifactId><version>1</version></project>").unwrap();
    let sync = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync a local parent range");
    let lock_path = project.path().join("raeva.lock");
    let bytes = fs::read(&lock_path).unwrap();
    let lock = rv_lock::Lockfile::read(&lock_path).unwrap();
    assert!(
        lock.platforms[0]
            .modules
            .iter()
            .all(|m| m.parent_ranges.is_empty())
    );
    let root = project.path().join("pom.xml");
    fs::write(
        &root,
        fs::read_to_string(&root)
            .unwrap()
            .replace("<version>1</version>", "<version>2</version>"),
    )
    .unwrap();
    let frozen = raeva_command(project.path(), home.path())
        .args(["sync", "--frozen", "--offline"])
        .output()
        .unwrap();
    assert_success(
        &frozen,
        "frozen accepts a local range parent's version change",
    );
    assert_selected_license(project.path(), home.path(), "a/pom.xml", "MIT");
    assert_eq!(fs::read(lock_path).unwrap(), bytes);
}

/// A reactor module's model is the one its own repositories give, as Maven
/// takes it from the reactor: a module that depends on it, with a
/// repository that has a newer parent in its range, sees the same parent,
/// dependencies and licenses.
#[test]
fn a_reactor_dependency_keeps_the_parent_its_own_repositories_select() {
    let (project, home) = temp_project();
    let root = project.path();
    let publish = |repo: &str, artifact: &str, version: &str, body: &str| {
        let dir = root.join(format!("{repo}/g/{artifact}/{version}"));
        fs::create_dir_all(&dir).unwrap();
        let packaging = if body.is_empty() { "jar" } else { "pom" };
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
             <artifactId>{artifact}</artifactId><version>{version}</version>\
             <packaging>{packaging}</packaging>{body}</project>"
        );
        let mut files = vec![(format!("{artifact}-{version}.pom"), pom.into_bytes())];
        if body.is_empty() {
            files.push((format!("{artifact}-{version}.jar"), b"jar".to_vec()));
        }
        for (name, bytes) in files {
            fs::write(dir.join(&name), &bytes).unwrap();
            fs::write(
                dir.join(format!("{name}.sha256")),
                crate::common::sha256_hex(&bytes),
            )
            .unwrap();
        }
    };
    let parent = |dependency: &str, license: &str| {
        format!(
            "<licenses><license><name>{license}</name></license></licenses><dependencies>\
             <dependency><groupId>g</groupId><artifactId>{dependency}</artifactId>\
             <version>1</version></dependency></dependencies>"
        )
    };
    for repo in ["low", "both"] {
        publish(repo, "one", "1", "");
        publish(repo, "two", "1", "");
        publish(repo, "parent", "1", &parent("one", "MIT"));
    }
    publish("both", "parent", "2", &parent("two", "Apache-2.0"));
    for (repo, versions) in [
        ("low", "<version>1</version>"),
        ("both", "<version>1</version><version>2</version>"),
    ] {
        let metadata = format!(
            "<metadata><groupId>g</groupId><artifactId>parent</artifactId><versioning>\
             <versions>{versions}</versions></versioning></metadata>"
        );
        let path = root.join(format!("{repo}/g/parent/maven-metadata.xml"));
        fs::write(&path, &metadata).unwrap();
        fs::write(
            path.with_extension("xml.sha256"),
            crate::common::sha256_hex(metadata.as_bytes()),
        )
        .unwrap();
    }
    let repository = |id: &str| {
        format!(
            "<repositories><repository><id>{id}</id>\
             <url>file://{}/{id}/</url></repository></repositories>",
            root.display()
        )
    };
    fs::write(root.join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>root</artifactId><version>1</version><packaging>pom</packaging><modules><module>a</module><module>b</module></modules></project>").unwrap();
    for (module, body) in [
        (
            "a",
            format!(
                "<parent><groupId>g</groupId><artifactId>parent</artifactId><version>[1,3)</version><relativePath/></parent><artifactId>a</artifactId><version>1</version>{}",
                repository("low")
            ),
        ),
        (
            "b",
            format!(
                "<groupId>g</groupId><artifactId>b</artifactId><version>1</version>{}<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies>",
                repository("both")
            ),
        ),
    ] {
        fs::create_dir(root.join(module)).unwrap();
        fs::write(
            root.join(module).join("pom.xml"),
            format!("<project><modelVersion>4.0.0</modelVersion>{body}</project>"),
        )
        .unwrap();
    }
    let sync = raeva_command(root, home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync");
    let lock = rv_lock::Lockfile::read(&root.join("raeva.lock")).unwrap();
    for module in &lock.platforms[0].modules {
        let selected: Vec<_> = (module.parent_ranges.iter())
            .map(|range| range.selected.as_str())
            .collect();
        assert!(
            selected.iter().all(|selected| *selected == "g:parent:1"),
            "{}: {selected:?}",
            module.path
        );
        let packages = format!("{:?}", module.packages);
        assert!(!packages.contains("\"two\""), "{}: {packages}", module.path);
    }
    let selected = raeva_command(root, home.path())
        .args(["sbom", "--offline", "--module", "b/pom.xml"])
        .output()
        .unwrap();
    assert_success(&selected, "sbom of b");
    let document: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
    let a = (document["components"].as_array().unwrap().iter())
        .find(|component| component["name"] == "a")
        .unwrap();
    assert_eq!(
        a["licenses"],
        serde_json::json!([{"license": {"id": "MIT"}}])
    );
}

/// A dependency whose parent range selects a reactor module inherits that
/// module's license, as resolution reads its parent from the reactor.
#[test]
fn a_dependency_parent_range_can_select_a_reactor_module() {
    let (project, home) = temp_project();
    let root = project.path();
    let dir = root.join("repository/ext/ext/1");
    fs::create_dir_all(&dir).unwrap();
    let pom = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
        <artifactId>root</artifactId><version>[1,2)</version><relativePath/></parent>\
        <groupId>ext</groupId><artifactId>ext</artifactId><version>1</version></project>";
    for (name, bytes) in [("ext-1.pom", pom.as_bytes()), ("ext-1.jar", b"jar")] {
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
    fs::write(
        root.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <licenses><license><name>MIT</name></license></licenses>\
             <repositories><repository><id>local</id><url>file://{}/repository/</url>\
             </repository></repositories><modules><module>a</module></modules></project>",
            root.display()
        ),
    )
    .unwrap();
    fs::create_dir(root.join("a")).unwrap();
    fs::write(
        root.join("a/pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
         <artifactId>root</artifactId><version>1</version></parent><artifactId>a</artifactId>\
         <dependencies><dependency><groupId>ext</groupId><artifactId>ext</artifactId>\
         <version>1</version></dependency></dependencies></project>",
    )
    .unwrap();
    let sync = raeva_command(root, home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync");
    let sbom = raeva_command(root, home.path())
        .args(["sbom", "--offline"])
        .output()
        .unwrap();
    assert_success(&sbom, "sbom");
    let document: serde_json::Value = serde_json::from_slice(&sbom.stdout).unwrap();
    let ext = (document["components"].as_array().unwrap().iter())
        .find(|component| component["name"] == "ext")
        .unwrap();
    assert_eq!(
        ext["licenses"],
        serde_json::json!([{"license": {"id": "MIT"}}])
    );
}

/// A dependency whose parent is a reactor module with a version only its
/// remote parent decides inherits that module's license, as resolution reads
/// the module under its effective coordinates.
#[test]
fn a_dependency_parent_can_be_a_module_whose_version_a_remote_parent_decides() {
    let (project, home) = temp_project();
    let root = project.path();
    let publish = |path: &str, name: &str, bytes: &[u8]| {
        let dir = root.join("repository").join(path);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    };
    publish(
        "g/remote/1",
        "remote-1.pom",
        b"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
          <artifactId>remote</artifactId><version>1</version><packaging>pom</packaging>\
          <properties><p.version>1</p.version></properties></project>",
    );
    publish(
        "ext/ext/1",
        "ext-1.pom",
        b"<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
          <artifactId>p</artifactId><version>1</version><relativePath/></parent>\
          <groupId>ext</groupId><artifactId>ext</artifactId><version>1</version></project>",
    );
    publish("ext/ext/1", "ext-1.jar", b"jar");
    let repositories = format!(
        "<repositories><repository><id>local</id><url>file://{}/repository/</url>\
         </repository></repositories>",
        root.display()
    );
    let files = [
        (
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
             <artifactId>root</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>p</module><module>a</module></modules></project>"
                .to_owned(),
        ),
        (
            "p/pom.xml",
            format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>\
                 <artifactId>remote</artifactId><version>1</version><relativePath/></parent>\
                 <artifactId>p</artifactId><version>${{p.version}}</version>\
                 <packaging>pom</packaging><licenses><license><name>MIT</name></license>\
                 </licenses>{repositories}</project>"
            ),
        ),
        (
            "a/pom.xml",
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
                 <artifactId>a</artifactId><version>1</version>{repositories}<dependencies>\
                 <dependency><groupId>ext</groupId><artifactId>ext</artifactId>\
                 <version>1</version></dependency></dependencies></project>"
            ),
        ),
    ];
    for (path, text) in files {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let sync = raeva_command(root, home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync");
    let sbom = raeva_command(root, home.path())
        .args(["sbom", "--offline"])
        .output()
        .unwrap();
    assert_success(&sbom, "sbom");
    let document: serde_json::Value = serde_json::from_slice(&sbom.stdout).unwrap();
    let ext = (document["components"].as_array().unwrap().iter())
        .find(|component| component["name"] == "ext")
        .unwrap();
    assert_eq!(
        ext["licenses"],
        serde_json::json!([{"license": {"id": "MIT"}}])
    );
}

/// A dependency whose POM does not parse keeps its row without a model, as
/// resolution keeps it, and the SBOM lists it without licenses.
#[test]
fn a_dependency_with_an_unparseable_pom_has_no_licenses() {
    let (project, home) = temp_project();
    let root = project.path();
    let dir = root.join("repository/ext/ext/1");
    fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in [
        ("ext-1.pom", b"<project><licenses>".as_slice()),
        ("ext-1.jar", b"jar"),
    ] {
        fs::write(dir.join(name), bytes).unwrap();
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .unwrap();
    }
    fs::write(
        root.join("pom.xml"),
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
             <artifactId>app</artifactId><version>1</version>\
             <repositories><repository><id>local</id><url>file://{}/repository/</url>\
             </repository></repositories><dependencies><dependency><groupId>ext</groupId>\
             <artifactId>ext</artifactId><version>1</version></dependency></dependencies>\
             </project>",
            root.display()
        ),
    )
    .unwrap();
    let sync = raeva_command(root, home.path())
        .args(["sync", "--offline"])
        .output()
        .unwrap();
    assert_success(&sync, "sync");
    let sbom = raeva_command(root, home.path())
        .args(["sbom", "--offline"])
        .output()
        .unwrap();
    assert_success(&sbom, "sbom");
    let document: serde_json::Value = serde_json::from_slice(&sbom.stdout).unwrap();
    let ext = (document["components"].as_array().unwrap().iter())
        .find(|component| component["name"] == "ext")
        .unwrap();
    assert!(ext.get("licenses").is_none(), "{ext}");
}
