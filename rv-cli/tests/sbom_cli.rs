mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use common::{rv_command, temp_project};
use rv_config::{Checksum, LockEdge, LockPackage, LockPlatform, Lockfile};

fn write_pom(project_root: &Path) {
    fs::write(
        project_root.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
</project>
"#,
    )
    .expect("write pom.xml");
}

fn package(artifact_id: &str, packaging: &str, classifier: Option<&str>) -> LockPackage {
    LockPackage {
        group_id: "org.example".to_string(),
        artifact_id: artifact_id.to_string(),
        version: "2.0.0".to_string(),
        snapshot_timestamp: None,
        packaging: packaging.to_string(),
        classifier: classifier.map(str::to_string),
        repo_url: "https://repo.example/maven2".to_string(),
        checksum: Some(Checksum::new(
            "sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )),
        system_path: None,
        direct_scope: Some("compile".to_string()),
        extra: BTreeMap::new(),
    }
}

fn write_fresh_lock(project_root: &Path, home: &Path) {
    write_pom(project_root);
    let output = rv_command(project_root, home)
        .args(["--quiet", "sync", "--offline"])
        .output()
        .expect("run rv sync");
    assert!(
        output.status.success(),
        "sync failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = project_root.join("rv.lock");
    let mut lock = Lockfile::read(&lock_path).expect("read generated lock");
    let platform = lock.platforms.first_mut().expect("generated platform");
    let module = platform.modules.first().expect("generated module");
    let mut converted = LockPlatform::single_module(
        platform.platform.clone(),
        platform.model_hash.clone(),
        &module.path,
        module.gav.clone(),
        &module.packaging,
        vec![
            package("zeta", "test-jar", Some("tests")),
            package("alpha", "jar", None),
        ],
        vec![LockEdge {
            from: 0,
            to: 1,
            scope: Some("compile".to_string()),
            optional: false,
            extra: BTreeMap::new(),
        }],
    );
    platform.artifacts = std::mem::take(&mut converted.artifacts);
    platform.modules[0].packages = std::mem::take(&mut converted.modules[0].packages);
    platform.modules[0].edges = std::mem::take(&mut converted.modules[0].edges);
    lock.write_atomic(&lock_path).expect("write fixture lock");
}

#[test]
fn sbom_defaults_to_reproducible_cyclonedx_on_stdout() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());

    let first = rv_command(project.path(), home.path())
        .arg("sbom")
        .output()
        .expect("run rv sbom");
    let second = rv_command(project.path(), home.path())
        .arg("sbom")
        .output()
        .expect("run rv sbom again");
    assert!(first.status.success());
    assert!(second.status.success());
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

#[test]
fn sbom_spdx_namespace_tracks_creation_time_and_uses_noassertion() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());
    let first_path = project.path().join("first.spdx.json");
    let second_path = project.path().join("second.spdx.json");

    let first_output = rv_command(project.path(), home.path())
        .args(["sbom", "--format", "spdx", "-o"])
        .arg(&first_path)
        .output()
        .expect("run SPDX generation");
    let second_output = rv_command(project.path(), home.path())
        .args(["sbom", "--format", "spdx", "-o"])
        .arg(&second_path)
        .output()
        .expect("run SPDX generation again");
    assert!(first_output.status.success());
    assert!(second_output.status.success());
    assert!(first_output.stdout.is_empty());

    let first: serde_json::Value =
        serde_json::from_slice(&fs::read(&first_path).expect("read first SPDX"))
            .expect("SPDX JSON");
    let second: serde_json::Value =
        serde_json::from_slice(&fs::read(&second_path).expect("read second SPDX"))
            .expect("SPDX JSON");
    assert_eq!(first["spdxVersion"], "SPDX-2.3");
    assert_eq!(first["name"], "com.example:demo:1.0.0");
    assert_eq!(
        first["creationInfo"]["creators"][0],
        format!("Tool: rv-{}", env!("CARGO_PKG_VERSION"))
    );
    assert_ne!(
        first["creationInfo"]["created"],
        second["creationInfo"]["created"]
    );
    assert_ne!(first["documentNamespace"], second["documentNamespace"]);

    let packages = first["packages"].as_array().expect("packages");
    assert_eq!(packages.len(), 3);
    assert_eq!(packages[0]["name"], "demo");
    for package in packages {
        assert_eq!(package["licenseConcluded"], "NOASSERTION");
        assert_eq!(package["licenseDeclared"], "NOASSERTION");
        assert_eq!(package["copyrightText"], "NOASSERTION");
        assert_eq!(package["filesAnalyzed"], false);
    }
}

#[test]
fn sbom_spdx_is_reproducible_with_source_date_epoch() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());

    let first = rv_command(project.path(), home.path())
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .args(["sbom", "--format", "spdx"])
        .output()
        .expect("run SPDX generation");
    let second = rv_command(project.path(), home.path())
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .args(["sbom", "--format", "spdx"])
        .output()
        .expect("run SPDX generation again");

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    let document: serde_json::Value = serde_json::from_slice(&first.stdout).expect("SPDX JSON");
    assert_eq!(document["creationInfo"]["created"], "2023-11-14T22:13:20Z");
}

#[test]
fn sbom_spdx_rejects_invalid_source_date_epoch() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());

    let output = rv_command(project.path(), home.path())
        .env("SOURCE_DATE_EPOCH", "not-a-timestamp")
        .args(["sbom", "--format", "spdx"])
        .output()
        .expect("run SPDX generation");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("SOURCE_DATE_EPOCH must be a Unix timestamp")
    );
}
