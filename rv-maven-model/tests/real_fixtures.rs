use std::path::{Path, PathBuf};

use rv_maven_model::Pom;

const FIXTURE_ROOT: &str = "test-fixtures";

fn fixture_path(rel_path: &str) -> PathBuf {
    let preferred = PathBuf::from(FIXTURE_ROOT).join(rel_path);
    if preferred.exists() {
        return preferred;
    }

    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-fixtures")
        .join(rel_path)
}

fn load_fixture(rel_path: &str) -> Option<String> {
    let path = fixture_path(rel_path);
    assert!(
        path.exists(),
        "fixture {rel_path} missing at {}; repo-shipped fixtures must be present, not silently skipped",
        path.display()
    );
    let contents = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "failed to read fixture {rel_path} at {}: {err}",
            path.display()
        )
    });
    Some(contents)
}

fn parse_fixture(rel_path: &str) -> Option<Pom> {
    let xml = load_fixture(rel_path)?;
    Some(Pom::parse(&xml).unwrap_or_else(|err| panic!("failed to parse {rel_path}: {err}")))
}

#[test]
fn parses_commons_lang3() {
    let Some(pom) = parse_fixture("simple-single-module/commons-lang3-pom.xml") else {
        return;
    };

    assert_eq!(
        pom.parent.as_ref().map(|parent| parent.group_id.as_str()),
        Some("org.apache.commons")
    );
    assert_eq!(pom.artifact_id.as_deref(), Some("commons-lang3"));
    assert_eq!(pom.version.as_deref(), Some("3.21.0-SNAPSHOT"));
    assert_eq!(pom.dependencies.len(), 7);
    assert!(
        pom.dependencies
            .iter()
            .all(|dep| dep.scope.as_deref() == Some("test"))
    );
}

#[test]
fn parses_jackson_bom_dependency_management() {
    let Some(pom) = parse_fixture("bom-usage/jackson-bom-pom.xml") else {
        return;
    };

    let managed = pom
        .dependency_management
        .as_ref()
        .expect("expected dependencyManagement");
    assert!(!managed.dependencies.is_empty());

    let databind = managed
        .dependencies
        .iter()
        .find(|dep| {
            dep.group_id == "com.fasterxml.jackson.core" && dep.artifact_id == "jackson-databind"
        })
        .expect("missing jackson-databind");
    assert_eq!(
        databind.version.as_deref(),
        Some("${jackson.version.databind}")
    );
}

#[test]
fn parses_netty_parent_profiles() {
    let Some(pom) = parse_fixture("profile-based/netty-parent-pom.xml") else {
        return;
    };

    assert!(pom.profiles.len() >= 34);
    assert!(pom.profiles.iter().all(|profile| !profile.id.is_empty()));
}

#[test]
fn parses_maven_shade_plugin_dependencies() {
    let Some(pom) = parse_fixture("dependency-types/maven-shade-plugin-pom.xml") else {
        return;
    };

    let provided: Vec<_> = pom
        .dependencies
        .iter()
        .filter(|dep| dep.scope.as_deref() == Some("provided"))
        .collect();
    assert_eq!(provided.len(), 6);
    assert!(pom.dependencies.iter().all(|dep| dep.type_.is_none()));
    assert!(pom.dependencies.iter().all(|dep| dep.classifier.is_none()));
    assert_eq!(provided[0].effective_type(), "jar");
}
