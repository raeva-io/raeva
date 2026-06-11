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
fn parses_all_real_fixtures() {
    let fixtures = [
        "simple-single-module/commons-lang3-pom.xml",
        "bom-usage/jackson-bom-pom.xml",
        "bom-usage/guava-bom-pom.xml",
        "profile-based/netty-parent-pom.xml",
        "dependency-types/maven-shade-plugin-pom.xml",
    ];

    for fixture in fixtures {
        let Some(xml) = load_fixture(fixture) else {
            continue;
        };
        Pom::parse(&xml).unwrap_or_else(|err| panic!("failed to parse {fixture}: {err}"));
    }
}

#[test]
fn simple_fixture_dependencies_and_scopes() {
    let Some(pom) = parse_fixture("simple-single-module/commons-lang3-pom.xml") else {
        return;
    };

    assert_eq!(pom.dependencies.len(), 7);
    assert!(
        pom.dependencies
            .iter()
            .all(|dep| dep.scope.as_deref() == Some("test"))
    );
}

#[test]
fn bom_managed_versions_available() {
    let Some(jackson) = parse_fixture("bom-usage/jackson-bom-pom.xml") else {
        return;
    };
    let jackson_managed = jackson
        .dependency_management
        .as_ref()
        .expect("jackson-bom missing dependencyManagement");
    let jackson_databind = jackson_managed
        .dependencies
        .iter()
        .find(|dep| {
            dep.group_id == "com.fasterxml.jackson.core" && dep.artifact_id == "jackson-databind"
        })
        .expect("missing jackson-databind");
    assert!(jackson_databind.version.is_some());

    let Some(guava) = parse_fixture("bom-usage/guava-bom-pom.xml") else {
        return;
    };
    let guava_managed = guava
        .dependency_management
        .as_ref()
        .expect("guava-bom missing dependencyManagement");
    let guava_dep = guava_managed
        .dependencies
        .iter()
        .find(|dep| dep.artifact_id == "guava")
        .expect("missing guava");
    assert_eq!(guava_dep.version.as_deref(), Some("${project.version}"));
}

#[test]
fn profile_fixture_counts_and_structure() {
    let Some(pom) = parse_fixture("profile-based/netty-parent-pom.xml") else {
        return;
    };

    assert!(pom.profiles.len() >= 34);
    assert!(pom.profiles.iter().all(|profile| !profile.id.is_empty()));
}
