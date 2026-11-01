//! Every POM under `test-fixtures` parses, and a few published POMs parse to
//! the values they declare.

use std::collections::BTreeMap;

use rv_maven_model::Pom;
use rv_test_support::fixtures;

fn parse_fixture(rel_path: &str) -> Pom {
    let path = fixtures::path(rel_path);
    let xml = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()));
    Pom::parse(&xml).unwrap_or_else(|err| panic!("failed to parse {rel_path}: {err}"))
}

fn is_pom(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name == "pom.xml" || name.ends_with("-pom.xml")
}

/// Copied published POMs are the Copied POMs table in `test-fixtures/README.md`.
/// A new file must fail here until it is listed and, for field checks, added
/// to [`published_poms_parse_to_their_declared_values`].
#[test]
fn every_copied_pom_fixture_is_listed() {
    let readme = fixtures::workspace_file("test-fixtures/README.md");
    let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in fixtures::markdown_first_column(&readme, "## Copied POMs") {
        let (dir, name) = path
            .split_once('/')
            .unwrap_or_else(|| panic!("Copied POMs table path {path}"));
        assert!(
            !name.contains('/') && (name == "pom.xml" || name.ends_with("-pom.xml")),
            "copied POM must be pom.xml or *-pom.xml in {dir}: {path}"
        );
        by_dir
            .entry(dir.to_string())
            .or_default()
            .push(name.to_string());
    }
    for (dir, mut names) in by_dir {
        names.sort();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        fixtures::assert_children(&fixtures::path(&dir), &[], &names);
    }
}

#[test]
fn parses_every_fixture() {
    let root = fixtures::root();
    let files: Vec<String> = fixtures::sorted_relative_files(&root)
        .into_iter()
        .filter(|rel| is_pom(rel) && !rel.starts_with("maven-parity/pom-markup/"))
        .collect();
    assert!(files.len() > 40, "found only {} fixtures", files.len());
    for rel in files {
        let path = root.join(&rel);
        let bytes =
            std::fs::read(&path).unwrap_or_else(|err| panic!("failed to read {rel}: {err}"));
        let xml = rv_maven_model::decode_pom(&bytes)
            .unwrap_or_else(|err| panic!("failed to decode {rel}: {err}"));
        Pom::parse(&xml).unwrap_or_else(|err| panic!("failed to parse {rel}: {err}"));
    }
}

#[test]
fn published_poms_parse_to_their_declared_values() {
    let lang3 = parse_fixture("simple-single-module/commons-lang3-pom.xml");
    let parent = lang3.parent.as_ref().map(|parent| parent.group_id.as_str());
    assert_eq!(parent, Some("org.apache.commons"));
    assert_eq!(lang3.artifact_id.as_deref(), Some("commons-lang3"));
    assert_eq!(lang3.version.as_deref(), Some("3.21.0-SNAPSHOT"));
    assert_eq!(lang3.dependencies.len(), 7);
    assert!(
        lang3
            .dependencies
            .iter()
            .all(|dep| dep.scope.as_deref() == Some("test"))
    );

    for (fixture, artifact_id, version) in [
        (
            "bom-usage/jackson-bom-pom.xml",
            "jackson-databind",
            "${jackson.version.databind}",
        ),
        ("bom-usage/guava-bom-pom.xml", "guava", "${project.version}"),
    ] {
        let pom = parse_fixture(fixture);
        let managed = &pom
            .dependency_management
            .as_ref()
            .expect(fixture)
            .dependencies;
        let entry = managed
            .iter()
            .find(|dep| dep.artifact_id == artifact_id)
            .expect(artifact_id);
        assert_eq!(entry.version.as_deref(), Some(version), "{fixture}");
    }

    let netty = parse_fixture("profile-based/netty-parent-pom.xml");
    assert!(netty.profiles.len() >= 34);
    assert!(netty.profiles.iter().all(|profile| !profile.id.is_empty()));

    let shade = parse_fixture("dependency-types/maven-shade-plugin-pom.xml");
    let provided = shade
        .dependencies
        .iter()
        .filter(|dep| dep.scope.as_deref() == Some("provided"));
    assert_eq!(provided.count(), 6);
    assert!(
        shade
            .dependencies
            .iter()
            .all(|dep| dep.type_.is_none() && dep.classifier.is_none())
    );
}
