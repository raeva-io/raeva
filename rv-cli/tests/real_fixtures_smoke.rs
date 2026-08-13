use std::path::{Path, PathBuf};

use rv_maven_model::{Pom, Scope};
use rv_resolver::{Edge, Graph, Node, Tree};
use rv_version::{Coord, Version};

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

fn parse_version_fallback(value: Option<&str>) -> Version {
    value
        .and_then(|version| Version::parse(version).ok())
        .unwrap_or_else(|| Version::parse("0.0.0").expect("fallback version is valid"))
}

#[test]
fn smoke_parses_fixture_and_builds_tree() {
    let Some(xml) = load_fixture("simple-single-module/commons-lang3-pom.xml") else {
        return;
    };

    let pom = Pom::parse(&xml).expect("fixture pom parses");
    let group_id = pom
        .group_id
        .clone()
        .or_else(|| pom.parent.as_ref().map(|parent| parent.group_id.clone()))
        .unwrap_or_else(|| "unknown.group".to_string());
    let artifact_id = pom
        .artifact_id
        .clone()
        .unwrap_or_else(|| "unknown-artifact".to_string());
    let root_artifact = artifact_id.clone();
    let version = parse_version_fallback(
        pom.version
            .as_deref()
            .or_else(|| pom.parent.as_ref().map(|parent| parent.version.as_str())),
    );

    let root = Node {
        coord: Coord {
            group_id: group_id.into(),
            artifact_id: artifact_id.into(),
            version,
            packaging: None,
            classifier: None,
        },
        scope: Scope::Compile,
        repo_url: None,
        checksum: None,
        workspace_module: None,
        local: false,
        system_path: None,
    };
    let mut graph = Graph::new(root);

    for dep in pom.dependencies.iter().take(3) {
        let dep_version = parse_version_fallback(dep.version.as_deref());
        let packaging = dep.type_.clone();
        let classifier = if packaging.is_some() {
            dep.classifier.clone()
        } else {
            None
        };
        let node = Node {
            coord: Coord {
                group_id: dep.group_id.clone().into(),
                artifact_id: dep.artifact_id.clone().into(),
                version: dep_version,
                packaging,
                classifier,
            },
            scope: dep.effective_scope(),
            repo_url: None,
            checksum: None,
            workspace_module: None,
            local: false,
            system_path: None,
        };
        let idx = graph.insert_node(node);
        graph.add_edge(
            graph.root(),
            idx,
            Edge {
                scope: dep.effective_scope(),
                optional: dep.effective_optional(),
                exclusions: dep.exclusions.clone(),
                requested: dep.version.clone(),
            },
        );
    }

    let tree = Tree::from_graph(&graph);
    let rendered = tree.render();
    assert!(!rendered.is_empty());
    assert!(rendered.contains(&root_artifact));
}
