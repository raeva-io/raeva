use std::collections::HashMap;
use std::sync::Arc;

use super::{
    Backend, ConstraintVersion, PlatformConstraint, PlatformConstraints, ResolvedProject,
    ResolvedVersion, Solver, SolverRoot,
};
use crate::ResolutionStrategy;
use crate::error::ResolveError;
use crate::graph::Graph;
use rv_maven_model::{Dependency, DependencyManagement, Project, Relocation, Scope};
use rv_version::{Coord, Version, VersionReq};

#[derive(Default)]
struct MockBackend {
    projects: HashMap<String, Project>,
    versions: HashMap<String, Vec<Version>>,
    platform_constraints: HashMap<String, PlatformConstraints>,
}

impl MockBackend {
    fn with_project(mut self, coord: &Coord, deps: Vec<Dependency>) -> Self {
        let project = Project {
            group_id: coord.group_id.to_string(),
            artifact_id: coord.artifact_id.to_string(),
            version: coord.version.to_string(),
            packaging: "jar".to_string(),
            properties: Default::default(),
            dependency_management: DependencyManagement::default(),
            dependencies: deps,
            repositories: Vec::new(),
            profiles: Vec::new(),
            modules: Vec::new(),
            relocation: None,
        };
        self.projects.insert(coord.to_string(), project);
        self
    }

    /// Like [`with_project`] but also attaches the artifact's effective
    /// `<dependencyManagement>`. Mirrors what the model layer produces for a
    /// fetched POM: parent-chain and BOM management already merged in. Used to
    /// exercise the solver's version-fill for a versionless child.
    fn with_project_and_mgmt(
        mut self,
        coord: &Coord,
        deps: Vec<Dependency>,
        management: Vec<Dependency>,
    ) -> Self {
        let project = Project {
            group_id: coord.group_id.to_string(),
            artifact_id: coord.artifact_id.to_string(),
            version: coord.version.to_string(),
            packaging: "jar".to_string(),
            properties: Default::default(),
            dependency_management: DependencyManagement {
                dependencies: management,
            },
            dependencies: deps,
            repositories: Vec::new(),
            profiles: Vec::new(),
            modules: Vec::new(),
            relocation: None,
        };
        self.projects.insert(coord.to_string(), project);
        self
    }

    fn with_relocated_project(
        mut self,
        coord: &Coord,
        relocation: Relocation,
        deps: Vec<Dependency>,
    ) -> Self {
        let project = Project {
            group_id: coord.group_id.to_string(),
            artifact_id: coord.artifact_id.to_string(),
            version: coord.version.to_string(),
            packaging: "jar".to_string(),
            properties: Default::default(),
            dependency_management: DependencyManagement::default(),
            dependencies: deps,
            repositories: Vec::new(),
            profiles: Vec::new(),
            modules: Vec::new(),
            relocation: Some(relocation),
        };
        self.projects.insert(coord.to_string(), project);
        self
    }

    fn with_versions(mut self, group_id: &str, artifact_id: &str, versions: Vec<&str>) -> Self {
        let key = format!("{group_id}:{artifact_id}");
        let parsed = versions
            .into_iter()
            .map(|v| Version::parse(v).unwrap())
            .collect();
        self.versions.insert(key, parsed);
        self
    }

    fn with_platform_constraints(
        mut self,
        coord: &Coord,
        constraints: PlatformConstraints,
    ) -> Self {
        self.platform_constraints
            .insert(coord.to_string(), constraints);
        self
    }

    fn key(group_id: &str, artifact_id: &str) -> String {
        format!("{group_id}:{artifact_id}")
    }
}

impl Backend for MockBackend {
    fn resolve_version<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
    ) -> super::BoxFuture<'a, super::Result<ResolvedVersion>> {
        Box::pin(async move {
            let key = MockBackend::key(group_id, artifact_id);
            let versions =
                self.versions
                    .get(&key)
                    .ok_or_else(|| ResolveError::ArtifactNotFound {
                        coord: key.clone(),
                        searched: Vec::new(),
                    })?;
            let mut selected = None;
            let dynamic = match req {
                VersionReq::Exact(version) | VersionReq::Soft(version) => {
                    match version.as_str().to_ascii_lowercase().as_str() {
                        "release" | "latest.release" => Some("release"),
                        "latest" | "latest.integration" => Some("latest"),
                        _ => None,
                    }
                }
                VersionReq::Ranges(_) => None,
            };
            for version in versions {
                let matches = match dynamic {
                    Some("release") => !version.as_str().ends_with("-SNAPSHOT"),
                    Some("latest") => true,
                    _ => req.matches(version),
                };
                if matches {
                    selected = Some(match selected {
                        Some(current) if current > version.clone() => current,
                        _ => version.clone(),
                    });
                }
            }
            let version = selected.ok_or_else(|| ResolveError::VersionNotFound {
                coord: key,
                requirement: req.to_string(),
            })?;
            Ok(ResolvedVersion {
                version,
                repo_url: Some(Arc::from("mock://repo")),
            })
        })
    }

    fn fetch_project<'a>(
        &'a self,
        coord: &'a Coord,
        _scope: Scope,
    ) -> super::BoxFuture<'a, super::Result<ResolvedProject>> {
        Box::pin(async move {
            let project = self
                .projects
                .get(&coord.to_string())
                .cloned()
                .ok_or_else(|| ResolveError::ArtifactNotFound {
                    coord: coord.to_string(),
                    searched: Vec::new(),
                })?;
            let platform_constraints = self.platform_constraints.get(&coord.to_string()).cloned();
            Ok(ResolvedProject {
                project,
                repo_url: Some(Arc::from("mock://repo")),
                workspace_module: None,
                platform_constraints,
            })
        })
    }
}

fn dep(group_id: &str, artifact_id: &str, version: &str) -> Dependency {
    Dependency {
        group_id: group_id.to_string(),
        artifact_id: artifact_id.to_string(),
        version: Some(version.to_string()),
        type_: None,
        classifier: None,
        scope: Some("compile".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    }
}

/// A dependency that declares no `<scope>`, so a managed scope may fill it in.
fn dep_no_scope(group_id: &str, artifact_id: &str, version: &str) -> Dependency {
    Dependency {
        scope: None,
        ..dep(group_id, artifact_id, version)
    }
}

/// A dependency with an explicit scope but no `<version>`, so the version must
/// be supplied by the resolving artifact's dependencyManagement.
fn dep_versionless(group_id: &str, artifact_id: &str, scope: &str) -> Dependency {
    Dependency {
        group_id: group_id.to_string(),
        artifact_id: artifact_id.to_string(),
        version: None,
        type_: None,
        classifier: None,
        scope: Some(scope.to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    }
}

fn dep_with_classifier(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    classifier: &str,
) -> Dependency {
    Dependency {
        group_id: group_id.to_string(),
        artifact_id: artifact_id.to_string(),
        version: Some(version.to_string()),
        type_: None,
        classifier: Some(classifier.to_string()),
        scope: Some("compile".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    }
}

fn coord(s: &str) -> Coord {
    Coord::parse(s).unwrap()
}

fn find_version(graph: &Graph, group_id: &str, artifact_id: &str) -> Option<String> {
    graph
        .node_indices()
        .filter_map(|idx| graph.node(idx))
        .find(|node| {
            node.coord.group_id.as_str() == group_id
                && node.coord.artifact_id.as_str() == artifact_id
        })
        .map(|node| node.coord.version.to_string())
}

fn find_scope(graph: &Graph, group_id: &str, artifact_id: &str) -> Option<Scope> {
    graph
        .node_indices()
        .filter_map(|idx| graph.node(idx))
        .find(|node| {
            node.coord.group_id.as_str() == group_id
                && node.coord.artifact_id.as_str() == artifact_id
        })
        .map(|node| node.scope)
}

#[tokio::test]
async fn nearest_wins_ties_by_first_declared() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");
    let c1 = coord("com.example:c:1.0");
    let c2 = coord("com.example:c:2.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "c", "1.0")])
        .with_project(&b, vec![dep("com.example", "c", "2.0")])
        .with_project(&c1, Vec::new())
        .with_project(&c2, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.0"),
                dep("com.example", "b", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "c"),
        Some("1.0".to_string())
    );
}

#[tokio::test]
async fn first_declared_wins_in_diamond() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");
    let c = coord("com.example:c:1.0");
    let d = coord("com.example:d:1.0");
    let e1 = coord("com.example:e:1.0");
    let e2 = coord("com.example:e:2.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "c", "1.0")])
        .with_project(&b, vec![dep("com.example", "d", "1.0")])
        .with_project(&c, vec![dep("com.example", "e", "1.0")])
        .with_project(&d, vec![dep("com.example", "e", "2.0")])
        .with_project(&e1, Vec::new())
        .with_project(&e2, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.0"),
                dep("com.example", "b", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "e"),
        Some("1.0".to_string())
    );
}

#[tokio::test]
async fn applies_exclusions() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");
    let c = coord("com.example:c:1.0");

    let mut dep_b = dep("com.example", "b", "1.0");
    dep_b.exclusions.push(rv_maven_model::Exclusion {
        group_id: "com.example".to_string(),
        artifact_id: "c".to_string(),
    });

    let backend = MockBackend::default()
        .with_project(&a, vec![dep_b])
        .with_project(&b, vec![dep("com.example", "c", "1.0")])
        .with_project(&c, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "a", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(find_version(&graph, "com.example", "c"), None);
}

/// Test that cyclic dependencies are handled gracefully like Maven.
/// When a cycle is detected, we break it by not re-resolving transitive dependencies.
#[tokio::test]
async fn handles_cycles_gracefully() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "b", "1.0")])
        .with_project(&b, vec![dep("com.example", "a", "1.0")]);

    let solver = Solver::new(&backend);
    // Resolution should succeed by breaking the cycle
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "a", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // Both a and b should be in the graph
    assert_eq!(
        find_version(&graph, "com.example", "a"),
        Some("1.0".to_string())
    );
    assert_eq!(
        find_version(&graph, "com.example", "b"),
        Some("1.0".to_string())
    );
}

/// Test that the graph correctly represents cyclic dependency edges.
#[tokio::test]
async fn cycle_edges_are_preserved_in_graph() {
    use petgraph::visit::EdgeRef;

    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "b", "1.0")])
        .with_project(&b, vec![dep("com.example", "a", "1.0")]);

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "a", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // Find the node indices
    let a_idx = graph
        .node_indices()
        .find(|idx| {
            graph
                .node(*idx)
                .map(|n| n.coord.artifact_id.as_str() == "a")
                .unwrap_or(false)
        })
        .expect("a should be in graph");

    let b_idx = graph
        .node_indices()
        .find(|idx| {
            graph
                .node(*idx)
                .map(|n| n.coord.artifact_id.as_str() == "b")
                .unwrap_or(false)
        })
        .expect("b should be in graph");

    // Verify edges: root -> a, a -> b, b -> a (cycle edge)
    let has_a_to_b = graph.graph().edges(a_idx).any(|e| e.target() == b_idx);
    let has_b_to_a = graph.graph().edges(b_idx).any(|e| e.target() == a_idx);

    assert!(has_a_to_b, "a should have edge to b");
    assert!(has_b_to_a, "b should have edge back to a (cycle edge)");
}

#[tokio::test]
async fn follows_relocations() {
    let root = coord("com.example:root:1.0");
    let legacy = coord("com.legacy:lib:1.0");
    let relocated = coord("com.new:lib-new:2.0");
    let child = coord("com.example:child:1.0");

    let relocation = Relocation {
        group_id: Some("com.new".to_string()),
        artifact_id: Some("lib-new".to_string()),
        version: Some("2.0".to_string()),
        message: None,
    };

    let backend = MockBackend::default()
        .with_relocated_project(&legacy, relocation, Vec::new())
        .with_project(&relocated, vec![dep("com.example", "child", "1.0")])
        .with_project(&child, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.legacy", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.new", "lib-new"),
        Some("2.0".to_string())
    );
    assert_eq!(find_version(&graph, "com.legacy", "lib"), None);
    assert_eq!(
        find_version(&graph, "com.example", "child"),
        Some("1.0".to_string())
    );
}

#[tokio::test]
async fn detects_relocation_cycles() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");

    let relocation_to_b = Relocation {
        group_id: Some("com.example".to_string()),
        artifact_id: Some("b".to_string()),
        version: Some("1.0".to_string()),
        message: None,
    };
    let relocation_to_a = Relocation {
        group_id: Some("com.example".to_string()),
        artifact_id: Some("a".to_string()),
        version: Some("1.0".to_string()),
        message: None,
    };

    let backend = MockBackend::default()
        .with_relocated_project(&a, relocation_to_b, Vec::new())
        .with_relocated_project(&b, relocation_to_a, Vec::new());

    let solver = Solver::new(&backend);
    let err = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "a", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap_err();

    match err {
        ResolveError::RelocationCycle(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn follows_partial_relocation() {
    let root = coord("com.example:root:1.0");
    let legacy = coord("com.old:lib:1.0");
    let relocated = coord("com.new:lib:1.0");

    let relocation = Relocation {
        group_id: Some("com.new".to_string()),
        artifact_id: None,
        version: None,
        message: None,
    };

    let backend = MockBackend::default()
        .with_relocated_project(&legacy, relocation, Vec::new())
        .with_project(&relocated, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.old", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.new", "lib"),
        Some("1.0".to_string())
    );
    assert_eq!(find_version(&graph, "com.old", "lib"), None);
}

#[tokio::test]
async fn resolves_version_ranges() {
    let root = coord("com.example:root:1.0");
    let d = coord("com.example:d:1.5");

    let backend = MockBackend::default()
        .with_project(&d, Vec::new())
        .with_versions("com.example", "d", vec!["1.0", "1.5", "2.0"]);

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "d", "[1.0,2.0)")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "d"),
        Some("1.5".to_string())
    );
}

#[tokio::test]
async fn resolves_latest_release_expression() {
    let root = coord("com.example:root:1.0");
    let rel = coord("com.example:dyn:1.0.5");
    let snap = coord("com.example:dyn:1.1.0-SNAPSHOT");

    let backend = MockBackend::default()
        .with_project(&rel, Vec::new())
        .with_project(&snap, Vec::new())
        .with_versions(
            "com.example",
            "dyn",
            vec!["1.0.0", "1.0.5", "1.1.0-SNAPSHOT"],
        );

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "dyn", "latest.release")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "dyn"),
        Some("1.0.5".to_string())
    );
}

#[tokio::test]
async fn resolves_latest_integration_expression() {
    let root = coord("com.example:root:1.0");
    let rel = coord("com.example:dyn:1.0.5");
    let snap = coord("com.example:dyn:1.1.0-SNAPSHOT");

    let backend = MockBackend::default()
        .with_project(&rel, Vec::new())
        .with_project(&snap, Vec::new())
        .with_versions(
            "com.example",
            "dyn",
            vec!["1.0.0", "1.0.5", "1.1.0-SNAPSHOT"],
        );

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "dyn", "LATEST")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "dyn"),
        Some("1.1.0-SNAPSHOT".to_string())
    );
}

#[tokio::test]
async fn unsupported_dynamic_syntax_returns_error() {
    let root = coord("com.example:root:1.0");
    let rel = coord("com.example:dyn:1.0.5");
    let snap = coord("com.example:dyn:1.1.0-SNAPSHOT");

    let backend = MockBackend::default()
        .with_project(&rel, Vec::new())
        .with_project(&snap, Vec::new())
        .with_versions(
            "com.example",
            "dyn",
            vec!["1.0.0", "1.0.5", "1.1.0-SNAPSHOT"],
        );

    let solver = Solver::new(&backend);
    let result = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "dyn", "1.+")],
            scope: Scope::Compile,
        })
        .await;

    assert!(result.is_err(), "1.+ syntax should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("com.example:dyn"),
        "error should mention the coordinate: {err}"
    );
}

#[tokio::test]
async fn classifier_creates_distinct_nodes() {
    let root = coord("com.example:root:1.0");
    let lib_plain = coord("com.example:lib:1.0");
    let lib_tests = Coord {
        group_id: "com.example".into(),
        artifact_id: "lib".into(),
        version: Version::parse("1.0").unwrap(),
        packaging: None,
        classifier: Some("tests".to_string()),
    };

    let backend = MockBackend::default()
        .with_project(&lib_plain, Vec::new())
        .with_project(&lib_tests, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "lib", "1.0"),
                dep_with_classifier("com.example", "lib", "1.0", "tests"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    let mut found_plain = false;
    let mut found_tests = false;
    let mut matches = 0;
    for node in graph.node_indices().filter_map(|idx| graph.node(idx)) {
        if node.coord.group_id.as_str() == "com.example" && node.coord.artifact_id.as_str() == "lib"
        {
            matches += 1;
            match node.coord.classifier.as_deref() {
                Some("tests") => found_tests = true,
                None => found_plain = true,
                _ => {}
            }
        }
    }

    assert_eq!(matches, 2);
    assert!(found_plain);
    assert!(found_tests);
}

#[tokio::test]
async fn direct_optional_dependencies_are_included_and_traversed() {
    // Per Maven spec: direct optional deps (depth=1) ARE included, and their
    // non-optional children ARE queued/traversed normally.
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");

    let mut dep_a = dep("com.example", "a", "1.0");
    dep_a.optional = Some("true".to_string());

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "b", "1.0")])
        .with_project(&b, vec![]);

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep_a],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // The direct optional dep itself is included
    assert_eq!(
        find_version(&graph, "com.example", "a"),
        Some("1.0".to_string())
    );
    // Its non-optional child IS also included (Maven spec: direct optional deps are traversed)
    assert_eq!(
        find_version(&graph, "com.example", "b"),
        Some("1.0".to_string()),
        "non-optional children of direct optional deps should be resolved"
    );
}

#[tokio::test]
async fn transitive_optional_dependencies_are_skipped() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");

    let mut dep_b = dep("com.example", "b", "1.0");
    dep_b.optional = Some("true".to_string());

    let backend = MockBackend::default().with_project(&a, vec![dep_b]);

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "a", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "a"),
        Some("1.0".to_string())
    );
    assert_eq!(find_version(&graph, "com.example", "b"), None);
}

#[tokio::test]
async fn optional_dependencies_of_optional_dependencies_are_not_resolved() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");

    let mut dep_a = dep("com.example", "a", "1.0");
    dep_a.optional = Some("true".to_string());

    let mut dep_b = dep("com.example", "b", "1.0");
    dep_b.optional = Some("true".to_string());

    let backend = MockBackend::default().with_project(&a, vec![dep_b]);

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep_a],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "a"),
        Some("1.0".to_string())
    );
    assert_eq!(find_version(&graph, "com.example", "b"), None);
}

/// A direct test dep carries its compile children onto the test classpath, in
/// both modes. The child is emitted at `test` scope (test applied to compile is
/// test), not its declared `compile`.
#[tokio::test]
async fn direct_test_dep_traverses_compile_child() {
    let root = coord("com.example:root:1.0");
    let test = coord("com.example:test:1.0");
    let test_child = coord("com.example:test-child:1.0");

    let mut dep_test = dep("com.example", "test", "1.0");
    dep_test.scope = Some("test".to_string());

    let backend = MockBackend::default()
        .with_project(&test, vec![dep("com.example", "test-child", "1.0")])
        .with_project(&test_child, Vec::new());

    for strict in [false, true] {
        let solver = Solver::new(&backend).with_strict_maven_compat(strict);
        let graph = solver
            .solve(SolverRoot {
                coord: root.clone(),
                dependencies: vec![dep_test.clone()],
                scope: Scope::Compile,
            })
            .await
            .unwrap();

        assert_eq!(
            find_version(&graph, "com.example", "test"),
            Some("1.0".to_string()),
            "direct test dep must be included (strict={strict})"
        );
        assert_eq!(
            find_version(&graph, "com.example", "test-child"),
            Some("1.0".to_string()),
            "a direct test dep's compile child must be traversed (strict={strict})"
        );
        let child = graph
            .node_indices()
            .filter_map(|idx| graph.node(idx))
            .find(|n| n.coord.artifact_id.as_str() == "test-child")
            .expect("test-child in graph");
        assert_eq!(
            child.scope,
            Scope::Test,
            "test dep's compile child must be classified test (strict={strict})"
        );
    }
}

/// Maven includes the compile/runtime children of a direct provided dep,
/// scoped as provided. This holds in both rv.toml (default) and pom.xml
/// (strict) modes, even though `transitive_from(Compile, Provided)` returns
/// None and would otherwise drop them.
#[tokio::test]
async fn direct_provided_dep_traverses_children() {
    let root = coord("com.example:root:1.0");
    let provided = coord("com.example:provided:1.0");
    let provided_child = coord("com.example:provided-child:1.0");

    let mut dep_provided = dep("com.example", "provided", "1.0");
    dep_provided.scope = Some("provided".to_string());

    let backend = MockBackend::default()
        .with_project(&provided, vec![dep("com.example", "provided-child", "1.0")])
        .with_project(&provided_child, Vec::new());

    for strict in [false, true] {
        let solver = Solver::new(&backend).with_strict_maven_compat(strict);
        let graph = solver
            .solve(SolverRoot {
                coord: root.clone(),
                dependencies: vec![dep_provided.clone()],
                scope: Scope::Compile,
            })
            .await
            .unwrap();

        assert_eq!(
            find_version(&graph, "com.example", "provided"),
            Some("1.0".to_string()),
            "provided dep missing (strict={strict})"
        );
        assert_eq!(
            find_version(&graph, "com.example", "provided-child"),
            Some("1.0".to_string()),
            "provided-child must be traversed (strict={strict})"
        );
    }
}

/// A direct test dep's compile children are included on the test classpath.
///
///   root -> test-lib (test)
///   test-lib -> compile-lib (compile)
///
/// `mvn dependency:list` puts `compile-lib` on the test classpath. rv must
/// match in both modes.
#[tokio::test]
async fn test_dep_compile_children_are_included() {
    let root = coord("com.example:root:1.0");
    let test_lib = coord("com.example:test-lib:1.0");
    let compile_lib = coord("com.example:compile-lib:1.0");

    let mut dep_test_lib = dep("com.example", "test-lib", "1.0");
    dep_test_lib.scope = Some("test".to_string());

    let backend = MockBackend::default()
        .with_project(&test_lib, vec![dep("com.example", "compile-lib", "1.0")])
        .with_project(&compile_lib, Vec::new());

    for strict in [false, true] {
        let solver = Solver::new(&backend).with_strict_maven_compat(strict);
        let graph = solver
            .solve(SolverRoot {
                coord: root.clone(),
                dependencies: vec![dep_test_lib.clone()],
                scope: Scope::Compile,
            })
            .await
            .unwrap();

        assert_eq!(
            find_version(&graph, "com.example", "test-lib"),
            Some("1.0".to_string()),
            "test-lib should be included (strict={strict})"
        );
        assert_eq!(
            find_version(&graph, "com.example", "compile-lib"),
            Some("1.0".to_string()),
            "compile-lib (a test dep's compile child) must be included (strict={strict})"
        );
    }
}

/// Test that NearestWins and HighestWins strategies produce different results.
///
/// Dependency graph:
///   root -> a:1.0 -> c:1.0
///   root -> b:1.0 -> c:2.0
///
/// With NearestWins: c:1.0 wins (first declared at same depth)
/// With HighestWins: c:2.0 wins (higher version)
#[tokio::test]
async fn resolution_strategy_affects_version_selection() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");
    let c1 = coord("com.example:c:1.0");
    let c2 = coord("com.example:c:2.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "c", "1.0")])
        .with_project(&b, vec![dep("com.example", "c", "2.0")])
        .with_project(&c1, Vec::new())
        .with_project(&c2, Vec::new());

    // Test NearestWins (Maven default) - first declared wins at same depth
    let solver_nearest = Solver::with_strategy(&backend, ResolutionStrategy::NearestWins, None);
    let graph_nearest = solver_nearest
        .solve(SolverRoot {
            coord: root.clone(),
            dependencies: vec![
                dep("com.example", "a", "1.0"),
                dep("com.example", "b", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // Test HighestWins - highest version wins
    let solver_highest = Solver::with_strategy(&backend, ResolutionStrategy::HighestWins, None);
    let graph_highest = solver_highest
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.0"),
                dep("com.example", "b", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // NearestWins should select c:1.0 (first declared)
    assert_eq!(
        find_version(&graph_nearest, "com.example", "c"),
        Some("1.0".to_string()),
        "NearestWins should select first declared version (1.0)"
    );

    // HighestWins should select c:2.0 (higher version)
    assert_eq!(
        find_version(&graph_highest, "com.example", "c"),
        Some("2.0".to_string()),
        "HighestWins should select highest version (2.0)"
    );
}

/// Test HighestWins with deeper dependency bringing higher version.
///
/// Dependency graph:
///   root -> a:1.0 (direct dep with c:1.0)
///   root -> b:1.0 -> d:1.0 -> c:3.0
///
/// With NearestWins: c:1.0 wins (depth 2 < depth 3)
/// With HighestWins: c:3.0 wins (3.0 > 1.0)
#[tokio::test]
async fn highest_wins_ignores_depth() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");
    let d = coord("com.example:d:1.0");
    let c1 = coord("com.example:c:1.0");
    let c3 = coord("com.example:c:3.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "c", "1.0")])
        .with_project(&b, vec![dep("com.example", "d", "1.0")])
        .with_project(&d, vec![dep("com.example", "c", "3.0")])
        .with_project(&c1, Vec::new())
        .with_project(&c3, Vec::new());

    // Test NearestWins - shallower depth wins
    let solver_nearest = Solver::with_strategy(&backend, ResolutionStrategy::NearestWins, None);
    let graph_nearest = solver_nearest
        .solve(SolverRoot {
            coord: root.clone(),
            dependencies: vec![
                dep("com.example", "a", "1.0"),
                dep("com.example", "b", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // Test HighestWins - version wins regardless of depth
    let solver_highest = Solver::with_strategy(&backend, ResolutionStrategy::HighestWins, None);
    let graph_highest = solver_highest
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.0"),
                dep("com.example", "b", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // NearestWins: c:1.0 at depth 2 beats c:3.0 at depth 3
    assert_eq!(
        find_version(&graph_nearest, "com.example", "c"),
        Some("1.0".to_string()),
        "NearestWins should select shallower version (1.0 at depth 2)"
    );

    // HighestWins: c:3.0 wins because 3.0 > 1.0
    assert_eq!(
        find_version(&graph_highest, "com.example", "c"),
        Some("3.0".to_string()),
        "HighestWins should select highest version (3.0) regardless of depth"
    );
}

/// Test that HighestWins handles equal versions correctly (no unnecessary replacement).
#[tokio::test]
async fn highest_wins_with_equal_versions() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");
    let c = coord("com.example:c:2.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "c", "2.0")])
        .with_project(&b, vec![dep("com.example", "c", "2.0")])
        .with_project(&c, Vec::new());

    let solver = Solver::with_strategy(&backend, ResolutionStrategy::HighestWins, None);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.0"),
                dep("com.example", "b", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // Both paths have same version, should still resolve to 2.0
    assert_eq!(
        find_version(&graph, "com.example", "c"),
        Some("2.0".to_string())
    );
}

/// Test default strategy is NearestWins.
#[tokio::test]
async fn default_strategy_is_nearest_wins() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");
    let c1 = coord("com.example:c:1.0");
    let c2 = coord("com.example:c:2.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "c", "1.0")])
        .with_project(&b, vec![dep("com.example", "c", "2.0")])
        .with_project(&c1, Vec::new())
        .with_project(&c2, Vec::new());

    // Default solver (no explicit strategy)
    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.0"),
                dep("com.example", "b", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // Should behave like NearestWins
    assert_eq!(
        find_version(&graph, "com.example", "c"),
        Some("1.0".to_string()),
        "Default strategy should be NearestWins"
    );
}

fn dep_with_type(group_id: &str, artifact_id: &str, version: &str, type_: &str) -> Dependency {
    Dependency {
        group_id: group_id.to_string(),
        artifact_id: artifact_id.to_string(),
        version: Some(version.to_string()),
        type_: Some(type_.to_string()),
        classifier: None,
        scope: Some("compile".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    }
}

/// Test that test-jar type dependencies are normalized to jar type with tests classifier.
///
/// Maven's test-jar type is a convention where:
/// - type="test-jar" means the actual file extension is ".jar"
/// - classifier should be "tests"
///
/// So org.slf4j:slf4j-api:2.0.17:test-jar should resolve to:
/// - path: org/slf4j/slf4j-api/2.0.17/slf4j-api-2.0.17-tests.jar
#[tokio::test]
async fn test_jar_type_normalizes_to_jar_with_tests_classifier() {
    let root = coord("com.example:root:1.0");
    // The coord for the test-jar artifact - note it has jar packaging and tests classifier
    let lib_tests = Coord {
        group_id: "com.example".into(),
        artifact_id: "lib".into(),
        version: Version::parse("1.0").unwrap(),
        packaging: None, // jar is default, so None
        classifier: Some("tests".to_string()),
    };

    let backend = MockBackend::default().with_project(&lib_tests, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep_with_type("com.example", "lib", "1.0", "test-jar")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // Find the node for lib
    let lib_node = graph
        .node_indices()
        .filter_map(|idx| graph.node(idx))
        .find(|node| {
            node.coord.group_id.as_str() == "com.example"
                && node.coord.artifact_id.as_str() == "lib"
        });

    assert!(lib_node.is_some(), "lib node should be in the graph");
    let lib_node = lib_node.unwrap();

    // Verify the coord has jar packaging (None means jar) and tests classifier
    assert_eq!(
        lib_node.coord.packaging, None,
        "test-jar type should normalize to jar packaging (None)"
    );
    assert_eq!(
        lib_node.coord.classifier.as_deref(),
        Some("tests"),
        "test-jar type should have tests classifier"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Task A: 3+ competing versions at different depths; nearest wins
// ──────────────────────────────────────────────────────────────────────────────

/// Root declares `org.foo:bar:1.0` at depth 1.
/// Root's dep A declares `org.foo:bar:2.0` at depth 2.
/// A's dep B declares `org.foo:bar:3.0` at depth 3.
/// Nearest-wins (Maven default): depth 1 wins → resolves to 1.0.
#[tokio::test]
async fn three_level_version_conflict_nearest_wins_at_depth_one() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");
    let bar_1 = coord("org.foo:bar:1.0");
    let bar_2 = coord("org.foo:bar:2.0");
    let bar_3 = coord("org.foo:bar:3.0");

    // B declares bar:3.0 transitively
    let backend = MockBackend::default()
        .with_project(
            &a,
            vec![dep("com.example", "b", "1.0"), dep("org.foo", "bar", "2.0")],
        )
        .with_project(&b, vec![dep("org.foo", "bar", "3.0")])
        .with_project(&bar_1, Vec::new())
        .with_project(&bar_2, Vec::new())
        .with_project(&bar_3, Vec::new());

    let solver = Solver::with_strategy(&backend, ResolutionStrategy::NearestWins, None);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            // Root declares bar:1.0 at depth 1, plus a:1.0 which pulls bar:2.0/3.0 deeper
            dependencies: vec![dep("org.foo", "bar", "1.0"), dep("com.example", "a", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "org.foo", "bar"),
        Some("1.0".to_string()),
        "NearestWins: root's depth-1 declaration (1.0) must beat depth-2 (2.0) and depth-3 (3.0)"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Task B: Direct dep beats BOM (platform constraint) when BOM is non-enforced
// ──────────────────────────────────────────────────────────────────────────────

/// When a dep is declared directly AND a (non-enforced) BOM/platform constraint
/// says a different version, the direct declaration wins.
/// Root imports BOM that says `org.foo:bar:2.0` (simulated via non-enforced constraint).
/// Root also directly declares `org.foo:bar:1.0` with a HARD pin (`[1.0]`).
/// Expected: 1.0 wins. The soft-pin variant (which wins the same way) is
/// covered by `soft_pinned_direct_dep_beats_bom`.
#[tokio::test]
async fn direct_dep_beats_non_enforced_bom_constraint() {
    let root = coord("com.example:root:1.0");
    let bar_1 = coord("org.foo:bar:1.0");

    let backend = MockBackend::default()
        .with_project(&bar_1, Vec::new())
        .with_versions("org.foo", "bar", vec!["1.0", "2.0"]);

    // Simulate BOM with a non-enforced platform constraint saying 2.0
    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "org.foo".to_string(),
        module: "bar".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: Some("2.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            // Hard pin `[1.0]` must beat the non-enforced BOM 2.0.
            dependencies: vec![dep("org.foo", "bar", "[1.0]")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "org.foo", "bar"),
        Some("1.0".to_string()),
        "hard-pinned direct dep (1.0) must win over non-enforced BOM constraint (2.0)"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Task C: Scope promotion in transitive chains
// ──────────────────────────────────────────────────────────────────────────────

/// Root --compile--> A --compile--> B:
/// B should end up in the graph (with strict_maven_compat enabled, compile→compile=compile).
/// Root --test--> C --compile--> D:
/// D is narrowed to test scope (test→compile=test in compat mode).
/// Verify C appears in graph but D does NOT appear without strict_maven_compat (default mode).
#[tokio::test]
async fn scope_promotion_compile_chain_in_compat_mode() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");

    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "b", "1.0")])
        .with_project(&b, Vec::new());

    // With strict_maven_compat: compile→compile→compile means B is resolved as compile
    let solver = Solver::new(&backend).with_strict_maven_compat(true);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "a", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "a"),
        Some("1.0".to_string()),
        "A (compile dep) must be resolved"
    );
    assert_eq!(
        find_version(&graph, "com.example", "b"),
        Some("1.0".to_string()),
        "B (compile→compile chain) must be resolved when strict_maven_compat=true"
    );
}

/// Test→compile chain: a direct test dep C traverses into its compile child D,
/// and D is narrowed to test scope (test → compile = test). This holds in both
/// resolution modes.
#[tokio::test]
async fn scope_promotion_test_chain_narrowing() {
    let root = coord("com.example:root:1.0");
    let c = coord("com.example:c:1.0");
    let d = coord("com.example:d:1.0");

    let mut dep_c = dep("com.example", "c", "1.0");
    dep_c.scope = Some("test".to_string());

    let backend = MockBackend::default()
        .with_project(&c, vec![dep("com.example", "d", "1.0")])
        .with_project(&d, Vec::new());

    for strict in [false, true] {
        let solver = Solver::new(&backend).with_strict_maven_compat(strict);
        let graph = solver
            .solve(SolverRoot {
                coord: root.clone(),
                dependencies: vec![dep_c.clone()],
                scope: Scope::Compile,
            })
            .await
            .unwrap();

        assert_eq!(
            find_version(&graph, "com.example", "c"),
            Some("1.0".to_string()),
            "C (test dep) must be in graph (strict={strict})"
        );
        assert_eq!(
            find_version(&graph, "com.example", "d"),
            Some("1.0".to_string()),
            "D must be in graph: test→compile=test (strict={strict})"
        );

        // D was narrowed from its declared compile scope to test via the test edge.
        let d_node = graph
            .node_indices()
            .filter_map(|idx| graph.node(idx))
            .find(|n| n.coord.artifact_id.as_str() == "d")
            .expect("d should be in graph");
        assert_eq!(
            d_node.scope,
            Scope::Test,
            "D scope must be narrowed to test by the test→compile chain (strict={strict})"
        );
    }
}

/// The real jackson-databind / guava-testlib case, checked against `mvn
/// dependency:list`: a test-scoped direct dep whose POM pulls a compile dep
/// that has its own transitive dep.
///
///   jackson-databind (root)
///     └─ com.google.guava:guava-testlib  (scope=test, direct)
///          └─ junit:junit                (compile in testlib's POM)
///               └─ org.hamcrest:hamcrest-core (compile in junit's POM)
///
/// Maven puts all three on the test classpath (test applied to compile stays
/// test, transitively), so rv resolves all three at `test` in both modes.
#[tokio::test]
async fn test_direct_dep_carries_full_compile_subtree_at_test_scope() {
    let root = coord("com.fasterxml.jackson.core:jackson-databind:2.18.2");
    let testlib = coord("com.google.guava:guava-testlib:31.1-jre");
    let junit = coord("junit:junit:4.13.2");
    let hamcrest = coord("org.hamcrest:hamcrest-core:1.3");

    // root depends on guava-testlib at <scope>test</scope> (direct edge).
    let mut dep_testlib = dep("com.google.guava", "guava-testlib", "31.1-jre");
    dep_testlib.scope = Some("test".to_string());
    // guava-testlib's own POM carries junit at compile ("testlib must carry
    // these transitively"); junit's POM carries hamcrest-core at compile.
    let dep_junit = dep("junit", "junit", "4.13.2");
    let dep_hamcrest = dep("org.hamcrest", "hamcrest-core", "1.3");

    let backend = MockBackend::default()
        .with_project(&testlib, vec![dep_junit])
        .with_project(&junit, vec![dep_hamcrest])
        .with_project(&hamcrest, Vec::new());

    let scope_of = |graph: &Graph, artifact: &str| -> Option<Scope> {
        graph
            .node_indices()
            .filter_map(|idx| graph.node(idx))
            .find(|n| n.coord.artifact_id.as_str() == artifact)
            .map(|n| n.scope)
    };

    for strict in [false, true] {
        let solver = Solver::new(&backend).with_strict_maven_compat(strict);
        let graph = solver
            .solve(SolverRoot {
                coord: root.clone(),
                dependencies: vec![dep_testlib.clone()],
                scope: Scope::Compile,
            })
            .await
            .unwrap();

        for (group, artifact, version) in [
            ("com.google.guava", "guava-testlib", "31.1-jre"),
            ("junit", "junit", "4.13.2"),
            ("org.hamcrest", "hamcrest-core", "1.3"),
        ] {
            assert_eq!(
                find_version(&graph, group, artifact),
                Some(version.to_string()),
                "{artifact} must be resolved (strict={strict})"
            );
            assert_eq!(
                scope_of(&graph, artifact),
                Some(Scope::Test),
                "{artifact} must be classified test (strict={strict})"
            );
        }
    }
}

/// Provided-scope analog of the above: a direct `provided` dep's compile
/// subtree is carried on the provided classpath, transitively, in both modes.
#[tokio::test]
async fn provided_direct_dep_carries_full_compile_subtree_at_provided_scope() {
    let root = coord("com.example:root:1.0");
    let api = coord("com.example:api:1.0");
    let impl_ = coord("com.example:impl:1.0");
    let util = coord("com.example:util:1.0");

    let mut dep_api = dep("com.example", "api", "1.0");
    dep_api.scope = Some("provided".to_string());
    let dep_impl = dep("com.example", "impl", "1.0");
    let dep_util = dep("com.example", "util", "1.0");

    let backend = MockBackend::default()
        .with_project(&api, vec![dep_impl])
        .with_project(&impl_, vec![dep_util])
        .with_project(&util, Vec::new());

    let scope_of = |graph: &Graph, artifact: &str| -> Option<Scope> {
        graph
            .node_indices()
            .filter_map(|idx| graph.node(idx))
            .find(|n| n.coord.artifact_id.as_str() == artifact)
            .map(|n| n.scope)
    };

    for strict in [false, true] {
        let solver = Solver::new(&backend).with_strict_maven_compat(strict);
        let graph = solver
            .solve(SolverRoot {
                coord: root.clone(),
                dependencies: vec![dep_api.clone()],
                scope: Scope::Compile,
            })
            .await
            .unwrap();

        for artifact in ["api", "impl", "util"] {
            assert_eq!(
                find_version(&graph, "com.example", artifact),
                Some("1.0".to_string()),
                "{artifact} must be resolved (strict={strict})"
            );
            assert_eq!(
                scope_of(&graph, artifact),
                Some(Scope::Provided),
                "{artifact} must be classified provided (strict={strict})"
            );
        }
    }
}

/// Guard against over-broadening: only the compile and runtime children of a
/// direct test dep are carried. A test or provided grandchild (a transitive
/// test/provided edge at depth > 1) is still dropped, like `mvn dependency:list`.
#[tokio::test]
async fn direct_test_dep_still_drops_test_and_provided_grandchildren() {
    let root = coord("com.example:root:1.0");
    let test_lib = coord("com.example:test-lib:1.0");
    let compile_kid = coord("com.example:compile-kid:1.0");
    let test_kid = coord("com.example:test-kid:1.0");
    let provided_kid = coord("com.example:provided-kid:1.0");

    let mut dep_test_lib = dep("com.example", "test-lib", "1.0");
    dep_test_lib.scope = Some("test".to_string());

    let dep_compile_kid = dep("com.example", "compile-kid", "1.0");
    let mut dep_test_kid = dep("com.example", "test-kid", "1.0");
    dep_test_kid.scope = Some("test".to_string());
    let mut dep_provided_kid = dep("com.example", "provided-kid", "1.0");
    dep_provided_kid.scope = Some("provided".to_string());

    let backend = MockBackend::default()
        .with_project(
            &test_lib,
            vec![dep_compile_kid, dep_test_kid, dep_provided_kid],
        )
        .with_project(&compile_kid, Vec::new())
        .with_project(&test_kid, Vec::new())
        .with_project(&provided_kid, Vec::new());

    for strict in [false, true] {
        let solver = Solver::new(&backend).with_strict_maven_compat(strict);
        let graph = solver
            .solve(SolverRoot {
                coord: root.clone(),
                dependencies: vec![dep_test_lib.clone()],
                scope: Scope::Compile,
            })
            .await
            .unwrap();

        assert_eq!(
            find_version(&graph, "com.example", "compile-kid"),
            Some("1.0".to_string()),
            "compile grandchild of a direct test dep is carried (strict={strict})"
        );
        assert_eq!(
            find_version(&graph, "com.example", "test-kid"),
            None,
            "a test transitive of a test dep must be dropped (strict={strict})"
        );
        assert_eq!(
            find_version(&graph, "com.example", "provided-kid"),
            None,
            "a provided transitive of a test dep must be dropped (strict={strict})"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Task D: Multi-level parent POM inheritance (three-level grandparent chain)
//
// At the solver level, parent POM inheritance is resolved before the solver
// runs (the Resolver layer handles it). The solver receives flattened projects
// with all managed versions already applied. We test this by setting up a
// three-level chain where each ancestor contributes deps, verifying that the
// solver correctly resolves all deps that the resolver would have provided.
// ──────────────────────────────────────────────────────────────────────────────

/// Simulates a three-level parent chain:
///   grandparent manages: org.foo:gp-lib:1.0
///   parent manages:      org.foo:p-lib:2.0   (inherits grandparent management)
///   child uses both deps without specifying versions
///
/// At the solver level, we model this by having child's project already contain
/// versioned deps (as the resolver would have applied after parent resolution).
#[tokio::test]
async fn multi_level_parent_chain_deps_resolve_correctly() {
    let root = coord("com.example:root:1.0");
    let child = coord("com.example:child:1.0");
    let gp_lib = coord("org.foo:gp-lib:1.0");
    let p_lib = coord("org.foo:p-lib:2.0");

    // After resolver applies grandparent + parent management, child has both deps with versions
    let backend = MockBackend::default()
        .with_project(
            &child,
            vec![
                dep("org.foo", "gp-lib", "1.0"), // version came from grandparent
                dep("org.foo", "p-lib", "2.0"),  // version came from parent
            ],
        )
        .with_project(&gp_lib, Vec::new())
        .with_project(&p_lib, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "child", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "child"),
        Some("1.0".to_string()),
        "child must be resolved"
    );
    assert_eq!(
        find_version(&graph, "org.foo", "gp-lib"),
        Some("1.0".to_string()),
        "gp-lib (from grandparent management) must resolve to 1.0"
    );
    assert_eq!(
        find_version(&graph, "org.foo", "p-lib"),
        Some("2.0".to_string()),
        "p-lib (from parent management) must resolve to 2.0"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Task E: BOM importing another BOM (transitive BOM constraint resolution)
// ──────────────────────────────────────────────────────────────────────────────

/// Root imports bom-a which itself imports bom-b.
/// bom-b constrains org.foo:bar:3.0.
/// Root depends on org.foo:bar (no version; relies on constraint).
///
/// At the solver level, transitive BOM imports are resolved by the Resolver and
/// delivered as a merged PlatformConstraints. We simulate this by providing a
/// PlatformConstraints that contains the constraint from bom-b (via bom-a).
#[tokio::test]
async fn transitive_bom_constraint_resolves_unversioned_dep() {
    let root = coord("com.example:root:1.0");
    let bar = coord("org.foo:bar:3.0");

    let backend = MockBackend::default().with_project(&bar, Vec::new());

    // Simulate bom-a → bom-b → bar:3.0 as a merged platform constraint
    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "org.foo".to_string(),
        module: "bar".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: Some("3.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep_no_version("org.foo", "bar")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "org.foo", "bar"),
        Some("3.0".to_string()),
        "transitive BOM constraint (3.0) must resolve the unversioned dep"
    );
}

/// Test that test-jar type with explicit classifier preserves the explicit classifier.
#[tokio::test]
async fn test_jar_type_with_explicit_classifier_preserves_classifier() {
    let root = coord("com.example:root:1.0");
    let lib_custom = Coord {
        group_id: "com.example".into(),
        artifact_id: "lib".into(),
        version: Version::parse("1.0").unwrap(),
        packaging: None,
        classifier: Some("custom".to_string()),
    };

    let backend = MockBackend::default().with_project(&lib_custom, Vec::new());

    // Create a dependency with test-jar type but explicit classifier
    let mut dep = dep_with_type("com.example", "lib", "1.0", "test-jar");
    dep.classifier = Some("custom".to_string());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    let lib_node = graph
        .node_indices()
        .filter_map(|idx| graph.node(idx))
        .find(|node| {
            node.coord.group_id.as_str() == "com.example"
                && node.coord.artifact_id.as_str() == "lib"
        });

    assert!(lib_node.is_some(), "lib node should be in the graph");
    let lib_node = lib_node.unwrap();

    // Verify explicit classifier takes precedence
    assert_eq!(
        lib_node.coord.classifier.as_deref(),
        Some("custom"),
        "explicit classifier should take precedence over test-jar implied classifier"
    );
}

/// Helper to create a dependency without version (for platform constraint testing).
fn dep_no_version(group_id: &str, artifact_id: &str) -> Dependency {
    Dependency {
        group_id: group_id.to_string(),
        artifact_id: artifact_id.to_string(),
        version: None,
        type_: None,
        classifier: None,
        scope: Some("compile".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    }
}

/// Test that platform constraints provide versions for dependencies without versions.
#[tokio::test]
async fn platform_constraints_provide_missing_version() {
    let root = coord("com.example:root:1.0");
    let lib = coord("com.example:lib:2.5.0");

    let backend = MockBackend::default().with_project(&lib, Vec::new());

    // Create platform constraints
    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: Some("2.5.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep_no_version("com.example", "lib")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // The version should come from the platform constraint
    assert_eq!(
        find_version(&graph, "com.example", "lib"),
        Some("2.5.0".to_string()),
        "Platform constraint should provide version for unversioned dependency"
    );
}

/// Test that enforced platform constraints override explicit versions.
#[tokio::test]
async fn enforced_platform_constraints_override_version() {
    let root = coord("com.example:root:1.0");
    let lib = coord("com.example:lib:3.0.0");

    let backend = MockBackend::default().with_project(&lib, Vec::new());

    // Create enforced platform constraints
    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: None,
            strictly: Some("3.0.0".to_string()),
        },
        enforced: true,
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            // Dependency specifies 1.0.0, but enforced platform should override
            dependencies: vec![dep("com.example", "lib", "1.0.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // The version should come from the enforced platform constraint
    assert_eq!(
        find_version(&graph, "com.example", "lib"),
        Some("3.0.0".to_string()),
        "Enforced platform constraint should override explicit version"
    );
}

/// Test that regular platform constraints don't override a HARD-pinned
/// explicit version (`[X]` syntax → VersionReq::Exact). A bare soft pin
/// (`<version>X</version>` → VersionReq::Soft) wins the same way; that case
/// is covered by `soft_pinned_direct_dep_beats_bom`.
#[tokio::test]
async fn regular_platform_constraints_dont_override_version() {
    let root = coord("com.example:root:1.0");
    let lib = coord("com.example:lib:1.0.0");

    let backend = MockBackend::default()
        .with_project(&lib, Vec::new())
        .with_versions("com.example", "lib", vec!["1.0.0", "2.0.0"]);

    // Create regular (non-enforced) platform constraints
    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: Some("2.0.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            // Hard pin `[1.0.0]`: non-enforced constraint must NOT override it.
            dependencies: vec![dep("com.example", "lib", "[1.0.0]")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // The explicit version should be used
    assert_eq!(
        find_version(&graph, "com.example", "lib"),
        Some("1.0.0".to_string()),
        "Regular platform constraint should not override explicit version"
    );
}

/// Test that platform constraints from a resolved project apply to its dependencies.
#[tokio::test]
async fn platform_constraints_from_project_apply_to_children() {
    let root = coord("com.example:root:1.0");
    let consumer = coord("com.example:consumer:1.0");
    let lib = coord("com.example:lib:2.0.0");

    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: Some("2.0.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    let backend = MockBackend::default()
        .with_project(&consumer, vec![dep_no_version("com.example", "lib")])
        .with_project(&lib, Vec::new())
        .with_platform_constraints(&consumer, constraints);

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "consumer", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "lib"),
        Some("2.0.0".to_string()),
        "Project platform constraints should apply to child dependencies"
    );
}

/// Test that unversioned dependency without platform constraint fails.
#[tokio::test]
async fn unversioned_dependency_without_constraint_fails() {
    let root = coord("com.example:root:1.0");

    let backend = MockBackend::default();

    // No platform constraints
    let solver = Solver::new(&backend);
    let result = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep_no_version("com.example", "lib")],
            scope: Scope::Compile,
        })
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ResolveError::MissingVersion {
            group_id,
            artifact_id,
        } => {
            assert_eq!(group_id, "com.example");
            assert_eq!(artifact_id, "lib");
        }
        other => panic!("Expected MissingVersion error, got: {:?}", other),
    }
}

/// In non-strict (default) mode, `transitive_from(Test, Compile)`
/// returns `Some(Test)`, so a compile-scoped child reached through a
/// test-scoped parent must end up classified as `Test`.
///
/// Regression guard: if `inherit_scope` bounced back to the child scope
/// via the `_ => child` fallthrough for such (parent, child) pairs, it
/// would emit the node as `Compile` in the lock and break downstream
/// test-classpath bookkeeping.
#[tokio::test]
async fn non_strict_test_chain_preserves_test_scope_on_compile_child() {
    let root = coord("com.example:root:1.0");
    let a = coord("com.example:a:1.0");
    let b = coord("com.example:b:1.0");

    // A is a compile dep that itself depends on B (compile). The
    // traversal is triggered through a Test-scoped root, so every dep
    // it reaches should appear as Test.
    let backend = MockBackend::default()
        .with_project(&a, vec![dep("com.example", "b", "1.0")])
        .with_project(&b, Vec::new());

    let solver = Solver::new(&backend); // strict_maven_compat defaults to false
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "a", "1.0")],
            scope: Scope::Test,
        })
        .await
        .unwrap();

    let b_node = graph
        .node_indices()
        .filter_map(|idx| graph.node(idx))
        .find(|n| n.coord.artifact_id.as_str() == "b")
        .expect("b must be in graph: transitive_from(Test, Compile)=Some(Test)");
    assert_eq!(
        b_node.scope,
        Scope::Test,
        "B reached through a test-scoped chain must keep effective scope Test, \
         not the child's declared Compile"
    );
}

// PlatformConstraint matches by (group, artifact, type, classifier).
// A BOM entry for the test-jar variant must not steal the version of a plain
// jar consumer at the same coordinate, and vice versa.

/// BOM manages `com.example:lib:test-jar:2.0`. The direct dep is a plain jar
/// at `1.0`. The managed test-jar entry must not apply: the resolved version
/// stays `1.0`.
#[tokio::test]
async fn platform_constraint_test_jar_does_not_match_plain_jar() {
    let root = coord("com.example:root:1.0");
    let lib_plain = coord("com.example:lib:1.0");

    let backend = MockBackend::default().with_project(&lib_plain, Vec::new());

    let mut constraints = PlatformConstraints::new();
    // Managed entry for the test-jar variant: effective_type="jar", classifier="tests".
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: Some("tests".to_string()),
        version: ConstraintVersion {
            requires: Some("2.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "lib"),
        Some("1.0".to_string()),
        "test-jar BOM entry must not match a plain-jar direct dep"
    );
}

/// Same scenario with both managed entries present (`jar:1.0` and
/// `test-jar:2.0`): each variant resolves to its own managed version.
#[tokio::test]
async fn platform_constraint_jar_and_test_jar_resolve_independently() {
    let root = coord("com.example:root:1.0");
    let lib_plain = coord("com.example:lib:1.0");
    let lib_tests = Coord {
        group_id: "com.example".into(),
        artifact_id: "lib".into(),
        version: Version::parse("2.0").unwrap(),
        packaging: None,
        classifier: Some("tests".to_string()),
    };

    let backend = MockBackend::default()
        .with_project(&lib_plain, Vec::new())
        .with_project(&lib_tests, Vec::new());

    let mut constraints = PlatformConstraints::new();
    // Managed: plain jar at 1.0.
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: Some("1.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });
    // Managed: test-jar (effective type=jar, classifier=tests) at 2.0.
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: Some("tests".to_string()),
        version: ConstraintVersion {
            requires: Some("2.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    // Both direct deps are unversioned; each picks the managed version that
    // matches its (type, classifier) key.
    let mut dep_jar = dep_no_version("com.example", "lib");
    dep_jar.scope = Some("compile".to_string());

    let mut dep_test_jar = dep_no_version("com.example", "lib");
    dep_test_jar.type_ = Some("test-jar".to_string());

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep_jar, dep_test_jar],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    // Two distinct nodes are expected: one plain, one with classifier=tests.
    let mut plain = None;
    let mut tests = None;
    for node in graph.node_indices().filter_map(|idx| graph.node(idx)) {
        if node.coord.group_id.as_str() != "com.example" || node.coord.artifact_id.as_str() != "lib"
        {
            continue;
        }
        match node.coord.classifier.as_deref() {
            None => plain = Some(node.coord.version.to_string()),
            Some("tests") => tests = Some(node.coord.version.to_string()),
            _ => {}
        }
    }

    assert_eq!(plain, Some("1.0".to_string()), "plain jar should be 1.0");
    assert_eq!(tests, Some("2.0".to_string()), "test-jar should be 2.0");
}

// A declared version on a direct dependency always beats <dependencyManagement>,
// soft pin included: declaring `jackson-databind 2.15.2` in <dependencies> is
// exactly how Maven users override a BOM-managed 2.15.0. Management only fills
// in missing versions at depth 1.

/// Direct dep `x:lib:1.0` (bare version = soft pin). BOM says `2.0`. Maven
/// resolves to `1.0`: dep-mgmt never replaces a declared direct-dep version.
#[tokio::test]
async fn soft_pinned_direct_dep_beats_bom() {
    let root = coord("com.example:root:1.0");
    let lib_1 = coord("com.example:lib:1.0");

    let backend = MockBackend::default()
        .with_project(&lib_1, Vec::new())
        .with_versions("com.example", "lib", vec!["1.0", "2.0"]);

    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: Some("2.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "lib"),
        Some("1.0".to_string()),
        "a soft-pinned direct dep (1.0) must beat the BOM (2.0)"
    );
}

/// Root depMgmt manages `x:mid` with an `<exclusions>` entry (and no
/// version): the canonical "globally exclude commons-logging" pattern.
/// The exclusion must prune the subtree below `mid` even when `mid` is
/// reached transitively, matching Maven's ClassicDependencyManager.
#[tokio::test]
async fn managed_exclusions_apply_to_transitive_nodes() {
    let root = coord("com.example:root:1.0");
    let lib = coord("com.example:lib:1.0");
    let mid = coord("com.example:mid:1.0");
    let clogging = coord("commons-logging:commons-logging:1.2");

    let backend = MockBackend::default()
        .with_project(&lib, vec![dep("com.example", "mid", "1.0")])
        .with_project(&mid, vec![dep("commons-logging", "commons-logging", "1.2")])
        .with_project(&clogging, Vec::new());

    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "mid".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        exclusions: vec![rv_maven_model::Exclusion {
            group_id: "commons-logging".to_string(),
            artifact_id: "commons-logging".to_string(),
        }],
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "mid"),
        Some("1.0".to_string()),
        "managed node itself stays in the graph"
    );
    assert_eq!(
        find_version(&graph, "commons-logging", "commons-logging"),
        None,
        "managed exclusion must prune the transitive subtree"
    );
}

/// Root depMgmt forces `<scope>test</scope>` on an unscoped transitive
/// coordinate: the managed scope fills the blank, and the test-scoped
/// transitive is then dropped from the closure. A dependency that declared its
/// own scope keeps it (see `managed_scope_does_not_override_declared_child_scope`).
#[tokio::test]
async fn managed_scope_test_prunes_transitive() {
    let root = coord("com.example:root:1.0");
    let lib = coord("com.example:lib:1.0");
    let extra = coord("com.example:extra:1.0");

    let backend = MockBackend::default()
        .with_project(&lib, vec![dep_no_scope("com.example", "extra", "1.0")])
        .with_project(&extra, Vec::new());

    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "extra".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        scope: Some("test".to_string()),
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "extra"),
        None,
        "managed test scope must fill in an unscoped transitive and drop it"
    );
}

/// Root depMgmt forces `<optional>true</optional>` on a transitive
/// coordinate; optional transitives are excluded from the closure.
#[tokio::test]
async fn managed_optional_prunes_transitive() {
    let root = coord("com.example:root:1.0");
    let lib = coord("com.example:lib:1.0");
    let extra = coord("com.example:extra:1.0");

    let backend = MockBackend::default()
        .with_project(&lib, vec![dep("com.example", "extra", "1.0")])
        .with_project(&extra, Vec::new());

    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "extra".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        optional: Some("true".to_string()),
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "extra"),
        None,
        "managed optional=true must drop the transitive dependency"
    );
}

/// guava-testlib shape: a resolved artifact D (whose parent manages child C's
/// version) declares C with no `<version>` and an explicit `<scope>compile`.
/// C's version must come from D's effective dependencyManagement, C must keep
/// its compile scope (not the management entry's test scope, which would drop it
/// under the depth > 1 test prune), and C's own transitive dep must be pulled in.
///
/// `testlib` is a direct test dep, as jackson-databind declares guava-testlib.
/// If the management entry's `test` scope were stamped onto `junit`, `junit`
/// would be pruned at depth 2 and both it and `hamcrest` would vanish.
#[tokio::test]
async fn versionless_child_version_from_transitive_depmgmt() {
    let root = coord("com.example:root:1.0");
    let testlib = coord("com.example:testlib:1.0");
    let junit = coord("com.example:junit:4.13.2");
    let hamcrest = coord("com.example:hamcrest:1.3");

    // Management entry as the model would surface it after merging P's
    // dependencyManagement into D: version 4.13.2, scope test.
    let managed_junit = Dependency {
        scope: Some("test".to_string()),
        ..dep("com.example", "junit", "4.13.2")
    };

    let backend = MockBackend::default()
        .with_project_and_mgmt(
            &testlib,
            // D declares junit with an explicit compile scope and NO version.
            vec![dep_versionless("com.example", "junit", "compile")],
            vec![managed_junit],
        )
        .with_project(&junit, vec![dep("com.example", "hamcrest", "1.3")])
        .with_project(&hamcrest, Vec::new());

    // testlib is a direct test dependency, as jackson-databind declares
    // guava-testlib.
    let testlib_dep = Dependency {
        scope: Some("test".to_string()),
        ..dep("com.example", "testlib", "1.0")
    };

    // strict Maven compatibility mirrors pom.xml resolution, where a direct
    // test dependency's compile children are traversed.
    let solver = Solver::new(&backend).with_strict_maven_compat(true);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![testlib_dep],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "junit"),
        Some("4.13.2".to_string()),
        "versionless child must take its version from the artifact's dependencyManagement"
    );
    // The management entry's test scope was not stamped onto the declared
    // compile scope; junit rides in on testlib's test edge instead of being
    // pruned as a depth > 1 test dependency, matching `mvn dependency:tree`
    // (junit:junit:4.13.2:test under a test-scoped guava-testlib).
    assert_eq!(
        find_scope(&graph, "com.example", "junit"),
        Some(Scope::Test),
        "junit must be included as a test dependency, not dropped"
    );
    assert_eq!(
        find_version(&graph, "com.example", "hamcrest"),
        Some("1.3".to_string()),
        "the managed child's own transitive dependency must be pulled in"
    );
}

/// The management-supplied version fills a blank only. An explicit
/// `<version>` on the child always wins over a differing dependencyManagement
/// entry for the same coordinate.
#[tokio::test]
async fn explicit_child_version_wins_over_transitive_depmgmt() {
    let root = coord("com.example:root:1.0");
    let lib = coord("com.example:lib:1.0");
    let child_2 = coord("com.example:child:2.0");

    let managed_child = dep("com.example", "child", "1.0");

    let backend = MockBackend::default()
        .with_project_and_mgmt(
            &lib,
            // Declared with an explicit 2.0; management says 1.0.
            vec![dep("com.example", "child", "2.0")],
            vec![managed_child],
        )
        .with_project(&child_2, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "child"),
        Some("2.0".to_string()),
        "an explicit child version must win over the dependencyManagement entry"
    );
}

/// Root dependencyManagement that carries a `<scope>test</scope>` for a
/// coordinate must NOT override a transitive dependency that declares its own
/// scope explicitly. `lib` (compile) declares `child` with an explicit
/// compile scope; the root management pins `child` to test. The declared
/// compile scope wins, so `child` stays on the graph rather than being pruned
/// as a transitive test dependency.
#[tokio::test]
async fn managed_scope_does_not_override_declared_child_scope() {
    let root = coord("com.example:root:1.0");
    let lib = coord("com.example:lib:1.0");
    let child = coord("com.example:child:1.0");

    let backend = MockBackend::default()
        .with_project(&lib, vec![dep("com.example", "child", "1.0")])
        .with_project(&child, Vec::new());

    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "child".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        scope: Some("test".to_string()),
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep("com.example", "lib", "1.0")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "child"),
        Some("1.0".to_string()),
        "an explicitly declared compile scope must survive a managed test scope"
    );
    assert_eq!(
        find_scope(&graph, "com.example", "child"),
        Some(Scope::Compile),
        "the child must keep its declared compile scope, not the managed test scope"
    );
}

/// Direct dep `x:lib:[1.0]` (hard pin via bracketed range). BOM says `2.0`.
/// Maven keeps the hard-pin's `1.0`.
#[tokio::test]
async fn hard_pinned_direct_dep_blocks_bom_override() {
    let root = coord("com.example:root:1.0");
    let lib_1 = coord("com.example:lib:1.0");

    let backend = MockBackend::default()
        .with_project(&lib_1, Vec::new())
        .with_versions("com.example", "lib", vec!["1.0", "2.0"]);

    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: Some("2.0".to_string()),
            strictly: None,
        },
        enforced: false,
        ..Default::default()
    });

    let solver = Solver::new(&backend).with_platform_constraints(constraints);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            // [1.0] is a Maven hard pin (Exact range).
            dependencies: vec![dep("com.example", "lib", "[1.0]")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "lib"),
        Some("1.0".to_string()),
        "hard-pinned direct dep must block non-enforced BOM override"
    );
}

/// Regression for the requeue path: when an intra-batch constraint discovery
/// invalidates a resolution, the requeued item must keep its original
/// `declared_at`. Overwriting it with `next_declared_at` shoves the item to
/// the back of every Maven first-declared-wins tiebreak.
#[tokio::test]
async fn requeue_preserves_declared_at_for_tiebreak() {
    let root = coord("com.example:root:1.0");
    let consumer = coord("com.example:consumer:1.0");
    let lib_1 = coord("com.example:lib:1.0");
    let lib_2 = coord("com.example:lib:2.0");

    // Consumer's project surfaces an enforced constraint that flips lib
    // from its soft-pinned 1.0 to 2.0 mid-batch.
    let mut consumer_constraints = PlatformConstraints::new();
    consumer_constraints.add_constraint(PlatformConstraint {
        group: "com.example".to_string(),
        module: "lib".to_string(),
        type_: "jar".to_string(),
        classifier: None,
        version: ConstraintVersion {
            requires: None,
            strictly: Some("2.0".to_string()),
        },
        enforced: true,
        ..Default::default()
    });

    let backend = MockBackend::default()
        .with_project(&consumer, Vec::new())
        .with_platform_constraints(&consumer, consumer_constraints)
        .with_project(&lib_1, Vec::new())
        .with_project(&lib_2, Vec::new());

    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                // Soft-pinned lib resolves to 1.0 on the first pass; the
                // enforced constraint discovered while processing `consumer`
                // forces a requeue. With this bug, `lib.declared_at` would
                // be bumped past `consumer.declared_at`, breaking ordering
                // assumptions on the requeued resolution.
                dep("com.example", "lib", "1.0"),
                dep("com.example", "consumer", "1.0"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "lib"),
        Some("2.0".to_string()),
        "enforced constraint discovered intra-batch should win after requeue"
    );
    assert_eq!(
        find_version(&graph, "com.example", "consumer"),
        Some("1.0".to_string())
    );
}

/// Regression: only BOM imports act as a barrier, not any version-less
/// dep. Two unversioned compile deps in one batch are fetched in parallel.
#[tokio::test]
async fn unversioned_compile_deps_share_a_batch() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    struct ParallelProbe {
        inner: MockBackend,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        barrier: Arc<Barrier>,
    }

    impl Backend for ParallelProbe {
        fn resolve_version<'a>(
            &'a self,
            group_id: &'a str,
            artifact_id: &'a str,
            req: &'a VersionReq,
        ) -> super::BoxFuture<'a, super::Result<ResolvedVersion>> {
            self.inner.resolve_version(group_id, artifact_id, req)
        }

        fn fetch_project<'a>(
            &'a self,
            coord: &'a Coord,
            scope: Scope,
        ) -> super::BoxFuture<'a, super::Result<ResolvedProject>> {
            Box::pin(async move {
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_in_flight.fetch_max(now, Ordering::SeqCst);
                self.barrier.wait().await;
                let out = self.inner.fetch_project(coord, scope).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                out
            })
        }
    }

    let root = coord("com.example:root:1.0");
    let lib_a = coord("com.example:lib-a:1.0");
    let lib_b = coord("com.example:lib-b:1.0");

    let inner = MockBackend::default()
        .with_project(&lib_a, Vec::new())
        .with_project(&lib_b, Vec::new());

    let probe = ParallelProbe {
        inner,
        in_flight: AtomicUsize::new(0),
        max_in_flight: AtomicUsize::new(0),
        barrier: Arc::new(Barrier::new(2)),
    };

    let mut existing = PlatformConstraints::new();
    for module in ["lib-a", "lib-b"] {
        existing.add_constraint(PlatformConstraint {
            group: "com.example".to_string(),
            module: module.to_string(),
            type_: "jar".to_string(),
            classifier: None,
            version: ConstraintVersion {
                requires: Some("1.0".to_string()),
                strictly: None,
            },
            enforced: false,
            ..Default::default()
        });
    }

    let solver = Solver::new(&probe).with_platform_constraints(existing);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep_no_version("com.example", "lib-a"),
                dep_no_version("com.example", "lib-b"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "lib-a"),
        Some("1.0".to_string())
    );
    assert_eq!(
        find_version(&graph, "com.example", "lib-b"),
        Some("1.0".to_string())
    );
    assert_eq!(
        probe.max_in_flight.load(Ordering::SeqCst),
        2,
        "two unversioned compile deps must fetch in parallel; barrier(2).wait() would deadlock otherwise"
    );
}

/// Regression: in the default (non-strict / rv.toml) mode, a direct
/// `provided` dep's compile children were silently dropped. They should be
/// included and scoped as provided.
#[tokio::test]
async fn rv_toml_root_provided_dep_includes_children() {
    let root = coord("com.example:root:1.0");
    let provided = coord("com.example:provided:1.0");
    let provided_child = coord("com.example:provided-child:1.0");

    let mut dep_provided = dep("com.example", "provided", "1.0");
    dep_provided.scope = Some("provided".to_string());

    let backend = MockBackend::default()
        .with_project(&provided, vec![dep("com.example", "provided-child", "1.0")])
        .with_project(&provided_child, Vec::new());

    // Default Solver::new => strict_maven_compat=false, matching rv.toml roots.
    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![dep_provided],
            scope: Scope::Compile,
        })
        .await
        .unwrap();

    assert_eq!(
        find_version(&graph, "com.example", "provided-child"),
        Some("1.0".to_string()),
        "direct provided dep's children must be included for rv.toml roots"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// VersionConflict when nearest-wins picks an out-of-range version
// ──────────────────────────────────────────────────────────────────────────────

/// Graph: root → a:1.5 (soft pin, depth=1); root → b:1.0 → a:[2,3) (hard range, depth=2).
///
/// NearestWins selects a:1.5 (depth=1 wins). When b's transitive requirement
/// `[2,3)` arrives as the loser, 1.5 ∉ [2,3) → `VersionConflict` must be raised.
///
/// The solver first resolves `[2,3)` to `a:2.5` (best match), fetches the
/// project, and only THEN enters the conflict-resolution path where a:1.5 is
/// already selected. The loser-branch check fires there.
#[tokio::test]
async fn nearest_wins_out_of_range_raises_version_conflict() {
    let root = coord("com.example:root:1.0");
    let a_15 = coord("com.example:a:1.5");
    let a_25 = coord("com.example:a:2.5"); // what [2,3) resolves to
    let b = coord("com.example:b:1.0");

    // `b` depends on `a` with a hard range `[2,3)`.
    let dep_a_range = Dependency {
        group_id: "com.example".to_string(),
        artifact_id: "a".to_string(),
        version: Some("[2,3)".to_string()),
        type_: None,
        classifier: None,
        scope: Some("compile".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    };

    // Register both `a:1.5` (the soft-pin winner) and `a:2.5` (what the range
    // resolves to). Without registering `a:2.5`, `fetch_project` would error
    // before the conflict path is reached.
    let backend = MockBackend::default()
        .with_project(&a_15, Vec::new())
        .with_project(&a_25, Vec::new())
        .with_project(&b, vec![dep_a_range])
        .with_versions("com.example", "a", vec!["1.5", "2.0", "2.5"]);

    let solver = Solver::with_strategy(&backend, ResolutionStrategy::NearestWins, None);
    let result = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.5"), // soft pin, depth=1, wins nearest
                dep("com.example", "b", "1.0"), // depth=1, pulls a:[2,3) at depth=2
            ],
            scope: Scope::Compile,
        })
        .await;

    match result {
        Err(ResolveError::VersionConflict {
            coord,
            requested,
            selected,
        }) => {
            assert!(coord.contains("com.example:a"), "coord = {coord}");
            assert!(
                requested.contains("2") || requested.contains("["),
                "requested = {requested}"
            );
            assert!(selected.contains("1.5"), "selected = {selected}");
        }
        Err(other) => panic!("expected VersionConflict, got {other:?}"),
        Ok(graph) => panic!(
            "expected VersionConflict but resolution succeeded; a resolved to {:?}",
            find_version(&graph, "com.example", "a")
        ),
    }
}

/// Converse: root → A:2.5 (soft, depth=1); root → B:1.0 → A:[2,3) (hard range, depth=2).
/// NearestWins selects A:2.5. 2.5 ∈ [2,3), so no conflict should be raised.
#[tokio::test]
async fn nearest_wins_in_range_succeeds() {
    let root = coord("com.example:root:1.0");
    let a_ok = coord("com.example:a:2.5");
    let b = coord("com.example:b:1.0");

    let mut dep_a_range = dep("com.example", "a", "[2,3)");
    dep_a_range.version = Some("[2,3)".to_string());

    let backend = MockBackend::default()
        .with_project(&a_ok, Vec::new())
        .with_project(&b, vec![dep_a_range])
        .with_versions("com.example", "a", vec!["2.5"]);

    let solver = Solver::with_strategy(&backend, ResolutionStrategy::NearestWins, None);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "2.5"), // soft pin, depth=1
                dep("com.example", "b", "1.0"), // depth=1, pulls a:[2,3) at depth=2
            ],
            scope: Scope::Compile,
        })
        .await
        .expect("2.5 is within [2,3), no conflict expected");

    assert_eq!(
        find_version(&graph, "com.example", "a"),
        Some("2.5".to_string()),
        "in-range nearest-wins should succeed without error"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// #49: a hard *pin* (`[X]` -> Exact) that loses nearest-wins must raise
// VersionConflict, consistent with a hard *range* losing. Earlier only Ranges
// raised; a losing Exact pin silently accepted the nearest-wins version.
// ──────────────────────────────────────────────────────────────────────────────

/// Graph: root → a:1.5 (soft pin, depth=1); root → b:1.0 → a:[2.5] (hard pin,
/// depth=2). NearestWins selects a:1.5 (depth=1 wins). The transitive hard pin
/// `[2.5]` arrives as the loser; 1.5 ≠ 2.5 → `VersionConflict` must be raised.
#[tokio::test]
async fn nearest_wins_loses_hard_pin_raises_version_conflict() {
    let root = coord("com.example:root:1.0");
    let a_15 = coord("com.example:a:1.5");
    let a_25 = coord("com.example:a:2.5"); // what [2.5] resolves to
    let b = coord("com.example:b:1.0");

    // `b` depends on `a` with a hard pin `[2.5]` (Exact).
    let mut dep_a_pin = dep("com.example", "a", "[2.5]");
    dep_a_pin.version = Some("[2.5]".to_string());

    let backend = MockBackend::default()
        .with_project(&a_15, Vec::new())
        .with_project(&a_25, Vec::new())
        .with_project(&b, vec![dep_a_pin])
        .with_versions("com.example", "a", vec!["1.5", "2.5"]);

    let solver = Solver::with_strategy(&backend, ResolutionStrategy::NearestWins, None);
    let result = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.5"), // soft pin, depth=1, wins nearest
                dep("com.example", "b", "1.0"), // depth=1, pulls a:[2.5] at depth=2
            ],
            scope: Scope::Compile,
        })
        .await;

    match result {
        Err(ResolveError::VersionConflict {
            coord,
            requested,
            selected,
        }) => {
            assert!(coord.contains("com.example:a"), "coord = {coord}");
            assert!(requested.contains("2.5"), "requested = {requested}");
            assert!(selected.contains("1.5"), "selected = {selected}");
        }
        Err(other) => panic!("expected VersionConflict, got {other:?}"),
        Ok(graph) => panic!(
            "expected VersionConflict but resolution succeeded; a resolved to {:?}",
            find_version(&graph, "com.example", "a")
        ),
    }
}

/// Converse of the above: a losing *soft* pin must NOT raise. Soft pins are
/// preferences, so a depth-2 soft `2.5` losing to a depth-1 soft `1.5` is the
/// intended nearest-wins outcome.
#[tokio::test]
async fn nearest_wins_loses_soft_pin_does_not_conflict() {
    let root = coord("com.example:root:1.0");
    let a_15 = coord("com.example:a:1.5");
    let a_25 = coord("com.example:a:2.5");
    let b = coord("com.example:b:1.0");

    let backend = MockBackend::default()
        .with_project(&a_15, Vec::new())
        .with_project(&a_25, Vec::new())
        // b's a:2.5 is a bare (soft) version.
        .with_project(&b, vec![dep("com.example", "a", "2.5")]);

    let solver = Solver::with_strategy(&backend, ResolutionStrategy::NearestWins, None);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![
                dep("com.example", "a", "1.5"), // soft pin, depth=1
                dep("com.example", "b", "1.0"), // depth=1, pulls soft a:2.5 at depth=2
            ],
            scope: Scope::Compile,
        })
        .await
        .expect("a losing soft pin must not raise VersionConflict");

    assert_eq!(
        find_version(&graph, "com.example", "a"),
        Some("1.5".to_string()),
        "depth-1 soft pin wins nearest; losing soft pin is silently overridden"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// A system-scoped dependency with no version must error clearly instead
// of being assigned a fake "SYSTEM" version.
// ──────────────────────────────────────────────────────────────────────────────

/// A direct system-scoped dep with `version = None` must surface
/// `MissingVersion`, not silently coin a bogus `SYSTEM` coordinate.
#[tokio::test]
async fn system_scope_without_version_errors_missing_version() {
    let root = coord("com.example:root:1.0");

    let system_dep = Dependency {
        group_id: "com.example".to_string(),
        artifact_id: "native".to_string(),
        version: None,
        type_: None,
        classifier: None,
        scope: Some("system".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: Some("/opt/native/native.jar".to_string()),
    };

    let backend = MockBackend::default();
    let solver = Solver::new(&backend);
    let result = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![system_dep],
            scope: Scope::Compile,
        })
        .await;

    match result {
        Err(ResolveError::MissingVersion {
            group_id,
            artifact_id,
        }) => {
            assert_eq!(group_id, "com.example");
            assert_eq!(artifact_id, "native");
        }
        other => panic!("expected MissingVersion for version-less system dep, got {other:?}"),
    }
}

/// A system-scoped dep WITH a version still resolves to that exact version
/// (guards against the version-requirement change rejecting valid system deps).
#[tokio::test]
async fn system_scope_with_version_resolves() {
    let root = coord("com.example:root:1.0");

    let system_dep = Dependency {
        group_id: "com.example".to_string(),
        artifact_id: "native".to_string(),
        version: Some("1.2.3".to_string()),
        type_: None,
        classifier: None,
        scope: Some("system".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: Some("/opt/native/native.jar".to_string()),
    };

    let backend = MockBackend::default();
    let solver = Solver::new(&backend);
    let graph = solver
        .solve(SolverRoot {
            coord: root,
            dependencies: vec![system_dep],
            scope: Scope::Compile,
        })
        .await
        .expect("system dep with an explicit version must resolve");

    assert_eq!(
        find_version(&graph, "com.example", "native"),
        Some("1.2.3".to_string())
    );
}
