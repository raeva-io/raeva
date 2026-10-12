//! Nearest-wins and relocation fixtures match Maven's verbose dependency trees.
//! See `test-fixtures/nearest-backtracking/reproduce.py` for reproduction.
use super::*;

#[tokio::test]
async fn backtracking_withdraws_constraints_from_shared_descendants() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![dep("test", "x", "[1]")])
        .with_project(&coord("test:a:2"), vec![dep("test", "x", "[2]")])
        .with_project(&coord("test:x:1"), vec![])
        .with_project(&coord("test:x:2"), vec![])
        .with_project(&coord("test:d:1"), vec![dep("test", "c", "1")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[2]")]);
    for concurrency in [1, 2, 32] {
        let graph = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![
                    dep("test", "a", "1"),
                    dep("test", "x", "1"),
                    dep("test", "d", "1"),
                ],
                scope: Scope::Compile,
            })
            .await
            .unwrap();
        assert_eq!(find_version(&graph, "test", "a"), Some("2".into()));
        assert_eq!(find_version(&graph, "test", "x"), Some("2".into()));
        assert_eq!(graph.edge_indices().count(), 6);
    }
}

#[tokio::test]
async fn backtracking_reconsiders_previously_rejected_shared_candidates() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![dep("test", "x", "[2]")])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:x:1"), vec![dep("test", "child", "1")])
        .with_project(&coord("test:x:2"), vec![dep("test", "child", "2")])
        .with_project(&coord("test:child:1"), vec![])
        .with_project(&coord("test:child:2"), vec![])
        .with_project(&coord("test:d:1"), vec![dep("test", "c", "1")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[2]")]);
    for concurrency in [1, 2, 32] {
        let graph = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![
                    dep("test", "a", "1"),
                    dep("test", "x", "1"),
                    dep("test", "d", "1"),
                ],
                scope: Scope::Compile,
            })
            .await
            .unwrap();
        assert_eq!(find_version(&graph, "test", "a"), Some("2".into()));
        assert_eq!(find_version(&graph, "test", "x"), Some("1".into()));
        let x = graph
            .node_index(&crate::graph::CoordKey::from(&coord("test:x:1")))
            .unwrap();
        let children: Vec<_> = graph
            .edges(x)
            .map(|(_, child, _)| graph.node(child).unwrap().coord.to_string())
            .collect();
        assert_eq!(children, ["test:child:1"]);
        assert_eq!(graph.edge_indices().count(), 6);
    }
}

#[tokio::test]
async fn relocation_target_management_resolves_intervals_and_unions() {
    let backend = MockBackend::default()
        .with_project(&coord("test:new:1"), vec![])
        .with_project(&coord("test:new:2"), vec![])
        .with_project(&coord("test:new:3"), vec![])
        .with_project(&coord("test:p:1"), vec![dep("test", "old", "1")])
        .with_versions("test", "new", vec!["1", "2", "3"])
        .with_relocated_project(
            &coord("test:old:1"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("1".into()),
                message: None,
            },
            vec![],
        );
    for (requirement, expected) in [("[2,4)", "3"), ("[1,2),[3,4)", "3")] {
        for concurrency in [1, 2, 32] {
            let mut constraints = PlatformConstraints::new();
            constraints.add_constraint(managed_constraint("test", "new", requirement));
            let graph = Solver::new(&backend)
                .with_platform_constraints(constraints)
                .with_fetch_concurrency(concurrency)
                .solve(SolverRoot {
                    coord: coord("test:root:1"),
                    dependencies: vec![dep("test", "p", "1")],
                    scope: Scope::Compile,
                })
                .await
                .unwrap();
            assert_eq!(find_version(&graph, "test", "new"), Some(expected.into()));
            assert_eq!(find_version(&graph, "test", "old"), None);
        }
    }
}

#[tokio::test]
async fn relocation_target_range_retains_alternatives_for_backtracking() {
    let backend = MockBackend::default()
        .with_project(&coord("test:new:1"), vec![])
        .with_project(&coord("test:new:2"), vec![dep("test", "child", "2")])
        .with_project(&coord("test:new:3"), vec![dep("test", "child", "3")])
        .with_project(&coord("test:child:2"), vec![])
        .with_project(&coord("test:child:3"), vec![])
        .with_project(&coord("test:p:1"), vec![dep("test", "old", "1")])
        .with_versions("test", "new", vec!["1", "2", "3"])
        .with_relocated_project(
            &coord("test:old:1"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("1".into()),
                message: None,
            },
            vec![],
        );
    for requirement in ["[2,4)", "[1,2),[2,4)"] {
        let mut constraints = PlatformConstraints::new();
        constraints.add_constraint(managed_constraint("test", "new", requirement));
        let graph = Solver::new(&backend)
            .with_platform_constraints(constraints)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "p", "1"), dep("test", "new", "[2]")],
                scope: Scope::Compile,
            })
            .await
            .unwrap();
        assert_eq!(find_version(&graph, "test", "new"), Some("2".into()));
        assert_eq!(find_version(&graph, "test", "child"), Some("2".into()));
    }
}

#[tokio::test]
async fn maven_range_alternatives() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:a:3"), vec![])
        .with_project(&coord("test:a:4"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "[1,2],[4]")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[2,3]")])
        .with_versions("test", "a", vec!["1", "2", "3", "4"]);
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "b", "1"), dep("test", "c", "1")],
                scope: Scope::Compile,
            })
            .await;
        let graph = result.unwrap();
        assert_eq!(
            find_version(&graph, "test", "a"),
            Some("2".into()),
            "concurrency={concurrency}"
        );
    }
}

#[tokio::test]
async fn maven_backtrack() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![dep("test", "old-child", "1")])
        .with_project(&coord("test:a:2"), vec![dep("test", "winner-child", "1")])
        .with_project(&coord("test:a:3"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "2")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[2,4)")])
        .with_project(&coord("test:old-child:1"), vec![])
        .with_project(&coord("test:winner-child:1"), vec![])
        .with_versions("test", "a", vec!["1", "2", "3"]);
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![
                    dep("test", "a", "1"),
                    dep("test", "b", "1"),
                    dep("test", "c", "1"),
                ],
                scope: Scope::Compile,
            })
            .await;
        let graph = result.unwrap();
        assert_eq!(
            find_version(&graph, "test", "a"),
            Some("2".into()),
            "concurrency={concurrency}"
        );
        assert_eq!(
            find_version(&graph, "test", "winner-child"),
            Some("1".into())
        );
        assert!(
            graph
                .node_index(&crate::graph::CoordKey::from(&coord("test:old-child:1")))
                .is_none()
        );
    }
}

#[tokio::test]
async fn maven_backtrack_reversed() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:a:3"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "2")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[2,4)")])
        .with_versions("test", "a", vec!["1", "2", "3"]);
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![
                    dep("test", "a", "1"),
                    dep("test", "c", "1"),
                    dep("test", "b", "1"),
                ],
                scope: Scope::Compile,
            })
            .await;
        let graph = result.unwrap();
        assert_eq!(
            find_version(&graph, "test", "a"),
            Some("3".into()),
            "concurrency={concurrency}"
        );
    }
}

#[tokio::test]
async fn maven_backtrack_prune() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:a:3"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "2")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[2,4)")])
        .with_project(&coord("test:d:1"), vec![dep("test", "a", "[3,4)")])
        .with_versions("test", "a", vec!["1", "2", "3"]);
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![
                    dep("test", "a", "1"),
                    dep("test", "b", "1"),
                    dep("test", "c", "1"),
                    dep("test", "d", "1"),
                ],
                scope: Scope::Compile,
            })
            .await;
        let graph = result.unwrap();
        assert_eq!(
            find_version(&graph, "test", "a"),
            Some("3".into()),
            "concurrency={concurrency}"
        );
    }
}

#[tokio::test]
async fn maven_hard_acceptability() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "[2,3)")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "1")])
        .with_versions("test", "a", vec!["1", "2"]);
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "b", "1"), dep("test", "c", "1")],
                scope: Scope::Compile,
            })
            .await;
        let graph = result.unwrap();
        assert_eq!(
            find_version(&graph, "test", "a"),
            Some("2".into()),
            "concurrency={concurrency}"
        );
    }
}

#[tokio::test]
async fn maven_hard_conflict() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "[2,3)")])
        .with_versions("test", "a", vec!["1", "2"]);
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "a", "[1]"), dep("test", "b", "1")],
                scope: Scope::Compile,
            })
            .await;
        assert!(
            matches!(result, Err(ResolveError::VersionConflict { .. })),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn maven_relocation() {
    let backend = MockBackend::default()
        .with_project(&coord("test:new:1"), vec![dep("test", "old-child", "1")])
        .with_project(&coord("test:new:2"), vec![dep("test", "winner-child", "1")])
        .with_relocated_project(
            &coord("test:old:1"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("1".into()),
                message: None,
            },
            vec![],
        )
        .with_project(&coord("test:old-child:1"), vec![])
        .with_project(&coord("test:p:1"), vec![dep("test", "old", "[1]")])
        .with_project(&coord("test:winner-child:1"), vec![]);
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "new", "2"), dep("test", "p", "1")],
                scope: Scope::Compile,
            })
            .await;
        let graph = result.unwrap();
        assert_eq!(
            find_version(&graph, "test", "new"),
            Some("2".into()),
            "concurrency={concurrency}"
        );
        assert_eq!(
            find_version(&graph, "test", "winner-child"),
            Some("1".into())
        );
        assert!(
            graph
                .node_index(&crate::graph::CoordKey::from(&coord("test:old-child:1")))
                .is_none()
        );
    }
}

#[tokio::test]
async fn maven_relocation_version() {
    let backend = MockBackend::default()
        .with_relocated_project(
            &coord("test:new:1"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("3".into()),
                message: None,
            },
            vec![],
        )
        .with_project(&coord("test:new:2"), vec![])
        .with_project(&coord("test:new:3"), vec![])
        .with_project(&coord("test:p:1"), vec![dep("test", "new", "[1]")]);
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "new", "2"), dep("test", "p", "1")],
                scope: Scope::Compile,
            })
            .await;
        let graph = result.unwrap();
        assert_eq!(
            find_version(&graph, "test", "new"),
            Some("2".into()),
            "concurrency={concurrency}"
        );
    }
}

#[tokio::test]
async fn maven_relocation_siblings() {
    let backend = MockBackend::default()
        .with_project(&coord("test:new:1"), vec![])
        .with_project(&coord("test:new:2"), vec![])
        .with_relocated_project(
            &coord("test:old:1"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("1".into()),
                message: None,
            },
            vec![],
        );
    for concurrency in [1, 2, 32] {
        let result = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "old", "[1]"), dep("test", "new", "2")],
                scope: Scope::Compile,
            })
            .await;
        let graph = result.unwrap();
        assert_eq!(
            find_version(&graph, "test", "new"),
            Some("2".into()),
            "concurrency={concurrency}"
        );
    }
}

/// Hard constraints apply to nearer candidates and higher sibling versions.
/// Conflict items may arrive from a depth-first collector.
#[test]
fn hard_range_rejects_nearer_and_higher_sibling_candidates() {
    use super::super::queue::{PathNode, QueueItem};
    use super::super::{Candidate, RequestedRequirement, Selected};
    use crate::graph::CoordKey;
    use petgraph::graph::NodeIndex;

    let root_key = CoordKey::from(&coord("test:root:1"));
    let make_candidate = |version: &str, parent: usize, depth: usize| {
        let coordinate = coord(&format!("test:a:{version}"));
        let backend = MockBackend::default().with_project(&coordinate, vec![]);
        Arc::new(Candidate {
            item: QueueItem::new(
                NodeIndex::new(parent),
                Arc::new(Version::parse("1").unwrap()),
                Arc::new(dep("test", "a", version)),
                Scope::Compile,
                depth,
                0,
                Arc::from(Vec::new()),
                PathNode::root(root_key.clone()),
            ),
            resolved: ResolvedVersion {
                version: coordinate.version.clone(),
                repo_url: None,
            },
            resolved_project: ResolvedProject {
                project: backend.projects[&coordinate.to_string()].clone(),
                repo_url: None,
                workspace_module: None,
                platform_constraints: None,
            },
            coord: coordinate,
            effective_scope: Scope::Compile,
            child_scope: Some(Scope::Compile),
        })
    };
    let winner = make_candidate("2", 1, 2);
    let mut selected = Selected {
        node: NodeIndex::new(2),
        version: winner.coord.version.clone(),
        hard: vec![VersionReq::parse("[2,3)").unwrap()],
        candidates: vec![Arc::clone(&winner)],
        winner: Some(Arc::clone(&winner)),
    };
    for (index, candidate) in [make_candidate("1", 0, 1), make_candidate("3", 1, 2)]
        .into_iter()
        .enumerate()
    {
        let requirement = RequestedRequirement::Soft(candidate.coord.version.clone());
        assert!(
            selected
                .consider(candidate, &requirement, ResolutionStrategy::NearestWins)
                .unwrap()
                .is_none()
        );
        assert!(Arc::ptr_eq(selected.winner.as_ref().unwrap(), &winner));
        assert_eq!(selected.candidates.len(), index + 2);
    }
}

/// The source's range is dropped, but a hard constraint explicitly managed
/// for the target still applies (including when its version is unchanged).
#[tokio::test]
async fn maven_relocation_target_range() {
    let backend = MockBackend::default()
        .with_project(&coord("test:new:1"), vec![])
        .with_project(&coord("test:new:2"), vec![])
        .with_project(&coord("test:p:1"), vec![dep("test", "old", "[1]")])
        .with_relocated_project(
            &coord("test:old:1"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("1".into()),
                message: None,
            },
            vec![],
        );
    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(managed_constraint("test", "new", "[1]"));
    for concurrency in [1, 2, 32] {
        let graph = Solver::new(&backend)
            .with_platform_constraints(constraints.clone())
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "new", "2"), dep("test", "p", "1")],
                scope: Scope::Compile,
            })
            .await
            .unwrap();
        assert_eq!(find_version(&graph, "test", "new"), Some("1".into()));
    }
}
