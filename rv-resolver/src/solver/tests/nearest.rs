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
    let graph = Solver::new(&backend)
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
    assert_eq!(graph.edge_count(), 6);
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
    let graph = Solver::new(&backend)
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
    assert_eq!(graph.edge_count(), 6);
}

#[tokio::test]
async fn backtracking_to_an_equal_version_spelled_differently_drops_its_children() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![dep("test", "p", "1.1")])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "p", "1-1")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[2]")])
        .with_project(&coord("test:p:1.1"), vec![dep("test", "old", "1")])
        .with_project(&coord("test:p:1-1"), vec![dep("test", "new", "1")])
        .with_project(&coord("test:old:1"), vec![])
        .with_project(&coord("test:new:1"), vec![]);
    let graph = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![
                dep("test", "a", "1"),
                dep("test", "b", "1"),
                dep("test", "c", "1"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "p"), Some("1-1".into()));
    assert_eq!(find_version(&graph, "test", "new"), Some("1".into()));
    assert_eq!(find_version(&graph, "test", "old"), None);
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
        let constraints = managed("test", "new", requirement);
        let graph = Solver::new(&backend)
            .with_management(constraints)
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

#[tokio::test]
async fn relocation_target_management_fetches_an_equal_version_spelled_differently() {
    let backend = MockBackend::default()
        .with_project(&coord("test:new:1-1"), vec![dep("test", "a", "1")])
        .with_project(&coord("test:new:1.1"), vec![dep("test", "b", "1")])
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:b:1"), vec![])
        .with_project(&coord("test:p:1"), vec![dep("test", "old", "1")])
        .with_relocated_project(
            &coord("test:old:1"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("1-1".into()),
                message: None,
            },
            vec![],
        );
    let graph = Solver::new(&backend)
        .with_management(managed("test", "new", "1.1"))
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "p", "1")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "new"), Some("1.1".into()));
    assert_eq!(find_version(&graph, "test", "b"), Some("1".into()));
    assert_eq!(find_version(&graph, "test", "a"), None);
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
        let constraints = managed("test", "new", requirement);
        let graph = Solver::new(&backend)
            .with_management(constraints)
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
    let result = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "b", "1"), dep("test", "c", "1")],
            scope: Scope::Compile,
        })
        .await;
    let graph = result.unwrap();
    assert_eq!(find_version(&graph, "test", "a"), Some("2".into()));
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
    let result = Solver::new(&backend)
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
    assert_eq!(find_version(&graph, "test", "a"), Some("2".into()));
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

#[tokio::test]
async fn maven_backtrack_reversed() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:a:3"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "2")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[2,4)")])
        .with_versions("test", "a", vec!["1", "2", "3"]);
    let result = Solver::new(&backend)
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
    assert_eq!(find_version(&graph, "test", "a"), Some("3".into()));
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
    let result = Solver::new(&backend)
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
    assert_eq!(find_version(&graph, "test", "a"), Some("3".into()));
}

#[tokio::test]
async fn maven_hard_acceptability() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "[2,3)")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "1")])
        .with_versions("test", "a", vec!["1", "2"]);
    let result = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "b", "1"), dep("test", "c", "1")],
            scope: Scope::Compile,
        })
        .await;
    let graph = result.unwrap();
    assert_eq!(find_version(&graph, "test", "a"), Some("2".into()));
}

#[tokio::test]
async fn maven_hard_conflict() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:a:2"), vec![])
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "[2,3)")])
        .with_versions("test", "a", vec!["1", "2"]);
    let result = Solver::new(&backend)
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
    let result = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "new", "2"), dep("test", "p", "1")],
            scope: Scope::Compile,
        })
        .await;
    let graph = result.unwrap();
    assert_eq!(find_version(&graph, "test", "new"), Some("2".into()));
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
    let result = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "new", "2"), dep("test", "p", "1")],
            scope: Scope::Compile,
        })
        .await;
    let graph = result.unwrap();
    assert_eq!(find_version(&graph, "test", "new"), Some("2".into()));
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
    let result = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "old", "[1]"), dep("test", "new", "2")],
            scope: Scope::Compile,
        })
        .await;
    let graph = result.unwrap();
    assert_eq!(find_version(&graph, "test", "new"), Some("2".into()));
}

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
    let constraints = managed("test", "new", "[1]");
    let graph = Solver::new(&backend)
        .with_management(constraints.clone())
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "new", "2"), dep("test", "p", "1")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "new"), Some("1".into()));
}
