use super::*;

#[tokio::test]
#[ignore = "lazy ranges do not load descriptors of losing alternatives"]
async fn losing_range_relocation_discovers_managed_target() {
    let backend = MockBackend::default()
        .with_project(&coord("test:a:1"), vec![])
        .with_project(&coord("test:b:1"), vec![])
        .with_project(&coord("test:b:2"), vec![])
        .with_project(&coord("test:p:1"), vec![dep("test", "a", "[1,3)")])
        .with_versions("test", "a", vec!["1", "2"])
        .with_relocated_project(
            &coord("test:a:2"),
            Relocation {
                group_id: None,
                artifact_id: Some("b".into()),
                version: Some("1".into()),
                message: None,
            },
            vec![],
        );
    let mut constraints = PlatformConstraints::new();
    constraints.add_constraint(managed_constraint("test", "b", "[2]"));
    let graph = Solver::new(&backend)
        .with_platform_constraints(constraints)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "a", "1"), dep("test", "p", "1")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "a"), Some("1".into()));
    assert_eq!(find_version(&graph, "test", "b"), Some("2".into()));
}

fn thirty_versions() -> MockBackend {
    let versions: Vec<_> = (1..=30).map(|v| v.to_string()).collect();
    let mut backend = MockBackend::default().with_versions(
        "test",
        "a",
        versions.iter().map(String::as_str).collect(),
    );
    for version in versions {
        backend = backend.with_project(&coord(&format!("test:a:{version}")), vec![]);
    }
    backend
}

#[tokio::test]
async fn thirty_version_range_fetches_only_winner() {
    for strategy in [
        ResolutionStrategy::NearestWins,
        ResolutionStrategy::HighestWins,
    ] {
        let backend = thirty_versions();
        let graph = Solver::with_strategy(&backend, strategy, None)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "a", "[1,31)")],
                scope: Scope::Compile,
            })
            .await
            .unwrap();
        assert_eq!(find_version(&graph, "test", "a"), Some("30".into()));
        assert_eq!(graph.edge_indices().count(), 1);
        assert_eq!(*backend.fetches.lock().unwrap(), ["test:a:30"]);
    }
}

#[tokio::test]
async fn range_backtracking_fetches_only_winners_and_keeps_one_edge_per_parent() {
    for concurrency in [1, 2, 32] {
        let backend = thirty_versions()
            .with_project(&coord("test:b:1"), vec![dep("test", "a", "[1,31)")])
            .with_project(&coord("test:c:1"), vec![dep("test", "a", "[1,11)")]);
        let graph = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "b", "1"), dep("test", "c", "1")],
                scope: Scope::Compile,
            })
            .await
            .unwrap();
        assert_eq!(find_version(&graph, "test", "a"), Some("10".into()));
        assert_eq!(graph.edge_indices().count(), 4);
        for parent in ["test:b:1", "test:c:1"] {
            let index = graph
                .node_index(&crate::graph::CoordKey::from(&coord(parent)))
                .unwrap();
            assert_eq!(graph.edges(index).count(), 1);
        }
        let fetches = backend.fetches.lock().unwrap();
        let range_fetches: Vec<_> = fetches
            .iter()
            .filter(|c| c.starts_with("test:a:"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            range_fetches,
            ["test:a:30", "test:a:10"],
            "concurrency={concurrency}"
        );
        assert_eq!(fetches.len(), 4);
    }
}

#[tokio::test]
async fn losing_range_does_not_fetch_descriptors() {
    let backend =
        thirty_versions().with_project(&coord("test:b:1"), vec![dep("test", "a", "[1,31)")]);
    let graph = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "a", "1"), dep("test", "b", "1")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "a"), Some("1".into()));
    assert_eq!(graph.edge_indices().count(), 3);
    assert_eq!(backend.fetches.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn visited_range_relocation_stops_source_alternatives() {
    let backend = thirty_versions()
        .with_relocated_project(
            &coord("test:a:30"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("1".into()),
                message: None,
            },
            vec![],
        )
        .with_project(&coord("test:new:1"), vec![])
        .with_project(&coord("test:new:2"), vec![]);
    let graph = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "a", "[1,31)"), dep("test", "new", "2")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "new"), Some("2".into()));
    assert_eq!(find_version(&graph, "test", "a"), None);
    assert_eq!(backend.fetches.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn backtracking_relocation_preserves_the_triggering_request() {
    for concurrency in [1, 2, 32] {
        let backend = thirty_versions()
            .with_project(&coord("test:b:1"), vec![dep("test", "a", "[1,31)")])
            .with_project(&coord("test:c:1"), vec![dep("test", "a", "[1,11)")])
            .with_relocated_project(
                &coord("test:a:10"),
                Relocation {
                    group_id: None,
                    artifact_id: Some("new".into()),
                    version: Some("1".into()),
                    message: None,
                },
                vec![],
            )
            .with_project(&coord("test:new:1"), vec![]);
        let graph = Solver::new(&backend)
            .with_fetch_concurrency(concurrency)
            .solve(SolverRoot {
                coord: coord("test:root:1"),
                dependencies: vec![dep("test", "b", "1"), dep("test", "c", "1")],
                scope: Scope::Compile,
            })
            .await
            .unwrap();
        for parent in ["test:b:1", "test:c:1"] {
            let index = graph
                .node_index(&crate::graph::CoordKey::from(&coord(parent)))
                .unwrap();
            let edges: Vec<_> = graph.edges(index).collect();
            assert_eq!(edges.len(), 1);
            assert_eq!(graph.node(edges[0].1).unwrap().coord, coord("test:new:1"));
        }
        assert_eq!(graph.edge_indices().count(), 4);
        assert!(
            graph
                .node_index(&crate::graph::CoordKey::from(&coord("test:a:1")))
                .is_none()
        );
    }
}
