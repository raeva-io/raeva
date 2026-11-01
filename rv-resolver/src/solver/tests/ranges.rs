use super::*;

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

fn ascending(to: usize) -> Vec<String> {
    (1..=to).map(|v| format!("test:a:{v}")).collect()
}

/// Maven 3.9 reads every version of a range, from the lowest up, before
/// mediation picks the highest.
#[tokio::test]
async fn thirty_version_range_reads_every_version() {
    let backend = thirty_versions();
    let graph = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "a", "[1,31)")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "a"), Some("30".into()));
    assert_eq!(graph.edge_count(), 1);
    assert_eq!(*backend.fetches.lock().unwrap(), ascending(30));
}

#[tokio::test]
async fn range_backtracking_keeps_one_edge_per_parent() {
    let backend = thirty_versions()
        .with_project(&coord("test:b:1"), vec![dep("test", "a", "[1,31)")])
        .with_project(&coord("test:c:1"), vec![dep("test", "a", "[1,11)")]);
    let graph = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "b", "1"), dep("test", "c", "1")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "a"), Some("10".into()));
    assert_eq!(graph.edge_count(), 4);
    for parent in ["test:b:1", "test:c:1"] {
        let index = graph
            .node_index(&crate::graph::CoordKey::from(&coord(parent)))
            .unwrap();
        assert_eq!(graph.edges(index).count(), 1);
    }
    let fetches = backend.fetches.lock().unwrap();
    let read: std::collections::BTreeSet<_> = fetches
        .iter()
        .filter(|c| c.starts_with("test:a:"))
        .collect();
    assert_eq!(read.len(), 30, "got {fetches:?}");
}

#[tokio::test]
async fn losing_range_reads_every_version() {
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
    assert_eq!(graph.edge_count(), 3);
    // Maven reads the losing range's versions too, so a relocation there
    // can join the group.
    let fetches = backend.fetches.lock().unwrap();
    assert_eq!(fetches.len(), 32, "{fetches:?}");
    assert!(fetches.ends_with(&ascending(30)), "{fetches:?}");
}

/// Maven reads no version of a range above the first that relocates.
#[tokio::test]
async fn range_reads_nothing_past_its_first_relocation() {
    let backend = thirty_versions()
        .with_relocated_project(
            &coord("test:a:5"),
            Relocation {
                group_id: None,
                artifact_id: Some("new".into()),
                version: Some("1".into()),
                message: None,
            },
            vec![],
        )
        .with_project(&coord("test:new:1"), vec![]);
    Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "a", "[1,31)")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    let fetches = backend.fetches.lock().unwrap();
    let read: Vec<_> = fetches
        .iter()
        .filter(|c| c.starts_with("test:a:"))
        .collect();
    assert_eq!(read, ascending(5).iter().collect::<Vec<_>>());
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
    // Maven walks the range up to the version that relocates; the highest
    // version below it wins over the relocation's soft target.
    assert_eq!(find_version(&graph, "test", "a"), Some("29".into()));
    assert_eq!(find_version(&graph, "test", "new"), None);
    let mut expected = ascending(30);
    expected.extend(["test:new:1".to_string(), "test:new:2".to_string()]);
    assert_eq!(*backend.fetches.lock().unwrap(), expected);
}

#[tokio::test]
async fn range_relocation_to_an_equal_version_spelled_differently_drops_the_range() {
    let backend = MockBackend::default()
        .with_versions("test", "a", vec!["1-1", "3"])
        .with_relocated_project(
            &coord("test:a:1-1"),
            Relocation {
                group_id: None,
                artifact_id: None,
                version: Some("1.1".into()),
                message: None,
            },
            vec![],
        )
        .with_project(&coord("test:a:1.1"), vec![])
        .with_project(&coord("test:a:3"), vec![])
        .with_project(&coord("test:p:1"), vec![dep("test", "a", "[3]")]);
    let graph = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "a", "[1,2)"), dep("test", "p", "1")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "a"), Some("3".into()));
}

#[tokio::test]
async fn backtracking_relocation_preserves_the_triggering_request() {
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
        assert_eq!(graph.node(edges[0].1).unwrap().coord, coord("test:a:9"));
    }
    assert_eq!(find_version(&graph, "test", "new"), None);
}

/// Maven 3.9 stops a range at its lowest version that relocates, even when
/// a higher one does not; Maven 3.10 takes `x:3`.
#[tokio::test]
async fn range_stops_at_its_lowest_version_that_relocates() {
    let backend = backend(&[
        "a:1 > x:[1,3]",
        "x:1 > e:1",
        "x:2 => g:y:1",
        "x:3 > e:1",
        "y:1 > yy:1",
        "yy:1",
        "e:1",
    ]);
    let solved = Solver::new(&backend).solve(root("a:1")).await;
    assert_eq!(render(solved), "a:1 e:1 x:1");
}

/// Maven reads no version above the first that relocates, so a range does
/// not wait for those loads.
#[tokio::test]
async fn range_drops_the_loads_above_its_first_relocation() {
    struct Stalled(MockBackend);
    impl Backend for Stalled {
        fn resolve_version<'a>(
            &'a self,
            group_id: &'a str,
            artifact_id: &'a str,
            req: &'a VersionReq,
            repos: &'a RepoContext,
        ) -> super::super::BoxFuture<'a, super::super::Result<ResolvedVersion>> {
            self.0.resolve_version(group_id, artifact_id, req, repos)
        }
        fn resolve_versions<'a>(
            &'a self,
            group_id: &'a str,
            artifact_id: &'a str,
            req: &'a VersionReq,
            repos: &'a RepoContext,
        ) -> super::super::BoxFuture<'a, super::super::Result<Vec<ResolvedVersion>>> {
            self.0.resolve_versions(group_id, artifact_id, req, repos)
        }
        fn fetch_project<'a>(
            &'a self,
            coord: &'a Coord,
            resolve_snapshot_pom: bool,
            repos: &'a RepoContext,
        ) -> super::super::BoxFuture<'a, super::super::Result<ResolvedProject>> {
            Box::pin(async move {
                if coord.artifact_id.as_str() == "x" && coord.version.as_str() != "1" {
                    std::future::pending::<()>().await;
                }
                self.0
                    .fetch_project(coord, resolve_snapshot_pom, repos)
                    .await
            })
        }
    }
    let backend = Stalled(backend(&[
        "a:1 > x:[1,3]",
        "x:1 => g:y:1",
        "x:2",
        "x:3",
        "y:1 > yy:1",
        "yy:1",
    ]));
    let solved = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        Solver::new(&backend).solve(root("a:1")),
    )
    .await
    .expect("the loads above x:1 are dropped");
    assert_eq!(render(solved), "a:1 y:1 yy:1");
}

/// A range that makes a direct winner lose retires its subtree after part of
/// it was queued. Maven 3.9.12 still reads that part, a relocation and its
/// target included.
#[tokio::test]
async fn a_retired_subtree_is_read() {
    let backend = MockBackend::default()
        .with_versions("t", "a", vec!["1", "2"])
        .with_project(&coord("t:a:1"), vec![dep("t", "c", "1")])
        .with_project(&coord("t:a:2"), vec![])
        .with_project(&coord("t:b:1"), vec![dep("t", "a", "[2,3)")])
        .with_project(&coord("t:c:1"), vec![dep("t", "z", "1")])
        .with_relocated_project(
            &coord("t:z:1"),
            Relocation {
                group_id: None,
                artifact_id: Some("target".into()),
                version: None,
                message: None,
            },
            vec![],
        )
        .with_project(&coord("t:target:1"), vec![])
        .with_project(&coord("t:filler:1"), vec![]);
    let graph = Solver::new(&backend)
        .solve(SolverRoot {
            coord: coord("t:root:1"),
            dependencies: vec![
                dep("t", "a", "1"),
                dep("t", "b", "1"),
                dep("t", "filler", "1"),
            ],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "t", "a"), Some("2".into()));
    assert_eq!(find_version(&graph, "t", "target"), None);
    let mut fetches = backend.fetches.lock().unwrap().clone();
    fetches.sort();
    assert_eq!(
        fetches,
        [
            "t:a:1",
            "t:a:2",
            "t:b:1",
            "t:c:1",
            "t:filler:1",
            "t:target:1",
            "t:z:1"
        ]
    );
}
