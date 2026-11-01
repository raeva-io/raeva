//! Behavior checked against Maven 3.10.0.

use super::*;

/// Maven reads a losing range's preferred version even when a nearer soft
/// pin already satisfies the range. That discovers a relocation onto a
/// managed coordinate and drops the soft pin once the groups merge.
#[tokio::test]
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
    let constraints = managed("test", "b", "[2]");
    let graph = Solver::new(&backend)
        .with_management(constraints)
        .solve(SolverRoot {
            coord: coord("test:root:1"),
            dependencies: vec![dep("test", "a", "1"), dep("test", "p", "1")],
            scope: Scope::Compile,
        })
        .await
        .unwrap();
    assert_eq!(find_version(&graph, "test", "a"), None);
    assert_eq!(find_version(&graph, "test", "b"), Some("2".into()));
    assert_eq!(find_version(&graph, "test", "p"), Some("1".into()));
}

/// Maven keeps the winner's own children after a cyclic declaration flips
/// the version. The data-pool reuse story that would drop `q:1` does not
/// match Maven 3.10.0.
#[tokio::test]
async fn cyclic_declaration_keeps_the_winner_children() {
    let backend = backend(&[
        "a:1 > b:1",
        "d:1 > b:1",
        "b:1 > a:[2,2]",
        "a:2 > q:1",
        "q:1",
    ]);
    let solved = Solver::new(&backend).solve(root("a:1 d:1")).await;
    assert_eq!(render(solved), "a:2 b:1 d:1 q:1");
}

/// A deeper hard range that relocates joins the nearer soft winner's group
/// and then loses mediation. Maven 3.10.0 keeps `old:lib:1` with its
/// children and drops `new:lib:2`.
#[tokio::test]
async fn relocated_range_loses_to_nearer_soft_with_children() {
    let backend = backend(&[
        "old:lib:1 > child:1",
        "child:1",
        "old:lib:2 => new:lib:2",
        "new:lib:2",
        "b:1 > old:lib:[2,3)",
        "versions old:lib 1 2",
    ]);
    let solved = Solver::new(&backend).solve(root("old:lib:1 b:1")).await;
    assert_eq!(render(solved), "b:1 child:1 old:lib:1");
}
