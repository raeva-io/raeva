//! The graphs of `test-fixtures/maven-modes/cases.txt`, solved in each
//! mode and compared with what Maven 3.9.12 and 3.10.0 resolved for them;
//! `differential.py` there checks the expected lines against real Maven.

use super::*;

struct ModeCase {
    name: String,
    projects: Vec<String>,
    root: String,
    manage: String,
    expect: Vec<(MavenMode, String)>,
    /// What raeva's 3.9 mode resolves where it knowingly differs from Maven.
    raeva_39: Option<String>,
    /// What Maven 3.9 resolves with `-Daether.dependencyCollector.impl=bf`
    /// where that is not the 3.10 result.
    bf_39: Option<String>,
    /// What Maven 3.10 resolves with `-Daether.dependencyCollector.impl=df`
    /// where that is not the 3.9 result.
    df_310: Option<String>,
}

fn cases() -> Vec<ModeCase> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-fixtures/maven-modes/cases.txt"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut cases: Vec<ModeCase> = Vec::new();
    for raw in text.lines() {
        if let Some(name) = raw.strip_prefix("## ") {
            cases.push(ModeCase {
                name: name.trim().to_string(),
                projects: Vec::new(),
                root: String::new(),
                manage: String::new(),
                expect: Vec::new(),
                raeva_39: None,
                bf_39: None,
                df_310: None,
            });
            continue;
        }
        let line = raw.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let case = cases.last_mut().expect("a case");
        if let Some(root) = line.strip_prefix("root:") {
            case.root = root.trim().to_string();
        } else if let Some(manage) = line.strip_prefix("manage:") {
            case.manage = manage.trim().to_string();
        } else if let Some(raeva_39) = line.strip_prefix("raeva 3.9:") {
            case.raeva_39 = Some(raeva_39.trim().to_string());
        } else if let Some(bf_39) = line.strip_prefix("expect 3.9-bf:") {
            case.bf_39 = Some(bf_39.trim().to_string());
        } else if let Some(df_310) = line.strip_prefix("expect 3.10-df:") {
            case.df_310 = Some(df_310.trim().to_string());
        } else if let Some(expect) = line.strip_prefix("expect ") {
            let (mode, value) = expect.split_once(':').unwrap();
            let mode = MavenMode::parse(mode.trim()).unwrap();
            case.expect.push((mode, value.trim().to_string()));
        } else {
            case.projects.push(line.to_string());
        }
    }
    cases
}

/// The `ResolveError` variant that stands for a failure Maven words as
/// `message`; raeva's own wording differs.
fn error_kind(message: &str) -> &'static str {
    if message.starts_with("No versions available") {
        "VersionNotFound"
    } else if message.starts_with("Unsolvable hard constraint")
        || message.starts_with("conflict resolver did not select winner")
    {
        "VersionConflict"
    } else {
        panic!("no error kind for {message}")
    }
}

#[tokio::test]
async fn each_mode_resolves_as_its_maven_line() {
    let cases = cases();
    assert!(cases.len() >= 20);
    let mut failures = Vec::new();
    for case in &cases {
        assert_eq!(case.expect.len(), 2, "{}", case.name);
        let maven_310 = &case
            .expect
            .iter()
            .find(|(mode, _)| *mode == MavenMode::Maven310);
        let bf_39 = (case.bf_39.as_ref().or(case.raeva_39.as_ref()))
            .unwrap_or(&maven_310.expect("a 3.10 result").1);
        let maven_39 = &(case.expect.iter())
            .find(|(mode, _)| *mode == MavenMode::Maven39)
            .expect("a 3.9 result")
            .1;
        if let Some(raeva_39) = &case.raeva_39 {
            // A deviation that has become Maven's result is stale.
            assert_ne!(raeva_39, maven_39, "{}", case.name);
        }
        let df_310 = case.df_310.as_ref().unwrap_or(maven_39);
        let runs = (case.expect.iter())
            .map(|(mode, expected)| (*mode, *mode == MavenMode::Maven310, expected))
            .chain([
                (MavenMode::Maven39, true, bf_39),
                (MavenMode::Maven310, false, df_310),
            ]);
        for (mode, breadth_first, expected) in runs {
            let overflows = expected == "ERR java.lang.StackOverflowError";
            let expected = match &case.raeva_39 {
                Some(raeva_39) if mode == MavenMode::Maven39 && (!breadth_first || overflows) => {
                    raeva_39
                }
                _ => expected,
            };
            // Maven 3.9 overflows its stack; raeva keeps the node, which
            // the case's `raeva 3.9` line records.
            assert_ne!(
                expected, "ERR java.lang.StackOverflowError",
                "{}: no raeva 3.9 result",
                case.name
            );
            let projects: Vec<&str> = case.projects.iter().map(String::as_str).collect();
            let backend = MockBackend {
                mode,
                ..backend(&projects)
            };
            let solved = Solver::new(&backend)
                .with_management(management(&case.manage))
                .breadth_first(breadth_first)
                .solve(root(&case.root))
                .await;
            // Maven lists a system dependency without its path.
            let actual = (render(solved).split(' '))
                .map(|label| label.split_once('=').map_or(label, |(label, _)| label))
                .collect::<Vec<_>>()
                .join(" ");
            let matches = match expected.strip_prefix("ERR ") {
                Some(message) => actual.starts_with(&format!("ERR {}:", error_kind(message))),
                None => actual == *expected,
            };
            if !matches {
                let bf = match (mode, breadth_first) {
                    (MavenMode::Maven39, true) => " bf",
                    (MavenMode::Maven310, false) => " df",
                    _ => "",
                };
                failures.push(format!(
                    "{} in {mode}{bf}: got {actual}, expected {expected}",
                    case.name
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Depth first, Maven 3.9.12 keeps both of a range's equal versions 1 and
/// 1.0, and the first listed wins. Breadth first, Maven keeps one of them,
/// and which one's descriptor is a race between its parallel reads.
#[tokio::test]
async fn maven_39_keeps_equal_versions_of_a_range() {
    let backend = backend(&[
        "z:1 > x:1",
        "r:1 > y:1",
        "r:1.0 > y:2",
        "versions r 1 1.0",
        "x:1",
        "y:1",
        "y:2",
    ]);
    let solved = Solver::new(&backend).solve(root("z:1 r:[1,2]")).await;
    assert_eq!(render(solved), "r:1 x:1 y:1 z:1");
}

/// What the 3.10 collector keeps from Maven beyond the graphs of cases.txt.
#[tokio::test]
async fn maven_310_rules() {
    #[rustfmt::skip]
    let cases: &[(&str, &[&str], &str, &str)] = &[
        ("a test root keeps test scope", &["a:1 > b:1", "b:1"], "@test a:1", "a:1@test b:1@test"),
        ("a relocation to an artifact id with a slash fails",
            &["a:1 => g:x/y:1", "x/y:1"], "a:1",
            "ERR Pom: pom error: invalid model: invalid relocation artifactId \"x/y\" in the POM of g:a:1: not a valid artifact coordinate component"),
        ("a fatjar is a jar that carries its dependencies", &["a:1 > b:1", "b:1"], "a:1#fatjar",
            "a:1"),
        ("and shares the jar's conflict group", &["a:1 > b:1", "b:1", "a:2"], "a:2 a:1#fatjar",
            "a:2"),
        ("a relocation to `..` fails", &["a:1 => ..:_:_"], "a:1",
            "ERR Pom: pom error: invalid model: invalid relocation groupId \"..\" in the POM of g:a:1: not a valid artifact coordinate component"),
    ];
    for (name, projects, root_deps, expected) in cases {
        let backend = MockBackend {
            mode: MavenMode::Maven310,
            ..backend(projects)
        };
        let actual = render(Solver::new(&backend).solve(root(root_deps)).await);
        assert_eq!(actual, *expected, "{name}");
    }
}

/// Where the 3.10 collector reads once for several declarations, each
/// winner keeps its own path and its own file.
#[tokio::test]
async fn maven_310_shared_reads() {
    let solve = |projects: &[&str], root_deps: &str| {
        let backend = MockBackend {
            mode: MavenMode::Maven310,
            ..backend(projects)
        };
        let root = root(root_deps);
        async move { Solver::new(&backend).solve(root).await }
    };
    let named = |graph: &Graph, artifact: &str| {
        (graph.node_indices())
            .find(|&idx| graph.node(idx).unwrap().coord.artifact_id.as_str() == artifact)
            .unwrap()
    };

    // m:1 below b:1 shares the children read below a:1, which loses.
    let pooled = [
        "a:1 > m:1",
        "b:1 > m:1",
        "d:1 > a:[2,2]",
        "a:2",
        "m:1 > x:1",
    ];
    let graph = solve(&[&pooled[..], &["x:1"]].concat(), "a:1 b:1 d:1")
        .await
        .unwrap();
    let (x, m) = (named(&graph, "x"), named(&graph, "m"));
    assert_eq!(graph.node(x).unwrap().winner_parent, Some(m));
    assert_eq!(graph.declared_via(x), ["g:b:1", "g:m:1"]);
    let missing = solve(&pooled, "a:1 b:1 d:1").await.unwrap_err();
    let ResolveError::Declared { via, .. } = missing else {
        panic!("{missing:?}");
    };
    assert_eq!(via, ["g:b:1", "g:m:1"]);

    // The system x:1 asks first; the winner still has its file.
    let projects = [
        "a:1 > x:1@system=/s.jar",
        "b:1 > x:1",
        "d:1 > a:[2,2]",
        "a:2",
        "x:1 > y:1",
        "y:1",
    ];
    let graph = solve(&projects, "a:1 b:1 d:1").await.unwrap();
    let x = graph.node(named(&graph, "x")).unwrap();
    assert!(!x.local);
    assert_eq!(x.repo_url.as_deref(), Some("mock://repo"));

    // A system x:1 that takes another's read still needs its path.
    let projects = [
        "b:1 > x:1",
        "a:1 > x:1@system",
        "d:1 > b:[2,2]",
        "b:2",
        "x:1",
    ];
    let failed = render(solve(&projects, "b:1 a:1 d:1").await);
    assert!(
        failed.contains("requires a non-empty <systemPath>"),
        "{failed}"
    );

    // The x:1 below b:1 takes the system x:1's read, so Maven reads no POM
    // for it, and raeva's read of it for its file fails no build. The
    // depth-first collector reads it.
    let graph = solve(&["b:1 > x:1"], "x:1@system=/s.jar b:1").await;
    assert_eq!(render(graph), "b:1 x:1@system=/s.jar+local");
    let df = MockBackend {
        mode: MavenMode::Maven39,
        ..backend(&["b:1 > x:1"])
    };
    let graph = Solver::new(&df).solve(root("x:1@system=/s.jar b:1")).await;
    assert_eq!(
        render(graph),
        "ERR ArtifactNotFound: artifact not found: g:x:1"
    );

    // The x:1 below a:1 asks after the range read x:1, and takes that read.
    let seeded = MockBackend {
        mode: MavenMode::Maven310,
        ..backend(&["a:1 > x:1", "x:1", "x:2"])
    };
    let graph = Solver::new(&seeded).solve(root("x:[1,2] a:1")).await;
    assert_eq!(render(graph), "a:1 x:2");
    let fetches = seeded.fetches.lock().unwrap();
    assert_eq!(*fetches, ["g:x:2", "g:x:1", "g:a:1"]);
}

/// Both modes read `compile-only` as a scope of its own, so no graph of
/// cases.txt warns about it.
#[test]
fn no_mode_warns_about_compile_only() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for case in cases().iter().filter(|case| case.name.starts_with("co-")) {
        for mode in [MavenMode::Maven39, MavenMode::Maven310] {
            let projects: Vec<&str> = case.projects.iter().map(String::as_str).collect();
            let backend = MockBackend {
                mode,
                ..backend(&projects)
            };
            let log = rv_test_support::capture_warnings(|| {
                let solver = Solver::new(&backend).with_management(management(&case.manage));
                runtime.block_on(solver.solve(root(&case.root))).unwrap();
            });
            assert!(
                !log.contains("unknown dependency scope"),
                "{} in {mode}",
                case.name
            );
        }
    }
}
