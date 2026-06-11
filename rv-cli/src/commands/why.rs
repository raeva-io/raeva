//! Dependency explanation command.
//!
//! Explains why a particular dependency exists in the lockfile by showing
//! all dependency paths that lead to it.

use std::path::Path;

use clap::Args;
use petgraph::Direction;
use petgraph::algo::all_simple_paths;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Serialize;

use rv_config::{Config, LockPlatform};
use rv_version::PartialCoord;

use crate::error::{CliError, Result};
use crate::output::{Table, heading, is_json_mode, json_result, quiet_enabled};

/// Upper bound on dependency-path depth searched by `all_simple_paths`.
/// Real-world Maven graphs cap out well below this (Spring Boot's
/// transitive chain sits around 20-25 levels); 64 is a generous
/// ceiling that still guarantees termination on a pathological lockfile.
const MAX_DEP_PATH_DEPTH: usize = 64;

/// Upper bound on the number of dependency paths emitted by `why`.
///
/// `all_simple_paths` enumerates *every* distinct root→target path, which is
/// combinatorial: a densely connected lockfile (e.g. one where many roots
/// reach the target through overlapping diamonds) can produce thousands of
/// near-identical paths and blow up both memory and the rendered table. Cap
/// the collection at a sane ceiling and flag truncation so the output stays
/// useful without enumerating the whole combinatorial set.
const MAX_DEP_PATHS: usize = 256;

#[derive(Debug, Args)]
#[command(about = "Explain why a dependency exists in rv.lock")]
pub struct WhyArgs {
    #[arg(
        value_name = "COORD",
        value_parser = parse_coord,
        help = "Dependency coordinate (artifact, group:artifact, or group:artifact:version)"
    )]
    pub coord: PartialCoord,
}

/// Parse the `<COORD>` argument at the clap layer.
///
/// Routing the parse through a clap `value_parser` (rather than parsing inside
/// `run`) means a malformed coordinate is rejected as a *usage* error: clap
/// prints the usage hint and exits 2, the conventional code for bad arguments.
/// This keeps the two failure cases distinct. An unparseable argument exits 2,
/// while a parseable-but-absent coordinate stays exit 0 (`found: false`).
/// Parsing inside `run` instead would surface a `VersionError` as
/// `RESOLUTION_ERROR` (5), indistinguishable from a valid-but-absent
/// coordinate that legitimately exits 0.
fn parse_coord(value: &str) -> std::result::Result<PartialCoord, String> {
    PartialCoord::parse(value).map_err(|err| err.to_string())
}

#[derive(Debug, Serialize)]
struct WhyOutput {
    target: String,
    platform: String,
    found: bool,
    /// `true` when path enumeration hit [`MAX_DEP_PATHS`] and stopped early,
    /// so `paths` is a (still useful) prefix of the full set rather than the
    /// complete enumeration.
    truncated: bool,
    paths: Vec<Vec<String>>,
}

pub fn run(args: &WhyArgs, project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;
    let lock = crate::commands::read_lockfile(&config)?;
    let platform = crate::commands::select_platform(&lock)?;
    // `coord` is already a validated `PartialCoord` (clap rejected malformed
    // arguments at parse time with usage exit 2).
    let target = &args.coord;

    let (graph, roots) = build_graph(platform)?;
    let targets = find_targets(platform, target);

    let (paths, truncated) = collect_paths(&graph, &roots, &targets);

    if is_json_mode() {
        let output = WhyOutput {
            target: target.to_string(),
            platform: platform.platform.to_string(),
            found: !paths.is_empty(),
            truncated,
            paths: paths
                .iter()
                .map(|path| {
                    path.iter()
                        .map(|idx| platform.packages[*idx].format_coord())
                        .collect()
                })
                .collect(),
        };
        json_result(true, serde_json::to_value(&output)?);
        return Ok(());
    }

    if targets.is_empty() || paths.is_empty() {
        // A coordinate that is not in the lockfile is a legitimate query
        // result, not a failure. Emit a human-readable line on stdout and
        // exit 0 so the JSON (`found: false`) and text modes converge.
        println!("no path found for {target} (not a dependency in rv.lock)");
        return Ok(());
    }

    // Heading is decorative chatter -> stderr, gated on --quiet.
    // The path table itself is the structured result and stays on
    // stdout.
    if !quiet_enabled() {
        eprintln!("{}", heading(format!("why {}", target)));
    }
    let mut table = Table::new(["#", "Path"]);
    for (idx, path) in paths.iter().enumerate() {
        let parts: Vec<String> = path
            .iter()
            .map(|idx| platform.packages[*idx].format_coord())
            .collect();
        table.add_row([format!("{}", idx + 1), parts.join(" -> ")]);
    }
    println!("{}", table.render());

    // Make truncation visible in human mode too: without this note the user
    // would read the capped table as the complete set of paths.
    if truncated {
        println!(
            "(showing first {MAX_DEP_PATHS} paths; more exist; narrow the query with a fuller coordinate)"
        );
    }

    Ok(())
}

/// Enumerate root→target dependency paths, capped at [`MAX_DEP_PATHS`].
///
/// Returns the collected paths (as node-index lists) and a `truncated` flag
/// that is `true` when the cap was reached and enumeration stopped early.
/// The cap is required: `all_simple_paths` is combinatorial and a dense
/// lockfile can otherwise produce an unbounded explosion of near-duplicate
/// paths.
fn collect_paths(
    graph: &DiGraph<usize, ()>,
    roots: &[NodeIndex],
    targets: &[usize],
) -> (Vec<Vec<usize>>, bool) {
    let mut paths: Vec<Vec<usize>> = Vec::new();
    for target_idx in targets {
        let target_node = NodeIndex::new(*target_idx);
        for root in roots {
            // `all_simple_paths` returns no path when source == target
            // (a singleton is not a "path" in the algorithm's sense),
            // but for `why` the target being a root IS a legitimate
            // finding, so emit it as a length-1 path.
            if *root == target_node {
                if paths.len() >= MAX_DEP_PATHS {
                    return (paths, true);
                }
                paths.push(vec![*target_idx]);
                continue;
            }
            for path in all_simple_paths::<Vec<NodeIndex>, _, std::hash::RandomState>(
                graph,
                *root,
                target_node,
                0,
                Some(MAX_DEP_PATH_DEPTH),
            ) {
                if paths.len() >= MAX_DEP_PATHS {
                    return (paths, true);
                }
                paths.push(path.into_iter().map(|n| n.index()).collect());
            }
        }
    }
    (paths, false)
}

fn build_graph(platform: &LockPlatform) -> Result<(DiGraph<usize, ()>, Vec<NodeIndex>)> {
    let count = platform.packages.len();
    let mut graph: DiGraph<usize, ()> = DiGraph::with_capacity(count, platform.edges.len());
    let nodes: Vec<NodeIndex> = (0..count).map(|i| graph.add_node(i)).collect();

    for edge in &platform.edges {
        if edge.from >= count || edge.to >= count {
            return Err(CliError::Message(format!(
                "lockfile edge out of bounds: {} -> {}",
                edge.from, edge.to
            )));
        }
        graph.add_edge(nodes[edge.from], nodes[edge.to], ());
    }

    let mut roots: Vec<NodeIndex> = graph.externals(Direction::Incoming).collect();
    if roots.is_empty() {
        roots = nodes;
    }
    roots.sort_by_key(|n| n.index());
    Ok((graph, roots))
}

fn find_targets(platform: &LockPlatform, target: &PartialCoord) -> Vec<usize> {
    let mut matches = Vec::new();
    for (idx, package) in platform.packages.iter().enumerate() {
        if matches_target(package, target) {
            matches.push(idx);
        }
    }
    matches
}

fn matches_target(package: &rv_config::LockPackage, target: &PartialCoord) -> bool {
    // Group ID is optional: if not specified (artifact-only search), match any group
    if let Some(ref group_id) = target.group_id
        && package.group_id != group_id.as_str()
    {
        return false;
    }
    // Artifact ID must always match
    if package.artifact_id != target.artifact_id.as_str() {
        return false;
    }
    // Version is optional: if not specified, match any version
    if let Some(ref version) = target.version
        && package.version != version.to_string()
    {
        return false;
    }
    if let Some(ref packaging) = target.packaging
        && package.packaging != *packaging
    {
        return false;
    }
    if let Some(ref classifier) = target.classifier
        && package.classifier.as_deref() != Some(classifier.as_str())
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{MAX_DEP_PATHS, collect_paths, matches_target, parse_coord};
    use petgraph::graph::{DiGraph, NodeIndex};
    use rv_config::{Checksum, LockPackage};
    use rv_version::PartialCoord;

    fn test_package() -> LockPackage {
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo".to_string(),
            checksum: Some(Checksum::new("sha256", "deadbeef")),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn target_matching_respects_packaging() {
        let pkg = test_package();
        let coord = PartialCoord::parse("com.example:demo:1.0").unwrap();
        assert!(matches_target(&pkg, &coord));
    }

    #[test]
    fn target_matching_without_version() {
        let pkg = test_package();
        // Should match without version specified
        let coord = PartialCoord::parse("com.example:demo").unwrap();
        assert!(matches_target(&pkg, &coord));
    }

    #[test]
    fn target_matching_wrong_version() {
        let pkg = test_package();
        // Should not match wrong version
        let coord = PartialCoord::parse("com.example:demo:2.0").unwrap();
        assert!(!matches_target(&pkg, &coord));
    }

    #[test]
    fn target_matching_wrong_artifact() {
        let pkg = test_package();
        // Should not match wrong artifact
        let coord = PartialCoord::parse("com.example:other").unwrap();
        assert!(!matches_target(&pkg, &coord));
    }

    #[test]
    fn target_matching_artifact_only() {
        let pkg = test_package();
        // Should match artifact-only search (no group specified)
        let coord = PartialCoord::parse("demo").unwrap();
        assert!(matches_target(&pkg, &coord));
    }

    #[test]
    fn target_matching_artifact_only_wrong_artifact() {
        let pkg = test_package();
        // Should not match artifact-only search with wrong artifact name
        let coord = PartialCoord::parse("other").unwrap();
        assert!(!matches_target(&pkg, &coord));
    }

    /// A malformed coordinate argument must be rejected by the clap
    /// `value_parser` (which yields usage exit 2) rather than parsing inside
    /// `run` and surfacing as a resolution error. A trailing-empty/oversized
    /// coordinate is unparseable.
    #[test]
    fn parse_coord_rejects_malformed_argument() {
        // Empty and >5-segment coordinates are unparseable per PartialCoord.
        assert!(parse_coord("").is_err());
        assert!(parse_coord("a:b:c:d:e:f").is_err());
        // A valid coordinate parses cleanly.
        assert!(parse_coord("com.example:demo:1.0").is_ok());
    }

    /// Path enumeration must stop at `MAX_DEP_PATHS` and report
    /// truncation. Build a "fan" graph: a single shared root that reaches the
    /// target through many disjoint intermediate nodes, producing far more
    /// simple paths than the cap.
    #[test]
    fn collect_paths_caps_at_limit_and_flags_truncation() {
        // Layout: node 0 = root, node 1 = target, and `fan` intermediate
        // nodes each forming a distinct 0 -> i -> 1 path. With more
        // intermediates than the cap, enumeration must truncate.
        let fan = MAX_DEP_PATHS + 50;
        let mut graph: DiGraph<usize, ()> = DiGraph::new();
        let root = graph.add_node(0);
        let target = graph.add_node(1);
        for _ in 0..fan {
            let mid = graph.add_node(2);
            graph.add_edge(root, mid, ());
            graph.add_edge(mid, target, ());
        }
        let roots = vec![root];
        let targets = vec![target.index()];

        let (paths, truncated) = collect_paths(&graph, &roots, &targets);
        assert!(truncated, "dense fan must trigger truncation");
        assert_eq!(
            paths.len(),
            MAX_DEP_PATHS,
            "collected paths must be capped at MAX_DEP_PATHS"
        );
    }

    /// A small graph below the cap returns every path with `truncated=false`.
    #[test]
    fn collect_paths_below_cap_is_not_truncated() {
        // 0 -> 1 -> 2 (single path to target node 2).
        let mut graph: DiGraph<usize, ()> = DiGraph::new();
        let n0 = graph.add_node(0);
        let n1 = graph.add_node(1);
        let n2 = graph.add_node(2);
        graph.add_edge(n0, n1, ());
        graph.add_edge(n1, n2, ());

        let roots = vec![n0];
        let targets = vec![n2.index()];
        let (paths, truncated) = collect_paths(&graph, &roots, &targets);
        assert!(!truncated, "single path must not be truncated");
        assert_eq!(paths, vec![vec![0usize, 1, 2]]);
    }

    /// A target that is itself a root is emitted as a length-1 path and is
    /// still subject to the cap accounting (regression guard for the
    /// `root == target` branch).
    #[test]
    fn collect_paths_target_is_root_emits_singleton() {
        let mut graph: DiGraph<usize, ()> = DiGraph::new();
        let n0 = graph.add_node(0);
        let roots = vec![n0];
        let targets = vec![n0.index()];
        let (paths, truncated) = collect_paths(&graph, &roots, &targets);
        assert!(!truncated);
        assert_eq!(paths, vec![vec![0usize]]);
        // Keep NodeIndex import meaningful for readers of the test.
        let _ = NodeIndex::<u32>::new(0);
    }
}
