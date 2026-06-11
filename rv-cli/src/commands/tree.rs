use std::collections::HashSet;
use std::path::Path;

use clap::Args;
use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Serialize;

use rv_config::{Config, LockPlatform};
use rv_maven_model::Scope;

use crate::error::{CliError, Result};
use crate::output::{Table, is_json_mode, json_result};

#[derive(Debug, Args)]
#[command(
    about = "Show the dependency tree from rv.lock",
    after_long_help = "\
Examples:
  rv tree                          # Show full dependency tree
  rv tree --scope compile          # Show only compile-scoped dependencies
  rv tree --depth 2                # Limit tree depth to 2 levels
  rv --json tree                   # Output as JSON
  rv tree --scope test --depth 3   # Test deps, max 3 levels deep
"
)]
pub struct TreeArgs {
    #[arg(
        long,
        value_name = "SCOPE",
        value_parser = crate::commands::parse_scope,
        help = "Filter tree by scope (compile, runtime, test, provided, system, import)"
    )]
    pub scope: Option<Scope>,
    #[arg(
        short = 'd',
        long,
        value_name = "N",
        help = "Limit tree depth (default: unlimited)"
    )]
    pub depth: Option<usize>,
}

#[derive(Debug, Serialize)]
struct TreeNode {
    coordinate: String,
    scope: String,
    optional: bool,
    children: Vec<TreeNode>,
}

#[derive(Debug, Serialize)]
struct TreeOutput {
    project: String,
    platform: String,
    dependencies: Vec<TreeNode>,
}

pub fn run(args: &TreeArgs, project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;
    let lock = crate::commands::read_lockfile(&config)?;
    let platform = crate::commands::select_platform(&lock)?;

    if is_json_mode() {
        let output = build_json_tree(platform, args.scope, args.depth, project_root)?;
        json_result(true, serde_json::to_value(&output)?);
    } else {
        match render_tree(platform, args.scope, args.depth, project_root)? {
            TreeRender::Table(table) => println!("{}", table.render()),
            TreeRender::Empty(message) => println!("{message}"),
        }
    }
    Ok(())
}

/// Shared data structure representing the dependency graph
struct TreeData {
    coords: Vec<String>,
    /// Adjacency-list view over `graph`: for each node index `n`,
    /// `children[n]` is the sorted list of outgoing `EdgeInfo`s. Kept
    /// alongside the petgraph so the recursive printers stay readable
    /// and we don't pay the per-step `edges_directed` cost on every
    /// node visit.
    children: Vec<Vec<EdgeInfo>>,
    roots: Vec<usize>,
    /// Per-node scope/optional cached from the first incoming edge. Computed
    /// once during graph construction so that tree-rendering doesn't redo
    /// an O(N*E) scan for every visited node.
    node_scope: Vec<(Scope, bool)>,
}

/// Build the dependency graph data structure from the platform
fn build_dep_tree_data(platform: &LockPlatform, scope_filter: Option<Scope>) -> Result<TreeData> {
    let count = platform.packages.len();
    let coords: Vec<String> = platform
        .packages
        .iter()
        .map(|pkg| pkg.format_coord())
        .collect();

    let mut graph: DiGraph<usize, EdgeInfo> = DiGraph::with_capacity(count, platform.edges.len());
    let nodes: Vec<NodeIndex> = (0..count).map(|i| graph.add_node(i)).collect();
    // Pre-compute the per-node (scope, optional) from the first incoming edge
    // we encounter. Without it, build_json_node/render_node would re-scan
    // every edge in the whole graph for every node, O(N*E) overall.
    let mut node_scope: Vec<(Scope, bool)> = vec![(Scope::Compile, false); count];
    let mut node_scope_set = vec![false; count];

    for edge in &platform.edges {
        if edge.from >= count || edge.to >= count {
            return Err(CliError::Message(format!(
                "lockfile edge out of bounds: {} -> {}",
                edge.from, edge.to
            )));
        }
        let edge_scope = parse_edge_scope(edge.scope.as_deref())?;
        if let Some(filter) = scope_filter
            && !scope_includes(filter, edge_scope)
        {
            continue;
        }
        graph.add_edge(
            nodes[edge.from],
            nodes[edge.to],
            EdgeInfo {
                to: edge.to,
                scope: edge_scope,
                optional: edge.optional,
            },
        );
        if !node_scope_set[edge.to] {
            node_scope[edge.to] = (edge_scope, edge.optional);
            node_scope_set[edge.to] = true;
        }
    }

    let mut children: Vec<Vec<EdgeInfo>> = (0..count)
        .map(|i| {
            let mut out: Vec<EdgeInfo> = graph
                .edges_directed(nodes[i], Direction::Outgoing)
                .map(|e| e.weight().clone())
                .collect();
            out.sort_by(|a, b| coords[a.to].cmp(&coords[b.to]));
            out
        })
        .collect();
    // Suppress the unused-mut lint in cfgs where the loop above produces an
    // empty Vec; the binding is still mutated unconditionally on the common
    // path. (No-op for current builds.)
    let _ = &mut children;

    let mut roots: Vec<usize> = graph
        .externals(Direction::Incoming)
        .map(|n| n.index())
        .collect();
    if roots.is_empty() {
        roots = (0..count).collect();
    }

    // Root packages have zero incoming edges, so the per-edge
    // scope_filter check above never gates them. Apply the filter to
    // root packages using their stamped `direct_scope` instead: that's
    // the scope the resolver recorded on the root dependency itself.
    // Otherwise `rv tree --scope compile` would still show a package
    // whose only declaration was test-scope.
    if let Some(filter) = scope_filter {
        roots.retain(
            |idx| match platform.packages[*idx].direct_scope.as_deref() {
                Some(scope_str) => scope_str
                    .parse::<Scope>()
                    .map(|scope| scope_includes(filter, scope))
                    .unwrap_or(true),
                // No recorded direct scope: assume `compile` (the resolver
                // default), matching how edges without a stamped scope are
                // treated above.
                None => scope_includes(filter, Scope::Compile),
            },
        );
    }

    roots.sort_by(|a, b| coords[*a].cmp(&coords[*b]));

    Ok(TreeData {
        coords,
        children,
        roots,
        node_scope,
    })
}

fn build_json_tree(
    platform: &LockPlatform,
    scope_filter: Option<Scope>,
    max_depth: Option<usize>,
    project_root: &Path,
) -> Result<TreeOutput> {
    let tree_data = build_dep_tree_data(platform, scope_filter)?;

    let project = project_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("root")
        .to_string();

    let mut dependencies = Vec::new();
    let mut visited: HashSet<usize> = HashSet::new();
    for root in tree_data.roots {
        dependencies.push(build_json_node(
            root,
            &tree_data.children,
            &tree_data.coords,
            &tree_data.node_scope,
            &mut visited,
            0,
            max_depth,
        ));
    }

    Ok(TreeOutput {
        project,
        platform: platform.platform.to_string(),
        dependencies,
    })
}

fn build_json_node(
    node: usize,
    edges: &[Vec<EdgeInfo>],
    coords: &[String],
    node_scope: &[(Scope, bool)],
    visited: &mut HashSet<usize>,
    current_depth: usize,
    max_depth: Option<usize>,
) -> TreeNode {
    let (scope, optional) = node_scope
        .get(node)
        .copied()
        .unwrap_or((Scope::Compile, false));

    let depth_exceeded = max_depth.is_some_and(|max| current_depth >= max);

    let children = if depth_exceeded {
        Vec::new()
    } else {
        visited.insert(node);
        // Skip edges that would re-enter a node already on the path.
        // Without this guard, a self-loop edge or a back-edge in the
        // graph would emit the cycled node as a phantom child with
        // empty grandchildren, leaving JSON consumers with a node
        // that looks like a real terminal dependency. Collect the
        // non-cycle child indices first so the closure does not
        // straddle a mutable borrow on `visited`.
        let live_children: Vec<usize> = edges[node]
            .iter()
            .filter(|edge| !visited.contains(&edge.to))
            .map(|edge| edge.to)
            .collect();
        let result: Vec<TreeNode> = live_children
            .into_iter()
            .map(|child| {
                build_json_node(
                    child,
                    edges,
                    coords,
                    node_scope,
                    visited,
                    current_depth + 1,
                    max_depth,
                )
            })
            .collect();
        visited.remove(&node);
        result
    };

    TreeNode {
        coordinate: coords[node].clone(),
        scope: scope.to_string(),
        optional,
        children,
    }
}

/// Render outcome: either a populated table or a "nothing to show" notice
/// that the caller should print verbatim instead of an empty table.
enum TreeRender {
    Table(Table),
    Empty(String),
}

fn render_tree(
    platform: &LockPlatform,
    scope_filter: Option<Scope>,
    max_depth: Option<usize>,
    project_root: &Path,
) -> Result<TreeRender> {
    let tree_data = build_dep_tree_data(platform, scope_filter)?;

    // An empty lockfile (or one whose entries were all filtered out by
    // `--scope`) would otherwise render as a single-row table with the
    // project directory name and no children, visually indistinguishable
    // from a tree that has exactly one root dependency named after the
    // project. Surface a clear "nothing here" line instead.
    if tree_data.roots.is_empty() {
        return Ok(TreeRender::Empty(format!(
            "No dependencies in rv.lock for platform {}",
            platform.platform
        )));
    }

    let root_label = project_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("root");

    let mut table = Table::new(["Dependency", "Scope", "Optional"]);
    table.add_row([root_label, "", ""]);

    let mut path: HashSet<usize> = HashSet::new();
    for (idx, root) in tree_data.roots.iter().enumerate() {
        let is_last = idx + 1 == tree_data.roots.len();
        render_node(
            *root,
            "",
            is_last,
            &tree_data.children,
            &tree_data.coords,
            &mut path,
            &mut table,
            None,
            0,
            max_depth,
        );
    }

    Ok(TreeRender::Table(table))
}

#[allow(clippy::too_many_arguments)]
fn render_node(
    node: usize,
    prefix: &str,
    is_last: bool,
    edges: &[Vec<EdgeInfo>],
    coords: &[String],
    path: &mut HashSet<usize>,
    table: &mut Table,
    edge_info: Option<&EdgeInfo>,
    current_depth: usize,
    max_depth: Option<usize>,
) {
    let connector = if is_last { "└──" } else { "├──" };
    let mut label = format!("{}{} {}", prefix, connector, coords[node]);
    let cycle = path.contains(&node);
    if cycle {
        label.push_str(" (cycle)");
    }
    let scope = edge_info
        .map(|edge| edge.scope.to_string())
        .unwrap_or_default();
    let mut optional = edge_info
        .map(|edge| if edge.optional { "optional" } else { "" })
        .unwrap_or("")
        .to_string();
    if cycle && optional.is_empty() {
        optional = "cycle".to_string();
    }
    table.add_row([label, scope, optional]);

    if cycle {
        return;
    }

    // Check if we've reached the depth limit
    let depth_exceeded = max_depth.is_some_and(|max| current_depth >= max);
    if depth_exceeded {
        let child_count = edges[node].len();
        if child_count > 0 {
            let next_prefix = if is_last {
                format!("{prefix}    ")
            } else {
                format!("{prefix}│   ")
            };
            let truncate_label = format!("{next_prefix}... ({child_count} more)");
            table.add_row([truncate_label, String::new(), String::new()]);
        }
        return;
    }

    let next_prefix = if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };

    path.insert(node);
    for (idx, edge) in edges[node].iter().enumerate() {
        let is_last = idx + 1 == edges[node].len();
        render_node(
            edge.to,
            &next_prefix,
            is_last,
            edges,
            coords,
            path,
            table,
            Some(edge),
            current_depth + 1,
            max_depth,
        );
    }
    path.remove(&node);
}

fn parse_edge_scope(value: Option<&str>) -> Result<Scope> {
    match value {
        Some(scope) => scope.parse::<Scope>().map_err(|_| CliError::InvalidScope {
            value: scope.to_string(),
        }),
        None => Ok(Scope::Compile),
    }
}

fn scope_includes(target: Scope, dependency: Scope) -> bool {
    match target {
        Scope::Compile => matches!(dependency, Scope::Compile | Scope::Provided | Scope::System),
        Scope::Runtime => matches!(dependency, Scope::Compile | Scope::Runtime),
        Scope::Test => matches!(
            dependency,
            Scope::Compile | Scope::Runtime | Scope::Test | Scope::Provided | Scope::System
        ),
        Scope::Provided => matches!(dependency, Scope::Provided | Scope::System),
        Scope::System => dependency == Scope::System,
        Scope::Import => dependency == Scope::Import,
    }
}

#[derive(Debug, Clone)]
struct EdgeInfo {
    to: usize,
    scope: Scope,
    optional: bool,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use rv_config::{LockEdge, LockPackage, LockPlatform, Platform};

    use super::{TreeRender, build_dep_tree_data, build_json_tree, render_tree};

    fn mk_pkg(idx: usize) -> LockPackage {
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: format!("a{idx}"),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo".to_string(),
            checksum: Some(rv_config::Checksum::new("sha256", "deadbeef")),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn coord_format_includes_classifier() {
        let pkg = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: Some("tests".to_string()),
            repo_url: "https://repo".to_string(),
            checksum: Some(rv_config::Checksum::new("sha256", "deadbeef")),
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        };
        assert!(pkg.format_coord().contains("tests"));
    }

    #[test]
    fn build_dep_tree_data_precomputes_node_scope() {
        let packages = (0..3).map(mk_pkg).collect::<Vec<_>>();
        let edges = vec![
            LockEdge {
                from: 0,
                to: 1,
                scope: Some("compile".to_string()),
                optional: false,
                extra: std::collections::BTreeMap::new(),
            },
            LockEdge {
                from: 1,
                to: 2,
                scope: Some("runtime".to_string()),
                optional: true,
                extra: std::collections::BTreeMap::new(),
            },
        ];
        let platform = LockPlatform {
            platform: Platform::new("linux", "x86_64").expect("platform"),
            packages,
            edges,
            extra: std::collections::BTreeMap::new(),
        };
        let data = build_dep_tree_data(&platform, None).expect("build");
        // node 2 picks up the runtime/optional from its incoming edge.
        assert_eq!(data.node_scope[2].0.to_string(), "runtime");
        assert!(data.node_scope[2].1);
        // node 1 picks up compile/non-optional.
        assert_eq!(data.node_scope[1].0.to_string(), "compile");
        assert!(!data.node_scope[1].1);
    }

    #[test]
    fn render_tree_empty_lockfile_returns_explicit_message() {
        let platform = LockPlatform {
            platform: Platform::new("linux", "x86_64").expect("platform"),
            packages: Vec::new(),
            edges: Vec::new(),
            extra: std::collections::BTreeMap::new(),
        };
        let project_root = std::path::PathBuf::from("/tmp/some-project");
        match render_tree(&platform, None, None, &project_root).expect("render") {
            TreeRender::Empty(msg) => {
                assert!(
                    msg.contains("No dependencies in rv.lock"),
                    "unexpected message: {msg}"
                );
                assert!(
                    msg.contains("linux-x86_64"),
                    "platform should appear in message: {msg}"
                );
            }
            TreeRender::Table(_) => panic!("empty lockfile should not render a table"),
        }
    }

    /// Regression: a 500-node deep chain used to take >1s due to O(N*E) scans
    /// in build_json_node / render_node. With the per-node scope cache and
    /// HashSet visited check, the whole render finishes in well under 100ms.
    #[test]
    fn build_json_tree_500_nodes_under_100ms() {
        let count = 500;
        let packages: Vec<LockPackage> = (0..count).map(mk_pkg).collect();
        // chain: 0 -> 1 -> 2 -> ... -> 499
        let edges: Vec<LockEdge> = (0..count - 1)
            .map(|i| LockEdge {
                from: i,
                to: i + 1,
                scope: Some("compile".to_string()),
                optional: false,
                extra: std::collections::BTreeMap::new(),
            })
            .collect();
        let platform = LockPlatform {
            platform: Platform::new("linux", "x86_64").expect("platform"),
            packages,
            edges,
            extra: std::collections::BTreeMap::new(),
        };
        let project_root = std::path::PathBuf::from("/tmp/dummy");
        let started = Instant::now();
        let out = build_json_tree(&platform, None, None, &project_root).expect("build");
        let elapsed = started.elapsed();
        assert_eq!(out.dependencies.len(), 1);
        assert!(
            elapsed < Duration::from_millis(100),
            "500-node tree took {elapsed:?}, expected < 100ms"
        );
    }
}
