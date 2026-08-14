//! Dependency explanation command.

use std::path::Path;

use clap::Args;
use petgraph::algo::all_simple_paths;
use petgraph::graph::{DiGraph, NodeIndex};
use rv_config::{Config, LockModule, LockModulePackage};
use rv_version::PartialCoord;
use serde::Serialize;

use crate::commands::module_selector::{LockModuleExt, ModuleSelector};
use crate::error::{CliError, Result};
use crate::output::{Table, heading, is_json_mode, json_result, quiet_enabled};

const MAX_DEP_PATH_DEPTH: usize = 64;
const MAX_DEP_PATHS: usize = 256;

#[derive(Debug, Args)]
#[command(
    about = "Explain why a dependency exists in rv.lock",
    after_long_help = "\
Examples:
  rv why org.slf4j:slf4j-api
  rv why commons-logging
  rv why org.slf4j:slf4j-api --module app/pom.xml
  rv why org.slf4j:slf4j-api --module com.acme:app
"
)]
pub struct WhyArgs {
    #[arg(
        value_name = "COORD",
        value_parser = parse_coord,
        help = "Dependency coordinate (artifact, group:artifact, or group:artifact:version)"
    )]
    pub coord: PartialCoord,
    #[command(flatten)]
    module: ModuleSelector,
}

fn parse_coord(value: &str) -> std::result::Result<PartialCoord, String> {
    PartialCoord::parse(value).map_err(|err| err.to_string())
}

#[derive(Debug, Serialize)]
struct WhyModuleOutput {
    module: String,
    /// Always a `group:artifact:version` string, including for the synthetic
    /// root of a legacy-adapted lock, where it is rv's documented placeholder
    /// (`__legacy__:__root__:0`, see `schemas/rv-lock.json`). Keeping the raw
    /// value holds the field's type stable for machine consumers; `label`
    /// carries what the text renderer prints.
    gav: String,
    #[serde(skip)]
    label: String,
    found: bool,
    truncated: bool,
    paths: Vec<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct WhyOutput {
    target: String,
    platform: String,
    found: bool,
    truncated: bool,
    /// Retained for single-module JSON consumers. Aggregate callers read
    /// `modules`, which attributes each path to its module.
    paths: Vec<Vec<String>>,
    modules: Vec<WhyModuleOutput>,
}

pub fn run(args: &WhyArgs, project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;
    let lock = crate::commands::read_lockfile(&config)?;
    let platform = crate::commands::select_platform(&lock)?;
    let selection = args.module.select(platform)?;
    let mut modules = Vec::with_capacity(selection.modules().len());
    for module in selection.modules() {
        modules.push(explain_module(module, &args.coord)?);
    }

    let found = modules.iter().any(|module| module.found);
    let truncated = modules.iter().any(|module| module.truncated);
    if is_json_mode() {
        let paths = if modules.len() == 1 {
            modules[0].paths.clone()
        } else {
            Vec::new()
        };
        json_result(
            true,
            serde_json::to_value(WhyOutput {
                target: args.coord.to_string(),
                platform: platform.platform.to_string(),
                found,
                truncated,
                paths,
                modules,
            })?,
        );
        return Ok(());
    }

    if !quiet_enabled() {
        eprintln!("{}", heading(format!("why {}", args.coord)));
    }
    if !found {
        println!(
            "no path found for {} (not a dependency in the selected module graph(s))",
            args.coord
        );
        return Ok(());
    }

    let show_headers = selection.is_aggregate();
    let mut rendered_section = false;
    for module in &modules {
        if !module.found {
            continue;
        }
        if show_headers {
            if rendered_section {
                println!();
            }
            println!("Module: {}", module.label);
        }
        rendered_section = true;
        let mut table = Table::new(["#", "Path"]);
        for (index, path) in module.paths.iter().enumerate() {
            table.add_row([format!("{}", index + 1), path.join(" -> ")]);
        }
        println!("{}", table.render());
        if module.truncated {
            println!(
                "(showing first {MAX_DEP_PATHS} paths; more exist; narrow the query with a fuller coordinate)"
            );
        }
    }
    Ok(())
}

fn explain_module(module: &LockModule, target: &PartialCoord) -> Result<WhyModuleOutput> {
    let (graph, roots) = build_graph(module)?;
    let targets = find_targets(module, target);
    let (paths, truncated) = collect_paths(&graph, &roots, &targets);
    let paths = paths
        .iter()
        .map(|path| {
            path.iter()
                .map(|index| package_label(&module.packages[*index]))
                .collect()
        })
        .collect::<Vec<_>>();
    Ok(WhyModuleOutput {
        module: module.path.clone(),
        gav: module.gav(),
        label: module.display_label(),
        found: !paths.is_empty(),
        truncated,
        paths,
    })
}

fn package_label(package: &LockModulePackage) -> String {
    let coordinate = package.coordinate.format_coord();
    if package.workspace_module.is_some() {
        format!("{coordinate} (workspace)")
    } else if package.system_path.is_some() {
        format!("{coordinate} (system)")
    } else {
        coordinate
    }
}

fn collect_paths(
    graph: &DiGraph<usize, ()>,
    roots: &[NodeIndex],
    targets: &[usize],
) -> (Vec<Vec<usize>>, bool) {
    let mut paths = Vec::new();
    for target_index in targets {
        let target = NodeIndex::new(*target_index);
        for root in roots {
            if *root == target {
                if paths.len() >= MAX_DEP_PATHS {
                    return (paths, true);
                }
                paths.push(vec![*target_index]);
                continue;
            }
            for path in all_simple_paths::<Vec<NodeIndex>, _, std::hash::RandomState>(
                graph,
                *root,
                target,
                0,
                Some(MAX_DEP_PATH_DEPTH),
            ) {
                if paths.len() >= MAX_DEP_PATHS {
                    return (paths, true);
                }
                paths.push(path.into_iter().map(|node| node.index()).collect());
            }
        }
    }
    paths.sort();
    paths.dedup();
    (paths, false)
}

fn build_graph(module: &LockModule) -> Result<(DiGraph<usize, ()>, Vec<NodeIndex>)> {
    let count = module.packages.len();
    let mut graph = DiGraph::with_capacity(count, module.edges.len());
    let nodes = (0..count)
        .map(|index| graph.add_node(index))
        .collect::<Vec<_>>();
    let mut incoming = vec![0_usize; count];
    for edge in &module.edges {
        if edge.from >= count || edge.to >= count {
            return Err(CliError::Message(format!(
                "lockfile edge out of bounds in module '{}': {} -> {}",
                module.path, edge.from, edge.to
            )));
        }
        graph.add_edge(nodes[edge.from], nodes[edge.to], ());
        incoming[edge.to] = incoming[edge.to].saturating_add(1);
    }

    let has_direct_scope = module
        .packages
        .iter()
        .any(|package| package.direct_scope.is_some());
    let mut roots = if has_direct_scope {
        module
            .packages
            .iter()
            .enumerate()
            .filter(|(_, package)| package.direct_scope.is_some())
            .map(|(index, _)| nodes[index])
            .collect::<Vec<_>>()
    } else {
        incoming
            .iter()
            .enumerate()
            .filter(|(_, count)| **count == 0)
            .map(|(index, _)| nodes[index])
            .collect::<Vec<_>>()
    };
    if roots.is_empty() {
        roots = nodes;
    }
    roots.sort_by(|left, right| {
        module.packages[left.index()]
            .coordinate
            .cmp(&module.packages[right.index()].coordinate)
    });
    Ok((graph, roots))
}

fn find_targets(module: &LockModule, target: &PartialCoord) -> Vec<usize> {
    module
        .packages
        .iter()
        .enumerate()
        .filter(|(_, package)| matches_target(package, target))
        .map(|(index, _)| index)
        .collect()
}

fn matches_target(package: &LockModulePackage, target: &PartialCoord) -> bool {
    let coordinate = &package.coordinate;
    if let Some(group) = target.group_id.as_ref()
        && coordinate.group != group.as_str()
    {
        return false;
    }
    if coordinate.artifact != target.artifact_id.as_str() {
        return false;
    }
    if let Some(version) = target.version.as_ref()
        && coordinate.version != version.to_string()
    {
        return false;
    }
    if let Some(packaging) = target.packaging.as_ref()
        && coordinate.packaging != *packaging
    {
        return false;
    }
    if let Some(classifier) = target.classifier.as_ref()
        && coordinate.classifier.as_deref() != Some(classifier.as_str())
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use petgraph::graph::DiGraph;
    use rv_config::{LockCoordinate, LockEdge, LockGav, LockModule, LockModulePackage};
    use rv_version::PartialCoord;

    use super::{MAX_DEP_PATHS, collect_paths, explain_module, matches_target, parse_coord};

    fn package(artifact: &str, direct: bool, workspace: Option<&str>) -> LockModulePackage {
        LockModulePackage {
            coordinate: LockCoordinate::new("com.example", artifact, "1", "jar", None),
            direct_scope: direct.then(|| "compile".to_string()),
            workspace_module: workspace.map(str::to_string),
            system_path: None,
            extra: BTreeMap::new(),
        }
    }

    fn module() -> LockModule {
        LockModule {
            path: "app/pom.xml".to_string(),
            gav: LockGav::new("com.example", "app", "1"),
            packaging: "jar".to_string(),
            packages: vec![
                package("lib", true, Some("lib/pom.xml")),
                package("external", false, None),
            ],
            edges: vec![LockEdge {
                from: 0,
                to: 1,
                scope: Some("compile".to_string()),
                optional: false,
                extra: BTreeMap::new(),
            }],
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn traces_through_workspace_sibling() {
        let output = explain_module(
            &module(),
            &PartialCoord::parse("com.example:external").expect("coordinate"),
        )
        .expect("explain");
        assert!(output.found);
        assert_eq!(output.paths.len(), 1);
        assert!(output.paths[0][0].contains("(workspace)"));
        assert!(output.paths[0][1].contains("external"));
    }

    /// The synthetic root of a legacy-adapted lock has no coordinate: the
    /// module header names its POM, while the JSON `gav` keeps the documented
    /// placeholder so the field stays a `group:artifact:version` string.
    #[test]
    fn legacy_placeholder_module_is_labeled_by_its_pom_path() {
        let mut module = module();
        module.path = "pom.xml".to_string();
        module.gav = LockGav::legacy_root();
        let output = explain_module(
            &module,
            &PartialCoord::parse("com.example:external").expect("coordinate"),
        )
        .expect("explain");
        assert!(output.found);
        assert_eq!(output.label, "pom.xml (legacy lockfile root)");
        assert_eq!(output.gav, "__legacy__:__root__:0");
    }

    #[test]
    fn target_matching_supports_partial_coordinates() {
        let package = package("external", false, None);
        assert!(matches_target(
            &package,
            &PartialCoord::parse("external").unwrap()
        ));
        assert!(matches_target(
            &package,
            &PartialCoord::parse("com.example:external:1").unwrap()
        ));
        assert!(!matches_target(
            &package,
            &PartialCoord::parse("com.example:other").unwrap()
        ));
    }

    #[test]
    fn parse_coord_rejects_malformed_argument() {
        assert!(parse_coord("").is_err());
        assert!(parse_coord("a:b:c:d:e:f").is_err());
        assert!(parse_coord("com.example:demo:1.0").is_ok());
    }

    #[test]
    fn collect_paths_caps_at_limit_and_flags_truncation() {
        let fan = MAX_DEP_PATHS + 50;
        let mut graph = DiGraph::new();
        let root = graph.add_node(0);
        let target = graph.add_node(1);
        for _ in 0..fan {
            let middle = graph.add_node(2);
            graph.add_edge(root, middle, ());
            graph.add_edge(middle, target, ());
        }
        let (paths, truncated) = collect_paths(&graph, &[root], &[target.index()]);
        assert!(truncated);
        assert_eq!(paths.len(), MAX_DEP_PATHS);
    }

    #[test]
    fn collect_paths_includes_singleton_root_target() {
        let mut graph = DiGraph::new();
        let root = graph.add_node(0);
        let (paths, truncated) = collect_paths(&graph, &[root], &[0]);
        assert_eq!(paths, vec![vec![0]]);
        assert!(!truncated);
    }

    #[test]
    fn collect_paths_returns_all_small_graph_paths() {
        let mut graph = DiGraph::new();
        let root = graph.add_node(0);
        let left = graph.add_node(1);
        let right = graph.add_node(2);
        let target = graph.add_node(3);
        graph.add_edge(root, left, ());
        graph.add_edge(root, right, ());
        graph.add_edge(left, target, ());
        graph.add_edge(right, target, ());
        let (paths, truncated) = collect_paths(&graph, &[root], &[target.index()]);
        assert_eq!(paths.len(), 2);
        assert!(!truncated);
    }
}
