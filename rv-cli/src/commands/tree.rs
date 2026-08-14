use std::collections::HashSet;
use std::path::Path;

use clap::Args;
use rv_config::{Config, LockModule};
use rv_maven_model::Scope;
use serde::Serialize;

use crate::commands::module_selector::{LockModuleExt, ModuleSelector};
use crate::error::{CliError, Result};
use crate::output::{Table, is_json_mode, json_result};

#[derive(Debug, Args)]
#[command(
    about = "Show dependency trees from rv.lock",
    after_long_help = "\
Examples:
  rv tree                          # Show every module's dependency tree
  rv tree --module app/pom.xml     # Show one module by path
  rv tree --module com.acme:app    # Show one module by unique GA
  rv tree --scope compile          # Show only compile-scoped dependencies
  rv tree --depth 2                # Limit tree depth to 2 levels
  rv --json tree                   # Output as JSON
"
)]
pub struct TreeArgs {
    #[command(flatten)]
    module: ModuleSelector,
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

#[derive(Clone, Debug, Serialize)]
struct TreeNode {
    coordinate: String,
    scope: String,
    optional: bool,
    workspace: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_module: Option<String>,
    children: Vec<TreeNode>,
}

#[derive(Debug, Serialize)]
struct TreeModuleOutput {
    module: String,
    /// Always a `group:artifact:version` string, including for the synthetic
    /// root of a legacy-adapted lock, where it is rv's documented placeholder
    /// (`__legacy__:__root__:0`, see `schemas/rv-lock.json`). Keeping the raw
    /// value holds the field's type stable for machine consumers; the text
    /// renderer substitutes the module's POM path instead.
    gav: String,
    dependencies: Vec<TreeNode>,
}

#[derive(Debug, Serialize)]
struct TreeOutput {
    project: String,
    platform: String,
    /// Retained for single-module JSON consumers. Aggregate callers read
    /// `modules`, which attributes each graph to its POM path.
    dependencies: Vec<TreeNode>,
    modules: Vec<TreeModuleOutput>,
}

pub fn run(args: &TreeArgs, project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;
    let lock = crate::commands::read_lockfile(&config)?;
    let platform = crate::commands::select_platform(&lock)?;
    let selection = args.module.select(platform)?;

    if is_json_mode() {
        let modules = selection
            .modules()
            .iter()
            .map(|module| build_json_module(module, args.scope, args.depth))
            .collect::<Result<Vec<_>>>()?;
        let dependencies = if modules.len() == 1 {
            modules[0].dependencies.clone()
        } else {
            Vec::new()
        };
        let project = project_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("root")
            .to_string();
        json_result(
            true,
            serde_json::to_value(TreeOutput {
                project,
                platform: platform.platform.to_string(),
                dependencies,
                modules,
            })?,
        );
        return Ok(());
    }

    let show_headers = selection.is_aggregate();
    for (index, module) in selection.modules().iter().enumerate() {
        if show_headers {
            if index > 0 {
                println!();
            }
            println!("Module: {}", module.display_label());
        }
        match render_tree(module, args.scope, args.depth)? {
            TreeRender::Table(table) => println!("{}", table.render()),
            TreeRender::Empty(message) => println!("{message}"),
        }
    }
    Ok(())
}

#[derive(Clone)]
struct NodeInfo {
    coordinate: String,
    workspace_module: Option<String>,
    system: bool,
}

impl NodeInfo {
    fn label(&self) -> String {
        if self.workspace_module.is_some() {
            format!("{} (workspace)", self.coordinate)
        } else if self.system {
            format!("{} (system)", self.coordinate)
        } else {
            self.coordinate.clone()
        }
    }
}

struct TreeData {
    nodes: Vec<NodeInfo>,
    children: Vec<Vec<EdgeInfo>>,
    roots: Vec<usize>,
    node_scope: Vec<(Scope, bool)>,
}

fn build_dep_tree_data(module: &LockModule, scope_filter: Option<Scope>) -> Result<TreeData> {
    let count = module.packages.len();
    let nodes = module
        .packages
        .iter()
        .map(|package| NodeInfo {
            coordinate: package.coordinate.format_coord(),
            workspace_module: package.workspace_module.clone(),
            system: package.system_path.is_some(),
        })
        .collect::<Vec<_>>();
    let mut children = vec![Vec::new(); count];
    let mut incoming = vec![0_usize; count];
    let mut node_scope = vec![(Scope::Compile, false); count];
    let mut node_scope_set = vec![false; count];

    for edge in &module.edges {
        if edge.from >= count || edge.to >= count {
            return Err(CliError::Message(format!(
                "lockfile edge out of bounds in module '{}': {} -> {}",
                module.path, edge.from, edge.to
            )));
        }
        let edge_scope = parse_edge_scope(edge.scope.as_deref())?;
        if scope_filter.is_some_and(|filter| !scope_includes(filter, edge_scope)) {
            continue;
        }
        children[edge.from].push(EdgeInfo {
            to: edge.to,
            scope: edge_scope,
            optional: edge.optional,
        });
        incoming[edge.to] = incoming[edge.to].saturating_add(1);
        if !node_scope_set[edge.to] {
            node_scope[edge.to] = (edge_scope, edge.optional);
            node_scope_set[edge.to] = true;
        }
    }
    for outgoing in &mut children {
        outgoing.sort_by(|left, right| {
            nodes[left.to]
                .coordinate
                .cmp(&nodes[right.to].coordinate)
                .then(left.to.cmp(&right.to))
        });
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
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
    } else {
        incoming
            .iter()
            .enumerate()
            .filter(|(_, count)| **count == 0)
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
    };
    if roots.is_empty() && count > 0 {
        roots = (0..count).collect();
    }

    if let Some(filter) = scope_filter {
        // A root without a `direct_scope` stamp (every root on a lock adapted
        // from schema 1-3) defaults to compile, exactly as an unscoped edge
        // does above. Keeping such roots unconditionally would make
        // `--scope provided` list the whole graph.
        let mut retained = Vec::with_capacity(roots.len());
        for index in roots {
            let scope = parse_edge_scope(module.packages[index].direct_scope.as_deref())?;
            if scope_includes(filter, scope) {
                retained.push(index);
            }
        }
        roots = retained;
    }
    for root in &roots {
        if let Some(scope) = module.packages[*root].direct_scope.as_deref() {
            node_scope[*root] = (parse_edge_scope(Some(scope))?, false);
        }
    }
    roots.sort_by(|left, right| {
        nodes[*left]
            .coordinate
            .cmp(&nodes[*right].coordinate)
            .then(left.cmp(right))
    });

    Ok(TreeData {
        nodes,
        children,
        roots,
        node_scope,
    })
}

fn build_json_module(
    module: &LockModule,
    scope_filter: Option<Scope>,
    max_depth: Option<usize>,
) -> Result<TreeModuleOutput> {
    let tree = build_dep_tree_data(module, scope_filter)?;
    let mut dependencies = Vec::new();
    let mut path = HashSet::new();
    for root in &tree.roots {
        dependencies.push(build_json_node(*root, &tree, &mut path, 0, max_depth));
    }
    Ok(TreeModuleOutput {
        module: module.path.clone(),
        gav: module.gav(),
        dependencies,
    })
}

fn build_json_node(
    node: usize,
    tree: &TreeData,
    path: &mut HashSet<usize>,
    current_depth: usize,
    max_depth: Option<usize>,
) -> TreeNode {
    let (scope, optional) = tree.node_scope[node];
    let children = if max_depth.is_some_and(|max| current_depth >= max) {
        Vec::new()
    } else {
        path.insert(node);
        let live_children = tree.children[node]
            .iter()
            .filter(|edge| !path.contains(&edge.to))
            .map(|edge| edge.to)
            .collect::<Vec<_>>();
        let children = live_children
            .into_iter()
            .map(|child| build_json_node(child, tree, path, current_depth + 1, max_depth))
            .collect();
        path.remove(&node);
        children
    };
    let info = &tree.nodes[node];
    TreeNode {
        coordinate: info.coordinate.clone(),
        scope: scope.to_string(),
        optional,
        workspace: info.workspace_module.is_some(),
        workspace_module: info.workspace_module.clone(),
        children,
    }
}

enum TreeRender {
    Table(Table),
    Empty(String),
}

fn render_tree(
    module: &LockModule,
    scope_filter: Option<Scope>,
    max_depth: Option<usize>,
) -> Result<TreeRender> {
    let tree = build_dep_tree_data(module, scope_filter)?;
    if tree.roots.is_empty() {
        return Ok(TreeRender::Empty(format!(
            "No dependencies in rv.lock for module {}",
            module.path
        )));
    }

    let mut table = Table::new(["Dependency", "Scope", "Optional"]);
    table.add_row([module.display_gav(), String::new(), String::new()]);
    let mut path = HashSet::new();
    for (index, root) in tree.roots.iter().enumerate() {
        render_node(
            *root,
            "",
            index + 1 == tree.roots.len(),
            &tree,
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
    tree: &TreeData,
    path: &mut HashSet<usize>,
    table: &mut Table,
    edge_info: Option<&EdgeInfo>,
    current_depth: usize,
    max_depth: Option<usize>,
) {
    let connector = if is_last { "└──" } else { "├──" };
    let cycle = path.contains(&node);
    let mut label = format!("{prefix}{connector} {}", tree.nodes[node].label());
    if cycle {
        label.push_str(" (cycle)");
    }
    let scope = edge_info
        .map(|edge| edge.scope.to_string())
        .or_else(|| {
            tree.nodes
                .get(node)
                .map(|_| tree.node_scope[node].0.to_string())
        })
        .unwrap_or_default();
    let mut optional = edge_info
        .filter(|edge| edge.optional)
        .map(|_| "optional")
        .unwrap_or("")
        .to_string();
    if cycle && optional.is_empty() {
        optional = "cycle".to_string();
    }
    table.add_row([label, scope, optional]);
    if cycle {
        return;
    }

    if max_depth.is_some_and(|max| current_depth >= max) {
        let child_count = tree.children[node].len();
        if child_count > 0 {
            let next_prefix = if is_last {
                format!("{prefix}    ")
            } else {
                format!("{prefix}│   ")
            };
            table.add_row([
                format!("{next_prefix}... ({child_count} more)"),
                String::new(),
                String::new(),
            ]);
        }
        return;
    }

    let next_prefix = if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };
    path.insert(node);
    for (index, edge) in tree.children[node].iter().enumerate() {
        render_node(
            edge.to,
            &next_prefix,
            index + 1 == tree.children[node].len(),
            tree,
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
    use std::collections::BTreeMap;

    use rv_config::{LockCoordinate, LockEdge, LockGav, LockModule, LockModulePackage};
    use rv_maven_model::Scope;

    use super::{TreeRender, build_dep_tree_data, build_json_module, render_tree};

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
                scope: Some("runtime".to_string()),
                optional: true,
                extra: BTreeMap::new(),
            }],
            extra: BTreeMap::new(),
        }
    }

    /// Shape of a lockfile adapted from schema 1-3: one synthetic root module
    /// carrying the placeholder GAV, and packages with no `direct_scope`.
    fn legacy_module() -> LockModule {
        let mut module = module();
        module.path = "pom.xml".to_string();
        module.gav = LockGav::legacy_root();
        module.packaging = "pom".to_string();
        for package in &mut module.packages {
            package.direct_scope = None;
        }
        module.edges.clear();
        module
    }

    #[test]
    fn workspace_nodes_are_marked_and_keep_children() {
        let module = module();
        let data = build_dep_tree_data(&module, None).expect("build");
        assert_eq!(data.roots, [0]);
        assert_eq!(data.children[0][0].to, 1);
        assert_eq!(
            data.nodes[0].workspace_module.as_deref(),
            Some("lib/pom.xml")
        );
        let json = build_json_module(&module, None, None).expect("JSON tree");
        assert!(json.dependencies[0].workspace);
        assert_eq!(json.dependencies[0].children.len(), 1);
    }

    #[test]
    fn direct_nodes_remain_roots_when_they_also_have_incoming_edges() {
        let mut module = module();
        module.packages[1].direct_scope = Some("compile".to_string());
        let data = build_dep_tree_data(&module, None).expect("build");
        assert_eq!(data.roots, [1, 0]);
    }

    /// A lock adapted from schema 1-3 stamps no `direct_scope`, so every root
    /// falls back to compile — the same default unscoped edges get. Without
    /// it, `--scope provided` listed the entire graph.
    #[test]
    fn scope_filter_defaults_scopeless_roots_to_compile() {
        let module = legacy_module();
        let compile = build_dep_tree_data(&module, Some(Scope::Compile)).expect("compile");
        assert_eq!(compile.roots.len(), 2);
        let provided = build_dep_tree_data(&module, Some(Scope::Provided)).expect("provided");
        assert!(provided.roots.is_empty(), "got {:?}", provided.roots);

        match render_tree(&module, Some(Scope::Provided), None).expect("render") {
            TreeRender::Empty(message) => assert!(message.contains("pom.xml")),
            TreeRender::Table(table) => {
                panic!(
                    "scope-less roots must not survive --scope provided:\n{}",
                    table.render()
                )
            }
        }
        assert_eq!(
            build_json_module(&module, Some(Scope::Provided), None)
                .expect("JSON tree")
                .dependencies
                .len(),
            0
        );
    }

    /// The synthetic root of a legacy lock has no coordinate; the text view
    /// names its POM, while the JSON `gav` keeps the documented placeholder so
    /// the field stays a `group:artifact:version` string for consumers.
    #[test]
    fn legacy_placeholder_renders_as_its_pom_path() {
        let module = legacy_module();
        let TreeRender::Table(table) = render_tree(&module, None, None).expect("render") else {
            panic!("legacy module has dependencies to render");
        };
        let rendered = table.render();
        assert!(
            rendered.contains("pom.xml (legacy lockfile root)"),
            "got {rendered}"
        );
        assert!(
            !rendered.contains("__legacy__"),
            "sentinel leaked: {rendered}"
        );

        let json = build_json_module(&module, None, None).expect("JSON tree");
        assert_eq!(json.module, "pom.xml");
        assert_eq!(json.gav, "__legacy__:__root__:0");
    }

    #[test]
    fn render_tree_empty_module_returns_explicit_message() {
        let mut module = module();
        module.packages.clear();
        module.edges.clear();
        match render_tree(&module, None, None).expect("render") {
            TreeRender::Empty(message) => assert!(message.contains("app/pom.xml")),
            TreeRender::Table(_) => panic!("empty graph should not render a table"),
        }
    }
}
