use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;

use clap::Args;
use rv_lock::LockModule;
use rv_lock::Scope;
use serde::Serialize;

use crate::commands::module_selector::{LockModuleExt, ModuleSelector};
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Report};
use crate::session::Session;

#[derive(Debug, Args)]
#[command(
    after_long_help = crate::commands::util::help_examples(&[
        ("tree", "Show every module's dependency tree"),
        ("tree --module app/pom.xml", "Show one module by path"),
        ("tree --module com.acme:app", "Show one module by unique GA"),
        ("tree --scope compile", "Show only compile-scoped dependencies"),
        ("tree --depth 1", "Show only the direct dependencies"),
        ("--json tree", "Output as JSON"),
    ])
)]
pub(crate) struct TreeArgs {
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
        value_parser = parse_depth,
        help = "Show N levels of dependencies; 1 shows the direct ones (default: all)"
    )]
    pub depth: Option<usize>,
}

fn parse_depth(value: &str) -> std::result::Result<usize, &'static str> {
    (value.trim().parse().ok())
        .filter(|&depth| depth > 0)
        .ok_or("expected a number of levels, 1 or more")
}

#[derive(Debug, Serialize)]
struct TreeNode {
    coordinate: String,
    scope: String,
    optional: bool,
    workspace: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_module: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    repeated: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cycle: bool,
    children: Vec<TreeNode>,
}

/// Drops a deep tree one node at a time instead of by recursion.
impl Drop for TreeNode {
    fn drop(&mut self) {
        let mut nodes = std::mem::take(&mut self.children);
        while let Some(mut node) = nodes.pop() {
            nodes.append(&mut node.children);
        }
    }
}

#[derive(Debug, Serialize)]
struct TreeModuleOutput {
    module: String,
    gav: String,
    dependencies: Vec<TreeNode>,
}

#[derive(Debug, Serialize)]
struct TreeOutput<'a> {
    project: &'a str,
    platform: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jdk: Option<&'a str>,
    modules: &'a [TreeModuleOutput],
}

/// The most levels `--json` nests. The walk and the drop of a tree are
/// iterative, but converting, printing and dropping JSON recurse once per
/// level; this many fit 1 MiB of stack in a debug build, with room to spare
/// in a release build.
const JSON_DEPTH_LIMIT: usize = 256;

pub(crate) fn run(args: &TreeArgs, session: &Session) -> Result<Report> {
    let config = session.lock_config()?;
    let lock = crate::commands::read_lockfile(&config)?;
    let platform = crate::commands::select_platform(&lock, config.host().java_version())?;
    let selection = args.module.select(platform)?;
    let lock_dir = config
        .lock_path
        .parent()
        .map_or_else(|| config.project_root.clone(), Path::to_path_buf);
    let show_headers = selection.is_aggregate();
    let modules = selection
        .modules()
        .iter()
        .map(|module| {
            let mut tree = ModuleTree::new(module, args.scope)?;
            tree.mark_declared_optional(&lock_dir, module);
            if show_headers {
                tree.header = Some(format!("Module: {}", module.display_label()));
            }
            Ok(tree)
        })
        .collect::<Result<Vec<_>>>()?;
    let json = if session.output().is_json() {
        modules
            .iter()
            .map(|module| json_module(module, args.depth))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    Ok(Report::data(TreeReport {
        project: session.project_name(),
        platform: platform.platform.os_arch(),
        jdk: platform.platform.jdk().map(str::to_string),
        max_depth: args.depth,
        modules,
        json,
    }))
}

struct TreeReport {
    project: String,
    platform: String,
    jdk: Option<String>,
    max_depth: Option<usize>,
    modules: Vec<ModuleTree>,
    /// The JSON trees, built only for `--json`.
    json: Vec<TreeModuleOutput>,
}

struct ModuleTree {
    path: String,
    gav: String,
    header: Option<String>,
    data: TreeData,
}

impl ModuleTree {
    fn new(module: &LockModule, scope_filter: Option<Scope>) -> Result<Self> {
        Ok(Self {
            path: module.path.clone(),
            gav: module.gav(),
            header: None,
            data: build_dep_tree_data(module, scope_filter)?,
        })
    }

    /// Mark the direct dependencies the module's own POM declares
    /// `<optional>true</optional>`. raeva.lock records the flag on edges only,
    /// so a direct dependency has no edge to carry it. A dependency the POM
    /// inherits from a parent, takes from a profile, or names through a
    /// property is not matched, and a POM that cannot be read marks nothing.
    fn mark_declared_optional(&mut self, lock_dir: &Path, module: &LockModule) {
        let Ok(bytes) = rv_config::read_project_input(&lock_dir.join(&module.path)) else {
            return;
        };
        let Ok(pom) = rv_maven_model::Pom::parse(&String::from_utf8_lossy(&bytes)) else {
            return;
        };
        let declared: HashSet<(&str, &str, &str, Option<&str>)> = pom
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency
                    .optional
                    .as_deref()
                    .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
            })
            .map(|dependency| {
                (
                    dependency.group_id.trim(),
                    dependency.artifact_id.trim(),
                    dependency.effective_type(),
                    dependency.effective_classifier(),
                )
            })
            .collect();
        for &root in &self.data.roots {
            let coordinate = &module.packages[root].coordinate;
            if declared.contains(&(
                coordinate.group_id(),
                coordinate.artifact_id(),
                coordinate.extension(),
                coordinate.classifier(),
            )) {
                self.data.declared_optional.insert(root);
            }
        }
    }
}

impl CommandOutput for TreeReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(TreeOutput {
            project: &self.project,
            platform: &self.platform,
            jdk: self.jdk.as_deref(),
            modules: &self.json,
        })
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        for (index, module) in self.modules.iter().enumerate() {
            if let Some(header) = &module.header {
                if index > 0 {
                    human.blank_line()?;
                }
                human.line(header)?;
            }
            for line in render_tree(module, self.max_depth) {
                human.line(line)?;
            }
        }
        let shown = self
            .modules
            .iter()
            .filter(|module| module.header.is_some())
            .count();
        if shown > 1 {
            let depth = match self.max_depth {
                None => ", --depth 1 the direct dependencies",
                Some(_) => "",
            };
            human.note(format!("{shown} modules; --module <path> shows one{depth}"))?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct NodeInfo {
    coordinate: String,
    display: String,
    workspace_module: Option<String>,
    system: bool,
}

struct TreeData {
    nodes: Vec<NodeInfo>,
    children: Vec<Vec<EdgeInfo>>,
    roots: Vec<usize>,
    /// The scope each package resolves to.
    scopes: Vec<Scope>,
    /// Direct dependencies the module's POM declares optional; the flag
    /// belongs to that declaration, not to other edges to the package.
    declared_optional: HashSet<usize>,
}

fn build_dep_tree_data(module: &LockModule, scope_filter: Option<Scope>) -> Result<TreeData> {
    let count = module.packages.len();
    let nodes = module
        .packages
        .iter()
        .map(|package| NodeInfo {
            coordinate: package.coordinate.to_string(),
            display: crate::commands::util::display_coordinate(&package.coordinate),
            workspace_module: package.workspace_module.clone(),
            system: package.system_path.is_some(),
        })
        .collect::<Vec<_>>();
    let mut children = vec![Vec::new(); count];
    let mut incoming = vec![0_usize; count];
    let scopes: Vec<Scope> = module
        .packages
        .iter()
        .map(|package| package.scope)
        .collect();

    for edge in &module.edges {
        crate::commands::util::check_edge(module, edge)?;
        if scope_filter.is_some_and(|filter| !scope_includes(filter, scopes[edge.to])) {
            continue;
        }
        children[edge.from].push(EdgeInfo {
            to: edge.to,
            optional: edge.optional,
        });
        incoming[edge.to] = incoming[edge.to].saturating_add(1);
    }
    for outgoing in &mut children {
        outgoing.sort_by(|left, right| {
            nodes[left.to]
                .coordinate
                .cmp(&nodes[right.to].coordinate)
                .then(left.to.cmp(&right.to))
        });
    }

    let mut roots = crate::commands::util::module_roots(module, &incoming);

    if let Some(filter) = scope_filter {
        // Keeping a root without a direct scope unconditionally would make
        // `--scope provided` list the whole graph.
        roots.retain(|&index| scope_includes(filter, scopes[index]));
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
        scopes,
        declared_optional: HashSet::new(),
    })
}

fn json_module(module: &ModuleTree, max_depth: Option<usize>) -> Result<TreeModuleOutput> {
    let mut walk = Walk::new(&module.data, max_depth);
    let dependencies = module
        .data
        .roots
        .iter()
        .map(|&root| walk.json_tree(root))
        .collect::<Option<_>>()
        .ok_or_else(|| {
            CliError::Usage(format!(
                "the dependency tree of {} is more than {JSON_DEPTH_LIMIT} levels deep, more than \
                 --json prints; pass --depth {JSON_DEPTH_LIMIT} or less",
                module.path
            ))
        })?;
    Ok(TreeModuleOutput {
        module: module.path.clone(),
        gav: module.gav.clone(),
        dependencies,
    })
}

/// The text tree: one line per dependency, with its scope in parentheses,
/// and a dependency whose own dependencies were already shown marked
/// instead of listed again, as Maven's `dependency:tree` lists each once.
fn render_tree(module: &ModuleTree, max_depth: Option<usize>) -> Vec<String> {
    let tree = &module.data;
    if tree.roots.is_empty() {
        return vec![format!(
            "No dependencies in raeva.lock for module {}",
            module.path
        )];
    }

    let mut walk = Walk::new(tree, max_depth);
    walk.lines.push(module.gav.clone());
    for (index, &root) in tree.roots.iter().enumerate() {
        walk.text_tree(root, index + 1 == tree.roots.len());
    }
    walk.lines
}

/// One pass over a module's graph. A node is expanded once, and where it
/// appears again with no more levels left to show, it is marked repeated.
struct Walk<'a> {
    tree: &'a TreeData,
    max_depth: Option<usize>,
    path: HashSet<usize>,
    expanded: HashMap<usize, usize>,
    lines: Vec<String>,
}

enum Visit {
    Expand,
    Cycle,
    Repeated,
    Cut,
}

impl<'a> Walk<'a> {
    fn new(tree: &'a TreeData, max_depth: Option<usize>) -> Self {
        Self {
            tree,
            max_depth,
            path: HashSet::new(),
            expanded: HashMap::new(),
            lines: Vec::new(),
        }
    }

    /// What to do with `node` at `depth`, where the roots are at depth 1,
    /// and record an expansion.
    fn visit(&mut self, node: usize, depth: usize) -> Visit {
        if self.path.contains(&node) {
            return Visit::Cycle;
        }
        if self.tree.children[node].is_empty() {
            return Visit::Expand;
        }
        let levels = self
            .max_depth
            .map_or(usize::MAX, |max| max.saturating_sub(depth));
        if levels == 0 {
            return Visit::Cut;
        }
        if self
            .expanded
            .get(&node)
            .is_some_and(|&shown| shown >= levels)
        {
            return Visit::Repeated;
        }
        self.expanded.insert(node, levels);
        Visit::Expand
    }

    /// Lines for `root` and what it brings in, walked with an explicit
    /// stack so a deep graph cannot overflow the call stack.
    fn text_tree(&mut self, root: usize, is_last: bool) {
        let mut stack = vec![self.text_node(root, "", is_last, None, 1)];
        while let Some(top) = stack.last_mut() {
            let Some((index, edge)) = top.edges.next() else {
                let done = stack.pop().expect("a frame");
                if done.expanded {
                    self.path.remove(&done.node);
                }
                continue;
            };
            let is_last = index + 1 == top.count;
            let frame = self.text_node(edge.to, &top.prefix, is_last, Some(edge), top.depth + 1);
            stack.push(frame);
        }
    }

    /// The line for one node; the frame lists the children to show next.
    fn text_node(
        &mut self,
        node: usize,
        prefix: &str,
        is_last: bool,
        edge: Option<&EdgeInfo>,
        depth: usize,
    ) -> TextFrame<'a> {
        let tree = self.tree;
        let info = &tree.nodes[node];
        let scope = tree.scopes[node];
        let optional = edge.map_or(tree.declared_optional.contains(&node), |edge| edge.optional);
        let visit = self.visit(node, depth);
        let mut notes = vec![scope.to_string()];
        if optional {
            notes.push("optional".to_string());
        }
        if info.workspace_module.is_some() {
            notes.push("workspace".to_string());
        } else if info.system && scope != Scope::System {
            notes.push("system".to_string());
        }
        match visit {
            Visit::Cycle => notes.push("cycle".to_string()),
            Visit::Repeated => notes.push("listed above".to_string()),
            Visit::Expand | Visit::Cut => {}
        }
        let connector = if is_last { "└──" } else { "├──" };
        self.lines.push(format!(
            "{prefix}{connector} {} ({})",
            info.display,
            notes.join(", ")
        ));
        let prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}│   ")
        };
        let expanded = matches!(visit, Visit::Expand);
        let children: &'a [EdgeInfo] = if expanded {
            self.path.insert(node);
            &tree.children[node]
        } else {
            &[]
        };
        TextFrame {
            node,
            expanded,
            depth,
            prefix,
            count: children.len(),
            edges: children.iter().enumerate(),
        }
    }

    /// The JSON node for `root`, built with an explicit stack so a deep
    /// graph cannot overflow the call stack. `None` when it nests more than
    /// [`JSON_DEPTH_LIMIT`] levels.
    fn json_tree(&mut self, root: usize) -> Option<TreeNode> {
        let mut stack = vec![self.json_node(root, 1, None)];
        loop {
            let top = stack.last_mut().expect("a frame");
            if let Some(edge) = top.edges.next() {
                let depth = top.depth + 1;
                if depth > JSON_DEPTH_LIMIT {
                    return None;
                }
                let frame = self.json_node(edge.to, depth, Some(edge));
                stack.push(frame);
                continue;
            }
            let done = stack.pop().expect("a frame");
            if done.expanded {
                self.path.remove(&done.index);
            }
            match stack.last_mut() {
                Some(parent) => parent.node.children.push(done.node),
                None => return Some(done.node),
            }
        }
    }

    /// One JSON node without its children; the frame lists them.
    fn json_node(&mut self, node: usize, depth: usize, edge: Option<&EdgeInfo>) -> JsonFrame<'a> {
        let tree = self.tree;
        let scope = tree.scopes[node];
        let optional = edge.map_or(tree.declared_optional.contains(&node), |edge| edge.optional);
        let visit = self.visit(node, depth);
        let expanded = matches!(visit, Visit::Expand);
        let children: &'a [EdgeInfo] = if expanded {
            self.path.insert(node);
            &tree.children[node]
        } else {
            &[]
        };
        let info = &tree.nodes[node];
        JsonFrame {
            index: node,
            expanded,
            depth,
            edges: children.iter(),
            node: TreeNode {
                coordinate: info.coordinate.clone(),
                scope: scope.to_string(),
                optional,
                workspace: info.workspace_module.is_some(),
                workspace_module: info.workspace_module.clone(),
                repeated: matches!(visit, Visit::Repeated),
                cycle: matches!(visit, Visit::Cycle),
                children: Vec::with_capacity(children.len()),
            },
        }
    }
}

/// A text node whose children are still to be shown.
struct TextFrame<'a> {
    node: usize,
    expanded: bool,
    depth: usize,
    prefix: String,
    count: usize,
    edges: std::iter::Enumerate<std::slice::Iter<'a, EdgeInfo>>,
}

/// A JSON node whose children are still to be built.
struct JsonFrame<'a> {
    index: usize,
    expanded: bool,
    depth: usize,
    edges: std::slice::Iter<'a, EdgeInfo>,
    node: TreeNode,
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
    optional: bool,
}

#[cfg(test)]
mod tests {

    use rv_lock::{LockEdge, LockModule, LockModulePackage};

    use rv_maven_types::{ArtifactCoord, Gav};

    use super::{ModuleTree, build_dep_tree_data, json_module, parse_depth, render_tree};

    #[test]
    fn depth_is_a_positive_number_of_levels() {
        assert_eq!(parse_depth(" 2 "), Ok(2));
        for bad in ["0", "-1", "x", ""] {
            assert_eq!(
                parse_depth(bad),
                Err("expected a number of levels, 1 or more")
            );
        }
    }

    fn package(artifact: &str, direct: bool, workspace: Option<&str>) -> LockModulePackage {
        let mut package = LockModulePackage::new(
            ArtifactCoord::new("com.example", artifact, "1", "jar", None),
            direct.then_some(rv_lock::Scope::Compile),
        );
        package.workspace_module = workspace.map(str::to_string);
        package
    }

    fn module() -> LockModule {
        let mut module = LockModule::new(
            "app/pom.xml".to_string(),
            Gav::new("com.example", "app", "1"),
            "jar".to_string(),
        );
        module.packages = vec![
            package("lib", true, Some("lib/pom.xml")),
            package("external", false, None),
        ];
        module.edges = vec![LockEdge::new(0, 1, Some(rv_lock::Scope::Runtime), true)];
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
        let json = json_module(&ModuleTree::new(&module, None).expect("tree"), None).expect("json");
        assert!(json.dependencies[0].workspace);
        assert_eq!(json.dependencies[0].children.len(), 1);
    }

    /// `skip_serializing_if` fields are absent from the json-payloads
    /// snapshots. Serializing a full node still requires them in the docs.
    #[test]
    fn the_docs_name_every_tree_node_field() {
        let keys = rv_test_support::fixtures::serde_serialize_fields(include_str!("tree.rs"));
        let docs = rv_test_support::fixtures::workspace_file("docs/json-output.md");
        let section =
            rv_test_support::fixtures::markdown_section(&docs, "## `raeva tree` and `raeva why`");
        rv_test_support::fixtures::assert_markdown_names(
            section,
            "docs/json-output.md tree/why section",
            &keys,
        );
    }

    /// `app -> a0 -> a1 -> ... -> a(n-1)`.
    fn chain(n: usize) -> LockModule {
        let mut module = LockModule::new(
            "pom.xml".to_string(),
            Gav::new("com.example", "app", "1"),
            "jar".to_string(),
        );
        module.packages = (0..n)
            .map(|index| package(&format!("a{index}"), index == 0, None))
            .collect();
        module.edges = (1..n)
            .map(|index| LockEdge::new(index - 1, index, None, false))
            .collect();
        module
    }

    /// A deep graph is walked without recursion: text has no depth limit,
    /// and JSON refuses more levels than it can serialize.
    #[test]
    fn a_deep_graph_does_not_overflow_the_stack() {
        let tree = ModuleTree::new(&chain(3_000), None).expect("tree");
        let text = lines(&tree, None);
        assert_eq!(text.len(), 3_001);
        assert!(text[3_000].ends_with("com.example:a2999:1 (compile)"));

        let limit = super::JSON_DEPTH_LIMIT;
        let tree = ModuleTree::new(&chain(limit), None).expect("tree");
        let json = json_module(&tree, None).expect("json");
        let mut node = &json.dependencies[0];
        for _ in 1..limit {
            node = &node.children[0];
        }
        assert!(node.children.is_empty());
        // The output path converts, serializes and drops the tree, each
        // recursively, within 1 MiB of stack.
        let report = super::TreeReport {
            project: String::new(),
            platform: String::new(),
            jdk: None,
            max_depth: None,
            modules: Vec::new(),
            json: vec![json],
        };
        let printed = std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(move || {
                use crate::output::CommandOutput;
                let value = report.to_json().expect("value");
                serde_json::to_string(&serde_json::json!({ "data": value })).expect("print")
            })
            .unwrap()
            .join()
            .expect("no overflow");
        assert_eq!(printed.matches("\"children\":[]").count(), 1);

        let tree = ModuleTree::new(&chain(limit + 1), None).expect("tree");
        let error = json_module(&tree, None).expect_err("too deep");
        let status = error.diagnose(&crate::error::HintEnv::discover()).status;
        assert_eq!(status as u8, 2, "{error}");
        assert!(error.to_string().contains("--depth 256"), "{error}");
        json_module(&tree, Some(limit)).expect("cut at --depth");

        let mut deep = Vec::new();
        for _ in 0..200_000 {
            deep = vec![super::TreeNode {
                coordinate: String::new(),
                scope: String::new(),
                optional: false,
                workspace: false,
                workspace_module: None,
                repeated: false,
                cycle: false,
                children: deep,
            }];
        }
        drop(deep);
    }

    /// Only the declaration with the same type and classifier marks a direct
    /// dependency optional.
    #[test]
    fn optional_is_matched_by_type_and_classifier() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
             <artifactId>app</artifactId><version>1</version><dependencies>\
             <dependency><groupId>com.example</groupId><artifactId>lib</artifactId>\
             <version>1</version></dependency>\
             <dependency><groupId>com.example</groupId><artifactId>lib</artifactId>\
             <version>1</version><type>test-jar</type><optional>true</optional></dependency>\
             </dependencies></project>",
        )
        .expect("pom");
        let mut module = LockModule::new(
            "pom.xml".to_string(),
            Gav::new("com.example", "app", "1"),
            "jar".to_string(),
        );
        module.packages = vec![
            package("lib", true, None),
            LockModulePackage::new(
                ArtifactCoord::new("com.example", "lib", "1", "jar", Some("tests")),
                Some(rv_lock::Scope::Compile),
            ),
        ];
        let mut tree = ModuleTree::new(&module, None).expect("tree");
        tree.mark_declared_optional(dir.path(), &module);
        assert_eq!(
            lines(&tree, None),
            [
                "com.example:app:1",
                "├── com.example:lib:1 (compile)",
                "└── com.example:lib:1:jar:tests (compile, optional)",
            ]
        );
    }

    fn lines(tree: &ModuleTree, max_depth: Option<usize>) -> Vec<String> {
        render_tree(tree, max_depth)
    }

    /// `app -> {a, b}`, `a -> shared`, `b -> shared`, `shared -> leaf`.
    fn diamond() -> LockModule {
        let mut module = LockModule::new(
            "pom.xml".to_string(),
            Gav::new("com.example", "app", "1"),
            "jar".to_string(),
        );
        module.packages = vec![
            package("a", true, None),
            package("b", true, None),
            package("shared", false, None),
            package("leaf", false, None),
        ];
        module.edges = vec![
            LockEdge::new(0, 2, None, false),
            LockEdge::new(1, 2, None, false),
            LockEdge::new(2, 3, None, false),
        ];
        module
    }

    #[test]
    fn an_edge_back_up_the_path_is_listed_as_a_cycle() {
        let mut module = diamond();
        module.edges.push(LockEdge::new(3, 2, None, false));
        let tree = ModuleTree::new(&module, None).expect("tree");
        assert_eq!(
            lines(&tree, None),
            [
                "com.example:app:1",
                "├── com.example:a:1 (compile)",
                "│   └── com.example:shared:1 (compile)",
                "│       └── com.example:leaf:1 (compile)",
                "│           └── com.example:shared:1 (compile, cycle)",
                "└── com.example:b:1 (compile)",
                "    └── com.example:shared:1 (compile, listed above)",
            ]
        );
        let json = json_module(&tree, None).expect("json");
        let back = &json.dependencies[0].children[0].children[0].children[0];
        assert!(back.cycle && !back.repeated && back.children.is_empty());
        let value = serde_json::to_value(&json.dependencies[1]).expect("json");
        assert!(value.to_string().contains("\"repeated\":true"), "{value}");
        assert!(!value.to_string().contains("cycle"), "{value}");
    }

    /// A system-scoped package already names its scope once. The human tree
    /// must not append a second "system" from `system_path`.
    #[test]
    fn a_system_scoped_package_is_not_annotated_twice() {
        let mut module = LockModule::new(
            "pom.xml".to_string(),
            Gav::new("com.example", "app", "1"),
            "jar".to_string(),
        );
        let mut tool = LockModulePackage::new(
            ArtifactCoord::new("com.example", "tool", "1", "jar", None),
            Some(rv_lock::Scope::System),
        );
        tool.system_path = Some("lib/tool.jar".into());
        module.packages = vec![tool];
        let tree = ModuleTree::new(&module, None).expect("tree");
        assert_eq!(
            lines(&tree, None),
            ["com.example:app:1", "└── com.example:tool:1 (system)",]
        );
    }

    /// JSON and text both show the scope the lock records for the package
    /// and the optional flag of the edge that reaches it. `--scope` keeps
    /// the packages that resolve into it, so a direct test dependency that a
    /// compile parent also declares is left out of `compile`, and, as in
    /// Maven's `dependency:tree -Dscope`, so is all below it, even a package
    /// management made compile.
    #[test]
    fn nodes_show_the_package_scope_and_the_edge_optional_flag() {
        let mut module = LockModule::new(
            "pom.xml".to_string(),
            Gav::new("com.example", "app", "1"),
            "jar".to_string(),
        );
        let mut direct_test = package("direct-test", true, None);
        direct_test.direct_scope = Some(rv_lock::Scope::Test);
        direct_test.scope = rv_lock::Scope::Test;
        let mut leaf = package("leaf", false, None);
        leaf.scope = rv_lock::Scope::Test;
        module.packages = vec![
            package("compile-parent", true, None),
            package("runtime-parent", true, None),
            package("shared", false, None),
            direct_test,
            leaf,
            package("managed", false, None),
        ];
        module.edges = vec![
            LockEdge::new(0, 2, Some(rv_lock::Scope::Compile), false),
            LockEdge::new(1, 2, Some(rv_lock::Scope::Runtime), true),
            LockEdge::new(0, 3, Some(rv_lock::Scope::Compile), false),
            LockEdge::new(3, 4, Some(rv_lock::Scope::Test), false),
            LockEdge::new(3, 5, Some(rv_lock::Scope::Compile), false),
        ];
        let tree = ModuleTree::new(&module, None).expect("tree");
        // shared is a leaf, so its second appearance is not "listed above".
        assert_eq!(
            lines(&tree, None),
            [
                "com.example:app:1",
                "├── com.example:compile-parent:1 (compile)",
                "│   ├── com.example:direct-test:1 (test)",
                "│   │   ├── com.example:leaf:1 (test)",
                "│   │   └── com.example:managed:1 (compile)",
                "│   └── com.example:shared:1 (compile)",
                "├── com.example:direct-test:1 (test, listed above)",
                "└── com.example:runtime-parent:1 (compile)",
                "    └── com.example:shared:1 (compile, optional)",
            ]
        );
        let json = json_module(&tree, None).expect("json");
        let via_compile = &json.dependencies[0].children[1];
        let via_runtime = &json.dependencies[2].children[0];
        assert_eq!(via_compile.scope, "compile");
        assert!(!via_compile.optional);
        assert_eq!(via_runtime.scope, "compile");
        assert!(via_runtime.optional);
        let compile = ModuleTree::new(&module, Some(rv_lock::Scope::Compile)).expect("tree");
        assert_eq!(
            lines(&compile, None),
            [
                "com.example:app:1",
                "├── com.example:compile-parent:1 (compile)",
                "│   └── com.example:shared:1 (compile)",
                "└── com.example:runtime-parent:1 (compile)",
                "    └── com.example:shared:1 (compile, optional)",
            ]
        );
    }
}
