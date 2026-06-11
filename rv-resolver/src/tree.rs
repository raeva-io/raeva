use std::collections::HashSet;
use std::fmt;

use rv_version::VersionReq;

use crate::graph::{CoordKey, Edge, Graph, Node};

pub struct Tree {
    lines: Vec<String>,
}

impl Tree {
    pub fn from_graph(graph: &Graph) -> Self {
        let mut lines = Vec::new();
        if let Some(root) = graph.node(graph.root()) {
            lines.push(root.coord.to_string());
            let mut path: HashSet<CoordKey> = HashSet::new();
            path.insert(CoordKey::from(&root.coord));
            render_children(graph, graph.root(), 1, &mut path, &mut lines);
        }
        Self { lines }
    }

    pub fn render(&self) -> String {
        self.lines.join("\n")
    }
}

impl fmt::Display for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

fn render_children(
    graph: &Graph,
    parent: petgraph::graph::NodeIndex,
    depth: usize,
    path: &mut HashSet<CoordKey>,
    lines: &mut Vec<String>,
) {
    for (_, child, edge) in graph.edges(parent) {
        let Some(node) = graph.node(child) else {
            continue;
        };
        let mut line = format!("{}- {} [{}]", indent(depth), node.coord, edge.scope);

        if let Some(conflict) = conflict_note(edge, node) {
            line.push_str(&conflict);
        }

        let key = CoordKey::from(&node.coord);
        if path.contains(&key) {
            line.push_str(" (cycle)");
            lines.push(line);
            continue;
        }

        lines.push(line);
        path.insert(key.clone());
        render_children(graph, child, depth + 1, path, lines);
        path.remove(&key);
    }
}

fn indent(depth: usize) -> String {
    "  ".repeat(depth)
}

fn conflict_note(edge: &Edge, node: &Node) -> Option<String> {
    let requested = edge.requested.as_deref()?;
    let parsed = VersionReq::parse(requested).ok()?;

    // Only flag a genuine version conflict: a hard constraint the resolved
    // version violates. A `Soft` pin (a bare `<version>X</version>`) is a
    // preference that Maven overrides via nearest-wins,
    // <dependencyManagement>, or a BOM import, so a mismatch there is the
    // intended outcome, not a conflict. Flagging those expected soft-pin/BOM
    // overrides would be spurious noise. `Exact` (the `[X]` hard pin) and
    // `Ranges` are real constraints; report a conflict only when the selected
    // version falls outside one of those.
    match parsed {
        VersionReq::Soft(_) => None,
        VersionReq::Exact(_) | VersionReq::Ranges(_) => {
            if parsed.matches(&node.coord.version) {
                None
            } else {
                Some(format!(" (conflict: requested {requested})"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Tree;
    use crate::graph::{Edge, Graph, Node};
    use rv_maven_model::Scope;
    use rv_version::Coord;

    fn node(coord: &str) -> Node {
        Node {
            coord: Coord::parse(coord).unwrap(),
            scope: Scope::Compile,
            repo_url: None,
            checksum: None,
            local: false,
            system_path: None,
        }
    }

    fn edge(requested: Option<&str>) -> Edge {
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: requested.map(str::to_string),
        }
    }

    /// A hard pin (`[1.0]` → `VersionReq::Exact`) that the resolved version
    /// (2.0) violates is a genuine conflict and must be labelled.
    #[test]
    fn tree_flags_hard_pin_conflict() {
        let mut graph = Graph::new(node("com.example:root:1.0"));
        let dep_idx = graph.insert_node(node("com.example:dep:2.0"));
        graph.add_edge(graph.root(), dep_idx, edge(Some("[1.0]")));

        let rendered = Tree::from_graph(&graph).render();
        assert!(rendered.contains("[compile]"));
        assert!(
            rendered.contains("conflict"),
            "hard-pin [1.0] vs selected 2.0 must be a conflict: {rendered}"
        );
    }

    /// A range (`[1.0,2.0)`) the resolved version (2.0) falls outside of is a
    /// genuine conflict and must be labelled.
    #[test]
    fn tree_flags_range_conflict() {
        let mut graph = Graph::new(node("com.example:root:1.0"));
        let dep_idx = graph.insert_node(node("com.example:dep:2.0"));
        graph.add_edge(graph.root(), dep_idx, edge(Some("[1.0,2.0)")));

        let rendered = Tree::from_graph(&graph).render();
        assert!(
            rendered.contains("conflict"),
            "range [1.0,2.0) vs selected 2.0 must be a conflict: {rendered}"
        );
    }

    /// #33: a soft pin (bare `1.0` → `VersionReq::Soft`) overridden to 2.0 by
    /// nearest-wins / <dependencyManagement> / a BOM is the intended Maven
    /// outcome, not a conflict. It must NOT be labelled.
    #[test]
    fn tree_does_not_flag_soft_pin_override() {
        let mut graph = Graph::new(node("com.example:root:1.0"));
        let dep_idx = graph.insert_node(node("com.example:dep:2.0"));
        graph.add_edge(graph.root(), dep_idx, edge(Some("1.0")));

        let rendered = Tree::from_graph(&graph).render();
        assert!(rendered.contains("[compile]"));
        assert!(
            !rendered.contains("conflict"),
            "soft-pin override (1.0 -> 2.0) must not be labelled a conflict: {rendered}"
        );
    }

    /// A satisfied hard pin must not be flagged.
    #[test]
    fn tree_does_not_flag_satisfied_hard_pin() {
        let mut graph = Graph::new(node("com.example:root:1.0"));
        let dep_idx = graph.insert_node(node("com.example:dep:2.0"));
        graph.add_edge(graph.root(), dep_idx, edge(Some("[2.0]")));

        let rendered = Tree::from_graph(&graph).render();
        assert!(
            !rendered.contains("conflict"),
            "hard pin [2.0] satisfied by selected 2.0 must not conflict: {rendered}"
        );
    }
}
