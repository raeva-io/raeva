use std::sync::Arc;

use indexmap::IndexMap;
use petgraph::Directed;
use petgraph::Direction::Incoming;
use petgraph::graph::{EdgeIndex, Graph as PetGraph, NodeIndex};
use petgraph::visit::EdgeRef;

use rv_config::Checksum;
use rv_maven_model::{Exclusion, Scope};
use rv_version::{ArtifactId, Coord, GroupId};

/// A resolved artifact node. Group/artifact identifiers and `repo_url` are
/// `Arc<str>`-shared to deduplicate the common strings across the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub coord: Coord,
    pub scope: Scope,
    pub repo_url: Option<Arc<str>>,
    pub checksum: Option<Checksum>,
    pub local: bool,
    /// Local file path for system-scoped dependencies.
    pub system_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub scope: Scope,
    pub optional: bool,
    pub exclusions: Vec<Exclusion>,
    pub requested: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct CoordKey {
    pub group_id: GroupId,
    pub artifact_id: ArtifactId,
    pub packaging: Option<String>,
    pub classifier: Option<String>,
}

impl From<&Coord> for CoordKey {
    fn from(coord: &Coord) -> Self {
        Self {
            group_id: coord.group_id.clone(),
            artifact_id: coord.artifact_id.clone(),
            packaging: coord.packaging.clone(),
            classifier: coord.classifier.clone(),
        }
    }
}

/// Dependency graph storing resolved artifacts and their relationships.
///
/// `petgraph::Graph` (directed adjacency list) plus an `IndexMap` for O(1)
/// coordinate lookup. Append-only during resolution.
#[derive(Debug, Clone)]
pub struct Graph {
    graph: PetGraph<Node, Edge, Directed>,
    root: NodeIndex,
    index: IndexMap<CoordKey, NodeIndex>,
}

impl Graph {
    pub fn new(root: Node) -> Self {
        Self::with_capacity(root, 256)
    }

    pub fn with_capacity(root: Node, capacity: usize) -> Self {
        let mut graph = PetGraph::with_capacity(capacity, capacity);
        let key = CoordKey::from(&root.coord);
        let root_index = graph.add_node(root);
        let mut index = IndexMap::with_capacity(capacity);
        index.insert(key, root_index);
        Self {
            graph,
            root: root_index,
            index,
        }
    }

    pub fn root(&self) -> NodeIndex {
        self.root
    }

    pub fn node(&self, idx: NodeIndex) -> Option<&Node> {
        self.graph.node_weight(idx)
    }

    pub fn node_mut(&mut self, idx: NodeIndex) -> Option<&mut Node> {
        self.graph.node_weight_mut(idx)
    }

    #[cfg(test)]
    pub(crate) fn node_index(&self, key: &CoordKey) -> Option<NodeIndex> {
        self.index.get(key).copied()
    }

    pub fn insert_node(&mut self, node: Node) -> NodeIndex {
        let key = CoordKey::from(&node.coord);
        if let Some(existing) = self.index.get(&key) {
            return *existing;
        }
        let idx = self.graph.add_node(node);
        self.index.insert(key, idx);
        idx
    }

    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: Edge) -> EdgeIndex {
        self.graph.add_edge(from, to, edge)
    }

    /// Replace the resolved version on `node_idx` in place and tear down the
    /// loser subgraph reachable through it. Returns the `CoordKey`s of every
    /// descendant whose secondary-index entry was purged so callers can drop
    /// matching entries from their own "selected" maps.
    ///
    /// `CoordKey` does not include `version`, so the index entry for this
    /// node's coordinate stays valid: it still points to `node_idx`, which
    /// now carries the winning version. Orphan descendants are left in the
    /// graph (their `NodeIndex` values are stable references held by other
    /// solver state) but their secondary-index entries are dropped so a
    /// later dependency for the same coordinate cannot resurrect them.
    pub(crate) fn replace_node_version(
        &mut self,
        node_idx: NodeIndex,
        new_coord: rv_version::Coord,
    ) -> Vec<CoordKey> {
        // Collect descendants reachable via outgoing edges, with cycle
        // protection (the graph may contain back-edges from broken cycles).
        let mut descendants: Vec<NodeIndex> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        visited.insert(node_idx);
        let mut stack = vec![node_idx];
        while let Some(n) = stack.pop() {
            let targets: Vec<NodeIndex> = self.graph.edges(n).map(|e| e.target()).collect();
            for child in targets {
                if visited.insert(child) {
                    descendants.push(child);
                    stack.push(child);
                }
            }
        }

        // Drop the node's outgoing edges so the loser subgraph is detached.
        let outgoing: Vec<_> = self.graph.edges(node_idx).map(|e| e.id()).collect();
        for edge_id in outgoing {
            self.graph.remove_edge(edge_id);
        }

        // Purge the secondary-index entries for orphans. Leave the orphan
        // nodes themselves alone: `petgraph::Graph::remove_node` swap-removes,
        // which would invalidate `NodeIndex` values held by `Selected` entries
        // elsewhere in the solver.
        //
        // Only purge the index entry for a descendant if it has no remaining
        // incoming edges. A descendant shared via a cross-edge from another
        // live parent (diamond pattern) must keep its index entry; otherwise
        // a subsequent `insert_node` for the same `CoordKey` would create a
        // duplicate node.
        let mut removed_keys: Vec<CoordKey> = Vec::new();
        for child in &descendants {
            if self.graph.edges_directed(*child, Incoming).next().is_some() {
                continue;
            }
            if let Some(node) = self.graph.node_weight(*child) {
                let key = CoordKey::from(&node.coord);
                if let Some(existing) = self.index.get(&key).copied()
                    && existing == *child
                {
                    self.index.shift_remove(&key);
                    removed_keys.push(key);
                }
            }
        }

        if let Some(node) = self.graph.node_weight_mut(node_idx) {
            node.coord = new_coord;
        }

        removed_keys
    }

    /// Debug-only invariant check: every entry in `index` must point at a
    /// live node whose `CoordKey` round-trips to the same key. The solver
    /// calls this after conflict eviction so a stale entry trips a debug
    /// build immediately instead of corrupting later resolution.
    #[cfg(debug_assertions)]
    pub fn assert_index_consistent(&self) {
        for (key, &idx) in self.index.iter() {
            let node = self
                .graph
                .node_weight(idx)
                .expect("index points at removed node");
            let actual = CoordKey::from(&node.coord);
            debug_assert_eq!(
                &actual, key,
                "index key {:?} does not match node coord {:?}",
                key, actual
            );
        }
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn node_indices(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.node_indices()
    }

    pub fn edge_indices(&self) -> impl Iterator<Item = EdgeIndex> + '_ {
        self.graph.edge_indices()
    }

    pub fn edges(&self, from: NodeIndex) -> impl Iterator<Item = (EdgeIndex, NodeIndex, &Edge)> {
        self.graph.edges(from).map(|edge| {
            let idx = edge.id();
            let target = edge.target();
            (idx, target, edge.weight())
        })
    }

    pub fn graph(&self) -> &PetGraph<Node, Edge, Directed> {
        &self.graph
    }
}

#[cfg(test)]
mod tests {
    use super::{CoordKey, Edge, Graph, Node};
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

    fn edge() -> Edge {
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: None,
        }
    }

    #[test]
    fn inserts_and_indexes_nodes() {
        let mut graph = Graph::new(node("com.example:root:1.0"));
        let lib = node("com.example:lib:1.0");
        let idx = graph.insert_node(lib.clone());
        let key = CoordKey::from(&lib.coord);
        assert_eq!(graph.node_index(&key), Some(idx));
        assert_eq!(graph.node_indices().count(), 2);
    }

    /// Diamond pattern regression: when evicting a parent (A1) that shares
    /// a child (D) with another live parent (B), the index entry for D must
    /// survive so a later insert for D returns the same node instead of a
    /// duplicate. Confirms `replace_node_version` respects incoming edges.
    #[test]
    fn replace_node_version_preserves_shared_descendants() {
        let mut graph = Graph::new(node("root:root:1"));
        let root = graph.root();
        let a = graph.insert_node(node("com.example:a:1"));
        let b = graph.insert_node(node("com.example:b:1"));
        let d = graph.insert_node(node("com.example:d:1"));
        graph.add_edge(root, a, edge());
        graph.add_edge(root, b, edge());
        graph.add_edge(a, d, edge());
        graph.add_edge(b, d, edge());

        let new_a_coord = Coord::parse("com.example:a:2").unwrap();
        let removed = graph.replace_node_version(a, new_a_coord);

        let d_key = CoordKey::from(&Coord::parse("com.example:d:1").unwrap());
        assert!(
            !removed.contains(&d_key),
            "shared descendant D must not be reported as purged",
        );
        assert_eq!(
            graph.node_index(&d_key),
            Some(d),
            "shared descendant D must keep its index entry pointing at the original node",
        );

        // A re-insert of D must reuse the existing node, not create a dup.
        let reinserted = graph.insert_node(node("com.example:d:1"));
        assert_eq!(reinserted, d);
    }
}
