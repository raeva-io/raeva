use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use petgraph::Directed;
use petgraph::Direction::Incoming;
use petgraph::graph::{EdgeIndex, Graph as PetGraph, NodeIndex};
use petgraph::visit::{Bfs, EdgeRef};

use rv_maven_model::{Exclusion, Scope};
use rv_maven_types::{ArtifactId, Coord, GroupId, Sha256};
use rv_repo::Repository;

use crate::error::ResolveError;
use crate::solver::{ExclusionKey, excludes};

/// The states one cycle's gathering may visit. Each exclusion set on a path
/// is a state of its own, as in Maven, so a crafted graph could otherwise
/// make the walk exponential.
const MAX_GATHER_STATES: usize = 100_000;

/// One configured repository, by id and URL: one URL can be declared under
/// two ids that resolve to different mirrors and credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoRef {
    pub id: Option<Arc<str>>,
    pub url: Arc<str>,
}

impl RepoRef {
    pub(crate) fn of(repo: &Repository) -> Self {
        Self {
            id: repo.id.as_deref().map(Arc::from),
            url: Arc::from(repo.url.as_str()),
        }
    }

    pub(crate) fn is(&self, repo: &Repository) -> bool {
        *self.url == *repo.url && self.id.as_deref() == repo.id.as_deref()
    }
}

/// A resolved artifact node. Group/artifact identifiers and `repo_url` are
/// `Arc<str>`-shared to deduplicate the common strings across the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub coord: Coord,
    /// The winner's declared scope while the solver walks, then the scope
    /// [`Graph::select_scopes`] picks.
    pub scope: Scope,
    pub repo_url: Option<Arc<str>>,
    /// The repository whose metadata named this SNAPSHOT build. As in
    /// Maven, the build's files come from it alone.
    pub build_repo: Option<RepoRef>,
    /// Per-path admitted transitive repositories in effect at this node.
    pub repos: crate::context::RepoContext,
    pub checksum: Option<Sha256>,
    /// Canonical workspace-root-relative POM path for a reactor project.
    ///
    /// Workspace projects have no repository provenance or artifact checksum;
    /// the requested packaging/classifier remain on `coord`.
    pub workspace_module: Option<String>,
    pub local: bool,
    pub system_path: Option<String>,
    /// The node whose declaration won mediation. Maven gathers below that
    /// occurrence alone once the group is resolved.
    pub winner_parent: Option<NodeIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Edge {
    /// The declared scope, or the one management set.
    pub scope: Scope,
    /// Management set `scope`, which Maven then takes as it is.
    pub managed_scope: bool,
    /// For a direct declaration, its place among the module's: the first
    /// one sets a node's scope.
    pub declared: Option<u64>,
    pub optional: bool,
    pub exclusions: Vec<Exclusion>,
    pub requested: Option<String>,
}

impl Edge {
    /// The dependency's scope below a parent that resolved to `parent`, by
    /// Maven's JavaScopeDeriver, unless management set it.
    pub(crate) fn scope_below(&self, parent: Scope) -> Scope {
        match (parent, self.scope) {
            _ if self.managed_scope => self.scope,
            (_, Scope::System | Scope::Test) | (Scope::Compile, _) => self.scope,
            (Scope::Test | Scope::Runtime, _) => parent,
            (Scope::Provided | Scope::System, _) => Scope::Provided,
            (Scope::Import, _) => Scope::Runtime,
        }
    }
}

/// Maven's ConflictMarker and ConflictIdSorter over the mediated graph: the
/// nodes in the order a depth-first walk in declaration order first finds
/// them, each with the depth Maven records for it, and the nodes below each
/// in the order Java's HashSet of those numbers iterates them.
struct ConflictOrder {
    order: Vec<NodeIndex>,
    depth: Vec<usize>,
    children: Vec<Vec<NodeIndex>>,
    in_degree: Vec<usize>,
}

impl ConflictOrder {
    fn of(graph: &Graph) -> Self {
        let count = graph.graph.node_count();
        let mut number = vec![usize::MAX; count];
        let mut this = Self {
            order: Vec::new(),
            depth: vec![usize::MAX; count],
            children: vec![Vec::new(); count],
            in_degree: vec![0; count],
        };
        let mut visited = vec![false; count];
        visited[graph.root.index()] = true;
        // `neighbors` lists the latest first, so popping takes them in
        // declaration order.
        let declared = |node| graph.graph.neighbors(node).collect::<Vec<_>>();
        let mut stack = vec![(graph.root, 0, declared(graph.root))];
        while let Some((node, depth, next)) = stack.last_mut() {
            let (node, depth) = (*node, *depth + 1);
            let Some(child) = next.pop() else {
                stack.pop();
                continue;
            };
            if number[child.index()] == usize::MAX {
                number[child.index()] = this.order.len();
                this.order.push(child);
                this.depth[child.index()] = depth;
            } else {
                this.pull_up(child, depth);
            }
            if node != graph.root && !this.children[node.index()].contains(&child) {
                this.children[node.index()].push(child);
                this.in_degree[child.index()] += 1;
            }
            if !std::mem::replace(&mut visited[child.index()], true) {
                stack.push((child, depth, declared(child)));
            }
        }
        for children in &mut this.children {
            let mut buckets = 16;
            while children.len() * 4 > buckets * 3 {
                buckets *= 2;
            }
            children.sort_by_key(|child| {
                let number = number[child.index()];
                (number ^ (number >> 16)) & (buckets - 1)
            });
        }
        this
    }

    fn pull_up(&mut self, node: NodeIndex, depth: usize) {
        let mut lift = vec![(node, depth)];
        while let Some((node, depth)) = lift.pop() {
            if depth < self.depth[node.index()] {
                self.depth[node.index()] = depth;
                lift.extend(
                    self.children[node.index()]
                        .iter()
                        .map(|&child| (child, depth + 1)),
                );
            }
        }
    }

    /// The cycles Maven's ConflictIdSorter records: those a depth-first walk
    /// from each node in turn closes.
    fn cycles(&self) -> Vec<Vec<NodeIndex>> {
        let mut cycles = Vec::new();
        let mut visited = vec![false; self.depth.len()];
        let mut on_path: HashMap<NodeIndex, usize> = HashMap::new();
        let mut path: Vec<NodeIndex> = Vec::new();
        let mut frames: Vec<(NodeIndex, usize)> = Vec::new();
        for &start in &self.order {
            let mut enter = Some(start);
            loop {
                if let Some(node) = enter.take() {
                    if let Some(&at) = on_path.get(&node) {
                        cycles.push(path[at..].to_vec());
                    } else if !std::mem::replace(&mut visited[node.index()], true) {
                        on_path.insert(node, path.len());
                        path.push(node);
                        frames.push((node, 0));
                    }
                }
                let Some((node, next)) = frames.last_mut() else {
                    break;
                };
                if let Some(&child) = self.children[node.index()].get(*next) {
                    *next += 1;
                    enter = Some(child);
                } else {
                    on_path.remove(node);
                    path.pop();
                    frames.pop();
                }
            }
        }
        cycles
    }
}

/// How Maven's JavaScopeSelector ranks the scopes of a dependency's paths.
fn width(scope: Scope) -> u8 {
    match scope {
        Scope::Compile => 4,
        Scope::Runtime => 3,
        Scope::Provided => 2,
        Scope::Test => 1,
        Scope::System | Scope::Import => 0,
    }
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
        // Maven conflict mediation keys artifacts by the artifact handler's
        // extension and classifier, not by the dependency's literal type.
        // `maven-plugin` uses the `jar` extension, so a direct jar and a
        // transitive maven-plugin declaration compete for one node. Keep the
        // winning node's requested type on `Coord` and normalize only the key.
        let packaging = match coord.packaging.as_deref() {
            None | Some("jar") | Some("maven-plugin") => None,
            Some(_) => coord.packaging.clone(),
        };
        Self {
            group_id: coord.group_id.clone(),
            artifact_id: coord.artifact_id.clone(),
            packaging,
            classifier: coord.classifier.clone(),
        }
    }
}

/// A coordinate compared by its exact text. [`Coord`] compares versions by
/// Maven ordering, so `1.0` and `1.0.0` are equal, and a cache keyed on it
/// hands one spelling the model, POM pin and repository recorded for the
/// other.
#[derive(Debug, Clone)]
pub(crate) struct ExactCoord(pub Coord);

pub(crate) fn coord_text(coord: &Coord) -> (&str, &str, &str, Option<&str>, Option<&str>) {
    (
        coord.group_id.as_str(),
        coord.artifact_id.as_str(),
        coord.version.as_str(),
        coord.packaging.as_deref(),
        coord.classifier.as_deref(),
    )
}

pub(crate) fn same_text(a: &Coord, b: &Coord) -> bool {
    coord_text(a) == coord_text(b)
}

impl PartialEq for ExactCoord {
    fn eq(&self, other: &Self) -> bool {
        same_text(&self.0, &other.0)
    }
}

impl Eq for ExactCoord {}

impl std::hash::Hash for ExactCoord {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        coord_text(&self.0).hash(state);
    }
}

/// Dependency graph storing resolved artifacts and their relationships.
///
/// A `petgraph::Graph` (directed adjacency list) that only grows during
/// resolution: a node whose winner is replaced keeps its index, and a node
/// that leaves the resolution loses its outgoing edges and is no longer
/// reachable from the root.
#[derive(Debug, Clone)]
pub(crate) struct Graph {
    graph: PetGraph<Node, Edge, Directed>,
    root: NodeIndex,
}

impl Graph {
    pub(crate) fn new(root: Node) -> Self {
        let capacity = 256;
        let mut graph = PetGraph::with_capacity(capacity, capacity);
        let root_index = graph.add_node(root);
        Self {
            graph,
            root: root_index,
        }
    }

    pub(crate) fn root(&self) -> NodeIndex {
        self.root
    }

    pub(crate) fn node(&self, idx: NodeIndex) -> Option<&Node> {
        self.graph.node_weight(idx)
    }

    pub(crate) fn node_mut(&mut self, idx: NodeIndex) -> Option<&mut Node> {
        self.graph.node_weight_mut(idx)
    }

    /// `group:artifact:version` of each node from a direct dependency down
    /// to the one that declares `idx`, through the declarations that won.
    pub(crate) fn declared_via(&self, idx: NodeIndex) -> Vec<String> {
        let reachable = self.reachable();
        let parent = |idx: NodeIndex| {
            (self.graph[idx].winner_parent).or_else(|| {
                (self.graph.neighbors_directed(idx, Incoming))
                    .find(|parent| reachable.contains(parent))
            })
        };
        let mut via = Vec::new();
        let mut at = parent(idx);
        while let Some(node) = at.filter(|&node| node != self.root) {
            if via.len() == self.graph.node_count() {
                break;
            }
            let coord = &self.graph[node].coord;
            via.push(format!(
                "{}:{}:{}",
                coord.group_id, coord.artifact_id, coord.version
            ));
            at = parent(node);
        }
        via.reverse();
        via
    }

    #[cfg(test)]
    pub(crate) fn node_index(&self, key: &CoordKey) -> Option<NodeIndex> {
        let mut bfs = Bfs::new(&self.graph, self.root);
        while let Some(node) = bfs.next(&self.graph) {
            if node != self.root && &CoordKey::from(&self.graph[node].coord) == key {
                return Some(node);
            }
        }
        None
    }

    pub(crate) fn insert_node(&mut self, node: Node) -> NodeIndex {
        self.graph.add_node(node)
    }

    pub(crate) fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: Edge) -> EdgeIndex {
        // Requeues and repeated paths must not multiply a declaration's edge.
        if let Some(existing) = self
            .graph
            .edges_connecting(from, to)
            .find(|e| e.weight() == &edge)
        {
            return existing.id();
        }
        self.graph.add_edge(from, to, edge)
    }

    pub(crate) fn remove_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: &Edge) {
        let existing = self
            .graph
            .edges_connecting(from, to)
            .find(|e| e.weight() == edge)
            .map(|e| e.id());
        if let Some(existing) = existing {
            self.graph.remove_edge(existing);
        }
    }

    /// Drop every edge out of `node`.
    pub(crate) fn clear_outgoing(&mut self, node: NodeIndex) {
        while let Some(edge) = self.graph.edges(node).next().map(|e| e.id()) {
            self.graph.remove_edge(edge);
        }
    }

    /// Drop every edge into `node`.
    pub(crate) fn clear_incoming(&mut self, node: NodeIndex) {
        while let Some(edge) = self
            .graph
            .edges_directed(node, Incoming)
            .next()
            .map(|e| e.id())
        {
            self.graph.remove_edge(edge);
        }
    }

    /// Point every edge into `from` at `to` instead.
    pub(crate) fn retarget_incoming(&mut self, from: NodeIndex, to: NodeIndex) {
        // Removing an edge renumbers another, so take them one at a time.
        while let Some((id, source)) = self
            .graph
            .edges_directed(from, Incoming)
            .next()
            .map(|e| (e.id(), e.source()))
        {
            if let Some(edge) = self.graph.remove_edge(id) {
                self.add_edge(source, to, edge);
            }
        }
    }

    /// The first declaration of each direct node in the module.
    pub(crate) fn direct_edges(&self) -> HashMap<NodeIndex, &Edge> {
        let mut first: HashMap<NodeIndex, &Edge> = HashMap::new();
        // `edges` lists the latest first, so of two edges with no place the
        // older one wins.
        for edge in self.graph.edges(self.root) {
            let found = edge.weight();
            first
                .entry(edge.target())
                .and_modify(|current| {
                    if found.declared <= current.declared {
                        *current = found;
                    }
                })
                .or_insert(found);
        }
        first
    }

    /// Give each reachable node the scope Maven's JavaScopeSelector picks
    /// once mediation is done: `system` for a system file, else the scope of
    /// the first direct declaration, else the widest the node has below its
    /// parents, each at the scope picked for it. Nodes are picked in the
    /// order Maven's ConflictIdSorter resolves their groups, and a node where
    /// that order breaks a cycle gathers as Maven's ConflictResolver does.
    ///
    /// Two differences remain, both only where groups form cycles. Maven
    /// gathers below the losing versions of a group it resolves later, and
    /// raeva reads no POM below a losing version. Maven also walks each
    /// occurrence of a dependency in its unmerged graph, which can number
    /// groups, and so record cycles, other than this walk of merged nodes.
    pub(crate) fn select_scopes(&mut self) -> Result<(), ResolveError> {
        let root = self.root;
        let count = self.graph.node_count();
        let groups = ConflictOrder::of(self);
        let mut picked: Vec<Option<Scope>> = vec![None; count];
        picked[root.index()] = Some(self.graph[root].scope);
        for (node, edge) in self.direct_edges() {
            picked[node.index()] = Some(edge.scope_below(self.graph[root].scope));
        }
        for &node in &groups.order {
            if self.graph[node].local {
                picked[node.index()] = Some(Scope::System);
            }
        }
        let mut cycles: Option<Vec<Vec<NodeIndex>>> = None;
        let mut ancestors = vec![false; count];
        let mut done = vec![false; count];
        done[root.index()] = true;
        let mut in_degree = groups.in_degree.clone();
        let mut ready: Vec<(NodeIndex, bool)> = (groups.order.iter())
            .filter(|node| in_degree[node.index()] == 0)
            .map(|&node| (node, false))
            .collect();
        loop {
            while let Some((node, broken)) = ready.pop() {
                if done[node.index()] {
                    continue;
                }
                // Maven gathers for a group through every group resolved so
                // far and through those of the cycles found through it.
                for cycle in cycles
                    .iter()
                    .flatten()
                    .filter(|cycle| cycle.contains(&node))
                {
                    for member in cycle {
                        ancestors[member.index()] = true;
                    }
                }
                if picked[node.index()].is_none() {
                    let scope = self.pick_scope(node, broken, &picked, &done, &ancestors)?;
                    picked[node.index()] = Some(scope);
                }
                done[node.index()] = true;
                ancestors[node.index()] = true;
                for &child in &groups.children[node.index()] {
                    let left = &mut in_degree[child.index()];
                    *left = left.saturating_sub(1);
                    if *left == 0 {
                        ready.push((child, false));
                    }
                }
            }
            // A cycle: Maven goes on at the nearest group left.
            let Some(&nearest) = (groups.order.iter())
                .filter(|node| !done[node.index()])
                .min_by_key(|node| (groups.depth[node.index()], in_degree[node.index()]))
            else {
                break;
            };
            cycles.get_or_insert_with(|| groups.cycles());
            in_degree[nearest.index()] = 0;
            ready.push((nearest, true));
        }
        for (node, scope) in self.graph.node_weights_mut().zip(picked) {
            if let Some(scope) = scope {
                node.scope = scope;
            }
        }
        Ok(())
    }

    /// The widest scope `node` has below its parents. A node whose parents
    /// are not all picked, where Maven broke a cycle, takes the scopes of
    /// Maven's gathering instead: depth first from the root in declaration
    /// order, never past `node`, only through `ancestors` and the winning
    /// occurrence of a resolved one, never to a node an exclusion on the path
    /// names, cut where a path comes back to a node on it, and through a node
    /// again only at a scope and exclusions it has not had.
    fn pick_scope(
        &self,
        node: NodeIndex,
        broken: bool,
        picked: &[Option<Scope>],
        done: &[bool],
        ancestors: &[bool],
    ) -> Result<Scope, ResolveError> {
        let mut widest: Option<Scope> = None;
        let mut offer = |scope: Scope| {
            // Maven drops a `system` path's scope from a node whose winner is
            // no system file.
            if scope != Scope::System && widest.is_none_or(|current| width(scope) > width(current))
            {
                widest = Some(scope);
            }
        };
        if !broken {
            for edge in self.graph.edges_directed(node, Incoming) {
                if let Some(parent) = picked[edge.source().index()] {
                    offer(edge.weight().scope_below(parent));
                }
            }
        } else {
            let start = picked[self.root.index()].expect("root picked");
            let none: Arc<[ExclusionKey]> = Arc::from([]);
            let mut seen = HashSet::from([(self.root, start, Arc::clone(&none))]);
            let mut on_path = HashSet::from([self.root]);
            // Whether an exclusion names `node` or an ancestor, the only
            // nodes the walk reaches.
            let names_gathered = |exclusion: &ExclusionKey| {
                self.graph.node_indices().any(|idx| {
                    let coord = &self.graph[idx].coord;
                    (idx == node || ancestors[idx.index()])
                        && excludes(
                            std::slice::from_ref(exclusion),
                            coord.group_id.as_str(),
                            coord.artifact_id.as_str(),
                        )
                })
            };
            let mut stack = vec![(
                self.root,
                start,
                Arc::clone(&none),
                self.graph.edges(self.root).collect::<Vec<_>>(),
            )];
            while let Some((from, scope, excluded, edges)) = stack.last_mut() {
                let (from, scope, excluded) = (*from, *scope, Arc::clone(excluded));
                // `edges` lists the latest first, so popping takes them in
                // declaration order.
                let Some(edge) = edges.pop() else {
                    on_path.remove(&from);
                    stack.pop();
                    continue;
                };
                let below = edge.weight().scope_below(scope);
                let child = edge.target();
                // The merged graph keeps an edge another occurrence of
                // `from` added, below which Maven collected nothing.
                let coord = &self.graph[child].coord;
                if excludes(
                    &excluded,
                    coord.group_id.as_str(),
                    coord.artifact_id.as_str(),
                ) {
                    continue;
                }
                if child == node {
                    offer(below);
                    continue;
                }
                // A resolved group is gathered through only below its winner.
                let at = if done[child.index()] {
                    let winner = self.graph[child]
                        .winner_parent
                        .filter(|&parent| self.graph.find_edge(parent, child).is_some());
                    if winner.is_some_and(|parent| parent != from) {
                        continue;
                    }
                    picked[child.index()]
                } else {
                    None
                };
                let excluded =
                    self.gathered_exclusions(&excluded, &edge.weight().exclusions, &names_gathered);
                let scope = at.unwrap_or(below);
                if ancestors[child.index()]
                    && !on_path.contains(&child)
                    && seen.insert((child, scope, Arc::clone(&excluded)))
                {
                    if seen.len() > MAX_GATHER_STATES {
                        let coord = &self.graph[node].coord;
                        return Err(ResolveError::GraphLimitExceeded {
                            what: "states gathering a cycle's scope",
                            limit: MAX_GATHER_STATES as u64,
                            coord: format!("{}:{}", coord.group_id, coord.artifact_id),
                        });
                    }
                    on_path.insert(child);
                    stack.push((child, scope, excluded, self.graph.edges(child).collect()));
                }
            }
        }
        Ok(widest.unwrap_or(self.graph[node].scope))
    }

    /// `parent` with the exclusions of `added` that `names_gathered`
    /// accepts, sorted and without repeats as Maven keys a node's children.
    fn gathered_exclusions(
        &self,
        parent: &Arc<[ExclusionKey]>,
        added: &[Exclusion],
        names_gathered: &impl Fn(&ExclusionKey) -> bool,
    ) -> Arc<[ExclusionKey]> {
        let mut merged = parent.to_vec();
        for exclusion in added.iter().map(ExclusionKey::from) {
            if !merged.contains(&exclusion) && names_gathered(&exclusion) {
                merged.push(exclusion);
            }
        }
        if merged.len() == parent.len() {
            return Arc::clone(parent);
        }
        merged.sort();
        Arc::from(merged)
    }

    pub(crate) fn reachable(&self) -> HashSet<NodeIndex> {
        let mut reachable = HashSet::new();
        let mut bfs = Bfs::new(&self.graph, self.root);
        while let Some(node) = bfs.next(&self.graph) {
            reachable.insert(node);
        }
        reachable
    }

    pub(crate) fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub(crate) fn node_indices(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.node_indices()
    }

    pub(crate) fn edge_references(
        &self,
    ) -> impl Iterator<Item = (NodeIndex, NodeIndex, &Edge)> + '_ {
        self.graph
            .edge_references()
            .map(|edge| (edge.source(), edge.target(), edge.weight()))
    }

    #[cfg(test)]
    pub(crate) fn edges(
        &self,
        from: NodeIndex,
    ) -> impl Iterator<Item = (EdgeIndex, NodeIndex, &Edge)> {
        self.graph.edges(from).map(|edge| {
            let idx = edge.id();
            let target = edge.target();
            (idx, target, edge.weight())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CoordKey;
    use rv_maven_types::Coord;

    /// Maven's JavaScopeDeriver, rows by the parent's scope and columns by
    /// the child's: compile, provided, runtime, test, system. A managed
    /// scope is taken as it is.
    #[test]
    fn scope_below_derives_as_maven_does() {
        use rv_maven_model::Scope::*;
        let children = [Compile, Provided, Runtime, Test, System];
        for (parent, row) in [
            (Compile, [Compile, Provided, Runtime, Test, System]),
            (Provided, [Provided, Provided, Provided, Test, System]),
            (Runtime, [Runtime, Runtime, Runtime, Test, System]),
            (Test, [Test, Test, Test, Test, System]),
            (System, [Provided, Provided, Provided, Test, System]),
        ] {
            for (child, expected) in children.into_iter().zip(row) {
                let edge = |managed_scope| super::Edge {
                    scope: child,
                    managed_scope,
                    declared: None,
                    optional: false,
                    exclusions: Vec::new(),
                    requested: None,
                };
                assert_eq!(
                    edge(false).scope_below(parent),
                    expected,
                    "{parent} {child}"
                );
                assert_eq!(
                    edge(true).scope_below(parent),
                    child,
                    "{parent} {child} managed"
                );
            }
        }
    }

    #[test]
    fn maven_plugin_and_jar_share_mediation_identity_but_classifiers_do_not() {
        let jar = Coord::parse("com.example:plugin:1").unwrap();
        let mut plugin = jar.clone();
        plugin.packaging = Some("maven-plugin".to_string());
        assert_eq!(CoordKey::from(&jar), CoordKey::from(&plugin));

        plugin.classifier = Some("javadoc".to_string());
        assert_ne!(CoordKey::from(&jar), CoordKey::from(&plugin));
    }
}
