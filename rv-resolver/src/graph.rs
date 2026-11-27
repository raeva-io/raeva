use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use petgraph::Directed;
use petgraph::Direction::Incoming;
use petgraph::graph::{EdgeIndex, Graph as PetGraph, NodeIndex};
use petgraph::visit::{Bfs, EdgeRef};

use rv_maven_model::{Dependency, Exclusion, Scope};
use rv_maven_types::{ArtifactId, BlobId, Coord, GroupId, Sha256};
use rv_repo::Repository;

/// One configured repository, by id and URL: one URL can be declared under
/// two ids that resolve to different mirrors and credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoRef {
    pub id: Option<Arc<str>>,
    pub url: Arc<str>,
    /// The build is the one raeva.lock pins, which this repository was
    /// taken to hold because the lock records it there, unread: the next
    /// repositories may serve it when this one does not.
    pub pinned: bool,
}

impl RepoRef {
    pub(crate) fn of(repo: &Repository) -> Self {
        Self {
            id: repo.id.as_deref().map(Arc::from),
            url: Arc::from(repo.url.as_str()),
            pinned: false,
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
    /// The `<type>` of the declaration that won mediation, when it is not
    /// the extension `coord` holds.
    pub type_: Option<String>,
    /// The scope conflict resolution picks.
    pub scope: Scope,
    /// The optionality conflict resolution picks, as Maven's
    /// SimpleOptionalitySelector does.
    pub optional: bool,
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
    /// Where the root's dependency management that supplied the winning
    /// declaration's version declares it, when it did.
    pub version_origin: rv_maven_model::ManagedOrigin,
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
            (_, Scope::System | Scope::Test) | (Scope::Compile | Scope::Empty, _) => self.scope,
            (Scope::Test | Scope::Runtime, _) => parent,
            (Scope::Provided | Scope::System, _) => Scope::Provided,
            (Scope::Import | Scope::CompileOnly | Scope::Other(_), _) => Scope::Runtime,
        }
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

/// An artifact as maven-resolver 1.9's DataPool keys its descriptor:
/// `AbstractArtifact.equals`, so the exact version text and the declared
/// type, whose properties a `maven-plugin` and a `jar` differ in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DescriptorKey {
    group_id: String,
    artifact_id: String,
    version: String,
    extension: Option<String>,
    classifier: Option<String>,
    type_: String,
}

impl DescriptorKey {
    /// `coord` as `dependency` declares it.
    pub(crate) fn of(coord: &Coord, dependency: &Dependency) -> Self {
        let type_ = (dependency.type_.as_deref()).filter(|type_| !type_.is_empty());
        Self {
            group_id: coord.group_id.to_string(),
            artifact_id: coord.artifact_id.to_string(),
            version: coord.version.to_string(),
            extension: coord.packaging.clone(),
            classifier: coord.classifier.clone(),
            type_: type_.unwrap_or("jar").to_string(),
        }
    }
}

impl fmt::Display for DescriptorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.group_id, self.artifact_id)?;
        if self.extension.is_some() || self.classifier.is_some() {
            write!(f, ":{}", self.extension.as_deref().unwrap_or("jar"))?;
        }
        if let Some(classifier) = &self.classifier {
            write!(f, ":{classifier}")?;
        }
        write!(f, ":{}", self.version)?;
        if self.type_ != self.extension.as_deref().unwrap_or("jar") {
            write!(f, " (type {})", self.type_)?;
        }
        Ok(())
    }
}

/// What a walk read as an artifact's POM, as Maven 3.9 pools it for the
/// whole build. Two readings are alike when they are both [`Self::Empty`]
/// or name the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PomReading {
    /// No POM, or one that gives Maven nothing to keep: no dependencies,
    /// managed dependencies, relocation or repositories.
    Empty,
    /// The POM's digest, or for a relocation that of each POM along it,
    /// `None` for one a repository lacks.
    Bytes(Vec<Option<BlobId>>),
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
    /// In the Maven 3.9 mode, the POM of each artifact the walk read from
    /// repositories, losers' and SNAPSHOT builds' included.
    pub descriptors: BTreeMap<DescriptorKey, PomReading>,
}

impl Graph {
    pub(crate) fn new(root: Node) -> Self {
        let capacity = 256;
        let mut graph = PetGraph::with_capacity(capacity, capacity);
        let root_index = graph.add_node(root);
        Self {
            graph,
            root: root_index,
            descriptors: BTreeMap::new(),
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
