use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use petgraph::graph::NodeIndex;
use rv_maven_model::{Dependency, Exclusion};
use rv_maven_types::{ArtifactId, Coord, GroupId, Version};

use crate::context::RepoContext;
use crate::error::{ResolveError, Result};
use crate::graph::CoordKey;

/// Bounds on the walk, so a hostile or runaway graph fails rather than
/// exhausting memory or time: items queued at once, depth below the root,
/// and declarations read in all. Large real reactors stay under depth 10 and
/// 3,000 declarations per module.
const MAX_QUEUE_SIZE: usize = 100_000;
const MAX_DEPTH: usize = 1_000;
const MAX_DECLARATIONS: u64 = 1_000_000;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExclusionKey {
    group_id: GroupId,
    artifact_id: ArtifactId,
}

impl From<&Exclusion> for ExclusionKey {
    fn from(exclusion: &Exclusion) -> Self {
        Self {
            group_id: exclusion.group_id.as_str().into(),
            artifact_id: exclusion.artifact_id.as_str().into(),
        }
    }
}

/// Ancestor chain from root down to the current item. The linked list of
/// `Arc<PathNode>` lets every frontier item share its prefix with siblings
/// for free. An alternative, a cloned `HashSet<CoordKey>` mirror per item for
/// O(1) `contains`, costs O(depth) per push and grows quadratically with BFS
/// frontier size. Real-world dependency depths stay under ~20, so walking the
/// parent chain is cheaper than rehashing a fresh set on every extend.
#[derive(Debug)]
pub(crate) struct PathNode {
    pub(crate) key: CoordKey,
    /// The version read here, as `group:artifact:version` names the POM.
    version: Arc<str>,
    pub(crate) parent: Option<Arc<PathNode>>,
    pub(crate) repos: RepoContext,
    depth: usize,
}

impl PathNode {
    pub(crate) fn root(coord: &Coord) -> Arc<Self> {
        Arc::new(Self {
            key: CoordKey::from(coord),
            version: Arc::from(coord.version.as_str()),
            parent: None,
            repos: RepoContext::default(),
            depth: 0,
        })
    }

    /// `coord` read at `version`, below `parent`, with the repositories
    /// its children are searched in.
    pub(crate) fn extend(
        parent: &Arc<PathNode>,
        coord: &Coord,
        version: &Version,
        repos: RepoContext,
    ) -> Arc<Self> {
        Arc::new(Self {
            key: CoordKey::from(coord),
            version: Arc::from(version.as_str()),
            parent: Some(Arc::clone(parent)),
            repos,
            depth: parent.depth + 1,
        })
    }

    /// Whether `key` is on the path below the root. maven-resolver cuts a
    /// cycle only at an ancestor that has a dependency, which the root does
    /// not have, so a dependency on the root's own group and artifact id is
    /// collected like any other.
    pub(crate) fn contains(&self, key: &CoordKey) -> bool {
        self.keys().any(|ancestor| ancestor == key)
    }

    pub(crate) fn format_cycle(&self, next: &CoordKey) -> String {
        let mut parts = Vec::with_capacity(self.depth + 2);
        parts.push(format!("{}:{}", next.group_id, next.artifact_id));
        parts.push(format!("{}:{}", self.key.group_id, self.key.artifact_id));
        let mut current = self.parent.as_ref();
        while let Some(node) = current {
            parts.push(format!("{}:{}", node.key.group_id, node.key.artifact_id));
            current = node.parent.as_ref();
        }
        parts.reverse();
        parts.join(" -> ")
    }

    /// The `group:artifact:version` of each POM from the root down to this
    /// node.
    pub(crate) fn coordinates(&self) -> Vec<String> {
        let mut path: Vec<_> = std::iter::successors(Some(self), |node| node.parent.as_deref())
            .map(|node| {
                format!(
                    "{}:{}:{}",
                    node.key.group_id, node.key.artifact_id, node.version
                )
            })
            .collect();
        path.reverse();
        path
    }

    /// The key and version of each POM below the root, from this node up.
    pub(crate) fn below_root(&self) -> impl Iterator<Item = (&CoordKey, &str)> {
        std::iter::successors(Some(self), |node| node.parent.as_deref())
            .filter(|node| node.parent.is_some())
            .map(|node| (&node.key, &*node.version))
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &CoordKey> {
        self.below_root().map(|(key, _)| key)
    }
}

impl Drop for PathNode {
    /// Unlinks the chain one node at a time instead of recursing down it.
    fn drop(&mut self) {
        let mut next = self.parent.take();
        while let Some(mut node) = next.and_then(Arc::into_inner) {
            next = node.parent.take();
        }
    }
}

/// Where a declaration sits in Maven's dependency tree: the index of each
/// declaration on the way down from the root, sharing its ancestors' with
/// their other descendants. Depth-first order is the lexicographic order of
/// these.
#[derive(Debug, Clone, Default)]
pub(crate) struct TreeOrder(Option<Arc<OrderNode>>);

#[derive(Debug)]
pub(crate) struct OrderNode {
    index: u32,
    len: usize,
    parent: TreeOrder,
}

impl TreeOrder {
    pub(crate) fn child(&self, index: usize) -> Self {
        Self(Some(Arc::new(OrderNode {
            index: u32::try_from(index).unwrap_or(u32::MAX),
            len: self.len() + 1,
            parent: self.clone(),
        })))
    }

    /// The order without its last index; the root's own for the root.
    pub(crate) fn parent(&self) -> &Self {
        self.0.as_ref().map_or(self, |node| &node.parent)
    }

    fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |node| node.len)
    }
}

impl Ord for TreeOrder {
    fn cmp(&self, other: &Self) -> Ordering {
        let by_len = self.len().cmp(&other.len());
        let (mut a, mut b) = (self, other);
        while a.len() > b.len() {
            a = a.parent();
        }
        while b.len() > a.len() {
            b = b.parent();
        }
        // Equal lengths: the topmost index that differs decides, and a
        // shared ancestor ends the walk.
        let mut first = Ordering::Equal;
        while let (Some(x), Some(y)) = (&a.0, &b.0) {
            if Arc::ptr_eq(x, y) {
                break;
            }
            first = x.index.cmp(&y.index).then(first);
            (a, b) = (&x.parent, &y.parent);
        }
        first.then(by_len)
    }
}

impl PartialOrd for TreeOrder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TreeOrder {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for TreeOrder {}

impl Hash for TreeOrder {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut order = self;
        while let Some(node) = &order.0 {
            node.index.hash(state);
            order = &node.parent;
        }
    }
}

impl Drop for OrderNode {
    fn drop(&mut self) {
        let mut next = self.parent.0.take();
        while let Some(mut node) = next.and_then(Arc::into_inner) {
            next = node.parent.0.take();
        }
    }
}

/// A shadow declaration: one Maven gathers below a losing candidate of the
/// group `group`, because the group's winner sits below the key the
/// declaration targets, which therefore was mediated first. It lives as long
/// as that candidate does.
#[derive(Debug, Clone)]
pub(crate) struct ShadowOrigin {
    pub(crate) group: CoordKey,
    pub(crate) instance: u64,
    pub(crate) coord: Coord,
}

#[derive(Debug, Clone)]
pub(crate) struct QueueItem {
    pub(crate) parent: NodeIndex,
    /// The parent's generation when it declared this item; an item from an
    /// older generation is stale.
    pub(crate) parent_generation: u64,
    pub(crate) dependency: Arc<Dependency>,
    /// Management set the dependency's scope.
    pub(crate) managed_scope: bool,
    pub(crate) depth: usize,
    pub(crate) order: TreeOrder,
    pub(crate) declared_at: u64,
    pub(crate) exclusions: Arc<[ExclusionKey]>,
    pub(crate) path: Arc<PathNode>,
    pub(crate) shadow: Option<Arc<ShadowOrigin>>,
}

pub(crate) type SortKey = (usize, TreeOrder, u64);

impl QueueItem {
    /// Breadth-first, then Maven's depth-first order within a depth.
    pub(crate) fn sort_key(&self) -> SortKey {
        (self.depth, self.order.clone(), self.declared_at)
    }
}

impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        (other.depth, &other.order, other.declared_at).cmp(&(
            self.depth,
            &self.order,
            self.declared_at,
        ))
    }
}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for QueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for QueueItem {}

pub(crate) fn push_queue(queue: &mut BinaryHeap<QueueItem>, item: QueueItem) -> Result<()> {
    let exceeded = if queue.len() >= MAX_QUEUE_SIZE {
        Some(("declarations queued at once", MAX_QUEUE_SIZE as u64))
    } else if item.depth > MAX_DEPTH {
        Some(("levels of depth", MAX_DEPTH as u64))
    } else if item.declared_at >= MAX_DECLARATIONS {
        Some(("declarations", MAX_DECLARATIONS))
    } else {
        None
    };
    if let Some((what, limit)) = exceeded {
        return Err(ResolveError::GraphLimitExceeded {
            what,
            limit,
            coord: format!(
                "{}:{}",
                item.dependency.group_id, item.dependency.artifact_id
            ),
        });
    }
    queue.push(item);
    Ok(())
}

pub(crate) fn is_excluded(dep: &Dependency, exclusions: &[ExclusionKey]) -> bool {
    excludes(exclusions, &dep.group_id, &dep.artifact_id)
}

pub(crate) fn excludes(exclusions: &[ExclusionKey], group_id: &str, artifact_id: &str) -> bool {
    let dep_group = group_id.trim();
    let dep_artifact = artifact_id.trim();
    exclusions.iter().any(|ex| {
        let ex_group = ex.group_id.as_str().trim();
        let ex_artifact = ex.artifact_id.as_str().trim();
        // Maven coordinates are case-sensitive; `*` is the only wildcard.
        let group_match = ex_group == "*" || ex_group == dep_group;
        let artifact_match = ex_artifact == "*" || ex_artifact == dep_artifact;
        group_match && artifact_match
    })
}

pub(crate) fn extend_exclusions(
    parent: &Arc<[ExclusionKey]>,
    current: &[Exclusion],
) -> Arc<[ExclusionKey]> {
    if current.is_empty() {
        return Arc::clone(parent);
    }

    let mut merged = Vec::with_capacity(parent.len() + current.len());
    merged.extend_from_slice(parent);
    merged.extend(current.iter().map(ExclusionKey::from));
    Arc::from(merged)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Shared orders sort, compare and hash as the index lists they stand
    /// for, whether or not two of them share nodes.
    #[test]
    fn tree_order_follows_its_index_lists() {
        let lists: Vec<Vec<u32>> = vec![
            vec![],
            vec![0],
            vec![1],
            vec![0, 0],
            vec![0, 1],
            vec![0, 1, 2],
            vec![0, 2, 0],
            vec![1, 0],
            vec![2, 1, 0],
            vec![2, 1, 1],
        ];
        let build = |list: &[u32]| {
            list.iter().fold(TreeOrder::default(), |order, &index| {
                order.child(index as usize)
            })
        };
        let mut shared: HashMap<Vec<u32>, TreeOrder> = HashMap::new();
        for list in &lists {
            let parent = shared.get(&list[..list.len().saturating_sub(1)]).cloned();
            let order = match (parent, list.last()) {
                (Some(parent), Some(&last)) => parent.child(last as usize),
                _ => build(list),
            };
            shared.insert(list.clone(), order);
        }
        let hash = |order: &TreeOrder| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            order.hash(&mut hasher);
            hasher.finish()
        };
        for a in &lists {
            for b in &lists {
                for (x, y) in [(&shared[a], &shared[b]), (&shared[a], &build(b))] {
                    assert_eq!(x.cmp(y), a.cmp(b), "{a:?} vs {b:?}");
                    if a == b {
                        assert_eq!(hash(x), hash(y), "{a:?}");
                    }
                }
            }
            assert_eq!(shared[a].parent(), &build(&a[..a.len().saturating_sub(1)]));
        }
    }

    /// A long chain drops without recursing down it.
    #[test]
    fn long_chains_drop_iteratively() {
        let coord = Coord::parse("g:a:1").unwrap();
        let mut path = PathNode::root(&coord);
        let mut order = TreeOrder::default();
        for _ in 0..1_000_000 {
            path = PathNode::extend(&path, &coord, &coord.version, RepoContext::default());
            order = order.child(0);
        }
        drop((path, order));
    }

    /// Past each bound, a declaration fails naming what it counts.
    #[test]
    fn bounds_name_what_they_count() {
        let coord = Coord::parse("g:a:1").unwrap();
        let item = |depth, declared_at| QueueItem {
            parent: NodeIndex::new(0),
            parent_generation: 0,
            dependency: Arc::new(Dependency {
                group_id: "g".into(),
                artifact_id: "a".into(),
                version: Some("1".into()),
                type_: None,
                classifier: None,
                scope: None,
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
            }),
            managed_scope: false,
            depth,
            order: TreeOrder::default(),
            declared_at,
            exclusions: Arc::from(Vec::new()),
            path: PathNode::root(&coord),
            shadow: None,
        };
        let mut queue = BinaryHeap::new();
        push_queue(&mut queue, item(MAX_DEPTH, MAX_DECLARATIONS - 1)).unwrap();
        for (item, message) in [
            (
                item(MAX_DEPTH + 1, 0),
                "dependency graph exceeds 1000 levels of depth at g:a",
            ),
            (
                item(1, MAX_DECLARATIONS),
                "dependency graph exceeds 1000000 declarations at g:a",
            ),
        ] {
            let err = push_queue(&mut queue, item).unwrap_err();
            assert_eq!(err.to_string(), message);
        }
    }
}
