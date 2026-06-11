use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;

use petgraph::graph::NodeIndex;
use rv_maven_model::{Dependency, Exclusion, Scope};
use rv_version::{ArtifactId, GroupId, Version};

use crate::error::{ResolveError, Result};
use crate::graph::CoordKey;

/// Upper bound on the work queue. Real-world graphs stay well under 10k
/// items; anything past 100k is almost certainly a pathological cycle or
/// transitive explosion and should fail fast rather than OOM.
const MAX_QUEUE_SIZE: usize = 100_000;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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
    pub(crate) parent: Option<Arc<PathNode>>,
    depth: usize,
}

impl PathNode {
    pub(crate) fn root(key: CoordKey) -> Arc<Self> {
        Arc::new(Self {
            key,
            parent: None,
            depth: 0,
        })
    }

    pub(crate) fn extend(parent: &Arc<PathNode>, key: CoordKey) -> Arc<Self> {
        Arc::new(Self {
            key,
            parent: Some(Arc::clone(parent)),
            depth: parent.depth + 1,
        })
    }

    pub(crate) fn contains(&self, key: &CoordKey) -> bool {
        if &self.key == key {
            return true;
        }
        let mut current = self.parent.as_deref();
        while let Some(node) = current {
            if &node.key == key {
                return true;
            }
            current = node.parent.as_deref();
        }
        false
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
}

#[derive(Debug, Clone)]
pub(crate) struct QueueItem {
    pub(crate) parent: NodeIndex,
    pub(crate) parent_version: Arc<Version>,
    pub(crate) dependency: Arc<Dependency>,
    pub(crate) parent_scope: Scope,
    pub(crate) depth: usize,
    pub(crate) declared_at: u64,
    pub(crate) exclusions: Arc<[ExclusionKey]>,
    pub(crate) path: Arc<PathNode>,
}

impl QueueItem {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        parent: NodeIndex,
        parent_version: Arc<Version>,
        dependency: Arc<Dependency>,
        parent_scope: Scope,
        depth: usize,
        declared_at: u64,
        exclusions: Arc<[ExclusionKey]>,
        path: Arc<PathNode>,
    ) -> Self {
        Self {
            parent,
            parent_version,
            dependency,
            parent_scope,
            depth,
            declared_at,
            exclusions,
            path,
        }
    }

    /// Returns true if this is a platform dependency that should be processed first.
    fn is_platform(&self) -> bool {
        matches!(
            self.dependency.type_.as_deref(),
            Some("platform") | Some("enforced-platform")
        )
    }
}

/// Ordering for the priority queue. BinaryHeap is a max-heap, so we order
/// such that higher-priority items compare as "greater".
///
/// Priority order (highest to lowest):
/// 1. Platform dependencies (processed first for constraint discovery)
/// 2. Lower depth (BFS order for nearest-wins strategy)
/// 3. Lower declared_at (earlier declarations win at same depth)
impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Platform dependencies have highest priority
        let self_platform = self.is_platform();
        let other_platform = other.is_platform();
        match (self_platform, other_platform) {
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => {}
        }

        // Lower depth = higher priority (reverse order for max-heap)
        match self.depth.cmp(&other.depth) {
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Lower declared_at = higher priority (reverse order for max-heap)
        match self.declared_at.cmp(&other.declared_at) {
            Ordering::Less => Ordering::Greater,
            Ordering::Greater => Ordering::Less,
            Ordering::Equal => Ordering::Equal,
        }
    }
}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for QueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.depth == other.depth
            && self.declared_at == other.declared_at
            && self.is_platform() == other.is_platform()
    }
}

impl Eq for QueueItem {}

pub(crate) fn push_queue(queue: &mut BinaryHeap<QueueItem>, item: QueueItem) -> Result<()> {
    if queue.len() >= MAX_QUEUE_SIZE {
        return Err(ResolveError::QueueLimitExceeded {
            limit: MAX_QUEUE_SIZE,
        });
    }

    queue.push(item);
    Ok(())
}

pub(crate) fn is_excluded(dep: &Dependency, exclusions: &[ExclusionKey]) -> bool {
    let dep_group = dep.group_id.trim();
    let dep_artifact = dep.artifact_id.trim();
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
