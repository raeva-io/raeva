use std::sync::Arc;

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
    /// The artifact id is a prefix: only Maven's WagonExcluder matches so.
    prefix: bool,
}

impl From<&Exclusion> for ExclusionKey {
    fn from(exclusion: &Exclusion) -> Self {
        Self {
            group_id: exclusion.group_id.as_str().into(),
            artifact_id: exclusion.artifact_id.as_str().into(),
            prefix: false,
        }
    }
}

impl ExclusionKey {
    /// What Maven's WagonExcluder drops below a Maven 2 core artifact when
    /// it collects a plugin's dependencies.
    fn wagon_providers() -> Self {
        Self {
            group_id: "org.apache.maven.wagon".into(),
            artifact_id: "wagon-".into(),
            prefix: true,
        }
    }
}

/// Whether Maven's WagonExcluder drops wagon providers below `coord`.
pub(crate) fn is_legacy_core(coord: &Coord) -> bool {
    coord.group_id.as_str() == "org.apache.maven"
        && coord.artifact_id.as_str().starts_with("maven-")
        && coord.version.as_str().starts_with("2.")
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

#[derive(Debug, Clone)]
pub(crate) struct QueueItem {
    pub(crate) dependency: Arc<Dependency>,
    /// Management set the dependency's scope.
    pub(crate) managed_scope: bool,
    pub(crate) depth: usize,
    pub(crate) declared_at: u64,
    pub(crate) exclusions: Arc<[ExclusionKey]>,
    pub(crate) path: Arc<PathNode>,
}

/// Fail past a bound of the walk with `queued` items queued and `counted`
/// declarations read before `item`.
pub(crate) fn check_bounds(queued: usize, counted: u64, item: &QueueItem) -> Result<()> {
    let exceeded = if queued >= MAX_QUEUE_SIZE {
        Some(("declarations queued at once", MAX_QUEUE_SIZE as u64))
    } else if item.depth > MAX_DEPTH {
        Some(("levels of depth", MAX_DEPTH as u64))
    } else if counted >= MAX_DECLARATIONS {
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
        let artifact_match = ex_artifact == "*"
            || ex_artifact == dep_artifact
            || (ex.prefix && dep_artifact.starts_with(ex_artifact));
        group_match && artifact_match
    })
}

/// The exclusions below a node: its parent's, its declaration's, and the
/// wagon providers when `drops_wagons`.
pub(crate) fn extend_exclusions(
    parent: &Arc<[ExclusionKey]>,
    current: &[Exclusion],
    drops_wagons: bool,
) -> Arc<[ExclusionKey]> {
    let wagons =
        (drops_wagons && !parent.iter().any(|key| key.prefix)).then(ExclusionKey::wagon_providers);
    if current.is_empty() && wagons.is_none() {
        return Arc::clone(parent);
    }

    let mut merged = Vec::with_capacity(parent.len() + current.len() + 1);
    merged.extend_from_slice(parent);
    merged.extend(current.iter().map(ExclusionKey::from));
    merged.extend(wagons);
    Arc::from(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A long chain drops without recursing down it.
    #[test]
    fn long_chains_drop_iteratively() {
        let coord = Coord::parse("g:a:1").unwrap();
        let mut path = PathNode::root(&coord);
        for _ in 0..1_000_000 {
            path = PathNode::extend(&path, &coord, &coord.version, RepoContext::default());
        }
        drop(path);
    }

    /// Past each bound, a declaration fails naming what it counts.
    #[test]
    fn bounds_name_what_they_count() {
        let coord = Coord::parse("g:a:1").unwrap();
        let item = |depth, declared_at| QueueItem {
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
                system_path_from_project: Default::default(),
                origin: Default::default(),
            }),
            managed_scope: false,
            depth,
            declared_at,
            exclusions: Arc::from(Vec::new()),
            path: PathNode::root(&coord),
        };
        check_bounds(0, MAX_DECLARATIONS - 1, &item(MAX_DEPTH, 0)).unwrap();
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
            let err = check_bounds(0, item.declared_at, &item).unwrap_err();
            assert_eq!(err.to_string(), message);
        }
    }
}
