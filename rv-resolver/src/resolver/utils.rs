//! Free helpers shared across the resolver submodules.
//!
//! Covers lock-data assembly, snapshot timestamp parsing, repository
//! filtering/merging, and artifact fetching.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rv_config::{LockEdge, LockPackage};
use rv_maven_model::Scope;
use rv_repo::{ArtifactRequest, RepoError, Repository};
use rv_store::ArtifactKey;
use rv_version::{Coord, Version};

use crate::error::{RepoSearchStatus, ResolveError, Result};
use crate::graph::Graph;

/// Internal error type for artifact fetching.
pub(super) enum FetchError {
    NotFound {
        searched: Vec<RepoSearchStatus>,
    },
    Transient {
        err: RepoError,
        searched: Vec<RepoSearchStatus>,
    },
    Fatal {
        err: RepoError,
        searched: Vec<RepoSearchStatus>,
    },
}

/// Fetch an artifact from a list of repositories, trying each in order.
/// Returns the blob hash and the repository URL on success.
///
/// GC race: the persist and the index commit go through
/// `fetch_artifact_to_store_and_index`, which funnels both through one held
/// `StoreLock`. The legacy two-step `fetch_artifact_to_store` then
/// `Store::add_artifact` left a window in which a concurrent
/// `Store::prune_blobs` could delete the freshly-persisted blob before the
/// index row was written, so the index pointed at an already-gone blob. The
/// atomic helper closes that window and
/// matches the path used by `rv_repo::sync`. A store-side failure surfaces as
/// `RepoError::Store`, which is non-transient and therefore classified as
/// `FetchError::Fatal` by the loop below.
pub(super) async fn fetch_artifact_from_repos(
    client: &rv_repo::RepoClient,
    store: &rv_store::Store,
    artifact_req: &ArtifactRequest,
    key: &ArtifactKey,
    repos: &[Repository],
) -> std::result::Result<(String, String), FetchError> {
    let mut last_error: Option<RepoError> = None;
    let mut searched: Vec<RepoSearchStatus> = Vec::with_capacity(repos.len());

    for repo in repos {
        match client
            .fetch_artifact_to_store_and_index_with_repository(repo, artifact_req, store, key)
            .await
        {
            Ok((blob, serving_repository)) => {
                return Ok((blob.to_string(), serving_repository));
            }
            Err(err) => {
                searched.push(RepoSearchStatus::from_error(repo.url.as_str(), &err));
                if matches!(err, RepoError::NotFound(_)) {
                    continue;
                }
                if err.is_transient() {
                    last_error = Some(err);
                    continue;
                }
                return Err(FetchError::Fatal { err, searched });
            }
        }
    }

    match last_error {
        Some(err) => Err(FetchError::Transient { err, searched }),
        None => Err(FetchError::NotFound { searched }),
    }
}

pub(super) fn dummy_coord(group_id: &str, artifact_id: &str) -> Result<Coord> {
    let version = Version::parse("0")?;
    Ok(Coord {
        group_id: group_id.into(),
        artifact_id: artifact_id.into(),
        version,
        packaging: None,
        classifier: None,
    })
}

pub(super) fn build_lock_data(graph: &Graph) -> Result<(Vec<LockPackage>, Vec<LockEdge>)> {
    tracing::debug!(
        node_count = graph.node_count(),
        edge_count = graph.graph().edge_count(),
        "building lock data from dependency graph"
    );

    // Compute reachable nodes from root via BFS to exclude orphaned nodes
    // left behind when version eviction removes outgoing edges.
    let reachable: HashSet<NodeIndex> = {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(graph.root());
        visited.insert(graph.root());
        while let Some(node) = queue.pop_front() {
            for edge in graph.graph().edges(node) {
                let target = edge.target();
                if visited.insert(target) {
                    queue.push_back(target);
                }
            }
        }
        visited
    };

    // Imported BOMs never enter the solver graph, but an ordinary dependency
    // with `<type>pom</type>` is still a real classpath entry in Maven's
    // resolved dependency set and must remain in the lock.
    let mut nodes: Vec<_> = graph
        .node_indices()
        .filter(|idx| *idx != graph.root() && reachable.contains(idx))
        .filter_map(|idx| {
            graph.node(idx).and_then(|node| {
                if node.local {
                    return None;
                }
                Some((idx, node))
            })
        })
        .collect();

    nodes.sort_by_cached_key(|(_, node)| node.coord.to_string());

    let mut index_map = HashMap::with_capacity(nodes.len());
    for (pos, (idx, _)) in nodes.iter().enumerate() {
        index_map.insert(*idx, pos);
    }

    // Single pass over edges: collect direct dependencies and build edge list
    let mut direct_deps: HashMap<NodeIndex, Scope> = HashMap::new();
    let mut edges = Vec::with_capacity(graph.graph().edge_count());

    for edge in graph.graph().edge_references() {
        let from = edge.source();
        let to = edge.target();

        if from == graph.root() {
            direct_deps.insert(to, edge.weight().scope);
            continue;
        }

        if to == graph.root() {
            continue;
        }

        if let (Some(&from_idx), Some(&to_idx)) = (index_map.get(&from), index_map.get(&to)) {
            edges.push(LockEdge {
                from: from_idx,
                to: to_idx,
                scope: Some(edge.weight().scope.to_string()),
                optional: edge.weight().optional,
                extra: std::collections::BTreeMap::new(),
            });
        }
    }

    // Sort edges for deterministic lockfile output. `petgraph::Graph::edge_references()`
    // yields edges in insertion order, which changes whenever the solver visits nodes in
    // a different sequence (e.g. after a batch-ordering refactor). Sorting by
    // (from_idx, to_idx, scope) gives a stable order independent of resolution order.
    edges.sort_by(|a, b| {
        a.from
            .cmp(&b.from)
            .then(a.to.cmp(&b.to))
            .then(a.scope.cmp(&b.scope))
    });

    let mut packages = Vec::with_capacity(nodes.len());
    for (idx, node) in nodes.iter() {
        // System-scoped dependencies use local paths, no remote fetch.
        let (repo_url, checksum, system_path) =
            if node.scope == Scope::System || node.workspace_module.is_some() {
                (String::new(), None, node.system_path.clone())
            } else {
                let repo_url =
                    node.repo_url
                        .as_ref()
                        .ok_or_else(|| ResolveError::ArtifactNotFound {
                            coord: node.coord.to_string(),
                            searched: Vec::new(),
                        })?;
                let checksum =
                    node.checksum
                        .as_ref()
                        .ok_or_else(|| ResolveError::ArtifactNotFound {
                            coord: node.coord.to_string(),
                            searched: Vec::new(),
                        })?;
                (repo_url.to_string(), Some(checksum.clone()), None)
            };

        let direct_scope = direct_deps.get(idx).map(|scope| scope.to_string());
        let snapshot_timestamp = snapshot_timestamp_from_version(node.coord.version.as_str());

        packages.push(LockPackage {
            group_id: node.coord.group_id.to_string(),
            artifact_id: node.coord.artifact_id.to_string(),
            version: node.coord.version.to_string(),
            snapshot_timestamp,
            packaging: node
                .coord
                .packaging
                .clone()
                .unwrap_or_else(|| "jar".to_string()),
            classifier: node.coord.classifier.clone(),
            repo_url,
            checksum,
            system_path,
            direct_scope,
            extra: std::collections::BTreeMap::new(),
        });
    }

    tracing::debug!(
        packages = packages.len(),
        edges = edges.len(),
        "built lock data"
    );

    Ok((packages, edges))
}

fn snapshot_timestamp_from_version(version: &str) -> Option<String> {
    let mut parts = version.rsplitn(3, '-');
    let build = parts.next()?;
    let timestamp = parts.next()?;
    let _base = parts.next()?;
    if build.is_empty() || !build.as_bytes().iter().all(u8::is_ascii_digit) {
        return None;
    }
    if !is_snapshot_timestamp(timestamp) {
        return None;
    }
    Some(timestamp.to_string())
}

fn is_snapshot_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 15 || bytes[8] != b'.' {
        return false;
    }
    for (idx, byte) in bytes.iter().enumerate() {
        if idx == 8 {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
    }
    true
}

pub(crate) fn filter_repos_for_version<'a>(
    repos: &'a [Repository],
    version: &str,
    coord: &Coord,
) -> Result<Vec<&'a Repository>> {
    let is_snapshot = rv_repo::is_snapshot_version(version);
    let eligible_repos: Vec<_> = repos
        .iter()
        .filter(|repo| repo.allows_version(version))
        .collect();

    if eligible_repos.is_empty() && is_snapshot {
        // No snapshot-enabled repository is configured. A "fallback to all
        // repos" branch here would be unreachable: rv_repo::RepoClient::resolve_snapshot_version
        // calls ensure_repo_allows_version before any HTTP request and returns
        // SnapshotsDisabled for every repo that does not enable snapshots, which
        // is reported as a fatal RepoError and aborts the search on the first
        // iteration. Emit a clear configuration error instead.
        let repo_names: Vec<_> = repos.iter().filter_map(|repo| repo.id.as_deref()).collect();
        let repos_list = if repo_names.is_empty() {
            "no configured repositories".to_string()
        } else {
            repo_names.join(", ")
        };
        return Err(ResolveError::NoSnapshotRepository {
            coord: coord.to_string(),
            message: format!(
                "none of the configured repositories ({}) have snapshots enabled. \
                 Add a repository with snapshots = true to resolve SNAPSHOT versions",
                repos_list
            ),
        });
    }

    Ok(eligible_repos)
}

pub(crate) fn merge_repos(base: Vec<Repository>, extra: Vec<Repository>) -> Vec<Repository> {
    let total_capacity = base.len() + extra.len();
    let mut seen = HashSet::with_capacity(total_capacity);
    let mut merged = Vec::with_capacity(total_capacity);
    for repo in base.into_iter().chain(extra) {
        if seen.insert(repo.url.clone()) {
            merged.push(repo);
        }
    }
    merged
}

pub(super) fn select_versions<'a>(metadata: &'a rv_repo::Metadata) -> Vec<Cow<'a, str>> {
    if !metadata.versions.is_empty() {
        return metadata
            .versions
            .iter()
            .map(|value| Cow::Borrowed(value.as_str()))
            .collect();
    }

    let mut fallback: Vec<Cow<'a, str>> = Vec::new();
    if let Some(release) = metadata.release.as_deref() {
        fallback.push(Cow::Borrowed(release));
    }
    if let Some(latest) = metadata.latest.as_deref()
        && !fallback.iter().any(|value| value.as_ref() == latest)
    {
        fallback.push(Cow::Borrowed(latest));
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Edge, Graph, Node};
    use rv_maven_model::Scope;
    use rv_repo::Repository;
    use rv_version::Coord;

    fn coord(version: &str) -> Coord {
        Coord::parse(&format!("g:a:{version}")).unwrap()
    }

    /// Build a minimal graph node for use in tests.
    fn make_node(group_id: &str, artifact_id: &str, version: &str) -> Node {
        Node {
            coord: Coord {
                group_id: group_id.into(),
                artifact_id: artifact_id.into(),
                version: rv_version::Version::parse(version).unwrap(),
                packaging: None,
                classifier: None,
            },
            scope: Scope::Compile,
            repo_url: Some(std::sync::Arc::from("https://central.example/")),
            checksum: Some(rv_config::Checksum {
                algorithm: "sha256".to_string(),
                digest: "a".repeat(64),
            }),
            workspace_module: None,
            local: false,
            system_path: None,
        }
    }

    fn compile_edge() -> Edge {
        Edge {
            scope: Scope::Compile,
            optional: false,
            exclusions: Vec::new(),
            requested: None,
        }
    }

    /// Regression: `edges` in `build_lock_data` must be sorted by (from, to, scope)
    /// so the lockfile is byte-identical regardless of which order the solver
    /// inserted edges into the petgraph (insertion order varies across refactors).
    ///
    /// Build the same three-node graph twice with edges inserted in opposite
    /// orders and assert that the serialised edge lists are identical.
    #[test]
    fn build_lock_data_edges_are_sorted_deterministically() {
        // Graph: root --compile--> a --compile--> b
        //                       \--compile--> b   (also direct edge a→b plus root→b)
        // We build two identical graphs but insert the transitive edges (a→b and a→c)
        // in opposite orders, then verify the edges vec is the same in both cases.

        let root_node = make_node("com.example", "root", "1.0");
        let a_node = make_node("com.example", "a", "1.0");
        let b_node = make_node("com.example", "b", "1.0");
        let c_node = make_node("com.example", "c", "1.0");

        // Graph 1: edges added in order root→a, root→b, root→c, a→b, a→c
        let mut g1 = Graph::new(root_node.clone());
        let a1 = g1.insert_node(a_node.clone());
        let b1 = g1.insert_node(b_node.clone());
        let c1 = g1.insert_node(c_node.clone());
        let root1 = g1.root();
        g1.add_edge(root1, a1, compile_edge());
        g1.add_edge(root1, b1, compile_edge());
        g1.add_edge(root1, c1, compile_edge());
        g1.add_edge(a1, b1, compile_edge()); // a → b first
        g1.add_edge(a1, c1, compile_edge()); // a → c second

        // Graph 2: same nodes, edges added in reverse transitive order: a→c before a→b
        let mut g2 = Graph::new(root_node);
        let a2 = g2.insert_node(a_node);
        let b2 = g2.insert_node(b_node);
        let c2 = g2.insert_node(c_node);
        let root2 = g2.root();
        g2.add_edge(root2, a2, compile_edge());
        g2.add_edge(root2, b2, compile_edge());
        g2.add_edge(root2, c2, compile_edge());
        g2.add_edge(a2, c2, compile_edge()); // a → c first (reversed)
        g2.add_edge(a2, b2, compile_edge()); // a → b second (reversed)

        let (_, edges1) = build_lock_data(&g1).expect("g1 lock data");
        let (_, edges2) = build_lock_data(&g2).expect("g2 lock data");

        assert_eq!(
            edges1, edges2,
            "edge lists must be identical regardless of insertion order"
        );

        // Verify the sort order: edges should be sorted by (from, to)
        let is_sorted = edges1
            .windows(2)
            .all(|w| (w[0].from, w[0].to, &w[0].scope) <= (w[1].from, w[1].to, &w[1].scope));
        assert!(
            is_sorted,
            "edges must be sorted by (from, to, scope): {edges1:?}"
        );
    }

    #[test]
    fn build_lock_data_keeps_explicit_pom_dependencies() {
        let mut graph = Graph::new(make_node("com.example", "root", "1.0"));
        let mut pom_dependency = make_node("com.example", "model", "1.0");
        pom_dependency.coord.packaging = Some("pom".to_string());
        pom_dependency.repo_url = None;
        pom_dependency.checksum = None;
        pom_dependency.workspace_module = Some("model/pom.xml".to_string());
        let dependency = graph.insert_node(pom_dependency);
        graph.add_edge(graph.root(), dependency, compile_edge());

        let (packages, _) = build_lock_data(&graph).expect("lock data");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].packaging, "pom");
        assert_eq!(packages[0].direct_scope.as_deref(), Some("compile"));
    }

    fn release_repo(id: &str, url: &str) -> Repository {
        Repository::new(Some(id.to_string()), url, true, false)
    }

    fn snapshot_repo(id: &str, url: &str) -> Repository {
        Repository::new(Some(id.to_string()), url, false, true)
    }

    /// Regression test: when only release repositories are configured and
    /// a SNAPSHOT version is requested, the caller-facing behaviour is a clear
    /// NoSnapshotRepository error listing the configured repos, rather than a
    /// fallback to all repos that fails inside the repo client (which itself
    /// rejects snapshot-disabled repos).
    #[test]
    fn snapshot_request_with_no_snapshot_repo_errors_clearly() {
        let repos = vec![
            release_repo("central", "https://central.example/"),
            release_repo("releases", "https://releases.example/"),
        ];
        let c = coord("1.0-SNAPSHOT");
        let err = filter_repos_for_version(&repos, "1.0-SNAPSHOT", &c)
            .expect_err("expected NoSnapshotRepository, got success");
        match err {
            ResolveError::NoSnapshotRepository { coord, message } => {
                assert!(coord.contains("1.0-SNAPSHOT"), "coord = {coord}");
                assert!(message.contains("central"), "message = {message}");
                assert!(message.contains("releases"), "message = {message}");
                assert!(message.contains("snapshots enabled"), "message = {message}");
            }
            other => panic!("expected NoSnapshotRepository, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_request_with_snapshot_repo_returns_only_snapshot_repos() {
        let repos = vec![
            release_repo("central", "https://central.example/"),
            snapshot_repo("snapshots", "https://snapshots.example/"),
        ];
        let c = coord("1.0-SNAPSHOT");
        let eligible =
            filter_repos_for_version(&repos, "1.0-SNAPSHOT", &c).expect("filter should succeed");
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].id.as_deref(), Some("snapshots"));
    }

    #[test]
    fn release_request_returns_only_release_repos() {
        let repos = vec![
            release_repo("central", "https://central.example/"),
            snapshot_repo("snapshots", "https://snapshots.example/"),
        ];
        let c = coord("1.0");
        let eligible = filter_repos_for_version(&repos, "1.0", &c).expect("filter should succeed");
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].id.as_deref(), Some("central"));
    }
}
