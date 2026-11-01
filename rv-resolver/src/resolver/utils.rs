//! Free helpers shared across the resolver submodules.
//!
//! Covers lock-data assembly, snapshot timestamp parsing, repository
//! filtering/merging, and artifact fetching.

use std::collections::{HashMap, HashSet};

use rv_lock::LockEdge;
use rv_maven_model::Scope;
use rv_maven_types::{ArtifactCoord, BlobId, Coord, SnapshotStamp, Version};
use rv_repo::{ArtifactRequest, RepoError, Repository};

use super::backend::{CompanionPomOrigin, PomGav, pom_gav};
use crate::context::RepoContext;
use crate::error::{RepoSearchStatus, ResolveError, Result};
use crate::graph::Graph;
use crate::output::{ResolvedArtifact, ResolvedPackage};

pub(super) enum FetchError {
    NotFound {
        searched: Vec<RepoSearchStatus>,
    },
    Failed {
        err: RepoError,
        searched: Vec<RepoSearchStatus>,
    },
}

/// Keep a refusal for the final auth diagnostic, but let other failures take
/// precedence regardless of repository order. A missing file adds no failure.
pub(super) fn remember_search_error(last: &mut Option<RepoError>, err: RepoError) {
    if matches!(err, RepoError::NotFound(_)) {
        return;
    }
    if last.is_none()
        || !matches!(err.status_code(), Some(401 | 403))
        || last
            .as_ref()
            .is_some_and(|err| matches!(err.status_code(), Some(401 | 403)))
    {
        *last = Some(err);
    }
}

/// Fetch an artifact from a list of repositories, trying each in order.
/// Returns the blob hash and the repository that had it, as declared, not
/// the mirror that served it.
///
/// The blob is stored but not indexed: the caller indexes every download of
/// a pass in one batch, so the blobs are made durable together.
pub(super) async fn fetch_artifact_from_repos(
    client: &rv_repo::RepoClient,
    store: &rv_store::Store,
    artifact_req: &ArtifactRequest,
    key: &ArtifactCoord,
    repos: &[Repository],
) -> std::result::Result<(BlobId, rv_store::Origin), FetchError> {
    let mut fallback = rv_repo::AuthFallback::default();
    let mut last_error: Option<RepoError> = None;
    let mut searched: Vec<RepoSearchStatus> = Vec::with_capacity(repos.len());

    let renew =
        rv_maven_types::resolves_through_snapshot_metadata(key.version()) && client.updates();
    for (pos, repo) in repos.iter().enumerate() {
        // Once the repositories before it missed, a remote repository
        // answers with the intact bytes it served before, as the caller's
        // store lookup does for the first one. A `file:` repository is read.
        if pos > 0 && !renew && !client.effective_repository(repo).is_local() {
            let served = served_before(client, store, repo, key)
                .await
                .map_err(|err| FetchError::Failed {
                    err: err.into(),
                    searched: std::mem::take(&mut searched),
                })?;
            if let Some(found) = served {
                let endpoint = client.effective_repository(repo);
                fallback.served(&endpoint, artifact_req, artifact_req.to_path());
                return Ok(found);
            }
        }
        match client
            .fetch_artifact(repo, artifact_req, store, rv_repo::FetchArtifact::default())
            .await
        {
            Ok(fetched) => {
                fallback.served(
                    &client.effective_repository(repo),
                    artifact_req,
                    fetched.path,
                );
                let origin = rv_store::Origin {
                    repo_url: repo.url.clone(),
                    endpoint_url: fetched.served_by,
                    checksum_verified: fetched.checksum_verified,
                    served: true,
                };
                return Ok((fetched.blob, origin));
            }
            Err(err) => {
                fallback.refused(&client.effective_repository(repo), &err);
                searched.push(RepoSearchStatus::from_fetch_error(repo, &err, |repo| {
                    client.effective_repository(repo)
                }));
                // Offline the search goes on as online, through what the
                // store holds from each repository.
                if matches!(err, RepoError::NotFound(_) | RepoError::OfflineNotCached(_)) {
                    remember_search_error(&mut last_error, err);
                    continue;
                }
                if err.moves_to_next_repository() {
                    remember_search_error(&mut last_error, err);
                    continue;
                }
                return Err(FetchError::Failed { err, searched });
            }
        }
    }

    match last_error {
        Some(err) => Err(FetchError::Failed { err, searched }),
        None => Err(FetchError::NotFound { searched }),
    }
}

/// The intact blob the store holds for `key` as `repo` served it, with its
/// origin, when the run's checksum policy accepts it.
async fn served_before(
    client: &rv_repo::RepoClient,
    store: &rv_store::Store,
    repo: &Repository,
    key: &ArtifactCoord,
) -> std::result::Result<Option<(BlobId, rv_store::Origin)>, rv_store::StoreError> {
    let Some((blob, checksum_verified)) = client.served_artifact(store, repo, key).await? else {
        return Ok(None);
    };
    if !store
        .verify_blobs(std::slice::from_ref(&blob), 1)
        .await?
        .contains(&blob)
    {
        return Ok(None);
    }
    let origin = rv_store::Origin {
        repo_url: repo.url.clone(),
        endpoint_url: client.effective_repository(repo).url,
        checksum_verified,
        served: true,
    };
    Ok(Some((blob, origin)))
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

fn lock_scope(scope: Scope) -> rv_lock::Scope {
    match scope {
        Scope::Compile => rv_lock::Scope::Compile,
        Scope::Provided => rv_lock::Scope::Provided,
        Scope::Runtime => rv_lock::Scope::Runtime,
        Scope::Test => rv_lock::Scope::Test,
        Scope::System => rv_lock::Scope::System,
        Scope::Import => rv_lock::Scope::Import,
    }
}

/// The lock rows of every package reachable from the root, in coordinate
/// order, and the edges between them. `companion_pom` names the POM bytes
/// this resolution parsed for a group, artifact and version.
pub(super) fn build_lock_data(
    graph: &Graph,
    companion_pom: impl Fn(&PomGav, &RepoContext) -> Option<(Option<BlobId>, CompanionPomOrigin)>,
) -> Result<(Vec<ResolvedPackage>, Vec<LockEdge>)> {
    tracing::debug!(
        node_count = graph.node_count(),
        edge_count = graph.edge_count(),
        "building lock data from dependency graph"
    );

    let reachable = graph.reachable();

    // Imported BOMs never enter the solver graph, but an ordinary dependency
    // with `<type>pom</type>` is still a real classpath entry in Maven's
    // resolved dependency set and must remain in the lock, as must a
    // `system` dependency, with its interpolated `<systemPath>`.
    let mut nodes: Vec<_> = graph
        .node_indices()
        .filter(|idx| *idx != graph.root() && reachable.contains(idx))
        .filter_map(|idx| graph.node(idx).map(|node| (idx, node)))
        .collect();

    nodes.sort_by_cached_key(|(_, node)| node.coord.to_string());

    let mut index_map = HashMap::with_capacity(nodes.len());
    for (pos, (idx, _)) in nodes.iter().enumerate() {
        index_map.insert(*idx, pos);
    }

    let direct_edges = graph.direct_edges();
    let mut edges = Vec::with_capacity(graph.edge_count());

    for (from, to, weight) in graph.edge_references() {
        if from == graph.root() {
            continue;
        }

        if to == graph.root() {
            continue;
        }

        if let (Some(&from_idx), Some(&to_idx), Some(parent)) =
            (index_map.get(&from), index_map.get(&to), graph.node(from))
        {
            edges.push(LockEdge::new(
                from_idx,
                to_idx,
                Some(lock_scope(weight.scope_below(parent.scope))),
                weight.optional,
            ));
        }
    }

    // Sort edges for deterministic lockfile output. `petgraph::Graph::edge_references()`
    // yields edges in insertion order, which changes whenever the solver visits nodes in
    // a different sequence (e.g. after a batch-ordering refactor). Sorting by
    // (from_idx, to_idx, scope) gives a stable order independent of resolution order.
    edges.sort_by_key(|edge| (edge.from, edge.to, edge.scope, edge.optional));

    // Distinct declarations may collapse to the same serialized relationship.
    edges.dedup();

    let mut packages = Vec::with_capacity(nodes.len());
    for (idx, node) in nodes.iter() {
        let version = node.coord.version.to_string();
        let coordinate = ArtifactCoord::new(
            node.coord.group_id.as_str(),
            node.coord.artifact_id.as_str(),
            &rv_maven_types::snapshot_base_version(&version).unwrap_or_else(|| version.clone()),
            node.coord.packaging.as_deref().unwrap_or("jar"),
            node.coord.classifier.as_deref(),
        );
        let direct_scope = direct_edges.get(idx).map(|edge| lock_scope(edge.scope));
        let scope = lock_scope(node.scope);
        // System-scoped dependencies use local paths, no remote fetch.
        if node.local || node.workspace_module.is_some() {
            packages.push(ResolvedPackage {
                coordinate,
                direct_scope,
                scope,
                workspace_module: node.workspace_module.clone(),
                system_path: node.system_path.clone(),
                artifact: None,
            });
            continue;
        }
        let not_found = || ResolveError::ArtifactNotFound {
            dropped_repos: Vec::new(),
            coord: node.coord.to_string(),
            searched: Vec::new(),
            classifier_like: None,
        };
        let repo_url = node.repo_url.as_ref().ok_or_else(not_found)?;
        let blob = node.checksum.clone().ok_or_else(not_found)?;
        // Every external node in the graph reached it through
        // `fetch_project`, which records a companion-POM identity (including
        // `None` when no repository has the POM). A gap here means the graph
        // and the pin map disagree about what was resolved. Leaving the row
        // unpinned instead would hand the POM choice back to the store's
        // coordinate index.
        let (companion_pom, pom_origin) = companion_pom(&pom_gav(&node.coord), &node.repos)
            .ok_or_else(|| {
                ResolveError::InternalError(format!(
                    "resolved artifact {} has no companion POM recorded by this resolution",
                    resolved_coord(&node.coord)
                ))
            })?;
        ensure_pom_packaging_identity(&node.coord, &blob, companion_pom.as_ref())?;
        let snapshot = match rv_maven_types::TimestampedSnapshot::parse(&version) {
            Some(_) => Some(SnapshotStamp::of_version(&version).ok_or_else(|| {
                ResolveError::UnrecordableSnapshotBuild {
                    coord: resolved_coord(&node.coord),
                }
            })?),
            None => None,
        };
        let pom_base = pom_origin.base && snapshot.is_some();
        packages.push(ResolvedPackage {
            coordinate,
            direct_scope,
            scope,
            workspace_module: None,
            system_path: None,
            artifact: Some(ResolvedArtifact {
                version,
                snapshot,
                pom_base,
                pom_snapshot: pom_origin.snapshot,
                pom_repo_url: (pom_origin.repo_url)
                    .filter(|url| {
                        rv_repo::normalize_repo_url(url) != rv_repo::normalize_repo_url(repo_url)
                    })
                    .map(|url| url.to_string()),
                repo_url: repo_url.to_string(),
                blob,
                companion_pom,
            }),
        });
    }

    tracing::debug!(
        packages = packages.len(),
        edges = edges.len(),
        "built lock data"
    );

    Ok((packages, edges))
}

/// For a `packaging = "pom"` package, require the artifact pin and the
/// companion-POM pin to name the same blob.
///
/// A pom-packaged dependency's artifact IS its POM: one file in the
/// repository, one path in `~/.m2`, and `raeva export-m2` exports it as the
/// primary artifact. The two pins are nonetheless produced by two independent
/// observations, artifact population and the model fetch that built the
/// graph, so they can disagree when the store's coordinate index is repointed
/// between them or the repository republishes the file mid-resolve. Left
/// unchecked, the lockfile records the artifact's bytes under `sha256` and the
/// model's under `pom_sha256`, and export ships the first while claiming the
/// second.
///
/// Rejecting rather than re-fetching to converge matches every other
/// byte-disagreement in this crate (`record_companion_pom_blob`,
/// `persist_support_pom`, `merge_support_pom_provenance`): a resolution that
/// saw two byte sequences for one file used both, and picking a winner after
/// the fact leaves whichever half lost pinned to bytes it never read. A
/// re-fetch could not repair that either, since the graph is already built from
/// the POM bytes while the artifact bytes are already recorded on the node and
/// in the reactor's artifact map.
///
/// A classifier'd row is a different file (`a-v-classifier.pom`) than the
/// coordinate's companion POM, so it is not compared. A row without a
/// companion POM is refused too: the lock pins its file by `pom_sha256`.
pub(super) fn ensure_pom_packaging_identity(
    coord: &Coord,
    artifact_blob: &BlobId,
    pom_blob: Option<&BlobId>,
) -> Result<()> {
    if coord.packaging.as_deref() != Some("pom")
        || !coord.classifier.as_deref().unwrap_or_default().is_empty()
        || pom_blob == Some(artifact_blob)
    {
        return Ok(());
    }
    Err(ResolveError::ConflictingPomPackagedBytes {
        coord: resolved_coord(coord),
        artifact_sha256: artifact_blob.to_string(),
        pom_sha256: pom_blob.map_or_else(|| "none".to_string(), ToString::to_string),
    })
}

/// `group:artifact:version:packaging[:classifier]` with the resolved version.
fn resolved_coord(coord: &Coord) -> String {
    let mut text = format!(
        "{}:{}:{}:{}",
        coord.group_id,
        coord.artifact_id,
        coord.version,
        coord.packaging.as_deref().unwrap_or("jar")
    );
    if let Some(classifier) = coord
        .classifier
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        text.push(':');
        text.push_str(classifier);
    }
    text
}

pub(crate) fn filter_repos_for_version<'a>(
    repos: &'a [Repository],
    version: &str,
    coord: &Coord,
) -> Result<Vec<&'a Repository>> {
    let is_snapshot = rv_maven_types::is_snapshot_version(version);
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
        let repo_names: Vec<_> = repos
            .iter()
            .filter_map(|repo| repo.id.as_deref())
            .map(|id| rv_maven_types::bounded(id).to_string())
            .collect();
        let repos_list = if repo_names.is_empty() {
            "no configured repositories".to_string()
        } else {
            repo_names.join(", ")
        };
        return Err(ResolveError::NoSnapshotRepository {
            coord: coord.to_string(),
            message: format!(
                "none of the configured repositories ({}) have snapshots enabled",
                repos_list
            ),
        });
    }

    Ok(eligible_repos)
}

/// `base` then the repositories of `extra` it does not list yet. One URL
/// stays listed under each of its ids, as each id has its own policies,
/// mirror and credential; the ids themselves are deduplicated when the list
/// is admitted.
pub(crate) fn merge_repos(base: Vec<Repository>, extra: Vec<Repository>) -> Vec<Repository> {
    let total_capacity = base.len() + extra.len();
    let mut seen = HashSet::with_capacity(total_capacity);
    let mut merged: Vec<Repository> = Vec::with_capacity(total_capacity);
    for repo in base.into_iter().chain(extra) {
        if seen.insert((repo.url.clone(), repo.id.clone())) {
            merged.push(repo);
        } else if repo.has_strict_checksum_policy()
            && let Some(existing) = merged
                .iter_mut()
                .find(|r| r.url == repo.url && r.id == repo.id)
        {
            existing.merge_checksum_policies(&repo);
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Edge, Graph, Node};
    use rv_maven_model::Scope;
    use rv_maven_types::Coord;
    use rv_repo::Repository;

    #[test]
    fn auth_search_errors_never_mask_other_failures() {
        let refusal = || RepoError::Unauthorized {
            status: reqwest::StatusCode::UNAUTHORIZED,
            url: "https://private.example/".to_string(),
            sent: None,
        };
        for auth_first in [true, false] {
            let hard = RepoError::HttpStatus {
                status: reqwest::StatusCode::BAD_GATEWAY,
                url: "https://broken.example/".to_string(),
                retry_after: None,
            };
            let errors = if auth_first {
                [refusal(), hard]
            } else {
                [hard, refusal()]
            };
            let mut last = None;
            for error in errors {
                remember_search_error(&mut last, error);
            }
            remember_search_error(&mut last, RepoError::NotFound("missing".to_string()));
            assert_eq!(last.unwrap().status_code(), Some(502));
        }
    }

    #[test]
    fn merge_repos_preserves_explicit_fail_from_either_declaration() {
        let default = Repository::new(None, "https://example.com/", true, true);
        let mut strict = default.clone();
        strict.releases_checksum_policy = rv_config::ChecksumPolicy::Fail;
        strict.snapshots_checksum_policy = rv_config::ChecksumPolicy::Fail;
        for (first, second) in [(default.clone(), strict.clone()), (strict, default)] {
            let repos = merge_repos(vec![first], vec![second]);
            assert_eq!(repos.len(), 1);
            assert_eq!(
                (
                    repos[0].releases_checksum_policy,
                    repos[0].snapshots_checksum_policy
                ),
                (
                    rv_config::ChecksumPolicy::Fail,
                    rv_config::ChecksumPolicy::Fail
                )
            );
        }
    }

    fn node(artifact_id: &str, version: &str) -> Node {
        Node {
            coord: Coord::parse(&format!("com.example:{artifact_id}:{version}")).unwrap(),
            scope: Scope::Compile,
            repo_url: Some(std::sync::Arc::from("https://central.example/")),
            build_repo: None,
            repos: crate::context::RepoContext::default(),
            checksum: Some("a".repeat(64).parse().unwrap()),
            workspace_module: None,
            local: false,
            system_path: None,
            winner_parent: None,
        }
    }

    fn compile_edge() -> Edge {
        Edge {
            scope: Scope::Compile,
            managed_scope: false,
            declared: None,
            optional: false,
            exclusions: Vec::new(),
            requested: None,
        }
    }

    fn graph(nodes: Vec<Node>, edges: &[(usize, usize)]) -> Graph {
        let mut graph = Graph::new(node("root", "1.0"));
        let mut indices = vec![graph.root()];
        indices.extend(nodes.into_iter().map(|node| graph.insert_node(node)));
        for (from, to) in edges {
            graph.add_edge(indices[*from], indices[*to], compile_edge());
        }
        graph
    }

    fn any_pom(_: &PomGav, _: &RepoContext) -> Option<(Option<BlobId>, CompanionPomOrigin)> {
        Some((
            Some(BlobId::from_bytes(b"<project/>")),
            CompanionPomOrigin::default(),
        ))
    }

    /// Each package records the scope picked for it and each edge the scope
    /// Maven derives for the dependency below the scope its parent took:
    /// `x`, which the test dependency `t` reaches first, is compile through
    /// `a`, and so is `x`'s own dependency `y`.
    #[test]
    fn build_lock_data_derives_edge_scopes_from_the_parent_pick() {
        let names = ["t", "a", "b", "x", "y"];
        let mut graph = graph(names.map(|name| node(name, "1.0")).to_vec(), &[]);
        let index = |graph: &Graph, artifact_id: &str| {
            let coord = Coord::parse(&format!("com.example:{artifact_id}:1.0")).unwrap();
            let key = crate::graph::CoordKey::from(&coord);
            graph.node_indices().find(|&i| {
                i != graph.root()
                    && crate::graph::CoordKey::from(&graph.node(i).unwrap().coord) == key
            })
        };
        let root = graph.root();
        let [t, a, b, x, y] = names.map(|name| index(&graph, name).unwrap());
        let test = Edge {
            scope: Scope::Test,
            ..compile_edge()
        };
        graph.add_edge(root, t, test);
        for (from, to) in [(root, a), (t, x), (a, b), (b, x), (x, y)] {
            graph.add_edge(from, to, compile_edge());
        }
        graph.select_scopes().unwrap();
        let (packages, edges) = build_lock_data(&graph, any_pom).unwrap();
        let name = |index: usize| packages[index].coordinate.artifact_id().to_string();
        let edges: Vec<String> = edges
            .iter()
            .map(|e| format!("{}>{}@{}", name(e.from), name(e.to), e.scope.unwrap()))
            .collect();
        assert_eq!(
            edges,
            ["a>b@compile", "b>x@compile", "t>x@test", "x>y@compile"]
        );
        let direct: Vec<String> = packages
            .iter()
            .map(|p| {
                let (artifact, direct) = (p.coordinate.artifact_id(), p.direct_scope);
                format!("{artifact}={direct:?}/{}", p.scope)
            })
            .collect();
        assert_eq!(
            direct,
            [
                "a=Some(Compile)/compile",
                "b=None/compile",
                "t=Some(Test)/test",
                "x=None/compile",
                "y=None/compile"
            ]
        );
    }

    /// One package per node and one edge per distinct serialized declaration
    /// below the root, sorted, so raeva.lock does not depend on the order the
    /// solver inserted them. An explicit POM dependency keeps its row; a
    /// timestamped snapshot is locked under its `-SNAPSHOT` version with its
    /// build and that build's POM. A build number raeva.lock cannot record and
    /// an external node whose POM was never recorded are errors.
    #[test]
    fn build_lock_data_rows() {
        let abc = || vec![node("a", "1.0"), node("b", "1.0"), node("c", "1.0")];
        let direct = [(0, 1), (0, 2), (0, 3)];
        let forward = graph(abc(), &[direct.as_slice(), &[(1, 2), (1, 3)]].concat());
        let reverse = graph(abc(), &[direct.as_slice(), &[(1, 3), (1, 2)]].concat());
        let (_, edges) = build_lock_data(&forward, any_pom).unwrap();
        assert_eq!(edges, build_lock_data(&reverse, any_pom).unwrap().1);
        assert!(edges.is_sorted_by_key(|edge| (edge.from, edge.to, edge.scope)));
        let rows = |graph: &Graph| {
            let (packages, edges) = build_lock_data(graph, any_pom).unwrap();
            let name = |index: usize| packages[index].coordinate.artifact_id().to_string();
            let direct: Vec<String> = packages
                .iter()
                .filter(|package| package.direct_scope.is_some())
                .map(|package| package.coordinate.artifact_id().to_string())
                .collect();
            let edges: Vec<String> = edges
                .iter()
                .map(|e| {
                    format!(
                        "{}>{}{}",
                        name(e.from),
                        name(e.to),
                        if e.optional { "?" } else { "" }
                    )
                })
                .collect();
            (direct.join(" "), edges.join(" "))
        };
        let diamond = graph(abc(), &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        assert_eq!(rows(&diamond), ("a b".into(), "a>c b>c".into()));
        let mut repeated = graph(vec![node("a", "1.0"), node("b", "1.0")], &[(0, 1), (1, 2)]);
        let index = |graph: &Graph, artifact_id: &str| {
            let coord = Coord::parse(&format!("com.example:{artifact_id}:1.0")).unwrap();
            graph
                .node_index(&crate::graph::CoordKey::from(&coord))
                .unwrap()
        };
        let (a, b) = (index(&repeated, "a"), index(&repeated, "b"));
        let ranged = Edge {
            requested: Some("[1,2)".into()),
            ..compile_edge()
        };
        repeated.add_edge(a, b, ranged);
        let optional = Edge {
            optional: true,
            ..compile_edge()
        };
        repeated.add_edge(a, b, optional);
        assert_eq!(rows(&repeated), ("a".into(), "a>b a>b?".into()));

        let mut model = node("model", "1.0");
        model.coord.packaging = Some("pom".to_string());
        model.repo_url = None;
        model.checksum = None;
        model.workspace_module = Some("model/pom.xml".to_string());
        let (packages, _) = build_lock_data(&graph(vec![model], &[(0, 1)]), any_pom).unwrap();
        assert_eq!(packages[0].coordinate.extension(), "pom");
        assert_eq!(packages[0].direct_scope, Some(rv_lock::Scope::Compile));
        assert_eq!(
            packages[0].workspace_module.as_deref(),
            Some("model/pom.xml")
        );

        let timestamped = "1.0-20260720.123253-28";
        let pom = BlobId::from_bytes(b"<project/>");
        let (packages, _) = build_lock_data(
            &graph(vec![node("demo", timestamped)], &[(0, 1)]),
            |gav, _| {
                (gav.2 == timestamped).then(|| (Some(pom.clone()), CompanionPomOrigin::default()))
            },
        )
        .unwrap();
        assert_eq!(packages[0].coordinate.version(), "1.0-SNAPSHOT");
        let artifact = packages[0].artifact.as_ref().expect("an external artifact");
        assert_eq!(artifact.version, timestamped);
        assert_eq!(
            artifact.snapshot.as_ref().map(|stamp| stamp.build()),
            Some(28)
        );
        assert_eq!(artifact.companion_pom.as_ref(), Some(&pom));

        let huge = graph(
            vec![node("demo", "1.0-20260720.123253-4294967296")],
            &[(0, 1)],
        );
        assert_eq!(
            build_lock_data(&huge, any_pom).unwrap_err().to_string(),
            "snapshot com.example:demo:1.0-20260720.123253-4294967296:jar has a build number \
             above 4294967295, which raeva.lock cannot record"
        );
        let error = build_lock_data(&graph(vec![node("demo", "1.0")], &[(0, 1)]), |_, _| None)
            .expect_err("no POM was recorded");
        assert!(
            matches!(&error, ResolveError::InternalError(message) if message.contains("com.example:demo:1.0:jar")),
            "{error:?}"
        );
        // A POM no repository has leaves the row without a companion POM.
        let (packages, _) =
            build_lock_data(&graph(vec![node("demo", "1.0")], &[(0, 1)]), |_, _| {
                Some((None, CompanionPomOrigin::default()))
            })
            .unwrap();
        let artifact = packages[0].artifact.as_ref().expect("an external artifact");
        assert_eq!(artifact.companion_pom, None);
    }

    /// A version is fetched only from repositories enabled for its kind. A
    /// snapshot with none fails clearly, naming the configured repositories,
    /// instead of failing later inside the repository client.
    #[test]
    fn versions_are_fetched_from_repositories_of_their_kind() {
        let central = Repository::new(
            Some("central".to_string()),
            "https://central.example/",
            true,
            false,
        );
        let releases = Repository::new(
            Some("releases".to_string()),
            "https://releases.example/",
            true,
            false,
        );
        let snapshots = Repository::new(
            Some("snapshots".to_string()),
            "https://snapshots.example/",
            false,
            true,
        );
        let eligible = |repos: &[Repository], version: &str| {
            let coord = Coord::parse(&format!("g:a:{version}")).unwrap();
            filter_repos_for_version(repos, version, &coord).map(|repos| {
                repos
                    .iter()
                    .map(|repo| repo.id.clone().unwrap())
                    .collect::<Vec<_>>()
            })
        };
        let mixed = [central.clone(), snapshots];
        assert_eq!(eligible(&mixed, "1.0").unwrap(), ["central"]);
        assert_eq!(eligible(&mixed, "1.0-SNAPSHOT").unwrap(), ["snapshots"]);
        match eligible(&[central, releases], "1.0-SNAPSHOT") {
            Err(ResolveError::NoSnapshotRepository { coord, message }) => {
                assert!(coord.contains("1.0-SNAPSHOT"), "{coord}");
                for part in ["central", "releases", "snapshots enabled"] {
                    assert!(message.contains(part), "{message}");
                }
            }
            other => panic!("expected NoSnapshotRepository, got {other:?}"),
        }
    }
}
