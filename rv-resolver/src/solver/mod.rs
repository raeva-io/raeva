use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::stream::{self, StreamExt};
use rv_maven_model::{Dependency, DependencyManagement, Project, Scope};
use rv_version::{Coord, Version, VersionReq};

use crate::ResolutionStrategy;
use crate::error::{DroppedRepo, RepoSearchStatus, ResolveError, Result};
use crate::graph::{CoordKey, Edge, Graph, Node};

mod platform;
mod queue;
mod relocation;

pub(crate) use self::platform::{ConstraintVersion, PlatformConstraint, PlatformConstraints};
use self::platform::{merge_platform_constraints, resolve_version_str};
use self::queue::{ExclusionKey, PathNode, QueueItem, extend_exclusions, is_excluded, push_queue};

#[cfg(test)]
mod tests;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Default parallel POM fetches. 32 saturates most home and corporate
/// connections without overwhelming the typical Maven repository's per-host
/// rate limit.
const DEFAULT_FETCH_CONCURRENCY: usize = 32;
/// Hard ceiling on fetch concurrency to keep file-descriptor and socket
/// usage bounded even when users override the default. Aligned with the
/// artifact-fetch ceiling in `Resolver::populate_artifacts`
/// (`network.concurrency.clamp(1, MAX_FETCH_CONCURRENCY)`) so the POM-fetch and
/// artifact-fetch stages share one cap instead of silently throttling POM
/// fetches to half.
pub(crate) const MAX_FETCH_CONCURRENCY: usize = 128;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedVersion {
    pub version: Version,
    pub repo_url: Option<Arc<str>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedProject {
    pub project: Project,
    pub repo_url: Option<Arc<str>>,
    pub workspace_module: Option<String>,
    pub platform_constraints: Option<PlatformConstraints>,
}

pub(crate) trait Backend {
    fn workspace_module(&self, _coord: &Coord) -> Option<String> {
        None
    }

    fn resolve_version<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
    ) -> BoxFuture<'a, Result<ResolvedVersion>>;

    /// All matching versions in ascending Maven version order.
    /// Range alternatives are siblings and must survive until conflict mediation.
    fn resolve_versions<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
    ) -> BoxFuture<'a, Result<Vec<ResolvedVersion>>> {
        let resolution = self.resolve_version(group_id, artifact_id, req);
        Box::pin(async move { resolution.await.map(|v| vec![v]) })
    }

    fn resolve_snapshot_version<'a>(
        &'a self,
        coord: &'a Coord,
    ) -> BoxFuture<'a, Result<ResolvedVersion>> {
        Box::pin(async move {
            Ok(ResolvedVersion {
                version: coord.version.clone(),
                repo_url: None,
            })
        })
    }

    fn fetch_project<'a>(
        &'a self,
        coord: &'a Coord,
        scope: Scope,
    ) -> BoxFuture<'a, Result<ResolvedProject>>;

    /// Transitive repositories that were ignored but declared by a POM on
    /// `path` (`group:artifact` pairs, root first) and could serve `version`.
    fn dropped_repos_on_path(
        &self,
        _path: &[(String, String)],
        _version: &str,
        _searched: &[RepoSearchStatus],
    ) -> Vec<DroppedRepo> {
        Vec::new()
    }
}

/// A fetch budget shared by concurrent module solves in one reactor.
///
/// Each share grows as other solves finish. The budget is advisory: a request
/// semaphore could deadlock when `block_on_async` parks a thread whose sibling
/// fetches hold permits and need that thread to progress.
#[derive(Debug)]
pub(crate) struct FetchShare {
    total: usize,
    active: AtomicUsize,
}

impl FetchShare {
    pub(crate) fn new(total: usize) -> Self {
        Self {
            total: total.clamp(1, MAX_FETCH_CONCURRENCY),
            active: AtomicUsize::new(0),
        }
    }

    /// Register one running solve until the guard drops.
    pub(crate) fn enter(self: &Arc<Self>) -> FetchShareGuard {
        self.active.fetch_add(1, Ordering::Relaxed);
        FetchShareGuard(Arc::clone(self))
    }

    pub(crate) fn current(&self) -> usize {
        (self.total / self.active.load(Ordering::Relaxed).max(1)).max(1)
    }
}

pub(crate) struct FetchShareGuard(Arc<FetchShare>);

impl Drop for FetchShareGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct Solver<'a, B: Backend> {
    backend: &'a B,
    strategy: ResolutionStrategy,
    platform_constraints: Option<PlatformConstraints>,
    fetch_concurrency: usize,
    fetch_share: Option<Arc<FetchShare>>,
    /// When true, use full Maven scope transitivity rules (e.g. compile->test = test).
    /// Set for pom.xml sources; false for rv.toml (simplified behavior).
    strict_maven_compat: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SolverRoot {
    pub coord: Coord,
    pub dependencies: Vec<Dependency>,
    pub scope: Scope,
}

impl<'a, B: Backend> Solver<'a, B> {
    pub(crate) fn with_strategy(
        backend: &'a B,
        strategy: ResolutionStrategy,
        platform_constraints: Option<PlatformConstraints>,
    ) -> Self {
        Self {
            backend,
            strategy,
            platform_constraints,
            fetch_concurrency: DEFAULT_FETCH_CONCURRENCY,
            fetch_share: None,
            strict_maven_compat: false,
        }
    }

    pub(crate) fn with_fetch_concurrency(mut self, concurrency: usize) -> Self {
        self.fetch_concurrency = concurrency.clamp(1, MAX_FETCH_CONCURRENCY);
        self
    }

    pub(crate) fn with_fetch_share(mut self, share: Arc<FetchShare>) -> Self {
        self.fetch_share = Some(share);
        self
    }

    /// Current number of items to resolve in parallel.
    fn current_fetch_concurrency(&self) -> usize {
        match &self.fetch_share {
            Some(share) => share.current(),
            None => self.fetch_concurrency.max(1),
        }
    }

    pub(crate) fn with_strict_maven_compat(mut self, enabled: bool) -> Self {
        self.strict_maven_compat = enabled;
        self
    }

    pub(crate) async fn solve(&self, root: SolverRoot) -> Result<Graph> {
        let SolverRoot {
            coord,
            dependencies,
            scope,
        } = root;
        let root_key = CoordKey::from(&coord);
        let root_version = coord.version.clone();
        let root_version_arc = Arc::new(root_version.clone());
        let root_node = Node {
            workspace_module: self.backend.workspace_module(&coord),
            coord,
            scope,
            repo_url: None,
            checksum: None,
            local: false,
            system_path: None,
        };
        let mut graph = Graph::new(root_node);

        // Estimate capacity based on typical dependency expansion factor.
        let estimated_deps = dependencies.len() * 10;
        let mut selected: HashMap<CoordKey, Selected<Option<ResolvedProject>>> =
            HashMap::with_capacity(estimated_deps);
        selected.insert(
            root_key.clone(),
            Selected {
                node: graph.root(),
                version: root_version.clone(),
                hard: Vec::new(),
                candidates: Vec::new(),
                winner: None,
            },
        );
        let mut requirements = HashMap::new();
        let relocation_cache = Mutex::new(HashMap::with_capacity(32));
        let mut platform_constraints =
            Arc::new(self.platform_constraints.clone().unwrap_or_default());
        let fetch_concurrency = self.current_fetch_concurrency();

        let mut next_declared_at: u64 = 0;
        let mut queue = BinaryHeap::with_capacity(estimated_deps);
        let root_path = PathNode::root(root_key.clone());
        let empty_exclusions: Arc<[ExclusionKey]> = Arc::from(Vec::new());
        for dep in dependencies {
            let declared_at = next_declared_at;
            next_declared_at += 1;
            push_queue(
                &mut queue,
                QueueItem::new(
                    graph.root(),
                    Arc::clone(&root_version_arc),
                    Arc::new(dep),
                    scope,
                    1,
                    declared_at,
                    Arc::clone(&empty_exclusions),
                    Arc::clone(&root_path),
                ),
            )?;
        }

        let mut batch: Vec<QueueItem> = Vec::with_capacity(fetch_concurrency);
        loop {
            while let Some(item) = queue.pop() {
                if is_barrier(&item) {
                    if !batch.is_empty() {
                        let current = std::mem::take(&mut batch);
                        process_batch(
                            self,
                            current,
                            &mut graph,
                            &mut selected,
                            &mut requirements,
                            &mut platform_constraints,
                            &mut queue,
                            &mut next_declared_at,
                            &relocation_cache,
                        )
                        .await?;
                    }
                    process_batch(
                        self,
                        vec![item],
                        &mut graph,
                        &mut selected,
                        &mut requirements,
                        &mut platform_constraints,
                        &mut queue,
                        &mut next_declared_at,
                        &relocation_cache,
                    )
                    .await?;
                    continue;
                }

                batch.push(item);
                if batch.len() >= self.current_fetch_concurrency() {
                    let current = std::mem::take(&mut batch);
                    process_batch(
                        self,
                        current,
                        &mut graph,
                        &mut selected,
                        &mut requirements,
                        &mut platform_constraints,
                        &mut queue,
                        &mut next_declared_at,
                        &relocation_cache,
                    )
                    .await?;
                }
            }

            if !batch.is_empty() {
                let current = std::mem::take(&mut batch);
                process_batch(
                    self,
                    current,
                    &mut graph,
                    &mut selected,
                    &mut requirements,
                    &mut platform_constraints,
                    &mut queue,
                    &mut next_declared_at,
                    &relocation_cache,
                )
                .await?;
            }

            if queue.is_empty() {
                break;
            }
        }

        Ok(graph)
    }
}

#[allow(clippy::large_enum_variant)] // Boxing adds complexity; enum is stack-local and short-lived
enum ResolutionOutcome {
    System {
        item: QueueItem,
        coord: Coord,
    },
    Resolved {
        item: QueueItem,
        coord: Coord,
        resolved: ResolvedVersion,
        resolved_project: Option<ResolvedProject>,
        alternatives: Vec<ResolvedVersion>,
        effective_scope: Scope,
        child_scope: Option<Scope>,
        /// Requirement for the final coordinate, reset after relocation.
        requirement: RequestedRequirement,
    },
}

#[derive(Debug, Clone)]
enum RequestedRequirement {
    Exact(Version),
    /// A Maven "soft" pin: a bare `<version>X</version>` that survived
    /// dep-mgmt processing (no covering constraint was found in
    /// `resolve_version_str`). Kept distinct from `Exact` so downstream
    /// mediation can still decide between two competing transitive soft
    /// pins without treating either as hard.
    Soft(Version),
    Ranges(VersionReq),
    DynamicRelease,
    DynamicIntegration,
}

/// Apply the root dependency management's non-version metadata to a transitive
/// dependency (depth >= 2): a managed `<scope>`/`<optional>` fills a blank the
/// dependency left, and managed `<exclusions>` union with the declared set.
/// Depth 1 is the model layer's job, and versions come from
/// `resolve_version_str`.
///
/// Maven's ClassicDependencyManager overrides declared scope but ignores managed `<optional>`.
/// `resolve_item` prunes transitive dependencies using declared values first.
/// A dependency managed to `test` therefore retains its subtree.
fn apply_managed_metadata(constraints: &PlatformConstraints, mut item: QueueItem) -> QueueItem {
    if item.depth <= 1 {
        return item;
    }
    let Some(managed) = constraints.managed(
        &item.dependency.group_id,
        &item.dependency.artifact_id,
        item.dependency.effective_type(),
        item.dependency.effective_classifier(),
    ) else {
        return item;
    };
    if managed.scope.is_none() && managed.exclusions.is_empty() {
        return item;
    }
    let dep = Arc::make_mut(&mut item.dependency);
    if let Some(scope) = &managed.scope {
        dep.scope = Some(scope.clone());
    }
    for exclusion in &managed.exclusions {
        if !dep.exclusions.contains(exclusion) {
            dep.exclusions.push(exclusion.clone());
        }
    }
    item
}

const MAX_RELOCATION_MANAGEMENT_PASSES: usize = 8;

async fn resolve_item<'a, B: Backend>(
    solver: &Solver<'a, B>,
    item: QueueItem,
    constraints: Arc<PlatformConstraints>,
    relocation_cache: &Mutex<HashMap<Coord, Coord>>,
) -> Result<Vec<ResolutionOutcome>> {
    // Maven's scope/optional selectors prune transitive deps on the declared
    // values, before dependency management is applied.
    let declared_scope = item.dependency.effective_scope();
    let declared_optional = item.dependency.effective_optional();
    let item = apply_managed_metadata(constraints.as_ref(), item);
    if is_excluded(&item.dependency, item.exclusions.as_ref()) {
        tracing::debug!(
            group_id = %item.dependency.group_id,
            artifact_id = %item.dependency.artifact_id,
            "excluded dependency skipped"
        );
        return Ok(Vec::new());
    }

    if declared_optional && item.depth > 1 {
        return Ok(Vec::new());
    }

    let dep_scope = item.dependency.effective_scope();

    if dep_scope == Scope::Import {
        return Ok(Vec::new());
    }

    if item.depth > 1
        && matches!(
            declared_scope,
            Scope::Test | Scope::Provided | Scope::System
        )
    {
        return Ok(Vec::new());
    }

    let effective_scope = inherit_scope(item.parent_scope, dep_scope);
    if effective_scope != dep_scope {
        tracing::debug!(
            group_id = %item.dependency.group_id,
            artifact_id = %item.dependency.artifact_id,
            original_scope = ?dep_scope,
            effective_scope = ?effective_scope,
            "scope mediation applied"
        );
    }
    // Per Maven spec:
    // - Direct optional deps (depth=1): the dep IS included, its children ARE queued normally.
    // - Transitive optional deps (depth>1): already skipped above; child_scope=None is moot.
    //
    // `transitive_from` answers "given my parent's effective scope and my
    // declared scope, what scope do I propagate as?". The answer matters
    // both for whether we descend (None drops the subtree) and for the
    // scope our children inherit as their `parent_scope`.
    //
    // A direct `provided` or `test` dep needs a special case: `transitive_from`
    // returns `None` for it (neither scope is transitive), which would drop its
    // compile/runtime children. Maven keeps those children on the provided/test
    // classpath, so a direct provided/test dep descends at its own scope and its
    // children inherit it (a compile child of a test dep is a `test` child).
    // Deeper provided/test transitive edges stay dropped by the `depth > 1` skip
    // above, matching Maven.
    //
    // Direct `optional` deps are handled by the early skip above.
    let child_scope = if declared_optional && item.depth > 1 {
        // Should not reach here (skipped above), but be safe
        None
    } else if matches!(dep_scope, Scope::Provided | Scope::Test) {
        // Maven retains subtrees managed to test or provided scope at that scope.
        Some(dep_scope)
    } else if solver.strict_maven_compat {
        Scope::transitive_from_maven_compat(item.parent_scope, dep_scope)
    } else {
        Scope::transitive_from(item.parent_scope, dep_scope)
    };

    if dep_scope == Scope::System {
        // A system-scoped dependency must carry an explicit version.
        // Without one, surface a MissingVersion error rather than coining a
        // fake "SYSTEM" version that parses into a bogus coordinate and ships
        // a non-existent pin into the graph/lockfile.
        let version_str =
            item.dependency
                .version
                .as_deref()
                .ok_or_else(|| ResolveError::MissingVersion {
                    group_id: item.dependency.group_id.clone(),
                    artifact_id: item.dependency.artifact_id.clone(),
                })?;
        let version = Version::parse(version_str)?;
        let packaging = packaging_opt(item.dependency.effective_type());
        let coord = Coord {
            group_id: item.dependency.group_id.clone().into(),
            artifact_id: item.dependency.artifact_id.clone().into(),
            version,
            packaging,
            classifier: item
                .dependency
                .effective_classifier()
                .map(|s| s.to_string()),
        };
        return Ok(vec![ResolutionOutcome::System { item, coord }]);
    }

    let version_str = resolve_version_str(constraints.as_ref(), &item.dependency, item.depth)?;

    let requirement = parse_requested_requirement(
        &item.dependency.group_id,
        &item.dependency.artifact_id,
        version_str.as_ref(),
    )?;

    let packaging = packaging_opt(item.dependency.effective_type());
    let classifier = item
        .dependency
        .effective_classifier()
        .map(|s| s.to_string());

    let versions = resolve_requirement_versions(
        solver,
        &item.dependency.group_id,
        &item.dependency.artifact_id,
        &requirement,
    )
    .await?;

    let mut versions = versions;
    let resolved = versions
        .pop()
        .ok_or_else(|| ResolveError::VersionNotFound {
            coord: format!(
                "{}:{}",
                item.dependency.group_id, item.dependency.artifact_id
            ),
            requirement: version_str.to_string(),
        })?;
    let coord = Coord {
        group_id: item.dependency.group_id.clone().into(),
        artifact_id: item.dependency.artifact_id.clone().into(),
        version: resolved.version.clone(),
        packaging,
        classifier,
    };
    // Only the version list is needed for mediation. A range descriptor is
    // fetched when its candidate wins, including a later backtracking winner.
    if matches!(requirement, RequestedRequirement::Ranges(_)) {
        return Ok(vec![ResolutionOutcome::Resolved {
            item,
            coord,
            resolved,
            resolved_project: None,
            alternatives: versions,
            effective_scope,
            child_scope,
            requirement,
        }]);
    }
    Ok(vec![
        load_candidate(
            solver,
            Candidate {
                item,
                coord,
                resolved,
                resolved_project: None,
                effective_scope,
                child_scope,
            },
            requirement,
            &constraints,
            relocation_cache,
        )
        .await?,
    ])
}

async fn resolve_requirement_versions<B: Backend>(
    solver: &Solver<'_, B>,
    group_id: &str,
    artifact_id: &str,
    requirement: &RequestedRequirement,
) -> Result<Vec<ResolvedVersion>> {
    Ok(match requirement {
        RequestedRequirement::Exact(version) | RequestedRequirement::Soft(version) => {
            // Without a platform constraint, use the soft requirement's recorded version.
            // Conflict mediation compares it with other requirements later.
            vec![ResolvedVersion {
                version: version.clone(),
                repo_url: None,
            }]
        }
        RequestedRequirement::Ranges(req) => {
            solver
                .backend
                .resolve_versions(group_id, artifact_id, req)
                .await?
        }
        RequestedRequirement::DynamicRelease => {
            let req = VersionReq::Exact(Version::parse("RELEASE").map_err(|err| {
                ResolveError::SolverInvariant {
                    detail: format!("failed to parse RELEASE marker: {err}"),
                }
            })?);
            vec![
                solver
                    .backend
                    .resolve_version(group_id, artifact_id, &req)
                    .await?,
            ]
        }
        RequestedRequirement::DynamicIntegration => {
            let req = VersionReq::Exact(Version::parse("LATEST").map_err(|err| {
                ResolveError::SolverInvariant {
                    detail: format!("failed to parse LATEST marker: {err}"),
                }
            })?);
            vec![
                solver
                    .backend
                    .resolve_version(group_id, artifact_id, &req)
                    .await?,
            ]
        }
    })
}

async fn load_candidate<B: Backend>(
    solver: &Solver<'_, B>,
    candidate: Candidate<Option<ResolvedProject>>,
    mut requirement: RequestedRequirement,
    constraints: &PlatformConstraints,
    relocation_cache: &Mutex<HashMap<Coord, Coord>>,
) -> Result<ResolutionOutcome> {
    let Candidate {
        item,
        coord,
        resolved,
        effective_scope,
        child_scope,
        ..
    } = candidate;
    let resolved = if resolved.version.as_str().ends_with("-SNAPSHOT") {
        let mut snapshot = solver.backend.resolve_snapshot_version(&coord).await?;
        if snapshot.repo_url.is_none() {
            snapshot.repo_url = resolved.repo_url.clone();
        }
        snapshot
    } else {
        resolved
    };
    let coord = Coord {
        version: resolved.version.clone(),
        ..coord
    };
    let original_coord = coord.clone();
    let (mut coord, mut resolved_project) = solver
        .fetch_project_with_relocation_cached(&coord, effective_scope, relocation_cache)
        .await
        .map_err(|err| attach_dropped_repos(solver, &item, &coord, err))?;
    let relocated = coord != original_coord;
    if relocated {
        // DfDependencyCollector restarts collection with the relocated
        // artifact. The source range belongs to the source coordinate;
        // the target's concrete version is a soft preference of its own.
        requirement = RequestedRequirement::Soft(coord.version.clone());
    }
    let mut resolved = resolved;
    let mut alternatives = Vec::new();
    // Maven reapplies root dependencyManagement to relocated transitive dependencies
    // (depth >= 2). The model layer manages direct dependencies. A managed target
    // may relocate again, so repeat until its coordinates stabilize.
    if relocated && item.depth > 1 {
        let mut source_coord = original_coord;
        for _ in 0..MAX_RELOCATION_MANAGEMENT_PASSES {
            if coord.group_id == source_coord.group_id
                && coord.artifact_id == source_coord.artifact_id
            {
                break;
            }
            let Some(managed) = constraints.apply_constraint(
                coord.group_id.as_str(),
                coord.artifact_id.as_str(),
                item.dependency.effective_type(),
                item.dependency.effective_classifier(),
                None,
            ) else {
                break;
            };
            requirement = parse_requested_requirement(
                coord.group_id.as_str(),
                coord.artifact_id.as_str(),
                managed.version.trim(),
            )?;
            let mut versions = resolve_requirement_versions(
                solver,
                coord.group_id.as_str(),
                coord.artifact_id.as_str(),
                &requirement,
            )
            .await?;
            resolved = versions
                .pop()
                .ok_or_else(|| ResolveError::VersionNotFound {
                    coord: format!("{}:{}", coord.group_id, coord.artifact_id),
                    requirement: managed.version.clone(),
                })?;
            let managed_coord = Coord {
                version: resolved.version.clone(),
                ..coord.clone()
            };
            alternatives = versions;
            if managed_coord == coord {
                break;
            }
            source_coord = managed_coord.clone();
            (coord, resolved_project) = solver
                .fetch_project_with_relocation_cached(
                    &managed_coord,
                    effective_scope,
                    relocation_cache,
                )
                .await
                .map_err(|err| attach_dropped_repos(solver, &item, &managed_coord, err))?;
            if coord != managed_coord {
                requirement = RequestedRequirement::Soft(coord.version.clone());
                alternatives.clear();
            }
        }
    }
    tracing::debug!(
        coord = %coord,
        scope = ?effective_scope,
        depth = item.depth,
        "resolved dependency"
    );
    Ok(ResolutionOutcome::Resolved {
        item,
        coord,
        resolved,
        resolved_project: Some(resolved_project),
        alternatives,
        effective_scope,
        child_scope,
        requirement,
    })
}

/// Name the ignored transitive repositories that could have served a
/// not-found dependency: those declared by a POM on its path from the root.
fn attach_dropped_repos<B: Backend>(
    solver: &Solver<'_, B>,
    item: &QueueItem,
    coord: &Coord,
    err: ResolveError,
) -> ResolveError {
    let ResolveError::ArtifactNotFound {
        coord: failed,
        searched,
        mut dropped_repos,
    } = err
    else {
        return err;
    };
    let mut path = Vec::new();
    let mut current = Some(&item.path);
    while let Some(node) = current {
        path.push((
            node.key.group_id.to_string(),
            node.key.artifact_id.to_string(),
        ));
        current = node.parent.as_ref();
    }
    path.reverse();
    dropped_repos.extend(solver.backend.dropped_repos_on_path(
        &path,
        &coord.version.to_string(),
        &searched,
    ));
    ResolveError::ArtifactNotFound {
        coord: failed,
        searched,
        dropped_repos,
    }
}

fn parse_requested_requirement(
    group_id: &str,
    artifact_id: &str,
    raw_version: &str,
) -> Result<RequestedRequirement> {
    let trimmed = raw_version.trim();
    let lowered = trimmed.to_ascii_lowercase();
    match lowered.as_str() {
        "release" | "latest.release" => return Ok(RequestedRequirement::DynamicRelease),
        "latest" | "latest.integration" => return Ok(RequestedRequirement::DynamicIntegration),
        _ => {}
    }

    if is_unsupported_dynamic_syntax(trimmed) {
        return Err(ResolveError::InvalidVersionRequirement {
            coord: format!("{group_id}:{artifact_id}"),
            value: trimmed.to_string(),
        });
    }

    let requirement =
        VersionReq::parse(trimmed).map_err(|_| ResolveError::InvalidVersionRequirement {
            coord: format!("{group_id}:{artifact_id}"),
            value: trimmed.to_string(),
        })?;
    match requirement {
        // Preserve Maven's soft-vs-hard distinction. Collapsing `Soft` into
        // `Exact` would harden transitive soft pins and bypass any later
        // override path that distinguishes the two.
        VersionReq::Exact(version) => Ok(RequestedRequirement::Exact(version)),
        VersionReq::Soft(version) => Ok(RequestedRequirement::Soft(version)),
        VersionReq::Ranges(_) => Ok(RequestedRequirement::Ranges(requirement)),
    }
}

fn is_unsupported_dynamic_syntax(version: &str) -> bool {
    let lowered = version.trim().to_ascii_lowercase();
    lowered.contains('+')
        || (lowered.starts_with("latest.")
            && lowered != "latest.release"
            && lowered != "latest.integration")
}

#[allow(clippy::too_many_arguments)] // process_batch is an internal helper with tightly related args
async fn process_batch<'a, B: Backend>(
    solver: &Solver<'a, B>,
    batch: Vec<QueueItem>,
    graph: &mut Graph,
    selected: &mut HashMap<CoordKey, Selected<Option<ResolvedProject>>>,
    requirements: &mut HashMap<u64, (CoordKey, RequestedRequirement)>,
    platform_constraints: &mut Arc<PlatformConstraints>,
    queue: &mut BinaryHeap<QueueItem>,
    next_declared_at: &mut u64,
    relocation_cache: &Mutex<HashMap<Coord, Coord>>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let batch_len = batch.len();
    let constraints_snapshot = Arc::clone(platform_constraints);
    let concurrency = solver.current_fetch_concurrency().min(batch_len).max(1);

    let results: Vec<_> = stream::iter(batch.into_iter().enumerate())
        .map(|(idx, item)| {
            let constraints_snapshot = Arc::clone(&constraints_snapshot);
            async move {
                let outcome =
                    resolve_item(solver, item, constraints_snapshot, relocation_cache).await;
                (idx, outcome)
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let mut results = results;
    results.sort_by_key(|(idx, _)| *idx);
    let mut outcomes = Vec::new();
    for (_, result) in results {
        outcomes.extend(result?.into_iter().map(Some));
    }

    // The production `RepoBackend` (resolver/backend.rs) always returns
    // `platform_constraints: None` because <dependencyManagement>/BOM handling
    // now happens in the model layer (`Project::from_pom_with_context`), not as
    // solver-surfaced platform constraints. So for the real resolver this whole
    // block is inert. It is kept (and exercised by the solver tests via mock
    // backends) as a live extension point: a `Backend` impl MAY surface
    // platform constraints here and the solver will merge them and requeue any
    // in-flight resolution they invalidate. Guarded behind `has_new_constraints`
    // so it costs nothing when no backend produces constraints.
    let has_new_constraints = outcomes.iter().flatten().any(|o| {
        matches!(
            o,
            ResolutionOutcome::Resolved { resolved_project, .. }
                if resolved_project.as_ref().is_some_and(|p| p.platform_constraints.is_some())
        )
    });

    if has_new_constraints {
        // This is the single merge point for a batch's newly discovered
        // constraints. The first-seen and replacement branches below do not
        // re-merge per outcome; they would only fold in the same constraints
        // already merged here. When `has_new_constraints` is false every
        // outcome carries `None`, which `merge_platform_constraints` treats
        // as a no-op, so nothing is lost by skipping the block.
        for outcome in outcomes.iter().flatten() {
            if let ResolutionOutcome::Resolved {
                resolved_project, ..
            } = outcome
            {
                merge_platform_constraints(
                    Arc::make_mut(platform_constraints),
                    resolved_project
                        .as_ref()
                        .and_then(|p| p.platform_constraints.as_ref()),
                );
            }
        }

        let mut requeued = HashSet::new();
        for outcome in outcomes.iter_mut() {
            let Some(ResolutionOutcome::Resolved { item, .. }) = outcome else {
                continue;
            };

            let new_version_str =
                resolve_version_str(platform_constraints.as_ref(), &item.dependency, item.depth)?;
            let old_version_str =
                resolve_version_str(&constraints_snapshot, &item.dependency, item.depth)?;

            if new_version_str != old_version_str {
                tracing::debug!(
                    dep = %item.dependency.artifact_id,
                    old = %old_version_str,
                    new = %new_version_str,
                    "intra-batch constraint discovery invalidated resolution; requeuing"
                );

                let stale_outcome =
                    outcome
                        .take()
                        .ok_or_else(|| ResolveError::SolverInvariant {
                            detail: "expected outcome during requeue".to_string(),
                        })?;
                if let ResolutionOutcome::Resolved { item, .. } = stale_outcome {
                    // Preserve declared_at to keep Maven's first-declared-wins
                    // tiebreak stable across requeues.
                    // All alternatives of one range share the same request.
                    if requeued.insert(item.declared_at) {
                        push_queue(queue, item)?;
                    }
                }
            }
        }
    }

    let mut outcomes: VecDeque<_> = outcomes.into_iter().flatten().collect();
    while let Some(outcome) = outcomes.pop_front() {
        match outcome {
            ResolutionOutcome::System { item, coord } => {
                let Some(parent_node) = graph.node(item.parent) else {
                    continue;
                };
                if &parent_node.coord.version != item.parent_version.as_ref() {
                    continue;
                }

                let key = CoordKey::from(&coord);
                if let Some(existing) = selected.get(&key) {
                    // Node already exists; still add parent->child edge
                    // so the graph reflects all dependency relationships.
                    let edge = Edge {
                        scope: Scope::System,
                        optional: item.dependency.effective_optional(),
                        exclusions: item.dependency.exclusions.clone(),
                        requested: item.dependency.version.clone(),
                    };
                    graph.add_edge(item.parent, existing.node, edge);
                    continue;
                }
                let coord_version = coord.version.clone();
                let node = Node {
                    coord,
                    scope: Scope::System,
                    repo_url: None,
                    checksum: None,
                    workspace_module: None,
                    local: true,
                    system_path: item.dependency.system_path.clone(),
                };
                let node_idx = graph.insert_node(node);
                let edge = Edge {
                    scope: Scope::System,
                    optional: item.dependency.effective_optional(),
                    exclusions: item.dependency.exclusions.clone(),
                    requested: item.dependency.version.clone(),
                };
                graph.add_edge(item.parent, node_idx, edge);
                selected.insert(
                    key,
                    Selected {
                        node: node_idx,
                        version: coord_version,
                        hard: Vec::new(),
                        candidates: Vec::new(),
                        winner: None,
                    },
                );
            }
            ResolutionOutcome::Resolved {
                item,
                coord,
                resolved,
                resolved_project,
                alternatives,
                effective_scope,
                child_scope,
                requirement,
            } => {
                let Some(parent_node) = graph.node(item.parent) else {
                    continue;
                };
                if &parent_node.coord.version != item.parent_version.as_ref() {
                    continue;
                }

                let key = CoordKey::from(&coord);
                let coord_version = coord.version.clone();

                let edge = Edge {
                    scope: effective_scope,
                    optional: item.dependency.effective_optional(),
                    exclusions: item.dependency.exclusions.clone(),
                    requested: item.dependency.version.clone(),
                };

                if let Some(workspace_module) = resolved_project
                    .as_ref()
                    .and_then(|p| p.workspace_module.as_deref())
                    && let Some(cycle) =
                        workspace_dependency_cycle(&item, workspace_module, graph, selected)
                {
                    return Err(ResolveError::WorkspaceDependencyCycle { cycle });
                }

                if item.path.contains(&key) {
                    if let Some(existing) = selected.get(&key) {
                        graph.add_edge(item.parent, existing.node, edge);
                        tracing::debug!(
                            cycle = %item.path.format_cycle(&key),
                            "breaking cyclic dependency"
                        );
                    }
                    continue;
                }

                let candidate = Arc::new(Candidate {
                    item,
                    coord,
                    resolved,
                    resolved_project,
                    effective_scope,
                    child_scope,
                });
                let retry_alternatives = alternatives.clone();
                let mut candidates = Vec::with_capacity(alternatives.len() + 1);
                for resolved in alternatives {
                    candidates.push(Arc::new(Candidate {
                        coord: Coord {
                            version: resolved.version.clone(),
                            ..candidate.coord.clone()
                        },
                        resolved,
                        resolved_project: None,
                        ..candidate.as_ref().clone()
                    }));
                }
                candidates.push(Arc::clone(&candidate));
                let mut selection = selected.get(&key).cloned().unwrap_or_else(|| Selected {
                    node: graph.root(), // replaced when the first winner is inserted
                    version: coord_version,
                    hard: Vec::new(),
                    candidates: Vec::new(),
                    winner: None,
                });
                let winner = selection.consider_all(candidates, &requirement, solver.strategy)?;
                let Some(mut winner) = winner else {
                    graph.add_edge(candidate.item.parent, selection.node, edge);
                    requirements.insert(candidate.item.declared_at, (key.clone(), requirement));
                    selected.insert(key, selection);
                    continue;
                };
                if winner.resolved_project.is_none() {
                    let winner_requirement = requirements
                        .get(&winner.item.declared_at)
                        .map(|(_, requirement)| requirement.clone())
                        .unwrap_or_else(|| requirement.clone());
                    let loaded = load_candidate(
                        solver,
                        winner.as_ref().clone(),
                        winner_requirement,
                        platform_constraints,
                        relocation_cache,
                    )
                    .await?;
                    let ResolutionOutcome::Resolved {
                        coord,
                        resolved,
                        resolved_project,
                        ..
                    } = &loaded
                    else {
                        unreachable!()
                    };
                    if coord != &winner.coord {
                        // Relocation ends this declaration's source alternatives and constraints.
                        // Mediate the target under its own requirement.
                        let declaration = winner.item.declared_at;
                        requirements.remove(&declaration);
                        let mut detached_source = false;
                        let mut discarded_parent = None;
                        if let Some(source) = selected.get_mut(&key) {
                            source
                                .candidates
                                .retain(|c| c.item.declared_at != declaration);
                            source.hard = requirements
                                .values()
                                .filter(|(source_key, _)| source_key == &key)
                                .filter_map(|(_, req)| hard_constraint(req))
                                .collect();
                            detached_source = graph.remove_edge(
                                winner.item.parent,
                                source.node,
                                &Edge {
                                    scope: winner.effective_scope,
                                    optional: winner.item.dependency.effective_optional(),
                                    exclusions: winner.item.dependency.exclusions.clone(),
                                    requested: winner.item.dependency.version.clone(),
                                },
                            );
                            if detached_source
                                || source
                                    .winner
                                    .as_ref()
                                    .is_some_and(|c| c.item.declared_at == declaration)
                            {
                                source.winner = None;
                                discarded_parent = Some(source.node);
                                let orphaned = graph.replace_node_version(
                                    source.node,
                                    graph
                                        .node(source.node)
                                        .expect("selected node")
                                        .coord
                                        .clone(),
                                );
                                for orphan in orphaned {
                                    selected.remove(&orphan);
                                }
                            }
                        }
                        if detached_source {
                            selected.remove(&key);
                        }
                        if let Some(parent) = discarded_parent {
                            withdraw_discarded_declarations(
                                parent,
                                graph,
                                selected,
                                requirements,
                                &mut outcomes,
                            );
                        }
                        if declaration != candidate.item.declared_at {
                            // Backtracking loaded a retained declaration. The
                            // new request still needs its constraint and edge.
                            outcomes.push_front(ResolutionOutcome::Resolved {
                                item: candidate.item.clone(),
                                coord: candidate.coord.clone(),
                                resolved: candidate.resolved.clone(),
                                resolved_project: candidate.resolved_project.clone(),
                                alternatives: retry_alternatives,
                                effective_scope: candidate.effective_scope,
                                child_scope: candidate.child_scope,
                                requirement,
                            });
                        }
                        outcomes.push_front(loaded);
                        continue;
                    }
                    let loaded_winner = Arc::new(Candidate {
                        coord: coord.clone(),
                        resolved: resolved.clone(),
                        resolved_project: resolved_project.clone(),
                        ..winner.as_ref().clone()
                    });
                    for retained in &mut selection.candidates {
                        if Arc::ptr_eq(retained, &winner) {
                            *retained = Arc::clone(&loaded_winner);
                        }
                    }
                    winner = loaded_winner;
                    selection.winner = Some(Arc::clone(&winner));
                }
                let project = winner
                    .resolved_project
                    .as_ref()
                    .expect("winner descriptor loaded");
                if let Some(workspace_module) = project.workspace_module.as_deref()
                    && let Some(cycle) =
                        workspace_dependency_cycle(&winner.item, workspace_module, graph, selected)
                {
                    return Err(ResolveError::WorkspaceDependencyCycle { cycle });
                }
                let replaced = selected.get(&key).map(|existing| existing.node);
                let node_idx = if let Some(existing) = selected.get(&key) {
                    let node_idx = existing.node;
                    let orphaned_keys = graph.replace_node_version(node_idx, winner.coord.clone());
                    for orphaned_key in orphaned_keys {
                        selected.remove(&orphaned_key);
                    }
                    node_idx
                } else {
                    graph.insert_node(Node {
                        coord: winner.coord.clone(),
                        scope: winner.effective_scope,
                        repo_url: None,
                        checksum: None,
                        workspace_module: None,
                        local: false,
                        system_path: winner.item.dependency.system_path.clone(),
                    })
                };
                if let Some(node) = graph.node_mut(node_idx) {
                    node.scope = winner.effective_scope;
                    node.repo_url = winner
                        .resolved
                        .repo_url
                        .clone()
                        .or_else(|| project.repo_url.clone());
                    node.workspace_module = project.workspace_module.clone();
                }
                graph.add_edge(candidate.item.parent, node_idx, edge);
                selection.node = node_idx;
                selection.version = winner.coord.version.clone();
                requirements.insert(candidate.item.declared_at, (key.clone(), requirement));
                selected.insert(key.clone(), selection);
                if let Some(parent) = replaced
                    && solver.strategy == ResolutionStrategy::NearestWins
                {
                    withdraw_discarded_declarations(
                        parent,
                        graph,
                        selected,
                        requirements,
                        &mut outcomes,
                    );
                }
                #[cfg(debug_assertions)]
                graph.assert_index_consistent();
                queue_children(
                    queue,
                    &winner.item,
                    &key,
                    node_idx,
                    winner.child_scope,
                    &winner.coord.version,
                    project,
                    next_declared_at,
                )?;
            }
        }
    }

    Ok(())
}

fn withdraw_discarded_declarations(
    parent: petgraph::graph::NodeIndex,
    graph: &mut Graph,
    selected: &mut HashMap<CoordKey, Selected<Option<ResolvedProject>>>,
    requirements: &mut HashMap<u64, (CoordKey, RequestedRequirement)>,
    outcomes: &mut VecDeque<ResolutionOutcome>,
) {
    let mut affected = HashSet::new();
    loop {
        let live_nodes: HashSet<_> = selected.values().map(|selection| selection.node).collect();
        let mut empty = Vec::new();
        for (key, selection) in selected.iter_mut() {
            let previous_len = selection.candidates.len();
            selection.candidates.retain(|candidate| {
                let item = &candidate.item;
                item.parent != parent
                    && live_nodes.contains(&item.parent)
                    && graph
                        .node(item.parent)
                        .is_some_and(|node| node.coord.version == *item.parent_version)
            });
            if selection.candidates.len() != previous_len {
                affected.insert(key.clone());
                selection.winner = None;
                if selection.candidates.is_empty() {
                    empty.push(key.clone());
                }
            }
        }
        if empty.is_empty() {
            break;
        }
        for key in empty {
            if let Some(selection) = selected.remove(&key) {
                let coord = graph
                    .node(selection.node)
                    .expect("selected node")
                    .coord
                    .clone();
                for orphan in graph.replace_node_version(selection.node, coord) {
                    selected.remove(&orphan);
                }
            }
        }
    }
    let declarations: HashSet<_> = selected
        .values()
        .flat_map(|selection| selection.candidates.iter().map(|c| c.item.declared_at))
        .collect();
    requirements.retain(|declaration, _| declarations.contains(declaration));
    let mut pending = Vec::new();
    for key in affected {
        let Some(selection) = selected.get_mut(&key) else {
            continue;
        };
        selection.hard = requirements
            .values()
            .filter(|(target, _)| target == &key)
            .filter_map(|(_, requirement)| hard_constraint(requirement))
            .collect();
        if let Some(candidate) = selection.candidates.first() {
            let requirement = requirements[&candidate.item.declared_at].1.clone();
            pending.push(ResolutionOutcome::Resolved {
                item: candidate.item.clone(),
                coord: candidate.coord.clone(),
                resolved: candidate.resolved.clone(),
                resolved_project: candidate.resolved_project.clone(),
                alternatives: Vec::new(),
                effective_scope: candidate.effective_scope,
                child_scope: candidate.child_scope,
                requirement,
            });
        }
    }
    pending.sort_by_key(|outcome| match outcome {
        ResolutionOutcome::Resolved { item, .. } => item.declared_at,
        ResolutionOutcome::System { item, .. } => item.declared_at,
    });
    for outcome in pending.into_iter().rev() {
        outcomes.push_front(outcome);
    }
}

/// The part of a request that is a hard constraint: a range or a bracketed pin.
fn hard_constraint(requirement: &RequestedRequirement) -> Option<VersionReq> {
    match requirement {
        RequestedRequirement::Ranges(range) => Some(range.clone()),
        RequestedRequirement::Exact(version) => Some(VersionReq::Exact(version.clone())),
        _ => None,
    }
}

fn workspace_dependency_cycle(
    item: &QueueItem,
    target_module: &str,
    graph: &Graph,
    selected: &HashMap<CoordKey, Selected<Option<ResolvedProject>>>,
) -> Option<String> {
    let mut coordinates = Vec::new();
    let mut current = Some(item.path.as_ref());
    while let Some(path) = current {
        let selected_node = selected.get(&path.key)?;
        let node = graph.node(selected_node.node)?;
        let workspace_module = node.workspace_module.as_deref()?;
        coordinates.push(format!(
            "{}:{}",
            node.coord.group_id, node.coord.artifact_id
        ));
        if workspace_module == target_module {
            coordinates.reverse();
            coordinates.push(coordinates.first().expect("cycle contains target").clone());
            return Some(coordinates.join(" -> "));
        }
        current = path.parent.as_deref();
    }
    None
}

#[cfg(test)]
impl<'a, B: Backend> Solver<'a, B> {
    pub(crate) fn new(backend: &'a B) -> Self {
        Self::with_strategy(backend, ResolutionStrategy::default(), None)
    }

    /// Set platform constraints for this solver.
    ///
    /// Platform constraints are applied to dependencies that don't have a version specified.
    /// Enforced platform constraints override any existing version.
    pub(crate) fn with_platform_constraints(mut self, constraints: PlatformConstraints) -> Self {
        self.platform_constraints = Some(constraints);
        self
    }
}

#[derive(Debug, Clone)]
struct Selected<P = ResolvedProject> {
    node: petgraph::graph::NodeIndex,
    version: Version,
    /// Hard constraints (ranges and `[x]` pins) requested for this key so far.
    /// Like maven-resolver's NearestVersionSelector, the winner must satisfy
    /// every one of them.
    hard: Vec<VersionReq>,
    candidates: Vec<Arc<Candidate<P>>>,
    winner: Option<Arc<Candidate<P>>>,
}

// Generic payloads let mediation compare fetched descriptors and lazy range
// candidates using only coordinates and traversal context.
#[derive(Debug, Clone)]
struct Candidate<P = ResolvedProject> {
    item: QueueItem,
    coord: Coord,
    resolved: ResolvedVersion,
    resolved_project: P,
    effective_scope: Scope,
    child_scope: Option<Scope>,
}

impl<P> Candidate<P> {
    fn is_nearer(&self, other: &Self) -> bool {
        // NearestVersionSelector compares sibling versions before depth.
        // Relocation can create siblings after model dependency deduplication.
        if self.item.parent == other.item.parent
            && self.item.parent_version == other.item.parent_version
        {
            self.coord.version > other.coord.version
        } else {
            // Ordered batch processing and the retained candidate list keep
            // the first encountered path on an equal-depth tie.
            self.item.depth < other.item.depth
        }
    }
}

impl<P> Selected<P> {
    /// Retain declarations so removing a parent can make rejected candidates eligible again.
    /// Backtrack when a new range rejects the winner.
    /// Return the new winner only when it changes.
    /// Return traversal context only when the winner changes.
    #[cfg(test)]
    fn consider(
        &mut self,
        candidate: Arc<Candidate<P>>,
        requirement: &RequestedRequirement,
        strategy: ResolutionStrategy,
    ) -> Result<Option<Arc<Candidate<P>>>> {
        self.consider_all(vec![candidate], requirement, strategy)
    }

    fn consider_all(
        &mut self,
        candidates: Vec<Arc<Candidate<P>>>,
        requirement: &RequestedRequirement,
        strategy: ResolutionStrategy,
    ) -> Result<Option<Arc<Candidate<P>>>> {
        let candidate = candidates.last().expect("nonempty declaration");
        if let Some(hard) = hard_constraint(requirement)
            && !self.hard.contains(&hard)
        {
            self.hard.push(hard);
        }
        let acceptable = |version: &Version| self.hard.iter().all(|hard| hard.matches(version));
        let previous = self.winner.clone();
        match strategy {
            ResolutionStrategy::NearestWins => {
                let backtrack = self.winner.is_none() || !acceptable(&self.version);
                for candidate in &candidates {
                    if acceptable(&candidate.coord.version)
                        && !backtrack
                        && self
                            .winner
                            .as_ref()
                            .is_none_or(|winner| candidate.is_nearer(winner))
                    {
                        self.winner = Some(Arc::clone(candidate));
                    }
                }
                for candidate in &candidates {
                    if !self.candidates.iter().any(|retained| {
                        retained.item.declared_at == candidate.item.declared_at
                            && retained.coord == candidate.coord
                    }) {
                        self.candidates.push(Arc::clone(candidate));
                    }
                }
                if backtrack {
                    self.winner = None;
                    for retained in self
                        .candidates
                        .iter()
                        .filter(|c| acceptable(&c.coord.version))
                    {
                        if self
                            .winner
                            .as_ref()
                            .is_none_or(|winner| retained.is_nearer(winner))
                        {
                            self.winner = Some(Arc::clone(retained));
                        }
                    }
                    if self.winner.is_none() {
                        return Err(self.conflict(candidate, requirement));
                    }
                }
            }
            ResolutionStrategy::HighestWins => {
                if self.winner.is_none() || candidate.coord.version > self.version {
                    self.winner = Some(Arc::clone(candidate));
                } else if hard_constraint(requirement)
                    .is_some_and(|hard| !hard.matches(&self.version))
                {
                    return Err(self.conflict(candidate, requirement));
                }
            }
        }
        Ok(self
            .winner
            .as_ref()
            .filter(|winner| {
                previous
                    .as_ref()
                    .is_none_or(|previous| !Arc::ptr_eq(winner, previous))
            })
            .cloned())
    }

    fn conflict(
        &self,
        candidate: &Candidate<P>,
        requirement: &RequestedRequirement,
    ) -> ResolveError {
        ResolveError::VersionConflict {
            coord: format!(
                "{}:{}",
                candidate.coord.group_id, candidate.coord.artifact_id
            ),
            requested: hard_constraint(requirement).map_or_else(
                || candidate.coord.version.to_string(),
                |hard| match hard {
                    VersionReq::Exact(version) => version.to_string(),
                    _ => hard.to_string(),
                },
            ),
            selected: self.version.to_string(),
        }
    }
}

/// Push the resolved project's declared dependencies onto the queue as
/// children of `node_idx`. Shared between the first-seen and the
/// replacement (conflict-resolved) branches in `process_batch`. No-op when
/// `child_scope` is `None` (the resolved item is a leaf for traversal).
// Distinct, well-named parameters threaded into the solver hot path; bundling
// them into a struct would only obscure the two call sites.
#[allow(clippy::too_many_arguments)]
fn queue_children(
    queue: &mut BinaryHeap<QueueItem>,
    item: &QueueItem,
    key: &CoordKey,
    node_idx: petgraph::graph::NodeIndex,
    child_scope: Option<Scope>,
    coord_version: &Version,
    resolved_project: &ResolvedProject,
    next_declared_at: &mut u64,
) -> Result<()> {
    let Some(child_scope) = child_scope else {
        return Ok(());
    };
    let next_path = PathNode::extend(&item.path, key.clone());
    let next_exclusions = extend_exclusions(&item.exclusions, &item.dependency.exclusions);
    let coord_version = Arc::new(coord_version.clone());
    let dep_mgmt = &resolved_project.project.dependency_management;
    for mut dep in resolved_project.project.dependencies.iter().cloned() {
        // A child with no <version> takes it from the resolving artifact's own
        // effective dependencyManagement (its entries plus the parent chain and
        // import BOMs, already merged by the model layer), as Maven does for
        // every artifact, not just the root. Only the version is filled here; an
        // explicit version wins and the declared scope is left untouched.
        if dep.version.is_none()
            && let Some(version) = managed_child_version(dep_mgmt, &dep)
        {
            dep.version = Some(version);
        }
        let declared_at = *next_declared_at;
        *next_declared_at += 1;
        push_queue(
            queue,
            QueueItem::new(
                node_idx,
                Arc::clone(&coord_version),
                Arc::new(dep),
                child_scope,
                item.depth + 1,
                declared_at,
                Arc::clone(&next_exclusions),
                Arc::clone(&next_path),
            ),
        )?;
    }
    Ok(())
}

/// Find the version a resolved artifact's effective dependencyManagement
/// supplies for one of its child dependencies, matched by Maven's management
/// key `(groupId, artifactId, type, classifier)`. Returns `None` when the
/// child is unmanaged or the matching entry carries no version (a management
/// entry may manage only scope/exclusions).
fn managed_child_version(mgmt: &DependencyManagement, dep: &Dependency) -> Option<String> {
    mgmt.dependencies
        .iter()
        .find(|managed| {
            managed.group_id == dep.group_id
                && managed.artifact_id == dep.artifact_id
                && managed.effective_type() == dep.effective_type()
                && managed.effective_classifier() == dep.effective_classifier()
        })
        .and_then(|managed| managed.version.clone())
}

fn inherit_scope(parent: Scope, child: Scope) -> Scope {
    match (parent, child) {
        // Runtime propagates onto compile-scoped children (Maven mediation).
        (Scope::Runtime, Scope::Compile) => Scope::Runtime,
        // Test-scoped ancestors keep their test classification on
        // transitive children. Without this, `transitive_from(Test,
        // Compile|Runtime)` would queue the child for traversal but
        // emit it with the child's declared scope, dropping the test
        // classification from the lock file.
        (Scope::Test, Scope::Compile | Scope::Runtime) => Scope::Test,
        // A test child (e.g. managed to test) of a provided parent stays test.
        (Scope::Provided, Scope::Test) => Scope::Test,
        // Other inherited (non-Compile/Runtime) parent scopes win
        // outright, matching maven-resolver's relaxed-mode semantics.
        (Scope::Test | Scope::Provided | Scope::System | Scope::Import, _) => parent,
        _ => child,
    }
}

fn is_barrier(item: &QueueItem) -> bool {
    // BOM-import deps are skipped upstream by `resolve_item`, so the only
    // remaining barrier is the platform/enforced-platform dep type. Those
    // must drain before sibling plain deps so their constraints land first.
    matches!(
        item.dependency.type_.as_deref(),
        Some("platform") | Some("enforced-platform")
    )
}

fn packaging_opt(effective_type: &str) -> Option<String> {
    (effective_type != "jar").then(|| effective_type.to_string())
}
