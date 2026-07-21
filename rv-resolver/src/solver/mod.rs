use std::collections::{BinaryHeap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::stream::{self, StreamExt};
use rv_maven_model::{Dependency, DependencyManagement, Project, Scope};
use rv_version::{Coord, Version, VersionReq};

use crate::ResolutionStrategy;
use crate::error::{ResolveError, Result};
use crate::graph::{CoordKey, Edge, Graph, Node};

mod platform;
mod queue;
mod relocation;

pub(crate) use self::platform::{ConstraintVersion, PlatformConstraint, PlatformConstraints};
use self::platform::{merge_platform_constraints, resolve_version_str};
use self::queue::{ExclusionKey, PathNode, QueueItem, extend_exclusions, is_excluded, push_queue};

#[cfg(test)]
mod tests;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

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
    pub platform_constraints: Option<PlatformConstraints>,
}

pub(crate) trait Backend {
    fn resolve_version<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
    ) -> BoxFuture<'a, Result<ResolvedVersion>>;

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
}

pub(crate) struct Solver<'a, B: Backend> {
    backend: &'a B,
    strategy: ResolutionStrategy,
    platform_constraints: Option<PlatformConstraints>,
    fetch_concurrency: usize,
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
            strict_maven_compat: false,
        }
    }

    pub(crate) fn with_fetch_concurrency(mut self, concurrency: usize) -> Self {
        self.fetch_concurrency = concurrency.clamp(1, MAX_FETCH_CONCURRENCY);
        self
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
        let mut selected: HashMap<CoordKey, Selected> = HashMap::with_capacity(estimated_deps);
        selected.insert(
            root_key.clone(),
            Selected {
                node: graph.root(),
                depth: 0,
                version: root_version.clone(),
                declared_at: 0,
            },
        );
        let relocation_cache = Mutex::new(HashMap::with_capacity(32));
        let mut platform_constraints =
            Arc::new(self.platform_constraints.clone().unwrap_or_default());
        let fetch_concurrency = self.fetch_concurrency.max(1);

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
                        &mut platform_constraints,
                        &mut queue,
                        &mut next_declared_at,
                        &relocation_cache,
                    )
                    .await?;
                    continue;
                }

                batch.push(item);
                if batch.len() >= fetch_concurrency {
                    let current = std::mem::take(&mut batch);
                    process_batch(
                        self,
                        current,
                        &mut graph,
                        &mut selected,
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
    Skip,
    System {
        item: QueueItem,
        coord: Coord,
    },
    Resolved {
        item: QueueItem,
        coord: Coord,
        resolved: ResolvedVersion,
        resolved_project: ResolvedProject,
        effective_scope: Scope,
        child_scope: Option<Scope>,
        /// The original requirement that triggered this resolution. Carried
        /// through so the conflict-resolution path can raise `VersionConflict`
        /// when nearest-wins selects a version that violates a hard range.
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
/// A managed scope only fills a blank; an explicitly declared scope wins, as in
/// the model layer's `apply_managed_dependency`. Otherwise a dep that declares
/// `<scope>compile</scope>` (as guava-testlib does for its `junit` child) would
/// be forced to the root's managed `test` scope and then pruned at depth > 1,
/// dropping its whole subtree.
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
    if managed.scope.is_none() && managed.optional.is_none() && managed.exclusions.is_empty() {
        return item;
    }
    let dep = Arc::make_mut(&mut item.dependency);
    if let Some(scope) = &managed.scope
        && dep.scope.is_none()
    {
        dep.scope = Some(scope.clone());
    }
    if let Some(optional) = &managed.optional
        && dep.optional.is_none()
    {
        dep.optional = Some(optional.clone());
    }
    for exclusion in &managed.exclusions {
        if !dep.exclusions.contains(exclusion) {
            dep.exclusions.push(exclusion.clone());
        }
    }
    item
}

async fn resolve_item<'a, B: Backend>(
    solver: &Solver<'a, B>,
    item: QueueItem,
    constraints: Arc<PlatformConstraints>,
    relocation_cache: &Mutex<HashMap<Coord, Coord>>,
) -> Result<ResolutionOutcome> {
    let item = apply_managed_metadata(constraints.as_ref(), item);
    if is_excluded(&item.dependency, item.exclusions.as_ref()) {
        tracing::debug!(
            group_id = %item.dependency.group_id,
            artifact_id = %item.dependency.artifact_id,
            "excluded dependency skipped"
        );
        return Ok(ResolutionOutcome::Skip);
    }

    if item.dependency.effective_optional() && item.depth > 1 {
        return Ok(ResolutionOutcome::Skip);
    }

    let dep_scope = item.dependency.effective_scope();

    if dep_scope == Scope::Import {
        return Ok(ResolutionOutcome::Skip);
    }

    if item.depth > 1
        && (dep_scope == Scope::Test || dep_scope == Scope::Provided || dep_scope == Scope::System)
    {
        return Ok(ResolutionOutcome::Skip);
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
    let child_scope = if item.dependency.effective_optional() && item.depth > 1 {
        // Should not reach here (skipped above), but be safe
        None
    } else if item.depth == 1 && matches!(dep_scope, Scope::Provided | Scope::Test) {
        // Descend at the dep's own scope; see the note above.
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
        return Ok(ResolutionOutcome::System { item, coord });
    }

    let version_str = resolve_version_str(constraints.as_ref(), &item.dependency, item.depth)?;

    let requirement = parse_requested_requirement(
        &item.dependency.group_id,
        &item.dependency.artifact_id,
        version_str.as_ref(),
    )?;

    let (resolved, resolved_project, coord) = {
        let packaging = packaging_opt(item.dependency.effective_type());
        let classifier = item
            .dependency
            .effective_classifier()
            .map(|s| s.to_string());

        let resolved = match &requirement {
            RequestedRequirement::Exact(version) | RequestedRequirement::Soft(version) => {
                // Soft reaches this layer only when no platform constraint
                // covered it (see `resolve_version_str`). At that point the
                // recorded version is the value to use; soft-vs-hard
                // mediation between competing requirements happens elsewhere.
                ResolvedVersion {
                    version: version.clone(),
                    repo_url: None,
                }
            }
            RequestedRequirement::Ranges(req) => {
                solver
                    .backend
                    .resolve_version(&item.dependency.group_id, &item.dependency.artifact_id, req)
                    .await?
            }
            RequestedRequirement::DynamicRelease => {
                let req = VersionReq::Exact(Version::parse("RELEASE").map_err(|err| {
                    ResolveError::SolverInvariant {
                        detail: format!("failed to parse RELEASE marker: {err}"),
                    }
                })?);
                solver
                    .backend
                    .resolve_version(
                        &item.dependency.group_id,
                        &item.dependency.artifact_id,
                        &req,
                    )
                    .await?
            }
            RequestedRequirement::DynamicIntegration => {
                let req = VersionReq::Exact(Version::parse("LATEST").map_err(|err| {
                    ResolveError::SolverInvariant {
                        detail: format!("failed to parse LATEST marker: {err}"),
                    }
                })?);
                solver
                    .backend
                    .resolve_version(
                        &item.dependency.group_id,
                        &item.dependency.artifact_id,
                        &req,
                    )
                    .await?
            }
        };

        let resolved = if resolved.version.as_str().ends_with("-SNAPSHOT") {
            let coord = Coord {
                group_id: item.dependency.group_id.clone().into(),
                artifact_id: item.dependency.artifact_id.clone().into(),
                version: resolved.version.clone(),
                packaging: packaging.clone(),
                classifier: classifier.clone(),
            };
            let mut snapshot = solver.backend.resolve_snapshot_version(&coord).await?;
            if snapshot.repo_url.is_none() {
                snapshot.repo_url = resolved.repo_url.clone();
            }
            snapshot
        } else {
            resolved
        };

        let coord = Coord {
            group_id: item.dependency.group_id.clone().into(),
            artifact_id: item.dependency.artifact_id.clone().into(),
            version: resolved.version.clone(),
            packaging,
            classifier,
        };
        let (coord, resolved_project) = solver
            .fetch_project_with_relocation_cached(&coord, effective_scope, relocation_cache)
            .await?;
        (resolved, resolved_project, coord)
    };

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
        resolved_project,
        effective_scope,
        child_scope,
        requirement,
    })
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
    selected: &mut HashMap<CoordKey, Selected>,
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
    let concurrency = solver.fetch_concurrency.min(batch_len).max(1);

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

    let mut outcomes: Vec<Option<ResolutionOutcome>> = (0..batch_len).map(|_| None).collect();
    for (idx, outcome) in results {
        outcomes[idx] = Some(outcome?);
    }

    // #6: the production `RepoBackend` (resolver/backend.rs) always returns
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
                if resolved_project.platform_constraints.is_some()
        )
    });

    if has_new_constraints {
        // #50: this is the single merge point for a batch's newly discovered
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
                    resolved_project.platform_constraints.as_ref(),
                );
            }
        }

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
                    push_queue(queue, item)?;
                }
            }
        }
    }

    for outcome in outcomes.into_iter().flatten() {
        match outcome {
            ResolutionOutcome::Skip => {}
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
                        depth: item.depth,
                        version: coord_version,
                        declared_at: item.declared_at,
                    },
                );
            }
            ResolutionOutcome::Resolved {
                item,
                coord,
                resolved,
                resolved_project,
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

                match selected.get(&key) {
                    None => {
                        let node = Node {
                            coord,
                            scope: effective_scope,
                            repo_url: resolved.repo_url.clone(),
                            checksum: None,
                            local: false,
                            system_path: item.dependency.system_path.clone(),
                        };
                        let node_idx = graph.insert_node(node);
                        graph.add_edge(item.parent, node_idx, edge);
                        selected.insert(
                            key.clone(),
                            Selected {
                                node: node_idx,
                                depth: item.depth,
                                version: coord_version.clone(),
                                declared_at: item.declared_at,
                            },
                        );

                        if let Some(node) = graph.node_mut(node_idx)
                            && node.repo_url.is_none()
                        {
                            node.repo_url = resolved_project.repo_url.clone();
                        }

                        // #50: the batch-level merge above already folded in
                        // this outcome's constraints; no per-outcome re-merge.

                        queue_children(
                            queue,
                            &item,
                            &key,
                            node_idx,
                            child_scope,
                            &coord_version,
                            &resolved_project,
                            next_declared_at,
                        )?;
                    }
                    Some(existing) => {
                        let node_idx = existing.node;
                        graph.add_edge(item.parent, node_idx, edge);

                        let should_replace = match solver.strategy {
                            ResolutionStrategy::NearestWins => {
                                item.depth < existing.depth
                                    || (item.depth == existing.depth
                                        && item.declared_at < existing.declared_at)
                            }
                            ResolutionStrategy::HighestWins => coord_version > existing.version,
                        };
                        if should_replace {
                            tracing::debug!(
                                group_id = %key.group_id,
                                artifact_id = %key.artifact_id,
                                winner = %coord_version,
                                loser = %existing.version,
                                strategy = ?solver.strategy,
                                "version conflict resolved"
                            );

                            // Atomically replace the node's version and tear
                            // down the loser subgraph. `replace_node_version`
                            // updates the node in place, drops outgoing edges
                            // to the descendants queued under the losing
                            // version, and purges secondary-index entries for
                            // orphaned descendants so a later dependency
                            // cannot resurrect a stale subgraph through
                            // `Graph::node_index`.
                            let new_coord = rv_version::Coord {
                                group_id: key.group_id.clone(),
                                artifact_id: key.artifact_id.clone(),
                                version: coord_version.clone(),
                                packaging: key.packaging.clone(),
                                classifier: key.classifier.clone(),
                            };
                            let orphaned_keys = graph.replace_node_version(node_idx, new_coord);
                            if let Some(node) = graph.node_mut(node_idx) {
                                node.scope = effective_scope;
                                if node.repo_url.is_none() {
                                    node.repo_url = resolved.repo_url.clone();
                                }
                            }

                            selected.insert(
                                key.clone(),
                                Selected {
                                    node: node_idx,
                                    depth: item.depth,
                                    version: coord_version.clone(),
                                    declared_at: item.declared_at,
                                },
                            );
                            for orphaned_key in &orphaned_keys {
                                selected.remove(orphaned_key);
                            }
                            #[cfg(debug_assertions)]
                            graph.assert_index_consistent();

                            if let Some(node) = graph.node_mut(node_idx)
                                && node.repo_url.is_none()
                            {
                                node.repo_url = resolved_project.repo_url.clone();
                            }

                            // #50: the batch-level merge above already folded
                            // in this outcome's constraints; no per-outcome
                            // re-merge.

                            queue_children(
                                queue,
                                &item,
                                &key,
                                node_idx,
                                child_scope,
                                &coord_version,
                                &resolved_project,
                                next_declared_at,
                            )?;
                        } else {
                            // Loser branch: the incoming resolution did not win
                            // the conflict. If the incoming requirement is a hard
                            // constraint and the already-selected version does not
                            // satisfy it, raise a `VersionConflict` error.
                            // Nearest-wins silently adopting a version that violates
                            // a declared hard constraint would break the contract.
                            //
                            // #49: both a hard range (`[1.0,2.0)`) and a hard
                            // pin (`[1.0]` parses to `Exact`) are constraints,
                            // not preferences, so both raise here. A losing
                            // `Exact` pin that did not raise would silently
                            // accept whatever nearest-wins picked, inconsistent
                            // with the range path. A `Soft` pin stays a
                            // preference and never raises (it is overridable).
                            let conflict = match &requirement {
                                RequestedRequirement::Ranges(range)
                                    if !range.matches(&existing.version) =>
                                {
                                    Some(range.to_string())
                                }
                                RequestedRequirement::Exact(version)
                                    if version != &existing.version =>
                                {
                                    Some(version.to_string())
                                }
                                _ => None,
                            };
                            if let Some(requested) = conflict {
                                let coord_str = format!("{}:{}", key.group_id, key.artifact_id);
                                return Err(ResolveError::VersionConflict {
                                    coord: coord_str,
                                    requested,
                                    selected: existing.version.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
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
struct Selected {
    node: petgraph::graph::NodeIndex,
    depth: usize,
    version: Version,
    declared_at: u64,
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
