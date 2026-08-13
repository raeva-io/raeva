//! High-level public resolver API: the [`Resolver`] type and helpers
//! orchestrating dependency graph construction.

mod backend;
mod fetcher;
mod utils;

use fetcher::RepoTrust;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use petgraph::graph::NodeIndex;
use rv_config::{
    ArtifactKey, BlobId, Checksum, LockCoordinate, LockEdge, LockGav, LockPackage, LockPlatform,
    Lockfile, Platform,
};
use rv_maven_model::{Pom, Project, Scope};
use rv_repo::{ArtifactRequest, Repository};
use rv_version::{Coord, Version};

use crate::ResolutionStrategy;
use crate::context::ResolveContext;
use crate::error::{ResolveError, Result};
use crate::graph::Graph;
use crate::solver::{
    ConstraintVersion, PlatformConstraint, PlatformConstraints, Solver, SolverRoot,
};
use crate::workspace::Workspace;

pub use backend::SupportPomProvenance;
use backend::{RepoBackend, WorkspaceSupportPomBuffer};
use fetcher::RepoParentResolver;
use utils::{FetchError, build_lock_data, fetch_artifact_from_repos};
pub(crate) use utils::{filter_repos_for_version, merge_repos};

/// Specifies the root of a dependency resolution.
///
/// Wraps the path to a `pom.xml` on disk. Tuple-struct form leaves room
/// for future construction helpers without breaking the call sites.
pub struct RootSpec(pub PathBuf);

/// The main dependency resolver. Resolves a dependency graph from a POM.
///
/// Supports Maven (nearest-wins) and highest-wins resolution strategies. Single-module only.
#[derive(Clone)]
pub struct Resolver {
    ctx: ResolveContext,
    strategy: ResolutionStrategy,
    strict: bool,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("strategy", &self.strategy)
            .field("strict", &self.strict)
            .field("ctx", &"<ResolveContext>")
            .finish()
    }
}

/// The output of dependency resolution: a resolved graph and lockfile data.
#[derive(Debug)]
pub struct ResolutionResult {
    pub graph: Graph,
    pub platform: Platform,
    pub packages: Vec<LockPackage>,
    pub edges: Vec<LockEdge>,
    /// Effective identity of the root module that produced this graph.
    pub module_gav: LockGav,
    pub module_packaging: String,
    /// Repositories that backed this resolution as `(normalized_url, id)`
    /// pairs, including POM-declared `<repositories>` discovered during the
    /// solve. `rv export-m2` can't otherwise see the observed (non-config)
    /// repositories, so persisting them lets it label `_remote.repositories`
    /// markers with the correct repository id instead of defaulting to
    /// `central`. Only repositories that carry an id are recorded.
    pub repositories: Vec<(String, String)>,
    /// Repositories approved for this resolution after applying the
    /// root-POM trust rule and the transitive-repository policy. Artifact
    /// population uses these during the same sync; they are never restored
    /// from lockfile metadata.
    pub trusted_repositories: Vec<Repository>,
    /// Provenance for each support POM (parent / imported BOM) as
    /// `("g:a:v", provenance)`. A support POM can resolve from a different
    /// repository than its referencing child, so this preserves both the
    /// serving repository id for `rv export-m2`'s `_remote.repositories`
    /// markers and the SHA-256 of the bytes export must ship.
    ///
    /// Every remotely fetched support POM appears here; one served by a
    /// repository that carries no id is recorded with an empty id. The
    /// coordinate is the load-bearing half — `rv export-m2` refuses to write an
    /// offline repository that is missing a POM named here — and an empty id
    /// says only that there is no repository id to put in the POM's marker.
    pub support_pom_provenance: Vec<(String, SupportPomProvenance)>,
    /// Content-store SHA-256 identity for every external artifact in this
    /// result, keyed by its structured lock coordinate.
    ///
    /// Reactor aggregation uses this instead of comparing server checksum
    /// sidecars. Two repositories may publish checksums under different
    /// algorithms, but the blob id answers directly whether two modules
    /// resolved the same coordinate to identical bytes.
    pub artifact_blobs: BTreeMap<LockCoordinate, BlobId>,
    /// SHA-256 of the companion `.pom` this resolution parsed for every
    /// external artifact in this result, under the same key `artifact_blobs`
    /// uses.
    ///
    /// This is where the lockfile's `pom_sha256` comes from. Recorded when the
    /// POM bytes were in hand, never read back out of the store's coordinate
    /// index: the index is last-writer-wins across every project sharing the
    /// store, so it can name different bytes by the time the lock is written.
    pub companion_pom_blobs: BTreeMap<LockCoordinate, BlobId>,
}

/// Maximum number of module graphs resolved concurrently.
///
/// During the graph/model phase each module receives a share of the workspace
/// network budget. Four modules keep CPU and model work parallel while
/// bounding per-reactor memory use.
pub const MAX_WORKSPACE_MODULE_CONCURRENCY: usize = 4;

/// Maximum aggregate fetch budget across an all-reactor resolution.
///
/// Every active graph receives at least one slot, so four modules cannot each
/// open a full `MAX_FETCH_CONCURRENCY` batch. Artifact population runs later
/// as a serialized phase, where the one active module uses this whole budget.
/// Four is deliberately low to bound the memory, open files, and connections a
/// large reactor holds at once.
pub const MAX_WORKSPACE_NETWORK_CONCURRENCY: usize = 4;

/// Number of module artifact-population passes allowed to use the shared store
/// at once.
///
/// Graph and model resolution finish in parallel first. Serializing the final
/// phase lets each module see the previous module's verified store entries
/// instead of concurrently downloading and indexing the reactor's heavily
/// overlapping artifacts.
pub const MAX_WORKSPACE_ARTIFACT_POPULATIONS: usize = 1;

/// How long an all-reactor resolution may raise no progress event at all
/// before it is declared stalled.
///
/// Deliberately far above any plausible real latency: the watchdog is a
/// backstop against a resolver bug that wedges the runtime, not a network
/// timeout (rv-repo owns those, and bounds a single request attempt). Every
/// request attempted, every response or failure returned, and every batch of
/// blobs verified is a progress event, so a slow mirror, a retrying one, and a
/// long local verification pass all keep resetting the clock no matter how
/// long the whole resolve takes.
const WORKSPACE_STALL_TIMEOUT: Duration = Duration::from_secs(900);

/// Overrides [`WORKSPACE_STALL_TIMEOUT`], in whole seconds. `0` disables the
/// watchdog entirely. An unparseable value falls back to the default rather
/// than failing the resolve.
const WORKSPACE_STALL_TIMEOUT_ENV: &str = "RV_WORKSPACE_STALL_TIMEOUT_SECS";

fn workspace_stall_timeout() -> Option<Duration> {
    let Ok(raw) = std::env::var(WORKSPACE_STALL_TIMEOUT_ENV) else {
        return Some(WORKSPACE_STALL_TIMEOUT);
    };
    match raw.trim().parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(Duration::from_secs(secs)),
        Err(_) => {
            tracing::warn!(
                env = WORKSPACE_STALL_TIMEOUT_ENV,
                value = %raw,
                "ignoring unparseable stall timeout; using the default"
            );
            Some(WORKSPACE_STALL_TIMEOUT)
        }
    }
}

/// Which part of the resolution a tracked unit of work is in, so a stall
/// diagnostic says what was happening and not only where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkPhase {
    /// Building the module's dependency graph: model fetches and the solve.
    Graph,
    /// Writing the reactor's buffered parent/BOM POMs to the content store.
    SupportPomFlush,
    /// Downloading, verifying and pinning the module's artifacts.
    ArtifactPopulation,
}

impl WorkPhase {
    fn label(self) -> &'static str {
        match self {
            Self::Graph => "graph",
            Self::SupportPomFlush => "support POM flush",
            Self::ArtifactPopulation => "artifact population",
        }
    }
}

/// One unit of work the watchdog can name.
struct InFlight {
    module: String,
    phase: WorkPhase,
}

/// Key for reactor-wide work that belongs to no single module. `BTreeMap`
/// ordering puts it after every real module index.
const REACTOR_WIDE: usize = usize::MAX;

/// Liveness signal for an all-reactor resolution.
///
/// `events` counts everything that means the resolve is still moving: a module
/// entering or leaving a phase, every repository request attempted, every
/// response or failure that comes back, every batch of blobs verified, every
/// buffered support POM written to the store. The watchdog watches this
/// counter and never wall-clock time, so an hour of genuinely slow downloads
/// reads as healthy while a wedged runtime — which by construction raises no
/// events — is caught.
///
/// A failure is progress: a repository that answers 500, or a request that
/// times out and retries, proves the process is alive, which is the only
/// question this counter exists to answer. Timeouts belong to rv-repo.
///
/// Cost on the hot path is one relaxed `fetch_add`.
pub(crate) struct WorkspaceProgress {
    events: AtomicU64,
    /// Work currently in flight, keyed by module index (or [`REACTOR_WIDE`])
    /// so the diagnostic can name exactly what was stuck and in which phase.
    in_flight: Mutex<BTreeMap<usize, InFlight>>,
}

impl WorkspaceProgress {
    fn new() -> Self {
        Self {
            events: AtomicU64::new(0),
            in_flight: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record that the resolution moved. Called from fetch paths in
    /// [`RepoBackend`], so it must stay allocation-free and lock-free.
    pub(crate) fn note(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
    }

    fn events(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn enter(&self, index: usize, module: &str, phase: WorkPhase) {
        self.lock().insert(
            index,
            InFlight {
                module: module.to_string(),
                phase,
            },
        );
        self.note();
    }

    fn leave(&self, index: usize) {
        self.lock().remove(&index);
        self.note();
    }

    fn stuck_modules(&self) -> String {
        self.lock()
            .values()
            .map(|entry| format!("{} ({})", entry.module, entry.phase.label()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<usize, InFlight>> {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Cancels the wrapped task when dropped, so abandoning a reactor resolution
/// (watchdog fired, caller cancelled) does not leave it running detached.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Resolve once `progress` has been idle for `timeout`, naming what was in
/// flight. Never resolves while the resolution keeps raising events.
async fn watch_for_stall(progress: Arc<WorkspaceProgress>, timeout: Duration) -> ResolveError {
    // Sample several times per window so the reported stall duration is close
    // to `timeout` rather than up to double it.
    let tick = (timeout / 4).max(Duration::from_millis(50));
    let mut interval = tokio::time::interval(tick);
    // `interval`'s first tick completes immediately.
    interval.tick().await;

    let mut last_seen = progress.events();
    let mut idle = Duration::ZERO;
    loop {
        interval.tick().await;
        let seen = progress.events();
        if seen != last_seen {
            last_seen = seen;
            idle = Duration::ZERO;
            continue;
        }
        idle += tick;
        if idle >= timeout {
            return ResolveError::WorkspaceStalled {
                modules: progress.stuck_modules(),
                stalled_for_secs: idle.as_secs(),
            };
        }
    }
}

struct WorkspaceStoreState {
    support_poms: WorkspaceSupportPomBuffer,
    artifact_blobs: Mutex<HashMap<ArtifactKey, HashMap<String, BlobId>>>,
    progress: Arc<WorkspaceProgress>,
}

impl WorkspaceStoreState {
    fn new() -> Self {
        Self {
            support_poms: Arc::new(Mutex::new(Vec::new())),
            artifact_blobs: Mutex::new(HashMap::new()),
            progress: Arc::new(WorkspaceProgress::new()),
        }
    }

    fn with_progress(progress: Arc<WorkspaceProgress>) -> Self {
        Self {
            progress,
            ..Self::new()
        }
    }

    #[cfg(test)]
    pub(crate) fn for_testing(support_poms: Vec<(ArtifactKey, Vec<u8>)>) -> Self {
        Self {
            support_poms: Arc::new(Mutex::new(support_poms)),
            ..Self::new()
        }
    }
}

struct PendingModuleResolution {
    backend: RepoBackend,
    graph: Graph,
    module_gav: LockGav,
    module_packaging: String,
    root_support_pom_provenance: Vec<(String, SupportPomProvenance)>,
}

struct WorkspaceModuleWork {
    index: usize,
    pom_path: String,
    resolver: Resolver,
    pending: PendingModuleResolution,
}

/// One module's graph in an all-reactor resolution.
#[derive(Debug)]
pub struct WorkspaceModuleResolution {
    pub pom_path: String,
    pub resolution: ResolutionResult,
}

/// Per-platform output from resolving every active module in a workspace.
#[derive(Debug)]
pub struct WorkspaceResolution {
    pub platform: Platform,
    pub modules: Vec<WorkspaceModuleResolution>,
}

impl Resolver {
    /// Creates a resolver with the specified conflict resolution strategy.
    pub fn with_strategy(ctx: ResolveContext, strategy: ResolutionStrategy) -> Self {
        Self {
            ctx,
            strategy,
            strict: false,
        }
    }

    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    pub fn strategy(&self) -> ResolutionStrategy {
        self.strategy
    }

    /// Resolves the full transitive dependency graph from the given root.
    ///
    /// Fetches POM metadata from configured repositories, applies BOM imports,
    /// resolves version conflicts, and returns a lockable result.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(resolver: rv_resolver::Resolver) -> Result<(), rv_resolver::ResolveError> {
    /// use rv_resolver::RootSpec;
    /// let result = resolver.resolve(RootSpec("pom.xml".into())).await?;
    /// println!("resolved {} packages", result.packages.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn resolve(&self, root: RootSpec) -> Result<ResolutionResult> {
        let RootSpec(path) = root;
        self.resolve_internal(&path, None, None).await
    }

    /// Resolve every active reactor module for this resolver's target platform.
    ///
    /// Project and model caches are scoped to a single module resolution.
    /// Repositories declared by module A must not make a cached project
    /// visible under module B's different repository context. The content
    /// store and the repository client's persistent metadata cache stay
    /// shared. This method builds graphs in a bounded parallel phase, then
    /// writes support POMs and artifacts in discovery order so the shared
    /// store never becomes an implicit cross-module synchronization point.
    ///
    /// A watchdog runs alongside the resolution and aborts it with
    /// [`ResolveError::WorkspaceStalled`] if nothing at all happens for
    /// [`WORKSPACE_STALL_TIMEOUT`]. It exists so a future scheduling bug of
    /// the kind this phase has already had once fails a build with a
    /// diagnostic naming the stuck modules instead of hanging CI forever.
    pub async fn resolve_workspace(&self, workspace: &Workspace) -> Result<WorkspaceResolution> {
        self.resolve_workspace_with_stall_timeout(workspace, workspace_stall_timeout())
            .await
    }

    /// [`Self::resolve_workspace`] with the watchdog window supplied directly,
    /// so tests do not have to reach for a process-global environment variable
    /// to get a bounded run.
    pub(crate) async fn resolve_workspace_with_stall_timeout(
        &self,
        workspace: &Workspace,
        stall_timeout: Option<Duration>,
    ) -> Result<WorkspaceResolution> {
        let progress = Arc::new(WorkspaceProgress::new());
        // The watchdog needs a tokio runtime to spawn onto and a timer to tick
        // on. Both hold for every `rv` entry point; an embedder driving this
        // future on another executor gets the resolution unguarded rather than
        // a panic from `tokio::spawn`.
        let timeout = stall_timeout.filter(|_| tokio::runtime::Handle::try_current().is_ok());
        let Some(timeout) = timeout else {
            return self.resolve_workspace_watched(workspace, progress).await;
        };

        // The resolution runs as its own task, not inline. The failure this
        // watchdog exists to catch is a resolution that stops being polled at
        // all; a watchdog awaited from inside that same task would stop being
        // polled with it and never fire. On a separate task the timer wakes
        // independently of whatever wedged the resolution.
        let resolver = self.clone();
        let owned = workspace.clone();
        let module_progress = Arc::clone(&progress);
        let mut resolution = AbortOnDrop(tokio::spawn(async move {
            resolver
                .resolve_workspace_watched(&owned, module_progress)
                .await
        }));

        tokio::select! {
            // Prefer the real result: if the resolution landed in the same
            // scheduler pass the watchdog fired in, it wins.
            biased;
            joined = &mut resolution.0 => match joined {
                Ok(result) => result,
                // Nothing cancels this handle but `AbortOnDrop`, which only
                // runs once this `select!` is done with it.
                Err(err) if err.is_cancelled() => Err(ResolveError::InternalError(
                    "reactor resolution task was cancelled".to_string(),
                )),
                // Re-raise a panic on this thread so it reads the same as it
                // did before the resolution moved onto its own task.
                Err(err) => std::panic::resume_unwind(err.into_panic()),
            },
            stalled = watch_for_stall(progress, timeout) => {
                tracing::error!(error = %stalled, "aborting stalled reactor resolution");
                Err(stalled)
            }
        }
    }

    async fn resolve_workspace_watched(
        &self,
        workspace: &Workspace,
        progress: Arc<WorkspaceProgress>,
    ) -> Result<WorkspaceResolution> {
        let workspace = Arc::new(workspace.clone());
        let configured_concurrency = self
            .ctx
            .config
            .network
            .concurrency
            .clamp(1, MAX_WORKSPACE_NETWORK_CONCURRENCY);
        let module_concurrency = MAX_WORKSPACE_MODULE_CONCURRENCY
            .min(configured_concurrency)
            .min(workspace.len().max(1));
        let per_module_concurrency = (configured_concurrency / module_concurrency).max(1);
        let store_state = Arc::new(WorkspaceStoreState::with_progress(progress));

        let module_specs: Vec<(usize, String, PathBuf)> = workspace
            .modules()
            .iter()
            .enumerate()
            .map(|(index, module)| {
                (
                    index,
                    module.pom_path.clone(),
                    workspace.root().join(&module.pom_path),
                )
            })
            .collect();

        let work: Vec<WorkspaceModuleWork> = stream::iter(module_specs)
            .map(|(index, pom_path, absolute_pom)| {
                let workspace = Arc::clone(&workspace);
                let store_state = Arc::clone(&store_state);
                let mut config = self.ctx.config.clone();
                config.network.concurrency = per_module_concurrency;
                let ctx = ResolveContext::new(
                    config,
                    self.ctx.repos.clone(),
                    Arc::clone(&self.ctx.store),
                    self.ctx.platform.clone(),
                    self.ctx.client.clone(),
                );
                let resolver = Resolver::with_strategy(ctx, self.strategy).with_strict(self.strict);
                async move {
                    tracing::debug!(
                        target: "rv_resolver::workspace",
                        module = %pom_path,
                        "starting workspace module resolution"
                    );
                    let progress = Arc::clone(&store_state.progress);
                    progress.enter(index, &pom_path, WorkPhase::Graph);
                    let pending = resolver
                        .resolve_graph_internal(&absolute_pom, Some(workspace), Some(store_state))
                        .await;
                    progress.leave(index);
                    Ok::<_, ResolveError>(WorkspaceModuleWork {
                        index,
                        pom_path,
                        resolver,
                        pending: pending?,
                    })
                }
            })
            .buffer_unordered(module_concurrency)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        let mut work = work;
        work.sort_by_key(|module| module.index);
        // Both phases below run outside any module's graph entry, so they
        // register their own in-flight work: a stall here would otherwise name
        // nothing at all, which is the least useful moment to lose the label.
        store_state
            .progress
            .enter(REACTOR_WIDE, "reactor", WorkPhase::SupportPomFlush);
        let flushed = self.flush_workspace_support_poms(&store_state).await;
        store_state.progress.leave(REACTOR_WIDE);
        flushed?;

        let mut modules = Vec::with_capacity(work.len());
        for mut module in work {
            // The graph phase split the aggregate budget across concurrent
            // modules. Artifact population is serialized, so the active
            // module can use the whole workspace budget.
            module.resolver.ctx.config.network.concurrency = configured_concurrency;
            store_state.progress.enter(
                module.index,
                &module.pom_path,
                WorkPhase::ArtifactPopulation,
            );
            let resolution = module
                .resolver
                .finish_resolution(module.pending, Some(&store_state.artifact_blobs))
                .await;
            store_state.progress.leave(module.index);
            let resolution = resolution?;
            tracing::debug!(
                target: "rv_resolver::workspace",
                module = %module.pom_path,
                nodes = resolution.graph.node_count(),
                "finished workspace module resolution"
            );
            modules.push(WorkspaceModuleResolution {
                pom_path: module.pom_path,
                resolution,
            });
        }

        Ok(WorkspaceResolution {
            platform: self.ctx.platform.clone(),
            modules,
        })
    }

    async fn resolve_internal(
        &self,
        path: &Path,
        workspace: Option<Arc<Workspace>>,
        workspace_store: Option<Arc<WorkspaceStoreState>>,
    ) -> Result<ResolutionResult> {
        let pending = self
            .resolve_graph_internal(path, workspace, workspace_store.clone())
            .await?;
        if let Some(state) = workspace_store.as_ref() {
            self.flush_workspace_support_poms(state).await?;
        }
        self.finish_resolution(pending, None).await
    }

    async fn resolve_graph_internal(
        &self,
        path: &Path,
        workspace: Option<Arc<Workspace>>,
        workspace_store: Option<Arc<WorkspaceStoreState>>,
    ) -> Result<PendingModuleResolution> {
        let mut repos = self.ctx.repos.clone();

        // `load_root_project` returns any extra repos observed while resolving
        // the parent chain. Parent POMs may declare `<repositories>` that host
        // their own deps; without merging them here the solver backend below
        // never sees them and resolution fails for parent-hosted artifacts.
        let (root_coord, project, observed_repos, root_support_pom_provenance) = self
            .load_root_project(
                path,
                &repos,
                workspace.clone(),
                workspace_store
                    .as_ref()
                    .map(|state| Arc::clone(&state.support_poms)),
            )
            .await?;
        if !project.repositories.is_empty() {
            let extra = project
                .repositories
                .iter()
                .cloned()
                .map(Repository::from)
                .collect::<Vec<_>>();
            repos = merge_repos(repos, extra);
        }
        if !observed_repos.is_empty() {
            repos = merge_repos(repos, observed_repos);
        }
        let root_dependency_management = project.dependency_management;
        let module_gav = LockGav::new(
            root_coord.group_id.to_string(),
            root_coord.artifact_id.to_string(),
            root_coord.version.to_string(),
        );
        let module_packaging = root_coord
            .packaging
            .clone()
            .unwrap_or_else(|| "jar".to_string());
        let root_spec = SolverRoot {
            coord: root_coord,
            dependencies: project.dependencies,
            scope: Scope::Compile,
        };

        tracing::debug!(
            direct_deps = root_spec.dependencies.len(),
            strategy = ?self.strategy,
            "starting dependency resolution"
        );

        let mut backend = RepoBackend::new(&self.ctx, repos, self.strict);
        if let Some(workspace) = workspace {
            backend = backend.with_workspace(workspace);
        }
        if let Some(state) = workspace_store.as_ref() {
            backend = backend.with_workspace_support_poms(Arc::clone(&state.support_poms));
            backend = backend.with_workspace_progress(Arc::clone(&state.progress));
        }

        // Apply the root project's fully-resolved dependency management as
        // platform constraints. The `dependency_management` field is already
        // fully inlined (BOM imports resolved, parent chain merged) by
        // `Project::from_pom_with_context`.
        let mut platform_constraints: Option<PlatformConstraints> = None;
        if !root_dependency_management.dependencies.is_empty() {
            let target = platform_constraints.get_or_insert_with(PlatformConstraints::new);
            for dep in &root_dependency_management.dependencies {
                // An entry with no version can still manage scope, optional
                // or exclusions (a version-less entry carrying only
                // `<exclusions>` is the canonical global-exclude pattern).
                let version = dep.version.as_deref();
                if version.is_none()
                    && dep.scope.is_none()
                    && dep.optional.is_none()
                    && dep.exclusions.is_empty()
                {
                    continue;
                }
                // `resolve_bom_imports` inlines scope=import entries upstream,
                // so encountering one here means an upstream invariant broke.
                debug_assert!(
                    dep.effective_scope() != Scope::Import,
                    "scope=import dependency leaked past BOM inlining: {}:{}",
                    dep.group_id,
                    dep.artifact_id,
                );
                target.add_constraint(PlatformConstraint {
                    group: dep.group_id.clone(),
                    module: dep.artifact_id.clone(),
                    type_: dep.effective_type().to_string(),
                    classifier: dep.effective_classifier().map(str::to_string),
                    version: ConstraintVersion {
                        requires: version.map(str::to_string),
                        strictly: None,
                    },
                    enforced: false,
                    scope: dep.scope.clone(),
                    optional: dep.optional.clone(),
                    exclusions: dep.exclusions.clone(),
                });
            }
            tracing::debug!(
                count = root_dependency_management.dependencies.len(),
                "applied root dependency management as platform constraints"
            );
        }

        let fetch_concurrency = self
            .ctx
            .config
            .network
            .concurrency
            .clamp(1, crate::solver::MAX_FETCH_CONCURRENCY);
        let solver = Solver::with_strategy(&backend, self.strategy, platform_constraints)
            .with_fetch_concurrency(fetch_concurrency)
            .with_strict_maven_compat(true);
        let graph = solver.solve(root_spec).await?;

        tracing::debug!(
            target: "rv_resolver::workspace",
            module = %path.display(),
            nodes = graph.node_count(),
            "built workspace module graph"
        );

        Ok(PendingModuleResolution {
            backend,
            graph,
            module_gav,
            module_packaging,
            root_support_pom_provenance,
        })
    }

    async fn finish_resolution(
        &self,
        pending: PendingModuleResolution,
        workspace_artifacts: Option<&Mutex<HashMap<ArtifactKey, HashMap<String, BlobId>>>>,
    ) -> Result<ResolutionResult> {
        let PendingModuleResolution {
            backend,
            mut graph,
            module_gav,
            module_packaging,
            root_support_pom_provenance,
        } = pending;
        self.populate_artifacts(&backend, &mut graph, workspace_artifacts)
            .await?;
        let (packages, edges) = build_lock_data(&graph)?;
        let mut artifact_blobs = BTreeMap::new();
        let mut companion_pom_blobs = BTreeMap::new();
        for package in &packages {
            if package.system_path.is_some() || package.repo_url.is_empty() {
                continue;
            }
            let coordinate = LockCoordinate::new(
                &package.group_id,
                &package.artifact_id,
                &package.version,
                &package.packaging,
                package.classifier.clone(),
            );
            let key = ArtifactKey::new(
                &package.group_id,
                &package.artifact_id,
                &package.version,
                &package.packaging,
                package.classifier.clone(),
            );
            // Artifact population records the content-addressed SHA-256 on
            // each graph node. Prefer that per-module value over the store's
            // coordinate index: a later module may probe the same coordinate
            // in another repository and replace the global index row before
            // aggregate conflict checking runs.
            let blob = if let Some(checksum) = package
                .checksum
                .as_ref()
                .filter(|checksum| checksum.algorithm == "sha256")
            {
                checksum.digest.parse::<BlobId>().map_err(|error| {
                    ResolveError::InternalError(format!(
                        "artifact {} has invalid SHA-256 blob identity: {error}",
                        package.format_coord()
                    ))
                })?
            } else {
                self.ctx.store.lookup_artifact(&key).await?.ok_or_else(|| {
                    ResolveError::ArtifactNotFound {
                        coord: package.format_coord(),
                        searched: Vec::new(),
                    }
                })?
            };
            // Every external node in the graph reached it through
            // `fetch_project`, which parsed a POM and recorded its identity, so
            // a gap here means the graph and the pin map disagree about what
            // was resolved. Leaving the row unpinned instead would hand the
            // POM choice back to the store's coordinate index.
            let pom_blob = backend
                .companion_pom_blob(&(
                    package.group_id.clone(),
                    package.artifact_id.clone(),
                    package.version.clone(),
                ))
                .ok_or_else(|| {
                    ResolveError::InternalError(format!(
                        "resolved artifact {} has no companion POM recorded by this resolution",
                        package.format_coord()
                    ))
                })?;
            ensure_pom_packaging_identity(package, &blob, &pom_blob)?;
            artifact_blobs.insert(coordinate.clone(), blob);
            companion_pom_blobs.insert(coordinate, pom_blob);
        }

        // Record the id'd repositories that backed this resolution (config +
        // any POM-declared ones the backend accumulated during the solve) so
        // export-m2 can label markers for repos it cannot otherwise see.
        let trusted_repositories = backend.repos_snapshot();
        let mut repositories: Vec<(String, String)> = trusted_repositories
            .iter()
            .filter_map(|repo| {
                repo.id
                    .as_deref()
                    .map(|id| (rv_repo::normalize_repo_url(&repo.url), id.to_string()))
            })
            .collect();
        repositories.sort();
        repositories.dedup();

        // Merge the solver backend's support provenance (transitive deps'
        // parents/BOMs) with the root project's own (captured in
        // load_root_project on a separate backend).
        let mut merged = backend.support_pom_provenance_snapshot();
        merged.extend(root_support_pom_provenance);
        let support_pom_provenance = merge_support_pom_provenance(merged)?;

        Ok(ResolutionResult {
            graph,
            platform: self.ctx.platform.clone(),
            packages,
            edges,
            module_gav,
            module_packaging,
            repositories,
            trusted_repositories,
            support_pom_provenance,
            artifact_blobs,
            companion_pom_blobs,
        })
    }

    async fn load_root_project(
        &self,
        path: &Path,
        repos: &[Repository],
        workspace: Option<Arc<Workspace>>,
        workspace_support_poms: Option<WorkspaceSupportPomBuffer>,
    ) -> Result<(
        Coord,
        Project,
        Vec<Repository>,
        Vec<(String, SupportPomProvenance)>,
    )> {
        let contents = crate::parent_resolver::read_project_input_string_async(path)
            .await
            .map_err(root_input_error)?;
        let mut pom = Pom::parse(&contents).map_err(|source| ResolveError::LocalPom {
            path: path.display().to_string(),
            source,
        })?;

        // Inject .mvn/maven.config properties into the POM property map.
        // These are typically used for CI-friendly versions: -Drevision=X.Y.Z
        //
        // Maven treats `-D` entries as user properties, which sit ABOVE POM
        // <properties> in the precedence chain, so `.mvn/maven.config`
        // entries override same-named POM properties. We model that here by
        // overwriting (Option A in the bug write-up). A proper user-properties
        // layer with CLI `-D key=value` plumbing is a follow-up; this minimal
        // fix unblocks the CI-friendly-version pattern that motivated the bug.
        if let Some(workspace) = workspace.as_deref() {
            workspace.inject_root_properties(&mut pom);
        } else if let Some(project_dir) = path.parent() {
            let maven_config = crate::parent_resolver::parse_maven_config_async(project_dir).await;
            for (key, value) in maven_config {
                pom.properties.insert(key, value);
            }
        }

        let base_dir = path.parent().map(Path::to_path_buf);
        // #5: resolve profiles against the TARGET platform for this pass, so a
        // `--platforms macos-aarch64` build on a Linux host activates the
        // macOS profiles (and their deps) instead of the host's.
        let activation_base = if workspace.is_some() {
            None
        } else {
            base_dir.clone()
        };
        let mut activation = crate::parent_resolver::build_activation_context_async(
            activation_base,
            &self.ctx.config,
            Some(&self.ctx.platform),
        )
        .await;
        if let Some(workspace) = workspace.as_deref() {
            activation.base_dir = base_dir.clone();
            workspace.apply_root_maven_config(&mut activation);
        }

        // Pre-merge the child POM's declared repositories so they are available
        // during parent resolution. Without this, a POM whose parent only exists
        // on a repo declared in the child (e.g. Jenkins → repo.jenkins-ci.org)
        // would fail because parent resolution happens before repo merging.
        let repos_with_pom = if pom.repositories.is_empty() {
            repos.to_vec()
        } else {
            let pom_repos: Vec<Repository> = pom
                .repositories
                .iter()
                .cloned()
                .map(Repository::from)
                .collect();
            merge_repos(repos.to_vec(), pom_repos)
        };

        // The user's own POM is the trusted entrypoint: its <repositories>
        // should always be honored even under default-deny
        // `allow_transitive_repositories`, because the user wrote the file.
        // Transitive POMs reached from here still go through the gated path.
        //
        // `local_parent_boundary` owns the containment rule, so discovery,
        // `rv sync`'s model hashing, and resolution accept the same parents.
        // Without a reactor the project is a lone module by definition.
        let project_root = workspace
            .as_deref()
            .map(Workspace::local_parent_boundary)
            .or_else(|| {
                base_dir
                    .as_deref()
                    .map(|directory| crate::local_parent_boundary(directory, 1))
            });
        let mut backend = RepoBackend::new(&self.ctx, repos_with_pom, self.strict);
        if let Some(workspace) = workspace {
            backend = backend.with_workspace(workspace);
        }
        if let Some(support_poms) = workspace_support_poms {
            backend = backend.with_workspace_support_poms(support_poms);
        }
        let backend_clone = backend.clone();
        // The ROOT project's own parent and imported BOMs are ALWAYS resolved
        // strictly, independent of `self.strict` (which tracks `--frozen` and
        // governs transitive leniency). The root pom.xml is the user's build
        // contract: if its parent or an imported BOM cannot be resolved, Maven
        // itself fails, so `rv` must fail too rather than silently writing a
        // lock from a model Maven cannot build. Transitive parents/BOMs stay
        // lenient by default (they go through `backend`'s `self.strict`).
        let resolver = RepoParentResolver::with_strict_and_trust(
            backend,
            base_dir.clone(),
            project_root,
            true,
            RepoTrust::Root,
        );
        let project = Project::from_pom_with_context(pom, resolver, &activation)?;

        // Snapshot the backend after parent-chain resolution. Parent POMs may
        // have declared `<repositories>` via the `observe_project_repositories`
        // callback; those are needed by the solver backend that gets built
        // after this function returns. Also capture the support-POM provenance
        // recorded while resolving the ROOT's own parent/imported BOMs: those
        // are fetched here, on this backend, not the solver backend, so without
        // returning them the root closure's export markers would lose their
        // source-repo id.
        let observed_repos = backend_clone.repos_snapshot();
        let root_support_pom_provenance = backend_clone.support_pom_provenance_snapshot();

        let version = Version::parse(&project.version)?;
        let coord = Coord {
            group_id: project.group_id.clone().into(),
            artifact_id: project.artifact_id.clone().into(),
            version,
            packaging: Some(project.packaging.clone()),
            classifier: None,
        };
        Ok((coord, project, observed_repos, root_support_pom_provenance))
    }

    /// Write the reactor's buffered support POMs (parents / imported BOMs) into
    /// the content store.
    ///
    /// Reactor modules resolve concurrently but share one store, so
    /// `persist_support_pom` buffers their support POMs instead of writing them
    /// from every module at once; this is the write. A store-write failure is
    /// fatal for the same reason it is in `persist_support_pom`: provenance for
    /// these coordinates was recorded when they were buffered, and a lock whose
    /// provenance names a support POM the store never took is an offline
    /// repository that only `rv export-m2` discovers is incomplete. Failing
    /// here keeps the invariant that every recorded coordinate has bytes behind
    /// it, since the resolve this provenance belongs to never produces a lock.
    async fn flush_workspace_support_poms(&self, state: &WorkspaceStoreState) -> Result<()> {
        let pending = {
            let mut guard = state
                .support_poms
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *guard)
        };

        for (key, bytes) in pending {
            let blob = self.ctx.store.put_bytes(&bytes).await?;
            self.ctx.store.add_artifact(&key, &blob).await?;
            // A reactor can buffer thousands of support POMs; keep the stall
            // watchdog fed while they are written.
            state.progress.note();
        }
        Ok(())
    }

    async fn populate_artifacts(
        &self,
        backend: &RepoBackend,
        graph: &mut Graph,
        workspace_artifacts: Option<&Mutex<HashMap<ArtifactKey, HashMap<String, BlobId>>>>,
    ) -> Result<()> {
        let backend_repos = backend.repos_snapshot();

        // Filter to root-reachable nodes. Conflict eviction leaves orphan
        // nodes in the graph (their parent's outgoing edge was removed but
        // the node itself is preserved to keep NodeIndex values stable), and
        // walking every node would re-fetch artifacts the lockfile is going
        // to drop. Matches the reachability filter `build_lock_data` already
        // applies.
        let reachable: std::collections::HashSet<NodeIndex> = {
            let mut visited = std::collections::HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(graph.root());
            visited.insert(graph.root());
            while let Some(node) = queue.pop_front() {
                for (_, target, _) in graph.edges(node) {
                    if visited.insert(target) {
                        queue.push_back(target);
                    }
                }
            }
            visited
        };

        // First pass: identify artifacts to fetch (skip root, local, and already-cached)
        let node_count = graph.node_count().saturating_sub(1);
        let mut to_fetch: Vec<(NodeIndex, ArtifactRequest, ArtifactKey, Vec<Repository>)> =
            Vec::with_capacity(node_count);
        struct CacheCandidate {
            idx: NodeIndex,
            blob: BlobId,
            effective_repo: Option<String>,
            artifact_req: ArtifactRequest,
            key: ArtifactKey,
            repo_candidates: Vec<Repository>,
            resolved_repo: Option<String>,
        }

        let mut cache_candidates: Vec<CacheCandidate> = Vec::with_capacity(node_count);

        let node_indices = graph.node_indices().collect::<Vec<_>>();
        for idx in node_indices {
            if idx == graph.root() {
                continue;
            }
            if !reachable.contains(&idx) {
                continue;
            }
            let Some(node) = graph.node(idx) else {
                continue;
            };
            if node.local {
                continue;
            }
            if node.workspace_module.is_some() {
                continue;
            }
            if backend_repos.is_empty() {
                return Err(ResolveError::NoRepositories);
            }

            let artifact_req = ArtifactRequest::from_coord(&node.coord);
            let mut repo_candidates =
                filter_repos_for_version(&backend_repos, &artifact_req.version, &node.coord)?
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>();
            if let Some(repo_url) = node.repo_url.as_deref()
                && let Some(pos) = repo_candidates.iter().position(|repo| repo.url == repo_url)
            {
                let preferred = repo_candidates.remove(pos);
                repo_candidates.insert(0, preferred);
            }

            let key = ArtifactKey::new(
                artifact_req.group_id.as_str(),
                artifact_req.artifact_id.as_str(),
                artifact_req.version.as_str(),
                artifact_req.packaging.as_str(),
                artifact_req.classifier.clone(),
            );
            let selected_repo = node
                .repo_url
                .as_deref()
                .and_then(|url| repo_candidates.iter().find(|repo| repo.url == url))
                .or_else(|| repo_candidates.first());
            let effective_repo = selected_repo.map(|repo| {
                self.ctx.client.as_ref().map_or_else(
                    || repo.url.clone(),
                    |client| client.effective_repository_url(repo),
                )
            });
            let resolved_repo = effective_repo.as_deref().map(rv_repo::normalize_repo_url);

            // Reuse a blob that this reactor pass already verified from the
            // same repository. Re-running the store verifier for every later
            // module turns a large reactor into repeated whole-CAS hashing. A
            // different repository still takes the forced-probe path below,
            // which preserves byte-conflict detection.
            let reactor_blob =
                if let (Some(state), Some(repo)) = (workspace_artifacts, resolved_repo.as_ref()) {
                    state
                        .lock()
                        .map_err(|_| {
                            ResolveError::InternalError(
                                "workspace artifact provenance lock poisoned".to_string(),
                            )
                        })?
                        .get(&key)
                        .and_then(|by_repo| by_repo.get(repo))
                        .cloned()
                } else {
                    None
                };
            if let Some(blob) = reactor_blob {
                if let Some(node) = graph.node_mut(idx) {
                    node.checksum = Some(Checksum::new("sha256", blob.as_str()));
                    node.repo_url = effective_repo.map(Into::into);
                }
                continue;
            }

            // Within one reactor pass, a coordinate seen from a new source
            // repository must be fetched once even if another module already
            // populated the global coordinate -> blob cache. Reusing that row
            // blindly would hide "same coordinate, different bytes" across
            // modules. Repeats from a repository already observed in this
            // pass retain the normal cache fast path.
            let force_repository_probe =
                if let (Some(state), Some(repo)) = (workspace_artifacts, resolved_repo.as_ref()) {
                    let known = state.lock().map_err(|_| {
                        ResolveError::InternalError(
                            "workspace artifact provenance lock poisoned".to_string(),
                        )
                    })?;
                    known
                        .get(&key)
                        .is_some_and(|by_repo| !by_repo.is_empty() && !by_repo.contains_key(repo))
                } else {
                    false
                };
            if force_repository_probe {
                to_fetch.push((idx, artifact_req, key, repo_candidates));
                continue;
            }

            // Check cache first - verify content before trusting the hit.
            if let Some(blob) = self.ctx.store.lookup_artifact(&key).await? {
                cache_candidates.push(CacheCandidate {
                    idx,
                    blob,
                    effective_repo,
                    artifact_req,
                    key,
                    repo_candidates,
                    resolved_repo,
                });
                continue;
            }

            to_fetch.push((idx, artifact_req, key, repo_candidates));
        }

        if !cache_candidates.is_empty() {
            // Verify every cache hit: sampling would let corrupted blobs flow
            // downstream.
            let all_ids: Vec<BlobId> = cache_candidates.iter().map(|c| c.blob.clone()).collect();
            // Honor user-configured `network.concurrency` so a Raspberry Pi
            // runner with `concurrency = 1` doesn't get 32 hashers spun up
            // behind its back; clamp into the store's reasonable upper bound.
            let parallelism = self.ctx.config.network.concurrency.clamp(
                1,
                rv_store::Store::default_verification_parallelism().max(1),
            );
            // Verify in batches rather than in one call. Re-hashing every
            // cached blob of a large reactor is minutes of purely local work
            // that raises no repository event, so a single call would look
            // exactly like a wedged runtime to the watchdog. The batch is far
            // larger than any plausible parallelism, so the pipeline stays
            // full between batches.
            const VERIFY_BATCH: usize = 256;
            let mut verified_set = std::collections::HashSet::with_capacity(all_ids.len());
            for batch in all_ids.chunks(VERIFY_BATCH) {
                verified_set.extend(self.ctx.store.verify_blobs(batch, parallelism).await?);
                if let Some(progress) = backend.workspace_progress.as_ref() {
                    progress.note();
                }
            }

            let invalid_count = all_ids.len() - verified_set.len();
            if invalid_count > 0 {
                tracing::warn!(
                    invalid = invalid_count,
                    total = all_ids.len(),
                    "cache corruption detected; refetching invalid blobs"
                );
            }

            for candidate in cache_candidates {
                if !verified_set.contains(&candidate.blob) {
                    tracing::warn!(blob = %candidate.blob, "invalid cached artifact, refetching");
                    to_fetch.push((
                        candidate.idx,
                        candidate.artifact_req,
                        candidate.key,
                        candidate.repo_candidates,
                    ));
                    continue;
                }

                if let Some(node) = graph.node_mut(candidate.idx) {
                    let checksum = Checksum::new("sha256", candidate.blob.as_str());
                    node.checksum = Some(checksum);
                    node.repo_url = candidate.effective_repo.map(Into::into);
                }
                if let (Some(state), Some(repo)) = (workspace_artifacts, candidate.resolved_repo) {
                    state
                        .lock()
                        .map_err(|_| {
                            ResolveError::InternalError(
                                "workspace artifact provenance lock poisoned".to_string(),
                            )
                        })?
                        .entry(candidate.key)
                        .or_default()
                        .insert(repo, candidate.blob);
                }
            }
        }

        if to_fetch.is_empty() {
            return Ok(());
        }

        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::MissingRepoClient)?;

        // Parallel fetch with bounded concurrency (clamped to safe max)
        let concurrency = self
            .ctx
            .config
            .network
            .concurrency
            .clamp(1, crate::solver::MAX_FETCH_CONCURRENCY);
        let store = self.ctx.store.clone();
        let client = client.clone();

        let progress = backend.workspace_progress.clone();
        let results: Vec<_> = stream::iter(to_fetch)
            .map(|(idx, artifact_req, key, repo_candidates)| {
                let client = client.clone();
                let store = store.clone();
                let progress = progress.clone();
                async move {
                    // Bracket the download with events. Recording only the
                    // completion would measure the watchdog window from the
                    // *previous* artifact, so a queue that drains slowly could
                    // read as a stall; the attempt event restarts the window
                    // at the moment this download begins. The completion event
                    // covers success and failure alike — a repository that
                    // answers 500 is a live process, which is the only thing
                    // being asked here.
                    if let Some(progress) = progress.as_ref() {
                        progress.note();
                    }
                    let result = fetch_artifact_from_repos(
                        &client,
                        &store,
                        &artifact_req,
                        &key,
                        &repo_candidates,
                    )
                    .await;
                    if let Some(progress) = progress.as_ref() {
                        progress.note();
                    }
                    (idx, artifact_req, key, result)
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        // Process results and collect errors
        let mut errors: Vec<ResolveError> = Vec::with_capacity(results.len());
        for (idx, artifact_req, key, result) in results {
            match result {
                Ok((blob, repo_url)) => {
                    if let Some(state) = workspace_artifacts {
                        let blob_id = blob.parse::<BlobId>().map_err(|error| {
                            ResolveError::InternalError(format!(
                                "repository returned invalid blob identity: {error}"
                            ))
                        })?;
                        state
                            .lock()
                            .map_err(|_| {
                                ResolveError::InternalError(
                                    "workspace artifact provenance lock poisoned".to_string(),
                                )
                            })?
                            .entry(key)
                            .or_default()
                            .insert(rv_repo::normalize_repo_url(&repo_url), blob_id);
                    }
                    if let Some(node) = graph.node_mut(idx) {
                        let checksum = Checksum::new("sha256", blob.as_str());
                        node.checksum = Some(checksum);
                        node.repo_url = Some(repo_url.into());
                    }
                }
                Err(FetchError::NotFound { searched }) => {
                    let coord = graph
                        .node(idx)
                        .map(|node| node.coord.to_string())
                        .unwrap_or_else(|| {
                            format!("{}:{}", artifact_req.group_id, artifact_req.artifact_id)
                        });
                    errors.push(ResolveError::ArtifactNotFound { coord, searched });
                }
                Err(FetchError::Transient { err, searched }) => {
                    errors.push(ResolveError::RepoWithContext {
                        source: err,
                        searched,
                    });
                }
                Err(FetchError::Fatal { err, searched }) => {
                    errors.push(ResolveError::RepoWithContext {
                        source: err,
                        searched,
                    });
                }
            }
        }

        // Report errors - aggregate multiple errors if present
        let mut errors_iter = errors.into_iter();
        if let Some(first) = errors_iter.next() {
            let rest: Vec<_> = errors_iter.collect();
            if rest.is_empty() {
                return Err(first);
            }
            return Err(ResolveError::MultipleArtifactErrors {
                first: Box::new(first),
                rest,
            });
        }

        Ok(())
    }
}

/// For a `packaging = "pom"` package, require the artifact pin and the
/// companion-POM pin to name the same blob.
///
/// A pom-packaged dependency's artifact IS its POM: one file in the
/// repository, one path in `~/.m2`, and `rv export-m2` exports it as the
/// primary artifact. The two pins are nonetheless produced by two independent
/// observations — artifact population versus the model fetch that built the
/// graph — so they can disagree when the store's coordinate index is repointed
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
/// coordinate's companion POM, so it is not compared.
fn ensure_pom_packaging_identity(
    package: &LockPackage,
    artifact_blob: &BlobId,
    pom_blob: &BlobId,
) -> Result<()> {
    if package.packaging != "pom"
        || !package.classifier.as_deref().unwrap_or_default().is_empty()
        || artifact_blob == pom_blob
    {
        return Ok(());
    }
    Err(ResolveError::ConflictingPomPackagedBytes {
        coord: package.format_coord(),
        artifact_sha256: artifact_blob.to_string(),
        pom_sha256: pom_blob.to_string(),
    })
}

/// Collapse support-POM provenance to one entry per coordinate, in coordinate
/// order.
///
/// The entries arrive from two backends (the solver's and the one
/// `load_root_project` uses for the root's own parent/BOM chain), which can
/// disagree on the serving repository for a coordinate. Sorting puts the
/// id-less form ("") first, so keeping the first entry alone would let a POM
/// fetched from an id-less repository hide an id learned elsewhere and drop
/// that coordinate's `_remote.repositories` marker.
///
/// Repository-id preference applies only when the two entries agree on the
/// digest. Two backends that fetched *different bytes* for one coordinate is a
/// conflict: the lockfile pins one digest per support POM and `rv export-m2`
/// writes one `.pom`, so preferring either entry would leave the other one's
/// half of the resolution exported against a POM it never read. Reporting it
/// here also keeps `rv sync`'s reactor-wide check a genuine cross-module
/// backstop instead of a check on already-collapsed data.
fn merge_support_pom_provenance(
    mut entries: Vec<(String, SupportPomProvenance)>,
) -> Result<Vec<(String, SupportPomProvenance)>> {
    entries.sort();
    let mut merged: Vec<(String, SupportPomProvenance)> = Vec::with_capacity(entries.len());
    for (coord, provenance) in entries {
        match merged.last_mut() {
            Some((kept_coord, kept)) if *kept_coord == coord => {
                if kept.sha256 != provenance.sha256 {
                    return Err(ResolveError::ConflictingResolvedPomBytes {
                        coord,
                        first_sha256: kept.sha256.clone(),
                        second_sha256: provenance.sha256,
                    });
                }
                if kept.repo_id.is_empty() && !provenance.repo_id.is_empty() {
                    kept.repo_id = provenance.repo_id;
                }
            }
            _ => merged.push((coord, provenance)),
        }
    }
    Ok(merged)
}

/// Map a bounded project-input read failure on the root `pom.xml` onto the
/// resolver's error type. Oversize input keeps its typed
/// [`rv_config::ConfigError::ProjectInputTooLarge`] shape through
/// [`ResolveError::Config`]; I/O failures stay [`ResolveError::Io`] so a
/// missing or unreadable root POM reports exactly what the unbounded
/// `read_to_string` reported before, non-UTF-8 input included.
fn root_input_error(error: rv_config::ConfigError) -> ResolveError {
    match error {
        rv_config::ConfigError::ProjectInputIo { source, .. } => ResolveError::Io(source),
        rv_config::ConfigError::ProjectInputEncoding { .. } => ResolveError::Io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()),
        ),
        other => ResolveError::Config(other),
    }
}

impl ResolutionResult {
    pub fn to_lockfile(&self) -> Lockfile {
        let platform = LockPlatform::single_module(
            self.platform.clone(),
            "",
            "pom.xml",
            self.module_gav.clone(),
            self.module_packaging.clone(),
            self.packages.clone(),
            self.edges.clone(),
        );
        let mut lock = Lockfile::new();
        lock.platforms.push(platform);
        lock
    }
}

#[cfg(test)]
mod tests;
