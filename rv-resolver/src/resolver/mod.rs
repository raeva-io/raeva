mod backend;
pub(crate) mod pom_source;
pub(crate) mod prefetch;
mod reactor_models;
mod scope;
mod utils;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foldhash::{HashMap, HashMapExt};
use futures::FutureExt;
use futures::future::{Either, select};
use futures::stream::{self, StreamExt};
use petgraph::graph::NodeIndex;
use rv_config::Config;
use rv_lock::Platform;
use rv_maven_model::held::{Held, Holds};
use rv_maven_model::{Pom, Project, Scope};
use rv_maven_types::{ArtifactCoord, BlobId, Coord, Gav, Version};
use rv_repo::{ArtifactRequest, RepoClient, Repository};
use rv_store::Store;

use crate::context::{ResolveContext, ResolveState};
use crate::error::{ResolveError, Result};
use crate::graph::Graph;
use crate::output::ModuleResolution;
use crate::parent_resolver::LocalParents;
use crate::solver::{Management, Solver, SolverRoot};
use crate::util::lock;
use crate::workspace::Workspace;

pub use backend::SupportPomProvenance;
pub(crate) use backend::pom_digest_text;
use backend::{ModelService, WorkspaceSupportPomBuffer};
use reactor_models::{KeptImports, ReactorModels};
use scope::ModelScope;
pub(crate) use scope::parent_coord;
use utils::{FetchError, build_lock_data, fetch_artifact_from_repos};
pub(crate) use utils::{filter_repos_for_version, merge_repos};

/// Evidence rows for [`rv_store::Store::record_served`]: a key, its blob,
/// and the repository and endpoint that served it.
type ServedRows = Vec<(ArtifactCoord, BlobId, String, String)>;

/// The dependency resolver. It resolves every active module of a
/// [`Workspace`] for one platform at a time, with Maven's nearest-wins
/// mediation.
///
/// Clones share the cache of parsed POMs, keyed by the bytes they were read
/// from, so one resolver can resolve several platforms. Everything else a
/// resolution caches belongs to one module on one platform.
#[derive(Clone)]
pub struct Resolver {
    config: Arc<Config>,
    store: Arc<Store>,
    client: RepoClient,
    stall_timeout: Option<Duration>,
    state: Arc<ResolveState>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("stall_timeout", &self.stall_timeout)
            .finish_non_exhaustive()
    }
}

impl Resolver {
    /// A resolver for the project `config` describes, writing to `store`
    /// and reading repositories through `client`.
    pub fn new(config: Arc<Config>, store: Arc<Store>, client: RepoClient) -> Self {
        Self {
            config,
            store,
            client,
            stall_timeout: Some(WORKSPACE_STALL_TIMEOUT),
            state: ResolveState::new(),
        }
    }

    /// How long a reactor resolution may make no progress before it fails
    /// with [`ResolveError::WorkspaceStalled`]; `None` turns the watchdog
    /// off. The default is 15 minutes.
    pub fn with_stall_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.stall_timeout = timeout;
        self
    }

    /// Resolve every active module of `workspace` for `platform`, which
    /// selects the configuration's per-platform settings and the profiles
    /// that activate.
    ///
    /// Modules build their graphs in parallel and populate their artifacts
    /// in discovery order as the graphs come in, downloading none before
    /// every module's own dependencies pass the checks a graph starts with;
    /// the support POMs and the store's rows are written at the end. A
    /// watchdog fails the resolution with [`ResolveError::WorkspaceStalled`]
    /// when nothing at all happens for the stall timeout, so a scheduling
    /// bug fails a build with the stuck modules named instead of hanging it.
    pub async fn resolve_workspace(
        &self,
        workspace: &Workspace,
        platform: &Platform,
    ) -> Result<WorkspaceResolution> {
        let ctx = ResolveContext::from_config_with_state(
            self.config
                .for_platforms([(platform.os(), platform.arch(), platform.jdk())]),
            Arc::clone(&self.store),
            platform.clone(),
            Some(self.client.clone()),
            Arc::clone(&self.state),
        );
        PlatformResolver::new(ctx)
            .resolve_workspace_with_stall_timeout(workspace, self.stall_timeout)
            .await
    }
}

#[derive(Clone)]
pub(crate) struct PlatformResolver {
    ctx: ResolveContext,
}

/// How many module graphs resolve at once: one per CPU, from four to eight.
/// Eight concurrent modules bound reactor memory use.
fn max_module_concurrency() -> usize {
    std::thread::available_parallelism().map_or(4, |cpus| cpus.get().clamp(4, 8))
}

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

/// Which part of the resolution a tracked unit of work is in, so a stall
/// diagnostic says what was happening and not only where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkPhase {
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
/// reads as healthy while a wedged runtime, which by construction raises no
/// events, is caught.
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
    /// [`ModelService`], so it must stay allocation-free and lock-free.
    pub(crate) fn note(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
    }

    fn events(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn enter(&self, index: usize, module: &str, phase: WorkPhase) {
        lock(&self.in_flight).insert(
            index,
            InFlight {
                module: module.to_string(),
                phase,
            },
        );
        self.note();
    }

    fn leave(&self, index: usize) {
        lock(&self.in_flight).remove(&index);
        self.note();
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

/// `work`, started now on a task of `runtime`, or run in place when awaited
/// without one.
fn on_task<T: Send + 'static>(
    runtime: Option<&tokio::runtime::Handle>,
    work: impl std::future::Future<Output = Result<T>> + Send + 'static,
) -> impl std::future::Future<Output = Result<T>> {
    let Some(runtime) = runtime else {
        return futures::future::Either::Right(work);
    };
    let mut task = AbortOnDrop(runtime.spawn(work));
    futures::future::Either::Left(async move {
        match (&mut task.0).await {
            Ok(result) => result,
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(_) => Err(ResolveError::InternalError(
                "module resolution task was cancelled".to_string(),
            )),
        }
    })
}

/// A module's resolution once its artifacts are populated: its lock rows
/// and the repositories, support POMs and parent ranges it recorded.
fn complete_resolution(
    platform: Platform,
    pending: PendingModuleResolution,
) -> Result<ModuleResolution> {
    let PendingModuleResolution {
        backend,
        graph,
        module_gav,
        module_packaging,
        root_support_pom_provenance,
        root_parent_ranges,
    } = pending;
    let (packages, edges) =
        build_lock_data(&graph, |gav, repos| backend.companion_pom(gav, repos))?;

    // Record the id'd repositories that backed this resolution (config +
    // any POM-declared ones the backend accumulated during the solve) so
    // export-m2 can label markers for repos it cannot otherwise see.
    let trusted_repositories = backend.effective_repos_snapshot();
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

    let mut parent_ranges: std::collections::BTreeSet<_> = root_parent_ranges.into_iter().collect();
    {
        let models = lock(&backend.parent_ranges);
        if !models.is_empty() {
            for index in graph.reachable() {
                if index != graph.root()
                    && let Some(node) = graph.node(index)
                    && let Some(selections) = models.get(&(
                        crate::graph::ExactCoord(node.coord.clone()),
                        node.repos.clone(),
                    ))
                {
                    parent_ranges.extend(selections.iter().cloned());
                }
            }
        }
    }
    Ok(ModuleResolution {
        graph,
        platform,
        packages,
        edges,
        module_gav,
        module_packaging,
        repositories,
        trusted_repositories,
        support_pom_provenance,
        parent_ranges: parent_ranges.into_iter().collect(),
        host_reads: Default::default(),
    })
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
            let modules = lock(&progress.in_flight)
                .values()
                .map(|entry| format!("{} ({})", entry.module, entry.phase.label()))
                .collect::<Vec<_>>()
                .join(", ");
            return ResolveError::WorkspaceStalled {
                modules,
                stalled_for_secs: idle.as_secs(),
            };
        }
    }
}

/// Normalized declared repository and serving endpoint URLs.
type RepositoryScope = (String, String);

struct WorkspaceStoreState {
    support_poms: WorkspaceSupportPomBuffer,
    artifact_blobs: Mutex<HashMap<ArtifactCoord, HashMap<RepositoryScope, BlobId>>>,
    /// Index rows for blobs this reactor pass stored, written together once
    /// every module's artifacts are in.
    pending_rows: Mutex<PendingRows>,
    progress: Arc<WorkspaceProgress>,
    models: Arc<ReactorModels>,
    /// Holds what a module logs ahead of its turn.
    holds: Holds,
}

impl WorkspaceStoreState {
    fn new() -> Self {
        Self {
            support_poms: Arc::default(),
            artifact_blobs: Mutex::new(HashMap::new()),
            pending_rows: Mutex::default(),
            progress: Arc::new(WorkspaceProgress::new()),
            models: Arc::default(),
            holds: Holds::default(),
        }
    }

    fn with_progress(progress: Arc<WorkspaceProgress>) -> Self {
        Self {
            progress,
            ..Self::new()
        }
    }

    #[cfg(test)]
    pub(crate) fn for_testing(support_poms: Vec<(ArtifactCoord, Vec<u8>)>) -> Self {
        let state = Self::new();
        let repo: Arc<str> = Arc::from("https://repo.example/");
        for (key, bytes) in support_poms {
            let route = backend::PomRoute {
                key: key.clone(),
                repo: Arc::clone(&repo),
                endpoint: Arc::clone(&repo),
            };
            (state.support_poms).record(&key, &BlobId::from_bytes(&bytes), &bytes, &route);
        }
        state
    }
}

struct PendingModuleResolution {
    backend: ModelService,
    graph: Graph,
    module_gav: Gav,
    module_packaging: String,
    root_support_pom_provenance: Vec<(String, SupportPomProvenance)>,
    root_parent_ranges: Vec<rv_lock::ParentRange>,
}

/// The classifier likes of a platform pass, and what finding them read.
/// Those reads, and the reactor when the first sorted project sets the
/// likes, count only once a build reads the likes, so a pass that never
/// reads `${os.detected.classifier}` records nothing of them.
struct ReactorLikes {
    likes: rv_maven_model::ClassifierLikes,
    reads: Arc<std::collections::BTreeSet<rv_maven_model::HostInput>>,
    from_project: bool,
}

struct WorkspaceModuleWork {
    index: usize,
    pom_path: String,
    resolver: PlatformResolver,
    pending: PendingModuleResolution,
}

/// One module's graph in an all-reactor resolution.
#[derive(Debug)]
#[non_exhaustive]
pub struct WorkspaceModuleResolution {
    /// The module's [`WorkspaceModule::pom_path`](crate::WorkspaceModule::pom_path).
    pub pom_path: String,
    /// The module's resolved graph and lock rows.
    pub resolution: ModuleResolution,
}

/// Per-platform output from resolving every active module in a workspace.
#[derive(Debug)]
#[non_exhaustive]
pub struct WorkspaceResolution {
    /// The platform every module was resolved for.
    pub platform: Platform,
    /// One entry per active module, in [`Workspace::modules`] order.
    pub modules: Vec<WorkspaceModuleResolution>,
    /// Whether a graph depends on the reactor in a way no module's own
    /// declarations show: a dependency's model read a reactor POM, or a
    /// transitive version range or dynamic version had reactor modules
    /// among its candidates.
    pub reactor_through_dependencies: bool,
    /// What the resolution read from the host outside the modules' own
    /// builds, which every graph depends on.
    pub host_reads: std::collections::BTreeSet<rv_maven_model::HostInput>,
}

impl PlatformResolver {
    pub(crate) fn new(ctx: ResolveContext) -> Self {
        Self { ctx }
    }

    #[cfg(test)]
    pub(crate) async fn resolve_workspace(
        &self,
        workspace: &Workspace,
    ) -> Result<WorkspaceResolution> {
        self.resolve_workspace_with_stall_timeout(workspace, Some(WORKSPACE_STALL_TIMEOUT))
            .await
    }

    /// Resolve every active reactor module for this resolver's platform,
    /// failing with [`ResolveError::WorkspaceStalled`] after `stall_timeout`
    /// without progress.
    ///
    /// Project and model caches are scoped to a single module resolution:
    /// repositories declared by module A must not make a cached project
    /// visible under module B's repository context.
    pub(crate) async fn resolve_workspace_with_stall_timeout(
        &self,
        workspace: &Workspace,
        stall_timeout: Option<Duration>,
    ) -> Result<WorkspaceResolution> {
        let progress = Arc::new(WorkspaceProgress::new());
        // The watchdog needs a tokio runtime to spawn onto and a timer to tick
        // on. Both hold for every `raeva` entry point; an embedder driving this
        // future on another executor gets the resolution unguarded rather than
        // a panic from `tokio::spawn`.
        let timeout = stall_timeout.filter(|_| tokio::runtime::Handle::try_current().is_ok());
        let Some(timeout) = timeout else {
            return self
                .resolve_workspace_watched(workspace.clone(), progress)
                .await;
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
                .resolve_workspace_watched(owned, module_progress)
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
            stalled = watch_for_stall(progress, timeout) => Err(stalled),
        }
    }

    async fn resolve_workspace_watched(
        &self,
        workspace: Workspace,
        progress: Arc<WorkspaceProgress>,
    ) -> Result<WorkspaceResolution> {
        // What the pass reads outside the modules' own builds counts for
        // every graph.
        let reactor_reads = rv_maven_model::HostReads::default();
        let reactor = Self::new(self.ctx.recording_into(reactor_reads.clone()));
        let store_state = Arc::new(WorkspaceStoreState::with_progress(progress));
        // The support POMs these models read are written with the modules'.
        let support_poms = &store_state.support_poms;
        let workspace =
            (reactor.with_effective_gavs(workspace, &store_state.progress, support_poms)).await?;
        let likes = reactor.classifier_likes(&workspace, support_poms).await;
        let module_concurrency = max_module_concurrency().min(workspace.len().max(1));

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

        // Each module's graph is resolved on its own task, so the model
        // building, which is most of a warm resolution, runs on as many
        // threads as there are modules in flight instead of on one.
        let runtime = tokio::runtime::Handle::try_current().ok();
        let module_ctx = || {
            self.ctx
                .for_module(self.ctx.config.clone())
                .with_classifier_likes(likes.as_ref().map(|likes| likes.likes.clone()))
                .recording_into(rv_maven_model::HostReads::default())
        };
        // A module fails on its own dependencies before it reads any, but
        // it may start only after the modules ahead of it have downloaded
        // their artifacts. So no artifact is downloaded until every module's
        // own dependencies pass their checks, beside the graphs, which start
        // once one would be, or until every graph is in; after a failed
        // graph, none is. A failed check is not one: a POM it could not
        // fetch, the graph may.
        // Without a prefetcher nothing is downloaded, and a lone module
        // checks its own dependencies before it reads any.
        let prefetcher = (self.ctx.prefetcher.as_ref()).filter(|_| workspace.len() > 1);
        if let Some(prefetcher) = prefetcher {
            prefetcher.hold_artifacts();
        }
        let imports = Arc::<KeptImports>::default();
        let checked = stream::iter(module_specs.clone())
            .map(|(_, _, absolute_pom)| {
                let workspace = Arc::clone(&workspace);
                let store_state = Arc::clone(&store_state);
                let imports = Arc::clone(&imports);
                let resolver = PlatformResolver::new(module_ctx());
                let check = async move {
                    let support_poms = &store_state.support_poms;
                    let check = resolver.check_own_dependencies(
                        &absolute_pom,
                        workspace,
                        support_poms,
                        &imports,
                    );
                    // The module's graph logs what this would.
                    Ok(store_state.holds.hold(check).await.0)
                };
                on_task(runtime.as_ref(), check).map(|checked| checked.flatten().is_ok())
            })
            .buffer_unordered(module_concurrency)
            .all(std::future::ready);
        let checking = async {
            let Some(prefetcher) = prefetcher else {
                return;
            };
            if prefetcher.downloads_wanted().await {
                let released = std::pin::pin!(prefetcher.downloads_released());
                if let Either::Left((true, _)) = select(std::pin::pin!(checked), released).await {
                    prefetcher.release_artifacts(true);
                }
            }
        };
        // Once a graph fails the pass fails, so no other module starts or
        // downloads its artifacts.
        let graph_failed = Arc::new(AtomicBool::new(false));
        let graphs = stream::iter(module_specs)
            .take_while(|_| std::future::ready(!graph_failed.load(Ordering::Relaxed)))
            .map(|(index, pom_path, absolute_pom)| {
                let graph_failed = Arc::clone(&graph_failed);
                let workspace = Arc::clone(&workspace);
                let store_state = Arc::clone(&store_state);
                let resolver = PlatformResolver::new(module_ctx());
                let module = async move {
                    tracing::debug!(
                        target: "rv_resolver::workspace",
                        module = %pom_path,
                        "starting workspace module resolution"
                    );
                    let progress = Arc::clone(&store_state.progress);
                    progress.enter(index, &pom_path, WorkPhase::Graph);
                    let holds = store_state.holds.clone();
                    let (pending, held) = holds
                        .hold(resolver.resolve_graph_internal(
                            &absolute_pom,
                            workspace,
                            Some(store_state),
                        ))
                        .await;
                    progress.leave(index);
                    if pending.is_err() {
                        graph_failed.store(true, Ordering::Relaxed);
                    }
                    let work = pending.map(|pending| WorkspaceModuleWork {
                        index,
                        pom_path,
                        resolver,
                        pending,
                    });
                    Ok((work, held))
                };
                on_task(runtime.as_ref(), module).map(move |joined| {
                    (
                        index,
                        joined.unwrap_or_else(|error| (Err(error), Held::default())),
                    )
                })
            })
            .buffer_unordered(module_concurrency);
        let (done, mut resolved) = futures::channel::mpsc::unbounded();
        let failed = Arc::clone(&graph_failed);
        let resolving = async move {
            graphs
                .for_each(|result| {
                    // The receiver is dropped only after the last result.
                    let _ = done.unbounded_send(result);
                    std::future::ready(())
                })
                .await;
            if let Some(prefetcher) = prefetcher {
                prefetcher.release_artifacts(!failed.load(Ordering::Relaxed));
            }
        };
        // Each module's artifacts are populated, in reactor order, as soon as
        // its graph and those of the modules before it are in, while later
        // graphs still resolve. Every row of the pass is written at the end,
        // in one transaction after one sync of the blobs they name, including
        // when a module fails, so a rerun reuses what was downloaded. What a
        // module logs is held until every graph is in and the support POMs
        // are flushed, then shown in reactor order up to the module that
        // failed, if one did. A failed graph shows only what graphs logged.
        let finishing = async {
            let mut ready = BTreeMap::new();
            let mut next = 0;
            let mut completing = Vec::new();
            let mut retired = Vec::new();
            // Graphs that were in before the failed one but not populated.
            let mut unpopulated = Vec::new();
            let (mut graph_failure, mut failure) = (None, None);
            loop {
                let result = resolved.next().await;
                let all_in = result.is_none();
                if let Some((index, work)) = result {
                    ready.insert(index, work);
                }
                while let Some((work, graph)) = ready.remove(&next) {
                    next += 1;
                    let module: WorkspaceModuleWork = match work {
                        Ok(module)
                            if graph_failure.is_none()
                                && failure.is_none()
                                && !graph_failed.load(Ordering::Relaxed) =>
                        {
                            module
                        }
                        Ok(_) if graph_failure.is_none() && failure.is_none() => {
                            unpopulated.push(graph);
                            continue;
                        }
                        Ok(_) => continue,
                        Err(error) => {
                            let module = &workspace.modules()[next - 1].pom_path;
                            graph_failure.get_or_insert((error.in_module(module), graph));
                            continue;
                        }
                    };
                    store_state.progress.enter(
                        module.index,
                        &module.pom_path,
                        WorkPhase::ArtifactPopulation,
                    );
                    let mut pending = module.pending;
                    let (populated, held) = (store_state.holds)
                        .hold(module.resolver.populate_artifacts(
                            &pending.backend,
                            &mut pending.graph,
                            Some(&store_state),
                        ))
                        .await;
                    let platform = module.resolver.ctx.platform.clone();
                    let reads = module.resolver.ctx.reads.clone().unwrap_or_default();
                    retired.push((pending.backend.clone(), module.resolver));
                    store_state.progress.leave(module.index);
                    match populated {
                        // The rest needs nothing of the other modules, so it
                        // runs while later modules populate.
                        Ok(()) => {
                            let holds = store_state.holds.clone();
                            let rows = async move {
                                let rows = async move { complete_resolution(platform, pending) };
                                let rows = holds.hold(rows).await;
                                // Nothing records into the module's reads now.
                                Ok((rows, reads.take()))
                            };
                            let rows = on_task(runtime.as_ref(), rows);
                            completing.push((module.pom_path, rows, graph, held));
                        }
                        Err(error) => {
                            let error = error.in_module(&module.pom_path);
                            failure = Some((error, (graph, held)));
                        }
                    }
                }
                if all_in {
                    break;
                }
            }
            // A module before the first failure to populate may still fail
            // to complete; the first failure in reactor order is reported.
            let mut modules = Vec::new();
            let mut held = Vec::new();
            for (pom_path, rows, graph, populated) in completing {
                let ((rows, completed), host_reads) = (rows.await)
                    .unwrap_or_else(|error| ((Err(error), Held::default()), BTreeSet::new()));
                held.push((graph, populated.and(completed)));
                match rows {
                    Ok(mut resolution) => {
                        resolution.host_reads = host_reads;
                        modules.push(WorkspaceModuleResolution {
                            pom_path,
                            resolution,
                        });
                    }
                    Err(error) => {
                        failure = Some((error.in_module(&pom_path), Default::default()));
                        break;
                    }
                }
            }
            let failure = failure.map(|(error, failed)| {
                held.push(failed);
                error
            });
            (modules, held, unpopulated, retired, graph_failure, failure)
        };
        let ((), (), (modules, held, unpopulated, retired, graph_failure, failure)) =
            futures::join!(checking, resolving, finishing);
        store_state.models.clear();
        crate::util::drop_in_background(retired);
        // Modules resolve in any order; a failed graph is reported first, the
        // first in reactor order.
        if let Some((error, failed)) = graph_failure {
            for (graph, _) in held {
                graph.show();
            }
            for graph in unpopulated {
                graph.show();
            }
            failed.show();
            return Err(error);
        }
        // The flush runs outside any module's graph entry, so it registers
        // its own in-flight work: a stall here would otherwise name nothing at
        // all, which is the least useful moment to lose the label.
        store_state
            .progress
            .enter(REACTOR_WIDE, "reactor", WorkPhase::SupportPomFlush);
        let flushed = self.flush_workspace_support_poms(&store_state).await;
        store_state.progress.leave(REACTOR_WIDE);
        let (support_rows, support_served) = flushed?;
        for (index, (graph, held)) in held.into_iter().enumerate() {
            graph.and(held).show();
            if let Some(module) = modules.get(index) {
                tracing::debug!(
                    target: "rv_resolver::workspace",
                    module = %module.pom_path,
                    nodes = module.resolution.graph.node_count(),
                    "finished workspace module resolution"
                );
            }
        }
        let PendingRows { mut rows, origins } =
            std::mem::take(&mut *lock(&store_state.pending_rows));
        rows.splice(0..0, support_rows);
        self.ctx.store.add_artifacts(rows).await?;
        self.ctx.store.record_origins(origins).await?;
        self.ctx.store.record_served(support_served).await?;
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(likes) = likes.filter(|likes| likes.likes.read()) {
            reactor.ctx.record_reads(&likes.reads);
            if likes.from_project {
                // Every module's classifier reads them, and edits anywhere in
                // the reactor can change which project Maven sorts first.
                self.ctx.note_reactor_through_dependencies();
            }
        }

        Ok(WorkspaceResolution {
            platform: self.ctx.platform.clone(),
            modules,
            reactor_through_dependencies: self.ctx.reactor_through_dependencies(),
            host_reads: reactor_reads.take(),
        })
    }

    /// os-maven-plugin's `os.detection.classifierWithLikes` for this
    /// platform's build. The plugin reads it once, after Maven sorts the
    /// reactor, from the first sorted project's model, else from the user
    /// properties, and the classifier of every model takes its suffix.
    /// `None` where no classifier can take one.
    async fn classifier_likes(
        &self,
        workspace: &Arc<Workspace>,
        support_poms: &WorkspaceSupportPomBuffer,
    ) -> Option<ReactorLikes> {
        const LIKES: &str = "os.detection.classifierWithLikes";
        if !self.ctx.environment().reads_classifier_likes() {
            return None;
        }
        let reads = rv_maven_model::HostReads::default();
        let search = Self::new(self.ctx.recording_only_into(reads.clone()));
        let first = search.first_sorted_project(workspace, support_poms).await;
        let own = first.and_then(|project| project.classifier_with_likes);
        let from_project = own.is_some();
        if (search.ctx.config.defined_settings_properties()).contains(LIKES) {
            // An active settings.xml profile's likes are the project's, over
            // any other, so a profile that sets them counts, active or not.
            search.ctx.environment().record_settings_property(LIKES);
        }
        let likes = own.or_else(|| {
            let environment = search.ctx.environment();
            environment.record_user_property(LIKES);
            let activation = rv_maven_model::ActivationContext::new(environment);
            workspace.root_user_properties(&activation).0.remove(LIKES)
        });
        Some(ReactorLikes {
            likes: rv_maven_model::ClassifierLikes::new(likes.as_deref()),
            reads: Arc::new(reads.take()),
            from_project,
        })
    }

    /// The project Maven 3.9's `ProjectSorter` puts first, the session's
    /// current project. Its `TopologicalSorter` starts from the first
    /// project the reactor builds, the one reached through each first
    /// `<module>`, and follows the first edge to another reactor project
    /// until a project has none. A project's edges lead to the projects its
    /// dependencies name, in order, then to its parent. The build plugin
    /// and extension edges Maven adds after those are not followed. A model
    /// that fails to build ends the search, and the resolution of that
    /// module reports it.
    async fn first_sorted_project(
        &self,
        workspace: &Arc<Workspace>,
        support_poms: &WorkspaceSupportPomBuffer,
    ) -> Option<Project> {
        let modules = workspace.modules();
        let mut by_id: HashMap<(&str, &str), Vec<(&str, usize)>> = HashMap::new();
        for (index, module) in modules.iter().enumerate() {
            let gav = module.gav();
            by_id
                .entry((&gav.group_id, &gav.artifact_id))
                .or_default()
                .push((&gav.version, index));
        }
        // Maven links a version that is empty or a range to every version
        // of the id in the reactor.
        let projects = |group: &str, artifact: &str, version: Option<&str>| -> Vec<usize> {
            let specific = version.filter(|v| !v.is_empty() && !v.starts_with(['[', '(']));
            by_id
                .get(&(group, artifact))
                .into_iter()
                .flatten()
                .filter(|(known, _)| specific.is_none_or(|version| version == *known))
                .map(|(_, index)| *index)
                .collect()
        };
        let mut vertex = modules
            .iter()
            .position(|module| module.descriptor.modules.is_empty())?;
        let mut visited = std::collections::HashSet::new();
        // The projects on the way build the same imported BOMs, each logging
        // what its own builds log.
        let imports = Arc::<KeptImports>::default();
        loop {
            // Maven refuses a reactor whose edges form a cycle.
            if !visited.insert(vertex) {
                return None;
            }
            let path = workspace.root().join(&modules[vertex].pom_path);
            let (_, project, _, _) = self
                .load_root_project(
                    &path,
                    &self.ctx.repos,
                    Arc::clone(workspace),
                    Some(support_poms),
                    Some(&imports),
                )
                .await
                .ok()?;
            imports.forget_logged();
            let dependencies = project.dependencies.iter().map(|dependency| {
                (
                    dependency.group_id.as_str(),
                    dependency.artifact_id.as_str(),
                    dependency.version.as_deref(),
                )
            });
            let parent = project.parent.iter().map(|parent| {
                (
                    parent.group_id.as_str(),
                    parent.artifact_id.as_str(),
                    Some(parent.version.as_str()),
                )
            });
            let next = dependencies
                .chain(parent)
                .flat_map(|(group, artifact, version)| projects(group, artifact, version))
                .find(|target| *target != vertex);
            match next {
                Some(target) => vertex = target,
                None => return Some(project),
            }
        }
    }

    /// `workspace` indexed by its modules' effective GAVs, as Maven indexes
    /// the reactor. Discovery reads local parents only, so a GAV that holds
    /// an expression or inherits from a remote parent may take another value
    /// from that parent's model. The GAV comes
    /// from the module's lineage alone, before any BOM import, which may
    /// name another such module.
    async fn with_effective_gavs(
        &self,
        workspace: Workspace,
        progress: &Arc<WorkspaceProgress>,
        support_poms: &WorkspaceSupportPomBuffer,
    ) -> Result<Arc<Workspace>> {
        let shared = Arc::new(workspace);
        let workspace = &*shared;
        let mut gavs = Vec::new();
        for (index, module) in workspace.modules().iter().enumerate() {
            if !module.descriptor.gav_is_provisional() {
                continue;
            }
            let path = workspace.root().join(&module.pom_path);
            progress.enter(index, &module.pom_path, WorkPhase::Graph);
            let in_module = |err: ResolveError| err.in_module(&module.pom_path);
            let (pom, activation, backend, local_parents) = self
                .root_model_inputs(
                    &path,
                    &self.ctx.repos,
                    Arc::clone(&shared),
                    Some(support_poms),
                    None,
                )
                .await
                .map_err(in_module)?;
            let backend = backend.with_workspace_progress(Arc::clone(progress));
            let descriptor = rv_maven_model::EffectiveDescriptor::build(
                pom,
                &ModelScope::root(&backend, local_parents),
                rv_maven_model::ModelPolicy::PROJECT,
                &activation,
            )
            .await
            .map_err(|err| in_module(project_model_error(err, &path)))?;
            progress.leave(index);
            gavs.push((index, descriptor.gav));
        }
        if gavs.is_empty() {
            return Ok(shared);
        }
        workspace
            .with_effective_gavs(gavs)
            .map(Arc::new)
            .map_err(|error| match error {
                crate::WorkspaceError::DuplicateGav { ref second_pom, .. } => {
                    ResolveError::LocalPom {
                        path: workspace.root().join(second_pom).display().to_string(),
                        source: rv_maven_model::PomError::InvalidModel(error.to_string()),
                    }
                }
                error => ResolveError::InternalError(error.to_string()),
            })
    }

    #[cfg(test)]
    async fn resolve_internal(
        &self,
        path: &Path,
        workspace: Arc<Workspace>,
        workspace_store: Option<Arc<WorkspaceStoreState>>,
    ) -> Result<ModuleResolution> {
        let pending = self
            .resolve_graph_internal(path, workspace, workspace_store.clone())
            .await?;
        if let Some(state) = workspace_store.as_ref() {
            let (rows, served) = self.flush_workspace_support_poms(state).await?;
            self.ctx.store.add_artifacts(rows).await?;
            self.ctx.store.record_served(served).await?;
        }
        let mut pending = pending;
        self.populate_artifacts(&pending.backend, &mut pending.graph, None)
            .await?;
        complete_resolution(self.ctx.platform.clone(), pending)
    }

    async fn resolve_graph_internal(
        &self,
        path: &Path,
        workspace: Arc<Workspace>,
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
                Arc::clone(&workspace),
                workspace_store.as_ref().map(|state| &state.support_poms),
                workspace_store.as_ref().map(|state| &state.models.imports),
            )
            .await?;
        if !project.repositories.is_empty() {
            let declared = project.repositories.iter().cloned().map(Repository::from);
            repos = merge_repos(repos, declared.collect());
        }
        if !observed_repos.is_empty() {
            repos = merge_repos(repos, observed_repos);
        }
        let module_gav = Gav::new(
            root_coord.group_id.as_str(),
            root_coord.artifact_id.as_str(),
            &root_coord.version.to_string(),
        );
        let module_packaging = root_coord
            .packaging
            .clone()
            .unwrap_or_else(|| "jar".to_string());
        let root_parent_ranges = backend::model_parent_ranges(&module_gav.to_string(), &project);
        let management = Management::new(project.dependency_management.dependencies);
        let root_spec = SolverRoot {
            coord: root_coord,
            dependencies: project.dependencies,
            scope: Scope::Compile,
        };

        tracing::debug!(
            direct_deps = root_spec.dependencies.len(),
            "starting dependency resolution"
        );

        let mut backend = ModelService::new(&self.ctx, repos).with_workspace(workspace);
        if let Some(state) = workspace_store.as_ref() {
            backend = backend.with_workspace_support_poms(Arc::clone(&state.support_poms));
            backend = backend.with_workspace_progress(Arc::clone(&state.progress));
            backend = backend.with_reactor_models(Arc::clone(&state.models));
        }

        let graph = Solver::new(&backend)
            .with_management(management)
            .solve(root_spec)
            .await?;
        backend.release_graph_caches();
        // With what the graph logged, which a reactor shows though another
        // module fails.
        let reachable = graph.reachable();
        for index in graph
            .node_indices()
            .filter(|index| reachable.contains(index))
        {
            if index != graph.root()
                && let Some(node) = graph.node(index)
                && !node.local
                && node.workspace_module.is_none()
            {
                backend.report_pom_problem(&node.coord);
            }
        }

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
            root_parent_ranges,
        })
    }

    /// The module POM at `path` as its build reads it, with the root's
    /// `.mvn/maven.config` applied, its activation context, and the model
    /// service and local parents the build reads.
    async fn root_model_inputs(
        &self,
        path: &Path,
        repos: &[Repository],
        workspace: Arc<Workspace>,
        support_poms: Option<&WorkspaceSupportPomBuffer>,
        kept_imports: Option<&Arc<KeptImports>>,
    ) -> Result<(
        Pom,
        rv_maven_model::ActivationContext,
        ModelService,
        LocalParents,
    )> {
        // Oversize input keeps its typed ConfigError through ResolveError::Config;
        // I/O and encoding failures stay ResolveError::Io so a missing or
        // unreadable root POM reports what unbounded read_to_string reported.
        let contents = crate::parent_resolver::read_project_input_async(path)
            .await
            .map_err(|error| match error {
                rv_config::ConfigError::ProjectInputIo { source, .. } => ResolveError::Io(source),
                rv_config::ConfigError::ProjectInputEncoding { .. } => ResolveError::Io(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()),
                ),
                other => ResolveError::Config(other),
            })?;
        // Discovery already parsed these bytes through ParsedPomCache; reuse
        // that entry instead of parsing the root POM again. unwrap_or_clone
        // keeps a unique Arc free and clones only when the cache still holds
        // the shared model.
        let mut pom = (self.ctx.parsed_poms())
            .parse(&BlobId::from_bytes(&contents), &contents)
            .map(Arc::unwrap_or_clone)
            .map_err(|source| ResolveError::LocalPom {
                path: path.display().to_string(),
                source,
            })?;
        pom.set_provenance(workspace.module_provenance(path).unwrap_or_else(|| {
            rv_maven_model::Provenance::RootProject {
                path: path.to_path_buf(),
            }
        }));

        let base_dir = path.parent().map(Path::to_path_buf);
        // Resolve profiles against the TARGET platform for this pass, so a
        // `--platforms macos-aarch64` build on a Linux host activates the
        // macOS profiles (and their deps) instead of the host's.
        let mut activation = self.ctx.activation_context();
        // `.mvn/maven.config` `-D` entries are Maven user properties, which
        // win over the POM's own `<properties>` in model interpolation.
        activation.base_dir = base_dir.as_deref().map(rv_fs::plain_path);
        workspace.apply_root_maven_config(&mut activation, &mut pom);

        // The user's own POM is the trusted entrypoint: its <repositories>
        // should always be honored even under default-deny
        // `allow_transitive_repositories`, because the user wrote the file.
        // Transitive POMs reached from here still go through the gated path.
        //
        // `local_parent_boundary` owns the containment rule, so discovery,
        // `raeva sync`'s model hashing, and resolution accept the same parents.
        let boundary = workspace.local_parent_boundary();
        let mut backend = ModelService::new(&self.ctx, repos.to_vec()).with_workspace(workspace);
        if let Some(support_poms) = support_poms {
            backend = backend.with_workspace_support_poms(Arc::clone(support_poms));
        }
        if let Some(kept_imports) = kept_imports {
            backend = backend.with_kept_imports(Arc::clone(kept_imports));
        }
        let local_parents = match base_dir.clone() {
            Some(base_dir) => {
                LocalParents::new(base_dir, boundary).cached_in(self.ctx.local_parents())
            }
            None => LocalParents::none(),
        };
        Ok((pom, activation, backend, local_parents))
    }

    /// Fail where the solver fails on the own dependencies of the module at
    /// `path` before it reads any of them.
    async fn check_own_dependencies(
        &self,
        path: &Path,
        workspace: Arc<Workspace>,
        support_poms: &WorkspaceSupportPomBuffer,
        imports: &Arc<KeptImports>,
    ) -> Result<()> {
        let (coord, project, ..) = self
            .load_root_project(
                path,
                &self.ctx.repos,
                Arc::clone(&workspace),
                Some(support_poms),
                Some(imports),
            )
            .await?;
        let backend = ModelService::new(&self.ctx, Vec::new()).with_workspace(workspace);
        let management = Management::new(project.dependency_management.dependencies);
        Solver::new(&backend)
            .with_management(management)
            .check_root(SolverRoot {
                coord,
                dependencies: project.dependencies,
                scope: Scope::Compile,
            })
    }

    async fn load_root_project(
        &self,
        path: &Path,
        repos: &[Repository],
        workspace: Arc<Workspace>,
        support_poms: Option<&WorkspaceSupportPomBuffer>,
        kept_imports: Option<&Arc<KeptImports>>,
    ) -> Result<(
        Coord,
        Project,
        Vec<Repository>,
        Vec<(String, SupportPomProvenance)>,
    )> {
        let (pom, activation, backend, local_parents) = self
            .root_model_inputs(path, repos, workspace, support_poms, kept_imports)
            .await?;
        let project = ModelScope::root(&backend, local_parents)
            .project(pom, &activation)
            .await
            .map_err(|err| project_model_error(err, path))?;
        // Reject unsupported repository schemes before resolution can reach them.
        // Only a repository the project's own POMs declare is project input;
        // one a fetched parent declares is that POM's fault.
        for repo in &project.repositories {
            let scheme = repo
                .url
                .split_once(':')
                .map(|(scheme, _)| scheme.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if !matches!(scheme.as_str(), "http" | "https" | "file") {
                let source = rv_maven_model::PomError::InvalidModel(format!(
                    "repository '{}' has unsupported URL '{}'; only http, https and file are supported",
                    rv_maven_types::bounded(repo.id.as_deref().unwrap_or("<no id>")),
                    rv_config::redact_url(&repo.url)
                ));
                return Err(if repo.root_declared {
                    ResolveError::LocalPom {
                        path: path.display().to_string(),
                        source,
                    }
                } else {
                    ResolveError::Pom(source)
                });
            }
        }

        // Snapshot the backend after parent-chain resolution. Parent POMs may
        // have declared `<repositories>` via the `observe_repositories`
        // callback; those are needed by the solver backend that gets built
        // after this function returns. Also capture the support-POM provenance
        // recorded while resolving the ROOT's own parent/imported BOMs: those
        // are fetched here, on this backend, not the solver backend, so without
        // returning them the root closure's export markers would lose their
        // source-repo id. A lineage entry left provisional is not taken: no
        // effective model declares it, and Maven's dependencies use only the
        // effective model's repositories.
        let observed_repos = backend.effective_repos_snapshot();
        let root_support_pom_provenance = backend.support_pom_provenance_snapshot();

        project
            .validate_build_coordinates()
            .map_err(|source| ResolveError::LocalPom {
                path: path.display().to_string(),
                source,
            })?;
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
    /// the content store, and return the index rows they need.
    ///
    /// Reactor modules resolve concurrently but share one store, so
    /// `persist_support_pom` buffers their support POMs instead of writing them
    /// from every module at once; this is the write. A store-write failure is
    /// fatal for the same reason it is in `persist_support_pom`: provenance for
    /// these coordinates was recorded when they were buffered, and a lock whose
    /// provenance names a support POM the store never took is an offline
    /// repository that only `raeva export-m2` discovers is incomplete. Failing
    /// here keeps the invariant that every recorded coordinate has bytes behind
    /// it, since the resolve this provenance belongs to never produces a lock.
    async fn flush_workspace_support_poms(
        &self,
        state: &WorkspaceStoreState,
    ) -> Result<(Vec<(ArtifactCoord, BlobId)>, ServedRows)> {
        let pending = state.support_poms.take_in_write_order();

        // The index ends up naming the last bytes seen for each coordinate,
        // so only that observation needs a row, and none when the index
        // already has it. Every blob is stored, since the lockfile may pin
        // any of them. The blobs are written concurrently; their rows, in
        // observation order, are returned for the caller to write.
        let mut last = HashMap::with_capacity(pending.len());
        for (position, (key, ..)) in pending.iter().enumerate() {
            last.insert(key.clone(), position);
        }
        let store = &self.ctx.store;
        let concurrency = self.ctx.config.network.fetch_concurrency() * 2;
        type Flushed = (Option<(ArtifactCoord, BlobId)>, ServedRows);
        let rows: Vec<Flushed> = stream::iter(pending.into_iter().enumerate())
            .map(|(position, (key, blob, bytes, routes))| {
                let indexes = last.get(&key) == Some(&position);
                async move {
                    let (indexed, served_by) = store.indexed_and_served(&key, &blob).await?;
                    let mut unserved = Vec::new();
                    for route in routes {
                        let served_by = match route.key == key {
                            true => served_by.clone(),
                            false => store.served_by(&route.key, &blob).await?,
                        };
                        if !(served_by.iter()).any(|(served, through)| {
                            **served == *route.repo && **through == *route.endpoint
                        }) {
                            let (repo, endpoint) =
                                (route.repo.to_string(), route.endpoint.to_string());
                            unserved.push((route.key, blob.clone(), repo, endpoint));
                        }
                    }
                    if indexes && indexed {
                        return Ok::<_, ResolveError>((None, unserved));
                    }
                    let written = store.put_bytes_with_id(blob.clone(), &bytes).await?;
                    debug_assert_eq!(written, blob, "store blob id must be the bytes' SHA-256");
                    Ok((indexes.then_some((key, written)), unserved))
                }
            })
            .buffered(concurrency)
            .inspect(|_| state.progress.note())
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<_>>()?;
        state.progress.note();
        let (rows, served): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        Ok((
            rows.into_iter().flatten().collect(),
            served.into_iter().flatten().collect(),
        ))
    }

    /// Fetch, or find in the store, the artifact of every node of `graph`.
    /// Within a reactor pass the index rows are left to `workspace`'s
    /// pending rows, and rows pending there count as indexed; otherwise
    /// they are written before this returns.
    async fn populate_artifacts(
        &self,
        backend: &ModelService,
        graph: &mut Graph,
        workspace: Option<&WorkspaceStoreState>,
    ) -> Result<()> {
        let workspace_artifacts = workspace.map(|state| &state.artifact_blobs);
        let root_repos = backend.root_effective_repos_snapshot();

        // Only what the lock keeps: orphans left by conflict eviction are skipped.
        let reachable = graph.reachable();

        let node_count = graph.node_count().saturating_sub(1);
        let mut to_fetch: Vec<(NodeIndex, ArtifactRequest, ArtifactCoord, Vec<Repository>)> =
            Vec::with_capacity(node_count);
        struct CacheCandidate {
            idx: NodeIndex,
            blob: BlobId,
            declared_repo: Option<String>,
            artifact_req: ArtifactRequest,
            key: ArtifactCoord,
            repo_candidates: Vec<Repository>,
            repo_scope: Option<RepositoryScope>,
        }

        let mut cache_candidates: Vec<CacheCandidate> = Vec::with_capacity(node_count);

        let node_indices = graph.node_indices().collect::<Vec<_>>();
        for idx in node_indices {
            let Some(node) = graph.node(idx) else {
                continue;
            };
            if idx == graph.root() || !reachable.contains(&idx) || node.workspace_module.is_some() {
                continue;
            }
            let coord = node.coord.to_string();
            if let Some(property) = crate::error::undefined_property(&coord) {
                let parent = graph.node(node.winner_parent.unwrap_or(graph.root()));
                let declared_by = parent.map(|parent| {
                    let Coord {
                        group_id,
                        artifact_id,
                        version,
                        ..
                    } = &parent.coord;
                    (parent.workspace_module.clone())
                        .unwrap_or_else(|| format!("{group_id}:{artifact_id}:{version}"))
                });
                return Err(ResolveError::UndefinedProperty {
                    property: property.to_string(),
                    declared_by: declared_by.unwrap_or_default(),
                    coord,
                }
                .declared_via(graph.declared_via(idx)));
            }
            if node.local {
                continue;
            }
            let node_repos: std::borrow::Cow<'_, [Repository]> = if node.repos.is_empty() {
                std::borrow::Cow::Borrowed(&root_repos)
            } else {
                let mut combined =
                    Vec::with_capacity(root_repos.len() + node.repos.as_slice().len());
                combined.extend_from_slice(&root_repos);
                combined.extend_from_slice(node.repos.as_slice());
                std::borrow::Cow::Owned(combined)
            };
            if node_repos.is_empty() {
                return Err(ResolveError::NoRepositories);
            }
            // A pom-packaged dependency's artifact is the POM this graph was
            // built from, one file in the repository, so its bytes are the
            // model's and are not fetched a second time.
            if node.coord.packaging.as_deref() == Some("pom")
                && node
                    .coord
                    .classifier
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty()
                && let Some(Some(blob)) = backend.companion_pom_blob(&backend::pom_gav(&node.coord))
            {
                if let Some(node) = graph.node_mut(idx) {
                    node.checksum = Some(blob);
                }
                continue;
            }

            let artifact_req = ArtifactRequest::from_coord(&node.coord);
            let mut repo_candidates =
                filter_repos_for_version(&node_repos, &artifact_req.version, &node.coord)
                    .map_err(|err| err.declared_via(graph.declared_via(idx)))?
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>();
            // As Maven's artifact resolver does, a SNAPSHOT build's files are
            // asked only of the repository whose metadata named the build.
            if let Some(build_repo) = node.build_repo.as_ref() {
                repo_candidates.retain(|repo| build_repo.is(repo));
            } else if let Some(repo_url) = node.repo_url.as_deref()
                && let Some(pos) = repo_candidates.iter().position(|repo| repo.url == repo_url)
            {
                let preferred = repo_candidates.remove(pos);
                repo_candidates.insert(0, preferred);
            }

            let key = ArtifactCoord::new(
                artifact_req.group_id.as_str(),
                artifact_req.artifact_id.as_str(),
                artifact_req.version.as_str(),
                artifact_req.packaging.as_str(),
                artifact_req.classifier.as_deref(),
            );
            // The lock records the repository the model declares, never the
            // mirror that serves it, so a lock written behind a mirror
            // matches one written without it.
            let selected_repo = repo_candidates.first();
            let declared_repo = selected_repo.map(|repo| repo.url.clone());
            let endpoint = selected_repo.map(|repo| {
                self.ctx
                    .client
                    .as_ref()
                    .map_or_else(|| repo.clone(), |client| client.effective_repository(repo))
            });
            let repo_scope = selected_repo
                .zip(endpoint.as_ref())
                .map(|(repo, endpoint)| {
                    (
                        rv_repo::normalize_repo_url(&repo.url),
                        rv_repo::normalize_repo_url(&endpoint.url),
                    )
                });

            // Within one reactor pass, a blob already verified from the same
            // repository and endpoint is reused rather than hashed again. One
            // seen from another repository is not: this repository's own
            // bytes, stored or fetched, are compared with it when the lock is
            // assembled.
            let seen = match (workspace_artifacts, repo_scope.as_ref()) {
                (Some(state), Some(repo)) => lock(state)
                    .get(&key)
                    .and_then(|by_repo| by_repo.get(repo).cloned()),
                _ => None,
            };
            if let Some(blob) = seen {
                if let Some(node) = graph.node_mut(idx) {
                    node.checksum = Some(blob);
                    node.repo_url = declared_repo.map(Into::into);
                }
                continue;
            }

            // Reuse only bytes this repository served, so a coordinate
            // another project fetched from elsewhere is not adopted; and,
            // unless missing checksums are allowed, only bytes its checksum
            // verified. A hit is verified below before use. `--update`
            // fetches a non-unique `-SNAPSHOT` again, as a rebuild replaces
            // it in place.
            let renew = rv_maven_types::resolves_through_snapshot_metadata(key.version())
                && self.ctx.client.as_ref().is_some_and(RepoClient::updates);
            let indexed = match (selected_repo.filter(|_| !renew), self.ctx.client.as_ref()) {
                (Some(repo), Some(client)) => {
                    client.stored_artifact(&self.ctx.store, repo, &key).await?
                }
                (Some(repo), None) => {
                    let store = &self.ctx.store;
                    store
                        .lookup_artifact_from(&key, &repo.url, &repo.url, false, false)
                        .await?
                }
                (None, _) => None,
            };
            if let Some(blob) = indexed {
                cache_candidates.push(CacheCandidate {
                    idx,
                    blob,
                    declared_repo,
                    artifact_req,
                    key,
                    repo_candidates,
                    repo_scope,
                });
                continue;
            }

            to_fetch.push((idx, artifact_req, key, repo_candidates));
        }

        if !cache_candidates.is_empty() {
            // Verify every cache hit: sampling would let corrupted blobs flow
            // downstream.
            let all_ids: Vec<BlobId> = cache_candidates.iter().map(|c| c.blob.clone()).collect();
            // `network.concurrency` hashers, at most one per core.
            let cores = std::thread::available_parallelism().map_or(4, |n| n.get().min(32));
            let parallelism = self.ctx.config.network.fetch_concurrency().min(cores);
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

            // Two coordinates with identical bytes share one blob, so count
            // the candidates that failed rather than the distinct blobs.
            let invalid_count = cache_candidates
                .iter()
                .filter(|candidate| !verified_set.contains(&candidate.blob))
                .count();
            if invalid_count > 0 {
                tracing::debug!(
                    invalid = invalid_count,
                    total = all_ids.len(),
                    "cache corruption detected; refetching invalid blobs"
                );
            }

            for candidate in cache_candidates {
                if !verified_set.contains(&candidate.blob) {
                    // Never repaired silently, `--frozen` included.
                    tracing::warn!(
                        sec_code = "STORE_FILE_REFETCHED",
                        coord = %candidate.key,
                        "the store's copy of {} does not match its checksum; downloading it again",
                        candidate.key
                    );
                    tracing::debug!(blob = %candidate.blob, "invalid cached artifact");
                    to_fetch.push((
                        candidate.idx,
                        candidate.artifact_req,
                        candidate.key,
                        candidate.repo_candidates,
                    ));
                    continue;
                }

                if let Some(node) = graph.node_mut(candidate.idx) {
                    node.checksum = Some(candidate.blob.clone());
                    node.repo_url = candidate.declared_repo.map(Into::into);
                }
                if let (Some(state), Some(repo)) = (workspace_artifacts, candidate.repo_scope) {
                    lock(state)
                        .entry(candidate.key)
                        .or_default()
                        .insert(repo, candidate.blob);
                }
            }
        }

        if to_fetch.is_empty() {
            return Ok(());
        }
        // Refused only once a graph fails, whose error is reported.
        if let Some(prefetcher) = self.ctx.prefetcher.as_deref()
            && !prefetcher.may_download().await
        {
            return Err(ResolveError::InternalError(
                "a reactor module failed before its graph did".to_string(),
            ));
        }

        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::MissingRepoClient)?;

        let concurrency = self.ctx.config.network.fetch_concurrency();
        let store = self.ctx.store.clone();
        let client = client.clone();

        let progress = backend.workspace_progress.clone();
        let mut results: Vec<_> = stream::iter(to_fetch)
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
                    // covers success and failure alike: a repository that
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
        // Downloads finish in any order; the results and the error reported
        // follow the graph instead.
        results.sort_unstable_by_key(|(idx, ..)| *idx);

        let environment = self.ctx.environment();
        let mut errors: Vec<ResolveError> = Vec::with_capacity(results.len());
        let mut rows = Vec::with_capacity(results.len());
        let mut origins = Vec::with_capacity(results.len());
        for (idx, artifact_req, key, result) in results {
            match result {
                Ok((blob_id, origin)) => {
                    rows.push((key.clone(), blob_id.clone()));
                    let repo_url = origin.repo_url.clone();
                    if let Some(state) = workspace_artifacts {
                        lock(state).entry(key.clone()).or_default().insert(
                            (
                                rv_repo::normalize_repo_url(&repo_url),
                                rv_repo::normalize_repo_url(&origin.endpoint_url),
                            ),
                            blob_id.clone(),
                        );
                    }
                    origins.push((key, blob_id.clone(), origin));
                    if let Some(node) = graph.node_mut(idx) {
                        node.checksum = Some(blob_id);
                        node.repo_url = Some(repo_url.into());
                    }
                }
                Err(FetchError::NotFound { searched }) => {
                    let node = graph.node(idx);
                    let coord = node.map(|node| node.coord.to_string()).unwrap_or_else(|| {
                        format!("{}:{}", artifact_req.group_id, artifact_req.artifact_id)
                    });
                    let classifier = node.and_then(|node| node.coord.classifier.as_deref());
                    let not_found = ResolveError::ArtifactNotFound {
                        dropped_repos: node
                            .map(|node| backend.missing_pom_dropped_repos(&node.coord, &searched))
                            .unwrap_or_default(),
                        coord,
                        searched,
                        classifier_like: environment
                            .classifier_like()
                            .filter(|(detected, like)| {
                                classifier == Some(format!("{detected}-{like}").as_str())
                            })
                            .map(|(detected, _)| detected),
                    };
                    errors.push(not_found.declared_via(graph.declared_via(idx)));
                }
                Err(FetchError::Failed { err, searched }) => {
                    let failed = ResolveError::Repo {
                        coord: Some(key.to_string()),
                        source: Box::new(err),
                        searched,
                    };
                    errors.push(failed.declared_via(graph.declared_via(idx)));
                }
            }
        }

        // The downloads that succeeded are indexed even when others failed,
        // so a rerun reuses them.
        match workspace {
            Some(state) => {
                let mut pending = lock(&state.pending_rows);
                pending.rows.extend(rows);
                pending.origins.extend(origins);
            }
            None => {
                self.ctx.store.add_artifacts(rows).await?;
                self.ctx.store.record_origins(origins).await?;
            }
        }

        let mut errors = errors.into_iter();
        let Some(first) = errors.next() else {
            return Ok(());
        };
        let rest: Vec<_> = errors.collect();
        Err(if rest.is_empty() {
            first
        } else {
            ResolveError::MultipleArtifactErrors {
                first: Box::new(first),
                rest,
            }
        })
    }
}

/// Index rows waiting for the end of a reactor pass, in the order they were
/// recorded, and the repositories the downloads among them came from.
#[derive(Default)]
struct PendingRows {
    rows: Vec<(ArtifactCoord, BlobId)>,
    origins: Vec<(ArtifactCoord, BlobId, rv_store::Origin)>,
}

/// Collapse the support-POM provenance of the solver's backend and the root
/// project's to one entry per coordinate, in coordinate order. Sorting puts an
/// empty repository id first, so `absorb` lets a known id replace it.
fn merge_support_pom_provenance(
    mut entries: Vec<(String, SupportPomProvenance)>,
) -> Result<Vec<(String, SupportPomProvenance)>> {
    entries.sort();
    let mut merged: Vec<(String, SupportPomProvenance)> = Vec::with_capacity(entries.len());
    for (coord, provenance) in entries {
        match merged.last_mut() {
            Some((kept_coord, kept)) if *kept_coord == coord => kept.absorb(&coord, &provenance)?,
            _ => merged.push((coord, provenance)),
        }
    }
    Ok(merged)
}

/// The model errors of building the project at `path` that are about the
/// project's own model rather than a POM fetched for it: an invalid
/// `<systemPath>` and a property cycle in the effective model, and a
/// `<parent>` that keeps a `${...}`. The model layer reports a property
/// cycle or a `<parent>` expression inside a fetched parent or BOM as
/// another error naming that POM, so those, like the other model errors,
/// stay [`ResolveError::Pom`].
pub(super) fn project_model_error(error: ResolveError, path: &Path) -> ResolveError {
    use rv_maven_model::PomError;
    match error {
        ResolveError::Pom(
            source @ (PomError::InvalidSystemPath(_)
            | PomError::PropertyCycle(_)
            | PomError::ParentExpression(_)),
        ) => ResolveError::LocalPom {
            path: path.display().to_string(),
            source,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests;
