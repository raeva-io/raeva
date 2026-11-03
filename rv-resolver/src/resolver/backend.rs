//! `ModelService`: the solver's backend. It resolves versions and snapshots
//! and builds the models of dependencies and reactor modules, reading POMs
//! and metadata through the context's [`PomSource`], and keeps the
//! repositories a resolution admits.
//!
//! [`PomSource`]: super::pom_source::PomSource

use bytes::Bytes;
use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use futures::stream::{self, StreamExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use rv_maven_model::{ActivationContext, ModelPolicy, ModelSource, Pom, PomError, Project};
use rv_maven_types::{ArtifactCoord, Coord, Version, VersionReq};
use rv_repo::{
    Admission, ArtifactRequest, Declaration, Metadata, Provenance, RepoError, Repository,
    RepositoryPolicy, SnapshotCandidate,
};
use rv_store::BlobId;

use crate::context::{MetadataKey, RepoContext, ResolveContext};
use crate::error::{ConflictingPom, DroppedRepo, RepoSearchStatus, ResolveError, Result};
use crate::graph::{ExactCoord, RepoRef};
use crate::parent_resolver::LocalParents;
use crate::solver::{Backend, PathNode, ResolvedProject, ResolvedVersion};
use crate::util::{DynamicVersionToken, lock, parse_dynamic_version_token};
use crate::workspace::{Workspace, WorkspaceModule};

use super::WorkspaceProgress;
use super::pom_source::PomSource;
use super::reactor_models::{ContextId, DependencyPom, KeptImports, ReactorModel, ReactorModels};
use super::scope::ModelScope;
use super::utils::{dummy_coord, filter_repos_for_version, remember_search_error};

pub(super) type WorkspaceSupportPomBuffer = Arc<SupportPoms>;

/// A reactor's [`SupportPomBuffer`], and whether a coordinate in it has
/// more than one blob, which a module reads without the lock to tell whether
/// a repeated observation can move anything.
#[derive(Default)]
pub(super) struct SupportPoms {
    buffer: Mutex<SupportPomBuffer>,
    split: AtomicBool,
}

impl SupportPoms {
    pub(super) fn record(
        &self,
        key: &ArtifactCoord,
        blob: &BlobId,
        bytes: &[u8],
        route: &PomRoute,
    ) {
        lock(&self.buffer).record(key, blob, bytes, route, &self.split);
    }

    /// Whether a coordinate has been seen with more than one blob, so that
    /// the order of observations decides its index row.
    fn split(&self) -> bool {
        self.split.load(Ordering::SeqCst)
    }

    pub(super) fn take_in_write_order(&self) -> Vec<SupportPomWrite> {
        lock(&self.buffer).take_in_write_order()
    }
}

/// Support POMs that the modules of one reactor resolution observed, held
/// until every module's graph is built and then written to the store once.
///
/// Each distinct `(key, bytes)` pair is held once. A repeated observation only
/// moves the pair later in the write order, so the last observation of a
/// coordinate still decides which bytes its index row names.
#[derive(Default)]
pub(super) struct SupportPomBuffer {
    /// Each blob seen under a key, with its bytes, when it was last seen
    /// and the routes that served it.
    entries: HashMap<ArtifactCoord, Vec<BufferedPom>>,
    next_sequence: u64,
}

struct BufferedPom {
    blob: BlobId,
    bytes: Vec<u8>,
    last_seen: u64,
    routes: Vec<PomRoute>,
}

/// Where a POM was read: the repository, the URL that served it for that
/// repository, and the coordinate of the file read, which for a SNAPSHOT
/// parent is its build's, as a restore keys it.
#[derive(Clone, PartialEq)]
pub(super) struct PomRoute {
    pub(super) key: ArtifactCoord,
    pub(super) repo: Arc<str>,
    pub(super) endpoint: Arc<str>,
}

/// A buffered support POM: its key, blob, bytes and the routes that
/// served it.
pub(super) type SupportPomWrite = (ArtifactCoord, BlobId, Vec<u8>, Vec<PomRoute>);

impl SupportPomBuffer {
    pub(super) fn record(
        &mut self,
        key: &ArtifactCoord,
        blob: &BlobId,
        bytes: &[u8],
        route: &PomRoute,
        split: &AtomicBool,
    ) {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let seen = self.entries.entry(key.clone()).or_default();
        let pom = match seen.iter().position(|pom| pom.blob == *blob) {
            Some(index) => &mut seen[index],
            None => {
                if !seen.is_empty() {
                    split.store(true, Ordering::SeqCst);
                }
                seen.push(BufferedPom {
                    blob: blob.clone(),
                    bytes: bytes.to_vec(),
                    last_seen: sequence,
                    routes: Vec::new(),
                });
                seen.last_mut().expect("just pushed")
            }
        };
        pom.last_seen = sequence;
        if !pom.routes.contains(route) {
            pom.routes.push(route.clone());
        }
    }

    pub(super) fn take_in_write_order(&mut self) -> Vec<SupportPomWrite> {
        let mut entries: Vec<_> = std::mem::take(&mut self.entries)
            .into_iter()
            .flat_map(|(key, seen)| seen.into_iter().map(move |pom| (key.clone(), pom)))
            .collect();
        entries.sort_unstable_by_key(|(_, pom)| pom.last_seen);
        entries
            .into_iter()
            .map(|(key, pom)| (key, pom.blob, pom.bytes, pom.routes))
            .collect()
    }
}

/// Bare `group:artifact:version` of a POM. A companion POM is per GAV (one
/// `.pom` serves every packaging and classifier of a coordinate, and Maven has
/// one local-repository path for it), so this, not the full `Coord`, is the
/// identity a POM pin is keyed by.
pub(super) type PomGav = (String, String, String);

/// Where an artifact's companion POM came from. A SNAPSHOT POM resolves on
/// its own, so its build may be other than the artifact's, and any POM's
/// repository may be other than the one that serves the jar.
#[derive(Debug, Clone, Default)]
pub(super) struct CompanionPomOrigin {
    pub(super) snapshot: Option<rv_maven_types::SnapshotStamp>,
    /// The POM is the base `-SNAPSHOT.pom`, whatever build the artifact is.
    pub(super) base: bool,
    pub(super) repo_url: Option<Arc<str>>,
}

type ModelParentRanges = HashMap<(ExactCoord, RepoContext), Vec<rv_lock::ParentRange>>;
type ReleasePomRepos = HashMap<(PomGav, RepoContext), Arc<str>>;
/// A POM's bytes and the repository that served them, if one did.
pub(super) type ServedPom = (BlobId, Option<Arc<str>>);

pub(super) fn pom_gav(coord: &Coord) -> PomGav {
    (
        coord.group_id.to_string(),
        coord.artifact_id.to_string(),
        coord.version.to_string(),
    )
}

/// Maven Central under either of its names.
fn is_central(url: &str) -> bool {
    let url = url.trim().trim_end_matches('/').to_ascii_lowercase();
    matches!(
        url.as_str(),
        "https://repo1.maven.org/maven2" | "https://repo.maven.apache.org/maven2"
    )
}

/// The repositories a dependency's effective model adds to the resolution.
/// Maven aggregates them by id with an absent id and an empty one under one
/// key, the first along the path winning; the model already holds one
/// repository per id, so only the second of an absent and an empty id is
/// dropped. A repository declared on another path stays: the shared list is
/// not kept per path.
fn resolution_repositories(
    repositories: &[rv_maven_model::Repository],
) -> impl Iterator<Item = Repository> + '_ {
    let mut blank_seen = false;
    repositories
        .iter()
        .filter(move |repo| {
            if repo.id.as_deref().is_some_and(|id| !id.is_empty()) {
                return true;
            }
            !std::mem::replace(&mut blank_seen, true)
        })
        .cloned()
        .map(Repository::from)
}

pub(crate) fn pom_digest_text(blob: Option<&BlobId>) -> String {
    blob.map_or_else(|| "none".to_string(), ToString::to_string)
}

/// What `raeva sync` records about one support POM (a parent or an imported BOM)
/// it fetched, so `raeva export-m2` can reproduce that exact file offline.
///
/// Support POMs never become lockfile packages, so this provenance is the only
/// thing standing behind them. The coordinate it is keyed by is the
/// load-bearing part: export refuses to write an offline repository missing a
/// POM named here.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct SupportPomProvenance {
    /// Id of the repository that served the POM. Empty when that repository
    /// carries no id of its own, which says only that the POM's
    /// `_remote.repositories` marker has no id to name.
    pub repo_id: String,
    /// URL of the declared repository that served the POM, never a mirror's.
    pub repo_url: String,
    /// The deployed build a `-SNAPSHOT` POM was read from, when the
    /// repository named one.
    pub snapshot: Option<rv_maven_types::SnapshotStamp>,
    /// SHA-256 of the exact POM bytes, which is also their content-store blob
    /// id. Pins which bytes export ships for the coordinate: the store's
    /// coordinate index is last-writer-wins, so another project syncing
    /// against the same store can repoint the coordinate at other bytes.
    pub sha256: String,
}

impl SupportPomProvenance {
    /// Fold another record of `coord` into this one. Different bytes are a
    /// conflict, never settled by picking one: the lock pins one POM per
    /// coordinate, so the losing half of the resolution would be exported
    /// against a POM it never read. For the same bytes a known repository
    /// replaces one without an id, which would otherwise drop the
    /// coordinate's `_remote.repositories` marker.
    pub(super) fn absorb(&mut self, coord: &str, other: &Self) -> Result<()> {
        if self.sha256 != other.sha256 {
            return Err(ResolveError::ConflictingResolvedPomBytes(Box::new(
                ConflictingPom {
                    coord: coord.to_string(),
                    first_origin: self.repo_url.clone(),
                    second_origin: other.repo_url.clone(),
                    first_sha256: self.sha256.clone(),
                    second_sha256: other.sha256.clone(),
                },
            )));
        }
        if self.repo_id.is_empty() && !other.repo_id.is_empty() {
            self.clone_from(other);
        }
        Ok(())
    }
}

/// A parent or imported BOM read from a repository, as a build that reuses
/// the model it served records it again.
pub(super) struct SupportPom {
    /// The store key of the POM.
    key: ArtifactCoord,
    /// The bare `g:a:v` the provenance is recorded under.
    name: String,
    provenance: SupportPomProvenance,
    pub(super) bytes: Bytes,
    pub(super) blob: BlobId,
    route: PomRoute,
}

impl SupportPom {
    fn new(coord: &Coord, repo: &Repository, endpoint: &str, path: &str, bytes: Bytes) -> Self {
        let file_version = path
            .rsplit('/')
            .next()
            .and_then(|name| name.strip_prefix(coord.artifact_id.as_str()))
            .and_then(|name| name.strip_prefix('-'))
            .and_then(|name| name.strip_suffix(".pom"));
        let version = coord.version.to_string();
        let blob = BlobId::from_bytes(&bytes);
        let snapshot = file_version
            .and_then(|file| rv_maven_types::SnapshotStamp::of_file_version(&version, file));
        // The file read, as a restore keys the pin.
        let file_version = (snapshot.as_ref())
            .and_then(|stamp| stamp.resolved_version(&version))
            .unwrap_or_else(|| version.clone());
        Self {
            key: pom_key(coord),
            // Every remote support POM is recorded, an id-less repository's
            // with an empty id, so export checks the store holds it. The key
            // is the bare `g:a:v` export looks up: `Coord`'s Display would
            // append the `pom` packaging.
            name: format!("{}:{}:{version}", coord.group_id, coord.artifact_id),
            provenance: SupportPomProvenance {
                repo_id: repo.id.clone().unwrap_or_default(),
                repo_url: repo.url.clone(),
                snapshot,
                sha256: blob.to_string(),
            },
            blob,
            bytes,
            route: PomRoute {
                key: ArtifactCoord::new(
                    coord.group_id.as_str(),
                    coord.artifact_id.as_str(),
                    &file_version,
                    "pom",
                    None,
                ),
                repo: Arc::from(repo.url.as_str()),
                endpoint: Arc::from(endpoint),
            },
        }
    }
}

/// The store key of `coord`'s POM.
fn pom_key(coord: &Coord) -> ArtifactCoord {
    ArtifactCoord::new(
        coord.group_id.as_str(),
        coord.artifact_id.as_str(),
        &coord.version.to_string(),
        "pom",
        None,
    )
}

#[derive(Clone)]
pub(super) struct ModelService {
    pub(super) ctx: ResolveContext,
    /// Shared, mutable list of repositories. Maven propagates `<repositories>`
    /// from every fetched POM into the resolution context, so this list grows
    /// as transitive projects are loaded. Reads take a cheap clone snapshot
    /// (repo lists are small) so callers never hold a lock across awaits.
    repos: Arc<RwLock<Repositories>>,
    /// Incremental dedup index for `extend_repos`. Each fetched POM can
    /// trigger an `extend_repos` call (potentially 100+ for a full Spring Boot
    /// stack); rebuilding the key set from `repos` on every call is O(N) per
    /// call (quadratic across the resolution). Sharing this index across
    /// clones via `Arc<RwLock<_>>` keeps lookups O(1) regardless of how many
    /// transitive POMs we visit.
    pub(super) seen_repos: Arc<RwLock<HashSet<RepoKey>>>,
    /// Ignored transitive repositories and their declaring POMs.
    /// Not-found errors can name repositories that could serve the missing artifact.
    pub(super) dropped_repos: Arc<Mutex<Vec<DroppedRepo>>>,
    /// The winning path of each graph coordinate whose POM no repository
    /// has, so its artifact's not-found error can name the dropped ones.
    /// Keyed by the whole coordinate: a classifier is mediated on its own.
    missing_pom_paths: Arc<Mutex<HashMap<ExactCoord, Arc<PathNode>>>>,
    /// Coordinates whose POM was missing in a specific repository context.
    missing_poms: Arc<Mutex<HashSet<(ExactCoord, RepoContext)>>>,
    /// The POM each mediation winner's repositories gave for its
    /// coordinate, `None` when they lacked it, which the lock pins over
    /// what another path's repositories gave.
    winner_poms: Arc<Mutex<HashMap<PomGav, Option<BlobId>>>>,
    /// Provenance for each support POM (parent / imported BOM) fetched during
    /// resolution, keyed by `"g:a:v"`. A support POM can resolve from a
    /// different repository than the child that referenced it; recording the
    /// serving repo's id here lets `raeva export-m2` label that POM's
    /// `_remote.repositories` marker with the correct id instead of guessing
    /// the child's repo, and recording the bytes' SHA-256 lets it export that
    /// exact blob rather than whatever the store's coordinate index points at
    /// by the time the export runs.
    pub(super) support_pom_provenance: Arc<RwLock<HashMap<String, SupportPomProvenance>>>,
    /// SHA-256 of the companion POM bytes this resolution actually parsed for
    /// each graph coordinate, recorded where those bytes are in hand, with
    /// the repository that served them. `None` records that no repository
    /// has the POM.
    ///
    /// The lockfile's `pom_sha256` comes from here and never from the store's
    /// coordinate index: the index is last-writer-wins, so between the fetch
    /// that built the graph and the moment the lock is written, any other
    /// project sharing the store can repoint `(g, a, v, pom)` at different
    /// bytes. Pinning the index entry would name a POM the graph was never
    /// resolved against.
    pub(super) companion_pom_blobs: Arc<RwLock<HashMap<PomGav, Option<ServedPom>>>>,
    /// The reused support POMs this service recorded, by address, each held
    /// so its address is not reused. See [`Self::recorded`].
    recorded_support_poms: Arc<Mutex<HashMap<usize, Arc<SupportPom>>>>,
    companion_pom_origins: Arc<RwLock<HashMap<PomGav, CompanionPomOrigin>>>,
    /// The repository that served a release POM to each repository context,
    /// so a row names the one its winning path read, which may differ from
    /// the jar's.
    release_pom_repos: Arc<Mutex<ReleasePomRepos>>,
    /// Trusted reactor models available to parent/BOM/dependency resolution.
    pub(super) workspace: Option<Arc<Workspace>>,
    /// Parent/BOM bytes collected while the modules build their graphs in
    /// parallel. The driver writes them in discovery order before artifact
    /// population, so the store sees the same writes whatever the timing.
    pub(super) workspace_support_poms: Option<WorkspaceSupportPomBuffer>,
    /// Liveness counter for the all-reactor stall watchdog. `None` outside a
    /// workspace resolve, where there is no watchdog to feed.
    pub(super) workspace_progress: Option<Arc<WorkspaceProgress>>,
    /// Range evidence by model and repository context; only graph winners enter the lock.
    pub(super) parent_ranges: Arc<Mutex<ModelParentRanges>>,
    dependency_activation: Arc<OnceLock<ActivationContext>>,
    /// URLs of root-lineage repositories, and of POM repositories whose URL
    /// may hold a credential, already refused and reported.
    refused_lineage_urls: Arc<Mutex<HashSet<String>>>,
    /// Dependency POMs read as invalid, reported by
    /// [`Self::report_pom_problem`] once the graph selects them: a range
    /// reads every candidate's POM, and the problem of one it does not
    /// select asks nothing of the build.
    pom_problems: Arc<Mutex<HashMap<PomGav, PomProblem>>>,
    /// Entries of [`Self::repos`] that a parent lookup added from a
    /// declaration still holding an expression, until an effective model's
    /// declaration of that repository replaces it. Each keeps the declarations from
    /// outside the root lineage that met the entry meanwhile, which the
    /// replacement merges again.
    provisional_repos: Arc<Mutex<ProvisionalRepos>>,
    /// Entries of [`Self::repos`] that a parent lookup added, which an
    /// effective model's declaration under the same id replaces.
    lineage_repos: Arc<Mutex<HashSet<RepoKey>>>,
    /// Ids of refused root-lineage declarations, which no later parent's
    /// declaration takes over.
    held_repo_ids: Arc<Mutex<HashSet<String>>>,
    /// Ids of the entries in [`Self::repos`] that the configuration or the
    /// root lineage added, which a dependency's POM cannot redeclare.
    root_repo_ids: Arc<Mutex<HashSet<String>>>,
    default_urls: Arc<HashSet<String>>,
    /// Imported BOMs built so far, by coordinates and context; see
    /// `ModelScope::reuse_import`.
    pub(super) kept_imports: Arc<KeptImports>,
    reactor_models: Option<Arc<ReactorModels>>,
    /// The model context of each repository context, and the generation of
    /// the repositories it was read at.
    model_contexts: Arc<Mutex<HashMap<RepoContext, (u64, ContextId)>>>,
}

#[derive(Debug)]
struct Repositories {
    entries: Vec<Repository>,
    project_end: usize,
    /// Raised by every change to these, the provisional entries or the root
    /// ids, which [`ModelService::model_context`] reads.
    generation: u64,
}

/// A repository in the shared list: one URL may be listed under several ids,
/// each with its own policies, mirror and credential.
pub(super) type RepoKey = (String, Option<String>);

pub(super) fn repo_key(repo: &Repository) -> RepoKey {
    (repo.url.clone(), repo.id.clone())
}

/// Provisional entries, each with the declarations recorded on it.
type ProvisionalRepos = HashMap<RepoKey, Vec<(Repository, Declared)>>;

/// How a declaration joins a URL already in the shared list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Declared {
    /// A root-lineage declaration without an expression: its checksum
    /// policies merge, the strictest kept.
    Lineage,
    Provisional,
    /// A root-lineage effective model's: it replaces a provisional entry,
    /// and merges as [`Declared::Lineage`] otherwise.
    Effective,
    /// Any other but [`Declared::Fetched`]: it merges as
    /// [`Declared::Lineage`], and a provisional entry keeps it for the
    /// replacement.
    Outside,
    /// A POM fetched for a dependency: as [`Declared::Outside`], except that
    /// its unsupported checksum policy merges as `fail`.
    Fetched,
    /// A reactor module's own, on a dependency path: as
    /// [`Declared::Fetched`], except that only a project repository of its
    /// id drops it, not a refusal, and its policies merge as
    /// [`Declared::Lineage`].
    Reactor,
}

impl Declared {
    fn merge(self, existing: &mut Repository, repo: &Repository) {
        if self == Declared::Fetched {
            existing.merge_fetched_checksum_policies(repo);
        } else {
            existing.merge_checksum_policies(repo);
        }
    }
}

/// `entries` with each provisional entry rebuilt from the declarations
/// outside the root lineage that met it, or left out when none did.
fn effective(entries: &[Repository], provisional: &ProvisionalRepos) -> Vec<Repository> {
    entries
        .iter()
        .filter_map(|repo| match provisional.get(&repo_key(repo)) {
            None => Some(repo.clone()),
            Some(outside) => {
                let ((first, _), rest) = outside.split_first()?;
                let mut kept = first.clone();
                for (other, declared) in rest {
                    declared.merge(&mut kept, other);
                }
                Some(kept)
            }
        })
        .collect()
}

/// Whether snapshot metadata updated at `new` replaces a build kept from one
/// updated at `kept`, as Maven's version resolver decides.
fn is_newer(new: Option<&str>, kept: Option<&str>) -> bool {
    new.is_some_and(|new| new > kept.unwrap_or_default())
}

/// Where one coordinate was looked for, for the error when no repository
/// serves it.
#[derive(Default)]
struct Search {
    fallback: rv_repo::RepositoryFallback,
    searched: Vec<RepoSearchStatus>,
    last_error: Option<RepoError>,
}

impl Search {
    fn snapshot_served(
        &self,
        source: &dyn PomSource,
        repo: &Repository,
        coord: &Coord,
        resolution: &rv_repo::SnapshotResolution,
    ) {
        if resolution.metadata_served {
            self.fallback.served(
                &source.effective_repository(repo),
                &ArtifactRequest::from_coord(coord),
                rv_maven_types::layout::metadata_path(
                    &coord.group_id,
                    &coord.artifact_id,
                    Some(coord.version.as_str()),
                ),
            );
        }
    }

    /// Record a failed fetch from `repo`, ending the search unless a later
    /// repository may still serve the coordinate. An offline miss is
    /// specific to one repository's cache scope.
    fn failed(
        &mut self,
        source: &dyn PomSource,
        repo: &Repository,
        coord: &Coord,
        err: RepoError,
    ) -> Result<()> {
        self.fallback
            .failed(&source.effective_repository(repo), &err);
        self.searched
            .push(RepoSearchStatus::from_fetch_error(repo, &err, |repo| {
                source.effective_repository(repo)
            }));
        if matches!(err, RepoError::NotFound(_)) {
            return Ok(());
        }
        if err.moves_to_next_repository() || matches!(err, RepoError::OfflineNotCached(_)) {
            remember_search_error(&mut self.last_error, err);
            return Ok(());
        }
        Err(ResolveError::Repo {
            coord: Some(coord.to_string()),
            source: Box::new(err),
            searched: std::mem::take(&mut self.searched),
        })
    }

    fn exhausted(self, coord: &Coord) -> ResolveError {
        match self.last_error {
            Some(source) => ResolveError::Repo {
                coord: Some(coord.to_string()),
                source: Box::new(source),
                searched: self.searched,
            },
            None => ResolveError::ArtifactNotFound {
                dropped_repos: Vec::new(),
                coord: coord.to_string(),
                searched: self.searched,
                classifier_like: None,
            },
        }
    }
}

impl ModelService {
    pub(super) fn new(ctx: &ResolveContext, repos: Vec<Repository>) -> Self {
        let backend = Self {
            ctx: ctx.clone(),
            repos: Arc::new(RwLock::new(Repositories {
                entries: Vec::with_capacity(repos.len()),
                project_end: 0,
                generation: 0,
            })),
            model_contexts: Arc::default(),
            seen_repos: Arc::new(RwLock::new(HashSet::with_capacity(repos.len()))),
            dropped_repos: Arc::new(Mutex::new(Vec::new())),
            missing_pom_paths: Arc::default(),
            missing_poms: Arc::default(),
            winner_poms: Arc::default(),
            support_pom_provenance: Arc::new(RwLock::new(HashMap::new())),
            companion_pom_blobs: Arc::new(RwLock::new(HashMap::new())),
            recorded_support_poms: Arc::default(),
            companion_pom_origins: Arc::new(RwLock::new(HashMap::new())),
            release_pom_repos: Arc::default(),
            workspace: None,
            workspace_support_poms: None,
            workspace_progress: None,
            parent_ranges: Arc::default(),
            dependency_activation: Arc::new(OnceLock::new()),
            refused_lineage_urls: Arc::new(Mutex::new(HashSet::new())),
            pom_problems: Arc::default(),
            provisional_repos: Arc::new(Mutex::new(HashMap::new())),
            lineage_repos: Arc::default(),
            held_repo_ids: Arc::default(),
            root_repo_ids: Arc::new(Mutex::new(HashSet::new())),
            default_urls: Arc::new(
                (ctx.config.default_repositories().iter())
                    .map(|repo| Repository::from(repo).url)
                    .collect(),
            ),
            kept_imports: Arc::default(),
            reactor_models: None,
        };
        // The starting list is not only the configuration: the driver merges
        // the root project's lineage `<repositories>` into it before the
        // backend exists, so they are admitted here as declared.
        backend.extend_root_repos(repos);
        backend
    }

    pub(super) fn with_workspace(mut self, workspace: Arc<Workspace>) -> Self {
        self.workspace = Some(workspace);
        self
    }

    /// The activation context Maven's `DefaultArtifactDescriptorReader`
    /// builds a dependency's model with: the target platform, no user
    /// properties, no active or inactive profile ids, and the project's user
    /// properties (the reactor root's `.mvn/maven.config` `-D` values) as
    /// system properties.
    fn dependency_activation(&self) -> ActivationContext {
        self.dependency_activation
            .get_or_init(|| {
                let mut activation = ActivationContext::new(self.ctx.environment());
                activation.set_external_properties(
                    Default::default(),
                    rv_maven_model::PropertySource::System,
                );
                if let Some(workspace) = self.workspace.as_deref() {
                    let (properties, expanded) = workspace.root_user_properties(&activation);
                    activation.set_external_properties(
                        properties,
                        rv_maven_model::PropertySource::System,
                    );
                    activation.expanded_properties = expanded;
                }
                activation
            })
            .clone()
    }

    pub(super) fn with_workspace_support_poms(
        mut self,
        support_poms: WorkspaceSupportPomBuffer,
    ) -> Self {
        self.workspace_support_poms = Some(support_poms);
        self
    }

    pub(super) fn with_workspace_progress(mut self, progress: Arc<WorkspaceProgress>) -> Self {
        self.workspace_progress = Some(progress);
        self
    }

    pub(super) fn with_kept_imports(mut self, imports: Arc<KeptImports>) -> Self {
        self.kept_imports = imports;
        self
    }

    pub(super) fn with_reactor_models(mut self, models: Arc<ReactorModels>) -> Self {
        self.kept_imports = Arc::clone(&models.imports);
        self.reactor_models = Some(models);
        self
    }

    /// Everything a model build reads from this resolution's repositories:
    /// the root list, the path's repository context, its provisional entries
    /// and the ids a build may not redeclare. `None` outside a reactor
    /// resolution, where no model is kept for another module.
    fn model_context(&self, repo_ctx: &RepoContext) -> Option<ContextId> {
        let models = self.reactor_models.as_deref()?;
        let repos = self.repos.read().expect("repos lock poisoned");
        if let Some(&(generation, id)) = lock(&self.model_contexts).get(repo_ctx)
            && generation == repos.generation
        {
            return Some(id);
        }
        let provisional = lock(&self.provisional_repos);
        let mut provisional: Vec<_> = provisional.iter().collect();
        provisional.sort_unstable_by(|a, b| a.0.cmp(b.0));
        let id = models.context_id(format!(
            "{:?}\n{:?}\n{:?}\n{:?}",
            &repos.entries[..repos.project_end],
            repo_ctx.as_slice(),
            provisional,
            self.root_repo_ids_snapshot()
        ));
        lock(&self.model_contexts).insert(repo_ctx.clone(), (repos.generation, id));
        Some(id)
    }

    fn reactor_model(
        &self,
        coord: &Coord,
        context: Option<ContextId>,
    ) -> Option<Arc<ReactorModel>> {
        self.reactor_models.as_deref()?.get(coord, context?)
    }

    /// Keep a model for the other modules, unless its build changed the
    /// repositories it read: what it built is then not what another module
    /// would build from the same starting point.
    fn keep_reactor_model(
        &self,
        coord: &Coord,
        repo_ctx: &RepoContext,
        context: Option<ContextId>,
        model: ReactorModel,
    ) {
        if let (Some(models), Some(context)) = (self.reactor_models.as_deref(), context)
            && self.model_context(repo_ctx) == Some(context)
        {
            models.insert(coord, context, model);
        }
    }

    /// Tell the all-reactor stall watchdog that something moved. One relaxed
    /// atomic add.
    ///
    /// Raised on both sides of every repository round trip: starting a request
    /// is progress (it restarts the watchdog window at the moment the wait
    /// begins, instead of leaving it running from whatever landed before), and
    /// so is a failed one (a 500, a timeout, a retry sequence), because the
    /// question this counter answers is whether the process is still alive,
    /// not whether it is succeeding. Bounding how long a single attempt may
    /// run belongs to rv-repo's request timeout.
    pub(super) fn note_progress(&self) {
        if let Some(progress) = self.workspace_progress.as_ref() {
            progress.note();
        }
    }

    /// A service for a reactor module's own model: the configured
    /// repositories, sharing this resolution's reactor state.
    fn reactor_module_service(&self) -> Self {
        let mut own = Self::new(&self.ctx, self.ctx.repos.clone());
        own.workspace.clone_from(&self.workspace);
        own.workspace_support_poms
            .clone_from(&self.workspace_support_poms);
        own.workspace_progress.clone_from(&self.workspace_progress);
        own.support_pom_provenance = Arc::clone(&self.support_pom_provenance);
        own.recorded_support_poms = Arc::clone(&self.recorded_support_poms);
        own.kept_imports = Arc::clone(&self.kept_imports);
        own.reactor_models.clone_from(&self.reactor_models);
        own
    }

    pub(super) fn workspace_module_for_coord(&self, coord: &Coord) -> Option<&WorkspaceModule> {
        self.workspace
            .as_deref()?
            .candidates(coord.group_id.as_str(), coord.artifact_id.as_str())
            .find(|module| module.gav().version == coord.version.as_str())
    }

    /// [`Workspace::stand_in_pom`] of the reactor module with `coord`'s
    /// effective coordinates. The root's `.mvn/maven.config` `-D` values
    /// overlay it only for a `reactor_side` build: Maven builds a
    /// dependency's model without them (MNG-7563).
    pub(super) fn workspace_pom_for_coord(&self, coord: &Coord, reactor_side: bool) -> Option<Pom> {
        let module = self.workspace_module_for_coord(coord)?;
        let workspace = self.workspace.as_deref()?;
        let mut pom = workspace.stand_in_pom(module);
        pom.mark_root_repositories();
        // Dependency models keep the version as written (MNG-7563): overlaying
        // the effective GAV would bake `.mvn/maven.config` `-D` into
        // `${project.version}` for a reactor parent found by that version.
        if reactor_side {
            pom.version = Some(module.gav().version.clone());
            let activation = rv_maven_model::ActivationContext::new(self.ctx.environment());
            workspace.inject_root_properties(&mut pom, &activation);
        }
        Some(pom)
    }

    /// The local parents a build of a POM not in the working tree may read:
    /// those a reactor module standing in for a parent or BOM names, whose
    /// `<relativePath>` [`Self::workspace_pom_for_coord`] made absolute.
    /// A repository POM names none.
    pub(super) fn reactor_parents(&self) -> LocalParents {
        match self.workspace.as_deref() {
            Some(workspace) => {
                let boundary = workspace.local_parent_boundary();
                LocalParents::new(boundary.clone(), boundary).cached_in(self.ctx.local_parents())
            }
            None => LocalParents::none(),
        }
    }

    fn workspace_versions(&self, group_id: &str, artifact_id: &str) -> Vec<Version> {
        self.workspace
            .as_deref()
            .into_iter()
            .flat_map(|workspace| workspace.candidates(group_id, artifact_id))
            .filter_map(|module| Version::parse(&module.gav().version).ok())
            .collect()
    }

    /// Every repository admitted so far, in admission order.
    #[cfg(test)]
    pub(super) fn repos_snapshot(&self) -> Vec<Repository> {
        self.repos
            .read()
            .expect("repos lock poisoned")
            .entries
            .clone()
    }

    /// Snapshot the root project's repositories (`entries[..project_end]`).
    pub(super) fn root_repos_snapshot(&self) -> Vec<Repository> {
        let repos = self.repos.read().expect("repos lock poisoned");
        repos.entries[..repos.project_end].to_vec()
    }

    /// [`ResolveContext::release_graph_caches`], then clear kept import
    /// models. The reactor's other modules keep those whose build logged
    /// nothing: building one again would log nothing either. One that
    /// logged is built again, warnings and all, as when a module's end
    /// cleared every kept build.
    pub(super) fn release_graph_caches(&self) {
        self.ctx.release_graph_caches();
        if self.reactor_models.is_none() {
            lock(&self.kept_imports.builds).clear();
        } else {
            self.kept_imports.forget_logged();
        }
    }

    /// The root project's effective repositories: [`Self::root_repos_snapshot`]
    /// as [`effective`] gives them.
    pub(super) fn root_effective_repos_snapshot(&self) -> Vec<Repository> {
        let repos = self.repos.read().expect("repos lock poisoned");
        effective(
            &repos.entries[..repos.project_end],
            &lock(&self.provisional_repos),
        )
    }

    /// The repositories a dependency search in `ctx` uses: the root project's
    /// effective repositories followed by `ctx`'s per-path transitive
    /// repositories.
    pub(super) fn search_repos(&self, ctx: &RepoContext) -> Vec<Repository> {
        let mut repos = self.root_effective_repos_snapshot();
        repos.extend_from_slice(ctx.as_slice());
        repos
    }

    /// The union of all effective repositories (root plus every admitted
    /// transitive repository across the resolution), used for lockfile trust
    /// recording and export markers.
    pub(super) fn effective_repos_snapshot(&self) -> Vec<Repository> {
        effective(
            &self.repos.read().expect("repos lock poisoned").entries,
            &lock(&self.provisional_repos),
        )
    }

    /// Warn that the POM of `coord`, which the graph selected, is invalid.
    pub(super) fn report_pom_problem(&self, coord: &Coord) {
        let Some(problem) = lock(&self.pom_problems).get(&pom_gav(coord)).cloned() else {
            return;
        };
        let PomProblem { repository, error } = problem;
        match repository {
            Some(repository) => tracing::warn!(
                sec_code = "POM_PROBLEM",
                coord = %coord,
                repository = %repository,
                error = %error,
                "POM is invalid; its transitive dependencies are not available"
            ),
            None => tracing::warn!(
                sec_code = "POM_PROBLEM",
                coord = %coord,
                "POM is invalid ({error}); its transitive dependencies are not available"
            ),
        }
    }

    /// [`Self::collect_dropped_repos`] on the winning path of `coord`, whose
    /// POM no repository has.
    pub(super) fn missing_pom_dropped_repos(
        &self,
        coord: &Coord,
        searched: &[RepoSearchStatus],
    ) -> Vec<DroppedRepo> {
        let path = lock(&self.missing_pom_paths)
            .get(&ExactCoord(coord.clone()))
            .cloned();
        path.map(|path| {
            self.collect_dropped_repos(&path.coordinates(), coord.version.as_str(), searched)
        })
        .unwrap_or_default()
    }

    /// Ignored transitive repositories declared by a POM on `path` (matched by
    /// `group:artifact:version`) that could serve `version` and were not
    /// searched.
    pub(super) fn collect_dropped_repos(
        &self,
        path: &[String],
        version: &str,
        searched: &[RepoSearchStatus],
    ) -> Vec<DroppedRepo> {
        // A SNAPSHOT build selected from metadata can read another build's
        // POM, which is the one that declared its repositories.
        let origins = self
            .companion_pom_origins
            .read()
            .expect("companion_pom_origins lock poisoned");
        let path: HashSet<String> = path
            .iter()
            .map(|gav| {
                let pom = match gav.splitn(3, ':').collect::<Vec<_>>()[..] {
                    [group, artifact, version] => origins
                        .get(&(group.into(), artifact.into(), version.into()))
                        .zip(rv_maven_types::snapshot_base_version(version))
                        .and_then(|(origin, base)| match &origin.snapshot {
                            Some(stamp) => stamp.resolved_version(&base),
                            None => origin.base.then_some(base),
                        })
                        .map(|pom| format!("{group}:{artifact}:{pom}")),
                    _ => None,
                };
                pom.unwrap_or_else(|| gav.clone())
            })
            .collect();
        drop(origins);
        let snapshot = rv_maven_types::is_snapshot_version(version);
        lock(&self.dropped_repos)
            .iter()
            .filter(|d| path.contains(&d.declared_by))
            .filter(|d| {
                if snapshot {
                    d.snapshots_enabled
                } else {
                    d.releases_enabled
                }
            })
            .filter(|d| {
                let url = rv_repo::normalize_repo_url(&d.url);
                !searched
                    .iter()
                    .any(|s| rv_repo::normalize_repo_url(&s.repo_url) == url)
            })
            .cloned()
            .collect()
    }

    /// Snapshot the `"g:a:v" -> provenance` records collected for support POMs.
    pub(super) fn support_pom_provenance_snapshot(&self) -> Vec<(String, SupportPomProvenance)> {
        self.support_pom_provenance
            .read()
            .expect("support_pom_provenance lock poisoned")
            .iter()
            .map(|(coord, provenance)| (coord.clone(), provenance.clone()))
            .collect()
    }

    /// The companion-POM digest recorded for one graph coordinate, if this
    /// resolution fetched (or replayed from cache) that coordinate's POM,
    /// `Some(None)` when it found no POM.
    pub(super) fn companion_pom_blob(&self, gav: &PomGav) -> Option<Option<BlobId>> {
        if let Some(blob) = lock(&self.winner_poms).get(gav) {
            return Some(blob.clone());
        }
        let recorded = self
            .companion_pom_blobs
            .read()
            .expect("companion_pom_blobs lock poisoned");
        (recorded.get(gav)).map(|served| served.as_ref().map(|(blob, _)| blob.clone()))
    }

    /// Record the bytes a POM fetch produced for `gav` and the repository
    /// that served them, `None` when no repository had it.
    ///
    /// A second observation with a different digest is an error rather than a
    /// winner: both were used to build this graph, and one lockfile row (and
    /// one `~/.m2` path) can only carry one of them, so keeping either would
    /// leave part of the resolution pinned to bytes it never saw.
    fn record_companion_pom_blob(&self, gav: PomGav, served: Option<ServedPom>) -> Result<()> {
        let mut recorded = self
            .companion_pom_blobs
            .write()
            .expect("companion_pom_blobs lock poisoned");
        match (recorded.get(&gav), served) {
            (Some(Some((existing, first))), Some((blob, second))) if *existing != blob => Err(
                ResolveError::ConflictingResolvedPomBytes(Box::new(ConflictingPom {
                    coord: format!("{}:{}:{}", gav.0, gav.1, gav.2),
                    first_origin: first.as_deref().unwrap_or_default().to_string(),
                    second_origin: second.as_deref().unwrap_or_default().to_string(),
                    first_sha256: pom_digest_text(Some(existing)),
                    second_sha256: pom_digest_text(Some(&blob)),
                })),
            ),
            (Some(Some(_)), _) => Ok(()),
            (Some(None), Some(served)) => {
                recorded.insert(gav, Some(served));
                Ok(())
            }
            (Some(None), None) => Ok(()),
            (None, served) => {
                recorded.insert(gav, served);
                Ok(())
            }
        }
    }

    /// The POM bytes this resolution parsed for `gav`, and where the path
    /// that read them in `repos` found them.
    pub(super) fn companion_pom(
        &self,
        gav: &PomGav,
        repos: &RepoContext,
    ) -> Option<(Option<BlobId>, CompanionPomOrigin)> {
        let blob = self.companion_pom_blob(gav)?;
        let origin = self
            .companion_pom_origins
            .read()
            .expect("companion_pom_origins lock poisoned")
            .get(gav)
            .cloned()
            .unwrap_or_else(|| CompanionPomOrigin {
                repo_url: lock(&self.release_pom_repos)
                    .get(&(gav.clone(), repos.clone()))
                    .cloned(),
                ..CompanionPomOrigin::default()
            });
        Some((blob, origin))
    }

    /// Admit `repos` as `from` declared them. The source's policy gives each
    /// what its provenance allows; without a source nothing is fetched, and
    /// the same repositories are refused.
    fn admission(&self, repos: Vec<Repository>, from: Declaration) -> Admission {
        match self.ctx.pom_source.as_deref() {
            Some(source) => source.admit(repos, from),
            None => RepositoryPolicy::screen(&self.ctx.config, repos, from),
        }
    }

    /// Append the repositories of the root project's lineage to the shared
    /// list, in order and deduplicated by id and URL: configured and caller-built
    /// ones as they are, those of the project's own POMs as declared there, and a remote
    /// parent's as a fetched POM's. The transitive repository policy does not
    /// apply; a fetched parent's repository that is not HTTP or HTTPS is
    /// refused and reported once.
    ///
    /// Transitive POMs encountered later during resolution must continue to
    /// go through [`Self::extend_repos`], which keeps the security gate.
    pub(super) fn extend_root_repos(&self, extra: impl IntoIterator<Item = Repository>) {
        self.append_root_repos(extra, Declared::Outside);
    }

    /// [`Self::extend_root_repos`] for the repositories a POM of the root
    /// lineage exposes to the parent lookups that follow it. A declaration
    /// flagged `true` still holds an expression in a policy or `<enabled>`
    /// and reads as Maven reads it there. It adds a URL not listed yet,
    /// without changing a listed one, and the effective model's declaration
    /// replaces it.
    pub(super) fn extend_root_lineage_repos(
        &self,
        extra: impl IntoIterator<Item = (Repository, bool)>,
    ) {
        for (repo, provisional) in extra {
            let declared = if provisional {
                Declared::Provisional
            } else {
                Declared::Lineage
            };
            self.append_root_repos(std::iter::once(repo), declared);
        }
    }

    /// [`Self::extend_root_repos`] for the interpolated repositories of a
    /// root-lineage effective model, which replace the provisional entries
    /// of their URLs.
    pub(super) fn extend_root_effective_repos(&self, extra: impl IntoIterator<Item = Repository>) {
        self.append_root_repos(extra, Declared::Effective);
    }

    /// Admit root-lineage declarations and append them as `declared`. A
    /// refused one still holds its id, as Maven's blocked mirror keeps the
    /// repository it replaces: a declaration under that id elsewhere in the
    /// lineage is not searched instead, and an effective model's retires
    /// the lineage entry it overrides.
    fn append_root_repos(&self, extra: impl IntoIterator<Item = Repository>, declared: Declared) {
        let (admitted, refused) = self.admit_root_lineage(extra);
        if !refused.is_empty() {
            self.hold_refused_ids(&refused, declared);
        }
        self.append_repos(admitted, declared);
    }

    fn hold_refused_ids(&self, refused: &[Repository], declared: Declared) {
        let mut seen = self.seen_repos.write().expect("seen_repos lock poisoned");
        let mut repos_guard = self.repos.write().expect("repos lock poisoned");
        repos_guard.generation += 1;
        let Repositories {
            entries: guard,
            project_end,
            ..
        } = &mut *repos_guard;
        let mut provisional = lock(&self.provisional_repos);
        let mut lineage = lock(&self.lineage_repos);
        let mut root_ids = lock(&self.root_repo_ids);
        let mut held = lock(&self.held_repo_ids);
        for repo in refused {
            let Some(id) = repo.id.as_deref().filter(|id| !id.is_empty()) else {
                continue;
            };
            if declared == Declared::Effective {
                while let Some(at) = guard[..*project_end].iter().position(|known| {
                    known.id.as_deref() == Some(id) && lineage.contains(&repo_key(known))
                }) {
                    let removed = repo_key(&guard.remove(at));
                    provisional.remove(&removed);
                    lineage.remove(&removed);
                    seen.remove(&removed);
                    *project_end -= 1;
                }
            }
            root_ids.insert(id.to_string());
            held.insert(id.to_string());
        }
    }

    /// The admitted repositories of those reactor module `coord` declares.
    /// A refused one holds no id: an admitted one holds its id only in the
    /// module's subtree, where Maven's blocking mirror does not keep a
    /// blocked one's. Admission only grants, so a declaration admitted
    /// whole once is admitted the same way again by the same source; one
    /// with a refusal is admitted again to report it. Without a source,
    /// admission reads each module's own configuration.
    fn admit_reactor_repos(
        &self,
        coord: &Coord,
        declared: &[rv_maven_model::Repository],
    ) -> Vec<Repository> {
        let known = (self.ctx.pom_source.is_some()).then_some(&self.ctx.reactor_admissions);
        if let Some(known) = known
            && let Some((repos, admitted)) = lock(known).get(coord)
            && repos == declared
        {
            return admitted.clone();
        }
        let (admitted, refused) = self.admit_root_lineage(resolution_repositories(declared));
        if refused.is_empty()
            && let Some(known) = known
        {
            lock(known).insert(coord.clone(), (declared.to_vec(), admitted.clone()));
        }
        admitted
    }

    pub(super) fn admit_root_lineage(
        &self,
        extra: impl IntoIterator<Item = Repository>,
    ) -> (Vec<Repository>, Vec<Repository>) {
        let mut admitted = Vec::new();
        let mut refused = Vec::new();
        for repo in extra {
            let from = match repo.provenance() {
                // The configuration's grants are in place, and a repository
                // read back from raeva.lock gains nothing until a POM declares it.
                Provenance::Configured | Provenance::Caller => {
                    admitted.push(repo);
                    continue;
                }
                Provenance::LocalPom => Declaration::LocalPom,
                _ => Declaration::RemoteParent,
            };
            let admission = self.admission(vec![repo], from);
            self.warn_secret_urls(&admission.secret_urls, None);
            admitted.extend(admission.admitted);
            refused.extend(admission.secret_urls);
            refused.extend(admission.blocked_http);
            for dropped in admission.dropped {
                let (refused_urls, url) =
                    (Arc::clone(&self.refused_lineage_urls), dropped.url.clone());
                rv_maven_model::held::when_shown(move || {
                    if lock(&refused_urls).insert(url.clone()) {
                        tracing::warn!(
                            sec_code = "FETCHED_POM_REPO_REFUSED",
                            url = %rv_config::redact_url(&url),
                            "ignoring a repository a fetched parent or BOM declares; a fetched \
                             POM may only name an http or https repository"
                        );
                    }
                });
                refused.push(dropped);
            }
        }
        (admitted, refused)
    }

    /// Report, once per URL, a POM repository refused because its URL may
    /// hold a credential, with its id and, when known, the POM declaring
    /// it. The URL is not shown at all: its host is no help without the
    /// part that was refused.
    fn warn_secret_urls(&self, refused: &[Repository], declared_by: Option<&str>) {
        if refused.is_empty() {
            return;
        }
        let secrets = self.ctx.config.secret_named_inputs();
        for repo in refused {
            let refused_urls = Arc::clone(&self.refused_lineage_urls);
            let id = repo.id.as_deref().unwrap_or_default();
            let (url, id) = (
                repo.url.clone(),
                rv_config::without_secret_values(id, &secrets).to_string(),
            );
            let declared_by = declared_by.map(str::to_string);
            let Some(refusal) = rv_repo::secret_url_refusal(&url, &secrets) else {
                continue;
            };
            rv_maven_model::held::when_shown(move || {
                if !lock(&refused_urls).insert(url.clone()) {
                    return;
                }
                let id = rv_maven_types::bounded(&id);
                match declared_by.as_deref().map(rv_maven_types::bounded) {
                    Some(declared_by) => tracing::warn!(
                        sec_code = "REPO_URL_SECRET_REFUSED",
                        repository = %id,
                        declared_by = %declared_by,
                        "ignoring repository '{id}' that {declared_by} declares because its URL \
                         {refusal}"
                    ),
                    None => tracing::warn!(
                        sec_code = "REPO_URL_SECRET_REFUSED",
                        repository = %id,
                        "ignoring repository '{id}' that a fetched POM declares because its URL \
                         {refusal}"
                    ),
                }
            });
        }
    }

    /// Add admitted repositories to the shared list, deduplicated by id and
    /// URL. A repeated declaration can only make its checksum policy
    /// stricter.
    fn append_repos(&self, repos: Vec<Repository>, declared: Declared) {
        if repos.is_empty() {
            return;
        }
        // Lock order: the key-set guard, the repos guard, the provisional
        // set, the lineage set, the root ids, then the held ids. All call
        // sites in this module follow the same order, so they cannot
        // deadlock.
        let mut seen = self.seen_repos.write().expect("seen_repos lock poisoned");
        let mut repos_guard = self.repos.write().expect("repos lock poisoned");
        repos_guard.generation += 1;
        let Repositories {
            entries: guard,
            project_end,
            ..
        } = &mut *repos_guard;
        let mut provisional = lock(&self.provisional_repos);
        let mut lineage = lock(&self.lineage_repos);
        let mut root_ids = lock(&self.root_repo_ids);
        let mut held = lock(&self.held_repo_ids);
        for repo in repos {
            let key = repo_key(&repo);
            let id = repo.id.as_deref().filter(|id| !id.is_empty());
            if let Some(id) = id
                && held.contains(id)
            {
                match declared {
                    Declared::Lineage | Declared::Provisional => continue,
                    Declared::Effective => {
                        held.remove(id);
                    }
                    Declared::Outside | Declared::Fetched | Declared::Reactor => {}
                }
            }
            // Maven aggregates a dependency's repositories under the ones
            // the project already has by id, so one that reuses such an id
            // on another URL is dropped. Kept, it would receive the
            // credential configured for that id.
            if matches!(declared, Declared::Fetched | Declared::Reactor)
                && let Some(id) = id
                && if declared == Declared::Reactor {
                    guard[..*project_end]
                        .iter()
                        .any(|known| known.id.as_deref() == Some(id))
                } else {
                    root_ids.contains(id)
                }
                && !seen.contains(&key)
            {
                tracing::debug!(
                    url = %rv_config::redact_url(&repo.url),
                    id,
                    "ignoring a dependency POM's repository under an id the project already uses"
                );
                continue;
            }
            if !matches!(declared, Declared::Fetched | Declared::Reactor)
                && let Some(id) = id
            {
                root_ids.insert(id.to_string());
            }
            let default = self.default_urls.contains(&repo.url);
            // The project's repositories are one per id, as in Maven's model.
            // One under a default's id replaces that default, as one under
            // `central` replaces the super POM's. Otherwise an effective
            // model's declaration replaces one a parent lookup added, and the
            // first declaration stays.
            if !matches!(declared, Declared::Fetched | Declared::Reactor)
                && let Some(id) = id
            {
                let listed = |known: &Repository, default_url: bool| {
                    known.id.as_deref() == Some(id)
                        && self.default_urls.contains(&known.url) == default_url
                };
                let replaced = if !default
                    && declared != Declared::Provisional
                    && let Some(at) = guard[..*project_end]
                        .iter()
                        .position(|known| listed(known, true))
                {
                    Some(at)
                } else if let Some(at) = guard[..*project_end]
                    .iter()
                    .position(|known| listed(known, false) && known.url != repo.url)
                {
                    if declared != Declared::Effective || !lineage.contains(&repo_key(&guard[at])) {
                        continue;
                    }
                    Some(at)
                } else {
                    None
                };
                if let Some(at) = replaced {
                    let removed = repo_key(&guard.remove(at));
                    provisional.remove(&removed);
                    lineage.remove(&removed);
                    seen.remove(&removed);
                    *project_end -= 1;
                }
            }
            if seen.insert(key.clone()) {
                if matches!(declared, Declared::Lineage | Declared::Provisional) {
                    lineage.insert(key.clone());
                }
                if declared == Declared::Provisional {
                    provisional.insert(key, Vec::new());
                }
                // The project's repositories go before the defaults, as Maven
                // searches the super POM's `central` last; a dependency's POM
                // adds its own after all of them, even after a project
                // declaration replaces the last default.
                let at = if matches!(declared, Declared::Fetched | Declared::Reactor) {
                    guard.len()
                } else {
                    let at = guard[..*project_end]
                        .iter()
                        .position(|known| !default && self.default_urls.contains(&known.url))
                        .unwrap_or(*project_end);
                    *project_end += 1;
                    at
                };
                guard.insert(at, repo);
                continue;
            }
            if declared == Declared::Provisional {
                continue;
            }
            let Some(existing) = guard.iter_mut().find(|r| repo_key(r) == key) else {
                continue;
            };
            if declared == Declared::Effective
                && let Some(outside) = provisional.remove(&key)
            {
                *existing = repo;
                for (other, declared) in &outside {
                    declared.merge(existing, other);
                }
                continue;
            }
            if repo.has_strict_checksum_policy() {
                declared.merge(existing, &repo);
            }
            if matches!(
                declared,
                Declared::Outside | Declared::Fetched | Declared::Reactor
            ) && let Some(outside) = provisional.get_mut(&key)
            {
                outside.push((repo, declared));
            }
        }
    }

    /// Append `<repositories>` declared by a TRANSITIVE POM (i.e. not the
    /// resolution root) to the shared list, deduplicated by id and URL.
    ///
    /// Maven propagates `<repositories>` from every fetched POM into the
    /// resolution context, so transitive deps could otherwise introduce their
    /// own repository URLs and have subsequent fetches in the same resolution
    /// trust them silently.
    ///
    /// Raeva's default is to **ignore** transitive `<repositories>`: a hostile
    /// transitive POM should not be able to redirect later fetches. Users opt
    /// in globally via the `[security] allow_transitive_repositories` flag or
    /// narrowly via the URL-prefix `transitive_repository_allowlist`.
    ///
    /// `declared_by` identifies the POM as `group:artifact:version`.
    /// Report and remember dropped repositories only when this identity is known.
    /// The parent-chain hook passes `None`; the post-parse call supplies the identity.
    pub(super) fn extend_repos(
        &self,
        extra: impl IntoIterator<Item = Repository>,
        declared_by: Option<&str>,
    ) {
        let (admitted, _) = self.admit_transitive(extra, declared_by);
        self.append_repos(admitted, Declared::Fetched);
    }

    /// Aggregate admitted transitive `<repositories>` onto `parent` for a
    /// dependency node's children, Maven style: an ID already in the root
    /// list or in `parent` is not replaced (the existing entry wins).
    pub(super) fn extend_context(
        &self,
        parent: &RepoContext,
        extra: impl IntoIterator<Item = Repository>,
        declared_by: Option<&str>,
    ) -> RepoContext {
        let (admitted, _) = self.admit_transitive(extra, declared_by);
        self.join_context(parent, admitted, Declared::Fetched)
    }

    /// `parent`, then each of `admitted` it and the project do not hold by
    /// id, as Maven aggregates a dependency's repositories for its own
    /// dependencies.
    fn join_context(
        &self,
        parent: &RepoContext,
        admitted: Vec<Repository>,
        declared: Declared,
    ) -> RepoContext {
        if admitted.is_empty() {
            return parent.clone();
        }
        self.append_repos(admitted.clone(), declared);
        let root_repos = self.root_repos_snapshot();
        let root_ids = lock(&self.root_repo_ids);
        let mut merged: Vec<Repository> = parent.as_slice().to_vec();
        for repo in admitted {
            let id = repo.id.as_deref().unwrap_or("");
            let shadowed = if declared == Declared::Reactor {
                (root_repos.iter()).any(|known| known.id.as_deref() == Some(id))
            } else {
                root_ids.contains(id)
            };
            if (!id.is_empty() && shadowed)
                || root_repos.iter().any(|r| repo_key(r) == repo_key(&repo))
            {
                continue;
            }
            if let Some(known) = merged
                .iter_mut()
                .find(|r| r.id.as_deref().unwrap_or("") == id)
            {
                if repo_key(known) == repo_key(&repo) && repo.has_strict_checksum_policy() {
                    declared.merge(known, &repo);
                }
                continue;
            }
            merged.push(repo);
        }
        drop(root_ids);
        if merged.as_slice() == parent.as_slice() {
            parent.clone()
        } else {
            RepoContext::from_repos(merged)
        }
    }

    /// The repositories of `extra` that the transitive repository policy
    /// admits, and the declarations it refused. Dropped ones are reported
    /// and remembered when `declared_by` names the POM that declares them.
    pub(super) fn admit_transitive(
        &self,
        extra: impl IntoIterator<Item = Repository>,
        declared_by: Option<&str>,
    ) -> (Vec<Repository>, Vec<Repository>) {
        let admission = self.admission(extra.into_iter().collect(), Declaration::Transitive);
        self.warn_secret_urls(&admission.secret_urls, declared_by);
        if let Some(declared_by) = declared_by {
            // A not-found error names these when they could have served the
            // artifact.
            let refused = (admission.dropped.iter().map(|repo| (repo, false)))
                .chain(admission.blocked_http.iter().map(|repo| (repo, true)));
            for (repo, http_blocked) in refused {
                let mut dropped = lock(&self.dropped_repos);
                if !dropped
                    .iter()
                    .any(|d| d.url == repo.url && d.declared_by == declared_by)
                {
                    // Central is searched anyway, and a release resolves no
                    // snapshot from a snapshot-only repository.
                    let quiet = is_central(&repo.url)
                        || (!repo.releases_enabled
                            && !(declared_by.rsplit(':').next())
                                .is_some_and(rv_maven_types::is_snapshot_version));
                    if !http_blocked && !quiet {
                        // `sec_code` routes warnings into `data.warnings` even when JSON mode suppresses tracing output.
                        tracing::warn!(
                            sec_code = "TRANSITIVE_REPO_DROPPED",
                            url = %rv_config::redact_url(&repo.url),
                            declared_by,
                            "ignoring transitive repository declaration; not on allowlist (see [security] allow_transitive_repositories)"
                        );
                    }
                    dropped.push(DroppedRepo {
                        url: repo.url.clone(),
                        declared_by: declared_by.to_string(),
                        releases_enabled: repo.releases_enabled,
                        snapshots_enabled: repo.snapshots_enabled,
                        http_blocked,
                    });
                }
            }
        }
        let mut refused = admission.dropped;
        refused.extend(admission.secret_urls);
        refused.extend(admission.blocked_http);
        (admission.admitted, refused)
    }

    /// The repositories a version listing reads, in order, each with the
    /// repository [`Repository::version_listing`] reads it as.
    fn version_listings(
        searched: Vec<Repository>,
        with_snapshots: bool,
    ) -> Result<(Vec<Repository>, Vec<Repository>)> {
        let mut repos = Vec::new();
        let mut listings = Vec::new();
        for repo in searched {
            match repo.version_listing(with_snapshots) {
                Ok(Some(listing)) => {
                    repos.push(repo);
                    listings.push(listing);
                }
                Ok(None) => {}
                Err(source) => {
                    let searched = vec![RepoSearchStatus::from_error(repo.url.as_str(), &source)];
                    return Err(ResolveError::Repo {
                        coord: None,
                        source: Box::new(source),
                        searched,
                    });
                }
            }
        }
        Ok((repos, listings))
    }

    /// The version metadata of `group_id:artifact_id` from each repository
    /// of `searched` a listing reads, in repository order, fetched
    /// concurrently. Finding
    /// none, unless `found` already, is an error: the first failure, else
    /// not found. A repository its configuration refuses fails the listing,
    /// as in Maven.
    async fn listed_metadata(
        &self,
        source: &dyn PomSource,
        searched: Vec<Repository>,
        group_id: &str,
        artifact_id: &str,
        with_snapshots: bool,
        found: bool,
    ) -> Result<Vec<(Repository, Arc<Metadata>)>> {
        let (repos, listings) = Self::version_listings(searched, with_snapshots)?;
        let concurrency = self
            .ctx
            .config
            .network
            .fetch_concurrency()
            .min(repos.len().max(1));
        let dummy = dummy_coord(group_id, artifact_id)?;
        // Iterate indices, not `repos.iter().enumerate()`. Borrowing the
        // closure's `&Repository` argument inside the `async move` block gives
        // the block a higher-ranked lifetime that `Send` inference cannot see
        // through, and `Backend`'s futures must be `Send`.
        let mut results: Vec<_> = stream::iter(0..repos.len())
            .map(|idx| {
                let listing = &listings[idx];
                let url = Arc::from(repos[idx].url.as_str());
                let key = MetadataKey::new(url, Arc::from(group_id), Arc::from(artifact_id))
                    .with_repo_id(repos[idx].id.as_deref())
                    .with_checksum_policy(listing.releases_checksum_policy)
                    .with_update_policy(listing.releases_update_policy);
                let dummy = &dummy;
                async move {
                    if let Some(metadata) = self.ctx.cached_metadata(&key) {
                        return (idx, Ok(metadata));
                    }
                    self.note_progress();
                    let fetched = source.metadata(listing, dummy).await;
                    // A failed response is progress too.
                    self.note_progress();
                    let metadata = fetched.map(|metadata| self.ctx.insert_metadata(key, metadata));
                    (idx, metadata)
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;
        results.sort_by_key(|(idx, _)| *idx);

        let mut hits = Vec::new();
        let mut searched = Vec::new();
        let mut first_error = None;
        let mut fallback = rv_repo::RepositoryFallback::default();
        let mut skipped = Vec::new();
        for (idx, result) in results {
            let repo = &repos[idx];
            let err = match result {
                Ok(metadata) => {
                    hits.push((repo.clone(), metadata));
                    continue;
                }
                Err(err) => err,
            };
            let effective = source.effective_repository(repo);
            let warned = fallback.failed(&effective, &err);
            if !matches!(err, RepoError::NotFound(_)) {
                skipped.push((effective, err.to_string(), warned));
            }
            searched.push(RepoSearchStatus::from_fetch_error(repo, &err, |repo| {
                source.effective_repository(repo)
            }));
            // A listing without a repository that failed a retried request
            // would differ from one with it.
            if matches!(err, RepoError::Config(_)) || err.is_transient() {
                return Err(ResolveError::Repo {
                    coord: Some(format!("{group_id}:{artifact_id}")),
                    source: Box::new(err),
                    searched,
                });
            }
            // One broken mirror does not fail the listing.
            if first_error
                .as_ref()
                .is_none_or(|error: &RepoError| matches!(error.status_code(), Some(401 | 403)))
            {
                remember_search_error(&mut first_error, err);
            }
        }
        // The versions of the repositories that answered are listed without
        // the failed ones', so say which were left out.
        let coordinate = format!("{group_id}:{artifact_id}");
        let file = rv_maven_types::layout::metadata_path(group_id, artifact_id, None);
        for (repo, _) in &hits {
            fallback.served_for(
                &source.effective_repository(repo),
                &coordinate,
                file.clone(),
            );
        }
        if !hits.is_empty() || found {
            for (repo, error, warned) in skipped {
                // A fallback warning already names this failure when
                // another repository answered.
                if warned && !hits.is_empty() {
                    continue;
                }
                let repository = rv_maven_types::bounded(
                    &repo
                        .id
                        .clone()
                        .unwrap_or_else(|| rv_config::redact_url(&repo.url)),
                )
                .to_string();
                tracing::warn!(
                    sec_code = "LISTING_REPO_SKIPPED",
                    repository,
                    coordinate,
                    "the versions of {coordinate} were listed without repository \
                     '{repository}', which failed: {error}"
                );
            }
        }
        if hits.is_empty() && !found {
            return Err(match first_error {
                Some(source) => ResolveError::Repo {
                    coord: Some(format!("{group_id}:{artifact_id}")),
                    source: Box::new(source),
                    searched,
                },
                None => ResolveError::ArtifactNotFound {
                    dropped_repos: Vec::new(),
                    coord: format!("{group_id}:{artifact_id}"),
                    searched,
                    classifier_like: None,
                },
            });
        }
        Ok(hits)
    }

    async fn resolve_versions_internal(
        &self,
        group_id: &str,
        artifact_id: &str,
        req: &VersionReq,
        repos: &RepoContext,
    ) -> Result<Vec<ResolvedVersion>> {
        if let VersionReq::Exact(version) = req
            && let Some(token) = parse_dynamic_version_token(version.as_str())
        {
            return self
                .resolve_dynamic_version_internal(group_id, artifact_id, token, repos)
                .await
                .map(|v| vec![v]);
        }

        let workspace_versions = self.workspace_versions(group_id, artifact_id);
        let found = !workspace_versions.is_empty();
        let hits = match self.ctx.pom_source.as_deref() {
            Some(source) => {
                let searched = self.search_repos(repos);
                self.listed_metadata(source, searched, group_id, artifact_id, true, found)
                    .await?
            }
            None if found => Vec::new(),
            None => return Err(ResolveError::MissingRepoClient),
        };
        let mut versions: Vec<_> = workspace_versions;
        for (repo, metadata) in hits {
            for candidate in &metadata.versions {
                // Gate each candidate on the repository that listed it, so a
                // range cannot select a snapshot that only a mirror the
                // consumer's policy excludes publishes.
                if repo.allows_listed_version(candidate)
                    && let Ok(version) = Version::parse(candidate)
                {
                    versions.push(version);
                }
            }
        }
        // Maven lists each spelling once, and two that compare equal both.
        let mut listed = HashSet::new();
        versions
            .retain(|version| listed.insert(version.as_str().to_string()) && req.matches(version));
        sort_as_maven_lists(&mut versions, listed.len());
        let versions: Vec<_> = versions
            .into_iter()
            .map(|version| ResolvedVersion {
                version,
                repo: None,
            })
            .collect();
        if versions.is_empty() {
            return Err(ResolveError::VersionNotFound {
                coord: format!("{group_id}:{artifact_id}"),
                requirement: req.to_string(),
            });
        }
        Ok(versions)
    }

    async fn resolve_dynamic_version_internal(
        &self,
        group_id: &str,
        artifact_id: &str,
        token: DynamicVersionToken,
        repos: &RepoContext,
    ) -> Result<ResolvedVersion> {
        // A reactor module stands in for the local repository's metadata,
        // which Maven also reads and raeva does not.
        let workspace = self
            .workspace_versions(group_id, artifact_id)
            .into_iter()
            .filter(|version| token.admits(version.as_str()))
            .max();
        let with_snapshots = token == DynamicVersionToken::Integration;
        let hits = match self.ctx.pom_source.as_deref() {
            Some(source) => {
                self.listed_metadata(
                    source,
                    self.search_repos(repos),
                    group_id,
                    artifact_id,
                    with_snapshots,
                    workspace.is_some(),
                )
                .await?
            }
            None if workspace.is_some() => Vec::new(),
            None => return Err(ResolveError::MissingRepoClient),
        };
        // DefaultVersionResolver takes `<release>`, or for LATEST `<latest>`
        // and else `<release>`, from the metadata with the newest
        // `<lastUpdated>`, the first on a tie. It never reads `<versions>`.
        let newest = |marker: fn(&Metadata) -> Option<&str>| {
            let mut newest: Option<(&str, &str)> = None;
            for (repo, metadata) in &hits {
                // Gate each marker on the repository that wrote it, as for
                // ranges.
                let Some(version) = marker(metadata).filter(|version| {
                    !version.is_empty() && token.admits(version) && repo.allows_version(version)
                }) else {
                    continue;
                };
                let stamp = metadata.last_updated.as_deref();
                if newest.is_none_or(|(_, known)| stamp.is_some_and(|stamp| stamp > known)) {
                    newest = Some((version, stamp.unwrap_or("")));
                }
            }
            newest.and_then(|(version, _)| Version::parse(version).ok())
        };
        let release: fn(&Metadata) -> Option<&str> = |metadata| metadata.release.as_deref();
        let marked = match token {
            DynamicVersionToken::Release => newest(release),
            DynamicVersionToken::Integration => {
                newest(|metadata| metadata.latest.as_deref()).or_else(|| newest(release))
            }
        };
        marked
            .or(workspace)
            .map(|version| ResolvedVersion {
                version,
                repo: None,
            })
            .ok_or_else(|| ResolveError::VersionNotFound {
                coord: format!("{group_id}:{artifact_id}"),
                requirement: token.requirement_label().to_string(),
            })
    }

    async fn resolve_snapshot_version_internal(
        &self,
        coord: &Coord,
        repos: &RepoContext,
    ) -> Result<ResolvedVersion> {
        if self.workspace_module_for_coord(coord).is_some() {
            return Ok(ResolvedVersion {
                version: coord.version.clone(),
                repo: None,
            });
        }

        let source = self
            .ctx
            .pom_source
            .as_deref()
            .ok_or(ResolveError::MissingRepoClient)?;

        let version_str = coord.version.as_str();
        let repos = self.search_repos(repos);
        let eligible_repos = filter_repos_for_version(&repos, version_str, coord)?;

        let mut search = Search::default();
        let (repo, resolution) = match self
            .newest_snapshot(source, eligible_repos, coord, &mut search)
            .await
        {
            Ok(newest) => newest,
            Err(failure) => return Err(failure.unwrap_or_else(|| search.exhausted(coord))),
        };
        search.snapshot_served(source, repo, coord, &resolution);
        // As in Maven, a base version no repository names leaves the file to
        // whichever repository serves it.
        let candidate = resolution.candidate != SnapshotCandidate::Absent;
        Ok(ResolvedVersion {
            version: Version::parse(&resolution.version)?,
            repo: candidate.then(|| RepoRef::of(repo)),
        })
    }

    /// The repository of `repos` with the newest SNAPSHOT build of `coord`,
    /// and its resolution. Failures are recorded in `search`; without a
    /// build, the failure that ended the search, if any, is returned.
    async fn newest_snapshot<'r>(
        &self,
        source: &dyn PomSource,
        repos: Vec<&'r Repository>,
        coord: &Coord,
        search: &mut Search,
    ) -> std::result::Result<(&'r Repository, rv_repo::SnapshotResolution), Option<ResolveError>>
    {
        // Maven merges the metadata of every repository and keeps the build
        // with the greatest `updated` value. A missing value compares as
        // empty, and the earlier repository wins a tie. Builds a file's own
        // `<snapshotVersion>` names and `<snapshot>` builds compete apart; a
        // `<snapshot>` build then wins only when it is newer and comes from
        // another repository.
        let mut failure = None;
        let mut specific: Option<(&'r Repository, rv_repo::SnapshotResolution)> = None;
        let mut generic: Option<(&'r Repository, rv_repo::SnapshotResolution)> = None;
        let mut base = None;
        let mut pinned = None;
        let mut served = Vec::new();
        let first = repos.first().copied();
        // Every repository is read, so all are asked at once.
        self.note_progress();
        let results = futures::future::join_all(repos.iter().map(|repo| async move {
            let result = source.snapshot(repo, coord).await;
            // A failed response is progress too.
            self.note_progress();
            result
        }))
        .await;
        for (repo, result) in repos.into_iter().zip(results) {
            if let Ok(resolution) = &result
                && resolution.candidate != SnapshotCandidate::Absent
            {
                served.push((repo, resolution.clone()));
            }
            match result {
                Ok(resolution) if resolution.candidate == SnapshotCandidate::Pinned => {
                    pinned.get_or_insert(resolution.version);
                }
                Ok(resolution) if resolution.candidate == SnapshotCandidate::Absent => {
                    base.get_or_insert((repo, resolution));
                }
                Ok(resolution) => {
                    let best = if resolution.candidate == SnapshotCandidate::Specific {
                        &mut specific
                    } else {
                        &mut generic
                    };
                    let newer = best.as_ref().is_none_or(|(_, kept)| {
                        is_newer(resolution.updated.as_deref(), kept.updated.as_deref())
                    });
                    if newer {
                        *best = Some((repo, resolution));
                    }
                }
                Err(err) => {
                    let retried = err.is_transient();
                    if let Err(err) = search.failed(source, repo, coord, err) {
                        // Another repository's build would stand in for
                        // one this repository may have.
                        if retried {
                            return Err(Some(err));
                        }
                        failure.get_or_insert(err);
                    }
                }
            }
        }
        // The build raeva.lock pins stands over newer ones, from the first
        // repository that serves it, as when it was locked.
        if let Some(version) = pinned {
            return Ok(served
                .into_iter()
                .find(|(_, resolution)| resolution.version == version)
                .expect("the pinned resolution is served"));
        }
        let best = match (specific, generic) {
            (Some(specific), Some(generic))
                if is_newer(generic.1.updated.as_deref(), specific.1.updated.as_deref())
                    && repo_key(generic.0) != repo_key(specific.0) =>
            {
                Some(generic)
            }
            (specific, generic) => specific.or(generic),
        }
        .or(base);
        match (best, failure, first) {
            (Some(best), ..) => Ok(best),
            // As in Maven, a SNAPSHOT that no repository has metadata for is
            // read at its base version, from whichever repository serves it.
            (None, None, Some(first)) => Ok((
                first,
                rv_repo::SnapshotResolution::base(coord.version.to_string()),
            )),
            (None, failure, _) => Err(failure),
        }
    }

    /// [`Backend::fetch_project`]. An explicit timestamp is fixed, but one
    /// SNAPSHOT metadata selected still resolves its POM independently. The
    /// build `1.0SNAPSHOT` resolves to, `1.020240101.010101-7`, is no
    /// SNAPSHOT to Maven, which reads it as a release.
    pub(super) async fn fetch_project_internal(
        &self,
        coord: &Coord,
        resolve_snapshot_pom: bool,
        repos: &RepoContext,
    ) -> Result<ResolvedProject> {
        let version = coord.version.as_str();
        let result = if (rv_maven_types::resolves_through_snapshot_metadata(version)
            || (resolve_snapshot_pom && rv_maven_types::snapshot_base_version(version).is_some()))
            && self.workspace_module_for_coord(coord).is_none()
        {
            self.fetch_snapshot_project_internal(coord, repos).await?
        } else {
            let result = self.fetch_project_at_version(coord, None, repos).await?;
            if let Some(repo_url) = &result.repo_url {
                lock(&self.release_pom_repos)
                    .insert((pom_gav(coord), repos.clone()), Arc::clone(repo_url));
            }
            result
        };
        self.record_parent_ranges(coord, repos, &result.project);
        Ok(result)
    }

    fn record_parent_ranges(&self, coord: &Coord, repos: &RepoContext, project: &Project) {
        if project.parent_ranges.is_empty() {
            return;
        }
        lock(&self.parent_ranges).insert(
            (ExactCoord(coord.clone()), repos.clone()),
            model_parent_ranges(
                &rv_maven_types::Gav::new(
                    coord.group_id.as_str(),
                    coord.artifact_id.as_str(),
                    &rv_maven_types::snapshot_base_version(coord.version.as_str())
                        .unwrap_or_else(|| coord.version.to_string()),
                )
                .to_string(),
                project,
            ),
        );
    }

    async fn fetch_snapshot_project_internal(
        &self,
        coord: &Coord,
        repos: &RepoContext,
    ) -> Result<ResolvedProject> {
        let base = rv_maven_types::snapshot_base_version(coord.version.as_str())
            .unwrap_or_else(|| coord.version.to_string());
        let pom = Coord {
            version: Version::parse(&base)?,
            packaging: Some("pom".to_string()),
            classifier: None,
            ..coord.clone()
        };
        let resolved = self.resolve_snapshot_version_internal(&pom, repos).await?;
        let pom = Coord {
            version: resolved.version,
            ..pom
        };
        let project = self
            .fetch_project_at_version(&pom, resolved.repo.as_ref(), repos)
            .await?;
        let recorded = self.companion_pom_blob(&pom_gav(&pom)).ok_or_else(|| {
            ResolveError::InternalError(format!("no companion POM recorded for {pom}"))
        })?;
        // The shared record keeps a POM another repository context found.
        let blob = if lock(&self.missing_poms).contains(&(ExactCoord(pom.clone()), repos.clone())) {
            None
        } else {
            recorded
        };
        let served = blob.clone().map(|blob| (blob, project.repo_url.clone()));
        self.record_companion_pom_blob(pom_gav(coord), served)?;
        if blob.is_none() {
            lock(&self.missing_poms).insert((ExactCoord(coord.clone()), repos.clone()));
        }
        let mut problems = lock(&self.pom_problems);
        if let Some(problem) = problems.get(&pom_gav(&pom)).cloned() {
            problems.insert(pom_gav(coord), problem);
        }
        drop(problems);
        let stamp = rv_maven_types::SnapshotStamp::of_version(pom.version.as_str());
        let origin = CompanionPomOrigin {
            base: stamp.is_none(),
            snapshot: stamp.filter(|stamp| {
                Some(stamp)
                    != rv_maven_types::SnapshotStamp::of_version(coord.version.as_str()).as_ref()
            }),
            repo_url: project.repo_url.clone(),
        };
        self.companion_pom_origins
            .write()
            .expect("companion_pom_origins lock poisoned")
            .insert(pom_gav(coord), origin);
        Ok(project)
    }

    async fn fetch_project_at_version(
        &self,
        coord: &Coord,
        resolved_repo: Option<&RepoRef>,
        repos: &RepoContext,
    ) -> Result<ResolvedProject> {
        if let Some(module) = self.workspace_module_for_coord(coord) {
            let workspace = self
                .workspace
                .as_deref()
                .expect("workspace module requires workspace");
            let pom_path = module.pom_path.clone();
            // Maven takes a reactor dependency's model from the reactor, built
            // from the configuration and the module's own POMs, never from
            // the consumer's repositories.
            let context = (self.reactor_models.as_deref()).and_then(|models| {
                models.own_context(|| {
                    (self.reactor_module_service()).model_context(&RepoContext::default())
                })
            });
            if let Some(model) = self.reactor_model(coord, context) {
                self.record_support_poms(&model.support_poms).await?;
                self.ctx.record_reads(&model.reads);
                return Ok(ResolvedProject {
                    project: Arc::clone(&model.project),
                    repo_url: None,
                    workspace_module: Some(pom_path),
                });
            }
            let base_dir = workspace
                .root()
                .join(&pom_path)
                .parent()
                .map(std::path::Path::to_path_buf);
            let local_parents = match base_dir.clone() {
                Some(base_dir) => LocalParents::new(base_dir, workspace.local_parent_boundary())
                    .cached_in(self.ctx.local_parents()),
                None => LocalParents::none(),
            };
            // Only the reactor root's `.mvn/maven.config` applies. Build the
            // target-platform context without probing a module-local `.mvn`,
            // then restore the module base directory for file activation and
            // `${basedir}` interpolation.
            let mut activation = self.ctx.activation_context();
            // What the build reads is kept with the model for the modules
            // that reuse it.
            let environment = activation.environment.clone();
            activation.environment = environment.detached();
            activation.base_dir = base_dir.as_deref().map(rv_fs::plain_path);
            let mut pom = module.pom().clone();
            workspace.apply_root_maven_config(&mut activation, &mut pom);
            let own = self.reactor_module_service();
            let scope = ModelScope::root(&own, local_parents);
            let project = scope.project(pom, &activation).await;
            let reads = Arc::new(activation.environment.take_reads());
            environment.record_reads(&reads);
            let project = project.map_err(|err| {
                super::project_model_error(err, &workspace.root().join(&pom_path))
            })?;
            let project = Arc::new(project);
            let effective_gav = format!(
                "{}:{}:{}",
                project.group_id, project.artifact_id, project.version
            );
            if effective_gav != module.gav().to_string() {
                return Err(ResolveError::InternalError(format!(
                    "workspace model {} resolved as {}, expected {}",
                    pom_path,
                    rv_maven_types::bounded(&effective_gav),
                    rv_maven_types::bounded(&module.gav().to_string())
                )));
            }
            let support_poms = scope.into_reads();
            // Every build starts from the same state, so what it adds to its
            // own repositories does not keep the model from another module.
            if let (Some(models), Some(context)) = (self.reactor_models.as_deref(), context) {
                models.insert(
                    coord,
                    context,
                    ReactorModel {
                        project: Arc::clone(&project),
                        pom: None,
                        support_poms,
                        reads,
                        problem: None,
                    },
                );
            }
            return Ok(ResolvedProject {
                project,
                repo_url: None,
                workspace_module: Some(pom_path),
            });
        }

        if let Some(cached) = self.ctx.cached_project(coord, repos) {
            // Replay the POM identity too. The cache can be shared with
            // another backend that did the fetch, and this graph is built from
            // the cached model, so the pin has to name the bytes that model
            // came from.
            let served = (cached.pom_blob.clone()).map(|blob| (blob, cached.repo_url.clone()));
            self.record_companion_pom_blob(pom_gav(coord), served)?;
            if cached.pom_blob.is_none() {
                lock(&self.missing_poms).insert((ExactCoord(coord.clone()), repos.clone()));
            }
            // Replay the repository that served the POM, so the artifact is
            // fetched from it and not from whichever repository comes first.
            return Ok(ResolvedProject {
                project: cached.project,
                repo_url: cached.repo_url,
                workspace_module: None,
            });
        }

        let context = self.model_context(repos);
        if let Some(model) = self.reactor_model(coord, context) {
            self.note_progress();
            self.record_support_poms(&model.support_poms).await?;
            self.ctx.record_reads(&model.reads);
            if let Some(problem) = &model.problem {
                lock(&self.pom_problems).insert(pom_gav(coord), problem.clone());
            }
            let pom = model.pom.as_ref().ok_or_else(|| {
                ResolveError::InternalError(format!("{coord} was kept as a reactor module"))
            })?;
            return self
                .admit_dependency(coord, repos, Arc::clone(&model.project), pom)
                .await;
        }

        let source = self
            .ctx
            .pom_source
            .as_deref()
            .ok_or(ResolveError::MissingRepoClient)?;
        let req = ArtifactRequest::from_coord(coord);

        let version_str = coord.version.to_string();
        let search_repos = self.search_repos(repos);
        let mut eligible_repos = filter_repos_for_version(&search_repos, &version_str, coord)?;
        // The repository version resolution picked is the only one asked, as
        // Maven's artifact resolver does, so a missing POM there is no
        // reason to read another repository's older build.
        if let Some(resolved) = resolved_repo {
            eligible_repos.retain(|repo| resolved.is(repo));
        }

        let mut search = Search::default();
        for repo in eligible_repos {
            self.note_progress();
            match self.read_pom(source, &search_repos, repo, &req).await {
                Ok((bytes, path)) => {
                    let effective = source.effective_repository(repo);
                    let endpoint: Arc<str> = Arc::from(effective.url.as_str());
                    search.fallback.served(&effective, &req, path.clone());
                    self.note_progress();
                    let repository_url = repo.base_url().map_err(|source| ResolveError::Repo {
                        coord: Some(coord.to_string()),
                        source: Box::new(source),
                        searched: std::mem::take(&mut search.searched),
                    })?;
                    let pom_blob = BlobId::from_bytes(&bytes);
                    let parsed = self.ctx.parsed_poms().parse(&pom_blob, &bytes);
                    let mut support_poms = Vec::new();
                    let mut reads = Arc::default();
                    let mut problem = None;
                    let project = match parsed {
                        Ok(pom) => {
                            let mut pom = Arc::unwrap_or_clone(pom);
                            pom.set_provenance(rv_maven_model::Provenance::Dependency);
                            let mut activation = self.dependency_activation();
                            let environment = activation.environment.clone();
                            activation.environment = environment.detached();
                            let scope = ModelScope::transitive(self, repos.clone());
                            let project = build_remote_project(pom, &scope, &activation).await;
                            reads = Arc::new(activation.environment.take_reads());
                            environment.record_reads(&reads);
                            support_poms = scope.into_reads();
                            match project? {
                                Ok(project) => project,
                                Err(error) => {
                                    problem = Some(PomProblem {
                                        repository: None,
                                        error: error.to_string(),
                                    });
                                    invalid_descriptor(coord)
                                }
                            }
                        }
                        // Malformed XML or a deserialize failure (duplicate
                        // fields, HTML login page, …): keep the artifact,
                        // drop transitives. Missing parents stay hard errors.
                        Err(err) if err.is_malformed_xml() || err.is_deserialize() => {
                            problem = Some(PomProblem {
                                repository: Some(rv_config::redact_url(&repository_url)),
                                error: err.to_string(),
                            });
                            invalid_descriptor(coord)
                        }
                        Err(err) => {
                            return Err(PomError::InvalidModel(format!(
                                "{coord} from {}: {err}",
                                rv_config::redact_url(&repository_url)
                            ))
                            .into());
                        }
                    };
                    let project = Arc::new(project);
                    if project.relocation.is_some() {
                        // Maven reads a relocated coordinate's POM to follow
                        // the relocation, whether that dependency wins
                        // mediation or not, and no lockfile row names it.
                        let stub = Arc::new(SupportPom::new(
                            coord,
                            repo,
                            &endpoint,
                            &path,
                            bytes.clone(),
                        ));
                        self.persist_support_pom(&stub).await?;
                        support_poms.push(stub);
                    }
                    let pom = DependencyPom {
                        bytes,
                        blob: pom_blob,
                        repo_url: Arc::from(repo.url.as_str()),
                        endpoint_url: endpoint,
                    };
                    self.keep_reactor_model(
                        coord,
                        repos,
                        context,
                        ReactorModel {
                            project: Arc::clone(&project),
                            pom: Some(pom.clone()),
                            support_poms,
                            reads,
                            problem: problem.clone(),
                        },
                    );
                    if let Some(problem) = problem {
                        lock(&self.pom_problems).insert(pom_gav(coord), problem);
                    }
                    return self.admit_dependency(coord, repos, project, &pom).await;
                }
                Err(err) => {
                    // A failed response is progress too.
                    self.note_progress();
                    search.failed(source, repo, coord, err)?;
                }
            }
        }
        match search.exhausted(coord) {
            // Maven resolves an artifact whose POM no repository has, without
            // its dependencies. The artifact itself must still be found.
            ResolveError::ArtifactNotFound { .. } => {
                tracing::warn!(
                    sec_code = "POM_PROBLEM",
                    coord = %coord,
                    "the POM is missing; no dependency information is available"
                );
                let stub = Arc::new(invalid_descriptor(coord));
                self.record_companion_pom_blob(pom_gav(coord), None)?;
                lock(&self.missing_poms).insert((ExactCoord(coord.clone()), repos.clone()));
                self.ctx
                    .insert_missing_project(coord.clone(), repos, Arc::clone(&stub));
                Ok(ResolvedProject {
                    project: stub,
                    repo_url: None,
                    workspace_module: None,
                })
            }
            error => Err(error),
        }
    }

    /// Record what reading `coord`'s POM and building `project` from it
    /// adds to this resolution.
    async fn admit_dependency(
        &self,
        coord: &Coord,
        repos: &RepoContext,
        project: Arc<Project>,
        pom: &DependencyPom,
    ) -> Result<ResolvedProject> {
        let (pom_blob, repo_url) = (&pom.blob, Arc::clone(&pom.repo_url));
        // Record admitted <repositories> declared by this transitive POM in
        // the shared list (for trusted_repositories / checksum policy
        // tightening) and report dropped ones.
        self.extend_repos(
            resolution_repositories(&project.repositories),
            Some(&format!(
                "{}:{}:{}",
                coord.group_id, coord.artifact_id, coord.version
            )),
        );
        // Persist and pin the exact bytes this graph node was
        // parsed from, here, where they are in hand. The download
        // pass would otherwise re-fetch the same URL and index
        // whatever it got, and the lockfile would pin that instead.
        let route = PomRoute {
            key: pom_key(coord),
            repo: Arc::clone(&pom.repo_url),
            endpoint: Arc::clone(&pom.endpoint_url),
        };
        self.store_pom_bytes(&pom_key(coord), &pom.bytes, pom_blob, &route)
            .await?;
        let served = (pom_blob.clone(), Some(Arc::clone(&repo_url)));
        self.record_companion_pom_blob(pom_gav(coord), Some(served))?;
        self.ctx.insert_project(
            coord.clone(),
            repos,
            Arc::clone(&project),
            pom_blob.clone(),
            Arc::clone(&repo_url),
        );
        Ok(ResolvedProject {
            project,
            repo_url: Some(repo_url),
            workspace_module: None,
        })
    }

    /// Record the support POMs another module's build of a reused model
    /// read, as this module's build would have.
    async fn record_support_poms(&self, poms: &[Arc<SupportPom>]) -> Result<()> {
        for pom in poms {
            if self.recorded(pom) {
                continue;
            }
            self.persist_support_pom(pom).await?;
            self.mark_recorded(Arc::clone(pom));
        }
        Ok(())
    }

    /// Whether this service recorded `pom` while no coordinate in the
    /// reactor's buffer has two blobs. Recording it again would absorb the
    /// same provenance and only move it later in the buffer's write order,
    /// which decides nothing while each coordinate has one blob. The buffer
    /// is checked at each POM's turn, as a record before it can split one.
    /// A large reactor's modules reuse hundreds of models that read the same
    /// parents and BOMs, so this skips most of the recording.
    fn recorded(&self, pom: &Arc<SupportPom>) -> bool {
        (self.workspace_support_poms.as_ref()).is_some_and(|buffer| !buffer.split())
            && lock(&self.recorded_support_poms).contains_key(&Arc::as_ptr(pom).addr())
    }

    /// Note `pom` as recorded, once its record succeeded: a failed one is
    /// checked again.
    fn mark_recorded(&self, pom: Arc<SupportPom>) {
        if self.workspace_support_poms.is_some() {
            lock(&self.recorded_support_poms).insert(Arc::as_ptr(&pom).addr(), pom);
        }
    }

    /// The ids [`Self::parent_search_list`] keeps a build from redeclaring,
    /// sorted. They can grow while the shared list stays the same, so a
    /// kept import is keyed on them too.
    pub(super) fn root_repo_ids_snapshot(&self) -> Vec<String> {
        let ids = lock(&self.root_repo_ids);
        let mut ids: Vec<String> = ids.iter().cloned().collect();
        ids.sort_unstable();
        ids
    }

    /// The root list, the path's repository context, and the repositories
    /// one build's lineage declared. A build's model resolver starts from
    /// the path's repositories, so a declaration under an id already used on
    /// another URL is left out.
    fn parent_search_list(&self, ctx: &RepoContext, build: &[Repository]) -> Vec<Repository> {
        let mut repos = self.root_repos_snapshot();
        for repo in self.parent_search_extra(&repos, ctx, build) {
            if !repos.iter().any(|known| repo_key(known) == repo_key(&repo)) {
                repos.push(repo);
            }
        }
        repos
    }

    /// The [`RepoContext`] representing the non-root repositories that
    /// [`Self::parent_search_list`] searches for `(ctx, build)`.
    pub(super) fn parent_search_context(
        &self,
        ctx: &RepoContext,
        build: &[Repository],
    ) -> RepoContext {
        if build.is_empty() {
            return ctx.clone();
        }
        let extra = self.parent_search_extra(&self.root_repos_snapshot(), ctx, build);
        if extra.as_slice() == ctx.as_slice() {
            ctx.clone()
        } else {
            RepoContext::from_repos(extra)
        }
    }

    /// `ctx`, then each of `build` that neither `root` nor an earlier entry
    /// holds, unless its id is a root id or one `ctx` uses on another URL.
    fn parent_search_extra(
        &self,
        root: &[Repository],
        ctx: &RepoContext,
        build: &[Repository],
    ) -> Vec<Repository> {
        let root_ids = lock(&self.root_repo_ids);
        let mut extra = ctx.as_slice().to_vec();
        for repo in build {
            let id = repo.id.as_deref().filter(|id| !id.is_empty());
            let blocked_id = id.is_some_and(|id| {
                root_ids.contains(id)
                    || ctx
                        .as_slice()
                        .iter()
                        .any(|r| r.id.as_deref() == Some(id) && r.url != repo.url)
            });
            if !blocked_id
                && !root
                    .iter()
                    .chain(&extra)
                    .any(|known| repo_key(known) == repo_key(repo))
            {
                extra.push(repo.clone());
            }
        }
        extra
    }

    /// Highest version in `range` for a parent lookup: reactor modules when
    /// `reactor`, then `<versions>` from the parent search list. Maven's range
    /// resolver never reads `<release>` or `<latest>`.
    pub(super) async fn parent_range_version(
        &self,
        group_id: &str,
        artifact_id: &str,
        range: &VersionReq,
        ctx: &RepoContext,
        build: &[Repository],
        reactor: bool,
    ) -> Result<Option<Version>> {
        let mut best = if reactor {
            self.workspace_versions(group_id, artifact_id)
                .into_iter()
                .filter(|version| range.matches(version))
                .max()
        } else {
            None
        };
        let Some(source) = self.ctx.pom_source.as_deref() else {
            return Ok(best);
        };
        // Maven lists a parent's versions in the repositories it would
        // fetch the parent from, the model's own among them.
        let searched = self.parent_search_list(ctx, build);
        let hits = match self
            .listed_metadata(source, searched, group_id, artifact_id, true, true)
            .await
        {
            Ok(hits) => hits,
            Err(ResolveError::ArtifactNotFound { .. }) => Vec::new(),
            Err(error) => return Err(error),
        };
        for (repo, metadata) in hits {
            for candidate in &metadata.versions {
                if repo.allows_listed_version(candidate)
                    && let Ok(version) = Version::parse(candidate)
                    && range.matches(&version)
                    && best.as_ref().is_none_or(|current| *current < version)
                {
                    best = Some(version);
                }
            }
        }
        Ok(best)
    }

    /// Start fetching the POM of `coord` from the repositories a read of it
    /// searches, so the read finds it fetched. For a parent or
    /// import, `build` holds the repositories the model being built
    /// declared so far, as for [`Self::fetch_pom_bytes`]; `None` marks a
    /// dependency's POM, which is searched only in the effective
    /// repositories. A `range` version is read for certain. Reactor
    /// modules, snapshots and POMs this resolution has already read are left
    /// alone.
    pub(super) fn prefetch_pom(
        &self,
        coord: &Coord,
        ctx: &RepoContext,
        build: Option<&[Repository]>,
        range: bool,
    ) {
        let Some(prefetcher) = self.ctx.prefetcher.as_deref() else {
            return;
        };
        let version = coord.version.to_string();
        if rv_maven_types::is_snapshot_version(&version)
            || self.workspace_module_for_coord(coord).is_some()
            || (build.is_none() && self.ctx.has_project(coord, ctx))
        {
            return;
        }
        let repos = match build {
            Some(build) => self.parent_search_list(ctx, build),
            None => self.search_repos(ctx),
        };
        if let Ok(eligible) = filter_repos_for_version(&repos, &version, coord) {
            let eligible = eligible.into_iter().cloned().collect();
            prefetcher.hint(eligible, ArtifactRequest::from_coord(coord), range);
        }
    }

    /// [`PomSource::pom`], with the parent and imported BOMs of a POM it
    /// downloads hinted from `repos` as soon as its bytes arrive.
    async fn read_pom(
        &self,
        source: &dyn PomSource,
        repos: &[Repository],
        repo: &Repository,
        req: &ArtifactRequest,
    ) -> std::result::Result<(Bytes, String), RepoError> {
        let read = source.pom(repo, req);
        match self.ctx.prefetcher.as_ref() {
            Some(prefetcher) => rv_repo::announcing_poms(prefetcher.arrival(repos), read).await,
            None => read.await,
        }
    }

    /// The bytes of a parent or imported BOM from the first repository
    /// that serves them, persisted and pinned as a support POM. `build`
    /// holds the repositories the model being built declared so far; they
    /// are searched after the shared ones.
    pub(super) async fn fetch_pom_bytes(
        &self,
        coord: &Coord,
        ctx: &RepoContext,
        build: &[Repository],
    ) -> Result<Arc<SupportPom>> {
        let source = self
            .ctx
            .pom_source
            .as_deref()
            .ok_or(ResolveError::MissingRepoClient)?;
        let mut req = ArtifactRequest::from_coord(coord);

        let version_str = coord.version.to_string();
        let repos = self.parent_search_list(ctx, build);
        let mut eligible_repos = filter_repos_for_version(&repos, &version_str, coord)?;
        let mut search = Search::default();
        // A SNAPSHOT parent or BOM is the newest build across the
        // repositories, as a dependency is, fetched from the repository that
        // names it.
        if rv_maven_types::resolves_through_snapshot_metadata(&version_str)
            && eligible_repos.len() > 1
        {
            let pom = Coord {
                packaging: Some("pom".to_string()),
                classifier: None,
                ..coord.clone()
            };
            let mut probe = Search::default();
            let newest = self
                .newest_snapshot(source, eligible_repos.clone(), &pom, &mut probe)
                .await;
            // A repository that failed a retried request may have the
            // newest build.
            let retried = |err: &ResolveError| match err {
                ResolveError::Repo { source, .. } => source.is_transient(),
                _ => false,
            };
            match newest {
                Ok((newest, resolution)) if resolution.candidate != SnapshotCandidate::Absent => {
                    eligible_repos = vec![newest];
                    req = ArtifactRequest::from_coord(&Coord {
                        version: Version::parse(&resolution.version)?,
                        ..coord.clone()
                    });
                }
                Err(Some(err)) if retried(&err) => return Err(err),
                _ => {}
            }
            // The repository that serves the POM is a fallback past those
            // that refused its metadata.
            search.fallback = probe.fallback;
        }

        for repo in eligible_repos {
            self.note_progress();
            match self.read_pom(source, &repos, repo, &req).await {
                Ok((bytes, path)) => {
                    let endpoint = source.effective_repository(repo).url;
                    let pom = SupportPom::new(coord, repo, &endpoint, &path, bytes);
                    search
                        .fallback
                        .served(&source.effective_repository(repo), &req, path);
                    self.note_progress();
                    // Persist this POM so `raeva export-m2` can materialize it
                    // for strict offline `mvn -o`. This path fetches only
                    // *support* POMs: parent POMs and imported BOMs (graph
                    // dependencies flow through `fetch_project_internal`),
                    // which are otherwise never persisted and break
                    // offline parent/BOM resolution. It runs across every
                    // eligible repo, so a parent that lives in a different
                    // repo than its child is still captured. A store-write
                    // failure is fatal, matching how artifact writes behave
                    // in `populate_artifacts`. The id is the declared
                    // repository's; export maps it to the mirror configured
                    // at export time.
                    let pom = Arc::new(pom);
                    self.persist_support_pom(&pom).await?;
                    self.mark_recorded(Arc::clone(&pom));
                    return Ok(pom);
                }
                Err(err) => {
                    // A failed response is progress too.
                    self.note_progress();
                    search.failed(source, repo, coord, err)?;
                }
            }
        }
        Err(search.exhausted(coord))
    }

    /// Record the support POMs that the build of a reused import read, as
    /// this module had read them. Other bytes for one this module read are
    /// a conflict, as a fetch of them would be.
    pub(super) fn record_kept_support_poms(&self, poms: &[Arc<SupportPom>]) -> Result<()> {
        for pom in poms {
            if self.recorded(pom) {
                continue;
            }
            if let Some(buffer) = self.workspace_support_poms.as_ref() {
                buffer.record(&pom.key, &pom.blob, &pom.bytes, &pom.route);
            }
            self.record_support_pom_provenance(pom)?;
            self.mark_recorded(Arc::clone(pom));
        }
        Ok(())
    }

    fn record_support_pom_provenance(&self, pom: &SupportPom) -> Result<()> {
        let mut recorded = self
            .support_pom_provenance
            .write()
            .expect("support_pom_provenance lock poisoned");
        if let Some(kept) = recorded.get_mut(&pom.name) {
            kept.absorb(&pom.name, &pom.provenance)?;
        } else {
            recorded.insert(pom.name.clone(), pom.provenance.clone());
        }
        Ok(())
    }

    /// Persist a fetched support POM (parent or imported BOM) into the content
    /// store under its `(group, artifact, version, "pom")` key, so
    /// `raeva export-m2` can materialize the parent/BOM closure for offline
    /// `mvn -o`.
    ///
    /// Nothing here fails for a remote-side reason (the POM has already been
    /// fetched), so a store error means a broken local store (unwritable
    /// directory, unusable index), which [`Self::store_pom_bytes`] treats as
    /// fatal like every other store write.
    async fn persist_support_pom(&self, pom: &SupportPom) -> Result<()> {
        self.store_pom_bytes(&pom.key, &pom.bytes, &pom.blob, &pom.route)
            .await?;
        self.record_support_pom_provenance(pom)
    }

    /// Put POM bytes in the content store under their
    /// `(group, artifact, version, "pom")` key, with `route`, the repository
    /// and the endpoint that served them, as evidence for a later restore.
    ///
    /// A store-write failure is fatal, the same severity `populate_artifacts`
    /// gives an artifact write: the alternative is a lockfile pinning a POM
    /// whose bytes never landed, which `raeva export-m2` can only discover
    /// afterwards.
    async fn store_pom_bytes(
        &self,
        key: &ArtifactCoord,
        bytes: &[u8],
        blob: &BlobId,
        route: &PomRoute,
    ) -> Result<()> {
        if let Some(support_poms) = self.workspace_support_poms.as_ref() {
            support_poms.record(key, blob, bytes, route);
            return Ok(());
        }
        let store = &self.ctx.store;
        let (indexed, mut served_by) = store.indexed_and_served(key, blob).await?;
        if !indexed {
            let written = store.put_bytes_with_id(blob.clone(), bytes).await?;
            store.add_artifact(key, &written).await?;
            debug_assert_eq!(&written, blob, "store blob id must be the bytes' SHA-256");
        }
        if route.key != *key {
            served_by = store.served_by(&route.key, blob).await?;
        }
        if !(served_by.iter())
            .any(|(repo, endpoint)| **repo == *route.repo && **endpoint == *route.endpoint)
        {
            let served = (
                route.key.clone(),
                blob.clone(),
                route.repo.to_string(),
                route.endpoint.to_string(),
            );
            store.record_served(vec![served]).await?;
        }
        Ok(())
    }
}

impl Backend for ModelService {
    fn workspace_module(&self, coord: &Coord) -> Option<String> {
        self.workspace_module_for_coord(coord)
            .map(|module| module.pom_path.clone())
    }

    fn note_transitive_selection(&self) {
        self.ctx.note_reactor_through_dependencies();
    }

    fn is_reactor_module(&self, group: &str, artifact: &str, version: &str) -> bool {
        (self.workspace.as_deref()).is_some_and(|workspace| {
            (workspace.candidates(group, artifact)).any(|module| module.gav().version == version)
        })
    }

    fn resolve_version<'b>(
        &'b self,
        group_id: &'b str,
        artifact_id: &'b str,
        req: &'b VersionReq,
        repos: &'b RepoContext,
    ) -> crate::solver::BoxFuture<'b, Result<ResolvedVersion>> {
        Box::pin(async move {
            let mut versions = self
                .resolve_versions_internal(group_id, artifact_id, req, repos)
                .await?;
            versions.pop().ok_or_else(|| ResolveError::VersionNotFound {
                coord: format!("{group_id}:{artifact_id}"),
                requirement: req.to_string(),
            })
        })
    }

    fn resolve_versions<'b>(
        &'b self,
        group_id: &'b str,
        artifact_id: &'b str,
        req: &'b VersionReq,
        repos: &'b RepoContext,
    ) -> crate::solver::BoxFuture<'b, Result<Vec<ResolvedVersion>>> {
        Box::pin(self.resolve_versions_internal(group_id, artifact_id, req, repos))
    }

    fn resolve_snapshot_version<'b>(
        &'b self,
        coord: &'b Coord,
        repos: &'b RepoContext,
    ) -> crate::solver::BoxFuture<'b, Result<ResolvedVersion>> {
        Box::pin(self.resolve_snapshot_version_internal(coord, repos))
    }

    fn dropped_repos_on_path(
        &self,
        path: &[String],
        version: &str,
        searched: &[RepoSearchStatus],
    ) -> Vec<DroppedRepo> {
        self.collect_dropped_repos(path, version, searched)
    }

    /// One POM pin serves every classifier of a coordinate, so winners
    /// whose repositories gave different POMs for it, or one and none, are
    /// refused as two fetches with different bytes are.
    fn note_winner(&self, coord: &Coord, path: &Arc<PathNode>) -> Result<()> {
        let gav = pom_gav(coord);
        let recorded = self
            .companion_pom_blobs
            .read()
            .expect("companion_pom_blobs lock poisoned")
            .get(&gav)
            .cloned();
        let seen = if lock(&self.missing_poms)
            .contains(&(ExactCoord(coord.clone()), path.repos.clone()))
        {
            None
        } else {
            match &recorded {
                Some(served) => served.as_ref().map(|(blob, _)| blob.clone()),
                None => return Ok(()),
            }
        };
        {
            let mut winners = lock(&self.winner_poms);
            match winners.get(&gav) {
                Some(first) if *first != seen => {
                    // One side has the one POM recorded for `gav`, and the
                    // other none.
                    let served_by = (recorded.flatten()).and_then(|(_, repo)| repo);
                    let repo = |blob: &Option<BlobId>| match (blob, &served_by) {
                        (Some(_), Some(repo)) => repo.to_string(),
                        _ => String::new(),
                    };
                    return Err(ResolveError::ConflictingResolvedPomBytes(Box::new(
                        ConflictingPom {
                            coord: format!("{}:{}:{}", gav.0, gav.1, gav.2),
                            first_origin: repo(first),
                            second_origin: repo(&seen),
                            first_sha256: pom_digest_text(first.as_ref()),
                            second_sha256: pom_digest_text(seen.as_ref()),
                        },
                    )));
                }
                Some(_) => {}
                None => {
                    winners.insert(gav, seen.clone());
                }
            }
        }
        if seen.is_none() {
            lock(&self.missing_pom_paths).insert(ExactCoord(coord.clone()), Arc::clone(path));
        }
        Ok(())
    }

    fn fetch_project<'b>(
        &'b self,
        coord: &'b Coord,
        resolve_snapshot_pom: bool,
        repos: &'b RepoContext,
    ) -> crate::solver::BoxFuture<'b, Result<ResolvedProject>> {
        Box::pin(self.fetch_project_internal(coord, resolve_snapshot_pom, repos))
    }

    fn extend_repo_context(
        &self,
        parent: &RepoContext,
        coord: &Coord,
        project: &Project,
    ) -> RepoContext {
        if project.repositories.is_empty() {
            return parent.clone();
        }
        if self.workspace_module_for_coord(coord).is_some() {
            // A reactor module's repositories are local declarations. As in
            // Maven, they serve its own dependencies, not its dependents'.
            let admitted = self.admit_reactor_repos(coord, &project.repositories);
            return self.join_context(parent, admitted, Declared::Reactor);
        }
        self.extend_context(
            parent,
            resolution_repositories(&project.repositories),
            Some(&format!(
                "{}:{}:{}",
                coord.group_id, coord.artifact_id, coord.version
            )),
        )
    }

    fn prefetches(&self) -> bool {
        self.ctx.prefetcher.is_some()
    }

    fn prefetch_project(&self, coord: &Coord, repos: &RepoContext) {
        self.prefetch_pom(coord, repos, None, false);
    }

    fn prefetch_range_version(&self, coord: &Coord, repos: &RepoContext) {
        self.prefetch_pom(coord, repos, None, true);
    }

    fn prefetch_range(
        &self,
        group_id: &str,
        artifact_id: &str,
        req: &VersionReq,
        repos: &RepoContext,
    ) {
        let Some(prefetcher) = self.ctx.prefetcher.as_ref() else {
            return;
        };
        let Ok(dummy) = dummy_coord(group_id, artifact_id) else {
            return;
        };
        let key = (format!("{group_id}:{artifact_id}:{req}"), repos.clone());
        let repos = repos.clone();
        prefetcher.hint_range(key, |lister| {
            // The task holds the prefetcher only while it hints, so dropping
            // the prefetcher still cancels it.
            let weak = Arc::downgrade(prefetcher);
            let mut service = self.clone();
            service.ctx.prefetcher = None;
            let req = req.clone();
            async move {
                let Ok((search_repos, listings)) =
                    Self::version_listings(service.search_repos(&repos), true)
                else {
                    return;
                };
                let listed = listings
                    .iter()
                    .map(|listing| lister.metadata(listing, &dummy));
                let listed = futures::future::join_all(listed).await;
                service.ctx.prefetcher = weak.upgrade();
                for (repo, metadata) in search_repos.iter().zip(listed) {
                    for listed in metadata.iter().flat_map(|metadata| &metadata.versions) {
                        if repo.allows_listed_version(listed)
                            && let Ok(version) = Version::parse(listed)
                            && req.matches(&version)
                        {
                            let coord = Coord {
                                version,
                                ..dummy.clone()
                            };
                            service.prefetch_pom(&coord, &repos, None, true);
                        }
                    }
                }
            }
        });
    }

    fn prefetch_artifact(&self, coord: &Coord, repo_url: Option<&str>, repos: &RepoContext) {
        let Some(prefetcher) = self.ctx.prefetcher.as_deref() else {
            return;
        };
        let request = ArtifactRequest::from_coord(coord);
        // A pom-packaged artifact is the POM the model was read from.
        let model =
            request.packaging == "pom" && request.classifier.as_deref().is_none_or(str::is_empty);
        if model || request.is_snapshot() || self.workspace_module_for_coord(coord).is_some() {
            return;
        }
        // The repository the artifact pass tries first: the one that served
        // the POM, else the first that may serve this version.
        let repos = self.search_repos(repos);
        let Ok(eligible) = filter_repos_for_version(&repos, &request.version, coord) else {
            return;
        };
        let repo = repo_url
            .and_then(|url| eligible.iter().find(|repo| repo.url == url))
            .or_else(|| eligible.first());
        if let Some(repo) = repo {
            let key = ArtifactCoord::new(
                request.group_id.as_str(),
                request.artifact_id.as_str(),
                request.version.as_str(),
                request.packaging.as_str(),
                request.classifier.as_deref(),
            );
            prefetcher.hint_artifact(repo, request, key);
        }
    }
}

/// Sort a range's versions, `listed` spellings in all, as Maven does: it
/// gathers them, in the order the repositories list them, in a
/// `java.util.HashMap` and sorts its entries stably, so the spellings that
/// compare equal follow the map's buckets.
fn sort_as_maven_lists(versions: &mut Vec<Version>, listed: usize) {
    let mut capacity = 16;
    while listed * 4 > capacity * 3 {
        capacity *= 2;
    }
    versions.sort_by_cached_key(|version| {
        let hash = (version.as_str().encode_utf16()).fold(0u32, |hash, unit| {
            hash.wrapping_mul(31).wrapping_add(unit.into())
        });
        (hash ^ (hash >> 16)) as usize & (capacity - 1)
    });
    Version::sort_by_key(versions, |version| version);
}

/// Build the effective model of a dependency POM fetched from a repository.
///
/// Maven's descriptor reader tells an unresolvable model from an invalid one.
/// A parent or imported BOM that no repository could serve, or that failed to
/// transfer, fails the build. A model that is invalid, such as a parent or BOM
/// that does not parse or a system dependency without `<systemPath>`, only
/// costs the artifact its transitive dependencies, with a warning. Reactor
/// POMs fail in both cases. The invalid descriptor is discarded without
/// repeating inheritance.
/// A dependency POM's effective model, or the model problem for which Maven
/// takes it as invalid and drops its dependencies.
async fn build_remote_project<S: ModelSource<Error = ResolveError>>(
    pom: Pom,
    source: &S,
    activation: &ActivationContext,
) -> Result<std::result::Result<Project, PomError>> {
    match Project::build(pom, source, ModelPolicy::DEPENDENCY, activation).await {
        Err(ResolveError::Pom(error))
            if matches!(
                error,
                PomError::UnparseablePom { .. }
                    | PomError::InvalidSystemPath(_)
                    | PomError::InvalidModel(_)
                    | PomError::MissingField(_)
            ) =>
        {
            Ok(Err(error))
        }
        other => other.map(Ok),
    }
}

/// An invalid dependency POM: the repository that served it when its XML
/// did not parse, and why.
#[derive(Clone)]
pub(super) struct PomProblem {
    repository: Option<String>,
    error: String,
}

/// What `DefaultArtifactDescriptorReader` returns for an invalid POM: the
/// artifact itself, with no dependencies, management or repositories.
fn invalid_descriptor(coord: &Coord) -> Project {
    let mut project = Project::new(
        &coord.group_id,
        &coord.artifact_id,
        &coord.version.to_string(),
    );
    if let Some(packaging) = &coord.packaging {
        project.packaging.clone_from(packaging);
    }
    project.provenance = Some(rv_maven_model::Provenance::Dependency);
    project
}

pub(super) fn model_parent_ranges(model: &str, project: &Project) -> Vec<rv_lock::ParentRange> {
    project
        .parent_ranges
        .iter()
        .map(|(parent, selected)| rv_lock::ParentRange {
            model: model.to_string(),
            parent: parent.clone(),
            selected: selected.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests;
