//! Resolution context and state.

use std::collections::BTreeSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use lru::LruCache;

use rv_config::Config;
use rv_lock::Platform;

use rv_maven_model::Project;
use rv_maven_types::{BlobId, Coord};
use rv_repo::{Metadata, RepoClient, Repository};
use rv_store::Store;

use crate::graph::ExactCoord;
use crate::parent_resolver::LocalParentCache;
use crate::parsed_pom_cache::ParsedPomCache;
use crate::resolver::pom_source::{PomSource, RepoPomSource};
use crate::resolver::prefetch::Prefetcher;
use crate::util::{lock, read_lock, write_lock};

/// 10k entries covers the transitive set of any realistic project.
const MAX_METADATA_CACHE_SIZE: usize = 10_000;
/// Avoids re-hitting the same 404 on every transitive dep resolution.
const MISSING_PARENT_TTL: Duration = Duration::from_secs(3600);

/// Per-path admitted transitive repositories appended after the root project
/// repositories. `None` is the empty context (no allocation, zero cost).
#[derive(Clone, Default, Debug)]
pub(crate) struct RepoContext(Option<Arc<RepoContextInner>>);

#[derive(Debug)]
struct RepoContextInner {
    repos: Box<[Repository]>,
    hash: u64,
}

fn hash_repository(repo: &Repository, state: &mut impl Hasher) {
    repo.id.hash(state);
    repo.url.hash(state);
    repo.releases_enabled.hash(state);
    repo.snapshots_enabled.hash(state);
    std::mem::discriminant(&repo.snapshots_update_policy).hash(state);
    repo.snapshots_update_policy.ttl_secs().hash(state);
    std::mem::discriminant(&repo.releases_update_policy).hash(state);
    repo.releases_update_policy.ttl_secs().hash(state);
    std::mem::discriminant(&repo.releases_checksum_policy).hash(state);
    std::mem::discriminant(&repo.snapshots_checksum_policy).hash(state);
}

impl RepoContext {
    pub(crate) fn from_repos(repos: Vec<Repository>) -> Self {
        if repos.is_empty() {
            return Self(None);
        }
        let mut hasher = DefaultHasher::new();
        for repo in &repos {
            hash_repository(repo, &mut hasher);
        }
        Self(Some(Arc::new(RepoContextInner {
            repos: repos.into_boxed_slice(),
            hash: hasher.finish(),
        })))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub(crate) fn as_slice(&self) -> &[Repository] {
        self.0.as_deref().map_or(&[], |inner| &inner.repos)
    }
}

impl PartialEq for RepoContext {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b) || (a.hash == b.hash && a.repos == b.repos),
            _ => false,
        }
    }
}

impl Eq for RepoContext {}

impl Hash for RepoContext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            None => 0u8.hash(state),
            Some(inner) => {
                1u8.hash(state);
                inner.hash.hash(state);
            }
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct MetadataKey {
    pub repo_url: Arc<str>,
    pub group_id: Arc<str>,
    pub artifact_id: Arc<str>,
    /// One URL under two ids is two repositories, each with its own mirror
    /// and credential.
    repo_id: Option<Arc<str>>,
    checksum_fail: bool,
    update_policy: rv_config::UpdatePolicy,
}

impl MetadataKey {
    pub(crate) fn new(repo_url: Arc<str>, group_id: Arc<str>, artifact_id: Arc<str>) -> Self {
        Self {
            repo_url,
            group_id,
            artifact_id,
            repo_id: None,
            checksum_fail: false,
            update_policy: rv_config::UpdatePolicy::Daily,
        }
    }

    pub(crate) fn with_repo_id(mut self, id: Option<&str>) -> Self {
        self.repo_id = id.map(Arc::from);
        self
    }

    pub(crate) fn with_checksum_policy(mut self, policy: rv_config::ChecksumPolicy) -> Self {
        self.checksum_fail = policy == rv_config::ChecksumPolicy::Fail;
        self
    }

    pub(crate) fn with_update_policy(mut self, policy: rv_config::UpdatePolicy) -> Self {
        self.update_policy = policy;
        self
    }
}

/// Tuple of (group_id, artifact_id, version, repo_context). `Arc<str>` to
/// dedupe the common upstream coordinate strings across all the parent-cache
/// probes that collide on them.
pub(crate) type MissingParentKey = (Arc<str>, Arc<str>, Arc<str>, RepoContext);

/// A parsed project plus the identity of the POM bytes it was parsed from.
///
/// The digest travels *inside* the cache entry rather than beside it: a cache
/// hit must be able to tell the caller which bytes produced this model, and a
/// caller that could not learn that would have to fall back to the store's
/// last-writer-wins coordinate index to pin the POM, the exact substitution
/// the pin exists to prevent. `None` marks a synthesized stub for a missing POM.
#[derive(Clone, Debug)]
pub(crate) struct CachedProject {
    pub project: Arc<Project>,
    pub pom_blob: Option<BlobId>,
    pub repo_url: Option<Arc<str>>,
}

/// Resolution caches. Module contexts get fresh metadata, project and
/// missing-parent caches while sharing parsed POMs and local parent lookups
/// across modules and platforms.
pub(crate) struct ResolveState {
    parsed_poms: Arc<ParsedPomCache>,
    local_parents: Arc<LocalParentCache>,
    metadata: RwLock<LruCache<MetadataKey, Arc<Metadata>>>,
    /// LRU-bounded; monorepos accumulate hundreds of MB of `Project` data.
    /// `Project` is `Clone`, so eviction is safe (a miss re-parses).
    ///
    /// Keyed by the exact coordinate, the `Platform`, and the `RepoContext`:
    /// a `Project` is built with the active-profile set of the resolve pass
    /// that fetched it and the path's repository context (which affects parent
    /// and BOM lookups as well as whether the POM is found at all).
    projects: RwLock<LruCache<(ExactCoord, Platform, RepoContext), CachedProject>>,
    /// `std::sync::Mutex` because every op is a single LRU `get`/`put` with
    /// no awaits.
    missing_parents: Mutex<LruCache<MissingParentKey, Instant>>,
}

impl ResolveState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn with_parsed_poms(
        parsed_poms: Arc<ParsedPomCache>,
        local_parents: Arc<LocalParentCache>,
    ) -> Self {
        Self {
            parsed_poms,
            local_parents,
            metadata: RwLock::new(new_lru()),
            projects: RwLock::new(new_lru()),
            missing_parents: Mutex::new(new_lru()),
        }
    }
}

/// Bounded, but allocated as entries arrive: every module of a reactor has
/// its own caches.
fn new_lru<K: std::hash::Hash + Eq, V>() -> LruCache<K, V> {
    let mut cache = LruCache::unbounded();
    cache.resize(NonZeroUsize::new(MAX_METADATA_CACHE_SIZE).expect("nonzero"));
    cache
}

impl Default for ResolveState {
    fn default() -> Self {
        let parsed_poms = Arc::new(ParsedPomCache::default());
        let local_parents = Arc::new(LocalParentCache::new(Arc::clone(&parsed_poms)));
        Self::with_parsed_poms(parsed_poms, local_parents)
    }
}

#[derive(Clone)]
pub(crate) struct ResolveContext {
    pub(crate) config: Config,
    pub(crate) repos: Vec<Repository>,
    pub(crate) store: Arc<Store>,
    pub(crate) platform: Platform,
    pub(crate) client: Option<RepoClient>,
    /// Where models read POMs and metadata: `client`, unless a test serves
    /// them from memory.
    pub(crate) pom_source: Option<Arc<dyn PomSource>>,
    /// Fetches POMs from `pom_source` ahead of their reads.
    pub(crate) prefetcher: Option<Arc<Prefetcher>>,
    /// The repositories reactor modules declare and those `pom_source`
    /// admitted whole, shared by every module.
    pub(crate) reactor_admissions: Arc<Mutex<ReactorAdmissions>>,
    /// os-maven-plugin's `os.detection.classifierWithLikes` for the
    /// reactor; see [`rv_maven_model::ModelEnvironment::with_classifier_likes`].
    classifier_likes: Option<rv_maven_model::ClassifierLikes>,
    state: Arc<ResolveState>,
    /// Set when a graph of the pass depends on the reactor in a way no
    /// module's declarations show. Every module of the pass shares it.
    reactor_through_dependencies: Arc<AtomicBool>,
    /// What the builds of this context read from the host, besides the
    /// record of the whole run; see [`Self::recording_into`].
    pub(crate) reads: Option<rv_maven_model::HostReads>,
}

pub(crate) type ReactorAdmissions =
    foldhash::HashMap<Coord, (Vec<rv_maven_model::Repository>, Vec<Repository>)>;

fn client_source(client: Option<&RepoClient>) -> Option<Arc<dyn PomSource>> {
    client.map(|client| Arc::new(RepoPomSource(client.clone())) as Arc<dyn PomSource>)
}

fn prefetcher_for(
    source: Option<&Arc<dyn PomSource>>,
    client: Option<&RepoClient>,
    store: &Arc<Store>,
    state: &ResolveState,
    config: &Config,
) -> Option<Arc<Prefetcher>> {
    // An offline client prefetches nothing.
    if client.is_some_and(RepoClient::is_offline) {
        return None;
    }
    source.map(|source| {
        Arc::new(Prefetcher::new(
            Arc::clone(source),
            Arc::clone(&state.parsed_poms),
            client.map(|client| (client.clone(), Arc::clone(store))),
            config.network.fetch_concurrency(),
        ))
    })
}

impl ResolveContext {
    pub(crate) fn environment(&self) -> rv_maven_model::ModelEnvironment {
        self.config
            .model_environment(
                self.platform.os(),
                self.platform.arch(),
                self.platform.jdk(),
            )
            .with_classifier_likes(self.classifier_likes.as_ref())
    }

    /// Record `reads` as read by this context's builds; see
    /// [`rv_maven_model::ModelEnvironment::record_reads`].
    pub(crate) fn record_reads(&self, reads: &Arc<BTreeSet<rv_maven_model::HostInput>>) {
        self.config.host().record_reads(reads, self.platform.jdk());
    }

    /// The activation context of a project model in this platform pass.
    pub(crate) fn activation_context(&self) -> rv_maven_model::ActivationContext {
        let mut activation = crate::parent_resolver::build_activation_context(
            None,
            &self.config,
            Some(&self.platform),
        );
        activation.environment = self.environment();
        activation
    }

    /// Note that resolution read a reactor module's POM through an external
    /// POM, as a dependency or as a parent or an import, that an import of a
    /// reactor BOM activated other profiles than its own build, or that a
    /// build read the classifier likes the first sorted project set: another
    /// branch can
    /// change the outcome by editing any reactor module.
    pub(crate) fn note_reactor_through_dependencies(&self) {
        self.reactor_through_dependencies
            .store(true, Ordering::Relaxed);
    }

    /// See [`Self::note_reactor_through_dependencies`].
    pub(crate) fn reactor_through_dependencies(&self) -> bool {
        self.reactor_through_dependencies.load(Ordering::Relaxed)
    }

    /// This context, whose builds also record what they read in `reads`.
    pub(crate) fn recording_into(&self, reads: rv_maven_model::HostReads) -> Self {
        Self {
            config: self.config.recording_into(&reads),
            reads: Some(reads),
            ..self.clone()
        }
    }

    /// This context, whose builds record what they read in `reads` alone,
    /// apart from the record of the run.
    pub(crate) fn recording_only_into(&self, reads: rv_maven_model::HostReads) -> Self {
        Self {
            config: self.config.recording_only_into(&reads),
            reads: Some(reads),
            ..self.clone()
        }
    }

    /// This context with `likes` as the reactor's classifier likes.
    pub(crate) fn with_classifier_likes(
        mut self,
        likes: Option<rv_maven_model::ClassifierLikes>,
    ) -> Self {
        self.classifier_likes = likes;
        self
    }

    #[cfg(test)]
    pub(crate) fn new(
        config: Config,
        repos: Vec<Repository>,
        store: Arc<Store>,
        platform: Platform,
        client: Option<RepoClient>,
    ) -> Self {
        let state = Arc::new(ResolveState::default());
        Self {
            repos,
            ..Self::from_config_with_state(config, store, platform, client, state)
        }
    }

    #[cfg(test)]
    pub(crate) fn with_pom_source(mut self, source: Arc<dyn PomSource>) -> Self {
        self.prefetcher =
            prefetcher_for(Some(&source), None, &self.store, &self.state, &self.config);
        self.pom_source = Some(source);
        self.reactor_admissions = Arc::default();
        self
    }

    /// Reuses an existing `ResolveState`. Derived module contexts retain its
    /// parsed-POM cache and get fresh metadata, project and missing-parent caches.
    pub(crate) fn from_config_with_state(
        config: Config,
        store: Arc<Store>,
        platform: Platform,
        client: Option<RepoClient>,
        state: Arc<ResolveState>,
    ) -> Self {
        let repos = config.repositories().iter().map(Repository::from).collect();
        let pom_source = client_source(client.as_ref());
        Self {
            prefetcher: prefetcher_for(
                pom_source.as_ref(),
                client.as_ref(),
                &store,
                &state,
                &config,
            ),
            config,
            repos,
            store,
            platform,
            pom_source,
            client,
            classifier_likes: None,
            reactor_admissions: Arc::default(),
            reactor_through_dependencies: Arc::default(),
            reads: None,
            state,
        }
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> Arc<ResolveState> {
        Arc::clone(&self.state)
    }

    pub(crate) fn for_module(&self, config: Config) -> Self {
        Self {
            config,
            state: Arc::new(ResolveState::with_parsed_poms(
                Arc::clone(&self.state.parsed_poms),
                Arc::clone(&self.state.local_parents),
            )),
            ..self.clone()
        }
    }

    /// Drop the module caches once its graph is built: a reactor keeps every
    /// module until the last graph is done, and only the graph phase reads
    /// them.
    pub(crate) fn release_graph_caches(&self) {
        *write_lock(&self.state.metadata) = new_lru();
        *write_lock(&self.state.projects) = new_lru();
        *lock(&self.state.missing_parents) = new_lru();
    }

    pub(crate) fn parsed_poms(&self) -> &ParsedPomCache {
        &self.state.parsed_poms
    }

    pub(crate) fn local_parents(&self) -> Arc<LocalParentCache> {
        Arc::clone(&self.state.local_parents)
    }

    pub(crate) fn cached_metadata(&self, key: &MetadataKey) -> Option<Arc<Metadata>> {
        read_lock(&self.state.metadata).peek(key).cloned()
    }

    /// Cache `metadata` under `key` and return the cached entry.
    pub(crate) fn insert_metadata(&self, key: MetadataKey, metadata: Metadata) -> Arc<Metadata> {
        let metadata = Arc::new(metadata);
        write_lock(&self.state.metadata).put(key, Arc::clone(&metadata));
        metadata
    }

    fn project_key(
        &self,
        coord: Coord,
        repos: &RepoContext,
    ) -> (ExactCoord, Platform, RepoContext) {
        (ExactCoord(coord), self.platform.clone(), repos.clone())
    }

    pub(crate) fn cached_project(
        &self,
        coord: &Coord,
        repos: &RepoContext,
    ) -> Option<CachedProject> {
        // `peek` (no LRU recency bump) lets reads share a read-lock, matching
        // the metadata cache's read-heavy concurrency tradeoff. The cache key
        // includes this context's target platform and repository context.
        read_lock(&self.state.projects)
            .peek(&self.project_key(coord.clone(), repos))
            .cloned()
    }

    pub(crate) fn has_project(&self, coord: &Coord, repos: &RepoContext) -> bool {
        read_lock(&self.state.projects).contains(&self.project_key(coord.clone(), repos))
    }

    pub(crate) fn insert_project(
        &self,
        coord: Coord,
        repos: &RepoContext,
        project: Arc<Project>,
        pom_blob: BlobId,
        repo_url: Arc<str>,
    ) {
        write_lock(&self.state.projects).put(
            self.project_key(coord, repos),
            CachedProject {
                project,
                pom_blob: Some(pom_blob),
                repo_url: Some(repo_url),
            },
        );
    }

    pub(crate) fn insert_missing_project(
        &self,
        coord: Coord,
        repos: &RepoContext,
        project: Arc<Project>,
    ) {
        write_lock(&self.state.projects).put(
            self.project_key(coord, repos),
            CachedProject {
                project,
                pom_blob: None,
                repo_url: None,
            },
        );
    }

    /// Lazily evicts expired entries under a single write-lock so observation
    /// and eviction can't race.
    pub(crate) fn is_parent_missing(&self, key: &MissingParentKey) -> bool {
        let mut guard = lock(&self.state.missing_parents);
        let Some(timestamp) = guard.get(key).copied() else {
            return false;
        };
        if timestamp.elapsed() >= MISSING_PARENT_TTL {
            guard.pop(key);
            false
        } else {
            true
        }
    }

    pub(crate) fn mark_parent_missing(&self, key: MissingParentKey) {
        let mut guard = lock(&self.state.missing_parents);
        guard.put(key, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::{MissingParentKey, RepoContext, ResolveContext, ResolveState};
    use std::sync::Arc;

    use rv_config::{Config, ResolvedPaths};

    use rv_maven_model::Project;
    use rv_maven_types::{BlobId, Coord};
    use rv_repo::Repository;
    use rv_store::Store;

    fn repo() -> Arc<str> {
        Arc::from("https://repo.example/maven2/")
    }

    fn make_test_ctx() -> ResolveContext {
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config =
            Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new());
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        ResolveContext::new(config, Vec::new(), store, platform, None)
    }

    /// `ctx` on another platform, sharing its state.
    fn on_aarch64(ctx: &ResolveContext) -> ResolveContext {
        ResolveContext::from_config_with_state(
            ctx.config.clone(),
            Arc::clone(&ctx.store),
            rv_lock::Platform::new("linux", "aarch64").unwrap(),
            None,
            ctx.state(),
        )
    }

    fn pk(group: &str, artifact: &str, version: &str) -> MissingParentKey {
        (
            Arc::from(group),
            Arc::from(artifact),
            Arc::from(version),
            RepoContext::default(),
        )
    }

    fn coord(artifact: &str, version: &str) -> Coord {
        Coord::parse(&format!("com.example:{artifact}:{version}")).unwrap()
    }

    /// A cached model keeps the POM pin a second backend uses. It is keyed by
    /// the version as written, since `1.0` and `1.0.0` order equal but name
    /// different POMs, and by platform, since profile activation bakes
    /// platform dependencies into it.
    #[test]
    fn project_cache_keys() {
        let ctx = make_test_ctx();
        let empty = RepoContext::default();
        let extra = RepoContext::from_repos(vec![Repository::new(
            None,
            "https://extra.example/maven2/",
            true,
            true,
        )]);
        let (short, long) = (coord("demo", "1.0"), coord("demo", "1.0.0"));
        assert_eq!(short, long);
        let project = Arc::new(Project::new("com.example", "demo", "1.0"));
        ctx.insert_project(
            short.clone(),
            &empty,
            Arc::clone(&project),
            BlobId::from_bytes(b"1.0"),
            repo(),
        );
        let cached = ctx.cached_project(&short, &empty).expect("cache hit");
        assert_eq!(
            (cached.project, cached.pom_blob),
            (project.clone(), Some(BlobId::from_bytes(b"1.0")))
        );
        assert!(ctx.cached_project(&long, &empty).is_none());
        assert!(ctx.cached_project(&short, &extra).is_none());
        assert!(on_aarch64(&ctx).cached_project(&short, &empty).is_none());
    }

    #[test]
    fn missing_parent_cache_keys() {
        let ctx = make_test_ctx();
        let other = on_aarch64(&ctx);
        let (v9, v7) = (
            pk("org.sonatype.oss", "oss-parent", "9"),
            pk("org.sonatype.oss", "oss-parent", "7"),
        );
        let v9_extra = (
            Arc::from("org.sonatype.oss"),
            Arc::from("oss-parent"),
            Arc::from("9"),
            RepoContext::from_repos(vec![Repository::new(
                None,
                "https://extra.example/maven2/",
                true,
                true,
            )]),
        );
        assert!(!other.is_parent_missing(&v9));
        ctx.mark_parent_missing(v9.clone());
        assert!(other.is_parent_missing(&v9));
        assert!(!ctx.is_parent_missing(&v7));
        assert!(!ctx.is_parent_missing(&v9_extra));
        assert!(Arc::ptr_eq(&ctx.state(), &other.state()));
    }

    #[test]
    fn modules_share_only_raw_parses_across_platforms() {
        let ctx = make_test_ctx();
        let other_platform = on_aarch64(&ctx);
        let module = ctx.for_module(ctx.config.clone());
        let empty = RepoContext::default();
        let coord = coord("demo", "1.0");
        let missing = pk("com.example", "missing", "1");
        let metadata = super::MetadataKey::new(
            Arc::from("https://example.test/"),
            Arc::from("com.example"),
            Arc::from("demo"),
        );
        module.insert_project(
            coord.clone(),
            &empty,
            Arc::new(Project::new("com.example", "demo", "1.0")),
            BlobId::from_bytes(b"pom"),
            repo(),
        );
        module.insert_metadata(metadata.clone(), rv_repo::Metadata::default());
        module.mark_parent_missing(missing.clone());

        for platform_ctx in [&ctx, &other_platform] {
            let sibling = platform_ctx.for_module(platform_ctx.config.clone());
            assert!(Arc::ptr_eq(
                &module.state.parsed_poms,
                &sibling.state.parsed_poms
            ));
            assert!(!Arc::ptr_eq(&module.state, &sibling.state));
            assert!(sibling.cached_project(&coord, &empty).is_none());
            assert!(sibling.cached_metadata(&metadata).is_none());
            assert!(!sibling.is_parent_missing(&missing));
        }
        assert!(!Arc::ptr_eq(
            &module.state.parsed_poms,
            &ResolveState::new().parsed_poms
        ));
    }
}
