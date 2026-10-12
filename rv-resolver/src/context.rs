//! Resolution context and state.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use lru::LruCache;

use rv_config::{BlobId, Config, Platform};
use rv_maven_model::Project;
use rv_repo::{Metadata, RepoClient, Repository};
use rv_store::Store;
use rv_version::Coord;

use crate::parsed_pom_cache::ParsedPomCache;

/// 10k entries covers the transitive set of any realistic project.
const MAX_METADATA_CACHE_SIZE: usize = 10_000;
/// Avoids re-hitting the same 404 on every transitive dep resolution.
const MISSING_PARENT_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MetadataKey {
    pub repo_url: Arc<str>,
    pub group_id: Arc<str>,
    pub artifact_id: Arc<str>,
    checksum_fail: bool,
}

impl MetadataKey {
    pub fn new(repo_url: Arc<str>, group_id: Arc<str>, artifact_id: Arc<str>) -> Self {
        Self {
            repo_url,
            group_id,
            artifact_id,
            checksum_fail: false,
        }
    }

    pub fn with_checksum_policy(mut self, policy: rv_config::ChecksumPolicy) -> Self {
        self.checksum_fail = policy == rv_config::ChecksumPolicy::Fail;
        self
    }
}

/// Triple of (group_id, artifact_id, version). `Arc<str>` to dedupe the
/// common upstream coordinate strings across all the parent-cache probes
/// that collide on them.
pub type MissingParentKey = (Arc<str>, Arc<str>, Arc<str>);

/// A parsed project plus the identity of the POM bytes it was parsed from.
///
/// The digest travels *inside* the cache entry rather than beside it: a cache
/// hit must be able to tell the caller which bytes produced this model, and a
/// caller that could not learn that would have to fall back to the store's
/// last-writer-wins coordinate index to pin the POM — the exact substitution
/// the pin exists to prevent.
#[derive(Clone, Debug)]
pub struct CachedProject {
    pub project: Project,
    pub pom_blob: BlobId,
}

/// Resolution caches. Module contexts get fresh metadata, project and
/// missing-parent caches while sharing parsed POMs across modules and platforms.
pub struct ResolveState {
    parsed_poms: Arc<ParsedPomCache>,
    metadata: RwLock<LruCache<MetadataKey, Arc<Metadata>>>,
    /// LRU-bounded; monorepos accumulate hundreds of MB of `Project` data.
    /// `Project` is `Clone`, so eviction is safe (a miss re-parses).
    ///
    /// Keyed by `(Coord, Platform)`, NOT `Coord` alone: a `Project` is built
    /// with the active-profile set of the resolve pass that fetched it, and
    /// profiles can activate on `os.name`/`family`/`arch` (and `os.*` system
    /// properties), so the resolved dependencies/management/repositories differ
    /// per target platform. Contexts sharing this state must not reuse another
    /// platform's effective project. Module contexts have separate states.
    projects: RwLock<LruCache<(Coord, Platform), CachedProject>>,
    /// `std::sync::Mutex` because every op is a single LRU `get`/`put` with
    /// no awaits, which lets the sync `ParentResolver` trait probe without
    /// bridging to async.
    missing_parents: Mutex<LruCache<MissingParentKey, Instant>>,
}

impl ResolveState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn with_parsed_poms(parsed_poms: Arc<ParsedPomCache>) -> Self {
        Self {
            parsed_poms,
            metadata: RwLock::new(new_lru()),
            projects: RwLock::new(new_lru()),
            missing_parents: Mutex::new(new_lru()),
        }
    }
}

fn new_lru<K: std::hash::Hash + Eq, V>() -> LruCache<K, V> {
    LruCache::new(
        NonZeroUsize::new(MAX_METADATA_CACHE_SIZE)
            .expect("MAX_METADATA_CACHE_SIZE validated at compile time"),
    )
}

impl Default for ResolveState {
    fn default() -> Self {
        Self::with_parsed_poms(Arc::new(ParsedPomCache::default()))
    }
}

#[derive(Clone)]
pub struct ResolveContext {
    pub config: Config,
    pub repos: Vec<Repository>,
    pub store: Arc<Store>,
    pub platform: Platform,
    pub client: Option<RepoClient>,
    state: Arc<ResolveState>,
}

impl ResolveContext {
    /// Test-facing constructor: builds a fresh `ResolveState` every call.
    /// Production code uses [`Self::from_config_with_state`]; module contexts
    /// share only parsed POMs from that state.
    pub fn new(
        config: Config,
        repos: Vec<Repository>,
        store: Arc<Store>,
        platform: Platform,
        client: Option<RepoClient>,
    ) -> Self {
        Self {
            config,
            repos,
            store,
            platform,
            client,
            state: Arc::new(ResolveState::default()),
        }
    }

    /// Reuses an existing `ResolveState`. Derived module contexts retain its
    /// parsed-POM cache and get fresh metadata, project and missing-parent caches.
    pub fn from_config_with_state(
        config: Config,
        store: Arc<Store>,
        platform: Platform,
        client: Option<RepoClient>,
        state: Arc<ResolveState>,
    ) -> Self {
        let repos = config.repositories().iter().map(Repository::from).collect();
        Self {
            config,
            repos,
            store,
            platform,
            client,
            state,
        }
    }

    pub fn state(&self) -> Arc<ResolveState> {
        Arc::clone(&self.state)
    }

    pub(crate) fn for_module(&self, config: Config) -> Self {
        Self {
            config,
            state: Arc::new(ResolveState::with_parsed_poms(Arc::clone(
                &self.state.parsed_poms,
            ))),
            ..self.clone()
        }
    }

    pub(crate) fn parsed_poms(&self) -> &ParsedPomCache {
        &self.state.parsed_poms
    }

    pub fn cached_metadata(&self, key: &MetadataKey) -> Option<Arc<Metadata>> {
        let guard = self.state.metadata.read().expect("metadata lock poisoned");
        guard.peek(key).cloned()
    }

    pub fn insert_metadata(&self, key: MetadataKey, metadata: Metadata) {
        let mut guard = self.state.metadata.write().expect("metadata lock poisoned");
        guard.put(key, Arc::new(metadata));
    }

    pub fn cached_project(&self, coord: &Coord) -> Option<CachedProject> {
        // `peek` (no LRU recency bump) lets reads share a read-lock, matching
        // the metadata cache's read-heavy concurrency tradeoff. The cache key
        // includes this context's target platform so concurrent per-platform
        // passes don't see each other's profile-activated `Project`.
        let key = (coord.clone(), self.platform.clone());
        let guard = self.state.projects.read().expect("projects lock poisoned");
        guard.peek(&key).cloned()
    }

    pub fn insert_project(&self, coord: Coord, project: Project, pom_blob: BlobId) {
        let key = (coord, self.platform.clone());
        let mut guard = self.state.projects.write().expect("projects lock poisoned");
        guard.put(key, CachedProject { project, pom_blob });
    }

    /// Lazily evicts expired entries under a single write-lock so observation
    /// and eviction can't race.
    pub fn is_parent_missing(&self, key: &MissingParentKey) -> bool {
        let mut guard = self
            .state
            .missing_parents
            .lock()
            .expect("missing_parents mutex poisoned");
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

    pub fn mark_parent_missing(&self, key: MissingParentKey) {
        let mut guard = self
            .state
            .missing_parents
            .lock()
            .expect("missing_parents mutex poisoned");
        guard.put(key, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::{MissingParentKey, ResolveContext, ResolveState};
    use std::sync::Arc;

    use rv_config::{BlobId, Config, ResolvedPaths};
    use rv_maven_model::{DependencyManagement, Project};
    use rv_store::Store;
    use rv_version::Coord;

    fn make_test_ctx() -> ResolveContext {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        ResolveContext::new(config, Vec::new(), store, platform, None)
    }

    fn demo_project() -> Project {
        Project {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0".to_string(),
            packaging: "jar".to_string(),
            properties: Default::default(),
            dependency_management: DependencyManagement::default(),
            dependencies: Vec::new(),
            repositories: Vec::new(),
            profiles: Vec::new(),
            modules: Vec::new(),
            relocation: None,
        }
    }

    #[tokio::test]
    async fn caches_project_roundtrip() {
        let ctx = make_test_ctx();
        let coord = Coord::parse("com.example:demo:1.0").unwrap();
        let project = demo_project();
        let pom_blob = BlobId::from_bytes(b"<project/>");
        ctx.insert_project(coord.clone(), project.clone(), pom_blob.clone());
        let cached = ctx.cached_project(&coord).expect("cache hit");
        assert_eq!(cached.project, project);
        // The POM identity round-trips with the model: a cache hit is what a
        // second backend uses to pin the coordinate's POM.
        assert_eq!(cached.pom_blob, pom_blob);
    }

    /// Two contexts that SHARE one `ResolveState` but target different
    /// platforms (exactly the multi-platform `rv sync` shape) must not see
    /// each other's cached, profile-activated `Project` for the same
    /// coordinate. Before the `(Coord, Platform)` key this leaked across
    /// platforms and silently corrupted per-platform lockfile sections.
    #[tokio::test]
    async fn project_cache_is_keyed_by_platform() {
        let ctx_x86 = make_test_ctx();
        let shared_state = ctx_x86.state();
        let aarch64 = rv_config::Platform::new("linux", "aarch64").unwrap();
        let ctx_arm = ResolveContext::from_config_with_state(
            ctx_x86.config.clone(),
            ctx_x86.store.clone(),
            aarch64,
            None,
            shared_state,
        );

        let coord = Coord::parse("com.example:demo:1.0").unwrap();
        let project = demo_project();
        ctx_x86.insert_project(
            coord.clone(),
            project.clone(),
            BlobId::from_bytes(b"<project/>"),
        );

        // Same platform as the writer: cache hit.
        assert_eq!(
            ctx_x86.cached_project(&coord).map(|cached| cached.project),
            Some(project)
        );
        // Different platform sharing the same cache: miss, no cross-contamination.
        assert!(ctx_arm.cached_project(&coord).is_none());
    }

    #[test]
    fn modules_share_only_raw_parses_across_platforms() {
        let ctx = make_test_ctx();
        let other_platform = ResolveContext::from_config_with_state(
            ctx.config.clone(),
            Arc::clone(&ctx.store),
            rv_config::Platform::new("linux", "aarch64").unwrap(),
            None,
            ctx.state(),
        );
        let module = ctx.for_module(ctx.config.clone());
        let coord = Coord::parse("com.example:demo:1.0").unwrap();
        let missing = pk("com.example", "missing", "1");
        let metadata = super::MetadataKey::new(
            Arc::from("https://example.test/"),
            Arc::from("com.example"),
            Arc::from("demo"),
        );
        module.insert_project(coord.clone(), demo_project(), BlobId::from_bytes(b"pom"));
        module.insert_metadata(metadata.clone(), rv_repo::Metadata::default());
        module.mark_parent_missing(missing.clone());

        for platform_ctx in [&ctx, &other_platform] {
            let sibling = platform_ctx.for_module(platform_ctx.config.clone());
            assert!(Arc::ptr_eq(
                &module.state.parsed_poms,
                &sibling.state.parsed_poms
            ));
            assert!(!Arc::ptr_eq(&module.state, &sibling.state));
            assert!(sibling.cached_project(&coord).is_none());
            assert!(sibling.cached_metadata(&metadata).is_none());
            assert!(!sibling.is_parent_missing(&missing));
        }
        assert!(!Arc::ptr_eq(
            &module.state.parsed_poms,
            &ResolveState::new().parsed_poms
        ));
    }

    fn pk(group: &str, artifact: &str, version: &str) -> MissingParentKey {
        (Arc::from(group), Arc::from(artifact), Arc::from(version))
    }

    #[test]
    fn caches_missing_parent_roundtrip() {
        let ctx = make_test_ctx();
        let key = pk("org.sonatype.oss", "oss-parent", "9");
        assert!(!ctx.is_parent_missing(&key));
        ctx.mark_parent_missing(key.clone());
        assert!(ctx.is_parent_missing(&key));
    }

    #[test]
    fn missing_parent_cache_is_unique_per_version() {
        let ctx = make_test_ctx();
        let key_v9 = pk("org.sonatype.oss", "oss-parent", "9");
        let key_v7 = pk("org.sonatype.oss", "oss-parent", "7");
        ctx.mark_parent_missing(key_v9.clone());
        assert!(ctx.is_parent_missing(&key_v9));
        assert!(!ctx.is_parent_missing(&key_v7));
    }

    #[test]
    fn missing_parents_cache_evicts_oldest_when_full() {
        let ctx = make_test_ctx();
        let make_key = |id: usize| pk("com.example", "missing", &format!("{id}"));
        let capacity = super::MAX_METADATA_CACHE_SIZE;
        let overflow = 10;
        for id in 0..capacity + overflow {
            ctx.mark_parent_missing(make_key(id));
        }
        for id in 0..overflow {
            assert!(!ctx.is_parent_missing(&make_key(id)), "id {id} evicted");
        }
        for id in overflow..capacity + overflow {
            assert!(ctx.is_parent_missing(&make_key(id)), "id {id} retained");
        }
    }

    #[tokio::test]
    async fn shared_state_is_visible_across_contexts() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform_a = rv_config::Platform::new("linux", "x86_64").unwrap();
        let platform_b = rv_config::Platform::new("macos", "aarch64").unwrap();

        let shared = ResolveState::new();
        let ctx_a = ResolveContext::from_config_with_state(
            config.clone(),
            Arc::clone(&store),
            platform_a,
            None,
            Arc::clone(&shared),
        );
        let ctx_b = ResolveContext::from_config_with_state(
            config,
            store,
            platform_b,
            None,
            Arc::clone(&shared),
        );

        // The platform-INDEPENDENT caches (metadata, missing-parents) are
        // shared across per-platform contexts so warm entries survive the
        // platform loop. (The Project cache is deliberately platform-keyed
        // because profile activation bakes platform-specific dependencies into
        // it; see `project_cache_is_keyed_by_platform`.)
        let parent = pk("com.example", "demo-parent", "1.0");
        assert!(!ctx_b.is_parent_missing(&parent));
        ctx_a.mark_parent_missing(parent.clone());
        assert!(
            ctx_b.is_parent_missing(&parent),
            "platform-independent missing-parent cache must be shared across platforms"
        );
        assert!(Arc::ptr_eq(&ctx_a.state(), &ctx_b.state()));
    }

    #[tokio::test]
    async fn projects_cache_evicts_oldest_when_full() {
        let ctx = make_test_ctx();
        let make_project = |id: usize| Project {
            group_id: "com.example".to_string(),
            artifact_id: format!("artifact-{id}"),
            version: "1.0".to_string(),
            packaging: "jar".to_string(),
            properties: Default::default(),
            dependency_management: DependencyManagement::default(),
            dependencies: Vec::new(),
            repositories: Vec::new(),
            profiles: Vec::new(),
            modules: Vec::new(),
            relocation: None,
        };
        let make_coord = |id: usize| {
            Coord::parse(&format!("com.example:artifact-{id}:1.0")).expect("coord parses")
        };

        let capacity = super::MAX_METADATA_CACHE_SIZE;
        let overflow = 10;
        for id in 0..capacity + overflow {
            ctx.insert_project(
                make_coord(id),
                make_project(id),
                BlobId::from_bytes(format!("<project>{id}</project>").as_bytes()),
            );
        }
        for id in 0..overflow {
            assert!(
                ctx.cached_project(&make_coord(id)).is_none(),
                "id {id} evicted"
            );
        }
        for id in overflow..capacity + overflow {
            assert!(
                ctx.cached_project(&make_coord(id)).is_some(),
                "id {id} retained"
            );
        }
    }
}
