//! [`RepoClient`]: the one entry point for repository reads. Requests go
//! through [`crate::routing`] for the endpoint and credential and through
//! [`crate::transport`] for the HTTP client.

mod artifacts;
mod models;
mod requests;
/// The path below a repository root of the file `key` names, by its file
/// version.
pub(super) fn file_path(key: &rv_maven_types::ArtifactCoord) -> String {
    let file = key.version();
    rv_maven_types::layout::artifact_path(key, &models::resolved_directory(file), file)
}

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rv_config::Config;
use rv_lock::Lockfile;
use rv_maven_types::Digest;

use crate::error::{RepoError, Result};
use crate::fetch::{FetchConfig, FetchProgress};
use crate::metadata::SnapshotCandidate;
use crate::policy::RepositoryPolicy;
use crate::repository::Repository;
use crate::routing::{RouteInfo, Router};
use crate::transport::ClientSet;
use rv_store::metadata_cache::MetadataCache;

use artifacts::{ArtifactFetches, ArtifactPrefetches};
pub use artifacts::{FetchArtifact, Fetched};
use models::{AbsentPaths, HeldPoms, MetadataFlights, MetadataMemo, PomInflight, PomMemo};
pub use models::{PomArrival, announcing_poms};
use requests::Sha256Gaps;

/// The client for every repository read: metadata, POMs, checksum sidecars
/// and artifacts.
///
/// It applies the configured mirrors, proxies and credentials, retries
/// transient failures, refuses redirects and addresses the redirect policy
/// does not allow, and caches metadata and POMs in `metadata.db`. Clones
/// share the HTTP clients, the cache and the in-flight POM downloads.
#[derive(Clone)]
pub struct RepoClient {
    transport: ClientSet,
    policy: RepositoryPolicy,
    router: Router,
    fetch: FetchConfig,
    progress: Option<Arc<dyn FetchProgress>>,
    cache: MetadataCache,
    offline: bool,
    /// Under `sync --update`, the time the run started: cached metadata,
    /// misses and non-unique SNAPSHOT POMs written before it are
    /// fetched again.
    refresh_before: Option<i64>,
    require_checksums: bool,
    /// The pin of each file raeva.lock pins, by path, and the origins it
    /// records as serving the file.
    lock_pins: Arc<HashMap<String, (Digest, std::collections::BTreeSet<String>)>>,
    /// The companion POMs raeva.lock records as missing, by path, which an
    /// offline run takes as missing rather than as not downloaded.
    lock_missing_poms: Arc<std::collections::HashSet<String>>,
    /// The snapshot builds raeva.lock pins, by `-SNAPSHOT` GAV: each file's
    /// build with its companion POM's.
    lock_snapshots:
        Arc<HashMap<rv_maven_types::Gav, std::collections::BTreeSet<rv_lock::PinnedSnapshot>>>,
    /// Whether a pinned snapshot build stands online too, see
    /// [`RepoClient::with_pinned_snapshots`].
    pinned_snapshots: bool,
    /// How raeva.lock spells this project's repository origins.
    origins: Arc<rv_lock::LockOrigins>,
    /// POM downloads in progress, so concurrent callers share one download.
    pom_inflight: PomInflight,
    /// POMs read before, kept in memory.
    pom_memo: Arc<std::sync::Mutex<PomMemo>>,
    /// Metadata read before, kept in memory.
    metadata_memo: MetadataMemo,
    /// Remote metadata and POM 404s shared by this client's clones.
    /// Misses stay in memory and include the repository context and attempted endpoint.
    absent_paths: AbsentPaths,
    /// Remote metadata paths being fetched.
    metadata_flights: MetadataFlights,
    /// Origins that have answered 404 for a `.sha256` sidecar.
    sha256_gaps: Sha256Gaps,
    /// Prefetched POMs no caller has read yet.
    held_poms: Arc<std::sync::Mutex<HeldPoms>>,
    /// Artifacts downloaded ahead of their fetch.
    artifact_prefetches: ArtifactPrefetches,
    /// Artifacts fetched into the store.
    artifact_fetches: ArtifactFetches,
    /// What prefetches log, held for the read that uses what they fetched.
    prefetch_holds: Arc<std::sync::OnceLock<rv_maven_model::held::Holds>>,
}

/// The file version a `-SNAPSHOT` resolves to, from
/// [`RepoClient::resolve_snapshot_version`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SnapshotResolution {
    /// The version to put in the file name: a timestamped version such as
    /// `1.0-20240101.010101-7`, or the `-SNAPSHOT` version itself when the
    /// metadata names no build or a local repository has no metadata.
    pub version: String,
    /// Whether resolution read metadata, rather than using a local layout
    /// whose metadata file was absent.
    pub metadata_served: bool,
    /// Metadata comparison value (`updated` or legacy `lastUpdated`).
    pub updated: Option<String>,
    /// What named `version`.
    pub candidate: SnapshotCandidate,
}

impl SnapshotResolution {
    /// `version` itself, read without metadata.
    pub fn base(version: String) -> Self {
        Self {
            version,
            metadata_served: false,
            updated: None,
            candidate: crate::SnapshotCandidate::Absent,
        }
    }
}

impl RepoClient {
    /// A client for `config`: its network settings, repositories, mirrors,
    /// proxies, credentials and security settings, with the metadata cache
    /// at `config.paths.metadata_db_path()`. Online, checksums required and
    /// no progress reporter until the `with_*` methods say otherwise.
    ///
    /// # Errors
    ///
    /// [`RepoError::Config`] or [`RepoError::AuthSetup`] for a proxy or
    /// credential setting raeva cannot use, and [`RepoError::Cache`] when the
    /// metadata cache cannot be opened. HTTP clients are built on the first
    /// request.
    pub async fn new(config: &Config) -> Result<Self> {
        let fetch = FetchConfig {
            retries: config.network.retries,
            timeout: Duration::from_secs(config.network.timeout),
            max_artifact_size: config.network.max_artifact_size,
            low_speed_limit: config.network.low_speed_limit,
            low_speed_time: Duration::from_secs(config.network.low_speed_time),
            cooldowns: Arc::default(),
            progress: None,
        };
        let transport = ClientSet::build(config)?;
        let cache = MetadataCache::new(&config.paths.metadata_db_path())?;
        let router = Router::from_config(config)?;
        Ok(Self::from_parts(transport, router, cache, fetch, config))
    }

    fn from_parts(
        transport: ClientSet,
        router: Router,
        cache: MetadataCache,
        fetch: FetchConfig,
        config: &Config,
    ) -> Self {
        Self {
            policy: RepositoryPolicy::new(
                config,
                transport.grants(),
                router.auth_store().named_origins(),
            ),
            transport,
            router,
            fetch,
            progress: None,
            cache,
            offline: false,
            refresh_before: None,
            require_checksums: true,
            lock_pins: Arc::default(),
            lock_missing_poms: Arc::default(),
            lock_snapshots: Arc::default(),
            pinned_snapshots: false,
            origins: Arc::new(rv_lock::LockOrigins::for_root(&config.project_root)),
            pom_inflight: PomInflight::default(),
            pom_memo: Arc::default(),
            metadata_memo: MetadataMemo::default(),
            absent_paths: AbsentPaths::default(),
            metadata_flights: MetadataFlights::default(),
            sha256_gaps: Sha256Gaps::default(),
            held_poms: Arc::default(),
            artifact_prefetches: ArtifactPrefetches::default(),
            artifact_fetches: ArtifactFetches::default(),
            prefetch_holds: Arc::default(),
        }
    }

    /// Run `prefetch`, holding what it logs. A prefetch that keeps a file
    /// keeps what it logged with it ([`requests::DeferredWarnings::after_logged`]);
    /// the rest is dropped, as the read that uses the file logs anew.
    async fn prefetching<T>(&self, prefetch: impl std::future::Future<Output = T>) -> T {
        let holds = (self.prefetch_holds).get_or_init(rv_maven_model::held::Holds::default);
        let (output, _dropped) = holds.hold(prefetch).await;
        output
    }

    /// A client over the given clients and routing, with default fetch
    /// settings and checksums required.
    #[cfg(test)]
    pub(crate) fn for_test(transport: ClientSet, router: Router, cache: MetadataCache) -> Self {
        Self::from_parts(
            transport,
            router,
            cache,
            FetchConfig::default(),
            &Config::for_testing(".".into(), rv_config::ResolvedPaths::for_testing().unwrap()),
        )
    }

    /// The policy that admits POM-declared repositories and decides what
    /// each may reach.
    pub fn policy(&self) -> &RepositoryPolicy {
        &self.policy
    }

    /// Whether the origin (scheme, host and port) of `url` is currently
    /// exempt from the address screen, i.e. may resolve off the public
    /// internet on a direct connection. An unparsable URL is not.
    #[cfg(any(test, feature = "testing"))]
    pub fn trusts_origin(&self, url: &str) -> bool {
        url::Url::parse(url).is_ok_and(|url| self.transport.trusts_origin(&url))
    }

    /// Reports the progress of every download, and every retry, to `progress`.
    pub fn with_progress(mut self, progress: Arc<dyn FetchProgress>) -> Self {
        self.fetch.progress = Some(Arc::clone(&progress));
        self.progress = Some(progress);
        self
    }

    /// With `offline` true, refuses every request to a remote repository
    /// with [`RepoError::OfflineNotCached`] and serves cached metadata and
    /// POMs even when their update policy says they are stale. `file:`
    /// repositories are still read.
    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Whether [`Self::with_offline`] refuses remote requests.
    pub fn is_offline(&self) -> bool {
        self.offline
    }

    /// With `update` true, as `mvn -U` does, fetches again the repository
    /// metadata, misses and non-unique `-SNAPSHOT` POMs the
    /// metadata cache holds from before this call, whatever their update
    /// policy says. Offline, the cache is still used.
    pub fn with_update(mut self, update: bool) -> Self {
        self.refresh_before = update.then(rv_store::metadata_cache::now_epoch_seconds);
        self
    }

    /// Whether mutable files are fetched again: [`Self::with_update`] asked
    /// for it and the client is not offline.
    pub fn updates(&self) -> bool {
        self.refresh_before.is_some() && !self.offline
    }

    /// Opt out of requiring a server-published checksum sidecar. Off by default;
    /// callers who set this true accept the risk that a hostile or misconfigured
    /// mirror could serve unverified bytes.
    pub fn with_allow_missing_checksums(mut self, allow: bool) -> Self {
        self.require_checksums = !allow;
        self
    }

    /// Accept a file without a checksum sidecar when it matches the SHA-256
    /// `lock` pins for it: the pin verifies it. Other bytes for a release
    /// file or timestamped snapshot build are refused before anything stores
    /// them, unless the run updates the lock; a non-unique `-SNAPSHOT` file
    /// that does not match is treated as if `lock` did not pin it. Offline,
    /// a `-SNAPSHOT` in a remote repository resolves to a build `lock` pins
    /// whose POM the cache holds for that repository.
    pub fn with_lock_pins(mut self, lock: &Lockfile) -> Self {
        self.lock_snapshots = Arc::new(lock.pinned_snapshots());
        self.lock_missing_poms = Arc::new(lock.missing_pom_paths());
        self.lock_pins = Arc::new(lock.pinned_paths());
        self
    }

    /// With `pinned` true, a `-SNAPSHOT` resolves to the build the lock
    /// [`Self::with_lock_pins`] gave pins for it, from the repository the
    /// lock records, without reading newer metadata, as it does offline. A
    /// frozen check restores the locked builds; only `sync --update` and an
    /// expired update policy in a plain sync look for newer ones.
    pub fn with_pinned_snapshots(mut self, pinned: bool) -> Self {
        self.pinned_snapshots = pinned;
        self
    }

    /// The digest raeva.lock pins for the file at `path`.
    fn lock_pin(&self, path: &str) -> Option<&Digest> {
        self.lock_pins.get(path).map(|(pin, _)| pin)
    }

    /// [`Self::lock_pin`] for a release file or timestamped snapshot build.
    /// Only non-unique snapshot filenames can be redeployed and are left
    /// out, as [`rv_lock::Lockfile::repinned_releases`] leaves them out.
    fn release_file_pin(&self, path: &str) -> Option<&Digest> {
        let snapshot = rv_maven_types::layout::is_mutable_snapshot_path(path);
        self.lock_pin(path).filter(|_| !snapshot)
    }

    /// [`Self::release_file_pin`], which other bytes must not replace unless
    /// [`Self::with_update`] asked to lock new bytes, online or from a local
    /// repository.
    fn release_lock_pin(&self, path: &str) -> Option<&Digest> {
        self.release_file_pin(path)
            .filter(|_| self.refresh_before.is_none())
    }

    /// The SHA-256 raeva.lock pins for the file `key` names, by its file
    /// version.
    pub fn lock_pin_for(
        &self,
        key: &rv_maven_types::ArtifactCoord,
    ) -> Option<&rv_maven_types::Sha256> {
        self.lock_pin(&file_path(key)).and_then(Digest::as_sha256)
    }

    /// Where requests for `repo` go: the mirror that serves it, if any, and
    /// whether the default credential is withheld from that endpoint.
    pub fn route(&self, repo: &Repository) -> RouteInfo {
        self.router.route(repo).info()
    }

    /// [`RepoClient::route`]'s endpoint: the repository that serves a request
    /// after mirror substitution. Maven records its ID in
    /// `_remote.repositories`.
    pub fn effective_repository(&self, repo: &Repository) -> Repository {
        self.router.route(repo).endpoint
    }
}

/// Validate coordinate components for path-traversal / SSRF safety before
/// they are incorporated into any URL path, with the rules of
/// [`crate::artifact::ArtifactRequest::validate`].
fn validate_coord_components(
    group_id: &str,
    artifact_id: &str,
    version: Option<&str>,
) -> Result<()> {
    use rv_maven_types::CoordinateField;
    [
        (CoordinateField::Group, group_id),
        (CoordinateField::Artifact, artifact_id),
    ]
    .into_iter()
    .chain(version.map(|version| (CoordinateField::Version, version)))
    .try_for_each(|(field, value)| rv_maven_types::validate_coordinate_component(field, value))
    .map_err(|err| RepoError::InvalidCoord(err.to_string()))
}
