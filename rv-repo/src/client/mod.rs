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

/// The path of `req` as Maven's layout names it for the remote repository
/// filters: a timestamped snapshot's file in its base version's directory.
pub(super) fn filter_path(req: &crate::ArtifactRequest) -> String {
    req.to_path_with_versions(&models::resolved_directory(&req.version), &req.version)
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
use rv_store::metadata_cache::{MetadataCache, RowsDue, SnapshotCheck};

use artifacts::{ArtifactFetches, ArtifactPrefetches};
pub use artifacts::{FetchArtifact, Fetched};
use models::{AbsentPaths, HeldPoms, MetadataFlights, MetadataMemo, PomInflight, PomMemo};
pub use models::{PomArrival, announcing_poms};
use requests::{LateChecks, LateFamily, SidecarHints};

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
    freshness: Freshness,
    require_checksums: bool,
    /// Whether a seed from the store leaves a cached POM that holds other
    /// bytes than the pin, as a check before a resolution must.
    keep_cached_poms: bool,
    /// The Maven line resolution follows, which decides what snapshot
    /// metadata counts as valid.
    maven_mode: rv_maven_types::MavenMode,
    /// The pin of each file raeva.lock pins, by path, and the origins it
    /// records as serving the file.
    lock_pins: Arc<HashMap<String, (Digest, std::collections::BTreeSet<String>)>>,
    /// The companion POMs raeva.lock records as missing, by path, which an
    /// offline run takes as missing rather than as not downloaded.
    lock_missing_poms: Arc<std::collections::HashSet<String>>,
    /// The files raeva.lock marks as accepted without a checksum file, by
    /// path, whose checksum file a download still asks for although the
    /// pin checks the bytes, so one published since clears the marker.
    lock_unverified: Arc<std::collections::HashSet<String>>,
    /// The snapshot builds raeva.lock pins, by `-SNAPSHOT` GAV: each file's
    /// build with its companion POM's.
    lock_snapshots:
        Arc<HashMap<rv_maven_types::Gav, std::collections::BTreeSet<rv_lock::PinnedSnapshot>>>,
    /// The build of each SNAPSHOT build extension raeva.lock pins, by
    /// platform, module path and `-SNAPSHOT` GAV.
    lock_extensions: Arc<HashMap<(rv_lock::Platform, String, rv_maven_types::Gav), String>>,
    /// How raeva.lock spells this project's repository origins.
    origins: Arc<rv_lock::LockOrigins>,
    /// POM downloads in progress, so concurrent callers share one download.
    pom_inflight: PomInflight,
    /// POMs read before, kept in memory.
    pom_memo: Arc<std::sync::Mutex<PomMemo>>,
    /// When the cached rows of SNAPSHOT versions this client took fall due.
    snapshot_rows: Arc<std::sync::Mutex<RowsDue>>,
    /// Metadata read before, kept in memory.
    metadata_memo: MetadataMemo,
    /// Remote metadata and POM 404s shared by this client's clones.
    /// Misses stay in memory and include the repository context and attempted endpoint.
    absent_paths: AbsentPaths,
    /// Remote metadata paths being fetched.
    metadata_flights: MetadataFlights,
    /// Where sidecars are likely missing, from the answers so far.
    sidecar_hints: SidecarHints,
    /// Prefetched POMs no caller has read yet.
    held_poms: Arc<std::sync::Mutex<HeldPoms>>,
    /// The paths of the non-unique `-SNAPSHOT` POMs reads used as fetched
    /// in this run; see [`Self::renews`].
    fetched_snapshots: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// The `.sha256` checks of POMs read without waiting for them, when this
    /// client reads so; see [`Self::checking_sha256_late`].
    late_checks: Option<Arc<LateChecks>>,
    /// The late checks of every clone, told when one of them moves.
    late_family: LateFamily,
    /// Artifacts downloaded ahead of their fetch.
    artifact_prefetches: ArtifactPrefetches,
    /// Artifacts fetched into the store.
    artifact_fetches: ArtifactFetches,
    /// How each file this client admitted was checked.
    admissions: artifacts::Admissions,
    /// What prefetches log, held for the read that uses what they fetched.
    prefetch_holds: Arc<std::sync::OnceLock<rv_maven_model::held::Holds>>,
    /// Maven's remote repository filters, which keep a request from a
    /// repository their rules say does not serve it.
    filters: Arc<rv_config::RepositoryFilters>,
}

/// How a [`RepoClient`] treats what the metadata cache holds and what
/// raeva.lock pins ([`RepoClient::with_lock_pins`]). Offline or not, and
/// whether checksums are required, are set apart: every combination with
/// them holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Cached metadata, POMs and misses stand until their update policy
    /// expires, a `-SNAPSHOT` resolves through metadata, and a pinned
    /// release file must keep its pinned bytes.
    Policy,
    /// As [`Freshness::Policy`], but a `-SNAPSHOT` resolves to the build
    /// the lock pins for it, from the repository the lock records, without
    /// reading newer metadata, as it does offline. A frozen check and a
    /// restore keep the locked builds.
    Locked,
    /// As `mvn -U` does, fetch again the repository metadata, misses and
    /// non-unique `-SNAPSHOT` POMs the cache holds unless this process wrote
    /// them at or after `since`, whatever their update policy says, and
    /// accept other bytes than the pinned ones for a release file. Offline, the cache is
    /// still used and nothing is fetched again, but pins may still change
    /// through a local repository.
    Update {
        /// When the run started.
        since: std::time::Instant,
    },
}

impl Freshness {
    /// [`Freshness::Update`] since now.
    #[cfg(test)]
    pub(crate) fn update_from_now() -> Self {
        Freshness::Update {
            since: std::time::Instant::now(),
        }
    }
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
            refusers: Arc::default(),
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
            freshness: Freshness::Policy,
            require_checksums: true,
            keep_cached_poms: false,
            maven_mode: config.lock.maven.mode,
            lock_pins: Arc::default(),
            lock_missing_poms: Arc::default(),
            lock_unverified: Arc::default(),
            lock_snapshots: Arc::default(),
            lock_extensions: Arc::default(),
            origins: Arc::new(rv_lock::LockOrigins::for_root(&config.project_root)),
            pom_inflight: PomInflight::default(),
            pom_memo: Arc::default(),
            snapshot_rows: Arc::default(),
            metadata_memo: MetadataMemo::default(),
            absent_paths: AbsentPaths::default(),
            metadata_flights: MetadataFlights::default(),
            sidecar_hints: SidecarHints::default(),
            held_poms: Arc::default(),
            fetched_snapshots: Arc::default(),
            late_checks: None,
            late_family: LateFamily::default(),
            artifact_prefetches: ArtifactPrefetches::default(),
            artifact_fetches: ArtifactFetches::default(),
            admissions: artifacts::Admissions::default(),
            prefetch_holds: Arc::default(),
            filters: Arc::clone(config.repository_filters()),
        }
    }

    /// This client for the platform of `config`, a [`Config::for_platforms`]
    /// of one platform of the configuration it was made for: with the
    /// repository filters and the Maven 3.10 credential scope a build there
    /// reads, which its `.mvn/maven.config` options can change. Clones
    /// share what they cache.
    ///
    /// [`Config::for_platforms`]: rv_config::Config::for_platforms
    pub fn for_platform(&self, config: &rv_config::Config) -> Self {
        let mut client = self.clone();
        client.filters = Arc::clone(config.repository_filters());
        client.router = client.router.with_credential_scope_of(config);
        client
    }

    /// Refuse a request for `path`, a file of `group_id`, from `route` when
    /// the remote repository filters keep it from the repository that would
    /// receive it, as a miss that no request and no cache answered.
    pub(super) fn ensure_filters_admit(
        &self,
        route: &crate::routing::Route<'_>,
        group_id: &str,
        path: &str,
    ) -> Result<()> {
        let endpoint = &route.endpoint;
        let url = endpoint.declared_url();
        match (self.filters).rejects(endpoint.id.as_deref(), url, group_id, path) {
            None => Ok(()),
            Some(reason) => {
                tracing::debug!(path, reason, "remote repository filter");
                Err(RepoError::NotFound(crate::Missing::filtered(format!(
                    "{path} ({reason})"
                ))))
            }
        }
    }

    /// Whether the remote repository filters let the repository that
    /// receives `repo`'s requests serve `key`.
    pub(crate) fn filters_admit(
        &self,
        repo: &Repository,
        key: &rv_maven_types::ArtifactCoord,
    ) -> bool {
        let route = self.router.route(repo);
        (self.ensure_filters_admit(&route, key.gav.group.as_str(), &file_path(key))).is_ok()
    }

    /// Whether some remote repository filter is enabled.
    pub(crate) fn filters_active(&self) -> bool {
        self.filters.is_active()
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

    /// This client, reading a POM whose `.sha1` has matched its bytes while
    /// its `.sha256` is still being asked for without waiting for that, when
    /// the two were asked for together: once the repository has answered 404
    /// for another `.sha256`, unless the POM's release has served one. Such a POM is
    /// written to the metadata cache, and the warnings for it are logged,
    /// only once its `.sha256` has been checked, and
    /// [`Self::settle_checksums`] fails if that check fails: it must be
    /// awaited before anything relies on what was read. At a CDN a missing
    /// `.sha256` can take ten times as long to answer as the POM, and
    /// resolution reads a chain of POMs one after another.
    #[must_use]
    pub fn checking_sha256_late(mut self) -> Self {
        let checks = Arc::default();
        self.late_family.join(&checks);
        self.late_checks = Some(checks);
        self
    }

    /// Wait for the `.sha256` checks [`Self::checking_sha256_late`] left
    /// running, all of them, also those of POMs only prefetched, then log the
    /// warnings of those that passed. A POM is written to the metadata cache
    /// as soon as its check passes. A settlement that is cancelled leaves
    /// the checks it had not finished to the next one.
    ///
    /// # Errors
    ///
    /// The error the first failed check, in the order of the reads, would
    /// have failed its read with, such as [`RepoError::ChecksumMismatch`] for
    /// a `.sha256` that holds another digest; each later settlement fails
    /// again. The POM is not kept, so a client that waits for its checksum
    /// files fails its read again.
    pub async fn settle_checksums(&self) -> Result<()> {
        let Some(checks) = &self.late_checks else {
            return Ok(());
        };
        checks
            .settle()
            .await
            .map_or(Ok(()), |err| Err(requests::unshared(err)))
    }

    /// Wait for the `.sha256` checks of the POMs read so far, as
    /// [`Self::settle_checksums`] does, but log no warnings yet: for a write
    /// that must not outlast a POM whose check fails, such as a store row
    /// for a jar such a POM names.
    ///
    /// # Errors
    ///
    /// Those of [`Self::settle_checksums`].
    pub async fn checked_so_far(&self) -> Result<()> {
        let Some(checks) = &self.late_checks else {
            return Ok(());
        };
        (checks.settle_relied_on().await).map_or(Ok(()), |err| Err(requests::unshared(err)))
    }

    /// Have `note` called whenever a `.sha256` check left running moves,
    /// with how long its request may then be quiet: as long as the wait
    /// before a retry. Once now, with the longest such wait still running.
    /// For a watchdog that waits for [`Self::settle_checksums`].
    pub fn report_late_checks(&self, note: impl Fn(std::time::Duration) + Send + Sync + 'static) {
        if let Some(checks) = &self.late_checks {
            checks.report_to(Arc::new(note));
        }
    }

    /// Whether [`Self::settle_checksums`] has failed.
    pub fn late_check_failed(&self) -> bool {
        (self.late_checks.as_ref()).is_some_and(|checks| checks.failed())
    }

    /// Whether [`Self::with_offline`] refuses remote requests.
    pub fn is_offline(&self) -> bool {
        self.offline
    }

    /// How cached metadata, POMs and misses, the pinned SNAPSHOT builds and
    /// the lock's pins stand, see [`Freshness`].
    pub fn with_freshness(mut self, freshness: Freshness) -> Self {
        self.freshness = freshness;
        self
    }

    /// Under [`Freshness::Update`], the time before which cached metadata,
    /// misses and non-unique SNAPSHOT POMs are fetched again.
    fn refresh_before(&self) -> Option<std::time::Instant> {
        match self.freshness {
            Freshness::Update { since } => Some(since),
            Freshness::Policy | Freshness::Locked => None,
        }
    }

    /// Whether mutable files are fetched again: [`Freshness::Update`] and
    /// not offline.
    pub fn updates(&self) -> bool {
        self.refresh_before().is_some() && !self.offline
    }

    /// Whether the stored file of `key` is fetched again rather than
    /// reused: a non-unique `-SNAPSHOT` under [`Self::updates`], or, unless
    /// the lock's builds are kept, one whose POM a read this run used as
    /// fetched with other bytes than raeva.lock pins, so the file is of the
    /// build the POM is.
    pub fn renews(&self, key: &rv_maven_types::ArtifactCoord) -> bool {
        let fetched = || {
            let pom = filter_path(&crate::ArtifactRequest::from(key).pom());
            (self.fetched_snapshots.lock())
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&pom)
        };
        rv_maven_types::resolves_through_snapshot_metadata(key.version())
            && (self.updates() || (!self.pinned_snapshots() && fetched()))
    }

    /// Whether a `-SNAPSHOT` resolves to the build the lock pins, online too:
    /// [`Freshness::Locked`].
    fn pinned_snapshots(&self) -> bool {
        self.freshness == Freshness::Locked
    }

    /// Opt out of requiring a server-published checksum sidecar. Off by default;
    /// callers who set this true accept the risk that a hostile or misconfigured
    /// mirror could serve unverified bytes.
    pub fn with_allow_missing_checksums(mut self, allow: bool) -> Self {
        self.require_checksums = !allow;
        self
    }

    /// This client, seeding from the store only POMs the cache lacks: a
    /// cached copy with other bytes stays, so the seed cannot change what a
    /// check that resolves next reads for it.
    #[must_use]
    pub fn keeping_cached_poms(mut self) -> Self {
        self.keep_cached_poms = true;
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
        let mut extensions = HashMap::new();
        for entry in &lock.platforms {
            for module in &entry.modules {
                for jar in &module.extensions {
                    let version = jar.gav.version();
                    if let Some(base) = rv_maven_types::snapshot_base_version(version) {
                        let gav = rv_maven_types::Gav::new(
                            jar.gav.group.as_str(),
                            jar.gav.artifact.as_str(),
                            &base,
                        );
                        let key = (entry.platform.clone(), module.path.clone(), gav);
                        extensions.insert(key, version.to_string());
                    }
                }
            }
        }
        self.lock_extensions = Arc::new(extensions);
        self.lock_missing_poms = Arc::new(lock.missing_pom_paths());
        self.lock_unverified = Arc::new(lock.missing_checksum_files().into_keys().collect());
        self.lock_pins = Arc::new(lock.pinned_paths());
        self
    }

    /// The build of the SNAPSHOT build extension `gav`, or of a SNAPSHOT
    /// jar of its realm, raeva.lock pins for `module` on `platform`, under
    /// `--frozen` or offline, where `mvn -o`
    /// reads no `file://` repository either. Maven resolves an extension per
    /// list of plugin repositories, so two modules may hold two builds of
    /// one, and the jar records no repository.
    pub fn pinned_extension(
        &self,
        platform: &rv_lock::Platform,
        module: &str,
        gav: &rv_maven_types::Gav,
    ) -> Option<&str> {
        if !self.offline && !self.pinned_snapshots() {
            return None;
        }
        let key = (platform.clone(), module.to_string(), gav.clone());
        self.lock_extensions.get(&key).map(String::as_str)
    }

    /// When a sync of `project` last asked the repositories for newer
    /// SNAPSHOT builds of `platform`, as [`Self::record_snapshot_check`]
    /// recorded it. `None` when it never did, or the record cannot be read.
    pub fn snapshot_check(&self, project: &str, platform: &str) -> Option<SnapshotCheck> {
        (self.cache.snapshot_check(project, platform))
            .inspect_err(|err| tracing::debug!("{err}"))
            .ok()
            .flatten()
    }

    /// Record that this client's resolution of `checked` of `project`,
    /// which began at `started` (Unix seconds), asked the repositories for
    /// newer SNAPSHOT builds, and when the cached rows of SNAPSHOT versions
    /// it took instead fall due; for `others`, which it resolved without
    /// asking, only those rows. An offline client, or one that keeps the
    /// locked builds, asked none and records nothing. A record that cannot
    /// be written only makes the next sync check again.
    pub fn record_snapshot_check(
        &self,
        project: &str,
        checked: &[String],
        others: &[String],
        started: i64,
    ) {
        if self.offline || self.pinned_snapshots() {
            return;
        }
        let rows = *(self.snapshot_rows.lock()).unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(err) =
            (self.cache).record_snapshot_check(project, checked, others, started, rows)
        {
            tracing::debug!("{err}");
        }
    }

    /// Count a cached row of `path` this client took, written at
    /// `fetched_at` and expiring at `expires_at`, when `path` is in the
    /// directory of a SNAPSHOT version.
    fn note_cached_row(&self, path: &str, fetched_at: i64, expires_at: i64) {
        if (path.rsplit('/').nth(1)).is_some_and(rv_maven_types::is_snapshot_version) {
            (self.snapshot_rows.lock())
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .note(fetched_at, expires_at);
        }
    }

    /// The SHA-256 of the raeva.lock of `project` a sync last wrote or
    /// checked, with the platforms it covered, one per line.
    pub fn checked_lock(&self, project: &str) -> Option<(String, String)> {
        (self.cache.checked_lock(project))
            .inspect_err(|err| tracing::debug!("{err}"))
            .ok()
            .flatten()
    }

    /// Record that a sync wrote or checked the raeva.lock of `project`
    /// whose SHA-256 is `sha256` for `platforms`. A record that cannot be
    /// written only makes the next sync check the lock again.
    pub fn record_checked_lock(&self, project: &str, sha256: &str, platforms: &str) {
        if let Err(err) = self.cache.record_checked_lock(project, sha256, platforms) {
            tracing::debug!("{err}");
        }
    }

    /// Whether [`Self::with_lock_pins`] pinned the file of `key`.
    pub fn pins(&self, key: &rv_maven_types::ArtifactCoord) -> bool {
        self.lock_pin(&file_path(key)).is_some()
    }

    /// The digest raeva.lock pins for the file at `path`.
    fn lock_pin(&self, path: &str) -> Option<&Digest> {
        self.lock_pins.get(path).map(|(pin, _)| pin)
    }

    /// Whether the SHA-256 pin of `path` stands in for its checksum file: a
    /// file raeva.lock marks as accepted without one still asks for it.
    fn pin_skips_checksum(&self, path: &str) -> bool {
        self.lock_pin(path).and_then(Digest::as_sha256).is_some()
            && !self.lock_unverified.contains(path)
    }

    /// [`Self::lock_pin`] for a release file or timestamped snapshot build.
    /// Only non-unique snapshot filenames can be redeployed and are left
    /// out, as [`rv_lock::Lockfile::repinned_releases`] leaves them out.
    fn release_file_pin(&self, path: &str) -> Option<&Digest> {
        let snapshot = rv_maven_types::layout::is_mutable_snapshot_path(path);
        self.lock_pin(path).filter(|_| !snapshot)
    }

    /// [`Self::release_file_pin`], which other bytes must not replace unless
    /// [`Freshness::Update`] asked to lock new bytes, online or from a local
    /// repository.
    fn release_lock_pin(&self, path: &str) -> Option<&Digest> {
        self.release_file_pin(path)
            .filter(|_| self.refresh_before().is_none())
    }

    /// Where requests for `repo` go: the mirror that serves it, if any, and
    /// whether the default credential is withheld from that endpoint.
    pub fn route(&self, repo: &Repository) -> RouteInfo {
        self.router.route(repo).info()
    }

    /// Whether a request to `repo` would carry a credential, or could not
    /// be sent at all.
    pub fn sends_credential(&self, repo: &Repository) -> bool {
        let route = self.router.route(repo);
        route.mirror.as_ref().is_some_and(|mirror| mirror.blocked)
            || (self.router.auth_store()).has_credential(&route.endpoint, route.cross_origin)
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
