use std::collections::{HashMap, HashSet};
use std::error::Error as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use regex::Regex;
use reqwest::Client;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tracing::{debug, warn};
use url::Url;

use rv_config::{BlobId, Config};

use rv_version::Coord;

use crate::artifact::ArtifactRequest;
use crate::auth::AuthStore;
use crate::cache::{CacheTable, MetadataCache};
use crate::error::{RedirectRejectionKind, RepoError, Result};
use crate::fetch::{
    Checksum, ChecksumAlgorithm, FetchConfig, FetchProgress, fetch_bytes,
    fetch_stream_to_store_verified, fetch_text, parse_checksum, redact_url, verify_checksum,
};
use crate::metadata::Metadata;
use crate::mirror::MirrorSelector;
use crate::proxy::build_proxy;
use crate::repository::{Repository, is_snapshot_version};
use rv_store::Store;

#[derive(Clone)]
pub struct RepoClient {
    /// Requests to a configured repository or mirror host. This is the only
    /// client that may follow a cross-origin redirect, and every screen it
    /// applies — policy and resolver alike — reads the frozen
    /// [`ConfiguredHosts`] set. It never consults runtime trust. See
    /// [`RepoClient::http_client_for`].
    client: Client,
    /// Requests to every other host, including repositories trusted at runtime
    /// by [`RepoClient::trust_repositories`]. Its resolver reads the live
    /// [`TrustedHosts`] set so a grant taken mid-resolve is honoured without a
    /// rebuild, and its redirect policy is same-origin only, so that live set
    /// can never widen what a redirect may reach.
    runtime_client: Client,
    auth: AuthStore,
    mirrors: MirrorSelector,
    fetch: FetchConfig,
    progress: Option<Arc<dyn FetchProgress>>,
    cache: MetadataCache,
    offline: bool,
    require_checksums: bool,
    mirror_failures: Arc<MirrorFailureTracker>,
    /// Hosts named by `rv.toml` (repositories, mirrors and proxies), frozen at
    /// construction. Decides which of the two clients above serves a request.
    configured_hosts: ConfiguredHosts,
    /// Hosts the runtime client may dial even when they resolve off the public
    /// internet: the configured ones above plus whatever
    /// [`RepoClient::trust_repositories`] adds. See [`TrustedHosts`].
    trusted_hosts: TrustedHosts,
}

const MIRROR_FAILURE_SUMMARY_THRESHOLD: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MirrorFailureKey {
    mirror: String,
    kind: RedirectRejectionKind,
}

#[derive(Debug, Default)]
struct MirrorFailureTracker {
    counts: Mutex<HashMap<MirrorFailureKey, usize>>,
}

impl MirrorFailureTracker {
    fn record(&self, mirror: &Repository, error: &RepoError) {
        let RepoError::RedirectRejected { kind, .. } = error else {
            return;
        };
        let mirror_url = Url::parse(&mirror.url)
            .map(|url| redact_url(&url))
            .unwrap_or_else(|_| "<invalid mirror URL>".to_string());
        let mirror_name = mirror
            .id
            .as_deref()
            .map_or_else(|| mirror_url.clone(), |id| format!("{id} ({mirror_url})"));
        let mut counts = self.counts.lock().unwrap_or_else(|err| err.into_inner());
        *counts
            .entry(MirrorFailureKey {
                mirror: mirror_name,
                kind: *kind,
            })
            .or_default() += 1;
    }

    fn report(&self) {
        let mut counts = self.counts.lock().unwrap_or_else(|err| err.into_inner());
        let mut summaries: Vec<_> = std::mem::take(&mut *counts).into_iter().collect();
        summaries.sort_by(|(left, _), (right, _)| {
            left.mirror
                .cmp(&right.mirror)
                .then(left.kind.summary().cmp(right.kind.summary()))
        });
        for (failure, count) in summaries {
            if count < MIRROR_FAILURE_SUMMARY_THRESHOLD {
                continue;
            }
            warn!(
                mirror = %failure.mirror,
                failures = count,
                reason = failure.kind.summary(),
                "mirror {} failed {} fetches ({}); results came from origin repositories",
                failure.mirror,
                count,
                failure.kind.summary(),
            );
        }
    }
}

impl Drop for RepoClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.mirror_failures) == 1 {
            self.mirror_failures.report();
        }
    }
}

#[derive(Debug, Clone)]
struct RedirectPolicyError {
    kind: RedirectRejectionKind,
    details: String,
}

impl std::fmt::Display for RedirectPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.details)
    }
}

impl std::error::Error for RedirectPolicyError {}

#[derive(Debug, Clone)]
pub struct SnapshotResolution {
    pub version: String,
    pub snapshot_timestamp: Option<String>,
}

#[derive(Debug, Clone)]
struct SnapshotPath {
    dir_version: String,
    file_version: String,
}

impl RepoClient {
    pub async fn new(config: &Config) -> Result<Self> {
        let fetch = FetchConfig {
            retries: config.network.retries,
            timeout: Duration::from_secs(config.network.timeout),
        };
        let guard = redirect_guard(config)?;
        // Seeded with the configured hosts, then grown by `trust_repositories`.
        // A separate set, not a second handle on the guard's: the guard's must
        // stay frozen.
        let trusted_hosts = guard.exempt_hosts.to_runtime_set();

        // Shared by both clients. `no_proxy` ignores HTTP_PROXY/HTTPS_PROXY and
        // friends: an implicit environment proxy resolves hostnames itself, so
        // it silently bypasses `GlobalOnlyResolver` while
        // `RedirectGuard::proxy_active` still reads false and the policy relaxes
        // accordingly. Proxies come from the user's own configuration, which is
        // the path both guards are told about. Must precede `proxy` calls: it
        // clears the accumulated list.
        let base_builder = || {
            Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .pool_max_idle_per_host(10)
                // Keep long-lived idle connections healthy and reclaim them
                // before the typical 60s NAT/idle-timeout would. Pairs with
                // pool_idle_timeout to bound the keep-alive window.
                .tcp_keepalive(Duration::from_secs(30))
                .pool_idle_timeout(Duration::from_secs(75))
                .no_proxy()
                .user_agent(USER_AGENT)
        };
        let mut configured_builder = base_builder()
            .redirect(trusted_redirect_policy(guard.clone()))
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                exempt_hosts: guard.exempt_hosts.clone(),
            }));
        let mut runtime_builder = base_builder()
            // Same-origin only, so nothing this client dials can be redirected
            // anywhere its live exemption set has not already been asked about.
            .redirect(same_origin_redirect_policy())
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                exempt_hosts: trusted_hosts.clone(),
            }));

        for proxy_config in config.proxies() {
            // Proxy auth (Basic and Bearer alike) is wired into the Proxy
            // object inside build_proxy so it rides the CONNECT for HTTPS
            // upstreams and is never leaked into the TLS tunnel.
            let proxy = build_proxy(proxy_config)?;
            configured_builder = configured_builder.proxy(proxy.clone());
            runtime_builder = runtime_builder.proxy(proxy);
        }

        let cache_path = config.paths.metadata_db_path();
        let cache = MetadataCache::new(&cache_path)?;

        Ok(Self {
            client: configured_builder.build()?,
            runtime_client: runtime_builder.build()?,
            auth: AuthStore::from_config(config)?,
            mirrors: MirrorSelector::from_config(config),
            fetch,
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            configured_hosts: guard.exempt_hosts,
            trusted_hosts,
        })
    }

    /// Pick the client that serves `url`.
    ///
    /// A host named in `rv.toml` gets the redirect-capable client; everything
    /// else — a repository the root POM declared, one the user's transitive
    /// policy approved, any endpoint trusted after construction — gets the
    /// same-origin-only client whose resolver reads the live trust set.
    ///
    /// Splitting the two is what keeps runtime trust out of the redirect
    /// decision entirely: a set that grows mid-resolve is read by exactly one
    /// resolver, and that resolver belongs to a client which cannot leave the
    /// origin it was pointed at. It costs no reach, because a cross-origin
    /// redirect has always required the *issuer* to be a configured origin
    /// (see [`RedirectGuard::evaluate`]), which a runtime-trusted repository
    /// is not: an object-storage-backed registry that answers `302` with a
    /// presigned storage URL had to be named in `rv.toml` — together with the
    /// storage origin — before this split, and still does.
    fn http_client_for(&self, url: &Url) -> &Client {
        match url.host_str() {
            Some(host) if self.configured_hosts.contains(host) => &self.client,
            _ => &self.runtime_client,
        }
    }

    /// Extend the address-screen exemption to repositories that became trusted
    /// after this client was built: the root POM's own `<repositories>` (the
    /// root POM belongs to the user) and transitive ones the user's policy
    /// approved. Both are deliberate trust decisions taken by the resolver;
    /// this mirrors them into the DNS screen so an on-prem registry the user
    /// named in their POM rather than in `rv.toml` stays reachable on an
    /// RFC1918 address.
    ///
    /// The exemption covers DIRECT connections only and carries no redirect
    /// authority: it is read by one resolver, and that resolver belongs to the
    /// same-origin-only client, so a hostile POM cannot parlay a grant into a
    /// probe of the private network — nor can a grant landing mid-request
    /// retroactively excuse a redirect the policy let through on the
    /// expectation that the resolver would screen it. See
    /// [`RepoClient::http_client_for`] and [`RedirectGuard`].
    pub fn trust_repositories<'a>(&self, repos: impl IntoIterator<Item = &'a Repository>) {
        for repo in repos {
            // An unparsable or non-HTTP endpoint never reaches the resolver,
            // so there is nothing to exempt; the fetch path reports it. Same
            // filter as `redirect_guard`.
            let Ok(url) = Url::parse(&repo.url) else {
                continue;
            };
            if origin_key(&url).is_none() {
                continue;
            }
            if let Some(host) = url.host_str() {
                self.trusted_hosts.insert(host);
            }
        }
    }

    /// Whether `host` is currently exempt from the address screen, i.e. may
    /// resolve off the public internet on a direct connection.
    pub fn trusts_host(&self, host: &str) -> bool {
        self.trusted_hosts.contains(host)
    }

    pub fn with_progress(mut self, progress: Arc<dyn FetchProgress>) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Opt out of requiring a server-published checksum sidecar. Off by default;
    /// callers who set this true accept the risk that a hostile or misconfigured
    /// mirror could serve unverified bytes.
    pub fn with_allow_missing_checksums(mut self, allow: bool) -> Self {
        self.require_checksums = !allow;
        self
    }

    pub fn is_offline(&self) -> bool {
        self.offline
    }

    pub fn set_progress(&mut self, progress: Option<Arc<dyn FetchProgress>>) {
        self.progress = progress;
    }

    /// Return the configured endpoint a fetch tries first after mirror
    /// substitution.
    ///
    /// Callers use this to keep cached-artifact provenance aligned with the
    /// current routing configuration even when no HTTP request happens.
    pub fn effective_repository_url(&self, repo: &Repository) -> String {
        self.mirrors.resolve_with_host_change(repo).0.url
    }

    pub async fn fetch_metadata(&self, repo: &Repository, coord: &Coord) -> Result<Metadata> {
        let version = coord.version.to_string();
        // Validate coordinate components before building any URL path to
        // prevent path-traversal / SSRF from hostile maven-metadata.xml content.
        validate_coord_components(
            coord.group_id.as_str(),
            coord.artifact_id.as_str(),
            Some(&version),
        )?;

        let (primary, host_changed, fallback) = self.resolve_repo_with_fallback(repo);
        self.ensure_repo_allows_version(&primary, &version)?;

        let path = if is_snapshot_version(&version) {
            metadata_path(
                coord.group_id.as_str(),
                coord.artifact_id.as_str(),
                Some(&version),
            )
        } else {
            metadata_path(coord.group_id.as_str(), coord.artifact_id.as_str(), None)
        };

        // #64: scope the cache key by (origin, resolved). When a mirror
        // substituted, `fallback` holds the original origin repo; otherwise the
        // primary IS the origin.
        let origin_url = fallback
            .as_ref()
            .map(|f| f.url.as_str())
            .unwrap_or(primary.url.as_str());
        let cache_scope = Self::cache_scope_key(origin_url, &primary.url);

        if let Some(bytes) = self
            .cache_get_bytes(CacheTable::VersionList, &cache_scope, &path)
            .await?
        {
            debug!(
                group = %coord.group_id,
                artifact = %coord.artifact_id,
                "metadata cache hit"
            );
            return Metadata::from_bytes(&bytes);
        }

        // Offline guard. Surface a clear error before touching the
        // network. `fetch_path` would also reject the request, but surfacing it
        // here honours the metadata-refresh contract for `--offline` mode.
        if self.offline {
            return Err(RepoError::OfflineNotCached(format!(
                "{path} (repo: {})",
                primary.url
            )));
        }

        debug!(
            group = %coord.group_id,
            artifact = %coord.artifact_id,
            "metadata cache miss, fetching from repository"
        );
        // Verify the metadata sidecar before parsing/caching. An attacker
        // on the wire (or a misconfigured mirror) can otherwise rewrite the
        // version list to downgrade a snapshot or steer resolution.
        // If the mirror is broken, retry the origin (Maven parity).
        let bytes = match self
            .fetch_with_checksums(&primary, &path, host_changed)
            .await
        {
            Ok(bytes) => bytes,
            Err(err) if fallback.is_some() && should_fallback_to_origin(&err) => {
                let origin = fallback.expect("fallback present");
                debug!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "metadata fetch failed against mirror; retrying against origin"
                );
                let result = self.fetch_with_checksums(&origin, &path, false).await;
                if result.is_ok() {
                    self.mirror_failures.record(&primary, &err);
                }
                result?
            }
            Err(err) => return Err(err),
        };
        let metadata = Metadata::from_bytes(&bytes)?;
        self.cache_insert_metadata(&primary, &cache_scope, &path, bytes.as_ref(), &version)
            .await?;
        Ok(metadata)
    }

    pub async fn resolve_snapshot(&self, repo: &Repository, coord: &Coord) -> Result<String> {
        let resolved = self.resolve_snapshot_version(repo, coord).await?;
        Ok(resolved.version)
    }

    pub async fn resolve_snapshot_version(
        &self,
        repo: &Repository,
        coord: &Coord,
    ) -> Result<SnapshotResolution> {
        let version = coord.version.to_string();
        if !is_snapshot_version(&version) {
            return Err(RepoError::InvalidCoord(format!(
                "{version} is not a snapshot"
            )));
        }
        // Public entry point: the caller passes the original (un-mirrored)
        // repo, so we run mirror selection here and derive `host_changed`.
        let (primary, host_changed, fallback) = self.resolve_repo_with_fallback(repo);
        self.resolve_snapshot_version_resolved(primary, host_changed, fallback, coord)
            .await
    }

    /// Snapshot-metadata resolution against an *already mirror-resolved* repo.
    ///
    /// `primary`/`host_changed`/`fallback` come straight from a single
    /// [`Self::resolve_repo_with_fallback`] call made by the caller. Threading
    /// them through here, rather than re-resolving, preserves the cross-host
    /// credential-suppression signal: the artifact/POM fetch paths resolve the
    /// mirror once, and re-running mirror selection on the *already substituted*
    /// URL would recompute `host_changed` as `false`, leaking the default
    /// credential to a third-party mirror host during the snapshot sub-fetch.
    async fn resolve_snapshot_version_resolved(
        &self,
        primary: Repository,
        host_changed: bool,
        fallback: Option<Repository>,
        coord: &Coord,
    ) -> Result<SnapshotResolution> {
        let version = coord.version.to_string();
        self.ensure_repo_allows_version(&primary, &version)?;
        // #64: scope the snapshot-metadata cache key by (origin, resolved) so a
        // wildcard mirror cannot serve one origin's snapshot metadata to
        // another origin. Both the mirror attempt and the origin retry use the
        // same scope so the retry can still populate/read the same entry.
        let origin_url = fallback
            .as_ref()
            .map(|f| f.url.as_str())
            .unwrap_or(primary.url.as_str());
        let cache_scope = Self::cache_scope_key(origin_url, &primary.url);
        // Snapshot metadata is itself fetched from the mirror; if the
        // mirror is down we have to retry against the origin or downstream
        // artifact fetches see "no resolved snapshot version".
        let metadata = match self
            .fetch_snapshot_metadata(
                &primary,
                &cache_scope,
                coord.group_id.as_str(),
                coord.artifact_id.as_str(),
                &version,
                host_changed,
            )
            .await
        {
            Ok(metadata) => metadata,
            Err(err) if fallback.is_some() && should_fallback_to_origin(&err) => {
                let origin = fallback.expect("fallback present");
                debug!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "snapshot metadata fetch failed against mirror; retrying against origin"
                );
                let result = self
                    .fetch_snapshot_metadata(
                        &origin,
                        &cache_scope,
                        coord.group_id.as_str(),
                        coord.artifact_id.as_str(),
                        &version,
                        false,
                    )
                    .await;
                if result.is_ok() {
                    self.mirror_failures.record(&primary, &err);
                }
                result?
            }
            Err(err) => return Err(err),
        };

        let extension = coord.packaging.as_deref().unwrap_or("jar");
        let resolved = metadata
            .snapshot_version_for(coord.classifier.as_deref(), extension)
            .map(str::to_string)
            .ok_or_else(|| {
                RepoError::InvalidMetadata("missing snapshot version data".to_string())
            })?;

        // The snapshot `<value>` comes straight from server-controlled
        // maven-metadata.xml and is about to be spliced into the artifact
        // filename and joined onto the repo path. Run it through the same
        // path-traversal/SSRF gate as the requested coordinate components so a
        // hostile/compromised repo cannot steer the fetch to an arbitrary path
        // (e.g. `<value>../../../../private/secret</value>`).
        crate::artifact::validate_coordinate_component(&resolved, "snapshot version")
            .map_err(RepoError::InvalidCoord)?;

        let snapshot_timestamp = snapshot_timestamp_from_version(&resolved);

        Ok(SnapshotResolution {
            version: resolved,
            snapshot_timestamp,
        })
    }

    pub async fn fetch_pom(&self, repo: &Repository, req: &ArtifactRequest) -> Result<Bytes> {
        req.validate().map_err(RepoError::InvalidCoord)?;
        self.fetch_pom_bytes(repo, req).await
    }

    async fn fetch_pom_bytes(&self, repo: &Repository, req: &ArtifactRequest) -> Result<Bytes> {
        let (primary, host_changed, fallback) = self.resolve_repo_with_fallback(repo);
        self.ensure_repo_allows_version(&primary, &req.version)?;

        let pom_req = req.pom();
        let path = if pom_req.is_snapshot() {
            let snapshot = self
                .resolve_snapshot_for_request(&primary, &pom_req, host_changed, fallback.as_ref())
                .await?;
            pom_req.to_path_with_versions(&snapshot.dir_version, &snapshot.file_version)
        } else {
            pom_req.to_path()
        };

        // #64: scope the POM cache key by (origin, resolved) so a wildcard
        // mirror cannot serve one origin's cached POM to another origin.
        let origin_url = fallback
            .as_ref()
            .map(|f| f.url.as_str())
            .unwrap_or(primary.url.as_str());
        let cache_scope = Self::cache_scope_key(origin_url, &primary.url);

        if let Some(bytes) = self
            .cache_get_bytes(CacheTable::Pom, &cache_scope, &path)
            .await?
        {
            debug!(
                group = %req.group_id,
                artifact = %req.artifact_id,
                version = %req.version,
                "POM cache hit"
            );
            return Ok(bytes);
        }

        debug!(
            group = %req.group_id,
            artifact = %req.artifact_id,
            version = %req.version,
            "POM cache miss, fetching"
        );
        let bytes = match self
            .fetch_with_checksums(&primary, &path, host_changed)
            .await
        {
            Ok(bytes) => bytes,
            Err(err) if fallback.is_some() && should_fallback_to_origin(&err) => {
                let origin = fallback.expect("fallback present");
                debug!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "POM fetch failed against mirror; retrying against origin"
                );
                let result = self.fetch_with_checksums(&origin, &path, false).await;
                if result.is_ok() {
                    self.mirror_failures.record(&primary, &err);
                }
                result?
            }
            Err(err) => return Err(err),
        };
        let ttl = primary.update_policy_ttl(&pom_req.version).as_secs() as i64;
        self.cache_insert_bytes_with_ttl(CacheTable::Pom, &cache_scope, &path, bytes.as_ref(), ttl)
            .await?;
        Ok(bytes)
    }

    pub async fn fetch_artifact_to_store(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        store: &Store,
    ) -> Result<BlobId> {
        req.validate().map_err(RepoError::InvalidCoord)?;
        debug!(
            group = %req.group_id,
            artifact = %req.artifact_id,
            version = %req.version,
            packaging = %req.packaging,
            "fetching artifact to store"
        );
        let (primary, host_changed, fallback) = self.resolve_repo_with_fallback(repo);
        self.ensure_repo_allows_version(&primary, &req.version)?;

        let path = if req.is_snapshot() {
            let snapshot = self
                .resolve_snapshot_for_request(&primary, req, host_changed, fallback.as_ref())
                .await?;
            req.to_path_with_versions(&snapshot.dir_version, &snapshot.file_version)
        } else {
            req.to_path()
        };

        if self.offline {
            return Err(RepoError::OfflineNotCached(path.clone()));
        }

        // Try the mirror first; if it dies on a 5xx (or other non-404),
        // retry against the origin.
        match self
            .fetch_artifact_to_store_attempt(&primary, &path, host_changed, store)
            .await
        {
            Ok(blob) => Ok(blob),
            Err(err) if fallback.is_some() && should_fallback_to_origin(&err) => {
                let origin = fallback.expect("fallback present");
                debug!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "artifact fetch failed against mirror; retrying against origin"
                );
                let result = self
                    .fetch_artifact_to_store_attempt(&origin, &path, false, store)
                    .await;
                if result.is_ok() {
                    self.mirror_failures.record(&primary, &err);
                }
                result
            }
            Err(err) => Err(err),
        }
    }

    async fn fetch_artifact_to_store_attempt(
        &self,
        repo: &Repository,
        path: &str,
        host_changed: bool,
        store: &Store,
    ) -> Result<BlobId> {
        let checksum = self.fetch_checksum(repo, path, host_changed).await?;

        // Refuse to write unverified bytes into the content-addressed store
        // when checksums are required. If we discovered no sidecar (the
        // `fetch_checksum` helper returned `None`) and the client is configured
        // to require one, bail out *before* `fetch_stream_to_store_verified`
        // streams the response into a CAS path. Previously the blob was
        // persisted first and the missing-checksum error was raised after, so
        // an attacker (or a misconfigured mirror) could leave orphan blobs in
        // CAS, and any retry would dedup against them.
        if checksum.is_none() && self.require_checksums {
            return Err(RepoError::MissingChecksum(path.to_string()));
        }

        let url = repo.url_for_path(path)?;
        let auth = self.auth.for_repository_with_policy(repo, host_changed)?;

        let blob = fetch_stream_to_store_verified(
            self.http_client_for(&url),
            &url,
            auth.as_ref(),
            &self.fetch,
            self.progress.as_deref(),
            store,
            checksum.as_ref(),
        )
        .await?;

        match checksum.as_ref() {
            Some(checksum) => {
                debug!(path, algorithm = ?checksum.algorithm, "verified checksum");
            }
            None => warn!(path, "missing checksum for artifact"),
        }

        Ok(blob)
    }

    /// Race-free counterpart to [`Self::fetch_artifact_to_store`] that also
    /// records the artifact-key → blob mapping under the same `Store` lock
    /// as the blob persist.
    ///
    /// GC race: a two-step
    /// `fetch_artifact_to_store` then `Store::add_artifact` sequence is racy.
    /// Between the persist and the index write, a concurrent
    /// `Store::prune_blobs` (or a `clean_blobs` reaper for unrooted blobs)
    /// can observe the freshly-persisted blob with no row pointing at it
    /// and delete the file, leaving the caller about to write an index row
    /// against an already-gone blob.
    ///
    /// Routing through [`fetch_stream_to_store_and_index`] funnels both the
    /// persist and the index commit through one held `StoreLock`, closing
    /// the GC race window documented on [`Store::put_stream_and_index`].
    pub async fn fetch_artifact_to_store_and_index(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        store: &Store,
        key: &rv_config::ArtifactKey,
    ) -> Result<BlobId> {
        self.fetch_artifact_to_store_and_index_with_repository(repo, req, store, key)
            .await
            .map(|(blob, _)| blob)
    }

    /// Fetch and index an artifact, returning the configured repository or
    /// mirror URL that actually served it.
    ///
    /// Redirect targets are transport details, so this never returns them. A
    /// presigned object-storage URL must never become durable lockfile
    /// provenance. When a mirror fails and the origin retry succeeds, this
    /// returns the origin URL.
    pub async fn fetch_artifact_to_store_and_index_with_repository(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        store: &Store,
        key: &rv_config::ArtifactKey,
    ) -> Result<(BlobId, String)> {
        req.validate().map_err(RepoError::InvalidCoord)?;
        debug!(
            group = %req.group_id,
            artifact = %req.artifact_id,
            version = %req.version,
            packaging = %req.packaging,
            "fetching artifact to store (atomic put+index)"
        );
        let (primary, host_changed, fallback) = self.resolve_repo_with_fallback(repo);
        self.ensure_repo_allows_version(&primary, &req.version)?;

        let path = if req.is_snapshot() {
            let snapshot = self
                .resolve_snapshot_for_request(&primary, req, host_changed, fallback.as_ref())
                .await?;
            req.to_path_with_versions(&snapshot.dir_version, &snapshot.file_version)
        } else {
            req.to_path()
        };

        if self.offline {
            return Err(RepoError::OfflineNotCached(path.clone()));
        }

        // Mirror-down fallback to origin. The atomic put+index helper is
        // idempotent in the failure-then-retry case: a failed primary fetch
        // leaves no partial blob in CAS (the streaming helper unwinds its
        // tempfile), so re-running against the origin is safe.
        match self
            .fetch_artifact_to_store_and_index_attempt(&primary, &path, host_changed, store, key)
            .await
        {
            Ok(blob) => Ok((blob, primary.url)),
            Err(err) if fallback.is_some() && should_fallback_to_origin(&err) => {
                let origin = fallback.expect("fallback present");
                debug!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "atomic artifact fetch failed against mirror; retrying against origin"
                );
                let result = self
                    .fetch_artifact_to_store_and_index_attempt(&origin, &path, false, store, key)
                    .await;
                if result.is_ok() {
                    self.mirror_failures.record(&primary, &err);
                }
                result.map(|blob| (blob, origin.url))
            }
            Err(err) => Err(err),
        }
    }

    async fn fetch_artifact_to_store_and_index_attempt(
        &self,
        repo: &Repository,
        path: &str,
        host_changed: bool,
        store: &Store,
        key: &rv_config::ArtifactKey,
    ) -> Result<BlobId> {
        let checksum = self.fetch_checksum(repo, path, host_changed).await?;

        if checksum.is_none() && self.require_checksums {
            return Err(RepoError::MissingChecksum(path.to_string()));
        }

        let url = repo.url_for_path(path)?;
        let auth = self.auth.for_repository_with_policy(repo, host_changed)?;

        let blob = crate::fetch::fetch_stream_to_store_and_index(
            self.http_client_for(&url),
            &url,
            auth.as_ref(),
            &self.fetch,
            self.progress.as_deref(),
            store,
            key,
            checksum.as_ref(),
        )
        .await?;

        match checksum.as_ref() {
            Some(checksum) => {
                debug!(path, algorithm = ?checksum.algorithm, "verified checksum");
            }
            None => warn!(path, "missing checksum for artifact"),
        }

        Ok(blob)
    }

    async fn cache_get_bytes(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
    ) -> Result<Option<Bytes>> {
        let cache = self.cache.clone();
        let repo_url: Arc<str> = repo_url.into();
        let path: Arc<str> = path.into();

        tokio::task::spawn_blocking(move || {
            let entry = cache.get(table, &repo_url, &path)?;
            cache_cleanup_tick(&cache);
            match entry {
                Some(entry) => {
                    let now = crate::cache::now_epoch_seconds();
                    if MetadataCache::is_expired(entry.expires_at, now) {
                        Ok(None)
                    } else {
                        Ok(Some(Bytes::from(entry.content)))
                    }
                }
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| RepoError::Io(std::io::Error::other(format!("cache task panicked: {e}"))))?
    }

    async fn cache_insert_bytes_with_ttl(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
        content: &[u8],
        ttl: i64,
    ) -> Result<()> {
        let cache = self.cache.clone();
        let repo_url: Arc<str> = repo_url.into();
        let path: Arc<str> = path.into();
        let content = content.to_vec();

        tokio::task::spawn_blocking(move || {
            let result = cache.insert_with_ttl(table, &repo_url, &path, &content, ttl);
            cache_cleanup_tick(&cache);
            result
        })
        .await
        .map_err(|e| RepoError::Io(std::io::Error::other(format!("cache task panicked: {e}"))))?
    }

    async fn cache_insert_metadata(
        &self,
        repo: &Repository,
        cache_scope: &str,
        path: &str,
        content: &[u8],
        version: &str,
    ) -> Result<()> {
        // Consult the repository's own update policy for both snapshot and
        // release metadata. Earlier code only honoured the snapshot policy
        // and fell back to a hardcoded release TTL.
        let ttl = repo.update_policy_ttl(version).as_secs() as i64;
        self.cache_insert_bytes_with_ttl(CacheTable::VersionList, cache_scope, path, content, ttl)
            .await
    }

    /// Build the metadata/POM cache scope key for a `(origin, resolved)` repo
    /// pair (#64).
    ///
    /// Keying the cache by the *resolved* (mirror) URL alone lets two distinct
    /// logical origins routed through one wildcard mirror collide under the
    /// same `(mirror_url, path)` key, a cross-origin stale reuse. Scoping the
    /// key by the origin URL joined with the resolved URL avoids this: the
    /// origin component isolates distinct upstreams sharing a mirror, and the
    /// resolved component means swapping a repo's mirror does not reuse an entry
    /// fetched through a different mirror.
    fn cache_scope_key(origin_url: &str, resolved_url: &str) -> String {
        // `\u{1f}` (unit separator) cannot appear in a URL, so the two
        // components can be concatenated without an ambiguous boundary.
        format!("{origin_url}\u{1f}{resolved_url}")
    }

    /// Resolve mirror substitution and also surface the unmirrored origin so
    /// fetch helpers can fall back to it when the mirror is unreachable.
    ///
    /// Returns `(primary, host_changed, fallback)`. `fallback` is `Some` only
    /// when the mirror selector actually substituted the repo URL. When no
    /// mirror matched, the primary and the original are identical and there
    /// is nothing to fall back to.
    ///
    /// Maven retries each mirror entry in order; rv currently picks one
    /// mirror per repo so the fallback list is at most length two
    /// (mirror, origin). When the user has explicitly configured a mirror
    /// for a repo, the origin retry is still safe: the user listed the
    /// origin in `rv.toml`, so it is a trusted target.
    fn resolve_repo_with_fallback(
        &self,
        repo: &Repository,
    ) -> (Repository, bool, Option<Repository>) {
        let (resolved, host_changed) = self.mirrors.resolve_with_host_change(repo);
        let substituted = resolved.url != repo.url;
        let fallback = if substituted {
            Some(repo.clone())
        } else {
            None
        };
        (resolved, host_changed, fallback)
    }

    fn ensure_repo_allows_version(&self, repo: &Repository, version: &str) -> Result<()> {
        if repo.allows_version(version) {
            Ok(())
        } else if is_snapshot_version(version) {
            let repo_id = repo.id.as_deref().unwrap_or("repository");
            Err(RepoError::SnapshotsDisabled {
                version: version.to_string(),
                reason: format!(
                    "repository '{}' has snapshots disabled. \
                     SNAPSHOT versions require a repository with snapshots enabled \
                     (e.g., a Sonatype Nexus or Artifactory snapshot repository)",
                    repo_id
                ),
            })
        } else {
            Err(RepoError::InvalidCoord(format!(
                "releases disabled for {}",
                repo.id.as_deref().unwrap_or("repository")
            )))
        }
    }

    async fn fetch_snapshot_metadata(
        &self,
        repo: &Repository,
        cache_scope: &str,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        host_changed: bool,
    ) -> Result<Metadata> {
        // Validate coordinate components before building URL path.
        validate_coord_components(group_id, artifact_id, Some(version))?;

        let path = metadata_path(group_id, artifact_id, Some(version));
        if let Some(bytes) = self
            .cache_get_bytes(CacheTable::VersionList, cache_scope, &path)
            .await?
        {
            return Metadata::from_bytes(&bytes);
        }

        // Offline guard. Surface a clear error before touching the
        // network. `fetch_path` would also reject the request, but surfacing it
        // here honours the metadata-refresh contract for `--offline` mode.
        if self.offline {
            return Err(RepoError::OfflineNotCached(format!(
                "{path} (repo: {})",
                repo.url
            )));
        }

        // Same protection as `fetch_metadata`. Verify the sidecar before
        // trusting the snapshot metadata pointer.
        let bytes = self.fetch_with_checksums(repo, &path, host_changed).await?;
        let metadata = Metadata::from_bytes(&bytes)?;
        self.cache_insert_metadata(repo, cache_scope, &path, bytes.as_ref(), version)
            .await?;
        Ok(metadata)
    }

    async fn resolve_snapshot_for_request(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        host_changed: bool,
        fallback: Option<&Repository>,
    ) -> Result<SnapshotPath> {
        if !is_snapshot_version(&req.version) {
            return Ok(SnapshotPath {
                dir_version: req.version.to_string(),
                file_version: req.version.to_string(),
            });
        }

        if req.version.ends_with("-SNAPSHOT") {
            let coord = Coord {
                group_id: req.group_id.clone().into(),
                artifact_id: req.artifact_id.clone().into(),
                version: req.version.parse().map_err(|err| {
                    RepoError::InvalidCoord(format!("invalid version {}: {err}", req.version))
                })?,
                packaging: Some(req.packaging.clone()),
                classifier: req.classifier.clone(),
            };
            // `repo` is already the mirror-resolved primary and `host_changed`
            // is the cross-host signal from that single resolution. Thread both
            // (plus the origin `fallback`) straight into the resolved snapshot
            // path so the snapshot-metadata sub-fetch reuses the same
            // auth/host-change policy instead of re-resolving the mirror. A
            // re-resolution would recompute `host_changed=false` and leak the
            // default credential to a third-party mirror host.
            let resolved = self
                .resolve_snapshot_version_resolved(
                    repo.clone(),
                    host_changed,
                    fallback.cloned(),
                    &coord,
                )
                .await?;
            return Ok(SnapshotPath {
                dir_version: req.version.to_string(),
                file_version: resolved.version,
            });
        }

        let dir_version = snapshot_dir_version(&req.version).unwrap_or_else(|| req.version.clone());
        Ok(SnapshotPath {
            dir_version,
            file_version: req.version.to_string(),
        })
    }

    async fn fetch_with_checksums(
        &self,
        repo: &Repository,
        path: &str,
        host_changed: bool,
    ) -> Result<Bytes> {
        // Close the trust gap: run the body and sidecar GETs in parallel, then
        // verify. Running them serially widens the window in which a mirror
        // could swap the body bytes between the two requests.
        let (bytes, checksum) = tokio::try_join!(
            self.fetch_path(repo, path, host_changed),
            self.fetch_checksum(repo, path, host_changed),
        )?;

        match checksum {
            Some(checksum) => {
                verify_checksum(&bytes, &checksum, path)?;
                debug!(path, algorithm = ?checksum.algorithm, "verified checksum");
            }
            None if self.require_checksums => {
                return Err(RepoError::MissingChecksum(path.to_string()));
            }
            None => {
                warn!(path, "missing checksum for artifact");
            }
        }

        Ok(bytes)
    }

    async fn fetch_checksum(
        &self,
        repo: &Repository,
        path: &str,
        host_changed: bool,
    ) -> Result<Option<Checksum>> {
        if self.offline {
            return Ok(None);
        }
        // Build the algorithm probe list. Always prefer SHA-256, then fall
        // back to the SHA-1 sidecar when SHA-256 is absent (404). Maven Central
        // publishes a `.sha1` for essentially every artifact but a `.sha256`
        // for almost none, so a SHA-256-only probe list would make a plain
        // `rv sync` against Central abort with `MissingChecksum`, which is the
        // launch blocker. The residual SHA-1 collision risk is bounded: the
        // durable pin recorded in rv.lock is always the locally-computed
        // SHA-256 of the downloaded bytes (trust-on-first-use), independent of
        // which sidecar gated this fetch. Repos that publish no sidecar at all
        // are still rejected unless the caller sets `--allow-missing-checksums`.
        let algorithms: &[ChecksumAlgorithm] =
            &[ChecksumAlgorithm::Sha256, ChecksumAlgorithm::Sha1];

        // First non-404, non-auth failure seen across the probe loop. If
        // every algorithm ends up unavailable, this is surfaced instead of a
        // generic MissingChecksum so the user sees the real reason the
        // preferred sidecar was rejected.
        let mut first_err: Option<RepoError> = None;

        for &algorithm in algorithms {
            let checksum_path = format!("{path}.{}", algorithm.as_ref());
            let checksum_url = repo.url_for_path(&checksum_path)?;
            let auth = self.auth.for_repository_with_policy(repo, host_changed)?;
            match fetch_text(
                self.http_client_for(&checksum_url),
                &checksum_url,
                auth.as_ref(),
                &self.fetch,
            )
            .await
            {
                Ok(text) => match parse_checksum(&text, algorithm) {
                    Ok(checksum) => {
                        if algorithm == ChecksumAlgorithm::Sha1 {
                            // `sec_code` is the stable machine identifier the
                            // CLI's `WarningCollectorLayer` mirrors into the
                            // JSON envelope's `data.warnings` channel. The fmt
                            // subscriber is off in `--json` mode and a
                            // security-relevant event must still surface there.
                            warn!(
                                sec_code = "WEAK_HASH_FALLBACK",
                                path,
                                "falling back to SHA-1 checksum (weak hash algorithm); \
                                 repository should provide SHA-256 checksums"
                            );
                        }
                        return Ok(Some(checksum));
                    }
                    Err(parse_err) => {
                        // A 200 body with no usable hex token: typically a
                        // server that answers missing paths with an HTML
                        // "not found" page and status 200, or a corrupt
                        // sidecar. Treat this algorithm as unavailable and
                        // probe the next one.
                        warn!(
                            repo = %repo.url,
                            path = %checksum_path,
                            error = %parse_err,
                            "checksum sidecar fetched but contained no valid checksum; \
                             trying next algorithm"
                        );
                        first_err.get_or_insert(parse_err);
                    }
                },
                Err(RepoError::NotFound(_)) => continue,
                // 401/403/407 mean the credentials (or lack of them) were
                // rejected. The same auth gates every sidecar probe, so the
                // next algorithm would fail identically; propagate so the
                // user sees the auth problem, not a missing-checksum one.
                Err(err @ RepoError::AuthError(_)) => return Err(err),
                Err(err) => {
                    // 5xx/429/network failures. `fetch_text` already ran the
                    // full `execute_retry` budget internally, so an error
                    // that is still classified transient here has exhausted
                    // its retries; falling through to the next algorithm
                    // does not bypass the retry layer.
                    warn!(
                        repo = %repo.url,
                        path = %checksum_path,
                        error = %err,
                        "checksum sidecar probe failed; trying next algorithm"
                    );
                    first_err.get_or_insert(err);
                }
            }
        }

        // Every probed algorithm failed. Prefer the first concrete failure
        // over the generic missing-sidecar outcome.
        if let Some(err) = first_err {
            return Err(err);
        }

        // Neither the SHA-256 nor the SHA-1 sidecar was served: the repo
        // publishes no checksum sidecar at all for this path. Return `None`
        // so the caller's `require_checksums` policy decides whether to abort
        // (the default) or proceed under `--allow-missing-checksums`.
        Ok(None)
    }

    async fn fetch_path(&self, repo: &Repository, path: &str, host_changed: bool) -> Result<Bytes> {
        if self.offline {
            return Err(RepoError::OfflineNotCached(path.to_string()));
        }
        let url = repo.url_for_path(path)?;
        let auth = self.auth.for_repository_with_policy(repo, host_changed)?;

        fetch_bytes(
            self.http_client_for(&url),
            &url,
            auth.as_ref(),
            &self.fetch,
            self.progress.as_deref(),
        )
        .await
    }
}

/// True when a mirror failure is "mirror broken" not "artifact missing".
/// 404 and other 4xx are authoritative (don't retry the origin, per Maven
/// semantics); network, 5xx, 429 and unexpected non-2xx (e.g. a 502 HTML
/// page) are not.
pub(crate) fn should_fallback_to_origin(err: &RepoError) -> bool {
    if matches!(err, RepoError::NotFound(_)) {
        return false;
    }
    if let Some(code) = err.status_code() {
        // 404 already filtered above; treat other 4xx (auth, 403, 410) as
        // authoritative too. Re-trying the origin would just expose the
        // same credentials and produce the same error.
        if (400..500).contains(&code) {
            return false;
        }
    }
    // ChecksumMismatch is an integrity violation, not a transient
    // failure. Keeping it out of the fallback list prevents a hostile mirror
    // from exploiting the retry path to poison the origin response.
    err.is_transient()
        || matches!(
            err,
            RepoError::UnexpectedResponse(_)
                | RepoError::Http(_)
                | RepoError::InvalidMetadata(_)
                | RepoError::RedirectRejected { .. }
        )
}

/// User-Agent advertised on every outbound HTTP request. Some private
/// repositories (and many CDN WAFs) reject requests without a UA. Pinning
/// to `raeva/<crate-version>` keeps the value stable and self-describing.
pub(crate) const USER_AGENT: &str = concat!("raeva/", env!("CARGO_PKG_VERSION"));

fn origin_key(url: &Url) -> Option<String> {
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

/// A set of hostnames allowed to sit on a non-global address, in whichever of
/// the two shapes the reader needs.
///
/// The distinction is the whole point of the split, so it is a type and not a
/// convention: [`ConfiguredHosts`] cannot change after the client is built,
/// [`TrustedHosts`] can. Anything screening a redirect reads the first kind.
trait ExemptHosts: Send + Sync + 'static {
    fn contains(&self, host: &str) -> bool;
}

/// Hostnames `rv.toml` named — repository, mirror and proxy endpoints — fixed
/// when the client is built.
///
/// Read by [`RedirectGuard`] and by the redirect-capable client's
/// [`GlobalOnlyResolver`], which is why it is immutable: those two read it at
/// different moments (policy evaluation, then connect), and a set that could
/// grow in between would let a trust grant taken by an unrelated concurrent
/// task retroactively excuse a redirect the policy only permitted because the
/// resolver was going to screen it.
#[derive(Debug, Default, Clone)]
struct ConfiguredHosts(Arc<HashSet<String>>);

impl ConfiguredHosts {
    /// Normalising on the way in is what keeps a configured `[fd00::1]` and a
    /// DNS name `fd00::1` from becoming two spellings of one host.
    fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        Self(Arc::new(
            hosts
                .into_iter()
                .map(|host| normalized_host(&host))
                .collect(),
        ))
    }

    fn contains(&self, host: &str) -> bool {
        self.0.contains(&normalized_host(host))
    }

    /// A fresh mutable set seeded with these hosts, for the runtime client.
    /// Deliberately a copy rather than a shared handle: growing it must not
    /// reach anything that screens redirects.
    fn to_runtime_set(&self) -> TrustedHosts {
        TrustedHosts(Arc::new(RwLock::new((*self.0).clone())))
    }
}

impl ExemptHosts for ConfiguredHosts {
    fn contains(&self, host: &str) -> bool {
        ConfiguredHosts::contains(self, host)
    }
}

/// Hostnames the runtime client may dial off the public internet: the
/// configured ones plus every repository trusted after construction.
///
/// Mutable because trust is not fully known when the client is built. The root
/// POM's `<repositories>`, and any transitive repository the user's policy
/// approves, are granted trust part-way through a resolve; a set frozen at
/// construction left every request to such a repository failing the address
/// screen the moment its name resolved onto RFC1918 — which is the normal shape
/// of an on-prem registry declared in the project's own POM.
///
/// Exactly one thing reads it: the DNS resolver of the client that follows
/// same-origin redirects only ([`RepoClient::http_client_for`]). Growing it
/// therefore widens nothing but the address screen on connections `rv` was
/// already told to make, and no redirect decision anywhere depends on when it
/// grew.
#[derive(Debug, Default, Clone)]
struct TrustedHosts(Arc<RwLock<HashSet<String>>>);

impl TrustedHosts {
    /// Add one host. Idempotent, and normalising on the way in is what keeps a
    /// configured `[fd00::1]` and a runtime `fd00::1` from becoming two
    /// spellings of one host.
    fn insert(&self, host: &str) {
        self.0
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .insert(normalized_host(host));
    }

    fn contains(&self, host: &str) -> bool {
        self.0
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .contains(&normalized_host(host))
    }
}

impl ExemptHosts for TrustedHosts {
    fn contains(&self, host: &str) -> bool {
        TrustedHosts::contains(self, host)
    }
}

/// Everything the SSRF guards derive from the user's configuration, in the
/// three shapes they consume it.
///
/// `origins` (scheme + host + port) is the authority a redirect can be granted:
/// it gates both which origin may issue a cross-origin redirect and which
/// non-global or proxied target may be followed. It is fixed at construction
/// from `rv.toml` alone. Repositories trusted later at runtime deliberately do
/// *not* join it: trusting the root POM's registry means fetching from the URL
/// it names, not licensing a hostile mirror to bounce `rv` at any port on that
/// private host.
///
/// `exempt_hosts` is bare hostnames, because a resolver only ever sees a name,
/// never a port. It is consumed by the redirect-capable client's
/// [`GlobalOnlyResolver`] and, for the one rejection below that depends on
/// knowing the resolver will stand down, by [`RedirectGuard::screen_target`].
/// It is deliberately *wider* than `origins`: it also carries configured proxy
/// hosts, so a corporate proxy at `proxy.corp` on an RFC1918 address stays
/// connectable. A merely exempt host must never turn into a redirect target the
/// user did not name, which is why the policy consults `origins` and never this
/// set for authorisation.
///
/// `proxy_active` records whether any proxy from the user's configuration is
/// attached to the client. Any configured proxy sets it, even one whose
/// `non_proxy_hosts` would send this particular request direct: the policy
/// cannot know at redirect time which route the next request would take, and
/// over-restricting a redirect is the safe direction.
///
/// All three are fixed at construction, and that is load-bearing: the policy
/// and the resolver read `exempt_hosts` at different moments, so a redirect
/// target that was not exempt at policy-evaluation time must be DNS-screened at
/// connect time, regardless of concurrent trust grants. Runtime trust lives in
/// a separate [`TrustedHosts`] set belonging to a separate, same-origin-only
/// client, so no grant can land in that window.
#[derive(Debug, Default, Clone)]
struct RedirectGuard {
    origins: HashSet<String>,
    exempt_hosts: ConfiguredHosts,
    proxy_active: bool,
}

/// Collect the repository, mirror and proxy endpoints the guards screen against.
fn redirect_guard(config: &Config) -> Result<RedirectGuard> {
    let mut guard = RedirectGuard::default();
    let mut exempt_hosts = HashSet::new();
    for configured_url in config
        .repositories()
        .iter()
        .map(|repository| repository.url.as_str())
        .chain(config.mirrors().iter().map(|mirror| mirror.url.as_str()))
    {
        let url = Url::parse(configured_url)?;
        if let Some(origin) = origin_key(&url) {
            guard.origins.insert(origin);
            if let Some(host) = url.host_str() {
                exempt_hosts.insert(host.to_string());
            }
        }
    }
    for proxy in config.proxies() {
        guard.proxy_active = true;
        exempt_hosts.insert(proxy.host.clone());
    }
    guard.exempt_hosts = ConfiguredHosts::new(exempt_hosts);
    Ok(guard)
}

/// Normalise a configured host for comparison against a DNS name. Bracketed
/// IPv6 literals never reach a resolver, but stripping the brackets keeps the
/// set free of two spellings of one host.
fn normalized_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// Longest redirect chain followed before the request is abandoned.
const MAX_REDIRECT_HOPS: usize = 5;

/// Follow same-origin redirects plus one explicitly trusted cross-origin hop.
///
/// The issuer of the cross-origin redirect must be a repository or mirror
/// origin present when the client was built. Both sides of that hop must use
/// HTTPS, and any later redirect must stay on the new origin. The chain is
/// capped at [`MAX_REDIRECT_HOPS`] redirects.
///
/// The cross-origin target must also be a public-internet address, established
/// by one of three screens depending on what `rv` can know at redirect time:
///
/// * An IP literal carries its address, so it is screened here.
/// * A hostname normally carries none, so it is screened by
///   [`GlobalOnlyResolver`] at connect time, which is also what closes the
///   check-then-use window a policy-side resolution would open.
/// * A hostname is screened *here* instead whenever the resolver could not do
///   it: when a proxy is active the name is resolved by the proxy and never
///   reaches the resolver, and when the host sits in the resolver's exempt set
///   the resolver waves it through by design.
///
/// Non-global targets are allowed only when the target origin — scheme, host
/// *and port* — is itself a configured repository or mirror, so pointing `rv`
/// at an on-prem registry stays a decision the user makes in `rv.toml`. Host-level
/// trust is not enough: configuring `https://nexus.corp` must not license a
/// redirect to `https://nexus.corp:8443`, which is a different service on the
/// same private machine.
///
/// The proxy case is the strictest, because a proxy dissolves the distinction
/// between public and private that every other screen rests on: `rv` hands the
/// proxy a name and the proxy resolves and connects on its behalf, so
/// `https://admin.internal/` becomes an internal connection made by a host that
/// can reach it. A proxied cross-origin redirect to a hostname is therefore
/// followed only to a configured origin. Users behind a proxy whose repository
/// redirects to a CDN must name that CDN origin in their configuration.
///
/// reqwest's default policy follows redirects to any origin, which would let a
/// hostile mirror bounce a fetch to `http://attacker/` and bypass both
/// `Repository::url_for_path`'s origin check and TLS, or aim it at
/// `https://169.254.169.254/` and turn `rv` into an SSRF probe for the private
/// network it runs on.
fn trusted_redirect_policy(guard: RedirectGuard) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let decision = guard.evaluate(attempt.previous(), attempt.url());
        match decision {
            Ok(()) => attempt.follow(),
            Err(rejection) => attempt.error(rejection),
        }
    })
}

impl RedirectGuard {
    /// Decide a single redirect hop. Split out of the policy closure so each
    /// branch is unit-testable without staging a server per case.
    fn evaluate(
        &self,
        previous: &[Url],
        target: &Url,
    ) -> std::result::Result<(), RedirectPolicyError> {
        if previous.len() >= MAX_REDIRECT_HOPS {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::ChainLimit,
                details: format!(
                    "redirect chain reached {MAX_REDIRECT_HOPS} hops before {}",
                    redact_url(target)
                ),
            });
        }

        let Some(issuer) = previous.last() else {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::OriginNotConfigured,
                details: format!(
                    "redirect to {} has no issuing request origin",
                    redact_url(target)
                ),
            });
        };
        if issuer.origin() == target.origin() {
            return Ok(());
        }

        let prior_cross_origin_hops = previous
            .windows(2)
            .filter(|pair| pair[0].origin() != pair[1].origin())
            .count();
        if prior_cross_origin_hops > 0 {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::SecondCrossOriginHop,
                details: format!(
                    "redirect chain already crossed origin once; refusing {} -> {}",
                    issuer.origin().ascii_serialization(),
                    redact_url(target)
                ),
            });
        }

        let issuer_origin = issuer.origin().ascii_serialization();
        if !self.origins.contains(&issuer_origin) {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::OriginNotConfigured,
                details: format!(
                    "redirect issuer {issuer_origin} is not a configured repository or mirror"
                ),
            });
        }
        if issuer.scheme() != "https" {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::InsecureOrigin,
                details: format!(
                    "plain-http configured origin {issuer_origin} may redirect only within its own origin"
                ),
            });
        }
        if target.scheme() != "https" {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::HttpsDowngrade,
                details: format!(
                    "redirect from {issuer_origin} to {} would downgrade transport",
                    redact_url(target)
                ),
            });
        }

        self.screen_target(target, &issuer_origin)
    }

    /// Screen the address the cross-origin target names, or the authority that
    /// will resolve it on `rv`'s behalf.
    fn screen_target(
        &self,
        target: &Url,
        issuer_origin: &str,
    ) -> std::result::Result<(), RedirectPolicyError> {
        let Some(host) = target.host() else {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::NonGlobalTarget,
                details: format!("redirect target {} has no host", redact_url(target)),
            });
        };
        let domain = match host {
            url::Host::Domain(domain) => domain,
            url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
                return match non_global_literal_target(target, &self.origins) {
                    Some(details) => Err(RedirectPolicyError {
                        kind: RedirectRejectionKind::NonGlobalTarget,
                        details,
                    }),
                    None => Ok(()),
                };
            }
        };

        if self
            .origins
            .contains(&target.origin().ascii_serialization())
        {
            return Ok(());
        }
        if self.proxy_active {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::ProxiedTargetNotConfigured,
                details: format!(
                    "a proxy would resolve and connect to {} on rv's behalf, so {issuer_origin} \
                     may redirect only to a configured repository or mirror origin",
                    redact_url(target)
                ),
            });
        }
        // This client's resolver waves an exempt host through, so this is the
        // only screen left standing between a hostile mirror and an
        // unconfigured port on that private host. The set is frozen, so what is
        // decided here is what the resolver will see: a redirect target that was
        // not exempt at policy-evaluation time must be DNS-screened at connect
        // time, regardless of concurrent trust grants.
        if self.exempt_hosts.contains(domain) {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::ExemptHostOriginMismatch,
                details: format!(
                    "{domain} is exempt from the address screen because it is configured, but \
                     {} is not a configured origin",
                    redact_url(target)
                ),
            });
        }
        // Nothing exempts this name, so the resolver screens its addresses when
        // the connection is made.
        Ok(())
    }
}

/// Reject a cross-origin target whose host is an IP literal outside the public
/// internet. Hostname targets carry no address at this point and are screened
/// by [`GlobalOnlyResolver`] instead.
fn non_global_literal_target(target: &Url, trusted_origins: &HashSet<String>) -> Option<String> {
    let addr = match target.host()? {
        url::Host::Ipv4(addr) => IpAddr::V4(addr),
        url::Host::Ipv6(addr) => IpAddr::V6(addr),
        url::Host::Domain(_) => return None,
    };
    if is_globally_routable(addr)
        || trusted_origins.contains(&target.origin().ascii_serialization())
    {
        return None;
    }
    Some(format!(
        "redirect target {} resolves to non-global address {addr}",
        redact_url(target)
    ))
}

/// DNS resolver that refuses any name resolving outside the public internet.
///
/// Screening here rather than in the redirect policy is what closes the
/// check-then-use window: hyper connects to exactly the addresses returned
/// below, so a name cannot answer with a public address for the check and a
/// private one for the connection. IP literals never reach a resolver, which is
/// why [`non_global_literal_target`] screens those separately.
///
/// A request routed through a configured proxy resolves at the proxy, so only
/// the proxy host passes through here. That is why the proxy host itself is
/// exempt (it is trusted by configuration and routinely private) and why
/// [`RedirectGuard::screen_target`] takes over the target screening whenever a
/// proxy is active.
struct GlobalOnlyResolver<E: ExemptHosts> {
    /// Hosts allowed to sit on a non-global address because the user named
    /// them, whether in `rv.toml` or in the project's own POM: an on-prem
    /// registry at `nexus.corp.internal` or a proxy at `proxy.corp` is a
    /// deliberate choice, not an SSRF target.
    ///
    /// Which kind of set this is decides what the client owning this resolver
    /// may do. [`ConfiguredHosts`] is frozen and pairs with the redirect policy
    /// on the redirect-capable client: a target that policy passed on the
    /// expectation of being screened here still is, because nothing can join
    /// the set in between. [`TrustedHosts`] grows mid-resolve and pairs with
    /// the same-origin-only client, which follows nothing the policy had to
    /// pass judgement on.
    ///
    /// Exemption is host-level and therefore port-blind, so it cannot stand in
    /// for authorisation. A redirect to a merely-exempt host is rejected by the
    /// policy before any connection is attempted; what reaches here is a direct
    /// request to a trusted endpoint, a hop the policy already matched
    /// against a full configured origin, or a connection to a proxy.
    exempt_hosts: E,
}

impl<E: ExemptHosts> Resolve for GlobalOnlyResolver<E> {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_ascii_lowercase();
        // Read per resolution, not per client: the runtime set grows while a
        // resolve runs.
        let exempt = self.exempt_hosts.contains(&host);
        Box::pin(async move {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0_u16))
                .await
                .map_err(ResolveError::from)?
                .collect();
            let screened = screen_resolved_addrs(&host, exempt, resolved)?;
            Ok(Box::new(screened.into_iter()) as Addrs)
        })
    }
}

type ResolveError = Box<dyn std::error::Error + Send + Sync>;

/// Reject the whole answer when any address in it is non-global, rather than
/// filtering: a hostile authoritative server can return a public and a private
/// address together and let connection ordering pick the private one.
fn screen_resolved_addrs(
    host: &str,
    exempt: bool,
    addrs: Vec<SocketAddr>,
) -> std::result::Result<Vec<SocketAddr>, RedirectPolicyError> {
    if exempt {
        return Ok(addrs);
    }
    match addrs.iter().find(|addr| !is_globally_routable(addr.ip())) {
        Some(blocked) => Err(RedirectPolicyError {
            kind: RedirectRejectionKind::NonGlobalTarget,
            details: format!("{host} resolves to non-global address {}", blocked.ip()),
        }),
        None => Ok(addrs),
    }
}

/// Whether an address is a plausible public-internet destination.
///
/// `IpAddr::is_global` is still unstable, so the non-global ranges are spelled
/// out here, following std's nightly implementation (`core::net::Ipv4Addr::
/// is_global` / `Ipv6Addr::is_global`) and the IANA special-purpose address
/// registries it is derived from. Three deliberate departures from std, all
/// erring towards rejection:
///
/// * std preserves the globally-reachable carve-outs inside otherwise-reserved
///   blocks: 192.0.0.9/32 (PCP anycast) and 192.0.0.10/32 (NAT64 discovery) in
///   192.0.0.0/24, and the PCP/TURN/AMT/AS112 addresses in 2001::/23. Each whole
///   block is excluded here instead. No Maven repository is served from one, and
///   one predicate per block is easier to audit than a predicate plus its holes.
/// * std treats 6to4 (2002::/16) and Teredo (2001::/32, inside 2001::/23) as
///   reachable. Both encode an arbitrary IPv4 address in the destination, which
///   is precisely the laundering step this screen exists to stop, so both are
///   excluded.
/// * std does not cover the 6to4 relay anycast prefix (192.88.99.0/24, whose
///   IANA entry became non-global when RFC 7526 deprecated it) or the dummy
///   prefix (100:0:0:1::/64, RFC 9780). Neither can carry a real destination,
///   and the first relays into the 6to4 addressing excluded above.
///
/// IPv4 addresses embedded in IPv6 are unwrapped first so `[::ffff:10.0.0.1]`
/// cannot smuggle an RFC1918 target past the check.
fn is_globally_routable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => is_globally_routable_v4(addr),
        IpAddr::V6(addr) => is_globally_routable_v6(addr),
    }
}

fn is_globally_routable_v4(addr: Ipv4Addr) -> bool {
    let [first, second, third, _] = addr.octets();
    !(addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_multicast()
        // 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
        || addr.is_documentation()
        // "This network" (0.0.0.0/8), which subsumes the unspecified address.
        || first == 0
        // IETF protocol assignments (192.0.0.0/24), carve-outs included.
        || (first == 192 && second == 0 && third == 0)
        // Deprecated 6to4 relay anycast (192.88.99.0/24).
        || (first == 192 && second == 88 && third == 99)
        // Shared address space (100.64.0.0/10), benchmarking (198.18.0.0/15)
        // and reserved (240.0.0.0/4) have no stable std predicate.
        || (first == 100 && (64..128).contains(&second))
        || (first == 198 && second & 0xfe == 18)
        || first >= 240)
}

fn is_globally_routable_v6(addr: Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    if let Some(mapped) = embedded_ipv4(addr) {
        return is_globally_routable_v4(mapped);
    }
    let segments = addr.segments();
    let [first, second, third, fourth, ..] = segments;
    !(
        // Unique-local (fc00::/7) and link-local (fe80::/10).
        first & 0xfe00 == 0xfc00
        || first & 0xffc0 == 0xfe80
        // Site-local (fec0::/10). Deprecated by RFC 3879 but still routed on
        // legacy networks, and never a public destination.
        || first & 0xffc0 == 0xfec0
        // Discard-only (100::/64).
        || (first == 0x0100 && second == 0 && third == 0 && fourth == 0)
        // Dummy prefix (100:0:0:1::/64), reserved by RFC 9780 as a placeholder
        // that is never routed.
        || (first == 0x0100 && second == 0 && third == 0 && fourth == 1)
        // IETF protocol assignments (2001::/23): Teredo, benchmarking,
        // ORCHIDv2 and friends, excluded as one block (see above).
        || (first == 0x2001 && second < 0x0200)
        // Documentation (2001:db8::/32 and 3fff::/20).
        || (first == 0x2001 && second == 0x0db8)
        || (first == 0x3fff && second <= 0x0fff)
        // 6to4 (2002::/16).
        || first == 0x2002
        // Local-use IPv4/IPv6 translation (64:ff9b:1::/48). The well-known
        // NAT64 prefix 64:ff9b::/96 is globally reachable and handled by
        // `embedded_ipv4` instead.
        || (first == 0x0064 && second == 0xff9b && third == 0x0001)
        // Segment Routing (SRv6) SIDs (5f00::/16).
        || first == 0x5f00
    )
}

/// Unwrap the IPv4-mapped (`::ffff:a.b.c.d`), deprecated IPv4-compatible
/// (`::a.b.c.d`) and well-known NAT64 (`64:ff9b::a.b.c.d`) forms. Callers must
/// have ruled out `::` and `::1` first, since both also match the compatible
/// prefix.
///
/// NAT64 is unwrapped rather than rejected outright: on a DNS64 network every
/// public destination arrives in this shape, so excluding the prefix would
/// break IPv6-only clients, while screening the address it carries is what
/// keeps `64:ff9b::10.0.0.1` out.
fn embedded_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let embedded = matches!(
        addr.segments(),
        [0, 0, 0, 0, 0, 0 | 0xffff, ..] | [0x0064, 0xff9b, 0, 0, 0, 0, ..]
    );
    if !embedded {
        return None;
    }
    let octets = addr.octets();
    Some(Ipv4Addr::new(
        octets[12], octets[13], octets[14], octets[15],
    ))
}

/// Strict same-origin policy retained for callers that do not have a resolved
/// repository configuration. Production `RepoClient` instances use
/// [`trusted_redirect_policy`] with the configured repository and mirror
/// origins.
pub fn same_origin_redirect_policy() -> reqwest::redirect::Policy {
    trusted_redirect_policy(RedirectGuard::default())
}

pub(crate) fn redirect_rejection_from_reqwest(
    error: &reqwest::Error,
) -> Option<(RedirectRejectionKind, String)> {
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(policy_error) = current.downcast_ref::<RedirectPolicyError>() {
            return Some((policy_error.kind, policy_error.details.clone()));
        }
        source = current.source();
    }
    None
}

/// Periodically prunes expired cache rows. Runs every Nth blocking
/// invocation so we amortise the cleanup over real traffic without a
/// dedicated background task.
static CLEANUP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn cache_cleanup_tick(cache: &MetadataCache) {
    let count = CLEANUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if count.is_multiple_of(100)
        && let Err(err) = cache.cleanup_expired()
    {
        warn!(error = %err, "failed to cleanup expired cache entries");
    }
}

/// Validate coordinate components for path-traversal / SSRF safety before
/// they are incorporated into any URL path. Reuses the same character-level
/// rules as [`crate::artifact::ArtifactRequest::validate`].
///
/// Returns `RepoError::InvalidCoord` if any component is unsafe.
fn validate_coord_components(
    group_id: &str,
    artifact_id: &str,
    version: Option<&str>,
) -> Result<()> {
    validate_one_component(group_id, "group_id")?;
    validate_one_component(artifact_id, "artifact_id")?;
    if let Some(v) = version {
        validate_one_component(v, "version")?;
    }
    Ok(())
}

/// Single-component check. Delegates to the shared
/// [`crate::artifact::validate_coordinate_component`] gate so the URL-path
/// validation rules (empty, `..`, path separators, URL-significant and control
/// characters) stay identical across the crate; only the error type differs.
fn validate_one_component(component: &str, field: &str) -> Result<()> {
    crate::artifact::validate_coordinate_component(component, field)
        .map_err(RepoError::InvalidCoord)
}

fn metadata_path(group_id: &str, artifact_id: &str, version: Option<&str>) -> String {
    let group_path = group_id.replace('.', "/");
    match version {
        Some(version) => format!(
            "{}/{}/{}/maven-metadata.xml",
            group_path, artifact_id, version
        ),
        None => format!("{}/{}/maven-metadata.xml", group_path, artifact_id),
    }
}

fn snapshot_timestamp_from_version(version: &str) -> Option<String> {
    static TIMESTAMP_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"-(\d{8}\.\d{6})-\d+$").expect("snapshot regex"));
    let caps = TIMESTAMP_RE.captures(version)?;
    caps.get(1).map(|m| m.as_str().to_string())
}

fn snapshot_dir_version(version: &str) -> Option<String> {
    if version.ends_with("-SNAPSHOT") {
        return Some(version.to_string());
    }
    static DIR_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(.*)-\d{8}\.\d{6}-\d+$").expect("snapshot dir regex"));
    let caps = DIR_RE.captures(version)?;
    let base = caps.get(1)?.as_str();
    Some(format!("{base}-SNAPSHOT"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{metadata_path, snapshot_dir_version, snapshot_timestamp_from_version};
    use crate::auth::AuthStore;
    use crate::cache::MetadataCache;
    use crate::mirror::MirrorSelector;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use secrecy::Secret;
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn plain_test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(same_origin_redirect_policy())
            .user_agent(USER_AGENT)
            .build()
            .expect("client")
    }

    /// Build a minimal in-process `RepoClient`, skipping `Config` so tests can
    /// isolate fetch/checksum/mirror logic. The returned `TempDir` must outlive
    /// the `RepoClient`: dropping it deletes the on-disk SQLite cache that
    /// `MetadataCache` holds open.
    fn test_client() -> (RepoClient, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
        let client = RepoClient {
            client: plain_test_client(),
            runtime_client: plain_test_client(),
            auth: AuthStore::default(),
            mirrors: MirrorSelector::default(),
            fetch: FetchConfig::default(),
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            configured_hosts: ConfiguredHosts::default(),
            trusted_hosts: TrustedHosts::default(),
        };
        (client, tmp)
    }

    fn test_client_with_mirrors(
        mirrors: Vec<rv_config::MirrorConfig>,
    ) -> (RepoClient, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
        let client = RepoClient {
            client: plain_test_client(),
            runtime_client: plain_test_client(),
            auth: AuthStore::default(),
            mirrors: MirrorSelector::from_mirrors(mirrors),
            fetch: FetchConfig {
                retries: 0,
                timeout: Duration::from_secs(5),
            },
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            configured_hosts: ConfiguredHosts::default(),
            trusted_hosts: TrustedHosts::default(),
        };
        (client, tmp)
    }

    /// Boxed per-connection response handler for the test stub.
    type StubHandler = Box<dyn Fn(&str) -> Vec<u8> + Send + Sync>;

    /// One-shot stub. The handler runs against the raw request bytes (so it
    /// can inspect the Proxy-Authorization header) and returns a fixed
    /// response for each connection. The handler index increments per
    /// connection.
    async fn spawn_stub_seq(responses: Vec<StubHandler>) -> (std::net::SocketAddr, Arc<AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connections = Arc::new(AtomicU32::new(0));
        let connections_clone = connections.clone();
        let responses = Arc::new(responses);
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let idx = connections_clone.fetch_add(1, Ordering::SeqCst) as usize;
                let responses = responses.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        if n == 0 {
                            return;
                        }
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&total).into_owned();
                    if let Some(handler) = responses.get(idx) {
                        let response = handler(&request);
                        let _ = sock.write_all(&response).await;
                    }
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, connections)
    }

    // Self-signed localhost certificate used only by the in-process redirect
    // stubs. The reqwest clients below opt into accepting it.
    const TEST_CERT_DER: &str = "308201993082013fa00302010202142edbe5ec174441664b0b0f3b828a97fe31e81747300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3236303732343233343131335a170d3336303732313233343131335a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004325fb4c3e179b836c763009e555ff7709191f1fec299a00a5cfb7a34d99fe02e9c346670096f9bd5c4a8b3d2acf3b1894646cb99f04584a20f3492fd8e99cc4ba36f306d301d0603551d0e04160414730484bd1929ef7f056e4256368807a07197a43c301f0603551d23041830168014730484bd1929ef7f056e4256368807a07197a43c300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300a06082a8648ce3d040302034800304502210099131112ae00cf55f0d34b1283ced2c520d4d9c029dfe2ccafc327456953de66022029cbd4d385d2d1d11fd11550073ccfaf8a1c6d2e6febe89f9439c928b33c78fe";
    const TEST_KEY_DER: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104200e9f9cb30589ef41f37a668cc1928b38f76ca3c443feb73aef12380ccac2f9a9a14403420004325fb4c3e179b836c763009e555ff7709191f1fec299a00a5cfb7a34d99fe02e9c346670096f9bd5c4a8b3d2acf3b1894646cb99f04584a20f3492fd8e99cc4b";

    struct HttpsStub {
        addr: std::net::SocketAddr,
        request: Arc<Mutex<Option<String>>>,
    }

    fn spawn_https_stub(handler: impl Fn(&str) -> Vec<u8> + Send + 'static) -> HttpsStub {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = CertificateDer::from(hex::decode(TEST_CERT_DER).expect("test certificate"));
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            hex::decode(TEST_KEY_DER).expect("test private key"),
        ));
        let tls = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("test TLS config"),
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind HTTPS stub");
        let addr = listener.local_addr().expect("HTTPS stub address");
        let request = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&request);
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept HTTPS stub");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let connection =
                rustls::ServerConnection::new(tls).expect("create TLS server connection");
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).expect("read HTTPS request");
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..read]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let raw_request = String::from_utf8_lossy(&bytes).into_owned();
            *captured.lock().expect("capture HTTPS request") = Some(raw_request.clone());
            stream
                .write_all(&handler(&raw_request))
                .expect("write HTTPS response");
            stream.flush().expect("flush HTTPS response");
        });
        HttpsStub { addr, request }
    }

    fn redirect_response(location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    fn ok_response(body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    /// A guard for a configuration that named exactly these origins. Mirrors
    /// `redirect_guard`: naming an origin also exempts its host from the
    /// address screen.
    fn origins_guard(origins: HashSet<String>) -> RedirectGuard {
        let exempt_hosts: Vec<String> = origins
            .iter()
            .filter_map(|origin| Url::parse(origin).ok())
            .filter_map(|origin| origin.host_str().map(str::to_string))
            .collect();
        RedirectGuard {
            origins,
            exempt_hosts: ConfiguredHosts::new(exempt_hosts),
            proxy_active: false,
        }
    }

    fn redirect_test_client(trusted_origins: HashSet<String>) -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .redirect(trusted_redirect_policy(origins_guard(trusted_origins)))
            .build()
            .expect("redirect test client")
    }

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("test URL")
    }

    fn origin_set<const N: usize>(raw: [&str; N]) -> HashSet<String> {
        raw.iter()
            .map(|value| url(value).origin().ascii_serialization())
            .collect()
    }

    /// A runtime (growable) exemption set, as `trust_repositories` builds one.
    fn host_set<const N: usize>(raw: [&str; N]) -> TrustedHosts {
        let hosts = TrustedHosts::default();
        for host in raw {
            hosts.insert(host);
        }
        hosts
    }

    /// A configured (frozen) exemption set, as `redirect_guard` builds one.
    fn frozen_hosts<const N: usize>(raw: [&str; N]) -> ConfiguredHosts {
        ConfiguredHosts::new(raw.iter().map(|host| host.to_string()))
    }

    async fn fetch_redirect_test(client: &reqwest::Client, url: &Url) -> Result<Bytes> {
        fetch_bytes(
            client,
            url,
            None,
            &FetchConfig {
                retries: 0,
                timeout: Duration::from_secs(5),
            },
            None,
        )
        .await
    }

    /// The stubs live on loopback, which the address guard rejects unless the
    /// target origin is configured too — so this configures both, the shape a
    /// user gets from an on-prem registry pair.
    #[tokio::test]
    async fn trusted_https_cross_origin_redirect_strips_sensitive_headers() {
        let target = spawn_https_stub(|_| ok_response(b"artifact bytes"));
        let target_url = format!("https://127.0.0.1:{}/artifact", target.addr.port());
        let source_location = target_url.clone();
        let source = spawn_https_stub(move |_| redirect_response(&source_location));
        let source_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
        let trusted = HashSet::from([
            source_url.origin().ascii_serialization(),
            Url::parse(&target_url)
                .unwrap()
                .origin()
                .ascii_serialization(),
        ]);
        let client = redirect_test_client(trusted);

        let response = client
            .get(source_url)
            .bearer_auth("registry-secret")
            .header(reqwest::header::COOKIE, "session=private")
            .send()
            .await
            .expect("trusted HTTPS redirect should succeed");
        assert_eq!(
            response.bytes().await.expect("response bytes"),
            Bytes::from_static(b"artifact bytes")
        );

        let source_request = source
            .request
            .lock()
            .expect("source request")
            .clone()
            .expect("source contacted");
        let target_request = target
            .request
            .lock()
            .expect("target request")
            .clone()
            .expect("target contacted");
        assert!(
            source_request
                .to_ascii_lowercase()
                .contains("authorization: bearer registry-secret"),
            "configured source must receive its Authorization header"
        );
        let target_request = target_request.to_ascii_lowercase();
        assert!(
            !target_request.contains("authorization:"),
            "redirect target must not receive Authorization"
        );
        assert!(
            !target_request.contains("cookie:"),
            "redirect target must not receive Cookie"
        );
    }

    #[tokio::test]
    async fn trusted_origin_rejects_loopback_target() {
        let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
        let target_url = format!("https://127.0.0.1:{}/artifact", target.addr.port());
        let source = spawn_https_stub(move |_| redirect_response(&target_url));
        let source_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
        let trusted = HashSet::from([source_url.origin().ascii_serialization()]);
        let client = redirect_test_client(trusted);

        let error = fetch_redirect_test(&client, &source_url)
            .await
            .expect_err("loopback redirect target must be rejected");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::NonGlobalTarget,
                    ..
                }
            ),
            "expected explicit non-global rejection, got {error:?}"
        );
        assert!(
            target.request.lock().expect("target request").is_none(),
            "loopback target must not be contacted"
        );
    }

    #[tokio::test]
    async fn trusted_origin_rejects_non_global_literal_targets() {
        for target_url in [
            "https://127.0.0.1/artifact",
            "https://10.0.0.1/artifact",
            "https://172.16.0.1/artifact",
            "https://192.168.1.10/artifact",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/artifact",
            "https://[::ffff:10.0.0.1]/artifact",
            "https://[fd00::1]/artifact",
        ] {
            let source = spawn_https_stub(move |_| redirect_response(target_url));
            let source_url =
                Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
            let trusted = HashSet::from([source_url.origin().ascii_serialization()]);
            let client = redirect_test_client(trusted);

            let error = fetch_redirect_test(&client, &source_url)
                .await
                .err()
                .unwrap_or_else(|| panic!("{target_url} must be rejected"));
            assert!(
                matches!(
                    error,
                    RepoError::RedirectRejected {
                        kind: RedirectRejectionKind::NonGlobalTarget,
                        ..
                    }
                ),
                "expected non-global rejection for {target_url}, got {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn trusted_origin_rejects_https_to_http_downgrade() {
        let (target_addr, target_hits) =
            spawn_stub_seq(vec![Box::new(|_| ok_response(b"no"))]).await;
        let target_url = format!("http://{target_addr}/artifact");
        let source = spawn_https_stub(move |_| redirect_response(&target_url));
        let source_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
        let trusted = HashSet::from([source_url.origin().ascii_serialization()]);
        let client = redirect_test_client(trusted);

        let error = fetch_redirect_test(&client, &source_url)
            .await
            .expect_err("HTTPS downgrade must be rejected");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::HttpsDowngrade,
                    ..
                }
            ),
            "expected explicit HTTPS downgrade rejection, got {error:?}"
        );
        assert!(
            error.to_string().contains("target is not HTTPS"),
            "rendered error must name the downgrade: {error}"
        );
        assert_eq!(
            target_hits.load(Ordering::SeqCst),
            0,
            "downgrade target must not be contacted"
        );
    }

    #[tokio::test]
    async fn redirect_policy_rejects_second_cross_origin_hop() {
        let final_target = spawn_https_stub(|_| ok_response(b"must not arrive"));
        let final_url = format!("https://127.0.0.1:{}/artifact", final_target.addr.port());
        let middle = spawn_https_stub(move |_| redirect_response(&final_url));
        let middle_url = format!("https://127.0.0.1:{}/middle", middle.addr.port());
        let middle_origin = middle_url.clone();
        let first = spawn_https_stub(move |_| redirect_response(&middle_url));
        let first_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", first.addr.port())).unwrap();
        // The middle origin is configured so the first hop clears the address
        // guard and the second hop is what fails.
        let trusted = HashSet::from([
            first_url.origin().ascii_serialization(),
            Url::parse(&middle_origin)
                .unwrap()
                .origin()
                .ascii_serialization(),
        ]);
        let client = redirect_test_client(trusted);

        let error = fetch_redirect_test(&client, &first_url)
            .await
            .expect_err("second cross-origin hop must be rejected");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::SecondCrossOriginHop,
                    ..
                }
            ),
            "expected explicit second-hop rejection, got {error:?}"
        );
        assert!(
            error.to_string().contains("second cross-origin hop"),
            "rendered error must name the second hop: {error}"
        );
        assert!(
            middle.request.lock().expect("middle request").is_some(),
            "first cross-origin target should be contacted"
        );
        assert!(
            final_target
                .request
                .lock()
                .expect("final request")
                .is_none(),
            "second cross-origin target must not be contacted"
        );
    }

    #[tokio::test]
    async fn redirect_policy_names_unconfigured_issuing_origin() {
        let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
        let target_url = format!("https://127.0.0.1:{}/artifact", target.addr.port());
        let source = spawn_https_stub(move |_| redirect_response(&target_url));
        let source_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
        let source_origin = source_url.origin().ascii_serialization();
        let client = redirect_test_client(HashSet::new());

        let error = fetch_redirect_test(&client, &source_url)
            .await
            .expect_err("unconfigured redirect issuer must be rejected");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::OriginNotConfigured,
                    ..
                }
            ),
            "expected explicit unconfigured-origin rejection, got {error:?}"
        );
        assert!(
            error.to_string().contains(&source_origin),
            "rendered error must name untrusted origin {source_origin}: {error}"
        );
        assert!(
            target.request.lock().expect("target request").is_none(),
            "target of an untrusted redirect must not be contacted"
        );
    }

    /// Minimal CONNECT-capable stub proxy. Records the request line of every
    /// connection it accepts, so a test can assert exactly which authorities
    /// the client asked it to reach, and tunnels CONNECT through to the real
    /// (loopback) address so a permitted hop can still complete.
    async fn spawn_stub_proxy() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let addr = listener.local_addr().expect("proxy address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut downstream, _)) = listener.accept().await else {
                    return;
                };
                let recorder = Arc::clone(&recorder);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    let mut head = Vec::new();
                    loop {
                        let Ok(read) = downstream.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        head.extend_from_slice(&buffer[..read]);
                        if head.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&head).into_owned();
                    let request_line = request.lines().next().unwrap_or_default().to_string();
                    recorder
                        .lock()
                        .expect("proxy log")
                        .push(request_line.clone());

                    let authority = request_line
                        .strip_prefix("CONNECT ")
                        .and_then(|rest| rest.split_whitespace().next())
                        .map(str::to_string);
                    let Some(authority) = authority else {
                        // Absolute-form GET: answer directly, no upstream.
                        let _ = downstream.write_all(&ok_response(b"proxied")).await;
                        return;
                    };
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(&authority).await else {
                        let _ = downstream
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                            .await;
                        return;
                    };
                    if downstream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .is_ok()
                    {
                        let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                    }
                });
            }
        });
        (addr, seen)
    }

    fn proxied_test_client(
        proxy_url: &str,
        guard: RedirectGuard,
        resolver_exempt: ConfiguredHosts,
    ) -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .proxy(reqwest::Proxy::all(proxy_url).expect("stub proxy"))
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                exempt_hosts: resolver_exempt,
            }))
            .redirect(trusted_redirect_policy(guard))
            .build()
            .expect("proxied test client")
    }

    /// The proxy-bypass blocker. A proxied request never resolves its target
    /// locally, so [`GlobalOnlyResolver`] cannot screen it: without the
    /// proxy-aware branch in the policy, `Location: https://admin.internal/`
    /// becomes a `CONNECT admin.internal:443` that the corporate proxy happily
    /// completes on rv's behalf. The proxy log is the assertion: the internal
    /// name must never be handed to it.
    #[tokio::test]
    async fn proxied_redirect_to_internal_hostname_never_reaches_the_proxy() {
        let (proxy_addr, proxy_log) = spawn_stub_proxy().await;
        let source = spawn_https_stub(|_| redirect_response("https://admin.internal/secret"));
        let source_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
        let guard = RedirectGuard {
            origins: HashSet::from([source_url.origin().ascii_serialization()]),
            exempt_hosts: ConfiguredHosts::default(),
            proxy_active: true,
        };
        let client = proxied_test_client(
            &format!("http://{proxy_addr}"),
            guard,
            frozen_hosts(["127.0.0.1"]),
        );

        let error = fetch_redirect_test(&client, &source_url)
            .await
            .expect_err("internal-hostname redirect must be rejected");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::ProxiedTargetNotConfigured,
                    ..
                }
            ),
            "expected a proxied-target rejection, got {error:?}"
        );

        let log = proxy_log.lock().expect("proxy log").clone();
        assert_eq!(
            log,
            vec![format!("CONNECT 127.0.0.1:{} HTTP/1.1", source.addr.port())],
            "the proxy must see the configured source and nothing else"
        );
        assert!(
            !log.iter().any(|line| line.contains("admin.internal")),
            "the internal name must never be handed to the proxy: {log:?}"
        );
    }

    /// The other half of the proxy story: a configured target origin is still
    /// followed through the proxy, so the guard does not simply break proxied
    /// redirects.
    #[tokio::test]
    async fn proxied_redirect_to_configured_origin_is_followed() {
        let (proxy_addr, proxy_log) = spawn_stub_proxy().await;
        let target = spawn_https_stub(|_| ok_response(b"artifact bytes"));
        let target_url = format!("https://127.0.0.1:{}/artifact", target.addr.port());
        let redirect_to = target_url.clone();
        let source = spawn_https_stub(move |_| redirect_response(&redirect_to));
        let source_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
        let guard = RedirectGuard {
            origins: HashSet::from([
                source_url.origin().ascii_serialization(),
                Url::parse(&target_url)
                    .unwrap()
                    .origin()
                    .ascii_serialization(),
            ]),
            exempt_hosts: ConfiguredHosts::default(),
            proxy_active: true,
        };
        let client = proxied_test_client(
            &format!("http://{proxy_addr}"),
            guard,
            frozen_hosts(["127.0.0.1"]),
        );

        let bytes = fetch_redirect_test(&client, &source_url)
            .await
            .expect("configured target must still be reachable through the proxy");
        assert_eq!(bytes, Bytes::from_static(b"artifact bytes"));
        let log = proxy_log.lock().expect("proxy log").clone();
        assert!(
            log.iter()
                .any(|line| line.contains(&format!("CONNECT 127.0.0.1:{}", target.addr.port()))),
            "the permitted hop must reach the proxy: {log:?}"
        );
    }

    /// A corporate proxy named by hostname that resolves onto RFC1918 must be
    /// dialable: its host is exempt from the address screen. That exemption is
    /// scoped to the resolver, so the redirect target arriving from behind it
    /// is screened exactly as before.
    #[tokio::test]
    async fn private_hostname_proxy_connects_while_target_stays_screened() {
        let (proxy_addr, proxy_log) = spawn_stub_proxy().await;
        let source = spawn_https_stub(|_| redirect_response("https://admin.internal/secret"));
        let source_url =
            Url::parse(&format!("https://127.0.0.1:{}/start", source.addr.port())).unwrap();
        let guard = RedirectGuard {
            origins: HashSet::from([source_url.origin().ascii_serialization()]),
            // `localhost` stands in for `proxy.corp`: a proxy named by hostname
            // that resolves to an address the screen would otherwise reject.
            exempt_hosts: frozen_hosts(["localhost", "127.0.0.1"]),
            proxy_active: true,
        };
        let proxy_url = format!("http://localhost:{}", proxy_addr.port());
        let client = proxied_test_client(&proxy_url, guard.clone(), guard.exempt_hosts.clone());

        let error = fetch_redirect_test(&client, &source_url)
            .await
            .expect_err("internal-hostname redirect must be rejected");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::ProxiedTargetNotConfigured,
                    ..
                }
            ),
            "expected a proxied-target rejection, got {error:?}"
        );
        let log = proxy_log.lock().expect("proxy log").clone();
        assert_eq!(
            log,
            vec![format!("CONNECT 127.0.0.1:{} HTTP/1.1", source.addr.port())],
            "the private-address proxy must have been reachable, and only for the source"
        );

        // Drop the proxy host from the resolver exemption and the same client
        // cannot even reach its proxy, which is what finding 4 was about.
        let unexempt = proxied_test_client(&proxy_url, guard, ConfiguredHosts::default());
        let error = fetch_redirect_test(&unexempt, &source_url)
            .await
            .expect_err("an unexempt private proxy host must not resolve");
        assert!(
            error.to_string().contains("localhost"),
            "rejection must name the host it refused to resolve: {error}"
        );
        assert_eq!(
            proxy_log.lock().expect("proxy log").len(),
            1,
            "no further connection may reach the proxy"
        );
    }

    /// The DNS exemption is host-level, so authorisation must not be.
    /// Configuring `https://nexus.corp` (port 443) exempts the *name* from the
    /// address screen; letting that exemption carry a redirect to
    /// `https://nexus.corp:8443` would hand a hostile mirror a port scanner
    /// pointed at a private host the user only meant to fetch artifacts from.
    #[test]
    fn redirect_to_exempt_host_requires_the_configured_origin() {
        let guard = RedirectGuard {
            origins: origin_set(["https://mirror.example", "https://nexus.corp"]),
            exempt_hosts: frozen_hosts(["mirror.example", "nexus.corp"]),
            proxy_active: false,
        };
        let previous = [url("https://mirror.example/demo-1.0.jar")];

        let rejection = guard
            .evaluate(&previous, &url("https://nexus.corp:8443/demo-1.0.jar"))
            .expect_err("a different port is a different service");
        assert_eq!(
            rejection.kind,
            RedirectRejectionKind::ExemptHostOriginMismatch
        );
        assert!(
            rejection.details.contains("nexus.corp:8443"),
            "rejection must name the origin it refused: {}",
            rejection.details
        );

        guard
            .evaluate(&previous, &url("https://nexus.corp/demo-1.0.jar"))
            .expect("the configured origin is still followed");
        // An unexempt name carries no address here and no exemption later, so
        // the policy defers to the resolver rather than second-guessing it.
        guard
            .evaluate(&previous, &url("https://cdn.example/demo-1.0.jar"))
            .expect("unexempt hostname is screened by the resolver");
    }

    /// With a proxy in play the proxy resolves hostnames, so
    /// [`GlobalOnlyResolver`] never sees the target and a hostname hop is
    /// followed only to an origin the user configured.
    #[test]
    fn proxied_redirect_requires_a_configured_target_origin() {
        let guard = RedirectGuard {
            origins: origin_set(["https://mirror.example", "https://cdn.example"]),
            exempt_hosts: frozen_hosts(["mirror.example", "cdn.example", "proxy.corp"]),
            proxy_active: true,
        };
        let previous = [url("https://mirror.example/demo-1.0.jar")];

        for target in [
            "https://admin.internal/",
            "https://cdn.example:8443/demo-1.0.jar",
            "https://elsewhere.example/demo-1.0.jar",
            // Finding 4's exemption must not become authority: the proxy host
            // is connectable, not a legitimate redirect target.
            "https://proxy.corp/demo-1.0.jar",
        ] {
            let Err(rejection) = guard.evaluate(&previous, &url(target)) else {
                panic!("{target} must not be followed through a proxy");
            };
            assert_eq!(
                rejection.kind,
                RedirectRejectionKind::ProxiedTargetNotConfigured,
                "unexpected rejection for {target}: {rejection}"
            );
        }

        guard
            .evaluate(&previous, &url("https://cdn.example/demo-1.0.jar"))
            .expect("a configured origin is still reachable through the proxy");
        // IP literals still carry their address, so the literal screen decides.
        guard
            .evaluate(&previous, &url("https://93.184.216.34/demo-1.0.jar"))
            .expect("global literal target stays followable");
        let rejection = guard
            .evaluate(&previous, &url("https://169.254.169.254/latest/meta-data"))
            .expect_err("non-global literal stays rejected under a proxy");
        assert_eq!(rejection.kind, RedirectRejectionKind::NonGlobalTarget);
    }

    /// A proxy host is exempt from the address screen so it can be dialled, and
    /// nothing more: with no proxy active the same host is still refused as a
    /// redirect target because no configured origin matches it.
    #[test]
    fn exempt_proxy_host_is_not_a_redirect_target() {
        let guard = RedirectGuard {
            origins: origin_set(["https://mirror.example"]),
            exempt_hosts: frozen_hosts(["mirror.example", "proxy.corp"]),
            proxy_active: false,
        };
        let previous = [url("https://mirror.example/demo-1.0.jar")];

        let rejection = guard
            .evaluate(&previous, &url("https://proxy.corp/demo-1.0.jar"))
            .expect_err("proxy host must not be a redirect target");
        assert_eq!(
            rejection.kind,
            RedirectRejectionKind::ExemptHostOriginMismatch
        );
    }

    /// Repository and mirror URLs must land in both sets, and a configuration
    /// with no proxy must leave the policy in its unproxied mode.
    #[test]
    fn redirect_guard_reads_repository_endpoints() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = rv_config::ResolvedPaths::discover().expect("paths");
        let config = rv_config::Config::for_testing_with_repos(
            temp.path().to_path_buf(),
            paths,
            vec![rv_config::RepoConfig {
                id: Some("internal".to_string()),
                url: "https://nexus.corp:8443/repository/maven/".to_string(),
                releases: Some(true),
                snapshots: Some(false),
                snapshots_update_policy: None,
            }],
        );

        let guard = redirect_guard(&config).expect("guard");
        assert!(guard.origins.contains("https://nexus.corp:8443"));
        assert!(guard.exempt_hosts.contains("nexus.corp"));
        assert!(
            !guard.proxy_active,
            "no configured proxy must leave the proxy screen off"
        );
    }

    /// Every IPv4 special-purpose block this screen excludes, at both edges,
    /// paired with the routable addresses immediately outside it. The
    /// neighbours are the point: an off-by-one in a mask silently either opens
    /// a private range or blackholes a public one.
    #[test]
    fn ipv4_special_purpose_blocks_are_excluded() {
        let cases: &[(&str, &str, [&str; 2], &[&str])] = &[
            (
                "0.0.0.0/8",
                "this network",
                ["0.0.0.0", "0.255.255.255"],
                &["1.0.0.0"],
            ),
            (
                "10.0.0.0/8",
                "private",
                ["10.0.0.0", "10.255.255.255"],
                &["9.255.255.255", "11.0.0.0"],
            ),
            (
                "100.64.0.0/10",
                "shared address space",
                ["100.64.0.0", "100.127.255.255"],
                &["100.63.255.255", "100.128.0.0"],
            ),
            (
                "127.0.0.0/8",
                "loopback",
                ["127.0.0.0", "127.255.255.255"],
                &["126.255.255.255", "128.0.0.1"],
            ),
            (
                "169.254.0.0/16",
                "link local",
                ["169.254.0.0", "169.254.169.254"],
                &["169.253.255.255", "169.255.0.0"],
            ),
            (
                "172.16.0.0/12",
                "private",
                ["172.16.0.0", "172.31.255.255"],
                &["172.15.255.255", "172.32.0.0"],
            ),
            (
                "192.0.0.0/24",
                "IETF protocol assignments",
                ["192.0.0.0", "192.0.0.255"],
                // The two globally-reachable /32s inside the block are
                // excluded with it, deliberately.
                &["191.255.255.255", "192.0.1.0"],
            ),
            (
                "192.0.2.0/24",
                "documentation TEST-NET-1",
                ["192.0.2.0", "192.0.2.255"],
                &["192.0.1.255", "192.0.3.0"],
            ),
            (
                "192.88.99.0/24",
                "deprecated 6to4 relay anycast",
                ["192.88.99.0", "192.88.99.255"],
                &["192.88.98.255", "192.88.100.0"],
            ),
            (
                "192.168.0.0/16",
                "private",
                ["192.168.0.0", "192.168.255.255"],
                &["192.167.255.255", "192.169.0.0"],
            ),
            (
                "198.18.0.0/15",
                "benchmarking",
                ["198.18.0.0", "198.19.255.255"],
                &["198.17.255.255", "198.20.0.0"],
            ),
            (
                "198.51.100.0/24",
                "documentation TEST-NET-2",
                ["198.51.100.0", "198.51.100.255"],
                &["198.51.99.255", "198.51.101.0"],
            ),
            (
                "203.0.113.0/24",
                "documentation TEST-NET-3",
                ["203.0.113.0", "203.0.113.255"],
                &["203.0.112.255", "203.0.114.0"],
            ),
            (
                "224.0.0.0/4",
                "multicast",
                ["224.0.0.0", "239.255.255.255"],
                &["223.255.255.255"],
            ),
            (
                "240.0.0.0/4",
                "reserved, including the broadcast address",
                ["240.0.0.0", "255.255.255.255"],
                // Nothing routable borders this block: 239.255.255.255 below it
                // is multicast, and above it is the end of the address space.
                &[],
            ),
        ];

        for (block, description, excluded, neighbours) in cases {
            for address in excluded {
                let addr: IpAddr = address.parse().expect("address");
                assert!(
                    !is_globally_routable(addr),
                    "{address} is in {block} ({description}) and must be non-global"
                );
            }
            for neighbour in *neighbours {
                let addr: IpAddr = neighbour.parse().expect("address");
                assert!(
                    is_globally_routable(addr),
                    "{neighbour} sits outside {block} ({description}) and must stay global"
                );
            }
        }

        for public in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "223.255.255.255"] {
            let addr: IpAddr = public.parse().expect("address");
            assert!(is_globally_routable(addr), "{public} should be global");
        }
    }

    /// The IPv6 half of the same table, plus the embedded-IPv4 forms that would
    /// otherwise launder an RFC1918 destination through a v6 literal.
    #[test]
    fn ipv6_special_purpose_blocks_are_excluded() {
        let cases: &[(&str, &str, &[&str], &[&str])] = &[
            ("::/128", "unspecified", &["::"], &[]),
            ("::1/128", "loopback", &["::1"], &[]),
            (
                "100::/64",
                "discard only",
                &["100::", "100::ffff:ffff:ffff:ffff"],
                // The block immediately above is the dummy prefix, also
                // excluded, so the nearest routable neighbour is one /64 further
                // out.
                &["100:0:0:2::1", "101::1"],
            ),
            (
                "100:0:0:1::/64",
                "dummy prefix",
                &["100:0:0:1::", "100:0:0:1:ffff:ffff:ffff:ffff"],
                // Below it sits the discard-only prefix, also excluded.
                &["100:0:0:2::1"],
            ),
            (
                "64:ff9b:1::/48",
                "local-use IPv4/IPv6 translation",
                &["64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff"],
                &["64:ff9b:2::1"],
            ),
            (
                "2001::/23",
                "IETF protocol assignments (Teredo, benchmarking, ORCHIDv2)",
                &[
                    "2001::",
                    "2001:1::1",
                    "2001:2::1",
                    "2001:20::1",
                    "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
                &["2000::1", "2001:200::1"],
            ),
            (
                "2001:db8::/32",
                "documentation",
                &["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"],
                &["2001:db7::1", "2001:db9::1"],
            ),
            (
                "2002::/16",
                "6to4, which embeds an arbitrary IPv4 destination",
                &[
                    "2002::",
                    "2002:a00:1::1",
                    "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
                &["2003::1"],
            ),
            (
                "3fff::/20",
                "documentation",
                &["3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"],
                &["3ffe::1", "3fff:1000::1"],
            ),
            (
                "5f00::/16",
                "segment routing SIDs",
                &["5f00::", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
                &["5eff:ffff::1", "5f01::1"],
            ),
            (
                "fc00::/7",
                "unique local",
                &[
                    "fc00::1",
                    "fd00::1",
                    "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                ],
                &["fbff:ffff::1"],
            ),
            (
                "fe80::/10",
                "link local",
                &["fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
                &[],
            ),
            (
                "fec0::/10",
                "deprecated site local",
                &["fec0::1", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
                &[],
            ),
            ("ff00::/8", "multicast", &["ff02::1", "ff05::1:3"], &[]),
        ];

        for (block, description, excluded, neighbours) in cases {
            for address in *excluded {
                let addr: IpAddr = address.parse().expect("address");
                assert!(
                    !is_globally_routable(addr),
                    "{address} is in {block} ({description}) and must be non-global"
                );
            }
            for neighbour in *neighbours {
                let addr: IpAddr = neighbour.parse().expect("address");
                assert!(
                    is_globally_routable(addr),
                    "{neighbour} sits outside {block} ({description}) and must stay global"
                );
            }
        }

        for embedded in [
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:0.0.0.1",
            // Deprecated IPv4-compatible form of 10.0.0.1.
            "::10.0.0.1",
            // Well-known NAT64 prefix carrying a private destination.
            "64:ff9b::10.0.0.1",
            "64:ff9b::169.254.169.254",
        ] {
            let addr: IpAddr = embedded.parse().expect("address");
            assert!(
                !is_globally_routable(addr),
                "{embedded} embeds a non-global IPv4 address and must be rejected"
            );
        }

        for public in [
            "2606:4700:4700::1111",
            "2a00:1450:4001:80e::200e",
            // A DNS64 network answers with these for every public destination,
            // so the well-known NAT64 prefix must stay usable.
            "64:ff9b::8.8.8.8",
            "::ffff:8.8.8.8",
        ] {
            let addr: IpAddr = public.parse().expect("address");
            assert!(is_globally_routable(addr), "{public} should be global");
        }
    }

    #[test]
    fn dns_screen_accepts_public_answer() {
        let addrs = vec![
            "8.8.8.8:443".parse().expect("socket address"),
            "[2606:4700:4700::1111]:443"
                .parse()
                .expect("socket address"),
        ];
        let screened =
            screen_resolved_addrs("cdn.example.com", false, addrs.clone()).expect("public answer");
        assert_eq!(screened, addrs);
    }

    /// A rebinding answer that mixes a public and a private address must be
    /// rejected wholesale: the connector uses the addresses returned here, so
    /// keeping the public one would still leave the private one reachable.
    #[test]
    fn dns_screen_rejects_mixed_answer() {
        let addrs = vec![
            "8.8.8.8:443".parse().expect("socket address"),
            "169.254.169.254:443".parse().expect("socket address"),
        ];
        let error = screen_resolved_addrs("rebind.example.com", false, addrs)
            .expect_err("mixed answer must be rejected");
        assert_eq!(error.kind, RedirectRejectionKind::NonGlobalTarget);
        assert!(
            error.details.contains("169.254.169.254"),
            "rejection must name the offending address: {}",
            error.details
        );
    }

    #[test]
    fn dns_screen_exempts_configured_host() {
        let addrs = vec!["10.1.2.3:8443".parse().expect("socket address")];
        let screened = screen_resolved_addrs("nexus.corp.internal", true, addrs.clone())
            .expect("configured host may be private");
        assert_eq!(screened, addrs);
    }

    #[tokio::test]
    async fn resolver_rejects_loopback_name_unless_configured() {
        let resolver = GlobalOnlyResolver {
            exempt_hosts: TrustedHosts::default(),
        };
        let error = resolver
            .resolve("localhost".parse().expect("name"))
            .await
            .err()
            .expect("localhost must not resolve for an unconfigured host");
        assert!(
            error.to_string().contains("not globally routable"),
            "resolver rejection must explain itself: {error}"
        );

        let resolver = GlobalOnlyResolver {
            exempt_hosts: host_set(["localhost"]),
        };
        let addrs = resolver
            .resolve("localhost".parse().expect("name"))
            .await
            .expect("configured host resolves");
        assert!(
            addrs.count() > 0,
            "configured loopback host must still resolve"
        );
    }

    /// A `RepoClient` wired the way [`RepoClient::new`] wires one: a
    /// redirect-capable client screening against the frozen configured set, and
    /// a same-origin-only client screening against the live runtime set that
    /// `trust_repositories` grows. Requests pick between them exactly as
    /// production does, through `http_client_for`.
    fn screened_test_client(guard: RedirectGuard) -> (RepoClient, tempfile::TempDir) {
        let (mut client, tmp) = test_client();
        let trusted_hosts = guard.exempt_hosts.to_runtime_set();
        client.client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .redirect(trusted_redirect_policy(guard.clone()))
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                exempt_hosts: guard.exempt_hosts.clone(),
            }))
            .build()
            .expect("screened test client");
        client.runtime_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .redirect(same_origin_redirect_policy())
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                exempt_hosts: trusted_hosts.clone(),
            }))
            .build()
            .expect("runtime test client");
        client.fetch = FetchConfig {
            retries: 0,
            timeout: Duration::from_secs(5),
        };
        client.configured_hosts = guard.exempt_hosts;
        client.trusted_hosts = trusted_hosts;
        (client, tmp)
    }

    /// `localhost` stands in for `nexus.corp.internal`: a *name* that resolves
    /// onto an address the screen rejects. Only a name exercises the resolver
    /// at all — an IP literal never reaches one, which is why the mock servers
    /// elsewhere in this file cannot see this class of failure.
    fn loopback_name_url(port: u16, path: &str) -> Url {
        url(&format!("https://localhost:{port}{path}"))
    }

    /// The routing rule the split rests on: only a host `rv.toml` named is
    /// served by the redirect-capable client, and no trust grant can move a
    /// host onto it afterwards.
    #[test]
    fn only_configured_hosts_reach_the_redirect_capable_client() {
        let (client, _tmp) =
            screened_test_client(origins_guard(origin_set(["https://mirror.example"])));

        assert!(
            std::ptr::eq(
                client.http_client_for(&url("https://mirror.example/demo-1.0.jar")),
                &client.client
            ),
            "a configured host is served by the redirect-capable client"
        );
        let runtime_url = url("https://nexus.corp.internal/demo-1.0.jar");
        for stage in ["before the grant", "after the grant"] {
            assert!(
                std::ptr::eq(client.http_client_for(&runtime_url), &client.runtime_client),
                "an unconfigured host must stay on the same-origin-only client {stage}"
            );
            client.trust_repositories(&[Repository::new(
                None,
                "https://nexus.corp.internal/repo/".to_string(),
                true,
                false,
            )]);
        }
        assert!(client.trusts_host("nexus.corp.internal"));
    }

    /// A hostname nothing has trusted still fails the address screen when it
    /// resolves onto a private network, and fails before any connection.
    #[tokio::test]
    async fn untrusted_private_hostname_fails_the_address_screen() {
        let repo = spawn_https_stub(|_| ok_response(b"must not arrive"));
        let (client, _tmp) = screened_test_client(origins_guard(HashSet::new()));

        let repo_url = loopback_name_url(repo.addr.port(), "/demo-1.0.jar");
        let error = fetch_redirect_test(client.http_client_for(&repo_url), &repo_url)
            .await
            .expect_err("an untrusted private hostname must not be dialled");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::NonGlobalTarget,
                    ..
                }
            ),
            "expected a non-global rejection, got {error:?}"
        );
        assert!(
            repo.request.lock().expect("repo request").is_none(),
            "the screened host must not be contacted"
        );
    }

    /// The regression: a repository the root POM declares becomes trusted
    /// part-way through a resolve, and the client that is already running the
    /// resolve has to honour that without being rebuilt. Freezing the exempt
    /// set at construction left every such fetch failing the address screen —
    /// the normal shape of an on-prem registry named only in the project's POM.
    #[tokio::test]
    async fn runtime_trusted_repository_host_fetches_without_a_client_rebuild() {
        let repo = spawn_https_stub(|_| ok_response(b"artifact bytes"));
        let repo_url = loopback_name_url(repo.addr.port(), "/demo-1.0.jar");
        let (client, _tmp) = screened_test_client(origins_guard(HashSet::new()));

        // Routing sends an unconfigured host to the same-origin-only client.
        assert!(
            std::ptr::eq(client.http_client_for(&repo_url), &client.runtime_client),
            "an unconfigured repository host must not be served by the redirect-capable client"
        );
        let error = fetch_redirect_test(client.http_client_for(&repo_url), &repo_url)
            .await
            .expect_err("the host is not trusted yet");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::NonGlobalTarget,
                    ..
                }
            ),
            "expected a non-global rejection before the grant, got {error:?}"
        );

        // What `RepoBackend::extend_repos_trusted` does when the root POM
        // declares a repository the configuration never named.
        client.trust_repositories(&[Repository::new(
            Some("internal".to_string()),
            loopback_name_url(repo.addr.port(), "/repo/").to_string(),
            true,
            false,
        )]);
        assert!(client.trusts_host("LOCALHOST"), "the grant is case-blind");

        let bytes = fetch_redirect_test(client.http_client_for(&repo_url), &repo_url)
            .await
            .expect("a trusted repository host must resolve and fetch");
        assert_eq!(bytes, Bytes::from_static(b"artifact bytes"));
    }

    /// Runtime trust buys a direct connection and nothing else: a hostile
    /// mirror bouncing `rv` at another port of a private host the root POM
    /// happened to name is the SSRF this whole screen exists to stop.
    ///
    /// The redirect-capable client's resolver never sees the grant, so the
    /// target is screened on its addresses and the connection dies there.
    #[tokio::test]
    async fn runtime_trusted_host_is_still_not_a_redirect_target() {
        let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
        let target_url = loopback_name_url(target.addr.port(), "/secret").to_string();
        let source = spawn_https_stub(move |_| redirect_response(&target_url));
        let source_url = url(&format!("https://127.0.0.1:{}/start", source.addr.port()));
        // Only the source is configured in `rv.toml`; the target host is
        // trusted at runtime, the way a root-POM repository is.
        let configured = HashSet::from([source_url.origin().ascii_serialization()]);
        let (client, _tmp) = screened_test_client(origins_guard(configured));
        client.trust_repositories(&[Repository::new(
            None,
            loopback_name_url(target.addr.port(), "/repo/").to_string(),
            true,
            false,
        )]);

        let error = fetch_redirect_test(client.http_client_for(&source_url), &source_url)
            .await
            .expect_err("a runtime-trusted host is not a redirect target");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::NonGlobalTarget,
                    ..
                }
            ),
            "expected a non-global rejection, got {error:?}"
        );
        assert!(
            target.request.lock().expect("target request").is_none(),
            "the redirect target must not be contacted"
        );
    }

    /// The interleaving the port-blind exemption made possible: a hostile
    /// configured mirror redirects to a host nothing trusts yet, the policy
    /// permits the hop *because* the resolver is expected to screen it, and a
    /// concurrent reactor task then trusts a direct repository on that same
    /// host. A redirect target that was not exempt at policy-evaluation time
    /// must be DNS-screened at connect time, regardless of concurrent trust
    /// grants — otherwise the grant retroactively licenses the hop, at any
    /// port, on a private machine the user only meant to fetch artifacts from.
    ///
    /// Driven in order rather than raced: the three steps are the ones the two
    /// tasks interleave, and the assertion is that step 3 cannot change what
    /// step 4 decides.
    #[tokio::test]
    async fn trust_granted_after_policy_evaluation_leaves_the_target_screened() {
        let target = spawn_https_stub(|_| ok_response(b"must not arrive"));
        let target_url = loopback_name_url(target.addr.port(), "/secret");
        let redirect_to = target_url.to_string();
        let source = spawn_https_stub(move |_| redirect_response(&redirect_to));
        let source_url = url(&format!("https://127.0.0.1:{}/start", source.addr.port()));
        let guard = origins_guard(HashSet::from([source_url.origin().ascii_serialization()]));
        let (client, _tmp) = screened_test_client(guard.clone());

        // (1) and (2): the hop is evaluated while nothing trusts the target
        // host, and permitted on the expectation that the resolver screens the
        // addresses the name answers with.
        guard
            .evaluate(std::slice::from_ref(&source_url), &target_url)
            .expect("an unexempt hostname target is left to the resolver");

        // (3) a concurrent task grants the host direct-connection trust, the
        // way a root-POM repository on the same machine would.
        client.trust_repositories(&[Repository::new(
            None,
            loopback_name_url(target.addr.port(), "/repo/").to_string(),
            true,
            false,
        )]);
        assert!(
            client.trusts_host("localhost"),
            "the grant must have landed"
        );

        // (4) the redirect-capable client screens the target anyway: its
        // resolver reads the frozen configured set, which runtime trust cannot
        // reach. `configured_hosts` is the same handle that client's resolver
        // holds, so this is the state the connection would see.
        assert!(
            !client.configured_hosts.contains("localhost"),
            "runtime trust must never reach the configured set"
        );
        let resolver = GlobalOnlyResolver {
            exempt_hosts: client.configured_hosts.clone(),
        };
        let error = resolver
            .resolve("localhost".parse().expect("name"))
            .await
            .err()
            .expect("the permitted redirect target must still be screened");
        assert!(
            error.to_string().contains("non-global address"),
            "resolver rejection must explain itself: {error}"
        );

        // And end to end, with the grant already in place before the request
        // runs: the hop is followed no further than the address screen.
        let error = fetch_redirect_test(client.http_client_for(&source_url), &source_url)
            .await
            .expect_err("a grant taken mid-flight must not unscreen the target");
        assert!(
            matches!(
                error,
                RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::NonGlobalTarget,
                    ..
                }
            ),
            "expected a non-global rejection, got {error:?}"
        );
        assert!(
            target.request.lock().expect("target request").is_none(),
            "the redirect target must not be contacted"
        );
    }

    /// A redirect that switches origin (e.g. attacker mirror sends
    /// `302 Location: http://other-host/`) must be rejected
    /// even when the redirect chain is short. Otherwise a hostile mirror
    /// can bypass TLS and the per-repository origin check by replying with
    /// a redirect to a malicious server.
    #[tokio::test]
    async fn redirect_policy_rejects_cross_origin() {
        let listener_a = TcpListener::bind("127.0.0.1:0").await.expect("bind a");
        let addr_a = listener_a.local_addr().expect("addr a");
        let listener_b = TcpListener::bind("127.0.0.1:0").await.expect("bind b");
        let addr_b = listener_b.local_addr().expect("addr b");

        // Server A returns a 302 pointing at server B (different port =
        // different origin). Server B would return 200 OK if we followed.
        let b_hits = Arc::new(AtomicU32::new(0));
        let b_hits_clone = b_hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener_a.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 302 Found\r\n\
                         Location: http://{addr_b}/jar\r\n\
                         Content-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener_b.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                b_hits_clone.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let body = b"hello";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(same_origin_redirect_policy())
            .build()
            .expect("client");
        let result = client.get(format!("http://{addr_a}/jar")).send().await;

        assert!(
            result.is_err(),
            "cross-origin redirect must surface as an error, got {result:?}"
        );
        assert_eq!(
            b_hits.load(Ordering::SeqCst),
            0,
            "cross-origin redirect target must NOT have been contacted"
        );
    }

    /// Same-origin redirects are still allowed (servers that bounce
    /// /foo -> /foo/ within the same host must keep working).
    #[tokio::test]
    async fn redirect_policy_allows_same_origin() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let idx = counter_clone.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let response = if idx == 0 {
                        // First hit -> redirect to /target on the same host.
                        "HTTP/1.1 302 Found\r\n\
                         Location: /target\r\n\
                         Content-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                            .to_string()
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                            .to_string()
                    };
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(same_origin_redirect_policy())
            .build()
            .expect("client");
        let response = client
            .get(format!("http://{addr}/start"))
            .send()
            .await
            .expect("same-origin redirect should be followed");
        assert!(response.status().is_success());
    }

    /// Long redirect chains on the same origin are still capped
    /// (defence against denial-of-service or loops).
    #[tokio::test]
    async fn redirect_policy_caps_chain_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    // Each hop redirects back into itself, infinitely.
                    let response = "HTTP/1.1 302 Found\r\n\
                                    Location: /loop\r\n\
                                    Content-Length: 0\r\n\
                                    Connection: close\r\n\r\n";
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(same_origin_redirect_policy())
            .build()
            .expect("client");
        let url = Url::parse(&format!("http://{addr}/loop")).expect("loop URL");
        let result = fetch_redirect_test(&client, &url).await;
        assert!(
            matches!(
                result,
                Err(RepoError::RedirectRejected {
                    kind: RedirectRejectionKind::ChainLimit,
                    ..
                })
            ),
            "redirect chain over the cap must name the chain limit, got {result:?}"
        );
    }

    #[test]
    fn repeated_mirror_redirect_failures_emit_one_summary_warning() {
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone)]
        struct VecWriter(Arc<Mutex<Vec<u8>>>);

        impl Write for VecWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("warning output")
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for VecWriter {
            type Writer = VecWriter;

            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let tracker = MirrorFailureTracker::default();
        let mirror = Repository::new(
            Some("object-store-mirror".to_string()),
            "https://registry.example/maven/".to_string(),
            true,
            false,
        );
        let error = RepoError::RedirectRejected {
            kind: RedirectRejectionKind::HttpsDowngrade,
            details: "test redirect".to_string(),
        };
        for _ in 0..MIRROR_FAILURE_SUMMARY_THRESHOLD {
            tracker.record(&mirror, &error);
        }

        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(VecWriter(Arc::clone(&output)))
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, || tracker.report());

        let rendered = String::from_utf8(output.lock().expect("warning output").clone())
            .expect("UTF-8 warning");
        assert!(
            rendered.contains(
                "mirror object-store-mirror (https://registry.example/maven/) failed 3 fetches"
            ),
            "summary must name the mirror and failure count: {rendered}"
        );
        assert!(
            rendered.contains("cross-origin redirect rejected: target is not HTTPS"),
            "summary must name the rejection class: {rendered}"
        );
        assert!(
            rendered.contains("results came from origin repositories"),
            "summary must disclose origin fallback: {rendered}"
        );
        assert_eq!(
            rendered
                .matches("results came from origin repositories")
                .count(),
            1,
            "repeated failures must collapse into one summary: {rendered}"
        );
    }

    #[tokio::test]
    async fn artifact_fetch_reports_successful_mirror_as_provenance() {
        use rv_config::{ArtifactKey, MirrorConfig};
        use rv_store::Store;
        use sha2::{Digest, Sha256};

        let body = b"mirror artifact";
        let digest = hex::encode(Sha256::digest(body));
        let checksum: StubHandler = Box::new(move |request| {
            assert!(request.contains(".sha256"), "first request is checksum");
            ok_response(digest.as_bytes())
        });
        let artifact: StubHandler = Box::new(move |request| {
            assert!(!request.contains(".sha"), "second request is artifact");
            ok_response(body)
        });
        let (mirror_addr, mirror_hits) = spawn_stub_seq(vec![checksum, artifact]).await;
        let mirror_url = format!("http://{mirror_addr}/");
        let (client, _cache) = test_client_with_mirrors(vec![MirrorConfig {
            id: Some("serving-mirror".to_string()),
            url: mirror_url.clone(),
            mirror_of: vec!["central".to_string()],
        }]);
        let origin = Repository::new(
            Some("central".to_string()),
            "http://127.0.0.1:9/".to_string(),
            true,
            false,
        );
        let request = ArtifactRequest::new("com.example", "demo", "1.0.0");
        let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let store = Store::open(store_dir.path()).expect("store");

        let (_, serving_repository) = client
            .fetch_artifact_to_store_and_index_with_repository(&origin, &request, &store, &key)
            .await
            .expect("mirror artifact fetch");
        assert_eq!(serving_repository, mirror_url);
        assert_eq!(mirror_hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn effective_repository_url_applies_mirror_without_network_fetch() {
        let mirror_url = "https://registry.example/maven/";
        let (client, _cache) = test_client_with_mirrors(vec![rv_config::MirrorConfig {
            id: Some("registry".to_string()),
            url: mirror_url.to_string(),
            mirror_of: vec!["central".to_string()],
        }]);
        let origin = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        );

        assert_eq!(client.effective_repository_url(&origin), mirror_url);
    }

    #[tokio::test]
    async fn artifact_fetch_reports_origin_after_mirror_fallback() {
        use rv_config::{ArtifactKey, MirrorConfig};
        use rv_store::Store;
        use sha2::{Digest, Sha256};

        let unavailable: StubHandler = Box::new(|_| {
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec()
        });
        let unavailable_again: StubHandler = Box::new(|_| {
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec()
        });
        let (mirror_addr, mirror_hits) = spawn_stub_seq(vec![unavailable, unavailable_again]).await;

        let body = b"origin artifact";
        let digest = hex::encode(Sha256::digest(body));
        let checksum: StubHandler = Box::new(move |_| ok_response(digest.as_bytes()));
        let artifact: StubHandler = Box::new(move |_| ok_response(body));
        let (origin_addr, origin_hits) = spawn_stub_seq(vec![checksum, artifact]).await;
        let origin_url = format!("http://{origin_addr}/");
        let (client, _cache) = test_client_with_mirrors(vec![MirrorConfig {
            id: Some("broken-mirror".to_string()),
            url: format!("http://{mirror_addr}/"),
            mirror_of: vec!["central".to_string()],
        }]);
        let origin = Repository::new(Some("central".to_string()), origin_url.clone(), true, false);
        let request = ArtifactRequest::new("com.example", "demo", "1.0.0");
        let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        let store_dir = tempfile::tempdir().expect("store tempdir");
        let store = Store::open(store_dir.path()).expect("store");

        let (_, serving_repository) = client
            .fetch_artifact_to_store_and_index_with_repository(&origin, &request, &store, &key)
            .await
            .expect("origin fallback artifact fetch");
        assert_eq!(serving_repository, origin_url);
        assert_eq!(mirror_hits.load(Ordering::SeqCst), 2);
        assert_eq!(origin_hits.load(Ordering::SeqCst), 2);
    }

    /// THE launch-blocker fix: a repo (like Maven Central) that serves only a
    /// SHA-1 sidecar, no SHA-256, must resolve by DEFAULT. The client prefers
    /// SHA-256, finds it 404, falls back to the `.sha1` sidecar (emitting the
    /// `WEAK_HASH_FALLBACK` warning), and returns it. The durable rv.lock pin
    /// is the locally-computed SHA-256 of the downloaded bytes, recorded
    /// independently of which sidecar gated the fetch (see the resolver), so
    /// the SHA-1 fallback never weakens the lockfile.
    #[tokio::test]
    async fn fetch_checksum_default_accepts_sha1_only_repo() {
        use crate::fetch::ChecksumAlgorithm;
        use crate::repository::Repository;

        // Stub: SHA-256 -> 404; SHA-1 -> 200. Default config must probe both
        // and accept the SHA-1 sidecar.
        let sha1_hits = Arc::new(AtomicU32::new(0));
        let sha1_hits_clone = sha1_hits.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let sha1_hits = sha1_hits_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&total);
                    let response: Vec<u8> = if request.contains(".sha256") {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    } else if request.contains(".sha1") {
                        sha1_hits.fetch_add(1, Ordering::SeqCst);
                        let body = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .into_bytes()
                    } else {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    };
                    let _ = sock.write_all(&response).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
        let (client, _tmp) = test_client();

        let result = client
            .fetch_checksum(&repo, "com/example/demo/1.0/demo-1.0.jar", false)
            .await
            .expect("fetch_checksum");
        let checksum = result.expect("sha1 sidecar must be accepted by default");
        assert_eq!(
            checksum.algorithm,
            ChecksumAlgorithm::Sha1,
            "default config must fall back to the .sha1 sidecar when sha256 is absent"
        );
        assert_eq!(checksum.value, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        assert_eq!(
            sha1_hits.load(Ordering::SeqCst),
            1,
            "the .sha1 sidecar must be fetched as the fallback"
        );
    }

    /// Spawn a stub that answers every `.sha256` request with `sha256_body`
    /// and every `.sha1` request with `sha1_body`, both as 200 OK. Used by
    /// the garbage-sidecar fallback tests below.
    async fn spawn_sidecar_stub(
        sha256_body: &'static str,
        sha1_body: &'static str,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&total);
                    let body = if request.contains(".sha256") {
                        sha256_body
                    } else {
                        sha1_body
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    /// A server that answers the `.sha256` probe with 200 + an HTML "not
    /// found" page (no hex token) must not abort the probe loop: the `.sha1`
    /// sidecar is still tried and accepted.
    #[tokio::test]
    async fn fetch_checksum_falls_back_when_sha256_body_is_garbage() {
        use crate::fetch::ChecksumAlgorithm;
        use crate::repository::Repository;

        let addr = spawn_sidecar_stub(
            "<html><body>404 not found</body></html>",
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        )
        .await;

        let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
        let (client, _tmp) = test_client();

        let checksum = client
            .fetch_checksum(&repo, "com/example/demo/1.0/demo-1.0.jar", false)
            .await
            .expect("fetch_checksum")
            .expect("sha1 fallback must be used");
        assert_eq!(
            checksum.algorithm,
            ChecksumAlgorithm::Sha1,
            "garbage sha256 body must fall through to the .sha1 sidecar"
        );
        assert_eq!(checksum.value, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }

    /// When EVERY probed sidecar serves an unparseable body, the probe loop
    /// must surface an error (the first concrete failure), not silently
    /// return `Ok(None)` as if the repo published no sidecars at all.
    #[tokio::test]
    async fn fetch_checksum_errors_when_all_sidecar_bodies_are_garbage() {
        use crate::repository::Repository;

        let addr = spawn_sidecar_stub(
            "<html><body>404 not found</body></html>",
            "<html><body>404 not found</body></html>",
        )
        .await;

        let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
        let (client, _tmp) = test_client();

        let result = client
            .fetch_checksum(&repo, "com/example/demo/1.0/demo-1.0.jar", false)
            .await;
        match result {
            Err(RepoError::MissingChecksum(_)) => {}
            other => panic!("expected the first parse failure to surface, got {other:?}"),
        }
    }

    /// Companion POMs fetched alongside a JAR must go through the
    /// sidecar-verification path. A repo that serves the POM body but no
    /// `.sha256`/`.sha1` sidecar must be rejected (in the
    /// `require_checksums=true` default), so a hostile mirror cannot inject
    /// a tampered POM with malicious `<dependency>` rows. The runtime
    /// mitigation is what this test pins down; lockfile-level POM pinning
    /// is the deeper fix.
    #[tokio::test]
    async fn pom_without_sidecar_is_refused_in_default_config() {
        use crate::artifact::ArtifactRequest;
        use crate::repository::Repository;
        use rv_store::Store;

        // Stub: POM body served, but both sidecars (.sha256 and .sha1) 404.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&total);
                    let response: Vec<u8> = if request.contains(".sha256")
                        || request.contains(".sha1")
                    {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    } else {
                        let body = b"<project><dependencies><dependency><groupId>evil</groupId><artifactId>x</artifactId><version>1.0</version></dependency></dependencies></project>";
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(body);
                        out
                    };
                    let _ = sock.write_all(&response).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, true);
        let (client, _tmp) = test_client();
        let store_dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(store_dir.path()).expect("store");

        let pom_req = ArtifactRequest::new("com.example", "demo", "1.0.0").pom();
        let result = client
            .fetch_artifact_to_store(&repo, &pom_req, &store)
            .await;

        match result {
            Err(RepoError::MissingChecksum(_)) => {}
            other => {
                panic!("POM without sidecar must be refused with MissingChecksum, got {other:?}")
            }
        }
    }

    /// Every outbound HTTP request must carry a
    /// `User-Agent: raeva/<version>` header. Some private repos block
    /// UA-less requests; reqwest's default sends nothing. Verify by
    /// capturing the raw request from a stub server.
    #[tokio::test]
    async fn user_agent_header_is_present_on_requests() {
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let captured_clone = captured.clone();
        let r: StubHandler = Box::new(move |req| {
            let mut guard = captured_clone.lock().expect("lock");
            *guard = req.to_string();
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
        });
        let (addr, _) = spawn_stub_seq(vec![r]).await;

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(same_origin_redirect_policy())
            .user_agent(USER_AGENT)
            .build()
            .expect("client");
        let _ = client
            .get(format!("http://{addr}/jar"))
            .send()
            .await
            .expect("send");

        let request = captured.lock().expect("lock").clone();
        let expected = format!("user-agent: {USER_AGENT}");
        assert!(
            request.to_ascii_lowercase().contains(&expected),
            "request must carry raeva User-Agent, got: {request}"
        );
    }

    /// A wildcard mirror that substitutes the original
    /// `central` repo URL with a third-party host MUST cause the default
    /// (no-id) `AuthConfig` to be suppressed when the client issues a real
    /// outbound request. The wiring is `MirrorSelector::resolve_with_host_change`
    /// → `host_changed` → `AuthStore::for_repository_with_policy`, and this
    /// test exercises the composition end-to-end through `fetch_path`.
    #[tokio::test]
    async fn cross_host_wildcard_mirror_suppresses_default_auth() {
        use crate::repository::Repository;
        use rv_config::{AuthConfig, MirrorConfig};

        // Server captures the raw request bytes so we can assert the
        // presence/absence of the Authorization header.
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let captured_clone = captured.clone();
        let r: StubHandler = Box::new(move |req| {
            *captured_clone.lock().expect("lock") = req.to_string();
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
        });
        let (addr, _) = spawn_stub_seq(vec![r]).await;

        // Default (no-id) bearer token configured globally. Without
        // host-change suppression this would be attached to every request.
        let auth = AuthStore::from_auth_configs(&[AuthConfig {
            id: None,
            username: None,
            password: None,
            token: Some(Secret::new("hostile-cdn-token".to_string())),
        }])
        .expect("auth store");

        // Wildcard mirror replacing every repo with the stub on a different
        // host (loopback 127.0.0.1:<port>); this triggers `origins_differ`.
        let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
            id: Some("hostile".to_string()),
            url: format!("http://{addr}/"),
            mirror_of: vec!["*".to_string()],
        }]);

        let _tmp = tempfile::tempdir().expect("tempdir");
        let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
        // _tmp stays bound for the rest of the test; dropping it would
        // delete the SQLite cache file MetadataCache still holds open.
        let client = RepoClient {
            client: plain_test_client(),
            runtime_client: plain_test_client(),
            auth,
            mirrors,
            fetch: FetchConfig::default(),
            progress: None,
            cache,
            offline: false,
            require_checksums: false,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            configured_hosts: ConfiguredHosts::default(),
            trusted_hosts: TrustedHosts::default(),
        };

        // Original repo is "https://repo.example/" (different host from the
        // stub). The mirror substitutes the URL but the host change must
        // make `for_repository_with_policy` return `None`.
        let original = Repository::new(None, "https://repo.example/maven2/", true, false);
        let (resolved, host_changed, _fallback) = client.resolve_repo_with_fallback(&original);
        assert!(
            host_changed,
            "test precondition: mirror substitution must cross hosts"
        );

        // Issue the actual GET through the mirror-resolved repo (which is
        // how production code paths reach `fetch_path` after the
        // resolve_repo+host_changed pair is computed at the entry point).
        let _ = client
            .fetch_path(&resolved, "com/example/demo/1.0/demo-1.0.jar", host_changed)
            .await
            .expect("fetch");

        let request = captured.lock().expect("lock").clone();
        let lc = request.to_ascii_lowercase();
        assert!(
            !lc.contains("authorization: bearer"),
            "default bearer token must NOT be forwarded across a wildcard mirror host change; got request:\n{request}"
        );
        assert!(
            !lc.contains("hostile-cdn-token"),
            "default credential value must not appear in the request line; got:\n{request}"
        );
    }

    /// The SNAPSHOT-metadata sub-fetch must keep the cross-host
    /// credential suppression. A `-SNAPSHOT` POM fetch routed through a
    /// cross-host wildcard mirror resolves the snapshot metadata as a
    /// sub-request. Re-resolving the already-mirrored repo inside
    /// `resolve_snapshot_version` would recompute `host_changed=false` and
    /// re-attach the default credential to the third-party mirror host.
    /// Every request issued during the whole snapshot POM fetch must be free
    /// of the default bearer token.
    #[tokio::test]
    async fn snapshot_metadata_subfetch_preserves_cross_host_suppression() {
        use crate::artifact::ArtifactRequest;
        use crate::repository::Repository;
        use rv_config::{AuthConfig, MirrorConfig};
        use sha2::Digest;

        // Capture every raw request across all connections so we can assert
        // the credential never leaks on the metadata, sidecar, or POM GET.
        let captured = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let captured_clone = captured.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let captured = captured_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&total).into_owned();
                    captured.lock().expect("lock").push(request.clone());

                    let snapshot_meta = "<metadata><groupId>com.example</groupId>\
                        <artifactId>demo</artifactId><version>1.0-SNAPSHOT</version>\
                        <versioning><snapshot><timestamp>20240101.010101</timestamp>\
                        <buildNumber>7</buildNumber></snapshot>\
                        <snapshotVersions><snapshotVersion><extension>pom</extension>\
                        <value>1.0-20240101.010101-7</value></snapshotVersion>\
                        </snapshotVersions></versioning></metadata>";
                    let pom_body = "<project><modelVersion>4.0.0</modelVersion>\
                        <groupId>com.example</groupId><artifactId>demo</artifactId>\
                        <version>1.0-SNAPSHOT</version></project>";

                    let response: Vec<u8> = if request.contains("maven-metadata.xml.sha256")
                        || request.contains(".pom.sha256")
                    {
                        // Serve a matching sha256 so verification succeeds.
                        let target = if request.contains("maven-metadata.xml.sha256") {
                            snapshot_meta.as_bytes()
                        } else {
                            pom_body.as_bytes()
                        };
                        let sidecar = hex::encode(sha2::Sha256::digest(target));
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            sidecar.len(),
                            sidecar
                        )
                        .into_bytes()
                    } else if request.contains(".sha1") {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    } else if request.contains("maven-metadata.xml") {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            snapshot_meta.len(),
                            snapshot_meta
                        )
                        .into_bytes()
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            pom_body.len(),
                            pom_body
                        )
                        .into_bytes()
                    };
                    let _ = sock.write_all(&response).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        // Default (no-id) bearer token configured globally.
        let auth = AuthStore::from_auth_configs(&[AuthConfig {
            id: None,
            username: None,
            password: None,
            token: Some(Secret::new("hostile-cdn-token".to_string())),
        }])
        .expect("auth store");

        // Wildcard mirror replacing every repo with the stub on a different
        // host than the configured origin.
        let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
            id: Some("hostile".to_string()),
            url: format!("http://{addr}/"),
            mirror_of: vec!["*".to_string()],
        }]);

        let _tmp = tempfile::tempdir().expect("tempdir");
        let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
        let client = RepoClient {
            client: plain_test_client(),
            runtime_client: plain_test_client(),
            auth,
            mirrors,
            fetch: FetchConfig::default(),
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            configured_hosts: ConfiguredHosts::default(),
            trusted_hosts: TrustedHosts::default(),
        };

        // Original repo lives on a different host (repo.example) than the
        // stub, so the mirror substitution crosses hosts.
        let repo = Repository::new(
            None,
            "https://repo.example/maven2/".to_string(),
            true,
            true, // snapshots enabled
        );
        let req = ArtifactRequest::new("com.example", "demo", "1.0-SNAPSHOT");

        // Drives resolve_snapshot_for_request -> resolve_snapshot_version_resolved
        // -> fetch_snapshot_metadata, then the POM body fetch.
        let _ = client
            .fetch_pom(&repo, &req)
            .await
            .expect("snapshot pom fetch should succeed against the stub");

        let requests = captured.lock().expect("lock").clone();
        assert!(
            requests.iter().any(|r| r.contains("maven-metadata.xml")),
            "test precondition: the snapshot metadata sub-fetch must have run; saw {requests:?}"
        );
        for request in &requests {
            let lc = request.to_ascii_lowercase();
            assert!(
                !lc.contains("authorization: bearer"),
                "default bearer token leaked across the cross-host mirror on a snapshot sub-fetch; got:\n{request}"
            );
            assert!(
                !lc.contains("hostile-cdn-token"),
                "default credential value leaked on a snapshot sub-fetch request; got:\n{request}"
            );
        }
    }

    /// When a mirror returns 503 (or any non-404 5xx), the client must
    /// retry the fetch against the ORIGINAL repo, mirroring
    /// Maven's "next mirror in the list, then origin" behavior. Substituting
    /// the mirror URL once with no fallback would let a broken mirror take the
    /// whole sync down.
    #[tokio::test]
    async fn mirror_503_falls_back_to_origin() {
        use crate::repository::Repository;
        use rv_config::MirrorConfig;
        use sha2::{Digest, Sha256};

        let body =
            b"<metadata><versioning><versions><version>1.0.0</version></versions></versioning></metadata>"
                .to_vec();
        let sha256 = hex::encode(Sha256::digest(&body));

        // Mirror always 503s. Track that we did hit it.
        let mirror_hits = Arc::new(AtomicU32::new(0));
        let mirror_hits_clone = mirror_hits.clone();
        let mirror_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mirror");
        let mirror_addr = mirror_listener.local_addr().expect("mirror addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match mirror_listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let mirror_hits = mirror_hits_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    mirror_hits.fetch_add(1, Ordering::SeqCst);
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        // Origin serves valid metadata + matching SHA-256 sidecar.
        let origin_hits = Arc::new(AtomicU32::new(0));
        let origin_hits_clone = origin_hits.clone();
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let origin_addr = origin_listener.local_addr().expect("origin addr");
        let body_arc: Arc<Vec<u8>> = Arc::new(body);
        let sha256_arc: Arc<String> = Arc::new(sha256);
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match origin_listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let origin_hits = origin_hits_clone.clone();
                let body_arc = body_arc.clone();
                let sha256_arc = sha256_arc.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    origin_hits.fetch_add(1, Ordering::SeqCst);
                    let request = String::from_utf8_lossy(&total);
                    let response: Vec<u8> = if request.contains(".sha256") {
                        let sidecar = sha256_arc.as_str();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            sidecar.len(),
                            sidecar
                        )
                        .into_bytes()
                    } else if request.contains(".sha1") {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    } else {
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body_arc.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(&body_arc);
                        out
                    };
                    let _ = sock.write_all(&response).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        // Mirror substitutes the origin's URL with the mirror URL.
        let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
            id: Some("broken-mirror".to_string()),
            url: format!("http://{mirror_addr}/"),
            mirror_of: vec!["*".to_string()],
        }]);

        let _tmp = tempfile::tempdir().expect("tempdir");
        let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
        // _tmp stays bound for the rest of the test; dropping it would
        // delete the SQLite cache file MetadataCache still holds open.
        let client = RepoClient {
            client: plain_test_client(),
            runtime_client: plain_test_client(),
            auth: AuthStore::default(),
            mirrors,
            // Speed the retry loop up so the test doesn't wait on backoff.
            fetch: FetchConfig {
                retries: 0,
                timeout: Duration::from_secs(5),
            },
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            configured_hosts: ConfiguredHosts::default(),
            trusted_hosts: TrustedHosts::default(),
        };

        let origin = Repository::new(
            Some("central".to_string()),
            format!("http://{origin_addr}/"),
            true,
            false,
        );
        let coord = rv_version::Coord {
            group_id: "com.example".into(),
            artifact_id: "demo".into(),
            version: "1.0.0".parse().expect("version"),
            packaging: Some("jar".to_string()),
            classifier: None,
        };

        let metadata = client
            .fetch_metadata(&origin, &coord)
            .await
            .expect("origin fallback must succeed when mirror 503s");
        // Quick sanity check that we actually got the origin-served payload.
        assert!(
            metadata.versions.contains(&"1.0.0".to_string()),
            "metadata from origin must contain version 1.0.0"
        );
        assert!(
            mirror_hits.load(Ordering::SeqCst) >= 1,
            "mirror must be hit first (got {} hits)",
            mirror_hits.load(Ordering::SeqCst)
        );
        assert!(
            origin_hits.load(Ordering::SeqCst) >= 1,
            "origin must be retried after mirror 503 (got {} hits)",
            origin_hits.load(Ordering::SeqCst)
        );
    }

    /// A mirror 404 must NOT trigger the origin fallback. 404 means
    /// "the artifact genuinely does not exist at this coordinate"; retrying
    /// the origin only adds latency and reissues the same authoritative
    /// negative answer. Maven matches this behavior.
    #[tokio::test]
    async fn mirror_404_does_not_fall_back_to_origin() {
        use crate::repository::Repository;
        use rv_config::MirrorConfig;

        let mirror_hits = Arc::new(AtomicU32::new(0));
        let mirror_hits_clone = mirror_hits.clone();
        let mirror_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mirror");
        let mirror_addr = mirror_listener.local_addr().expect("mirror addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match mirror_listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let mirror_hits = mirror_hits_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    mirror_hits.fetch_add(1, Ordering::SeqCst);
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        // Origin would panic the test if hit; 404 must stop the chain.
        let origin_hits = Arc::new(AtomicU32::new(0));
        let origin_hits_clone = origin_hits.clone();
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let origin_addr = origin_listener.local_addr().expect("origin addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match origin_listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let origin_hits = origin_hits_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    origin_hits.fetch_add(1, Ordering::SeqCst);
                    let _ = sock.shutdown().await;
                });
            }
        });

        let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
            id: Some("404-mirror".to_string()),
            url: format!("http://{mirror_addr}/"),
            mirror_of: vec!["*".to_string()],
        }]);

        let _tmp = tempfile::tempdir().expect("tempdir");
        let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
        // _tmp stays bound for the rest of the test; dropping it would
        // delete the SQLite cache file MetadataCache still holds open.
        let client = RepoClient {
            client: plain_test_client(),
            runtime_client: plain_test_client(),
            auth: AuthStore::default(),
            mirrors,
            fetch: FetchConfig {
                retries: 0,
                timeout: Duration::from_secs(5),
            },
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            configured_hosts: ConfiguredHosts::default(),
            trusted_hosts: TrustedHosts::default(),
        };

        let origin = Repository::new(
            Some("central".to_string()),
            format!("http://{origin_addr}/"),
            true,
            false,
        );
        let coord = rv_version::Coord {
            group_id: "com.example".into(),
            artifact_id: "demo".into(),
            version: "1.0.0".parse().expect("version"),
            packaging: Some("jar".to_string()),
            classifier: None,
        };

        let result = client.fetch_metadata(&origin, &coord).await;
        assert!(
            matches!(result, Err(RepoError::NotFound(_))),
            "404 from mirror must surface as NotFound, got {result:?}"
        );
        assert!(
            mirror_hits.load(Ordering::SeqCst) >= 1,
            "mirror must be hit at least once"
        );
        assert_eq!(
            origin_hits.load(Ordering::SeqCst),
            0,
            "origin must NOT be retried on a mirror 404 (Maven parity)"
        );
    }

    /// #64: the metadata/POM cache scope key must distinguish two different
    /// origins that resolve through the same mirror, and also distinguish the
    /// same origin across a mirror change, so neither cross-origin reuse nor
    /// stale-after-mirror-swap reuse can occur.
    #[test]
    fn cache_scope_key_isolates_origin_and_mirror() {
        let mirror = "https://mirror.corp/";
        let origin_a = "https://repo.maven.apache.org/maven2/";
        let origin_b = "https://nexus.corp/releases/";

        // Two distinct origins behind one mirror must not collide.
        assert_ne!(
            RepoClient::cache_scope_key(origin_a, mirror),
            RepoClient::cache_scope_key(origin_b, mirror),
            "distinct origins routed through one mirror must not share a cache scope"
        );

        // The same origin across two different mirrors must not collide either,
        // so swapping a repo's mirror cannot reuse the previous mirror's entry.
        let mirror_2 = "https://mirror2.corp/";
        assert_ne!(
            RepoClient::cache_scope_key(origin_a, mirror),
            RepoClient::cache_scope_key(origin_a, mirror_2),
            "a mirror change for one origin must not reuse the previous mirror's entry"
        );

        // Deterministic for identical inputs.
        assert_eq!(
            RepoClient::cache_scope_key(origin_a, mirror),
            RepoClient::cache_scope_key(origin_a, mirror),
        );
    }

    #[test]
    fn metadata_path_for_release() {
        let path = metadata_path("com.example", "demo", None);
        assert_eq!(path, "com/example/demo/maven-metadata.xml");
    }

    #[test]
    fn metadata_path_for_snapshot() {
        let path = metadata_path("com.example", "demo", Some("1.0-SNAPSHOT"));
        assert_eq!(path, "com/example/demo/1.0-SNAPSHOT/maven-metadata.xml");
    }

    #[test]
    fn extracts_snapshot_timestamp() {
        let version = "1.0-20240101.010101-7";
        assert_eq!(
            snapshot_timestamp_from_version(version),
            Some("20240101.010101".to_string())
        );
    }

    #[test]
    fn derives_snapshot_directory_version() {
        let version = "1.0-20240101.010101-7";
        assert_eq!(
            snapshot_dir_version(version),
            Some("1.0-SNAPSHOT".to_string())
        );
    }

    // -------------------------------------------------------------------------
    // validate_coord_components / metadata_path traversal guard
    // -------------------------------------------------------------------------

    /// A version string containing `../` must be rejected before any URL is
    /// built, preventing path-traversal / SSRF from hostile maven-metadata.xml.
    #[test]
    fn validate_coord_rejects_path_traversal_in_version() {
        let err = validate_coord_components("com.example", "demo", Some("../../etc/shadow"))
            .expect_err("traversal version must be rejected");
        assert!(
            matches!(err, RepoError::InvalidCoord(_)),
            "expected InvalidCoord, got {err:?}"
        );
    }

    /// A group ID containing a forward slash is also rejected.
    #[test]
    fn validate_coord_rejects_slash_in_group_id() {
        let err = validate_coord_components("com/evil", "demo", Some("1.0.0"))
            .expect_err("slash in group_id must be rejected");
        assert!(matches!(err, RepoError::InvalidCoord(_)));
    }

    /// Normal Maven coordinates must pass validation.
    #[test]
    fn validate_coord_accepts_normal_coordinates() {
        validate_coord_components("com.example", "demo", Some("1.0.0-SNAPSHOT"))
            .expect("normal coordinate must be accepted");
        validate_coord_components("org.springframework.boot", "spring-boot", None)
            .expect("no-version path must be accepted");
    }

    // -------------------------------------------------------------------------
    // ChecksumMismatch must not trigger mirror->origin fallback
    // -------------------------------------------------------------------------

    /// A `ChecksumMismatch` error returned by a mirror must NOT cause a
    /// fallback to the origin. It is an integrity violation, not a transient
    /// failure; retrying the origin would let a hostile mirror exploit the
    /// retry path.
    #[test]
    fn checksum_mismatch_does_not_trigger_fallback() {
        let err = RepoError::ChecksumMismatch {
            path: "com/example/demo/1.0/demo-1.0.jar".to_string(),
            expected: "deadbeef".to_string(),
            actual: "cafebabe".to_string(),
        };
        assert!(
            !should_fallback_to_origin(&err),
            "ChecksumMismatch must not trigger origin fallback"
        );
    }

    /// A mirror returning a mismatched checksum on `fetch_metadata` must NOT
    /// cause an origin retry; the error must propagate as-is.
    #[tokio::test]
    async fn mirror_checksum_mismatch_does_not_fall_back_to_origin() {
        use crate::repository::Repository;
        use rv_config::MirrorConfig;

        // Mirror serves a valid body but a deliberately wrong SHA-256 sidecar.
        let body =
            b"<metadata><versioning><versions><version>1.0.0</version></versions></versioning></metadata>"
                .to_vec();
        let wrong_sha256 = "0".repeat(64);

        let mirror_hits = Arc::new(AtomicU32::new(0));
        let mirror_hits_clone = mirror_hits.clone();
        let mirror_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mirror");
        let mirror_addr = mirror_listener.local_addr().expect("mirror addr");
        let body_arc = Arc::new(body);
        let wrong_sha256_arc = Arc::new(wrong_sha256);
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match mirror_listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let mirror_hits = mirror_hits_clone.clone();
                let body_arc = body_arc.clone();
                let wrong_sha256_arc = wrong_sha256_arc.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    mirror_hits.fetch_add(1, Ordering::SeqCst);
                    let request = String::from_utf8_lossy(&total);
                    let response: Vec<u8> = if request.contains(".sha256") {
                        // Return a sidecar whose value does NOT match the body.
                        let sidecar = wrong_sha256_arc.as_str();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            sidecar.len(),
                            sidecar
                        )
                        .into_bytes()
                    } else if request.contains(".sha1") {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    } else {
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body_arc.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(&body_arc);
                        out
                    };
                    let _ = sock.write_all(&response).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let origin_hits = Arc::new(AtomicU32::new(0));
        let origin_hits_clone = origin_hits.clone();
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let origin_addr = origin_listener.local_addr().expect("origin addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match origin_listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let origin_hits = origin_hits_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    origin_hits.fetch_add(1, Ordering::SeqCst);
                    let _ = sock.shutdown().await;
                });
            }
        });

        let mirrors = MirrorSelector::from_mirrors(vec![MirrorConfig {
            id: Some("mismatch-mirror".to_string()),
            url: format!("http://{mirror_addr}/"),
            mirror_of: vec!["*".to_string()],
        }]);

        let _tmp = tempfile::tempdir().expect("tempdir");
        let cache = MetadataCache::new(&_tmp.path().join("metadata.db")).expect("cache");
        let client = RepoClient {
            client: plain_test_client(),
            runtime_client: plain_test_client(),
            auth: AuthStore::default(),
            mirrors,
            fetch: FetchConfig {
                retries: 0,
                timeout: Duration::from_secs(5),
            },
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            configured_hosts: ConfiguredHosts::default(),
            trusted_hosts: TrustedHosts::default(),
        };

        let origin = Repository::new(
            Some("central".to_string()),
            format!("http://{origin_addr}/"),
            true,
            false,
        );
        let coord = rv_version::Coord {
            group_id: "com.example".into(),
            artifact_id: "demo".into(),
            version: "1.0.0".parse().expect("version"),
            packaging: Some("jar".to_string()),
            classifier: None,
        };

        let result = client.fetch_metadata(&origin, &coord).await;
        assert!(
            matches!(result, Err(RepoError::ChecksumMismatch { .. })),
            "ChecksumMismatch from mirror must propagate, got {result:?}"
        );
        assert!(
            mirror_hits.load(Ordering::SeqCst) >= 1,
            "mirror must have been contacted"
        );
        assert_eq!(
            origin_hits.load(Ordering::SeqCst),
            0,
            "origin must NOT be retried on a mirror ChecksumMismatch"
        );
    }

    // -------------------------------------------------------------------------
    // offline guard for fetch_metadata and fetch_snapshot_metadata
    // -------------------------------------------------------------------------

    /// Calling `fetch_metadata` in offline mode with a cold cache must return
    /// `OfflineNotCached` without making any network connection.
    #[tokio::test]
    async fn fetch_metadata_offline_cold_cache_returns_offline_error() {
        use crate::repository::Repository;

        // Bind a listener on a random port so we can detect any accidental
        // network contact from the offline client.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hit_count = Arc::new(AtomicU32::new(0));
        let hit_count_clone = hit_count.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(_) => {
                        hit_count_clone.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => return,
                }
            }
        });

        let (client, _tmp) = test_client();
        let client = client.with_offline(true);
        let repo = Repository::new(Some("stub".into()), format!("http://{addr}/"), true, false);
        let coord = rv_version::Coord {
            group_id: "com.example".into(),
            artifact_id: "demo".into(),
            version: "1.0.0".parse().expect("version"),
            packaging: None,
            classifier: None,
        };

        let result = client.fetch_metadata(&repo, &coord).await;
        assert!(
            matches!(result, Err(RepoError::OfflineNotCached(_))),
            "offline + cold cache must return OfflineNotCached, got {result:?}"
        );
        assert_eq!(
            hit_count.load(Ordering::SeqCst),
            0,
            "no network connection must be made in offline mode"
        );
    }

    /// Calling `resolve_snapshot_version` in offline mode with a cold cache
    /// must return `OfflineNotCached` without making any network connection.
    #[tokio::test]
    async fn fetch_snapshot_metadata_offline_cold_cache_returns_offline_error() {
        use crate::repository::Repository;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hit_count = Arc::new(AtomicU32::new(0));
        let hit_count_clone = hit_count.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(_) => {
                        hit_count_clone.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => return,
                }
            }
        });

        let (client, _tmp) = test_client();
        let client = client.with_offline(true);
        let repo = Repository::new(
            Some("stub".into()),
            format!("http://{addr}/"),
            true,
            true, // snapshots enabled
        );
        let coord = rv_version::Coord {
            group_id: "com.example".into(),
            artifact_id: "demo".into(),
            version: "1.0-SNAPSHOT".parse().expect("version"),
            packaging: None,
            classifier: None,
        };

        let result = client.resolve_snapshot_version(&repo, &coord).await;
        assert!(
            matches!(result, Err(RepoError::OfflineNotCached(_))),
            "offline + cold cache must return OfflineNotCached for snapshot metadata, got {result:?}"
        );
        assert_eq!(
            hit_count.load(Ordering::SeqCst),
            0,
            "no network connection must be made in offline mode"
        );
    }

    // -------------------------------------------------------------------------
    // clone_repo_error exhaustive match (no silent catch-all)
    // -------------------------------------------------------------------------
}
