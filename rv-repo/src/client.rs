use std::borrow::Cow;
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

#[derive(Hash, PartialEq, Eq)]
struct SnapshotMissKey {
    scope: String,
    endpoint: String,
    path: String,
}

type AbsentSnapshots = Arc<Mutex<HashMap<SnapshotMissKey, String>>>;

type PomInflight = Arc<Mutex<HashMap<String, Arc<tokio::sync::OnceCell<Bytes>>>>>;

#[derive(Clone)]
pub struct RepoClient {
    /// Requests to a configured repository or mirror host. Its redirect
    /// policy and resolver read the frozen [`ConfiguredHosts`] set.
    /// It never consults runtime DNS trust. See
    /// [`RepoClient::http_client_for`].
    client: Client,
    /// Per-root-origin clients freeze their DNS exemptions before any request.
    root_redirects: Arc<RootRedirectClients>,
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
    /// POM downloads in progress, so concurrent callers share one download.
    pom_inflight: PomInflight,
    /// Remote snapshot metadata and POM 404s shared by this client's clones.
    /// Misses stay in memory and include the repository context and attempted endpoint.
    /// An origin fallback's 404 must not mask a recovering mirror.
    absent_snapshots: AbsentSnapshots,
    /// Hosts named by `rv.toml` (repositories, mirrors and proxies), frozen at
    /// construction. Selects the configured client for non-root requests.
    configured_hosts: ConfiguredHosts,
    /// Hosts the runtime client may dial even when they resolve off the public
    /// internet: the configured ones above plus whatever
    /// [`RepoClient::trust_repositories`] adds. See [`TrustedHosts`].
    trusted_hosts: TrustedHosts,
}

/// Root grants select cached clients without changing their DNS policies.
/// A concurrent grant must not disable address checks on an in-progress redirect.
#[derive(Default)]
struct RootRedirectClients {
    guard: RedirectGuard,
    proxies: Vec<reqwest::Proxy>,
    clients: RwLock<HashMap<String, Option<Client>>>,
    #[cfg(test)]
    accept_invalid_certs: bool,
}

impl RootRedirectClients {
    fn client_for(&self, url: &Url) -> Result<Option<Client>> {
        let Some(origin) = origin_key(url) else {
            return Ok(None);
        };
        {
            let clients = self.clients.read().unwrap_or_else(|e| e.into_inner());
            match clients.get(&origin) {
                None => return Ok(None),
                Some(Some(client)) => return Ok(Some(client.clone())),
                Some(None) => {}
            }
        }
        let mut clients = self.clients.write().unwrap_or_else(|e| e.into_inner());
        let entry = clients
            .get_mut(&origin)
            .expect("root issuer grant persists");
        if let Some(client) = entry {
            return Ok(Some(client.clone()));
        }
        let mut guard = self.guard.clone();
        guard.root_issuer = Some(origin);
        guard.exempt_hosts = ConfiguredHosts::new(
            guard
                .exempt_hosts
                .0
                .iter()
                .cloned()
                .chain(url.host_str().map(str::to_owned)),
        );
        let mut builder = http_client_builder()
            .redirect(trusted_redirect_policy(guard.clone()))
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                exempt_hosts: guard.exempt_hosts,
            }));
        for proxy in &self.proxies {
            builder = builder.proxy(proxy.clone());
        }
        #[cfg(test)]
        {
            builder = builder.danger_accept_invalid_certs(self.accept_invalid_certs);
        }
        let client = builder.build()?;
        *entry = Some(client.clone());
        Ok(Some(client))
    }
}

fn http_client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .tcp_keepalive(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(75))
        .no_proxy()
        .user_agent(USER_AGENT)
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

fn max_artifact_size_from_env() -> u64 {
    use crate::fetch::{DEFAULT_MAX_ARTIFACT_SIZE, MAX_ARTIFACT_SIZE_ENV};
    match std::env::var(MAX_ARTIFACT_SIZE_ENV) {
        Ok(val) => match val.trim().parse::<u64>() {
            Ok(limit) if limit > 0 => limit,
            _ => {
                tracing::warn!(
                    env = MAX_ARTIFACT_SIZE_ENV,
                    value = %val,
                    "ignoring invalid RV_MAX_ARTIFACT_SIZE value; expected a positive byte count"
                );
                DEFAULT_MAX_ARTIFACT_SIZE
            }
        },
        Err(_) => DEFAULT_MAX_ARTIFACT_SIZE,
    }
}

impl RepoClient {
    pub async fn new(config: &Config) -> Result<Self> {
        let fetch = FetchConfig {
            retries: config.network.retries,
            timeout: Duration::from_secs(config.network.timeout),
            max_artifact_size: max_artifact_size_from_env(),
            low_speed_limit: config.network.low_speed_limit,
            low_speed_time: Duration::from_secs(config.network.low_speed_time),
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
        let mut configured_builder = http_client_builder()
            .redirect(trusted_redirect_policy(guard.clone()))
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                exempt_hosts: guard.exempt_hosts.clone(),
            }));
        let mut runtime_builder = http_client_builder()
            // Same-origin only, so nothing this client dials can be redirected
            // anywhere its live exemption set has not already been asked about.
            .redirect(same_origin_redirect_policy())
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                exempt_hosts: trusted_hosts.clone(),
            }));

        let mut proxies = Vec::new();
        for proxy_config in config.proxies() {
            // Proxy auth (Basic and Bearer alike) is wired into the Proxy
            // object inside build_proxy so it rides the CONNECT for HTTPS
            // upstreams and is never leaked into the TLS tunnel.
            let proxy = build_proxy(proxy_config)?;
            configured_builder = configured_builder.proxy(proxy.clone());
            runtime_builder = runtime_builder.proxy(proxy.clone());
            proxies.push(proxy);
        }

        let cache_path = config.paths.metadata_db_path();
        let cache = MetadataCache::new(&cache_path)?;

        Ok(Self {
            client: configured_builder.build()?,
            root_redirects: Arc::new(RootRedirectClients {
                guard: guard.clone(),
                proxies,
                ..Default::default()
            }),
            runtime_client: runtime_builder.build()?,
            auth: AuthStore::from_config(config)?,
            mirrors: MirrorSelector::from_config(config),
            fetch,
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
            mirror_failures: Arc::new(MirrorFailureTracker::default()),
            pom_inflight: PomInflight::default(),
            absent_snapshots: AbsentSnapshots::default(),
            configured_hosts: guard.exempt_hosts,
            trusted_hosts,
        })
    }

    /// Root issuers use a client with a frozen exemption for their own host.
    /// Runtime/transitive DNS grants never widen any redirect client's screen.
    fn http_client_for(&self, url: &Url) -> Result<Cow<'_, Client>> {
        if let Some(client) = self.root_redirects.client_for(url)? {
            return Ok(Cow::Owned(client));
        }
        Ok(Cow::Borrowed(match url.host_str() {
            Some(host) if self.configured_hosts.contains(host) => &self.client,
            _ => &self.runtime_client,
        }))
    }

    /// Grant redirect issuer authority from the user's root model only.
    /// Do not call this for lockfile entries or policy-approved transitive repos.
    /// Origins shared with a root declaration share its authority, irrespective
    /// of which POM later asks to use that endpoint.
    pub fn trust_root_repositories<'a>(&self, repos: impl IntoIterator<Item = &'a Repository>) {
        let mut issuers = self
            .root_redirects
            .clients
            .write()
            .unwrap_or_else(|e| e.into_inner());
        for repo in repos {
            if let Ok(url) = Url::parse(&repo.url)
                && let Some(origin) = origin_key(&url)
            {
                issuers.entry(origin).or_insert(None);
            }
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
    /// `RepoClient::http_client_for` and `RedirectGuard`.
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
        self.effective_repository(repo).url
    }

    /// Return the repository that serves a request after mirror substitution.
    /// Maven records its ID in `_remote.repositories`.
    pub fn effective_repository(&self, repo: &Repository) -> Repository {
        self.mirrors.resolve_with_host_change(repo).0
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

        // Scope the cache key by (origin, resolved). When a mirror is
        // substituted, `fallback` holds the original origin repo; otherwise the
        // primary IS the origin.
        let origin_url = fallback
            .as_ref()
            .map(|f| f.url.as_str())
            .unwrap_or(primary.url.as_str());
        let cache_scope = Self::cache_scope_key(origin_url, &primary.url);

        if let Some(bytes) = self
            .cache_get_bytes(
                CacheTable::VersionList,
                &Self::metadata_cache_scope(&primary, &cache_scope, &version),
                &path,
            )
            .await?
        {
            debug!(
                group = %coord.group_id,
                artifact = %coord.artifact_id,
                "metadata cache hit"
            );
            return Metadata::from_bytes(&bytes);
        }

        // Offline blocks remote access, including after mirror substitution;
        // file repositories remain readable. `fetch_path` also guards remote
        // requests, but reporting this here preserves the metadata diagnostic.
        if self.offline && !primary.is_local() {
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
        // If the mirror is unavailable, retry the origin, as Maven does.
        let bytes = match self
            .fetch_model_bytes(&primary, &cache_scope, &path, &version, host_changed)
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
                let result = self
                    .fetch_model_bytes(&origin, &cache_scope, &path, &version, false)
                    .await;
                if result.is_ok() {
                    self.mirror_failures.record(&primary, &err);
                }
                result?
            }
            Err(err) => return Err(err),
        };
        let metadata = Metadata::from_bytes(&bytes)?;
        self.cache_insert_metadata(&primary, &cache_scope, &path, bytes.as_ref(), &version)
            .await;
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
        // Scope the snapshot-metadata cache key by (origin, resolved) so a
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
            // Maven reads a plain `-SNAPSHOT` layout from a local repository
            // that has no remote `maven-metadata.xml`.
            Err(RepoError::NotFound(_)) if primary.is_local() => {
                return Ok(SnapshotResolution {
                    version,
                    snapshot_timestamp: None,
                });
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

        // Scope the POM cache key by (origin, resolved) so a wildcard
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

        // Concurrent requests for the same parent or BOM share one download.
        let flight_key = format!("{cache_scope}\n{path}");
        let cell = {
            let mut inflight = self
                .pom_inflight
                .lock()
                .map_err(|_| RepoError::Io(std::io::Error::other("POM in-flight map poisoned")))?;
            Arc::clone(inflight.entry(flight_key.clone()).or_default())
        };
        let result = cell
            .get_or_try_init(|| async {
                // Another initializer may fill the cache before this caller acquires the cell.
                if let Some(bytes) = self
                    .cache_get_bytes(CacheTable::Pom, &cache_scope, &path)
                    .await?
                {
                    return Ok(bytes);
                }
                debug!(
                    group = %req.group_id,
                    artifact = %req.artifact_id,
                    version = %req.version,
                    "POM cache miss, fetching"
                );
                let bytes = match self
                    .fetch_model_bytes(
                        &primary,
                        &cache_scope,
                        &path,
                        &pom_req.version,
                        host_changed,
                    )
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
                        let result = self
                            .fetch_model_bytes(
                                &origin,
                                &cache_scope,
                                &path,
                                &pom_req.version,
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
                let ttl = primary.update_policy_ttl(&pom_req.version).as_secs() as i64;
                self.cache_insert_bytes_with_ttl(
                    CacheTable::Pom,
                    &cache_scope,
                    &path,
                    bytes.as_ref(),
                    ttl,
                )
                .await;
                Ok(bytes)
            })
            .await
            .cloned();
        if let Ok(mut inflight) = self.pom_inflight.lock() {
            inflight.remove(&flight_key);
        }
        result
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

        if self.offline && !primary.is_local() {
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
        // Check each actual endpoint, including a remote origin fallback from
        // a local mirror, before checksum policy or streaming can bypass it.
        if self.offline && !repo.is_local() {
            return Err(RepoError::OfflineNotCached(path.to_string()));
        }
        let checksum = self.fetch_checksum(repo, path, host_changed).await?;

        // Enforce required sidecars before streaming into CAS, so a hostile or
        // misconfigured mirror cannot leave unverified orphan blobs that later
        // retries would deduplicate against.
        if checksum.is_none() && self.require_checksums && !repo.is_local() {
            return Err(RepoError::MissingChecksum(path.to_string()));
        }

        let url = repo.url_for_path(path)?;
        let auth = self.auth.for_repository_with_policy(repo, host_changed)?;

        let blob = fetch_stream_to_store_verified(
            self.http_client_for(&url)?.as_ref(),
            &url,
            Some(&repo.base_url()?),
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
    /// This method funnels both the persist and the index commit through one
    /// held `StoreLock`, closing the GC race window documented on
    /// [`Store::put_stream_and_index`].
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

        if self.offline && !primary.is_local() {
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
        // Check each actual endpoint, including a remote origin fallback from
        // a local mirror, before checksum policy or streaming can bypass it.
        if self.offline && !repo.is_local() {
            return Err(RepoError::OfflineNotCached(path.to_string()));
        }
        let checksum = self.fetch_checksum(repo, path, host_changed).await?;

        if checksum.is_none() && self.require_checksums && !repo.is_local() {
            return Err(RepoError::MissingChecksum(path.to_string()));
        }

        let url = repo.url_for_path(path)?;
        let auth = self.auth.for_repository_with_policy(repo, host_changed)?;

        let blob = crate::fetch::fetch_stream_to_store_and_index(
            self.http_client_for(&url)?.as_ref(),
            &url,
            Some(&repo.base_url()?),
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
        // Local `file://` repositories are mutable by the user and cheap to
        // read; caching them would only serve stale content.
        if Self::cache_scope_is_local(repo_url) {
            return Ok(None);
        }
        let cache = self.cache.clone();
        let offline = self.offline;
        let repo_url: Arc<str> = repo_url.into();
        let path: Arc<str> = path.into();

        tokio::task::spawn_blocking(move || {
            let entry = cache.get(table, &repo_url, &path)?;
            match entry {
                Some(entry) => {
                    let now = crate::cache::now_epoch_seconds();
                    if !offline && MetadataCache::is_expired(entry.expires_at, now) {
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

    // These TTL rows are disposable fetch accelerators. Blob persistence,
    // artifact indexing and lockfile POM pins use Store and must still fail
    // if their writes fail.
    async fn cache_insert_bytes_with_ttl(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
        content: &[u8],
        ttl: i64,
    ) {
        if Self::cache_scope_is_local(repo_url) {
            return;
        }
        let cache = self.cache.clone();
        let repo_url: Arc<str> = repo_url.into();
        let path: Arc<str> = path.into();
        let content = content.to_vec();

        let result = tokio::task::spawn_blocking(move || {
            cache.insert_with_ttl(table, &repo_url, &path, &content, ttl)
        })
        .await
        .unwrap_or_else(|_| {
            Err(RepoError::Io(std::io::Error::other(
                "cache write task failed",
            )))
        });
        if let Err(err) = result {
            warn_cache_write_failure(&err);
        }
    }

    async fn cache_insert_metadata(
        &self,
        repo: &Repository,
        cache_scope: &str,
        path: &str,
        content: &[u8],
        version: &str,
    ) {
        let ttl = repo.update_policy_ttl(version).as_secs() as i64;
        self.cache_insert_bytes_with_ttl(
            CacheTable::VersionList,
            &Self::metadata_cache_scope(repo, cache_scope, version),
            path,
            content,
            ttl,
        )
        .await
    }

    fn metadata_cache_scope(repo: &Repository, scope: &str, version: &str) -> String {
        // Neither tightening checksum policy nor shortening update policy may
        // reuse metadata accepted under the previous, more permissive policy.
        format!(
            "{scope}\u{1f}checksum-fail={}\u{1f}update={}",
            repo.metadata_checksum_policy(version) == rv_config::ChecksumPolicy::Fail,
            repo.update_policy_for(version),
        )
    }

    /// Build the metadata/POM cache scope key for a `(origin, resolved)` repo
    /// pair.
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

    fn cache_scope_is_local(scope: &str) -> bool {
        let resolved_url = scope.split('\u{1f}').nth(1).unwrap_or(scope);
        Url::parse(resolved_url).is_ok_and(|url| url.scheme() == "file")
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

    /// Remember only authoritative remote snapshot misses.
    /// Transient failures, rejected redirects, and checksum errors must remain retryable.
    /// Local repositories may gain files during this client's lifetime.
    async fn fetch_model_bytes(
        &self,
        repo: &Repository,
        cache_scope: &str,
        path: &str,
        version: &str,
        host_changed: bool,
    ) -> Result<Bytes> {
        let key = (is_snapshot_version(version) && !repo.is_local() && !self.offline).then(|| {
            SnapshotMissKey {
                scope: cache_scope.to_string(),
                endpoint: repo.url.clone(),
                path: path.to_string(),
            }
        });
        if let Some(key) = &key
            && let Some(missing) = self
                .absent_snapshots
                .lock()
                .ok()
                .and_then(|misses| misses.get(key).cloned())
        {
            debug!(path, "snapshot not-found cache hit");
            return Err(RepoError::NotFound(missing));
        }
        let result = self
            .fetch_with_checksums(repo, path, version, host_changed)
            .await;
        if let (Some(key), Err(RepoError::NotFound(missing))) = (key, &result)
            && let Ok(mut misses) = self.absent_snapshots.lock()
        {
            misses.insert(key, missing.clone());
        }
        result
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
            .cache_get_bytes(
                CacheTable::VersionList,
                &Self::metadata_cache_scope(repo, cache_scope, version),
                &path,
            )
            .await?
        {
            return Metadata::from_bytes(&bytes);
        }

        // Offline blocks remote access, including after mirror substitution;
        // file repositories remain readable. `fetch_path` also guards remote
        // requests, but reporting this here preserves the metadata diagnostic.
        if self.offline && !repo.is_local() {
            return Err(RepoError::OfflineNotCached(format!(
                "{path} (repo: {})",
                repo.url
            )));
        }

        let bytes = self
            .fetch_model_bytes(repo, cache_scope, &path, version, host_changed)
            .await?;
        let metadata = Metadata::from_bytes(&bytes)?;
        self.cache_insert_metadata(repo, cache_scope, &path, bytes.as_ref(), version)
            .await;
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
        version: &str,
        host_changed: bool,
    ) -> Result<Bytes> {
        // Only repository metadata is mutable enough to tolerate stale
        // sidecars. POMs and artifact payloads retain mandatory verification.
        let remote_metadata = !repo.is_local() && path.ends_with("/maven-metadata.xml");
        let fail = repo.metadata_checksum_policy(version) == rv_config::ChecksumPolicy::Fail;
        for attempt in 0..=1 {
            // A publisher may update metadata and its sidecar separately, so refetch both.
            let (bytes, checksum) = tokio::try_join!(
                self.fetch_path(repo, path, host_changed),
                self.fetch_checksum(repo, path, host_changed),
            )?;
            match checksum {
                Some(checksum) => {
                    if let Err(err) = verify_checksum(&bytes, &checksum, path) {
                        if !remote_metadata {
                            return Err(err);
                        }
                        if attempt == 0 {
                            continue;
                        }
                        if fail {
                            return Err(err);
                        }
                        // Even Maven's ignore policy emits this diagnostic in
                        // rv, so accepting inconsistent metadata is visible.
                        warn!(
                            sec_code = "METADATA_CHECKSUM_MISMATCH",
                            repository_url = %redact_url(&repo.base_url()?),
                            path,
                            "metadata checksum mismatch after retry; using fetched metadata"
                        );
                    } else {
                        debug!(path, algorithm = ?checksum.algorithm, "verified checksum");
                    }
                }
                None if !repo.is_local()
                    && (self.require_checksums || (remote_metadata && fail)) =>
                {
                    return Err(RepoError::MissingChecksum(path.to_string()));
                }
                None => warn!(path, "missing checksum for artifact"),
            }
            return Ok(bytes);
        }
        unreachable!("the second metadata fetch returns a result")
    }

    async fn fetch_checksum(
        &self,
        repo: &Repository,
        path: &str,
        host_changed: bool,
    ) -> Result<Option<Checksum>> {
        if self.offline && !repo.is_local() {
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
                self.http_client_for(&checksum_url)?.as_ref(),
                &checksum_url,
                Some(&repo.base_url()?),
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
        if self.offline && !repo.is_local() {
            return Err(RepoError::OfflineNotCached(path.to_string()));
        }
        let url = repo.url_for_path(path)?;
        let auth = self.auth.for_repository_with_policy(repo, host_changed)?;

        fetch_bytes(
            self.http_client_for(&url)?.as_ref(),
            &url,
            Some(&repo.base_url()?),
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
/// from `rv.toml` alone. Root issuers enter `root_issuer`, without target
/// exemptions. A root declaration cannot authorize a mirror redirect to its
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
/// Each HTTP client fixes these fields at construction, including root clients. The policy
/// and the resolver read `exempt_hosts` at different moments, so a redirect
/// target that was not exempt at policy-evaluation time must be DNS-screened at
/// connect time, regardless of concurrent trust grants. Runtime trust lives in
/// a separate [`TrustedHosts`] set belonging to a separate, same-origin-only
/// client, so no grant can land in that window.
#[derive(Debug, Default, Clone)]
struct RedirectGuard {
    origins: HashSet<String>,
    /// Additional issuer only; never a redirect-target exemption.
    root_issuer: Option<String>,
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
/// origin present when the client was built, or its root-model issuer.
/// Both sides of that hop must use
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
        if !self.origins.contains(&issuer_origin)
            && self.root_issuer.as_ref() != Some(&issuer_origin)
        {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::OriginNotConfigured,
                details: format!(
                    "redirect issuer {issuer_origin} is not a configured repository, mirror or root-model repository"
                ),
            });
        }
        if issuer.scheme() != "https" {
            return Err(RedirectPolicyError {
                kind: RedirectRejectionKind::InsecureOrigin,
                details: format!(
                    "plain-http trusted origin {issuer_origin} may redirect only within its own origin"
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
/// `trusted_redirect_policy` with the configured repository and mirror
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

fn warn_cache_write_failure(error: &RepoError) {
    static WARNING: std::sync::Once = std::sync::Once::new();
    WARNING.call_once(|| {
        // Never log the error text: scopes may contain URL credentials, and
        // SQLite messages (including trigger errors) can contain arbitrary data.
        let sqlite = match error {
            RepoError::DbError(error) => error.sqlite_error(),
            _ => None,
        };
        warn!(
            sqlite_code = ?sqlite.map(|error| error.code),
            sqlite_extended_code = ?sqlite.map(|error| error.extended_code),
            "metadata cache write failed; continuing without this cache update (further warnings suppressed)"
        );
    });
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
mod tests;
