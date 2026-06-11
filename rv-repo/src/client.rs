use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use regex::Regex;
use reqwest::Client;
use tracing::{debug, warn};

use rv_config::{BlobId, Config};

use rv_version::Coord;

use crate::artifact::ArtifactRequest;
use crate::auth::AuthStore;
use crate::cache::{CacheTable, MetadataCache};
use crate::error::{RepoError, Result};
use crate::fetch::{
    Checksum, ChecksumAlgorithm, FetchConfig, FetchProgress, fetch_bytes,
    fetch_stream_to_store_verified, fetch_text, parse_checksum, verify_checksum,
};
use crate::metadata::Metadata;
use crate::mirror::MirrorSelector;
use crate::proxy::build_proxy;
use crate::repository::{Repository, is_snapshot_version};
use rv_store::Store;

#[derive(Clone)]
pub struct RepoClient {
    client: Client,
    auth: AuthStore,
    mirrors: MirrorSelector,
    fetch: FetchConfig,
    progress: Option<Arc<dyn FetchProgress>>,
    cache: MetadataCache,
    offline: bool,
    require_checksums: bool,
}

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
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(10)
            // Keep long-lived idle connections healthy and reclaim them
            // before the typical 60s NAT/idle-timeout would. Pairs with
            // pool_idle_timeout to bound the keep-alive window.
            .tcp_keepalive(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(75))
            .redirect(same_origin_redirect_policy())
            .user_agent(USER_AGENT);

        for proxy_config in config.proxies() {
            // Proxy auth (Basic and Bearer alike) is wired into the Proxy
            // object inside build_proxy so it rides the CONNECT for HTTPS
            // upstreams and is never leaked into the TLS tunnel.
            let proxy = build_proxy(proxy_config)?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;
        let cache_path = config.paths.metadata_db_path();
        let cache = MetadataCache::new(&cache_path)?;

        Ok(Self {
            client,
            auth: AuthStore::from_config(config)?,
            mirrors: MirrorSelector::from_config(config),
            fetch,
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
        })
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
                warn!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "metadata fetch failed against mirror; retrying against origin"
                );
                self.fetch_with_checksums(&origin, &path, false).await?
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
                warn!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "snapshot metadata fetch failed against mirror; retrying against origin"
                );
                self.fetch_snapshot_metadata(
                    &origin,
                    &cache_scope,
                    coord.group_id.as_str(),
                    coord.artifact_id.as_str(),
                    &version,
                    false,
                )
                .await?
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
                warn!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "POM fetch failed against mirror; retrying against origin"
                );
                self.fetch_with_checksums(&origin, &path, false).await?
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
                warn!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "artifact fetch failed against mirror; retrying against origin"
                );
                self.fetch_artifact_to_store_attempt(&origin, &path, false, store)
                    .await
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
        let auth = self.auth.for_repository_with_policy(repo, host_changed);

        let blob = fetch_stream_to_store_verified(
            &self.client,
            &url,
            auth,
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
            Ok(blob) => Ok(blob),
            Err(err) if fallback.is_some() && should_fallback_to_origin(&err) => {
                let origin = fallback.expect("fallback present");
                warn!(
                    mirror_url = %primary.url,
                    origin_url = %origin.url,
                    error = %err,
                    "atomic artifact fetch failed against mirror; retrying against origin"
                );
                self.fetch_artifact_to_store_and_index_attempt(&origin, &path, false, store, key)
                    .await
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
        let auth = self.auth.for_repository_with_policy(repo, host_changed);

        let blob = crate::fetch::fetch_stream_to_store_and_index(
            &self.client,
            &url,
            auth,
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
            let auth = self.auth.for_repository_with_policy(repo, host_changed);
            match fetch_text(&self.client, &checksum_url, auth, &self.fetch).await {
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
        let auth = self.auth.for_repository_with_policy(repo, host_changed);

        fetch_bytes(
            &self.client,
            &url,
            auth,
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
            RepoError::UnexpectedResponse(_) | RepoError::Http(_) | RepoError::InvalidMetadata(_)
        )
}

/// User-Agent advertised on every outbound HTTP request. Some private
/// repositories (and many CDN WAFs) reject requests without a UA. Pinning
/// to `raeva/<crate-version>` keeps the value stable and self-describing.
pub(crate) const USER_AGENT: &str = concat!("raeva/", env!("CARGO_PKG_VERSION"));

/// Redirect policy that refuses cross-origin redirects and caps the chain at
/// 5 hops. reqwest's default (`Policy::limited(10)`) follows redirects across
/// any origin, which would let a hostile mirror bounce us to `http://attacker/`,
/// bypassing both `Repository::url_for_path`'s origin check and TLS.
pub fn same_origin_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let previous_origin = attempt.previous().last().map(|prev| prev.origin());
        if previous_origin != Some(attempt.url().origin()) {
            attempt.error("cross-origin redirect rejected")
        } else if attempt.previous().len() >= 5 {
            attempt.error("too many redirects")
        } else {
            attempt.follow()
        }
    })
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
    use secrecy::Secret;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Build a minimal in-process `RepoClient`, skipping `Config` so tests can
    /// isolate fetch/checksum/mirror logic. The returned `TempDir` must outlive
    /// the `RepoClient`: dropping it deletes the on-disk SQLite cache that
    /// `MetadataCache` holds open.
    fn test_client() -> (RepoClient, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = MetadataCache::new(&tmp.path().join("metadata.db")).expect("cache");
        let client = RepoClient {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(same_origin_redirect_policy())
                .user_agent(USER_AGENT)
                .build()
                .expect("client"),
            auth: AuthStore::default(),
            mirrors: MirrorSelector::default(),
            fetch: FetchConfig::default(),
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
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
        let result = client.get(format!("http://{addr}/loop")).send().await;
        assert!(
            result.is_err(),
            "redirect chain over the cap must surface as an error"
        );
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
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(same_origin_redirect_policy())
                .user_agent(USER_AGENT)
                .build()
                .expect("client"),
            auth,
            mirrors,
            fetch: FetchConfig::default(),
            progress: None,
            cache,
            offline: false,
            require_checksums: false,
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
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(same_origin_redirect_policy())
                .user_agent(USER_AGENT)
                .build()
                .expect("client"),
            auth,
            mirrors,
            fetch: FetchConfig::default(),
            progress: None,
            cache,
            offline: false,
            require_checksums: true,
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
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(same_origin_redirect_policy())
                .user_agent(USER_AGENT)
                .build()
                .expect("client"),
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
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(same_origin_redirect_policy())
                .user_agent(USER_AGENT)
                .build()
                .expect("client"),
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
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(same_origin_redirect_policy())
                .user_agent(USER_AGENT)
                .build()
                .expect("client"),
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
