//! Metadata and POM reads: the metadata cache, snapshot resolution and the
//! checksum checks on model bytes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tracing::warn;
use url::Url;

use rv_config::redact_url;
use rv_maven_types::{
    Coord, CoordinateField, Digest, Gav, Sha256, is_snapshot_version, layout::metadata_path,
    resolves_through_snapshot_metadata,
};

use super::requests::DeferredWarnings;
use super::{RepoClient, SnapshotResolution, validate_coord_components};
use crate::artifact::ArtifactRequest;
use crate::auth::{Auth, SentCredential};
use crate::error::{RepoError, Result};
use crate::fetch::verify_checksum;
use crate::metadata::Metadata;
use crate::repository::Repository;
use crate::routing::Route;
use rv_store::metadata_cache::{CacheEntry, CacheTable, MetadataCache, now_epoch_seconds};

/// What sees the bytes of a POM as soon as they arrive; see
/// [`announcing_poms`].
pub type PomArrival = Arc<dyn Fn(&Bytes) + Send + Sync>;

tokio::task_local! {
    static ARRIVAL: PomArrival;
}

/// Run `read`, handing the bytes of each POM it downloads to `arrival` as
/// soon as they arrive, before its checksum file has answered and so before
/// they are verified. A repository can take far longer to answer for a
/// missing `.sha256` than for the POM, and a caller may learn what to fetch
/// next from the bytes meanwhile. A POM `read` finds cached, or that another
/// read is downloading, is not handed over.
pub async fn announcing_poms<T>(arrival: PomArrival, read: impl Future<Output = T>) -> T {
    ARRIVAL.scope(arrival, read).await
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) struct MissKey {
    scope: String,
    endpoint: String,
    path: String,
}

/// Each miss, with the credential generation it was recorded under.
pub(super) type AbsentPaths = Arc<Mutex<HashMap<MissKey, (Miss, u64)>>>;

/// A remote answer the same request gets again in this run: a 404, a 401
/// or 403 to the same credential, or a busy answer to the file itself, not
/// its checksum, that outlasted its retries, which a speculative read and
/// the read that joins it would otherwise each wait out.
#[derive(Clone)]
pub(super) enum Miss {
    Absent(String),
    Refused {
        status: reqwest::StatusCode,
        url: String,
        sent: Option<Box<SentCredential>>,
    },
    Busy {
        status: reqwest::StatusCode,
        url: String,
        retry_after: Option<std::time::Duration>,
        /// The attempts made, when there were retries.
        attempts: Option<usize>,
    },
}

impl Miss {
    fn of(err: &RepoError, path: &str) -> Option<Self> {
        match err.cause() {
            RepoError::NotFound(missing) => Some(Self::Absent(missing.clone())),
            RepoError::Unauthorized { status, url, sent }
                if matches!(status.as_u16(), 401 | 403) =>
            {
                Some(Self::Refused {
                    status: *status,
                    url: url.clone(),
                    sent: sent.clone(),
                })
            }
            RepoError::HttpStatus {
                status,
                url,
                retry_after,
            } if err.is_transient() && url.ends_with(path) => Some(Self::Busy {
                status: *status,
                url: url.clone(),
                retry_after: *retry_after,
                attempts: match err {
                    RepoError::Retried { attempts, .. } => Some(*attempts),
                    _ => None,
                },
            }),
            _ => None,
        }
    }

    /// The status a miss is kept as across runs. A busy answer is not kept.
    fn kept_status(&self) -> Option<u16> {
        match self {
            Self::Absent(_) => Some(404),
            Self::Refused { status, .. } => Some(status.as_u16()),
            Self::Busy { .. } => None,
        }
    }

    /// The miss a status [`Self::kept_status`] kept for `path` on `route`
    /// stands for, refused to `sent`, naming the URL as a fetch does.
    fn kept(status: &[u8], route: &Route<'_>, path: &str, sent: Option<&Auth>) -> Option<Self> {
        let url = redact_url(route.endpoint.url_for_path(path).ok()?);
        match status {
            b"404" => Some(Self::Absent(format!("{url} (HTTP 404)"))),
            b"401" | b"403" => Some(Self::Refused {
                status: reqwest::StatusCode::from_bytes(status).ok()?,
                url,
                sent: sent.map(|auth| Box::new(auth.sent.clone())),
            }),
            _ => None,
        }
    }

    fn error(self) -> RepoError {
        match self {
            Self::Absent(missing) => RepoError::NotFound(missing),
            Self::Refused { status, url, sent } => RepoError::Unauthorized { status, url, sent },
            Self::Busy {
                status,
                url,
                retry_after,
                attempts,
            } => {
                let error = RepoError::HttpStatus {
                    status,
                    url,
                    retry_after,
                };
                match attempts {
                    Some(attempts) => RepoError::Retried {
                        attempts,
                        error: Box::new(error),
                    },
                    None => error,
                }
            }
        }
    }
}

/// One lock per remote metadata path, held while it is fetched, so that
/// concurrent readers of a path ask the repository once. Not a fair lock:
/// one hands a released turn to the next waiter even while that waiter's
/// worker runs other work, which stalls every reader queued behind it.
pub(super) type MetadataFlights = Arc<Mutex<HashMap<MissKey, Arc<futures::lock::Mutex<()>>>>>;

pub(super) type PomInflight = Arc<Mutex<HashMap<String, Arc<tokio::sync::OnceCell<Bytes>>>>>;

/// What this client's reads of the metadata cache found, by scope and path,
/// then by the settings that decide whether a row is usable: the metadata
/// with the time its row expires, or `None` when no row was usable. A write
/// through this client or a clone forgets the scope and path. Every module
/// of a reactor reads the same snapshot and version metadata, and reading it
/// from `metadata.db` each time was much of a warm resolution's time.
pub(super) type MetadataMemo = Arc<Mutex<HashMap<String, HashMap<String, MemoizedMetadata>>>>;

type MemoizedMetadata = Option<(Metadata, i64)>;

const MAX_MEMO_BYTES: usize = 64 * 1024 * 1024;

/// Verified POMs of fixed content this client has read, by in-flight key.
/// A resolution reads the same parents and BOMs for many of its models,
/// and reading each from `metadata.db` every time was much of a warm
/// resolution's time.
#[derive(Default)]
pub(super) struct PomMemo {
    poms: HashMap<String, Bytes>,
    bytes: usize,
}

impl PomMemo {
    fn get(&self, key: &str) -> Option<Bytes> {
        self.poms.get(key).cloned()
    }

    fn insert(&mut self, key: &str, bytes: &Bytes) {
        if self.bytes + bytes.len() > MAX_MEMO_BYTES || self.poms.contains_key(key) {
            return;
        }
        self.bytes += bytes.len();
        self.poms.insert(key.to_string(), bytes.clone());
    }
}

const MAX_HELD_BYTES: usize = 64 * 1024 * 1024;

/// POMs [`RepoClient::prefetch_pom`] fetched and verified, by in-flight
/// key, held in memory until a [`RepoClient::fetch_pom`] reads them. Only
/// that read writes one to the metadata cache and logs its warnings, so a
/// POM this run never reads leaves no trace, and the next run that needs
/// it fetches it and warns, as without the prefetch.
#[derive(Default)]
pub(super) struct HeldPoms {
    poms: HashMap<String, HeldPom>,
    bytes: usize,
}

struct HeldPom {
    bytes: Bytes,
    ttl: i64,
    checked: Checked,
    /// `None` once a read adopted the POM and is writing it to the cache.
    warnings: Option<DeferredWarnings>,
}

impl HeldPoms {
    fn full(&self) -> bool {
        self.bytes >= MAX_HELD_BYTES
    }

    fn get(&self, key: &str) -> Option<Bytes> {
        self.poms.get(key).map(|held| held.bytes.clone())
    }

    fn insert(&mut self, key: String, held: HeldPom) {
        self.bytes += held.bytes.len();
        if let Some(old) = self.poms.insert(key, held) {
            self.bytes -= old.bytes.len();
        }
    }

    /// The POM held under `key` and its warnings, for the one read that
    /// adopts it. The bytes stay held until [`Self::remove`], so a read
    /// arriving before the cache has them still finds them here.
    fn adopt(&mut self, key: &str) -> Option<(Bytes, i64, Checked, DeferredWarnings)> {
        let held = self.poms.get_mut(key)?;
        let warnings = held.warnings.take()?;
        Some((held.bytes.clone(), held.ttl, held.checked, warnings))
    }

    fn remove(&mut self, key: &str) {
        if let Some(held) = self.poms.remove(key) {
            self.bytes -= held.bytes.len();
        }
    }
}

/// Who a POM or version list is read for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PomRead {
    Use,
    /// [`RepoClient::prefetch_pom`] or [`RepoClient::prefetch_metadata`]:
    /// its warnings wait for a use.
    Prefetch,
}

#[derive(Debug, Clone)]
pub(super) struct SnapshotPath {
    pub(super) dir_version: String,
    pub(super) file_version: String,
}

impl RepoClient {
    /// The `maven-metadata.xml` for `coord` from `repo` or the mirror that
    /// serves it: the version-level file for a snapshot version, the
    /// artifact-level version list otherwise.
    ///
    /// Served from the metadata cache while the repository's update policy
    /// allows. A fetched copy is checked against its checksum sidecar; a
    /// mismatch is refetched once and then fails only under a `fail`
    /// checksum policy.
    ///
    /// # Errors
    ///
    /// [`RepoError::InvalidCoord`] for an unsafe coordinate,
    /// [`RepoError::SnapshotsDisabled`] or [`RepoError::ReleasesDisabled`]
    /// for a version kind the repository disables, [`RepoError::Config`]
    /// for an unsupported checksum policy that covers the request,
    /// [`RepoError::OfflineNotCached`], [`RepoError::InvalidMetadata`], and
    /// the request errors of any fetch.
    pub async fn fetch_metadata(&self, repo: &Repository, coord: &Coord) -> Result<Metadata> {
        let version = coord.version.to_string();
        self.read_metadata(
            &self.router.route(repo),
            coord.group_id.as_str(),
            coord.artifact_id.as_str(),
            &version,
            PomRead::Use,
        )
        .await
    }

    /// Read the `maven-metadata.xml` for `coord` from `repo` ahead of a
    /// [`Self::fetch_metadata`] for it, as that would, and return it. As
    /// for [`Self::prefetch_pom`], a fetched file is held in memory until
    /// `fetch_metadata` reads it. Offline, for a snapshot, once the held
    /// files fill their budget and on any failure this returns `None`; only
    /// a 404 is kept, as a read keeps it.
    pub async fn prefetch_metadata(&self, repo: &Repository, coord: &Coord) -> Option<Metadata> {
        let version = coord.version.to_string();
        if self.offline || is_snapshot_version(&version) || self.held().full() {
            return None;
        }
        let read = async {
            let route = self.router.route(repo);
            let (group, artifact) = (coord.group_id.as_str(), coord.artifact_id.as_str());
            (self.read_metadata(&route, group, artifact, &version, PomRead::Prefetch)).await
        };
        self.prefetching(read).await.ok()
    }

    /// The file version a `-SNAPSHOT` `coord` resolves to in `repo`, read
    /// from its version-level `maven-metadata.xml` for the coordinate's
    /// classifier and extension (`jar` when it has none).
    ///
    /// # Errors
    ///
    /// [`RepoError::InvalidCoord`] when `coord` is not a snapshot version,
    /// [`RepoError::InvalidMetadata`] when the metadata names no usable
    /// version, and the errors of [`RepoClient::fetch_metadata`].
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
        let route = self.router.route(repo);
        self.resolve_snapshot_version_routed(&route, coord).await
    }

    /// Snapshot-metadata resolution on a route the caller already decided,
    /// so the metadata sub-fetch of an artifact or POM request sends the
    /// credential that request sends.
    pub(super) async fn resolve_snapshot_version_routed(
        &self,
        route: &Route<'_>,
        coord: &Coord,
    ) -> Result<SnapshotResolution> {
        let version = coord.version.to_string();
        self.ensure_repo_allows_version(&route.endpoint, &version)?;
        // A restore fetches the pinned build without its metadata, and the
        // cached metadata may name another build. Offline, which sees no
        // upstream change anyway, and in a frozen check, a pinned build this
        // repository served stands.
        if (self.offline && !route.endpoint.is_local()) || self.pinned_snapshots {
            let gav = Gav::new(
                coord.group_id.as_str(),
                coord.artifact_id.as_str(),
                &version,
            );
            // A POM is checked under its own build, which may differ from
            // its file's and come from another repository; a file from the
            // repository the lock records for it stands without one.
            let classifier = coord.classifier.as_deref().filter(|c| !c.is_empty());
            let extension = coord.packaging.as_deref().unwrap_or("jar");
            let is_pom = extension == "pom" && classifier.is_none();
            let builds = self.lock_snapshots.get(&gav).into_iter().flatten().rev();
            for pin in builds {
                let this_file = pin
                    .file
                    .as_ref()
                    .is_some_and(|(pinned, pinned_classifier)| {
                        pinned == extension && pinned_classifier.as_deref() == classifier
                    });
                if !is_pom && !this_file {
                    continue;
                }
                // A build of `None` is the base `-SNAPSHOT` file.
                let at = |stamp: Option<&rv_maven_types::SnapshotStamp>| match stamp {
                    Some(stamp) => stamp.resolved_version(&version),
                    None => Some(version.clone()),
                };
                let stamp = if is_pom {
                    pin.pom.as_ref()
                } else {
                    pin.build.as_ref()
                };
                let (Some(resolved), Some(pom_version)) = (at(stamp), at(pin.pom.as_ref())) else {
                    continue;
                };
                let pom =
                    ArtifactRequest::new(gav.group.as_str(), gav.artifact.as_str(), &pom_version)
                        .pom()
                        .to_path_with_versions(&resolved_directory(&pom_version), &pom_version);
                // A frozen check takes the pinned POM build from the
                // repository the lock records for the POM, and a file's from
                // any the lock records for the file.
                let recorded = |origin: &String| self.origins.matches(origin, &route.origin);
                let served = if is_pom {
                    self.lock_missing_poms.contains(&pom)
                        || (self.pinned_snapshots && pin.pom_origins.iter().any(recorded))
                } else {
                    pin.file_origins.iter().any(recorded)
                };
                if served
                    || matches!(
                        self.cache_get_bytes(CacheTable::Pom, &route.scope, &pom)
                            .await,
                        Ok(Some(_))
                    )
                {
                    return Ok(SnapshotResolution {
                        version: resolved,
                        metadata_served: true,
                        updated: None,
                        candidate: crate::SnapshotCandidate::Pinned,
                    });
                }
            }
            // The same holds for a pinned non-unique file.
            let plain = ArtifactRequest::new(gav.group.as_str(), gav.artifact.as_str(), &version)
                .pom()
                .to_path_with_versions(&version, &version);
            if self.lock_pin(&plain).is_some()
                && let Ok(Some(_)) = self
                    .cache_get_bytes(CacheTable::Pom, &route.scope, &plain)
                    .await
            {
                return Ok(SnapshotResolution {
                    version,
                    metadata_served: true,
                    updated: None,
                    candidate: crate::SnapshotCandidate::Pinned,
                });
            }
        }
        let metadata = match self
            .read_metadata(
                route,
                coord.group_id.as_str(),
                coord.artifact_id.as_str(),
                &version,
                PomRead::Use,
            )
            .await
        {
            Ok(metadata) => metadata,
            // Maven reads a plain `-SNAPSHOT` layout from a local repository
            // that has no remote `maven-metadata.xml`.
            Err(RepoError::NotFound(_)) if route.endpoint.is_local() => {
                return Ok(SnapshotResolution::base(version));
            }
            Err(err) => return Err(err),
        };

        let extension = coord.packaging.as_deref().unwrap_or("jar");
        let resolved = metadata
            .snapshot_version_for(coord.classifier.as_deref(), extension)
            .ok_or_else(|| {
                RepoError::InvalidMetadata("missing snapshot version data".to_string())
            })?;

        // The snapshot `<value>` comes straight from server-controlled
        // maven-metadata.xml and is about to be spliced into the artifact
        // filename and joined onto the repo path. Run it through the same
        // path-traversal/SSRF gate as the requested coordinate components so a
        // hostile/compromised repo cannot steer the fetch to an arbitrary path
        // (e.g. `<value>../../../../private/secret</value>`).
        // The value is server text, so the error names only its size.
        rv_maven_types::validate_coordinate_component(CoordinateField::Version, &resolved)
            .map_err(|_| {
                RepoError::InvalidMetadata(format!(
                    "maven-metadata.xml for {coord} names a snapshot version that is not a valid \
                     version ({} bytes)",
                    resolved.len()
                ))
            })?;

        Ok(SnapshotResolution {
            version: resolved,
            metadata_served: true,
            updated: metadata
                .snapshot_updated_for(coord.classifier.as_deref(), extension)
                .map(str::to_string),
            candidate: metadata.snapshot_candidate(coord.classifier.as_deref(), extension),
        })
    }

    /// The POM bytes for `req` (its packaging and classifier are ignored)
    /// from `repo` or the mirror that serves it, resolving a `-SNAPSHOT`
    /// to its timestamped file first.
    ///
    /// Served from the metadata cache when a usable copy is there. A
    /// release or timestamped POM verified against its sidecar is cached
    /// without expiry; any other copy expires with the update policy.
    /// Concurrent requests for the same POM share one download.
    ///
    /// # Errors
    ///
    /// [`RepoError::InvalidCoord`] for an unsafe coordinate,
    /// [`RepoError::MissingChecksum`] or [`RepoError::ChecksumMismatch`]
    /// when the bytes cannot be verified, and the request errors of any
    /// fetch.
    pub async fn fetch_pom(&self, repo: &Repository, req: &ArtifactRequest) -> Result<Bytes> {
        self.fetch_pom_with_path(repo, req)
            .await
            .map(|(bytes, _)| bytes)
    }

    /// Read the POM for `req` from `repo` ahead of a [`Self::fetch_pom`]
    /// for it, as that would, and return its bytes. A fetched POM is held
    /// in memory until `fetch_pom` reads it; only then does it reach the
    /// metadata cache and are its warnings logged, so a POM that is never
    /// used leaves nothing behind. Offline, for a `-SNAPSHOT` and once the
    /// held POMs fill their budget this asks nothing and returns `None`, and
    /// the later `fetch_pom` makes its own requests. A failed fetch keeps
    /// only the miss a `fetch_pom` would keep.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::fetch_pom`].
    pub async fn prefetch_pom(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
    ) -> Result<Option<Bytes>> {
        if self.offline || req.validate().is_err() || req.pom().is_snapshot() || self.held().full()
        {
            return Ok(None);
        }
        let read = self.read_pom(repo, req, PomRead::Prefetch);
        let (bytes, _) = self.prefetching(read).await?;
        Ok(Some(bytes))
    }

    /// The POM bytes and the repository-relative path actually read, including
    /// the resolved timestamp when `req` names a snapshot.
    ///
    /// # Errors
    ///
    /// The same errors as [`Self::fetch_pom`].
    pub async fn fetch_pom_with_path(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
    ) -> Result<(Bytes, String)> {
        req.validate().map_err(RepoError::InvalidCoord)?;
        self.read_pom(repo, req, PomRead::Use).await
    }

    /// The time before which a row of `path` in `table` is fetched again,
    /// under `--update`.
    fn renew_before(&self, table: CacheTable, path: &str) -> Option<i64> {
        // A release or timestamped POM names fixed content; `--update`
        // renews only what a deploy can change.
        let mutable = !matches!(table, CacheTable::Pom)
            || path
                .rsplit('/')
                .next()
                .is_some_and(|file| file.ends_with("SNAPSHOT.pom"));
        self.refresh_before.filter(|_| mutable && !self.offline)
    }

    /// Which of `poms` [`Self::seed_pinned_pom`] would cache: raeva.lock pins
    /// those bytes for the file and the cache holds no current copy of them.
    /// One cache read covers them all.
    pub(crate) async fn unseeded_poms(
        &self,
        poms: &[(&Repository, ArtifactRequest, &Sha256)],
    ) -> Result<Vec<bool>> {
        // Rows share a few repositories, and selecting a mirror per row costs.
        let mut scopes: Vec<(&Repository, String)> = Vec::new();
        let keys: Vec<_> = (poms.iter())
            .map(|&(repo, ref req, pinned)| {
                let scope = match scopes.iter().find(|(known, _)| std::ptr::eq(*known, repo)) {
                    Some((_, scope)) => scope.clone(),
                    None => {
                        let scope = self.router.route(repo).scope;
                        scopes.push((repo, scope.clone()));
                        scope
                    }
                };
                let pom_req = req.pom();
                let path = pom_req
                    .to_path_with_versions(&resolved_directory(&pom_req.version), &pom_req.version);
                let locked = self.lock_pin(&path).and_then(Digest::as_sha256) == Some(pinned);
                (locked && !Self::cache_scope_is_local(&scope)).then(|| {
                    let renewed = self.renew_before(CacheTable::Pom, &path);
                    (scope, path, pinned.clone(), renewed)
                })
            })
            .collect();
        let probed: Vec<_> = keys.iter().flatten().cloned().collect();
        let cache = self.cache.clone();
        let now = (!self.offline).then(now_epoch_seconds);
        let mut cached =
            tokio::task::spawn_blocking(move || cache.holds(CacheTable::Pom, &probed, now))
                .await
                .map_err(|e| RepoError::Internal(format!("cache task panicked: {e}")))??
                .into_iter();
        Ok((keys.iter())
            .map(|key| key.is_some() && cached.next() == Some(false))
            .collect())
    }

    /// Cache the POM of `req` that `repo` serves from the store file `blob`,
    /// when raeva.lock pins `pinned` for that file, the file holds those
    /// bytes, and the cache has no row yet. A restore uses this for each
    /// platform whose lock records `repo`, so an offline resolution of that
    /// platform finds the POM.
    pub(crate) async fn seed_pinned_pom(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        pinned: &Sha256,
        blob: &std::path::Path,
    ) -> Result<()> {
        let route = self.router.route(repo);
        let pom_req = req.pom();
        let path =
            pom_req.to_path_with_versions(&resolved_directory(&pom_req.version), &pom_req.version);
        if self.lock_pin(&path).and_then(Digest::as_sha256) != Some(pinned)
            || (self
                .cache_get_bytes(CacheTable::Pom, &route.scope, &path)
                .await?)
                .is_some()
        {
            return Ok(());
        }
        let bytes = match tokio::fs::read(blob).await {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            read => read?,
        };
        if Sha256::from_bytes(&bytes) != *pinned {
            return Ok(());
        }
        // Only the pin vouches for the bytes, so a client without it still
        // asks for a checksum file.
        let ttl = route.endpoint.update_policy_ttl(&pom_req.version);
        (self.cache_insert_bytes_with_ttl(
            CacheTable::Pom,
            &route.scope,
            &path,
            &bytes,
            ttl,
            Checked::Missing,
        ))
        .await;
        Ok(())
    }

    async fn read_pom(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        read: PomRead,
    ) -> Result<(Bytes, String)> {
        let route = self.router.route(repo);
        self.ensure_repo_allows_version(&route.endpoint, &req.version)?;

        let pom_req = req.pom();
        let snapshot = self.resolve_snapshot_for_request(&route, &pom_req).await?;
        let path = pom_req.to_path_with_versions(&snapshot.dir_version, &snapshot.file_version);
        // A release or timestamped snapshot POM path names fixed content, so
        // a verified copy never expires, as Maven never re-downloads one it
        // has. A non-unique `-SNAPSHOT` file is replaced in place, and a copy
        // accepted without a checksum file ages out too. A run that requires
        // checksums never reads a copy accepted without a checksum file.
        let fixed_content = !resolves_through_snapshot_metadata(&snapshot.file_version);
        let policy_ttl = route.endpoint.update_policy_ttl(&pom_req.version);
        let cache_scope = route.scope.as_str();
        // Concurrent requests for the same parent or BOM share one download.
        // The repository id, checksum requirement and lock pin are in the
        // key: clones share the map, a credential's answer is its own, and a
        // strict client must not take bytes a lenient one, or one with
        // another pin, accepted without a checksum file.
        let flight_key = format!(
            "{cache_scope}\n{path}\n{}\n{}",
            self.require_checksums,
            self.lock_pin(&path)
                .map(ToString::to_string)
                .unwrap_or_default()
        );

        // Only a copy that never expires is kept in memory, so the memo
        // answers exactly as the metadata cache would.
        if fixed_content && let Some(bytes) = self.memo().get(&flight_key) {
            return Ok((bytes, path));
        }
        if let Some((bytes, expires_at)) = self
            .cache_get_entry(CacheTable::Pom, cache_scope, &path)
            .await?
        {
            if fixed_content && expires_at == i64::MAX {
                self.memo().insert(&flight_key, &bytes);
            }
            return Ok((bytes, path));
        }
        // Bound first, so the guard is released before the adoption locks
        // the held POMs again.
        let held = self.held().get(&flight_key);
        if let Some(bytes) = held {
            if read == PomRead::Use {
                self.adopt_held_pom(&flight_key, cache_scope, &path).await;
            }
            return Ok((bytes, path));
        }

        let cell = {
            let mut inflight = self
                .pom_inflight
                .lock()
                .map_err(|_| RepoError::Internal("POM in-flight map poisoned".to_string()))?;
            Arc::clone(inflight.entry(flight_key.clone()).or_default())
        };
        let result = cell
            .get_or_try_init(|| async {
                // Another initializer may fill the cache, or hold a prefetched
                // copy, before this caller acquires the cell.
                if let Some(bytes) = self
                    .cache_get_bytes(CacheTable::Pom, cache_scope, &path)
                    .await?
                {
                    return Ok(bytes);
                }
                let held = self.held().get(&flight_key);
                if let Some(bytes) = held {
                    return Ok(bytes);
                }
                let mut warnings = DeferredWarnings::default();
                let fetched = self
                    .fetch_model_bytes(&route, &path, &pom_req.version, &mut warnings)
                    .await;
                // A read that uses the POM logs its warnings now; a
                // prefetch holds them with the bytes.
                let held_warnings = match read {
                    PomRead::Use => {
                        warnings.emit();
                        None
                    }
                    PomRead::Prefetch => Some(warnings.after_logged()),
                };
                let (bytes, checked) = fetched?;
                let ttl = if fixed_content && matches!(checked, Checked::Verified | Checked::Pinned)
                {
                    i64::MAX
                } else {
                    policy_ttl
                };
                if let Some(warnings) = held_warnings {
                    self.held().insert(
                        flight_key.clone(),
                        HeldPom {
                            bytes: bytes.clone(),
                            ttl,
                            checked,
                            warnings: Some(warnings),
                        },
                    );
                    return Ok(bytes);
                }
                self.cache_pom(&flight_key, cache_scope, &path, &bytes, ttl, checked)
                    .await;
                Ok(bytes)
            })
            .await
            .cloned();
        if let Ok(mut inflight) = self.pom_inflight.lock() {
            inflight.remove(&flight_key);
        }
        if read == PomRead::Use && result.is_ok() {
            // This read may have joined a prefetch's download.
            self.adopt_held_pom(&flight_key, cache_scope, &path).await;
        }
        result.map(|bytes| (bytes, path))
    }

    /// Take the POM a prefetch holds under `flight_key`, if any, for a read
    /// that uses it: write it to the metadata cache and log its warnings,
    /// as the read would have had it fetched the POM itself. Only one read
    /// takes it.
    async fn adopt_held_pom(&self, flight_key: &str, cache_scope: &str, path: &str) {
        let Some((bytes, ttl, checked, warnings)) = self.held().adopt(flight_key) else {
            return;
        };
        warnings.emit();
        (self.cache_pom(flight_key, cache_scope, path, &bytes, ttl, checked)).await;
        self.held().remove(flight_key);
    }

    /// Write a POM to the metadata cache, and to the memo when it never
    /// expires and a read under the same pin would take the cached copy.
    async fn cache_pom(
        &self,
        flight_key: &str,
        cache_scope: &str,
        path: &str,
        bytes: &Bytes,
        ttl: i64,
        checked: Checked,
    ) {
        let cached = (self.cache_insert_bytes_with_ttl(
            CacheTable::Pom,
            cache_scope,
            path,
            bytes,
            ttl,
            checked,
        ))
        .await;
        // Bytes checked against their checksum file while a pin names the
        // path are other bytes than the pinned ones.
        let pin = self.lock_pin(path).and_then(Digest::as_sha256);
        if cached && ttl == i64::MAX && (pin.is_none() || checked == Checked::Pinned) {
            self.memo().insert(flight_key, bytes);
        }
    }

    fn memo(&self) -> std::sync::MutexGuard<'_, PomMemo> {
        self.pom_memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn held(&self) -> std::sync::MutexGuard<'_, HeldPoms> {
        self.held_poms
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The cached bytes for `path`, unless the row is stale, differs from the
    /// SHA-256 raeva.lock pins for `path` or, in a run that requires
    /// checksums, it was accepted without a checksum file and does not match
    /// the lock pin. Offline, a stale row is used, but such a row still is
    /// not. Under `--update`, a mutable row written before the run started
    /// counts as stale. A row whose metadata mismatched its checksum file was accepted under the
    /// checksum policy its scope records, as a fresh fetch would be.
    pub(super) async fn cache_get_bytes(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
    ) -> Result<Option<Bytes>> {
        Ok(self
            .cache_get_entry(table, repo_url, path)
            .await?
            .map(|(bytes, _)| bytes))
    }

    /// [`Self::cache_get_bytes`], with the time the row expires.
    async fn cache_get_entry(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
    ) -> Result<Option<(Bytes, i64)>> {
        // Local `file://` repositories are mutable by the user and cheap to
        // read; caching them would only serve stale content.
        if Self::cache_scope_is_local(repo_url) {
            return Ok(None);
        }
        let cache = self.cache.clone();
        let offline = self.offline;
        let require_checksum = self.require_checksums;
        // A miss row holds the answer, not the file a pin names.
        let pin = (self.lock_pin(path).and_then(Digest::as_sha256))
            .filter(|_| !matches!(table, CacheTable::Miss))
            .cloned();
        let refresh_before = self.renew_before(table, path);
        let repo_url: Arc<str> = repo_url.into();
        let path: Arc<str> = path.into();

        tokio::task::spawn_blocking(move || {
            // A copy that differs from the pin is a miss, so a repository
            // that once served other bytes does not wedge every later run.
            let differs = |entry: &CacheEntry| pin.as_ref().is_some_and(|pin| *pin != entry.sha256);
            // A row that matches the pin needs no checksum file.
            let unchecked =
                |entry: &CacheEntry| require_checksum && !entry.checksum_checked && pin.is_none();
            let entry = cache.get(table, &repo_url, &path).map_err(|err| {
                // The scope starts with the repository URL; the rest is the
                // mirror URL and policy flags.
                let repository = repo_url.split('\u{1f}').next().unwrap_or_default();
                err.for_repository(&redact_url(repository))
            })?;
            match entry {
                Some(entry)
                    if differs(&entry)
                        || refresh_before.is_some_and(|start| entry.fetched_at < start) =>
                {
                    Ok(None)
                }
                // Read inside "offline mode: ... not available in local cache".
                Some(entry) if offline && unchecked(&entry) => {
                    Err(RepoError::OfflineNotCached(format!(
                        "a checked copy of {path} (the cached one has no checksum file, \
                         which only --allow-missing-checksums accepts)"
                    )))
                }
                Some(entry)
                    if unchecked(&entry)
                        || (!offline
                            && MetadataCache::is_expired(
                                entry.expires_at,
                                now_epoch_seconds(),
                            )) =>
                {
                    Ok(None)
                }
                Some(entry) => Ok(Some((Bytes::from(entry.content), entry.expires_at))),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| RepoError::Internal(format!("cache task panicked: {e}")))?
    }

    // These TTL rows are disposable fetch accelerators. Blob persistence,
    // artifact indexing and lockfile POM pins use Store and must still fail
    // if their writes fail.
    pub(super) async fn cache_insert_bytes_with_ttl(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
        content: &[u8],
        ttl: i64,
        checked: Checked,
    ) -> bool {
        if Self::cache_scope_is_local(repo_url) {
            return false;
        }
        let cache = self.cache.clone();
        let repo_url: Arc<str> = repo_url.into();
        let path: Arc<str> = path.into();
        let content = content.to_vec();
        // Bytes accepted by a lock pin alone are not served to a run without it.
        let checksum_checked = matches!(checked, Checked::Verified | Checked::Mismatched);

        tokio::task::spawn_blocking(move || {
            cache.insert_with_ttl(table, &repo_url, &path, &content, ttl, checksum_checked)
        })
        .await
        .is_ok_and(|written| written.is_ok())
    }

    pub(super) async fn cache_insert_metadata(
        &self,
        route: &Route<'_>,
        path: &str,
        content: &[u8],
        version: &str,
        checked: Checked,
    ) {
        let ttl = route.endpoint.update_policy_ttl(version);
        self.cache_insert_bytes_with_ttl(
            CacheTable::VersionList,
            &Self::metadata_cache_scope(route, version),
            path,
            content,
            ttl,
            checked,
        )
        .await;
    }

    pub(super) fn metadata_cache_scope(route: &Route<'_>, version: &str) -> String {
        Self::metadata_scope(&route.endpoint, &route.scope, version)
    }

    pub(super) fn metadata_scope(endpoint: &Repository, scope: &str, version: &str) -> String {
        // Neither tightening checksum policy nor shortening update policy may
        // reuse metadata accepted under the previous, more permissive policy.
        format!(
            "{scope}\u{1f}checksum-fail={}\u{1f}update={}",
            endpoint.metadata_checksum_policy(version) == rv_config::ChecksumPolicy::Fail,
            endpoint.update_policy_for(version),
        )
    }

    pub(super) fn cache_scope_is_local(scope: &str) -> bool {
        let resolved_url = scope.split('\u{1f}').nth(1).unwrap_or(scope);
        Url::parse(resolved_url).is_ok_and(|url| url.scheme() == "file")
    }

    pub(super) fn ensure_repo_allows_version(
        &self,
        repo: &Repository,
        version: &str,
    ) -> Result<()> {
        let snapshot = is_snapshot_version(version);
        let kind = if snapshot { "snapshots" } else { "releases" };
        if !repo.allows_version(version) {
            let repo_id = rv_maven_types::bounded(repo.id.as_deref().unwrap_or("repository"));
            let version = version.to_string();
            let reason = format!("repository '{repo_id}' has {kind} disabled");
            return Err(if snapshot {
                RepoError::SnapshotsDisabled {
                    version,
                    reason: format!(
                        "{reason}. SNAPSHOT versions require a repository with snapshots \
                         enabled (e.g., a Sonatype Nexus or Artifactory snapshot repository)"
                    ),
                }
            } else {
                RepoError::ReleasesDisabled { version, reason }
            });
        }
        if repo.metadata_checksum_policy(version) == rv_config::ChecksumPolicy::Unsupported {
            return Err(crate::repository::unsupported_policy(repo, kind));
        }
        Ok(())
    }

    /// The turn of the caller that reads the remote metadata at `path`
    /// next. Readers of one path take turns, so that the first one's answer
    /// is in the cache, or remembered as missing, before the next one
    /// looks; without turns every module and platform of a reactor asked
    /// for it at once. `None` for local repositories and offline reads.
    async fn metadata_turn(
        &self,
        route: &Route<'_>,
        path: &str,
    ) -> Option<futures::lock::OwnedMutexGuard<()>> {
        let key = self.miss_key(route, path)?;
        let flight = Arc::clone(
            self.metadata_flights
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(key)
                .or_default(),
        );
        Some(flight.lock_owned().await)
    }

    /// Remember only authoritative remote misses and refusals, for this
    /// client's clones, so a repository searched before the one that serves
    /// a parent is asked for it once. Transient failures, rejected
    /// redirects, and checksum errors must remain retryable. Local
    /// repositories may gain files during this client's lifetime.
    ///
    /// A 404, 401 or 403 is also kept in the metadata cache for as long as
    /// the repository's update policy keeps a found file, under the
    /// credential the request sent, so a later run does not ask again
    /// within that time, as Maven does not ask again for a POM it holds.
    /// `--update` asks again, and so does a request with another credential,
    /// or with one where none was sent.
    pub(super) async fn fetch_model_bytes(
        &self,
        route: &Route<'_>,
        path: &str,
        version: &str,
        warnings: &mut DeferredWarnings,
    ) -> Result<(Bytes, Checked)> {
        let repo = &route.endpoint;
        let key = self.miss_key(route, path);
        let generation = self.credential_generation();
        // A repository may answer 404 for a request whose credentials it
        // refuses, so a kept miss is keyed by the credential sent: a fixed
        // token, or credentials added later, is not met by it. Looked up
        // first, so a miss a prefetch met gives this read's credential
        // warnings. Offline it stands too, as a cached file does.
        let sent = (!route.endpoint.is_local())
            .then(|| route.auth().ok())
            .flatten();
        if let Some(key) = &key
            && let Some(miss) = self.recorded_miss(key)
        {
            return Err(miss);
        }
        let miss_scope = sent.and_then(|auth| self.miss_scope(route, version, auth));
        // A file raeva.lock records this repository as serving is asked
        // for again, and so is every file under `--update`.
        let served = (self.lock_pins.get(path)).is_some_and(|(_, origins)| {
            origins
                .iter()
                .any(|o| self.origins.matches(o, &route.origin))
        });
        if let (Some(scope), Some(auth)) = (&miss_scope, sent)
            && !served
            && !self.updates()
            && let Some(kept) = self
                .cache_get_bytes(CacheTable::Miss, scope, path)
                .await
                .ok()
                .flatten()
            && let Some(miss) = Miss::kept(&kept, route, path, auth)
        {
            let miss = miss.error();
            if let Some(key) = &key {
                self.record_miss(route, key.clone(), &miss, generation);
            }
            return Err(miss);
        }
        let result = self
            .fetch_with_checksums(route, path, version, warnings)
            .await;
        if let (Some(key), Err(err)) = (key, &result) {
            self.record_miss(route, key, err, generation);
            let ttl = repo.update_policy_ttl(version);
            if let (Some(status), Some(scope)) = (
                Miss::of(err, path).and_then(|miss| miss.kept_status()),
                miss_scope,
            ) && ttl > 0
            {
                self.cache_insert_bytes_with_ttl(
                    CacheTable::Miss,
                    &scope,
                    path,
                    status.to_string().as_bytes(),
                    ttl,
                    Checked::Verified,
                )
                .await;
            }
        }
        result
    }

    /// The key of remote `path` on `route`, which remembers its misses and
    /// is shared by a snapshot path's readers; `None` for local repositories
    /// and offline reads.
    pub(super) fn miss_key(&self, route: &Route<'_>, path: &str) -> Option<MissKey> {
        (!route.endpoint.is_local() && !self.offline).then(|| MissKey {
            scope: route.scope.clone(),
            endpoint: route.endpoint.url.clone(),
            path: path.to_string(),
        })
    }

    /// A project POM naming a new origin may let a credential follow a
    /// fetched POM's repository there, so a miss recorded before is asked
    /// again. A request takes the generation before it picks its
    /// credential, so one answered after the change counts as before it.
    pub(super) fn credential_generation(&self) -> u64 {
        self.router.auth_store().generation()
    }

    /// The miss recorded for `key` under the current credentials, as the
    /// error the request failed with.
    pub(super) fn recorded_miss(&self, key: &MissKey) -> Option<RepoError> {
        let generation = self.credential_generation();
        let misses = self.absent_paths.lock().ok()?;
        let (miss, at) = misses.get(key)?;
        (*at == generation).then(|| miss.clone().error())
    }

    /// Remember `err` for `key` if it is a [`Miss`], under `generation` or
    /// the earlier one `route` picked its credential under.
    pub(super) fn record_miss(
        &self,
        route: &Route<'_>,
        key: MissKey,
        err: &RepoError,
        generation: u64,
    ) {
        let generation = route
            .auth_generation()
            .map_or(generation, |at| at.min(generation));
        if let Some(miss) = Miss::of(err, &key.path)
            && let Ok(mut misses) = self.absent_paths.lock()
        {
            misses.insert(key, (miss, generation));
        }
    }

    /// The metadata cache scope of a remote miss: the route, the endpoint
    /// asked, the policies and the credential sent, so a miss recorded under
    /// one is not read under another. `None` when the credential has no
    /// keyed digest, so the miss is not kept.
    fn miss_scope(&self, route: &Route<'_>, version: &str, sent: Option<&Auth>) -> Option<String> {
        let auth = match sent {
            None => "none".to_string(),
            Some(auth) => auth.identity(&route.endpoint.url, self.cache.keyed_digest()?),
        };
        Some(format!(
            "{}\u{1f}endpoint={}\u{1f}auth={auth}",
            Self::metadata_cache_scope(route, version),
            route.endpoint.url,
        ))
    }

    /// The version-level metadata for a snapshot `version`, the
    /// artifact-level version list otherwise, from the metadata cache or
    /// `route`.
    async fn read_metadata(
        &self,
        route: &Route<'_>,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        read: PomRead,
    ) -> Result<Metadata> {
        // Validate coordinate components before building any URL path to
        // prevent path-traversal / SSRF from hostile maven-metadata.xml content.
        validate_coord_components(group_id, artifact_id, Some(version))?;
        let repo = &route.endpoint;
        self.ensure_repo_allows_version(repo, version)?;
        let path = metadata_path(
            group_id,
            artifact_id,
            is_snapshot_version(version).then_some(version),
        );
        let _turn = self.metadata_turn(route, &path).await;
        let scope = Self::metadata_cache_scope(route, version);
        let memo_key = format!("{scope}\n{path}");
        let read_key = format!(
            "{} {} {}",
            self.offline,
            self.require_checksums,
            self.lock_pin(&path)
                .map(ToString::to_string)
                .unwrap_or_default()
        );
        let held_key = format!("{memo_key}\n{read_key}");
        let cached = match self.memoized_metadata(&memo_key, &read_key) {
            Some(cached) => cached,
            None => {
                let cached = match self
                    .cache_get_entry(CacheTable::VersionList, &scope, &path)
                    .await?
                {
                    Some((bytes, expires_at)) => Some((Metadata::from_bytes(&bytes)?, expires_at)),
                    None => None,
                };
                self.metadata_memo()
                    .entry(memo_key.clone())
                    .or_default()
                    .insert(read_key, cached.clone());
                cached.map(|(metadata, _)| metadata)
            }
        };
        if let Some(metadata) = cached {
            return Ok(metadata);
        }
        match read {
            PomRead::Use => {
                let held = self.held().adopt(&held_key);
                if let Some((bytes, _, checked, warnings)) = held {
                    warnings.emit();
                    self.cache_insert_metadata(route, &path, bytes.as_ref(), version, checked)
                        .await;
                    self.metadata_memo().remove(&memo_key);
                    self.held().remove(&held_key);
                    return Metadata::from_bytes(&bytes);
                }
            }
            PomRead::Prefetch => {
                let held = self.held().get(&held_key);
                if let Some(bytes) = held {
                    return Metadata::from_bytes(&bytes);
                }
            }
        }

        // Offline blocks remote access, including after mirror substitution;
        // file repositories remain readable. `fetch_path` also guards remote
        // requests, but reporting this here preserves the metadata diagnostic.
        if self.offline && !repo.is_local() {
            return Err(RepoError::OfflineNotCached(format!(
                "{path} (repo: {})",
                rv_config::redact_url(&repo.url)
            )));
        }

        let mut warnings = DeferredWarnings::default();
        let fetched = self
            .fetch_model_bytes(route, &path, version, &mut warnings)
            .await;
        // A prefetch holds its warnings with the file, for the read that
        // uses it; a miss stands for both, as it does for a POM.
        if read == PomRead::Prefetch {
            let (bytes, checked) = fetched?;
            let metadata = Metadata::from_bytes(&bytes)?;
            let held = HeldPom {
                bytes,
                ttl: 0,
                checked,
                warnings: Some(warnings.after_logged()),
            };
            self.held().insert(held_key, held);
            return Ok(metadata);
        }
        warnings.emit();
        let (bytes, checked) = fetched?;
        let metadata = Metadata::from_bytes(&bytes)?;
        self.cache_insert_metadata(route, &path, bytes.as_ref(), version, checked)
            .await;
        self.metadata_memo().remove(&memo_key);
        Ok(metadata)
    }

    /// What a read under `key` would find in the metadata cache, when an
    /// earlier read found it: a row expires meanwhile, and a missing or
    /// unusable one stays so until this client writes it.
    fn memoized_metadata(&self, key: &str, read_key: &str) -> Option<Option<Metadata>> {
        let memo = self.metadata_memo();
        let read = memo.get(key)?.get(read_key)?;
        Some(read.as_ref().and_then(|(metadata, expires_at)| {
            (self.offline || !MetadataCache::is_expired(*expires_at, now_epoch_seconds()))
                .then(|| metadata.clone())
        }))
    }

    fn metadata_memo(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, HashMap<String, MemoizedMetadata>>> {
        self.metadata_memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) async fn resolve_snapshot_for_request(
        &self,
        route: &Route<'_>,
        req: &ArtifactRequest,
    ) -> Result<SnapshotPath> {
        if !req.is_snapshot() {
            return Ok(SnapshotPath {
                dir_version: req.version.clone(),
                file_version: req.version.clone(),
            });
        }
        if resolves_through_snapshot_metadata(&req.version) {
            let coord = Coord {
                group_id: req.group_id.clone().into(),
                artifact_id: req.artifact_id.clone().into(),
                version: req.version.parse().map_err(|err| {
                    RepoError::InvalidCoord(format!("invalid version {}: {err}", req.version))
                })?,
                packaging: Some(req.packaging.clone()),
                classifier: req.classifier.clone(),
            };
            let resolved = self.resolve_snapshot_version_routed(route, &coord).await?;
            return Ok(SnapshotPath {
                dir_version: resolved_directory(&resolved.version),
                file_version: resolved.version,
            });
        }

        let dir_version = rv_maven_types::snapshot_base_version(&req.version)
            .unwrap_or_else(|| req.version.clone());
        Ok(SnapshotPath {
            dir_version,
            file_version: req.version.to_string(),
        })
    }

    /// The bytes at `path`, checked against its checksum sidecar. Warnings
    /// go to `warnings`, for the caller to log.
    pub(super) async fn fetch_with_checksums(
        &self,
        route: &Route<'_>,
        path: &str,
        version: &str,
        warnings: &mut DeferredWarnings,
    ) -> Result<(Bytes, Checked)> {
        let repo = &route.endpoint;
        // Only repository metadata is mutable enough to tolerate stale
        // sidecars. POMs and artifact payloads retain mandatory verification.
        let remote_metadata = !repo.is_local() && path.ends_with("/maven-metadata.xml");
        let fail = repo.metadata_checksum_policy(version) == rv_config::ChecksumPolicy::Fail;
        // Looked up before the two requests below run concurrently, so they
        // share one lookup.
        if !self.offline || repo.is_local() {
            route.auth()?;
        }
        // raeva.lock's pin checks the file without its sidecar, which is
        // read only when the bytes do not match.
        let pin = self.lock_pin(path).and_then(Digest::as_sha256);
        for attempt in 0..=1 {
            // A publisher may update metadata and its sidecar separately, so refetch both.
            // A failed file request ends both and is the result, whichever
            // request failed first; the probe's warnings are logged only once
            // the file has arrived.
            let mut probed = DeferredWarnings::default();
            let (bytes, checksum) = match pin {
                Some(pin) => {
                    let bytes = self.fetch_path(route, path).await?;
                    if Sha256::from_bytes(&bytes) == *pin {
                        return Ok((bytes, Checked::Pinned));
                    }
                    (bytes, self.probe_checksum(route, path, &mut probed).await)
                }
                None => {
                    let fetch = async {
                        let bytes = self.fetch_path(route, path).await?;
                        // A SNAPSHOT POM read fetches metadata first, in the
                        // same scope.
                        if path.ends_with(".pom") {
                            let _ = ARRIVAL.try_with(|arrived| arrived(&bytes));
                        }
                        Ok::<_, RepoError>(bytes)
                    };
                    tokio::try_join!(fetch, async {
                        Ok(self.probe_checksum(route, path, &mut probed).await)
                    })?
                }
            };
            warnings.append(probed);
            let checksum = checksum?;
            let checked = match checksum {
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
                        // raeva, so accepting inconsistent metadata is visible.
                        let (repository_url, path) =
                            (redact_url(&repo.base_url()?), path.to_string());
                        warnings.push(move || {
                            warn!(
                                sec_code = "METADATA_CHECKSUM_MISMATCH",
                                repository_url = %repository_url,
                                path,
                                "metadata checksum mismatch after retry; using fetched metadata"
                            );
                        });
                        Checked::Mismatched
                    } else {
                        Checked::Verified
                    }
                }
                None if !repo.is_local()
                    && (self.require_checksums || (remote_metadata && fail)) =>
                {
                    return Err(RepoError::MissingChecksum(path.to_string()));
                }
                None => {
                    if !repo.is_local() {
                        let (repository_url, path) = (redact_url(&repo.url), path.to_string());
                        warnings.push(move || {
                            warn!(
                                sec_code = "CHECKSUM_MISSING",
                                repository_url = %repository_url,
                                path, "the repository has no checksum file for this download"
                            );
                        });
                    }
                    Checked::Missing
                }
            };
            return Ok((bytes, checked));
        }
        unreachable!("the second metadata fetch returns a result")
    }
}

/// How fetched model bytes fared against the repository's checksum file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Checked {
    Verified,
    /// They did not match, and the metadata checksum policy accepts that.
    Mismatched,
    /// There was no checksum file, and the run accepts that.
    Missing,
    /// raeva.lock pins the bytes, so the checksum file was not read.
    Pinned,
}

/// The directory of the resolved snapshot file version `resolved`. Maven
/// Resolver takes it from the resolved version, so `1.0SNAPSHOT` at build 7
/// lives under `1.020240101.010101-7/`.
pub(super) fn resolved_directory(resolved: &str) -> String {
    rv_maven_types::snapshot_base_version(resolved).unwrap_or_else(|| resolved.to_string())
}
