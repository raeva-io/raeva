//! Metadata and POM reads: the metadata cache, snapshot resolution and the
//! checksum checks on model bytes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tracing::warn;
use url::Url;

use rv_config::redact_url;
use rv_maven_types::{
    Coord, CoordinateField, Digest, Gav, HashAlgorithm, Sha256, is_snapshot_version,
    layout::metadata_path, resolves_through_snapshot_metadata,
};

use super::requests::{self, DeferredWarnings, LateCheck, LateSha256};
use super::{RepoClient, SnapshotResolution, validate_coord_components};
use crate::artifact::ArtifactRequest;
use crate::auth::{Auth, SentCredential};
use crate::error::{IntegritySource, RepoError, Result};
use crate::fetch::verify_checksum;
use crate::metadata::{Metadata, MetadataReader};
use crate::repository::Repository;
use crate::routing::Route;
use rv_store::metadata_cache::{CacheEntry, CacheTable, Expiry, MetadataCache, now_epoch_seconds};

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

/// Each miss, with the credential generation it was recorded under and
/// whether a prefetch met it, so that the read that uses it keeps it.
pub(super) type AbsentPaths = Arc<Mutex<HashMap<MissKey, (Miss, u64, bool)>>>;

/// A remote answer the same request gets again in this run: a 404, a 401
/// or 403 to the same credential, or a busy answer to the file itself, not
/// its checksum, that outlasted its retries, which a speculative read and
/// the read that joins it would otherwise each wait out.
#[derive(Clone)]
pub(super) enum Miss {
    Absent(crate::Missing),
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
            b"404" => Some(Self::Absent(format!("{url} (HTTP 404)").into())),
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

pub(super) type PomInflight =
    Arc<Mutex<HashMap<String, Arc<tokio::sync::OnceCell<(Bytes, Option<LateCheck>)>>>>>;

/// What this client's reads of the metadata cache found, by scope and path,
/// then by the settings that decide whether a row is usable: the metadata, or
/// `None` when no row was usable. What this client or a clone fetches
/// replaces the reads of its scope and path. A read stands for the client's
/// life, which is one run, so the run sees one version of each file though
/// its row expires or another process replaces it meanwhile: a SNAPSHOT's jar
/// and POM resolve from one version of its metadata. Every module of a
/// reactor reads the same snapshot and version metadata, and reading it from
/// `metadata.db` each time was much of a warm resolution's time.
pub(super) type MetadataMemo = Arc<Mutex<HashMap<String, HashMap<String, MemoizedMetadata>>>>;

type MemoizedMetadata = Option<Metadata>;

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

type AdoptedPom = (Bytes, Expiry, Checked, DeferredWarnings, Option<LateCheck>);

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
    expiry: Expiry,
    checked: Checked,
    /// `None` once a read adopted the POM and is writing it to the cache.
    warnings: Option<DeferredWarnings>,
    /// The check of its `.sha256`, for every read that uses it.
    check: Option<LateCheck>,
}

impl HeldPoms {
    fn full(&self) -> bool {
        self.bytes >= MAX_HELD_BYTES
    }

    fn get(&self, key: &str) -> Option<(Bytes, Option<LateCheck>)> {
        (self.poms.get(key)).map(|held| (held.bytes.clone(), held.check.clone()))
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
    fn adopt(&mut self, key: &str) -> Option<AdoptedPom> {
        let held = self.poms.get_mut(key)?;
        let warnings = held.warnings.take()?;
        Some((
            held.bytes.clone(),
            held.expiry,
            held.checked,
            warnings,
            held.check.clone(),
        ))
    }

    fn remove(&mut self, key: &str) {
        if let Some(held) = self.poms.remove(key) {
            self.bytes -= held.bytes.len();
        }
    }

    /// Stop holding `bytes` under `key`, which failed their check.
    fn remove_failed(&mut self, key: &str, bytes: &Bytes) {
        if self.poms.get(key).is_some_and(|held| held.bytes == *bytes) {
            self.remove(key);
        }
    }
}

/// Who a POM or version list is read for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PomRead {
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

    /// The group-level `maven-metadata.xml` of `group_id` from `repo` or the
    /// mirror that serves it, whose `<plugins>` give the goal prefixes of
    /// the group's plugins. Cached, checked and refused offline as
    /// [`Self::fetch_metadata`] is for a release version list.
    ///
    /// # Errors
    ///
    /// [`RepoError::InvalidCoord`] for an unsafe group, and the errors of
    /// [`Self::fetch_metadata`].
    pub async fn fetch_group_metadata(
        &self,
        repo: &Repository,
        group_id: &str,
    ) -> Result<Metadata> {
        // Any release version: the release policies apply.
        const RELEASE: &str = "0";
        rv_maven_types::validate_coordinate_component(
            rv_maven_types::CoordinateField::Group,
            group_id,
        )
        .map_err(|err| RepoError::InvalidCoord(err.to_string()))?;
        let route = self.router.route(repo);
        self.ensure_repo_allows_version(&route.endpoint, RELEASE)?;
        let path = format!("{}/maven-metadata.xml", group_id.replace('.', "/"));
        self.ensure_filters_admit(&route, group_id, &path)?;
        let _turn = self.metadata_turn(&route, &path).await;
        let scope = Self::metadata_cache_scope(&route, RELEASE);
        let (memo_key, read_key) = self.metadata_memo_keys(&scope, &path);
        if let Some(metadata) = (self.cached_metadata(&scope, &path, &memo_key, &read_key)).await? {
            return Ok(metadata);
        }
        let mut warnings = DeferredWarnings::default();
        let fetched = self
            .fetch_model_bytes(&route, &path, RELEASE, None, &mut warnings, PomRead::Use)
            .await;
        warnings.emit();
        let (bytes, checked, _) = fetched?;
        let metadata = Metadata::from_bytes(&bytes)?;
        self.cache_insert_metadata(&route, &path, bytes.as_ref(), RELEASE, checked)
            .await;
        self.keep_fetched_metadata(memo_key, read_key, &metadata);
        Ok(metadata)
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
        (self.resolve_snapshot_version_routed(&route, coord, PomRead::Use, None)).await
    }

    /// Snapshot-metadata resolution on a route the caller already decided,
    /// so the metadata sub-fetch of an artifact or POM request sends the
    /// credential that request sends. A restore of the file raeva.lock pins
    /// to `restored` asks every repository for the pinned build.
    pub(super) async fn resolve_snapshot_version_routed(
        &self,
        route: &Route<'_>,
        coord: &Coord,
        read: PomRead,
        restored: Option<&Digest>,
    ) -> Result<SnapshotResolution> {
        let version = coord.version.to_string();
        self.ensure_repo_allows_version(&route.endpoint, &version)?;
        // Maven resolves a snapshot only through the repositories the
        // filters let serve its file, the pinned build too.
        let request = ArtifactRequest::from_coord(coord);
        self.ensure_filters_admit(route, &request.group_id, &super::filter_path(&request))?;
        // A restore fetches the pinned build without its metadata, and the
        // cached metadata may name another build. Offline, which sees no
        // upstream change anyway, and in a frozen check, a pinned build this
        // repository served stands.
        if (self.offline && !route.endpoint.is_local())
            || self.pinned_snapshots()
            || restored.is_some()
        {
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
                // A POM recorded as missing is so on the repository that
                // served its file, offline as an online run's 404 proves.
                let missing = self.lock_missing_poms.contains(&pom)
                    && pin.file_origins.iter().any(recorded)
                    && (!self.offline || self.proven_absent(route, &pom).await);
                let served = if is_pom {
                    missing || (self.pinned_snapshots() && pin.pom_origins.iter().any(recorded))
                } else {
                    pin.file_origins.iter().any(recorded)
                };
                let restores = restored.is_some_and(|restored| {
                    let path =
                        request.to_path_with_versions(&resolved_directory(&resolved), &resolved);
                    self.lock_pin(&path) == Some(restored)
                });
                if served
                    || restores
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
                read,
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

        // Maven 3.10 takes metadata with a version token that is no path
        // component for invalid and reads it as empty, so this repository
        // names no build.
        if self.maven_mode == rv_maven_types::MavenMode::Maven310
            && metadata.has_invalid_token(MetadataReader::Version)
        {
            // The read that uses the metadata warns.
            if read == PomRead::Prefetch {
                return Ok(SnapshotResolution::base(version));
            }
            warn!(
                sec_code = "POM_PROBLEM",
                repository = %redact_url(&route.endpoint.url),
                "ignoring {coord} snapshot metadata with an invalid version token"
            );
            return Ok(SnapshotResolution {
                metadata_served: true,
                ..SnapshotResolution::base(version)
            });
        }
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
    /// used leaves nothing behind. A `-SNAPSHOT`'s `maven-metadata.xml` is
    /// held the same way. Offline and once the held POMs fill their budget
    /// this asks nothing and returns `None`, and the later `fetch_pom` makes
    /// its own requests. A failed fetch keeps only the miss a `fetch_pom`
    /// would keep.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::fetch_pom`].
    pub async fn prefetch_pom(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
    ) -> Result<Option<Bytes>> {
        if self.offline || req.validate().is_err() || self.held().full() {
            return Ok(None);
        }
        let read = self.read_pom(repo, req, PomRead::Prefetch, None);
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
        self.read_pom(repo, req, PomRead::Use, None).await
    }

    pub(crate) async fn fetch_pinned_pom_with_path(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        pin: &Digest,
    ) -> Result<(Bytes, String)> {
        req.validate().map_err(RepoError::InvalidCoord)?;
        self.read_pom(repo, req, PomRead::Use, Some(pin)).await
    }

    /// The time before which a row of `path` in `table` that this process
    /// wrote is fetched again under `--update`, as is one it did not write.
    fn renew_before(&self, table: CacheTable, path: &str) -> Option<std::time::Instant> {
        // A release or timestamped POM names fixed content; `--update`
        // renews only what a deploy can change.
        let mutable = !matches!(table, CacheTable::Pom)
            || path
                .rsplit('/')
                .next()
                .is_some_and(|file| file.ends_with("SNAPSHOT.pom"));
        self.refresh_before().filter(|_| mutable && !self.offline)
    }

    /// Which of `poms` [`Self::seed_pinned_pom`] would cache: raeva.lock pins
    /// those bytes for the file and the cache holds no current copy of them,
    /// nor, for [`RepoClient::keeping_cached_poms`], other bytes. One cache
    /// read covers them all.
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
        let (now, other) = (
            (!self.offline).then(now_epoch_seconds),
            self.keep_cached_poms,
        );
        let mut cached =
            tokio::task::spawn_blocking(move || cache.holds(CacheTable::Pom, &probed, now, other))
                .await
                .map_err(|e| RepoError::Internal(format!("cache task panicked: {e}")))??
                .into_iter();
        Ok((keys.iter())
            .map(|key| key.is_some() && cached.next() == Some(false))
            .collect())
    }

    /// Cache the POM of `req` that `repo` serves from the store blob `pinned`,
    /// when [`Self::unseeded_poms`] counts it and the file holds the pinned
    /// bytes. A restore uses this for each platform whose lock records
    /// `repo`, so an offline resolution of that platform finds the POM.
    pub(crate) async fn seed_pinned_pom(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        pinned: &Sha256,
        store: &rv_store::Store,
    ) -> Result<()> {
        if !self.unseeded_poms(&[(repo, req.clone(), pinned)]).await?[0] {
            return Ok(());
        }
        let route = self.router.route(repo);
        let pom_req = req.pom();
        let path =
            pom_req.to_path_with_versions(&resolved_directory(&pom_req.version), &pom_req.version);
        let Some(bytes) = store.read_blob_async(pinned).await? else {
            return Ok(());
        };
        if Sha256::from_bytes(&bytes) != *pinned {
            return Ok(());
        }
        // Only the pin vouches for the bytes, so a client without it still
        // asks for a checksum file.
        let expiry = route.endpoint.update_policy_expiry(&pom_req.version);
        (self.cache_insert_bytes(
            CacheTable::Pom,
            &route.scope,
            &path,
            &bytes,
            expiry,
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
        pin: Option<&Digest>,
    ) -> Result<(Bytes, String)> {
        // Bytes another read held failed their `.sha256` and are no longer
        // held, so reading again asks for the POM and fails as that read
        // would have.
        match self.read_pom_once(repo, req, read, pin).await? {
            Ok(read) => Ok(read),
            Err(_) => (self.read_pom_once(repo, req, read, pin).await?).map_err(requests::unshared),
        }
    }

    /// [`Self::read_pom`], or the error of a check this client waited for
    /// on bytes another read fetched.
    async fn read_pom_once(
        &self,
        repo: &Repository,
        req: &ArtifactRequest,
        read: PomRead,
        pin: Option<&Digest>,
    ) -> Result<std::result::Result<(Bytes, String), Arc<RepoError>>> {
        let route = self.router.route(repo);
        self.ensure_repo_allows_version(&route.endpoint, &req.version)?;

        let pom_req = req.pom();
        self.ensure_filters_admit(&route, &pom_req.group_id, &super::filter_path(&pom_req))?;
        let snapshot = (self.resolve_snapshot_for_request(&route, &pom_req, read, pin)).await?;
        let path = pom_req.to_path_with_versions(&snapshot.dir_version, &snapshot.file_version);
        // Maven judges a snapshot by the build its metadata resolves to.
        self.ensure_filters_admit(&route, &pom_req.group_id, &path)?;
        // A verified copy never expires, as Maven never re-downloads a POM
        // it has, even a non-unique `-SNAPSHOT` one replaced in place: that
        // one is fetched again only under `--update`, so it stays with its
        // jar. A copy accepted without a checksum file ages out. A run that
        // requires checksums never reads a copy accepted without a checksum
        // file.
        let fixed_content = !resolves_through_snapshot_metadata(&snapshot.file_version);
        let policy_expiry = route.endpoint.update_policy_expiry(&pom_req.version);
        let cache_scope = route.scope.as_str();
        // Concurrent requests for the same parent or BOM share one download.
        // The repository id, checksum requirement and lock pin are in the
        // key: clones share the map, a credential's answer is its own, and a
        // strict client must not take bytes a lenient one, or one with
        // another pin, accepted without a checksum file. A read under a later
        // credential generation does not take a prefetch's bytes; a -SNAPSHOT
        // route picked its credential for the metadata.
        let flight_key = format!(
            "{cache_scope}\n{path}\n{}\n{}\n{}\n{}",
            route.picked_under(self.credential_generation()),
            self.require_checksums,
            pin.is_some(),
            pin.or_else(|| self.lock_pin(&path))
                .map(ToString::to_string)
                .unwrap_or_default()
        );

        // Only a copy that never expires is kept in memory, so the memo
        // answers exactly as the metadata cache would.
        if fixed_content && let Some(bytes) = self.memo().get(&flight_key) {
            return Ok(Ok((bytes, path)));
        }
        if let Some((bytes, expires_at)) = self
            .cache_get_entry(CacheTable::Pom, cache_scope, &path, pin, read)
            .await?
        {
            // The memo answers without noting the admission.
            if read == PomRead::Use && fixed_content && expires_at == i64::MAX {
                self.memo().insert(&flight_key, &bytes);
            }
            return Ok(Ok((bytes, path)));
        }
        // Bound first, so the guard is released before the adoption locks
        // the held POMs again.
        let held = self.held().get(&flight_key);
        if let Some((bytes, check)) = held {
            if read == PomRead::Use {
                let adopted = (self.adopt_held_pom(&route, &flight_key, cache_scope, &path)).await;
                if let Err(err) = self.rely_on(adopted, check).await {
                    return Ok(Err(err));
                }
            }
            return Ok(Ok((bytes, path)));
        }

        let cell = {
            let mut inflight = self
                .pom_inflight
                .lock()
                .map_err(|_| RepoError::Internal("POM in-flight map poisoned".to_string()))?;
            Arc::clone(inflight.entry(flight_key.clone()).or_default())
        };
        let result: Result<(Bytes, Option<LateCheck>)> = cell
            .get_or_try_init(|| async {
                // Another initializer may fill the cache, or hold a prefetched
                // copy, before this caller acquires the cell.
                if let Some((bytes, _)) = self
                    .cache_get_entry(CacheTable::Pom, cache_scope, &path, pin, read)
                    .await?
                {
                    return Ok((bytes, None));
                }
                let held = self.held().get(&flight_key);
                if let Some(held) = held {
                    return Ok(held);
                }
                if fixed_content && let Some(twin) = self.router.central_twin(&route) {
                    let cached =
                        self.cache_get_entry(CacheTable::Pom, &twin.scope, &path, pin, read);
                    if let Some((bytes, _)) = cached.await? {
                        return Ok((bytes, None));
                    }
                }
                let mut warnings = DeferredWarnings::default();
                let fetched = self
                    .fetch_model_bytes(&route, &path, &pom_req.version, pin, &mut warnings, read)
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
                let (bytes, checked, late) = fetched?;
                let expiry = if matches!(checked, Checked::Verified | Checked::Pinned(_)) {
                    Expiry::NEVER
                } else {
                    policy_expiry
                };
                // A POM whose `.sha256` is still being asked for is held as
                // a prefetched one is, and a read that uses it adopts it.
                if held_warnings.is_some() || late.is_some() {
                    // Held before a failed check can stop holding it.
                    let mut held = self.held();
                    let check = late.zip(self.late_checks.as_ref()).map(|(late, checks)| {
                        // Weak: the held POM holds the check.
                        let (poms, key, failed) = (
                            Arc::downgrade(&self.held_poms),
                            flight_key.clone(),
                            bytes.clone(),
                        );
                        let failed = move || {
                            if let Some(poms) = poms.upgrade() {
                                (poms.lock())
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .remove_failed(&key, &failed);
                            }
                        };
                        late.spawn(bytes.clone(), failed, checks)
                    });
                    // A prefetch may ask a repository the read never
                    // reaches, so only the read notes the admission.
                    held.insert(
                        flight_key.clone(),
                        HeldPom {
                            bytes: bytes.clone(),
                            expiry,
                            checked,
                            warnings: Some(held_warnings.unwrap_or_default()),
                            check: check.clone(),
                        },
                    );
                    return Ok((bytes, check));
                }
                self.note_pom_admission(&route, &path, checked);
                self.note_fetched_pom(&path, checked);
                self.cache_pom(&flight_key, cache_scope, &path, &bytes, expiry, checked)
                    .await;
                Ok((bytes, None))
            })
            .await
            .cloned();
        if let Ok(mut inflight) = self.pom_inflight.lock() {
            inflight.remove(&flight_key);
        }
        let (bytes, check) = result?;
        if read == PomRead::Use {
            // This read may have joined a prefetch's download.
            let adopted = (self.adopt_held_pom(&route, &flight_key, cache_scope, &path)).await;
            if let Err(err) = self.rely_on(adopted, check).await {
                return Ok(Err(err));
            }
        }
        Ok(Ok((bytes, path)))
    }

    /// Take the POM held under `flight_key`, if any, for a read that uses
    /// it: write it to the metadata cache and log its warnings, as the read
    /// would have had it fetched the POM itself. Only one read takes it. A
    /// POM whose `.sha256` is still being asked for is written once that is
    /// checked, by a task whose check this returns.
    async fn adopt_held_pom(
        &self,
        route: &Route<'_>,
        flight_key: &str,
        cache_scope: &str,
        path: &str,
    ) -> Option<LateCheck> {
        let (bytes, expiry, checked, warnings, check) = self.held().adopt(flight_key)?;
        warnings.emit();
        self.note_pom_admission(route, path, checked);
        self.note_fetched_pom(path, checked);
        // A clone that leaves no check behind, which settling would wait for.
        let mut client = self.clone();
        client.late_checks = None;
        let (flight_key, cache_scope, path) = (
            flight_key.to_string(),
            cache_scope.to_string(),
            path.to_string(),
        );
        let cache = async move {
            (client.cache_pom(&flight_key, &cache_scope, &path, &bytes, expiry, checked)).await;
            client.held().remove(&flight_key);
        };
        match check {
            Some(check) => Some(check.then(cache)),
            None => {
                cache.await;
                None
            }
        }
    }

    /// Rely on bytes whose `.sha256` is `check`, or `adopted` for the read
    /// that adopted them, which logs the weak-hash warning: a client that
    /// [`RepoClient::checking_sha256_late`] leaves the check to
    /// [`RepoClient::settle_checksums`], and another waits for it.
    async fn rely_on(
        &self,
        adopted: Option<LateCheck>,
        check: Option<LateCheck>,
    ) -> std::result::Result<(), Arc<RepoError>> {
        let (check, warns) = match (adopted, check) {
            (Some(adopted), _) => (adopted, true),
            (None, Some(check)) => (check, false),
            (None, None) => return Ok(()),
        };
        if let Some(checks) = &self.late_checks {
            checks.rely_on(check, warns);
            return Ok(());
        }
        if check.outcome().await? && warns {
            check.weak_hash()();
        }
        Ok(())
    }

    /// Note for raeva.lock whether a repository checksum file admitted the
    /// POM at `path` that a read uses.
    fn note_pom_admission(&self, route: &Route<'_>, path: &str, checked: Checked) {
        if route.endpoint.is_local() {
            return;
        }
        match checked {
            Checked::Verified | Checked::Pinned(true) => self.note_admission(path, true),
            Checked::Missing => self.note_admission(path, false),
            Checked::Mismatched | Checked::Pinned(false) => {}
        }
    }

    /// Note a non-unique `-SNAPSHOT` POM at `path` that a read uses as
    /// fetched, unless raeva.lock pins these bytes: its files are fetched
    /// again too, as the store may hold them from another build.
    fn note_fetched_pom(&self, path: &str, checked: Checked) {
        if path.ends_with("SNAPSHOT.pom") && !matches!(checked, Checked::Pinned(_)) {
            (self.fetched_snapshots.lock())
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(path.to_string());
        }
    }

    /// Write a POM to the metadata cache, and to the memo when it never
    /// expires and a read under the same pin would take the cached copy.
    async fn cache_pom(
        &self,
        flight_key: &str,
        cache_scope: &str,
        path: &str,
        bytes: &Bytes,
        expiry: Expiry,
        checked: Checked,
    ) {
        // Other bytes than the ones a fixed file is pinned to are not kept,
        // so another project cannot take them for verified.
        if self.release_lock_pin(path).is_some() && !matches!(checked, Checked::Pinned(_)) {
            return;
        }
        let cached =
            (self.cache_insert_bytes(CacheTable::Pom, cache_scope, path, bytes, expiry, checked))
                .await;
        // Bytes checked against their checksum file while a pin names the
        // path are other bytes than the pinned ones.
        let pin = self.lock_pin(path).and_then(Digest::as_sha256);
        if cached
            && expiry == Expiry::NEVER
            && (pin.is_none() || matches!(checked, Checked::Pinned(_)))
        {
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
            .cache_get_entry(table, repo_url, path, None, PomRead::Use)
            .await?
            .map(|(bytes, _)| bytes))
    }

    /// [`Self::cache_get_bytes`], with the time the row expires. Only a
    /// POM `read` uses notes its admission.
    pub(super) async fn cache_get_entry(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
        pin: Option<&Digest>,
        read: PomRead,
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
        let pin = pin
            .or_else(|| self.lock_pin(path))
            .filter(|_| !matches!(table, CacheTable::Miss))
            .cloned();
        let refresh_before = self.renew_before(table, path);
        let pinned = pin.is_some();
        // `--update` asks again for the checksum file of a POM raeva.lock
        // marks as accepted without one.
        let recheck = matches!(table, CacheTable::Pom)
            && self.updates()
            && self.lock_unverified.contains(path);
        let repo_url: Arc<str> = repo_url.into();
        let path: Arc<str> = path.into();
        let note = path.clone();

        let found = tokio::task::spawn_blocking(move || {
            // A copy that differs from the pin is a miss, so a repository
            // that once served other bytes does not wedge every later run.
            let differs = |entry: &CacheEntry| {
                pin.as_ref().is_some_and(|pin| match pin {
                    Digest::Sha256(expected) => *expected != entry.sha256,
                    _ => Digest::of_bytes(pin.algorithm(), &entry.content) != *pin,
                })
            };
            // A row that matches a pin, of either algorithm, needs no
            // checksum file, as a download the pin verifies needs none.
            let unchecked =
                |entry: &CacheEntry| require_checksum && !entry.checksum_checked && pin.is_none();
            let entry = cache.get(table, &repo_url, &path).map_err(|err| {
                err.for_repository(&redact_url(crate::cache_scope_repository(&repo_url)))
            })?;
            match entry {
                Some(entry)
                    if differs(&entry)
                        || refresh_before.is_some_and(|start| !entry.written_since(start)) =>
                {
                    Ok(None)
                }
                Some(entry) if recheck && !entry.checksum_checked => Ok(None),
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
                            && MetadataCache::is_stale(
                                entry.fetched_at,
                                entry.expires_at,
                                now_epoch_seconds(),
                            )) =>
                {
                    Ok(None)
                }
                Some(entry) => Ok(Some((
                    Bytes::from(entry.content),
                    entry.fetched_at,
                    entry.expires_at,
                    entry.checksum_checked,
                ))),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| RepoError::Internal(format!("cache task panicked: {e}")))??;
        Ok(found.map(|(bytes, fetched_at, expires_at, checked)| {
            if matches!(table, CacheTable::Pom) && (checked || !pinned) && read == PomRead::Use {
                self.note_admission(&note, checked);
            }
            self.note_cached_row(&note, fetched_at, expires_at);
            (bytes, expires_at)
        }))
    }

    // These TTL rows are disposable fetch accelerators. Blob persistence,
    // artifact indexing and lockfile POM pins use Store and must still fail
    // if their writes fail.
    pub(super) async fn cache_insert_bytes(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
        content: &[u8],
        expiry: Expiry,
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
        let checksum_checked = matches!(
            checked,
            Checked::Verified | Checked::Mismatched | Checked::Pinned(true)
        );

        tokio::task::spawn_blocking(move || {
            cache.insert(table, &repo_url, &path, &content, expiry, checksum_checked)
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
        let expiry = route.endpoint.update_policy_expiry(version);
        self.cache_insert_bytes(
            CacheTable::VersionList,
            &Self::metadata_cache_scope(route, version),
            path,
            content,
            expiry,
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
        pin: Option<&Digest>,
        warnings: &mut DeferredWarnings,
        read: PomRead,
    ) -> Result<(Bytes, Checked, Option<LateSha256>)> {
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
        let miss_scope = sent.and_then(|auth| self.miss_scope(route, version, auth));
        if let Some(key) = &key
            && let Some(miss) = self.recorded_miss(key)
        {
            if read == PomRead::Use && self.take_unkept(key) {
                (self.keep_miss(route, path, version, miss_scope.as_deref(), &miss)).await;
            }
            return Err(miss);
        }
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
                self.record_miss(route, key.clone(), &miss, generation, false);
            }
            return Err(miss);
        }
        let result = self
            .fetch_with_checksums(route, path, version, pin, warnings)
            .await;
        if let (Some(key), Err(err)) = (key, &result) {
            // A prefetch may ask a repository the read never reaches.
            let keep = read == PomRead::Use;
            self.record_miss(route, key, err, generation, !keep);
            if keep {
                (self.keep_miss(route, path, version, miss_scope.as_deref(), err)).await;
            }
        }
        result
    }

    /// Keep `err` under `scope` if it is a 404, 401 or 403, for as long as
    /// the repository's update policy keeps a found file. A 404 is also
    /// kept under [`Self::absence_scope`], whatever credential asked, as the
    /// proof an offline run takes that the file is missing; offline a stale
    /// row stands, so it is kept even when the policy keeps nothing.
    async fn keep_miss(
        &self,
        route: &Route<'_>,
        path: &str,
        version: &str,
        scope: Option<&str>,
        err: &RepoError,
    ) {
        let Some(status) = Miss::of(err, path).and_then(|miss| miss.kept_status()) else {
            return;
        };
        let expiry = route.endpoint.update_policy_expiry(version);
        let absent = (status == 404).then(|| Self::absence_scope(route));
        for scope in scope.map(str::to_string).into_iter().chain(absent) {
            self.cache_insert_bytes(
                CacheTable::Miss,
                &scope,
                path,
                status.to_string().as_bytes(),
                expiry,
                Checked::Verified,
            )
            .await;
        }
    }

    /// The metadata cache scope of the 404s `route` answered, with no
    /// credential in it, so a seed carries them to another home.
    pub(super) fn absence_scope(route: &Route<'_>) -> String {
        format!("{}\u{1f}absent", route.scope)
    }

    /// Whether an online run kept a 404 for `path` from `route`, which is
    /// what proves a POM raeva.lock records as missing missing offline.
    pub(super) async fn proven_absent(&self, route: &Route<'_>, path: &str) -> bool {
        let scope = Self::absence_scope(route);
        let kept = self.cache_get_bytes(CacheTable::Miss, &scope, path).await;
        kept.ok()
            .flatten()
            .is_some_and(|status| &status[..] == b"404")
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
        let (miss, at, _) = misses.get(key)?;
        (*at == generation).then(|| miss.clone().error())
    }

    /// Whether the miss recorded for `key` is not kept yet, which it now is.
    fn take_unkept(&self, key: &MissKey) -> bool {
        let mut misses =
            (self.absent_paths.lock()).unwrap_or_else(std::sync::PoisonError::into_inner);
        misses
            .get_mut(key)
            .is_some_and(|(_, _, unkept)| std::mem::take(unkept))
    }

    /// Remember `err` for `key` if it is a [`Miss`], under `generation` or
    /// the earlier one `route` picked its credential under; `unkept` when
    /// the metadata cache does not have it yet.
    pub(super) fn record_miss(
        &self,
        route: &Route<'_>,
        key: MissKey,
        err: &RepoError,
        generation: u64,
        unkept: bool,
    ) {
        let generation = route.picked_under(generation);
        if let Some(miss) = Miss::of(err, &key.path)
            && let Ok(mut misses) = self.absent_paths.lock()
        {
            misses.insert(key, (miss, generation, unkept));
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
        self.ensure_filters_admit(route, group_id, &path)?;
        let _turn = self.metadata_turn(route, &path).await;
        let scope = Self::metadata_cache_scope(route, version);
        let (memo_key, read_key) = self.metadata_memo_keys(&scope, &path);
        let held_key = format!(
            "{memo_key}\n{read_key}\n{}",
            route.picked_under(self.credential_generation())
        );
        if let Some(metadata) = (self.cached_metadata(&scope, &path, &memo_key, &read_key)).await? {
            return Ok(metadata);
        }
        match read {
            PomRead::Use => {
                let held = self.held().adopt(&held_key);
                if let Some((bytes, _, checked, warnings, _)) = held {
                    warnings.emit();
                    self.cache_insert_metadata(route, &path, bytes.as_ref(), version, checked)
                        .await;
                    self.held().remove(&held_key);
                    let metadata = Metadata::from_bytes(&bytes)?;
                    self.keep_fetched_metadata(memo_key, read_key, &metadata);
                    return Ok(metadata);
                }
            }
            PomRead::Prefetch => {
                let held = self.held().get(&held_key);
                if let Some((bytes, _)) = held {
                    return Metadata::from_bytes(&bytes);
                }
            }
        }

        let mut warnings = DeferredWarnings::default();
        let fetched = self
            .fetch_model_bytes(route, &path, version, None, &mut warnings, read)
            .await;
        // A prefetch holds its warnings with the file, for the read that
        // uses it; a miss stands for both, as it does for a POM.
        if read == PomRead::Prefetch {
            let (bytes, checked, _) = fetched?;
            let metadata = Metadata::from_bytes(&bytes)?;
            let held = HeldPom {
                bytes,
                expiry: Expiry::After(0),
                checked,
                warnings: Some(warnings.after_logged()),
                check: None,
            };
            self.held().insert(held_key, held);
            return Ok(metadata);
        }
        warnings.emit();
        let (bytes, checked, _) = fetched?;
        let metadata = Metadata::from_bytes(&bytes)?;
        self.cache_insert_metadata(route, &path, bytes.as_ref(), version, checked)
            .await;
        self.keep_fetched_metadata(memo_key, read_key, &metadata);
        Ok(metadata)
    }

    /// The keys of `path` in `scope` in the metadata memo: the file, then
    /// the settings that decide whether a row of it is usable.
    fn metadata_memo_keys(&self, scope: &str, path: &str) -> (String, String) {
        let read_key = format!(
            "{} {} {}",
            self.offline,
            self.require_checksums,
            self.lock_pin(path)
                .map(ToString::to_string)
                .unwrap_or_default()
        );
        (format!("{scope}\n{path}"), read_key)
    }

    /// The metadata at `path` in `scope` that this client read or fetched
    /// before under `key` and `read_key`, else that a usable row of the
    /// metadata cache holds. `None` when there is no usable row, which stays
    /// so until this client fetches the file.
    async fn cached_metadata(
        &self,
        scope: &str,
        path: &str,
        key: &str,
        read_key: &str,
    ) -> Result<Option<Metadata>> {
        let memoized =
            (self.metadata_memo().get(key)).and_then(|reads| reads.get(read_key).cloned());
        if let Some(read) = memoized {
            return Ok(read);
        }
        let read = match self
            .cache_get_entry(CacheTable::VersionList, scope, path, None, PomRead::Use)
            .await?
        {
            Some((bytes, _)) => Some(Metadata::from_bytes(&bytes)?),
            None => None,
        };
        (self.metadata_memo().entry(key.to_string()).or_default())
            .insert(read_key.to_string(), read.clone());
        Ok(read)
    }

    /// Serve `metadata`, which this client fetched, to its later reads under
    /// `key` and `read_key` instead of the row it wrote, which another
    /// process can replace with what it fetched before.
    fn keep_fetched_metadata(&self, key: String, read_key: String, metadata: &Metadata) {
        let reads = HashMap::from([(read_key, Some(metadata.clone()))]);
        self.metadata_memo().insert(key, reads);
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
        read: PomRead,
        pin: Option<&Digest>,
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
            let resolved = (self.resolve_snapshot_version_routed(route, &coord, read, pin)).await?;
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
    /// go to `warnings`, for the caller to log. For a POM that
    /// [`RepoClient::checking_sha256_late`] took on its `.sha1`, the check of
    /// its `.sha256` comes with them, for the caller to finish.
    pub(super) async fn fetch_with_checksums(
        &self,
        route: &Route<'_>,
        path: &str,
        version: &str,
        pin: Option<&Digest>,
        warnings: &mut DeferredWarnings,
    ) -> Result<(Bytes, Checked, Option<LateSha256>)> {
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
        let required_pin = pin.or_else(|| self.release_lock_pin(path));
        let sha256 = pin
            .or_else(|| self.lock_pin(path))
            .and_then(Digest::as_sha256);
        for attempt in 0..=1 {
            // A publisher may update metadata and its sidecar separately, so refetch both.
            // A failed file request ends both and is the result, whichever
            // request failed first; the probe's warnings are logged only once
            // the file has arrived.
            let mut probed = DeferredWarnings::default();
            let mut late = None;
            let (bytes, checksum) = match sha256 {
                Some(pin) => {
                    let bytes = self.fetch_path(route, path).await?;
                    let actual = Sha256::from_bytes(&bytes);
                    if actual == *pin {
                        // A POM raeva.lock marks as accepted without a
                        // checksum file asks for one again.
                        let mut verified = false;
                        if !repo.is_local() && self.lock_unverified.contains(path) {
                            let mut probed = DeferredWarnings::default();
                            if let Some(checksum) =
                                self.probe_checksum(route, path, &mut probed, None).await?
                            {
                                verify_checksum(&bytes, &checksum, path)?;
                                verified = true;
                            }
                            warnings.append(probed);
                        }
                        return Ok((bytes, Checked::Pinned(verified), None));
                    }
                    if required_pin.is_some() {
                        return Err(RepoError::ChecksumMismatch {
                            subject: path.to_string().into(),
                            artifact: None,
                            expected: Digest::Sha256(pin.clone()),
                            actual: Digest::Sha256(actual),
                            check: IntegritySource::LockPin,
                        });
                    }
                    (
                        bytes,
                        self.probe_checksum(route, path, &mut probed, None).await,
                    )
                }
                None => {
                    let (sha1, arrived) = tokio::sync::watch::channel(None);
                    let fetch = async {
                        let bytes = self.fetch_path(route, path).await?;
                        // A SNAPSHOT POM read fetches metadata first, in the
                        // same scope.
                        if path.ends_with(".pom") {
                            let _ = ARRIVAL.try_with(|arrived| arrived(&bytes));
                        }
                        sha1.send_replace(Some(Digest::of_bytes(HashAlgorithm::Sha1, &bytes)));
                        Ok::<_, RepoError>(bytes)
                    };
                    let defer = self.late_checks.is_some() && path.ends_with(".pom");
                    let probe = self.probe_checksum(
                        route,
                        path,
                        &mut probed,
                        defer.then_some((arrived, &mut late)),
                    );
                    if self.sidecar_hints.file_first(&repo.url) {
                        let bytes = fetch.await?;
                        (bytes, probe.await)
                    } else {
                        tokio::try_join!(fetch, async { Ok(probe.await) })?
                    }
                }
            };
            // A pin of another algorithm than SHA-256 decides the bytes as a
            // SHA-256 pin does, whatever their checksum file says.
            if let Some(pin) = required_pin.filter(|pin| pin.as_sha256().is_none()) {
                let actual = Digest::of_bytes(pin.algorithm(), &bytes);
                if actual != *pin {
                    return Err(RepoError::ChecksumMismatch {
                        subject: path.to_string().into(),
                        artifact: None,
                        expected: pin.clone(),
                        actual,
                        check: IntegritySource::LockPin,
                    });
                }
                return Ok((bytes, Checked::Pinned(false), None));
            }
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
                // No flag lifts a `fail` policy, so it is named before the flag.
                None if !repo.is_local() && remote_metadata && fail => {
                    return Err(RepoError::MissingMetadataChecksum(path.to_string()));
                }
                None if !repo.is_local() && self.require_checksums => {
                    return Err(RepoError::MissingChecksum(path.to_string()));
                }
                None => {
                    if !repo.is_local() {
                        let (repository_url, path) = (
                            rv_config::redact_repository_url(&repo.url),
                            path.to_string(),
                        );
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
            return Ok((bytes, checked, late));
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
    /// raeva.lock pins the bytes, so the checksum file was not read, unless
    /// the lock marks the file as accepted without one: then `true` when
    /// one verified them.
    Pinned(bool),
}

/// The directory of the resolved snapshot file version `resolved`. Maven
/// Resolver takes it from the resolved version, so `1.0SNAPSHOT` at build 7
/// lives under `1.020240101.010101-7/`.
pub(super) fn resolved_directory(resolved: &str) -> String {
    rv_maven_types::snapshot_base_version(resolved).unwrap_or_else(|| resolved.to_string())
}
