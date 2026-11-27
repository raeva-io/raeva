//! Artifact downloads into the content-addressed store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::warn;

use rv_maven_types::{ArtifactCoord, BlobId, Digest};
use rv_store::metadata_cache::CacheTable;
use rv_store::{Origin, PinCheck, Staged, Store};

use super::models::PomRead;
use super::requests::{DeferredWarnings, wrong_sha256 as wrong_sha256_warning};
use super::{RepoClient, file_path, filter_path};
use crate::artifact::ArtifactRequest;
use crate::error::{IntegritySource, RepoError, Result};
use crate::fetch::{ArtifactChecks, Transfer, fetch_artifact_staged, publish_artifact};
use crate::routing::Route;

/// What [`RepoClient::fetch_artifact`] checks beyond the repository's
/// checksum sidecar, and where it records the artifact.
#[derive(Debug, Clone, Copy, Default)]
pub struct FetchArtifact<'a> {
    /// The checksum raeva.lock pins. Bytes that do not match it are not stored.
    pub pin: Option<&'a Digest>,
    /// The coordinate to index the artifact under, in the same store lock
    /// that publishes the bytes, with the repository as its [`Origin`].
    pub index: Option<&'a ArtifactCoord>,
}

/// An artifact in the store, and the repository that served it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Fetched {
    /// The id of the verified blob in the store.
    pub blob: BlobId,
    /// The configured repository or mirror URL the bytes came from. Redirect
    /// targets are transport details and never appear here. raeva.lock records
    /// the declared repository, not this URL. Not redacted: pass it through
    /// [`rv_config::redact_url`] before showing or logging it.
    pub served_by: String,
    /// The repository-relative path actually served, after snapshot resolution.
    pub path: String,
    /// Whether the bytes matched the repository's checksum file, independently
    /// of acceptance under a lock pin or the local-file policy.
    pub checksum_verified: bool,
}

/// Artifact downloads [`RepoClient::prefetch_artifact`] made, by in-flight
/// key, shared by a client's clones. An entry stays once a download has
/// claimed it, so a late prefetch does not download the file again.
pub(super) type ArtifactPrefetches =
    Arc<Mutex<HashMap<String, Arc<tokio::sync::OnceCell<Mutex<Option<Prefetched>>>>>>>;

pub(super) struct Prefetched {
    /// The sidecar probe's answer, `None` when a lock pin made it unneeded.
    checksum: Option<Result<Option<Digest>>>,
    /// The credential generation it was asked under: a later credential
    /// may get another answer.
    generation: u64,
    warnings: DeferredWarnings,
    staged: Staged,
    /// The SHA-1 the server sent with the file.
    included: Option<Digest>,
}

/// The artifacts [`RepoClient::fetch_artifact`] stored, by the same key as
/// [`ArtifactPrefetches`], with whether a repository checksum verified them,
/// shared by a client's clones. Platforms resolved together fetch the same
/// files, and the first download answers the others.
pub(super) type ArtifactFetches =
    Arc<Mutex<HashMap<String, Arc<tokio::sync::OnceCell<(BlobId, bool)>>>>>;

/// The files a client admitted, by repository path: true once a checksum
/// file verified the bytes, false when the repository published none and
/// neither a lock pin nor a `file:` repository vouched for them. Shared by
/// a client's clones.
pub(super) type Admissions = Arc<Mutex<HashMap<String, bool>>>;

impl RepoClient {
    /// The files this client and its clones admitted, by repository path:
    /// `true` for a file a checksum file verified, `false`
    /// for one accepted without any (`--allow-missing-checksums`). A file
    /// a lock pin or a `file:` repository admitted is not listed.
    pub fn admissions(&self) -> HashMap<String, bool> {
        (self.admissions.lock())
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) fn note_admission(&self, path: &str, verified: bool) {
        let mut admissions =
            (self.admissions.lock()).unwrap_or_else(std::sync::PoisonError::into_inner);
        *admissions.entry(path.to_string()).or_insert(verified) |= verified;
    }

    /// [`Self::note_admission`] for `blob`, stored bytes of `path` from
    /// `repo`: a lock pin or a `file:` repository vouches for unverified
    /// bytes.
    /// Whether `--update` downloads the file at `path` again instead of
    /// taking stored bytes no checksum file verified: raeva.lock marks it
    /// as accepted without one, and the download asks for one again.
    pub(super) fn rechecks(&self, path: &str) -> bool {
        self.updates() && self.lock_unverified.contains(path)
    }

    fn note_stored(&self, repo: &crate::Repository, path: &str, blob: &BlobId, verified: bool) {
        let pinned = || self.lock_pin(path).and_then(Digest::as_sha256) == Some(blob);
        if verified || !(repo.is_local() || pinned()) {
            self.note_admission(path, verified);
        }
    }

    /// Download the artifact of `req` from `repo`, with its checksum
    /// sidecar, ahead of a [`Self::fetch_artifact`] for it. The bytes wait
    /// in a private temporary file of `store`; that later call checks them
    /// as it checks its own download and publishes them only if they pass.
    /// Warnings wait for that call too. A `-SNAPSHOT` is the build its
    /// metadata names, read as a POM prefetch reads it. Offline, for a local
    /// repository, and when the file fails this keeps nothing, and the later
    /// call downloads the artifact itself. A checksum file that failed, once
    /// retried, is kept with the file: the later call fails as its own
    /// probe would have, without downloading the file again. `slot` is
    /// dropped once the file has arrived, before the checksum files it
    /// waits for.
    pub async fn prefetch_artifact(
        &self,
        repo: &crate::Repository,
        req: &ArtifactRequest,
        store: &Store,
        slot: impl Send,
    ) {
        if self.offline || req.validate().is_err() {
            return;
        }
        self.prefetching(async {
            let route = self.router.route(repo);
            if route.endpoint.is_local() {
                return;
            }
            let Ok(path) = self
                .artifact_path(&route, req, PomRead::Prefetch, None)
                .await
            else {
                return;
            };
            if self.known_absent(&route, &path).is_some()
                || self.twin_fetched(&route, &path).is_some()
            {
                return;
            }
            let cell = self.artifact_prefetch_cell(&route, &path);
            cell.get_or_init(|| async {
                Mutex::new(self.download_for_later(&route, &path, store, slot).await)
            })
            .await;
        })
        .await;
    }

    async fn download_for_later(
        &self,
        route: &Route<'_>,
        path: &str,
        store: &Store,
        slot: impl Send,
    ) -> Option<Prefetched> {
        let repo = &route.endpoint;
        let url = repo.url_for_path(path).ok()?;
        let client = self.transport.client_for(&url).ok()?;
        let repository_root = repo.base_url().ok()?;
        let generation = self.credential_generation();
        let auth = route.auth().ok()?;
        // The route may have picked its credential earlier, for the metadata.
        let generation = route.picked_under(generation);
        let mut warnings = DeferredWarnings::default();
        let pinned = self.pin_skips_checksum(path);
        let file_first = self.sidecar_hints.file_first(&repo.url);
        let (checksum, staged) = {
            let probe = std::pin::pin!(async {
                if pinned {
                    return Ok(None);
                }
                self.probe_checksum(route, path, &mut warnings, None)
                    .await
                    .map(Some)
            });
            let download = std::pin::pin!(async {
                let staged = fetch_artifact_staged(
                    &client,
                    &url,
                    Some(&repository_root),
                    auth,
                    &self.fetch,
                    None,
                    store,
                    None,
                    true,
                )
                .await;
                drop(slot);
                staged
            });
            if file_first {
                match download.await {
                    Err(err) => (Ok(None), Err(err)),
                    staged => (probe.await, staged),
                }
            } else {
                match futures::future::select(probe, download).await {
                    futures::future::Either::Left((checksum, download)) => {
                        (checksum, download.await)
                    }
                    futures::future::Either::Right((staged, probe)) => match staged {
                        // A missing file has no checksum file either.
                        Err(err) => (Ok(None), Err(err)),
                        staged => (probe.await, staged),
                    },
                }
            }
        };
        self.sidecar_hints.note_file(&repo.url, &staged);
        let (staged, _, included) = staged
            .inspect_err(|err| self.remember_absent(route, path, err, generation))
            .ok()?;
        Some(Prefetched {
            generation,
            checksum: checksum.transpose(),
            warnings: warnings.after_logged(),
            staged,
            included,
        })
    }

    fn artifact_key(&self, route: &Route<'_>, path: &str) -> String {
        format!(
            "{}
{path}
{}",
            route.scope, self.require_checksums
        )
    }

    fn artifact_prefetch_cell(
        &self,
        route: &Route<'_>,
        path: &str,
    ) -> Arc<tokio::sync::OnceCell<Mutex<Option<Prefetched>>>> {
        let key = self.artifact_key(route, path);
        let mut prefetches = self
            .artifact_prefetches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(prefetches.entry(key).or_default())
    }

    async fn take_prefetched_artifact(&self, route: &Route<'_>, path: &str) -> Option<Prefetched> {
        let cell = self.artifact_prefetch_cell(route, path);
        cell.get_or_init(|| async { Mutex::new(None) })
            .await
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .filter(|prefetched| prefetched.generation == self.credential_generation())
    }

    /// Download an artifact from `repo`, or the mirror that serves it, into
    /// `store`. The bytes must match the repository's checksum sidecar and
    /// `options.pin`, or without it the pin [`Self::with_lock_pins`]
    /// recorded for a release file or timestamped snapshot build, unless
    /// this run updates the lock. A file without a sidecar is accepted when
    /// one of those pins verifies it, and otherwise only when missing
    /// sidecars are allowed. The bytes are hashed while they
    /// stream and enter the store only after the checks pass, so a mismatch
    /// leaves no blob and no index row.
    pub async fn fetch_artifact(
        &self,
        repo: &crate::Repository,
        req: &ArtifactRequest,
        store: &Store,
        options: FetchArtifact<'_>,
    ) -> Result<Fetched> {
        req.validate().map_err(RepoError::InvalidCoord)?;
        let route = self.router.route(repo);
        let path = (self.artifact_path(&route, req, PomRead::Use, options.pin)).await?;
        let (blob, checksum_verified) = self
            .fetch_artifact_attempt(&route, &path, store, options)
            .await?;
        if let Some(key) = options.index {
            let origin = Origin {
                repo_url: repo.url.clone(),
                endpoint_url: route.endpoint.url.clone(),
                checksum_verified,
                served: true,
            };
            store
                .record_origins(vec![(key.clone(), blob.clone(), origin)])
                .await?;
        }
        Ok(Fetched {
            blob,
            served_by: route.endpoint.url,
            path,
            checksum_verified,
        })
    }

    /// The blob `store` holds for `key` as `repo` serves it now: one a
    /// repository checksum verified or, when the run accepts missing
    /// checksums or raeva.lock pins those bytes, one admitted without. A
    /// hint, as [`Store::lookup_artifact_from`] is.
    ///
    /// # Errors
    ///
    /// The store's, when its index cannot be read.
    pub async fn stored_artifact(
        &self,
        store: &Store,
        repo: &crate::Repository,
        key: &ArtifactCoord,
    ) -> std::result::Result<Option<BlobId>, rv_store::StoreError> {
        let found = self.stored_from(store, repo, key, true).await?;
        Ok(found.map(|(blob, _)| blob))
    }

    /// [`Self::stored_artifact`], of only the bytes this route served, and
    /// whether a repository checksum verified them.
    ///
    /// # Errors
    ///
    /// The store's, when its index cannot be read.
    pub async fn served_artifact(
        &self,
        store: &Store,
        repo: &crate::Repository,
        key: &ArtifactCoord,
    ) -> std::result::Result<Option<(BlobId, bool)>, rv_store::StoreError> {
        self.stored_from(store, repo, key, false).await
    }

    /// The stored blob for `key` as `repo` serves it, and whether a checksum
    /// verified it. Bytes raeva.lock pins count without a checksum, and with
    /// `recorded` also ones a lockfile recorded rather than the route served.
    async fn stored_from(
        &self,
        store: &Store,
        repo: &crate::Repository,
        key: &ArtifactCoord,
        recorded: bool,
    ) -> std::result::Result<Option<(BlobId, bool)>, rv_store::StoreError> {
        let Some(endpoint) = self.unblocked_endpoint(repo, key) else {
            return Ok(None);
        };
        let lookup = |unverified, recorded| {
            store.lookup_artifact_from(key, &repo.url, &endpoint.url, unverified, recorded)
        };
        for verified in [true, false] {
            if !verified && (self.require_checksums || self.rechecks(&file_path(key))) {
                break;
            }
            if let Some(blob) = lookup(!verified, false).await?
                && self.holds_release_pin(store, key, &blob).await?
            {
                self.note_stored(&endpoint, &file_path(key), &blob, verified);
                return Ok(Some((blob, verified)));
            }
        }
        // `--update` downloads again the bytes raeva.lock marks as accepted
        // without a checksum file; the others its pins verified when locked.
        let Some(pin) =
            (self.lock_pin(&file_path(key))).filter(|_| !self.rechecks(&file_path(key)))
        else {
            return Ok(None);
        };
        match lookup(true, recorded).await? {
            Some(blob) if holds_pin(store, &blob, pin).await? => Ok(Some((blob, false))),
            _ => Ok(None),
        }
    }

    /// Whether stored `blob` may stand for `key`: it matches the pin
    /// raeva.lock gives the release file or timestamped snapshot build, if
    /// any. Under `--update` too, other bytes are not the repository's answer,
    /// so the file is fetched again.
    async fn holds_release_pin(
        &self,
        store: &Store,
        key: &ArtifactCoord,
        blob: &BlobId,
    ) -> std::result::Result<bool, rv_store::StoreError> {
        match self.release_file_pin(&file_path(key)) {
            Some(pin) => holds_pin(store, blob, pin).await,
            None => Ok(true),
        }
    }

    /// The endpoint that serves `repo`, or `None` behind a blocked mirror
    /// or when the remote repository filters keep `key` from it, whose
    /// stored answers count no more than its live ones.
    fn unblocked_endpoint(
        &self,
        repo: &crate::Repository,
        key: &ArtifactCoord,
    ) -> Option<crate::Repository> {
        let route = self.router.route(repo);
        (!route.mirror.as_ref().is_some_and(|mirror| mirror.blocked)
            && self.filters_admit(repo, key))
        .then_some(route.endpoint)
    }

    /// [`RepoClient::fetch_artifact`] without a pin or an index row.
    #[cfg(test)]
    pub(crate) async fn fetch_artifact_to_store(
        &self,
        repo: &crate::Repository,
        req: &ArtifactRequest,
        store: &Store,
    ) -> Result<BlobId> {
        self.fetch_artifact(repo, req, store, FetchArtifact::default())
            .await
            .map(|fetched| fetched.blob)
    }

    /// [`RepoClient::fetch_artifact`] indexed under `key`, without a pin.
    pub async fn fetch_artifact_to_store_and_index(
        &self,
        repo: &crate::Repository,
        req: &ArtifactRequest,
        store: &Store,
        key: &ArtifactCoord,
    ) -> Result<BlobId> {
        let options = FetchArtifact {
            pin: None,
            index: Some(key),
        };
        Ok(self.fetch_artifact(repo, req, store, options).await?.blob)
    }

    /// The repository path of `req` on `route`, with a snapshot version
    /// resolved through the endpoint's metadata as `read` reads it, or to
    /// the build raeva.lock pins to `pin`.
    pub(super) async fn artifact_path(
        &self,
        route: &Route<'_>,
        req: &ArtifactRequest,
        read: PomRead,
        pin: Option<&Digest>,
    ) -> Result<String> {
        self.ensure_repo_allows_version(&route.endpoint, &req.version)?;
        self.ensure_filters_admit(route, &req.group_id, &filter_path(req))?;
        let snapshot = (self.resolve_snapshot_for_request(route, req, read, pin)).await?;
        let path = req.to_path_with_versions(&snapshot.dir_version, &snapshot.file_version);
        // Maven judges a snapshot by the build its metadata resolves to.
        self.ensure_filters_admit(route, &req.group_id, &path)?;
        Ok(path)
    }

    /// The blob for `path` on `route` in `store`, and whether a repository
    /// checksum verified it: the one an earlier fetch stored, when this
    /// fetch's checks accept it, otherwise a download.
    pub(super) async fn fetch_artifact_attempt(
        &self,
        route: &Route<'_>,
        path: &str,
        store: &Store,
        options: FetchArtifact<'_>,
    ) -> Result<(BlobId, bool)> {
        if let Some(miss) = self.known_absent(route, path) {
            // A miss a prefetch met stands for this read, credential
            // warnings included.
            let _ = route.auth();
            return Err(miss);
        }
        let generation = self.credential_generation();
        let result = self.fetch_artifact_once(route, path, store, options).await;
        if let Err(err) = &result {
            self.remember_absent(route, path, err, generation);
        }
        result
    }

    /// The miss recorded for `path` on `route` in this run. A repository
    /// searched before the one that serves a file is asked for it once, as
    /// for a POM.
    fn known_absent(&self, route: &Route<'_>, path: &str) -> Option<RepoError> {
        self.recorded_miss(&self.miss_key(route, path)?)
    }

    fn remember_absent(&self, route: &Route<'_>, path: &str, err: &RepoError, generation: u64) {
        if let Some(key) = self.miss_key(route, path) {
            self.record_miss(route, key, err, generation, false);
        }
    }

    /// The pin the bytes at `path` must match: the caller's, or the one
    /// [`Self::release_lock_pin`] names, whichever repository serves them.
    /// Other bytes would otherwise sit in the store as that repository's
    /// copy of a coordinate the lock pins.
    fn required_pin<'a>(&'a self, path: &str, options: FetchArtifact<'a>) -> Option<&'a Digest> {
        (options.pin).or_else(|| self.release_lock_pin(path))
    }

    async fn fetch_artifact_once(
        &self,
        route: &Route<'_>,
        path: &str,
        store: &Store,
        options: FetchArtifact<'_>,
    ) -> Result<(BlobId, bool)> {
        let cell = {
            let mut fetches = self
                .artifact_fetches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(fetches.entry(self.artifact_key(route, path)).or_default())
        };
        let downloaded = std::sync::atomic::AtomicBool::new(false);
        let (blob, verified) = match self.twin_fetched(route, path) {
            Some(fetched) if !cell.initialized() => fetched,
            _ => cell
                .get_or_try_init(|| async {
                    if let Some(blob) = self.cached_pom(route, path, store, options).await? {
                        return Ok((blob, false));
                    }
                    downloaded.store(true, std::sync::atomic::Ordering::Relaxed);
                    self.download_artifact(route, path, store, options).await
                })
                .await?
                .clone(),
        };
        if downloaded.into_inner() {
            return Ok((blob, verified));
        }
        let accepted = match self.required_pin(path, options) {
            Some(pin) => holds_pin(store, &blob, pin).await?,
            None => {
                verified
                    || !self.require_checksums
                    || match self.lock_pin(path) {
                        Some(pin) => holds_pin(store, &blob, pin).await?,
                        None => false,
                    }
            }
        };
        if !accepted || !store.exists_async(&blob).await {
            return self.download_artifact(route, path, store, options).await;
        }
        if let Some(key) = options.index {
            store.add_artifact(key, &blob).await?;
        }
        Ok((blob, verified))
    }

    /// What this run fetched for `path` under Central's other name, which
    /// a fetch here takes as it would join its own earlier one
    /// ([`crate::routing::Router::central_twin`]).
    fn twin_fetched(&self, route: &Route<'_>, path: &str) -> Option<(BlobId, bool)> {
        let key = self.artifact_key(&self.router.central_twin(route)?, path);
        let fetches =
            (self.artifact_fetches.lock()).unwrap_or_else(|poisoned| poisoned.into_inner());
        fetches.get(&key)?.get().cloned()
    }

    /// The POM at `path`, put in the store, when a model read cached the
    /// bytes the pin requires for this repository or under Central's other
    /// name, which would serve this fetch ([`Self::twin_fetched`]).
    async fn cached_pom(
        &self,
        route: &Route<'_>,
        path: &str,
        store: &Store,
        options: FetchArtifact<'_>,
    ) -> Result<Option<BlobId>> {
        let Some(pin @ Digest::Sha256(sha256)) = self.required_pin(path, options) else {
            return Ok(None);
        };
        if !path.ends_with(".pom") {
            return Ok(None);
        }
        let twin = self.router.central_twin(route);
        for scope in std::iter::once(&route.scope).chain(twin.as_ref().map(|twin| &twin.scope)) {
            let cached =
                self.cache_get_entry(CacheTable::Pom, scope, path, Some(pin), PomRead::Use);
            if let Some((bytes, _)) = cached.await?
                && BlobId::from_bytes(&bytes) == *sha256
            {
                return Ok(Some(store.put_bytes(&bytes).await?));
            }
        }
        Ok(None)
    }

    async fn download_artifact(
        &self,
        route: &Route<'_>,
        path: &str,
        store: &Store,
        options: FetchArtifact<'_>,
    ) -> Result<(BlobId, bool)> {
        let repo = &route.endpoint;
        // Check the endpoint before checksum policy or streaming can bypass it.
        if self.offline && !repo.is_local() {
            return Err(RepoError::OfflineNotCached(path.to_string()));
        }
        let url = repo.url_for_path(path)?;
        let client = self.transport.client_for(&url)?;
        let repository_root = repo.base_url()?;
        let auth = route.auth()?;
        // A SHA-256 pin checks the file without its sidecar, which is read
        // only when the bytes do not match a lock pin.
        let pin = match options.pin {
            Some(pin) => pin.as_sha256(),
            None => self.lock_pin(path).and_then(Digest::as_sha256),
        };
        // Otherwise the sidecar and the file are requested together. The
        // file waits in a private temporary file until the sidecar has
        // decided the checks, so nothing is published unverified. The
        // file's own failure is reported before a sidecar's.
        let prefetched = self.take_prefetched_artifact(route, path).await;
        // A prefetch that found no file answers for this request too.
        if prefetched.is_none()
            && let Some(miss) = self.known_absent(route, path)
        {
            return Err(miss);
        }
        let fresh = prefetched.is_none();
        let download = || {
            fetch_artifact_staged(
                &client,
                &url,
                Some(&repository_root),
                auth,
                &self.fetch,
                self.progress.as_ref(),
                store,
                options.index,
                true,
            )
        };
        // What a sidecar probe beside the file logs waits for the file.
        let mut probed = DeferredWarnings::default();
        let (checksum, staged) = match prefetched {
            Some(prefetched) => {
                prefetched.warnings.emit();
                // The bytes arrived earlier, unseen by progress; they count
                // now, as one transfer that is already complete.
                let transfer =
                    Transfer::arrived(self.progress.as_ref(), &url, prefetched.staged.size());
                (
                    prefetched.checksum,
                    Ok((prefetched.staged, transfer, prefetched.included)),
                )
            }
            None if pin.is_some() && !self.lock_unverified.contains(path) => {
                (None, download().await)
            }
            // At an origin that mostly misses, the sidecar waits for the file.
            None if self.sidecar_hints.file_first(&repo.url) => {
                let staged = download().await;
                let checksum = match staged {
                    Ok(_) => Some(self.probe_checksum(route, path, &mut probed, None).await),
                    Err(_) => None,
                };
                (checksum, staged)
            }
            None => {
                let sidecar = std::pin::pin!(self.probe_checksum(route, path, &mut probed, None));
                let download = std::pin::pin!(download());
                match futures::future::select(sidecar, download).await {
                    futures::future::Either::Left((checksum, download)) => {
                        (Some(checksum), download.await)
                    }
                    // A missing file has no checksum file either, so the
                    // next repository is asked without waiting for its probe.
                    futures::future::Either::Right((Err(err), _)) => (None, Err(err)),
                    futures::future::Either::Right((staged, sidecar)) => {
                        (Some(sidecar.await), staged)
                    }
                }
            }
        };

        if fresh {
            self.sidecar_hints.note_file(&repo.url, &staged);
        }
        // A file that failed to download reports that failure, before any
        // of its sidecar: a missing file has no checksum file either.
        let (staged, transfer, included) = staged?;
        probed.emit();
        // maven-resolver checks the SHA-1 the server sent with the file
        // first: one that matches stands for the checksum files, as Central
        // serves stale `.sha1` and `.md5` files for captcha-1.4.0.jar, and
        // one that does not fails the bytes, whatever the files say.
        let sha1 = staged.sha1().map(|sha1| Digest::Sha1(sha1.clone()));
        if let (Some(expected), Some(actual)) = (&included, &sha1)
            && expected != actual
        {
            return Err(RepoError::ChecksumMismatch {
                subject: rv_config::redact_url(url.as_str()).into(),
                artifact: options.index.map(|key| Box::new(key.clone())),
                expected: expected.clone(),
                actual: actual.clone(),
                check: IntegritySource::Header,
            });
        }
        let checksum = match included.filter(|_| sha1.is_some()) {
            Some(included) => Some(Some(included)),
            None => checksum.transpose()?,
        };
        // A pin verifies or refuses the bytes without a sidecar: the
        // required one, or the one raeva.lock records when the bytes match it.
        let required = self.required_pin(path, options);
        let pinned = required.is_some()
            || self
                .lock_pin(path)
                .and_then(Digest::as_sha256)
                .is_some_and(|pin| staged.blob() == pin);
        let checksum = match checksum {
            Some(checksum) => checksum,
            None if pinned => None,
            None => self.fetch_checksum(route, path).await?,
        };
        let unverified = checksum.is_none() && !pinned && !repo.is_local();
        if unverified && self.require_checksums {
            return Err(RepoError::MissingChecksum(path.to_string()));
        }

        // A `.sha256` that disagrees leaves the bytes to the `.sha1`, else
        // the `.md5`, as for a POM ([`RepoClient::maven_vouches`]); when
        // that disagrees too, the `.sha256` mismatch is the error.
        let mut wrong_sha256 = None;
        let checksum = match checksum {
            Some(sha256 @ Digest::Sha256(_)) if sha256 != Digest::Sha256(staged.blob().clone()) => {
                match self.maven_checksum(route, path).await {
                    Ok(Some(maven)) => {
                        wrong_sha256 = Some(sha256);
                        Some(maven)
                    }
                    _ => Some(sha256),
                }
            }
            checksum => checksum,
        };
        let actual = Digest::Sha256(staged.blob().clone());
        let checks = ArtifactChecks {
            sidecar: checksum.as_ref(),
            pin: required,
            index: options.index,
        };
        let verified = match (
            publish_artifact(&url, transfer, store, staged, checks).await,
            &wrong_sha256,
        ) {
            (
                Err(RepoError::ChecksumMismatch {
                    subject,
                    artifact,
                    check: IntegritySource::Sidecar,
                    ..
                }),
                Some(expected),
            ) => {
                return Err(RepoError::ChecksumMismatch {
                    subject,
                    artifact,
                    expected: expected.clone(),
                    actual,
                    check: IntegritySource::Sidecar,
                });
            }
            (verified, _) => verified?,
        };
        if wrong_sha256.is_some()
            && let Some(maven) = &checksum
        {
            wrong_sha256_warning(repo, path, maven.algorithm())();
        }

        if checksum.is_some() || unverified {
            self.note_admission(path, checksum.is_some());
        }
        if unverified {
            warn!(
                sec_code = "CHECKSUM_MISSING",
                repository_url = %rv_config::redact_repository_url(&repo.url),
                path, "the repository has no checksum file for this download"
            );
        }

        Ok((verified.blob, checksum.is_some()))
    }
}

/// Whether `blob` holds the bytes `pin` names: a SHA-256 pin is the blob id,
/// another algorithm's is checked against the stored file.
async fn holds_pin(
    store: &Store,
    blob: &BlobId,
    pin: &Digest,
) -> std::result::Result<bool, rv_store::StoreError> {
    Ok(match pin.as_sha256() {
        Some(pinned) => pinned == blob,
        None => matches!(store.check_pin_async(blob, pin).await?, PinCheck::Match),
    })
}
