//! Artifact downloads into the content-addressed store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::warn;

use rv_maven_types::{ArtifactCoord, BlobId, Digest};
use rv_store::{Origin, PinCheck, Staged, Store};

use super::RepoClient;
use super::requests::DeferredWarnings;
use crate::artifact::ArtifactRequest;
use crate::error::{RepoError, Result};
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
    warnings: DeferredWarnings,
    staged: Staged,
}

/// The artifacts [`RepoClient::fetch_artifact`] stored, by the same key as
/// [`ArtifactPrefetches`], with whether a repository checksum verified them,
/// shared by a client's clones. Platforms resolved together fetch the same
/// files, and the first download answers the others.
pub(super) type ArtifactFetches =
    Arc<Mutex<HashMap<String, Arc<tokio::sync::OnceCell<(BlobId, bool)>>>>>;

impl RepoClient {
    /// Download the artifact of `req` from `repo`, with its checksum
    /// sidecar, ahead of a [`Self::fetch_artifact`] for it. The bytes wait
    /// in a private temporary file of `store`; that later call checks them
    /// as it checks its own download and publishes them only if they pass.
    /// Warnings wait for that call too. Offline, for a local repository or
    /// a `-SNAPSHOT`, and on any failure this keeps nothing, and the later
    /// call downloads the artifact itself.
    pub async fn prefetch_artifact(
        &self,
        repo: &crate::Repository,
        req: &ArtifactRequest,
        store: &Store,
    ) {
        if self.offline || req.validate().is_err() || req.is_snapshot() {
            return;
        }
        self.prefetching(async {
            let route = self.router.route(repo);
            let repo = &route.endpoint;
            if repo.is_local() || self.ensure_repo_allows_version(repo, &req.version).is_err() {
                return;
            }
            let path = req.to_path();
            if self.known_absent(&route, &path).is_some() {
                return;
            }
            let cell = self.artifact_prefetch_cell(&route, &path);
            cell.get_or_init(|| async {
                Mutex::new(self.download_for_later(&route, &path, store).await)
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
    ) -> Option<Prefetched> {
        let repo = &route.endpoint;
        let url = repo.url_for_path(path).ok()?;
        let client = self.transport.client_for(&url).ok()?;
        let repository_root = repo.base_url().ok()?;
        let generation = self.credential_generation();
        let auth = route.auth().ok()?;
        let mut warnings = DeferredWarnings::default();
        let pinned = self.lock_pin(path).and_then(Digest::as_sha256).is_some();
        let (checksum, staged) = {
            let probe = std::pin::pin!(async {
                if pinned {
                    return Ok(None);
                }
                self.probe_checksum(route, path, &mut warnings)
                    .await
                    .map(Some)
            });
            let download = std::pin::pin!(fetch_artifact_staged(
                client.as_ref(),
                &url,
                Some(&repository_root),
                auth,
                &self.fetch,
                None,
                store,
                None,
                true,
            ));
            match futures::future::select(probe, download).await {
                futures::future::Either::Left((checksum, download)) => (checksum, download.await),
                futures::future::Either::Right((staged, probe)) => match staged {
                    // A missing file has no checksum file either.
                    Err(err) => (Ok(None), Err(err)),
                    staged => (probe.await, staged),
                },
            }
        };
        let staged = staged
            .inspect_err(|err| self.remember_absent(route, path, err, generation))
            .ok()?
            .0;
        Some(Prefetched {
            checksum: checksum.transpose(),
            warnings: warnings.after_logged(),
            staged,
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
    }

    /// Download an artifact from `repo`, or the mirror that serves it, into
    /// `store`. The bytes must match the repository's checksum sidecar and
    /// `options.pin`. A file without a sidecar is accepted when `options.pin`
    /// is given or the bytes match the pin [`Self::with_lock_pins`] recorded,
    /// and otherwise only when missing sidecars are allowed. The bytes are
    /// hashed while they stream and enter the store only after the checks
    /// pass, so a mismatch leaves no blob and no index row.
    pub async fn fetch_artifact(
        &self,
        repo: &crate::Repository,
        req: &ArtifactRequest,
        store: &Store,
        options: FetchArtifact<'_>,
    ) -> Result<Fetched> {
        req.validate().map_err(RepoError::InvalidCoord)?;
        let route = self.router.route(repo);
        let path = self.artifact_path(&route, req).await?;
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
        let Some(endpoint) = self.unblocked_endpoint(repo) else {
            return Ok(None);
        };
        let lookup = |unverified, recorded| {
            store.lookup_artifact_from(key, &repo.url, &endpoint.url, unverified, recorded)
        };
        if let Some(blob) = lookup(!self.require_checksums, false).await? {
            return Ok(Some(blob));
        }
        // `--update` fetches bytes a restore took without a checksum file
        // again.
        let Some(pin) = self.lock_pin_for(key).filter(|_| !self.updates()) else {
            return Ok(None);
        };
        Ok(lookup(true, true).await?.filter(|blob| blob == pin))
    }

    /// The blob `store` holds for `key` as `repo` serves it now, and whether
    /// a repository checksum verified it: only bytes this route served, and
    /// unverified ones only when the run accepts missing checksums. A hint,
    /// as [`Store::lookup_artifact_from`] is.
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
        let Some(endpoint) = self.unblocked_endpoint(repo) else {
            return Ok(None);
        };
        for verified in [true, false] {
            if !verified && self.require_checksums {
                break;
            }
            let found = store
                .lookup_artifact_from(key, &repo.url, &endpoint.url, !verified, false)
                .await?;
            if let Some(blob) = found {
                return Ok(Some((blob, verified)));
            }
        }
        Ok(None)
    }

    /// The endpoint that serves `repo`, or `None` behind a blocked mirror,
    /// whose stored answers count no more than its live ones.
    fn unblocked_endpoint(&self, repo: &crate::Repository) -> Option<crate::Repository> {
        let route = self.router.route(repo);
        (!route.mirror.is_some_and(|mirror| mirror.blocked)).then_some(route.endpoint)
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
    /// resolved through the endpoint's metadata.
    pub(super) async fn artifact_path(
        &self,
        route: &Route<'_>,
        req: &ArtifactRequest,
    ) -> Result<String> {
        self.ensure_repo_allows_version(&route.endpoint, &req.version)?;
        let snapshot = self.resolve_snapshot_for_request(route, req).await?;
        Ok(req.to_path_with_versions(&snapshot.dir_version, &snapshot.file_version))
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
            self.record_miss(route, key, err, generation);
        }
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
        let (blob, verified) = cell
            .get_or_try_init(|| async {
                downloaded.store(true, std::sync::atomic::Ordering::Relaxed);
                self.download_artifact(route, path, store, options).await
            })
            .await?
            .clone();
        if downloaded.into_inner() {
            return Ok((blob, verified));
        }
        let accepted = match options.pin {
            Some(pin) => holds_pin(store, &blob, pin).await?,
            None => {
                verified
                    || !self.require_checksums
                    || self.lock_pin(path).and_then(Digest::as_sha256) == Some(&blob)
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
        let (checksum, staged) = match prefetched {
            Some(prefetched) => {
                prefetched.warnings.emit();
                // The bytes arrived earlier, unseen by progress; they count
                // now, as one transfer that is already complete.
                let transfer =
                    Transfer::arrived(self.progress.as_ref(), &url, prefetched.staged.size());
                (prefetched.checksum, Ok((prefetched.staged, transfer)))
            }
            None if pin.is_some() => {
                let staged = fetch_artifact_staged(
                    client.as_ref(),
                    &url,
                    Some(&repository_root),
                    auth,
                    &self.fetch,
                    self.progress.as_ref(),
                    store,
                    options.index,
                    true,
                );
                (None, staged.await)
            }
            None => {
                let sidecar = std::pin::pin!(self.fetch_checksum(route, path));
                let download = std::pin::pin!(fetch_artifact_staged(
                    client.as_ref(),
                    &url,
                    Some(&repository_root),
                    auth,
                    &self.fetch,
                    self.progress.as_ref(),
                    store,
                    options.index,
                    true,
                ));
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

        // A file that failed to download reports that failure, before any
        // of its sidecar: a missing file has no checksum file either.
        let (staged, transfer) = staged?;
        let checksum = checksum.transpose()?;
        // A pin verifies the bytes without a sidecar: the caller's, or the
        // one raeva.lock records when the bytes match it.
        let pinned = options.pin.is_some()
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

        let checks = ArtifactChecks {
            sidecar: checksum.as_ref(),
            pin: options.pin,
            index: options.index,
        };
        let verified = publish_artifact(&url, transfer, store, staged, checks).await?;

        if unverified {
            warn!(
                sec_code = "CHECKSUM_MISSING",
                repository_url = %rv_config::redact_url(&repo.url),
                path, "the repository has no checksum file for this download"
            );
        }

        Ok((verified.blob, checksum.is_some()))
    }
}

/// Whether `blob` holds the bytes `pin` names: a SHA-256 pin is the blob id,
/// another algorithm's is checked against the stored file.
async fn holds_pin(store: &Store, blob: &BlobId, pin: &Digest) -> Result<bool> {
    Ok(match pin.as_sha256() {
        Some(pinned) => pinned == blob,
        None => matches!(store.check_pin_async(blob, pin).await?, PinCheck::Match),
    })
}
