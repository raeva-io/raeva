//! Single requests on a route: one file, or the checksum sidecar of one.

use bytes::Bytes;
use rv_maven_types::{Digest, HashAlgorithm};
use tracing::warn;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use super::RepoClient;
use crate::error::{RepoError, Result};
use crate::fetch::{fetch_bytes, fetch_text, parse_checksum};
use crate::routing::Route;

impl RepoClient {
    pub(super) async fn fetch_checksum(
        &self,
        route: &Route<'_>,
        path: &str,
    ) -> Result<Option<Digest>> {
        let mut warnings = DeferredWarnings::default();
        let checksum = self.probe_checksum(route, path, &mut warnings).await;
        warnings.emit();
        checksum
    }

    /// [`Self::fetch_checksum`], with its warnings held in `warnings` rather
    /// than logged.
    pub(super) async fn probe_checksum(
        &self,
        route: &Route<'_>,
        path: &str,
        warnings: &mut DeferredWarnings,
    ) -> Result<Option<Digest>> {
        let repo = &route.endpoint;
        if self.offline && !repo.is_local() {
            return Ok(None);
        }
        // SHA-256 is preferred, then SHA-1, then MD5, the last of Maven's
        // default algorithms: Maven Central publishes a `.sha1` for
        // essentially every artifact, a `.sha256` for almost none, and for a
        // few files only an `.md5`. The durable pin in raeva.lock is always
        // the locally computed SHA-256, whichever sidecar gated this fetch.
        //
        // The `.sha1` request starts with the `.sha256` one once this origin
        // has answered 404 for a `.sha256`, since another 404 is then likely
        // and costs a round trip before the fallback. The answers are still
        // taken in preference order.
        // A key, not shown: redaction could make two mirrors look alike.
        let origin = repo.url.clone();
        let request = |algorithm: HashAlgorithm| async move {
            let checksum_url = repo.url_for_path(&format!("{path}.{}", algorithm.as_str()))?;
            fetch_text(
                self.transport.client_for(&checksum_url)?.as_ref(),
                &checksum_url,
                Some(&repo.base_url()?),
                route.auth()?,
                &self.fetch,
            )
            .await
        };
        let mut sha1_early =
            (self.sha256_gaps.contains(&origin)).then(|| Box::pin(request(HashAlgorithm::Sha1)));
        let mut sha1_done = None;
        let sha256 = match sha1_early.as_mut() {
            Some(early) => {
                let sha256 = Box::pin(request(HashAlgorithm::Sha256));
                match futures::future::select(sha256, early).await {
                    futures::future::Either::Left((result, _)) => result,
                    futures::future::Either::Right((sha1, sha256)) => {
                        sha1_done = Some(sha1);
                        sha256.await
                    }
                }
            }
            None => request(HashAlgorithm::Sha256).await,
        };
        if sha256.as_ref().is_err_and(sidecar_absent) {
            self.sha256_gaps.insert(origin);
        }
        // The first failure other than a 404 is reported when no sidecar
        // is usable, rather than a generic missing checksum.
        let mut first_err = None;
        let sha256 = checksum_outcome(path, HashAlgorithm::Sha256, sha256, &mut first_err);
        if let Some(outcome) = sha256 {
            return outcome;
        }
        let sha1 = match (sha1_done, sha1_early) {
            (Some(done), _) => done,
            (None, Some(early)) => early.await,
            (None, None) => request(HashAlgorithm::Sha1).await,
        };
        let mut outcome = checksum_outcome(path, HashAlgorithm::Sha1, sha1, &mut first_err);
        if outcome.is_none() {
            let md5 = request(HashAlgorithm::Md5).await;
            outcome = checksum_outcome(path, HashAlgorithm::Md5, md5, &mut first_err);
        }
        if let Some(Ok(Some(checksum))) = &outcome {
            // `sec_code` is mirrored into the JSON envelope's warnings,
            // which `--json` runs still show.
            let path = path.to_string();
            let name = match checksum.algorithm() {
                HashAlgorithm::Md5 => "MD5",
                _ => "SHA-1",
            };
            warnings.push(move || {
                warn!(
                    sec_code = "WEAK_HASH_FALLBACK",
                    path,
                    "falling back to {name} checksum (weak hash algorithm); \
                     repository should provide SHA-256 checksums"
                );
            });
        }
        // No usable digest from any algorithm: every sidecar 404ed, or a
        // 200 body held no hex token (HTML "not found"): the caller's
        // `require_checksums` and lock pin decide, as they do for all-404.
        outcome.unwrap_or_else(|| match first_err {
            None | Some(RepoError::MissingChecksum(_)) => Ok(None),
            Some(err) => Err(err),
        })
    }

    pub(super) async fn fetch_path(&self, route: &Route<'_>, path: &str) -> Result<Bytes> {
        let repo = &route.endpoint;
        if self.offline && !repo.is_local() {
            if self.lock_missing_poms.contains(path) {
                return Err(RepoError::NotFound(path.to_string()));
            }
            return Err(RepoError::OfflineNotCached(path.to_string()));
        }
        let url = repo.url_for_path(path)?;

        fetch_bytes(
            self.transport.client_for(&url)?.as_ref(),
            &url,
            Some(&repo.base_url()?),
            route.auth()?,
            &self.fetch,
            self.progress.as_ref(),
        )
        .await
    }
}

/// What one sidecar answer decides: `Some` ends the probe, `None` moves on
/// to the next algorithm, recording a failure in `first_err`.
fn checksum_outcome(
    path: &str,
    algorithm: HashAlgorithm,
    fetched: Result<String>,
    first_err: &mut Option<RepoError>,
) -> Option<Result<Option<Digest>>> {
    match fetched {
        // A 200 body with no usable hex token, such as an HTML "not found"
        // page, is no sidecar: the lock pin or the checksum policy decides.
        Ok(text) => {
            if let Some(checksum) = parse_checksum(&text, algorithm) {
                return Some(Ok(Some(checksum)));
            }
            tracing::debug!(
                path,
                bytes = text.len(),
                "the {algorithm} checksum file holds no digest"
            );
        }
        Err(err) if sidecar_absent(&err) => {}
        // A proxy refusal, a credential that cannot be set up, or a
        // rejected certificate gates every probe the same way, unless an
        // earlier algorithm's retried failure already ends the search.
        Err(err)
            if matches!(
                err,
                RepoError::Unauthorized { .. } | RepoError::AuthSetup(_)
            ) || err
                .tls_cause()
                .is_some_and(rv_http::tls_failure_is_permanent) =>
        {
            let retried = first_err.take().filter(RepoError::is_transient);
            return Some(Err(retried.unwrap_or(err)));
        }
        // Transient failures here have already used their retries, and one
        // is kept over other failures: it ends the repository search.
        Err(err) => {
            if first_err
                .as_ref()
                .is_none_or(|first| err.is_transient() && !first.is_transient())
            {
                *first_err = Some(err);
            }
        }
    }
    None
}

/// Whether a sidecar request found no sidecar. Object stores such as S3, GCS
/// and R2 answer 403 for a missing key, so a repository's 401 or 403 moves on
/// to the next algorithm as a 404 does, as in Maven; a refused file fails its
/// own request.
fn sidecar_absent(err: &RepoError) -> bool {
    matches!(err, RepoError::NotFound(_))
        || matches!(err, RepoError::Unauthorized { status, .. } if matches!(status.as_u16(), 401 | 403))
}

/// Warnings held back until [`DeferredWarnings::emit`]. A checksum probe that
/// runs beside the request for the file it checks logs nothing when that
/// request fails and cancels it, however far the probe got.
#[derive(Default)]
pub(super) struct DeferredWarnings(Vec<Box<dyn FnOnce() + Send>>);

impl DeferredWarnings {
    pub(super) fn push(&mut self, warning: impl FnOnce() + Send + 'static) {
        self.0.push(Box::new(warning));
    }

    /// Hold `other`'s warnings after these.
    pub(super) fn append(&mut self, mut other: DeferredWarnings) {
        self.0.append(&mut other.0);
    }

    /// These warnings, after what the prefetch held on this thread has
    /// logged so far.
    pub(super) fn after_logged(self) -> Self {
        let logged = rv_maven_model::held::take();
        let mut warnings = DeferredWarnings::default();
        warnings.push(move || logged.show());
        warnings.append(self);
        warnings
    }

    pub(super) fn emit(self) {
        for warning in self.0 {
            warning();
        }
    }
}

/// Origins that have answered 404 for a `.sha256` sidecar, shared by a
/// client's clones.
#[derive(Clone, Default)]
pub(super) struct Sha256Gaps(Arc<Mutex<HashSet<String>>>);

impl Sha256Gaps {
    fn contains(&self, origin: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(origin)
    }

    fn insert(&self, origin: String) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(origin);
    }
}
