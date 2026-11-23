//! Single requests on a route: one file, or the checksum sidecar of one.

use bytes::Bytes;
use futures::future::Either;
use rv_maven_types::{Digest, HashAlgorithm};
use tracing::warn;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::RepoClient;
use crate::error::{RepoError, Result};
use crate::fetch::{
    FetchConfig, OptionalAnswer, Refusers, admitted, fetch_bytes, fetch_text, optional,
    parse_checksum, verify_checksum,
};
use crate::routing::Route;

impl RepoClient {
    pub(super) async fn fetch_checksum(
        &self,
        route: &Route<'_>,
        path: &str,
    ) -> Result<Option<Digest>> {
        let mut warnings = DeferredWarnings::default();
        let checksum = self.probe_checksum(route, path, &mut warnings, None).await;
        warnings.emit();
        checksum
    }

    /// [`Self::fetch_checksum`], with its warnings held in `warnings` rather
    /// than logged. Given the SHA-1 of the file's bytes once they arrive, a
    /// `.sha256` still pending once the `.sha1` has matched them is left in
    /// `late` rather than waited for, and the `.sha1` is the answer for now;
    /// see [`LateSha256::check`].
    pub(super) async fn probe_checksum(
        &self,
        route: &Route<'_>,
        path: &str,
        warnings: &mut DeferredWarnings,
        late: Option<(ArrivedSha1, &mut Option<LateSha256>)>,
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
        // The `.sha1` request starts with the `.sha256` one when another 404
        // is likely, since it costs a round trip before the fallback: when
        // the last `.sha256` asked of this origin for the same groupId and
        // version was missing, or, for a release not asked about before,
        // once the origin has answered 404 for any `.sha256`. Files of one
        // release are published together, so they agree. The answers are
        // still taken in preference order.
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
        // The `.sha256` and an early `.sha1` both go out unless the server is
        // refused when they start, so that a busy answer to one, whichever
        // comes first, does not keep the other unsent. Nothing is awaited
        // between the look at the server's cooldown and sending them. The
        // early `.sha1` is optional: a busy answer to it holds back only
        // other optional requests, and after one, none is sent early. Once
        // the `.sha256` has no digest, the early `.sha1` stands in for the
        // one asked for then, and counts only as that one would.
        let sha1_path = format!("{path}.{}", HashAlgorithm::Sha1.as_str());
        let cooldowns = (repo.url_for_path(path).ok()).map(|url| {
            let cooldowns = &self.fetch.cooldowns;
            (cooldowns.of(&url), cooldowns.of_optional(&url))
        });
        let early = self.sidecar_hints.sha256_likely_missing(&origin, path)
            && match &cooldowns {
                Some((cooldown, optional_cooldown)) => {
                    cooldown.ready().await.is_ok() && optional_cooldown.is_clear()
                }
                None => false,
            };
        let mut sha1_early =
            early.then(|| Box::pin(admitted(true, optional(request(HashAlgorithm::Sha1)))));
        let mut sha1_done = None;
        let sha256 = match (sha1_early.as_mut(), late) {
            (Some(early), None) => {
                let sha256 = Box::pin(admitted(true, request(HashAlgorithm::Sha256)));
                match futures::future::select(sha256, early).await {
                    Either::Left((result, _)) => result,
                    Either::Right((sha1, sha256)) => {
                        sha1_done = Some(sha1);
                        sha256.await
                    }
                }
            }
            // The `.sha256` request moves to its own task, to outlive the
            // read, once the `.sha1` has matched the bytes.
            (Some(early), Some((arrived, late))) => {
                let mut sha256 = Box::pin(admitted(true, self.sha256_request(route, path)));
                match futures::future::select(&mut sha256, early).await {
                    Either::Left((result, _)) => result,
                    Either::Right((sha1, _)) => {
                        let vouched = (sha1.0.as_ref().ok())
                            .and_then(|text| parse_checksum(text, HashAlgorithm::Sha1));
                        sha1_done = Some(sha1);
                        match vouched {
                            None => sha256.await,
                            Some(vouched) => {
                                let matched = std::pin::pin!(arrived_as(arrived, vouched.clone()));
                                match futures::future::select(&mut sha256, matched).await {
                                    Either::Left((result, _)) => result,
                                    Either::Right((false, _)) => sha256.await,
                                    Either::Right((true, _)) => {
                                        *late = Some(LateSha256 {
                                            answer: Spawned(tokio::spawn(sha256)),
                                            hints: self.sidecar_hints.clone(),
                                            origin: origin.clone(),
                                            path: path.to_string(),
                                            sha1: (cooldowns.clone())
                                                .zip(repo.url_for_path(&sha1_path).ok())
                                                .map(|((cooldown, _), url)| {
                                                    let refusers = &self.fetch.refusers;
                                                    (cooldown, Arc::clone(refusers), url)
                                                }),
                                        });
                                        return Ok(Some(vouched));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (None, _) => request(HashAlgorithm::Sha256).await,
        };
        self.sidecar_hints
            .note_sha256_answer(&origin, path, &sha256);
        // The first failure other than a 404 is reported when no sidecar
        // is usable, rather than a generic missing checksum.
        let mut first_err = None;
        let sha256 = checksum_outcome(path, HashAlgorithm::Sha256, sha256, &mut first_err);
        if let Some(outcome) = sha256 {
            return outcome;
        }
        // Now the `.sha1` is needed, and the early one stands in for one
        // asked for now: a server refused now refuses it unsent.
        let refused =
            (cooldowns.as_ref()).is_some_and(|(cooldown, _)| cooldown.refusal().is_some());
        let sha1 = match (sha1_done, sha1_early) {
            _ if refused => None,
            (Some(done), _) => Some(done),
            (None, Some(early)) => Some(early.await),
            (None, None) => None,
        };
        let sha1_url = repo.url_for_path(&sha1_path).ok();
        let sha1 = match needed_sha1(sha1, &self.fetch, sha1_url.as_ref()) {
            Some(sha1) => sha1,
            None => request(HashAlgorithm::Sha1).await,
        };
        let mut outcome = checksum_outcome(path, HashAlgorithm::Sha1, sha1, &mut first_err);
        if outcome.is_none() {
            let md5 = request(HashAlgorithm::Md5).await;
            outcome = checksum_outcome(path, HashAlgorithm::Md5, md5, &mut first_err);
        }
        if let Some(Ok(Some(checksum))) = &outcome {
            warnings.push(weak_hash(path, checksum.algorithm()));
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
            // Only the 404 an online run kept proves a POM missing; the
            // lock's word does not.
            if self.lock_missing_poms.contains(path) {
                return Err(match self.proven_absent(route, path).await {
                    true => RepoError::NotFound(path.into()),
                    false => RepoError::UnprovenMissingPom(path.to_string()),
                });
            }
            return Err(RepoError::OfflineNotCached(path.to_string()));
        }
        let url = repo.url_for_path(path)?;

        let fetched = fetch_bytes(
            self.transport.client_for(&url)?.as_ref(),
            &url,
            Some(&repo.base_url()?),
            route.auth()?,
            &self.fetch,
            self.progress.as_ref(),
        )
        .await;
        self.sidecar_hints.note_file(&repo.url, &fetched);
        fetched
    }

    fn sha256_request(
        &self,
        route: &Route<'_>,
        path: &str,
    ) -> impl Future<Output = Result<String>> + Send + 'static {
        let repo = &route.endpoint;
        let request = (|| {
            let url = repo.url_for_path(&format!("{path}.{}", HashAlgorithm::Sha256.as_str()))?;
            let client = self.transport.client_for(&url)?.into_owned();
            Ok::<_, RepoError>((client, url, repo.base_url()?, route.auth()?.cloned()))
        })();
        let mut config = self.fetch.clone();
        if self.late_checks.is_some() {
            config.progress = Some(Arc::new(LateProgress {
                inner: config.progress.take(),
                family: self.late_family.clone(),
            }));
        }
        async move {
            let (client, url, root, auth) = request?;
            fetch_text(&client, &url, Some(&root), auth.as_ref(), &config).await
        }
    }
}

/// The SHA-1 of a file's bytes, once they have arrived.
pub(super) type ArrivedSha1 = tokio::sync::watch::Receiver<Option<Digest>>;

/// Whether the bytes that arrive have the SHA-1 `sha1`; false when none do.
async fn arrived_as(mut arrived: ArrivedSha1, sha1: Digest) -> bool {
    let arrived = arrived.wait_for(Option::is_some).await;
    arrived.is_ok_and(|arrived| *arrived == Some(sha1))
}

/// A task that is cancelled when dropped.
pub(super) struct Spawned<T>(tokio::task::JoinHandle<T>);

impl<T> Future for Spawned<T> {
    type Output = std::result::Result<T, tokio::task::JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}

impl<T> Drop for Spawned<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The output of a task that ran a request.
pub(super) fn joined<T>(task: std::result::Result<Result<T>, tokio::task::JoinError>) -> Result<T> {
    task.unwrap_or_else(|err| Err(RepoError::Internal(format!("request task failed: {err}"))))
}

/// The answer a needed `.sha1` takes from the early one, or `None` when it
/// is asked for now: when it was not sent, or was refused for a time that is
/// over, since one asked for now would meet the server's refusal afresh. A
/// refusal still in force counts from when it came, for every request.
pub(super) fn needed_sha1(
    early: Option<(Result<String>, OptionalAnswer)>,
    fetch: &FetchConfig,
    url: Option<&url::Url>,
) -> Option<Result<String>> {
    match early? {
        (sha1, OptionalAnswer::Other) => Some(sha1),
        (_, OptionalAnswer::Unsent) => None,
        (
            sha1,
            OptionalAnswer::Refused {
                status,
                retry_after,
                answered,
            },
        ) => {
            let over = (answered.checked_add(retry_after))
                .is_some_and(|until| until <= tokio::time::Instant::now());
            if over {
                return None;
            }
            // Noted first, so that a request the refusal keeps unsent finds
            // the answer.
            if let Some(url) = url {
                fetch.refusers.note(url, status, retry_after, answered);
                (fetch.cooldowns.of(url)).refuse_from(status, retry_after, answered);
            }
            Some(sha1)
        }
    }
}

/// The `.sha256` request a probe left running once the `.sha1` had matched
/// the bytes.
pub(super) struct LateSha256 {
    answer: Spawned<Result<String>>,
    hints: SidecarHints,
    origin: String,
    path: String,
    /// The cooldown of the server and the URL of the `.sha1` that vouched,
    /// which stood in for one asked for once the `.sha256` answered.
    sha1: Option<(Arc<rv_http::retry::Cooldown>, Arc<Refusers>, url::Url)>,
}

impl LateSha256 {
    /// Check `bytes`, which match the `.sha1`, in a task of its own, as the
    /// probe would have had it waited for the `.sha256`: it fails as the
    /// probe would have, such as on another SHA-256, and otherwise says
    /// whether the `.sha1` alone vouched for them. `failed` runs before a
    /// failure is seen, and when the task is cancelled. The task is not
    /// cancelled with the check, so every read that shares the check gets
    /// its answer; it is cancelled once `checks` and every other client's
    /// checks that rely on it are dropped.
    pub(super) fn spawn(
        self,
        bytes: Bytes,
        failed: impl FnOnce() + Send + 'static,
        checks: &LateChecks,
    ) -> LateCheck {
        let path: Arc<str> = Arc::from(self.path.as_str());
        let on_failure = OnFailure(Some(Box::new(failed)));
        let task = tokio::spawn(async move {
            let mut on_failure = on_failure;
            let answer = joined(self.answer.await);
            self.hints
                .note_sha256_answer(&self.origin, &self.path, &answer);
            let mut first_err = None;
            let outcome =
                match checksum_outcome(&self.path, HashAlgorithm::Sha256, answer, &mut first_err) {
                    Some(Ok(Some(sha256))) => {
                        verify_checksum(&bytes, &sha256, &self.path).map(|()| false)
                    }
                    Some(Err(err)) => Err(err),
                    // A `.sha1` asked for now would be refused unsent, and
                    // the probe would fail as it does when the `.sha256`
                    // answers first.
                    Some(Ok(None)) | None => match &self.sha1 {
                        Some((cooldown, refusers, url)) => match cooldown.refusal() {
                            Some((status, retry_after)) => Err(first_err
                                .filter(RepoError::is_transient)
                                .unwrap_or_else(|| refusers.refused(url, status, retry_after))),
                            None => Ok(true),
                        },
                        None => Ok(true),
                    },
                };
            if outcome.is_ok() {
                on_failure.0 = None;
            }
            drop(on_failure);
            outcome.map_err(Arc::new)
        });
        let owner = Arc::new(Ownership(task.abort_handle()));
        let check = LateCheck {
            path,
            owner: Arc::downgrade(&owner),
            outcome: futures::FutureExt::shared(Box::pin(joined_check(task)) as LateFuture),
        };
        checks.start(check.clone(), owner);
        check
    }
}

/// The outcome of a check's task.
async fn joined_check(task: tokio::task::JoinHandle<LateOutcome>) -> LateOutcome {
    task.await.unwrap_or_else(|err| {
        Err(Arc::new(RepoError::Internal(format!(
            "checksum task failed: {err}"
        ))))
    })
}

/// Runs its function when dropped unless taken: when a check fails, or
/// when its task is cancelled, even before it started.
struct OnFailure(Option<Box<dyn FnOnce() + Send>>);

impl Drop for OnFailure {
    fn drop(&mut self) {
        if let Some(failed) = self.0.take() {
            failed();
        }
    }
}

/// Cancels the task of a check once no client's checks hold it.
pub(super) struct Ownership(tokio::task::AbortHandle);

impl Drop for Ownership {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type LateFuture = std::pin::Pin<Box<dyn Future<Output = LateOutcome> + Send>>;

/// Whether a late check found the file vouched for by its `.sha1` alone,
/// or the error its read would have failed with, shared by every read of
/// the check; see [`unshared`].
pub(super) type LateOutcome = std::result::Result<bool, Arc<RepoError>>;

/// The `.sha256` check of a POM read on its `.sha1`, shared by every read
/// of those bytes.
#[derive(Clone)]
pub(super) struct LateCheck {
    path: Arc<str>,
    /// The task that asks for the `.sha256`, which a client relying on the
    /// check keeps from being cancelled.
    owner: std::sync::Weak<Ownership>,
    outcome: futures::future::Shared<LateFuture>,
}

impl LateCheck {
    /// This check, followed in a task of its own by `then` once it has
    /// passed; the outcome is still the check's.
    pub(super) fn then(&self, then: impl Future<Output = ()> + Send + 'static) -> LateCheck {
        let check = self.outcome.clone();
        let task = tokio::spawn(async move {
            let outcome = check.await;
            if outcome.is_ok() {
                then.await;
            }
            outcome
        });
        LateCheck {
            path: Arc::clone(&self.path),
            owner: self.owner.clone(),
            outcome: futures::FutureExt::shared(Box::pin(joined_check(task)) as LateFuture),
        }
    }

    /// Whether `other` is this check.
    fn is(&self, other: &LateCheck) -> bool {
        self.outcome.ptr_eq(&other.outcome)
    }

    /// Wait for the check; `Ok(true)` when the `.sha1` alone vouched for
    /// the bytes.
    pub(super) async fn outcome(&self) -> LateOutcome {
        self.outcome.clone().await
    }

    /// The warning for bytes the `.sha1` alone vouched for.
    pub(super) fn weak_hash(&self) -> impl FnOnce() + Send + 'static {
        weak_hash(&self.path, HashAlgorithm::Sha1)
    }
}

/// The error a shared check failed with, for one read: a copy where the
/// error can be copied, so the read can match it, and the shared error
/// otherwise, such as the error of a transport.
pub(super) fn unshared(err: Arc<RepoError>) -> RepoError {
    match &*err {
        RepoError::ChecksumMismatch {
            subject,
            artifact,
            expected,
            actual,
            check,
        } => RepoError::ChecksumMismatch {
            subject: subject.clone(),
            artifact: artifact.clone(),
            expected: expected.clone(),
            actual: actual.clone(),
            check: *check,
        },
        RepoError::Unauthorized { status, url, sent } => RepoError::Unauthorized {
            status: *status,
            url: url.clone(),
            sent: sent.clone(),
        },
        RepoError::HttpStatus {
            status,
            url,
            retry_after,
        } => RepoError::HttpStatus {
            status: *status,
            url: url.clone(),
            retry_after: *retry_after,
        },
        RepoError::AuthSetup(reason) => RepoError::AuthSetup(reason.clone()),
        _ => RepoError::Shared(err),
    }
}

/// The warning for a file checked against its `.sha1` or `.md5`.
fn weak_hash(path: &str, algorithm: HashAlgorithm) -> impl FnOnce() + Send + 'static {
    // `sec_code` is mirrored into the JSON envelope's warnings, which
    // `--json` runs still show.
    let path = path.to_string();
    let name = match algorithm {
        HashAlgorithm::Md5 => "MD5",
        _ => "SHA-1",
    };
    move || {
        warn!(
            sec_code = "WEAK_HASH_FALLBACK",
            path,
            "falling back to {name} checksum (weak hash algorithm); \
             repository should provide SHA-256 checksums"
        );
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
        // A 200 body whose first token is no digest, such as an HTML "not
        // found" page, is no sidecar: the lock pin or the checksum policy
        // decides.
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

/// What the answers so far say about where sidecars are missing, shared by
/// a client's clones. They decide only when a sidecar request starts, never
/// which sidecar is asked for or which one decides, and each origin's answers
/// count only for that origin.
#[derive(Clone, Default)]
pub(super) struct SidecarHints(Arc<Mutex<Hints>>);

#[derive(Default)]
struct Hints {
    /// Origins that have answered 404 for a `.sha256` sidecar.
    sha256_gaps: HashSet<String>,
    /// Whether the last `.sha256` asked for under an origin, groupId and
    /// version was served.
    sha256_by_release: HashMap<(String, String), bool>,
    /// How many file requests, sidecars aside, each origin has answered
    /// with the file and with a miss.
    files: HashMap<String, (u64, u64)>,
}

/// The most releases [`Hints::sha256_by_release`] remembers.
const MAX_RELEASES: usize = 100_000;

impl SidecarHints {
    fn hints(&self) -> std::sync::MutexGuard<'_, Hints> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn sha256_likely_missing(&self, origin: &str, path: &str) -> bool {
        let hints = self.hints();
        match release_key(path).and_then(|release| {
            (hints.sha256_by_release)
                .get(&(origin.to_string(), release))
                .copied()
        }) {
            Some(served) => !served,
            None => hints.sha256_gaps.contains(origin),
        }
    }

    /// Record the answer of `origin` to a request for the `.sha256` of
    /// `path`.
    fn note_sha256_answer(&self, origin: &str, path: &str, answer: &Result<String>) {
        let served = match answer {
            Ok(text) => parse_checksum(text, HashAlgorithm::Sha256).is_some(),
            Err(err) if sidecar_absent(err) => false,
            Err(_) => return,
        };
        let mut hints = self.hints();
        if !served {
            hints.sha256_gaps.insert(origin.to_string());
        }
        if let Some(release) = release_key(path)
            && (hints.sha256_by_release.len() < MAX_RELEASES
                || hints
                    .sha256_by_release
                    .contains_key(&(origin.to_string(), release.clone())))
        {
            hints
                .sha256_by_release
                .insert((origin.to_string(), release), served);
        }
    }

    /// Record the answer of `origin` to a request for a file, sidecars
    /// aside: the file, or a miss as [`sidecar_absent`] counts one.
    pub(super) fn note_file<T>(&self, origin: &str, answer: &Result<T>) {
        let served = match answer {
            Ok(_) => true,
            Err(err) if sidecar_absent(err) => false,
            Err(_) => return,
        };
        let mut hints = self.hints();
        let (hits, misses) = hints.files.entry(origin.to_string()).or_default();
        if served {
            *hits += 1;
        } else {
            *misses += 1;
        }
    }

    /// Whether a file of `origin` is asked for before its sidecar rather
    /// than together with it: when the origin has answered more file
    /// requests with a miss than with the file, as a repository listed
    /// before the one that serves most files does. A missing file has no
    /// sidecar, so the sidecar requests a miss would cancel are not sent.
    pub(super) fn file_first(&self, origin: &str) -> bool {
        self.hints()
            .files
            .get(origin)
            .is_some_and(|(hits, misses)| misses > hits)
    }
}

/// The groupId and version directories of the file at `path`, without its
/// artifactId: the files of one release share it. `None` for a path that is
/// not a file in a version directory, such as `maven-metadata.xml` of an
/// artifact.
fn release_key(path: &str) -> Option<String> {
    let (directory, file) = path.rsplit_once('/')?;
    let (artifact_directory, version) = directory.rsplit_once('/')?;
    let (group, artifact) = artifact_directory.rsplit_once('/')?;
    (file.starts_with(artifact) && !file.starts_with("maven-metadata"))
        .then(|| format!("{group}/{version}"))
}

/// What [`RepoClient::settle_checksums`] waits for: the checks of the POMs
/// read without waiting for their `.sha256`, in the order of the reads, and
/// every check the client started. Each stays until a settlement has its
/// outcome, so one that is cancelled leaves the rest to the next.
#[derive(Default)]
pub(super) struct LateChecks {
    /// Each check a read relied on, and whether its read logs the
    /// weak-hash warning.
    relied_on: Mutex<std::collections::VecDeque<(LateCheck, bool)>>,
    /// Each check the client started, also of a POM only prefetched.
    started: Mutex<Vec<LateCheck>>,
    /// The tasks of the checks the client started or relies on.
    owned: Mutex<Vec<Arc<Ownership>>>,
    /// The warnings and the first error of the checks settled so far.
    settled: Mutex<Settled>,
    failed: std::sync::atomic::AtomicBool,
    activity: Mutex<Activity>,
}

#[derive(Default)]
struct Settled {
    warnings: DeferredWarnings,
    failure: Option<Arc<RepoError>>,
}

/// Who is told that a check moved, and until when its request is known to
/// wait without a word.
#[derive(Default)]
struct Activity {
    note: Option<Arc<dyn Fn(std::time::Duration) + Send + Sync>>,
    quiet_until: Option<tokio::time::Instant>,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl LateChecks {
    fn start(&self, check: LateCheck, owner: Arc<Ownership>) {
        locked(&self.started).push(check);
        locked(&self.owned).push(owner);
    }

    pub(super) fn rely_on(&self, check: LateCheck, warns: bool) {
        if let Some(owner) = check.owner.upgrade() {
            locked(&self.owned).push(owner);
        }
        locked(&self.relied_on).push_back((check, warns));
    }

    pub(super) fn failed(&self) -> bool {
        self.failed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Tell `note` of every move of a check from now on, with how long its
    /// request may then be quiet, as while it waits to be retried.
    pub(super) fn report_to(&self, note: Arc<dyn Fn(std::time::Duration) + Send + Sync>) {
        let quiet = {
            let mut activity = locked(&self.activity);
            activity.note = Some(Arc::clone(&note));
            (activity.quiet_until).map_or(std::time::Duration::ZERO, |until| {
                until.saturating_duration_since(tokio::time::Instant::now())
            })
        };
        note(quiet);
    }

    /// A check moved; its request may then be quiet for `quiet`.
    fn moved(&self, quiet: std::time::Duration) {
        let note = {
            let mut activity = locked(&self.activity);
            let until = tokio::time::Instant::now() + quiet;
            if activity
                .quiet_until
                .is_none_or(|quiet_until| quiet_until < until)
            {
                activity.quiet_until = Some(until);
            }
            activity.note.clone()
        };
        if let Some(note) = note {
            note(quiet);
        }
    }

    /// Wait for each check a read relied on, keeping their warnings, and
    /// return the first failure among them, in the order of the reads.
    pub(super) async fn settle_relied_on(&self) -> Option<Arc<RepoError>> {
        loop {
            let next = locked(&self.relied_on).front().cloned();
            let Some((check, warns)) = next else {
                break;
            };
            let outcome = check.outcome().await;
            self.moved(std::time::Duration::ZERO);
            let mut settled = locked(&self.settled);
            let mut relied_on = locked(&self.relied_on);
            // Another settlement may have taken this one meanwhile.
            let Some(at) = relied_on.iter().position(|(other, _)| other.is(&check)) else {
                continue;
            };
            relied_on.remove(at);
            match outcome {
                Ok(true) if warns => settled.warnings.push(check.weak_hash()),
                Ok(_) => {}
                Err(err) => {
                    settled.failure.get_or_insert(err);
                }
            }
        }
        locked(&self.settled).failure.clone()
    }

    /// [`Self::settle_relied_on`], then wait for every other check the
    /// client started, whose outcome nothing relies on, and log the
    /// warnings.
    pub(super) async fn settle(&self) -> Option<Arc<RepoError>> {
        loop {
            self.settle_relied_on().await;
            let next = locked(&self.started).first().cloned();
            let Some(check) = next else {
                break;
            };
            let _ = check.outcome().await;
            self.moved(std::time::Duration::ZERO);
            locked(&self.started).retain(|other| !other.is(&check));
        }
        let (warnings, failure) = {
            let mut settled = locked(&self.settled);
            (
                std::mem::take(&mut settled.warnings),
                settled.failure.clone(),
            )
        };
        warnings.emit();
        if failure.is_some() {
            self.failed
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        failure
    }
}

/// The late checks of the clones of one client, which share its held
/// POMs: a client may rely on a check another one started, so each is told
/// when any of their checks moves.
#[derive(Clone, Default)]
pub(super) struct LateFamily(Arc<Mutex<Vec<std::sync::Weak<LateChecks>>>>);

impl LateFamily {
    /// Add `checks`, which hear of a wait for a retry already running.
    pub(super) fn join(&self, checks: &Arc<LateChecks>) {
        let mut family = locked(&self.0);
        family.retain(|member| member.strong_count() > 0);
        let quiet_until = (family.iter())
            .filter_map(std::sync::Weak::upgrade)
            .filter_map(|member| locked(&member.activity).quiet_until)
            .max();
        locked(&checks.activity).quiet_until = quiet_until;
        family.push(Arc::downgrade(checks));
    }

    fn moved(&self, quiet: std::time::Duration) {
        let members: Vec<_> = (locked(&self.0).iter())
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        for member in members {
            member.moved(quiet);
        }
    }
}

/// The progress of a `.sha256` request left running, which also tells the
/// [`LateFamily`] that the check moved.
struct LateProgress {
    inner: Option<Arc<dyn crate::fetch::FetchProgress>>,
    family: LateFamily,
}

impl LateProgress {
    fn moved(&self, quiet: std::time::Duration) {
        self.family.moved(quiet);
    }
}

impl crate::fetch::FetchProgress for LateProgress {
    fn on_start(&self, url: &str, total: Option<u64>) {
        if let Some(inner) = &self.inner {
            inner.on_start(url, total);
        }
        self.moved(std::time::Duration::ZERO);
    }

    fn on_chunk(&self, bytes: usize) {
        if let Some(inner) = &self.inner {
            inner.on_chunk(bytes);
        }
    }

    fn on_finish(&self, url: &str, total: Option<usize>) {
        if let Some(inner) = &self.inner {
            inner.on_finish(url, total);
        }
        self.moved(std::time::Duration::ZERO);
    }

    fn on_retry(
        &self,
        url: &str,
        error: &RepoError,
        wait: std::time::Duration,
        attempt: usize,
        attempts: usize,
    ) {
        if let Some(inner) = &self.inner {
            inner.on_retry(url, error, wait, attempt, attempts);
        }
        self.moved(wait);
    }
}
