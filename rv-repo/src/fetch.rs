use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;
use backon::ExponentialBuilder;
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use sha1::Sha1;
use tokio_stream::StreamExt;
use url::Url;

use crate::auth::Auth;
use crate::error::{RepoError, Result, io_error_with_context};
use rv_config::{ArtifactKey, BlobId};
use rv_store::{BlobOrigin, Store};

/// Internal classification used by `execute_retry` to drive backon's
/// `Retryable::retry`.
///
/// `Transient { retry_after }` propagates the 429 `Retry-After` value to
/// `execute_retry`, which feeds it into backon's `adjust` callback. backon
/// has no first-class slot for a server-supplied delay, so we inject it
/// there.
#[derive(Debug)]
enum RetryError {
    Permanent(RepoError),
    Transient {
        err: RepoError,
        retry_after: Option<Duration>,
    },
}

impl RetryError {
    fn permanent(err: RepoError) -> Self {
        RetryError::Permanent(err)
    }

    fn transient(err: RepoError) -> Self {
        RetryError::Transient {
            err,
            retry_after: None,
        }
    }

    fn into_inner(self) -> RepoError {
        match self {
            RetryError::Permanent(err) => err,
            RetryError::Transient { err, .. } => err,
        }
    }

    fn is_transient(&self) -> bool {
        matches!(self, RetryError::Transient { .. })
    }
}

/// Redacts sensitive components from a URL for safe logging.
/// Strips query parameters (which may contain presigned tokens) and
/// userinfo (which may contain credentials).
pub fn redact_url(url: &Url) -> String {
    redacted_url(url).to_string()
}

/// Url-typed redaction so it can be re-attached to a reqwest error via
/// `with_url` without re-leaking `user:pass@` from the original.
fn redacted_url(url: &Url) -> Url {
    let mut redacted = url.clone();
    redacted.set_query(None);
    redacted.set_fragment(None);
    if redacted.password().is_some() || !redacted.username().is_empty() {
        let _ = redacted.set_username("");
        let _ = redacted.set_password(None);
    }
    redacted
}

#[derive(Debug, Clone)]
pub struct FetchConfig {
    pub retries: usize,
    pub timeout: Duration,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            retries: 2,
            timeout: Duration::from_secs(30),
        }
    }
}

pub trait FetchProgress: Send + Sync {
    fn on_start(&self, _url: &Url, _total: Option<u64>) {}
    fn on_chunk(&self, _bytes: usize) {}
    fn on_finish(&self, _url: &Url, _total: usize) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr)]
#[strum(serialize_all = "lowercase")]
pub enum ChecksumAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    pub algorithm: ChecksumAlgorithm,
    pub value: String,
}

const MAX_METADATA_SIZE: u64 = 20 * 1024 * 1024; // 20MB
const MAX_ARTIFACT_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB
/// Upper bound on an honoured `Retry-After`. A hostile or misconfigured
/// server can send `Retry-After: 999999999` (≈31 years); without a clamp a
/// single attempt would sleep effectively forever. Two minutes is well above
/// any legitimate rate-limit window while keeping the worst case bounded.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(120);
/// Checksum sidecars (`.sha1`/`.sha256`) carry a single hex token plus an
/// optional filename, a few dozen bytes in practice. `fetch_text` is only
/// ever used to pull these sidecars, so it gets a tight dedicated cap rather
/// than sharing the 20MB metadata limit; this bounds buffering and the
/// whitespace scan in `extract_hex_token` against a hostile or oversized
/// sidecar.
const MAX_CHECKSUM_SIZE: u64 = 4 * 1024; // 4KB

/// Headerless wrapper kept for the redaction-coverage tests; production
/// code calls [`classify_response_status_with_headers`] directly so the
/// `Retry-After` value on a 429 reaches the backoff layer.
#[cfg(test)]
fn classify_response_status(status: StatusCode, url: &Url) -> std::result::Result<(), RetryError> {
    classify_response_status_with_headers(status, url, None)
}

/// Classifies an HTTP status into permanent/transient; on 429/503 the
/// `Retry-After` header (integer seconds or RFC 2822 date, per RFC 7231 §7.1.3)
/// is parsed and attached so the backoff layer sleeps at least that long.
fn classify_response_status_with_headers(
    status: StatusCode,
    url: &Url,
    headers: Option<&HeaderMap>,
) -> std::result::Result<(), RetryError> {
    if status.is_success() {
        return Ok(());
    }

    let display_url = redact_url(url);
    if status == StatusCode::NOT_FOUND {
        return Err(RetryError::permanent(RepoError::NotFound(display_url)));
    }

    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(RetryError::permanent(RepoError::AuthError(format!(
            "{status} for {display_url}"
        ))));
    }

    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        return Err(RetryError::permanent(RepoError::AuthError(format!(
            "407 Proxy Authentication Required for {display_url} - check proxy configuration (proxy username/password/token in rv.toml or settings.xml)"
        ))));
    }

    if matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    ) {
        let err = RepoError::UnexpectedResponse(format!("{status} for {display_url}"));
        let retry_after = headers
            .and_then(|h| h.get(RETRY_AFTER))
            .and_then(parse_retry_after);
        return Err(RetryError::Transient { err, retry_after });
    }

    Err(RetryError::permanent(RepoError::UnexpectedResponse(
        format!("{status} for {display_url}"),
    )))
}

/// Parse RFC 7231 §7.1.3 `Retry-After`: delta-seconds or HTTP-date. Past
/// dates clamp to zero; unparseable values yield `None` (caller falls back).
fn parse_retry_after(value: &HeaderValue) -> Option<Duration> {
    let text = value.to_str().ok()?.trim();
    if let Ok(secs) = text.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let target = chrono::DateTime::parse_from_rfc2822(text).ok()?;
    let now = chrono::Utc::now();
    let delta = target.with_timezone(&chrono::Utc) - now;
    delta.to_std().ok().or(Some(Duration::ZERO))
}

async fn execute_retry<F, Fut, T>(config: &FetchConfig, op: F) -> Result<T>
where
    F: FnMut() -> Fut + backon::Retryable<ExponentialBuilder, T, RetryError, Fut, F>,
    Fut: std::future::Future<Output = std::result::Result<T, RetryError>>,
{
    // 500ms min matches the `backoff` crate's old default; the ±50% jitter
    // window widens to ±250ms, breaking up the thundering herd when many
    // fan-out fetches all hit a 503 at the same instant.
    //
    // `with_max_times(retries)` yields exactly `retries` sleep durations,
    // so backon runs 1 initial + `retries` retried calls, matching the
    // contract `execute_retry_runs_exactly_initial_plus_retries` enforces.
    let total_budget = config.timeout * (config.retries as u32 + 1) + Duration::from_secs(5);
    let backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(30))
        .with_factor(2.0)
        .with_max_times(config.retries)
        .with_total_delay(Some(total_budget))
        .with_jitter();

    op.retry(backoff)
        .when(RetryError::is_transient)
        // 429 `Retry-After` has no first-class slot in backon's
        // `ExponentialBuilder`; the `adjust` hook is how we honour the
        // server-supplied delay. Returning `Some(d)` overrides the
        // exponential sleep for that one attempt; the next failure falls
        // back to the regular schedule.
        //
        // CRITICAL: only override while `dur` is `Some`. backon yields
        // `dur == None` precisely when the retry budget is exhausted
        // (`max_times` reached or `with_total_delay` spent), and that `None`
        // is the authoritative "stop now" signal. Returning `Some(..)`
        // there would resurrect the loop, so a server that answers every
        // attempt with 429/503 + `Retry-After` would retry forever,
        // bypassing `network.retries` entirely. We also clamp the
        // server-supplied value so an absurd `Retry-After` can't pin one
        // attempt for minutes/years.
        .adjust(|err, dur| match (err, dur) {
            (
                RetryError::Transient {
                    retry_after: Some(d),
                    ..
                },
                Some(_),
            ) => Some((*d).min(MAX_RETRY_AFTER)),
            (_, dur) => dur,
        })
        .await
        .map_err(RetryError::into_inner)
}

pub(crate) async fn fetch_bytes(
    client: &Client,
    url: &Url,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&dyn FetchProgress>,
) -> Result<Bytes> {
    tracing::debug!(url = %redact_url(url), method = "GET", "HTTP request start");
    execute_retry(config, || async {
        let mut request = client.get(url.as_str());
        request = request.timeout(config.timeout);

        if let Some(auth) = auth {
            request = auth.apply(request);
        }

        let response = request.send().await.map_err(|e| {
            // Strip and reattach a redacted URL so the rendered error never
            // exposes `user:pass@host` or query tokens through Debug/Display.
            let err = e.without_url().with_url(redacted_url(url));
            if err.is_timeout() || err.is_connect() {
                RetryError::transient(RepoError::Http(err))
            } else {
                RetryError::permanent(RepoError::Http(err))
            }
        })?;

        let status = response.status();
        let content_length = response.content_length();
        tracing::debug!(url = %redact_url(url), status = %status, content_length = ?content_length, "HTTP response");
        classify_response_status_with_headers(status, url, Some(response.headers()))?;

        let total = content_length;
        if let Some(len) = total
            && len > MAX_METADATA_SIZE {
                return Err(RetryError::permanent(RepoError::Io(
                    std::io::Error::other(
                        format!(
                            "metadata too large: {} bytes (limit {})",
                            len, MAX_METADATA_SIZE
                        ),
                    ),
                )));
            }

        if let Some(progress) = progress {
            progress.on_start(url, total);
        }

        // Get content length hint, but cap it to prevent unbounded allocation
        let capacity = total
            .map(|len| len.min(MAX_METADATA_SIZE) as usize)
            .unwrap_or(4096);
        let mut bytes = Vec::with_capacity(capacity);
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    // Check BEFORE extending to prevent allocation beyond limit.
                    // Compute the sum in u64 so a hostile chunk on a 32-bit
                    // target cannot wrap the bound check.
                    if (bytes.len() as u64).saturating_add(chunk.len() as u64) > MAX_METADATA_SIZE {
                        return Err(RetryError::permanent(RepoError::Io(
                            std::io::Error::other(
                                format!("metadata too large (limit {} bytes)", MAX_METADATA_SIZE),
                            ),
                        )));
                    }
                    bytes.extend_from_slice(&chunk);

                    if let Some(progress) = progress {
                        progress.on_chunk(chunk.len());
                    }
                }
                Err(e) => {
                    let err = e.without_url().with_url(redacted_url(url));
                    return Err(RetryError::transient(RepoError::Http(err)));
                }
            }
        }

        if let Some(progress) = progress {
            progress.on_finish(url, bytes.len());
        }

        Ok(Bytes::from(bytes))
    })
    .await
}

/// Convert a non-success status code to a RepoError (non-backoff version).
/// Used only by the redaction-coverage tests; production code routes through
/// `classify_response_status_with_headers`.
#[cfg(test)]
fn classify_status_to_error(status: StatusCode, url: &Url) -> RepoError {
    let display_url = redact_url(url);
    if status == StatusCode::NOT_FOUND {
        RepoError::NotFound(display_url)
    } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        RepoError::AuthError(format!("{status} for {display_url}"))
    } else {
        RepoError::UnexpectedResponse(format!("{status} for {display_url}"))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_stream_to_store_verified(
    client: &Client,
    url: &Url,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&dyn FetchProgress>,
    store: &Store,
    expected_checksum: Option<&Checksum>,
) -> Result<BlobId> {
    let path = url.path().to_string();
    tracing::debug!(url = %redact_url(url), method = "GET", "HTTP stream request start");
    execute_retry(config, || async {
        let mut request = client.get(url.as_str()).timeout(config.timeout);
        if let Some(auth) = auth {
            request = auth.apply(request);
        }

        let response = request.send().await.map_err(|e| {
            // Strip and reattach a redacted URL so the rendered error never
            // exposes `user:pass@host` or query tokens through Debug/Display.
            let err = e.without_url().with_url(redacted_url(url));
            if err.is_timeout() || err.is_connect() {
                RetryError::transient(RepoError::Http(err))
            } else {
                RetryError::permanent(RepoError::Http(err))
            }
        })?;

        let status = response.status();
        let content_length = response.content_length();
        tracing::debug!(url = %redact_url(url), status = %status, content_length = ?content_length, "HTTP stream response");
        classify_response_status_with_headers(status, url, Some(response.headers()))?;

        let total = content_length;
        if let Some(len) = total
            && len > MAX_ARTIFACT_SIZE {
                return Err(RetryError::permanent(RepoError::Io(
                    std::io::Error::other(
                        format!(
                            "artifact too large: {} bytes (limit {})",
                            len, MAX_ARTIFACT_SIZE
                        ),
                    ),
                )));
            }

        if let Some(progress) = progress {
            progress.on_start(url, total);
        }

        let bytes_read = std::sync::Arc::new(AtomicU64::new(0));
        let bytes_read_clone = bytes_read.clone();

        // Stream chunks through the store's put_stream, which writes to
        // a temp file incrementally (hashing as it goes) instead of buffering
        // the entire artifact in memory.
        let byte_stream = response.bytes_stream().map(move |chunk| match chunk {
            Ok(bytes) => {
                if bytes_read_clone.load(Ordering::Relaxed) + bytes.len() as u64 > MAX_ARTIFACT_SIZE {
                    return Err(std::io::Error::other("artifact too large"));
                }
                bytes_read_clone.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                Ok(bytes)
            }
            Err(e) => Err(std::io::Error::other(e)),
        });

        let boxed_stream: std::pin::Pin<Box<dyn futures_core::Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send>> =
            Box::pin(byte_stream);

        match store.put_stream_with_origin(boxed_stream).await {
            Ok((blob, origin)) => {
                if let Some(progress) = progress {
                    progress.on_finish(url, bytes_read.load(Ordering::Relaxed) as usize);
                }

                // Verify the sidecar checksum BEFORE considering the blob valid.
                // Re-hashing from disk is CPU-bound (SHA-256/SHA-1 over a JAR),
                // so push it to the blocking pool. The parent runtime stays
                // responsive for other in-flight fetches and timers.
                if let Some(checksum) = expected_checksum
                    && let Err(err) = verify_blob_checksum_offload(store, &blob, checksum, &path).await
                {
                    // Only remove the blob file if WE just created it. If
                    // `put_stream` deduplicated against a pre-existing blob,
                    // deleting it would corrupt every other artifact-key row
                    // pointing at the same content-addressed file.
                    //
                    // A bytes-identical response that fails the sidecar check
                    // also implies the *sidecar* (or lockfile pin) is the bad
                    // input, not the on-disk blob, another reason to keep it.
                    match origin {
                        BlobOrigin::Created => {
                            // KNOWN LIMITATION: `remove_file` runs without
                            // the StoreLock that serialises `prune_blobs`.
                            // The race window is narrow (we just persisted
                            // this blob) but a concurrent GC could have
                            // unlinked it first. The atomic
                            // `Store::adopt_blob_atomic` helper that would
                            // close this race lives in rv-store and is out
                            // of scope here.
                            let blob_path = store.get_path(&blob);
                            match tokio::fs::remove_file(&blob_path).await {
                                Ok(_) => {}
                                Err(remove_err)
                                    if remove_err.kind()
                                        == std::io::ErrorKind::NotFound =>
                                {
                                    tracing::warn!(
                                        sec_code = "GC_RACE",
                                        path = %blob_path.display(),
                                        "bad blob already gone (concurrent GC?) on checksum-mismatch cleanup"
                                    );
                                }
                                Err(remove_err) => {
                                    tracing::warn!(
                                        path = %blob_path.display(),
                                        error = %remove_err,
                                        "failed to remove bad blob after checksum mismatch"
                                    );
                                }
                            }
                        }
                        BlobOrigin::Existed => {
                            tracing::warn!(
                                blob = %blob,
                                path = %path,
                                "sidecar checksum mismatch on deduplicated blob; preserving \
                                 on-disk content because other artifact rows may reference it"
                            );
                        }
                    }

                    return Err(RetryError::permanent(err));
                }

                Ok(blob)
            }
            Err(err) => Err(RetryError::transient(RepoError::Store(err))),
        }
    })
    .await
}

/// Race-free counterpart to [`fetch_stream_to_store_verified`] that also
/// records the artifact-key → blob mapping under the same store lock as the
/// blob persist.
///
/// A two-step sequence (`fetch_stream_to_store_verified` then
/// `Store::add_artifact`) has a window between the persist and the index write
/// where a concurrent `Store::prune_blobs` sweep can observe a
/// freshly-persisted blob with no index row pointing at it and delete it (the
/// race documented on `Store::put_stream_and_index`). Funneling the
/// persist+index through `put_stream_and_index` closes that window because the
/// store lock is held across both operations.
///
/// Sidecar checksum verification happens *after* persist+index, but on a
/// mismatch the just-committed index row is removed (and a freshly Created
/// blob best-effort unlinked) before the error returns, so no key->blob
/// mapping ever durably points at unverified bytes. This matters for unpinned
/// companion POMs, whose `needs_download_unpinned` fast-path trusts any
/// present row without re-hashing; dropping the row forces the next sync to
/// re-fetch and re-verify.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_stream_to_store_and_index(
    client: &Client,
    url: &Url,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&dyn FetchProgress>,
    store: &Store,
    key: &ArtifactKey,
    expected_checksum: Option<&Checksum>,
) -> Result<BlobId> {
    let path = url.path().to_string();
    tracing::debug!(url = %redact_url(url), method = "GET", "HTTP stream+index request start");
    execute_retry(config, || async {
        let mut request = client.get(url.as_str()).timeout(config.timeout);
        if let Some(auth) = auth {
            request = auth.apply(request);
        }

        let response = request.send().await.map_err(|e| {
            // Strip and reattach a redacted URL so the rendered error never
            // exposes `user:pass@host` or query tokens through Debug/Display.
            let err = e.without_url().with_url(redacted_url(url));
            if err.is_timeout() || err.is_connect() {
                RetryError::transient(RepoError::Http(err))
            } else {
                RetryError::permanent(RepoError::Http(err))
            }
        })?;

        let status = response.status();
        let content_length = response.content_length();
        tracing::debug!(url = %redact_url(url), status = %status, content_length = ?content_length, "HTTP stream+index response");
        classify_response_status_with_headers(status, url, Some(response.headers()))?;

        let total = content_length;
        if let Some(len) = total
            && len > MAX_ARTIFACT_SIZE
        {
            return Err(RetryError::permanent(RepoError::Io(
                std::io::Error::other(format!(
                    "artifact too large: {} bytes (limit {})",
                    len, MAX_ARTIFACT_SIZE
                )),
            )));
        }

        if let Some(progress) = progress {
            progress.on_start(url, total);
        }

        let bytes_read = std::sync::Arc::new(AtomicU64::new(0));
        let bytes_read_clone = bytes_read.clone();

        let byte_stream = response.bytes_stream().map(move |chunk| match chunk {
            Ok(bytes) => {
                if bytes_read_clone.load(Ordering::Relaxed) + bytes.len() as u64
                    > MAX_ARTIFACT_SIZE
                {
                    return Err(std::io::Error::other("artifact too large"));
                }
                bytes_read_clone.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                Ok(bytes)
            }
            Err(e) => Err(std::io::Error::other(e)),
        });

        let boxed_stream: std::pin::Pin<
            Box<dyn futures_core::Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send>,
        > = Box::pin(byte_stream);

        match store.put_stream_and_index(key, boxed_stream).await {
            Ok((blob, origin)) => {
                if let Some(progress) = progress {
                    progress.on_finish(url, bytes_read.load(Ordering::Relaxed) as usize);
                }

                if let Some(checksum) = expected_checksum
                    && let Err(err) =
                        verify_blob_checksum_offload(store, &blob, checksum, &path).await
                {
                    // Drop the index row we just committed so a verification
                    // failure never leaves a key->blob mapping pointing at
                    // unverified bytes. Without this, an unpinned companion
                    // POM whose sidecar mismatched would be trusted forever:
                    // `needs_download_unpinned` treats any present row+file as
                    // good and does not re-hash. Removing the row forces the
                    // next sync to re-fetch and re-verify. The blob itself is
                    // left to GC (it may be shared); for a freshly Created
                    // blob we also best-effort unlink it.
                    if let Err(unindex_err) = store.remove_artifact(key).await {
                        tracing::warn!(
                            key = %key,
                            error = %unindex_err,
                            "failed to drop index row after checksum mismatch; \
                             next sync's pin re-hash will still repair it"
                        );
                    }

                    // KNOWN LIMITATION: the Created-blob unlink runs without
                    // the StoreLock that serialises `prune_blobs`; the row
                    // removal above is the durable repair, so this is only a
                    // best-effort cleanup of the just-written bytes.
                    //
                    // KNOWN LIMITATION: two further multi-process races exist
                    // in this repair flow beyond the prune race above.
                    // (1) `remove_artifact` deletes by key unconditionally,
                    //     so it can drop a row that a concurrent process just
                    //     verified and indexed for the same key against good
                    //     bytes.
                    // (2) the Created-blob unlink runs without the store
                    //     lock, so it can delete a blob a concurrent process
                    //     just indexed a fresh row against (same content
                    //     hash), leaving that row dangling.
                    // Both self-heal on the next sync: the file-stat fast
                    // paths treat a missing row, or a row whose blob file is
                    // gone, as "needs download" and re-fetch + re-verify.
                    if matches!(origin, BlobOrigin::Created) {
                        let blob_path = store.get_path(&blob);
                        match tokio::fs::remove_file(&blob_path).await {
                            Ok(_) => {}
                            Err(remove_err)
                                if remove_err.kind() == std::io::ErrorKind::NotFound =>
                            {
                                tracing::warn!(
                                    sec_code = "GC_RACE",
                                    path = %blob_path.display(),
                                    "bad blob already gone (concurrent GC?) on checksum-mismatch cleanup"
                                );
                            }
                            Err(remove_err) => {
                                tracing::warn!(
                                    path = %blob_path.display(),
                                    error = %remove_err,
                                    "failed to remove bad blob after checksum mismatch"
                                );
                            }
                        }
                    }

                    return Err(RetryError::permanent(err));
                }

                Ok(blob)
            }
            Err(err) => Err(RetryError::transient(RepoError::Store(err))),
        }
    })
    .await
}

/// Fetch a checksum sidecar (`.sha1`/`.sha256`) as trimmed UTF-8 text.
///
/// Buffering and the post-fetch whitespace scan are bounded by the small
/// [`MAX_CHECKSUM_SIZE`] cap rather than the 20MB metadata limit, since a
/// sidecar is only ever a single hex token plus an optional filename.
pub(crate) async fn fetch_text(
    client: &Client,
    url: &Url,
    auth: Option<&Auth>,
    config: &FetchConfig,
) -> Result<String> {
    tracing::debug!(url = %redact_url(url), method = "GET", "HTTP text request start");
    execute_retry(config, || async {
        let mut request = client.get(url.as_str());
        request = request.timeout(config.timeout);
        if let Some(auth) = auth {
            request = auth.apply(request);
        }

        let response = request.send().await.map_err(|e| {
            // Strip and reattach a redacted URL so the rendered error never
            // exposes `user:pass@host` or query tokens through Debug/Display.
            let err = e.without_url().with_url(redacted_url(url));
            if err.is_timeout() || err.is_connect() {
                RetryError::transient(RepoError::Http(err))
            } else {
                RetryError::permanent(RepoError::Http(err))
            }
        })?;

        let status = response.status();
        let content_length = response.content_length();
        tracing::debug!(url = %redact_url(url), status = %status, content_length = ?content_length, "HTTP text response");
        classify_response_status_with_headers(status, url, Some(response.headers()))?;

        // A content-length larger than the checksum cap is rejected up front,
        // before we allocate or stream a single byte.
        let total = content_length;
        if let Some(len) = total
            && len > MAX_CHECKSUM_SIZE
        {
            return Err(RetryError::permanent(RepoError::Io(std::io::Error::other(
                format!(
                    "checksum sidecar too large: {} bytes (limit {})",
                    len, MAX_CHECKSUM_SIZE
                ),
            ))));
        }

        // Get content length hint, but cap it to prevent unbounded allocation
        let capacity = total
            .map(|len| len.min(MAX_CHECKSUM_SIZE) as usize)
            .unwrap_or(MAX_CHECKSUM_SIZE as usize);
        let mut bytes = Vec::with_capacity(capacity);
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    // Check BEFORE extending to prevent allocation beyond limit.
                    // u64 sum keeps the bound check honest on 32-bit targets.
                    if (bytes.len() as u64).saturating_add(chunk.len() as u64) > MAX_CHECKSUM_SIZE {
                        return Err(RetryError::permanent(RepoError::Io(
                            std::io::Error::other(format!(
                                "checksum sidecar too large (limit {} bytes)",
                                MAX_CHECKSUM_SIZE
                            )),
                        )));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Err(e) => {
                    return Err(RetryError::transient(RepoError::Http(
                        e.without_url().with_url(redacted_url(url)),
                    )));
                }
            }
        }

        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("failed to decode response text from {}", redact_url(url)))
            .map_err(|err| {
                RetryError::permanent(RepoError::InvalidMetadata(err.to_string()))
            })?;
        Ok(text.trim().to_string())
    })
    .await
}

pub(crate) fn parse_checksum(text: &str, algorithm: ChecksumAlgorithm) -> Result<Checksum> {
    let expected_len = match algorithm {
        ChecksumAlgorithm::Sha1 => 40,
        ChecksumAlgorithm::Sha256 => 64,
    };
    let value = extract_hex_token(text, expected_len)
        .ok_or_else(|| RepoError::MissingChecksum(text.to_string()))?;
    Ok(Checksum { algorithm, value })
}

pub(crate) fn verify_checksum(bytes: &[u8], checksum: &Checksum, path: &str) -> Result<()> {
    let actual = match checksum.algorithm {
        ChecksumAlgorithm::Sha1 => sha1_hex(bytes),
        ChecksumAlgorithm::Sha256 => sha256_hex(bytes),
    };
    // The expected checksum here is fetched from a public sidecar (e.g.
    // `.sha256`) on the same repository as the artifact, so it is not a
    // secret: there is no timing-side-channel benefit to a constant-time
    // compare. Use plain equality.
    if actual == checksum.value {
        Ok(())
    } else {
        Err(RepoError::ChecksumMismatch {
            path: path.to_string(),
            expected: checksum.value.clone(),
            actual,
        })
    }
}

pub(crate) fn verify_blob_checksum(
    store: &Store,
    blob: &BlobId,
    checksum: &Checksum,
    path: &str,
) -> Result<()> {
    // Re-hash from disk for both algorithms. `BlobId` is computed during
    // streaming and could in principle disagree with on-disk content if the
    // store was tampered with after persist; re-hashing closes that gap.
    let on_disk = store.get_path(blob);
    let actual = match checksum.algorithm {
        ChecksumAlgorithm::Sha256 => sha256_hex_file(&on_disk)?,
        ChecksumAlgorithm::Sha1 => sha1_hex_file(&on_disk)?,
    };
    // Public-sidecar comparison; see verify_checksum for the rationale on
    // dropping constant-time compare here.
    if actual == checksum.value {
        Ok(())
    } else {
        Err(RepoError::ChecksumMismatch {
            path: path.to_string(),
            expected: checksum.value.clone(),
            actual,
        })
    }
}

/// Off-runtime sibling of [`verify_blob_checksum`]: re-hash the on-disk blob
/// on the blocking pool so the SHA-256/SHA-1 work does not pin a tokio
/// worker thread.
///
/// Callers in `rv-repo::fetch` (post-stream sidecar verify) and
/// `rv-repo::sync` (post-fetch lockfile-pin verify) run from an `async`
/// function. Invoking the synchronous variant directly there would freeze the
/// executor for the duration of a large-JAR hash; routing through this helper
/// keeps the runtime responsive under fan-out fetches.
pub(crate) async fn verify_blob_checksum_offload(
    store: &Store,
    blob: &BlobId,
    checksum: &Checksum,
    path: &str,
) -> Result<()> {
    let store = store.clone();
    let blob = blob.clone();
    let checksum = checksum.clone();
    let path = path.to_string();
    tokio::task::spawn_blocking(move || verify_blob_checksum(&store, &blob, &checksum, &path))
        .await
        .map_err(|e| {
            RepoError::Io(std::io::Error::other(format!(
                "verify_blob_checksum task panicked: {e}"
            )))
        })?
}

fn extract_hex_token(text: &str, expected_len: usize) -> Option<String> {
    for token in text.split_whitespace() {
        let candidate = token.trim();
        if candidate.len() == expected_len && hex::decode(candidate).is_ok() {
            return Some(candidate.to_ascii_lowercase());
        }
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::Digest;
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn hex_file<D: sha2::digest::Digest>(path: &std::path::Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open checksum file {}", path.display()))
        .map_err(|err| RepoError::Io(io_error_with_context(err)))?;
    let mut hasher = D::new();
    let mut buf = [0u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("failed to read checksum file {}", path.display()))
            .map_err(|err| RepoError::Io(io_error_with_context(err)))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn sha1_hex_file(path: &std::path::Path) -> Result<String> {
    hex_file::<Sha1>(path)
}

fn sha256_hex_file(path: &std::path::Path) -> Result<String> {
    hex_file::<sha2::Sha256>(path)
}

#[cfg(test)]
mod tests {
    use super::{ChecksumAlgorithm, parse_checksum, verify_checksum};

    #[test]
    fn parses_checksum_with_filename() {
        let checksum = parse_checksum(
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  file.jar",
            ChecksumAlgorithm::Sha1,
        )
        .unwrap();
        assert_eq!(checksum.value, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }

    #[test]
    fn verifies_sha1_checksum() {
        let bytes = b"hello";
        let checksum = parse_checksum(
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            ChecksumAlgorithm::Sha1,
        )
        .unwrap();
        verify_checksum(bytes, &checksum, "hello.txt").unwrap();
    }

    #[test]
    fn verifies_sha256_checksum() {
        let bytes = b"hello";
        let checksum = parse_checksum(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ChecksumAlgorithm::Sha256,
        )
        .unwrap();
        verify_checksum(bytes, &checksum, "hello.txt").unwrap();
    }

    /// Errors produced by `classify_response_status` and
    /// `classify_status_to_error` must not embed the raw URL when it carries
    /// a username/password; those errors get logged and surfaced to the
    /// user, which would leak the password.
    #[test]
    fn classify_response_status_redacts_userinfo_in_error_messages() {
        use super::{classify_response_status, classify_status_to_error};
        use reqwest::StatusCode;
        use url::Url;

        let url = Url::parse("https://alice:hunter2@repo.example/com/foo/1.0/foo.jar").unwrap();

        // 401 -> AuthError (must redact)
        let err = classify_response_status(StatusCode::UNAUTHORIZED, &url).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "401 AuthError must not contain credentials: {rendered}"
        );
        assert!(
            !rendered.contains("alice"),
            "401 AuthError must not contain username: {rendered}"
        );

        // 407 -> AuthError (must redact)
        let err =
            classify_response_status(StatusCode::PROXY_AUTHENTICATION_REQUIRED, &url).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "407 AuthError must not contain credentials: {rendered}"
        );

        // 503 -> transient UnexpectedResponse (must redact)
        let err = classify_response_status(StatusCode::SERVICE_UNAVAILABLE, &url).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "503 UnexpectedResponse must not contain credentials: {rendered}"
        );

        // 418 -> permanent UnexpectedResponse (must redact)
        let err = classify_response_status(StatusCode::IM_A_TEAPOT, &url).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "418 UnexpectedResponse must not contain credentials: {rendered}"
        );

        // 404 -> NotFound (must redact)
        let err = classify_response_status(StatusCode::NOT_FOUND, &url).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "404 NotFound must not contain credentials: {rendered}"
        );

        // classify_status_to_error (non-backoff variant) must redact too.
        let err = classify_status_to_error(StatusCode::FORBIDDEN, &url);
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("hunter2"),
            "403 AuthError (non-backoff) must not contain credentials: {rendered}"
        );
    }

    #[test]
    fn retry_after_seconds_form_parses_to_duration() {
        use super::parse_retry_after;
        use reqwest::header::HeaderValue;
        use std::time::Duration;

        let d = parse_retry_after(&HeaderValue::from_static("120")).unwrap();
        assert_eq!(d, Duration::from_secs(120));
    }

    #[test]
    fn retry_after_http_date_form_parses_to_duration() {
        use super::parse_retry_after;
        use reqwest::header::HeaderValue;

        let future = chrono::Utc::now() + chrono::Duration::seconds(3600);
        // RFC 7231 IMF-fixdate format. chrono renders it via `to_rfc2822`, which
        // is the parent format RFC 7231 §7.1.1.1 cites.
        let formatted = future.to_rfc2822();
        let header = HeaderValue::from_str(&formatted).unwrap();
        let d = parse_retry_after(&header).expect("http-date must parse");
        assert!(d.as_secs() > 3500 && d.as_secs() <= 3600, "got {d:?}");
    }

    #[test]
    fn retry_after_429_sets_transient_retry_after() {
        use super::{RetryError, classify_response_status_with_headers};
        use reqwest::StatusCode;
        use reqwest::header::{HeaderMap, HeaderValue};
        use std::time::Duration;
        use url::Url;

        let url = Url::parse("https://repo.example/path").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Retry-After", HeaderValue::from_static("42"));
        let err = classify_response_status_with_headers(
            StatusCode::TOO_MANY_REQUESTS,
            &url,
            Some(&headers),
        )
        .unwrap_err();
        match err {
            RetryError::Transient {
                retry_after: Some(d),
                ..
            } => assert_eq!(d, Duration::from_secs(42)),
            other => panic!("expected Transient with retry_after, got {other:?}"),
        }
    }

    #[test]
    fn redact_url_strips_query_and_userinfo() {
        use super::redact_url;
        use url::Url;

        let url =
            Url::parse("https://user:pass@example.com/path?token=secret&sig=abc#frag").unwrap();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("token=secret"));
        assert!(!redacted.contains("sig=abc"));
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(!redacted.contains("#frag"));
        assert!(redacted.contains("example.com/path"));
    }

    #[tokio::test]
    async fn execute_retry_runs_exactly_initial_plus_retries() {
        use super::{FetchConfig, RetryError, execute_retry};
        use crate::error::RepoError;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        // Configure 3 retries -> we expect 1 initial + 3 retries = 4 total
        // calls. An off-by-one (N+2) would produce 5 calls here.
        let config = FetchConfig {
            retries: 3,
            timeout: Duration::from_secs(30),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let result: Result<(), _> = execute_retry(&config, move || {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(RetryError::transient(RepoError::UnexpectedResponse(
                    "transient".to_string(),
                )))
            }
        })
        .await;

        assert!(result.is_err(), "exhausted retries should surface error");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "with retries=3 we must run exactly 1 initial + 3 retries = 4 attempts"
        );
    }

    /// A server that answers EVERY attempt with a transient error carrying a
    /// `Retry-After` must still stop once the retry budget is spent. An
    /// `adjust` closure that returned `Some(retry_after)` unconditionally,
    /// ignoring backon's `dur == None` "stop" signal, would loop forever.
    #[tokio::test]
    async fn execute_retry_honours_budget_even_with_retry_after_every_time() {
        use super::{FetchConfig, RetryError, execute_retry};
        use crate::error::RepoError;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let config = FetchConfig {
            retries: 3,
            timeout: Duration::from_secs(30),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let result: Result<(), _> = execute_retry(&config, move || {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                // Tiny delay keeps the test fast; the point is that a present
                // `Retry-After` does not defeat the attempt-count budget.
                Err::<(), _>(RetryError::Transient {
                    err: RepoError::UnexpectedResponse("429".to_string()),
                    retry_after: Some(Duration::from_millis(1)),
                })
            }
        })
        .await;

        assert!(result.is_err(), "budget exhaustion must surface an error");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "Retry-After must not resurrect the loop past 1 initial + 3 retries"
        );
    }

    #[tokio::test]
    async fn execute_retry_stops_immediately_on_permanent_error() {
        use super::{FetchConfig, RetryError, execute_retry};
        use crate::error::RepoError;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let config = FetchConfig {
            retries: 5,
            timeout: Duration::from_secs(30),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let result: Result<(), _> = execute_retry(&config, move || {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(RetryError::permanent(RepoError::NotFound("x".to_string())))
            }
        })
        .await;

        let err = result.expect_err("permanent error must propagate");
        assert!(matches!(err, RepoError::NotFound(_)), "got {err:?}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "permanent errors must not be retried"
        );
    }

    #[tokio::test]
    async fn execute_retry_succeeds_after_transient_failures() {
        use super::{FetchConfig, RetryError, execute_retry};
        use crate::error::RepoError;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let config = FetchConfig {
            retries: 3,
            timeout: Duration::from_secs(30),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let result: std::result::Result<u32, _> = execute_retry(&config, move || {
            let calls = calls_clone.clone();
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err(RetryError::transient(RepoError::UnexpectedResponse(
                        "still failing".to_string(),
                    )))
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// A sidecar checksum mismatch on a download that
    /// `Store::put_stream` deduplicated against a pre-existing blob must NOT
    /// delete the on-disk file. Other artifact-key rows may point at the
    /// same content-addressed blob.
    #[tokio::test]
    async fn checksum_mismatch_on_dedup_preserves_shared_blob() {
        use super::{Checksum, ChecksumAlgorithm, FetchConfig, fetch_stream_to_store_verified};
        use crate::error::RepoError;
        use reqwest::Client;
        use rv_config::{ArtifactKey, BlobId};
        use rv_store::Store;
        use tempfile::tempdir;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use url::Url;

        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        // Seed the store: first artifact already references the shared blob.
        let payload = b"shared-jar-contents".to_vec();
        let blob_id = store.put_bytes(&payload).await.expect("put");
        let first_key = ArtifactKey::new("com.example", "first", "1.0.0", "jar", None);
        store
            .add_artifact(&first_key, &blob_id)
            .await
            .expect("add first");

        let blob_path = store.get_path(&blob_id);
        assert!(blob_path.is_file(), "seeded blob must exist");

        // Tiny HTTP/1.1 server that responds with the same bytes on every
        // request. We only need it to live long enough to satisfy one GET.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            // Drain the request headers (until \r\n\r\n).
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload_for_server.len()
            );
            sock.write_all(header.as_bytes()).await.expect("write head");
            sock.write_all(&payload_for_server)
                .await
                .expect("write body");
            sock.shutdown().await.ok();
        });

        // Wrong SHA-256 pin: represents a malicious or stale sidecar.
        let bad_sidecar = Checksum {
            algorithm: ChecksumAlgorithm::Sha256,
            value: "0".repeat(64),
        };

        let url = Url::parse(&format!("http://{addr}/second.jar")).expect("parse url");
        let client = Client::builder().build().expect("client");
        let cfg = FetchConfig {
            retries: 0,
            timeout: std::time::Duration::from_secs(5),
        };

        let result = fetch_stream_to_store_verified(
            &client,
            &url,
            None,
            &cfg,
            None,
            &store,
            Some(&bad_sidecar),
        )
        .await;

        let _ = server.await;

        assert!(
            matches!(result, Err(RepoError::ChecksumMismatch { .. })),
            "expected checksum mismatch, got {result:?}"
        );

        // The shared blob must still be present on disk and the first
        // artifact's lookup must still resolve to a valid file.
        assert!(
            blob_path.is_file(),
            "shared blob must NOT have been deleted; \
             first artifact key still references it"
        );
        let actual = BlobId::from_file(&blob_path).expect("rehash");
        assert_eq!(actual, blob_id, "blob bytes must be intact");
        let looked_up = store
            .lookup_artifact(&first_key)
            .await
            .expect("lookup")
            .expect("first artifact still indexed");
        assert_eq!(looked_up, blob_id);
    }

    /// A `Store::prune_blobs` sweep that runs between the
    /// blob persist and the index commit must NOT delete the freshly-stored
    /// blob, leaving a dangling index row. Routing the fetch through
    /// `fetch_stream_to_store_and_index` holds the `StoreLock` across the
    /// entire persist+index window, serialising it against any concurrent GC.
    ///
    /// The test launches a GC loop on a background task that repeatedly
    /// calls `prune_blobs` with an empty `keep` set. After the indexed
    /// fetch returns, the blob file MUST still be on disk and resolvable
    /// via the indexed artifact key.
    #[tokio::test]
    async fn fetch_stream_to_store_and_index_survives_concurrent_gc() {
        use super::{FetchConfig, fetch_stream_to_store_and_index};
        use reqwest::Client;
        use rv_config::ArtifactKey;
        use rv_store::Store;
        use std::collections::HashSet;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tempfile::tempdir;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use url::Url;

        let dir = tempdir().expect("tempdir");
        let store = Arc::new(Store::open(dir.path()).expect("open"));
        let key = ArtifactKey::new("com.example", "racey", "1.0.0", "jar", None);

        // Tiny HTTP server returning a fixed payload on every connection.
        let payload = b"atomic-put-and-index-payload".to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = stop.clone();
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            loop {
                if stop_for_server.load(Ordering::SeqCst) {
                    return;
                }
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let payload = payload_for_server.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        total.extend_from_slice(&buf[..n]);
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&payload).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        // Concurrent GC: keep sweeping with an empty `keep` set. Any blob
        // that lacks an index row pointing at it would be deleted.
        let gc_store = store.clone();
        let stop_for_gc = stop.clone();
        let gc = tokio::spawn(async move {
            while !stop_for_gc.load(Ordering::SeqCst) {
                let _ = gc_store.prune_blobs(&HashSet::new(), false).await;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        let url = Url::parse(&format!("http://{addr}/jar")).expect("parse");
        let client = Client::builder().build().expect("client");
        let cfg = FetchConfig {
            retries: 0,
            timeout: std::time::Duration::from_secs(5),
        };

        // Run several fetches back-to-back so we have multiple chances to
        // race against the GC loop.
        for _ in 0..6 {
            let blob = fetch_stream_to_store_and_index(
                &client, &url, None, &cfg, None, &store, &key, None,
            )
            .await
            .expect("indexed fetch");
            let blob_path = store.get_path(&blob);
            assert!(
                blob_path.is_file(),
                "blob must remain on disk after atomic put+index, even with concurrent GC"
            );
            // The index row must still resolve to a present, readable blob.
            let looked_up = store
                .lookup_artifact(&key)
                .await
                .expect("lookup")
                .expect("indexed");
            assert_eq!(looked_up, blob);
            let on_disk = store.get_path(&looked_up);
            assert!(
                on_disk.is_file(),
                "indexed row must point at a still-present blob"
            );
        }

        stop.store(true, Ordering::SeqCst);
        let _ = gc.await;
        // Connect once to unblock the listener accept loop.
        let _ = tokio::net::TcpStream::connect(addr).await;
        let _ = server.await;
    }

    /// A fan-out of `fetch_stream_to_store_verified` calls with sidecar
    /// checksum verification must NOT pin every tokio worker
    /// thread. The post-stream `verify_blob_checksum` runs on the blocking
    /// pool; the executor must stay responsive for a timer task scheduled
    /// during the fan-out.
    #[test]
    fn fetch_post_stream_verify_keeps_runtime_responsive() {
        use super::{
            Checksum, ChecksumAlgorithm, FetchConfig, fetch_stream_to_store_verified, sha256_hex,
        };
        use reqwest::Client;
        use rv_store::Store;
        use std::sync::Arc;
        use std::time::Duration;
        use tempfile::tempdir;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::runtime::Builder;
        use url::Url;

        let rt = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("rt");

        rt.block_on(async {
            let dir = tempdir().expect("tempdir");
            let store = Arc::new(Store::open(dir.path()).expect("open"));

            // Larger payload (~256 KB) so the SHA-256 work is non-trivial.
            let payload = vec![7u8; 256 * 1024];
            let expected = sha256_hex(&payload);

            // Spawn a server that yields the same payload for every request.
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let payload_for_server = payload.clone();
            tokio::spawn(async move {
                loop {
                    let (mut sock, _) = match listener.accept().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let payload = payload_for_server.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let mut total = Vec::new();
                        loop {
                            let n = sock.read(&mut buf).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            total.extend_from_slice(&buf[..n]);
                            if total.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(&payload).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });

            let checksum = Checksum {
                algorithm: ChecksumAlgorithm::Sha256,
                value: expected,
            };
            let cfg = FetchConfig {
                retries: 0,
                timeout: Duration::from_secs(5),
            };
            let client = Client::builder().build().expect("client");

            let verify_fut = async {
                let mut handles = Vec::new();
                for i in 0..12 {
                    let url = Url::parse(&format!("http://{addr}/{i}.jar")).expect("url");
                    let store = store.clone();
                    let client = client.clone();
                    let checksum = checksum.clone();
                    let cfg = cfg.clone();
                    handles.push(tokio::spawn(async move {
                        fetch_stream_to_store_verified(
                            &client,
                            &url,
                            None,
                            &cfg,
                            None,
                            &store,
                            Some(&checksum),
                        )
                        .await
                        .expect("fetch")
                    }));
                }
                for h in handles {
                    h.await.expect("join");
                }
            };

            let responsive_fut = async {
                tokio::time::timeout(
                    Duration::from_millis(200),
                    tokio::time::sleep(Duration::from_millis(10)),
                )
                .await
                .expect("timer must fire while fetches are in flight");
            };

            tokio::time::timeout(Duration::from_secs(15), async {
                tokio::join!(verify_fut, responsive_fut);
            })
            .await
            .expect("fan-out + timer must complete within 15 s");
        });
    }

    /// The 407 proxy-auth error message must read cleanly, with no run of
    /// stray spaces between "configuration" and the parenthetical hint.
    #[test]
    fn proxy_auth_407_message_has_no_stray_spaces() {
        use super::classify_response_status;
        use reqwest::StatusCode;
        use url::Url;

        let url = Url::parse("https://repo.example/path").unwrap();
        let err =
            classify_response_status(StatusCode::PROXY_AUTHENTICATION_REQUIRED, &url).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("  "),
            "407 message must not contain a run of stray spaces: {rendered}"
        );
        assert!(
            rendered.contains("configuration (proxy"),
            "407 message should read 'configuration (proxy ...)': {rendered}"
        );
    }

    /// A checksum sidecar whose advertised `Content-Length` exceeds the
    /// dedicated cap must be rejected up front, before any body is streamed.
    #[tokio::test]
    async fn fetch_text_rejects_oversized_content_length() {
        use super::{FetchConfig, MAX_CHECKSUM_SIZE, fetch_text};
        use crate::error::RepoError;
        use reqwest::Client;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use url::Url;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Advertise a body far bigger than the checksum cap; we never write it.
        let advertised = MAX_CHECKSUM_SIZE + 1;
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {advertised}\r\nConnection: close\r\n\r\n"
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let url = Url::parse(&format!("http://{addr}/foo.jar.sha256")).expect("url");
        let client = Client::builder().build().expect("client");
        let cfg = FetchConfig {
            retries: 0,
            timeout: std::time::Duration::from_secs(5),
        };

        let result = fetch_text(&client, &url, None, &cfg).await;
        let _ = server.await;

        match result {
            Err(RepoError::Io(err)) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("checksum sidecar too large"),
                    "expected checksum-cap rejection, got {msg}"
                );
            }
            other => panic!("expected Io(checksum sidecar too large), got {other:?}"),
        }
    }

    /// A sidecar that streams more bytes than the cap (no/under-stated
    /// `Content-Length`) must also be rejected mid-stream rather than buffered
    /// in full.
    #[tokio::test]
    async fn fetch_text_rejects_oversized_streamed_body() {
        use super::{FetchConfig, MAX_CHECKSUM_SIZE, fetch_text};
        use crate::error::RepoError;
        use reqwest::Client;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use url::Url;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Stream well past the cap without advertising a Content-Length, so the
        // streaming bound check is what must fire.
        let body = vec![b'a'; (MAX_CHECKSUM_SIZE as usize) * 2];
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Chunked transfer so reqwest reports no content_length up front.
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await;
            let _ = sock.write_all(&body).await;
            let _ = sock.shutdown().await;
        });

        let url = Url::parse(&format!("http://{addr}/foo.jar.sha256")).expect("url");
        let client = Client::builder().build().expect("client");
        let cfg = FetchConfig {
            retries: 0,
            timeout: std::time::Duration::from_secs(5),
        };

        let result = fetch_text(&client, &url, None, &cfg).await;
        let _ = server.await;

        match result {
            Err(RepoError::Io(err)) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("checksum sidecar too large"),
                    "expected checksum-cap rejection, got {msg}"
                );
            }
            other => panic!("expected Io(checksum sidecar too large), got {other:?}"),
        }
    }

    /// A well-formed, small sidecar still fetches and trims correctly under the
    /// dedicated cap.
    #[tokio::test]
    async fn fetch_text_accepts_small_sidecar() {
        use super::{FetchConfig, fetch_text};
        use reqwest::Client;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use url::Url;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let payload = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  foo.jar\n";
        let payload_for_server = payload.to_string();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload_for_server.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(payload_for_server.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let url = Url::parse(&format!("http://{addr}/foo.jar.sha1")).expect("url");
        let client = Client::builder().build().expect("client");
        let cfg = FetchConfig {
            retries: 0,
            timeout: std::time::Duration::from_secs(5),
        };

        let text = fetch_text(&client, &url, None, &cfg)
            .await
            .expect("small sidecar fetch");
        let _ = server.await;
        assert_eq!(text, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  foo.jar");
    }
}
