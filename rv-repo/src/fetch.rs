use std::collections::VecDeque;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use backon::ExponentialBuilder;
use bytes::Bytes;
use futures::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use sha1::Sha1;
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

fn request_error(error: reqwest::Error, url: &Url) -> RetryError {
    if let Some((kind, details)) = crate::client::redirect_rejection_from_reqwest(&error) {
        return RetryError::permanent(RepoError::RedirectRejected { kind, details });
    }

    // Strip and reattach a redacted URL so the rendered error never exposes
    // userinfo or presigned query tokens through Debug/Display.
    let error = error.without_url().with_url(redacted_url(url));
    if error.is_timeout() || error.is_connect() {
        RetryError::transient(RepoError::Http(error))
    } else {
        RetryError::permanent(RepoError::Http(error))
    }
}

#[derive(Debug, Clone)]
pub struct FetchConfig {
    pub retries: usize,
    /// Timeout for metadata and sidecars, or for headers and idle gaps in artifact streams.
    /// Artifact idle gaps include waits for the store to consume chunks. EOF ends
    /// the network deadline; total transfer time has no limit.
    pub timeout: Duration,
    /// Upper bound on a single artifact body, guarding against a hostile
    /// server streaming forever.
    pub max_artifact_size: u64,
    /// Minimum artifact throughput in bytes/s; zero disables the check.
    pub low_speed_limit: u64,
    /// Sliding window of network wait time, excluding store backpressure.
    pub low_speed_time: Duration,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            retries: 2,
            timeout: Duration::from_secs(30),
            max_artifact_size: DEFAULT_MAX_ARTIFACT_SIZE,
            low_speed_limit: rv_config::NetworkConfig::default().low_speed_limit,
            low_speed_time: Duration::from_secs(rv_config::NetworkConfig::default().low_speed_time),
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
/// Default artifact size cap in bytes, overridden by `RV_MAX_ARTIFACT_SIZE`.
pub const DEFAULT_MAX_ARTIFACT_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16GiB
pub const MAX_ARTIFACT_SIZE_ENV: &str = "RV_MAX_ARTIFACT_SIZE";
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

/// Parse RFC 9110 §10.2.3 `Retry-After`: delta-seconds or any of the three
/// HTTP-date forms. Past dates clamp to zero; unparseable values yield `None`
/// (caller falls back).
fn parse_retry_after(value: &HeaderValue) -> Option<Duration> {
    let text = value.to_str().ok()?.trim();
    if let Ok(secs) = text.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let target = httpdate::parse_http_date(text).ok()?;
    Some(
        target
            .duration_since(std::time::SystemTime::now())
            .unwrap_or(Duration::ZERO),
    )
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
    repository_root: Option<&Url>,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&dyn FetchProgress>,
) -> Result<Bytes> {
    if url.scheme() == "file" {
        return read_local_bytes(url, repository_root, MAX_METADATA_SIZE, progress).await;
    }
    tracing::debug!(url = %redact_url(url), method = "GET", "HTTP request start");
    execute_retry(config, || async {
        let mut request = client.get(url.as_str());
        request = request.timeout(config.timeout);

        if let Some(auth) = auth {
            request = auth.apply(request);
        }

        let response = request
            .send()
            .await
            .map_err(|error| request_error(error, url))?;

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

/// Names what was being downloaded, and from where, for a mid-body failure.
///
/// An artifact body is streamed straight into the store, so a transport error
/// partway through the response has to cross a `std::io::Error` boundary to
/// reach `Store::put_stream*`. Coming back out as `RepoError::Store` it lost
/// every bit of request identity: a dropped connection rendered as the bare
/// `store error: io error: error decoding response body`, naming neither the
/// artifact nor the repository, which is useless for deciding whether a
/// transient sync failure is worth retrying or points at one bad mirror.
///
/// The URL is redacted (no query, no `user:pass@`) exactly as elsewhere.
fn download_context(coordinate: Option<&ArtifactKey>, url: &Url) -> String {
    match coordinate {
        Some(coordinate) => {
            format!(" while downloading {coordinate} from {}", redact_url(url))
        }
        None => format!(" while downloading {}", redact_url(url)),
    }
}

type ByteStream = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send>,
>;

/// Map a `file://` repository URL to a local path for reading.
///
/// Only root and parent POMs may authorize these read-only repositories.
/// Transitive declarations cannot. Reject decoded `..` segments because percent
/// encoding can hide them from the URL join check.
fn local_path(url: &Url) -> Result<std::path::PathBuf> {
    let path = url.to_file_path().map_err(|()| {
        RepoError::InvalidCoord(format!("'{}' is not a usable file:// path", url.path()))
    })?;
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(RepoError::InvalidCoord(format!(
            "file:// path '{}' contains a parent-directory segment",
            path.display()
        )));
    }
    Ok(path)
}

fn local_open_error(err: std::io::Error, path: &std::path::Path) -> RepoError {
    if err.kind() == std::io::ErrorKind::NotFound {
        RepoError::NotFound(path.display().to_string())
    } else {
        RepoError::Io(std::io::Error::new(
            err.kind(),
            format!("{}: {err}", path.display()),
        ))
    }
}

/// Every local read (including metadata and checksum sidecars) must carry its
/// repository root. A bare file URL is not authority to read an arbitrary file.
async fn open_local_file(url: &Url, repository_root: Option<&Url>) -> Result<tokio::fs::File> {
    let root = repository_root.ok_or_else(|| {
        RepoError::InvalidCoord("file:// read requires a repository root".to_string())
    })?;
    let root = local_path(root)?;
    let path = local_path(url)?;
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| {
            RepoError::InvalidCoord("file:// path escapes the repository root".to_string())
        })?
        .to_path_buf();
    if relative.as_os_str().is_empty() {
        return Err(RepoError::InvalidCoord(
            "file:// path names the repository root".to_string(),
        ));
    }
    let file = tokio::task::spawn_blocking(move || {
        let canonical_root = root
            .canonicalize()
            .map_err(|err| local_open_error(err, &root))?;
        open_confined_file(&canonical_root, &relative).map_err(|err| local_open_error(err, &path))
    })
    .await
    .map_err(|err| {
        RepoError::Io(std::io::Error::other(format!(
            "local read task failed: {err}"
        )))
    })??;
    Ok(tokio::fs::File::from_std(file))
}

/// Open a file relative to a directory descriptor, rejecting symlinks in every component.
/// Walk the canonical root too, preventing ancestor substitution after canonicalization.
#[cfg(unix)]
fn open_confined_file(root: &std::path::Path, relative: &std::path::Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::path::Component;

    let directory_flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY;
    let mut directory = open("/", directory_flags, Mode::empty())?;
    for component in root.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, directory_flags, Mode::empty())?
            }
            _ => return Err(std::io::Error::other("invalid canonical repository root")),
        }
    }
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::other("invalid repository path component"));
        };
        if components.peek().is_some() {
            directory = openat(&directory, name, directory_flags, Mode::empty())?;
        } else {
            // NONBLOCK prevents an adversarial FIFO from hanging the read before
            // the regular-file check can reject it.
            let fd = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            let file = File::from(fd);
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::other(
                    "repository entry is not a regular file",
                ));
            }
            return Ok(file);
        }
    }
    Err(std::io::Error::other("empty repository path"))
}

/// Check each resolved component, not only the final target: a directory link
/// must not leave the repository even if a later link points back inside it.
#[cfg(not(unix))]
fn open_confined_file(root: &std::path::Path, relative: &std::path::Path) -> std::io::Result<File> {
    let mut path = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::other("invalid repository path component"));
        };
        path.push(name);
        path = path.canonicalize()?;
        if !path.starts_with(root) {
            return Err(std::io::Error::other(
                "file:// path escapes the repository root",
            ));
        }
    }
    open_checked_repository_entry(&path)
}

#[cfg(not(unix))]
fn open_checked_repository_entry(path: &std::path::Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "repository entry is not a regular file",
        ));
    }
    Ok(file)
}

async fn read_local_bytes(
    url: &Url,
    repository_root: Option<&Url>,
    limit: u64,
    progress: Option<&dyn FetchProgress>,
) -> Result<Bytes> {
    use tokio::io::AsyncReadExt;
    let path = local_path(url)?;
    let file = open_local_file(url, repository_root).await?;
    let mut bytes = Vec::new();
    // Read one byte past the limit so an oversized file is detected, not truncated.
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|err| local_open_error(err, &path))?;
    if bytes.len() as u64 > limit {
        return Err(RepoError::Io(std::io::Error::other(format!(
            "{} too large (limit {limit} bytes)",
            path.display()
        ))));
    }
    if let Some(progress) = progress {
        progress.on_start(url, Some(bytes.len() as u64));
        progress.on_finish(url, bytes.len());
    }
    Ok(Bytes::from(bytes))
}

async fn open_local_stream(
    url: &Url,
    repository_root: Option<&Url>,
) -> Result<(Option<u64>, ByteStream)> {
    use tokio::io::AsyncReadExt;
    let path = local_path(url)?;
    let file = open_local_file(url, repository_root).await?;
    let len = file
        .metadata()
        .await
        .map_err(|err| local_open_error(err, &path))?
        .len();
    let stream = futures::stream::unfold(file, |mut file| async move {
        let mut buf = vec![0u8; 64 * 1024];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(Bytes::from(buf)), file))
            }
            Err(err) => Some((Err(err), file)),
        }
    });
    Ok((Some(len), Box::pin(stream)))
}

/// Turn a mid-body transport error into an io error that still names the
/// artifact and repository it came from.
fn stream_chunk_error(error: reqwest::Error, context: &str) -> std::io::Error {
    let mut reason = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        reason.push_str(": ");
        reason.push_str(&cause.to_string());
        source = cause.source();
    }
    std::io::Error::other(format!("{reason}{context}"))
}

fn too_large_message(limit: u64, context: &str) -> String {
    format!(
        "artifact exceeds the size limit of {limit} bytes{context} \
         (raise it with {MAX_ARTIFACT_SIZE_ENV})"
    )
}

/// Wait for response headers without imposing a deadline on the body.
async fn send_for_headers(
    request: reqwest::RequestBuilder,
    url: &Url,
    config: &FetchConfig,
) -> std::result::Result<reqwest::Response, RetryError> {
    match tokio::time::timeout(config.timeout, request.send()).await {
        Ok(result) => result.map_err(|error| request_error(error, url)),
        Err(_) => Err(RetryError::transient(RepoError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "timed out after {}s waiting for response headers from {} \
                     (raise RV_TIMEOUT)",
                config.timeout.as_secs(),
                redact_url(url)
            ),
        )))),
    }
}

type ArtifactStream = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send>,
>;

/// Activity observed by the body stream and its consumer's idle deadline.
/// The critical section only copies an Instant/bool; it never covers I/O.
struct ArtifactBodyActivity {
    last_data: tokio::time::Instant,
    finished: bool,
}

struct ArtifactIdleDeadline {
    activity: Arc<Mutex<ArtifactBodyActivity>>,
    timeout: Duration,
    context: String,
}

impl ArtifactIdleDeadline {
    /// Enforce the idle deadline even while the store awaits filesystem work.
    /// A timeout around the stream alone cannot fire when its consumer stops polling.
    ///
    /// EOF ends this deadline. The store uses its own locking policy for publication;
    /// canceling a `spawn_blocking` commit cannot stop it from publishing after a retry.
    async fn run<T>(
        self,
        operation: impl Future<Output = std::result::Result<T, rv_store::StoreError>>,
    ) -> std::result::Result<T, rv_store::StoreError> {
        let mut operation = std::pin::pin!(operation);
        let mut deadline = std::pin::pin!(tokio::time::sleep(self.timeout));
        std::future::poll_fn(|cx| {
            // Available data or completion takes precedence when the deadline is also ready.
            if let std::task::Poll::Ready(result) = operation.as_mut().poll(cx) {
                return std::task::Poll::Ready(result);
            }
            let activity = self.activity.lock().unwrap_or_else(|e| e.into_inner());
            if activity.finished {
                return std::task::Poll::Pending;
            }
            let next = activity.last_data + self.timeout;
            drop(activity);
            if deadline.deadline() != next {
                deadline.as_mut().reset(next);
            }
            if deadline.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(Err(rv_store::StoreError::IoError(
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "timed out: no data received for {:?}{} (raise RV_TIMEOUT)",
                            self.timeout, self.context
                        ),
                    ),
                )));
            }
            std::task::Poll::Pending
        })
        .await
    }
}

/// Bounded rolling history that retains the boundary bucket in full.
/// This overestimates speed by at most one bucket's bytes, avoiding false rejections
/// when a chunk straddles the window boundary.
struct ArtifactSpeedWindow {
    elapsed: Duration,
    window: Duration,
    bucket_width: Duration,
    buckets: VecDeque<(Duration, Duration, u64)>,
}

impl ArtifactSpeedWindow {
    fn new(window: Duration) -> Self {
        Self {
            elapsed: Duration::ZERO,
            window,
            bucket_width: (window / 32).max(Duration::from_nanos(1)),
            buckets: VecDeque::new(),
        }
    }

    fn observe(&mut self, elapsed: Duration, bytes: u64) -> Option<f64> {
        self.elapsed += elapsed;
        let cutoff = self.elapsed.saturating_sub(self.window);
        while self.elapsed >= self.window
            && self
                .buckets
                .front()
                .is_some_and(|(_, end, _)| *end <= cutoff)
        {
            self.buckets.pop_front();
        }
        if bytes != 0 {
            if let Some((start, end, count)) = self.buckets.back_mut()
                && self.elapsed - *start < self.bucket_width
            {
                *end = self.elapsed;
                *count += bytes;
            } else {
                self.buckets.push_back((self.elapsed, self.elapsed, bytes));
            }
        }
        (self.elapsed >= self.window).then(|| {
            self.buckets
                .iter()
                .map(|(_, _, bytes)| *bytes as f64)
                .sum::<f64>()
                / self.window.as_secs_f64()
        })
    }
}

/// Measure throughput using only time spent awaiting network reads.
/// Exclude headers, file creation, writes, and store publication.
fn low_speed_body_stream(
    mut raw: ByteStream,
    context: String,
    limit: u64,
    window: Duration,
) -> ByteStream {
    if limit == 0 || window.is_zero() {
        return raw;
    }
    let mut history = ArtifactSpeedWindow::new(window);
    let mut pending_since = None;
    let mut tick = Box::pin(tokio::time::sleep(history.bucket_width));
    Box::pin(futures::stream::poll_fn(move |cx| {
        let now = tokio::time::Instant::now();
        let elapsed = pending_since
            .take()
            .map_or(Duration::ZERO, |since| now - since);
        let item = raw.as_mut().poll_next(cx);
        // Completion and transport errors win over the throughput check.
        if matches!(item, std::task::Poll::Ready(None | Some(Err(_)))) {
            return item;
        }
        let bytes = match &item {
            std::task::Poll::Ready(Some(Ok(bytes))) => bytes.len() as u64,
            _ => 0,
        };
        if let Some(rate) = history.observe(elapsed, bytes)
            && rate < limit as f64
        {
            return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "artifact download too slow{context}: {rate:.0} bytes/s over {:.3}s \
                     (minimum {limit} bytes/s); lower RV_LOW_SPEED_LIMIT (0 disables) or \
                     raise RV_LOW_SPEED_TIME, or set network.low_speed_limit / network.low_speed_time in rv.toml",
                    window.as_secs_f64(),
                ),
            ))));
        }
        if item.is_pending() {
            pending_since = Some(now);
            // Register a wakeup to check throughput even if no more bytes arrive.
            tick.as_mut().reset(now + history.bucket_width);
            let _ = tick.as_mut().poll(cx);
        }
        item
    }))
}

/// Enforce the size cap and track actual body progress for the idle deadline.
/// Return the deadline separately so it can be polled even when the store is
/// awaiting filesystem work rather than polling this stream.
/// `cap_hit` lets the caller distinguish permanent size failures from retries.
fn artifact_body_stream(
    raw_stream: ByteStream,
    context: String,
    config: &FetchConfig,
    bytes_read: Arc<AtomicU64>,
    cap_hit: Arc<std::sync::atomic::AtomicBool>,
) -> (ArtifactStream, ArtifactIdleDeadline) {
    let limit = config.max_artifact_size;
    let mut raw_stream = low_speed_body_stream(
        raw_stream,
        context.clone(),
        config.low_speed_limit,
        config.low_speed_time,
    );
    let activity = Arc::new(Mutex::new(ArtifactBodyActivity {
        last_data: tokio::time::Instant::now(),
        finished: false,
    }));
    let idle = ArtifactIdleDeadline {
        activity: activity.clone(),
        timeout: config.timeout,
        context: context.clone(),
    };
    let stream = futures::stream::poll_fn(move |cx| {
        raw_stream.as_mut().poll_next(cx).map(|item| match item {
            Some(Ok(bytes)) => {
                let total = bytes_read.load(Ordering::Relaxed) + bytes.len() as u64;
                if total > limit {
                    cap_hit.store(true, Ordering::Relaxed);
                    return Some(Err(std::io::Error::other(too_large_message(
                        limit, &context,
                    ))));
                }
                if !bytes.is_empty() {
                    activity.lock().unwrap_or_else(|e| e.into_inner()).last_data =
                        tokio::time::Instant::now();
                }
                bytes_read.store(total, Ordering::Relaxed);
                Some(Ok(bytes))
            }
            None => {
                activity.lock().unwrap_or_else(|e| e.into_inner()).finished = true;
                None
            }
            Some(Err(error)) => Some(Err(error)),
        })
    });
    (Box::pin(stream), idle)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_stream_to_store_verified(
    client: &Client,
    url: &Url,
    repository_root: Option<&Url>,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&dyn FetchProgress>,
    store: &Store,
    expected_checksum: Option<&Checksum>,
) -> Result<BlobId> {
    let path = url.path().to_string();
    tracing::debug!(url = %redact_url(url), method = "GET", "HTTP stream request start");
    let attempts = AtomicU64::new(0);
    execute_retry(config, || async {
        let retry = attempts.fetch_add(1, Ordering::Relaxed) != 0;
        let context = download_context(None, url);
        let (total, raw_stream) = if url.scheme() == "file" {
            open_local_stream(url, repository_root).await.map_err(RetryError::permanent)?
        } else {
            let mut request = client.get(url.as_str());
            // Dropping an incomplete HTTP/1 body discards its connection.
            // Close retry connections too, preserving the configured proxy, TLS, and redirect policy.
            if retry {
                request = request.header(reqwest::header::CONNECTION, "close");
            }
            if let Some(auth) = auth {
                request = auth.apply(request);
            }

            let response = send_for_headers(request, url, config).await?;

            let status = response.status();
            let content_length = response.content_length();
            tracing::debug!(url = %redact_url(url), status = %status, content_length = ?content_length, "HTTP stream response");
            classify_response_status_with_headers(status, url, Some(response.headers()))?;
            let http_context = context.clone();
            let stream: ByteStream = Box::pin(
                response
                    .bytes_stream()
                    .map(move |chunk| chunk.map_err(|e| stream_chunk_error(e, &http_context))),
            );
            (content_length, stream)
        };
        if let Some(len) = total
            && len > config.max_artifact_size
        {
            return Err(RetryError::permanent(RepoError::Io(
                std::io::Error::other(too_large_message(
                    config.max_artifact_size,
                    &format!(" ({len} bytes advertised){}", download_context(None, url)),
                )),
            )));
        }

        if let Some(progress) = progress {
            progress.on_start(url, total);
        }

        let bytes_read = std::sync::Arc::new(AtomicU64::new(0));
        let cap_hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let (boxed_stream, idle) = artifact_body_stream(
            raw_stream,
            context,
            config,
            bytes_read.clone(),
            cap_hit.clone(),
        );

        match idle.run(store.put_stream_with_origin(boxed_stream)).await {
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
            Err(err) if cap_hit.load(Ordering::Relaxed) => {
                Err(RetryError::permanent(RepoError::Store(err)))
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
    repository_root: Option<&Url>,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&dyn FetchProgress>,
    store: &Store,
    key: &ArtifactKey,
    expected_checksum: Option<&Checksum>,
) -> Result<BlobId> {
    let path = url.path().to_string();
    tracing::debug!(url = %redact_url(url), method = "GET", "HTTP stream+index request start");
    let attempts = AtomicU64::new(0);
    execute_retry(config, || async {
        let retry = attempts.fetch_add(1, Ordering::Relaxed) != 0;
        let context = download_context(Some(key), url);
        let (total, raw_stream) = if url.scheme() == "file" {
            open_local_stream(url, repository_root).await.map_err(RetryError::permanent)?
        } else {
            let mut request = client.get(url.as_str());
            // Dropping an incomplete HTTP/1 body discards its connection.
            // Close retry connections too, preserving the configured proxy, TLS, and redirect policy.
            if retry {
                request = request.header(reqwest::header::CONNECTION, "close");
            }
            if let Some(auth) = auth {
                request = auth.apply(request);
            }

            let response = send_for_headers(request, url, config).await?;

            let status = response.status();
            let content_length = response.content_length();
            tracing::debug!(url = %redact_url(url), status = %status, content_length = ?content_length, "HTTP stream+index response");
            classify_response_status_with_headers(status, url, Some(response.headers()))?;
            let http_context = context.clone();
            let stream: ByteStream = Box::pin(
                response
                    .bytes_stream()
                    .map(move |chunk| chunk.map_err(|e| stream_chunk_error(e, &http_context))),
            );
            (content_length, stream)
        };
        if let Some(len) = total
            && len > config.max_artifact_size
        {
            return Err(RetryError::permanent(RepoError::Io(
                std::io::Error::other(too_large_message(
                    config.max_artifact_size,
                    &format!(" ({len} bytes advertised){}", download_context(Some(key), url)),
                )),
            )));
        }

        if let Some(progress) = progress {
            progress.on_start(url, total);
        }

        let bytes_read = std::sync::Arc::new(AtomicU64::new(0));
        let cap_hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let (boxed_stream, idle) = artifact_body_stream(
            raw_stream,
            context,
            config,
            bytes_read.clone(),
            cap_hit.clone(),
        );

        match idle.run(store.put_stream_and_index(key, boxed_stream)).await {
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
            Err(err) if cap_hit.load(Ordering::Relaxed) => {
                Err(RetryError::permanent(RepoError::Store(err)))
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
    repository_root: Option<&Url>,
    auth: Option<&Auth>,
    config: &FetchConfig,
) -> Result<String> {
    if url.scheme() == "file" {
        let bytes = read_local_bytes(url, repository_root, MAX_CHECKSUM_SIZE, None).await?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|err| RepoError::InvalidMetadata(err.to_string()))?;
        return Ok(text.trim().to_string());
    }
    tracing::debug!(url = %redact_url(url), method = "GET", "HTTP text request start");
    execute_retry(config, || async {
        let mut request = client.get(url.as_str());
        request = request.timeout(config.timeout);
        if let Some(auth) = auth {
            request = auth.apply(request);
        }

        let response = request
            .send()
            .await
            .map_err(|error| request_error(error, url))?;

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

    /// Errors produced by `classify_response_status_with_headers` must not
    /// embed the raw URL when it carries a username/password; those errors
    /// get logged and surfaced to the user, which would leak the password.
    #[test]
    fn classify_response_status_redacts_userinfo_in_error_messages() {
        use super::classify_response_status_with_headers;
        use reqwest::StatusCode;
        use url::Url;

        let url = Url::parse("https://alice:hunter2@repo.example/com/foo/1.0/foo.jar").unwrap();

        // 401 -> AuthError (must redact)
        let err = classify_response_status_with_headers(StatusCode::UNAUTHORIZED, &url, None)
            .unwrap_err();
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
        let err = classify_response_status_with_headers(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            &url,
            None,
        )
        .unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "407 AuthError must not contain credentials: {rendered}"
        );

        // 503 -> transient UnexpectedResponse (must redact)
        let err =
            classify_response_status_with_headers(StatusCode::SERVICE_UNAVAILABLE, &url, None)
                .unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "503 UnexpectedResponse must not contain credentials: {rendered}"
        );

        // 418 -> permanent UnexpectedResponse (must redact)
        let err =
            classify_response_status_with_headers(StatusCode::IM_A_TEAPOT, &url, None).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "418 UnexpectedResponse must not contain credentials: {rendered}"
        );

        // 404 -> NotFound (must redact)
        let err =
            classify_response_status_with_headers(StatusCode::NOT_FOUND, &url, None).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "404 NotFound must not contain credentials: {rendered}"
        );

        // 403 -> AuthError (must redact)
        let err =
            classify_response_status_with_headers(StatusCode::FORBIDDEN, &url, None).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2"),
            "403 AuthError must not contain credentials: {rendered}"
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

        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        let header = HeaderValue::from_str(&httpdate::fmt_http_date(future)).unwrap();
        let d = parse_retry_after(&header).expect("http-date must parse");
        assert!(d.as_secs() > 3500 && d.as_secs() <= 3600, "got {d:?}");

        for obsolete in ["Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] {
            let header = HeaderValue::from_static(obsolete);
            assert_eq!(
                parse_retry_after(&header),
                Some(std::time::Duration::ZERO),
                "{obsolete}"
            );
        }
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
    fn download_context_names_coordinate_and_repository() {
        use super::download_context;
        use rv_config::ArtifactKey;
        use url::Url;

        let url = Url::parse(
            "https://user:pass@repo.example.com/maven2/junit/junit/4.13.2/junit-4.13.2.jar?sig=abc",
        )
        .unwrap();
        let key = ArtifactKey::new("junit", "junit", "4.13.2", "jar", None);

        let context = download_context(Some(&key), &url);
        assert!(
            context.contains("junit:junit:4.13.2:jar"),
            "context must name the artifact coordinate: {context}"
        );
        assert!(
            context.contains("repo.example.com/maven2/junit/junit/4.13.2/junit-4.13.2.jar"),
            "context must name the repository URL: {context}"
        );
        assert!(
            !context.contains("sig=abc") && !context.contains("pass"),
            "context must reuse URL redaction: {context}"
        );

        // Without a coordinate the URL alone still identifies the download.
        let context = download_context(None, &url);
        assert!(
            context.contains("junit-4.13.2.jar"),
            "coordinate-less context must still name the URL: {context}"
        );
        assert!(
            !context.contains("sig=abc") && !context.contains("pass"),
            "context must reuse URL redaction: {context}"
        );
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

    #[tokio::test(start_paused = true)]
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

    #[tokio::test(start_paused = true)]
    async fn execute_retry_succeeds_after_transient_failures() {
        use super::{FetchConfig, RetryError, execute_retry};
        use crate::error::RepoError;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let config = FetchConfig {
            retries: 3,
            timeout: Duration::from_secs(30),
            ..Default::default()
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
        use rv_test_support::http::{Response, StubServer};
        use tempfile::tempdir;
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
        let payload_for_server = payload.clone();
        let server = StubServer::start(move |_| Response::new(200, payload_for_server.clone()));
        let addr = server.addr();

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
            ..Default::default()
        };

        let result = fetch_stream_to_store_verified(
            &client,
            &url,
            None,
            None,
            &cfg,
            None,
            &store,
            Some(&bad_sidecar),
        )
        .await;

        server.stop();

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
        use rv_test_support::http::{Response, StubServer};
        use std::collections::HashSet;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tempfile::tempdir;
        use url::Url;

        let dir = tempdir().expect("tempdir");
        let store = Arc::new(Store::open(dir.path()).expect("open"));
        let key = ArtifactKey::new("com.example", "racey", "1.0.0", "jar", None);

        // Tiny HTTP server returning a fixed payload on every connection.
        let payload = b"atomic-put-and-index-payload".to_vec();
        let payload_for_server = payload.clone();
        let server = StubServer::start(move |_| Response::new(200, payload_for_server.clone()));
        let addr = server.addr();
        let stop = Arc::new(AtomicBool::new(false));

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
            ..Default::default()
        };

        // Run several fetches back-to-back so we have multiple chances to
        // race against the GC loop.
        for _ in 0..6 {
            let blob = fetch_stream_to_store_and_index(
                &client, &url, None, None, &cfg, None, &store, &key, None,
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
        server.stop();
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
                ..Default::default()
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
        use super::classify_response_status_with_headers;
        use reqwest::StatusCode;
        use url::Url;

        let url = Url::parse("https://repo.example/path").unwrap();
        let err = classify_response_status_with_headers(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            &url,
            None,
        )
        .unwrap_err();
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
            ..Default::default()
        };

        let result = fetch_text(&client, &url, None, None, &cfg).await;
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
            ..Default::default()
        };

        let result = fetch_text(&client, &url, None, None, &cfg).await;
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
        use rv_test_support::http::{Response, StubServer};
        use url::Url;

        let payload = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  foo.jar\n";
        let server = StubServer::start(move |_| Response::new(200, payload));
        let addr = server.addr();

        let url = Url::parse(&format!("http://{addr}/foo.jar.sha1")).expect("url");
        let client = Client::builder().build().expect("client");
        let cfg = FetchConfig {
            retries: 0,
            timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        };

        let text = fetch_text(&client, &url, None, None, &cfg)
            .await
            .expect("small sidecar fetch");
        server.stop();
        assert_eq!(text, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  foo.jar");
    }

    /// Serve one chunked 200 response per connection.
    /// Send `chunks` bodies of `chunk_len` bytes, `gap` apart; `hang` leaves the response open.
    /// Return the URL and a connection counter.
    async fn spawn_chunked_server(
        chunks: usize,
        chunk_len: usize,
        gap: std::time::Duration,
        hang: bool,
    ) -> (url::Url, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                hits_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut seen = Vec::new();
                    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => seen.extend_from_slice(&buf[..n]),
                        }
                    }
                    let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
                    if sock.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for _ in 0..chunks {
                        let mut frame = format!("{chunk_len:x}\r\n").into_bytes();
                        frame.extend(std::iter::repeat_n(b'x', chunk_len));
                        frame.extend_from_slice(b"\r\n");
                        if sock.write_all(&frame).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(gap).await;
                    }
                    if hang {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    } else {
                        let _ = sock.write_all(b"0\r\n\r\n").await;
                    }
                });
            }
        });
        let url =
            url::Url::parse(&format!("http://{addr}/org/ex/big/1.0/big-1.0.jar")).expect("url");
        (url, hits)
    }

    /// First connection trickles; a retry can serve the same body immediately.
    /// Keep the first response open so a successful retry proves a new socket.
    async fn spawn_low_speed_server(
        fast_retry: bool,
    ) -> (
        url::Url,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let close_seen = Arc::new(AtomicBool::new(false));
        let server_hits = hits.clone();
        let server_close = close_seen.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let attempt = server_hits.fetch_add(1, Ordering::SeqCst);
                let close = server_close.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        let n = socket.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..n]);
                    }
                    if attempt > 0 {
                        close.store(
                            String::from_utf8_lossy(&request)
                                .to_ascii_lowercase()
                                .contains("connection: close\r\n"),
                            Ordering::SeqCst,
                        );
                    }
                    if socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if attempt > 0 && fast_retry {
                        let _ = socket.write_all(&[b'x'; 10000]).await;
                    } else {
                        for _ in 0..100 {
                            if socket.write_all(&[b'x'; 100]).await.is_err() {
                                return;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                });
            }
        });
        (
            url::Url::parse(&format!("http://{addr}/big.jar")).unwrap(),
            hits,
            close_seen,
        )
    }

    #[tokio::test]
    async fn low_speed_exhausts_retries_on_the_verified_path() {
        low_speed_case(false, false).await;
    }

    #[tokio::test]
    async fn low_speed_retries_on_a_new_connection_on_the_verified_path() {
        low_speed_case(false, true).await;
    }

    #[tokio::test]
    async fn low_speed_exhausts_retries_on_the_indexed_path() {
        low_speed_case(true, false).await;
    }

    #[tokio::test]
    async fn low_speed_retries_on_a_new_connection_on_the_indexed_path() {
        low_speed_case(true, true).await;
    }

    async fn low_speed_case(indexed: bool, fast_retry: bool) {
        use super::{FetchConfig, fetch_stream_to_store_and_index, fetch_stream_to_store_verified};
        use std::{sync::atomic::Ordering, time::Duration};
        let dir = tempfile::tempdir().unwrap();
        let store = rv_store::Store::open(dir.path()).unwrap();
        let (url, hits, close) = spawn_low_speed_server(fast_retry).await;
        let cfg = FetchConfig {
            retries: 1,
            timeout: Duration::from_secs(5),
            low_speed_limit: 10000,
            low_speed_time: Duration::from_millis(300),
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let key = big_key();
        let result = tokio::time::timeout(Duration::from_secs(6), async {
            if indexed {
                fetch_stream_to_store_and_index(
                    &client, &url, None, None, &cfg, None, &store, &key, None,
                )
                .await
            } else {
                fetch_stream_to_store_verified(&client, &url, None, None, &cfg, None, &store, None)
                    .await
            }
        })
        .await
        .expect("bounded retries");
        if fast_retry {
            let blob = result.expect("fast second connection succeeds");
            assert_eq!(
                std::fs::read(store.get_path(&blob)).unwrap(),
                vec![b'x'; 10000]
            );
            if indexed {
                assert_eq!(store.lookup_artifact(&key).await.unwrap(), Some(blob));
            }
        } else {
            let message = result.unwrap_err().to_string();
            for expected in [
                "artifact download too slow",
                "bytes/s",
                "0.300s",
                "RV_LOW_SPEED_LIMIT",
                "RV_LOW_SPEED_TIME",
                url.as_str(),
            ] {
                assert!(message.contains(expected), "{message}");
            }
            if indexed {
                assert!(message.contains("org.ex:big"), "{message}");
            }
            assert_eq!(store.lookup_artifact(&key).await.unwrap(), None);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(
            close.load(Ordering::SeqCst),
            "retry requests Connection: close"
        );
        assert_eq!(
            std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
            0
        );
    }

    #[tokio::test]
    async fn low_speed_allows_above_floor_disabled_and_small_bodies() {
        use super::{FetchConfig, fetch_stream_to_store_verified};
        use std::{sync::atomic::Ordering, time::Duration};
        // The first two outlast the window. The tiny body finishes before it.
        for (limit, chunks, size) in [(1000, 12, 1000), (0, 12, 1), (100000, 1, 2048)] {
            let dir = tempfile::tempdir().unwrap();
            let store = rv_store::Store::open(dir.path()).unwrap();
            let (url, hits) =
                spawn_chunked_server(chunks, size, Duration::from_millis(40), false).await;
            let cfg = FetchConfig {
                retries: 0,
                timeout: Duration::from_secs(5),
                low_speed_limit: limit,
                low_speed_time: Duration::from_millis(200),
                ..Default::default()
            };
            let blob = fetch_stream_to_store_verified(
                &reqwest::Client::new(),
                &url,
                None,
                None,
                &cfg,
                None,
                &store,
                None,
            )
            .await
            .unwrap();
            assert_eq!(
                std::fs::metadata(store.get_path(&blob)).unwrap().len(),
                (chunks * size) as u64
            );
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn low_speed_ignores_store_backpressure_and_eof_commit() {
        use super::{FetchConfig, artifact_body_stream};
        use futures::StreamExt;
        use std::{
            sync::{
                Arc,
                atomic::{AtomicBool, AtomicU64},
            },
            time::Duration,
        };
        let raw = futures::stream::unfold(0, |n| async move {
            if n == 3 {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((Ok(bytes::Bytes::from_static(b"xx")), n + 1))
        });
        let cfg = FetchConfig {
            timeout: Duration::from_secs(100),
            low_speed_limit: 1,
            low_speed_time: Duration::from_secs(2),
            ..Default::default()
        };
        let (mut stream, idle) = artifact_body_stream(
            Box::pin(raw),
            " test.jar".into(),
            &cfg,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(false)),
        );
        idle.run(async move {
            // Store creation and writes each take much longer than the window.
            tokio::time::sleep(Duration::from_secs(10)).await;
            for _ in 0..3 {
                stream.next().await.unwrap()?;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            assert!(stream.next().await.is_none());
            tokio::time::sleep(Duration::from_secs(200)).await;
            Ok(())
        })
        .await
        .expect("store time must not lower network throughput or cancel commit");
    }

    #[tokio::test(start_paused = true)]
    async fn low_speed_window_forgets_fast_start_and_wakes_without_bytes() {
        use futures::StreamExt;
        use std::time::Duration;
        let raw = futures::stream::once(async { Ok(bytes::Bytes::from(vec![0; 100000])) })
            .chain(futures::stream::pending());
        let mut stream = super::low_speed_body_stream(
            Box::pin(raw),
            " big.jar".into(),
            1000,
            Duration::from_secs(2),
        );
        stream.next().await.unwrap().unwrap();
        let start = tokio::time::Instant::now();
        let error = stream.next().await.unwrap().unwrap_err();
        assert!(error.to_string().contains("0 bytes/s"), "{error}");
        // Tokio timers round up to milliseconds. Detection is within one
        // sample interval of a full window, including that timer granularity.
        assert!(start.elapsed() >= Duration::from_secs(2));
        assert!(start.elapsed() <= Duration::from_millis(2070));
    }

    #[tokio::test]
    async fn low_speed_excludes_initial_header_wait() {
        use super::{FetchConfig, fetch_stream_to_store_verified};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = url::Url::parse(&format!(
            "http://{}/tiny.pom",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n")
                .await
                .unwrap();
            socket.write_all(&[b'x'; 2048]).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let store = rv_store::Store::open(dir.path()).unwrap();
        let cfg = FetchConfig {
            retries: 0,
            timeout: Duration::from_secs(5),
            low_speed_limit: 100000,
            low_speed_time: Duration::from_millis(200),
            ..Default::default()
        };
        let blob = fetch_stream_to_store_verified(
            &reqwest::Client::new(),
            &url,
            None,
            None,
            &cfg,
            None,
            &store,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::metadata(store.get_path(&blob)).unwrap().len(),
            2048
        );
        server.await.unwrap();
    }

    fn big_key() -> rv_config::ArtifactKey {
        rv_config::ArtifactKey::new("org.ex", "big", "1.0", "jar", None)
    }

    /// A transfer may exceed `timeout` overall if no idle gap exceeds it.
    #[tokio::test]
    async fn artifact_stream_outlasting_timeout_succeeds_while_data_flows() {
        use super::{FetchConfig, fetch_stream_to_store_and_index};
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = rv_store::Store::open(dir.path()).expect("open");
        let (url, _) = spawn_chunked_server(10, 1024, Duration::from_millis(250), false).await;
        let cfg = FetchConfig {
            retries: 0,
            timeout: Duration::from_millis(800),
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let client = reqwest::Client::new();
        let blob = fetch_stream_to_store_and_index(
            &client,
            &url,
            None,
            None,
            &cfg,
            None,
            &store,
            &big_key(),
            None,
        )
        .await
        .expect("slow but steady download must succeed");
        assert!(
            started.elapsed() > cfg.timeout,
            "transfer must outlast the timeout"
        );
        let len = std::fs::metadata(store.get_path(&blob))
            .expect("blob")
            .len();
        assert_eq!(len, 10 * 1024);
    }

    /// A body that goes silent fails with a timeout error naming the artifact.
    #[tokio::test]
    async fn artifact_stream_stall_reports_timeout_and_artifact() {
        use super::{FetchConfig, fetch_stream_to_store_and_index};
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = rv_store::Store::open(dir.path()).expect("open");
        let (url, _) = spawn_chunked_server(1, 16, Duration::from_millis(10), true).await;
        let cfg = FetchConfig {
            retries: 0,
            timeout: Duration::from_millis(400),
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let err = fetch_stream_to_store_and_index(
            &client,
            &url,
            None,
            None,
            &cfg,
            None,
            &store,
            &big_key(),
            None,
        )
        .await
        .expect_err("stalled body must fail");
        let msg = format!("{err:?}");
        assert!(msg.contains("timed out"), "{msg}");
        assert!(msg.contains("org.ex:big"), "must name the artifact: {msg}");
    }

    /// The body deadline must remain active while the store awaits filesystem work.
    /// Bound the blocking pool and release it after failure so runtime shutdown cannot hang.
    #[test]
    fn artifact_idle_timeout_covers_a_blocked_store_and_retries() {
        use super::{FetchConfig, fetch_stream_to_store_and_index, fetch_stream_to_store_verified};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for indexed in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let store = rv_store::Store::open(dir.path()).unwrap();
                let (url, hits) = spawn_chunked_server(0, 16, Duration::ZERO, true).await;
                let cfg = FetchConfig {
                    retries: 1,
                    timeout: Duration::from_millis(200),
                    ..Default::default()
                };
                let client = reqwest::Client::new();
                let (release, blocked) = std::sync::mpsc::channel();
                let (entered, started) = tokio::sync::oneshot::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    entered.send(()).unwrap();
                    blocked.recv().unwrap();
                });
                started.await.unwrap();
                let key = big_key();
                let outcome = tokio::time::timeout(Duration::from_secs(4), async {
                    if indexed {
                        fetch_stream_to_store_and_index(
                            &client, &url, None, None, &cfg, None, &store, &key, None,
                        )
                        .await
                    } else {
                        fetch_stream_to_store_verified(
                            &client, &url, None, None, &cfg, None, &store, None,
                        )
                        .await
                    }
                })
                .await;
                release.send(()).unwrap();
                blocker.await.unwrap();
                let error = outcome
                    .expect("idle timeout must not depend on the store polling the body")
                    .expect_err("the body never arrives");
                assert!(
                    error.to_string().contains("timed out: no data received"),
                    "{error}"
                );
                assert!(error.to_string().contains(url.as_str()), "{error}");
                assert_eq!(hits.load(Ordering::SeqCst), 1 + cfg.retries);
                assert_eq!(store.lookup_artifact(&key).await.unwrap(), None);
            }
        });
    }

    /// EOF must disable the network deadline before a queued store commit.
    /// Another store user may hold the publication lock longer than the network timeout.
    #[tokio::test]
    async fn artifact_idle_timeout_does_not_cancel_commit_after_eof() {
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let store = rv_store::Store::open(dir.path()).unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join(".lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        let (url, _) = spawn_chunked_server(1, 16, Duration::ZERO, false).await;
        let cfg = super::FetchConfig {
            retries: 0,
            timeout: Duration::from_millis(200),
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let key = big_key();
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                super::fetch_stream_to_store_and_index(
                    &client, &url, None, None, &cfg, None, &store, &key, None,
                ),
                async {
                    tokio::time::sleep(cfg.timeout * 3).await;
                    fs2::FileExt::unlock(&lock).unwrap();
                }
            )
        })
        .await
        .expect("commit must complete after releasing the store lock");
        let blob = result.expect("EOF must disarm the network deadline before publication");
        assert_eq!(store.lookup_artifact(&key).await.unwrap(), Some(blob));
    }

    #[tokio::test]
    async fn stalled_headers_exhaust_retries_on_the_verified_path() {
        stalled_body_case(false, 0).await;
    }

    #[tokio::test]
    async fn stalled_partial_body_exhausts_retries_on_the_verified_path() {
        stalled_body_case(false, 1).await;
    }

    #[tokio::test]
    async fn stalled_headers_exhaust_retries_on_the_indexed_path() {
        stalled_body_case(true, 0).await;
    }

    #[tokio::test]
    async fn stalled_partial_body_exhausts_retries_on_the_indexed_path() {
        stalled_body_case(true, 1).await;
    }

    /// Headers alone, or a partial body, must time out on every attempt.
    /// Both store paths must leave no blob or coordinate after failure.
    /// An outer deadline bounds the test.
    async fn stalled_body_case(indexed: bool, chunks: usize) {
        use super::{FetchConfig, fetch_stream_to_store_and_index, fetch_stream_to_store_verified};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = rv_store::Store::open(dir.path()).expect("store");
        let (url, hits) = spawn_chunked_server(chunks, 16, Duration::ZERO, true).await;
        let cfg = FetchConfig {
            retries: 2,
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let key = big_key();
        let error = tokio::time::timeout(Duration::from_secs(10), async {
            if indexed {
                fetch_stream_to_store_and_index(
                    &client, &url, None, None, &cfg, None, &store, &key, None,
                )
                .await
            } else {
                fetch_stream_to_store_verified(&client, &url, None, None, &cfg, None, &store, None)
                    .await
            }
        })
        .await
        .expect("stalled downloads must not hang")
        .expect_err("all attempts stall");
        let message = error.to_string();
        assert!(message.contains("timed out: no data received"), "{message}");
        assert!(message.contains(url.as_str()), "{message}");
        if indexed {
            assert!(message.contains("org.ex:big"), "{message}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1 + cfg.retries);
        assert_eq!(store.lookup_artifact(&key).await.unwrap(), None);
        assert_eq!(
            std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
            0
        );
    }

    /// Exceeding the body cap must report `RV_MAX_ARTIFACT_SIZE` without retrying.
    #[tokio::test]
    async fn artifact_stream_over_cap_reports_limit_and_is_not_retried() {
        use super::{FetchConfig, fetch_stream_to_store_verified};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = rv_store::Store::open(dir.path()).expect("open");
        let (url, hits) = spawn_chunked_server(8, 1024, Duration::from_millis(1), false).await;
        let cfg = FetchConfig {
            retries: 2,
            timeout: Duration::from_secs(5),
            max_artifact_size: 2048,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let err =
            fetch_stream_to_store_verified(&client, &url, None, None, &cfg, None, &store, None)
                .await
                .expect_err("over-cap body must fail");
        let msg = format!("{err:?}");
        assert!(msg.contains("size limit of 2048"), "{msg}");
        assert!(msg.contains("RV_MAX_ARTIFACT_SIZE"), "{msg}");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "cap violations must not be retried"
        );
    }

    #[cfg(windows)]
    #[test]
    fn checked_repository_entry_rejects_a_replaced_final_symlink() {
        use super::open_checked_repository_entry;
        use std::os::windows::fs::symlink_file;

        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path().join("entry");
        let target = dir.path().join("target");
        std::fs::write(&entry, b"original").unwrap();
        std::fs::write(&target, b"replacement").unwrap();
        assert!(open_checked_repository_entry(&entry).is_ok());
        std::fs::remove_file(&entry).unwrap();
        if let Err(err) = symlink_file(&target, &entry) {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("create symlink: {err}");
        }
        assert!(open_checked_repository_entry(&entry).is_err());
    }

    /// Both directory and final-component links must fail through every local
    /// read entry point, before bytes can enter the content store.
    #[cfg(unix)]
    #[tokio::test]
    async fn local_reads_confine_directory_and_final_symlinks() {
        use super::{
            FetchConfig, fetch_bytes, fetch_stream_to_store_and_index,
            fetch_stream_to_store_verified, fetch_text,
        };
        use reqwest::Client;
        use rv_config::{ArtifactKey, BlobId};
        use rv_store::Store;
        use std::os::unix::fs::symlink;
        use url::Url;

        for directory_link in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("repo");
            let outside = tmp.path().join("repo-outside");
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(&outside).unwrap();
            let secret = b"outside repository bytes";
            std::fs::write(outside.join("a.jar"), secret).unwrap();
            if directory_link {
                symlink(&outside, root.join("g")).unwrap();
            } else {
                std::fs::create_dir(root.join("g")).unwrap();
                symlink(outside.join("a.jar"), root.join("g/a.jar")).unwrap();
            }
            let root_url = Url::from_directory_path(&root).unwrap();
            let url = root_url.join("g/a.jar").unwrap();
            let client = Client::new();
            let config = FetchConfig::default();
            let store = Store::open(&tmp.path().join("store")).unwrap();
            let key = ArtifactKey::new("g", "a", "1", "jar", None);
            assert!(
                fetch_bytes(&client, &url, Some(&root_url), None, &config, None)
                    .await
                    .is_err()
            );
            assert!(
                fetch_text(&client, &url, Some(&root_url), None, &config)
                    .await
                    .is_err()
            );
            assert!(
                fetch_stream_to_store_verified(
                    &client,
                    &url,
                    Some(&root_url),
                    None,
                    &config,
                    None,
                    &store,
                    None
                )
                .await
                .is_err()
            );
            assert!(
                fetch_stream_to_store_and_index(
                    &client,
                    &url,
                    Some(&root_url),
                    None,
                    &config,
                    None,
                    &store,
                    &key,
                    None
                )
                .await
                .is_err()
            );
            assert!(!store.exists_async(&BlobId::from_bytes(secret)).await);
        }
    }

    #[tokio::test]
    async fn local_reads_require_a_containing_repository_root() {
        use super::open_local_file;
        use crate::RepoError;
        use url::Url;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let outside = tmp.path().join("secret");
        std::fs::write(&outside, b"secret").unwrap();
        let root_url = Url::from_directory_path(&root).unwrap();
        let url = Url::from_file_path(&outside).unwrap();
        assert!(matches!(
            open_local_file(&url, None).await,
            Err(RepoError::InvalidCoord(_))
        ));
        assert!(matches!(
            open_local_file(&url, Some(&root_url)).await,
            Err(RepoError::InvalidCoord(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_repository_root_itself_may_be_a_symlink() {
        use super::read_local_bytes;
        use url::Url;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("a.jar"), b"inside").unwrap();
        let link = tmp.path().join("root-link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        let root_url = Url::from_directory_path(&link).unwrap();
        let url = root_url.join("a.jar").unwrap();
        let bytes = read_local_bytes(&url, Some(&root_url), 100, None)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"inside");
    }

    /// `file://` artifacts go through the same size cap as HTTP ones.
    #[tokio::test]
    async fn local_file_artifact_honours_size_cap() {
        use super::{FetchConfig, fetch_stream_to_store_verified};
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = rv_store::Store::open(&dir.path().join("store")).expect("open");
        let file = dir.path().join("big.jar");
        std::fs::write(&file, vec![7u8; 4096]).expect("write");
        let url = url::Url::from_file_path(&file).expect("file url");
        let root = url::Url::from_directory_path(dir.path()).unwrap();
        let client = reqwest::Client::new();

        let small = FetchConfig {
            retries: 0,
            timeout: Duration::from_secs(5),
            max_artifact_size: 2048,
            ..Default::default()
        };
        let err = fetch_stream_to_store_verified(
            &client,
            &url,
            Some(&root),
            None,
            &small,
            None,
            &store,
            None,
        )
        .await
        .expect_err("over-cap file must fail");
        assert!(format!("{err:?}").contains("size limit of 2048"), "{err:?}");

        let ok = FetchConfig {
            max_artifact_size: 4096,
            ..small
        };
        fetch_stream_to_store_verified(&client, &url, Some(&root), None, &ok, None, &store, None)
            .await
            .expect("file within cap is stored");
    }
}
