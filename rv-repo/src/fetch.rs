use std::collections::VecDeque;
use std::fs::File;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use reqwest::header::HeaderMap;
use reqwest::{Client, StatusCode};
use url::Url;

use crate::auth::Auth;
use crate::error::{IntegritySource, RepoError, Result};
use rv_config::{redact_url, redacted_url};
use rv_http::body::{BodyError, read_limited};
use rv_http::retry::{Cooldowns, Outcome, RetryPolicy};
use rv_http::transient::{
    TunnelRefusal, status_is_transient, transport_is_lookup_failure, transport_is_retryable,
};
use rv_maven_types::{ArtifactCoord, Digest, HashAlgorithm};
use rv_store::{Expect, Expectation, PutError, Staged, Store, Verified};

/// How one attempt of a repository request failed, for the shared retry
/// rule in [`rv_http::retry`].
type RetryError = Outcome<RepoError>;

fn request_error(error: reqwest::Error, url: &Url) -> RetryError {
    if let Some((kind, details)) = crate::transport::redirect_rejection_from_reqwest(&error) {
        return RetryError::permanent(RepoError::RedirectRejected { kind, details });
    }

    // A 407 to the `CONNECT` of an `https:` URL is the proxy's refusal, as a
    // 407 answer to a plain `http:` request is.
    match rv_http::transient::tunnel_refusal(&error) {
        Some(TunnelRefusal::AuthRequired) => {
            return RetryError::permanent(RepoError::Unauthorized {
                status: StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                url: redact_url(url),
                sent: None,
            });
        }
        Some(TunnelRefusal::Refused) => {
            return RetryError::permanent(RepoError::ProxyTunnelRefused(redact_url(url)));
        }
        None => {}
    }

    // Strip and reattach a redacted URL so the rendered error never exposes
    // userinfo or presigned query tokens through Debug/Display.
    let error = error.without_url().with_url(redacted_url(url));
    if transport_is_retryable(&error) {
        RetryError::transient(RepoError::Http(error))
    } else if transport_is_lookup_failure(&error) {
        RetryError::Unresolved(RepoError::Http(error))
    } else {
        RetryError::permanent(RepoError::Http(error))
    }
}

#[derive(Clone)]
pub(crate) struct FetchConfig {
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
    /// Shared by every request of a run, see [`rv_http::retry::Cooldown`].
    pub cooldowns: Arc<Cooldowns>,
    /// Told of every retry, checksum sidecars' included.
    pub progress: Option<Arc<dyn FetchProgress>>,
}

impl Default for FetchConfig {
    fn default() -> Self {
        let network = rv_config::NetworkConfig::default();
        Self {
            retries: network.retries,
            timeout: Duration::from_secs(network.timeout),
            max_artifact_size: network.max_artifact_size,
            low_speed_limit: network.low_speed_limit,
            low_speed_time: Duration::from_secs(network.low_speed_time),
            cooldowns: Arc::default(),
            progress: None,
        }
    }
}

/// Receives download progress from a [`crate::RepoClient`] built with
/// [`crate::RepoClient::with_progress`]. Every method has an empty default.
///
/// Transfers run concurrently, so calls for different URLs interleave, and
/// [`FetchProgress::on_chunk`] does not say which transfer the bytes belong
/// to. The `url` passed is the request URL after [`rv_config::redact_url`],
/// with userinfo removed and any query masked.
pub trait FetchProgress: Send + Sync {
    /// A response arrived for `url`, or a `file:` read began. `total` is
    /// its `Content-Length` (the file size for `file:`), when known. Called
    /// again for each retry, after the failed attempt's
    /// [`FetchProgress::on_finish`].
    fn on_start(&self, _url: &str, _total: Option<u64>) {}
    /// `bytes` more of a body arrived: metadata, a POM, a sidecar or an
    /// artifact streaming into the store.
    fn on_chunk(&self, _bytes: usize) {}
    /// The transfer [`FetchProgress::on_start`] began for `url` ended, once
    /// per `on_start`: `Some(total)` when the body is complete (`total`
    /// bytes, verified when it was an artifact), `None` when it failed or
    /// was cancelled.
    fn on_finish(&self, _url: &str, _total: Option<usize>) {}
    /// A request for `url` failed with `error` and is sent again after
    /// `wait`, as attempt `attempt` of at most `attempts`. Also called for
    /// checksum sidecars, which report no transfers.
    fn on_retry(
        &self,
        _url: &str,
        _error: &RepoError,
        _wait: Duration,
        _attempt: usize,
        _attempts: usize,
    ) {
    }
}

/// One transfer as a [`FetchProgress`] sees it: `on_start` when it begins
/// and `on_finish` exactly once, with `None` when it is dropped unfinished,
/// as on an error or a cancelled request.
pub(crate) struct Transfer {
    progress: Option<Arc<dyn FetchProgress>>,
    url: String,
    finished: bool,
}

impl Transfer {
    fn start(progress: Option<&Arc<dyn FetchProgress>>, url: &Url, total: Option<u64>) -> Self {
        let url = progress.map(|_| redact_url(url)).unwrap_or_default();
        if let Some(progress) = progress {
            progress.on_start(&url, total);
        }
        Self {
            progress: progress.cloned(),
            url,
            finished: false,
        }
    }

    pub(crate) fn arrived(
        progress: Option<&Arc<dyn FetchProgress>>,
        url: &Url,
        total: u64,
    ) -> Self {
        let transfer = Self::start(progress, url, Some(total));
        transfer.chunk(total as usize);
        transfer
    }

    fn chunk(&self, bytes: usize) {
        if let Some(progress) = &self.progress {
            progress.on_chunk(bytes);
        }
    }

    fn finish(mut self, total: usize) {
        self.finished = true;
        if let Some(progress) = &self.progress {
            progress.on_finish(&self.url, Some(total));
        }
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        if !self.finished
            && let Some(progress) = &self.progress
        {
            progress.on_finish(&self.url, None);
        }
    }
}

const MAX_METADATA_SIZE: u64 = 20 * 1024 * 1024; // 20MB
/// Checksum sidecars (`.sha256`, `.sha1`, `.md5`) carry a single hex token plus an
/// optional filename, a few dozen bytes in practice. `fetch_text` is only
/// ever used to pull these sidecars, so it gets a tight dedicated cap rather
/// than sharing the 20MB metadata limit; this bounds buffering and the
/// whitespace scan in `parse_checksum` against a hostile or oversized
/// sidecar.
const MAX_CHECKSUM_SIZE: u64 = 4 * 1024; // 4KB

/// Classifies an HTTP status into permanent/transient; a 401 or 403 names
/// the credential `auth` sent. On 429/502/503/504 the
/// `Retry-After` header (delta-seconds or HTTP-date, per RFC 9110 §10.2.3)
/// is parsed and attached so the backoff layer sleeps at least that long.
fn classify_response_status_with_headers(
    status: StatusCode,
    url: &Url,
    headers: Option<&HeaderMap>,
    auth: Option<&Auth>,
) -> std::result::Result<(), RetryError> {
    if status.is_success() {
        return Ok(());
    }
    let url = redact_url(url);
    Err(match status {
        StatusCode::NOT_FOUND => {
            RetryError::permanent(RepoError::NotFound(format!("{url} (HTTP 404)")))
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            RetryError::permanent(RepoError::Unauthorized {
                status,
                url,
                sent: auth.map(|auth| Box::new(auth.sent.clone())),
            })
        }
        StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
            RetryError::permanent(RepoError::Unauthorized {
                status,
                url,
                sent: None,
            })
        }
        _ if status_is_transient(status) => {
            let retry_after = headers.and_then(rv_http::headers::retry_after);
            RetryError::Busy {
                error: RepoError::HttpStatus {
                    status,
                    url,
                    retry_after,
                },
                retry_after,
            }
        }
        _ => RetryError::permanent(RepoError::HttpStatus {
            status,
            url,
            retry_after: None,
        }),
    })
}

/// The most of an error response's body that is read and dropped so its
/// connection can carry the next request. A longer body, or one slower
/// than [`ERROR_BODY_DRAIN_TIME`], closes the connection instead.
const MAX_DRAINED_ERROR_BODY: u64 = 64 * 1024;
const ERROR_BODY_DRAIN_TIME: Duration = Duration::from_secs(2);

/// Read and drop the body of an error response, so an HTTP/1 connection
/// goes back to the pool instead of closing, as dropping an unread body
/// would. A 404 for a missing `.sha256` would otherwise cost a new
/// connection, with its DNS lookup and TLS handshake. The body is server
/// text and is never looked at.
async fn drain_error_body(response: reqwest::Response) {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_DRAINED_ERROR_BODY)
    {
        return;
    }
    let _ = tokio::time::timeout(
        ERROR_BODY_DRAIN_TIME,
        read_limited(response, MAX_DRAINED_ERROR_BODY, |_| {}),
    )
    .await;
}

async fn execute_retry<F, Fut, T>(config: &FetchConfig, url: &Url, op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, RetryError>>,
{
    let mut retries = 0;
    let result = rv_http::retry::run(
        &RetryPolicy::new(config.retries, config.timeout),
        &config.cooldowns.of(url),
        op,
        |error, wait| {
            retries += 1;
            // A prefetch prints too: the read that needs the file joins it
            // and waits out the same retries.
            if let Some(progress) = &config.progress {
                let attempts = config.retries.saturating_add(1);
                progress.on_retry(&redact_url(url), error, wait, retries + 1, attempts);
            }
        },
    )
    .await;
    result.map_err(|error| {
        if retries == 0 || !error.is_transient() {
            return error;
        }
        RepoError::Retried {
            attempts: retries + 1,
            error: Box::new(error),
        }
    })
}

/// What a bounded read takes: the limit and the name its size error uses.
struct Bounded {
    limit: u64,
    what: &'static str,
}

const METADATA: Bounded = Bounded {
    limit: MAX_METADATA_SIZE,
    what: "metadata",
};

const SIDECAR: Bounded = Bounded {
    limit: MAX_CHECKSUM_SIZE,
    what: "checksum sidecar",
};

pub(crate) async fn fetch_bytes(
    client: &Client,
    url: &Url,
    repository_root: Option<&Url>,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&Arc<dyn FetchProgress>>,
) -> Result<Bytes> {
    fetch_bounded(
        client,
        url,
        repository_root,
        auth,
        config,
        METADATA,
        progress,
    )
    .await
}

async fn fetch_bounded(
    client: &Client,
    url: &Url,
    repository_root: Option<&Url>,
    auth: Option<&Auth>,
    config: &FetchConfig,
    bounded: Bounded,
    progress: Option<&Arc<dyn FetchProgress>>,
) -> Result<Bytes> {
    if url.scheme() == "file" {
        return read_local_bytes(url, repository_root, bounded.limit, progress).await;
    }
    execute_retry(config, url, || async {
        let mut request = client.get(url.as_str()).timeout(config.timeout);
        if let Some(auth) = auth {
            request = auth.apply(request);
        }
        let response = request
            .send()
            .await
            .map_err(|error| request_error(error, url))?;

        let content_length = response.content_length();
        if let Err(error) = classify_response_status_with_headers(
            response.status(),
            url,
            Some(response.headers()),
            auth,
        ) {
            drain_error_body(response).await;
            return Err(error);
        }

        let transfer = Transfer::start(progress, url, content_length);
        let bytes = read_limited(response, bounded.limit, |len| transfer.chunk(len))
            .await
            .map_err(|error| match error {
                BodyError::Transport(error) => request_error(error, url),
                BodyError::TooLarge { limit, declared } => {
                    RetryError::permanent(RepoError::TooLarge {
                        subject: format!("{} at {}", bounded.what, redact_url(url)),
                        limit,
                        declared,
                        setting: None,
                    })
                }
            })?;
        transfer.finish(bytes.len());
        Ok(bytes)
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
fn download_context(coordinate: Option<&ArtifactCoord>, url: &Url) -> String {
    let url = redact_url(url);
    match coordinate {
        Some(coordinate) => format!(" while downloading {coordinate} from {url}"),
        None => format!(" while downloading {url}"),
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
    let path = rv_lock::file_url_path(url).ok_or_else(|| {
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
    .map_err(|err| RepoError::Internal(format!("local read task failed: {err}")))??;
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
    progress: Option<&Arc<dyn FetchProgress>>,
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
        return Err(RepoError::TooLarge {
            subject: path.display().to_string(),
            limit,
            declared: None,
            setting: None,
        });
    }
    let transfer = Transfer::start(progress, url, Some(bytes.len() as u64));
    transfer.chunk(bytes.len());
    transfer.finish(bytes.len());
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

/// Wait for response headers without imposing a deadline on the body.
async fn send_for_headers(
    request: reqwest::RequestBuilder,
    url: &Url,
    config: &FetchConfig,
) -> std::result::Result<reqwest::Response, RetryError> {
    match tokio::time::timeout(config.timeout, request.send()).await {
        Ok(result) => result.map_err(|error| request_error(error, url)),
        Err(_) => Err(RetryError::transient(RepoError::Transfer(
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "timed out after {}s waiting for response headers from {} \
                     (raise RAEVA_TIMEOUT)",
                    config.timeout.as_secs(),
                    redact_url(url)
                ),
            ),
        ))),
    }
}

/// How an artifact body failed before the store had all of it.
#[derive(Debug)]
enum BodyFault {
    Transfer(std::io::Error),
    TooLarge,
}

type ArtifactStream = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = std::result::Result<Bytes, BodyFault>> + Send>,
>;

struct ArtifactIdleDeadline {
    /// When the body last delivered data, `None` once it ended. The critical
    /// section only copies an Instant; it never covers I/O.
    activity: Arc<Mutex<Option<tokio::time::Instant>>>,
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
        operation: impl Future<Output = std::result::Result<T, PutError<BodyFault>>>,
    ) -> std::result::Result<T, PutError<BodyFault>> {
        let mut operation = std::pin::pin!(operation);
        let mut deadline = std::pin::pin!(tokio::time::sleep(self.timeout));
        std::future::poll_fn(|cx| {
            // Available data or completion takes precedence when the deadline is also ready.
            if let Poll::Ready(result) = operation.as_mut().poll(cx) {
                return Poll::Ready(result);
            }
            let last_data = *self.activity.lock().unwrap_or_else(|e| e.into_inner());
            // A timeout too large to add to an instant never fires.
            let Some(next) = last_data.and_then(|last| last.checked_add(self.timeout)) else {
                return Poll::Pending;
            };
            if deadline.deadline() != next {
                deadline.as_mut().reset(next);
            }
            if deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(PutError::Stream(BodyFault::Transfer(
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "timed out: no data received for {:?}{} (raise RAEVA_TIMEOUT)",
                            self.timeout, self.context
                        ),
                    ),
                ))));
            }
            Poll::Pending
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
        if matches!(item, Poll::Ready(None | Some(Err(_)))) {
            return item;
        }
        let bytes = match &item {
            Poll::Ready(Some(Ok(bytes))) => bytes.len() as u64,
            _ => 0,
        };
        if let Some(rate) = history.observe(elapsed, bytes)
            && rate < limit as f64
        {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "artifact download too slow{context}: {rate:.0} bytes/s over {:.3}s \
                     (minimum {limit} bytes/s); lower RAEVA_LOW_SPEED_LIMIT (0 disables) or \
                     raise RAEVA_LOW_SPEED_TIME, or set network.low_speed_limit / network.low_speed_time in raeva.toml",
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

/// Enforce the size cap, track body progress for the idle deadline and
/// report each chunk to `progress`. Return the deadline separately so it can
/// be polled even when the store is awaiting filesystem work rather than
/// polling this stream.
fn artifact_body_stream(
    raw_stream: ByteStream,
    context: String,
    config: &FetchConfig,
    progress: Option<Arc<dyn FetchProgress>>,
) -> (ArtifactStream, ArtifactIdleDeadline) {
    let limit = config.max_artifact_size;
    let mut raw_stream = low_speed_body_stream(
        raw_stream,
        context.clone(),
        config.low_speed_limit,
        config.low_speed_time,
    );
    let activity = Arc::new(Mutex::new(Some(tokio::time::Instant::now())));
    let idle = ArtifactIdleDeadline {
        activity: activity.clone(),
        timeout: config.timeout,
        context,
    };
    let mut read = 0u64;
    let stream = futures::stream::poll_fn(move |cx| {
        raw_stream.as_mut().poll_next(cx).map(|item| match item {
            Some(Ok(bytes)) => {
                read += bytes.len() as u64;
                if read > limit {
                    return Some(Err(BodyFault::TooLarge));
                }
                if !bytes.is_empty() {
                    *activity.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(tokio::time::Instant::now());
                    if let Some(progress) = &progress {
                        progress.on_chunk(bytes.len());
                    }
                }
                Some(Ok(bytes))
            }
            None => {
                *activity.lock().unwrap_or_else(|e| e.into_inner()) = None;
                None
            }
            Some(Err(error)) => Some(Err(BodyFault::Transfer(error))),
        })
    });
    (Box::pin(stream), idle)
}

/// What one artifact download must match, and the coordinate it is
/// recorded under.
#[derive(Clone, Copy, Default)]
pub(crate) struct ArtifactChecks<'a> {
    /// The repository's published checksum.
    pub(crate) sidecar: Option<&'a Digest>,
    /// The checksum raeva.lock pins.
    pub(crate) pin: Option<&'a Digest>,
    pub(crate) index: Option<&'a ArtifactCoord>,
}

/// Download an artifact into the store. The bytes are hashed while they are
/// written to a private temporary file and published, and indexed, only
/// when they match every checksum in `checks`; see
/// [`Store::put_stream_verified`].
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_artifact_into_store(
    client: &Client,
    url: &Url,
    repository_root: Option<&Url>,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&Arc<dyn FetchProgress>>,
    store: &Store,
    checks: ArtifactChecks<'_>,
) -> Result<Verified> {
    let sha1 = [checks.sidecar, checks.pin]
        .into_iter()
        .flatten()
        .any(|digest| digest.algorithm() == HashAlgorithm::Sha1);
    let (staged, transfer) = fetch_artifact_staged(
        client,
        url,
        repository_root,
        auth,
        config,
        progress,
        store,
        checks.index,
        sha1,
    )
    .await?;
    publish_artifact(url, transfer, store, staged, checks).await
}

/// Download an artifact into a private temporary file of the store,
/// hashed with SHA-256 and, with `sha1`, SHA-1, retrying as configured.
/// Nothing is published; see [`publish_artifact`], which also ends the
/// returned transfer. `index` only names the artifact in errors.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_artifact_staged(
    client: &Client,
    url: &Url,
    repository_root: Option<&Url>,
    auth: Option<&Auth>,
    config: &FetchConfig,
    progress: Option<&Arc<dyn FetchProgress>>,
    store: &Store,
    index: Option<&ArtifactCoord>,
    sha1: bool,
) -> Result<(Staged, Transfer)> {
    let attempts = AtomicU64::new(0);
    let local = url.scheme() == "file";
    execute_retry(config, url, || async {
        let retry = attempts.fetch_add(1, Ordering::Relaxed) != 0;
        let context = download_context(index, url);
        let (total, raw_stream) = if local {
            open_local_stream(url, repository_root)
                .await
                .map_err(RetryError::permanent)?
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

            let content_length = response.content_length();
            if let Err(error) = classify_response_status_with_headers(
                response.status(),
                url,
                Some(response.headers()),
                auth,
            ) {
                drain_error_body(response).await;
                return Err(error);
            }
            let http_context = context.clone();
            let stream: ByteStream = Box::pin(response.bytes_stream().map(move |chunk| {
                chunk.map_err(|error| {
                    // Keep the artifact and repository name on a mid-body
                    // transport failure.
                    // The cause as a transport error names it: h2's own text
                    // carries data the server chose.
                    let reason = match rv_http::transient::transport_detail(&error) {
                        Some(cause) => format!("{error}: {cause}"),
                        None => error.to_string(),
                    };
                    std::io::Error::other(format!("{reason}{http_context}"))
                })
            }));
            (content_length, stream)
        };
        let too_large = |declared| {
            RetryError::permanent(RepoError::TooLarge {
                subject: format!("artifact{context}"),
                limit: config.max_artifact_size,
                declared,
                setting: Some(rv_config::MAX_ARTIFACT_SIZE_ENV),
            })
        };
        if let Some(len) = total
            && len > config.max_artifact_size
        {
            return Err(too_large(Some(len)));
        }

        let transfer = Transfer::start(progress, url, total);
        let (body, idle) =
            artifact_body_stream(raw_stream, context.clone(), config, progress.cloned());
        match idle.run(store.stage_stream(body, sha1)).await {
            Ok(staged) => Ok((staged, transfer)),
            Err(PutError::Stream(BodyFault::TooLarge)) => Err(too_large(None)),
            Err(PutError::Stream(BodyFault::Transfer(err))) if local => {
                Err(RetryError::permanent(RepoError::Io(err)))
            }
            Err(PutError::Stream(BodyFault::Transfer(err))) => {
                Err(RetryError::transient(RepoError::Transfer(err)))
            }
            Err(PutError::Mismatch { .. }) => Err(RetryError::permanent(RepoError::Internal(
                "staging checks no checksum".to_string(),
            ))),
            Err(PutError::Store(err)) => Err(RetryError::permanent(RepoError::Store(err))),
        }
    })
    .await
}

/// Publish an artifact [`fetch_artifact_staged`] downloaded from `url`, if
/// it matches every checksum in `checks`, and index it under `checks.index`.
/// `transfer` ends complete only if it is published.
pub(crate) async fn publish_artifact(
    url: &Url,
    transfer: Transfer,
    store: &Store,
    staged: Staged,
    checks: ArtifactChecks<'_>,
) -> Result<Verified> {
    let expect = Expect {
        sidecar: checks.sidecar,
        pin: checks.pin,
    };
    match store
        .publish_staged::<std::convert::Infallible>(staged, expect, checks.index)
        .await
    {
        Ok(verified) => {
            transfer.finish(verified.size as usize);
            Ok(verified)
        }
        Err(PutError::Mismatch {
            against,
            expected,
            actual,
        }) => {
            let (subject, check) = match (against, checks.index) {
                (Expectation::Pin, Some(key)) => (
                    format!("{key} from {}", rv_config::redact_url(url.as_str())),
                    IntegritySource::LockPin,
                ),
                (Expectation::Pin, None) => (
                    redacted_url(url).path().to_string(),
                    IntegritySource::LockPin,
                ),
                (Expectation::Sidecar, _) => (
                    redacted_url(url).path().to_string(),
                    IntegritySource::Sidecar,
                ),
            };
            Err(RepoError::ChecksumMismatch {
                subject: subject.into(),
                artifact: checks.index.map(|key| Box::new(key.clone())),
                expected,
                actual,
                check,
            })
        }
        Err(PutError::Store(err)) => Err(RepoError::Store(err)),
        Err(PutError::Stream(never)) => match never {},
    }
}

/// Fetch a checksum sidecar (`.sha256`, `.sha1`, `.md5`) as trimmed UTF-8 text.
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
    let bytes = fetch_bounded(client, url, repository_root, auth, config, SIDECAR, None).await?;
    let text = std::str::from_utf8(&bytes).map_err(|err| {
        RepoError::InvalidMetadata(if url.scheme() == "file" {
            err.to_string()
        } else {
            format!("failed to decode response text from {}", redact_url(url))
        })
    })?;
    Ok(text.trim().to_string())
}

/// The `algorithm` digest a checksum sidecar holds, if it holds one.
/// Maven sidecars are a hex token, optionally followed by a filename.
pub(crate) fn parse_checksum(text: &str, algorithm: HashAlgorithm) -> Option<Digest> {
    text.split_whitespace()
        .find_map(|token| Digest::from_hex(algorithm, token).ok())
}

pub(crate) fn verify_checksum(bytes: &[u8], checksum: &Digest, path: &str) -> Result<()> {
    let actual = Digest::of_bytes(checksum.algorithm(), bytes);
    // The expected checksum here is fetched from a public sidecar (e.g.
    // `.sha256`) on the same repository as the artifact, so it is not a
    // secret: there is no timing-side-channel benefit to a constant-time
    // compare. Use plain equality.
    if actual == *checksum {
        Ok(())
    } else {
        Err(RepoError::ChecksumMismatch {
            subject: path.into(),
            artifact: None,
            expected: checksum.clone(),
            actual,
            check: IntegritySource::Sidecar,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rv_maven_types::{ArtifactCoord, BlobId};
    use rv_store::Store;
    use rv_test_support::http::{Response, StubServer};
    use tokio::io::AsyncWriteExt;
    use url::Url;

    use super::{
        ArtifactChecks, Digest, FetchConfig, FetchProgress, HashAlgorithm, MAX_CHECKSUM_SIZE,
        RetryError, classify_response_status_with_headers, fetch_artifact_into_store, fetch_text,
        parse_checksum, verify_checksum,
    };
    use crate::error::{IntegritySource, RepoError};

    fn client() -> reqwest::Client {
        rv_http::client_builder().build().expect("client")
    }

    fn config(retries: usize, timeout: Duration) -> FetchConfig {
        FetchConfig {
            retries,
            timeout,
            ..Default::default()
        }
    }

    fn big_key() -> ArtifactCoord {
        ArtifactCoord::new("org.ex", "big", "1.0", "jar", None)
    }

    /// Download into the store against `sidecar`, indexing under `key` when
    /// one is given.
    async fn fetch_into(
        url: &Url,
        root: Option<&Url>,
        cfg: &FetchConfig,
        store: &Store,
        key: Option<&ArtifactCoord>,
        sidecar: Option<&Digest>,
    ) -> crate::error::Result<BlobId> {
        let checks = ArtifactChecks {
            sidecar,
            pin: None,
            index: key,
        };
        fetch_artifact_into_store(&client(), url, root, None, cfg, None, store, checks)
            .await
            .map(|verified| verified.blob)
    }

    #[test]
    fn checksums_parse_and_verify() {
        let sha1 = parse_checksum(
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  file.jar",
            HashAlgorithm::Sha1,
        )
        .unwrap();
        assert_eq!(sha1.hex(), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        verify_checksum(b"hello", &sha1, "hello.txt").unwrap();
        let sha256 = parse_checksum(
            "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824  file.jar",
            HashAlgorithm::Sha256,
        )
        .unwrap();
        verify_checksum(b"hello", &sha256, "hello.txt").unwrap();

        // A `:` in the path, as on a Windows `file://` repository, keeps the
        // failure a sidecar one, with the sidecar's algorithm.
        let err = verify_checksum(b"other", &sha1, "/C:/repo/g/a/1/a-1.jar").unwrap_err();
        assert_eq!(
            err.class(),
            crate::ErrorClass::Integrity(IntegritySource::Sidecar)
        );
        let RepoError::ChecksumMismatch {
            expected, actual, ..
        } = err
        else {
            panic!("expected a checksum mismatch");
        };
        assert_eq!(expected, sha1);
        assert_eq!(actual, Digest::of_bytes(HashAlgorithm::Sha1, b"other"));
    }

    #[test]
    fn status_errors_are_redacted_and_classified() {
        use reqwest::StatusCode;
        use reqwest::header::{HeaderMap, HeaderValue};

        let url = Url::parse("https://alice:hunter2@repo.example/com/foo/1.0/foo.jar").unwrap();
        for status in [401, 403, 404, 407, 418, 503] {
            let status = StatusCode::from_u16(status).unwrap();
            let err = classify_response_status_with_headers(status, &url, None, None).unwrap_err();
            let rendered = format!("{err:?}");
            assert!(
                !rendered.contains("hunter2") && !rendered.contains("alice"),
                "{status}: {rendered}"
            );
        }
        let proxy_auth = classify_response_status_with_headers(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            &url,
            None,
            None,
        )
        .unwrap_err()
        .into_error()
        .to_string();
        assert!(
            !proxy_auth.contains("  ") && proxy_auth.contains("wants credentials: username"),
            "{proxy_auth}"
        );

        let mut headers = HeaderMap::new();
        headers.insert("Retry-After", HeaderValue::from_static("42"));
        let err = classify_response_status_with_headers(
            StatusCode::TOO_MANY_REQUESTS,
            &url,
            Some(&headers),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, RetryError::Busy { retry_after: Some(d), .. } if d == Duration::from_secs(42)),
            "{err:?}"
        );

        let url = Url::parse("https://u:pass@repo.example/m2/junit-4.13.2.jar?sig=abc").unwrap();
        let key = ArtifactCoord::new("junit", "junit", "4.13.2", "jar", None);
        let context = super::download_context(Some(&key), &url);
        assert!(
            context.contains("junit:junit:4.13.2:jar from "),
            "{context}"
        );
        for context in [context, super::download_context(None, &url)] {
            assert!(
                context.contains("repo.example/m2/junit-4.13.2.jar"),
                "{context}"
            );
            assert!(!context.contains("sig=abc") && !context.contains("pass"));
        }
    }

    /// Bytes that do not match the lock pin never enter the store and are
    /// not retried, and a blob the store already holds for
    /// another artifact keeps its bytes and index row.
    #[tokio::test]
    async fn mismatched_bytes_store_nothing_and_are_not_retried() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");
        let payload = b"shared-jar-contents".to_vec();
        let served = store.put_bytes(&payload).await.expect("put");
        let first_key = ArtifactCoord::new("com.example", "first", "1.0.0", "jar", None);
        store.add_artifact(&first_key, &served).await.unwrap();
        let server = StubServer::start(move |_| Response::new(200, payload.clone()));
        let url = Url::parse(&format!("http://{}/a.jar", server.addr())).expect("url");
        let key = ArtifactCoord::new("com.example", "a", "1.0.0", "jar", None);
        let wrong = Digest::Sha256("1".repeat(64).parse().unwrap());
        let cfg = config(2, Duration::from_secs(5));
        let checks = ArtifactChecks {
            pin: Some(&wrong),
            index: Some(&key),
            ..Default::default()
        };
        let result =
            fetch_artifact_into_store(&client(), &url, None, None, &cfg, None, &store, checks)
                .await;
        let Err(RepoError::ChecksumMismatch {
            subject,
            artifact,
            expected,
            actual,
            check: IntegritySource::LockPin,
        }) = result
        else {
            panic!("expected a lock pin mismatch, got {result:?}");
        };
        assert_eq!(
            &*subject,
            format!(
                "com.example:a:1.0.0:jar from {}",
                rv_config::redact_url(url.as_str())
            )
        );
        assert_eq!(artifact.as_deref(), Some(&key));
        assert_eq!((expected, actual), (wrong, Digest::Sha256(served.clone())));
        assert_eq!(server.answered(), 1);
        server.stop();
        assert_eq!(BlobId::from_file(&store.get_path(&served)).unwrap(), served);
        assert_eq!(
            store.lookup_artifact(&first_key).await.unwrap(),
            Some(served)
        );
        assert_eq!(store.lookup_artifact(&key).await.expect("lookup"), None);
    }

    #[derive(Default)]
    struct RecordedProgress(std::sync::Mutex<Vec<String>>, AtomicUsize);

    impl FetchProgress for RecordedProgress {
        fn on_start(&self, url: &str, total: Option<u64>) {
            self.0
                .lock()
                .unwrap()
                .push(format!("start {url} {total:?}"));
        }
        fn on_chunk(&self, bytes: usize) {
            self.1.fetch_add(bytes, Ordering::SeqCst);
        }
        fn on_finish(&self, url: &str, total: Option<usize>) {
            self.0
                .lock()
                .unwrap()
                .push(format!("finish {url} {total:?}"));
        }
    }

    /// Progress names the redacted URL, and every start ends in one finish:
    /// with the size when the bytes are stored, `None` when refused.
    #[tokio::test]
    async fn artifact_downloads_report_chunks_and_one_finish_per_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");
        let payload = vec![7u8; 100_000];
        let digest = Digest::Sha256(BlobId::from_bytes(&payload));
        let server = StubServer::start(move |_| Response::new(200, payload.clone()));
        let url = format!("http://user:secret@{}/a.jar?token=t0k", server.addr());
        let url = Url::parse(&url).expect("url");
        let shown = rv_config::redact_url(&url);
        let cfg = config(0, Duration::from_secs(5));
        let recorded = Arc::new(RecordedProgress::default());
        let progress: Arc<dyn FetchProgress> = recorded.clone();
        let wrong = Digest::Sha256("1".repeat(64).parse().unwrap());
        for pin in [&digest, &wrong] {
            let checks = ArtifactChecks {
                pin: Some(pin),
                ..Default::default()
            };
            let progress = Some(&progress);
            let _ = fetch_artifact_into_store(
                &client(),
                &url,
                None,
                None,
                &cfg,
                progress,
                &store,
                checks,
            )
            .await;
        }
        server.stop();
        assert!(!shown.contains("secret") && !shown.contains("t0k"));
        let start = format!("start {shown} Some(100000)");
        let events = [start.clone(), format!("finish {shown} Some(100000)"), start];
        let events = [&events[..], &[format!("finish {shown} None")]].concat();
        assert_eq!(*recorded.0.lock().unwrap(), events);
        assert_eq!(recorded.1.load(Ordering::SeqCst), 200_000);
    }

    #[tokio::test]
    async fn fetch_text_caps_sidecars() {
        let cfg = config(0, Duration::from_secs(5));
        let cap = MAX_CHECKSUM_SIZE as usize;
        let declared = StubServer::start(move |_| Response::new(200, vec![b'a'; cap + 1]));
        let (streamed, _) =
            spawn_chunked_server(move |_| (1, cap * 2, Duration::ZERO), false).await;
        let declared_url =
            Url::parse(&format!("http://{}/foo.jar.sha256", declared.addr())).unwrap();
        for url in [declared_url, streamed] {
            match fetch_text(&client(), &url, None, None, &cfg).await {
                Err(err @ RepoError::TooLarge { limit, .. }) => {
                    assert_eq!(limit, MAX_CHECKSUM_SIZE);
                    assert!(err.to_string().starts_with("checksum sidecar at "), "{err}");
                }
                other => panic!("expected TooLarge, got {other:?}"),
            }
        }
        declared.stop();

        let server = StubServer::start(|_| {
            Response::new(200, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  foo.jar\n")
        });
        let url = Url::parse(&format!("http://{}/foo.jar.sha1", server.addr())).unwrap();
        let text = fetch_text(&client(), &url, None, None, &cfg).await.unwrap();
        server.stop();
        assert_eq!(text, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  foo.jar");

        // A missing sidecar's 404 body is drained, so its connection is reused.
        let server = StubServer::start(|_| {
            Response::new(404, "<html>no such key</html>").header("Connection", "keep-alive")
        });
        let client = client();
        for name in ["a", "b", "c"] {
            let url = Url::parse(&format!("http://{}/{name}.jar.sha256", server.addr())).unwrap();
            let result = fetch_text(&client, &url, None, None, &cfg).await;
            assert!(matches!(result, Err(RepoError::NotFound(_))), "{result:?}");
        }
        assert_eq!(server.connections(), 1);
    }

    /// Fails the first `fails` lookups, as a resolver that cannot answer
    /// does, then resolves every name to `addr`.
    struct FlakyResolver {
        addr: std::net::SocketAddr,
        fails: AtomicUsize,
        lookups: AtomicUsize,
    }

    impl reqwest::dns::Resolve for FlakyResolver {
        fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            let fail = (self.fails)
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            let addr = self.addr;
            Box::pin(async move {
                if fail {
                    return Err(
                        std::io::Error::other("temporary failure in name resolution").into(),
                    );
                }
                Ok(Box::new(std::iter::once(addr)) as reqwest::dns::Addrs)
            })
        }
    }

    /// A host name that fails to resolve once is looked up again; one that
    /// fails twice fails the request as an unreachable host, which the
    /// search moves on from.
    #[tokio::test]
    async fn a_failed_lookup_is_tried_once_more() {
        let server = StubServer::start(|_| Response::new(200, "abc"));
        let cfg = config(3, Duration::from_secs(5));
        for fails in [1, 2] {
            let resolver = Arc::new(FlakyResolver {
                addr: server.addr(),
                fails: AtomicUsize::new(fails),
                lookups: AtomicUsize::new(0),
            });
            let client = rv_http::client_builder()
                .no_proxy()
                .dns_resolver(Arc::clone(&resolver))
                .build()
                .unwrap();
            let url = format!("http://repo.example:{}/a.sha1", server.addr().port());
            let result = fetch_text(&client, &Url::parse(&url).unwrap(), None, None, &cfg).await;
            assert_eq!(resolver.lookups.load(Ordering::SeqCst), 2);
            if fails == 1 {
                assert_eq!(result.unwrap(), "abc");
                continue;
            }
            let err = result.unwrap_err();
            assert!(matches!(err, RepoError::Http(_)), "{err:?}");
            assert!(err.is_unreachable() && !err.is_transient(), "{err:?}");
            assert!(err.moves_to_next_repository(), "{err:?}");
        }
        assert_eq!(server.answered(), 1);
    }

    type Heads = Arc<std::sync::Mutex<Vec<String>>>;

    /// Serve one chunked 200 response per connection: `plan(attempt)` gives
    /// the chunk count, chunk length and gap; `hang` leaves the response
    /// open. Records each request head.
    async fn spawn_chunked_server(
        plan: impl Fn(usize) -> (usize, usize, Duration) + Send + Sync + 'static,
        hang: bool,
    ) -> (Url, Heads) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let heads = Heads::default();
        let (server_heads, plan) = (heads.clone(), Arc::new(plan));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (heads, plan) = (server_heads.clone(), plan.clone());
                tokio::spawn(async move {
                    let Some(head) = rv_test_support::http::read_request_head(&mut sock).await
                    else {
                        return;
                    };
                    let (chunks, chunk_len, gap) = {
                        let mut heads = heads.lock().unwrap();
                        heads.push(String::from_utf8_lossy(&head).to_ascii_lowercase());
                        plan(heads.len() - 1)
                    };
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
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    } else {
                        let _ = sock.write_all(b"0\r\n\r\n").await;
                    }
                });
            }
        });
        let url = Url::parse(&format!("http://{addr}/org/ex/big/1.0/big-1.0.jar")).unwrap();
        (url, heads)
    }

    #[tokio::test]
    async fn low_speed_retries_on_a_new_connection() {
        for fast_retry in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(dir.path()).unwrap();
            let trickle = (100, 100, Duration::from_millis(50));
            let plan = move |n| {
                if n > 0 && fast_retry {
                    (1, 10000, Duration::ZERO)
                } else {
                    trickle
                }
            };
            let (url, heads) = spawn_chunked_server(plan, false).await;
            let cfg = FetchConfig {
                low_speed_limit: 10000,
                low_speed_time: Duration::from_millis(300),
                ..config(1, Duration::from_secs(5))
            };
            let key = big_key();
            let fetch = fetch_into(&url, None, &cfg, &store, Some(&key), None);
            let result = tokio::time::timeout(Duration::from_secs(6), fetch)
                .await
                .unwrap();
            if fast_retry {
                let blob = result.expect("fast second connection succeeds");
                assert_eq!(std::fs::read(store.get_path(&blob)).unwrap(), [b'x'; 10000]);
                assert_eq!(store.lookup_artifact(&key).await.unwrap(), Some(blob));
            } else {
                let message = result.unwrap_err().to_string();
                for expected in [
                    "artifact download too slow",
                    "0.300s",
                    "RAEVA_LOW_SPEED_LIMIT",
                    "RAEVA_LOW_SPEED_TIME",
                    url.as_str(),
                ] {
                    assert!(message.contains(expected), "{message}");
                }
            }
            let heads = heads.lock().unwrap().clone();
            assert_eq!(heads.len(), 2);
            assert!(heads[1].contains("connection: close\r\n"), "{}", heads[1]);
            assert_eq!(
                std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
                0
            );
        }
    }

    #[tokio::test]
    async fn artifact_idle_timeout_applies_between_chunks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");
        let (url, _) =
            spawn_chunked_server(move |_| (10, 1024, Duration::from_millis(250)), false).await;
        let cfg = config(0, Duration::from_millis(800));
        let started = std::time::Instant::now();
        let blob = fetch_into(&url, None, &cfg, &store, Some(&big_key()), None)
            .await
            .expect("slow but steady download must succeed");
        assert!(started.elapsed() > cfg.timeout);
        assert_eq!(
            std::fs::metadata(store.get_path(&blob)).unwrap().len(),
            10 * 1024
        );

        for (indexed, chunks) in [(false, 0), (true, 1)] {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = Store::open(dir.path()).expect("store");
            let (url, hits) =
                spawn_chunked_server(move |_| (chunks, 16, Duration::ZERO), true).await;
            let cfg = config(2, Duration::from_millis(100));
            let key = big_key();
            let message = tokio::time::timeout(
                Duration::from_secs(10),
                fetch_into(&url, None, &cfg, &store, indexed.then_some(&key), None),
            )
            .await
            .expect("stalled downloads must not hang")
            .expect_err("all attempts stall")
            .to_string();
            assert!(message.contains("timed out: no data received"), "{message}");
            assert!(message.contains(url.as_str()), "{message}");
            if indexed {
                assert!(message.contains("org.ex:big"), "{message}");
            }
            assert_eq!(hits.lock().unwrap().len(), 1 + cfg.retries);
            assert_eq!(store.lookup_artifact(&key).await.unwrap(), None);
            assert_eq!(
                std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
                0
            );
        }
    }

    #[tokio::test]
    async fn artifact_size_cap_is_enforced_and_not_retried() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("store")).expect("open");
        let (url, hits) =
            spawn_chunked_server(move |_| (8, 1024, Duration::from_millis(1)), false).await;
        let small = FetchConfig {
            max_artifact_size: 2048,
            ..config(2, Duration::from_secs(5))
        };
        let msg = fetch_into(&url, None, &small, &store, None, None)
            .await
            .expect_err("over-cap body must fail")
            .to_string();
        assert!(msg.contains("size limit of 2048"), "{msg}");
        assert!(msg.contains("RAEVA_MAX_ARTIFACT_SIZE"), "{msg}");
        assert_eq!(hits.lock().unwrap().len(), 1);

        let file = dir.path().join("big.jar");
        std::fs::write(&file, vec![7u8; 4096]).expect("write");
        let url = Url::from_file_path(&file).expect("file url");
        let root = Url::from_directory_path(dir.path()).unwrap();
        let err = fetch_into(&url, Some(&root), &small, &store, None, None)
            .await
            .expect_err("over-cap file must fail");
        assert!(err.to_string().contains("size limit of 2048"), "{err}");
        let ok = FetchConfig {
            max_artifact_size: 4096,
            ..small
        };
        fetch_into(&url, Some(&root), &ok, &store, None, None)
            .await
            .expect("file within cap is stored");
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
            // ERROR_PRIVILEGE_NOT_HELD: symlinks need Developer Mode or admin.
            if err.kind() == std::io::ErrorKind::PermissionDenied
                || err.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("create symlink: {err}");
        }
        assert!(open_checked_repository_entry(&entry).is_err());
    }

    /// Directory and final-component links fail through every local read
    /// entry point, before bytes can enter the content store.
    #[cfg(unix)]
    #[tokio::test]
    async fn local_reads_confine_directory_and_final_symlinks() {
        use std::os::unix::fs::symlink;

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
            let config = FetchConfig::default();
            let store = Store::open(&tmp.path().join("store")).unwrap();
            let key = ArtifactCoord::new("g", "a", "1", "jar", None);
            let root = Some(&root_url);
            assert!(
                super::fetch_bytes(&client(), &url, root, None, &config, None)
                    .await
                    .is_err()
            );
            assert!(
                fetch_text(&client(), &url, root, None, &config)
                    .await
                    .is_err()
            );
            for key in [None, Some(&key)] {
                assert!(
                    fetch_into(&url, root, &config, &store, key, None)
                        .await
                        .is_err()
                );
            }
            assert!(!store.exists_async(&BlobId::from_bytes(secret)).await);
        }
    }

    #[tokio::test]
    async fn local_reads_require_a_containing_repository_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("a.jar"), b"inside").unwrap();
        let outside = tmp.path().join("secret");
        std::fs::write(&outside, b"secret").unwrap();
        let root_url = Url::from_directory_path(&root).unwrap();
        let url = Url::from_file_path(&outside).unwrap();
        for root in [None, Some(&root_url)] {
            assert!(matches!(
                super::open_local_file(&url, root).await,
                Err(RepoError::InvalidCoord(_))
            ));
        }

        // The repository root itself may be a symlink.
        #[cfg(unix)]
        {
            let link = tmp.path().join("root-link");
            std::os::unix::fs::symlink(&root, &link).unwrap();
            let root_url = Url::from_directory_path(&link).unwrap();
            let url = root_url.join("a.jar").unwrap();
            let bytes = super::read_local_bytes(&url, Some(&root_url), 100, None)
                .await
                .unwrap();
            assert_eq!(&bytes[..], b"inside");
        }
    }
}
