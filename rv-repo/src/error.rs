use reqwest::StatusCode;
use rv_http::transient::{status_is_transient, transport_is_retryable, transport_is_unreachable};
use rv_http::{tls_cause, tls_failure_is_permanent};
use rv_maven_types::{ArtifactCoord, Digest};
use thiserror::Error;

use crate::auth::SentCredential;

/// Why a request was refused before or during a redirect, carried by
/// [`RepoError::RedirectRejected`]. Same-origin redirects are always
/// followed; the other kinds name the rule a cross-origin hop broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RedirectRejectionKind {
    /// The response that redirected came from an origin that is not a
    /// configured repository, mirror or root-model repository, or the
    /// redirect had no issuing request.
    OriginNotConfigured,
    /// A plain `http:` origin redirected to another origin. Such an origin
    /// may redirect only within itself.
    InsecureOrigin,
    /// A cross-origin redirect to a target that is not `https:`.
    HttpsDowngrade,
    /// The target has no host, or it is or resolves to an address outside
    /// the public internet. The resolver also returns this for a direct
    /// request whose host name resolves to such an address, so it is not
    /// only a redirect outcome.
    NonGlobalTarget,
    /// A proxy is configured, so it would resolve the target, and the
    /// target origin is not a configured repository or mirror.
    ProxiedTargetNotConfigured,
    /// The target host is exempt from the address screen because it is
    /// configured, but the target's scheme or port is not a configured
    /// origin.
    ExemptHostOriginMismatch,
    /// The chain already crossed origins once; only one cross-origin hop
    /// is followed.
    SecondCrossOriginHop,
    /// The chain reached 5 hops.
    ChainLimit,
}

impl RedirectRejectionKind {
    /// A one-line description of the rule, the first part of the
    /// [`RepoError::RedirectRejected`] message and this type's `Display`.
    pub fn summary(self) -> &'static str {
        match self {
            Self::OriginNotConfigured => {
                "cross-origin redirect rejected: redirect origin is not configured"
            }
            Self::InsecureOrigin => "cross-origin redirect rejected: redirect origin is not HTTPS",
            Self::HttpsDowngrade => "cross-origin redirect rejected: target is not HTTPS",
            // The resolver screens direct connections and redirect targets
            // alike, so this names neither.
            Self::NonGlobalTarget => "refused: target address is not globally routable",
            Self::ProxiedTargetNotConfigured => {
                "cross-origin redirect rejected: a proxy is configured and the target origin is not \
                 a configured repository or mirror"
            }
            Self::ExemptHostOriginMismatch => {
                "cross-origin redirect rejected: target host is configured but the target origin is not"
            }
            Self::SecondCrossOriginHop => "cross-origin redirect rejected: second cross-origin hop",
            Self::ChainLimit => "redirect rejected: chain exceeds 5 hops",
        }
    }
}

impl std::fmt::Display for RedirectRejectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.summary())
    }
}

/// An error from a repository read.
///
/// Messages are safe to show: a URL in a variant has been passed through
/// [`rv_config::redact_url`], and a lockfile origin through
/// [`rv_lock::redact_origin`], before it was stored. [`RepoError::class`]
/// sorts the variants for callers that only need the kind of failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RepoError {
    /// The request failed without an HTTP status, such as a refused
    /// connection, a timeout or a TLS failure, or the HTTP client could not
    /// be built. A request error carries the redacted request URL. Retried
    /// when [`RepoError::is_transient`] says so.
    #[error("http error: {0}{cause}", cause = http_cause(.0))]
    Http(#[from] reqwest::Error),
    /// Offline mode is on and the file would need a request to a remote
    /// repository. Holds the repository path, sometimes with the redacted
    /// repository URL or a note on why the cached copy cannot be used.
    /// `file:` repositories stay readable offline.
    #[error("offline mode: {0} not available in local cache")]
    OfflineNotCached(String),
    /// A repository URL, or a URL joined from it, did not parse.
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    /// A local read or write failed, such as reading a `file:` repository
    /// file (a missing one is [`RepoError::NotFound`]) or a stored blob that
    /// has gone missing.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A request that got no response headers in time, or a response body
    /// that broke off, stalled or arrived too slowly. raeva retries it.
    #[error("transfer failed: {0}")]
    Transfer(std::io::Error),
    /// A response larger than raeva accepts for what it is. `setting` names
    /// what raises the limit, when something does.
    #[error(
        "{subject} exceeds the size limit of {limit} bytes{}{}",
        declared.map(|len| format!(" ({len} bytes advertised)")).unwrap_or_default(),
        setting.map(|name| format!(" (raise it with {name})")).unwrap_or_default()
    )]
    TooLarge {
        /// What was refused: the body kind and its redacted URL, a local
        /// path, or `artifact` with the coordinate and redacted URL.
        subject: String,
        /// The limit in bytes.
        limit: u64,
        /// The size declared before reading, a `Content-Length` or a local
        /// file's length, when it was above the limit. `None` when the body
        /// crossed the limit while streaming.
        declared: Option<u64>,
        /// The environment variable that raises the limit, set only for
        /// artifact bodies ([`rv_config::MAX_ARTIFACT_SIZE_ENV`]).
        setting: Option<&'static str>,
    },
    /// The repository answered 404, or a `file:` repository has no such
    /// file. Holds the redacted URL or the local path. [`ensure_artifacts`]
    /// also returns it, with a message, for a platform the lockfile lacks or
    /// a support POM no candidate repository has.
    ///
    /// [`ensure_artifacts`]: crate::ensure_artifacts
    #[error("not found: {0}")]
    NotFound(String),
    /// Bytes that do not match a checksum. `check` says which promise
    /// failed; `expected` and `actual` use that checksum's algorithm.
    #[error("checksum mismatch for {subject}: expected {expected}, got {actual} ({})", check.describe())]
    ChecksumMismatch {
        /// The coordinate for a lock pin check (the URL path when no
        /// coordinate is known), the repository path for a sidecar check. Boxed, like `artifact`, so `RepoError` stays small.
        subject: Box<str>,
        /// The artifact the bytes were fetched for, when there is one.
        /// Metadata files have none.
        artifact: Option<Box<ArtifactCoord>>,
        /// The digest the sidecar or the pin promised.
        expected: Digest,
        /// The digest of the bytes received.
        actual: Digest,
        /// Which checksum failed.
        check: IntegritySource,
    },
    /// The repository publishes no usable `.sha256`, `.sha1` or `.md5`
    /// sidecar for a remote file and missing sidecars are not allowed.
    /// Holds the repository path.
    #[error(
        "missing checksum for {0}: the repository publishes no usable .sha256, .sha1 or .md5 sidecar for this file. \
         If you trust this repository without checksums, run 'raeva sync --allow-missing-checksums' and review \
         raeva.lock (SUPPLY-CHAIN RISK: the bytes are not checked against a server-published checksum)"
    )]
    MissingChecksum(String),
    /// Remote metadata without a usable sidecar, from a repository whose
    /// checksum policy is `fail`, which no flag overrides. Holds the
    /// repository path.
    #[error(
        "missing checksum for {0}: the repository publishes no usable .sha256, .sha1 or .md5 sidecar for this \
         metadata, and its checksum policy is fail. The repository must publish one; to accept the metadata \
         unverified, set that policy to warn or ignore and run 'raeva sync --allow-missing-checksums', then \
         review raeva.lock"
    )]
    MissingMetadataChecksum(String),
    /// A lockfile row that [`ensure_artifacts`] would download records no
    /// checksum, so nothing could verify the bytes. Holds the coordinate.
    /// Nothing is fetched; a repository sidecar does not stand in for the
    /// pin.
    ///
    /// [`ensure_artifacts`]: crate::ensure_artifacts
    #[error("raeva.lock records no checksum for {0}, so a download of it cannot be verified")]
    UnpinnedLockRow(String),
    /// A `maven-metadata.xml` that is not UTF-8, does not parse, or names a
    /// snapshot version that is missing or not a valid version; or a
    /// checksum sidecar that is not UTF-8. The message gives sizes, never the
    /// server's text.
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),
    /// A coordinate component or repository path raeva refuses to put in a URL:
    /// one that fails the coordinate rules, contains a `..` segment, or
    /// would leave the repository's origin or base path. Also returned for a
    /// non-snapshot version passed to
    /// [`RepoClient::resolve_snapshot_version`](crate::RepoClient::resolve_snapshot_version).
    #[error("invalid coordinate: {0}")]
    InvalidCoord(String),
    /// The server refused the request: 401 or 403 from a repository, or 407
    /// from a proxy.
    #[error(
        "auth error: {status} for {url}{}",
        if *status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            " - the proxy wants credentials: username and password (or token) in config.toml or settings.xml, or user:password@ in HTTPS_PROXY or HTTP_PROXY"
        } else {
            ""
        }
    )]
    Unauthorized {
        /// 401, 403 or 407.
        status: StatusCode,
        /// The redacted request URL.
        url: String,
        /// The credential a refused 401 or 403 request carried, `None` when
        /// it carried none.
        sent: Option<Box<SentCredential>>,
    },
    /// The proxy answered the `CONNECT` for an `https:` URL with something
    /// other than 200 or an HTTP/1.1 407. Holds the redacted request URL.
    /// Not passed over for the next repository: hyper-util reports a 200
    /// whose first read ends inside the status line the same way.
    #[error(
        "proxy error: the proxy refused the tunnel to {0}, as it does for a host it blocks \
         or, answering HTTP/1.0, for missing credentials"
    )]
    ProxyTunnelRefused(String),
    /// Credentials or proxy authentication could not be set up from the
    /// configuration, so no request was sent.
    #[error("auth error: {0}")]
    AuthSetup(String),
    /// A configured value raeva cannot use, such as a malformed proxy host.
    /// Reported before any request.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// A direct request to an IP address outside the public internet, for a
    /// repository whose host no configuration, project POM or transitive
    /// repository allowlist entry names. Not retried; a repository search
    /// moves on to the next repository, as it does when a host name
    /// resolves to such an address.
    #[error(
        "refusing to connect to {url}: {addr} is not a public address, and only a repository \
         that raeva.toml, settings.xml, the project's own POM or the transitive repository \
         allowlist names may use one"
    )]
    NonGlobalAddress {
        /// The redacted request URL.
        url: String,
        /// The non-global address the URL names.
        addr: std::net::IpAddr,
    },
    /// A failure inside raeva itself: a poisoned lock or a background task that
    /// panicked. Not retried and not a property of the repository.
    #[error("internal error: {0}")]
    Internal(String),
    /// The content-addressed store refused or failed an operation.
    #[error("store error: {0}")]
    Store(#[from] rv_store::StoreError),
    /// The metadata cache could not be opened, read or written.
    #[error(transparent)]
    Cache(#[from] rv_store::metadata_cache::CacheError),
    /// An unsuccessful HTTP status other than 404 and the refusals in
    /// [`RepoError::Unauthorized`].
    #[error("unexpected response: {status} for {url}")]
    HttpStatus {
        /// The status the server answered with.
        status: StatusCode,
        /// The redacted request URL.
        url: String,
        /// The delay a busy answer's `Retry-After` asked for.
        retry_after: Option<std::time::Duration>,
    },
    /// A `-SNAPSHOT` or timestamped version was requested from a repository
    /// with snapshots disabled.
    #[error("snapshot version {version} cannot be fetched: {reason}")]
    SnapshotsDisabled {
        /// The requested version.
        version: String,
        /// Which repository (by id) refused it and what would allow it.
        reason: String,
    },
    /// A release version was requested from a repository with releases
    /// disabled.
    #[error("release version {version} cannot be fetched: {reason}")]
    ReleasesDisabled {
        /// The requested version.
        version: String,
        /// Which repository (by id) refused it.
        reason: String,
    },
    /// A lockfile row's `repo_url` names no repository the current
    /// configuration or resolution declares, so raeva refuses to fetch from it.
    /// Holds the origin as [`rv_lock::redact_origin`] spells it.
    #[error(
        "lockfile references repository '{0}' which is not in the current raeva.toml; refusing to fetch from an unconfigured origin"
    )]
    UntrustedRepoUrl(String),
    /// A project-relative lockfile origin that declared repositories with
    /// different URLs all map to, so raeva will not pick one. Holds the origin
    /// as [`rv_lock::redact_origin`] spells it.
    #[error(
        "lockfile origin '{0}' names a project directory that more than one declared repository URL spells; declare it with one URL"
    )]
    AmbiguousRepoOrigin(String),
    /// The mirror that serves the repository is blocked, so it gets no
    /// request. Holds the mirror's id, else its redacted URL.
    #[error("mirror '{0}' is blocked in the configuration, so raeva sends it no requests")]
    BlockedMirror(String),
    /// A request that failed after `attempts` attempts, with the last
    /// failure, one [`RepoError::is_transient`] says is retried.
    /// [`RepoError::cause`] unwraps it, and the methods here answer for the
    /// error it holds.
    #[error("{error} (after {attempts} attempts)")]
    Retried {
        /// How many times the request was sent.
        attempts: usize,
        /// The last attempt's failure.
        #[source]
        error: Box<RepoError>,
    },
    /// The redirect policy or the address-screening resolver refused a hop
    /// or a connection. Not retried.
    #[error("{kind}: {details}")]
    RedirectRejected {
        /// The rule that refused it.
        kind: RedirectRejectionKind,
        /// The hop or host refused. URLs in it are redacted; origins appear
        /// as scheme, host and port only.
        details: String,
    },
}

pub(crate) type Result<T> = std::result::Result<T, RepoError>;

/// The cause reqwest's message leaves out, and for a request that timed
/// out the setting that bounds it. The connect limit is fixed.
fn http_cause(err: &reqwest::Error) -> String {
    let Some(cause) = rv_http::transient::transport_detail(err) else {
        return String::new();
    };
    if err.is_timeout() && !err.is_connect() {
        format!(": {cause} (raise RAEVA_TIMEOUT)")
    } else {
        format!(": {cause}")
    }
}

/// What kind of failure a [`RepoError`] is, independent of the operation
/// that hit it. Callers decide what a class means for them, such as an exit
/// status or a `doctor` verdict; [`RepoError::class`] is the one mapping
/// from the error variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorClass {
    /// No response: a timeout, a failed connection, or a request or body
    /// that broke off, stalled or arrived too slowly. `retried` says whether
    /// the fetch retries it ([`RepoError::is_transient`]).
    Transport {
        /// Whether the fetch retries it.
        retried: bool,
    },
    /// No server was reached: the host name did not resolve, or the
    /// connection was refused or had no route ([`RepoError::is_unreachable`]).
    /// Not retried.
    Unreachable,
    /// TLS refused the server. A `permanent` failure, such as an untrusted
    /// certificate, needs other trust roots or another URL; any other one
    /// may pass on a retry.
    Tls {
        /// Whether a retry cannot help.
        permanent: bool,
    },
    /// An unsuccessful status other than 404 and the refusals, with whether
    /// the fetch retries it (429, 502, 503, 504).
    Status {
        /// The HTTP status code.
        code: u16,
        /// Whether the fetch retries it.
        retried: bool,
    },
    /// The repository answered 404, or a local file or locked platform is
    /// absent.
    NotFound,
    /// The repository refused the credentials (401, 403), or none could be
    /// set up.
    Auth,
    /// A proxy refused the request: a 407, or any refusal of the tunnel to
    /// an `https:` URL.
    ProxyAuth,
    /// The fetched bytes do not match a checksum.
    Integrity(IntegritySource),
    /// The local store, the metadata cache or local I/O failed.
    Store,
    /// `--offline` and the file is not cached.
    Offline,
    /// The configuration names something raeva refuses to fetch: a bad URL,
    /// releases or snapshots disabled, an unsupported checksum policy, an
    /// origin the configuration does not declare.
    Config,
    /// raeva.lock cannot be used as written: a row to download records no
    /// checksum.
    Lockfile,
    /// Anything else: invalid metadata, a refused redirect, a missing or
    /// unsupported sidecar, a coordinate that would leave the repository.
    Other,
}

/// Which checksum the bytes failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegritySource {
    /// A checksum sidecar the repository published next to the file.
    Sidecar,
    /// The pin raeva.lock records.
    LockPin,
}

impl IntegritySource {
    fn describe(self) -> &'static str {
        match self {
            Self::Sidecar => "the repository's checksum file",
            Self::LockPin => "the raeva.lock pin",
        }
    }
}

impl RepoError {
    /// The failure without the [`RepoError::Retried`] count around it.
    pub fn cause(&self) -> &RepoError {
        match self {
            RepoError::Retried { error, .. } => error.cause(),
            other => other,
        }
    }

    /// The kind of failure this is; see [`ErrorClass`].
    pub fn class(&self) -> ErrorClass {
        match self {
            RepoError::Retried { error, .. } => error.class(),
            RepoError::Unauthorized { status, .. }
                if *status == StatusCode::PROXY_AUTHENTICATION_REQUIRED =>
            {
                ErrorClass::ProxyAuth
            }
            RepoError::ProxyTunnelRefused(_) => ErrorClass::ProxyAuth,
            RepoError::Unauthorized { .. } | RepoError::AuthSetup(_) => ErrorClass::Auth,
            RepoError::Http(http) => match tls_cause(http) {
                Some(tls) => ErrorClass::Tls {
                    permanent: tls_failure_is_permanent(tls),
                },
                None if self.is_unreachable() => ErrorClass::Unreachable,
                None => ErrorClass::Transport {
                    retried: self.is_transient(),
                },
            },
            RepoError::Transfer(_) => ErrorClass::Transport { retried: true },
            RepoError::HttpStatus { status, .. } => ErrorClass::Status {
                code: status.as_u16(),
                retried: self.is_transient(),
            },
            RepoError::NotFound(_) => ErrorClass::NotFound,
            RepoError::ChecksumMismatch { check, .. } => ErrorClass::Integrity(*check),
            RepoError::Url(_)
            | RepoError::SnapshotsDisabled { .. }
            | RepoError::ReleasesDisabled { .. }
            | RepoError::UntrustedRepoUrl(_)
            | RepoError::AmbiguousRepoOrigin(_)
            | RepoError::BlockedMirror(_)
            | RepoError::Config(_) => ErrorClass::Config,
            RepoError::Store(_) | RepoError::Cache(_) | RepoError::Io(_) => ErrorClass::Store,
            RepoError::OfflineNotCached(_) => ErrorClass::Offline,
            RepoError::UnpinnedLockRow(_) => ErrorClass::Lockfile,
            // An invalid coordinate comes from POM content, such as a path
            // that would leave the repository, not from the configuration.
            RepoError::InvalidCoord(_)
            | RepoError::TooLarge { .. }
            | RepoError::InvalidMetadata(_)
            | RepoError::MissingChecksum(_)
            | RepoError::MissingMetadataChecksum(_)
            | RepoError::RedirectRejected { .. }
            | RepoError::NonGlobalAddress { .. }
            | RepoError::Internal(_) => ErrorClass::Other,
        }
    }

    /// Whether raeva retries the request that failed with this error. The
    /// fetch retry loop and every caller that asks this question use the
    /// same rule.
    pub fn is_transient(&self) -> bool {
        match self {
            RepoError::Retried { error, .. } => error.is_transient(),
            RepoError::Http(err) => transport_is_retryable(err),
            RepoError::Transfer(_) => true,
            RepoError::HttpStatus { status, .. } => status_is_transient(*status),
            _ => false,
        }
    }

    /// Whether the request never reached a server: the host name did not
    /// resolve, or the connection was refused or had no route
    /// ([`rv_http::transient::transport_is_unreachable`]). A network
    /// failure all the same, though not retried, except that a host name
    /// that did not resolve is looked up once more.
    pub fn is_unreachable(&self) -> bool {
        matches!(self.cause(), RepoError::Http(err) if transport_is_unreachable(err))
    }

    /// Whether a search over the configured repositories goes on to the
    /// next one after this error. Maven moves on after any failed transfer,
    /// and so does raeva, except for bytes that fail their checksum or have
    /// none, and a redirect to plain HTTP, which it reports rather than
    /// work around. Nor does it move on after a failure it retried, such as
    /// a 429 or a timeout: the lock would then name whichever repository
    /// happened to answer, and a later `--frozen` would see drift.
    pub fn moves_to_next_repository(&self) -> bool {
        if self.is_transient() {
            return false;
        }
        match self.cause() {
            RepoError::RedirectRejected { kind, .. } => {
                *kind != RedirectRejectionKind::HttpsDowngrade
            }
            RepoError::Http(_)
            | RepoError::Io(_)
            | RepoError::Transfer(_)
            | RepoError::TooLarge { .. }
            | RepoError::Unauthorized { .. }
            | RepoError::HttpStatus { .. }
            | RepoError::BlockedMirror(_)
            | RepoError::NonGlobalAddress { .. } => true,
            _ => false,
        }
    }

    /// The HTTP status of an HTTP error, `404` for any not-found one.
    pub fn status_code(&self) -> Option<u16> {
        match self.cause() {
            RepoError::NotFound(_) => Some(404),
            RepoError::Unauthorized { status, .. } | RepoError::HttpStatus { status, .. } => {
                Some(status.as_u16())
            }
            _ => None,
        }
    }

    /// The TLS failure behind an HTTP error, such as an untrusted server
    /// certificate. See [`rv_http::tls_cause`].
    pub fn tls_cause(&self) -> Option<&rustls::Error> {
        match self.cause() {
            RepoError::Http(err) => tls_cause(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorClass, IntegritySource, RedirectRejectionKind, RepoError};
    use reqwest::StatusCode;
    use rv_maven_types::{Digest, HashAlgorithm};

    /// A server answering the ClientHello with a fatal `bad_certificate`
    /// alert fails the handshake inside rustls, as an untrusted certificate
    /// does. Both it and a refused connection, which has no TLS cause, move
    /// on to the next repository.
    #[tokio::test]
    async fn tls_cause_is_found_behind_a_connect_error() {
        let client = rv_http::client_builder().build().expect("client");
        let (address, server) =
            rv_test_support::tls::reject_one_handshake(rv_test_support::tls::BAD_CERTIFICATE);
        let err = client
            .get(format!("https://{address}/"))
            .send()
            .await
            .expect_err("handshake must fail");
        server.join().expect("server");
        let err = RepoError::Http(err);
        let cause = err.tls_cause().expect("TLS cause");
        assert!(cause.to_string().contains("BadCertificate"), "{cause}");
        assert_eq!(err.class(), ErrorClass::Tls { permanent: true });
        assert!(err.moves_to_next_repository());

        let refusing = rv_test_support::net::RefusingPort::bind();
        let err = client
            .get(format!("https://{}/", refusing.addr()))
            .send()
            .await
            .expect_err("nothing listens");
        let err = RepoError::Http(err);
        assert!(err.to_string().ends_with(": connection refused"), "{err}");
        assert!(err.tls_cause().is_none());
        assert_eq!(err.class(), ErrorClass::Unreachable);
        assert!(!err.is_transient());
        assert!(err.is_unreachable());
        assert!(err.moves_to_next_repository());
    }

    /// Each variant's class, whether it is retried, whether the search
    /// moves on to the next repository, and what its message tells the user.
    #[test]
    fn each_variant_has_one_class_and_says_what_to_do() {
        use ErrorClass as C;
        let url = || "https://repo.example/".to_string();
        let status = |code| RepoError::HttpStatus {
            status: StatusCode::from_u16(code).unwrap(),
            url: url(),
            retry_after: None,
        };
        let unauthorized = |code| RepoError::Unauthorized {
            status: StatusCode::from_u16(code).unwrap(),
            url: url(),
            sent: None,
        };
        let mismatch = |check| RepoError::ChecksumMismatch {
            subject: "artifact.jar".into(),
            artifact: None,
            expected: Digest::of_bytes(HashAlgorithm::Sha256, b"a"),
            actual: Digest::of_bytes(HashAlgorithm::Sha256, b"b"),
            check,
        };
        let code = |code, retried| C::Status { code, retried };
        let path = "com/example/demo/1.0/demo-1.0.jar";
        let snapshots = RepoError::SnapshotsDisabled {
            version: "1.0-SNAPSHOT".to_string(),
            reason: "repository 'central' has snapshots disabled".to_string(),
        };
        let disk = || std::io::Error::other("disk");
        #[rustfmt::skip]
        let cases = [
            (status(429), code(429, true), true, false, ""),
            (status(502), code(502, true), true, false, ""),
            (status(503), code(503, true), true, false, "unexpected response: 503 Service Unavailable for https://repo.example/"),
            (status(504), code(504, true), true, false, ""),
            (RepoError::Retried { attempts: 4, error: Box::new(status(503)) }, code(503, true), true, false,
                "unexpected response: 503 Service Unavailable for https://repo.example/ (after 4 attempts)"),
            (status(500), code(500, false), false, true, ""),
            (status(418), code(418, false), false, true, ""),
            (RepoError::NotFound("p".to_string()), C::NotFound, false, false, ""),
            (unauthorized(401), C::Auth, false, true, ""),
            (unauthorized(403), C::Auth, false, true, ""),
            (RepoError::AuthSetup("no token".to_string()), C::Auth, false, false, ""),
            (unauthorized(407), C::ProxyAuth, false, true, "auth error: 407 Proxy Authentication Required for https://repo.example/ \
                - the proxy wants credentials: username and password (or token) in config.toml or settings.xml, or user:password@ in HTTPS_PROXY or HTTP_PROXY"),
            (RepoError::ProxyTunnelRefused("https://repo.example/".to_string()), C::ProxyAuth, false, false, "refused the tunnel to https://repo.example/"),
            (RepoError::Transfer(std::io::Error::other("stalled")), C::Transport { retried: true }, true, false, ""),
            (mismatch(IntegritySource::Sidecar), C::Integrity(IntegritySource::Sidecar), false, false,
                "checksum mismatch for artifact.jar: expected sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb, \
                got sha256:3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d (the repository's checksum file)"),
            (mismatch(IntegritySource::LockPin), C::Integrity(IntegritySource::LockPin), false, false, ""),
            (RepoError::Io(disk()), C::Store, false, true, ""),
            (RepoError::Store(rv_store::StoreError::IoError(disk())), C::Store, false, false, ""),
            (RepoError::Cache(rv_store::metadata_cache::CacheError::Pool("busy".to_string())), C::Store, false, false, ""),
            (RepoError::OfflineNotCached(path.to_string()), C::Offline, false, false, "offline mode"),
            (RepoError::UntrustedRepoUrl(url()), C::Config, false, false, ""),
            (RepoError::BlockedMirror("corp".to_string()), C::Config, false, true, "mirror 'corp' is blocked"),
            (RepoError::InvalidCoord("../x".to_string()), C::Other, false, false, ""),
            (RepoError::MissingChecksum(path.to_string()), C::Other, false, false, "raeva sync --allow-missing-checksums"),
            (RepoError::MissingMetadataChecksum(path.to_string()), C::Other, false, false, "checksum policy is fail"),
            (RepoError::NonGlobalAddress { url: url(), addr: std::net::IpAddr::from([10, 0, 0, 5]) }, C::Other, false, true, ""),
            (RepoError::RedirectRejected { kind: RedirectRejectionKind::NonGlobalTarget, details: "nexus.internal".to_string() },
                C::Other, false, true, ""),
            (RepoError::RedirectRejected { kind: RedirectRejectionKind::ChainLimit, details: url() }, C::Other, false, true, ""),
            (RepoError::RedirectRejected { kind: RedirectRejectionKind::HttpsDowngrade, details: url() }, C::Other, false, false, ""),
            (snapshots, C::Config, false, false, "1.0-SNAPSHOT"),
        ];
        for (err, class, transient, moves_on, says) in cases {
            assert_eq!(err.class(), class, "{err}");
            assert_eq!(err.is_transient(), transient, "{err}");
            assert_eq!(err.moves_to_next_repository(), moves_on, "{err}");
            let rendered = err.to_string();
            assert!(rendered.contains(says), "{rendered}");
            if matches!(
                err,
                RepoError::OfflineNotCached(_)
                    | RepoError::MissingChecksum(_)
                    | RepoError::MissingMetadataChecksum(_)
            ) {
                assert!(rendered.contains(path), "{rendered}");
            }
        }
        assert_eq!(unauthorized(401).status_code(), Some(401));
        let retried = RepoError::Retried {
            attempts: 2,
            error: Box::new(status(429)),
        };
        assert_eq!(retried.status_code(), Some(429));
        assert!(matches!(retried.cause(), RepoError::HttpStatus { .. }));
    }
}
