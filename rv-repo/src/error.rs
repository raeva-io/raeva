use anyhow::Error as AnyhowError;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectRejectionKind {
    OriginNotConfigured,
    InsecureOrigin,
    HttpsDowngrade,
    NonGlobalTarget,
    ProxiedTargetNotConfigured,
    ExemptHostOriginMismatch,
    SecondCrossOriginHop,
    ChainLimit,
}

impl RedirectRejectionKind {
    pub fn summary(self) -> &'static str {
        match self {
            Self::OriginNotConfigured => {
                "cross-origin redirect rejected: redirect origin is not configured"
            }
            Self::InsecureOrigin => "cross-origin redirect rejected: redirect origin is not HTTPS",
            Self::HttpsDowngrade => "cross-origin redirect rejected: target is not HTTPS",
            Self::NonGlobalTarget => {
                "cross-origin redirect rejected: target address is not globally routable"
            }
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

// Re-use the io context helper from rv-config.
pub(crate) use rv_config::io_error_with_context;

/// Wrap an `anyhow::Error` as a `rusqlite::Error` so context can flow through
/// rusqlite-returning closures without losing the message. Mirrors the same
/// helper in rv-store; duplicated here so rv-store does not have to expose
/// the rusqlite type in its public API.
pub(crate) fn db_error_with_context(err: AnyhowError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(DbContextError(err.to_string())))
}

#[derive(Debug)]
struct DbContextError(String);

impl std::fmt::Display for DbContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DbContextError {}

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("offline mode: {0} not available in local cache")]
    OfflineNotCached(String),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("xml error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("checksum mismatch for {path}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error(
        "missing checksum for {0}: the repository publishes no .sha256 or .sha1 sidecar for this artifact. \
         Pass --allow-missing-checksums to fetch it anyway (SUPPLY-CHAIN RISK: bytes will not be verified against a server-published checksum)"
    )]
    MissingChecksum(String),
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),
    #[error("invalid coordinate: {0}")]
    InvalidCoord(String),
    #[error("auth error: {0}")]
    AuthError(String),
    #[error("store error: {0}")]
    Store(#[from] rv_store::StoreError),
    #[error("sqlite error: {0}")]
    DbError(#[from] rusqlite::Error),
    #[error("unsupported checksum type: {0}")]
    UnsupportedChecksum(String),
    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),
    #[error("snapshot version {version} cannot be fetched: {reason}")]
    SnapshotsDisabled { version: String, reason: String },
    #[error(
        "lockfile references repository '{0}' which is not in the current rv.toml; refusing to fetch from an unconfigured origin"
    )]
    UntrustedRepoUrl(String),
    #[error("{kind}: {details}")]
    RedirectRejected {
        kind: RedirectRejectionKind,
        details: String,
    },
}

pub type Result<T> = std::result::Result<T, RepoError>;

impl RepoError {
    pub fn is_transient(&self) -> bool {
        match self {
            // SnapshotsDisabled is a permanent configuration issue: the repository
            // has snapshots disabled and this won't change on retry.
            RepoError::SnapshotsDisabled { .. } => false,
            RepoError::Http(err) => {
                err.is_timeout() || err.is_connect() || err.is_body() || err.is_request()
            }
            RepoError::UnexpectedResponse(message) => is_transient_status(message),
            _ => false,
        }
    }

    pub fn status_code(&self) -> Option<u16> {
        match self {
            RepoError::NotFound(_) => Some(404),
            RepoError::AuthError(message) => parse_status_code(message),
            RepoError::UnexpectedResponse(message) => parse_status_code(message),
            _ => None,
        }
    }
}

fn is_transient_status(message: &str) -> bool {
    parse_status_code(message)
        .map(|code| code == 429 || (500..600).contains(&code))
        .unwrap_or(false)
}

fn parse_status_code(message: &str) -> Option<u16> {
    message.split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::RepoError;

    #[test]
    fn offline_not_cached_error_formats() {
        let err = RepoError::OfflineNotCached("com/example/demo/1.0/demo-1.0.jar".to_string());
        let rendered = format!("{err}");
        assert!(rendered.contains("offline mode"));
        assert!(rendered.contains("com/example/demo/1.0/demo-1.0.jar"));
        assert!(rendered.contains("not available in local cache"));
    }

    #[test]
    fn checksum_mismatch_formats() {
        let err = RepoError::ChecksumMismatch {
            path: "artifact.jar".to_string(),
            expected: "deadbeef".to_string(),
            actual: "cafebabe".to_string(),
        };
        let rendered = format!("{err}");
        assert!(rendered.contains("artifact.jar"));
        assert!(rendered.contains("deadbeef"));
        assert!(rendered.contains("cafebabe"));
    }

    #[test]
    fn missing_checksum_error_names_escape_hatch() {
        let err = RepoError::MissingChecksum("com/example/demo/1.0/demo-1.0.jar".to_string());
        let rendered = format!("{err}");
        assert!(
            rendered.contains("com/example/demo/1.0/demo-1.0.jar"),
            "message must name the artifact path: {rendered}"
        );
        assert!(
            rendered.contains("--allow-missing-checksums"),
            "missing-checksum message must name the escape hatch: {rendered}"
        );
        assert!(
            rendered.contains(".sha256") && rendered.contains(".sha1"),
            "message must explain that neither sidecar was published: {rendered}"
        );
    }

    #[test]
    fn snapshots_disabled_error_includes_version_and_reason() {
        let err = RepoError::SnapshotsDisabled {
            version: "1.0-SNAPSHOT".to_string(),
            reason: "repository 'central' has snapshots disabled".to_string(),
        };
        let rendered = format!("{err}");
        assert!(rendered.contains("1.0-SNAPSHOT"));
        assert!(rendered.contains("snapshots disabled"));
    }

    #[test]
    fn transient_unexpected_response_detects_5xx() {
        let err = RepoError::UnexpectedResponse(
            "503 Service Unavailable for https://example.com".to_string(),
        );
        assert!(err.is_transient());
    }

    #[test]
    fn non_transient_unexpected_response_detects_4xx() {
        let err =
            RepoError::UnexpectedResponse("404 Not Found for https://example.com".to_string());
        assert!(!err.is_transient());
    }

    #[test]
    fn snapshots_disabled_is_not_transient() {
        let err = RepoError::SnapshotsDisabled {
            version: "1.0-SNAPSHOT".to_string(),
            reason: "repository 'central' has snapshots disabled".to_string(),
        };
        // SnapshotsDisabled is a permanent configuration issue, not transient
        assert!(!err.is_transient());
    }
}
