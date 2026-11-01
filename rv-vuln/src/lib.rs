//! Vulnerability scanning for Raeva with the OSV API.
//!
//! [`VulnScanner`] queries OSV through an [`OsvClient`] for each
//! [`Dependency`] and returns a [`ScanReport`]. Only Maven purls are
//! queried, and OSV answers are bounded in size and page count and checked
//! before they are returned.
//!
//! The crate reports what OSV knows and ranks it with [`SeverityBand`]. A
//! record OSV names but does not serve is listed in
//! [`ScanReport::failed_fetches`], so an incomplete scan is never silent. It
//! does not read lockfiles (the caller supplies the dependencies), does not
//! cache answers, and does not decide what a finding means for the build:
//! thresholds and exit codes belong to the caller.

mod osv;
mod scanner;
mod types;

pub use osv::{FailedFetch, OsvClient, OsvSettings, RetryNotice};
pub use scanner::{Dependency, ScanReport, VulnScanner};
pub use types::{
    Affected, Package, Range, RangeEvent, Reference, Severity, SeverityBand, VulnResult,
    Vulnerability,
};

use std::time::Duration;

/// Why a query to OSV failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VulnError {
    /// The HTTP client could not be built, or the request failed in
    /// transport (connect, TLS, timeout, or reading the body).
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// An unsuccessful status other than 429. The response body is server
    /// text, so only its size is kept, or `None` when it could not be read.
    #[error(
        "unexpected OSV status {status}: {} ({})",
        describe_status(*status),
        match *body_size {
            Some(size) => format!("{size}-byte response body not shown"),
            None => "response body not read".to_string(),
        }
    )]
    HttpStatus {
        /// The status OSV answered with, after any same-origin redirects.
        status: reqwest::StatusCode,
        /// Size in bytes of the error body. A body over 64 KiB fails as
        /// [`VulnError::InvalidResponse`] instead.
        body_size: Option<usize>,
    },
    /// OSV answered 429 and the retry policy stopped retrying, because the
    /// retries or the wait budget ran out.
    #[error("rate limited by OSV API")]
    RateLimited {
        /// The delay the `Retry-After` header asked for, when it had one.
        retry_after: Option<Duration>,
    },
    /// A purl is not a Maven purl with a namespace, name and version, or a
    /// [`Dependency`] coordinate cannot be written as one. The message
    /// quotes the purl or coordinate.
    #[error("invalid purl: {0}")]
    InvalidPurl(String),
    /// OSV answered with a body that is malformed, too large, paginated
    /// past the page limit, missing results, or naming an implausible
    /// vulnerability id, or answered a record request with another record.
    /// The message does not quote the body.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// A `Result` whose error is [`VulnError`].
pub type Result<T> = std::result::Result<T, VulnError>;

fn describe_status(status: reqwest::StatusCode) -> &'static str {
    if status.is_redirection() {
        "OSV answered with a redirect, which raeva does not follow"
    } else if status.is_client_error() {
        "OSV refused the request"
    } else if status.is_server_error() {
        "the OSV service failed"
    } else {
        "OSV did not answer with a result"
    }
}
