mod cache;
mod osv;
mod scanner;
mod types;

pub use cache::{CacheStats, VulnCache};
pub use osv::{BatchQueryResult, FetchResult, OsvClient};
pub use scanner::{Dependency, ScanReport, VulnScanner};
pub use types::{
    Affected, Package, Range, RangeEvent, Reference, Severity, SeverityBand, VulnResult,
    Vulnerability,
};

use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum VulnError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("unexpected OSV status {status}: {body}")]
    HttpStatus {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("rate limited by OSV API")]
    RateLimited { retry_after: Option<Duration> },
    #[error("invalid purl: {0}")]
    InvalidPurl(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("timeout: {0}")]
    Timeout(String),
}

pub type Result<T> = std::result::Result<T, VulnError>;
