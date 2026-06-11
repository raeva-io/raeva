use std::fmt;
use std::path::PathBuf;

use anyhow::Error as AnyhowError;
use thiserror::Error;

// Re-use the io context helper from rv-config; the db variant is owned here.
pub(crate) use rv_config::io_error_with_context;

/// Converts an `anyhow::Error` into a `rusqlite::Error` so context can flow
/// through the rusqlite return path without losing the underlying message.
///
/// Prefer [`StoreError::DbContext`] for new code; this helper exists to keep
/// the legacy `?` ergonomics on `rusqlite::Error`-returning closures.
///
/// Crate-internal: rusqlite::Error in the signature would otherwise leak the
/// SQLite type into the public API.
pub(crate) fn db_error_with_context(err: AnyhowError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(ContextError(err.to_string())))
}

/// Newtype wrapper that implements `std::error::Error` for a plain `String`.
#[derive(Debug)]
pub(crate) struct ContextError(String);

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ContextError {}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("sqlite error: {0}")]
    DbError(#[from] rusqlite::Error),
    /// Database error with structured context. Prefer this over
    /// `db_error_with_context` so callers can still match on the underlying
    /// `rusqlite::Error` kind.
    #[error("{ctx}: {source}")]
    DbContext {
        ctx: String,
        #[source]
        source: rusqlite::Error,
    },
    #[error("connection pool error: {0}")]
    PoolError(String),
    #[error("invalid blob id: {0}")]
    InvalidBlobId(String),
    #[error("integrity error: {0}")]
    IntegrityError(String),
    #[error(
        "lock timeout acquiring {path}\n\nAnother rv process holds the store lock. \
         Wait for it to finish or terminate the holder process before retrying. \
         Do NOT delete the lock file while a process may still be running: with \
         advisory file locks, removing the file creates a new inode that a fresh \
         process can lock independently of the existing holder, breaking mutual \
         exclusion.\n\nLock holder info: {holder_info}"
    )]
    LockTimeout { path: PathBuf, holder_info: String },
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Extension trait to simplify error wrapping with context.
pub(crate) trait IoResultExt<T> {
    fn io_context(self, context: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E> IoResultExt<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn io_context(self, context: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| {
            let err = anyhow::Error::new(e).context(context());
            StoreError::IoError(io_error_with_context(err))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::StoreError;

    #[test]
    fn invalid_blob_id_formats() {
        let err = StoreError::InvalidBlobId("bad".to_string());
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn lock_timeout_error_contains_helpful_message() {
        let err = StoreError::LockTimeout {
            path: PathBuf::from("/tmp/store/.lock"),
            holder_info: "pid=12345 time=1234567890".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/tmp/store/.lock"));
        assert!(msg.contains("pid=12345"));
        // The advice must NOT tell the user to delete the lock file: with
        // advisory locks that would let a second process lock a fresh inode
        // alongside the current holder.
        assert!(!msg.contains("rm /tmp/store/.lock"));
        assert!(msg.contains("holder process") || msg.contains("Wait"));
    }
}
