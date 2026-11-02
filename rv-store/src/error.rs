use std::path::PathBuf;

use thiserror::Error;

/// Why a store operation failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A file operation failed, or a blocking task could not be joined.
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    /// Database error with the operation that failed. The SQLite error is
    /// kept so callers can classify it by its result code.
    #[error("{ctx}: {source}")]
    DbContext {
        /// The operation that failed.
        ctx: String,
        /// The SQLite error.
        #[source]
        source: rusqlite::Error,
    },
    /// The index connection pool could not hand out or open a connection.
    #[error("connection pool error: {0}")]
    PoolError(String),
    /// A computed digest did not parse as a blob id.
    #[error("invalid blob id: {0}")]
    InvalidBlobId(rv_maven_types::DigestError),
    /// A stored blob is not what its id or the index requires, for example
    /// its bytes hash to another id or its file is missing.
    #[error("integrity error: {0}")]
    IntegrityError(String),
    /// The store lock was not acquired before the timeout.
    #[error(
        "lock timeout acquiring {path}\n\nAnother raeva process holds the store lock. \
         Wait for it to finish or terminate the holder process before retrying. \
         Do NOT delete the lock file while a process may still be running: with \
         advisory file locks, removing the file creates a new inode that a fresh \
         process can lock independently of the existing holder, breaking mutual \
         exclusion.\n\nLock holder info: {holder_info}"
    )]
    LockTimeout {
        /// The lock file.
        path: PathBuf,
        /// What the lock file says about its holder (`unknown` when it is
        /// empty), or that another thread of this process holds the lock.
        holder_info: String,
    },
    /// SQLite did not switch the index to WAL journal mode.
    #[error(
        "SQLite refused to enable WAL journal mode at {}: got journal_mode={mode}. \
         Network filesystems (NFS, SMB) often reject WAL; move it to local storage.",
        path.display()
    )]
    WalUnavailable {
        /// The database file.
        path: PathBuf,
        /// The journal mode SQLite reported instead.
        mode: String,
    },
    /// A newer raeva wrote the database, at a later schema generation than
    /// this one knows. It is left as it is.
    #[error(
        "{} was written by a newer raeva (schema generation {found}, this raeva knows up to \
         {supported}), so this one leaves it alone",
        path.display()
    )]
    NewerDatabase {
        /// The database file.
        path: PathBuf,
        /// The generation the file names.
        found: i64,
        /// The latest generation this raeva knows.
        supported: i64,
    },
}

pub(crate) type Result<T> = std::result::Result<T, StoreError>;

/// What a failed SQLite call says about the database, from its result code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DbFailure {
    /// The disk or the database is full.
    DiskFull,
    /// SQLite could not grow the database's shared-memory (`-shm`) file,
    /// most often because the volume is full; an I/O error can cause it
    /// too.
    SharedMemory,
    /// The database file could not be opened.
    CannotOpen,
    /// The file is damaged or is not an SQLite database.
    Corrupt,
    /// Any other result code.
    Other,
}

impl StoreError {
    /// For a database error, what its SQLite result code says; `None` for
    /// any other error.
    pub fn db_failure(&self) -> Option<DbFailure> {
        match self {
            StoreError::DbContext { source, .. } => Some(DbFailure::of(source)),
            _ => None,
        }
    }

    /// Whether the volume ran out of space or the user out of quota.
    pub fn is_disk_full(&self) -> bool {
        match self {
            StoreError::IoError(err) => out_of_space(err),
            _ => self.db_failure() == Some(DbFailure::DiskFull),
        }
    }
}

pub(crate) fn out_of_space(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded
    )
}

impl DbFailure {
    pub(crate) fn of(source: &rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;
        let Some(error) = source.sqlite_error() else {
            return DbFailure::Other;
        };
        match error.code {
            ErrorCode::DiskFull => DbFailure::DiskFull,
            // A full volume shows as this I/O error rather than SQLITE_FULL.
            ErrorCode::SystemIoFailure
                if error.extended_code == rusqlite::ffi::SQLITE_IOERR_SHMSIZE =>
            {
                DbFailure::SharedMemory
            }
            ErrorCode::CannotOpen => DbFailure::CannotOpen,
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => DbFailure::Corrupt,
            _ => DbFailure::Other,
        }
    }
}

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
            // Keep the kind of an io::Error in the chain.
            let kind = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>().map(|io| io.kind()))
                .unwrap_or(std::io::ErrorKind::Other);
            StoreError::IoError(std::io::Error::new(kind, err))
        })
    }
}

pub(crate) trait DbResultExt<T> {
    /// Names the failed operation and keeps the SQLite error.
    fn db_context<C: Into<String>>(self, ctx: impl FnOnce() -> C) -> Result<T>;
}

impl<T> DbResultExt<T> for std::result::Result<T, rusqlite::Error> {
    fn db_context<C: Into<String>>(self, ctx: impl FnOnce() -> C) -> Result<T> {
        self.map_err(|source| StoreError::DbContext {
            ctx: ctx().into(),
            source,
        })
    }
}

pub(crate) fn pool_error(ctx: &str, err: r2d2::Error) -> StoreError {
    StoreError::PoolError(format!("{ctx}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{DbFailure, DbResultExt, StoreError};

    #[test]
    fn classifies_database_errors_by_code() {
        use rusqlite::ffi;
        for (code, failure) in [
            (ffi::SQLITE_FULL, DbFailure::DiskFull),
            (ffi::SQLITE_CANTOPEN, DbFailure::CannotOpen),
            (ffi::SQLITE_CORRUPT, DbFailure::Corrupt),
            (ffi::SQLITE_NOTADB, DbFailure::Corrupt),
            (ffi::SQLITE_BUSY, DbFailure::Other),
            (ffi::SQLITE_IOERR_SHMSIZE, DbFailure::SharedMemory),
            (ffi::SQLITE_IOERR_WRITE, DbFailure::Other),
        ] {
            let err = Err::<(), _>(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None))
                .db_context(|| "failed to upsert artifact")
                .unwrap_err();
            assert_eq!(err.db_failure(), Some(failure));
        }
        assert_eq!(StoreError::PoolError("timed out".into()).db_failure(), None);
    }

    /// With advisory locks, deleting the lock file would let a second
    /// process lock a fresh inode next to the holder.
    #[test]
    fn lock_timeout_names_the_holder_and_does_not_advise_deleting_the_lock() {
        let msg = StoreError::LockTimeout {
            path: "/tmp/store/.lock".into(),
            holder_info: "pid=12345 time=1234567890".to_string(),
        }
        .to_string();
        assert!(msg.contains("/tmp/store/.lock") && msg.contains("pid=12345"));
        assert!(msg.contains("Do NOT delete the lock file"));
    }
}
