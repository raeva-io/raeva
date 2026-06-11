use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tokio::fs as tokio_fs;
use tokio::io::AsyncWriteExt;

use crate::error::{IoResultExt, Result, StoreError, db_error_with_context};
use crate::index;
use crate::paths;
use rv_config::{ArtifactKey, BlobId};

const INDEX_DB: &str = "index.sqlite";

const TMP_DIR: &str = "tmp";
const LOCK_FILE: &str = ".lock";
/// r2d2 pool size for the SQLite index. SQLite handles concurrent readers
/// in WAL mode; eight is enough for the resolver/sync fan-out without
/// running into the per-process file-descriptor ceiling.
const DEFAULT_POOL_SIZE: u32 = 8;

/// Sweep `tmp/` of files older than 24 hours. Uses a non-blocking `StoreLock`
/// to defer to active writers; the next `Store::open` retries.
fn sweep_temp_dir(root: &Path) {
    let lock_path = root.join(LOCK_FILE);
    let lock_file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(
                path = %lock_path.display(),
                error = %e,
                "skipping temp cleanup: cannot open lock file"
            );
            return;
        }
    };

    // Non-blocking try-lock so cleanup never blocks store open. If a real
    // writer is mid-flight, defer this sweep to the next open.
    use fs2::FileExt;
    if lock_file.try_lock_exclusive().is_err() {
        tracing::debug!("skipping temp cleanup: store lock held by another process");
        return;
    }
    // RAII guard so we unlock on every exit path.
    struct UnlockOnDrop<'a>(&'a File);
    impl Drop for UnlockOnDrop<'_> {
        fn drop(&mut self) {
            let _ = fs2::FileExt::unlock(self.0);
        }
    }
    let _guard = UnlockOnDrop(&lock_file);

    let tmp_dir = root.join(TMP_DIR);
    let stale_threshold = Duration::from_secs(24 * 3600);
    sweep_temp_dir_recursive(&tmp_dir, stale_threshold);
}

fn sweep_temp_dir_recursive(dir: &Path, stale_threshold: Duration) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "failed to read temp directory during cleanup"
            );
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    path = %dir.display(),
                    error = %e,
                    "failed to read temp directory entry during cleanup"
                );
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %e,
                    "failed to stat temp entry during cleanup"
                );
                continue;
            }
        };

        // Skip symlinks: temp dir should not legitimately contain them and
        // following them would let an attacker steer cleanup at a chosen file.
        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            sweep_temp_dir_recursive(&path, stale_threshold);
            // Best-effort attempt to remove the directory if empty after
            // descending. Ignore errors (not-empty / not-found are both fine).
            let _ = fs::remove_dir(&path);
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|age| age > stale_threshold);
        if stale && let Err(e) = fs::remove_file(&path) {
            tracing::debug!(path = %path.display(), error = %e, "failed to remove stale temp file");
        }
    }
}

/// Verifies that the blob at path matches the expected ID by computing its hash.
/// Returns Ok(id) if the blob exists and matches, Err otherwise.
fn verify_blob_at_path(path: &Path, expected: &BlobId) -> Result<BlobId> {
    let actual = BlobId::from_file(path)?;
    if &actual == expected {
        Ok(actual)
    } else {
        Err(StoreError::IntegrityError(format!(
            "blob at {} has hash {} but expected {}",
            path.display(),
            actual,
            expected
        )))
    }
}

/// Set 0o444 on a freshly-staged CAS blob before publish so the published
/// inode is world-readable. The tempfile crate defaults to 0o600, which
/// breaks multi-user / CI runs where `mvn` runs under a different uid than
/// the writer. Unix only; Windows ACLs are left to the OS default.
#[cfg(unix)]
fn set_blob_readonly(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o444)) {
        tracing::debug!(
            path = %path.display(),
            error = %e,
            "failed to set 0o444 on staged CAS blob"
        );
    }
}

#[cfg(not(unix))]
fn set_blob_readonly(_path: &Path) {}

/// fsync the directory chain from a published blob's parent up to and
/// including the store's blob root so every dirent the publish may have
/// created (both shard directories plus the blob itself) survives a crash.
/// Syncing all levels unconditionally is two extra opens per publish and is
/// simpler than tracking which directories create_dir_all actually made.
///
/// Failures are returned, not advisory: an EIO here means the dirent may not
/// be durable, so committing an index row for the blob could leave the row
/// pointing at a file that vanishes after a crash. Callers must treat a
/// failure as a failed publish and must not index the blob. The published
/// file itself is left in place; without an index row it is a harmless
/// orphan that GC collects, and deleting it could orphan other index rows
/// when the blob already existed.
#[cfg(unix)]
fn fsync_blob_dirs(blob_root: &Path, blob_path: &Path) -> Result<()> {
    let mut dir = blob_path.parent();
    while let Some(d) = dir {
        let handle = File::open(d)
            .io_context(|| format!("failed to open directory {} for fsync", d.display()))?;
        handle
            .sync_all()
            .io_context(|| format!("failed to fsync directory {}", d.display()))?;
        if d == blob_root {
            break;
        }
        dir = d.parent();
    }
    Ok(())
}

/// Directory fsync is unavailable on this platform (File::open on a
/// directory fails on Windows); dirent durability is left to the OS,
/// matching the previous advisory behavior.
#[cfg(not(unix))]
fn fsync_blob_dirs(_blob_root: &Path, _blob_path: &Path) -> Result<()> {
    Ok(())
}

/// Atomically publish `src` at `target` via `hard_link(2) + unlink(2)`. The
/// link call refuses to overwrite an existing inode (POSIX "noclobber rename"
/// pattern), so a concurrent writer who beat us to the punch keeps their
/// bytes; we verify their hash and report `BlobOrigin::Existed` in that case.
fn publish_noclobber(
    src: &Path,
    target: &Path,
    expected_id: &BlobId,
    on_success: BlobOrigin,
) -> Result<(BlobId, BlobOrigin)> {
    match fs::hard_link(src, target) {
        Ok(()) => {
            // hard_link succeeded: `src` is now an extra link to the same
            // inode. Unlink the temp path; if it fails we still have the
            // published file in place, so just log.
            if let Err(e) = fs::remove_file(src) {
                tracing::debug!(
                    path = %src.display(),
                    error = %e,
                    "failed to unlink temp source after hard_link"
                );
            }
            Ok((expected_id.clone(), on_success))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another writer won the publish race. Verify their bytes and
            // adopt their inode.
            let result = verify_blob_at_path(target, expected_id);
            let _ = fs::remove_file(src);
            match result {
                Ok(id) => Ok((id, BlobOrigin::Existed)),
                Err(err) => Err(err),
            }
        }
        Err(e) => {
            // hard_link can fail with EXDEV on cross-device temp dirs
            // (which shouldn't happen for our sibling TMP_DIR) or with
            // permission errors on filesystems that disallow links (FAT,
            // some FUSE mounts). Fall back to rename but never silently
            // clobber a target that already has content; verify it first.
            tracing::debug!(
                src = %src.display(),
                target = %target.display(),
                error = %e,
                "hard_link failed, falling back to rename"
            );
            // `fs::metadata` follows symlinks, so a dangling symlink at
            // `target` returns Err here and we fall through to the rename;
            // a regular file at `target` (or a symlink to one) is detected
            // and gets the verify-then-adopt treatment that prevents a
            // silent overwrite of someone else's bytes. `symlink_metadata`
            // would instead treat a dangling symlink as a non-file and let
            // `fs::rename` clobber it.
            if let Ok(meta) = fs::metadata(target)
                && meta.is_file()
            {
                let verify = verify_blob_at_path(target, expected_id);
                let _ = fs::remove_file(src);
                return match verify {
                    Ok(id) => Ok((id, BlobOrigin::Existed)),
                    Err(err) => Err(err),
                };
            }
            match fs::rename(src, target) {
                Ok(()) => {}
                Err(rename_err) if rename_err.kind() == std::io::ErrorKind::AlreadyExists => {
                    // On Windows, `fs::rename` returns `ERROR_ALREADY_EXISTS`
                    // when the destination exists (unlike POSIX which atomically
                    // replaces it). This is a legitimate CAS race: another
                    // writer published the same content between our pre-flight
                    // metadata check and this rename. Verify the winner's bytes
                    // and adopt their inode rather than erroring.
                    let verify = verify_blob_at_path(target, expected_id);
                    let _ = fs::remove_file(src);
                    return match verify {
                        Ok(id) => Ok((id, BlobOrigin::Existed)),
                        Err(err) => Err(err),
                    };
                }
                Err(rename_err) => {
                    let _ = fs::remove_file(src);
                    return Err(StoreError::IoError(std::io::Error::other(format!(
                        "failed to publish blob from {} to {}: {}",
                        src.display(),
                        target.display(),
                        rename_err
                    ))));
                }
            }
            Ok((expected_id.clone(), on_success))
        }
    }
}

/// Persist a tempfile via `persist_noclobber` so concurrent writers with the
/// same bytes keep their inode. On collision, verify the existing file; if it
/// hashes wrong it is treated as corrupt and the write is retried (repair).
fn persist_blob_with_repair(
    temp_file: NamedTempFile,
    target: &Path,
    expected_id: &BlobId,
) -> Result<BlobId> {
    match temp_file.persist_noclobber(target) {
        Ok(_) => Ok(expected_id.clone()),
        Err(persist_err) => {
            if persist_err.error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(StoreError::IoError(std::io::Error::other(format!(
                    "failed to persist blob to {}: {}",
                    target.display(),
                    persist_err
                ))));
            }

            // File already exists: verify it has the correct hash.
            match verify_blob_at_path(target, expected_id) {
                Ok(id) => Ok(id),
                Err(StoreError::IntegrityError(msg)) => {
                    // Corrupt file detected; repair by deleting and retrying.
                    // Use `persist_noclobber` on the retry: if another writer
                    // raced us between the `remove_file` and the retry,
                    // overwriting their fresh inode with ours could publish a
                    // half-flushed file. Verify their bytes instead.
                    tracing::warn!(
                        path = %target.display(),
                        "detected corrupt blob, repairing: {}",
                        msg
                    );
                    fs::remove_file(target).io_context(|| {
                        format!("failed to remove corrupt blob at {}", target.display())
                    })?;
                    match persist_err.file.persist_noclobber(target) {
                        Ok(_) => Ok(expected_id.clone()),
                        Err(retry_err)
                            if retry_err.error.kind() == std::io::ErrorKind::AlreadyExists =>
                        {
                            verify_blob_at_path(target, expected_id)
                        }
                        Err(retry_err) => Err(StoreError::IoError(std::io::Error::other(format!(
                            "failed to persist blob after repair to {}: {}",
                            target.display(),
                            retry_err
                        )))),
                    }
                }
                Err(StoreError::IoError(io_err))
                    if io_err.kind() == std::io::ErrorKind::NotFound =>
                {
                    // TOCTOU: file was deleted between persist failure and
                    // verify. Same race window as the repair branch above:
                    // use `persist_noclobber` so a winning concurrent writer
                    // keeps their bytes.
                    tracing::debug!(
                        path = %target.display(),
                        "blob deleted during persist, retrying"
                    );
                    match persist_err.file.persist_noclobber(target) {
                        Ok(_) => Ok(expected_id.clone()),
                        Err(retry_err)
                            if retry_err.error.kind() == std::io::ErrorKind::AlreadyExists =>
                        {
                            verify_blob_at_path(target, expected_id)
                        }
                        Err(retry_err) => Err(StoreError::IoError(std::io::Error::other(format!(
                            "failed to persist blob after TOCTOU retry to {}: {}",
                            target.display(),
                            retry_err
                        )))),
                    }
                }
                Err(e) => Err(e),
            }
        }
    }
}

/// Similar to `persist_blob_with_repair` but for `TempPath` instead of `NamedTempFile`.
/// Note: TempPath's persist error doesn't retain the file handle, so we need the
/// temp_path reference to be convertible back to the source path for retry.
fn persist_blob_path_with_repair(
    temp_path: tempfile::TempPath,
    target: &Path,
    expected_id: &BlobId,
) -> Result<(BlobId, BlobOrigin)> {
    // Use `persist_noclobber` so we can detect when a blob with this content
    // hash is already present on disk and avoid clobbering it. `TempPath::persist`
    // would unconditionally overwrite, which prevents the dedup signal that
    // callers rely on for safe rollback.
    match temp_path.persist_noclobber(target) {
        Ok(_) => Ok((expected_id.clone(), BlobOrigin::Created)),
        Err(persist_err) => {
            if persist_err.error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(StoreError::IoError(std::io::Error::other(format!(
                    "failed to persist blob to {}: {}",
                    target.display(),
                    persist_err
                ))));
            }

            // File already exists: verify it has the correct hash.
            // The temp file (persist_err.path) still exists since persist failed.
            let temp_source = persist_err.path;

            match verify_blob_at_path(target, expected_id) {
                Ok(id) => {
                    // Target is valid; clean up the temp file.
                    let _ = fs::remove_file(&temp_source);
                    Ok((id, BlobOrigin::Existed))
                }
                Err(StoreError::IntegrityError(msg)) => {
                    // Corrupt file detected; repair by deleting and retrying.
                    // We are overwriting the corrupt on-disk blob with the
                    // freshly streamed bytes, so the caller now owns it.
                    tracing::warn!(
                        path = %target.display(),
                        "detected corrupt blob, repairing: {}",
                        msg
                    );
                    if let Err(remove_err) = fs::remove_file(target) {
                        // Drop our temp bytes so we don't leak an inode on
                        // the way out.
                        let _ = fs::remove_file(&temp_source);
                        return Err(StoreError::IoError(std::io::Error::other(format!(
                            "failed to remove corrupt blob at {}: {}",
                            target.display(),
                            remove_err
                        ))));
                    }
                    // Noclobber publish: if a third writer raced us between
                    // remove_file and link, the link fails with AlreadyExists
                    // and we verify-and-reuse their inode (#13).
                    publish_noclobber(&temp_source, target, expected_id, BlobOrigin::Created)
                }
                Err(StoreError::IoError(io_err))
                    if io_err.kind() == std::io::ErrorKind::NotFound =>
                {
                    // TOCTOU: file was deleted between persist failure and
                    // verify. Retry the write with noclobber semantics so a
                    // concurrent winner is preserved.
                    tracing::debug!(
                        path = %target.display(),
                        "blob deleted during persist, retrying"
                    );
                    publish_noclobber(&temp_source, target, expected_id, BlobOrigin::Created)
                }
                Err(e) => {
                    // Clean up temp file on other errors
                    let _ = fs::remove_file(&temp_source);
                    Err(e)
                }
            }
        }
    }
}

/// Content-addressed artifact store backed by SHA-256 hashed blobs and a SQLite index.
///
/// Blobs are stored in a directory tree keyed by their SHA-256 hash. A SQLite database
/// maps Maven coordinates (`ArtifactKey`) to blob IDs. Concurrent access is safe via
/// file locking and connection pooling.
#[derive(Clone)]
pub struct Store {
    root: PathBuf,
    pool: Arc<Pool<SqliteConnectionManager>>,
}

/// Summary statistics for the content-addressed store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub blob_count: usize,
    pub total_bytes: u64,
}

/// Result of a garbage collection or clean operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcSummary {
    pub removed_blobs: usize,
    pub removed_bytes: u64,
}

/// Whether a CAS insertion landed on a fresh blob or hit an existing one.
///
/// Callers that perform a post-insert verification step (e.g. comparing a
/// sidecar checksum against the streamed bytes) must only delete the blob
/// when they created it; deleting a pre-existing blob would orphan every
/// other artifact-key row that references it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobOrigin {
    /// The blob did not exist on disk and was just written.
    Created,
    /// The blob was already in the store; the streamed bytes were discarded.
    Existed,
}

struct BlobEntry {
    id: BlobId,
    path: PathBuf,
    size: u64,
}

impl Store {
    /// Opens or creates a content-addressed store at the given path.
    ///
    /// Uses a connection pool with 8 connections by default.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory cannot be created
    /// - The SQLite index database cannot be opened or initialized
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_pool_size(path, DEFAULT_POOL_SIZE)
    }

    /// Opens a store with a custom SQLite connection pool size.
    pub fn open_with_pool_size(path: &Path, pool_size: u32) -> Result<Self> {
        fs::create_dir_all(path)
            .io_context(|| format!("failed to create store directory {}", path.display()))?;
        fs::create_dir_all(paths::blob_root(path)).io_context(|| {
            format!(
                "failed to create blob directory {}",
                paths::blob_root(path).display()
            )
        })?;
        fs::create_dir_all(path.join(TMP_DIR)).io_context(|| {
            format!(
                "failed to create temp directory {}",
                path.join(TMP_DIR).display()
            )
        })?;

        let db_path = path.join(INDEX_DB);

        // Cross-process serialise WAL bootstrap + schema initialization (#2).
        // Two `rv` processes calling `Store::open` concurrently must not race
        // on `PRAGMA journal_mode=WAL` (database-scoped, requires exclusive
        // lock to flip) or on `CREATE TABLE` / `ALTER TABLE` migrations.
        // Same advisory lock writers use; any in-flight writer also serialises
        // us behind it.
        let bootstrap_lock = StoreLock::acquire(path)?;

        // Fast-fail on a clearly corrupt SQLite file before we hand it to the
        // pool. Without this check, a non-SQLite file (or a truncated one)
        // still sees the connection initializer run, and `busy_timeout` makes
        // the header-validation probe wait up to 30 s before erroring. Run
        // this AFTER acquiring bootstrap_lock so a concurrent bootstrap that
        // just touched index.sqlite (zero bytes, header not yet written) is
        // never misread as a corrupt file; an empty / short-read file is
        // treated as "not yet initialised" and the open proceeds.
        if let Ok(meta) = fs::metadata(&db_path)
            && meta.is_file()
            && meta.len() > 0
        {
            let mut header = [0u8; 16];
            let mut f = File::open(&db_path)
                .io_context(|| format!("failed to open index file {}", db_path.display()))?;
            let n = f
                .read(&mut header)
                .io_context(|| format!("failed to read index header from {}", db_path.display()))?;
            const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
            if n == SQLITE_MAGIC.len() && &header != SQLITE_MAGIC {
                return Err(StoreError::DbError(db_error_with_context(anyhow::anyhow!(
                    "index file {} is not a valid SQLite database (bad header)",
                    db_path.display()
                ))));
            }
            // n < SQLITE_MAGIC.len(): file is being initialised by a peer
            // who beat us to bootstrap_lock; SQLite::open below will block
            // on the file lock as usual.
        }

        // Set WAL/synchronous mode on a single bootstrap connection BEFORE
        // building the r2d2 pool. r2d2 eagerly opens `max_size` connections
        // and runs `with_init` on each in parallel; if every connection tries
        // to flip `journal_mode=WAL` concurrently, the losers log
        // `database is locked` through rusqlite's `log` callback. Doing the
        // mode switch once up-front makes the per-connection initializer a
        // no-op write of session-scoped pragmas only.
        {
            let bootstrap = rusqlite::Connection::open(&db_path)
                .with_context(|| {
                    format!(
                        "failed to open index for WAL bootstrap at {}",
                        db_path.display()
                    )
                })
                .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
            bootstrap
                .busy_timeout(std::time::Duration::from_secs(5))
                .with_context(|| "failed to set busy_timeout on bootstrap connection")
                .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
            bootstrap
                .pragma_update(None, "journal_mode", "WAL")
                .with_context(|| "failed to set journal_mode=WAL")
                .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
            // Verify the mode actually flipped (#2). SQLite can silently
            // fall back to DELETE if the filesystem refuses WAL (network
            // mounts, etc.); a silent fallback would erase the concurrency
            // guarantees the rest of the store relies on.
            let mode: String = bootstrap
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .with_context(|| "failed to read back journal_mode")
                .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(StoreError::DbError(db_error_with_context(anyhow::anyhow!(
                    "SQLite refused to enable WAL journal mode at {}: got journal_mode={}. \
                     Network filesystems (NFS, SMB) frequently reject WAL; move the store to local storage.",
                    db_path.display(),
                    mode
                ))));
            }
            bootstrap
                .pragma_update(None, "synchronous", "NORMAL")
                .with_context(|| "failed to set synchronous=NORMAL")
                .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
            // Drop closes the connection so the pool can take over cleanly.
        }

        let manager = SqliteConnectionManager::file(&db_path).with_init(|conn| {
            // journal_mode is database-scoped (set on the bootstrap connection
            // above). synchronous is stored per-connection by SQLite, so a
            // pooled connection that skips the pragma falls back to FULL and
            // the durability-vs-throughput tradeoff splits across the pool.
            // foreign_keys is per-connection and OFF by default; turn it on
            // so any future FK constraints are actually enforced. temp_store
            // pushes temp B-trees into memory instead of /tmp, which both
            // speeds up sorts and avoids leaking temp files on crash.
            conn.execute_batch(
                "PRAGMA busy_timeout=5000;
                 PRAGMA cache_size=-32000;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA temp_store=MEMORY;",
            )?;
            Ok(())
        });

        let pool = Pool::builder()
            .max_size(pool_size)
            .build(manager)
            .with_context(|| format!("failed to create connection pool for {}", db_path.display()))
            .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;

        {
            let conn = pool
                .get()
                .with_context(|| "failed to get connection from pool for initialization")
                .map_err(|err| StoreError::DbError(db_error_with_context(err)))?;
            index::init_db(&conn)?;
        }

        // Release the bootstrap lock before the synchronous temp sweep:
        // the sweep takes its own non-blocking try_lock and would otherwise
        // always fail (we hold the lock).
        drop(bootstrap_lock);

        let store = Self {
            root: path.to_path_buf(),
            pool: Arc::new(pool),
        };

        // Inline temp cleanup synchronously (#19). The sweep takes a
        // non-blocking `StoreLock`; if another process is actively writing
        // it returns immediately and the next open retries.
        sweep_temp_dir(path);

        tracing::debug!(path = %path.display(), "store opened");

        Ok(store)
    }

    /// If content already exists, returns the existing blob ID without re-storing.
    pub async fn put_bytes(&self, bytes: &[u8]) -> Result<BlobId> {
        let size = bytes.len();

        let root = self.root.clone();
        // `Arc::from(&[u8])` copies the slice into a fresh owned allocation
        // (it is not zero-copy); the Arc then lets us move ownership across the
        // `spawn_blocking` boundary cheaply. We do this because SHA-256 of
        // multi-MB payloads can stall the tokio runtime if computed on the
        // async worker, so the hash runs inside `spawn_blocking` below (#7).
        let bytes: Arc<[u8]> = Arc::from(bytes);

        tokio::task::spawn_blocking(move || {
            // Hash on the blocking pool, not the async worker (#7).
            let id = BlobId::from_bytes(&bytes);
            tracing::debug!(sha256 = %id, size, "storing blob");
            let target = root.join(paths::blob_path(&id));

            let tmp_dir = root.join(TMP_DIR);
            fs::create_dir_all(&tmp_dir)
                .io_context(|| format!("failed to create temp directory {}", tmp_dir.display()))?;

            // Write to temp file WITHOUT holding the lock
            let mut temp_file = NamedTempFile::new_in(&tmp_dir)
                .io_context(|| "failed to create temp file".to_string())?;

            temp_file
                .write_all(&bytes)
                .io_context(|| "failed to write blob content".to_string())?;

            temp_file
                .as_file()
                .sync_all()
                .io_context(|| "failed to sync blob".to_string())?;

            set_blob_readonly(temp_file.path());

            // Only acquire lock for the final persist operation
            let _lock = StoreLock::acquire(&root)?;

            let parent = target.parent().ok_or_else(|| {
                StoreError::IntegrityError("blob path missing parent directory".to_string())
            })?;
            fs::create_dir_all(parent)
                .io_context(|| format!("failed to create blob directory {}", parent.display()))?;

            let result = persist_blob_with_repair(temp_file, &target, &id)?;
            fsync_blob_dirs(&paths::blob_root(&root), &target)?;
            Ok(result)
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Stores a blob from an async byte stream, computing the SHA-256 hash incrementally.
    ///
    /// Reachable only inside this crate so that out-of-tree callers cannot
    /// reopen the GC race that the two-step `put_stream` + `add_artifact`
    /// sequence allowed. Use [`Store::put_stream_and_index`] for the
    /// atomic put-and-index path, or [`Store::put_stream_with_origin`] when
    /// you only need the blob without an index row.
    #[cfg(test)]
    pub(crate) async fn put_stream<S, E>(&self, stream: S) -> Result<BlobId>
    where
        S: Stream<Item = std::result::Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        self.put_stream_with_origin(stream).await.map(|(id, _)| id)
    }

    /// Like `put_stream`, but also reports whether the blob was created by
    /// this call or already existed (deduplicated).
    ///
    /// Callers that perform a post-insert verification step (sidecar checksum,
    /// signature, etc.) should rely on this signal: deleting a blob that was
    /// already in the store on a verification failure corrupts every other
    /// artifact-key row pointing at it.
    pub async fn put_stream_with_origin<S, E>(&self, stream: S) -> Result<(BlobId, BlobOrigin)>
    where
        S: Stream<Item = std::result::Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        let tmp_dir = self.root.join(TMP_DIR);
        tokio_fs::create_dir_all(&tmp_dir)
            .await
            .io_context(|| format!("failed to create temp directory {}", tmp_dir.display()))?;

        let temp_file = tokio::task::spawn_blocking(move || {
            NamedTempFile::new_in(&tmp_dir).io_context(|| "failed to create temp file".to_string())
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))??;

        let (std_file, temp_path) = temp_file.into_parts();
        let mut async_file = tokio_fs::File::from_std(std_file);

        let mut hasher = Sha256::new();
        futures_util::pin_mut!(stream);

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(bytes) => bytes,
                Err(err) => {
                    return Err(StoreError::IoError(std::io::Error::other(err.to_string())));
                }
            };
            hasher.update(&chunk);
            async_file
                .write_all(&chunk)
                .await
                .io_context(|| "failed to write blob chunk".to_string())?;
        }

        async_file
            .sync_all()
            .await
            .io_context(|| "failed to sync temp blob".to_string())?;

        drop(async_file);

        set_blob_readonly(&temp_path);

        let digest = hasher.finalize();
        let id = BlobId::from_str(&hex::encode(digest)).map_err(StoreError::InvalidBlobId)?;

        let target = self.get_path(&id);

        let root = self.root.clone();

        tokio::task::spawn_blocking(move || {
            let _lock = StoreLock::acquire(&root)?;

            let parent = target.parent().ok_or_else(|| {
                StoreError::IntegrityError("blob path missing parent directory".to_string())
            })?;
            fs::create_dir_all(parent)
                .io_context(|| format!("failed to create blob directory {}", parent.display()))?;

            let result = persist_blob_path_with_repair(temp_path, &target, &id)?;
            fsync_blob_dirs(&paths::blob_root(&root), &target)?;
            Ok(result)
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Stores a blob from a stream and atomically indexes it under the given
    /// Maven coordinate, holding the store lock across both steps.
    ///
    /// This is the race-free alternative to calling `put_stream` followed by
    /// `add_artifact`. Between those two calls, a concurrent `prune_blobs`
    /// (GC) sweep could observe the freshly-persisted blob without an index
    /// row pointing at it and delete it, leaving the eventual artifact row
    /// dangling. By holding the store lock for the entire persist + index
    /// step, this method makes the put-and-index transition atomic with
    /// respect to GC.
    ///
    /// Returns the blob id along with whether this call created the blob or
    /// found it already present in the store.
    pub async fn put_stream_and_index<S, E>(
        &self,
        key: &ArtifactKey,
        stream: S,
    ) -> Result<(BlobId, BlobOrigin)>
    where
        S: Stream<Item = std::result::Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        let tmp_dir = self.root.join(TMP_DIR);
        tokio_fs::create_dir_all(&tmp_dir)
            .await
            .io_context(|| format!("failed to create temp directory {}", tmp_dir.display()))?;

        let temp_file = tokio::task::spawn_blocking(move || {
            NamedTempFile::new_in(&tmp_dir).io_context(|| "failed to create temp file".to_string())
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))??;

        let (std_file, temp_path) = temp_file.into_parts();
        let mut async_file = tokio_fs::File::from_std(std_file);

        let mut hasher = Sha256::new();
        futures_util::pin_mut!(stream);

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(bytes) => bytes,
                Err(err) => {
                    return Err(StoreError::IoError(std::io::Error::other(err.to_string())));
                }
            };
            hasher.update(&chunk);
            async_file
                .write_all(&chunk)
                .await
                .io_context(|| "failed to write blob chunk".to_string())?;
        }

        async_file
            .sync_all()
            .await
            .io_context(|| "failed to sync temp blob".to_string())?;

        drop(async_file);

        set_blob_readonly(&temp_path);

        let digest = hasher.finalize();
        let id = BlobId::from_str(&hex::encode(digest)).map_err(StoreError::InvalidBlobId)?;

        let target = self.get_path(&id);
        let root = self.root.clone();
        let pool = self.pool.clone();
        let key = key.clone();
        let id_for_blocking = id.clone();

        tokio::task::spawn_blocking(move || {
            // Hold the store lock across BOTH the blob persist and the
            // index insert. This closes the GC race window where a sweep
            // could observe a just-persisted blob with no index row and
            // delete it before the caller had a chance to record the
            // mapping.
            let _lock = StoreLock::acquire(&root)?;

            let parent = target.parent().ok_or_else(|| {
                StoreError::IntegrityError("blob path missing parent directory".to_string())
            })?;
            fs::create_dir_all(parent)
                .io_context(|| format!("failed to create blob directory {}", parent.display()))?;

            let (blob_id, origin) =
                persist_blob_path_with_repair(temp_path, &target, &id_for_blocking)?;
            // A dirent that is not durable must not gain an index row; the
            // error return here skips the add_artifact below.
            fsync_blob_dirs(&paths::blob_root(&root), &target)?;

            // Stat the just-published blob so we can record size_bytes (#20).
            // We just wrote it under the lock, so the stat is essentially free
            // and the row is guaranteed to point at a real file.
            let size_bytes = fs::symlink_metadata(&target).map(|m| m.len()).unwrap_or(0);

            let conn = pool
                .get()
                .map_err(|err| StoreError::PoolError(err.to_string()))?;
            index::add_artifact(&conn, &key, &blob_id, size_bytes)?;

            Ok((blob_id, origin))
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Stores a file from the filesystem into the content-addressed store.
    ///
    /// The file is read in 128KB chunks to avoid loading large files into memory.
    /// The hash is computed incrementally while streaming to a temp file, then
    /// the temp file is atomically renamed to its final content-addressed path.
    pub async fn put_file(&self, path: &Path) -> Result<BlobId> {
        let root = self.root.clone();
        let source_path = path.to_path_buf();

        tokio::task::spawn_blocking(move || {
            let tmp_dir = root.join(TMP_DIR);
            fs::create_dir_all(&tmp_dir)
                .io_context(|| format!("failed to create temp directory {}", tmp_dir.display()))?;

            let mut temp_file = NamedTempFile::new_in(&tmp_dir)
                .io_context(|| "failed to create temp file".to_string())?;

            let mut source = fs::File::open(&source_path)
                .io_context(|| format!("failed to open source file {}", source_path.display()))?;

            let mut hasher = Sha256::new();
            let mut buf = [0u8; 128 * 1024];
            loop {
                let n = source
                    .read(&mut buf)
                    .io_context(|| "failed to read source file".to_string())?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                temp_file
                    .write_all(&buf[..n])
                    .io_context(|| "failed to write temp blob".to_string())?;
            }

            temp_file
                .as_file()
                .sync_all()
                .io_context(|| "failed to sync temp blob".to_string())?;

            set_blob_readonly(temp_file.path());

            let digest = hasher.finalize();
            let id = BlobId::from_str(&hex::encode(digest)).map_err(StoreError::InvalidBlobId)?;

            let target = root.join(crate::paths::blob_path(&id));

            let _lock = StoreLock::acquire(&root)?;

            let parent = target.parent().ok_or_else(|| {
                StoreError::IntegrityError("blob path missing parent directory".to_string())
            })?;
            fs::create_dir_all(parent)
                .io_context(|| format!("failed to create blob directory {}", parent.display()))?;

            let result = persist_blob_with_repair(temp_file, &target, &id)?;
            fsync_blob_dirs(&paths::blob_root(&root), &target)?;
            Ok(result)
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Returns the filesystem path for a blob by its content hash.
    pub fn get_path(&self, id: &BlobId) -> PathBuf {
        self.root.join(paths::blob_path(id))
    }

    // Test-only synchronous probe. Production code uses `exists_async`; this
    // shorthand exists for in-crate unit tests that need a quick boolean
    // without paying for a tokio task hop.
    #[cfg(test)]
    fn exists(&self, id: &BlobId) -> bool {
        let found = self.get_path(id).is_file();
        tracing::debug!(sha256 = %id, hit = found, "blob lookup");
        found
    }

    /// Async version of `exists` using `tokio::fs::metadata` so the runtime
    /// stays on its async I/O path instead of paying for a thread hop.
    pub async fn exists_async(&self, id: &BlobId) -> bool {
        let path = self.get_path(id);
        let found = match tokio::fs::metadata(&path).await {
            Ok(meta) => meta.is_file(),
            Err(_) => false,
        };
        tracing::debug!(sha256 = %id, hit = found, "blob lookup (async)");
        found
    }

    /// Records a mapping from a Maven coordinate to a blob in the index.
    pub async fn add_artifact(&self, key: &ArtifactKey, id: &BlobId) -> Result<()> {
        tracing::debug!(
            group_id = %key.group_id,
            artifact_id = %key.artifact_id,
            version = %key.version,
            sha256 = %id,
            "indexing artifact"
        );
        let pool = self.pool.clone();
        let root = self.root.clone();
        let key = key.clone();
        let id = id.clone();
        tokio::task::spawn_blocking(move || {
            // Acquire the store lock so add_artifact and prune_blobs (which
            // also takes the lock) cannot interleave and observe a state
            // where a blob file exists but has no index row, or the reverse.
            let _lock = StoreLock::acquire(&root)?;
            // Verify the blob file exists before writing the row (#11). Stat
            // only (no re-hash): a hash recompute would dominate the hot
            // path, but a missing inode is cheap to detect and avoids
            // writing a row that no caller could ever follow.
            let path = root.join(paths::blob_path(&id));
            let size_bytes = match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() => meta.len(),
                Ok(_) => {
                    return Err(StoreError::IntegrityError(format!(
                        "refusing to index {key} -> {id}: path {} is not a regular file",
                        path.display()
                    )));
                }
                Err(e) => {
                    return Err(StoreError::IntegrityError(format!(
                        "refusing to index {key} -> {id}: blob file {} not present ({})",
                        path.display(),
                        e
                    )));
                }
            };
            let conn = pool
                .get()
                .map_err(|err| StoreError::PoolError(err.to_string()))?;
            index::add_artifact(&conn, &key, &id, size_bytes)
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Remove the index row for `key`, if any.
    ///
    /// Used to repair a row that was committed before its checksum sidecar
    /// verification failed: dropping the row makes the next sync re-fetch and
    /// re-verify the artifact instead of trusting the unverified bytes forever
    /// (which mattered most for unpinned companion POMs, whose `needs_download`
    /// fast-path does not re-hash). Does NOT delete the content-addressed blob.
    /// It may be shared with other coordinates; blob lifecycle is GC's job.
    pub async fn remove_artifact(&self, key: &ArtifactKey) -> Result<()> {
        let pool = self.pool.clone();
        let root = self.root.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            // Same lock ordering as add_artifact/prune_blobs so the row delete
            // cannot interleave with GC.
            let _lock = StoreLock::acquire(&root)?;
            let conn = pool
                .get()
                .map_err(|err| StoreError::PoolError(err.to_string()))?;
            index::remove_artifact(&conn, &key)
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Looks up the blob ID for a Maven coordinate, returning `None` if not indexed.
    ///
    /// This API does NOT hold the store lock between the index lookup and
    /// any subsequent file access by the caller; a concurrent GC pass can
    /// delete the blob in that window (#4). For the read-modify-validate
    /// pattern, prefer [`Self::lookup_artifact_locked`], which acquires the
    /// same lock GC takes and stat-verifies the file before returning.
    /// Callers that keep using this method must be prepared to treat a
    /// returned id as a cache hint and retry on stale-blob errors.
    pub async fn lookup_artifact(&self, key: &ArtifactKey) -> Result<Option<BlobId>> {
        let pool = self.pool.clone();
        let key_clone = key.clone();
        let result = tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|err| StoreError::PoolError(err.to_string()))?;
            index::lookup_artifact(&conn, &key_clone)
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?;
        let found = result?;
        tracing::debug!(
            group_id = %key.group_id,
            artifact_id = %key.artifact_id,
            version = %key.version,
            hit = found.is_some(),
            "artifact lookup"
        );
        Ok(found)
    }

    /// Race-free lookup that takes the store lock for the duration of the
    /// index query and on-disk stat (#4). Returns `Some(id)` only if a row
    /// points at a blob that exists on disk at lookup time. A concurrent GC
    /// sweep is serialised behind this call's lock, so the returned id is
    /// safe to hand to a downstream `Store::get_path` + `open` without a
    /// TOCTOU retry. Returns `None` if the row is absent OR the row points
    /// at a blob whose file is missing (a dangling row, which a follow-up
    /// GC sweep will scrub).
    pub async fn lookup_artifact_locked(&self, key: &ArtifactKey) -> Result<Option<BlobId>> {
        let pool = self.pool.clone();
        let root = self.root.clone();
        let key_clone = key.clone();
        tokio::task::spawn_blocking(move || {
            let _lock = StoreLock::acquire(&root)?;
            let conn = pool
                .get()
                .map_err(|err| StoreError::PoolError(err.to_string()))?;
            let Some(id) = index::lookup_artifact(&conn, &key_clone)? else {
                return Ok(None);
            };
            let path = root.join(paths::blob_path(&id));
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() => Ok(Some(id)),
                Ok(_) => {
                    tracing::warn!(
                        path = %path.display(),
                        blob_id = %id,
                        "indexed blob path is not a regular file; treating as miss"
                    );
                    Ok(None)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!(
                        path = %path.display(),
                        blob_id = %id,
                        "indexed blob missing on disk; treating as miss"
                    );
                    Ok(None)
                }
                Err(e) => Err(StoreError::IoError(e)),
            }
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Missing artifacts are not included in the returned map.
    pub async fn lookup_artifacts_batch(
        &self,
        keys: &[ArtifactKey],
    ) -> Result<HashMap<ArtifactKey, BlobId>> {
        let pool = self.pool.clone();
        // Arc allows sharing keys across thread boundary without cloning each key
        let keys: Arc<[ArtifactKey]> = Arc::from(keys);
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|err| StoreError::PoolError(err.to_string()))?;
            // `index::lookup_artifacts_batch` already chunks the input into
            // 100-key SQL statements; the outer chunk loop was redundant.
            index::lookup_artifacts_batch(&conn, &keys)
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Recommended default parallelism for [`Self::verify_blobs`] when the
    /// caller has no user-configured value to thread through (e.g.
    /// `network.concurrency`). Derived from `available_parallelism()` and
    /// clamped to a small range so it stays useful on tiny VMs and bounded
    /// on large machines where saturating the spawn_blocking pool with
    /// SHA-256 work hurts more than it helps.
    pub fn default_verification_parallelism() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 32)
    }

    /// Async wrapper using buffer_unordered for concurrent verification.
    ///
    /// Uses tokio's spawn_blocking for each blob verification, running them
    /// concurrently with bounded parallelism via buffer_unordered. This avoids
    /// the inefficiency of nesting Rayon's thread pool inside spawn_blocking.
    ///
    /// `parallelism` controls the maximum number of concurrent re-hash tasks.
    /// Callers should thread `network.concurrency` (or a similar
    /// user-configured knob) through here; pass
    /// [`Self::default_verification_parallelism`] when no such value is
    /// available. Values <= 0 are clamped to 1.
    pub async fn verify_blobs(
        &self,
        ids: &[BlobId],
        parallelism: usize,
    ) -> Result<HashSet<BlobId>> {
        use futures_util::stream::{self, StreamExt};

        if ids.is_empty() {
            return Ok(HashSet::new());
        }

        let root = self.root.clone();
        let parallelism = parallelism.max(1);

        let results: Vec<Result<Option<BlobId>>> = stream::iter(ids.iter().cloned())
            .map(|id| {
                let root = root.clone();
                async move {
                    tokio::task::spawn_blocking(move || {
                        let path = root.join(paths::blob_path(&id));
                        // No is_file() probe: between the probe and the
                        // open below a concurrent GC can unlink the file.
                        // Open directly inside from_file; treat NotFound
                        // as "blob absent" rather than an error.
                        match BlobId::from_file(&path) {
                            Ok(actual) => {
                                if actual == id {
                                    Ok(Some(id))
                                } else {
                                    Ok(None)
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                            Err(e) => Err(StoreError::IoError(e)),
                        }
                    })
                    .await
                    .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
                }
            })
            .buffer_unordered(parallelism)
            .collect()
            .await;

        let mut verified = HashSet::with_capacity(results.len());
        for result in results {
            if let Some(id) = result? {
                verified.insert(id);
            }
        }
        Ok(verified)
    }

    /// Computes aggregate statistics (blob count and total size) for the store.
    ///
    /// GC/stats note: this is part of the store's garbage-collection subsystem,
    /// which is library-internal and intentionally NOT exposed via the `rv` CLI
    /// for the v1 launch (DECISION #3). The API is kept public and tested so a
    /// later release (or the deferred cloud component) can wire it up.
    ///
    /// This walks the on-disk blob tree (via `list_blob_entries`) rather than
    /// reading a SQL aggregate: the index only knows about blobs associated
    /// with an artifact row, so a store that mixes indexed artifacts with raw
    /// `put_bytes` / `put_stream` blobs would be undercounted by an index-only
    /// query. Walking the disk counts every blob exactly once regardless of how
    /// it was written. The cost is O(n) syscalls in the number of blobs; this
    /// is a library-internal stats/GC path, not a hot lookup path (see #18).
    pub async fn cache_stats(&self) -> Result<CacheStats> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            // WHY: walk the disk for the authoritative count. A store that
            // mixes indexed artifacts with raw `put_bytes` blobs would
            // otherwise be undercounted: the SQL-only path returns just the
            // indexed rows and ignores the raw blobs entirely. Walking the
            // disk gives every blob exactly one count regardless of how it
            // got there.
            let entries = store.list_blob_entries()?;
            let total_bytes = entries.iter().map(|entry| entry.size).sum();
            Ok(CacheStats {
                blob_count: entries.len(),
                total_bytes,
            })
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Removes blobs not in the `keep` set. Pass `dry_run=true` to preview without deleting.
    ///
    /// GC/stats note: this garbage-collection entry point is library-internal
    /// and intentionally NOT exposed via the `rv` CLI for the v1 launch
    /// (DECISION #3). It stays public and tested for a later release / the
    /// deferred cloud component.
    ///
    /// `keep` is the caller's snapshot of "blobs I still need", typically
    /// computed from a lockfile BEFORE this call. The snapshot can be stale:
    /// between when the caller built it and when GC actually runs, a
    /// concurrent sync may have indexed a brand-new blob. To avoid
    /// collecting that new blob as garbage, this method also intersects
    /// `keep` with `referenced_blob_ids(index)` computed UNDER `StoreLock`
    /// (#3). Any blob referenced by an index row at lock-acquire time is
    /// protected, even if the caller didn't list it in `keep`.
    pub async fn prune_blobs(&self, keep: &HashSet<BlobId>, dry_run: bool) -> Result<GcSummary> {
        let store = self.clone();
        let caller_keep = keep.clone();
        tokio::task::spawn_blocking(move || {
            let _lock = StoreLock::acquire(&store.root)?;

            // Re-derive the protected set under the lock (#3) so a
            // concurrent sync that indexed a fresh blob between snapshot
            // and prune cannot lose it. Union with caller's `keep` (which
            // may include uncommitted blobs the caller is about to add).
            let mut keep: HashSet<BlobId> = caller_keep;
            {
                let conn = store
                    .pool
                    .get()
                    .map_err(|err| StoreError::PoolError(err.to_string()))?;
                let referenced = index::referenced_blob_ids(&conn)?;
                keep.extend(referenced);
            }

            let entries = store.list_blob_entries()?;
            let mut removed_blobs = 0usize;
            let mut removed_bytes = 0u64;

            let mut removed_entries = Vec::new();

            for entry in entries {
                if keep.contains(&entry.id) {
                    continue;
                }
                removed_blobs = removed_blobs.saturating_add(1);
                removed_bytes = removed_bytes.saturating_add(entry.size);
                removed_entries.push(entry);
            }

            if !dry_run {
                // Remove index rows BEFORE deleting blob files. Concurrent
                // readers (lookup_artifact, lookup_artifacts_batch) do not
                // hold StoreLock, so the invariant they rely on ("a row
                // returned by lookup points at a file on disk") requires
                // the row to disappear no later than the file. A crash
                // between row delete and file delete leaves orphan files
                // (no row points at them); the next sweep finds them via
                // list_blob_entries and removes them since their hash is
                // not in `keep`.
                let mut conn = store
                    .pool
                    .get()
                    .map_err(|err| StoreError::PoolError(err.to_string()))?;

                let ids_to_remove: Vec<BlobId> =
                    removed_entries.iter().map(|e| e.id.clone()).collect();
                if !ids_to_remove.is_empty() {
                    index::remove_artifacts_for_blobs(&mut conn, &ids_to_remove)?;
                }

                let mut failed_count = 0usize;
                for entry in removed_entries {
                    match fs::remove_file(&entry.path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            failed_count += 1;
                            tracing::warn!(
                                path = %entry.path.display(),
                                blob_id = %entry.id,
                                error = %e,
                                "failed to remove blob file during GC; the next sweep will retry"
                            );
                        }
                    }
                }

                if failed_count > 0 {
                    tracing::warn!(
                        failed_count,
                        "GC left {failed_count} orphan blob file(s) on disk. Run `rv store gc` again."
                    );
                }

                // Recovery sweep: scrub any index rows that point at blob
                // files which no longer exist on disk. These rows are
                // typically left behind by a crash between the file-delete
                // and row-delete halves of an earlier GC. We look at every
                // referenced blob (not filtered by `keep`) because a row
                // whose file is missing is dangling regardless of how the
                // caller classified it.
                //
                // Two-phase approach (#1): collect candidate ids via a
                // short-lived non-transactional SELECT (we hold StoreLock,
                // no concurrent writer can race), then only open an
                // IMMEDIATE transaction for the DELETE. Holding an IMMEDIATE
                // write txn open across a per-row `is_file()` syscall loop
                // would block every pool connection for the duration of
                // every stat.
                //
                // Filesystem probing distinguishes definitive NotFound from
                // transient errors (EACCES, EMFILE, EIO). Only definitive
                // NotFound marks a row as dangling; transient errors are
                // logged and the row is left in place for the next sweep.
                // Rows whose blob_id does not parse can never resolve to a
                // file; scrub them along with the dangling rows instead of
                // skipping them, otherwise they would survive every sweep.
                let mut dangling: Vec<String> = Vec::new();
                let candidate_ids: Vec<BlobId> = {
                    let mut stmt = conn
                        .prepare("SELECT DISTINCT blob_id FROM artifacts")
                        .map_err(StoreError::DbError)?;
                    let rows = stmt
                        .query_map([], |row| row.get::<_, String>(0))
                        .map_err(StoreError::DbError)?;
                    let mut ids = Vec::new();
                    for row in rows {
                        let s = row.map_err(StoreError::DbError)?;
                        match BlobId::from_str(&s) {
                            Ok(id) => ids.push(id),
                            Err(_) => {
                                tracing::warn!(
                                    blob_id = %s,
                                    "index row has unparseable blob_id; scrubbing"
                                );
                                dangling.push(s);
                            }
                        }
                    }
                    ids
                };

                for id in candidate_ids {
                    let path = store.get_path(&id);
                    match fs::symlink_metadata(&path) {
                        Ok(meta) if meta.is_file() => {
                            // File is fine, skip.
                        }
                        Ok(_) => {
                            // Path exists but is not a regular file. Unusual,
                            // so leave the row alone and warn.
                            tracing::warn!(
                                path = %path.display(),
                                blob_id = %id,
                                "indexed blob path is not a regular file; not deleting row"
                            );
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            dangling.push(id.as_str().to_string());
                        }
                        Err(e) => {
                            // Transient errors (EACCES, EMFILE, EIO) must
                            // not be treated as definitive NotFound; the
                            // file may still exist. Log and skip; the next
                            // sweep retries.
                            tracing::warn!(
                                path = %path.display(),
                                blob_id = %id,
                                error = %e,
                                "transient stat error during dangling sweep; skipping"
                            );
                        }
                    }
                }

                if !dangling.is_empty() {
                    let tx = conn
                        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                        .map_err(StoreError::DbError)?;
                    const BATCH: usize = 500;
                    for chunk in dangling.chunks(BATCH) {
                        let placeholders: String = std::iter::repeat_n("?", chunk.len())
                            .collect::<Vec<_>>()
                            .join(", ");
                        let sql = format!(
                            "DELETE FROM artifacts WHERE blob_id IN ({})",
                            placeholders
                        );
                        let params: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
                        tx.execute(&sql, rusqlite::params_from_iter(params))
                            .map_err(StoreError::DbError)?;
                    }
                    tx.commit().map_err(StoreError::DbError)?;
                }

                // Truncate the WAL so it doesn't grow unboundedly across
                // GC cycles (#14). TRUNCATE is best-effort; failures are
                // logged at debug and don't fail the GC.
                if let Err(e) = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE") {
                    tracing::debug!(error = %e, "WAL checkpoint TRUNCATE failed after prune");
                }
            }

            Ok(GcSummary {
                removed_blobs,
                removed_bytes,
            })
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    /// Removes all blobs and clears the artifact index. Pass `dry_run=true` to preview.
    ///
    /// GC/stats note: like [`Store::prune_blobs`] / [`Store::cache_stats`], this
    /// is part of the library-internal garbage-collection subsystem that is NOT
    /// exposed via the `rv` CLI for the v1 launch (DECISION #3).
    pub async fn clean_blobs(&self, dry_run: bool) -> Result<GcSummary> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let _lock = StoreLock::acquire(&store.root)?;
            let entries = store.list_blob_entries()?;
            let removed_blobs = entries.len();
            let removed_bytes = entries.iter().map(|entry| entry.size).sum();

            if !dry_run {
                // Clear the index first so a crash between the SQL DELETE
                // and the directory rm-rf leaves the store consistent: with
                // no index rows, whatever partial filesystem state survives
                // is harmless. The reverse order would leave rows pointing
                // at blobs that have just vanished.
                let conn = store
                    .pool
                    .get()
                    .map_err(|err| StoreError::PoolError(err.to_string()))?;
                index::clear_artifacts(&conn)?;

                let blob_root = paths::blob_root(&store.root);
                if blob_root.exists() {
                    fs::remove_dir_all(&blob_root).io_context(|| {
                        format!("failed to remove blob directory {}", blob_root.display())
                    })?;
                }
                fs::create_dir_all(&blob_root).io_context(|| {
                    format!("failed to create blob directory {}", blob_root.display())
                })?;

                // Truncate the WAL after the bulk delete so the journal
                // doesn't retain now-discarded rows indefinitely (#14).
                if let Err(e) = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE") {
                    tracing::debug!(error = %e, "WAL checkpoint TRUNCATE failed after clean");
                }
            }

            Ok(GcSummary {
                removed_blobs,
                removed_bytes,
            })
        })
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
    }

    fn list_blob_entries(&self) -> Result<Vec<BlobEntry>> {
        let raw_root = paths::blob_root(&self.root);
        if !raw_root.is_dir() {
            return Ok(Vec::new());
        }
        // Canonicalize the blob root once and assert every discovered entry
        // stays under it before recording (#5). Guards against symlink-based
        // path traversal that an attacker could plant in the blob tree.
        // Fail closed: if the root cannot be canonicalised, refuse to walk
        // rather than defeating the traversal guard with raw_root. NotFound
        // means the root vanished since the is_dir probe (lock-free
        // cache_stats can race a clean), which is an empty store; any other
        // error propagates so stats/GC report the unreadable store instead
        // of silently claiming it is empty.
        let canonical_root = match fs::canonicalize(&raw_root) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).io_context(|| {
                    format!("failed to canonicalize blob root {}", raw_root.display())
                });
            }
        };
        let mut entries = Vec::new();
        // Hard cap on directory recursion. The sharded blob layout never
        // exceeds three levels deep; 100 protects against a corrupted store
        // without affecting real workloads. Symlinks are skipped entirely,
        // so symlink loops are not a concern.
        const MAX_DEPTH: usize = 100;
        let mut stack = vec![(canonical_root.clone(), 0usize)];

        while let Some((dir, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                continue;
            }

            // The lock-free cache_stats path can race a concurrent prune or
            // clean; entries (or whole shard directories) that vanish between
            // listing and stat are skipped rather than failing the walk.
            let dir_entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(e)
                        .io_context(|| format!("failed to read directory {}", dir.display()));
                }
            };
            for entry in dir_entries {
                let entry =
                    entry.io_context(|| format!("failed to read entry in {}", dir.display()))?;
                let path = entry.path();
                // Use file_type() instead of metadata() so we don't follow
                // symlinks (#5). metadata() resolves the target, which would
                // otherwise let the walk descend into symlinked directories.
                let file_type = match entry.file_type() {
                    Ok(t) => t,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        return Err(e).io_context(|| {
                            format!("failed to read file type for {}", path.display())
                        });
                    }
                };

                // Skip symlinks entirely. Blob storage never legitimately
                // contains them, and following them is the entire bug.
                if file_type.is_symlink() {
                    continue;
                }

                if file_type.is_dir() {
                    stack.push((path, depth + 1));
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }

                // Verify the entry's path stays under the canonicalized blob
                // root before we record it for deletion (#5). We canonicalize
                // the root exactly once (above) and never traverse symlinks
                // during the walk, so `path` is built entirely from canonical
                // components: a lexical `starts_with` is sufficient and avoids
                // an O(n) `canonicalize` syscall per blob on every GC/stats
                // call (#19). `fs::canonicalize` resolves symlinks, not
                // hardlinks, so it would not catch a hardlinked blob anyway.
                if !path.starts_with(&canonical_root) {
                    tracing::warn!(
                        path = %path.display(),
                        root = %canonical_root.display(),
                        "blob entry resolved outside canonical blob root; skipping"
                    );
                    continue;
                }

                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                let Ok(id) = BlobId::from_str(name) else {
                    continue;
                };
                // Stat via symlink_metadata so we don't follow links. A blob
                // unlinked by a concurrent prune between read_dir and this
                // stat is skipped, not an error.
                let size = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta.len(),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        return Err(e)
                            .io_context(|| format!("failed to stat blob {}", path.display()));
                    }
                };
                entries.push(BlobEntry { id, path, size });
            }
        }
        Ok(entries)
    }
}

/// Cross-process exclusive lock on the store's `.lock` file.
///
/// Acquired before any r2d2 SQLite pool connection is taken out. Lock order
/// is: `StoreLock` first, then a pooled `Connection`. Releasing happens in
/// reverse via `Drop` (connection returned to pool, then lock unlocked).
///
/// Uses `fs2::FileExt` which wraps `flock(2)` on Unix and `LockFileEx` on
/// Windows behind a safe API.
///
/// On Linux `flock(2)` locks are per-open-file-description: two threads in
/// the same process that each open `.lock` would both observe a successful
/// `try_lock_exclusive`. The `_intra` guard below adds an in-process Mutex
/// keyed by canonicalised store root so threads serialise before the flock
/// is even attempted.
struct StoreLock {
    file: File,
    _intra: std::sync::MutexGuard<'static, ()>,
}

// WHY: leak a `Box<Mutex<()>>` per store root so we get a genuine `'static`
// reference, no `unsafe` transmute and no Arc lifetime gymnastics. Entries in
// this map MUST never be removed: the leaked allocation has to outlive every
// `StoreLock` it ever produced, and removing the map entry would lose the
// only reference we keep to the live `&'static Mutex`. The growth is bounded
// by the number of distinct store roots a process touches over its lifetime,
// which is at most a handful in any real workload.
static STORE_LOCKS: OnceLock<Mutex<HashMap<PathBuf, &'static Mutex<()>>>> = OnceLock::new();

fn intra_process_mutex_for(root: &Path) -> &'static Mutex<()> {
    let key = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let map = STORE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|p| p.into_inner());
    guard
        .entry(key)
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
}

/// Default lock acquisition timeout. 60s tolerates other rv processes that
/// are mid-write without blocking forever on a stale lock holder.
const LOCK_TIMEOUT: Duration = Duration::from_secs(60);
/// Initial sleep between try-lock attempts. Doubles on every retry up to
/// `LOCK_RETRY_MAX`, with ±25% jitter so two contenders don't lockstep.
const LOCK_RETRY_INITIAL: Duration = Duration::from_millis(50);
const LOCK_RETRY_MAX: Duration = Duration::from_secs(1);

/// Doubles `current` (capped at `LOCK_RETRY_MAX`) and perturbs by ±25% so
/// racing callers don't lockstep.
fn next_retry_delay(current: Duration) -> Duration {
    let base = (current * 2).min(LOCK_RETRY_MAX);
    let base_nanos = base.as_nanos() as u64;
    let pct: i64 = rand::Rng::gen_range(&mut rand::thread_rng(), -25..=25);
    let delta_nanos = (base_nanos as i64).saturating_mul(pct) / 100;
    let jittered = (base_nanos as i64).saturating_add(delta_nanos).max(1) as u64;
    Duration::from_nanos(jittered)
}

impl StoreLock {
    fn acquire(root: &Path) -> Result<Self> {
        Self::acquire_with_timeout(root, LOCK_TIMEOUT)
    }

    fn acquire_with_timeout(root: &Path, timeout: Duration) -> Result<Self> {
        use fs2::FileExt;

        let lock_path = root.join(LOCK_FILE);

        let intra_static = intra_process_mutex_for(root);
        let deadline = std::time::Instant::now() + timeout;
        let mut backoff = LOCK_RETRY_INITIAL;
        let intra_guard = loop {
            match intra_static.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(StoreError::LockTimeout {
                            path: lock_path,
                            holder_info: "another thread in this process".to_string(),
                        });
                    }
                    std::thread::sleep(backoff);
                    backoff = next_retry_delay(backoff);
                }
                Err(std::sync::TryLockError::Poisoned(p)) => break p.into_inner(),
            }
        };

        // Open without truncate so a second contender does not destroy
        // the lock file contents before it has acquired the lock. Truncation is
        // performed only after the lock is held.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .io_context(|| format!("failed to open lock file {}", lock_path.display()))?;

        // Retry-with-timeout loop around try_lock_exclusive instead of
        // an infinite-blocking lock_exclusive call.
        let mut flock_backoff = LOCK_RETRY_INITIAL;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        // Read holder info from the lock file for the error message.
                        // Seek to start before reading since we may have positioned past 0.
                        let holder_info = {
                            use std::io::{Read, Seek, SeekFrom};
                            let mut buf = String::new();
                            let mut f = &file;
                            let _ = f.seek(SeekFrom::Start(0));
                            let _ = f.read_to_string(&mut buf);
                            if buf.trim().is_empty() {
                                "unknown".to_string()
                            } else {
                                buf.trim().to_string()
                            }
                        };
                        return Err(StoreError::LockTimeout {
                            path: lock_path,
                            holder_info,
                        });
                    }
                    std::thread::sleep(flock_backoff);
                    flock_backoff = next_retry_delay(flock_backoff);
                }
                Err(e) => {
                    return Err(StoreError::IoError(e));
                }
            }
        }

        // Write the full metadata buffer first, then truncate to its length.
        // A set_len(0)+writeln pattern would leave an empty file on SIGKILL
        // between the two calls, and a follow-up contender would read
        // "unknown" instead of useful holder info. Writing first means the
        // file always contains some valid content (either the previous
        // holder's, or ours), never zero bytes.
        let metadata = format!(
            "pid={} time={}\n",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        {
            use std::io::{Seek, SeekFrom};
            let mut writer = &file;
            writer
                .seek(SeekFrom::Start(0))
                .io_context(|| format!("failed to seek lock file {}", lock_path.display()))?;
            writer
                .write_all(metadata.as_bytes())
                .io_context(|| format!("failed to write lock info to {}", lock_path.display()))?;
        }
        file.set_len(metadata.len() as u64)
            .io_context(|| format!("failed to truncate lock file {}", lock_path.display()))?;

        Ok(Self {
            file,
            _intra: intra_guard,
        })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // flock first (cross-process), then drop the intra-process guard.
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};

    use bytes::Bytes;
    use futures_util::stream;
    use tempfile::tempdir;

    use super::Store;
    use crate::error::StoreError;
    use rv_config::{ArtifactKey, BlobId};

    #[test]
    fn open_creates_index_and_blob_directories() {
        let dir = tempdir().expect("tempdir");
        let store_root = dir.path().join("fresh-store");

        assert!(!store_root.exists());
        let _store = Store::open(&store_root).expect("open");

        assert!(store_root.join("index.sqlite").is_file());
        assert!(crate::paths::blob_root(&store_root).is_dir());
    }

    #[test]
    fn open_existing_store_reuses_existing_data() {
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let dir = tempdir().expect("tempdir");
        let store_root = dir.path().join("store");

        let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        let expected_id = BlobId::from_bytes(b"persisted");

        rt.block_on(async {
            let store = Store::open(&store_root).expect("open first");
            let id = store.put_bytes(b"persisted").await.expect("put");
            store.add_artifact(&key, &id).await.expect("add");
        });

        rt.block_on(async {
            let reopened = Store::open(&store_root).expect("open second");
            assert_eq!(
                reopened.lookup_artifact(&key).await.expect("lookup"),
                Some(expected_id.clone())
            );
            assert!(reopened.exists(&expected_id));
        });
    }

    #[test]
    fn temp_cleanup_runs_for_each_distinct_store_path() {
        // A process that opens two stores at different paths must
        // schedule cleanup for both temp dirs, not just the first.
        use std::time::{Duration, SystemTime};

        let dir = tempdir().expect("tempdir");
        let root_a = dir.path().join("store-a");
        let root_b = dir.path().join("store-b");

        // Pre-seed each store's temp dir with a stale file so we can verify
        // the cleanup thread observed it. Files older than 24h are removed.
        let stale = SystemTime::now() - Duration::from_secs(48 * 3600);
        for root in [&root_a, &root_b] {
            let tmp = root.join(super::TMP_DIR);
            std::fs::create_dir_all(&tmp).expect("mkdir tmp");
            let stale_path = tmp.join("stale.tmp");
            std::fs::write(&stale_path, b"x").expect("seed");
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&stale_path)
                .expect("open stale");
            f.set_modified(stale).expect("set mtime");
        }

        let _a = Store::open(&root_a).expect("open a");
        let _b = Store::open(&root_b).expect("open b");

        // Cleanup runs on a background thread; give it a moment.
        for _ in 0..50 {
            let a_gone = !root_a.join(super::TMP_DIR).join("stale.tmp").exists();
            let b_gone = !root_b.join(super::TMP_DIR).join("stale.tmp").exists();
            if a_gone && b_gone {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "expected stale temp files in both stores to be cleaned; \
             a_exists={} b_exists={}",
            root_a.join(super::TMP_DIR).join("stale.tmp").exists(),
            root_b.join(super::TMP_DIR).join("stale.tmp").exists(),
        );
    }

    #[test]
    fn open_allows_concurrent_access() {
        let dir = tempdir().expect("tempdir");
        let store_root = dir.path().join("store");
        let barrier = Arc::new(Barrier::new(3));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let barrier = barrier.clone();
            let root = store_root.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                Store::open(&root).map(|_| ())
            }));
        }

        barrier.wait();
        for handle in handles {
            let result = handle.join().expect("thread join");
            result.expect("concurrent open");
        }
    }

    #[tokio::test]
    async fn batch_lookup_round_trips_empty_classifier() {
        // #55: a key whose classifier is `Some("")` is normalized to `None`,
        // and the index stores/reconstructs it as "" <-> None consistently, so
        // the batch lookup must return a hit keyed by the (normalized) key the
        // caller passed in. A reconstructed key that kept `None` while a
        // `Some("")` query key did not would drop the entry.
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = store.put_bytes(b"classifier-payload").await.expect("put");

        // Add under a key built with an explicit empty classifier.
        let added_key =
            ArtifactKey::new("com.example", "demo", "1.0.0", "jar", Some(String::new()));
        store.add_artifact(&added_key, &id).await.expect("add");

        // Query with both an empty-string classifier and an explicit None; both
        // must resolve to the same stored blob.
        let query_empty =
            ArtifactKey::new("com.example", "demo", "1.0.0", "jar", Some(String::new()));
        let query_none = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);

        let found = store
            .lookup_artifacts_batch(&[query_empty.clone(), query_none.clone()])
            .await
            .expect("batch lookup");

        // Both query keys normalize to the same key, so there is exactly one
        // entry and both lookups hit it.
        assert_eq!(found.get(&query_empty), Some(&id));
        assert_eq!(found.get(&query_none), Some(&id));
        assert_eq!(found.len(), 1);
    }

    #[tokio::test]

    async fn put_bytes_round_trip() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");
        let payload = b"round-trip";

        let id = store.put_bytes(payload).await.expect("put");
        let path = store.get_path(&id);

        assert!(store.exists(&id));
        assert_eq!(path, dir.path().join(crate::paths::blob_path(&id)));
        let stored = std::fs::read(&path).expect("read");
        assert_eq!(stored, payload);
    }

    #[tokio::test]
    async fn put_bytes_empty_data_succeeds() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = store.put_bytes(b"").await.expect("put");
        assert_eq!(id, BlobId::from_bytes(b""));
        assert!(store.exists(&id));
        assert_eq!(
            std::fs::metadata(store.get_path(&id))
                .expect("metadata")
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn put_bytes_and_lookup() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");
        let id = store.put_bytes(b"hello").await.expect("put");

        assert!(store.exists(&id));
        assert_eq!(
            store.get_path(&id),
            dir.path().join(crate::paths::blob_path(&id))
        );

        let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        store.add_artifact(&key, &id).await.expect("add");
        let found = store.lookup_artifact(&key).await.expect("lookup");
        assert_eq!(found, Some(id));
    }

    #[tokio::test]
    async fn put_stream_round_trip() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");
        let expected = b"streamed-bytes";

        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"streamed-")),
            Ok(Bytes::from_static(b"bytes")),
        ];
        let id = store
            .put_stream(stream::iter(chunks))
            .await
            .expect("put stream");

        assert_eq!(id, BlobId::from_bytes(expected));
        assert!(store.exists(&id));
        let stored = std::fs::read(store.get_path(&id)).expect("read");
        assert_eq!(stored, expected);
    }

    #[tokio::test]
    async fn duplicate_content_returns_same_blob_id() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let first = store.put_bytes(b"dup").await.expect("put");
        let second = store.put_bytes(b"dup").await.expect("put");

        assert_eq!(first, second);
        assert_eq!(store.cache_stats().await.expect("stats").blob_count, 1);
    }

    /// #5/#19: a symlink planted in the blob tree must be skipped by the
    /// directory walk and never counted by `cache_stats` / collected by GC.
    /// After #19 the per-entry `canonicalize` is gone, so this guards that the
    /// symlink-skip at traversal time (not the lexical containment check) is
    /// what protects the walk.
    #[cfg(unix)]
    #[tokio::test]
    async fn list_blob_entries_skips_symlinks() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        // One legitimate blob.
        let id = store.put_bytes(b"real-blob").await.expect("put");
        assert!(store.exists(&id));

        // A target file outside the blob tree that a symlink will point at.
        let outside = dir.path().join("outside.bin");
        std::fs::write(&outside, b"outside-content").expect("write outside");

        // Plant a symlink inside the sharded blob layout. Its name is a valid
        // blob id so the only thing that can exclude it is the symlink check.
        let fake_id = BlobId::from_bytes(b"outside-content");
        let link_path = store.get_path(&fake_id);
        std::fs::create_dir_all(link_path.parent().expect("parent")).expect("mkdir shard");
        std::os::unix::fs::symlink(&outside, &link_path).expect("symlink");

        // Only the real blob is counted; the symlink is skipped.
        let stats = store.cache_stats().await.expect("stats");
        assert_eq!(stats.blob_count, 1, "symlinked entry must not be counted");

        // And a GC sweep with an empty keep set must not delete the symlink's
        // target (it never even sees the symlink as a collectable blob).
        store
            .prune_blobs(&HashSet::new(), false)
            .await
            .expect("prune");
        assert!(outside.exists(), "symlink target must be untouched by GC");
    }

    #[tokio::test]
    async fn different_content_returns_different_blob_ids() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let first = store.put_bytes(b"one").await.expect("put");
        let second = store.put_bytes(b"two").await.expect("put");

        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn put_file_matches_hash() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let file_path = dir.path().join("artifact.jar");
        std::fs::write(&file_path, b"artifact").expect("write");

        let id = store.put_file(&file_path).await.expect("put");
        let expected = BlobId::from_bytes(b"artifact");

        assert_eq!(id, expected);
        assert!(store.exists(&id));
    }

    #[tokio::test]
    async fn put_file_missing_path_returns_error() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");
        let missing = dir.path().join("does-not-exist.jar");

        let err = store
            .put_file(&missing)
            .await
            .expect_err("missing file should error");
        assert!(matches!(err, StoreError::IoError(_)));
    }

    #[tokio::test]
    async fn exists_false_for_missing_blob() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = BlobId::from_bytes(b"missing");
        assert!(!store.exists(&id));
    }

    #[tokio::test]
    async fn cache_stats_counts_blobs() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        store.put_bytes(b"one").await.expect("put");
        store.put_bytes(b"two").await.expect("put");

        let stats = store.cache_stats().await.expect("stats");
        assert_eq!(stats.blob_count, 2);
        assert_eq!(stats.total_bytes, 6);
    }

    #[tokio::test]
    async fn add_artifact_duplicate_key_overwrites_existing_mapping() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        let first = store.put_bytes(b"first").await.expect("put");
        let second = store.put_bytes(b"second").await.expect("put");

        store.add_artifact(&key, &first).await.expect("add first");
        store.add_artifact(&key, &second).await.expect("add second");

        assert_eq!(
            store.lookup_artifact(&key).await.expect("lookup"),
            Some(second)
        );
    }

    #[tokio::test]
    async fn prune_removes_unreferenced_blobs() {
        // Under the #3 fix, `prune_blobs` protects every blob referenced by
        // the index at lock-acquire time so a concurrent indexer's row
        // can't be stranded. To exercise the "remove this blob" path, the
        // caller must remove the row first (or never index it). Here we
        // only index `keep_id`; `remove_id` is an orphan blob and gets
        // collected.
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let keep_id = store.put_bytes(b"keep").await.expect("put");
        let remove_id = store.put_bytes(b"remove").await.expect("put");
        let keep_key = ArtifactKey::new("com.example", "keep", "1.0.0", "jar", None);
        store.add_artifact(&keep_key, &keep_id).await.expect("add");
        // intentionally NOT indexing remove_id

        let mut keep = HashSet::new();
        keep.insert(keep_id.clone());

        let summary = store.prune_blobs(&keep, true).await.expect("prune dry run");
        assert_eq!(summary.removed_blobs, 1);
        assert!(store.exists(&remove_id));

        let summary = store.prune_blobs(&keep, false).await.expect("prune");
        assert_eq!(summary.removed_blobs, 1);
        assert!(store.exists(&keep_id));
        assert!(!store.exists(&remove_id));
        assert_eq!(
            store.lookup_artifact(&keep_key).await.expect("lookup"),
            Some(keep_id)
        );
    }

    #[tokio::test]
    async fn prune_all_referenced_removes_nothing() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id1 = store.put_bytes(b"artifact1").await.expect("put");
        let id2 = store.put_bytes(b"artifact2").await.expect("put");

        let mut keep = HashSet::new();
        keep.insert(id1.clone());
        keep.insert(id2.clone());

        let summary = store.prune_blobs(&keep, false).await.expect("prune");
        assert_eq!(summary.removed_blobs, 0);
        assert_eq!(summary.removed_bytes, 0);
        assert!(store.exists(&id1));
        assert!(store.exists(&id2));
    }

    #[tokio::test]
    async fn clean_blobs_dry_run_does_not_delete() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = store.put_bytes(b"dry").await.expect("put");
        let key = ArtifactKey::new("com.example", "dry", "1.0.0", "jar", None);
        store.add_artifact(&key, &id).await.expect("add");

        let summary = store.clean_blobs(true).await.expect("clean dry run");
        assert_eq!(summary.removed_blobs, 1);
        assert!(store.exists(&id));
        assert_eq!(store.lookup_artifact(&key).await.expect("lookup"), Some(id));
        assert_eq!(store.cache_stats().await.expect("stats").blob_count, 1);
    }

    #[tokio::test]
    async fn clean_removes_all_blobs() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = store.put_bytes(b"clean").await.expect("put");
        let key = ArtifactKey::new("com.example", "clean", "1.0.0", "jar", None);
        store.add_artifact(&key, &id).await.expect("add");

        let summary = store.clean_blobs(false).await.expect("clean");
        assert_eq!(summary.removed_blobs, 1);
        assert_eq!(store.cache_stats().await.expect("stats").blob_count, 0);
        assert_eq!(store.lookup_artifact(&key).await.expect("lookup"), None);
    }

    #[test]
    fn open_fails_with_corrupt_index() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("index.sqlite");
        std::fs::write(&db_path, b"not a sqlite database").expect("write");

        // With the header-magic pre-check the failure path is microseconds.
        // We allow up to a second for slow CI hosts. Without the pre-check the
        // open would instead wait the full 30s busy_timeout.
        let started = std::time::Instant::now();
        let err = Store::open(dir.path()).err().expect("error");
        let elapsed = started.elapsed();
        assert!(matches!(err, StoreError::DbError(_)));
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "Store::open on corrupt index should fail fast, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn batch_lookup_finds_stored_artifacts() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id1 = store.put_bytes(b"artifact1").await.expect("put");
        let id2 = store.put_bytes(b"artifact2").await.expect("put");
        let key1 = ArtifactKey::new("com.example", "first", "1.0.0", "jar", None);
        let key2 = ArtifactKey::new("com.example", "second", "2.0.0", "jar", None);
        let missing_key = ArtifactKey::new("com.example", "missing", "1.0.0", "jar", None);

        store.add_artifact(&key1, &id1).await.expect("add");
        store.add_artifact(&key2, &id2).await.expect("add");

        let keys = vec![key1.clone(), key2.clone(), missing_key.clone()];
        let found = store
            .lookup_artifacts_batch(&keys)
            .await
            .expect("batch lookup");

        assert_eq!(found.len(), 2);
        assert_eq!(found.get(&key1), Some(&id1));
        assert_eq!(found.get(&key2), Some(&id2));
        assert_eq!(found.get(&missing_key), None);
    }

    #[tokio::test]
    async fn remove_artifact_drops_only_the_index_row() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = store.put_bytes(b"companion-pom-bytes").await.expect("put");
        let key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
        store.add_artifact(&key, &id).await.expect("add");
        assert_eq!(
            store.lookup_artifact(&key).await.expect("lookup"),
            Some(id.clone())
        );

        store.remove_artifact(&key).await.expect("remove row");

        // The index row is gone (so the next sync re-fetches+re-verifies)...
        assert_eq!(store.lookup_artifact(&key).await.expect("lookup"), None);
        // ...but the content-addressed blob is left in place for GC / other refs.
        assert!(store.get_path(&id).is_file());

        // Removing a key that has no row is a no-op, not an error.
        store
            .remove_artifact(&key)
            .await
            .expect("idempotent remove");
    }

    #[tokio::test]
    async fn batch_lookup_empty_input_returns_empty_map() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let found = store
            .lookup_artifacts_batch(&[])
            .await
            .expect("batch lookup");
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn verify_blobs_accepts_valid_blob() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = store.put_bytes(b"verified").await.expect("put");
        let verified = store
            .verify_blobs(
                std::slice::from_ref(&id),
                Store::default_verification_parallelism(),
            )
            .await
            .expect("verify");
        assert!(verified.contains(&id));
    }

    #[tokio::test]
    async fn verify_blobs_detects_corruption() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = store.put_bytes(b"good").await.expect("put");
        let blob_path = store.get_path(&id);
        // Published blobs are 0o444; remove the read-only file before
        // overwriting it with corrupt bytes.
        let _ = std::fs::remove_file(&blob_path);
        std::fs::write(&blob_path, b"corrupt").expect("corrupt write");

        let verified = store
            .verify_blobs(
                std::slice::from_ref(&id),
                Store::default_verification_parallelism(),
            )
            .await
            .expect("verify");
        assert!(!verified.contains(&id));
    }

    /// Regression test: `put_stream` followed by `add_artifact`
    /// has a window where a concurrent `prune_blobs` (GC) can delete the
    /// freshly-persisted blob before its index row is written, leaving the
    /// eventual artifact row pointing at a deleted file.
    ///
    /// Reproduce the legacy hazard against the unfixed API: call
    /// `put_stream` directly, then a GC with an empty `keep` set, then
    /// `add_artifact`. The legacy sequence ends with an indexed row but no
    /// blob on disk.
    ///
    /// With the new `put_stream_and_index` method, the lock is held across
    /// both halves and a GC observing an empty `keep` set cannot interleave
    /// in the middle: after `put_stream_and_index` returns, the blob must be
    /// present AND indexed even if GC runs against an empty keep set
    /// concurrently or afterwards (since the row now references the blob,
    /// the caller can pass it in `keep`).
    #[tokio::test]
    async fn put_stream_and_index_survives_concurrent_gc() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let key = ArtifactKey::new("com.example", "atomic", "1.0.0", "jar", None);
        let payload = b"atomic-put-and-index";

        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![Ok(Bytes::from_static(payload))];
        let (id, _origin) = store
            .put_stream_and_index(&key, stream::iter(chunks))
            .await
            .expect("put_stream_and_index");

        // Blob must be present and indexed atomically. A GC over an empty
        // `keep` set CANNOT have interleaved between the persist and the
        // index insert, because both happened under the store lock.
        assert!(store.exists(&id), "blob must exist after atomic put+index");
        assert_eq!(
            store.lookup_artifact(&key).await.expect("lookup"),
            Some(id.clone()),
            "artifact must be indexed after atomic put+index"
        );

        // Simulate the previous-API race: between put_stream and add_artifact,
        // a GC sweep with an empty `keep` set could have deleted the blob.
        // Under the #11 fix, `add_artifact` stats the blob under the lock and
        // refuses to record a row pointing at a missing file, so the
        // dangling-row bug demonstrated here cannot be committed. The file is
        // gone after GC and a follow-up `add_artifact` errors out instead of
        // silently creating a dangling row.
        let key2 = ArtifactKey::new("com.example", "legacy", "1.0.0", "jar", None);
        let chunks2: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::from_static(b"legacy-payload"))];
        let legacy_id = store
            .put_stream(stream::iter(chunks2))
            .await
            .expect("put_stream legacy");
        store
            .prune_blobs(&HashSet::new(), false)
            .await
            .expect("prune");
        assert!(
            !store.exists(&legacy_id),
            "legacy two-step API loses the blob to a concurrent GC sweep"
        );
        let err = store
            .add_artifact(&key2, &legacy_id)
            .await
            .expect_err("add_artifact must refuse missing blobs (#11)");
        assert!(
            matches!(err, StoreError::IntegrityError(_)),
            "expected IntegrityError refusing to index a missing blob, got {err:?}"
        );
        assert_eq!(
            store.lookup_artifact(&key2).await.expect("lookup legacy"),
            None,
            "no row should be written for a missing blob under the #11 fix"
        );

        // Now do the same scenario through the new API: a GC with an empty
        // keep set running AFTER an atomic put+index must not delete a blob
        // that is referenced by an index row that the caller will include in
        // `keep`. (We test the typical caller pattern: build `keep` from the
        // current index.)
        let key3 = ArtifactKey::new("com.example", "atomic-survives-gc", "1.0.0", "jar", None);
        let chunks3: Vec<Result<Bytes, std::io::Error>> = vec![Ok(Bytes::from_static(b"safe"))];
        let (id3, _) = store
            .put_stream_and_index(&key3, stream::iter(chunks3))
            .await
            .expect("put_stream_and_index 3");
        let mut keep = HashSet::new();
        keep.insert(id3.clone());
        store.prune_blobs(&keep, false).await.expect("prune keep");
        assert!(
            store.exists(&id3),
            "atomic put+index plus keep-set GC must preserve the blob"
        );
        assert_eq!(
            store.lookup_artifact(&key3).await.expect("lookup"),
            Some(id3)
        );
    }

    /// GC must delete the blob file before the index row, and a crash between
    /// the two halves must leave a state the next GC sweep can clean up.
    /// Simulates the crash by deleting the file by hand and then re-running
    /// `prune_blobs` with an empty `keep` set.
    #[tokio::test]
    async fn gc_recovers_from_crash_between_file_delete_and_row_delete() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let key = ArtifactKey::new("com.example", "crash", "1.0.0", "jar", None);
        let id = store.put_bytes(b"will-be-crashed").await.expect("put");
        store.add_artifact(&key, &id).await.expect("add");

        // Step (2): simulate the file-delete half of a partial GC.
        let blob_path = store.get_path(&id);
        std::fs::remove_file(&blob_path).expect("simulated crash file delete");

        // Step (3): the row is still there, pointing at a now-missing file.
        assert!(!blob_path.exists(), "file deleted (crash sim)");
        assert_eq!(
            store
                .lookup_artifact(&key)
                .await
                .expect("lookup post-crash"),
            Some(id.clone()),
            "dangling index row from simulated crash"
        );

        // Step (5): the next GC sweep with an empty keep set must clean up
        // the dangling row. The fixed code path treats NotFound on the file
        // delete as success and proceeds to remove the index row.
        store
            .prune_blobs(&HashSet::new(), false)
            .await
            .expect("recovery prune");

        assert_eq!(
            store
                .lookup_artifact(&key)
                .await
                .expect("lookup after recovery"),
            None,
            "dangling index row must be removed by the next GC after a crash"
        );
        assert!(!blob_path.exists(), "file is still gone after recovery GC");
    }

    /// `prune_blobs` protects every blob still pointed at by an index row, so
    /// the only way to exercise the file-then-row delete path is to remove
    /// the row first (making the blob unreferenced) before the next prune.
    #[tokio::test]
    async fn gc_removes_index_row_after_file_delete() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let id = store.put_bytes(b"order-test").await.expect("put");

        // Do NOT index the blob: under the new semantics, an indexed blob
        // is always protected. We're testing the file-delete half of GC.
        let blob_path = store.get_path(&id);
        assert!(blob_path.exists());
        store
            .prune_blobs(&HashSet::new(), false)
            .await
            .expect("prune");

        assert!(!blob_path.exists(), "file must be deleted");
    }

    /// Inject an index row whose blob_id is not a parseable hash, bypassing
    /// the typed API the way on-disk corruption or an external writer would.
    fn inject_corrupt_blob_id_row(store: &Store, key: &ArtifactKey, corrupt_blob_id: &str) {
        let conn = store.pool.get().expect("conn");
        conn.execute(
            "INSERT OR REPLACE INTO artifacts
             (group_id, artifact_id, version, packaging, classifier, blob_id, size_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            rusqlite::params![
                &key.group_id,
                &key.artifact_id,
                &key.version,
                &key.packaging,
                key.classifier_key(),
                corrupt_blob_id
            ],
        )
        .expect("inject corrupt row");
    }

    fn count_rows_for_artifact(store: &Store, artifact_id: &str) -> i64 {
        let conn = store.pool.get().expect("conn");
        conn.query_row(
            "SELECT COUNT(*) FROM artifacts WHERE artifact_id = ?1",
            rusqlite::params![artifact_id],
            |row| row.get(0),
        )
        .expect("count rows")
    }

    /// A row with an unparseable blob_id must read as a miss (not a permanent
    /// hard error), be scrubbed from the index, and leave the key re-indexable.
    #[tokio::test]
    async fn lookup_treats_unparseable_blob_id_row_as_miss_and_scrubs_it() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let key = ArtifactKey::new("com.example", "corrupt", "1.0.0", "jar", None);
        inject_corrupt_blob_id_row(&store, &key, "not-a-valid-blob-id");

        assert_eq!(
            store.lookup_artifact(&key).await.expect("lookup"),
            None,
            "corrupt row must be a miss, not an error"
        );
        assert_eq!(
            count_rows_for_artifact(&store, "corrupt"),
            0,
            "corrupt row must be scrubbed by lookup"
        );

        // The locked variant shares the same repair path.
        inject_corrupt_blob_id_row(&store, &key, "also-not-valid");
        assert_eq!(
            store
                .lookup_artifact_locked(&key)
                .await
                .expect("locked lookup"),
            None
        );
        assert_eq!(count_rows_for_artifact(&store, "corrupt"), 0);

        // The key is usable again after the scrub.
        let id = store.put_bytes(b"replacement").await.expect("put");
        store.add_artifact(&key, &id).await.expect("add");
        assert_eq!(store.lookup_artifact(&key).await.expect("lookup"), Some(id));
    }

    /// Batch lookup must skip and scrub unparseable rows instead of failing
    /// the whole batch, and still return hits for the healthy keys.
    #[tokio::test]
    async fn batch_lookup_skips_and_scrubs_unparseable_blob_id_rows() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let good_key = ArtifactKey::new("com.example", "good", "1.0.0", "jar", None);
        let good_id = store.put_bytes(b"good-bytes").await.expect("put");
        store.add_artifact(&good_key, &good_id).await.expect("add");

        let bad_key = ArtifactKey::new("com.example", "bad", "1.0.0", "jar", None);
        inject_corrupt_blob_id_row(&store, &bad_key, "garbage");

        let found = store
            .lookup_artifacts_batch(&[good_key.clone(), bad_key.clone()])
            .await
            .expect("batch lookup");
        assert_eq!(found.get(&good_key), Some(&good_id));
        assert_eq!(found.get(&bad_key), None, "corrupt row must be a miss");
        assert_eq!(
            count_rows_for_artifact(&store, "bad"),
            0,
            "corrupt row must be scrubbed by batch lookup"
        );
    }

    /// The GC dangling sweep must scrub rows with unparseable blob_ids
    /// instead of skipping them forever.
    #[tokio::test]
    async fn gc_scrubs_unparseable_blob_id_rows() {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(dir.path()).expect("open");

        let key = ArtifactKey::new("com.example", "gc-corrupt", "1.0.0", "jar", None);
        inject_corrupt_blob_id_row(&store, &key, "zzzz-not-a-hash");

        store
            .prune_blobs(&HashSet::new(), false)
            .await
            .expect("prune");

        assert_eq!(
            count_rows_for_artifact(&store, "gc-corrupt"),
            0,
            "GC must scrub rows with unparseable blob_ids"
        );
    }

    /// Two store handles pointing at the same directory both write the same artifact
    /// concurrently. After both writes complete, the artifact on disk must have the
    /// correct SHA-256; the exclusive fs2 lock prevents corruption.
    #[test]
    fn concurrent_writes_same_artifact_no_corruption() {
        use std::sync::Barrier;

        let dir = tempdir().expect("tempdir");
        let store_root = dir.path().join("concurrent-store");
        let barrier = Arc::new(Barrier::new(2));
        let payload = b"concurrent-artifact-content";
        let expected_id = BlobId::from_bytes(payload);

        let mut handles = Vec::new();
        for _ in 0..2 {
            let barrier = barrier.clone();
            let root = store_root.clone();
            handles.push(std::thread::spawn(move || {
                // Both threads open their own handle to the same store root
                let store = Store::open(&root).expect("store open");
                barrier.wait(); // synchronise so both start writing simultaneously
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                rt.block_on(async move { store.put_bytes(payload).await.expect("put") })
            }));
        }

        let ids: Vec<BlobId> = handles
            .into_iter()
            .map(|h| h.join().expect("thread join"))
            .collect();

        // Both threads must have received the correct blob ID
        for id in &ids {
            assert_eq!(
                id, &expected_id,
                "each writer must receive the correct blob ID"
            );
        }

        // The blob on disk must have exactly the right content (no corruption)
        let store = Store::open(&store_root).expect("store open for verify");
        let blob_path = store.get_path(&expected_id);
        assert!(
            blob_path.is_file(),
            "blob file must exist after concurrent writes"
        );
        let on_disk = std::fs::read(&blob_path).expect("read blob");
        assert_eq!(
            on_disk, payload,
            "blob content must not be corrupted by concurrent writes"
        );
        let actual_id = BlobId::from_bytes(&on_disk);
        assert_eq!(
            actual_id, expected_id,
            "SHA-256 of stored blob must match expected hash"
        );
    }

    #[test]
    fn store_lock_serialises_threads_in_same_process() {
        // On Linux, flock(2) is per-open-file-description: two threads in
        // the same process can both acquire the file lock independently.
        // The intra-process Mutex registry must serialise them before the
        // flock is even attempted.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempdir().expect("tempdir");
        let store_root = dir.path().join("locked-store");
        let _store = Store::open(&store_root).expect("open");

        let in_section = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(4));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let root = store_root.clone();
            let in_section = in_section.clone();
            let max_observed = max_observed.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..5 {
                    let _lock = super::StoreLock::acquire(&root).expect("lock");
                    let cur = in_section.fetch_add(1, Ordering::SeqCst) + 1;
                    max_observed.fetch_max(cur, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    in_section.fetch_sub(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            1,
            "StoreLock must serialise threads in the same process"
        );
    }

    /// Simulate the Windows `fs::rename` → `AlreadyExists` race in
    /// `publish_noclobber`. When the target already contains the correct bytes,
    /// `publish_noclobber` must return `BlobOrigin::Existed` rather than an error.
    ///
    /// On POSIX this path is normally unreachable (rename is atomic-replace),
    /// but the logic is cross-platform and the test exercises it on all
    /// platforms via `publish_noclobber`'s pre-flight metadata guard: we
    /// pre-populate the target so the pre-flight branch fires and returns
    /// `Existed` before reaching the rename; this is the same code path Windows hits
    /// when the OS returns `ERROR_ALREADY_EXISTS` from `MoveFileExW`.
    #[test]
    fn publish_noclobber_rename_already_exists_returns_existed() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();

        let payload = b"windows-cas-race-test";
        let id = BlobId::from_bytes(payload);

        // Write the "winning" copy at the target path.
        let target = root.join("target_blob");
        std::fs::write(&target, payload).expect("write target");

        // The src copy (what we'd normally rename).
        let src = root.join("src_blob");
        std::fs::write(&src, payload).expect("write src");

        // publish_noclobber should detect the existing valid target and
        // return Existed without touching it.
        let (returned_id, origin) =
            super::publish_noclobber(&src, &target, &id, super::BlobOrigin::Created)
                .expect("publish_noclobber");

        assert_eq!(returned_id, id, "returned id must match expected");
        assert_eq!(
            origin,
            super::BlobOrigin::Existed,
            "pre-existing valid target must yield BlobOrigin::Existed"
        );
        // Target still exists with correct bytes.
        assert_eq!(std::fs::read(&target).expect("read target"), payload);
    }
}
