use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{RepoError, Result, db_error_with_context, io_error_with_context};

/// r2d2 pool size for metadata cache connections. SQLite handles concurrent
/// readers in WAL mode; eight is enough headroom for the resolver's parallel
/// fetch tasks without exhausting file descriptors.
const CACHE_POOL_SIZE: u32 = 8;

/// RAII guard holding an exclusive advisory file lock on a sibling `.lock`
/// file. Dropping the guard releases the lock; `fs2` wraps `flock(2)` on Unix
/// and `LockFileEx` on Windows, so the guarantee is cross-platform.
struct BootstrapLock(File);

impl Drop for BootstrapLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

/// How long to wait for the bootstrap lock before giving up. The critical
/// section it guards (one PRAGMA bootstrap connection) takes milliseconds, so
/// 60s only ever elapses when a peer process is wedged (SIGSTOP'd
/// mid-bootstrap, NFS stall). Mirrors rv-store's StoreLock timeout.
const BOOTSTRAP_LOCK_TIMEOUT: Duration = Duration::from_secs(60);
/// Sleep between non-blocking lock attempts. Contention is rare and the
/// critical section is short, so a flat short sleep is enough; no need for
/// the exponential backoff rv-store uses for its long-held store lock.
const BOOTSTRAP_LOCK_RETRY: Duration = Duration::from_millis(50);

/// Acquire an exclusive advisory lock on `lock_path`. Creates the file if
/// absent. Unlike a blocking `lock_exclusive`, this loops on
/// `try_lock_exclusive` and gives up after `timeout` with an error naming
/// the lock file, so a wedged peer process cannot hang every rv invocation
/// silently (the pattern rv-store's `StoreLock::acquire_with_timeout` uses).
fn acquire_bootstrap_lock(lock_path: &Path) -> Result<BootstrapLock> {
    acquire_bootstrap_lock_with_timeout(lock_path, BOOTSTRAP_LOCK_TIMEOUT)
}

fn acquire_bootstrap_lock_with_timeout(
    lock_path: &Path,
    timeout: Duration,
) -> Result<BootstrapLock> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .with_context(|| {
            format!(
                "failed to open metadata cache lock file {}",
                lock_path.display()
            )
        })
        .map_err(|err| RepoError::Io(io_error_with_context(err)))?;

    let deadline = Instant::now() + timeout;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(BootstrapLock(file)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(RepoError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "timed out after {}s waiting for metadata cache lock {}; \
                             another rv process appears to be holding it without making \
                             progress. If no other rv process is running, remove the \
                             lock file and retry.",
                            timeout.as_secs(),
                            lock_path.display()
                        ),
                    )));
                }
                std::thread::sleep(BOOTSTRAP_LOCK_RETRY);
            }
            Err(err) => {
                return Err(RepoError::Io(io_error_with_context(
                    anyhow::Error::new(err).context(format!(
                        "failed to acquire metadata cache lock {}",
                        lock_path.display()
                    )),
                )));
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CacheTable {
    Pom,
    VersionList,
}

impl CacheTable {
    fn name(self) -> &'static str {
        match self {
            CacheTable::Pom => "pom_cache",
            CacheTable::VersionList => "version_list_cache",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CacheEntry {
    pub(crate) content: Vec<u8>,
    pub(crate) expires_at: i64,
}

#[derive(Clone)]
pub(crate) struct MetadataCache {
    pool: Arc<Pool<SqliteConnectionManager>>,
}

impl MetadataCache {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| {
                    format!(
                        "failed to create metadata cache directory {}",
                        parent.display()
                    )
                })
                .map_err(|err| RepoError::Io(io_error_with_context(err)))?;
        }

        // --- Cross-process WAL bootstrap serialization ---
        //
        // Two concurrent `rv` processes opening the same `metadata.db` both
        // running `PRAGMA journal_mode=WAL` races on the SQLite exclusive writer
        // lock. With a `busy_timeout=5s`, this usually succeeds, but on slow
        // CI it surfaces as "database is locked". Mirroring the pattern from
        // `rv-store/src/store.rs`: acquire an advisory flock on a sibling
        // `.lock` file, set WAL on a single bootstrap connection, drop the
        // connection, release the lock, THEN build the r2d2 pool.
        let lock_path = {
            let mut p = path.to_path_buf();
            let mut name = p.file_name().unwrap_or_default().to_os_string();
            name.push(".lock");
            p.set_file_name(name);
            p
        };
        let bootstrap_lock = acquire_bootstrap_lock(&lock_path)?;

        // Set WAL on a single bootstrap connection before the pool is built.
        // r2d2 eagerly opens `max_size` connections in parallel; if every
        // connection tries to flip journal_mode=WAL concurrently, the losers
        // hit "database is locked".
        {
            let bootstrap = rusqlite::Connection::open(path)
                .with_context(|| {
                    format!(
                        "failed to open metadata cache for WAL bootstrap at {}",
                        path.display()
                    )
                })
                .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
            bootstrap
                .busy_timeout(std::time::Duration::from_secs(5))
                .with_context(
                    || "failed to set busy_timeout on metadata cache bootstrap connection",
                )
                .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
            bootstrap
                .pragma_update(None, "journal_mode", "WAL")
                .with_context(|| "failed to set journal_mode=WAL on metadata cache")
                .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
            // Verify the mode actually flipped; some network filesystems silently
            // refuse WAL and fall back to DELETE.
            let mode: String = bootstrap
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .with_context(|| "failed to read back journal_mode from metadata cache")
                .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(RepoError::DbError(db_error_with_context(anyhow::anyhow!(
                    "SQLite refused to enable WAL journal mode at {}: got journal_mode={}. \
                     Network filesystems frequently reject WAL; move the cache to local storage.",
                    path.display(),
                    mode
                ))));
            }
            bootstrap
                .pragma_update(None, "synchronous", "NORMAL")
                .with_context(|| "failed to set synchronous=NORMAL on metadata cache bootstrap")
                .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
            // Drop closes the bootstrap connection before the pool takes over.
        }

        // Release the lock BEFORE building the pool so concurrent processes
        // can proceed to their own bootstrap immediately.
        drop(bootstrap_lock);

        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            // journal_mode is database-scoped (set above). Only set the
            // session-scoped pragmas here; flipping journal_mode would race
            // under concurrent pool initialization.
            conn.execute_batch(
                "PRAGMA synchronous=NORMAL;
                 PRAGMA busy_timeout=5000;",
            )?;
            Ok(())
        });

        let pool = Pool::builder()
            .max_size(CACHE_POOL_SIZE)
            .build(manager)
            .with_context(|| format!("failed to create metadata cache pool {}", path.display()))
            .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;

        let conn = pool
            .get()
            .with_context(|| "failed to take a metadata cache connection for init")
            .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
        init_schema(&conn)?;
        drop(conn);

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.pool
            .get()
            .with_context(|| "failed to take metadata cache connection from pool")
            .map_err(|err| RepoError::DbError(db_error_with_context(err)))
    }

    pub(crate) fn get(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
    ) -> Result<Option<CacheEntry>> {
        let conn = self.conn()?;
        // `fetched_at` stays in the schema for compatibility but is no longer
        // read; selecting only the columns we use saves one i64.
        let sql = format!(
            "SELECT content, expires_at FROM {}
             WHERE repo_url = ?1 AND path = ?2",
            table.name()
        );
        let entry = conn
            .query_row(&sql, params![repo_url, path], |row| {
                Ok(CacheEntry {
                    content: row.get(0)?,
                    expires_at: row.get(1)?,
                })
            })
            .optional()
            .with_context(|| {
                format!(
                    "failed to read metadata cache entry for {}:{}",
                    repo_url, path
                )
            })
            .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
        Ok(entry)
    }

    pub(crate) fn insert_with_ttl(
        &self,
        table: CacheTable,
        repo_url: &str,
        path: &str,
        content: &[u8],
        ttl: i64,
    ) -> Result<()> {
        let conn = self.conn()?;
        let fetched_at = now_epoch_seconds();
        let expires_at = fetched_at.saturating_add(ttl);
        let sql = format!(
            "INSERT INTO {} (repo_url, path, content, fetched_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(repo_url, path) DO UPDATE
             SET content = excluded.content,
                 fetched_at = excluded.fetched_at,
                 expires_at = excluded.expires_at",
            table.name()
        );
        conn.execute(
            &sql,
            params![repo_url, path, content, fetched_at, expires_at],
        )
        .with_context(|| {
            format!(
                "failed to insert metadata cache entry for {}:{}",
                repo_url, path
            )
        })
        .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
        Ok(())
    }

    pub(crate) fn is_expired(expires_at: i64, now: i64) -> bool {
        expires_at <= now
    }

    /// Deletes all expired entries from all cache tables.
    /// Returns the total number of deleted rows.
    pub(crate) fn cleanup_expired(&self) -> Result<usize> {
        let conn = self.conn()?;
        let now = now_epoch_seconds();
        let mut deleted = 0usize;

        for table in [CacheTable::Pom, CacheTable::VersionList] {
            let sql = format!("DELETE FROM {} WHERE expires_at < ?1", table.name());
            let count = conn
                .execute(&sql, params![now])
                .with_context(|| format!("failed to cleanup expired entries from {}", table.name()))
                .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
            deleted = deleted.saturating_add(count);
        }

        if deleted > 0 {
            tracing::debug!(deleted, "cleaned up expired metadata cache entries");
        }

        Ok(deleted)
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pom_cache (
            repo_url   TEXT NOT NULL,
            path       TEXT NOT NULL,
            content    BLOB NOT NULL,
            fetched_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (repo_url, path)
         );
         CREATE TABLE IF NOT EXISTS version_list_cache (
            repo_url   TEXT NOT NULL,
            path       TEXT NOT NULL,
            content    BLOB NOT NULL,
            fetched_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (repo_url, path)
         );",
    )
    .with_context(|| "failed to initialize metadata cache database")
    .map_err(|err| RepoError::DbError(db_error_with_context(err)))?;
    Ok(())
}

/// Current Unix time in whole seconds, clamped to zero if the system clock is
/// before the epoch. Shared by the cache TTL bookkeeping here and the
/// expiry check in `client.rs` so the two cannot drift in their clock handling.
pub(crate) fn now_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::{CacheTable, MetadataCache};
    use tempfile::tempdir;

    #[test]
    fn is_expired_checks_timestamp_bounds() {
        assert!(MetadataCache::is_expired(100, 100));
        assert!(MetadataCache::is_expired(100, 101));
        assert!(!MetadataCache::is_expired(101, 100));
    }

    #[test]
    fn cleanup_expired_removes_old_entries() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&db_path).expect("cache");

        // Insert an entry with negative TTL (already expired in the past)
        cache
            .insert_with_ttl(
                CacheTable::Pom,
                "https://repo.example/",
                "com/example/expired/1.0.0/expired-1.0.0.pom",
                b"<expired/>",
                -1, // Negative TTL means already expired
            )
            .expect("insert expired");

        // Insert a fresh entry with long TTL (1 day).
        cache
            .insert_with_ttl(
                CacheTable::Pom,
                "https://repo.example/",
                "com/example/fresh/1.0.0/fresh-1.0.0.pom",
                b"<fresh/>",
                24 * 60 * 60,
            )
            .expect("insert fresh");

        // Verify both entries exist before cleanup (DB still has them even if expired)
        assert!(
            cache
                .get(
                    CacheTable::Pom,
                    "https://repo.example/",
                    "com/example/expired/1.0.0/expired-1.0.0.pom"
                )
                .expect("get")
                .is_some()
        );
        assert!(
            cache
                .get(
                    CacheTable::Pom,
                    "https://repo.example/",
                    "com/example/fresh/1.0.0/fresh-1.0.0.pom"
                )
                .expect("get")
                .is_some()
        );

        // Run cleanup
        let deleted = cache.cleanup_expired().expect("cleanup");
        assert_eq!(deleted, 1, "expected 1 deleted, got {deleted}");

        // Expired entry should be gone
        assert!(
            cache
                .get(
                    CacheTable::Pom,
                    "https://repo.example/",
                    "com/example/expired/1.0.0/expired-1.0.0.pom"
                )
                .expect("get")
                .is_none()
        );

        // Fresh entry should still exist
        assert!(
            cache
                .get(
                    CacheTable::Pom,
                    "https://repo.example/",
                    "com/example/fresh/1.0.0/fresh-1.0.0.pom"
                )
                .expect("get")
                .is_some()
        );
    }

    /// A peer that holds the bootstrap lock and never releases it (wedged
    /// process) must produce a timeout error naming the lock file rather
    /// than blocking forever.
    #[test]
    fn bootstrap_lock_times_out_when_held() {
        use super::acquire_bootstrap_lock_with_timeout;
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("metadata.db.lock");

        // Holder thread: acquires the lock and keeps it until told to stop.
        // flock locks are per open file description, so the second open in
        // the main thread genuinely contends with this one.
        let holder_path = lock_path.clone();
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let guard = acquire_bootstrap_lock_with_timeout(&holder_path, Duration::from_secs(5))
                .expect("holder must acquire the uncontended lock");
            held_tx.send(()).expect("signal held");
            release_rx.recv().expect("wait for release signal");
            drop(guard);
        });
        held_rx.recv().expect("holder signals lock held");

        let result = acquire_bootstrap_lock_with_timeout(&lock_path, Duration::from_millis(100));
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("contended lock must time out, not succeed"),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("timed out"),
            "error must say it timed out: {rendered}"
        );
        assert!(
            rendered.contains(&lock_path.display().to_string()),
            "error must name the lock file so the user can investigate: {rendered}"
        );

        release_tx.send(()).expect("release holder");
        holder.join().expect("holder thread");

        // After the holder releases, acquisition succeeds again.
        acquire_bootstrap_lock_with_timeout(&lock_path, Duration::from_secs(5))
            .expect("lock must be acquirable after release");
    }

    // --- concurrent MetadataCache::new against the same db ---

    /// Two `MetadataCache` instances opened concurrently against the same
    /// database file must both succeed. This exercises the cross-process WAL
    /// bootstrap serialization for concurrent MetadataCache::new.
    #[test]
    fn concurrent_open_same_db_both_succeed() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().expect("tempdir");
        let db_path = Arc::new(dir.path().join("metadata.db"));

        // Spawn two threads that both call `MetadataCache::new` concurrently.
        let path_a = Arc::clone(&db_path);
        let handle_a = thread::spawn(move || MetadataCache::new(&path_a));

        let path_b = Arc::clone(&db_path);
        let handle_b = thread::spawn(move || MetadataCache::new(&path_b));

        let cache_a = handle_a
            .join()
            .expect("thread A panicked")
            .expect("cache A");
        let cache_b = handle_b
            .join()
            .expect("thread B panicked")
            .expect("cache B");

        // Both caches must be functional: write via A, read via B.
        cache_a
            .insert_with_ttl(
                CacheTable::Pom,
                "https://repo.example/",
                "com/example/artifact/1.0/artifact-1.0.pom",
                b"<pom/>",
                3600,
            )
            .expect("insert via cache A");

        let entry = cache_b
            .get(
                CacheTable::Pom,
                "https://repo.example/",
                "com/example/artifact/1.0/artifact-1.0.pom",
            )
            .expect("get via cache B")
            .expect("entry must be present");
        assert_eq!(entry.content, b"<pom/>");
    }
}
