//! The repository metadata cache: fetched POMs and version lists, each row
//! keyed by a caller-chosen scope and repository path and carrying an
//! expiry time and whether the content was checked against a checksum
//! file. It lives in its own database (`metadata.db`), apart from the store
//! index, because it is disposable: deleting it costs only refetches.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{DbResultExt, StoreError};
use rv_fs::lock_exclusive_until;

/// Why the metadata cache could not be opened, read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// Creating the cache directory or taking the bootstrap lock failed.
    #[error("{0}")]
    Io(std::io::Error),
    /// A query failed. `ctx` names it without the cache scope, which can hold
    /// repository URLs.
    #[error("{ctx}: {source}")]
    Db {
        /// The query that failed.
        ctx: String,
        /// The SQLite error.
        #[source]
        source: Box<rusqlite::Error>,
    },
    /// The pool could not hand out a connection.
    #[error("{0}")]
    Pool(String),
    /// The database could not be switched to WAL mode or pooled.
    #[error(transparent)]
    Setup(Box<StoreError>),
}

impl CacheError {
    /// For a database error, what its SQLite result code says.
    pub fn db_failure(&self) -> Option<crate::DbFailure> {
        match self {
            CacheError::Db { source, .. } => Some(crate::DbFailure::of(source)),
            CacheError::Setup(err) => err.db_failure(),
            _ => None,
        }
    }

    /// Whether the volume ran out of space or the user out of quota.
    pub fn is_disk_full(&self) -> bool {
        match self {
            CacheError::Io(err) => crate::error::out_of_space(err),
            CacheError::Db { source, .. } => {
                crate::DbFailure::of(source) == crate::DbFailure::DiskFull
            }
            CacheError::Setup(err) => err.is_disk_full(),
            CacheError::Pool(_) => false,
        }
    }

    /// Name the repository a failed query was for. `repository` must already
    /// be redacted.
    pub fn for_repository(self, repository: &str) -> Self {
        match self {
            CacheError::Db { ctx, source } => CacheError::Db {
                ctx: format!("{ctx} for {repository}"),
                source,
            },
            other => other,
        }
    }
}

type Result<T> = std::result::Result<T, CacheError>;

impl From<StoreError> for CacheError {
    fn from(err: StoreError) -> Self {
        CacheError::Setup(Box::new(err))
    }
}

impl crate::sqlite::DbError for CacheError {
    fn is_corrupt(&self) -> bool {
        self.db_failure() == Some(crate::DbFailure::Corrupt)
    }

    fn pool(err: r2d2::Error) -> Self {
        CacheError::Pool(format!(
            "failed to take metadata cache connection from pool: {err}"
        ))
    }
}

fn io_error(context: String, err: std::io::Error) -> std::io::Error {
    std::io::Error::new(err.kind(), format!("{context}: {err}"))
}

/// r2d2 pool size: headroom for the resolver's parallel fetch tasks without
/// exhausting file descriptors.
const CACHE_POOL_SIZE: u32 = 8;

const CACHE: crate::sqlite::Spec = crate::sqlite::Spec {
    pragmas: "PRAGMA synchronous=NORMAL;
              PRAGMA busy_timeout=5000;",
    max_size: CACHE_POOL_SIZE,
    generation: 1,
    init: init_schema,
    lock: |path| Ok(Box::new(bootstrap_lock(path)?)),
};

/// How long to wait for the bootstrap lock. The section it guards takes
/// milliseconds, so this only elapses when a peer process is wedged.
const BOOTSTRAP_LOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// Take the lock on the `.lock` file beside the cache at `path`. Two
/// processes setting up or recreating one `metadata.db` would race on
/// `PRAGMA journal_mode=WAL`.
fn bootstrap_lock(path: &Path) -> std::io::Result<File> {
    let mut lock_name = path.file_name().unwrap_or_default().to_os_string();
    lock_name.push(".lock");
    acquire_bootstrap_lock(&path.with_file_name(lock_name), BOOTSTRAP_LOCK_TIMEOUT)
}

/// Take an exclusive advisory lock on `lock_path`, creating the file if
/// absent. Dropping the file releases it.
fn acquire_bootstrap_lock(lock_path: &Path, timeout: Duration) -> std::io::Result<File> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|err| {
            let what = format!(
                "failed to open metadata cache lock file {}",
                lock_path.display()
            );
            io_error(what, err)
        })?;
    match lock_exclusive_until(&mut file, Instant::now() + timeout) {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "timed out after {}s waiting for the metadata cache lock {}. \
                 Another raeva process holds it. Wait for that process to finish, \
                 or stop it, and retry. Do not delete the lock file while that \
                 process runs: a new process would lock a new file at the same \
                 path, and both would proceed at once.",
                timeout.as_secs(),
                lock_path.display()
            ),
        )),
        Err(std::fs::TryLockError::Error(err)) => Err(io_error(
            format!(
                "failed to acquire metadata cache lock {}",
                lock_path.display()
            ),
            err,
        )),
    }
}

/// The kinds of row the cache holds.
#[derive(Debug, Clone, Copy)]
pub enum CacheTable {
    /// Fetched POM bytes.
    Pom,
    /// Fetched `maven-metadata.xml` bytes.
    VersionList,
    /// Remote paths a repository answered 404, 401 or 403 for, with that
    /// status.
    Miss,
}

impl CacheTable {
    fn name(self) -> &'static str {
        match self {
            CacheTable::Pom => "pom_cache_v3",
            CacheTable::VersionList => "version_list_cache_v3",
            CacheTable::Miss => "miss_cache_v3",
        }
    }
}

/// One cached row.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CacheEntry {
    /// The cached bytes, as fetched.
    pub content: Vec<u8>,
    /// Unix time in seconds after which the row is stale.
    pub expires_at: i64,
    /// Whether the writer checked `content` against the repository's
    /// checksum file. False when there was none and the writer accepted the
    /// content anyway.
    pub checksum_checked: bool,
    /// Unix time in seconds the row was written.
    pub fetched_at: i64,
    /// The SHA-256 of `content`, which matched the one written with it.
    pub sha256: rv_maven_types::Sha256,
}

/// A handle on `metadata.db`. Clones share one connection pool.
#[derive(Clone)]
pub struct MetadataCache {
    pool: Arc<crate::sqlite::Db>,
    // WAL permits concurrent readers, but only one writer. Queue writes before
    // taking a pooled connection so our own clones do not exhaust the busy
    // timeout (or occupy every connection while waiting for the writer).
    writer: Arc<Mutex<()>>,
    key: Option<[u8; KEY_LEN]>,
}

const KEY_LEN: usize = 32;

/// HMAC-SHA256 under the key in the `cache-key` file beside `metadata.db`.
/// A digest of a secret kept in the cache is taken under it, so the cache,
/// which CI caches carry between jobs, gives no way to test a guessed secret.
pub struct KeyedDigest {
    inner: sha2::Sha256,
    outer_pad: [u8; 64],
}

impl KeyedDigest {
    fn new(key: &[u8; KEY_LEN]) -> Self {
        use sha2::Digest as _;
        let mut block = [0u8; 64];
        block[..KEY_LEN].copy_from_slice(key);
        let mut inner = sha2::Sha256::new();
        inner.update(block.map(|byte| byte ^ 0x36));
        Self {
            inner,
            outer_pad: block.map(|byte| byte ^ 0x5c),
        }
    }

    /// Feed `bytes` to the digest.
    pub fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest as _;
        self.inner.update(bytes);
    }

    /// The digest, hex encoded.
    pub fn finalize_hex(self) -> String {
        use sha2::Digest as _;
        let mut outer = sha2::Sha256::new();
        outer.update(self.outer_pad);
        outer.update(self.inner.finalize());
        hex::encode(outer.finalize())
    }
}

/// The key in `path`, created with owner-only access when missing or not a
/// key. A key that cannot be kept lasts this process: what is recorded under
/// it is never matched again. `None` when no random bytes are to be had.
/// Runs under the bootstrap lock, so concurrent opens agree on the key.
fn load_or_create_key(path: &Path) -> Option<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == KEY_LEN => {
            key.copy_from_slice(&bytes);
            return Some(key);
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            tracing::warn!(
                sec_code = "CACHE_KEY_UNAVAILABLE",
                "failed to read {}: {err}",
                path.display()
            );
            getrandom::fill(&mut key).ok()?;
            return Some(key);
        }
    }
    getrandom::fill(&mut key).ok()?;
    if let Err(err) = rv_fs::write_file_atomic(path, &key, rv_fs::NewFileAccess::Private) {
        tracing::warn!(
            sec_code = "CACHE_KEY_UNAVAILABLE",
            "failed to write {}: {err}",
            path.display()
        );
    }
    Some(key)
}

impl MetadataCache {
    /// Open the cache at `path`, creating it and its directory if needed.
    pub fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                CacheError::Io(io_error(
                    format!(
                        "failed to create metadata cache directory {}",
                        parent.display()
                    ),
                    err,
                ))
            })?;
        }

        let bootstrap_lock = bootstrap_lock(path).map_err(CacheError::Io)?;

        let pool = crate::sqlite::open(path, CACHE)?;
        let key = load_or_create_key(&path.with_file_name("cache-key"));
        drop(bootstrap_lock);

        Ok(Self {
            pool,
            writer: Arc::new(Mutex::new(())),
            key,
        })
    }

    /// A digest under the key kept beside this cache. `None` when there is
    /// no key to take one under.
    pub fn keyed_digest(&self) -> Option<KeyedDigest> {
        self.key.as_ref().map(KeyedDigest::new)
    }

    /// The row for `path` in `scope`, expired or not. A row whose bytes no
    /// longer match the digest written with them is dropped and reads as
    /// none.
    pub fn get(&self, table: CacheTable, scope: &str, path: &str) -> Result<Option<CacheEntry>> {
        let sql = format!(
            "SELECT content, expires_at, checksum_checked, fetched_at, sha256 FROM {}
             WHERE repo_url = ?1 AND path = ?2",
            table.name()
        );
        let row = self.pool.run(|conn| {
            conn.prepare_cached(&sql)
                .and_then(|mut statement| {
                    statement.query_row(params![scope, path], |row| {
                        // A flipped bit in a row's header can make its bytes
                        // text, and a digest that is not text matches none.
                        let content = row.get_ref(0)?.as_bytes()?.to_vec();
                        let written = row.get_ref(4)?.as_bytes().ok().map(<[u8]>::to_vec);
                        let row: (_, i64, i64, i64, _) =
                            (content, row.get(1)?, row.get(2)?, row.get(3)?, written);
                        Ok(row)
                    })
                })
                .optional()
                .map_err(|source| CacheError::Db {
                    ctx: format!("failed to read metadata cache entry {path}"),
                    source: Box::new(source),
                })
        })?;
        let Some((content, expires_at, checksum_checked, fetched_at, written)) = row else {
            return Ok(None);
        };
        let sha256 = rv_maven_types::Sha256::from_bytes(&content);
        if written.as_deref() == Some(sha256.as_str().as_bytes()) {
            return Ok(Some(CacheEntry {
                content,
                expires_at,
                checksum_checked: checksum_checked != 0,
                fetched_at,
                sha256,
            }));
        }
        tracing::warn!(
            sec_code = "CACHE_ENTRY_DAMAGED",
            "the metadata cache's copy of {path} does not match the checksum it was written \
             with, so raeva dropped it"
        );
        let sql = format!(
            "DELETE FROM {} WHERE repo_url = ?1 AND path = ?2 AND CAST(content AS BLOB) = ?3",
            table.name()
        );
        let _writer = crate::store::lock(&self.writer);
        self.pool.write(|conn| {
            conn.execute(&sql, params![scope, path, content])
                .map_err(|source| CacheError::Db {
                    ctx: format!("failed to drop metadata cache entry {path}"),
                    source: Box::new(source),
                })
        })?;
        Ok(None)
    }

    /// Whether `table` has a row for each `(scope, path, pin, renewed)` that
    /// holds the bytes `pin` names, was written at or after `renewed` when
    /// given, and is not stale at `now` ([`Self::is_stale`]) when given, in
    /// one read. The
    /// digest written with the row stands for its bytes, which a read that
    /// returns them hashes again.
    pub fn holds(
        &self,
        table: CacheTable,
        keys: &[(String, String, rv_maven_types::Sha256, Option<i64>)],
        now: Option<i64>,
    ) -> Result<Vec<bool>> {
        let sql = format!(
            "SELECT sha256, expires_at, fetched_at FROM {} WHERE repo_url = ?1 AND path = ?2",
            table.name()
        );
        let db = |source| CacheError::Db {
            ctx: "failed to read metadata cache entries".to_string(),
            source: Box::new(source),
        };
        self.pool.run(|conn| {
            let mut statement = conn.prepare_cached(&sql).map_err(db)?;
            (keys.iter())
                .map(|(scope, path, pin, renewed)| {
                    let held = |row: &rusqlite::Row<'_>| {
                        let (expires_at, fetched_at): (i64, i64) = (row.get(1)?, row.get(2)?);
                        Ok(
                            now.is_none_or(|now| !Self::is_stale(fetched_at, expires_at, now))
                                && renewed.is_none_or(|start| fetched_at >= start)
                                && row.get_ref(0)?.as_str()? == pin.as_str(),
                        )
                    };
                    let held = statement.query_row(params![scope, path], held).optional();
                    Ok(held.map_err(db)? == Some(true))
                })
                .collect()
        })
    }

    /// Write the row for `path` in `scope`, expiring `ttl` seconds from now.
    /// `checksum_checked` records whether `content` was checked against the
    /// repository's checksum file.
    pub fn insert_with_ttl(
        &self,
        table: CacheTable,
        scope: &str,
        path: &str,
        content: &[u8],
        ttl: i64,
        checksum_checked: bool,
    ) -> Result<()> {
        let sha256 = rv_maven_types::Sha256::from_bytes(content);
        let _writer = crate::store::lock(&self.writer);
        let fetched_at = now_epoch_seconds();
        let expires_at = fetched_at.saturating_add(ttl);
        let sql = format!(
            "INSERT INTO {}
             (repo_url, path, content, sha256, fetched_at, expires_at, checksum_checked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(repo_url, path) DO UPDATE
             SET content = excluded.content,
                 sha256 = excluded.sha256,
                 fetched_at = excluded.fetched_at,
                 expires_at = excluded.expires_at,
                 checksum_checked = excluded.checksum_checked",
            table.name()
        );
        // The context names the path only: the scope can contain repository
        // credentials.
        self.pool.write(|conn| {
            conn.execute(
                &sql,
                params![
                    scope,
                    path,
                    content,
                    sha256.as_str(),
                    fetched_at,
                    expires_at,
                    checksum_checked
                ],
            )
            .map_err(|source| CacheError::Db {
                ctx: format!("failed to write metadata cache entry {path}"),
                source: Box::new(source),
            })
        })?;
        Ok(())
    }

    /// Whether a row that expires at `expires_at` is stale at `now`.
    pub fn is_expired(expires_at: i64, now: i64) -> bool {
        expires_at <= now
    }

    /// Whether a row written at `fetched_at` that expires at `expires_at`
    /// is stale at `now`. A row dated after `now`, as a clock that ran ahead
    /// or a cache copied from one leaves it, is stale too: its expiry would
    /// keep it fresh for as long as that clock was ahead, and `--update`
    /// would take it for a row written during the run.
    pub fn is_stale(fetched_at: i64, expires_at: i64, now: i64) -> bool {
        fetched_at > now || Self::is_expired(expires_at, now)
    }
}

fn init_schema(conn: &Connection) -> crate::error::Result<()> {
    drop_unkeyed_misses(conn)?;
    for table in [CacheTable::Pom, CacheTable::VersionList, CacheTable::Miss] {
        // The content comes last: a read of a column after it walks its
        // overflow pages.
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                repo_url   TEXT NOT NULL,
                path       TEXT NOT NULL,
                sha256     TEXT NOT NULL,
                fetched_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                checksum_checked INTEGER NOT NULL,
                content    BLOB NOT NULL,
                PRIMARY KEY (repo_url, path)
             )",
            table.name()
        );
        conn.execute_batch(&sql)
            .db_context(|| "failed to initialize metadata cache database")?;
    }
    Ok(())
}

/// Remove the misses kept under unkeyed credential digests, which would let
/// a copy of the cache test a guessed credential, with their pages zeroed
/// and the write-ahead log emptied. The zeroed pages reach `metadata.db`
/// only when a checkpoint completes, which a reader can hold up, so a
/// marker table keeps the checkpoint pending for a later open until one
/// does.
fn drop_unkeyed_misses(conn: &Connection) -> crate::error::Result<()> {
    let db_error = |source| StoreError::DbContext {
        ctx: "failed to remove unkeyed misses from the metadata cache".to_string(),
        source,
    };
    let exists = |table: &str| -> crate::error::Result<bool> {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )
        .map_err(db_error)
    };
    let legacy = exists("miss_cache_v2")?;
    if legacy {
        conn.execute_batch(
            "PRAGMA secure_delete = ON;
             BEGIN;
             DROP TABLE IF EXISTS miss_cache_v2;
             CREATE TABLE IF NOT EXISTS unkeyed_misses_dropped (pending INTEGER);
             COMMIT;
             PRAGMA secure_delete = OFF;",
        )
        .map_err(db_error)?;
    }
    if legacy || exists("unkeyed_misses_dropped")? {
        let busy: i64 = (conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0)))
            .map_err(db_error)?;
        if busy == 0 {
            conn.execute_batch("DROP TABLE IF EXISTS unkeyed_misses_dropped")
                .map_err(db_error)?;
        }
    }
    Ok(())
}

/// Current Unix time in whole seconds, clamped to zero if the system clock is
/// before the epoch. Shared by the TTL bookkeeping here and callers' expiry
/// checks so the two cannot drift in their clock handling.
pub fn now_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CacheTable, KeyedDigest, MetadataCache, acquire_bootstrap_lock};

    fn digest(cache: &MetadataCache, secret: &[u8]) -> String {
        let mut digest = cache.keyed_digest().unwrap();
        digest.update(secret);
        digest.finalize_hex()
    }

    #[test]
    fn keyed_digest_is_hmac_sha256() {
        // RFC 4231 test case 2; HMAC pads a short key with zeros itself.
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(b"Jefe");
        let mut digest = KeyedDigest::new(&key);
        digest.update(b"what do ya want ");
        digest.update(b"for nothing?");
        assert_eq!(
            digest.finalize_hex(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// The key lives in an owner-only `cache-key` beside `metadata.db`, so
    /// the database alone, as a CI cache carries it, gives no digest; with
    /// the file gone, the digests recorded before stop matching.
    #[test]
    fn the_digest_key_is_kept_beside_the_database_and_not_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let first = digest(&cache, b"token");
        cache
            .insert_with_ttl(
                CacheTable::Miss,
                &first,
                "g/a/1/a-1.pom",
                b"404",
                3600,
                true,
            )
            .unwrap();
        let key_path = dir.path().join("cache-key");
        let key = std::fs::read(&key_path).unwrap();
        assert_eq!(key.len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(digest(&MetadataCache::new(&path).unwrap(), b"token"), first);
        assert_ne!(digest(&cache, b"other"), first);
        drop(cache);

        let mut stored = Vec::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() != "cache-key" {
                stored.extend(std::fs::read(entry.path()).unwrap());
            }
        }
        assert!(stored.windows(key.len()).all(|window| window != key));
        let copy = tempfile::tempdir().unwrap();
        std::fs::copy(&path, copy.path().join("metadata.db")).unwrap();
        let copied = MetadataCache::new(&copy.path().join("metadata.db")).unwrap();
        assert_ne!(digest(&copied, b"token"), first);

        std::fs::remove_file(&key_path).unwrap();
        assert_ne!(digest(&MetadataCache::new(&path).unwrap(), b"token"), first);
        std::fs::write(&key_path, b"short").unwrap();
        let rekeyed = digest(&MetadataCache::new(&path).unwrap(), b"token");
        assert_eq!(std::fs::read(&key_path).unwrap().len(), 32);
        assert_eq!(
            digest(&MetadataCache::new(&path).unwrap(), b"token"),
            rekeyed
        );
    }

    /// A peer that never releases the bootstrap lock times the open out with
    /// an error naming the lock file, which must not advise deleting it.
    #[test]
    fn bootstrap_lock_times_out_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("metadata.db.lock");
        let held = acquire_bootstrap_lock(&lock_path, Duration::from_secs(5)).unwrap();
        let err = acquire_bootstrap_lock(&lock_path, Duration::from_millis(100))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("timed out"), "{err}");
        assert!(err.contains(&lock_path.display().to_string()), "{err}");
        assert!(err.contains("Do not delete the lock file"), "{err}");
        drop(held);
        acquire_bootstrap_lock(&lock_path, Duration::from_secs(5)).unwrap();
    }

    /// A damaged cache, as a partial CI cache restore leaves, is replaced
    /// instead of failing every later run.
    #[test]
    fn open_replaces_a_damaged_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, content) = ("https://repo.example/", [b'x'; 4096]);
        for n in 0..200 {
            let pom = format!("g/a/{n}/a-{n}.pom");
            cache
                .insert_with_ttl(CacheTable::Pom, scope, &pom, &content, 3600, true)
                .unwrap();
        }
        drop(cache);
        let len = std::fs::metadata(&path).unwrap().len();
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_len(len / 2).unwrap();
        drop(file);
        for _ in 0..2 {
            let cache = MetadataCache::new(&path).unwrap();
            cache
                .insert_with_ttl(
                    CacheTable::Pom,
                    scope,
                    "g/b/1/b-1.pom",
                    b"<pom/>",
                    3600,
                    true,
                )
                .unwrap();
            assert!(
                cache
                    .get(CacheTable::Pom, scope, "g/b/1/b-1.pom")
                    .unwrap()
                    .is_some()
            );
            drop(cache);
            std::fs::write(&path, [7u8; 8192]).unwrap();
        }
    }

    /// A cache that a newer raeva stamped with a later generation is not
    /// opened, and keeps its rows.
    #[test]
    fn a_cache_from_a_newer_raeva_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, pom) = ("https://repo.example/", "g/a/1/a-1.pom");
        cache
            .insert_with_ttl(CacheTable::Pom, scope, pom, b"<pom/>", 3600, true)
            .unwrap();
        drop(cache);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        drop(conn);
        let err = MetadataCache::new(&path).err().unwrap();
        assert!(
            err.to_string().contains("written by a newer raeva"),
            "{err}"
        );
        let conn = rusqlite::Connection::open(&path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM pom_cache_v3", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    /// A cache that a newer raeva stamps with a later generation while this
    /// handle has it open takes no write through the handle: neither a new
    /// row nor the drop of one whose bytes do not match its digest.
    #[test]
    fn an_open_cache_takes_no_write_once_a_newer_raeva_stamped_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, pom) = ("https://repo.example/", "g/a/1/a-1.pom");
        cache
            .insert_with_ttl(CacheTable::Pom, scope, pom, b"<pom/>", 3600, true)
            .unwrap();
        let peer = rusqlite::Connection::open(&path).unwrap();
        peer.execute("UPDATE pom_cache_v3 SET content = x'00'", [])
            .unwrap();
        peer.pragma_update(None, "user_version", 2).unwrap();
        let version = || -> i64 {
            peer.pragma_query_value(None, "data_version", |row| row.get(0))
                .unwrap()
        };
        let before = version();
        let errors = [
            cache
                .insert_with_ttl(
                    CacheTable::Pom,
                    scope,
                    "g/b/1/b-1.pom",
                    b"<pom/>",
                    3600,
                    true,
                )
                .unwrap_err(),
            cache.get(CacheTable::Pom, scope, pom).unwrap_err(),
        ];
        for err in errors {
            assert!(
                err.to_string().contains("written by a newer raeva"),
                "{err}"
            );
        }
        assert_eq!(version(), before);
    }

    /// Damage past the schema page passes the check at open; the first
    /// query that reads it recreates the cache.
    #[test]
    fn a_query_that_finds_the_cache_damaged_recreates_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, content) = ("https://repo.example/", [b'x'; 4096]);
        for n in 0..200 {
            let pom = format!("g/a/{n}/a-{n}.pom");
            cache
                .insert_with_ttl(CacheTable::Pom, scope, &pom, &content, 3600, true)
                .unwrap();
        }
        drop(cache);
        crate::sqlite::damage_past_schema(&path);
        let cache = MetadataCache::new(&path).unwrap();
        let pom = "g/a/7/a-7.pom";
        assert!(cache.get(CacheTable::Pom, scope, pom).unwrap().is_none());
        cache
            .insert_with_ttl(CacheTable::Pom, scope, pom, b"<pom/>", 3600, true)
            .unwrap();
        assert!(cache.get(CacheTable::Pom, scope, pom).unwrap().is_some());
    }

    /// A row dated in the future is stale, under `--update` too, where it
    /// would otherwise pass for a row written during the run.
    #[test]
    fn a_row_dated_in_the_future_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, pom) = ("https://repo.example/", "g/a/1/a-1.pom");
        cache
            .insert_with_ttl(CacheTable::Pom, scope, pom, b"<pom/>", 3600, true)
            .unwrap();
        let pin = rv_maven_types::Sha256::from_bytes(b"<pom/>");
        let now = cache
            .get(CacheTable::Pom, scope, pom)
            .unwrap()
            .unwrap()
            .fetched_at;
        let holds = |renewed: Option<i64>| {
            let key = (scope.to_string(), pom.to_string(), pin.clone(), renewed);
            cache.holds(CacheTable::Pom, &[key], Some(now)).unwrap()[0]
        };
        assert!(holds(None) && holds(Some(now)));
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE pom_cache_v3 SET fetched_at = ?1 + 600", [now])
            .unwrap();
        assert!(!holds(None) && !holds(Some(now)));
        let entry = cache.get(CacheTable::Pom, scope, pom).unwrap().unwrap();
        assert!(MetadataCache::is_stale(
            entry.fetched_at,
            entry.expires_at,
            now
        ));
        assert!(!MetadataCache::is_stale(now, entry.expires_at, now));
    }

    /// A row whose bytes changed after they were written, as damage inside
    /// a page or an edit leaves it, reads as none and is dropped; the rows
    /// beside it stay.
    #[test]
    fn a_row_that_no_longer_matches_its_digest_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let scope = "https://repo.example/";
        for table in [CacheTable::Pom, CacheTable::VersionList, CacheTable::Miss] {
            for pom in [
                "g/a/1/a-1.pom",
                "g/a/2/a-2.pom",
                "g/a/3/a-3.pom",
                "g/a/4/a-4.pom",
            ] {
                cache
                    .insert_with_ttl(table, scope, pom, b"<pom/>", 3600, true)
                    .unwrap();
            }
            // Other bytes, a digest that is not text, and bytes stored as text.
            rusqlite::Connection::open(&path)
                .unwrap()
                .execute_batch(&format!(
                    "UPDATE {0} SET content = x'00' WHERE path = 'g/a/1/a-1.pom';
                     UPDATE {0} SET sha256 = CAST(x'ff' AS TEXT) WHERE path = 'g/a/3/a-3.pom';
                     UPDATE {0} SET content = 'other' WHERE path = 'g/a/4/a-4.pom';",
                    table.name()
                ))
                .unwrap();
            assert!(cache.get(table, scope, "g/a/3/a-3.pom").unwrap().is_none());
            assert!(cache.get(table, scope, "g/a/4/a-4.pom").unwrap().is_none());
            assert!(cache.get(table, scope, "g/a/1/a-1.pom").unwrap().is_none());
            let rows: i64 = rusqlite::Connection::open(&path)
                .unwrap()
                .query_row(
                    &format!("SELECT count(*) FROM {}", table.name()),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rows, 1, "{}", table.name());
            let entry = cache.get(table, scope, "g/a/2/a-2.pom").unwrap().unwrap();
            assert_eq!(entry.sha256, rv_maven_types::Sha256::from_bytes(b"<pom/>"));
        }
    }

    /// Damage that only creating the schema reads, here in the table of
    /// unkeyed misses it drops, recreates the cache at open.
    #[test]
    fn damage_the_schema_setup_reads_recreates_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        drop(MetadataCache::new(&path).unwrap());
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE miss_cache_v2 (path TEXT, content BLOB);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 200)
             INSERT INTO miss_cache_v2 SELECT i, zeroblob(2000) FROM n;",
        )
        .unwrap();
        drop(conn);
        crate::sqlite::damage_past_schema(&path);
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, pom) = ("https://repo.example/", "g/a/1/a-1.pom");
        cache
            .insert_with_ttl(CacheTable::Pom, scope, pom, b"<pom/>", 3600, true)
            .unwrap();
        assert!(cache.get(CacheTable::Pom, scope, pom).unwrap().is_some());
    }

    /// Misses kept under the unkeyed digests of earlier releases are
    /// removed, and their bytes with them.
    #[test]
    fn unkeyed_misses_are_removed_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let marker = "unkeyed-credential-digest";
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE miss_cache_v2 (repo_url TEXT, path TEXT, content BLOB);",
            )
            .unwrap();
            for index in 0..50 {
                conn.execute(
                    "INSERT INTO miss_cache_v2 VALUES (?1, 'g/a/1/a-1.pom', x'00')",
                    [format!("{marker}-{index}")],
                )
                .unwrap();
            }
        }
        let left = || {
            std::fs::read_dir(dir.path()).unwrap().any(|entry| {
                let bytes = std::fs::read(entry.unwrap().path()).unwrap();
                bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
            })
        };
        // A reader holds up the checkpoint, so the next open completes it.
        let reader = rusqlite::Connection::open(&path).unwrap();
        reader
            .execute_batch("BEGIN; SELECT count(*) FROM sqlite_master;")
            .unwrap();
        drop(MetadataCache::new(&path).unwrap());
        assert!(left(), "the reader's snapshot kept the pages");
        drop(reader);
        // Concurrent opens both complete the pending checkpoint.
        let opens: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || MetadataCache::new(&path).map(drop))
            })
            .collect();
        for open in opens {
            open.join().unwrap().unwrap();
        }
        let cache = MetadataCache::new(&path).unwrap();
        cache
            .insert_with_ttl(
                CacheTable::Miss,
                "scope",
                "g/a/1/a-1.pom",
                b"404",
                3600,
                true,
            )
            .unwrap();
        assert!(!left(), "an unkeyed digest is left");
        let conn = rusqlite::Connection::open(&path).unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE '%v2' OR name = 'unkeyed_misses_dropped'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
    }

    #[test]
    fn concurrent_opens_share_one_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let opens: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || MetadataCache::new(&path).unwrap())
            })
            .collect();
        let caches: Vec<_> = opens.into_iter().map(|t| t.join().unwrap()).collect();
        let (scope, pom) = ("https://repo.example/", "g/a/1.0/a-1.0.pom");
        caches[0]
            .insert_with_ttl(CacheTable::Pom, scope, pom, b"<pom/>", 3600, true)
            .unwrap();
        let entry = caches[1].get(CacheTable::Pom, scope, pom).unwrap().unwrap();
        assert_eq!(entry.content, b"<pom/>");
        assert!(entry.checksum_checked);
        assert!(
            caches[1]
                .get(CacheTable::VersionList, scope, pom)
                .unwrap()
                .is_none()
        );
    }
}
