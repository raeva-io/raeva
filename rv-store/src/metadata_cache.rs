//! The repository metadata cache: fetched POMs and version lists, each row
//! keyed by a caller-chosen scope and repository path and carrying an
//! expiry time and whether the content was checked against a checksum
//! file, and when each project's SNAPSHOT builds were last checked. It
//! lives in its own database (`metadata.db`), apart from the store index,
//! because it is disposable: deleting it costs only refetches. A scope is
//! kept as [`rv_config::stored_urls`] names its URLs, so the file holds no
//! token a mirror URL takes.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
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
    generation: 2,
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
    let mut file = rv_fs::open_lock_file(lock_path).map_err(|err| {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Each generation of a table holds rows whose `expires_at` means what
    /// this raeva reads it as. 0.6 decides `daily` when it reads, so it reads
    /// none of the rows 0.5.3 kept, which fixed a `daily` expiry in the zone
    /// that fetched.
    fn name(self) -> &'static str {
        match self {
            CacheTable::Pom => "pom_cache_v5",
            CacheTable::VersionList => "version_list_cache_v4",
            CacheTable::Miss => "miss_cache_v4",
        }
    }
}

/// How long a row stays fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// This many seconds after it is written.
    After(i64),
    /// Until Maven's `daily` policy is due, decided when the row is read
    /// and in the zone of the run that reads it ([`crate::daily`]).
    Daily,
}

impl Expiry {
    /// A row that never expires.
    pub const NEVER: Self = Self::After(i64::MAX);
}

/// The `expires_at` an [`Expiry::Daily`] row is written with. Any
/// `expires_at` below 0 marks a `daily` row, so one moved with its
/// `fetched_at` still is one; and below every `now`, so a raeva that does
/// not know it, as 0.5.3, takes the row for expired.
pub const DAILY: i64 = -1;

/// When the cached rows a resolution took fall due.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowsDue {
    /// The earliest `expires_at` of those that expire at a fixed instant.
    pub expire_at: Option<i64>,
    /// The earliest `fetched_at` of the `daily` ones, which fall due by the
    /// zone that asks.
    pub daily_from: Option<i64>,
}

impl RowsDue {
    /// Count a row written at `fetched_at` that expires at `expires_at`.
    pub fn note(&mut self, fetched_at: i64, expires_at: i64) {
        let earliest = |at: Option<i64>, other: i64| Some(at.map_or(other, |at| at.min(other)));
        match expires_at {
            ..0 => self.daily_from = earliest(self.daily_from, fetched_at),
            i64::MAX => {}
            expires_at => self.expire_at = earliest(self.expire_at, expires_at),
        }
    }

    /// Whether one of the rows is stale at `now`, as
    /// [`MetadataCache::is_stale`] decides it.
    pub fn due(&self, now: i64) -> bool {
        self.expire_at.is_some_and(|at| at <= now)
            || (self.daily_from).is_some_and(|at| crate::daily::due(at, now))
    }
}

/// A platform's last check for newer SNAPSHOT builds, as
/// [`MetadataCache::record_snapshot_check`] recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotCheck {
    /// When the resolution that checked began, in Unix seconds.
    pub checked_at: i64,
    /// When the cached rows its resolutions took instead of asking fall due.
    pub rows: RowsDue,
}

/// One cached row.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CacheEntry {
    /// The cached bytes, as fetched.
    pub content: Vec<u8>,
    /// Unix time in seconds after which the row is stale, or below 0 for a
    /// `daily` row ([`DAILY`]).
    pub expires_at: i64,
    /// Whether the writer checked `content` against the repository's
    /// checksum file. False when there was none and the writer accepted the
    /// content anyway.
    pub checksum_checked: bool,
    /// Unix time in seconds the row was written.
    pub fetched_at: i64,
    /// The SHA-256 of `content`, which matched the one written with it.
    pub sha256: rv_maven_types::Sha256,
    /// When this process last wrote the row; `None` when it did not, or
    /// when the row no longer holds the bytes it wrote.
    pub written_here: Option<Instant>,
}

impl CacheEntry {
    /// Whether this process wrote the row at or after `start`.
    pub fn written_since(&self, start: Instant) -> bool {
        self.written_here.is_some_and(|at| at >= start)
    }
}

/// When this process last wrote each row, and the SHA-256 of what it wrote,
/// by table, scope and path. Another process can replace a row's bytes
/// after this one wrote them, and the replacement is not this run's fetch.
type Writes = Mutex<HashMap<(CacheTable, String, String), (Instant, rv_maven_types::Sha256)>>;

/// The [`Writes`] of each cache file, shared by every handle on it, so one
/// opened after another dropped still has them. `fetched_at` counts whole
/// seconds, so it cannot tell a row this run wrote from one an earlier
/// command wrote in the same second.
static WRITES: OnceLock<Mutex<HashMap<PathBuf, Arc<Writes>>>> = OnceLock::new();

/// A handle on `metadata.db`. Clones share one connection pool.
#[derive(Clone)]
pub struct MetadataCache {
    pool: Arc<crate::sqlite::Db>,
    // WAL permits concurrent readers, but only one writer. Queue writes before
    // taking a pooled connection so our own clones do not exhaust the busy
    // timeout (or occupy every connection while waiting for the writer).
    writer: Arc<Mutex<()>>,
    key: Option<[u8; KEY_LEN]>,
    writes: Arc<Writes>,
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
    // A link or FIFO planted in a restored cache is replaced, not read: a
    // link to a known file would choose the key.
    let read = crate::store::open_unfollowed_regular(path).and_then(|file| {
        let mut bytes = Vec::new();
        if let Some(file) = file {
            file.take(KEY_LEN as u64 + 1).read_to_end(&mut bytes)?;
        }
        Ok(bytes)
    });
    match read {
        Ok(bytes) if bytes.len() == KEY_LEN => {
            key.copy_from_slice(&bytes);
            return Some(key);
        }
        Ok(_) => {}
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

        let pool = crate::sqlite::open(path, CACHE)?;
        let bootstrap_lock = bootstrap_lock(path).map_err(CacheError::Io)?;
        let key = load_or_create_key(&path.with_file_name("cache-key"));
        drop(bootstrap_lock);
        let writes = (WRITES.get_or_init(Mutex::default).lock())
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(crate::sqlite::file_key(path))
            .or_default()
            .clone();

        Ok(Self {
            pool,
            writer: Arc::new(Mutex::new(())),
            key,
            writes,
        })
    }

    /// When this process last wrote the row of `path` in the stored `scope`,
    /// if what it wrote has the SHA-256 `sha256`, the one the row holds.
    fn written_here(
        &self,
        table: CacheTable,
        scope: &str,
        path: &str,
        sha256: &str,
    ) -> Option<Instant> {
        let writes = (self.writes.lock()).unwrap_or_else(std::sync::PoisonError::into_inner);
        let (at, wrote) = writes.get(&(table, scope.to_string(), path.to_string()))?;
        (wrote.as_str() == sha256).then_some(*at)
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
        let scope = rv_config::stored_urls(scope);
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
                written_here: self.written_here(table, &scope, path, sha256.as_str()),
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

    /// Every row of `table` as `(scope, path, entry)`, leaving out a row whose
    /// bytes no longer match the digest written with them.
    pub fn rows(&self, table: CacheTable) -> Result<Vec<(String, String, CacheEntry)>> {
        let sql = format!(
            "SELECT repo_url, path, content, expires_at, checksum_checked, fetched_at, sha256
             FROM {} ORDER BY repo_url, path",
            table.name()
        );
        let db = |source| CacheError::Db {
            ctx: "failed to read metadata cache entries".to_string(),
            source: Box::new(source),
        };
        let rows = self.pool.run(|conn| {
            let mut statement = conn.prepare(&sql).map_err(db)?;
            let rows = (statement.query_map([], |row| {
                let written = row.get_ref(6)?.as_bytes().ok().map(<[u8]>::to_vec);
                let row: (String, String, Vec<u8>, i64, i64, i64, _) = (
                    row.get(0)?,
                    row.get(1)?,
                    row.get_ref(2)?.as_bytes()?.to_vec(),
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    written,
                );
                Ok(row)
            }))
            .map_err(db)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)
        })?;
        Ok((rows.into_iter())
            .filter_map(
                |(scope, path, content, expires_at, checked, fetched_at, written)| {
                    let sha256 = rv_maven_types::Sha256::from_bytes(&content);
                    let written_here = self.written_here(table, &scope, &path, sha256.as_str());
                    let scope = rv_config::restored_urls(&scope).into_owned();
                    (written.as_deref() == Some(sha256.as_str().as_bytes())).then(|| {
                        let entry = CacheEntry {
                            content,
                            expires_at,
                            checksum_checked: checked != 0,
                            fetched_at,
                            sha256,
                            written_here,
                        };
                        (scope, path, entry)
                    })
                },
            )
            .collect())
    }

    /// Whether `table` has a row for each `(scope, path, pin, renewed)` that
    /// holds the bytes `pin` names, was written with them by this process at
    /// or after `renewed` when given, and is not stale at `now` ([`Self::is_stale`]) when given, in
    /// one read, or, with `other`, holds any other bytes. The digest written
    /// with the row stands for its bytes, which a read that returns them
    /// hashes again.
    pub fn holds(
        &self,
        table: CacheTable,
        keys: &[(String, String, rv_maven_types::Sha256, Option<Instant>)],
        now: Option<i64>,
        other: bool,
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
                    let scope = rv_config::stored_urls(scope);
                    let held = |row: &rusqlite::Row<'_>| {
                        let (expires_at, fetched_at): (i64, i64) = (row.get(1)?, row.get(2)?);
                        let sha256 = row.get_ref(0)?.as_str()?;
                        let pinned = sha256 == pin.as_str();
                        let renewed = renewed.is_none_or(|start| {
                            (self.written_here(table, &scope, path, sha256))
                                .is_some_and(|at| at >= start)
                        });
                        Ok((other && !pinned)
                            || (pinned
                                && now.is_none_or(|now| {
                                    !Self::is_stale(fetched_at, expires_at, now)
                                })
                                && renewed))
                    };
                    let held = statement.query_row(params![scope, path], held).optional();
                    Ok(held.map_err(db)? == Some(true))
                })
                .collect()
        })
    }

    /// Write the row for `path` in `scope`, fetched now, expiring as
    /// `expiry` says. `checksum_checked` records whether `content` was
    /// checked against the repository's checksum file.
    pub fn insert(
        &self,
        table: CacheTable,
        scope: &str,
        path: &str,
        content: &[u8],
        expiry: Expiry,
        checksum_checked: bool,
    ) -> Result<()> {
        let now = now_epoch_seconds();
        self.insert_fetched_at(table, scope, path, content, expiry, now, checksum_checked)
    }

    /// [`Self::insert`] for a row fetched at `fetched_at`, as a seed keeps
    /// it: a `daily` row is due by when it was fetched.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_fetched_at(
        &self,
        table: CacheTable,
        scope: &str,
        path: &str,
        content: &[u8],
        expiry: Expiry,
        fetched_at: i64,
        checksum_checked: bool,
    ) -> Result<()> {
        let sha256 = rv_maven_types::Sha256::from_bytes(content);
        let scope = rv_config::stored_urls(scope);
        let _writer = crate::store::lock(&self.writer);
        let expires_at = match expiry {
            Expiry::After(secs) => fetched_at.saturating_add(secs).max(0),
            Expiry::Daily => DAILY,
        };
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
        (self.writes.lock())
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                (table, scope.into_owned(), path.to_string()),
                (Instant::now(), sha256),
            );
        Ok(())
    }

    /// When a sync of the project `project` last asked its repositories for
    /// newer SNAPSHOT builds of `platform`, as [`Self::record_snapshot_check`]
    /// recorded it.
    pub fn snapshot_check(&self, project: &str, platform: &str) -> Result<Option<SnapshotCheck>> {
        self.pool.run(|conn| {
            conn.prepare_cached(
                "SELECT checked_at, checked_at + rows_stale_in, checked_at - daily_rows_age
                 FROM snapshot_checks_v3 WHERE project = ?1 AND platform = ?2",
            )
            .and_then(|mut statement| {
                statement.query_row(params![project, platform], |row| {
                    Ok(SnapshotCheck {
                        checked_at: row.get(0)?,
                        rows: RowsDue {
                            expire_at: row.get(1)?,
                            daily_from: row.get(2)?,
                        },
                    })
                })
            })
            .optional()
            .map_err(|source| CacheError::Db {
                ctx: "failed to read when SNAPSHOT builds were last checked".to_string(),
                source: Box::new(source),
            })
        })
    }

    /// Record that a sync of the project `project` asked its repositories
    /// for newer SNAPSHOT builds of each of `checked` at `started`, in Unix
    /// seconds, taking `rows` from the cache. For each of `others`, whose
    /// builds it did not ask for, `rows` only make the last check due
    /// sooner. The rows are kept as seconds from the check, so moving
    /// `checked_at` moves them.
    pub fn record_snapshot_check(
        &self,
        project: &str,
        checked: &[String],
        others: &[String],
        started: i64,
        rows: RowsDue,
    ) -> Result<()> {
        let _writer = crate::store::lock(&self.writer);
        self.pool.write(|conn| {
            let mut statement = conn
                .prepare_cached(
                    "INSERT INTO snapshot_checks_v3
                     (project, platform, checked_at, rows_stale_in, daily_rows_age)
                     VALUES (?1, ?2, ?3, ?4 - ?3, ?3 - ?5)
                     ON CONFLICT(project, platform) DO UPDATE SET
                     checked_at = excluded.checked_at,
                     rows_stale_in = excluded.rows_stale_in,
                     daily_rows_age = excluded.daily_rows_age",
                )
                .map_err(record_error)?;
            for platform in checked {
                (statement.execute(params![
                    project,
                    platform,
                    started,
                    rows.expire_at,
                    rows.daily_from
                ]))
                .map_err(record_error)?;
            }
            let mut statement = conn
                .prepare_cached(
                    "UPDATE snapshot_checks_v3 SET
                     rows_stale_in = CASE WHEN ?3 IS NOT NULL
                         AND (rows_stale_in IS NULL OR checked_at + rows_stale_in > ?3)
                         THEN ?3 - checked_at ELSE rows_stale_in END,
                     daily_rows_age = CASE WHEN ?4 IS NOT NULL
                         AND (daily_rows_age IS NULL OR checked_at - daily_rows_age > ?4)
                         THEN checked_at - ?4 ELSE daily_rows_age END
                     WHERE project = ?1 AND platform = ?2",
                )
                .map_err(record_error)?;
            for platform in others {
                (statement.execute(params![project, platform, rows.expire_at, rows.daily_from]))
                    .map_err(record_error)?;
            }
            Ok(())
        })
    }

    /// The SHA-256 of the raeva.lock of the project `project` that a sync
    /// last wrote or checked, with the platforms it covered, as
    /// [`Self::record_checked_lock`] recorded them.
    pub fn checked_lock(&self, project: &str) -> Result<Option<(String, String)>> {
        self.pool.run(|conn| {
            conn.prepare_cached("SELECT sha256, platforms FROM checked_locks WHERE project = ?1")
                .and_then(|mut statement| {
                    statement.query_row(params![project], |row| Ok((row.get(0)?, row.get(1)?)))
                })
                .optional()
                .map_err(|source| CacheError::Db {
                    ctx: "failed to read which raeva.lock was last checked".to_string(),
                    source: Box::new(source),
                })
        })
    }

    /// Record that a sync of the project `project` wrote or checked the
    /// raeva.lock whose SHA-256 is `sha256` for `platforms`.
    pub fn record_checked_lock(&self, project: &str, sha256: &str, platforms: &str) -> Result<()> {
        let _writer = crate::store::lock(&self.writer);
        self.pool.write(|conn| {
            conn.execute(
                "INSERT INTO checked_locks (project, sha256, platforms) VALUES (?1, ?2, ?3)
                 ON CONFLICT(project) DO UPDATE SET sha256 = excluded.sha256,
                 platforms = excluded.platforms",
                params![project, sha256, platforms],
            )
            .map(|_| ())
            .map_err(|source| CacheError::Db {
                ctx: "failed to record a check of raeva.lock".to_string(),
                source: Box::new(source),
            })
        })
    }

    /// Whether a row written at `fetched_at` that expires at `expires_at`
    /// is stale at `now`: a `daily` row ([`DAILY`]) once Maven's `daily` policy is due
    /// in this run's zone. A row dated after `now`, as a clock that ran ahead
    /// or a cache copied from one leaves it, is stale too: its expiry would
    /// keep it fresh for as long as that clock was ahead, and `--update`
    /// would take it for a row written during the run.
    pub fn is_stale(fetched_at: i64, expires_at: i64, now: i64) -> bool {
        fetched_at > now
            || match expires_at {
                ..0 => crate::daily::due(fetched_at, now),
                expires_at => expires_at <= now,
            }
    }
}

fn record_error(source: rusqlite::Error) -> CacheError {
    CacheError::Db {
        ctx: "failed to record a SNAPSHOT check".to_string(),
        source: Box::new(source),
    }
}

fn init_schema(conn: &Connection) -> crate::error::Result<()> {
    let path = Path::new(conn.path().unwrap_or_default());
    let tx = crate::sqlite::write_transaction(conn, path, CACHE.generation)?;
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
        tx.execute_batch(&sql)
            .db_context(|| "failed to initialize metadata cache database")?;
    }
    // An older raeva neither reads nor writes these tables, so they need
    // no new generation. A check record counts until the rows it took fall
    // due, so it goes with the tables that hold them.
    tx.execute_batch(
        "DROP TABLE IF EXISTS snapshot_checks;
         DROP TABLE IF EXISTS snapshot_checks_v2;
         CREATE TABLE IF NOT EXISTS snapshot_checks_v3 (
            project        TEXT NOT NULL,
            platform       TEXT NOT NULL,
            checked_at     INTEGER NOT NULL,
            rows_stale_in  INTEGER,
            daily_rows_age INTEGER,
            PRIMARY KEY (project, platform)
         );
         CREATE TABLE IF NOT EXISTS checked_locks (
            project   TEXT PRIMARY KEY,
            sha256    TEXT NOT NULL,
            platforms TEXT NOT NULL
         )",
    )
    .db_context(|| "failed to initialize metadata cache database")?;
    let generation: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .db_context(|| "failed to read the database generation")?;
    if generation < CACHE.generation {
        tx.pragma_update(None, "user_version", CACHE.generation)
            .db_context(|| "failed to write the database generation")?;
    }
    tx.commit()
        .db_context(|| "failed to initialize metadata cache database")?;
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
    use std::time::{Duration, Instant};

    use rusqlite::params;

    use super::{
        CacheTable, Expiry, KeyedDigest, MetadataCache, RowsDue, SnapshotCheck,
        acquire_bootstrap_lock,
    };

    fn digest(cache: &MetadataCache, secret: &[u8]) -> String {
        let mut digest = cache.keyed_digest().unwrap();
        digest.update(secret);
        digest.finalize_hex()
    }

    /// A SNAPSHOT check is kept per project and platform, and a later one
    /// replaces it.
    #[test]
    fn snapshot_checks_are_kept_per_project_and_platform() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MetadataCache::new(&dir.path().join("metadata.db")).unwrap();
        let platforms = ["linux-x86_64".to_string(), "macos-aarch64".to_string()];
        let none = RowsDue::default();
        cache
            .record_snapshot_check("/a", &platforms, &[], 10, none)
            .unwrap();
        cache
            .record_snapshot_check("/a", &platforms[..1], &[], 20, none)
            .unwrap();
        let checked = |project, platform| {
            (cache.snapshot_check(project, platform).unwrap()).map(|check| check.checked_at)
        };
        assert_eq!(checked("/a", "linux-x86_64"), Some(20));
        assert_eq!(checked("/a", "macos-aarch64"), Some(10));
        assert_eq!(checked("/b", "linux-x86_64"), None);
    }

    /// A check keeps when the cached rows its resolution took fall due; a
    /// later resolution that checked nothing only makes them sooner, and
    /// one that checked replaces them.
    #[test]
    fn a_snapshot_check_keeps_when_its_cached_rows_fall_due() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MetadataCache::new(&dir.path().join("metadata.db")).unwrap();
        let platform = ["linux-x86_64".to_string()];
        let rows = |expire_at, daily_from| RowsDue {
            expire_at,
            daily_from,
        };
        let check = || cache.snapshot_check("/a", "linux-x86_64").unwrap().unwrap();
        (cache.record_snapshot_check("/a", &platform, &[], 100, rows(Some(500), None))).unwrap();
        assert_eq!(check().rows, rows(Some(500), None));
        (cache.record_snapshot_check("/a", &[], &platform, 200, rows(Some(300), Some(50))))
            .unwrap();
        (cache.record_snapshot_check("/a", &[], &platform, 250, rows(Some(400), Some(80))))
            .unwrap();
        assert_eq!(check().checked_at, 100);
        assert_eq!(check().rows, rows(Some(300), Some(50)));
        (cache.record_snapshot_check("/a", &platform, &[], 600, rows(None, None))).unwrap();
        assert_eq!(
            check(),
            SnapshotCheck {
                checked_at: 600,
                rows: rows(None, None)
            }
        );

        let mut due = RowsDue::default();
        due.note(10, i64::MAX);
        assert_eq!(due, RowsDue::default());
        due.note(10, 70);
        due.note(20, 60);
        due.note(30, super::DAILY);
        due.note(40, super::DAILY - 5);
        assert_eq!(due, rows(Some(60), Some(30)));
        assert!(!due.due(59) && due.due(60));
    }

    /// A `daily` row is due by the zone of the run that reads it, not of the
    /// one that wrote it: fetched at 22:30 UTC on 2025-11-23 by a run in
    /// UTC, it is fresh at 23:30 UTC there, and due then in Oslo, where the
    /// next day began at 23:00 UTC.
    #[cfg(unix)]
    #[test]
    fn a_daily_row_is_due_by_the_zone_that_reads_it() {
        const DB: &str = "RV_TEST_DAILY_ROW_DB";
        let (fetched, now) = (1_763_937_000, 1_763_940_600);
        let path = "g/a/1-SNAPSHOT/maven-metadata.xml";
        if let Ok(db) = std::env::var(DB) {
            let cache = MetadataCache::new(std::path::Path::new(&db)).unwrap();
            let zone = std::env::var("TZ").unwrap();
            if zone == "UTC" {
                let content = b"<metadata/>";
                (cache.insert_fetched_at(
                    CacheTable::VersionList,
                    "s",
                    path,
                    content,
                    Expiry::Daily,
                    fetched,
                    true,
                ))
                .unwrap();
            }
            let entry = cache
                .get(CacheTable::VersionList, "s", path)
                .unwrap()
                .unwrap();
            let stale = MetadataCache::is_stale(entry.fetched_at, entry.expires_at, now);
            assert_eq!(stale, zone == "Europe/Oslo", "{zone}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        for zone in ["UTC", "Europe/Oslo"] {
            let run = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "metadata_cache::tests::a_daily_row_is_due_by_the_zone_that_reads_it",
                ])
                .env(DB, dir.path().join("metadata.db"))
                .env("TZ", zone)
                .output()
                .unwrap();
            let said = String::from_utf8_lossy(&run.stdout);
            assert!(
                run.status.success() && said.contains("1 passed"),
                "{zone}: {said}"
            );
        }
    }

    /// A row 0.5.3 wrote, in its own table, is never read: its `daily`
    /// expiry was fixed in the zone of the run that fetched it.
    #[test]
    fn a_row_of_0_5_3_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let old = rusqlite::Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE version_list_cache_v3 (repo_url TEXT NOT NULL, path TEXT NOT NULL,
             sha256 TEXT NOT NULL, fetched_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
             checksum_checked INTEGER NOT NULL, content BLOB NOT NULL,
             PRIMARY KEY (repo_url, path))",
        )
        .unwrap();
        let content = b"<metadata/>";
        let sha256 = rv_maven_types::Sha256::from_bytes(content);
        old.execute(
            "INSERT INTO version_list_cache_v3 VALUES ('s', 'g/a/maven-metadata.xml', ?1,
             unixepoch(), unixepoch() + 3600, 1, ?2)",
            params![sha256.as_str(), &content[..]],
        )
        .unwrap();
        drop(old);
        let cache = MetadataCache::new(&path).unwrap();
        let read = cache.get(CacheTable::VersionList, "s", "g/a/maven-metadata.xml");
        assert!(read.unwrap().is_none());
    }

    /// A SNAPSHOT check record an earlier 0.6 candidate kept counted rows of
    /// the tables before these, so it is dropped, and the check is due.
    #[test]
    fn an_older_snapshot_check_record_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let old = rusqlite::Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE snapshot_checks_v2 (project TEXT NOT NULL, platform TEXT NOT NULL,
             checked_at INTEGER NOT NULL, rows_stale_in INTEGER, daily_rows_age INTEGER,
             PRIMARY KEY (project, platform));
             INSERT INTO snapshot_checks_v2 VALUES ('p', 'linux-x86_64', unixepoch(), 3600, NULL);",
        )
        .unwrap();
        drop(old);
        let cache = MetadataCache::new(&path).unwrap();
        assert!(cache.snapshot_check("p", "linux-x86_64").unwrap().is_none());
        let db = rusqlite::Connection::open(&path).unwrap();
        let left: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'snapshot_checks_v2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn a_checked_lock_is_kept_per_project() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MetadataCache::new(&dir.path().join("metadata.db")).unwrap();
        cache
            .record_checked_lock("/a", "aa", "linux-x86_64")
            .unwrap();
        cache
            .record_checked_lock("/a", "bb", "macos-aarch64")
            .unwrap();
        let checked = |project| cache.checked_lock(project).unwrap();
        assert_eq!(
            checked("/a"),
            Some(("bb".to_string(), "macos-aarch64".to_string()))
        );
        assert_eq!(checked("/b"), None);
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
            .insert(
                CacheTable::Miss,
                &first,
                "g/a/1/a-1.pom",
                b"404",
                Expiry::After(3600),
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

    /// A bootstrap lock that is a link, as a poisoned cache restore can
    /// plant, is refused and creates nothing where it points.
    #[cfg(unix)]
    #[test]
    fn a_bootstrap_lock_that_is_a_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::os::unix::fs::symlink(&victim, dir.path().join("metadata.db.lock")).unwrap();
        let err = MetadataCache::new(&dir.path().join("metadata.db")).err();
        assert!(format!("{err:?}").contains("symbolic link"), "{err:?}");
        assert!(!victim.exists());
    }

    /// A `cache-key` that is a link is not read, so a planted link to a
    /// known file does not choose the key, and the new key replaces the
    /// link, not the file it names. One that is a FIFO does not wait for a
    /// writer.
    #[cfg(unix)]
    #[test]
    fn a_cache_key_that_is_not_a_regular_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let key_path = dir.path().join("cache-key");
        let known = dir.path().join("known");
        std::fs::write(&known, [0u8; 32]).unwrap();
        std::os::unix::fs::symlink(&known, &key_path).unwrap();
        let linked = digest(&MetadataCache::new(&path).unwrap(), b"token");
        let mut zeros = KeyedDigest::new(&[0u8; 32]);
        zeros.update(b"token");
        assert_ne!(linked, zeros.finalize_hex());
        assert_eq!(std::fs::read(&known).unwrap(), [0u8; 32]);
        let meta = std::fs::symlink_metadata(&key_path).unwrap();
        assert!(meta.is_file());
        assert_eq!(
            digest(&MetadataCache::new(&path).unwrap(), b"token"),
            linked
        );

        std::fs::remove_file(&key_path).unwrap();
        let made = std::process::Command::new("mkfifo").arg(&key_path).status();
        assert!(made.unwrap().success());
        let (sent, opened) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sent.send(MetadataCache::new(&path).map(|_| ()).is_ok());
        });
        let opened = opened.recv_timeout(Duration::from_secs(20));
        assert_eq!(opened, Ok(true), "opening beside a FIFO key hangs");
        assert!(std::fs::symlink_metadata(&key_path).unwrap().is_file());
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
    /// instead of failing every later run, wherever the file was cut: at a
    /// page boundary, or inside a page, which SQLite reads as a short read.
    #[test]
    fn open_replaces_a_damaged_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, content) = ("https://repo.example/", [b'x'; 4096]);
        for n in 0..40 {
            let pom = format!("g/a/{n}/a-{n}.pom");
            cache
                .insert(
                    CacheTable::Pom,
                    scope,
                    &pom,
                    &content,
                    Expiry::After(3600),
                    true,
                )
                .unwrap();
        }
        drop(cache);
        let whole = std::fs::read(&path).unwrap();
        let cuts = (1..whole.len() / 4096)
            .flat_map(|page| [page * 4096 - 1, page * 4096, page * 4096 + 2048].into_iter());
        let damage = cuts
            .map(|cut| whole[..cut].to_vec())
            .chain([vec![7u8; 8192]]);
        for damaged in damage {
            std::fs::write(&path, &damaged).unwrap();
            let len = damaged.len();
            let cache = MetadataCache::new(&path).unwrap_or_else(|err| panic!("{len}: {err}"));
            let read = || -> super::Result<()> {
                cache.insert(
                    CacheTable::Pom,
                    scope,
                    "g/b/1/b-1.pom",
                    b"<pom/>",
                    Expiry::After(3600),
                    true,
                )?;
                assert!(
                    cache
                        .get(CacheTable::Pom, scope, "g/b/1/b-1.pom")?
                        .is_some()
                );
                cache.rows(CacheTable::Pom)?;
                Ok(())
            };
            read().unwrap_or_else(|err| panic!("{len}: {err}"));
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
            .insert(
                CacheTable::Pom,
                scope,
                pom,
                b"<pom/>",
                Expiry::After(3600),
                true,
            )
            .unwrap();
        drop(cache);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", super::CACHE.generation + 1)
            .unwrap();
        drop(conn);
        let err = MetadataCache::new(&path).err().unwrap();
        assert!(
            err.to_string().contains("written by a newer raeva"),
            "{err}"
        );
        let conn = rusqlite::Connection::open(&path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM pom_cache_v5", [], |row| row.get(0))
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
            .insert(
                CacheTable::Pom,
                scope,
                pom,
                b"<pom/>",
                Expiry::After(3600),
                true,
            )
            .unwrap();
        let peer = rusqlite::Connection::open(&path).unwrap();
        peer.execute("UPDATE pom_cache_v5 SET content = x'00'", [])
            .unwrap();
        peer.pragma_update(None, "user_version", super::CACHE.generation + 1)
            .unwrap();
        let version = || -> i64 {
            peer.pragma_query_value(None, "data_version", |row| row.get(0))
                .unwrap()
        };
        let before = version();
        let errors = [
            cache
                .insert(
                    CacheTable::Pom,
                    scope,
                    "g/b/1/b-1.pom",
                    b"<pom/>",
                    Expiry::After(3600),
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
                .insert(
                    CacheTable::Pom,
                    scope,
                    &pom,
                    &content,
                    Expiry::After(3600),
                    true,
                )
                .unwrap();
        }
        drop(cache);
        crate::sqlite::damage_past_schema(&path);
        let cache = MetadataCache::new(&path).unwrap();
        let pom = "g/a/7/a-7.pom";
        assert!(cache.get(CacheTable::Pom, scope, pom).unwrap().is_none());
        cache
            .insert(
                CacheTable::Pom,
                scope,
                pom,
                b"<pom/>",
                Expiry::After(3600),
                true,
            )
            .unwrap();
        assert!(cache.get(CacheTable::Pom, scope, pom).unwrap().is_some());
    }

    /// A row counts as written by a run only when this process wrote it
    /// since the run started, as `fetched_at`, in whole seconds, cannot
    /// tell: one another process wrote in the same second does not, nor
    /// does one this process wrote before, and a second handle on the file
    /// sees what the first wrote.
    #[test]
    fn only_this_process_writes_a_row_for_a_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, ours, theirs) = ("https://repo.example/", "g/a/1/a-1.pom", "g/a/2/a-2.pom");
        let earlier = Instant::now();
        cache
            .insert(
                CacheTable::Pom,
                scope,
                ours,
                b"<pom/>",
                Expiry::After(3600),
                true,
            )
            .unwrap();
        let start = Instant::now();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO pom_cache_v5
                 (repo_url, path, content, sha256, fetched_at, expires_at, checksum_checked)
                 VALUES (?1, ?2, ?3, ?4, unixepoch(), unixepoch() + 3600, 1)",
                params![
                    scope,
                    theirs,
                    &b"<pom/>"[..],
                    rv_maven_types::Sha256::from_bytes(b"<pom/>").as_str()
                ],
            )
            .unwrap();
        let other = MetadataCache::new(&path).unwrap();
        let get = |path| other.get(CacheTable::Pom, scope, path).unwrap().unwrap();
        assert!(get(ours).written_since(earlier) && !get(ours).written_since(start));
        assert!(get(theirs).written_here.is_none());
        let pin = rv_maven_types::Sha256::from_bytes(b"<pom/>");
        let holds = |path: &str, renewed| {
            let key = (scope.to_string(), path.to_string(), pin.clone(), renewed);
            other.holds(CacheTable::Pom, &[key], None, false).unwrap()[0]
        };
        assert!(holds(ours, Some(earlier)) && !holds(ours, Some(start)));
        assert!(holds(theirs, None) && !holds(theirs, Some(earlier)));
    }

    /// A row this process wrote that another process then replaced with
    /// other bytes is not this run's: neither a read nor `holds` takes it for
    /// one, while the row holds the replacement.
    #[test]
    fn a_row_another_process_replaced_is_not_this_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, pom) = ("https://repo.example/", "g/a/1-SNAPSHOT/a-1-SNAPSHOT.pom");
        let (ours, theirs) = (&b"<pom>2</pom>"[..], &b"<pom>1</pom>"[..]);
        let start = Instant::now();
        cache
            .insert(CacheTable::Pom, scope, pom, ours, Expiry::After(3600), true)
            .unwrap();
        let replace = |content: &[u8]| {
            rusqlite::Connection::open(&path)
                .unwrap()
                .execute(
                    "UPDATE pom_cache_v5 SET content = ?1, sha256 = ?2 WHERE path = ?3",
                    params![
                        content,
                        rv_maven_types::Sha256::from_bytes(content).as_str(),
                        pom
                    ],
                )
                .unwrap();
        };
        let ours_now = || {
            let entry = cache.get(CacheTable::Pom, scope, pom).unwrap().unwrap();
            let holds = |content: &[u8]| {
                let pin = rv_maven_types::Sha256::from_bytes(content);
                let key = (scope.to_string(), pom.to_string(), pin, Some(start));
                cache.holds(CacheTable::Pom, &[key], None, false).unwrap()[0]
            };
            (entry.written_since(start), holds(ours), holds(theirs))
        };
        assert_eq!(ours_now(), (true, true, false));
        replace(theirs);
        assert_eq!(ours_now(), (false, false, false));
        let entry = cache.get(CacheTable::Pom, scope, pom).unwrap().unwrap();
        assert!(entry.written_here.is_none() && entry.content == theirs);
        replace(ours);
        assert_eq!(ours_now(), (true, true, false));
    }

    /// A row dated in the future is stale, under `--update` too, where it
    /// would otherwise pass for a row written during the run.
    #[test]
    fn a_row_dated_in_the_future_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.db");
        let cache = MetadataCache::new(&path).unwrap();
        let (scope, pom) = ("https://repo.example/", "g/a/1/a-1.pom");
        let start = Instant::now();
        cache
            .insert(
                CacheTable::Pom,
                scope,
                pom,
                b"<pom/>",
                Expiry::After(3600),
                true,
            )
            .unwrap();
        let pin = rv_maven_types::Sha256::from_bytes(b"<pom/>");
        let now = cache
            .get(CacheTable::Pom, scope, pom)
            .unwrap()
            .unwrap()
            .fetched_at;
        let holds = |renewed: Option<Instant>| {
            let key = (scope.to_string(), pom.to_string(), pin.clone(), renewed);
            cache
                .holds(CacheTable::Pom, &[key], Some(now), false)
                .unwrap()[0]
        };
        assert!(holds(None) && holds(Some(start)));
        // Other bytes hold only when asked.
        let other = rv_maven_types::Sha256::from_bytes(b"other");
        let key = (scope.to_string(), pom.to_string(), other, None);
        assert!(
            !cache
                .holds(
                    CacheTable::Pom,
                    std::slice::from_ref(&key),
                    Some(now),
                    false
                )
                .unwrap()[0]
        );
        assert!(
            cache
                .holds(CacheTable::Pom, &[key], Some(now), true)
                .unwrap()[0]
        );
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE pom_cache_v5 SET fetched_at = ?1 + 600", [now])
            .unwrap();
        assert!(!holds(None) && !holds(Some(start)));
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
                    .insert(table, scope, pom, b"<pom/>", Expiry::After(3600), true)
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
            .insert(
                CacheTable::Pom,
                scope,
                pom,
                b"<pom/>",
                Expiry::After(3600),
                true,
            )
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
