//! SQLite setup shared by the store index and rv-repo's metadata cache.
//!
//! Workspace-internal: the signatures expose r2d2 types and carry no stability
//! promise.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

use crate::error::{DbFailure, DbResultExt, IoResultExt, Result, StoreError};

/// How [`open`] sets up one of the databases.
#[derive(Clone, Copy)]
pub(crate) struct Spec {
    /// Run on each new connection. `synchronous` and `busy_timeout` are per
    /// connection, so these must set them again; a connection without
    /// `synchronous=NORMAL` falls back to `FULL`.
    pub(crate) pragmas: &'static str,
    pub(crate) max_size: u32,
    /// The schema's generation, kept as the file's `user_version` once
    /// [`Spec::init`] ran. A file of a later generation was written by a
    /// newer raeva, which this one may misread as damaged: it neither opens
    /// nor recreates it, and a handle open on it writes nothing more (see
    /// [`write_transaction`]). A raeva that changes the schema or the
    /// meaning of its rows in a way an older one cannot read bumps it,
    /// under the bootstrap lock and in a transaction that holds the write
    /// lock, with the change. Raeva 0.5.0 and older never check it, so that
    /// raeva must also keep their writes out of what it reads, as with new
    /// table names.
    pub(crate) generation: i64,
    /// Creates the schema, on open and again after a recreate.
    pub(crate) init: fn(&rusqlite::Connection) -> Result<()>,
    /// Takes the cross-process lock that callers of [`open`] hold, for the
    /// file at the given path.
    pub(crate) lock: fn(&Path) -> Result<Box<dyn std::any::Any>>,
}

/// One open database: a pool of connections that each hold its [`DbUser`].
///
/// A process keeps one per file (see [`open`]), so when an operation finds
/// the file damaged, [`Db::run`] knows every connection this process has to
/// it and can close them all before it recreates the file.
pub(crate) struct Db {
    path: PathBuf,
    spec: Spec,
    state: RwLock<State>,
}

struct State {
    /// `None` once a recreate failed or found the file in use: every later
    /// query fails as on a damaged file.
    pool: Option<Pool<Manager>>,
    /// The lock the pool's connections hold, gone once they all closed.
    user: Weak<DbUser>,
    /// The [`epoch`] of the file the pool opened.
    epoch: u64,
    /// Bumped by each recreate, so an operation that failed on the old file
    /// runs again instead of recreating the new one.
    generation: u64,
    recreated: bool,
}

/// Errors [`Db::run`] can classify and build.
pub(crate) trait DbError: From<StoreError> + std::fmt::Display {
    fn is_corrupt(&self) -> bool;
    fn pool(err: r2d2::Error) -> Self;
}

impl DbError for StoreError {
    fn is_corrupt(&self) -> bool {
        self.db_failure() == Some(DbFailure::Corrupt)
    }

    fn pool(err: r2d2::Error) -> Self {
        StoreError::PoolError(err.to_string())
    }
}

static OPEN: OnceLock<Mutex<HashMap<PathBuf, Weak<Db>>>> = OnceLock::new();

static RECREATED: AtomicU64 = AtomicU64::new(0);

/// How many times this process reopened a database that it or another
/// process recreated after a query found it damaged. Rows written to one
/// before are gone.
pub fn recreated_mid_run() -> u64 {
    RECREATED.load(Ordering::Relaxed)
}

/// The [`Db`] for the file at `path`, which this process shares: an open one
/// if any, else a new one through [`enable_wal`]. Callers hold a
/// cross-process bootstrap lock around this call, which also keeps two
/// threads from opening one file at once.
pub(crate) fn open(path: &Path, spec: Spec) -> Result<Arc<Db>> {
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    let key = match path.file_name() {
        Some(name) => fs::canonicalize(dir.unwrap_or(Path::new(".")))
            .map(|dir| dir.join(name))
            .unwrap_or_else(|_| path.to_path_buf()),
        None => path.to_path_buf(),
    };
    let registry = || {
        OPEN.get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    };
    if let Some(db) = registry().get(&key).and_then(Weak::upgrade) {
        return Ok(db);
    }
    let user = Arc::new(enable_wal(path, spec.generation)?);
    let db = Db {
        path: path.to_path_buf(),
        spec,
        state: RwLock::new(State {
            user: Arc::downgrade(&user),
            epoch: user.epoch,
            pool: Some(wal_pool(path, user, spec)?),
            generation: 0,
            recreated: false,
        }),
    };
    {
        // Creating the schema can read damage the check at open missed.
        let mut state = db.state.write().unwrap_or_else(PoisonError::into_inner);
        if let Err(err) = state
            .checkout(path)
            .and_then(|conn| set_up(&conn, path, spec))
            && !(err.is_corrupt() && state.close() && db.reset(&mut state, &err)?)
        {
            return Err(err);
        }
    }
    let db = Arc::new(db);
    let mut open = registry();
    open.retain(|_, db| db.strong_count() > 0);
    open.insert(key, Arc::downgrade(&db));
    Ok(db)
}

impl Db {
    /// Runs `op` on a connection. If it fails because the file is damaged
    /// or is not SQLite, which the check at open misses for damage past
    /// the schema, the file is recreated as at open and `op` runs once
    /// more on the new one. That happens once per `Db`, and only once no
    /// other process has the file open; otherwise the error is returned.
    ///
    /// No lock that `op` or a recreate takes, such as the store lock, may
    /// be held around a call of `run`, and `op` must not call `run`: a
    /// recreate waits for every running `op`.
    pub(crate) fn run<T, E: DbError>(
        &self,
        op: impl FnMut(&mut rusqlite::Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        self.run_with(false, op)
    }

    /// [`Db::run`] holding the spec's cross-process lock around `op`. The
    /// lock is taken before the connection, so a wait for it holds none.
    pub(crate) fn run_locked<T, E: DbError>(
        &self,
        op: impl FnMut(&mut rusqlite::Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        self.run_with(true, op)
    }

    /// [`Db::run`] for an `op` that writes, in one [`write_transaction`].
    pub(crate) fn write<T, E: DbError>(
        &self,
        mut op: impl FnMut(&rusqlite::Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        self.run(|conn| self.in_write(conn, &mut op))
    }

    /// [`Db::write`] holding the spec's cross-process lock, as
    /// [`Db::run_locked`] does.
    pub(crate) fn write_locked<T, E: DbError>(
        &self,
        mut op: impl FnMut(&rusqlite::Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        self.run_locked(|conn| self.in_write(conn, &mut op))
    }

    fn in_write<T, E: DbError>(
        &self,
        conn: &rusqlite::Connection,
        op: &mut impl FnMut(&rusqlite::Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let tx = write_transaction(conn, &self.path, self.spec.generation)?;
        let value = op(&tx)?;
        tx.commit()
            .db_context(|| format!("failed to commit a write to {}", self.path.display()))?;
        Ok(value)
    }

    fn run_with<T, E: DbError>(
        &self,
        locked: bool,
        mut op: impl FnMut(&mut rusqlite::Connection) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let mut attempt = || -> std::result::Result<_, E> {
            let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
            let _lock = locked.then(|| (self.spec.lock)(&self.path)).transpose()?;
            let mut conn = state.checkout::<E>(&self.path)?;
            Ok((state.generation, op(&mut conn)))
        };
        let (generation, result) = attempt()?;
        match result {
            Err(err) if err.is_corrupt() && self.recreate(generation, &err)? => attempt()?.1,
            result => result,
        }
    }

    /// Whether `op` should run again: the file was recreated, by this
    /// process or another, or another operation reopened it since `seen`.
    fn recreate(&self, seen: u64, err: &dyn std::fmt::Display) -> Result<bool> {
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if state.generation != seen {
            return Ok(true);
        }
        // A peer that found the damage too waits for the bootstrap lock
        // with its connections closed, so this closes them before taking
        // it, or neither is alone. The lock goes between tries, so a peer
        // that holds its connections while it waits for the store lock in
        // `run_locked` can run its query and find the damage.
        if !state.close() {
            return Ok(false);
        }
        let deadline = Instant::now() + PEER_WAIT;
        loop {
            // No operation of this process runs now, and no other process
            // is between the two lock calls in `enable_wal`.
            let bootstrap = (self.spec.lock)(&self.path)?;
            if self.reset(&mut state, err)? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            drop(bootstrap);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Opens the file again if another process recreated it since this one
    /// opened it, else recreates it if no connection to it is open in this
    /// process or another, and creates the schema in it. When neither
    /// happens the file stays closed. The caller holds the write guard and
    /// the bootstrap lock, and closed the pool.
    fn reset(&self, state: &mut State, err: &dyn std::fmt::Display) -> Result<bool> {
        let users_path = sibling(&self.path, ".users");
        let users = open_users(&users_path)?;
        let mut epoch = epoch(&users, &users_path)?;
        if epoch == state.epoch {
            if users.try_lock().is_err() {
                return Ok(false);
            }
            epoch = recreate_files(&self.path, self.spec.generation, &users, err)?;
            users
                .unlock()
                .io_context(|| format!("failed to unlock {}", users_path.display()))?;
        }
        users
            .lock_shared()
            .io_context(|| format!("failed to lock {}", users_path.display()))?;
        let user = Arc::new(DbUser {
            epoch,
            _lock: users,
        });
        state.epoch = epoch;
        state.user = Arc::downgrade(&user);
        // A peer's new file may be a newer raeva's. A pooled connection's
        // pragmas load the schema, which may not parse, so this checks first.
        let conn = rusqlite::Connection::open(&self.path)
            .db_context(|| format!("failed to open {}", self.path.display()))?;
        check_generation(&conn, &self.path, self.spec.generation)?;
        drop(conn);
        state.pool = Some(wal_pool(&self.path, user, self.spec)?);
        set_up(
            &*state.checkout::<StoreError>(&self.path)?,
            &self.path,
            self.spec,
        )?;
        state.generation += 1;
        RECREATED.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }
}

/// How long [`Db::recreate`] waits for the other processes that have the
/// file open to find the damage too and close it.
const PEER_WAIT: Duration = Duration::from_secs(2);

impl State {
    /// Closes the pool, once per `Db`, and whether that released this
    /// process's shared lock: r2d2's worker keeps the old pool for a moment
    /// after handing out a connection it opened, and a connection that
    /// outlives the wait keeps the lock, so no recreate can happen.
    fn close(&mut self) -> bool {
        if std::mem::replace(&mut self.recreated, true) {
            return false;
        }
        drop(self.pool.take());
        let deadline = Instant::now() + Duration::from_secs(1);
        while self.user.strong_count() > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        self.user.strong_count() == 0
    }

    /// A connection, or for `None` an error naming `path`.
    fn checkout<E: DbError>(
        &self,
        path: &Path,
    ) -> std::result::Result<PooledConnection<Manager>, E> {
        let Some(pool) = &self.pool else {
            let corrupt = rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT);
            return Err(E::from(StoreError::DbContext {
                ctx: format!("{} is damaged and was not recreated", path.display()),
                source: rusqlite::Error::SqliteFailure(corrupt, None),
            }));
        };
        pool.get().map_err(E::pool)
    }
}

#[cfg(test)]
impl Db {
    pub(crate) fn conn(&self) -> PooledConnection<Manager> {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        state.checkout::<StoreError>(&self.path).unwrap()
    }
}

fn open_users(path: &Path) -> Result<File> {
    fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .io_context(|| format!("failed to open {}", path.display()))
}

/// Switches the database at `path` to WAL journal mode with
/// `synchronous=NORMAL`, creating the file if absent.
///
/// `journal_mode` is database-scoped and needs SQLite's exclusive lock to
/// change, so this runs on one connection before any pool exists: r2d2
/// opens all its connections in parallel, and if each one flipped the mode
/// the losers would log `database is locked`. Callers hold a cross-process
/// lock around this call so two processes do not race on it either.
///
/// Fails with [`StoreError::WalUnavailable`] when SQLite falls back to
/// another mode, as it does on filesystems that refuse WAL (often NFS or
/// SMB). Running without WAL would drop the concurrency the store and the
/// metadata cache rely on.
///
/// Both databases only speed up later runs, so a file that is damaged or is
/// not SQLite, as a partial CI cache restore leaves, is deleted with its
/// `-wal` and `-shm` files and created anew instead of failing every run.
/// That happens only while no other handle, in this process or another,
/// has the database open: the returned [`DbUser`] marks this one as open,
/// and [`wal_pool`] keeps it until the last connection closes.
fn enable_wal(path: &Path, generation: i64) -> Result<DbUser> {
    let users_path = sibling(path, ".users");
    let users = open_users(&users_path)?;
    let alone = users.try_lock().is_ok();
    match open_wal(path, generation) {
        Err(err) if alone && err.is_corrupt() => {
            recreate_files(path, generation, &users, &err)?;
        }
        result => result?,
    }
    // Callers hold their bootstrap lock, so no other opener can take the
    // exclusive lock between these two calls.
    if alone {
        users
            .unlock()
            .io_context(|| format!("failed to unlock {}", users_path.display()))?;
    }
    users
        .try_lock_shared()
        .map_err(|err| match err {
            fs::TryLockError::Error(err) => err,
            fs::TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
        })
        .io_context(|| format!("failed to lock {}", users_path.display()))?;
    Ok(DbUser {
        epoch: epoch(&users, &users_path)?,
        _lock: users,
    })
}

/// How many times the database beside the `.users` file was recreated, kept
/// in that file, so a process that closed the database to recreate it can
/// tell that another did. Read under the bootstrap lock and written under
/// the exclusive lock, which only a holder of the bootstrap lock takes.
fn epoch(users: &File, path: &Path) -> Result<u64> {
    let mut bytes = [0u8; 8];
    match (&*users)
        .seek(SeekFrom::Start(0))
        .and_then(|_| (&*users).read_exact(&mut bytes))
    {
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
        read => read
            .map(|()| u64::from_le_bytes(bytes))
            .io_context(|| format!("failed to read {}", path.display())),
    }
}

/// Deletes the damaged database at `path` with its `-wal` and `-shm` files,
/// creates it anew, and bumps its [`epoch`], which it returns. The caller
/// holds the exclusive lock on `users`. A file that still names a later
/// generation than `generation` is kept: a newer raeva wrote it.
fn recreate_files(
    path: &Path,
    generation: i64,
    users: &File,
    err: &dyn std::fmt::Display,
) -> Result<u64> {
    if let Ok(conn) = rusqlite::Connection::open(path)
        && let Err(err @ StoreError::NewerDatabase { .. }) =
            check_generation(&conn, path, generation)
    {
        return Err(err);
    }
    for suffix in ["", "-wal", "-shm"] {
        let file = sibling(path, suffix);
        match fs::remove_file(&file) {
            Err(remove) if remove.kind() != io::ErrorKind::NotFound => {
                return Err(remove).io_context(|| {
                    format!("failed to delete the damaged database {}", file.display())
                });
            }
            _ => {}
        }
    }
    tracing::warn!(
        sec_code = "DATABASE_RECREATED",
        path = %path.display(),
        "deleted a damaged database and started a new one: {err}"
    );
    open_wal(path, generation)?;
    // Bumped once the new file is set up, so a peer that sees the new epoch
    // opens that file.
    let users_path = sibling(path, ".users");
    let next = epoch(users, &users_path)?.wrapping_add(1);
    (&*users)
        .seek(SeekFrom::Start(0))
        .and_then(|_| (&*users).write_all(&next.to_le_bytes()))
        .io_context(|| format!("failed to write {}", users_path.display()))?;
    Ok(next)
}

/// A shared lock on the `.users` file next to a database, held by every
/// open handle on it. See [`enable_wal`].
#[derive(Debug)]
pub(crate) struct DbUser {
    _lock: File,
    epoch: u64,
}

/// Opens SQLite connections that hold the [`DbUser`] lock.
pub(crate) struct Manager {
    inner: SqliteConnectionManager,
    user: Arc<DbUser>,
}

/// A connection with the lock that marks its database open.
pub(crate) struct Conn {
    // Dropped first: closes the connection before the lock goes.
    conn: rusqlite::Connection,
    _user: Arc<DbUser>,
}

impl std::ops::Deref for Conn {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl std::ops::DerefMut for Conn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl r2d2::ManageConnection for Manager {
    type Connection = Conn;
    type Error = rusqlite::Error;

    fn connect(&self) -> std::result::Result<Conn, rusqlite::Error> {
        Ok(Conn {
            conn: self.inner.connect()?,
            _user: Arc::clone(&self.user),
        })
    }

    fn is_valid(&self, conn: &mut Conn) -> std::result::Result<(), rusqlite::Error> {
        self.inner.is_valid(&mut conn.conn)
    }

    fn has_broken(&self, conn: &mut Conn) -> bool {
        self.inner.has_broken(&mut conn.conn)
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

/// The generation of the database `conn` has open. Fails with
/// [`StoreError::NewerDatabase`] when it is later than `generation`.
/// Reading it loads no schema, which a newer raeva's may not parse.
fn check_generation(conn: &rusqlite::Connection, path: &Path, generation: i64) -> Result<i64> {
    let found: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .db_context(|| format!("failed to read the generation of {}", path.display()))?;
    if found > generation {
        return Err(StoreError::NewerDatabase {
            path: path.to_path_buf(),
            found,
            supported: generation,
        });
    }
    Ok(found)
}

/// A transaction on `conn` to the database at `path` that holds SQLite's
/// write lock from its start, so a newer raeva cannot stamp the file with
/// its generation before it ends, and that found the file of no later
/// generation than `generation`. Every write goes through one: a newer raeva
/// may keep the tables readable while it gives their rows new meaning.
pub(crate) fn write_transaction<'a>(
    conn: &'a rusqlite::Connection,
    path: &Path,
    generation: i64,
) -> Result<rusqlite::Transaction<'a>> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .db_context(|| format!("failed to begin a write to {}", path.display()))?;
    check_generation(&tx, path, generation)?;
    Ok(tx)
}

/// Whether the database `conn` opens has a table named `name`.
pub(crate) fn has_table(conn: &rusqlite::Connection, name: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )
    .db_context(|| "failed to read the database schema")
}

/// Reports that this raeva upgraded the database at `path` from an older
/// raeva's and dropped `dropped`.
pub(crate) fn warn_upgraded(path: &Path, dropped: &str) {
    tracing::warn!(
        sec_code = "DATABASE_UPGRADED",
        path = %path.display(),
        "upgraded {} from an older raeva and dropped {dropped}; the next resolution fetches \
         what it needs again. raeva 0.5.1 refuses the file now, so give an older raeva its own \
         RAEVA_HOME",
        path.display()
    );
}

/// Runs `spec.init` on `conn` to the database at `path`, then stamps it
/// with the spec's generation, unless a newer raeva's generation is there.
fn set_up(conn: &rusqlite::Connection, path: &Path, spec: Spec) -> Result<()> {
    let found = check_generation(conn, path, spec.generation)?;
    (spec.init)(conn)?;
    if found < spec.generation {
        conn.pragma_update(None, "user_version", spec.generation)
            .db_context(|| "failed to write the database generation")?;
    }
    Ok(())
}

fn open_wal(path: &Path, generation: i64) -> Result<()> {
    // A file that is not SQLite would otherwise wait out the busy timeout.
    // A shorter one is still being created by another process.
    if fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() >= 16) {
        let mut header = [0u8; 16];
        File::open(path)
            .and_then(|mut file| file.read_exact(&mut header))
            .io_context(|| format!("failed to read the header of {}", path.display()))?;
        if &header != b"SQLite format 3\0" {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
                None,
            ))
            .db_context(|| format!("{} has no SQLite header", path.display()));
        }
    }
    let conn = rusqlite::Connection::open(path)
        .db_context(|| format!("failed to open {} for WAL bootstrap", path.display()))?;
    conn.busy_timeout(Duration::from_secs(5))
        .db_context(|| "failed to set busy_timeout on bootstrap connection")?;
    check_generation(&conn, path, generation)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .db_context(|| "failed to set journal_mode=WAL")?;
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .db_context(|| "failed to read back journal_mode")?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::WalUnavailable {
            path: path.to_path_buf(),
            mode,
        });
    }
    conn.pragma_update(None, "synchronous", "NORMAL")
        .db_context(|| "failed to set synchronous=NORMAL")?;
    // The schema is read before every query, so damage to it shows here.
    conn.query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))
        .db_context(|| format!("failed to read the schema of {}", path.display()))
}

/// A pool of `spec.max_size` connections to `path`, each running
/// `spec.pragmas` and holding `user`. Building it opens no connection.
fn wal_pool(path: &Path, user: Arc<DbUser>, spec: Spec) -> Result<Pool<Manager>> {
    let pragmas = spec.pragmas;
    let manager = Manager {
        inner: SqliteConnectionManager::file(path)
            .with_init(move |conn| conn.execute_batch(pragmas)),
        user,
    };
    // A local database connection does not go stale; checking each checkout
    // with a query costs a statement prepare per use. Connections open on
    // first use: each reads the schema, and most runs need few of them.
    Pool::builder()
        .max_size(spec.max_size)
        .min_idle(Some(0))
        .test_on_check_out(false)
        .build(manager)
        .map_err(|err| {
            crate::error::pool_error(
                &format!("failed to create connection pool for {}", path.display()),
                err,
            )
        })
}

/// Overwrites every page of the database at `path` but the first, which
/// holds the header and the schema.
#[cfg(test)]
pub(crate) fn damage_past_schema(path: &Path) {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = File::options().write(true).open(path).unwrap();
    let len = file.metadata().unwrap().len();
    assert!(len > 2 * 4096, "{len}");
    file.seek(SeekFrom::Start(4096)).unwrap();
    file.write_all(&vec![0x5a; (len - 4096) as usize]).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DbResultExt;

    const SPEC: Spec = Spec {
        pragmas: "PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;",
        max_size: 2,
        generation: 1,
        init: |conn| {
            conn.execute_batch("CREATE TABLE IF NOT EXISTS t (n BLOB)")
                .db_context(|| "init")
        },
        lock: |path| {
            let lock = open_users(&sibling(path, ".lock"))?;
            lock.lock().io_context(|| "lock".to_string())?;
            Ok(Box::new(lock))
        },
    };

    fn count(conn: &mut rusqlite::Connection) -> Result<i64> {
        conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0))
            .db_context(|| "count")
    }

    /// A database damaged past its schema page, and the shared lock of a
    /// peer process that has it open.
    fn damaged_in_use(path: &Path) -> File {
        let lock = (SPEC.lock)(path).unwrap();
        let db = open(path, SPEC).unwrap();
        db.run(|conn| {
            conn.execute_batch(
                "INSERT INTO t WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n \
                 WHERE i < 500) SELECT randomblob(100) FROM n",
            )
            .db_context(|| "fill")
        })
        .unwrap();
        drop((db, lock));
        damage_past_schema(path);
        let peer = open_users(&sibling(path, ".users")).unwrap();
        peer.lock_shared().unwrap();
        peer
    }

    /// A peer that found the damage too closes the file a moment later; the
    /// first to find it then recreates it.
    #[test]
    fn a_damaged_database_is_recreated_once_its_peer_closes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let peer = damaged_in_use(&path);
        let lock = (SPEC.lock)(&path).unwrap();
        let db = open(&path, SPEC).unwrap();
        drop(lock);
        let closes = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(peer);
        });
        assert_eq!(db.run(count).unwrap(), 0);
        closes.join().unwrap();
    }

    /// A peer that recreated the file while this process waited to is not
    /// undone: this process opens the new file and keeps what the peer
    /// wrote to it, unless the peer was a newer raeva.
    #[test]
    fn a_database_a_peer_recreated_is_opened_again() {
        for newer in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("db.sqlite");
            let peer = damaged_in_use(&path);
            let lock = (SPEC.lock)(&path).unwrap();
            let db = open(&path, SPEC).unwrap();
            drop(lock);
            let recreates = std::thread::spawn({
                let path = path.clone();
                move || {
                    std::thread::sleep(Duration::from_millis(300));
                    let _lock = (SPEC.lock)(&path).unwrap();
                    peer.unlock().unwrap();
                    peer.lock().unwrap();
                    recreate_files(&path, 1, &peer, &"peer").unwrap();
                    let conn = rusqlite::Connection::open(&path).unwrap();
                    (SPEC.init)(&conn).unwrap();
                    conn.execute("INSERT INTO t VALUES (x'00')", []).unwrap();
                    drop(conn);
                    if newer {
                        write_as_newer_raeva(&path, "CREATE TABLE t (n BLOB) NEWER");
                    }
                    drop(peer);
                }
            });
            let counted = db.run(count);
            recreates.join().unwrap();
            if newer {
                let err = counted.unwrap_err();
                assert!(
                    matches!(err, StoreError::NewerDatabase { found: 2, .. }),
                    "{err}"
                );
                assert_eq!(generation(&path), 2);
            } else {
                assert_eq!(counted.unwrap(), 1);
            }
            let users_path = sibling(&path, ".users");
            assert_eq!(
                epoch(&open_users(&users_path).unwrap(), &users_path).unwrap(),
                1
            );
        }
    }

    /// Stands in for a newer raeva: stamps the database at `path` with a
    /// later generation and gives its table the definition `sql`.
    fn write_as_newer_raeva(path: &Path, sql: &str) {
        let conn = rusqlite::Connection::open(path).unwrap();
        let cookie: i64 = conn
            .pragma_query_value(None, "schema_version", |row| row.get(0))
            .unwrap();
        conn.execute_batch(&format!(
            "PRAGMA writable_schema = ON;
             UPDATE sqlite_schema SET sql = '{sql}' WHERE name = 't';
             PRAGMA schema_version = {};
             PRAGMA user_version = 2;",
            cookie + 1
        ))
        .unwrap();
    }

    fn generation(path: &Path) -> i64 {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap()
    }

    /// A database is stamped with its generation. One that a newer raeva
    /// stamped later is neither recreated, though its schema reads as
    /// damaged, mid-run or at open, nor opened when it reads well.
    #[test]
    fn a_newer_generation_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let opened = || {
            let _lock = (SPEC.lock)(&path).unwrap();
            open(&path, SPEC)
        };
        let db = opened().unwrap();
        let insert = |conn: &mut rusqlite::Connection| {
            conn.execute("INSERT INTO t VALUES (x'00')", [])
                .db_context(|| "insert")
        };
        db.run(insert).unwrap();
        assert_eq!(generation(&path), 1);

        write_as_newer_raeva(&path, "CREATE TABLE t (n BLOB) NEWER");
        let mid_run = db.run(count).unwrap_err();
        drop(db);
        let at_open = opened().err().unwrap();
        write_as_newer_raeva(&path, "CREATE TABLE t (n BLOB)");
        let readable = opened().err().unwrap();
        for err in [mid_run, at_open, readable] {
            assert!(
                matches!(
                    err,
                    StoreError::NewerDatabase {
                        found: 2,
                        supported: 1,
                        ..
                    }
                ),
                "{err}"
            );
        }
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(count(&mut conn).unwrap(), 1);
        assert_eq!(generation(&path), 2);
    }

    /// A connection outliving its pool and manager, as one r2d2 still owns
    /// internally can, keeps the database marked open.
    #[test]
    fn a_connection_keeps_its_database_open() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let manager = Manager {
            inner: SqliteConnectionManager::file(&path),
            user: Arc::new(enable_wal(&path, 1).unwrap()),
        };
        let conn = r2d2::ManageConnection::connect(&manager).unwrap();
        drop(manager);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all(b"not a sqlite header")
            .unwrap();
        assert!(enable_wal(&path, 1).is_err());
        drop(conn);
        enable_wal(&path, 1).expect("recreated once the connection is closed");
    }
}
