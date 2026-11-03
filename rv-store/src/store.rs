use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tempfile::{NamedTempFile, TempPath};

use crate::durability::Durability;
use crate::error::{IoResultExt, Result, StoreError};
use crate::index;
use crate::paths;
use crate::pin::StoredBlob;
use crate::sqlite;
use rv_fs::lock_exclusive_until;
use rv_maven_types::{ArtifactCoord, BlobId};

const INDEX_DB: &str = "index.sqlite";

pub(crate) const TMP_DIR: &str = "tmp";
const LOCK_FILE: &str = ".lock";
/// r2d2 pool size for the SQLite index: enough for the resolver's fan-out
/// without running into the per-process file-descriptor ceiling.
const POOL_SIZE: u32 = 8;

// foreign_keys is per connection and OFF by default. temp_store keeps temp
// B-trees in memory, so a crash leaves no temp files behind.
pub(crate) const INDEX: sqlite::Spec = sqlite::Spec {
    pragmas: "PRAGMA busy_timeout=5000;
              PRAGMA cache_size=-32000;
              PRAGMA synchronous=NORMAL;
              PRAGMA foreign_keys=ON;
              PRAGMA temp_store=MEMORY;",
    max_size: POOL_SIZE,
    generation: 2,
    init: index::init_db,
    lock: |path| Ok(Box::new(StoreLock::acquire(path.parent().unwrap_or(path))?)),
};
/// Files in `tmp/` older than this are removed when a store opens.
const STALE_TEMP_AGE: Duration = Duration::from_secs(24 * 3600);
/// How long a writer waits for the store lock before giving up.
const LOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// Remove stale files from `tmp/`, unless another writer holds the store
/// lock; the next open retries then. Dropping the file releases the lock.
fn sweep_temp_dir(root: &Path) {
    let Ok(lock) = open_lock_file(&root.join(LOCK_FILE)) else {
        return;
    };
    if lock.try_lock().is_ok() {
        sweep_stale(&root.join(TMP_DIR));
    }
}

fn sweep_stale(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    // `DirEntry::file_type` does not follow symlinks, so a symlink, which
    // could steer the sweep at another file, is neither a file nor a
    // directory here.
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_dir() {
            sweep_stale(&path);
            let _ = fs::remove_dir(&path);
        } else if file_type.is_file()
            && entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > STALE_TEMP_AGE)
        {
            let _ = fs::remove_file(&path);
        }
    }
}

fn open_lock_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn verify_blob_at_path(path: &Path, expected: &BlobId) -> Result<()> {
    let file = match open_unfollowed(path) {
        Ok(file) => file,
        Err(err) if is_nofollow_symlink(&err) => {
            return Err(StoreError::IntegrityError(format!(
                "blob at {} is not a regular file",
                path.display()
            )));
        }
        Err(err) => {
            return Err(err).io_context(|| format!("failed to stat blob {}", path.display()));
        }
    };
    let meta = file
        .metadata()
        .io_context(|| format!("failed to stat blob {}", path.display()))?;
    if !opened_is_regular(&meta) {
        return Err(StoreError::IntegrityError(format!(
            "blob at {} is not a regular file",
            path.display()
        )));
    }
    let actual = BlobId::from_reader(file)?;
    if &actual == expected {
        Ok(())
    } else {
        Err(StoreError::IntegrityError(format!(
            "blob at {} has hash {actual} but expected {expected}",
            path.display()
        )))
    }
}

/// Whether `path` is a regular file. Symlinks, including those to a regular
/// file, are not.
pub(crate) fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
}

/// Open `path` without following a final symlink or reparse point.
fn open_unfollowed(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
    );
    #[cfg(windows)]
    {
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        std::os::windows::fs::OpenOptionsExt::custom_flags(
            &mut options,
            FILE_FLAG_OPEN_REPARSE_POINT,
        );
    }
    options.open(path)
}

fn opened_is_regular(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        meta.is_file() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    }
    #[cfg(not(windows))]
    {
        meta.is_file()
    }
}

/// `O_NOFOLLOW` on a symlink is `ELOOP` (`ErrorKind::FilesystemLoop` is
/// unstable on the MSRV).
fn is_nofollow_symlink(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        rustix::io::Errno::from_io_error(err) == Some(rustix::io::Errno::LOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

fn is_absent_or_symlink(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound || is_nofollow_symlink(err)
}

/// [`open_unfollowed_regular`] for a blob, with the path in the error.
pub(crate) fn open_regular_file(path: &Path) -> Result<Option<File>> {
    open_unfollowed_regular(path).io_context(|| format!("failed to open blob {}", path.display()))
}

/// Open `path` as a regular file without following a symlink. A missing
/// path, a symlink, or anything else that is not a regular file is
/// `Ok(None)`. Something swapped in for a regular file, such as a link or a
/// FIFO, is neither opened through nor blocks the open; on Windows the open
/// does not follow a reparse point and refuses the reparse point itself.
pub fn open_unfollowed_regular(path: &Path) -> std::io::Result<Option<File>> {
    match open_unfollowed(path) {
        Ok(file) => {
            let meta = file.metadata()?;
            Ok(opened_is_regular(&meta).then_some(file))
        }
        Err(err) if is_absent_or_symlink(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Locks `mutex`, recovering the data from a panicked holder.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Make a staged blob 0o444 so users other than the writer, such as `mvn`
/// under another uid in CI, can read it. tempfile creates 0o600 files.
#[cfg(unix)]
pub(crate) fn set_blob_readonly(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o444)) {
        tracing::debug!(path = %path.display(), error = %e, "failed to set 0o444 on staged CAS blob");
    }
}

#[cfg(not(unix))]
pub(crate) fn set_blob_readonly(_path: &Path) {}

/// Sync a blob file before it is published where its directories cannot be
/// synced later (see the `durability` module).
pub(crate) fn sync_before_publish(file: &File) -> Result<()> {
    if cfg!(unix) {
        return Ok(());
    }
    file.sync_all()
        .io_context(|| "failed to sync blob".to_string())
}

/// Link `temp` at `target` without replacing a file already there, so a
/// concurrent writer of the same bytes keeps its inode. A file found there is
/// reused if it hashes to `id`; a corrupt one is replaced once. Returns
/// whether this call published the file.
fn persist_blob(temp: TempPath, target: &Path, id: &BlobId) -> Result<bool> {
    let mut temp = temp;
    for retry in [false, true] {
        match temp.persist_noclobber(target) {
            Ok(()) => {
                if is_regular_file(target) {
                    return Ok(true);
                }
                // The temp path was replaced with a symlink (or other
                // non-file) before the link; do not leave it as a blob.
                let _ = fs::remove_file(target);
                return Err(StoreError::IntegrityError(format!(
                    "blob at {} is not a regular file",
                    target.display()
                )));
            }
            Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => temp = err.path,
            Err(err) => {
                return Err(err.error)
                    .io_context(|| format!("failed to persist blob to {}", target.display()));
            }
        }
        match verify_blob_at_path(target, id) {
            Ok(()) => return Ok(false),
            // The run that found the file damaged warned about it; this only
            // replaces the bytes.
            Err(StoreError::IntegrityError(msg)) if !retry => {
                tracing::debug!(path = %target.display(), "detected corrupt blob, repairing: {msg}");
                fs::remove_file(target).io_context(|| {
                    format!("failed to remove corrupt blob at {}", target.display())
                })?;
            }
            // Removed between the link attempt and the check.
            Err(StoreError::IoError(err))
                if !retry && err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    unreachable!("the retry returns")
}

/// Publish the staged file `temp` as blob `id` of the store at `root` and
/// queue it for the next sync. Returns the sync ticket and whether this call
/// published the file.
pub(crate) fn publish_blob(root: &Path, temp: TempPath, id: &BlobId) -> Result<(u64, bool)> {
    let target = root.join(paths::blob_path(id));
    let created = {
        let _lock = StoreLock::acquire(root)?;
        let parent = target.parent().expect("a blob path has a parent");
        fs::create_dir_all(parent)
            .io_context(|| format!("failed to create blob directory {}", parent.display()))?;
        persist_blob(temp, &target, id)?
    };
    let durability = &root_shared(root).durability;
    let ticket = durability.register(&paths::blob_root(root), &target, created)?;
    Ok((ticket, created))
}

/// Record the check of blob `id` when this process wrote it from bytes it
/// hashed and it is durable and unchanged since, so the first check of it
/// does not read it again.
pub(crate) fn record_hashed_stamp(
    conn: &rusqlite::Connection,
    root: &Path,
    id: &BlobId,
) -> Result<()> {
    let path = root.join(paths::blob_path(id));
    let Some(stamp) = root_shared(root).durability.hashed_stamp(&path) else {
        return Ok(());
    };
    let current = open_regular_file(&path).ok().flatten().and_then(|file| {
        let meta = file.metadata().ok()?;
        crate::pin::file_stamp(&file, &meta)
    });
    if current.as_deref() == Some(stamp.as_str()) {
        index::set_checked_stamp(conn, id, &stamp)?;
    }
    Ok(())
}

pub(crate) async fn blocking<T: Send + 'static>(
    task: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?
}

/// The repository a coordinate's bytes were downloaded from, recorded by
/// [`Store::record_origins`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// The repository URL as raeva.lock records it: the declared repository,
    /// not a mirror that served it.
    pub repo_url: String,
    /// The repository or mirror URL that served the bytes.
    pub endpoint_url: String,
    /// Whether the bytes matched the repository's checksum file.
    pub checksum_verified: bool,
    /// Whether this repository served these bytes, rather than a lockfile
    /// recording it as their origin after they came from elsewhere.
    pub served: bool,
}

/// Content-addressed artifact store: blobs named by the SHA-256 of their
/// bytes, and a SQLite index from Maven coordinates to blobs. Concurrent use
/// from several processes is safe through a file lock.
#[derive(Clone)]
pub struct Store {
    pub(crate) root: PathBuf,
    pub(crate) pool: Arc<sqlite::Db>,
}

impl Store {
    /// Opens or creates the store at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let blob_root = paths::blob_root(path);
        let tmp = path.join(TMP_DIR);
        for (dir, what) in [(path, "store"), (&blob_root, "blob"), (&tmp, "temp")] {
            fs::create_dir_all(dir)
                .io_context(|| format!("failed to create {what} directory {}", dir.display()))?;
        }

        let db_path = path.join(INDEX_DB);
        // Two processes must not race on switching to WAL or creating the
        // schema.
        let bootstrap_lock = StoreLock::acquire(path)?;

        let pool = sqlite::open(&db_path, INDEX)?;
        // The sweep takes the lock with a try-lock of its own.
        drop(bootstrap_lock);
        sweep_temp_dir(path);
        tracing::debug!(path = %path.display(), "store opened");

        Ok(Self {
            root: path.to_path_buf(),
            pool,
        })
    }

    /// Stores `bytes` and returns their blob id. Content already stored,
    /// and hashing to its id, is not written again.
    ///
    /// The blob is published without an fsync; the next index write makes
    /// it durable first (see the `durability` module).
    pub async fn put_bytes(&self, bytes: &[u8]) -> Result<BlobId> {
        let bytes: Arc<[u8]> = Arc::from(bytes);
        let store = self.clone();
        // Hashing multi-MB payloads would stall an async worker.
        blocking(move || {
            let id = BlobId::from_bytes(&bytes);
            store.put_bytes_blocking(id, &bytes)
        })
        .await
    }

    /// Like [`Self::put_bytes`], but reuses a caller-computed `id` so the
    /// same bytes are not hashed twice.
    pub async fn put_bytes_with_id(&self, id: BlobId, bytes: &[u8]) -> Result<BlobId> {
        let bytes: Arc<[u8]> = Arc::from(bytes);
        let store = self.clone();
        blocking(move || store.put_bytes_blocking(id, &bytes)).await
    }

    fn put_bytes_blocking(&self, id: BlobId, bytes: &[u8]) -> Result<BlobId> {
        let target = self.root.join(paths::blob_path(&id));
        // A file already at the path is reused only if it hashes to the
        // id; one torn by a crash goes through the repair.
        if self
            .stored_blob(&id)
            .is_ok_and(|stored| stored == StoredBlob::Intact)
        {
            tracing::debug!(sha256 = %id, size = bytes.len(), "blob already stored");
            let durability = &root_shared(&self.root).durability;
            durability.register(&paths::blob_root(&self.root), &target, false)?;
            return Ok(id);
        }
        tracing::debug!(sha256 = %id, size = bytes.len(), "storing blob");
        let tmp_dir = self.root.join(TMP_DIR);
        fs::create_dir_all(&tmp_dir)
            .io_context(|| format!("failed to create temp directory {}", tmp_dir.display()))?;
        let mut temp = NamedTempFile::new_in(&tmp_dir)
            .io_context(|| "failed to create temp file".to_string())?;
        temp.write_all(bytes)
            .io_context(|| "failed to write blob content".to_string())?;
        sync_before_publish(temp.as_file())?;
        set_blob_readonly(temp.path());
        publish_blob(&self.root, temp.into_temp_path(), &id)?;
        Ok(id)
    }

    /// Returns the filesystem path for a blob by its content hash.
    pub fn get_path(&self, id: &BlobId) -> PathBuf {
        self.root.join(paths::blob_path(id))
    }

    /// Whether the blob's file exists. The bytes are not re-hashed.
    pub async fn exists_async(&self, id: &BlobId) -> bool {
        let found = tokio::fs::symlink_metadata(self.get_path(id))
            .await
            .is_ok_and(|meta| meta.is_file());
        tracing::debug!(sha256 = %id, hit = found, "blob lookup (async)");
        found
    }

    /// Records a mapping from a Maven coordinate to a blob in the index.
    pub async fn add_artifact(&self, key: &ArtifactCoord, id: &BlobId) -> Result<()> {
        tracing::debug!(%key, sha256 = %id, "indexing artifact");
        self.add_artifacts(vec![(key.clone(), id.clone())]).await
    }

    /// Records several coordinate to blob mappings in one transaction, in
    /// order, so a coordinate listed twice ends up naming its last blob.
    /// Every blob must be a regular file in the store.
    pub async fn add_artifacts(&self, rows: Vec<(ArtifactCoord, BlobId)>) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let pool = self.pool.clone();
        let root = self.root.clone();
        blocking(move || {
            // A row may name a blob another process published and has not
            // synced, so every blob a row names is synced first, with
            // everything this process published so far.
            let durability = &root_shared(&root).durability;
            let mut ticket = durability.registered();
            for (_, id) in &rows {
                let path = root.join(paths::blob_path(id));
                if is_regular_file(&path) {
                    let queued = durability.register(&paths::blob_root(&root), &path, false)?;
                    ticket = ticket.max(queued);
                }
            }
            durability.make_durable(ticket)?;
            // The store lock keeps lock-holding writers out between the file
            // check and the row write.
            pool.write_locked(|conn| {
                for (key, id) in &rows {
                    let path = root.join(paths::blob_path(id));
                    match fs::symlink_metadata(&path) {
                        Ok(meta) if meta.is_file() => {}
                        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                            return Err(err)
                                .io_context(|| format!("failed to stat blob {}", path.display()));
                        }
                        _ => {
                            return Err(StoreError::IntegrityError(format!(
                                "refusing to index {key} -> {id}: blob file {} is not a regular file",
                                path.display()
                            )));
                        }
                    }
                }
                for (key, id) in &rows {
                    index::add_artifact(conn, key, id)?;
                    record_hashed_stamp(conn, &root, id)?;
                }
                Ok(())
            })
        })
        .await
    }

    /// Whether `key` is indexed as `id` and the blob file is present. The
    /// bytes are not re-hashed: an index row is only written for a durable
    /// blob that hashed to its id.
    pub async fn is_indexed(&self, key: &ArtifactCoord, id: &BlobId) -> Result<bool> {
        let pool = self.pool.clone();
        let path = self.get_path(id);
        let (key, id) = (key.clone(), id.clone());
        blocking(move || {
            Ok(pool
                .run(|conn| index::lookup_artifact(conn, &key))?
                .as_ref()
                == Some(&id)
                && is_regular_file(&path))
        })
        .await
    }

    /// Whether the index names `id` for `key` with its file present, as
    /// [`Self::is_indexed`] says, and the routes [`Self::served_by`] lists,
    /// in one index read.
    pub async fn indexed_and_served(
        &self,
        key: &ArtifactCoord,
        id: &BlobId,
    ) -> Result<(bool, Vec<(String, String)>)> {
        let pool = self.pool.clone();
        let path = self.get_path(id);
        let (key, id) = (key.clone(), id.clone());
        blocking(move || {
            let (found, served_by) = pool.run(|conn| -> Result<_> {
                Ok((
                    index::lookup_artifact(conn, &key)?,
                    index::served_by(conn, &key, &id)?,
                ))
            })?;
            Ok((
                found.as_ref() == Some(&id) && is_regular_file(&path),
                served_by,
            ))
        })
        .await
    }

    /// Keep as evidence that each (repository, endpoint) served the blob for
    /// its coordinate, as a [served](Origin::served) origin does, without
    /// recording it as that route's answer.
    pub async fn record_served(
        &self,
        rows: Vec<(ArtifactCoord, BlobId, String, String)>,
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let pool = self.pool.clone();
        blocking(move || {
            pool.write(|conn| {
                for (key, id, repo_url, endpoint_url) in &rows {
                    index::add_served(conn, key, id, repo_url, endpoint_url)?;
                }
                Ok(())
            })
        })
        .await
    }

    /// Record which repository served each coordinate's blob, for
    /// [`Self::lookup_artifact_from`]. A row is a hint: the blob may be gone
    /// or changed, so a reader verifies it before use.
    pub async fn record_origins(&self, rows: Vec<(ArtifactCoord, BlobId, Origin)>) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let pool = self.pool.clone();
        blocking(move || {
            pool.write(|conn| {
                for (key, id, origin) in &rows {
                    index::add_origin(conn, key, id, origin)?;
                }
                Ok(())
            })
        })
        .await
    }

    /// The repository and endpoint URLs [`Self::record_origins`] recorded
    /// as having [served](Origin::served) `id` for `key`. A hint, like
    /// [`Self::lookup_artifact`].
    pub async fn served_by(
        &self,
        key: &ArtifactCoord,
        id: &BlobId,
    ) -> Result<Vec<(String, String)>> {
        let pool = self.pool.clone();
        let (key, id) = (key.clone(), id.clone());
        blocking(move || pool.run(|conn| index::served_by(conn, &key, &id))).await
    }

    /// Each row whose origin [`Self::record_origins`] has not recorded as its
    /// blob, in place, and `None` for one it has, in one index read.
    pub async fn unrecorded_origins(
        &self,
        rows: Vec<(ArtifactCoord, BlobId, Origin)>,
    ) -> Result<Vec<Option<(ArtifactCoord, BlobId, Origin)>>> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let pool = self.pool.clone();
        blocking(move || {
            let found = pool.run(|conn| {
                (rows.iter())
                    .map(|(key, _, origin)| {
                        index::lookup_origin(
                            conn,
                            key,
                            &origin.repo_url,
                            &origin.endpoint_url,
                            true,
                            true,
                        )
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
            Ok((rows.into_iter().zip(found))
                .map(|(row, found)| (found.as_ref() != Some(&row.1)).then_some(row))
                .collect())
        })
        .await
    }

    /// The blob `endpoint_url` served for `key` under `repo_url`, as [`Self::record_origins`]
    /// recorded it, skipping one admitted without a checksum unless
    /// `allow_unverified`, and one a lockfile recorded rather than the
    /// repository [served](Origin::served) unless `allow_recorded`. Unlike
    /// [`Self::lookup_artifact`], another repository or mirror's bytes for the
    /// coordinate never answer. A hint, like [`Self::lookup_artifact`].
    pub async fn lookup_artifact_from(
        &self,
        key: &ArtifactCoord,
        repo_url: &str,
        endpoint_url: &str,
        allow_unverified: bool,
        allow_recorded: bool,
    ) -> Result<Option<BlobId>> {
        let pool = self.pool.clone();
        let (key, repo_url, endpoint_url) =
            (key.clone(), repo_url.to_string(), endpoint_url.to_string());
        blocking(move || {
            pool.run(|conn| {
                index::lookup_origin(
                    conn,
                    &key,
                    &repo_url,
                    &endpoint_url,
                    allow_unverified,
                    allow_recorded,
                )
            })
        })
        .await
    }

    /// Looks up the blob ID for a Maven coordinate, returning `None` if not indexed.
    ///
    /// This does not hold the store lock or check the file, so the returned
    /// id can name a blob that is missing or about to be removed by another
    /// process. Treat it as a cache hint, or use
    /// [`Self::lookup_artifact_locked`].
    pub async fn lookup_artifact(&self, key: &ArtifactCoord) -> Result<Option<BlobId>> {
        let pool = self.pool.clone();
        let owned = key.clone();
        let found = blocking(move || pool.run(|conn| index::lookup_artifact(conn, &owned))).await?;
        tracing::debug!(%key, hit = found.is_some(), "artifact lookup");
        Ok(found)
    }

    /// Lookup that takes the store lock for the index query and a stat of
    /// the file: `Some(id)` only if a row names a blob that exists on disk at
    /// lookup time. Another process can still remove the file after the lock
    /// is released, but raeva removes a blob file only when its bytes fail
    /// verification.
    pub async fn lookup_artifact_locked(&self, key: &ArtifactCoord) -> Result<Option<BlobId>> {
        let pool = self.pool.clone();
        let root = self.root.clone();
        let key = key.clone();
        blocking(move || {
            pool.run_locked(|conn| {
                let Some(id) = index::lookup_artifact(conn, &key)? else {
                    return Ok(None);
                };
                match fs::symlink_metadata(root.join(paths::blob_path(&id))) {
                    Ok(meta) => Ok(meta.is_file().then_some(id)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(StoreError::IoError(e)),
                }
            })
        })
        .await
    }

    /// The ids among `ids` whose files hash to them, checking at most
    /// `parallelism` files at once. A file unchanged since it last hashed to
    /// its id is not read again (see [`Store::check_pin_unless_unchanged`]).
    /// The first error in `ids` order is returned.
    pub async fn verify_blobs(
        &self,
        ids: &[BlobId],
        parallelism: usize,
    ) -> Result<HashSet<BlobId>> {
        use futures_util::stream::{self, StreamExt};

        let mut results: Vec<(usize, Result<Option<BlobId>>)> = stream::iter(ids.iter().cloned())
            .enumerate()
            .map(|(index, id)| {
                let store = self.clone();
                async move {
                    let verified = blocking(move || {
                        Ok((store.stored_blob(&id)? == StoredBlob::Intact).then_some(id))
                    });
                    (index, verified.await)
                }
            })
            .buffer_unordered(parallelism.max(1))
            .collect()
            .await;
        results.sort_unstable_by_key(|(index, _)| *index);
        results
            .into_iter()
            .filter_map(|(_, result)| result.transpose())
            .collect()
    }
}

/// Cross-process exclusive lock on the store's `.lock` file. A query takes
/// it through [`sqlite::Db::run_locked`], never around [`sqlite::Db::run`].
///
/// `flock(2)` locks belong to open file descriptions, so separate opens of
/// `.lock` do not exclude each other within one process. The `_intra` guard
/// serializes this process's callers per store root first. Both waits share
/// one deadline.
pub(crate) struct StoreLock {
    file: File,
    _intra: IntraGuard,
}

/// State shared by every handle on one store root in this process: the
/// in-process half of the store lock and the queue of blobs to sync.
pub(crate) struct RootShared {
    lock: IntraLock,
    pub(crate) durability: Durability,
}

/// One leaked entry per store root, never removed: an entry must outlive
/// every `StoreLock` it produced. A process touches a handful of roots.
static STORE_ROOTS: OnceLock<Mutex<HashMap<PathBuf, &'static RootShared>>> = OnceLock::new();

pub(crate) fn root_shared(root: &Path) -> &'static RootShared {
    let key = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let map = STORE_ROOTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = lock(map);
    guard.entry(key).or_insert_with(|| {
        Box::leak(Box::new(RootShared {
            lock: IntraLock::default(),
            durability: Durability::for_blob_root(&paths::blob_root(root)),
        }))
    })
}

#[derive(Default)]
struct IntraLock {
    held: Mutex<bool>,
    released: Condvar,
}

struct IntraGuard(&'static IntraLock);

impl IntraLock {
    fn acquire(&'static self, deadline: Instant) -> Option<IntraGuard> {
        let mut held = lock(&self.held);
        while *held {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            held = self
                .released
                .wait_timeout(held, deadline - now)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        *held = true;
        Some(IntraGuard(self))
    }
}

impl Drop for IntraGuard {
    fn drop(&mut self) {
        *lock(&self.0.held) = false;
        self.0.released.notify_one();
    }
}

impl StoreLock {
    pub(crate) fn acquire(root: &Path) -> Result<Self> {
        Self::acquire_with_timeout(root, LOCK_TIMEOUT)
    }

    fn acquire_with_timeout(root: &Path, timeout: Duration) -> Result<Self> {
        let lock_path = root.join(LOCK_FILE);
        let deadline = Instant::now() + timeout;
        let intra =
            root_shared(root)
                .lock
                .acquire(deadline)
                .ok_or_else(|| StoreError::LockTimeout {
                    path: lock_path.clone(),
                    holder_info: "another thread in this process".to_string(),
                })?;
        // Not truncated on open: a contender must not wipe the holder's info.
        let mut file = open_lock_file(&lock_path)
            .io_context(|| format!("failed to open lock file {}", lock_path.display()))?;
        match lock_exclusive_until(&mut file, deadline) {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                let mut info = String::new();
                let _ = (&file).read_to_string(&mut info);
                let info = info.trim();
                return Err(StoreError::LockTimeout {
                    path: lock_path,
                    holder_info: if info.is_empty() { "unknown" } else { info }.to_string(),
                });
            }
            Err(fs::TryLockError::Error(e)) => return Err(StoreError::IoError(e)),
        }
        // Written before truncating, so a kill between the two calls never
        // leaves the file empty.
        let info = format!(
            "pid={} time={}\n",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        (&file)
            .seek(SeekFrom::Start(0))
            .and_then(|_| (&file).write_all(info.as_bytes()))
            .and_then(|()| file.set_len(info.len() as u64))
            .io_context(|| format!("failed to write lock info to {}", lock_path.display()))?;
        Ok(Self {
            file,
            _intra: intra,
        })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // The file lock first, then the in-process guard.
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::stream;
    use rv_maven_types::{ArtifactCoord, Digest, Sha1};
    use tempfile::tempdir;

    use super::{LOCK_FILE, Store, StoreLock, TMP_DIR, root_shared};
    use crate::BlobId;
    use crate::error::StoreError;
    use crate::verified::{Expect, Expectation, PutError};

    fn coord(artifact: &str, classifier: Option<&str>) -> ArtifactCoord {
        ArtifactCoord::new("com.example", artifact, "1.0.0", "jar", classifier)
    }

    /// Another handle holding the file lock, as a second `raeva` process does,
    /// times the store out, and threads of one process take turns.
    #[test]
    fn store_lock_excludes_other_handles_and_threads() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let holder = super::open_lock_file(&root.join(LOCK_FILE)).unwrap();
        holder.lock().unwrap();
        let err = StoreLock::acquire_with_timeout(&root, Duration::from_millis(100)).err();
        assert!(
            matches!(err, Some(StoreError::LockTimeout { .. })),
            "{err:?}"
        );
        holder.unlock().unwrap();

        let (inside, most) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let (root, inside, most) = (root.clone(), inside.clone(), most.clone());
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        let _lock = StoreLock::acquire(&root).unwrap();
                        most.fetch_max(inside.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(1));
                        inside.fetch_sub(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        assert_eq!(most.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn only_unrecorded_origins_are_returned() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let blob = store.put_bytes(b"bytes").await.unwrap();
        let other = store.put_bytes(b"other").await.unwrap();
        let row = |name, blob: &BlobId| {
            let origin = crate::Origin {
                repo_url: "https://repo.example/".into(),
                endpoint_url: "https://repo.example/".into(),
                checksum_verified: false,
                served: true,
            };
            (coord(name, None), blob.clone(), origin)
        };
        store.record_origins(vec![row("a", &blob)]).await.unwrap();
        let rows = vec![row("a", &blob), row("a", &other), row("b", &blob)];
        let unrecorded = store.unrecorded_origins(rows).await.unwrap();
        let unrecorded: Vec<_> = unrecorded.iter().map(Option::is_some).collect();
        assert_eq!(unrecorded, [false, true, true]);
    }

    /// A row a lockfile recorded names no repository that served the bytes,
    /// and a later answer at a route keeps the evidence of the earlier one,
    /// as two generations of a non-unique SNAPSHOT need.
    #[tokio::test]
    async fn served_by_leaves_out_origins_a_lock_recorded() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = coord("demo", None);
        let blob = store.put_bytes(b"bytes").await.unwrap();
        let row = |repo: &str, served| {
            let origin = crate::Origin {
                repo_url: repo.into(),
                endpoint_url: format!("{repo}mirror/"),
                checksum_verified: false,
                served,
            };
            (key.clone(), blob.clone(), origin)
        };
        let rows = vec![
            row("https://a.example/", true),
            row("https://b.example/", false),
        ];
        store.record_origins(rows).await.unwrap();
        assert_eq!(
            store.served_by(&key, &blob).await.unwrap(),
            [(
                "https://a.example/".into(),
                "https://a.example/mirror/".into()
            )]
        );
        let other = BlobId::from_bytes(b"other");
        assert!(store.served_by(&key, &other).await.unwrap().is_empty());

        let newer = store.put_bytes(b"newer").await.unwrap();
        let (_, _, origin) = row("https://a.example/", true);
        let lookup = |allow_recorded| {
            store.lookup_artifact_from(
                &key,
                "https://b.example/",
                "https://b.example/mirror/",
                true,
                allow_recorded,
            )
        };
        assert_eq!(lookup(false).await.unwrap(), None);
        assert_eq!(lookup(true).await.unwrap(), Some(blob.clone()));
        store
            .record_origins(vec![(key.clone(), newer.clone(), origin)])
            .await
            .unwrap();
        assert_eq!(store.served_by(&key, &blob).await.unwrap().len(), 1);
        assert_eq!(store.served_by(&key, &newer).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn artifact_evidence_requires_the_declared_repository_and_serving_endpoint() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = coord("demo", None);
        let declared = "https://repo.example/";
        let mirror = "https://mirror.example/";
        for (endpoint, bytes) in [
            (mirror, b"mirror".as_slice()),
            (declared, b"origin".as_slice()),
        ] {
            let blob = store.put_bytes(bytes).await.unwrap();
            store
                .record_origins(vec![(
                    key.clone(),
                    blob,
                    crate::Origin {
                        repo_url: declared.into(),
                        endpoint_url: endpoint.into(),
                        checksum_verified: true,
                        served: true,
                    },
                )])
                .await
                .unwrap();
        }
        for (endpoint, bytes) in [
            (mirror, b"mirror".as_slice()),
            (declared, b"origin".as_slice()),
        ] {
            assert_eq!(
                store
                    .lookup_artifact_from(&key, declared, endpoint, false, false)
                    .await
                    .unwrap(),
                Some(BlobId::from_bytes(bytes))
            );
        }
        assert_eq!(
            store
                .lookup_artifact_from(&key, mirror, mirror, false, false)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .lookup_artifact_from(&key, declared, "https://other.example/", false, false)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn stores_and_indexes_blobs_across_reopens() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("store");
        let store = Store::open(&root).unwrap();
        assert!(root.join("index.sqlite").is_file());

        let id = store.put_bytes(b"hello").await.unwrap();
        assert_eq!(id, BlobId::from_bytes(b"hello"));
        assert_eq!(store.put_bytes(b"hello").await.unwrap(), id);
        assert_eq!(std::fs::read(store.get_path(&id)).unwrap(), b"hello");
        let empty = store.put_bytes(b"").await.unwrap();
        assert!(store.exists_async(&empty).await);
        assert!(!store.exists_async(&BlobId::from_bytes(b"missing")).await);

        // An empty classifier and none are the same coordinate.
        let (blank, none) = (coord("demo", Some("")), coord("demo", None));
        store.add_artifact(&blank, &empty).await.unwrap();
        store.add_artifact(&none, &id).await.unwrap();
        drop(store);
        let store = Store::open(&root).unwrap();
        assert_eq!(
            store.lookup_artifact(&blank).await.unwrap(),
            Some(id.clone())
        );
        assert_eq!(store.lookup_artifact_locked(&none).await.unwrap(), Some(id));
    }

    #[tokio::test]
    async fn verify_and_put_bytes_catch_a_torn_blob() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let id = store.put_bytes(b"whole content").await.unwrap();
        let good = store.put_bytes(b"good").await.unwrap();
        let path = store.get_path(&id);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"whole").unwrap();
        let missing = BlobId::from_bytes(b"missing");
        let all = [id.clone(), good.clone(), missing];
        assert_eq!(store.verify_blobs(&all, 2).await.unwrap(), [good].into());

        assert_eq!(store.put_bytes(b"whole content").await.unwrap(), id);
        assert_eq!(std::fs::read(&path).unwrap(), b"whole content");
    }

    /// A damaged index, as a partial CI cache restore leaves, is replaced
    /// at once instead of failing every later run.
    #[tokio::test]
    async fn open_replaces_a_damaged_index() {
        let dir = tempdir().unwrap();
        let index = dir.path().join("index.sqlite");
        std::fs::write(&index, b"not a sqlite database").unwrap();
        let started = std::time::Instant::now();
        let store = Store::open(dir.path()).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        let id = store.put_bytes(b"bytes").await.unwrap();
        for n in 0..500 {
            store
                .add_artifact(&coord(&format!("a{n}"), None), &id)
                .await
                .unwrap();
        }
        drop(store);
        let len = std::fs::metadata(&index).unwrap().len();
        std::fs::File::options()
            .write(true)
            .open(&index)
            .unwrap()
            .set_len(len / 2)
            .unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.add_artifact(&coord("b", None), &id).await.unwrap();
        assert_eq!(
            store.lookup_artifact(&coord("b", None)).await.unwrap(),
            Some(id)
        );
    }

    /// An index cut short on a page boundary keeps an intact first page;
    /// SQLite compares the page count it records with the file.
    #[tokio::test]
    async fn open_replaces_an_index_cut_on_a_page_boundary() {
        let dir = tempdir().unwrap();
        let index = dir.path().join("index.sqlite");
        let store = Store::open(dir.path()).unwrap();
        let id = store.put_bytes(b"bytes").await.unwrap();
        let rows = (0..3000).map(|n| (coord(&format!("a{n}"), None), id.clone()));
        store.add_artifacts(rows.collect()).await.unwrap();
        drop(store);
        let len = std::fs::metadata(&index).unwrap().len();
        assert!(len >= 16 * 4096, "{len}");
        std::fs::File::options()
            .write(true)
            .open(&index)
            .unwrap()
            .set_len(len / 2 / 4096 * 4096)
            .unwrap();
        let store = Store::open(dir.path()).unwrap();
        for n in (0..3000).step_by(25) {
            assert_eq!(
                store
                    .lookup_artifact(&coord(&format!("a{n}"), None))
                    .await
                    .unwrap(),
                None
            );
        }
    }

    /// Damage past the schema page passes the check at open, so the first
    /// query that reads it recreates the index, for every handle on it.
    #[tokio::test]
    async fn a_query_that_finds_the_index_damaged_recreates_it() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let id = store.put_bytes(b"bytes").await.unwrap();
        let rows = (0..3000).map(|n| (coord(&format!("a{n}"), None), id.clone()));
        store.add_artifacts(rows.collect()).await.unwrap();
        drop(store);
        crate::sqlite::damage_past_schema(&dir.path().join("index.sqlite"));
        let (store, other) = (
            Store::open(dir.path()).unwrap(),
            Store::open(dir.path()).unwrap(),
        );
        assert_eq!(
            store.lookup_artifact(&coord("a7", None)).await.unwrap(),
            None
        );
        other.add_artifact(&coord("b", None), &id).await.unwrap();
        assert_eq!(
            store.lookup_artifact(&coord("b", None)).await.unwrap(),
            Some(id)
        );
    }

    /// A damaged index that another process has open, or that a
    /// connection outside the pool still reads, is not deleted under it;
    /// a later handle recreates it once it is alone.
    #[tokio::test]
    async fn a_damaged_index_in_use_is_kept() {
        let dir = tempdir().unwrap();
        let index = dir.path().join("index.sqlite");
        let store = Store::open(dir.path()).unwrap();
        let id = store.put_bytes(b"bytes").await.unwrap();
        let rows = (0..3000).map(|n| (coord(&format!("a{n}"), None), id.clone()));
        store.add_artifacts(rows.collect()).await.unwrap();
        drop(store);
        crate::sqlite::damage_past_schema(&index);
        let damaged = std::fs::read(&index).unwrap();
        let corrupt = |result: Result<Option<BlobId>, StoreError>| {
            let err = result.unwrap_err();
            assert_eq!(err.db_failure(), Some(crate::DbFailure::Corrupt), "{err}");
        };

        let peer = std::fs::File::open(dir.path().join("index.sqlite.users")).unwrap();
        peer.lock_shared().unwrap();
        let mut header = damaged.clone();
        header[..16].fill(0x5a);
        std::fs::write(&index, &header).unwrap();
        assert!(Store::open(dir.path()).is_err());
        assert_eq!(std::fs::read(&index).unwrap(), header);
        std::fs::write(&index, &damaged).unwrap();
        let store = Store::open(dir.path()).unwrap();
        corrupt(store.lookup_artifact(&coord("a7", None)).await);
        drop((store, peer));
        assert_eq!(std::fs::read(&index).unwrap(), damaged);

        let store = Store::open(dir.path()).unwrap();
        let outside = store.pool.conn();
        corrupt(store.lookup_artifact(&coord("a7", None)).await);
        assert_eq!(std::fs::read(&index).unwrap(), damaged);
        drop(store);
        let users = std::fs::File::open(dir.path().join("index.sqlite.users")).unwrap();
        assert!(
            users.try_lock().is_err(),
            "the outside connection keeps it open"
        );
        drop((outside, users));

        let store = Store::open(dir.path()).unwrap();
        assert_eq!(
            store.lookup_artifact(&coord("a7", None)).await.unwrap(),
            None
        );
    }

    /// A newer raeva may stamp the index with a later generation while this
    /// handle has it open, keeping its tables readable. No write through
    /// the open handle reaches it then.
    #[tokio::test]
    async fn no_write_reaches_an_index_a_newer_raeva_stamped() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let id = store.put_bytes(b"bytes").await.unwrap();
        store.add_artifact(&coord("a", None), &id).await.unwrap();
        // A value this raeva cannot parse, which it would otherwise delete.
        store
            .pool
            .conn()
            .execute(
                "INSERT INTO artifacts VALUES ('com.example', 'b', '1.0.0', 'jar', '', 'sha512:00')",
                [],
            )
            .unwrap();
        let peer = rusqlite::Connection::open(dir.path().join("index.sqlite")).unwrap();
        peer.pragma_update(None, "user_version", super::INDEX.generation + 1)
            .unwrap();
        let version = || -> i64 {
            peer.pragma_query_value(None, "data_version", |row| row.get(0))
                .unwrap()
        };
        let before = version();
        let origin = crate::Origin {
            repo_url: "https://repo.example/".into(),
            endpoint_url: "https://repo.example/".into(),
            checksum_verified: true,
            served: true,
        };
        let url = || "https://repo.example/".to_string();
        let pin = Digest::Sha256(BlobId::from_bytes(b"other"));
        let expect = Expect {
            sidecar: None,
            pin: None,
        };
        let errors = [
            store
                .add_artifact(&coord("c", None), &id)
                .await
                .unwrap_err(),
            (store
                .record_origins(vec![(coord("c", None), id.clone(), origin)])
                .await)
                .unwrap_err(),
            (store
                .record_served(vec![(coord("c", None), id.clone(), url(), url())])
                .await)
                .unwrap_err(),
            store.lookup_artifact(&coord("b", None)).await.unwrap_err(),
            store.check_pin(&id, &pin).unwrap_err(),
            match put(&store, b"more", expect, Some(&coord("c", None))).await {
                Err(PutError::Store(err)) => err,
                other => panic!("{:?}", other.map(|verified| verified.blob)),
            },
        ];
        for err in errors {
            assert!(
                matches!(err, StoreError::NewerDatabase { found, .. } if found == super::INDEX.generation + 1),
                "{err}"
            );
        }
        assert_eq!(version(), before);
    }

    /// A query waiting for the store lock holds no connection, so the
    /// queries that need no lock run meanwhile.
    #[test]
    fn a_wait_for_the_store_lock_holds_no_connection() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let lookup = |conn: &mut rusqlite::Connection| {
            crate::index::lookup_artifact(conn, &coord("a", None))
        };
        let lock = StoreLock::acquire(dir.path()).unwrap();
        let waiting: Vec<_> = (0..super::POOL_SIZE)
            .map(|_| {
                let pool = Arc::clone(&store.pool);
                std::thread::spawn(move || pool.run_locked(lookup))
            })
            .collect();
        std::thread::sleep(Duration::from_millis(100));
        let started = std::time::Instant::now();
        assert_eq!(store.pool.run(lookup).unwrap(), None);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(lock);
        for thread in waiting {
            assert_eq!(thread.join().unwrap().unwrap(), None);
        }
    }

    /// A blob that cannot be published keeps the cause's kind, so a full
    /// volume or a permission problem is reported as such.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_publish_keeps_the_error_kind() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let parent = store.get_path(&BlobId::from_bytes(b"bytes"));
        let parent = parent.parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root writes anyway.
        let writable = std::fs::write(parent.join("probe"), b"").is_ok();
        let result = store.put_bytes(b"bytes").await;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        if writable {
            return;
        }
        match result {
            Err(StoreError::IoError(err)) => {
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn open_sweeps_stale_temp_files() {
        let dir = tempdir().unwrap();

        let root = dir.path().join("store");
        let stale = root.join(TMP_DIR).join("nested").join("stale.tmp");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, b"x").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(48 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let fresh = root.join(TMP_DIR).join("fresh.tmp");
        std::fs::write(&fresh, b"x").unwrap();
        Store::open(&root).unwrap();
        assert!(!stale.exists() && !stale.parent().unwrap().exists());
        assert!(fresh.exists());
    }

    async fn put(
        store: &Store,
        body: &'static [u8],
        expect: Expect<'_>,
        key: Option<&ArtifactCoord>,
    ) -> Result<crate::Verified, PutError<std::io::Error>> {
        let chunks = vec![Ok(Bytes::from_static(body))];
        store
            .put_stream_verified(stream::iter(chunks), expect, key)
            .await
    }

    #[tokio::test]
    async fn verified_put_indexes_only_matching_bytes() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let body = b"served bytes";
        let sha1 = Digest::Sha1(Sha1::from_bytes(body));
        let sha256 = Digest::Sha256(BlobId::from_bytes(body));
        let other = Digest::Sha256(BlobId::from_bytes(b"locked bytes"));

        let bad = coord("bad", None);
        for (sidecar, pin, failed) in [
            (&other, None, Expectation::Sidecar),
            (&sha1, Some(&other), Expectation::Pin),
        ] {
            let expect = Expect {
                sidecar: Some(sidecar),
                pin,
            };
            match put(&store, body, expect, Some(&bad)).await {
                Err(PutError::Mismatch {
                    against,
                    expected,
                    actual,
                }) => {
                    assert_eq!((against, &expected, &actual), (failed, &other, &sha256));
                }
                other => panic!("expected a mismatch, got {other:?}"),
            }
        }
        // A failed check leaves no blob, row or temporary file behind.
        assert!(!store.get_path(&BlobId::from_bytes(body)).exists());
        assert_eq!(store.lookup_artifact(&bad).await.unwrap(), None);
        assert_eq!(
            std::fs::read_dir(dir.path().join(TMP_DIR)).unwrap().count(),
            0
        );

        let good = coord("good", None);
        let expect = Expect {
            sidecar: Some(&sha1),
            pin: Some(&sha256),
        };
        let verified = put(&store, body, expect, Some(&good)).await.unwrap();
        assert_eq!(verified.size, body.len() as u64);
        assert_eq!(
            store.lookup_artifact(&good).await.unwrap(),
            Some(verified.blob)
        );
    }

    #[tokio::test]
    async fn index_writes_sync_found_blobs_and_refuse_missing_ones() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        // A blob another process published and did not sync.
        let found = BlobId::from_bytes(b"published elsewhere");
        let path = store.get_path(&found);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"published elsewhere").unwrap();
        let durability = &root_shared(&store.root).durability;
        let before = durability.registered();

        let (key, other) = (coord("demo", None), coord("other", None));
        let first = store.put_bytes(b"first").await.unwrap();
        store
            .add_artifacts(vec![
                (key.clone(), first.clone()),
                (other.clone(), found.clone()),
                (key.clone(), found.clone()),
            ])
            .await
            .unwrap();
        assert!(durability.registered() > before);
        assert!(durability.synced() >= durability.registered());
        assert!(store.is_indexed(&key, &found).await.unwrap());
        assert!(!store.is_indexed(&key, &first).await.unwrap());

        let missing = BlobId::from_bytes(b"never stored");
        let err = store.add_artifact(&other, &missing).await.unwrap_err();
        assert!(matches!(err, StoreError::IntegrityError(_)), "{err:?}");
        assert!(store.is_indexed(&other, &found).await.unwrap());
        std::fs::remove_file(&path).unwrap();
        assert!(!store.is_indexed(&other, &found).await.unwrap());
        assert_eq!(store.lookup_artifact_locked(&other).await.unwrap(), None);
    }

    #[tokio::test]
    async fn lookup_scrubs_an_unparseable_blob_id_row() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = coord("corrupt", None);
        let rows = || -> i64 {
            let conn = store.pool.conn();
            conn.query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))
                .unwrap()
        };
        let id = store.put_bytes(b"replacement").await.unwrap();
        for locked in [false, true] {
            store.pool.conn().execute(
                "INSERT OR REPLACE INTO artifacts VALUES ('com.example', 'corrupt', '1.0.0', 'jar', '', 'not-a-blob-id')",
                [],
            )
            .unwrap();
            let found = if locked {
                store.lookup_artifact_locked(&key).await
            } else {
                store.lookup_artifact(&key).await
            };
            assert_eq!(found.unwrap(), None);
            assert_eq!(rows(), 0);
        }
        store.add_artifact(&key, &id).await.unwrap();
        assert_eq!(store.lookup_artifact(&key).await.unwrap(), Some(id));
    }

    #[test]
    fn concurrent_opens_and_writers_of_one_blob_agree() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("store");
        let barrier = Arc::new(Barrier::new(2));
        let payload = b"concurrent-artifact-content";
        let writers: Vec<_> = (0..2)
            .map(|_| {
                let (root, barrier) = (root.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let store = Store::open(&root).unwrap();
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .unwrap();
                    rt.block_on(store.put_bytes(payload)).unwrap()
                })
            })
            .collect();
        for writer in writers {
            assert_eq!(writer.join().unwrap(), BlobId::from_bytes(payload));
        }
        let store = Store::open(&root).unwrap();
        let path = store.get_path(&BlobId::from_bytes(payload));
        assert_eq!(std::fs::read(path).unwrap(), payload);
    }
}
