//! When published blobs reach the disk.
//!
//! A blob is published without an fsync: its bytes go to a temporary file,
//! which is linked under its content hash. [`Durability::make_durable`] runs
//! before every index write and syncs, in one batch from several threads,
//! every blob registered so far: its file, then each directory from its
//! shard up to the blob root. Concurrent callers share a batch; one that
//! arrives during a batch waits on a condition variable.
//!
//! Crash safety rests on two facts. First, an index row is written only
//! after the blob file it names and the directory entries leading to it are
//! durable, so after a crash no row names a blob the crash lost or tore. An
//! index write also registers the blobs it found rather than wrote, and the
//! whole directory chain is synced, since another process may have
//! published them without a sync. The lockfile is written after the rows of
//! everything it pins. Second, a blob without a row may be torn or missing
//! after a crash, which is harmless: a writer that finds a file present
//! hashes it before reusing it and replaces a corrupt one, and readers reach
//! a blob through a row or check it against the lockfile pin.
//!
//! A failed sync fails every later durability claim of this process, and
//! the blobs it published in that batch are unlinked: their bytes may never
//! reach the disk while staying readable from the page cache, and another
//! process's later fsync need not report the error.
//!
//! On Linux 5.8 and later a large batch on ext4, XFS, Btrfs or F2FS is one
//! `syncfs(2)` instead. From 5.8 the kernel reports a writeback error to
//! `syncfs` on a descriptor opened before the error, and this one is opened
//! with the store, before any blob is written. Older kernels and other
//! filesystems (FUSE, overlayfs) keep the per-path syncs.
//!
//! Windows cannot fsync a directory, so there each blob file is synced
//! before it is published and the queue stays empty.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};

use crate::error::{Result, StoreError};
use crate::pin::file_stamp;

/// The most blobs that wait for a sync. A writer that registers one more
/// syncs the batch itself, so a long run of writes without an index row
/// does not pile up unsynced work.
const MAX_PENDING: usize = 256;

const SYNC_THREADS: usize = 16;

/// The fewest paths a batch syncs with one `syncfs` rather than one by one.
#[cfg(target_os = "linux")]
const SYNCFS_MIN_PATHS: usize = 32;

#[derive(Default)]
pub(crate) struct Durability {
    state: Mutex<State>,
    batch_done: Condvar,
    #[cfg(target_os = "linux")]
    filesystem: Option<File>,
}

#[derive(Default)]
struct State {
    /// Blob files to sync, registered after the last batch began.
    files: Vec<Pending>,
    dirs: BTreeSet<PathBuf>,
    registered: u64,
    /// Every blob registered up to this count is durable.
    synced: u64,
    /// File identities, the batch tickets that make them durable, and
    /// whether this process wrote the file from bytes it hashed. A
    /// replacement at the same path must not inherit the old file's ticket.
    stamps: HashMap<PathBuf, (String, u64, bool)>,
    syncing: bool,
    failed: Option<String>,
}

struct Pending {
    path: PathBuf,
    /// This process published the file, rather than found it in the store.
    created: bool,
}

impl Durability {
    pub(crate) fn for_blob_root(blob_root: &Path) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                filesystem: syncfs_reports_errors()
                    .then(|| File::open(blob_root).ok())
                    .flatten()
                    .filter(syncfs_covers_filesystem),
                ..Self::default()
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = blob_root;
            Self::default()
        }
    }

    /// Queue `blob`, a blob file under `blob_root` that this process
    /// published (`created`) or found in the store, for the next batch and
    /// return the count [`Self::make_durable`] waits for. A found file that
    /// is unchanged since it was queued keeps its count and is not synced
    /// again.
    pub(crate) fn register(&self, blob_root: &Path, blob: &Path, created: bool) -> Result<u64> {
        let stamp = crate::store::open_unfollowed_regular(blob)
            .ok()
            .flatten()
            .and_then(|file| {
                file.metadata()
                    .ok()
                    .and_then(|meta| file_stamp(&file, &meta))
            });
        let mut state = self.lock();
        if !created
            && let Some(stamp) = &stamp
            && let Some((known, ticket, _)) = state.stamps.get(blob)
            && known == stamp
        {
            return Ok(*ticket);
        }
        if cfg!(unix) {
            state.files.push(Pending {
                path: blob.to_path_buf(),
                created,
            });
            let mut dir = blob.parent();
            while let Some(d) = dir {
                state.dirs.insert(d.to_path_buf());
                if d == blob_root {
                    break;
                }
                dir = d.parent();
            }
        }
        state.registered += 1;
        let ticket = state.registered;
        if let Some(stamp) = stamp {
            let hashed = created
                || (state.stamps.get(blob))
                    .is_some_and(|(known, _, hashed)| *hashed && *known == stamp);
            state
                .stamps
                .insert(blob.to_path_buf(), (stamp, ticket, hashed));
        }
        let full = state.files.len() >= MAX_PENDING;
        drop(state);
        if full {
            self.make_durable(ticket)?;
        }
        Ok(ticket)
    }

    pub(crate) fn is_durable(&self, blob: &Path, stamp: &str) -> bool {
        let state = self.lock();
        state.failed.is_none()
            && state
                .stamps
                .get(blob)
                .is_some_and(|(checked, ticket, _)| checked == stamp && *ticket <= state.synced)
    }

    /// The identity of `blob` when this process wrote it from bytes it
    /// hashed and a successful batch covered it, so a later check of the
    /// unchanged file need not hash it again.
    pub(crate) fn hashed_stamp(&self, blob: &Path) -> Option<String> {
        let state = self.lock();
        let (stamp, ticket, hashed) = state.stamps.get(blob)?;
        (state.failed.is_none() && *hashed && *ticket <= state.synced).then(|| stamp.clone())
    }

    #[cfg(test)]
    pub(crate) fn synced(&self) -> u64 {
        self.lock().synced
    }

    pub(crate) fn registered(&self) -> u64 {
        self.lock().registered
    }

    pub(crate) fn make_durable(&self, ticket: u64) -> Result<()> {
        let mut state = self.lock();
        loop {
            if let Some(error) = &state.failed {
                return Err(StoreError::IoError(std::io::Error::other(format!(
                    "failed to make published blobs durable: {error}"
                ))));
            }
            if state.synced >= ticket {
                return Ok(());
            }
            if state.syncing {
                state = self
                    .batch_done
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                continue;
            }
            let files = std::mem::take(&mut state.files);
            let dirs = std::mem::take(&mut state.dirs);
            let upto = state.registered;
            state.syncing = true;
            drop(state);

            let result = self.sync_batch(&files, &dirs);
            if result.is_err() {
                for pending in files.iter().filter(|pending| pending.created) {
                    let _ = std::fs::remove_file(&pending.path);
                }
            }

            state = self.lock();
            state.syncing = false;
            match result {
                Ok(()) => state.synced = upto,
                Err(error) => state.failed = Some(error),
            }
            self.batch_done.notify_all();
        }
    }

    fn sync_batch(
        &self,
        files: &[Pending],
        dirs: &BTreeSet<PathBuf>,
    ) -> std::result::Result<(), String> {
        #[cfg(target_os = "linux")]
        if let Some(filesystem) = &self.filesystem
            && files.len() + dirs.len() >= SYNCFS_MIN_PATHS
        {
            return rustix::fs::syncfs(filesystem)
                .map_err(|err| format!("failed to sync the store's filesystem: {err}"));
        }
        sync_all(files, dirs)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        crate::store::lock(&self.state)
    }
}

/// Whether this kernel reports writeback errors to `syncfs`, which Linux
/// does from 5.8.
#[cfg(target_os = "linux")]
fn syncfs_reports_errors() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .is_ok_and(|release| release_reports_syncfs_errors(&release))
}

#[cfg(target_os = "linux")]
fn syncfs_covers_filesystem(filesystem: &File) -> bool {
    const EXT4: u32 = 0xEF53;
    const XFS: u32 = 0x5846_5342;
    const BTRFS: u32 = 0x9123_683E;
    const F2FS: u32 = 0xF2F5_2010;
    rustix::fs::fstatfs(filesystem).is_ok_and(|stat| {
        // `f_type` is signed on some targets; the magic numbers are 32 bits.
        #[allow(clippy::unnecessary_cast)]
        let magic = stat.f_type as u32;
        [EXT4, XFS, BTRFS, F2FS].contains(&magic)
    })
}

#[cfg(target_os = "linux")]
fn release_reports_syncfs_errors(release: &str) -> bool {
    let mut parts = release
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .map(|part| part.parse::<u32>().ok());
    match (parts.next().flatten(), parts.next().flatten()) {
        (Some(major), Some(minor)) => (major, minor) >= (5, 8),
        _ => false,
    }
}

/// Sync `files`, then `dirs`, each set from up to [`SYNC_THREADS`] threads.
/// The files go first so a directory entry is never synced ahead of the
/// data it names; on Linux either order is safe, elsewhere it may not be.
fn sync_all(files: &[Pending], dirs: &BTreeSet<PathBuf>) -> std::result::Result<(), String> {
    let dirs: Vec<&PathBuf> = dirs.iter().collect();
    let files: Vec<&PathBuf> = files.iter().map(|pending| &pending.path).collect();
    sync_parallel(&files, SyncKind::File)?;
    sync_parallel(&dirs, SyncKind::Dir)
}

#[derive(Clone, Copy)]
enum SyncKind {
    File,
    Dir,
}

fn sync_parallel(paths: &[&PathBuf], kind: SyncKind) -> std::result::Result<(), String> {
    if paths.is_empty() {
        return Ok(());
    }
    let threads = paths.len().min(SYNC_THREADS);
    let chunk = paths.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let workers: Vec<_> = paths
            .chunks(chunk)
            .map(|part| scope.spawn(move || part.iter().try_for_each(|path| sync_one(path, kind))))
            .collect();
        workers.into_iter().try_for_each(|worker| {
            worker
                .join()
                .unwrap_or_else(|_| Err("sync thread panicked".to_string()))
        })
    })
}

fn sync_one(path: &Path, kind: SyncKind) -> std::result::Result<(), String> {
    let file = match kind {
        // Do not follow a symlink swapped in for a blob: fsync the store
        // file, or skip if it is gone or is not a regular file.
        SyncKind::File => match crate::store::open_unfollowed_regular(path) {
            Ok(Some(file)) => file,
            Ok(None) => return Ok(()),
            Err(err) => return Err(format!("failed to open {}: {err}", path.display())),
        },
        SyncKind::Dir => match File::open(path) {
            Ok(file) => file,
            Err(err) => return Err(format!("failed to open {}: {err}", path.display())),
        },
    };
    let synced = match kind {
        SyncKind::File => file.sync_data(),
        SyncKind::Dir => file.sync_all(),
    };
    synced.map_err(|err| format!("failed to fsync {}: {err}", path.display()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::Durability;
    use std::sync::Arc;

    /// Concurrent callers share batches, large enough for `syncfs` where the
    /// filesystem allows it, and every one returns once its blob is synced.
    #[test]
    fn concurrent_callers_share_batches_and_all_return() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("blobs");
        std::fs::create_dir_all(&root).expect("root");
        for durability in [Durability::default(), Durability::for_blob_root(&root)] {
            let durability = Arc::new(durability);
            let threads: Vec<_> = (0..40)
                .map(|i| {
                    let (root, durability) = (root.clone(), Arc::clone(&durability));
                    std::thread::spawn(move || {
                        let leaf = root.join(format!("{:02x}", i % 4)).join("00");
                        std::fs::create_dir_all(&leaf).expect("dirs");
                        let blob = leaf.join(format!("blob{i}"));
                        std::fs::write(&blob, b"bytes").expect("write");
                        let ticket = durability.register(&root, &blob, true).expect("register");
                        durability.make_durable(ticket).expect("durable");
                    })
                })
                .collect();
            threads.into_iter().for_each(|t| t.join().expect("thread"));
            let state = durability.lock();
            assert_eq!(state.synced, 40);
            assert!(state.files.is_empty() && state.dirs.is_empty());
        }
    }

    /// A found blob that is unchanged since it was queued is not queued or
    /// synced again; a changed one is.
    #[test]
    fn an_unchanged_found_blob_is_synced_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("blobs");
        std::fs::create_dir_all(&root).expect("root");
        let blob = root.join("blob");
        std::fs::write(&blob, b"bytes").expect("write");
        let durability = Durability::default();
        let ticket = durability.register(&root, &blob, false).expect("register");
        assert_eq!(
            durability.register(&root, &blob, false).expect("again"),
            ticket
        );
        assert_eq!(durability.lock().files.len(), 1);
        durability.make_durable(ticket).expect("durable");
        assert_eq!(
            durability.register(&root, &blob, false).expect("synced"),
            ticket
        );
        assert!(durability.lock().files.is_empty());

        std::fs::remove_file(&blob).expect("remove");
        std::fs::write(&blob, b"other bytes").expect("rewrite");
        let changed = durability.register(&root, &blob, false).expect("changed");
        assert!(changed > ticket);
        assert_eq!(durability.lock().files.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syncfs_is_used_from_linux_5_8() {
        for (release, reports) in [
            ("5.8.0\n", true),
            ("6.1.0-13-amd64", true),
            ("5.7.19", false),
            ("4.19.0-27-amd64", false),
            ("garbage", false),
        ] {
            assert_eq!(
                super::release_reports_syncfs_errors(release),
                reports,
                "{release}"
            );
        }
    }

    #[test]
    fn a_failed_batch_fails_later_callers_and_unlinks_what_it_published() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("blobs");
        let shard = root.join("cc");
        std::fs::create_dir_all(&shard).expect("dirs");
        let published = shard.join("published");
        let found = shard.join("found");
        std::fs::write(&published, b"bytes").expect("write");
        std::fs::write(&found, b"bytes").expect("write");
        let durability = Durability::default();
        durability
            .register(&root, &published, true)
            .expect("register");
        durability.register(&root, &found, false).expect("register");
        // A shard directory that does not exist fails the batch.
        let ticket = durability
            .register(&root, &root.join("aa").join("bb").join("blob"), true)
            .expect("register");
        assert!(durability.make_durable(ticket).is_err());
        assert!(durability.make_durable(durability.registered()).is_err());
        assert!(
            !published.exists(),
            "a blob this process published is unlinked"
        );
        assert!(found.exists(), "a blob found in the store is left alone");
    }
}
