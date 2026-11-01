use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rv_fs::lock_exclusive_until;
use sha2::Digest as _;

/// An exclusive advisory lock on a guard file under the user cache
/// directory, named by a hash of the canonical project root. Two concurrent
/// `raeva sync` runs that resolve disjoint platform sets would otherwise
/// read-modify-write `raeva.lock` in a last-writer-wins race; holding this guard
/// around the full read-resolve-write sequence serializes them. Only runs
/// with the same cache directory share the guard: one with another
/// `RAEVA_HOME` or `XDG_CACHE_HOME` does not wait.
///
/// Dropping the guard closes the file, which releases the lock. The file is
/// never removed: a contender that opened it before an unlink could still
/// take the lock on the old inode while a later arrival locks a new one, and
/// both would be inside the critical section at once.
#[derive(Debug)]
pub struct LockfileGuard {
    _file: File,
}

impl LockfileGuard {
    /// Acquire the guard for `raeva.lock` in `project_root`, with the guard file
    /// under `lock_root` (the user cache dir), waiting at most `timeout`. A
    /// wedged holder surfaces as `io::ErrorKind::TimedOut`. `on_wait` runs
    /// once, before the wait, when another process holds the guard.
    pub fn acquire(
        lock_root: &Path,
        project_root: &Path,
        timeout: Duration,
        on_wait: impl FnOnce(),
    ) -> io::Result<Self> {
        let path = guard_path(lock_root, project_root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => return Ok(Self { _file: file }),
            Err(fs::TryLockError::WouldBlock) => on_wait(),
            Err(fs::TryLockError::Error(err)) => return Err(err),
        }
        match lock_exclusive_until(&mut file, Instant::now() + timeout) {
            Ok(()) => Ok(Self { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out waiting for lockfile guard at {} after {timeout:?}; another \
                     `raeva sync` of this project is still running",
                    path.display()
                ),
            )),
            Err(fs::TryLockError::Error(err)) => Err(err),
        }
    }

    /// [`Self::acquire`] on the blocking pool, so the executor is not pinned
    /// during contention.
    pub async fn acquire_async(
        lock_root: &Path,
        project_root: &Path,
        timeout: Duration,
        on_wait: impl FnOnce() + Send + 'static,
    ) -> io::Result<Self> {
        let lock_root = lock_root.to_path_buf();
        let project_root = project_root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            Self::acquire(&lock_root, &project_root, timeout, on_wait)
        })
        .await
        .map_err(|e| io::Error::other(format!("lockfile-guard acquire task panicked: {e}")))?
    }
}

/// `lock_root/locks/<sha256 of the canonical project root>.lock`, so the
/// syncs of one checkout that share a cache directory contend on one file
/// outside the working tree.
fn guard_path(lock_root: &Path, project_root: &Path) -> PathBuf {
    let canonical =
        dunce::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    let digest = hex::encode(sha2::Sha256::digest(canonical.to_string_lossy().as_bytes()));
    lock_root.join("locks").join(format!("{digest}.lock"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{LockfileGuard, guard_path};

    #[test]
    fn the_guard_excludes_a_second_holder_and_lives_outside_the_project() {
        let cache = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let waits = std::cell::Cell::new(0);
        let acquire = |timeout| {
            LockfileGuard::acquire(cache.path(), project.path(), timeout, || {
                waits.set(waits.get() + 1);
            })
        };

        let held = acquire(Duration::from_secs(1)).unwrap();
        let path = guard_path(cache.path(), project.path());
        assert!(path.starts_with(cache.path()) && path.exists());
        assert!(std::fs::read_dir(project.path()).unwrap().next().is_none());
        assert_eq!(waits.get(), 0, "a free guard is taken without a wait");
        let err = acquire(Duration::from_millis(150)).expect_err("held");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(waits.get(), 1, "a held guard is announced once");

        drop(held);
        assert!(path.exists(), "the guard file is never removed");
        // The timed-out acquire left a thread blocked on the lock, which takes
        // it after the drop and lets go at once, so this acquire may wait for
        // it.
        acquire(Duration::from_secs(10)).expect("free after drop");
    }
}
