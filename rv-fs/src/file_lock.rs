use std::fs::{File, TryLockError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;

/// Takes an exclusive advisory lock on `file`, waiting until `deadline`.
/// Returns `TryLockError::WouldBlock` when another holder still has the lock
/// at the deadline, so a wedged holder surfaces as a timeout instead of
/// hanging the caller. A free lock is taken at once, even if `deadline` has
/// passed.
///
/// A held lock is waited for by a blocking lock call in a helper thread, so
/// the waiter wakes as soon as the holder releases. On success `file` is
/// replaced by the handle that holds the lock, so unlocking `file` releases
/// it on every platform. When the deadline passes first, the helper releases
/// the lock as soon as it gets it; until then it stays blocked in the kernel.
/// On Unix the helper's handle is a duplicate and shares `file`'s lock, so
/// retry with a new handle, not with `file`. On Windows a duplicate shares
/// the file object, and a blocked `LockFileEx` stalls reads and writes of
/// every handle to that object, so the helper reopens the file.
pub fn lock_exclusive_until(file: &mut File, deadline: Instant) -> Result<(), TryLockError> {
    match file.try_lock() {
        Err(TryLockError::WouldBlock) => {}
        result => return result,
    }
    let waiter = handle_for_wait(file).map_err(TryLockError::Error)?;
    let state = Arc::new((Mutex::new(Wait::Pending), Condvar::new()));
    let helper_state = Arc::clone(&state);
    thread::Builder::new()
        .name("raeva-file-lock".to_string())
        .spawn(move || {
            let result = waiter.lock();
            let (lock, ready) = &*helper_state;
            let mut wait = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match (&*wait, result) {
                (Wait::Abandoned, Ok(())) => {
                    let _ = waiter.unlock();
                }
                (Wait::Abandoned, Err(_)) => {}
                (_, Ok(())) => *wait = Wait::Locked(waiter),
                (_, Err(err)) => *wait = Wait::Failed(err),
            }
            ready.notify_all();
        })
        .map_err(TryLockError::Error)?;

    let (lock, ready) = &*state;
    let mut wait = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    loop {
        match std::mem::replace(&mut *wait, Wait::Pending) {
            Wait::Locked(holder) => {
                *file = holder;
                return Ok(());
            }
            Wait::Failed(err) => return Err(TryLockError::Error(err)),
            Wait::Pending | Wait::Abandoned => {}
        }
        let now = Instant::now();
        if now >= deadline {
            *wait = Wait::Abandoned;
            return Err(TryLockError::WouldBlock);
        }
        wait = ready
            .wait_timeout(wait, deadline - now)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0;
    }
}

enum Wait {
    Pending,
    Locked(File),
    Failed(std::io::Error),
    Abandoned,
}

fn handle_for_wait(file: &File) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        reopen_for_lock(file)
    }
    #[cfg(not(windows))]
    {
        file.try_clone()
    }
}

/// A new file object for the same file. `File::try_clone` shares the object
/// a `LockFileEx` blocks on, which also blocks the caller's later read.
#[cfg(windows)]
#[allow(unsafe_code)]
fn reopen_for_lock(file: &File) -> std::io::Result<File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
    };

    // SAFETY: `file` stays open for the call. A non-null handle other than
    // `INVALID_HANDLE_VALUE` is owned by the caller and becomes the `File`
    // returned below.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the handle was just opened by `ReOpenFile` and is not invalid,
    // so this `File` owns it.
    Ok(unsafe { File::from(OwnedHandle::from_raw_handle(handle)) })
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions, TryLockError};
    use std::time::{Duration, Instant};

    use super::lock_exclusive_until;

    fn open(path: &std::path::Path) -> File {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        options.open(path).unwrap()
    }

    #[test]
    fn waits_for_the_holder_until_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.lock");
        let holder = open(&path);
        holder.lock().unwrap();
        let mut contender = open(&path);
        let result =
            lock_exclusive_until(&mut contender, Instant::now() + Duration::from_millis(30));
        assert!(matches!(result, Err(TryLockError::WouldBlock)));

        // The abandoned waiter must not keep the lock once the holder lets
        // go, and a waiter wakes as soon as it does.
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            holder.unlock().unwrap();
        });
        let start = Instant::now();
        let mut contender = open(&path);
        lock_exclusive_until(&mut contender, start + Duration::from_secs(10)).unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
        release.join().unwrap();
        assert!(matches!(
            open(&path).try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        contender.unlock().unwrap();
        lock_exclusive_until(&mut open(&path), Instant::now()).unwrap();
    }
}
