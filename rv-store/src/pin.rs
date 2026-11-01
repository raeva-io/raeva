use std::fs::{File, Metadata};
use std::io;

use rv_maven_types::{ArtifactCoord, BlobId, Digest};

use crate::error::{DbResultExt, IoResultExt, Result};
use crate::index;
use crate::store::{Store, open_regular_file, root_shared};

/// How a stored blob compares with a checksum pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    /// The file hashes to the pin.
    Match,
    /// The store has no file for the blob.
    Missing,
    /// The file hashes to `actual` (lowercase hex) instead of the pin.
    Mismatch {
        /// The file's digest with the pin's algorithm.
        actual: String,
    },
}

/// A blob that hashed to its id but is not yet known durable. Its checked
/// stamp is recorded by [`Store::record_checks_async`], which syncs it first.
#[derive(Debug)]
pub struct QueuedCheck {
    blob: BlobId,
    stamp: String,
    ticket: u64,
}

/// What the index records for a blob matching a pin under a coordinate.
#[derive(Debug, Default)]
pub struct StoredFor {
    /// Whether the index names the blob for the coordinate.
    pub indexed: bool,
    /// [`Store::served_by`] for the coordinate and the blob.
    pub served_by: Vec<(String, String)>,
}

/// What the store holds for a blob id.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StoredBlob {
    Missing,
    Intact,
    Other(BlobId),
}

impl Store {
    /// Re-hashes the stored file for `blob` with the pin's algorithm and
    /// compares the digest with the pin. Reading the file, rather than
    /// comparing `blob` itself, also catches a file changed on disk after it
    /// was stored. A mismatch invalidates its cached check so a subsequent
    /// repair cannot reuse a stamp that full verification proved stale.
    pub fn check_pin(&self, blob: &BlobId, pin: &Digest) -> Result<PinCheck> {
        let path = self.get_path(blob);
        let Some(file) = open_regular_file(&path)? else {
            return Ok(PinCheck::Missing);
        };
        let hashed =
            Digest::of_reader(pin.algorithm(), file).map(|digest| digest.hex().to_string());
        let actual = match hashed {
            Ok(actual) => actual,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(PinCheck::Missing),
            Err(err) => {
                return Err(err).io_context(|| format!("failed to hash blob {}", path.display()));
            }
        };
        if actual == pin.hex() {
            Ok(PinCheck::Match)
        } else {
            self.pool
                .run(|conn| index::clear_checked_stamp(conn, blob))?;
            Ok(PinCheck::Mismatch { actual })
        }
    }

    /// [`Store::check_pin`] on the blocking pool, so hashing a large file
    /// does not hold up an async worker.
    pub async fn check_pin_async(&self, blob: &BlobId, pin: &Digest) -> Result<PinCheck> {
        let store = self.clone();
        let (blob, pin) = (blob.clone(), pin.clone());
        crate::store::blocking(move || store.check_pin(&blob, &pin)).await
    }

    /// [`Store::check_pin`] for a SHA-256 pin, without reading a file
    /// unchanged since it last hashed to `blob`: the pin is then compared
    /// with `blob`. A matching SHA-256 blob is made durable before its
    /// checked stamp is recorded, so an unchanged match also proves durability.
    pub fn check_pin_unless_unchanged(&self, blob: &BlobId, pin: &Digest) -> Result<PinCheck> {
        let (check, queued) = self.check_pin_queued(blob, pin)?;
        self.record_checks(queued.into_iter().collect())?;
        Ok(check)
    }

    /// [`Store::check_pin_queued_async`] on the calling thread.
    fn check_pin_queued(
        &self,
        blob: &BlobId,
        pin: &Digest,
    ) -> Result<(PinCheck, Option<QueuedCheck>)> {
        let Digest::Sha256(pinned) = pin else {
            return Ok((self.check_pin(blob, pin)?, None));
        };
        let (stored, queued) = self.stored_blob_queued(blob)?;
        Ok((
            match stored {
                StoredBlob::Missing => PinCheck::Missing,
                StoredBlob::Other(actual) => PinCheck::Mismatch {
                    actual: actual.to_string(),
                },
                StoredBlob::Intact if pinned == blob => PinCheck::Match,
                StoredBlob::Intact => PinCheck::Mismatch {
                    actual: blob.to_string(),
                },
            },
            queued,
        ))
    }

    /// [`Store::record_checks_async`] on the calling thread.
    fn record_checks(&self, checks: Vec<QueuedCheck>) -> Result<()> {
        let Some(ticket) = checks.iter().map(|check| check.ticket).max() else {
            return Ok(());
        };
        root_shared(&self.root).durability.make_durable(ticket)?;
        self.pool.run(|conn| {
            let tx = conn
                .transaction()
                .db_context(|| "failed to begin the blob check transaction")?;
            for check in &checks {
                index::set_checked_stamp(&tx, &check.blob, &check.stamp)?;
            }
            tx.commit()
                .db_context(|| "failed to commit the blob check transaction")
        })
    }

    /// Whether the file for `blob` hashes to `blob`. A file whose size,
    /// timestamps and identity are those it had when it last did is not read
    /// again. A write to the file changes them; a change that keeps them,
    /// such as bit rot, is left to [`Store::check_pin`].
    pub(crate) fn stored_blob(&self, blob: &BlobId) -> Result<StoredBlob> {
        let (stored, queued) = self.stored_blob_queued(blob)?;
        self.record_checks(queued.into_iter().collect())?;
        Ok(stored)
    }

    /// [`Store::stored_blob`] with the sync and checked stamp of a file it
    /// hashed left to [`Store::record_checks`].
    fn stored_blob_queued(&self, blob: &BlobId) -> Result<(StoredBlob, Option<QueuedCheck>)> {
        let path = self.get_path(blob);
        let Some(file) = open_regular_file(&path)? else {
            return Ok((StoredBlob::Missing, None));
        };
        let meta = file
            .metadata()
            .io_context(|| format!("failed to stat blob {}", path.display()))?;
        let stamp = file_stamp(&file, &meta);
        if stamp.is_some() && self.pool.run(|conn| index::checked_stamp(conn, blob))? == stamp {
            return Ok((StoredBlob::Intact, None));
        }
        let actual = BlobId::from_reader(file)
            .io_context(|| format!("failed to hash blob {}", path.display()))?;
        if actual != *blob {
            return Ok((StoredBlob::Other(actual), None));
        }
        let durability = &root_shared(&self.root).durability;
        let blob_root = crate::paths::blob_root(&self.root);
        let Some(stamp) = stamp else {
            // Without a stamp nothing is recorded; the file is still synced.
            durability.make_durable(durability.register(&blob_root, &path, false)?)?;
            return Ok((StoredBlob::Intact, None));
        };
        if durability.is_durable(&path, &stamp) {
            self.pool
                .run(|conn| index::set_checked_stamp(conn, blob, &stamp))?;
            return Ok((StoredBlob::Intact, None));
        }
        let ticket = durability.register(&blob_root, &path, false)?;
        let queued = QueuedCheck {
            blob: blob.clone(),
            stamp,
            ticket,
        };
        Ok((StoredBlob::Intact, Some(queued)))
    }

    /// [`Store::check_pin_unless_unchanged`] on the blocking pool.
    pub async fn check_pin_unless_unchanged_async(
        &self,
        blob: &BlobId,
        pin: &Digest,
    ) -> Result<PinCheck> {
        let store = self.clone();
        let (blob, pin) = (blob.clone(), pin.clone());
        crate::store::blocking(move || store.check_pin_unless_unchanged(&blob, &pin)).await
    }

    /// [`Store::check_pin_unless_unchanged`] on the blocking pool and, on a
    /// match, [`Store::served_by`] for `key` in the same task.
    pub async fn check_served_pin_async(
        &self,
        blob: &BlobId,
        pin: &Digest,
        key: &ArtifactCoord,
    ) -> Result<(PinCheck, Vec<(String, String)>)> {
        let store = self.clone();
        let (blob, pin, key) = (blob.clone(), pin.clone(), key.clone());
        crate::store::blocking(move || {
            let check = store.check_pin_unless_unchanged(&blob, &pin)?;
            let served_by = match check {
                PinCheck::Match => store.pool.run(|conn| index::served_by(conn, &key, &blob))?,
                _ => Vec::new(),
            };
            Ok((check, served_by))
        })
        .await
    }

    /// [`Store::check_pin_unless_unchanged`] on the blocking pool, leaving the
    /// sync and the checked stamp of a file it hashed to
    /// [`Store::record_checks_async`], so many checks share one sync. On a
    /// match it also reads, in the same task, whether the index names `blob`
    /// for `key`, and [`Store::served_by`].
    pub async fn check_pin_queued_async(
        &self,
        blob: &BlobId,
        pin: &Digest,
        key: Option<&ArtifactCoord>,
    ) -> Result<(PinCheck, Option<QueuedCheck>, Result<StoredFor>)> {
        let store = self.clone();
        let (blob, pin, key) = (blob.clone(), pin.clone(), key.cloned());
        crate::store::blocking(move || {
            let (check, queued) = store.check_pin_queued(&blob, &pin)?;
            let stored = match (&check, key) {
                (PinCheck::Match, Some(key)) => store.pool.run(|conn| {
                    Ok(StoredFor {
                        indexed: index::lookup_artifact(conn, &key)?.as_ref() == Some(&blob),
                        served_by: index::served_by(conn, &key, &blob)?,
                    })
                }),
                _ => Ok(StoredFor::default()),
            };
            Ok((check, queued, stored))
        })
        .await
    }

    /// Syncs the files of `checks` in one batch, then records their checked
    /// stamps.
    pub async fn record_checks_async(&self, checks: Vec<QueuedCheck>) -> Result<()> {
        let store = self.clone();
        crate::store::blocking(move || store.record_checks(checks)).await
    }
}

#[cfg(unix)]
pub(crate) fn file_stamp(_file: &File, meta: &Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    Some(format!(
        "{} {} {} {}.{} {}.{}",
        meta.dev(),
        meta.ino(),
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec()
    ))
}

/// Includes the NTFS change time, which a write updates and `SetFileTime`
/// cannot restore. `None`, so the file is always hashed, where the file
/// system keeps no change time or file id.
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn file_stamp(file: &File, meta: &Metadata) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FileBasicInfo, FileIdInfo,
        GetFileInformationByHandleEx,
    };

    /// # Safety
    /// `T` must be the struct that `class` fills in.
    unsafe fn query<T: Default>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> Option<T> {
        let mut info = T::default();
        let size = u32::try_from(size_of::<T>()).ok()?;
        // SAFETY: the handle stays open for the call and `info` is a
        // writable buffer of `size` bytes of the type `class` fills in.
        let ok = unsafe {
            GetFileInformationByHandleEx(file.as_raw_handle(), class, (&raw mut info).cast(), size)
        };
        (ok != 0).then_some(info)
    }
    // SAFETY: each class fills in the struct it is read as.
    let basic: FILE_BASIC_INFO = unsafe { query(file, FileBasicInfo) }?;
    let id: FILE_ID_INFO = unsafe { query(file, FileIdInfo) }?;
    (basic.ChangeTime != 0).then(|| {
        format!(
            "{} {} {} {} {} {}",
            id.VolumeSerialNumber,
            hex::encode(id.FileId.Identifier),
            meta.len(),
            basic.CreationTime,
            basic.LastWriteTime,
            basic.ChangeTime
        )
    })
}

#[cfg(test)]
mod tests {
    use rv_maven_types::{BlobId, Digest};

    use super::PinCheck;
    use crate::Store;

    const HELLO_SHA1: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

    #[tokio::test]
    async fn checked_stamps_cover_durable_files_not_replacements() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let blob = store.put_bytes(b"hello").await.unwrap();
        let key = rv_maven_types::ArtifactCoord::new("org.test", "demo", "1", "jar", None);
        store.add_artifact(&key, &blob).await.unwrap();
        let pin = Digest::Sha256(blob.clone());
        let durability = &crate::store::root_shared(&store.root).durability;
        let before = durability.registered();
        let conn = store.pool.conn();
        let checked = crate::index::checked_stamp(&conn, &blob).unwrap();
        assert!(
            checked.is_some(),
            "a blob this process hashed and synced is checked when indexed"
        );

        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &pin).unwrap(),
            PinCheck::Match
        );
        assert_eq!(
            durability.registered(),
            before,
            "a blob synced during resolution needs no second sync"
        );
        assert_eq!(crate::index::checked_stamp(&conn, &blob).unwrap(), checked);

        let path = store.get_path(&blob);
        // Keep the old inode alive so the replacement cannot reuse its id.
        std::fs::rename(&path, dir.path().join("old-blob")).unwrap();
        // Another process publishes identical bytes without syncing them.
        std::fs::write(&path, b"hello").unwrap();
        assert_eq!(
            store.lookup_artifact(&key).await.unwrap(),
            Some(blob.clone())
        );
        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &pin).unwrap(),
            PinCheck::Match
        );
        assert!(
            durability.registered() > before,
            "the replacement must sync"
        );
        assert_eq!(durability.synced(), durability.registered());
        assert_ne!(crate::index::checked_stamp(&conn, &blob).unwrap(), checked);

        let before = durability.registered();
        let observer = rusqlite::Connection::open(dir.path().join("index.sqlite")).unwrap();
        let data_version = || {
            observer
                .pragma_query_value::<i64, _>(None, "data_version", |row| row.get(0))
                .unwrap()
        };
        let version = data_version();
        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &pin).unwrap(),
            PinCheck::Match
        );
        assert_eq!(
            durability.registered(),
            before,
            "unchanged files skip syncing"
        );
        assert_eq!(data_version(), version, "unchanged files skip index writes");
    }

    #[tokio::test]
    async fn full_verification_invalidates_an_unchanged_corrupt_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let blob = store.put_bytes(b"hello").await.unwrap();
        let pin = Digest::Sha256(blob.clone());
        let path = store.get_path(&blob);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"jello").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let stamp = super::file_stamp(&file, &file.metadata().unwrap()).unwrap();
        let conn = store.pool.conn();
        // Simulate bit rot: the corrupt file still has its last checked stamp.
        crate::index::set_checked_stamp(&conn, &blob, &stamp).unwrap();
        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &pin).unwrap(),
            PinCheck::Match
        );
        assert!(matches!(
            store.check_pin(&blob, &pin).unwrap(),
            PinCheck::Mismatch { .. }
        ));
        assert_eq!(crate::index::checked_stamp(&conn, &blob).unwrap(), None);
        assert!(matches!(
            store.check_pin_unless_unchanged(&blob, &pin).unwrap(),
            PinCheck::Mismatch { .. }
        ));
        store.put_bytes(b"hello").await.unwrap();
        assert_eq!(store.check_pin(&blob, &pin).unwrap(), PinCheck::Match);
    }

    #[tokio::test]
    async fn rehashes_the_file_with_the_pins_algorithm() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let blob = store.put_bytes(b"hello").await.unwrap();
        let sha256 = Digest::Sha256(blob.clone());
        let sha1 = Digest::Sha1(HELLO_SHA1.parse().unwrap());
        assert_eq!(store.check_pin(&blob, &sha256).unwrap(), PinCheck::Match);
        assert_eq!(
            store.check_pin_async(&blob, &sha1).await.unwrap(),
            PinCheck::Match
        );
        let zero = Digest::Sha1("0".repeat(40).parse().unwrap());
        let actual = HELLO_SHA1.to_string();
        assert_eq!(
            store.check_pin(&blob, &zero).unwrap(),
            PinCheck::Mismatch { actual }
        );

        // The file is read, not its address trusted.
        let path = store.get_path(&blob);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"tampered").unwrap();
        let actual = BlobId::from_bytes(b"tampered").to_string();
        assert_eq!(
            store.check_pin(&blob, &sha256).unwrap(),
            PinCheck::Mismatch { actual }
        );
        std::fs::remove_file(&path).unwrap();
        assert_eq!(store.check_pin(&blob, &sha256).unwrap(), PinCheck::Missing);
    }

    #[tokio::test]
    async fn rehashes_a_file_rewritten_since_its_last_check() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let blob = store.put_bytes(b"hello").await.unwrap();
        let sha256 = Digest::Sha256(blob.clone());
        for _ in 0..2 {
            assert_eq!(
                store.check_pin_unless_unchanged(&blob, &sha256).unwrap(),
                PinCheck::Match
            );
        }
        let other = Digest::Sha256(BlobId::from_bytes(b"other"));
        let actual = blob.to_string();
        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &other).unwrap(),
            PinCheck::Mismatch { actual }
        );

        let path = store.get_path(&blob);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"tampered").unwrap();
        let actual = BlobId::from_bytes(b"tampered").to_string();
        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &sha256).unwrap(),
            PinCheck::Mismatch { actual }
        );
    }

    #[tokio::test]
    async fn rehashes_a_file_edited_in_place_with_its_times_restored() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let blob = store.put_bytes(b"hello").await.unwrap();
        let sha256 = Digest::Sha256(blob.clone());
        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &sha256).unwrap(),
            PinCheck::Match
        );

        let path = store.get_path(&blob);
        let meta = std::fs::metadata(&path).unwrap();
        let times = std::fs::FileTimes::new().set_modified(meta.modified().unwrap());
        #[cfg(windows)]
        let times = std::os::windows::fs::FileTimesExt::set_created(times, meta.created().unwrap());
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .unwrap();
        // Past the file system's timestamp granularity.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all(b"jello").unwrap();
        file.set_times(times).unwrap();
        drop(file);
        let actual = BlobId::from_bytes(b"jello").to_string();
        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &sha256).unwrap(),
            PinCheck::Mismatch { actual }
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_is_not_a_stored_blob() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let blob = store.put_bytes(b"hello").await.unwrap();
        let pin = Digest::Sha256(blob.clone());
        let path = store.get_path(&blob);
        let real = dir.path().join("real-hello");
        std::fs::copy(&path, &real).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(!store.exists_async(&blob).await);
        assert_eq!(store.check_pin(&blob, &pin).unwrap(), PinCheck::Missing);
        assert_eq!(
            store.check_pin_unless_unchanged(&blob, &pin).unwrap(),
            PinCheck::Missing
        );
        store.put_bytes(b"hello").await.unwrap();
        assert_eq!(store.check_pin(&blob, &pin).unwrap(), PinCheck::Match);
    }

    #[tokio::test]
    async fn queued_checks_share_one_sync_before_their_stamps() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let durability = &crate::store::root_shared(&store.root).durability;
        let conn = store.pool.conn();
        let mut queued = Vec::new();
        for (index, bytes) in [&b"one"[..], b"two"].into_iter().enumerate() {
            let blob = store.put_bytes(bytes).await.unwrap();
            let path = store.get_path(&blob);
            // As restored from a cache: the same bytes in a new file, never
            // synced or checked by this process.
            std::fs::rename(&path, dir.path().join(format!("old-{index}"))).unwrap();
            std::fs::write(&path, bytes).unwrap();
            let pin = Digest::Sha256(blob.clone());
            let (check, check_queued) = store.check_pin_queued(&blob, &pin).unwrap();
            assert_eq!(check, PinCheck::Match);
            queued.push(check_queued.expect("a hashed file waits for its sync"));
            assert_eq!(crate::index::checked_stamp(&conn, &blob).unwrap(), None);
        }
        assert!(durability.synced() < durability.registered());
        let blobs: Vec<_> = queued.iter().map(|check| check.blob.clone()).collect();
        store.record_checks(queued).unwrap();
        assert_eq!(durability.synced(), durability.registered());
        for blob in &blobs {
            assert!(crate::index::checked_stamp(&conn, blob).unwrap().is_some());
        }
    }
}
