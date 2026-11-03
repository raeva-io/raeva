//! Writing a stream into the store only after its bytes pass the checks the
//! caller names.

use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use rv_maven_types::{ArtifactCoord, BlobId, Digest, HashAlgorithm, Sha1};
use sha2::Digest as _;
use tempfile::NamedTempFile;
use tokio::fs as tokio_fs;
use tokio::io::AsyncWriteExt;

use crate::error::{IoResultExt, StoreError};
use crate::index;
use crate::store::{
    Store, TMP_DIR, blocking, is_regular_file, publish_blob, root_shared, set_blob_readonly,
};

/// The checksums a stream's bytes must match before they enter the store.
#[derive(Debug, Clone, Copy, Default)]
pub struct Expect<'a> {
    /// The checksum the repository published next to the file.
    pub sidecar: Option<&'a Digest>,
    /// The checksum raeva.lock pins.
    pub pin: Option<&'a Digest>,
}

impl Expect<'_> {
    fn needs_sha1(&self) -> bool {
        [self.sidecar, self.pin]
            .into_iter()
            .flatten()
            .any(|digest| digest.algorithm() == HashAlgorithm::Sha1)
    }
}

/// Which of the [`Expect`] checksums the bytes failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// [`Expect::sidecar`].
    Sidecar,
    /// [`Expect::pin`].
    Pin,
}

/// Why [`Store::put_stream_verified`] stored nothing.
#[derive(Debug)]
pub enum PutError<E> {
    /// The stream yielded an error.
    Stream(E),
    /// The bytes do not hash to an expected checksum. The sidecar is
    /// checked first.
    Mismatch {
        /// The checksum that failed.
        against: Expectation,
        /// Its value.
        expected: Digest,
        /// The bytes' digest with the same algorithm.
        actual: Digest,
    },
    /// The store failed.
    Store(StoreError),
}

impl<E> From<StoreError> for PutError<E> {
    fn from(err: StoreError) -> Self {
        PutError::Store(err)
    }
}

/// Bytes that passed their checks and are in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verified {
    /// The blob id, the SHA-256 of the bytes.
    pub blob: BlobId,
    /// The number of bytes.
    pub size: u64,
}

/// Bytes written to a private temporary file by [`Store::stage_stream`],
/// not yet checked or published. Dropping it deletes the file. It holds no
/// open descriptor, so any number can wait.
#[derive(Debug)]
pub struct Staged {
    temp_path: tempfile::TempPath,
    blob: BlobId,
    sha1: Option<Sha1>,
    size: u64,
}

impl Staged {
    /// The number of bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The blob id, the SHA-256 of the bytes.
    pub fn blob(&self) -> &BlobId {
        &self.blob
    }
}

impl Store {
    /// Stream `stream` into the store, hashing as it is written to a private
    /// temporary file. Only bytes that match every checksum in `expect` are
    /// published under their blob id and, with `index`, recorded under that
    /// coordinate once the blob is durable. Failing bytes never reach the blob
    /// directory or the index, so no other process can see or reuse them.
    pub async fn put_stream_verified<S, E>(
        &self,
        stream: S,
        expect: Expect<'_>,
        index: Option<&ArtifactCoord>,
    ) -> Result<Verified, PutError<E>>
    where
        S: Stream<Item = Result<Bytes, E>>,
    {
        let staged = self.stage_stream(stream, expect.needs_sha1()).await?;
        self.publish_staged(staged, expect, index).await
    }

    /// Write `stream` to a private temporary file, hashing it with SHA-256
    /// and, with `sha1`, SHA-1, so the checks [`Self::publish_staged`] makes
    /// can be decided while the bytes arrive.
    pub async fn stage_stream<S, E>(&self, stream: S, sha1: bool) -> Result<Staged, PutError<E>>
    where
        S: Stream<Item = Result<Bytes, E>>,
    {
        let tmp_dir = self.root.join(TMP_DIR);
        tokio_fs::create_dir_all(&tmp_dir)
            .await
            .io_context(|| format!("failed to create temp directory {}", tmp_dir.display()))?;
        let temp_file = blocking(move || {
            NamedTempFile::new_in(&tmp_dir).io_context(|| "failed to create temp file".to_string())
        })
        .await?;
        let (std_file, temp_path) = temp_file.into_parts();
        let mut file = tokio_fs::File::from_std(std_file);

        let mut sha256 = sha2::Sha256::new();
        let mut sha1 = sha1.then(sha1::Sha1::new);
        let mut size = 0u64;
        futures_util::pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(PutError::Stream)?;
            sha256.update(&chunk);
            if let Some(sha1) = sha1.as_mut() {
                sha1.update(&chunk);
            }
            size += chunk.len() as u64;
            file.write_all(&chunk)
                .await
                .io_context(|| "failed to write blob chunk".to_string())?;
        }
        file.flush()
            .await
            .io_context(|| "failed to write blob".to_string())?;
        // Where the file must be synced before it is published, the handle
        // that can is this one. Tokio syncs it on the blocking pool, so a
        // slow sync does not hold an async worker.
        if cfg!(not(unix)) {
            file.sync_all()
                .await
                .io_context(|| "failed to sync blob".to_string())?;
        }
        // Closed before it is published, which Windows needs to rename it.
        drop(file.into_std().await);

        let blob =
            BlobId::from_str(&hex::encode(sha256.finalize())).map_err(StoreError::InvalidBlobId)?;
        let sha1 = sha1
            .map(|sha1| Sha1::from_str(&hex::encode(sha1.finalize())))
            .transpose()
            .map_err(StoreError::InvalidBlobId)?;
        Ok(Staged {
            temp_path,
            blob,
            sha1,
            size,
        })
    }

    /// Publish staged bytes if they match every checksum in `expect`, and
    /// with `index` record them under that coordinate once the blob is
    /// durable, as [`Self::put_stream_verified`] does.
    pub async fn publish_staged<E>(
        &self,
        staged: Staged,
        expect: Expect<'_>,
        index: Option<&ArtifactCoord>,
    ) -> Result<Verified, PutError<E>> {
        let Staged {
            temp_path,
            blob,
            sha1,
            size,
        } = staged;
        // The pin decides first, so bytes that differ from raeva.lock are
        // reported as that, whatever their checksum file says.
        let checks = [
            (Expectation::Pin, expect.pin),
            (Expectation::Sidecar, expect.sidecar),
        ];
        for (against, expected) in checks {
            let Some(expected) = expected else { continue };
            let actual = match (expected.algorithm(), &sha1) {
                (HashAlgorithm::Sha256, _) => Digest::Sha256(blob.clone()),
                (HashAlgorithm::Sha1, Some(sha1)) => Digest::Sha1(sha1.clone()),
                // An algorithm not hashed while staging, such as the MD5 of
                // a rare `.md5`-only sidecar, is hashed from the file.
                (algorithm, _) => {
                    let path = temp_path.to_path_buf();
                    blocking(move || {
                        Digest::of_file(algorithm, &path)
                            .io_context(|| format!("failed to hash {}", path.display()))
                    })
                    .await?
                }
            };
            if &actual != expected {
                // Dropping the path deletes the temporary copy.
                return Err(PutError::Mismatch {
                    against,
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        set_blob_readonly(&temp_path);
        let root = self.root.clone();
        let pool = Arc::clone(&self.pool);
        let key = index.cloned();
        let id = blob.clone();
        blocking(move || {
            let (ticket, _) = publish_blob(&root, temp_path, &id)?;
            let Some(key) = key else {
                return Ok(());
            };
            // A blob that is not durable must not gain an index row.
            root_shared(&root).durability.make_durable(ticket)?;
            pool.write_locked(|conn| {
                // Another writer may have replaced or removed the file since
                // it was published; index only a regular file.
                let target = root.join(crate::paths::blob_path(&id));
                if !is_regular_file(&target) {
                    return Err(StoreError::IntegrityError(format!(
                        "refusing to index {key} -> {id}: blob file {} is gone",
                        target.display()
                    )));
                }
                index::add_artifact(conn, &key, &id)?;
                crate::store::record_hashed_stamp(conn, &root, &id)
            })
        })
        .await?;
        Ok(Verified { blob, size })
    }
}
