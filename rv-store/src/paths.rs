use std::path::{Path, PathBuf};

use crate::BlobId;

pub(crate) const BLOBS_DIR: &str = "blobs";

pub(crate) fn blob_root(root: &Path) -> PathBuf {
    root.join(BLOBS_DIR)
}

pub(crate) fn blob_path(id: &BlobId) -> PathBuf {
    let hash = id.as_str();
    let (first, rest) = hash.split_at(2);
    let (second, _) = rest.split_at(2);
    PathBuf::from(BLOBS_DIR).join(first).join(second).join(hash)
}
