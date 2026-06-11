//! Disk-space sanity check for the store volume.

use std::path::Path;

/// Warn-only floor for free space on the store volume; not a hard stop. Chosen
/// to roughly accommodate a single large transitive closure (e.g. Spring Boot
/// starters) so the user sees a hint before downloads start failing.
pub(super) const MIN_DISK_SPACE_BYTES: u64 = 100 * 1024 * 1024;

pub(super) fn check_disk_space(store_path: &Path) {
    match fs2::available_space(store_path) {
        Ok(available) if available < MIN_DISK_SPACE_BYTES => {
            // 1 MiB = 1024 * 1024 bytes.
            let available_mb = available / (1024 * 1024);
            tracing::warn!(
                available_mb,
                path = %store_path.display(),
                "low disk space on store volume ({available_mb} MB free); downloads may fail"
            );
        }
        Ok(_) => {}
        Err(err) => {
            tracing::debug!(
                error = %err,
                path = %store_path.display(),
                "unable to check available disk space"
            );
        }
    }
}
