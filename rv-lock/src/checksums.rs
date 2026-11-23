//! Which locked files were accepted without a checksum file.

use std::collections::{BTreeMap, HashMap};

use rv_maven_types::Digest;

use crate::lock::{LockPlatform, Lockfile};
use crate::pinned::PinnedFile;

impl Lockfile {
    /// Set the missing-checksum markers of every row from `admitted`, the
    /// files this run admitted by repository path (`true` when a checksum
    /// file verified them, `false` when the repository published none). A
    /// file this run did not admit that way, as a lock pin or a `file:`
    /// repository admits it, keeps the marker `previous` gives the same
    /// bytes at the same path.
    pub fn mark_missing_checksums(
        &mut self,
        admitted: &HashMap<String, bool>,
        previous: Option<&Lockfile>,
    ) {
        let carried = previous
            .map(Lockfile::missing_checksum_files)
            .unwrap_or_default();
        let marked = |path: String, pin: Option<Digest>| match admitted.get(&path) {
            Some(verified) => !verified,
            None => pin.is_some_and(|pin| carried.get(&path) == Some(&pin)),
        };
        for platform in &mut self.platforms {
            for artifact in &mut platform.artifacts {
                artifact.missing_checksum =
                    marked(artifact.repository_path(), artifact.pin().cloned());
                artifact.pom_missing_checksum = (artifact.pom_sha256.clone())
                    .is_some_and(|pom| marked(artifact.pom_path(), Some(Digest::Sha256(pom))));
            }
            for (coord, pin) in &mut platform.support_poms {
                pin.missing_checksum = pin
                    .repository_path(coord)
                    .is_some_and(|path| marked(path, Some(Digest::Sha256(pin.sha256.clone()))));
            }
        }
    }

    /// The files a row marks as accepted without a checksum file, by
    /// repository path, with the pin of each.
    pub fn missing_checksum_files(&self) -> BTreeMap<String, Digest> {
        (self.platforms.iter())
            .flat_map(LockPlatform::pinned_files)
            .filter(PinnedFile::missing_checksum)
            .map(|file| (file.path(), file.pin))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::test_lock::linux_lock;

    /// A file this run admitted takes the marker its admission gives; one a
    /// pin admitted keeps the previous marker only for the same bytes.
    #[test]
    fn markers_follow_this_run_and_carry_for_pinned_bytes() {
        let mut lock = linux_lock("1.0", 'a');
        let jar = lock.platforms[0].artifacts[0].repository_path();
        lock.mark_missing_checksums(&HashMap::from([(jar.clone(), false)]), None);
        assert!(lock.platforms[0].artifacts[0].missing_checksum);
        assert_eq!(
            lock.missing_checksum_files().keys().collect::<Vec<_>>(),
            [&jar]
        );
        let previous = lock.clone();

        let mut pinned = linux_lock("1.0", 'a');
        pinned.mark_missing_checksums(&HashMap::new(), Some(&previous));
        assert!(pinned.platforms[0].artifacts[0].missing_checksum);
        let mut other_bytes = linux_lock("1.0", 'b');
        other_bytes.mark_missing_checksums(&HashMap::new(), Some(&previous));
        assert!(!other_bytes.platforms[0].artifacts[0].missing_checksum);
        let mut verified = linux_lock("1.0", 'a');
        verified.mark_missing_checksums(&HashMap::from([(jar, true)]), Some(&previous));
        assert!(!verified.platforms[0].artifacts[0].missing_checksum);
        assert!(verified.missing_checksum_files().is_empty());
    }
}
