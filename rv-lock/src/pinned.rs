//! The files raeva.lock pins, walked one way for every reader: each
//! artifact row's file, the companion POM it pins, and each support POM.

use std::collections::{BTreeMap, BTreeSet};

use rv_maven_types::{ArtifactCoord, Digest};

use crate::lock::{LockArtifact, LockPlatform, Lockfile, SupportPom};
use crate::plugins::PluginFiles;

/// The row a [`PinnedFile`] comes from.
#[derive(Clone, Copy, Debug)]
pub enum PinnedRow<'a> {
    /// An artifact row's own file.
    File(&'a LockArtifact),
    /// The companion POM an artifact row pins.
    Pom(&'a LockArtifact),
    /// A parent or imported BOM, by its `group:artifact:version`.
    Support(&'a str, &'a SupportPom),
}

/// One file a row pins.
#[derive(Clone, Debug)]
pub struct PinnedFile<'a> {
    /// The file, with the timestamped version of a snapshot build.
    pub key: ArtifactCoord,
    /// The checksum its bytes must match.
    pub pin: Digest,
    /// The origins the row records as serving it, first the one it was
    /// fetched from.
    pub origins: Vec<&'a str>,
    /// Where the lock records it.
    pub row: PinnedRow<'a>,
}

impl PinnedFile<'_> {
    /// The file below a Maven repository root.
    pub fn path(&self) -> String {
        match self.row {
            PinnedRow::File(artifact) => artifact.repository_path(),
            PinnedRow::Pom(artifact) => artifact.pom_path(),
            PinnedRow::Support(coord, pin) => (pin.repository_path(coord))
                .expect("a pinned support POM's coordinate is group:artifact:version"),
        }
    }

    /// Whether the row records the file as accepted without a checksum
    /// file.
    pub fn missing_checksum(&self) -> bool {
        match self.row {
            PinnedRow::File(artifact) => artifact.missing_checksum,
            PinnedRow::Pom(artifact) => artifact.pom_missing_checksum,
            PinnedRow::Support(_, pin) => pin.missing_checksum,
        }
    }
}

/// Each file of `files`, once by file and pin, with the origins of every
/// row that pins it.
pub type PinnedFiles<'a> = BTreeMap<(ArtifactCoord, Digest), BTreeSet<&'a str>>;

/// `files` as [`PinnedFiles`]: platforms share most rows.
pub fn pinned_once<'a>(files: impl IntoIterator<Item = PinnedFile<'a>>) -> PinnedFiles<'a> {
    let mut once = PinnedFiles::new();
    for file in files {
        (once.entry((file.key, file.pin)).or_default()).extend(file.origins);
    }
    once
}

fn rows<'a>(
    artifacts: &'a [LockArtifact],
    support_poms: &'a BTreeMap<String, SupportPom>,
) -> impl Iterator<Item = PinnedFile<'a>> {
    let artifacts = artifacts.iter().flat_map(|artifact| {
        let file = artifact.pin().map(|pin| PinnedFile {
            key: artifact.coord(),
            pin: pin.clone(),
            origins: artifact.file_origins().collect(),
            row: PinnedRow::File(artifact),
        });
        let pom = artifact.pom_sha256.as_ref().map(|pom| PinnedFile {
            key: ArtifactCoord::of(artifact.pom_gav(), "pom", None),
            pin: Digest::Sha256(pom.clone()),
            origins: artifact.pom_origins().collect(),
            row: PinnedRow::Pom(artifact),
        });
        file.into_iter().chain(pom)
    });
    // The codec refuses a support POM coordinate that is not
    // `group:artifact:version`, so none is left out.
    let support = support_poms.iter().filter_map(|(coord, pin)| {
        Some(PinnedFile {
            key: ArtifactCoord::of(pin.file_gav(coord)?, "pom", None),
            pin: Digest::Sha256(pin.sha256.clone()),
            origins: vec![pin.repo_url.as_str()],
            row: PinnedRow::Support(coord, pin),
        })
    });
    artifacts.chain(support)
}

impl LockPlatform {
    /// Each file this platform's rows pin, as often as rows pin it.
    pub fn pinned_files(&self) -> impl Iterator<Item = PinnedFile<'_>> {
        rows(&self.artifacts, &self.support_poms)
    }
}

impl PluginFiles {
    /// Each file the plugin sets' rows pin.
    pub fn pinned_files(&self) -> impl Iterator<Item = PinnedFile<'_>> {
        rows(&self.artifacts, &self.poms)
    }
}

impl Lockfile {
    /// Each file any platform pins, once, with the origins every row
    /// records for it.
    pub fn pinned_files(&self) -> PinnedFiles<'_> {
        pinned_once(self.platforms.iter().flat_map(LockPlatform::pinned_files))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_lock::{linux_lock, platform, set_support_pom};

    /// A row's file, its companion POM and a support POM, each with its
    /// own origins; a second platform with the same rows adds none.
    #[test]
    fn walks_each_file_once_with_its_origins() {
        let mut lock = linux_lock("1.0", 'a');
        set_support_pom(&mut lock, "com.example:parent:2", 'b');
        let row = &mut lock.platforms[0].artifacts[0];
        row.pom_repo_urls = vec!["https://poms.example/".to_string()];
        let mut other = lock.platforms[0].clone();
        other.platform = platform("macos-aarch64");
        lock.platforms.push(other);
        let walked: Vec<_> = (lock.platforms[0].pinned_files())
            .map(|file| (file.path(), file.origins))
            .collect();
        assert_eq!(
            walked,
            [
                (
                    "com/example/a/1.0/a-1.0.jar".to_string(),
                    vec!["https://repo.example/"]
                ),
                (
                    "com/example/a/1.0/a-1.0.pom".to_string(),
                    vec!["https://poms.example/"]
                ),
                (
                    "com/example/parent/2/parent-2.pom".to_string(),
                    vec!["https://repo.example/"]
                ),
            ]
        );
        assert_eq!(lock.pinned_files().len(), 3);
    }
}
