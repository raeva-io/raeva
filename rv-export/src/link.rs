use std::fs;
use std::io;
use std::path::Path;

use strum::Display;
use tracing::debug;

use super::error::LinkError;

/// How a blob from the content store is put at its local-repository path.
/// Displays in lowercase (`hardlink`, `symlink`, `copy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[strum(serialize_all = "lowercase")]
pub enum LinkStrategy {
    /// A hard link to the store's file, which shares its inode and its
    /// read-only mode. Falls back to a symbolic link, then a copy.
    Hardlink,
    /// A symbolic link to the store's file, relative where a relative path
    /// can be computed, otherwise to the store path as given. Falls back to
    /// a copy.
    Symlink,
    /// A copy with the store file's modification time, made writable by its
    /// owner. The data is not synced. A failure to set the mode is reported
    /// as [`ExportWarning::PermissionsNotSet`](crate::ExportWarning::PermissionsNotSet),
    /// and a failure to set the time is ignored.
    Copy,
}

fn symlink(src: &Path, dest: &Path) -> io::Result<()> {
    // Relative, so the link survives moving the store and the destination
    // together. The link is resolved from the directory it is in, so both
    // ends are canonical: a `..` step from a directory reached through a
    // symbolic link leaves its real parent, not the one the path names.
    let target = (|| {
        let parent = dunce::canonicalize(dest.parent()?).ok()?;
        pathdiff::diff_paths(dunce::canonicalize(src).ok()?, parent)
    })()
    .unwrap_or_else(|| src.to_path_buf());
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, dest);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(target, dest);
}

fn copy(src: &Path, dest: &Path) -> io::Result<()> {
    // Bytes only: `fs::copy` also copies the store blob's read-only mode and
    // fails where a mode change is refused, such as on a CIFS or
    // root-squashed NFS mount. A new file is writable by its owner; the
    // exporter sets the mode and warns when it cannot.
    let mut from = fs::File::open(src)?;
    let mut to = fs::File::create(dest)?;
    io::copy(&mut from, &mut to)?;
    // Maven keys some freshness checks off the mtime. The data is not
    // synced, as Maven does not sync a download: a later export hashes
    // every copy and reports one a crash left torn.
    if let Err(err) = from
        .metadata()
        .and_then(|meta| to.set_modified(meta.modified()?))
    {
        debug!(error = %err, dest = %dest.display(), "copy keeps its own modification time");
    }
    Ok(())
}

/// Puts `src` at `dest` with `strategy` or the next one down, and returns
/// the strategy that worked.
pub(super) fn link_with_fallback(
    src: &Path,
    dest: &Path,
    strategy: LinkStrategy,
) -> Result<LinkStrategy, LinkError> {
    let io_error = |strategy, source| LinkError::IoError {
        strategy,
        src: src.to_path_buf(),
        dest: dest.to_path_buf(),
        source,
    };
    // A vanished source would otherwise leave a dangling symlink, or a
    // zero-byte copy on some Linux configurations.
    match fs::symlink_metadata(src) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(LinkError::SourceMissing {
                src: src.to_path_buf(),
            });
        }
        Err(err) => return Err(io_error(strategy, err)),
        Ok(_) => {}
    }
    let order: &[LinkStrategy] = match strategy {
        LinkStrategy::Hardlink => &[
            LinkStrategy::Hardlink,
            LinkStrategy::Symlink,
            LinkStrategy::Copy,
        ],
        LinkStrategy::Symlink => &[LinkStrategy::Symlink, LinkStrategy::Copy],
        LinkStrategy::Copy => &[LinkStrategy::Copy],
    };
    let mut last_error = None;
    for &attempt in order {
        let result = match attempt {
            LinkStrategy::Hardlink => fs::hard_link(src, dest),
            LinkStrategy::Symlink => symlink(src, dest),
            LinkStrategy::Copy => copy(src, dest),
        };
        match result {
            Ok(()) => return Ok(attempt),
            Err(err) => {
                debug!(strategy = %attempt, error = %err, "link attempt failed");
                last_error = Some(io_error(attempt, err));
            }
        }
    }
    Err(last_error.expect("every strategy tries at least a copy"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{LinkError, LinkStrategy, link_with_fallback};

    #[test]
    fn a_missing_source_leaves_no_destination() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("ghost.bin");
        for strategy in [
            LinkStrategy::Hardlink,
            LinkStrategy::Symlink,
            LinkStrategy::Copy,
        ] {
            let dest = dir.path().join(strategy.to_string());
            let err = link_with_fallback(&src, &dest, strategy).expect_err("no source");
            assert!(matches!(err, LinkError::SourceMissing { src: ref s } if *s == src));
            assert!(fs::symlink_metadata(&dest).is_err(), "{strategy}");
        }
    }

    #[test]
    fn each_strategy_puts_the_source_bytes_at_the_destination() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("store/blob");
        fs::create_dir_all(src.parent().unwrap()).unwrap();
        fs::write(&src, b"content").unwrap();
        // Windows needs Developer Mode or the symlink privilege, without
        // which the documented fallback copies.
        #[cfg(unix)]
        let can_symlink = true;
        #[cfg(windows)]
        let can_symlink =
            std::os::windows::fs::symlink_file(&src, dir.path().join("probe")).is_ok();
        for strategy in [
            LinkStrategy::Hardlink,
            LinkStrategy::Symlink,
            LinkStrategy::Copy,
        ] {
            // The destination directory does not exist when the link is computed.
            let dest = dir.path().join("m2/repo").join(strategy.to_string());
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            let expected = if strategy == LinkStrategy::Symlink && !can_symlink {
                LinkStrategy::Copy
            } else {
                strategy
            };
            assert_eq!(link_with_fallback(&src, &dest, strategy).unwrap(), expected);
            assert_eq!(fs::read(&dest).unwrap(), b"content");
        }
        // A copy of a read-only blob is writable and carries its
        // modification time over.
        let copied = dir.path().join("m2/repo/copy");
        let blob = fs::metadata(&src).unwrap();
        let mut readonly = blob.permissions();
        readonly.set_readonly(true);
        fs::set_permissions(&src, readonly).unwrap();
        fs::remove_file(&copied).unwrap();
        link_with_fallback(&src, &copied, LinkStrategy::Copy).unwrap();
        assert_eq!(
            fs::metadata(&copied).unwrap().modified().unwrap(),
            blob.modified().unwrap()
        );
        assert!(!fs::metadata(&copied).unwrap().permissions().readonly());
        #[cfg(unix)]
        assert_eq!(
            fs::read_link(dir.path().join("m2/repo/symlink")).unwrap(),
            std::path::Path::new("../../store/blob")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_through_a_linked_directory_resolves() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("store/blob");
        fs::create_dir_all(src.parent().unwrap()).unwrap();
        fs::write(&src, b"content").unwrap();
        let real = dir.path().join("disks/one/m2");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("m2")).unwrap();
        let dest = dir.path().join("m2/blob");
        assert_eq!(
            link_with_fallback(&src, &dest, LinkStrategy::Symlink).unwrap(),
            LinkStrategy::Symlink
        );
        assert_eq!(fs::read(&dest).unwrap(), b"content");
    }
}
