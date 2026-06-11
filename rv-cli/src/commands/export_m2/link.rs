use std::fs;
use std::path::{Path, PathBuf};

use strum::Display;
use tracing::debug;

use super::error::LinkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[strum(serialize_all = "lowercase")]
pub enum LinkStrategy {
    Hardlink,
    Symlink,
    Copy,
}

pub(super) fn try_hardlink(src: &Path, dest: &Path) -> Result<(), LinkError> {
    fs::hard_link(src, dest).map_err(|err| link_error(LinkStrategy::Hardlink, src, dest, err))
}

pub(super) fn try_symlink(src: &Path, dest: &Path) -> Result<(), LinkError> {
    // Use relative symlink for portability (works if store/m2 are moved together)
    let relative_src = compute_relative_path(src, dest).unwrap_or_else(|| src.to_path_buf());

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&relative_src, dest)
            .map_err(|err| link_error(LinkStrategy::Symlink, src, dest, err))
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(&relative_src, dest)
            .map_err(|err| link_error(LinkStrategy::Symlink, src, dest, err))
    }
}

/// Compute a relative path from dest's parent directory to src. Returns
/// None if the paths cannot be made relative (e.g., different drives on
/// Windows or one path can't be made absolute).
///
/// Uses std::path::absolute to resolve without requiring existence, so the
/// destination directory does not need to be created yet (common during
/// initial export).
fn compute_relative_path(src: &Path, dest: &Path) -> Option<PathBuf> {
    let src_abs = std::path::absolute(src).ok()?;
    let dest_parent_abs = std::path::absolute(dest.parent()?).ok()?;
    pathdiff::diff_paths(&src_abs, &dest_parent_abs)
}

pub(super) fn copy_file(src: &Path, dest: &Path) -> Result<(), LinkError> {
    fs::copy(src, dest)
        .map(|_| ())
        .map_err(|err| link_error(LinkStrategy::Copy, src, dest, err))?;
    // Persist the destination contents to disk before the caller renames it
    // into place. Without this, `fs::copy` followed by `fs::rename` is not
    // crash-safe: the rename can be durable while the data is still in the
    // page cache. Also reassert the source mtime on dest: fs::copy preserves
    // it on Linux/macOS but not on Windows, and Maven keys some freshness
    // checks off mtime.
    if let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(dest) {
        if let Ok(src_mtime) = fs::metadata(src).and_then(|m| m.modified())
            && let Err(err) = file.set_modified(src_mtime)
        {
            debug!(
                path = %dest.display(),
                error = %err,
                "failed to copy source mtime onto destination"
            );
        }
        if let Err(err) = file.sync_all() {
            debug!(
                path = %dest.display(),
                error = %err,
                "failed to sync copied artifact before rename"
            );
        }
    }
    Ok(())
}

pub(super) fn link_with_fallback(
    src: &Path,
    dest: &Path,
    strategy: LinkStrategy,
) -> Result<LinkStrategy, LinkError> {
    // Detect a vanished source up front. Without this, `symlink` would happily
    // produce a dangling link and `copy` can race with the unlink to leave a
    // zero-byte destination on some Linux configurations. Surfacing
    // `SourceMissing` lets the caller map it to the existing "missing blob"
    // error path instead of falling through to fallbacks that mask the
    // problem.
    match fs::symlink_metadata(src) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(LinkError::SourceMissing {
                src: src.to_path_buf(),
            });
        }
        Err(err) => {
            // Other metadata errors (permission denied, etc.) are surfaced as
            // a regular IoError tagged with the requested strategy so the
            // caller still gets actionable context.
            return Err(link_error(strategy, src, dest, err));
        }
    }

    let mut last_error = None;
    for attempt in fallback_order(strategy) {
        let result = match attempt {
            LinkStrategy::Hardlink => try_hardlink(src, dest),
            LinkStrategy::Symlink => try_symlink(src, dest),
            LinkStrategy::Copy => copy_file(src, dest),
        };

        match result {
            Ok(()) => return Ok(*attempt),
            Err(err) => {
                debug!(strategy = %attempt, error = %err, "link attempt failed");
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        link_error(
            strategy,
            src,
            dest,
            std::io::Error::other("link attempts exhausted"),
        )
    }))
}

fn link_error(strategy: LinkStrategy, src: &Path, dest: &Path, err: std::io::Error) -> LinkError {
    LinkError::IoError {
        strategy,
        src: src.to_path_buf(),
        dest: dest.to_path_buf(),
        source: err,
    }
}

fn fallback_order(strategy: LinkStrategy) -> &'static [LinkStrategy] {
    const HARDLINK_FALLBACK: [LinkStrategy; 3] = [
        LinkStrategy::Hardlink,
        LinkStrategy::Symlink,
        LinkStrategy::Copy,
    ];
    const SYMLINK_FALLBACK: [LinkStrategy; 2] = [LinkStrategy::Symlink, LinkStrategy::Copy];
    const COPY_FALLBACK: [LinkStrategy; 1] = [LinkStrategy::Copy];

    match strategy {
        LinkStrategy::Hardlink => &HARDLINK_FALLBACK,
        LinkStrategy::Symlink => &SYMLINK_FALLBACK,
        LinkStrategy::Copy => &COPY_FALLBACK,
    }
}

#[cfg(test)]
mod tests {
    use super::super::error::LinkError;
    use super::{LinkStrategy, compute_relative_path, copy_file, link_with_fallback, try_symlink};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn link_with_fallback_returns_source_missing_when_src_absent() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("does-not-exist");
        let dest = dir.path().join("dest.txt");

        let err = link_with_fallback(&src, &dest, LinkStrategy::Hardlink).expect_err("should fail");
        match &err {
            LinkError::SourceMissing { src: reported } => {
                assert_eq!(reported, &src);
            }
            other => panic!("expected SourceMissing, got {:?}", other),
        }
        // Critically, no destination file (zero-byte or otherwise) was created.
        assert!(
            !dest.exists(),
            "destination must not exist after SourceMissing"
        );
        // And no dangling symlink either.
        assert!(
            fs::symlink_metadata(&dest).is_err(),
            "no symlink should be left behind"
        );
    }

    #[test]
    fn link_with_fallback_does_not_create_dest_after_src_removed() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        let dest1 = dir.path().join("dest1.bin");
        let dest2 = dir.path().join("dest2.bin");
        fs::write(&src, b"payload").expect("write src");

        // First link succeeds.
        link_with_fallback(&src, &dest1, LinkStrategy::Copy).expect("first link");
        assert!(dest1.exists());

        // Simulate a concurrent removal of the CAS source.
        fs::remove_file(&src).expect("remove src");

        // Second call must NOT silently create a dangling/zero-byte file.
        let err =
            link_with_fallback(&src, &dest2, LinkStrategy::Hardlink).expect_err("should fail");
        assert!(matches!(err, LinkError::SourceMissing { .. }));
        assert!(
            !dest2.exists(),
            "no zero-byte destination must be created when src vanished"
        );
    }

    #[cfg(unix)]
    #[test]
    fn link_with_fallback_symlink_strategy_does_not_create_dangling_link() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("ghost.bin");
        let dest = dir.path().join("link.bin");

        // Without the up-front existence check, `symlink` would happily create
        // a link pointing at a non-existent target. Confirm we refuse instead.
        let err = link_with_fallback(&src, &dest, LinkStrategy::Symlink).expect_err("should fail");
        assert!(matches!(err, LinkError::SourceMissing { .. }));
        assert!(fs::symlink_metadata(&dest).is_err());
    }

    #[test]
    fn copy_file_copies_contents() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dest.txt");
        fs::write(&src, b"content").expect("write");

        copy_file(&src, &dest).expect("copy");
        let bytes = fs::read(&dest).expect("read");
        assert_eq!(bytes, b"content");
    }

    #[test]
    fn link_with_fallback_uses_copy_when_selected() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dest.txt");
        fs::write(&src, b"content").expect("write");

        let used = link_with_fallback(&src, &dest, LinkStrategy::Copy).expect("link");
        assert_eq!(used, LinkStrategy::Copy);
        let bytes = fs::read(&dest).expect("read");
        assert_eq!(bytes, b"content");
    }

    #[test]
    fn compute_relative_path_same_dir() {
        let dir = tempdir().expect("tempdir");
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dest.txt");
        fs::write(&src, b"content").expect("write");

        let relative = compute_relative_path(&src, &dest).expect("relative path");
        assert_eq!(relative.to_str().unwrap(), "src.txt");
    }

    #[test]
    fn compute_relative_path_different_dirs() {
        let dir = tempdir().expect("tempdir");
        let src_dir = dir.path().join("store");
        let dest_dir = dir.path().join("m2").join("repo");
        fs::create_dir_all(&src_dir).expect("create src dir");
        fs::create_dir_all(&dest_dir).expect("create dest dir");

        let src = src_dir.join("blob.txt");
        let dest = dest_dir.join("artifact.jar");
        fs::write(&src, b"content").expect("write");

        let relative = compute_relative_path(&src, &dest).expect("relative path");
        // Should be something like "../../store/blob.txt"
        assert!(relative.to_str().unwrap().contains(".."));
        assert!(relative.to_str().unwrap().contains("store"));
    }

    #[test]
    fn compute_relative_path_nonexistent_dest_parent() {
        let dir = tempdir().expect("tempdir");
        let src_dir = dir.path().join("store");
        fs::create_dir_all(&src_dir).expect("create src dir");

        let src = src_dir.join("blob.txt");
        fs::write(&src, b"content").expect("write");

        // dest_dir does NOT exist - this is the key scenario for initial export
        let dest = dir.path().join("m2").join("repo").join("artifact.jar");

        let relative = compute_relative_path(&src, &dest).expect("relative path");
        assert!(relative.to_str().unwrap().contains(".."));
        assert!(relative.to_str().unwrap().contains("store"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_creates_relative_link() {
        let dir = tempdir().expect("tempdir");
        let src_dir = dir.path().join("store");
        let dest_dir = dir.path().join("m2");
        fs::create_dir_all(&src_dir).expect("create src dir");
        fs::create_dir_all(&dest_dir).expect("create dest dir");

        let src = src_dir.join("blob.txt");
        let dest = dest_dir.join("link.txt");
        fs::write(&src, b"content").expect("write");

        try_symlink(&src, &dest).expect("symlink");

        // Verify the symlink works
        let content = fs::read(&dest).expect("read via symlink");
        assert_eq!(content, b"content");

        // Verify the symlink target is relative
        let link_target = fs::read_link(&dest).expect("read link");
        assert!(
            !link_target.is_absolute(),
            "symlink should be relative: {:?}",
            link_target
        );
    }
}
