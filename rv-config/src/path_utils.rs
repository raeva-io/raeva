//! Filesystem path helpers shared across crates.
//!
//! These utilities deal with resolving user-supplied paths to absolute,
//! symlink-aware locations without requiring the path to exist yet.

use std::path::{Path, PathBuf};

use crate::error::ConfigError;

/// Resolve `path` to an absolute, symlink-resolved form even when the path
/// does not (yet) exist on disk. The deepest existing ancestor is
/// canonicalized; any remaining components are appended lexically.
///
/// This is the building block for containment checks: callers can compare
/// a not-yet-created destination against an existing root while still
/// refusing symlinked ancestors that escape the root (a symlinked
/// ancestor canonicalizes to its real target, so a subsequent
/// `starts_with` check will fail).
///
/// Returns an error only if the path is relative and the current working
/// directory cannot be read.
pub fn canonicalize_existing_prefix(path: &Path) -> Result<PathBuf, ConfigError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let cwd = std::env::current_dir().map_err(ConfigError::Io)?;
        cwd.join(path)
    };

    let mut existing: Option<PathBuf> = None;
    let mut remainder: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cursor: &Path = &absolute;
    loop {
        if cursor.exists() {
            existing = Some(cursor.to_path_buf());
            break;
        }
        match (cursor.parent(), cursor.file_name()) {
            (Some(parent), Some(name)) => {
                remainder.push(name);
                cursor = parent;
            }
            // Walked to the root without finding anything that exists.
            _ => break,
        }
    }

    let base = match existing {
        // `dunce::canonicalize` strips the `\\?\` UNC prefix that
        // `std::fs::canonicalize` adds on Windows, preventing
        // `path.starts_with(other)` containment checks from failing when
        // one side has the prefix and the other does not.
        Some(p) => dunce::canonicalize(&p).unwrap_or(p),
        None => absolute.clone(),
    };

    let mut result = base;
    // `remainder` was collected from leaf to root; reverse to glue back on.
    for name in remainder.into_iter().rev() {
        result.push(name);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::canonicalize_existing_prefix;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn absolute_existing_path_is_canonicalized() {
        let dir = TempDir::new().unwrap();
        // Use dunce here too so the reference value never carries the \\?\ prefix.
        let real = dunce::canonicalize(dir.path()).unwrap();
        let resolved = canonicalize_existing_prefix(dir.path()).unwrap();
        assert_eq!(resolved, real);
    }

    #[test]
    fn nonexistent_descendant_is_appended_lexically() {
        let dir = TempDir::new().unwrap();
        let real = dunce::canonicalize(dir.path()).unwrap();
        let target = dir.path().join("does/not/exist");
        let resolved = canonicalize_existing_prefix(&target).unwrap();
        assert_eq!(resolved, real.join("does/not/exist"));
    }

    #[test]
    fn relative_path_is_absolutized_against_cwd() {
        // Use a relative path that doesn't exist; the function should still
        // produce an absolute path rooted at the current cwd.
        let cwd = std::env::current_dir().unwrap();
        let resolved = canonicalize_existing_prefix(std::path::Path::new(
            "__rv_config_path_utils_no_such_dir__",
        ))
        .unwrap();
        assert!(resolved.is_absolute());
        // The first component should be inside cwd (possibly canonicalized).
        let canonical_cwd =
            dunce::canonicalize(&cwd).unwrap_or_else(|_| fs::canonicalize(&cwd).unwrap_or(cwd));
        assert!(resolved.starts_with(canonical_cwd));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ancestor_is_resolved_to_real_target() {
        use std::os::unix::fs::symlink;
        let outer = TempDir::new().unwrap();
        let real_root = outer.path().join("real_root");
        fs::create_dir(&real_root).unwrap();
        let link = outer.path().join("link_root");
        symlink(&real_root, &link).unwrap();

        let resolved = canonicalize_existing_prefix(&link.join("child")).unwrap();
        let expected_root = fs::canonicalize(&real_root).unwrap();
        assert_eq!(resolved, expected_root.join("child"));
    }
}
