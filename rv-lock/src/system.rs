//! System-scoped files as raeva.lock records them.
//!
//! A `system`-scope dependency names a file by `<systemPath>` instead of
//! coming from a repository. raeva.lock records such a file only when it lies
//! inside the directory that holds raeva.lock, by its path relative to that
//! directory and the SHA-256 of its bytes, so the lock means the same in
//! every checkout and `raeva sync --frozen` notices when the file changes.
//!
//! A resolver that keeps a system-scoped node emits, for its module package
//! row: `scope = Scope::System`, the direct scope the module declares it
//! with (`None` when it is only reached transitively), no
//! `workspace_module`, the [`SystemFile`] that [`SystemFile::record`]
//! returns for the interpolated `<systemPath>` as `system_path` and
//! `system_sha256`, and no artifact row. A `<systemPath>` that `record`
//! refuses is a project error: the dependency cannot be locked. A direct
//! `system` declaration that a range elsewhere moves to another version is
//! that version's repository artifact, with `direct_scope` and `scope`
//! still `system`, as Maven keeps the declared scope.

use std::io;
use std::path::{Component, Path, PathBuf};

use rv_maven_types::Sha256;

use crate::error::printable;

/// Longest recorded path accepted, in bytes.
const MAX_SYSTEM_PATH_LEN: usize = 4096;

/// A system-scoped file: its path relative to the directory that holds
/// raeva.lock, with `/` separators, and the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SystemFile {
    /// The path relative to the directory that holds raeva.lock.
    pub path: String,
    /// The SHA-256 of the file's bytes.
    pub sha256: Sha256,
}

/// Why a `<systemPath>` cannot be recorded in raeva.lock.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SystemPathError {
    /// Maven requires an absolute `<systemPath>` after interpolation.
    #[error("systemPath {} is not an absolute path", shown(.path))]
    NotAbsolute {
        /// The `<systemPath>` as given.
        path: PathBuf,
    },
    /// The file or the lock directory could not be read.
    #[error("cannot read systemPath {}: {source}", shown(.path))]
    Unreadable {
        /// The `<systemPath>` or the lock directory, whichever failed.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The path names a directory or another non-file.
    #[error("systemPath {} is not a regular file", shown(.path))]
    NotAFile {
        /// The `<systemPath>` as given.
        path: PathBuf,
    },
    /// The file, after following links, is outside the directory that holds
    /// raeva.lock.
    #[error(
        "systemPath {} is outside the project; raeva.lock records only system files inside the \
         directory that holds it",
        shown(.path)
    )]
    OutsideProject {
        /// The `<systemPath>` as given.
        path: PathBuf,
    },
    /// The relative path has a part raeva.lock cannot hold, such as a `:` or a
    /// control character.
    #[error("systemPath {} cannot be recorded in raeva.lock: {reason}", shown(.path))]
    NotRecordable {
        /// The `<systemPath>` as given.
        path: PathBuf,
        /// Which rule the relative path breaks.
        reason: &'static str,
    },
}

fn shown(path: &Path) -> String {
    printable(&path.display().to_string())
}

impl SystemFile {
    /// Record the file an interpolated `<systemPath>` names, for the lock in
    /// `lock_root`.
    ///
    /// Both paths are resolved through links first, so a link inside the
    /// project that points outside it is refused like the outside path
    /// itself.
    pub fn record(lock_root: &Path, system_path: &Path) -> Result<Self, SystemPathError> {
        if !system_path.is_absolute() {
            return Err(SystemPathError::NotAbsolute {
                path: system_path.to_path_buf(),
            });
        }
        let unreadable = |path: &Path| {
            let path = path.to_path_buf();
            move |source| SystemPathError::Unreadable { path, source }
        };
        let root = dunce::canonicalize(lock_root).map_err(unreadable(lock_root))?;
        let file = dunce::canonicalize(system_path).map_err(unreadable(system_path))?;
        if !std::fs::metadata(&file)
            .map_err(unreadable(system_path))?
            .is_file()
        {
            return Err(SystemPathError::NotAFile {
                path: system_path.to_path_buf(),
            });
        }
        let relative = file
            .strip_prefix(&root)
            .map_err(|_| SystemPathError::OutsideProject {
                path: system_path.to_path_buf(),
            })?;
        let mut parts = Vec::new();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                return Err(SystemPathError::OutsideProject {
                    path: system_path.to_path_buf(),
                });
            };
            let Some(part) = part.to_str() else {
                return Err(SystemPathError::NotRecordable {
                    path: system_path.to_path_buf(),
                    reason: "a part of the path is not valid UTF-8",
                });
            };
            parts.push(part);
        }
        let path = parts.join("/");
        if let Err(reason) = check_system_path(&path) {
            return Err(SystemPathError::NotRecordable {
                path: system_path.to_path_buf(),
                reason,
            });
        }
        let sha256 = Sha256::from_file(&file).map_err(unreadable(system_path))?;
        Ok(Self { path, sha256 })
    }
}

/// Whether `path` is a `system_path` raeva.lock can hold: a normalized relative
/// path with `/` separators, no empty, `.` or `..` part, no `\` or `:`, and
/// no control or invisible characters. The reason when it is not.
pub(crate) fn check_system_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("the path is empty");
    }
    if path.len() > MAX_SYSTEM_PATH_LEN {
        return Err("the path is longer than 4096 bytes");
    }
    if !rv_maven_types::is_terminal_safe(path) {
        return Err("the path contains control or invisible characters");
    }
    if path.contains('\\') || path.contains(':') {
        return Err("the path contains '\\' or ':'");
    }
    if path.starts_with('/') {
        return Err("the path is absolute");
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("the path has an empty, '.' or '..' part");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_a_file_inside_the_project_by_relative_path_and_digest() {
        let project = tempfile::tempdir().unwrap();
        let lib = project.path().join("lib");
        std::fs::create_dir(&lib).unwrap();
        std::fs::write(lib.join("vendor.jar"), b"jar bytes").unwrap();
        let recorded = SystemFile::record(project.path(), &lib.join("vendor.jar")).unwrap();
        assert_eq!(recorded.path, "lib/vendor.jar");
        assert_eq!(recorded.sha256, Sha256::from_bytes(b"jar bytes"));
        // `${project.basedir}/../x` is resolved before the containment check.
        let dotted = lib.join("..").join("lib").join("vendor.jar");
        assert_eq!(
            SystemFile::record(project.path(), &dotted).unwrap(),
            recorded
        );
    }

    #[test]
    fn refuses_relative_missing_outside_and_directory_paths() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("x.jar"), b"x").unwrap();
        std::fs::create_dir(project.path().join("dir")).unwrap();
        let record = |path: &Path| SystemFile::record(project.path(), path);
        assert!(matches!(
            record(Path::new("lib/x.jar")),
            Err(SystemPathError::NotAbsolute { .. })
        ));
        assert!(matches!(
            record(&project.path().join("missing.jar")),
            Err(SystemPathError::Unreadable { .. })
        ));
        assert!(matches!(
            record(&outside.path().join("x.jar")),
            Err(SystemPathError::OutsideProject { .. })
        ));
        assert!(matches!(
            record(&project.path().join("dir")),
            Err(SystemPathError::NotAFile { .. })
        ));
        #[cfg(unix)]
        {
            let link = project.path().join("x.jar");
            std::os::unix::fs::symlink(outside.path().join("x.jar"), &link).unwrap();
            assert!(matches!(
                record(&link),
                Err(SystemPathError::OutsideProject { .. })
            ));
        }
    }

    #[test]
    fn recorded_paths_are_normalized_and_relative() {
        assert!(check_system_path("lib/vendor-1.0.jar").is_ok());
        for bad in [
            "",
            "/opt/vendor.jar",
            "lib//x.jar",
            "./x.jar",
            "lib/../x.jar",
            "C:/x.jar",
            "lib\\x.jar",
            "lib/x\u{202e}.jar",
            "lib/x\n.jar",
        ] {
            assert!(check_system_path(bad).is_err(), "{bad:?}");
        }
        assert!(check_system_path(&"a".repeat(4097)).is_err());
    }
}
