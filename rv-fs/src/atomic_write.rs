use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Who may read a file [`write_file_atomic`] creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewFileAccess {
    /// Owner only (0600 on Unix), for credentials.
    Private,
    /// 0666 masked by the umask on Unix, as `File::create` gives. tempfile
    /// alone would create 0600 files, leaving `raeva.lock`, SBOMs and the files
    /// `raeva export-m2` writes unreadable to the other users of a shared
    /// checkout, `~/.m2` or CI cache.
    Shared,
}

/// Replaces `path` with `contents` so a reader sees the old file or the new
/// one, never a partial write. The bytes go to a temp file in the same
/// directory, which is synced and then renamed over `path`; the directory is
/// synced afterwards on a best-effort basis so the rename survives a power
/// loss. The temp file is removed if any step fails. On Windows the rename
/// replaces an existing file too.
///
/// The parent directory must exist. A path without one is written in the
/// current directory.
pub fn write_file_atomic(path: &Path, contents: &[u8], access: NewFileAccess) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = temp_file_in(parent, access)?;
    temp.as_file_mut().write_all(contents)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|err| err.error)?;
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

/// A temp file in `parent` with the mode `access` gives, removed on drop
/// unless persisted. For writers that stage several files before renaming
/// any of them.
pub fn temp_file_in(parent: &Path, access: NewFileAccess) -> io::Result<tempfile::NamedTempFile> {
    #[cfg(unix)]
    if access == NewFileAccess::Shared {
        use std::os::unix::fs::PermissionsExt;
        return tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o666))
            .tempfile_in(parent)
            .map_err(without_temp_name);
    }
    #[cfg(not(unix))]
    let _ = access;
    // tempfile creates its files with 0600.
    tempfile::NamedTempFile::new_in(parent).map_err(without_temp_name)
}

/// tempfile ends its error with the random name of the file it could not
/// create, which tells the user nothing; callers name the file they write.
fn without_temp_name(err: io::Error) -> io::Error {
    match err.to_string().rsplit_once(" at path ") {
        Some((cause, _)) => io::Error::new(err.kind(), cause),
        None => err,
    }
}

#[cfg(test)]
mod tests {
    use super::{NewFileAccess, write_file_atomic};

    #[test]
    fn replaces_the_file_with_the_mode_of_its_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        std::fs::write(&path, b"old").unwrap();
        write_file_atomic(&path, b"new", NewFileAccess::Shared).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temp file left"
        );
        let orphan = dir.path().join("missing").join("out.txt");
        assert!(write_file_atomic(&orphan, b"new", NewFileAccess::Shared).is_err());
        let err = write_file_atomic(&path.join("out.txt"), b"new", NewFileAccess::Shared)
            .expect_err("a file is not a directory");
        assert!(!err.to_string().contains(".tmp"), "{err}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &std::path::Path| {
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777
            };
            let private = dir.path().join("private");
            write_file_atomic(&private, b"x", NewFileAccess::Private).unwrap();
            assert_eq!(mode(&private), 0o600);
            let created = dir.path().join("created");
            std::fs::File::create(&created).unwrap();
            assert_eq!(mode(&path), mode(&created), "shared files follow the umask");
        }
    }
}
