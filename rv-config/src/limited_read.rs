use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::ConfigError;

/// Maximum size for project POM and configuration inputs.
pub const MAX_PROJECT_INPUT_SIZE: usize = 5 * 1024 * 1024;

/// Why [`read_capped`] refused a file.
pub(crate) enum CappedReadError {
    Io(std::io::Error),
    TooLarge,
    /// A FIFO, device or directory, whose open or read can block.
    NotRegular,
}

/// Reads `path` up to `limit` bytes, stopping one byte past the limit so an
/// oversized file is never held in memory whole. Only a regular file, or a
/// link to one, is opened, as `mvn`'s `[ -f ... ]` and `MavenCli`'s
/// `isFile()` test it.
pub(crate) fn read_capped(path: &Path, limit: usize) -> Result<Vec<u8>, CappedReadError> {
    if !std::fs::metadata(path)
        .map_err(CappedReadError::Io)?
        .is_file()
    {
        return Err(CappedReadError::NotRegular);
    }
    let file = File::open(path).map_err(CappedReadError::Io)?;
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(CappedReadError::Io)?;
    if bytes.len() > limit {
        return Err(CappedReadError::TooLarge);
    }
    Ok(bytes)
}

/// Reads `path` in full, refusing a file larger than
/// [`MAX_PROJECT_INPUT_SIZE`] with [`ConfigError::ProjectInputTooLarge`],
/// and one that is not a regular file. The read stops one byte past the
/// limit, so an oversized file is never held in memory whole.
pub fn read_project_input(path: &Path) -> Result<Vec<u8>, ConfigError> {
    read_capped(path, MAX_PROJECT_INPUT_SIZE).map_err(|error| match error {
        CappedReadError::NotRegular => ConfigError::ProjectInputIo {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, NOT_REGULAR),
        },
        CappedReadError::Io(source) => ConfigError::ProjectInputIo {
            path: path.to_path_buf(),
            source,
        },
        CappedReadError::TooLarge => ConfigError::ProjectInputTooLarge {
            path: path.to_path_buf(),
            limit: MAX_PROJECT_INPUT_SIZE,
        },
    })
}

const NOT_REGULAR: &str = "not a regular file";

/// [`read_project_input`], with `None` for a file that does not exist or
/// is no regular file, which the launcher and `MavenCli` skip.
pub fn read_optional_project_input(path: &Path) -> Result<Option<Vec<u8>>, ConfigError> {
    not_found_none(read_project_input(path))
}

/// [`read_project_input`] as text, refusing bytes that are not UTF-8 with
/// [`ConfigError::ProjectInputEncoding`].
pub fn read_project_input_string(path: &Path) -> Result<String, ConfigError> {
    String::from_utf8(read_project_input(path)?).map_err(|_| ConfigError::ProjectInputEncoding {
        path: path.to_path_buf(),
    })
}

/// [`read_project_input_string`], with `None` for a file that does not
/// exist or is no regular file.
pub fn read_optional_project_input_string(path: &Path) -> Result<Option<String>, ConfigError> {
    not_found_none(read_project_input_string(path))
}

fn not_found_none<T>(result: Result<T, ConfigError>) -> Result<Option<T>, ConfigError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(ConfigError::ProjectInputIo { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound
                || source.to_string() == NOT_REGULAR =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounded_and_utf8_checked() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("pom.xml");
        assert!(read_optional_project_input_string(&path).unwrap().is_none());
        std::fs::write(&path, vec![b'x'; MAX_PROJECT_INPUT_SIZE + 1]).expect("write input");
        let error = read_project_input(&path).expect_err("oversized input must fail");
        assert!(error.to_string().contains("5242880-byte limit"), "{error}");
        std::fs::write(&path, [0xff]).expect("write input");
        for error in [
            read_project_input_string(&path).unwrap_err(),
            read_optional_project_input_string(&path).unwrap_err(),
        ] {
            assert!(matches!(error, ConfigError::ProjectInputEncoding { .. }));
        }
        std::fs::write(&path, "ok").expect("write input");
        assert_eq!(
            read_optional_project_input_string(&path)
                .unwrap()
                .as_deref(),
            Some("ok")
        );
        // A directory is no regular file; it is skipped, as a FIFO is.
        assert!(read_optional_project_input(temp.path()).unwrap().is_none());
        assert!(read_project_input(temp.path()).is_err());
    }

    /// A FIFO without a writer blocks an open: it is skipped as optional
    /// input and refused otherwise, without opening it.
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_not_opened() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let fifo = temp.path().join("jvm.config");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(made.is_ok_and(|status| status.success()));
        let (sent, received) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let optional = read_optional_project_input_string(&path).map(|text| text.is_none());
            let required = read_project_input(&path).is_err();
            let _ = sent.send((optional.ok(), required));
        });
        let read = received.recv_timeout(std::time::Duration::from_secs(10));
        assert_eq!(read.ok(), Some((Some(true), true)));
    }
}
