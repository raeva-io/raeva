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
}

/// Reads `path` up to `limit` bytes, stopping one byte past the limit so an
/// oversized file is never held in memory whole.
pub(crate) fn read_capped(path: &Path, limit: usize) -> Result<Vec<u8>, CappedReadError> {
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
/// [`MAX_PROJECT_INPUT_SIZE`] with [`ConfigError::ProjectInputTooLarge`].
/// The read stops one byte past the limit, so an oversized file is never
/// held in memory whole.
pub fn read_project_input(path: &Path) -> Result<Vec<u8>, ConfigError> {
    read_capped(path, MAX_PROJECT_INPUT_SIZE).map_err(|error| match error {
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

/// [`read_project_input`], with `None` for a file that does not exist.
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
/// exist.
pub fn read_optional_project_input_string(path: &Path) -> Result<Option<String>, ConfigError> {
    not_found_none(read_project_input_string(path))
}

fn not_found_none<T>(result: Result<T, ConfigError>) -> Result<Option<T>, ConfigError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(ConfigError::ProjectInputIo { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
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
    }
}
