use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::ConfigError;

/// Maximum size for project POM and configuration inputs.
pub const MAX_PROJECT_INPUT_SIZE: usize = 5 * 1024 * 1024;

pub fn read_project_input(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let file = File::open(path).map_err(|source| ConfigError::ProjectInputIo {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(MAX_PROJECT_INPUT_SIZE.min(64 * 1024));
    file.take(MAX_PROJECT_INPUT_SIZE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigError::ProjectInputIo {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > MAX_PROJECT_INPUT_SIZE {
        return Err(ConfigError::ProjectInputTooLarge {
            path: path.to_path_buf(),
            limit: MAX_PROJECT_INPUT_SIZE,
        });
    }
    Ok(bytes)
}

pub fn read_optional_project_input(path: &Path) -> Result<Option<Vec<u8>>, ConfigError> {
    match read_project_input(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(ConfigError::ProjectInputIo { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub fn read_project_input_string(path: &Path) -> Result<String, ConfigError> {
    String::from_utf8(read_project_input(path)?).map_err(|_| ConfigError::ProjectInputEncoding {
        path: path.to_path_buf(),
    })
}

pub fn read_optional_project_input_string(path: &Path) -> Result<Option<String>, ConfigError> {
    read_optional_project_input(path)?
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|_| ConfigError::ProjectInputEncoding {
                path: path.to_path_buf(),
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use super::{MAX_PROJECT_INPUT_SIZE, read_project_input, read_project_input_string};
    use crate::ConfigError;

    #[test]
    fn rejects_input_over_limit() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("pom.xml");
        let mut file = std::fs::File::create(&path).expect("create input");
        file.write_all(&vec![b'x'; MAX_PROJECT_INPUT_SIZE + 1])
            .expect("write input");

        let error = read_project_input(&path).expect_err("oversized input must fail");
        assert!(matches!(error, ConfigError::ProjectInputTooLarge { .. }));
        assert!(error.to_string().contains("5242880-byte limit"));
    }

    #[test]
    fn rejects_non_utf8_text_input() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("pom.xml");
        std::fs::write(&path, [0xff]).expect("write input");

        let error = read_project_input_string(&path).expect_err("non-UTF-8 input must fail");
        assert!(matches!(error, ConfigError::ProjectInputEncoding { .. }));
    }
}
