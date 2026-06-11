use std::env;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Environment variable that, when set, roots Raeva's config, store, and cache
/// directories instead of the platform-specific defaults.
pub const RAEVA_HOME_ENV: &str = "RAEVA_HOME";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPaths {
    pub config_dir: PathBuf,
    pub store_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl ResolvedPaths {
    /// Discovers standard paths for configuration, store, and cache directories.
    ///
    /// If `RAEVA_HOME` is set, all paths are rooted there.
    /// Otherwise, uses platform-specific directories (e.g., `~/.config`, `~/.local/share`).
    ///
    /// # Errors
    ///
    /// Returns an error if platform-specific directories cannot be determined
    /// and `RAEVA_HOME` is not set.
    pub fn discover() -> Result<Self, ConfigError> {
        if let Some(base) = raeva_home_override(env::var_os(RAEVA_HOME_ENV))? {
            return Ok(Self::from_raeva_home(base));
        }

        let config_base = dirs::config_dir().ok_or(ConfigError::ConfigDirUnavailable)?;
        let data_base = dirs::data_dir().ok_or(ConfigError::DataDirUnavailable)?;
        let cache_base = dirs::cache_dir().ok_or(ConfigError::CacheDirUnavailable)?;

        let config_dir = config_base.join("raeva");
        let store_dir = data_base.join("raeva").join("store");
        let cache_dir = cache_base.join("raeva");

        Ok(Self {
            config_dir,
            store_dir,
            cache_dir,
        })
    }

    pub fn from_raeva_home(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        let store_dir = base.join("store");
        let cache_dir = base.join("cache");
        Self {
            config_dir: base,
            store_dir,
            cache_dir,
        }
    }

    pub fn config_file_path(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn metadata_db_path(&self) -> PathBuf {
        self.store_dir.with_file_name("metadata.db")
    }
}

/// Interpret the raw `RAEVA_HOME` value.
///
/// A set-but-empty (or whitespace-only) value is treated as unset with a
/// warning, mirroring how invalid `RV_TIMEOUT`/`RV_RETRIES` values are
/// ignored with a warning. A relative value is rejected outright: silently
/// resolving it against the current working directory would scatter the
/// store and cache across whichever directory rv happens to run from.
fn raeva_home_override(value: Option<std::ffi::OsString>) -> Result<Option<PathBuf>, ConfigError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.to_string_lossy().trim().is_empty() {
        tracing::warn!(
            env = RAEVA_HOME_ENV,
            "ignoring empty RAEVA_HOME; using platform default directories"
        );
        return Ok(None);
    }
    let path = PathBuf::from(value);
    if path.is_relative() {
        return Err(ConfigError::RaevaHomeNotAbsolute(path));
    }
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::{ResolvedPaths, raeva_home_override};
    use std::env;
    use std::ffi::OsString;

    #[test]
    fn raeva_home_unset_yields_no_override() {
        assert_eq!(raeva_home_override(None).expect("ok"), None);
    }

    #[test]
    fn raeva_home_empty_is_treated_as_unset() {
        let resolved = raeva_home_override(Some(OsString::new())).expect("ok");
        assert_eq!(
            resolved, None,
            "empty RAEVA_HOME must fall back to defaults"
        );
        let resolved = raeva_home_override(Some(OsString::from("   "))).expect("ok");
        assert_eq!(
            resolved, None,
            "whitespace-only RAEVA_HOME must fall back to defaults"
        );
    }

    #[test]
    fn raeva_home_relative_is_rejected() {
        let err = raeva_home_override(Some(OsString::from("relative/raeva")))
            .expect_err("relative RAEVA_HOME must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("absolute") && message.contains("relative/raeva"),
            "error must name the offending path and the fix: {message}"
        );
    }

    #[test]
    fn raeva_home_absolute_is_accepted() {
        let base = env::temp_dir().join("raeva-abs");
        let resolved = raeva_home_override(Some(base.clone().into_os_string()))
            .expect("ok")
            .expect("absolute RAEVA_HOME must be honored");
        assert_eq!(resolved, base);
    }

    #[test]
    fn raeva_home_layout_is_consistent() {
        let base = env::temp_dir().join("raeva-test");
        let paths = ResolvedPaths::from_raeva_home(&base);
        assert_eq!(paths.config_dir, base);
        assert_eq!(paths.store_dir, base.join("store"));
        assert_eq!(paths.cache_dir, base.join("cache"));
        assert_eq!(paths.config_file_path(), base.join("config.toml"));
        assert_eq!(paths.metadata_db_path(), base.join("metadata.db"));
    }
}
