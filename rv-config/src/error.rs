use std::path::PathBuf;

use thiserror::Error;

use crate::paths::{PlatformDir, platform_dir_unavailable};

/// Why loading or validating configuration failed.
///
/// Most rejected values arrive as [`ConfigError::Invalid`], which names the
/// [`ConfigOrigin`] they came from.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// An I/O error with no file named.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A `settings.xml` or `settings-security.xml` that is malformed or
    /// fails the XML hardening checks, before the file path is known.
    /// [`Config::load`](crate::Config::load) reports it as
    /// [`ConfigError::Invalid`] with the path.
    #[error("invalid settings.xml: {0}")]
    InvalidSettings(String),
    /// A value or file that was read but rejected.
    #[error("invalid {origin}: {message}")]
    Invalid {
        /// Where the value or file came from.
        origin: ConfigOrigin,
        /// What is wrong with it, in the terms its origin uses.
        message: String,
    },
    /// A project input (a POM, `raeva.toml` or other file read with the size
    /// limit) that could not be opened or read.
    #[error("failed to read project input {path}: {source}")]
    ProjectInputIo {
        /// The file being read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A project input larger than [`MAX_PROJECT_INPUT_SIZE`](crate::MAX_PROJECT_INPUT_SIZE).
    #[error("project input {path} exceeds {limit}-byte limit")]
    ProjectInputTooLarge {
        /// The file being read.
        path: PathBuf,
        /// The limit it exceeded, in bytes.
        limit: usize,
    },
    /// A project input read as text that is not UTF-8.
    #[error("project input {path} is not valid UTF-8")]
    ProjectInputEncoding {
        /// The file being read.
        path: PathBuf,
    },
    // These name what the lookup reads on this platform, not the path it
    // would have produced: the environment can change between the failure
    // and rendering, and a stale path would confuse more than it helps.
    /// The platform has no config directory and `RAEVA_HOME` is unset.
    #[error(
        "{}",
        platform_dir_unavailable(PlatformDir::Config, std::env::consts::OS)
    )]
    ConfigDirUnavailable,
    #[error(
        "{}",
        platform_dir_unavailable(PlatformDir::Data, std::env::consts::OS)
    )]
    /// The platform has no local data directory and `RAEVA_HOME` is unset.
    /// Also returned when the temporary directory for a test configuration
    /// cannot be created.
    DataDirUnavailable,
    /// The platform has no cache directory and `RAEVA_HOME` is unset.
    #[error(
        "{}",
        platform_dir_unavailable(PlatformDir::Cache, std::env::consts::OS)
    )]
    CacheDirUnavailable,
    #[error(
        "RAEVA_HOME must be an absolute path, got {0:?}; set an absolute path or unset the variable"
    )]
    /// `RAEVA_HOME` is set to a relative path.
    RaevaHomeNotAbsolute(PathBuf),
    /// `RAEVA_HOME` names something that exists and is not a directory.
    #[error(
        "RAEVA_HOME names {}, which is not a directory; set it to a directory or unset the variable",
        .0.display()
    )]
    RaevaHomeNotADirectory(PathBuf),
    /// The project root passed to [`Config::load`](crate::Config::load)
    /// does not exist.
    #[error("project root not found: {0}")]
    ProjectRootMissing(PathBuf),
    /// The command line's `-s` file is not a file. The message is Maven's.
    #[error("The specified user settings file does not exist: {}", .0.display())]
    SettingsFileMissing(PathBuf),
    /// A `settings-security.xml` `<relocation>` chain longer than the limit,
    /// which usually means a cycle.
    #[error("relocation depth exceeded maximum (possible circular reference)")]
    RelocationDepthExceeded,
}

/// Where a rejected configuration value or file came from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigOrigin {
    /// An environment variable, by name.
    Env(&'static str),
    /// The project's `raeva.toml`.
    ProjectConfig(PathBuf),
    /// The user's `config.toml`.
    UserConfig(PathBuf),
    /// Maven's `settings.xml`.
    MavenSettings(PathBuf),
    /// Maven's `settings-security.xml`.
    MavenSettingsSecurity(PathBuf),
    /// The project's `.mvn/maven.config`.
    MavenConfig(PathBuf),
    /// The `-D` and `-P` options given to `raeva`.
    CommandLine,
}

impl std::fmt::Display for ConfigOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env(name) => write!(f, "environment variable {name}"),
            Self::ProjectConfig(path) => write!(f, "project config {}", path.display()),
            Self::UserConfig(path) => write!(f, "user config {}", path.display()),
            Self::MavenSettings(path) => write!(f, "Maven settings {}", path.display()),
            Self::MavenSettingsSecurity(path) => {
                write!(f, "Maven settings security file {}", path.display())
            }
            Self::MavenConfig(path) => write!(f, "{}", path.display()),
            Self::CommandLine => write!(f, "-D or -P option"),
        }
    }
}
