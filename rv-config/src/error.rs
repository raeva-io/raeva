use std::path::PathBuf;

use anyhow::Error as AnyhowError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("toml deserialize error: {0}")]
    TomlDeserialize(#[from] toml::de::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("xml error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("xml escape error: {0}")]
    Escape(#[from] quick_xml::escape::EscapeError),
    #[error("invalid utf-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("invalid settings.xml: {0}")]
    InvalidSettings(String),
    // Append a hint pointing at the env vars that drive the lookup so the
    // user has somewhere to start. We deliberately do not call
    // `dirs::config_dir()` from `Display` because the env can change
    // between failure and rendering, and a stale path would confuse more
    // than it helps.
    #[error("config directory is unavailable (check $HOME or $XDG_CONFIG_HOME)")]
    ConfigDirUnavailable,
    #[error("data directory is unavailable (check $HOME or $XDG_DATA_HOME)")]
    DataDirUnavailable,
    #[error("cache directory is unavailable (check $HOME or $XDG_CACHE_HOME)")]
    CacheDirUnavailable,
    #[error("invalid platform: {0}")]
    InvalidPlatform(String),
    #[error(
        "RAEVA_HOME must be an absolute path, got {0:?}; set an absolute path or unset the variable"
    )]
    RaevaHomeNotAbsolute(PathBuf),
    #[error(
        "unsupported lockfile schema version {found}, expected {expected}; this lockfile was likely written by a newer rv. Upgrade rv, or delete rv.lock and run 'rv sync' to regenerate it"
    )]
    UnsupportedSchema { found: u32, expected: u32 },
    #[error("project root not found: {0}")]
    ProjectRootMissing(PathBuf),
    #[error("relocation depth exceeded maximum (possible circular reference)")]
    RelocationDepthExceeded,
    #[error("invalid lockfile: {0}")]
    InvalidLockfile(String),
}

/// Convert an `anyhow::Error` into a `std::io::Error`, preserving the
/// original `ErrorKind` when the chain contains an `io::Error`.
///
/// This is used by multiple crates (rv-config, rv-repo, rv-store) to
/// bridge `anyhow` context errors back into typed error enums that
/// wrap `std::io::Error`.
pub fn io_error_with_context(err: AnyhowError) -> std::io::Error {
    let kind = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>().map(|io| io.kind()))
        .unwrap_or(std::io::ErrorKind::Other);
    std::io::Error::new(kind, err)
}

pub(crate) fn toml_de_error_with_context(err: AnyhowError) -> toml::de::Error {
    <toml::de::Error as serde::de::Error>::custom(err)
}

pub(crate) fn toml_ser_error_with_context(err: AnyhowError) -> toml::ser::Error {
    <toml::ser::Error as serde::ser::Error>::custom(err)
}
