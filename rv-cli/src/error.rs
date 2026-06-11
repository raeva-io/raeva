use std::path::PathBuf;

use thiserror::Error;

mod report;

pub type Result<T> = std::result::Result<T, CliError>;

/// Numeric exit codes returned by the `rv` binary (stable CLI contract).
///
/// Code assignments:
/// - 0: success (not listed here; `ExitCode::SUCCESS` is used directly)
/// - 1: general / unclassified error (`GENERAL_ERROR`)
/// - 2: usage error (clap exits with 2 on bad flags / subcommands; not surfaced
///   by Raeva's own error paths but reserved here so the full table is
///   self-documenting)
/// - 3: configuration error, e.g. bad rv.toml, bad URL, auth problem (`CONFIG_ERROR`)
/// - 4: network error, e.g. timeout, DNS, proxy (`NETWORK_ERROR`)
/// - 5: dependency resolution failure (`RESOLUTION_ERROR`)
/// - 6: startup failure, e.g. runtime, crypto provider (`STARTUP_ERROR`)
/// - 7: lockfile mismatch, e.g. `--frozen` drift or checksum mismatch (`LOCKFILE_MISMATCH`)
/// - 8: partial success, some repos OK and others failed (`PARTIAL_SUCCESS`)
pub struct ExitCodes;
impl ExitCodes {
    pub const GENERAL_ERROR: i32 = 1;
    /// Clap exits with 2 on usage errors (unknown flag, missing required arg,
    /// etc.). Raeva's own error paths never produce this code, but it is named
    /// here so scripts can distinguish usage mistakes from runtime failures.
    #[allow(dead_code)]
    pub const USAGE_ERROR: i32 = 2;
    pub const CONFIG_ERROR: i32 = 3;
    pub const NETWORK_ERROR: i32 = 4;
    pub const RESOLUTION_ERROR: i32 = 5;
    pub const STARTUP_ERROR: i32 = 6;
    pub const LOCKFILE_MISMATCH: i32 = 7;
    pub const PARTIAL_SUCCESS: i32 = 8;
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("configuration error: {0}")]
    Config(#[from] rv_config::ConfigError),

    #[error("dependency resolution failed: {0}")]
    Resolve(#[from] rv_resolver::ResolveError),

    #[error("repository error: {0}")]
    Repo(#[from] rv_repo::RepoError),

    #[error("artifact store error: {0}")]
    Store(#[from] rv_store::StoreError),

    #[error("export error: {0}")]
    Export(#[from] crate::commands::export_m2::ExportError),

    #[error("version parsing error: {0}")]
    Version(#[from] rv_version::VersionError),

    #[error("POM parsing error: {0}")]
    Pom(#[from] rv_maven_model::PomError),

    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // Wrapper used when the offending path is known at the call site, so
    // the displayed message points at the file instead of just "No such
    // file or directory". Prefer this over the bare `Io` variant.
    #[error("I/O error: {path}: {source}")]
    IoWithPath {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),

    // Surfaced when our own serialization (output envelopes, doctor
    // reports) fails. The raw serde error message leaks internal field
    // names and is unactionable for users, so wrap it behind a generic
    // "please file a bug" prefix while still retaining the cause for
    // operators digging into logs.
    #[error("internal serialization error (please file a bug): {0}")]
    Internal(#[from] serde_json::Error),

    #[error("lockfile not found: {path} (run 'rv sync' to create)")]
    LockfileMissing { path: PathBuf },

    #[error(
        "lockfile path is not a regular file: {path} (expected an rv.lock file; remove the existing entry or pick a different project root)"
    )]
    LockfileNotAFile { path: PathBuf },

    #[error("lockfile mismatch: {details} (run 'rv sync' to update)")]
    LockfileMismatch { details: String },

    #[error("platform '{platform}' not in lockfile (run 'rv sync' on this platform)")]
    PlatformMissing { platform: String },

    #[error("project file not found: {path}")]
    ProjectFileMissing { path: PathBuf },

    #[error("invalid scope: '{value}'")]
    InvalidScope { value: String },

    #[error(
        "multi-module reactor POM at {path} is not supported in v1; run rv from an individual module's directory (follow-up: v1.1)"
    )]
    MultiModuleNotSupported { path: PathBuf },

    #[error("{0}")]
    Message(String),

    /// Suppresses the top-level error envelope.
    #[error("(silent)")]
    AlreadyReported { exit_code: i32 },
}

impl CliError {
    pub fn user_message(&self) -> String {
        match self {
            CliError::Resolve(err) => report::render_resolve_error(err),
            CliError::Pom(err) => report::render_pom_error(err),
            CliError::Repo(err) => report::render_repo_error(err, None),
            CliError::Reqwest(err) => report::render_reqwest_error(err),
            CliError::Store(err) => report::render_store_error(err),
            _ => self.to_string(),
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Config(_)
            | CliError::Toml(_)
            | CliError::ProjectFileMissing { .. }
            | CliError::Pom(_) => ExitCodes::CONFIG_ERROR,

            CliError::Reqwest(_) => ExitCodes::NETWORK_ERROR,

            CliError::Repo(err) => {
                if err.is_transient() {
                    ExitCodes::NETWORK_ERROR
                } else {
                    ExitCodes::RESOLUTION_ERROR
                }
            }

            CliError::Resolve(_) | CliError::Version(_) | CliError::InvalidScope { .. } => {
                ExitCodes::RESOLUTION_ERROR
            }

            CliError::LockfileMismatch { .. } => ExitCodes::LOCKFILE_MISMATCH,

            CliError::LockfileMissing { .. }
            | CliError::LockfileNotAFile { .. }
            | CliError::PlatformMissing { .. }
            | CliError::MultiModuleNotSupported { .. } => ExitCodes::CONFIG_ERROR,

            CliError::Store(_)
            | CliError::Export(_)
            | CliError::Io(_)
            | CliError::IoWithPath { .. }
            | CliError::Internal(_)
            | CliError::Message(_) => ExitCodes::GENERAL_ERROR,

            CliError::AlreadyReported { exit_code } => *exit_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExitCodes;

    /// `USAGE_ERROR` must equal 2 (clap's exit code for bad flags/args)
    /// and must not collide with any other named constant.
    #[test]
    fn usage_error_is_2_and_unique() {
        assert_eq!(
            ExitCodes::USAGE_ERROR,
            2,
            "USAGE_ERROR must be 2 (clap convention)"
        );
        // Verify no other constant is accidentally 2.
        assert_ne!(ExitCodes::GENERAL_ERROR, 2);
        assert_ne!(ExitCodes::CONFIG_ERROR, 2);
        assert_ne!(ExitCodes::NETWORK_ERROR, 2);
        assert_ne!(ExitCodes::RESOLUTION_ERROR, 2);
        assert_ne!(ExitCodes::STARTUP_ERROR, 2);
        assert_ne!(ExitCodes::LOCKFILE_MISMATCH, 2);
        assert_ne!(ExitCodes::PARTIAL_SUCCESS, 2);
    }

    /// All exit codes must be distinct (no two constants may share a value).
    #[test]
    fn all_exit_codes_are_distinct() {
        let codes = [
            ExitCodes::GENERAL_ERROR,
            ExitCodes::USAGE_ERROR,
            ExitCodes::CONFIG_ERROR,
            ExitCodes::NETWORK_ERROR,
            ExitCodes::RESOLUTION_ERROR,
            ExitCodes::STARTUP_ERROR,
            ExitCodes::LOCKFILE_MISMATCH,
            ExitCodes::PARTIAL_SUCCESS,
        ];
        let unique: std::collections::HashSet<i32> = codes.iter().copied().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "exit codes must all be distinct; got duplicates in {codes:?}"
        );
    }
}
