use std::path::PathBuf;

use thiserror::Error;

mod classify;
mod diagnose;
pub(crate) mod report;
mod status;

pub(crate) use classify::ErrorClass;
pub(crate) use diagnose::{Diagnostic, HintEnv};
pub(crate) use status::ExitStatus;

pub(crate) type Result<T> = std::result::Result<T, CliError>;

#[derive(Debug, Error)]
pub(crate) enum CliError {
    #[error("configuration error: {0}")]
    Config(#[from] rv_config::ConfigError),

    /// raeva.lock could not be read, written or used.
    #[error("configuration error: {0}")]
    Lock(#[from] rv_lock::LockError),

    #[error("configuration error: {0}")]
    Platform(#[from] rv_lock::InvalidPlatform),

    #[error("dependency resolution failed: {0}")]
    Resolve(#[from] rv_resolver::ResolveError),

    #[error("repository error: {0}")]
    Repo(#[from] rv_repo::RepoError),

    /// Artifacts that could not be downloaded. `first` decides the class.
    #[error("failed to download {} artifact(s): {first}", failures.len())]
    Download {
        failures: Vec<String>,
        first: rv_repo::RepoError,
    },

    #[error("artifact store error: {0}")]
    Store(#[from] rv_store::StoreError),

    #[error("export error: {0}")]
    Export(#[from] crate::commands::export_m2::ExportError),

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

    #[error("vulnerability error: {0}")]
    Vuln(#[from] rv_vuln::VulnError),

    /// `raeva vuln` could not finish its scan. The cause gives the message,
    /// hints and status, except that a cause with status 1 exits 2, since
    /// `raeva vuln` exits 1 for findings ([`ExitStatus::of_failed_scan`]).
    #[error("vulnerability scan failed: {0}")]
    VulnerabilityScan(Box<CliError>),

    /// OSV named vulnerability records that could not be fetched, so the
    /// scan is incomplete. The status follows the fetch errors.
    #[error("OSV named {} vulnerability record(s) that could not be fetched", failures.len())]
    VulnRecordsUnfetched { failures: Vec<rv_vuln::FailedFetch> },

    #[error("SBOM generation failed: {0}")]
    Sbom(#[from] rv_sbom::SbomError),

    // Our own serialization (output envelopes, doctor reports) failed. The
    // raw serde message names internal fields and is unactionable, so it
    // sits behind a "please file a bug" prefix.
    #[error("internal serialization error (please file a bug): {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("internal error (please file a bug): {0}")]
    Internal(String),

    /// The command line asks for something that cannot be done.
    #[error("{0}")]
    Usage(String),

    /// Two repository declarations that raeva.lock would record as one
    /// project-relative origin name different directories. The URLs are
    /// redacted.
    #[error(
        "repositories {first} and {second} name different directories, which raeva.lock would \
         record as the one origin {origin}; declare each directory with a path of its own"
    )]
    RepositoryOriginAlias {
        origin: String,
        first: String,
        second: String,
    },

    /// A project file such as pom.xml that raeva cannot use.
    #[error("invalid {path}: {reason}")]
    InvalidProjectInput { path: PathBuf, reason: String },

    #[error(
        "lockfile not found: {}{}",
        from_working_dir(path),
        match reactor {
            Some(root) => format!(
                " (this directory is a module of the Maven project in {}, whose raeva.lock \
                 covers every module: add -C {})",
                root.display(),
                crate::commands::util::shell_word(&root.display().to_string())
            ),
            None => String::new(),
        }
    )]
    LockfileMissing {
        path: PathBuf,
        /// The project's own raeva.lock, which `raeva sync` creates.
        sync_creates: bool,
        reactor: Option<PathBuf>,
    },

    #[error(
        "lockfile path is not a regular file: {path} (expected a raeva.lock file; remove the existing entry or pick a different project root)"
    )]
    LockfileNotAFile { path: PathBuf },

    /// raeva.lock is not a lockfile this raeva can use. `regenerable` when
    /// a plain sync reads enough of it to replace it, which it cannot for a
    /// file too large or not UTF-8.
    #[error("raeva.lock cannot be used: {reason}")]
    LockfileIncompatible { reason: String, regenerable: bool },

    /// raeva.lock has a schema a later raeva wrote. A sync with this one
    /// would rewrite it in the older schema, so nothing regenerates it.
    #[error(
        "raeva.lock has schema version {found}, which a newer raeva wrote; this raeva reads schema {expected}"
    )]
    LockfileTooNew { found: u32, expected: u32 },

    /// raeva.lock no longer matches what it was written for. `hint` says what
    /// fixes it; without one, the fix is a plain `raeva sync`.
    #[error("{details}")]
    LockfileMismatch {
        details: String,
        hint: Option<String>,
    },

    /// raeva.lock parses, but holds a value this command cannot use, such as a
    /// malformed digest or a graph edge that points nowhere.
    #[error("raeva.lock is invalid: {details} (run 'raeva sync' to rewrite it)")]
    LockfileDefect { details: String },

    /// Another raeva process holds the project's lockfile guard.
    #[error(
        "raeva.lock in {} is in use by another raeva process: {source}. Wait for it to finish and run the command again",
        project_root.display()
    )]
    LockfileBusy {
        project_root: PathBuf,
        source: std::io::Error,
    },

    /// raeva.lock has no section for `platform`. `recorded` lists the
    /// platforms it has, sorted.
    #[error(
        "raeva.lock has no section for platform {platform}{}",
        if recorded.is_empty() {
            "; it records no platform".to_string()
        } else {
            format!("; it records {}", recorded.join(", "))
        }
    )]
    PlatformMissing {
        platform: String,
        recorded: Vec<String>,
        /// Raised by `sync --frozen`, which can check the recorded
        /// platforms instead.
        frozen: bool,
    },

    #[error(
        "cannot export to the configured local repository {path}: {reason}; pass --m2-path to choose the destination"
    )]
    LocalRepository { path: String, reason: &'static str },

    #[error("project file not found: {path}")]
    ProjectFileMissing { path: PathBuf },

    /// `raeva why` found no path to the coordinate in the selected modules.
    #[error("no path found for {target} (not a dependency in the selected module graph(s))")]
    NoDependencyPath { target: String },

    /// `raeva doctor` checks failed. `status` follows the kind of failures.
    #[error("{failed} check(s) failed")]
    DoctorChecksFailed { failed: usize, status: ExitStatus },

    /// `raeva vuln` found vulnerabilities at or above `--fail-on`.
    #[error("{}", vulnerabilities_found(*findings, threshold))]
    VulnerabilitiesFound {
        findings: usize,
        threshold: &'static str,
    },

    #[error("{0}")]
    Message(String),
}

/// `path` relative to the working directory when it lies under it: a CI
/// log reads `raeva.lock` better than the runner's checkout path.
fn from_working_dir(path: &std::path::Path) -> String {
    // Both sides resolve links, as macOS's /var does.
    let relative = || {
        let cwd = dunce::canonicalize(std::env::current_dir().ok()?).ok()?;
        let dir = dunce::canonicalize(path.parent()?).ok()?;
        Some(dir.strip_prefix(cwd).ok()?.join(path.file_name()?))
    };
    relative().as_deref().unwrap_or(path).display().to_string()
}

fn vulnerabilities_found(findings: usize, threshold: &str) -> String {
    let found =
        crate::commands::util::plural(findings, "known vulnerability", "known vulnerabilities");
    if threshold == "any" {
        format!("found {found}")
    } else {
        format!("found {found} at {threshold} severity or above")
    }
}

impl CliError {
    pub(crate) fn lockfile_mismatch(reason: impl std::fmt::Display) -> Self {
        CliError::LockfileMismatch {
            details: reason.to_string(),
            hint: None,
        }
    }

    /// A lockfile mismatch that `hint` says how to fix.
    pub(crate) fn lockfile_mismatch_with(
        reason: impl std::fmt::Display,
        hint: impl Into<String>,
    ) -> Self {
        CliError::LockfileMismatch {
            details: reason.to_string(),
            hint: Some(hint.into()),
        }
    }

    /// Maps an I/O error to [`CliError::IoWithPath`] for `path`.
    pub(crate) fn io_at(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Self {
        let path = path.into();
        |source| CliError::IoWithPath { path, source }
    }

    pub(crate) fn task_failed(what: &str, err: tokio::task::JoinError) -> Self {
        CliError::Internal(format!("{what} task failed: {err}"))
    }
}
