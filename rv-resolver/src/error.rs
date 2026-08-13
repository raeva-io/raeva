use thiserror::Error;

pub type Result<T> = std::result::Result<T, ResolveError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSearchStatus {
    pub repo_url: String,
    pub status: RepoStatus,
}

impl RepoSearchStatus {
    pub fn new(repo_url: impl Into<String>, status: RepoStatus) -> Self {
        Self {
            repo_url: repo_url.into(),
            status,
        }
    }

    pub fn from_error(repo_url: impl Into<String>, err: &rv_repo::RepoError) -> Self {
        Self::new(repo_url, RepoStatus::from_repo_error(err))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoStatus {
    Http(u16),
    Error(&'static str),
}

impl RepoStatus {
    pub fn from_repo_error(err: &rv_repo::RepoError) -> Self {
        if let Some(code) = err.status_code() {
            return RepoStatus::Http(code);
        }

        match err {
            rv_repo::RepoError::Http(err) if err.is_timeout() => RepoStatus::Error("timeout"),
            rv_repo::RepoError::Http(err) if err.is_connect() => RepoStatus::Error("connect error"),
            rv_repo::RepoError::Http(_) => RepoStatus::Error("network error"),
            rv_repo::RepoError::AuthError(_) => RepoStatus::Error("auth error"),
            rv_repo::RepoError::InvalidMetadata(_) | rv_repo::RepoError::Xml(_) => {
                RepoStatus::Error("invalid metadata")
            }
            rv_repo::RepoError::Io(_) => RepoStatus::Error("I/O error"),
            _ => RepoStatus::Error("error"),
        }
    }
}

/// Which parts of a reactor disagreed about a POM's bytes, and what each one
/// resolved.
///
/// Boxed into the `Conflicting*PomBytes` variants: five inline `String`s would
/// make every `Result` in the crate wider for the sake of one error nobody
/// hits twice.
#[derive(Debug)]
pub struct ConflictingPom {
    /// The POM's bare `g:a:v`.
    pub coord: String,
    /// Where the first observation came from: a reactor module path, or a
    /// `platform/module` pair when the two sides are on different platforms.
    pub first_origin: String,
    pub second_origin: String,
    pub first_sha256: String,
    pub second_sha256: String,
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("version conflict for {coord}: requested {requested}, selected {selected}")]
    VersionConflict {
        coord: String,
        requested: String,
        selected: String,
    },
    #[error("relocation cycle detected: {0}")]
    RelocationCycle(String),
    #[error("workspace dependency cycle detected: {cycle}")]
    WorkspaceDependencyCycle { cycle: String },
    #[error(
        "artifact {coord} resolved to different bytes in reactor modules \
         {first_module} ({first_blob}) and {second_module} ({second_blob})"
    )]
    ConflictingArtifactBytes {
        coord: String,
        first_module: String,
        second_module: String,
        first_blob: String,
        second_blob: String,
    },
    #[error(
        "support POM {} (parent or imported BOM) resolved to different bytes in reactor \
         modules {} ({}) and {} ({}); one lockfile cannot pin both",
        .0.coord, .0.first_origin, .0.first_sha256, .0.second_origin, .0.second_sha256
    )]
    ConflictingSupportPomBytes(Box<ConflictingPom>),
    #[error(
        "companion POM for {} resolved to different bytes in {} ({}) and {} ({}); \
         Maven has one local-repository path per coordinate, so one lockfile cannot pin both",
        .0.coord, .0.first_origin, .0.first_sha256, .0.second_origin, .0.second_sha256
    )]
    ConflictingCompanionPomBytes(Box<ConflictingPom>),
    #[error(
        "pom-packaged dependency {coord} resolved its artifact to {artifact_sha256} and its \
         companion POM to {pom_sha256}, but for packaging=pom those are the same Maven file; \
         one lockfile row cannot pin both. Re-run `rv sync --update`"
    )]
    ConflictingPomPackagedBytes {
        coord: String,
        artifact_sha256: String,
        pom_sha256: String,
    },
    #[error(
        "POM {coord} was fetched more than once during resolution and returned different \
         bytes ({first_sha256}, {second_sha256}); one lockfile cannot pin both"
    )]
    ConflictingResolvedPomBytes {
        coord: String,
        first_sha256: String,
        second_sha256: String,
    },
    #[error("artifact not found: {coord}")]
    ArtifactNotFound {
        coord: String,
        searched: Vec<RepoSearchStatus>,
    },
    #[error("no repositories configured")]
    NoRepositories,
    #[error("missing version for dependency {group_id}:{artifact_id}")]
    MissingVersion {
        group_id: String,
        artifact_id: String,
    },
    #[error("invalid version requirement for {coord}: {value}")]
    InvalidVersionRequirement { coord: String, value: String },
    #[error("no available version for {coord} matching {requirement}")]
    VersionNotFound { coord: String, requirement: String },
    #[error("resolution queue exceeded limit ({limit} items)")]
    QueueLimitExceeded { limit: usize },
    #[error("repository client missing from resolve context")]
    MissingRepoClient,
    #[error("no snapshot-enabled repository available for {coord}: {message}")]
    NoSnapshotRepository { coord: String, message: String },
    #[error("config error: {0}")]
    Config(#[from] rv_config::ConfigError),
    #[error("store error: {0}")]
    Store(#[from] rv_store::StoreError),
    #[error("repo error: {0}")]
    Repo(#[from] rv_repo::RepoError),
    #[error("repo error: {source}")]
    RepoWithContext {
        #[source]
        source: rv_repo::RepoError,
        searched: Vec<RepoSearchStatus>,
    },
    #[error("pom error: {0}")]
    Pom(#[from] rv_maven_model::PomError),
    #[error("invalid pom.xml at {path}: {source}")]
    LocalPom {
        path: String,
        #[source]
        source: rv_maven_model::PomError,
    },
    #[error("version error: {0}")]
    Version(#[from] rv_version::VersionError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("solver invariant violated: {detail}")]
    SolverInvariant { detail: String },
    /// The all-reactor resolution raised no progress event for
    /// `stalled_for_secs` — no module started or finished a phase, no request
    /// was attempted, no response or failure came back, no blob was verified,
    /// no support POM was written. That is not slowness (real work raises
    /// events as it goes, and a failing repository raises them too); it means
    /// the resolution can no longer make progress, so this fails loudly
    /// instead of hanging a build forever.
    #[error(
        "reactor resolution stalled: no progress for {stalled_for_secs}s while resolving {modules}. \
         This is a bug in rv, not in your project; please report it with this message. \
         Set RV_WORKSPACE_STALL_TIMEOUT_SECS to raise the limit, or to 0 to disable the check."
    )]
    WorkspaceStalled {
        /// The modules that were still in flight, comma separated. Empty when
        /// the stall happened between phases.
        modules: String,
        stalled_for_secs: u64,
    },
    #[error("internal error: {0}")]
    InternalError(String),
    #[error("{} artifact fetch error(s), first: {first}", .rest.len() + 1)]
    MultipleArtifactErrors {
        first: Box<ResolveError>,
        rest: Vec<ResolveError>,
    },
}

#[cfg(test)]
mod tests {
    use super::ResolveError;

    #[test]
    fn version_conflict_message_mentions_coord() {
        let err = ResolveError::VersionConflict {
            coord: "com.example:demo".to_string(),
            requested: "1.0".to_string(),
            selected: "2.0".to_string(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("com.example:demo"));
        assert!(rendered.contains("1.0"));
        assert!(rendered.contains("2.0"));
    }

    #[test]
    fn no_snapshot_repository_error_includes_coord_and_message() {
        let err = ResolveError::NoSnapshotRepository {
            coord: "com.example:lib:1.0-SNAPSHOT".to_string(),
            message: "none of the configured repositories (central) have snapshots enabled"
                .to_string(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("com.example:lib:1.0-SNAPSHOT"));
        assert!(rendered.contains("snapshots enabled"));
    }

    #[test]
    fn multiple_artifact_errors_shows_count_and_first_error() {
        let first = ResolveError::ArtifactNotFound {
            coord: "com.example:first:1.0".to_string(),
            searched: vec![],
        };
        let rest = vec![
            ResolveError::ArtifactNotFound {
                coord: "com.example:second:2.0".to_string(),
                searched: vec![],
            },
            ResolveError::ArtifactNotFound {
                coord: "com.example:third:3.0".to_string(),
                searched: vec![],
            },
        ];
        let err = ResolveError::MultipleArtifactErrors {
            first: Box::new(first),
            rest,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("3 artifact fetch error(s)"));
        assert!(rendered.contains("com.example:first:1.0"));
    }
}
