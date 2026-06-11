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
