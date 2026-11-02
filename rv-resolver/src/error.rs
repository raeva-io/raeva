use rv_maven_types::bounded;
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, ResolveError>;

/// One repository a failed lookup tried, and how it answered. Not-found and
/// repository errors carry one per repository, in the order they were tried.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoSearchStatus {
    /// The repository's URL as configured or declared, before mirror
    /// substitution. Not redacted: it can hold userinfo, so pass it through
    /// [`rv_config::redact_url`] before showing it.
    pub repo_url: String,
    /// How the repository answered.
    pub status: RepoStatus,
    /// The repository that answered 401 or 403, after mirror substitution:
    /// its id and URL are the ones credentials are looked up under, which
    /// differ from `repo_url` when a mirror served the request.
    pub refused_by: Option<CredentialTarget>,
    /// The URL of the mirror the request went to, when one served
    /// `repo_url`. Not redacted.
    pub served_by: Option<String>,
}

/// The id and endpoint a credential would have to be stored under, and the
/// credential the refused request carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialTarget {
    /// The repository or mirror id, `None` when it declares none.
    pub id: Option<String>,
    /// The repository or mirror URL, not redacted.
    pub url: String,
    /// The credential sent, `None` when the request carried none.
    pub sent: Option<rv_repo::SentCredential>,
}

impl RepoSearchStatus {
    /// A status for `repo_url` with no refusing repository recorded.
    pub fn new(repo_url: impl Into<String>, status: RepoStatus) -> Self {
        Self {
            repo_url: repo_url.into(),
            status,
            refused_by: None,
            served_by: None,
        }
    }

    pub(crate) fn from_error(repo_url: impl Into<String>, err: &rv_repo::RepoError) -> Self {
        Self::new(repo_url, RepoStatus::from_repo_error(err))
    }

    /// Record a failed fetch from `repo`, naming the mirror the request went
    /// to, if any, and the repository that served it, after mirroring, when
    /// the failure was an authentication refusal.
    pub(crate) fn from_fetch_error(
        repo: &rv_repo::Repository,
        err: &rv_repo::RepoError,
        effective_repository: impl FnOnce(&rv_repo::Repository) -> rv_repo::Repository,
    ) -> Self {
        let mut status = Self::from_error(repo.url.as_str(), err);
        let served_by = effective_repository(repo);
        if served_by.url != repo.url {
            status.served_by = Some(served_by.url.clone());
        }
        if let rv_repo::RepoError::Unauthorized {
            status: code, sent, ..
        } = err
            && matches!(code.as_u16(), 401 | 403)
        {
            status.refused_by = Some(CredentialTarget {
                id: served_by.id,
                url: served_by.url,
                sent: sent.as_deref().cloned(),
            });
        }
        status
    }
}

/// A transitive repository ignored by the default-deny policy.
/// Not-found errors include it when its declaring POM is on the dependency path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedRepo {
    /// The repository URL as the POM declared it, not redacted.
    pub url: String,
    /// `group:artifact:version` of the POM that declared the repository.
    pub declared_by: String,
    /// Whether the declaration enables releases.
    pub releases_enabled: bool,
    /// Whether the declaration enables snapshots.
    pub snapshots_enabled: bool,
    /// Whether it was refused as plain HTTP to a host that is not
    /// loopback, rather than for being transitive.
    pub http_blocked: bool,
}

/// How one repository answered a request, as a not-found or repository
/// error lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoStatus {
    /// An HTTP status code.
    Http(u16),
    /// The request or the body transfer timed out.
    Timeout,
    /// The TLS handshake or certificate check failed.
    Tls,
    /// No connection could be made.
    Connect,
    /// Any other transport failure, including a body transfer cut short.
    Network,
    /// Credentials for the repository could not be set up.
    Auth,
    /// The repository's `maven-metadata.xml` was malformed or lacked the
    /// data the lookup needed.
    InvalidMetadata,
    /// A local I/O failure while handling the response.
    Io,
    /// A failure that fits none of the other kinds.
    Other,
}

impl std::fmt::Display for RepoStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(code) => write!(f, "{code}"),
            Self::Timeout => f.write_str("timeout"),
            Self::Tls => f.write_str("TLS error"),
            Self::Connect => f.write_str("connect error"),
            Self::Network => f.write_str("network error"),
            Self::Auth => f.write_str("auth error"),
            Self::InvalidMetadata => f.write_str("invalid metadata"),
            Self::Io => f.write_str("I/O error"),
            Self::Other => f.write_str("error"),
        }
    }
}

impl RepoStatus {
    pub(crate) fn from_repo_error(err: &rv_repo::RepoError) -> Self {
        if let Some(code) = err.status_code() {
            return RepoStatus::Http(code);
        }

        match err.cause() {
            rv_repo::RepoError::Http(err) if err.is_timeout() => RepoStatus::Timeout,
            rv_repo::RepoError::Http(err) if rv_http::tls_cause(err).is_some() => RepoStatus::Tls,
            rv_repo::RepoError::Http(err) if err.is_connect() => RepoStatus::Connect,
            rv_repo::RepoError::Http(_) => RepoStatus::Network,
            rv_repo::RepoError::Transfer(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                RepoStatus::Timeout
            }
            rv_repo::RepoError::Transfer(_) => RepoStatus::Network,
            rv_repo::RepoError::AuthSetup(_) => RepoStatus::Auth,
            rv_repo::RepoError::InvalidMetadata(_) => RepoStatus::InvalidMetadata,
            rv_repo::RepoError::Io(_) => RepoStatus::Io,
            _ => RepoStatus::Other,
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
#[non_exhaustive]
pub struct ConflictingPom {
    /// The POM's bare `g:a:v`.
    pub coord: String,
    /// Where the first observation came from: a reactor module path, or a
    /// `platform/module` pair when the two sides are on different platforms,
    /// and the repository that served it. Within one resolution, the
    /// repository alone, empty where none had the POM.
    pub first_origin: String,
    /// Where the second observation came from, in the same form.
    pub second_origin: String,
    /// SHA-256 of the first origin's bytes, as 64 lowercase hex characters.
    pub first_sha256: String,
    /// SHA-256 of the second origin's bytes, in the same form.
    pub second_sha256: String,
}

/// Why a resolution, or assembling resolutions into lock rows, failed.
#[derive(Debug, Error)]
pub enum ResolveError {
    /// Hard version ranges (`[1.0]`, `[1.0,2.0)`) requested for one group
    /// and artifact leave no acceptable version: no candidate seen so far
    /// satisfies all of them.
    #[error(
        "version conflict for {}: requested {}, selected {}",
        bounded(coord),
        bounded(requested),
        bounded(selected)
    )]
    VersionConflict {
        /// `group:artifact` of the conflicting dependency.
        /// The artifact coordinate as raeva.lock records it.
        coord: String,
        /// The hard requirement of the declaration that failed.
        requested: String,
        /// The version selected before that declaration.
        selected: String,
    },
    /// Following `<relocation>` elements returned to a coordinate already
    /// on the chain. Holds the chain, coordinates joined by ` -> `.
    #[error("relocation cycle detected: {0}")]
    RelocationCycle(String),
    /// A reactor module depends, directly or transitively, on a module that
    /// depends back on it.
    #[error("workspace dependency cycle detected: {cycle}")]
    WorkspaceDependencyCycle {
        /// `group:artifact` of each module on the cycle, joined by ` -> `,
        /// ending where it starts.
        cycle: String,
    },
    /// Two modules of one platform resolved different bytes for one artifact
    /// coordinate; a platform's artifact rows are shared, so raeva.lock cannot
    /// pin both. Returned by [`crate::lock::assemble`].
    #[error(
        "artifact {coord} resolved to different bytes in reactor modules \
         {first_module} ({first_blob}) and {second_module} ({second_blob})"
    )]
    ConflictingArtifactBytes {
        /// The artifact coordinate as raeva.lock records it.
        coord: String,
        /// POM path of the module whose row was recorded first.
        first_module: String,
        /// POM path of the module that disagreed.
        second_module: String,
        /// SHA-256 (the content-store blob id) of the first module's bytes.
        first_blob: String,
        /// SHA-256 of the second module's bytes.
        second_blob: String,
    },
    /// Two modules fetched different bytes for one parent or imported BOM.
    /// Returned by [`crate::lock::assemble`].
    #[error(
        "support POM {} (parent or imported BOM) resolved to different bytes in reactor \
         modules {} ({}) and {} ({}); one lockfile cannot pin both",
        .0.coord, .0.first_origin, .0.first_sha256, .0.second_origin, .0.second_sha256
    )]
    ConflictingSupportPomBytes(Box<ConflictingPom>),
    /// Two modules, possibly on different platforms, parsed different
    /// companion `.pom` bytes for one `g:a:v`, each origin with the
    /// repository that served it. Returned by [`crate::lock::assemble`].
    #[error(
        "companion POM for {} resolved to different bytes in {} ({}) and {} ({}); \
         Maven has one local-repository path per coordinate, so one lockfile cannot pin both",
        .0.coord, .0.first_origin, .0.first_sha256, .0.second_origin, .0.second_sha256
    )]
    ConflictingCompanionPomBytes(Box<ConflictingPom>),
    /// A `pom`-packaged dependency without a classifier resolved different
    /// bytes for its artifact and its companion POM, which are one file in
    /// Maven's layout.
    #[error(
        "pom-packaged dependency {coord} resolved its artifact to {artifact_sha256} and its \
         companion POM to {pom_sha256}, but for packaging=pom those are the same Maven file; \
         one lockfile row cannot pin both"
    )]
    ConflictingPomPackagedBytes {
        /// The resolved coordinate.
        coord: String,
        /// SHA-256 of the artifact bytes.
        artifact_sha256: String,
        /// SHA-256 of the companion POM bytes.
        pom_sha256: String,
    },
    /// One module's resolution fetched a POM more than once and got
    /// different bytes back.
    #[error(
        "POM {} was fetched more than once during resolution and returned different \
         bytes ({}, {}); one lockfile cannot pin both",
        .0.coord,
        served_by(&.0.first_sha256, &.0.first_origin),
        served_by(&.0.second_sha256, &.0.second_origin)
    )]
    ConflictingResolvedPomBytes(Box<ConflictingPom>),
    /// No repository had the metadata or the file for `coord`, and none
    /// failed in a way that [`ResolveError::Repo`] reports instead.
    #[error("artifact not found: {coord}")]
    ArtifactNotFound {
        /// `group:artifact` when version metadata was missing, the full
        /// coordinate when a file was.
        coord: String,
        /// Each repository tried, in order. Empty when the error does not
        /// come from a fetch, such as a resolved node left without a pin.
        searched: Vec<RepoSearchStatus>,
        /// Ignored transitive repositories declared on the path to `coord`.
        dropped_repos: Vec<DroppedRepo>,
        /// os-maven-plugin's `os.detected.classifier` for the platform, when
        /// the missing file's classifier is exactly that with the
        /// `os.detection.classifierWithLikes` entry the plugin appends on
        /// this machine.
        classifier_like: Option<String>,
    },
    /// An external artifact has to be fetched and the module has no
    /// repositories at all.
    #[error("no repositories configured")]
    NoRepositories,
    /// A dependency declares no `<version>` and neither dependency
    /// management nor a platform constraint supplies one.
    #[error(
        "missing version for dependency {}:{}",
        bounded(group_id),
        bounded(artifact_id)
    )]
    MissingVersion {
        /// The dependency's group id.
        group_id: String,
        /// The dependency's artifact id.
        artifact_id: String,
    },
    /// A `<version>` that is neither a version, a range, nor `RELEASE` /
    /// `LATEST`, or uses dynamic syntax raeva does not support.
    #[error(
        "invalid version requirement for {}: {}",
        bounded(coord),
        bounded(value)
    )]
    InvalidVersionRequirement {
        /// `group:artifact` of the dependency.
        coord: String,
        /// The requirement as written, trimmed.
        value: String,
    },
    /// A dependency's coordinate still holds a `${...}` once its POM is
    /// interpolated: no property defines the name.
    #[error(
        "property {} is not defined: {} declares {}",
        bounded(property),
        bounded(declared_by),
        bounded(coord)
    )]
    UndefinedProperty {
        /// The dependency's coordinate as interpolated.
        coord: String,
        /// The first name left undefined.
        property: String,
        /// The POM that declares the dependency: a project POM's path or a
        /// `group:artifact:version`.
        declared_by: String,
    },
    /// Version metadata was found but no listed version satisfies the
    /// requirement.
    #[error(
        "no available version for {} matching {}",
        bounded(coord),
        bounded(requirement)
    )]
    VersionNotFound {
        /// `group:artifact` of the dependency.
        coord: String,
        /// The requirement nothing matched.
        requirement: String,
    },
    /// The dependency graph reached one of the solver's fixed bounds, which
    /// stop a hostile or runaway graph from growing without limit.
    #[error("dependency graph exceeds {limit} {what} at {}", bounded(coord))]
    GraphLimitExceeded {
        /// What the bound counts.
        what: &'static str,
        /// The bound that was reached.
        limit: u64,
        /// `group:artifact` of the declaration past the bound.
        coord: String,
    },
    /// Declarations kept overturning the winner of one artifact, so its
    /// mediation has no version to settle on.
    #[error(
        "mediation of {} did not settle after {changes} changes of its version",
        bounded(coord)
    )]
    MediationDiverged {
        /// `group:artifact` of the dependency.
        coord: String,
        /// The bound on winner changes that was reached.
        changes: u32,
    },
    /// A resolution step that needs the network ran without a repository
    /// client. [`crate::Resolver`] always holds one, so this marks a bug.
    #[error("repository client missing from resolve context")]
    MissingRepoClient,
    /// A `-SNAPSHOT` version is needed and no configured repository enables
    /// snapshots.
    #[error(
        "no snapshot-enabled repository available for {}: {message}",
        bounded(coord)
    )]
    NoSnapshotRepository {
        /// The snapshot coordinate.
        coord: String,
        /// Which repositories were considered (ids bounded), and the fix.
        message: String,
    },
    /// A timestamped snapshot's build number does not fit the `u32` raeva.lock
    /// stores.
    #[error(
        "snapshot {} has a build number above {}, which raeva.lock cannot record",
        bounded(coord),
        u32::MAX
    )]
    UnrecordableSnapshotBuild {
        /// The resolved snapshot coordinate.
        coord: String,
    },
    /// Configuration could not be used, including a root `pom.xml` over the
    /// project input size limit.
    #[error("config error: {0}")]
    Config(#[from] rv_config::ConfigError),
    /// The content store failed.
    #[error("store error: {0}")]
    Store(#[from] rv_store::StoreError),
    /// A repository failed in a way other than not having the file, such as
    /// a refusal, a transport error or a bad checksum.
    #[error("repo error: {source}")]
    Repo {
        /// The coordinate being fetched, when the failure concerns a file or metadata.
        coord: Option<String>,
        /// The repository failure being reported.
        #[source]
        source: Box<rv_repo::RepoError>,
        /// Each repository tried, in order.
        searched: Vec<RepoSearchStatus>,
    },
    /// A POM, one of its parents or an imported BOM could not be parsed or
    /// built into a model, or a remote parent of the root declares a
    /// repository whose URL scheme is not `http`, `https` or `file`.
    #[error("pom error: {0}")]
    Pom(#[from] rv_maven_model::PomError),
    /// A reactor module's own `pom.xml` could not be parsed or built into a
    /// model: invalid build coordinates, a `system` dependency without an
    /// absolute `<systemPath>`, a property cycle, a `<parent>` that keeps a
    /// `${...}`, or a repository it or a local parent declares whose URL
    /// scheme is not `http`, `https` or `file`.
    #[error("invalid pom.xml at {path}: {source}")]
    LocalPom {
        /// The module POM's path, [`crate::Workspace::root`] joined with the
        /// module's, as [`std::path::Path::display`] prints it.
        path: String,
        /// What is wrong with it.
        #[source]
        source: rv_maven_model::PomError,
    },
    /// A version string could not be parsed.
    #[error("version error: {0}")]
    Version(#[from] rv_maven_types::VersionError),
    /// A local read failed, such as the root `pom.xml` being missing or
    /// unreadable.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The all-reactor resolution raised no progress event for
    /// `stalled_for_secs`: no module started or finished a phase, no request
    /// was attempted, no response or failure came back, no blob was verified,
    /// no support POM was written. That is not slowness (real work raises
    /// events as it goes, and a failing repository raises them too); it means
    /// the resolution can no longer make progress, so this fails loudly
    /// instead of hanging a build forever.
    #[error(
        "reactor resolution stalled: no progress for {stalled_for_secs}s while resolving {modules}"
    )]
    WorkspaceStalled {
        /// The modules that were still in flight, comma separated. Empty when
        /// the stall happened between phases.
        modules: String,
        /// How long nothing happened, in whole seconds.
        stalled_for_secs: u64,
    },
    /// A state the resolver's stages should rule out, such as a resolved
    /// artifact with no companion POM recorded, a module whose model
    /// resolves to another GAV than discovery found, or a cancelled
    /// resolution task. Holds the description.
    #[error("internal error: {0}")]
    InternalError(String),
    /// A failure that concerns one declared dependency, with where it is
    /// declared.
    #[error("{error}")]
    Declared {
        /// The POM path, relative to the reactor root, of the module whose
        /// graph failed. Empty until the reactor pass names it.
        module: String,
        /// `group:artifact:version` of each POM from the module's direct
        /// dependency down to the one that declares the failed dependency.
        /// Empty when the module declares it.
        via: Vec<String>,
        /// The failure itself.
        error: Box<ResolveError>,
    },
    /// More than one artifact of a module failed to download. The errors
    /// follow the graph's order, not the order downloads finished in.
    #[error("{} artifact fetch error(s), first: {first}", .rest.len() + 1)]
    MultipleArtifactErrors {
        /// The first failure in graph order.
        first: Box<ResolveError>,
        /// The other failures, in graph order.
        rest: Vec<ResolveError>,
    },
}

impl ResolveError {
    /// The failure without the [`ResolveError::Declared`] context around it.
    pub fn cause(&self) -> &ResolveError {
        match self {
            Self::Declared { error, .. } => error.cause(),
            other => other,
        }
    }

    /// This failure, for a dependency declared below the POMs `via` names.
    pub(crate) fn declared_via(self, via: Vec<String>) -> Self {
        match self {
            Self::Declared { .. } => self,
            error => Self::Declared {
                module: String::new(),
                via,
                error: Box::new(error),
            },
        }
    }

    /// This failure, met while loading the model of `coord`, a relocation
    /// or management target: a fault in that model, or in one below it that
    /// already names its POM, is put below `coord`.
    pub(crate) fn in_model_of(self, coord: &rv_maven_types::Coord) -> Self {
        let coord = format!("{}:{}:{}", coord.group_id, coord.artifact_id, coord.version);
        match self {
            Self::Declared {
                module,
                mut via,
                error,
            } if module.is_empty() => {
                via.insert(0, coord);
                Self::Declared { module, via, error }
            }
            Self::Pom(_) => self.declared_via(vec![coord]),
            other => other,
        }
    }

    /// This failure, raised while resolving the graph of the module at
    /// `module`. Failures that name their file or concern no dependency
    /// stay as they are.
    pub(crate) fn in_module(self, module: &str) -> Self {
        match self {
            Self::Declared {
                module: named,
                via,
                error,
            } if named.is_empty() => Self::Declared {
                module: module.to_string(),
                via,
                error,
            },
            Self::MultipleArtifactErrors { first, rest } => Self::MultipleArtifactErrors {
                first: Box::new(first.in_module(module)),
                rest: rest.into_iter().map(|err| err.in_module(module)).collect(),
            },
            Self::Declared { .. }
            | Self::LocalPom { .. }
            | Self::Config(_)
            | Self::Store(_)
            | Self::Io(_)
            | Self::InternalError(_)
            | Self::MissingRepoClient
            | Self::NoRepositories
            | Self::WorkspaceStalled { .. }
            | Self::WorkspaceDependencyCycle { .. } => self,
            error => Self::Declared {
                module: module.to_string(),
                via: Vec::new(),
                error: Box::new(error),
            },
        }
    }
}

/// `sha256` and the repository that served those bytes, if one did.
fn served_by(sha256: &str, repo: &str) -> String {
    match repo {
        "" => sha256.to_string(),
        repo => format!("{sha256} from {repo}"),
    }
}

/// The first `${name}` left in `text`, the name of a property nothing
/// defined.
pub(crate) fn undefined_property(text: &str) -> Option<&str> {
    let first = text.find("${")?;
    let end = first + text[first..].find('}')?;
    // The innermost of `${outer.${inner}}`, which left the outer one unread.
    let start = text[..end].rfind("${")? + 2;
    Some(&text[start..end])
}

#[cfg(test)]
mod tests {
    use super::ResolveError;

    #[test]
    fn multiple_artifact_errors_shows_count_and_first_error() {
        let not_found = |coord: &str| ResolveError::ArtifactNotFound {
            coord: coord.to_string(),
            searched: vec![],
            dropped_repos: vec![],
            classifier_like: None,
        };
        let err = ResolveError::MultipleArtifactErrors {
            first: Box::new(not_found("com.example:first:1.0")),
            rest: vec![
                not_found("com.example:second:2.0"),
                not_found("com.example:third:3.0"),
            ],
        };
        let rendered = err.to_string();
        assert!(rendered.contains("3 artifact fetch error(s)"), "{rendered}");
        assert!(rendered.contains("com.example:first:1.0"), "{rendered}");
    }
}
