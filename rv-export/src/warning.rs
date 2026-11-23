use std::fmt;
use std::path::PathBuf;

/// A condition an export survived but the user should hear about.
///
/// Warnings are returned in [`ExportStats::warnings`](crate::ExportStats) and
/// from [`ExportPlan::authorize_classifiers`](crate::ExportPlan), never
/// logged: the caller decides where they go. The text names the condition
/// only; advice that depends on how the caller is invoked, such as which
/// command to run, is the caller's to add. Values that came from POMs or
/// raeva.lock are untrusted text, so a terminal front end must escape them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportWarning {
    /// Dependencies with a `systemPath` have no bytes in the content store
    /// and were not exported.
    SystemScopedSkipped {
        /// Their `g:a:v`, sorted and deduplicated.
        coordinates: Vec<String>,
    },
    /// The mode of a copied artifact could not be set to writable-by-owner.
    PermissionsNotSet {
        /// The destination file.
        path: PathBuf,
        /// The error setting the mode returned.
        reason: String,
    },
    /// The support-POM limit variable was set to something unusable, so the
    /// default limit applies.
    SupportPomLimitIgnored {
        /// [`MAX_SUPPORT_POM_NODES_ENV`](crate::MAX_SUPPORT_POM_NODES_ENV).
        variable: &'static str,
        /// The value the caller passed, as given.
        value: String,
    },
    /// raeva.lock records an origin for a coordinate that no configured
    /// repository, mirror or project POM declares, so its classifier jars
    /// were not fetched. `origin` is already redacted.
    UntrustedClassifierOrigin {
        /// The row's group id.
        group_id: String,
        /// The row's artifact id.
        artifact_id: String,
        /// The version in the file names, the timestamped build of a
        /// snapshot.
        version: String,
        /// The recorded origin, redacted.
        origin: String,
    },
    /// `mvn -o` may read version lists under these repository ids, and the
    /// export writes none: an id no file name can carry, or one a reactor
    /// POM spells with an expression its properties do not resolve. A
    /// range, SNAPSHOT, `RELEASE`
    /// or `LATEST` may then resolve from a tail's list under the id.
    UnusableRepositoryIds {
        /// The ids, sorted.
        ids: Vec<String>,
    },
    /// raeva.lock records no repository id for these origins, so their files
    /// are labelled `central`, which `mvn -o` accepts only where it reads
    /// `central` itself or through a mirror the export knows.
    RepositoryIdGuessed {
        /// The origins, redacted and sorted.
        origins: Vec<String>,
    },
    /// Version ranges that lost mediation name no version the export lists
    /// otherwise, so `mvn -o`, which still lists them, would find none
    /// ("No versions available"). Outside the shared repository a version
    /// a repository listed for each is listed under that repository's ids,
    /// the highest whose POM the export writes or else the lowest; for the
    /// latter raeva.lock pins no POM, so Maven warns that its POM is
    /// missing. In the shared repository nothing is listed.
    LosingRangeVersions {
        /// The `g:a:v` of each version listed for such a range whose POM
        /// the export does not write, sorted.
        coordinates: Vec<String>,
        /// The versions were listed.
        listed: bool,
    },
    /// An earlier export into this local repository stopped before it
    /// finished, so `mvn -o` there may read the files of one lock with the
    /// metadata of another.
    UnfinishedExport {
        /// The local repository.
        path: PathBuf,
        /// This export wrote every file and metadata the plan names and
        /// cleared the record, which a dry run does not.
        repaired: bool,
    },
}

impl fmt::Display for ExportWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemScopedSkipped { coordinates } => write!(
                f,
                "system-scoped dependencies not exported (systemPath artifacts are not in the content-addressed store): {}",
                coordinates.join(", ")
            ),
            Self::PermissionsNotSet { path, reason } => write!(
                f,
                "could not make {} writable by its owner: {reason}",
                path.display()
            ),
            Self::SupportPomLimitIgnored { variable, value } => write!(
                f,
                "ignoring {variable}={value:?}, which is not a positive number; using the default support-POM limit"
            ),
            Self::UntrustedClassifierOrigin {
                group_id,
                artifact_id,
                version,
                origin,
            } => write!(
                f,
                "skipping classifier jars for {group_id}:{artifact_id}:{version}: raeva.lock records the origin {origin}, which no configured repository, mirror or project POM declares"
            ),
            Self::UnusableRepositoryIds { ids } => write!(
                f,
                "no version list written under the repository ids {}, which no file name can carry or which hold an expression",
                ids.join(", ")
            ),
            Self::RepositoryIdGuessed { origins } => write!(
                f,
                "raeva.lock records no repository id for {}; their files are labelled central",
                origins.join(", ")
            ),
            Self::LosingRangeVersions {
                coordinates,
                listed: true,
            } => write!(
                f,
                "listed versions of version ranges that lose mediation, whose POMs raeva.lock does not pin: {}",
                coordinates.join(", ")
            ),
            Self::LosingRangeVersions {
                coordinates,
                listed: false,
            } => write!(
                f,
                "version ranges that lose mediation name no locked version, and the shared local repository does not list theirs: {}",
                coordinates.join(", ")
            ),
            Self::UnfinishedExport { path, repaired } => write!(
                f,
                "an earlier export into {} did not finish; {}",
                path.display(),
                if *repaired {
                    "this export repaired it"
                } else {
                    "it is not repaired yet"
                }
            ),
        }
    }
}
