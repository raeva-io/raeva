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
        }
    }
}
