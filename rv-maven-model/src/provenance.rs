//! Where a POM that `raeva` loads comes from.

use std::path::PathBuf;

/// The source of a POM, set by the loader that read it.
///
/// POM text cannot set it: [`crate::Pom::parse`] leaves it unset, and only
/// the code that read the bytes from the working tree or a repository
/// records it. It is recorded on every POM a resolution loads, so trust
/// decisions about the repositories a POM declares can be derived from it.
/// Inheritance reads it: a project repository whose URL takes a value from a
/// parent that is not local, or whose origin is unknown, loses the project's
/// trust.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Provenance {
    /// The POM the build starts from: the reactor root, or the project file
    /// when there is no reactor.
    RootProject {
        /// The POM file.
        path: PathBuf,
    },
    /// A module of the reactor other than its root.
    ReactorModule {
        /// The POM file.
        path: PathBuf,
    },
    /// A parent read from the working tree through `<relativePath>`.
    LocalParent {
        /// The POM file.
        path: PathBuf,
    },
    /// A parent of the root project or of a reactor module, or one of that
    /// parent's ancestors, fetched from a repository.
    RemoteParentOfRoot,
    /// A dependency's POM, or one of its parents, fetched from a repository.
    Dependency,
    /// A POM imported with `<scope>import</scope>`, or one of its parents,
    /// fetched from a repository.
    BomImport,
}

impl Provenance {
    /// Whether the POM was read from the working tree, so the user wrote it.
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Provenance::RootProject { .. }
                | Provenance::ReactorModule { .. }
                | Provenance::LocalParent { .. }
        )
    }
}
