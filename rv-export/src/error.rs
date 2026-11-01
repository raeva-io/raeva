use std::path::PathBuf;

use thiserror::Error;

use rv_store::StoreError;

use super::link::LinkStrategy;
use super::warning::ExportWarning;

pub(crate) type Result<T> = std::result::Result<T, ExportError>;

/// Why an export, or building an [`ExportPlan`](crate::ExportPlan), failed.
///
/// Every check that inspects the plan as a whole (pins, coordinates, names,
/// collisions, the support-POM closure) runs before the first file is
/// written. Coordinates in these errors come from raeva.lock or POMs and are
/// untrusted text.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExportError {
    /// A local file system operation failed, such as creating a directory,
    /// staging a temporary file or writing metadata.
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    /// The content store failed.
    #[error("store error: {0}")]
    StoreError(#[from] StoreError),
    /// Every strategy in the fallback chain failed to put a blob in place.
    #[error("link error: {0}")]
    LinkError(#[from] LinkError),
    /// A row is pinned only by a checksum algorithm the content store is not
    /// keyed by (SHA-1), and the store's coordinate index has no blob for it.
    #[error("unsupported checksum algorithm {algorithm} for {key}")]
    UnsupportedChecksum {
        /// The row's coordinate.
        key: String,
        /// The pin's algorithm.
        algorithm: String,
    },
    /// The content store has no file for an artifact the plan writes, or the
    /// file vanished before it could be linked.
    #[error("missing blob for {key}")]
    MissingBlob {
        /// The artifact's coordinate.
        key: String,
    },
    /// The store file of a blob does not hash to the blob's id, as a torn
    /// write or a partial copy of the store leaves it.
    #[error("store corruption: blob at {} has SHA-256 {actual} but index recorded {expected}", path.display())]
    CorruptBlob {
        /// The store file.
        path: PathBuf,
        /// The file's SHA-256.
        actual: String,
        /// The blob id.
        expected: String,
    },
    /// The blob the store's coordinate index names for a row does not match
    /// the row's checksum pin, as when another project sharing the store
    /// synced other bytes for the coordinate.
    #[error(
        "lockfile pin for {key} ({algorithm}={expected}) does not match the blob in the global store ({actual})"
    )]
    PinMismatch {
        /// The row's coordinate.
        key: String,
        /// The pin's algorithm, such as `sha256`.
        algorithm: String,
        /// The pinned digest, as hex.
        expected: String,
        /// The indexed blob's digest with the pin's algorithm.
        actual: String,
    },
    /// The walk over parents and imported BOMs reached more unique POMs than
    /// the limit. The export stops instead of writing a partial closure.
    #[error(
        "support-POM closure exceeds the limit of {limit} unique POMs; refusing to write an incomplete offline repository. Raise the limit with {variable}=<count>"
    )]
    SupportClosureTooLarge {
        /// The limit in force.
        limit: usize,
        /// The environment variable a caller reads the limit from,
        /// [`MAX_SUPPORT_POM_NODES_ENV`](crate::MAX_SUPPORT_POM_NODES_ENV).
        variable: &'static str,
    },
    /// raeva.lock pins a companion or support POM by digest, and the store has
    /// no blob with that digest that a repository the lock records served.
    #[error(
        "raeva.lock pins the POM for {coordinate} to sha256 {digest}, but the content store holds no copy of those bytes that a repository raeva.lock records served; refusing to export a POM this lockfile was not resolved against"
    )]
    MissingPinnedPom {
        /// The POM's `g:a:v`.
        coordinate: String,
        /// The pinned SHA-256, as hex.
        digest: String,
    },
    /// A remote parent has no support-POM pin.
    #[error(
        "raeva.lock records no POM digest for {coordinate}; refusing to export a POM this lockfile does not pin"
    )]
    UnpinnedPom {
        /// The row's coordinate.
        coordinate: String,
    },
    /// Two artifact rows of raeva.lock that share one companion POM (other
    /// classifiers, or other platforms) pin it to different digests.
    /// Returned by [`ExportPlan::from_lock`](crate::ExportPlan::from_lock).
    #[error(
        "raeva.lock pins the POM for {coordinate} to two different digests ({first}, {second}); Maven has one local-repository path per coordinate, so no export can satisfy both"
    )]
    ConflictingPinnedPom {
        /// The POM's `g:a:v`.
        coordinate: String,
        /// The digest seen first.
        first: String,
        /// The digest that disagreed.
        second: String,
    },
    /// A `pom`-packaged row without a classifier pins its artifact and its
    /// companion POM, one file in Maven's layout, to different digests.
    #[error(
        "raeva.lock pins the pom-packaged artifact {coordinate} to sha256 {artifact} but its POM to {pom}; for packaging=pom those are the same Maven file, so no export can write both"
    )]
    ConflictingPomPackagedPin {
        /// The row's `g:a:v`.
        coordinate: String,
        /// The SHA-256 the artifact resolves to.
        artifact: String,
        /// The pinned POM SHA-256.
        pom: String,
    },
    /// Two independent records name different bytes for one file: an
    /// artifact row, a row's companion POM pin, or the support-POM closure.
    #[error(
        "{coordinate} is claimed by two different files: {first_source} names sha256 {first}, {second_source} names sha256 {second}; Maven has one local-repository path per coordinate, so no export can write both"
    )]
    ConflictingExportSources {
        /// The file's coordinate.
        coordinate: String,
        /// Which record queued the file first.
        first_source: &'static str,
        /// The SHA-256 that record names.
        first: String,
        /// Which record disagreed.
        second_source: &'static str,
        /// The SHA-256 that record names.
        second: String,
    },
    /// Two files, or artifact or version directories, differ only in letter
    /// case and the destination's file system folds case, so one would
    /// overwrite the other.
    #[error(
        "{first} and {second} differ only in letter case, and the file system holding {path:?} does not distinguish case, so both would be written to the same file"
    )]
    CaseCollision {
        /// The coordinate queued first.
        first: String,
        /// The coordinate that collides with it.
        second: String,
        /// The second coordinate's colliding file or directory under the
        /// destination.
        path: PathBuf,
    },
    /// A coordinate field that becomes a path segment is refused by
    /// [`rv_maven_types::validate_coordinate_component`]: empty, over 255
    /// bytes, holding a separator, `..` or a character outside the field's
    /// set, or ending in `.`. Holds the coordinate and the reason.
    #[error("invalid coordinate: {0}")]
    InvalidCoordinate(String),
    /// A path segment of a coordinate is a name Windows cannot store as
    /// written. Refused on every platform, since a local repository is often
    /// read on Windows later.
    #[error(
        "{coordinate} would be written to the name {name:?}, which Windows cannot store as written (a device name such as CON or NUL, a trailing dot or space, a reserved character, or more than 255 characters), so the repository could not be copied to or used on a Windows volume"
    )]
    WindowsUnsafeName {
        /// The coordinate.
        coordinate: String,
        /// The refused segment.
        name: String,
    },
    /// A path segment of a coordinate has the shape of an NTFS 8.3 short
    /// name, such as `LONGAR~1`. Refused on every platform.
    #[error(
        "{coordinate} would be written to the name {name:?}, which has the form of an NTFS 8.3 short name; on a volume that generates short names it can address a different file of the same directory"
    )]
    ShortNameAlias {
        /// The coordinate.
        coordinate: String,
        /// The refused segment.
        name: String,
    },
    /// A destination path resolves, after canonicalizing its existing
    /// prefix, outside [`ExportOptions::m2_path`](crate::ExportOptions::m2_path),
    /// as through a symbolic link inside the local repository. Holds the
    /// destination as built, before canonicalizing.
    #[error("path traversal attempt detected: {0}")]
    PathTraversal(PathBuf),
    /// The local repository directory cannot be created, or its export
    /// lock file cannot be opened there.
    #[error("cannot use the local repository {}: {source}", path.display())]
    Destination {
        /// [`ExportOptions::m2_path`](crate::ExportOptions::m2_path).
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A destination file already holds other bytes than the locked blob
    /// and [`ExportOptions::overwrite`](crate::ExportOptions::overwrite) is
    /// off.
    #[error(
        "destination {path:?} already exists with different bytes than raeva.lock pins for {key} (expected sha256 {expected}, found {actual})"
    )]
    DestinationMismatch {
        /// The file's coordinate.
        key: String,
        /// The destination file.
        path: PathBuf,
        /// The locked SHA-256, as hex.
        expected: String,
        /// The destination's SHA-256, or `<unreadable>` when it could not be
        /// hashed.
        actual: String,
    },
}

/// An export that stopped, with the warnings it had collected before the
/// error. The caller reports both: a warning such as a missing companion POM
/// still describes the destination after a later file failed.
#[derive(Debug, Error)]
#[error("{error}")]
#[non_exhaustive]
pub struct ExportFailure {
    /// The error that stopped the export.
    pub error: ExportError,
    /// In the order found, as [`ExportStats::warnings`](crate::ExportStats).
    pub warnings: Vec<ExportWarning>,
}

impl From<ExportError> for ExportFailure {
    fn from(error: ExportError) -> Self {
        Self {
            error,
            warnings: Vec::new(),
        }
    }
}

/// Why a blob could not be put at its destination.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The last attempt in the fallback chain failed, or the source could
    /// not be inspected.
    #[error("{strategy} failed for {src:?} -> {dest:?}: {source}")]
    IoError {
        /// The strategy that failed: the last one tried, or the requested
        /// one when the source could not be inspected.
        strategy: LinkStrategy,
        /// The store's file.
        src: PathBuf,
        /// The staging path next to the destination.
        dest: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// The store's file was gone before any attempt. The exporter reports
    /// this as [`ExportError::MissingBlob`].
    #[error("source missing: {src:?}")]
    SourceMissing {
        /// The store's file.
        src: PathBuf,
    },
}
