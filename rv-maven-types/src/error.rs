use thiserror::Error;

use crate::text::bounded;

/// The text a variant holds comes from a POM, a lockfile or a command
/// line, so its message shows it through [`bounded`].
#[derive(Error, Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum VersionError {
    /// The string is not a version: it is empty, whitespace only or longer
    /// than 255 bytes.
    #[error("invalid version string: {}", bounded(.0))]
    InvalidVersion(String),
    /// The string is not a range that
    /// [`VersionRange::parse`](crate::VersionRange::parse) or a requirement
    /// that [`VersionReq::parse`](crate::VersionReq::parse) accepts.
    #[error("invalid version range: {}", bounded(.0))]
    InvalidRange(String),
    /// The string is not a coordinate that [`Coord::parse`](crate::Coord::parse)
    /// or [`PartialCoord::parse`](crate::PartialCoord::parse) accepts.
    #[error("invalid coordinate: {}", bounded(.0))]
    InvalidCoord(String),
    /// A version string contained a `${...}` Maven property placeholder
    /// that never got expanded. Parsing this as a real version would
    /// produce a "soft pin" that can never match a published release.
    #[error("unresolved property in version string: {}", bounded(.0))]
    UnresolvedProperty(String),
}
