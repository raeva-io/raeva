//! The Maven vocabulary Raeva shares: versions and ranges, coordinates,
//! repository layout, digests, purls and the coordinate character rules.
//!
//! Everything here is a value type or a pure function: the crate does no
//! network or repository access, reads no environment variables, and only
//! touches the filesystem when a digest hashes a file. It does not resolve
//! dependencies or read POMs. Parsing and validation are separate:
//! [`Coord::parse`], [`Gav::new`] and the [`layout`] functions accept any
//! characters, and a value from an untrusted source goes through
//! [`validate_coordinate_component`] before it reaches a path, a URL or a
//! terminal.

mod component;
mod coord;
mod digest;
mod error;
mod id;
pub mod layout;
mod par;
mod purl;
mod range;
mod snapshot;
mod text;
mod version;

pub use component::{
    CoordinateField, InvalidCoordinateComponent, MAX_COMPONENT_BYTES, is_maven_id_text,
    is_terminal_safe, validate_coordinate_component, validate_reactor_version,
};
pub use coord::{ArtifactCoord, Coord, Gav, PartialCoord};
pub use digest::{BlobId, Digest, DigestError, HashAlgorithm, Md5, Sha1, Sha256};
pub use error::VersionError;
pub use id::{ArtifactId, GroupId};
pub use par::par_map;
pub use purl::{
    PurlError, canonicalize_purl, maven_purl, maven_purl_name_version, maven_purl_with_qualifiers,
};
pub use range::{VersionRange, VersionReq};
pub use snapshot::{
    SnapshotStamp, TimestampedSnapshot, is_listed_snapshot_version, is_snapshot_timestamp,
    is_snapshot_version, resolves_through_snapshot_metadata, snapshot_base_version,
    timestamped_snapshot_version,
};
pub use text::{Untrusted, bounded, quoted};
pub use version::Version;
