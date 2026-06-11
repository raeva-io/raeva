//! Maven version parsing, comparison, and range matching.

mod coord;
mod error;
mod ids;
mod qualifier;
mod range;
mod version;

pub use coord::{Coord, PartialCoord};
pub use error::VersionError;
pub use ids::{ArtifactId, GroupId};
pub use range::{VersionRange, VersionReq};
pub use version::Version;

// Crate-internal re-export used by sibling modules.
pub(crate) use qualifier::Qualifier;
