//! Content-addressed artifact storage for Raeva.
//!
//! [`Store`] keeps blobs named by the SHA-256 hash of their bytes, and an
//! SQLite index that maps Maven coordinates ([`rv_maven_types::ArtifactCoord`]) to blobs.
//! [`Store::put_stream_verified`] publishes a stream only after its bytes
//! match the checksums the caller names ([`Expect`]), and
//! [`Store::check_pin`] re-hashes a stored file against a lockfile pin.
//! [`Store::lookup_artifact_from`] requires the declared repository and the
//! endpoint that served it ([`Origin`]), so another repository or mirror's
//! evidence cannot satisfy a fresh resolution.
//! [`Store::check_pin_unless_unchanged`] skips files unchanged since they last
//! hashed to their id.
//! [`metadata_cache`] keeps fetched POMs and `maven-metadata.xml` files with
//! an expiry time, in a separate database whose deletion costs only
//! refetches.
//!
//! The crate does not download anything or decide which checksum is right:
//! callers fetch the bytes, pass in the digests they expect and name the
//! repository that served them. It has no garbage collection, so a blob stays on disk until
//! the store directory is deleted.

mod durability;
mod error;
mod index;
pub mod metadata_cache;
mod paths;
mod pin;
mod sqlite;
mod store;
mod verified;

pub use error::{DbFailure, StoreError};
pub use pin::{PinCheck, QueuedCheck, StoredFor};
pub use rv_maven_types::BlobId;
pub use sqlite::recreated_mid_run;
pub use store::{Origin, Store, open_unfollowed_regular};
pub use verified::{Expect, Expectation, PutError, Staged, Verified};
