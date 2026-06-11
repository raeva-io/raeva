//! Content-addressed storage for Raeva.
//!
//! This crate implements a SHA-256 keyed blob store with SQLite index
//! for mapping Maven coordinates to stored artifacts.

mod error;
mod index;
mod paths;
mod store;

pub use error::StoreError;
pub use rv_config::{ArtifactKey, BlobId};
pub use store::{BlobOrigin, Store};
