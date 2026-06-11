//! Configuration and lockfile management.

pub mod artifact;
pub mod blob;
mod config;
mod encryption;
mod error;
mod lock;
mod maven_settings;
mod path_utils;
mod paths;
mod platform;
mod settings;

pub use artifact::ArtifactKey;
pub use blob::BlobId;
pub use config::{Config, NetworkConfig, SecurityConfig};
pub use error::{ConfigError, io_error_with_context};
pub use lock::{
    Checksum, LOCKFILE_SCHEMA_VERSION, LockEdge, LockPackage, LockPlatform, Lockfile,
    LockfileGuard, normalize_checksum_algorithm,
};
pub use path_utils::canonicalize_existing_prefix;
pub use paths::ResolvedPaths;
pub use platform::Platform;
pub use settings::{
    AuthConfig, MirrorConfig, ProxyAuthType, ProxyConfig, RepoConfig, UpdatePolicy,
};
