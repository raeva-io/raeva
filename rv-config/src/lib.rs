//! Configuration and lockfile management.

pub mod artifact;
pub mod blob;
mod config;
mod credential;
mod encryption;
mod error;
mod limited_read;
mod lock;
mod maven_settings;
mod path_utils;
mod paths;
mod platform;
mod settings;

pub use artifact::ArtifactKey;
pub use blob::BlobId;
pub use config::{AuthConfigLayers, Config, NetworkConfig, SecurityConfig};
pub use credential::{
    AuthType, CredentialError, CredentialIndex, CredentialIndexEntry, CredentialManager,
    CredentialRecord, CredentialStore, KeyringCredentialStore, NormalizedEndpoint,
};
pub use error::{ConfigError, io_error_with_context};
pub use limited_read::{
    MAX_PROJECT_INPUT_SIZE, read_optional_project_input, read_optional_project_input_string,
    read_project_input, read_project_input_string,
};
pub use lock::{
    Checksum, LEGACY_ROOT_ARTIFACT, LEGACY_ROOT_GROUP, LEGACY_ROOT_VERSION, LOCK_SUPPORT_POMS_KEY,
    LOCKFILE_SCHEMA_VERSION, LockArtifact, LockCoordinate, LockEdge, LockGav, LockModule,
    LockModulePackage, LockPackage, LockPlatform, LockResolution, LockResolutionStrategy,
    LockSnapshot, Lockfile, LockfileGuard, SupportPomLine, decode_support_pom_lines,
    encode_support_pom_lines, normalize_checksum_algorithm,
};
pub use path_utils::canonicalize_existing_prefix;
pub use paths::ResolvedPaths;
pub use platform::Platform;
pub use settings::{
    AuthConfig, MirrorConfig, ProxyAuthType, ProxyConfig, RepoConfig, UpdatePolicy,
};
