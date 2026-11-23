//! The `raeva.lock` model for Raeva.
//!
//! [`Lockfile`] reads and writes `raeva.lock`, which has schema
//! [`LOCKFILE_SCHEMA_VERSION`]; a lockfile of any other schema is refused.
//! [`LockfileGuard`] serializes the read-modify-write of one lockfile across
//! processes. [`Platform`] names the `os-arch` a resolution is recorded for.
//! [`LockOrigins`] decides how the lock spells a repository origin, with a
//! `file:` repository inside the project recorded as a project-relative
//! token. [`inputs`] holds the recipes for the `config_hash` and
//! `model_hash` a lockfile records and the checks that it still matches them.
//! [`drift`] compares a recorded lockfile with a fresh resolution, and
//! [`merge`] decides which platforms of the previous lockfile a run that
//! resolved only some platforms carries forward. [`conflict`] splits a lock's
//! text at its Git merge conflicts.
//!
//! The crate does not resolve dependencies, parse POMs, read configuration
//! or fetch anything. Callers build a [`Lockfile`] from a resolution and
//! gather the hash inputs themselves; the only files it reads are raeva.lock,
//! its guard file and the system-scoped files ([`SystemFile`]) a lock pins.

mod ambient;
mod checksums;
mod codec;
pub mod conflict;
pub mod drift;
mod error;
mod guard;
pub mod inputs;
mod lock;
mod lock_origin;
pub mod merge;
mod pinned;
mod platform;
mod plugins;
mod split_parse;
mod system;
#[cfg(test)]
mod test_lock;

pub use ambient::{AmbientInput, HostCondition, InvalidAmbientInput, MAX_CONDITION_TEXT_LEN};
pub use codec::is_command_line_name;
pub use error::LockError;
pub use guard::LockfileGuard;
pub use lock::{
    EvictedRange, ExtensionJar, LOCKFILE_SCHEMA_VERSION, LockArtifact, LockEdge, LockModule,
    LockModulePackage, LockPlatform, LockResolution, Lockfile, MAX_LOCKFILE_BYTES, MetadataVersion,
    MetadataVersionKind, ModelInputs, PackageSource, ParentRange, PinnedSnapshot, RangeVersion,
    RepoIds, SupportPom, TargetReads, split_support_pom_coord,
};
pub use lock_origin::{
    LockOrigins, OriginAlias, OriginSelection, file_url_path, is_http_origin,
    is_project_relative_origin, is_recordable_repo_id, normalize_repo_url, recorded_key,
    redact_origin,
};
pub use pinned::{PinnedFile, PinnedFiles, PinnedRow, pinned_once};
pub use platform::{InvalidPlatform, Platform};
pub use plugins::{
    DescriptorReads, PluginFiles, PluginPrefix, PluginRole, PluginSet, PluginTables, PomReader,
    PomReads, pomless_read, read_difference, several_unrecordable_plugin_origins,
    unrecordable_plugin_origin, unrecorded_origins,
};
pub use rv_maven_types::{InvalidScope, Scope, SnapshotStamp};
pub use system::{SystemFile, SystemPathError};
