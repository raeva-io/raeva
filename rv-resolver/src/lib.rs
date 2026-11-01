//! Maven dependency resolution for Raeva.
//!
//! [`Resolver`] builds the dependency graph of a project from its `pom.xml`
//! and mediates version conflicts as Maven does. [`Workspace`] discovers the
//! active modules of a reactor.
//!
//! Resolution fetches the POMs, metadata and artifacts it needs into the
//! content store and binds each external package to the bytes it resolved
//! to. [`lock::assemble`] turns the resolutions of every platform into one
//! in-memory [`rv_lock::Lockfile`], failing when modules or platforms disagree
//! about bytes the lockfile pins once.
//!
//! This crate does not write `raeva.lock` (the caller serializes the assembled
//! lockfile), does not decide whether an existing lock is still current, and
//! does not put artifacts into a Maven local repository such as `~/.m2`
//! (that is `rv-export`). Settings come from an [`rv_config::Config`], not
//! from the process environment.

mod context;
mod error;
mod graph;
pub mod lock;
mod metadata;
mod output;
mod parent_resolver;
mod parsed_pom_cache;
mod resolver;
mod solver;
mod util;
mod workspace;

pub use error::{
    ConflictingPom, CredentialTarget, DroppedRepo, RepoSearchStatus, RepoStatus, ResolveError,
};
pub use output::{ModuleResolution, ResolvedArtifact, ResolvedPackage};
pub use resolver::{
    Resolver, SupportPomProvenance, WorkspaceModuleResolution, WorkspaceResolution,
};
pub use rv_config::maven_config::MavenConfigError;
pub use workspace::{ModuleContext, Workspace, WorkspaceError, WorkspaceModule};
