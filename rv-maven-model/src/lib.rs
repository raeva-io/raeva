//! Maven POM parsing and effective model computation for Raeva.
//!
//! This crate parses pom.xml files and computes the effective POM
//! after applying parent inheritance, property interpolation, and profiles.

mod activation;
mod dependency;
mod error;
#[allow(clippy::field_reassign_with_default)]
mod inheritance;
mod pom;
mod profile;
mod project;
mod properties;
mod repository;
mod scope;

pub use activation::{Activation, ActivationContext};
pub use dependency::{Dependency, DependencyManagement, Exclusion};
pub use error::PomError;
pub use inheritance::ParentResolver;
pub use pom::{Parent, Pom, Relocation};
pub use project::Project;
pub use properties::{env_substitution_allowlist, set_env_substitution_allowlist};
pub use repository::Repository;
pub use scope::Scope;

// Crate-internal re-exports used by sibling modules.
pub(crate) use profile::Profile;

// PropertyMap is exposed as a public primitive so downstream crates and the
// benchmark suite can exercise Maven-style ${...} interpolation directly.
pub use properties::PropertyMap;
