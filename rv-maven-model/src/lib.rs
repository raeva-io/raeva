//! Maven POM parsing and effective model computation for Raeva.
//!
//! [`decode_pom`] turns POM bytes into text by the encoding they declare,
//! and [`Pom::parse`] reads that text. [`Project::build`] computes the
//! effective model: parent inheritance, active profiles, property
//! interpolation, and dependency management with BOM imports.
//! [`EffectiveDescriptor::build`] computes only the coordinates, modules and
//! repositories reactor discovery needs.
//!
//! The crate does no network or repository access. Parents and imported
//! BOMs come from a [`ModelSource`] the caller implements, and it does not
//! resolve the dependency graph, mediate versions or write a lockfile.
//! Of `<build>`, only the single values `${project.build.*}` reads are
//! parsed; plugins and resources are not part of the effective model.
//!
//! Host reads are deliberate and few. [`HostSnapshot::capture`] reads the
//! environment variables `JAVA_HOME` and `JAVA_VERSION`, the `release`
//! file under `JAVA_HOME`, and the variables in the caller's `${env.*}`
//! allowlist, once, and model builds see only that snapshot through a
//! [`ModelEnvironment`]. Profile activation reads the filesystem for
//! `<file>` conditions, relative to [`ActivationContext::base_dir`].

/// `name`, a deserializer of a list of `tag` elements of `item` in a wrapper
/// element; an absent or empty wrapper is an empty list.
macro_rules! element_list {
    ($vis:vis fn $name:ident, $tag:literal, $item:ty) => {
        $vis fn $name<'de, D>(deserializer: D) -> Result<Vec<$item>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(serde::Deserialize)]
            struct Wrapper {
                #[serde(rename = $tag, default)]
                items: Vec<$item>,
            }
            let wrapper: Option<Wrapper> = serde::Deserialize::deserialize(deserializer)?;
            Ok(wrapper.map(|wrapper| wrapper.items).unwrap_or_default())
        }
    };
}

mod activation;
mod artifact_version;
mod dependency;
mod document;
mod effective;
mod environment;
mod error;
pub mod held;
mod inheritance;
mod metadata;
mod model;
mod pom;
mod profile;
mod project;
mod properties;
mod provenance;
mod relevance;
mod repository;
mod scope;
mod source;
mod xml;

pub use activation::{
    Activation, ActivationContext, ActivationFile, ActivationOs, ActivationProperty, PropertySource,
};
pub use dependency::{Dependency, DependencyManagement, Exclusion};
pub use effective::{EffectiveDescriptor, Gav};
#[cfg(any(test, feature = "testing"))]
pub use environment::OS_RELEASE_TEST_ENV;
pub use environment::{
    ClassifierLikes, HostInput, HostReads, HostSnapshot, ModelEnvironment, ModelEnvironmentBuilder,
};
pub use error::{ParentCoordMismatch, PomError};
pub use inheritance::{
    MAX_PARENT_CHAIN_DEPTH, local_parent_in_range, parent_has_expression, parent_version_range,
};
pub use metadata::EffectiveMetadata;
pub use pom::{License, Parent, Pom, Relocation};
pub use profile::Profile;
pub use project::{ImportedBom, Project};
pub use provenance::Provenance;
pub use repository::Repository;
pub use scope::Scope;
pub use source::{
    ImportCoord, MAX_IMPORT_DEPTH, MissingParent, ModelPolicy, ModelSource, ParentLookup, ready,
};
#[cfg(test)]
pub(crate) use source::{MemorySource, MemorySourceError};
pub use xml::{MavenEntities, decode_pom};

// PropertyMap is exposed as a public primitive so downstream crates and the
// benchmark suite can exercise Maven-style ${...} interpolation directly.
pub use properties::{ModelLookup, PropertyMap};
