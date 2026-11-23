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
//! Of `<build>`, the single values `${project.build.*}` reads and the
//! plugin sections are parsed; resources are not. A project build's
//! [`Project::plugins`] gives its effective plugin model, which plugin
//! locking reads and dependency resolution does not.
//!
//! Host reads are deliberate and few. [`HostSnapshot::capture`] reads the
//! environment variables `JAVA_HOME` and `JAVA_VERSION`, the `release`
//! file of the JDK Maven runs (`JAVA_HOME`, else the `java` on `PATH`), and
//! the variables in the caller's `${env.*}`
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
pub mod file_transport;
mod handler;
pub mod held;
mod inheritance;
pub mod mavenrc;
mod metadata;
mod model;
mod plugin;
mod pom;
mod profile;
mod project;
mod properties;
mod provenance;
mod relevance;
mod repository;
mod source;
mod strict;
mod xml;

pub use activation::{
    Activation, ActivationContext, ActivationFile, ActivationOs, ActivationProperty, HostProperty,
    PLATFORM_PROPERTIES, PropertySource, answered_host_properties, expand_host_properties,
    fixed_over_jvm_config, host_property, jvm_config_by_jdk, jvm_owned, unread_host_reference,
    unread_property_fix,
};
pub use dependency::{
    Dependency, DependencyManagement, Exclusion, ManagedOrigin, ProjectDirectory,
};
pub use effective::{EffectiveDescriptor, Gav};
#[cfg(any(test, feature = "testing"))]
pub use environment::{AVX512_VBMI_TEST_ENV, JAVA_PATH_TEST_ENV, OS_RELEASE_TEST_ENV};
pub use environment::{
    ClassifierLikes, HostInput, HostReads, HostSnapshot, JdkRelease, ModelEnvironment,
    ModelEnvironmentBuilder, avx512_vbmi_cpu, launcher_root,
};
pub use error::{ParentCoordMismatch, PomError};
pub use handler::{
    ArtifactHandler, ArtifactTypes, ClassFiles, DefinedType, is_core_type, merge_realm_handlers,
    read_artifact_handlers,
};
pub use inheritance::{
    MAX_PARENT_CHAIN_DEPTH, local_parent_in_range, parent_has_expression, parent_version_range,
};
pub use mavenrc::mavenrc_paths;
pub use metadata::EffectiveMetadata;
pub use plugin::{
    ConfigNode, CoreExtension, DEFAULT_PLUGIN_GROUP, EffectivePlugins, Extension, MappedMojo,
    Plugin, PluginDescriptor, PluginExecution, ProcessorPath, ProcessorPaths,
    parse_core_extensions, parse_exported_artifacts, parse_lifecycle_mappings,
    parse_plugin_descriptor,
};
pub use pom::{License, Parent, Pom, Relocation};
pub use profile::Profile;
pub use project::{ImportedBom, Project};
pub use provenance::Provenance;
pub use repository::Repository;
pub use rv_maven_types::Scope;
pub use source::{
    ImportCoord, MAX_IMPORT_DEPTH, MissingParent, ModelPolicy, ModelSource, ParentLookup,
    PluginModel, ready,
};
#[cfg(test)]
pub(crate) use source::{MemorySource, MemorySourceError};
pub use strict::check_project_pom;
pub use xml::{MavenEntities, decode_pom};

// PropertyMap is exposed as a public primitive so downstream crates and the
// benchmark suite can exercise Maven-style ${...} interpolation directly.
pub use properties::{ModelLookup, PropertyMap, directory_uri};
