use crate::activation::Activation;
use crate::dependency::{Dependency, DependencyManagement, deserialize_dependencies};
use crate::pom::deserialize_modules;
use crate::properties::PropertyMap;
use crate::repository::{Repository, deserialize_repositories};

/// A `<profile>` of a POM: the conditions that activate it and what it
/// adds to the model when active.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Profile {
    /// The `<id>`, `default` when absent, which `-P` selects it by.
    #[serde(default = "default_profile_id")]
    pub id: String,
    /// The `<activation>` conditions. Without them the profile activates
    /// only when selected with `-P`.
    pub activation: Option<Activation>,
    /// The dependencies the profile adds or replaces.
    #[serde(default, deserialize_with = "deserialize_dependencies")]
    pub dependencies: Vec<Dependency>,
    /// The managed dependencies the profile adds or replaces.
    pub dependency_management: Option<DependencyManagement>,
    /// The repositories the profile puts before the POM's.
    #[serde(default, deserialize_with = "deserialize_repositories")]
    pub repositories: Vec<Repository>,
    /// The modules the profile adds to the reactor.
    #[serde(default, deserialize_with = "deserialize_modules")]
    pub modules: Vec<String>,
    /// The properties the profile sets over the POM's.
    #[serde(default)]
    pub properties: PropertyMap,
    #[serde(default)]
    pub(crate) build: Box<crate::pom::Build>,
    #[serde(default)]
    pub(crate) reporting: crate::pom::Reporting,
    /// Read for the deployment repository ids Maven validates.
    #[serde(default)]
    pub(crate) distribution_management: Option<crate::pom::DistributionManagement>,
    /// The plugins and managed plugins of the profile's `<build>`, empty
    /// until [`crate::Pom::load_plugins`] reads them.
    #[serde(skip)]
    pub(crate) plugins: Option<Box<crate::plugin::BuildPlugins>>,
    /// The `<pluginRepositories>` the profile puts before the POM's, read
    /// with [`Self::plugins`].
    #[serde(skip)]
    pub(crate) plugin_repositories: Vec<Repository>,
}

/// Maven's `Profile` model gives a profile without `<id>` the id `default`,
/// which `-P default` selects and `help:active-profiles` reports.
fn default_profile_id() -> String {
    "default".to_string()
}
