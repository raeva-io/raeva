//! The plugins, plugin management and build extensions of a POM, merged as
//! Maven 3.9 builds them into a project's effective model.
//!
//! A POM's `<build>` and each profile's `<build>` are parsed into
//! [`BuildPlugins`], and `<pluginRepositories>` into
//! [`crate::Repository`] lists. A project build merges them through its
//! parents and active profiles beside the rest of the model; dependency and
//! BOM models keep them only as parsed. [`crate::Project::plugins`] then
//! gives the [`EffectivePlugins`]: interpolated, with plugin management and
//! the default lifecycle bindings of the packaging applied, and each
//! execution's configuration expanded from its plugin's.
//!
//! Nothing here resolves a plugin: a plugin without a version stays without
//! one, as Maven leaves it for its plugin version resolver, and the
//! artifacts a mojo resolves while it runs are not part of any model.

mod config;
mod descriptor;
mod effective;
mod extensions;
pub(crate) mod lifecycle;
pub(crate) mod merge;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::Deserialize;

use crate::dependency::{Dependency, Exclusion, deserialize_dependencies};
use crate::{HostInput, PomError, Repository};

pub use config::ConfigNode;
pub(crate) use descriptor::root as descriptor_root;
pub use descriptor::{
    MappedMojo, PluginDescriptor, parse_exported_artifacts, parse_lifecycle_mappings,
    parse_plugin_descriptor,
};
pub(crate) use effective::PluginInputs;
pub use extensions::{CoreExtension, parse_core_extensions};

/// The `groupId` Maven gives a `<plugin>` that declares none.
pub const DEFAULT_PLUGIN_GROUP: &str = "org.apache.maven.plugins";

/// The `<configuration>` parameters plugin resolution reads: the compiler
/// plugin's processor paths and whether its management applies to them, and
/// Surefire's and Failsafe's `parallel`, `groups`, `excludedGroups` and
/// `properties`, which pick test providers. What a mojo reads of any other
/// parameter changes how it runs, not what the build resolves.
pub(crate) const RESOLVED_PARAMETERS: [&str; 6] = [
    "annotationProcessorPaths",
    "annotationProcessorPathsUseDepMgmt",
    "parallel",
    "groups",
    "excludedGroups",
    "properties",
];

/// A `<plugin>` of a `<build>` or of its `<pluginManagement>`, with its
/// text trimmed and, once in an [`EffectivePlugins`], interpolated.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Plugin {
    /// The `<groupId>`, [`DEFAULT_PLUGIN_GROUP`] when absent.
    #[serde(default = "default_plugin_group")]
    pub group_id: String,
    /// The `<artifactId>`, empty when absent.
    #[serde(default)]
    pub artifact_id: String,
    /// The `<version>`. `None` when neither the plugin, its management nor
    /// the lifecycle bindings give one, which Maven resolves from the
    /// plugin repositories' metadata when it loads the plugin.
    pub version: Option<String>,
    /// The `<extensions>` text; see [`Self::is_extensions`].
    pub extensions: Option<String>,
    /// The `<inherited>` text; see [`Self::is_inherited`].
    pub inherited: Option<String>,
    /// The plugin's own `<dependencies>`, which its class path adds or puts
    /// in place of the plugin POM's.
    #[serde(default, deserialize_with = "deserialize_dependencies")]
    pub dependencies: Vec<Dependency>,
    /// The `<executions>`, in declaration order.
    #[serde(default, deserialize_with = "deserialize_executions")]
    pub executions: Vec<PluginExecution>,
    /// The plugin-level `<configuration>`.
    pub configuration: Option<ConfigNode>,
}

fn default_plugin_group() -> String {
    DEFAULT_PLUGIN_GROUP.to_string()
}

impl Plugin {
    /// A plugin with this `groupId`, `artifactId` and version and nothing
    /// else.
    pub fn new(group_id: &str, artifact_id: &str, version: Option<&str>) -> Self {
        Self {
            group_id: group_id.to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.map(str::to_string),
            extensions: None,
            inherited: None,
            dependencies: Vec::new(),
            executions: Vec::new(),
            configuration: None,
        }
    }

    /// `groupId:artifactId`, the key Maven merges plugins by.
    pub fn key(&self) -> String {
        format!("{}:{}", self.group_id, self.artifact_id)
    }

    /// Whether `<extensions>` is `true` in any case, which loads the plugin
    /// into the project's build extensions before the build plan is made.
    pub fn is_extensions(&self) -> bool {
        parse_boolean(self.extensions.as_deref(), false)
    }

    /// Whether child POMs inherit the plugin: `<inherited>` absent or `true`
    /// in any case.
    pub fn is_inherited(&self) -> bool {
        parse_boolean(self.inherited.as_deref(), true)
    }

    /// The [`RESOLVED_PARAMETERS`] of the plugin's configuration and its
    /// executions'.
    pub(crate) fn resolved_parameters(&self) -> impl Iterator<Item = &ConfigNode> {
        let executions = self
            .executions
            .iter()
            .map(|execution| &execution.configuration);
        (std::iter::once(&self.configuration).chain(executions))
            .flatten()
            .flat_map(|configuration| &configuration.children)
            .filter(|child| RESOLVED_PARAMETERS.contains(&child.name.as_str()))
    }

    /// The processor paths of the compiler plugin's executions. With
    /// `lifecycle`, of each execution that runs `compile` or `testCompile`,
    /// which Maven resolves apart, or of the plugin's configuration when
    /// none names those goals. An execution bound to a phase no lifecycle
    /// has, such as `none`, never runs. Then of each `direct` execution a goal runs from the
    /// command line: the one with that id, goals or not, else the plugin's
    /// configuration. Each differing configuration with paths appears once,
    /// in the order first seen. Empty for any other plugin.
    pub fn processor_paths(&self, lifecycle: bool, direct: &[String]) -> Vec<ProcessorPaths> {
        if self.group_id != DEFAULT_PLUGIN_GROUP || self.artifact_id != "maven-compiler-plugin" {
            return Vec::new();
        }
        let compiling: Vec<_> = (self.executions.iter())
            .filter(|execution| {
                (execution.goals.iter()).any(|goal| goal == "compile" || goal == "testCompile")
            })
            .collect();
        let runs = |execution: &&PluginExecution| {
            (execution.phase.as_deref()).is_none_or(|phase| LIFECYCLE_PHASES.contains(&phase))
        };
        let mut configurations = match (lifecycle, compiling.is_empty()) {
            (false, _) => Vec::new(),
            (true, true) => vec![&self.configuration],
            (true, false) => (compiling.into_iter().filter(runs))
                .map(|execution| &execution.configuration)
                .collect(),
        };
        configurations.extend(direct.iter().map(|id| {
            (self.executions.iter())
                .find(|execution| execution.id == *id)
                .map_or(&self.configuration, |execution| &execution.configuration)
        }));
        let mut found: Vec<ProcessorPaths> = Vec::new();
        for configuration in configurations.into_iter().flatten() {
            let Some(list) = configuration.child("annotationProcessorPaths") else {
                continue;
            };
            let mut paths: Vec<ProcessorPath> = Vec::new();
            for path in list.children.iter().map(ProcessorPath::from_node) {
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
            let use_dep_mgmt = parse_boolean(
                configuration.child_value("annotationProcessorPathsUseDepMgmt"),
                false,
            );
            let entry = ProcessorPaths {
                paths,
                use_dep_mgmt,
            };
            if !entry.paths.is_empty() && !found.contains(&entry) {
                found.push(entry);
            }
        }
        found
    }
}

/// The phases of Maven 3's `default`, `clean` and `site` lifecycles.
const LIFECYCLE_PHASES: [&str; 30] = [
    "validate",
    "initialize",
    "generate-sources",
    "process-sources",
    "generate-resources",
    "process-resources",
    "compile",
    "process-classes",
    "generate-test-sources",
    "process-test-sources",
    "generate-test-resources",
    "process-test-resources",
    "test-compile",
    "process-test-classes",
    "test",
    "prepare-package",
    "package",
    "pre-integration-test",
    "integration-test",
    "post-integration-test",
    "verify",
    "install",
    "deploy",
    "pre-clean",
    "clean",
    "post-clean",
    "pre-site",
    "site",
    "post-site",
    "site-deploy",
];

/// `Boolean.parseBoolean`: `true` in any case is true, anything else false;
/// `absent` when there is no text.
fn parse_boolean(text: Option<&str>, absent: bool) -> bool {
    text.map_or(absent, |text| text.eq_ignore_ascii_case("true"))
}

/// An `<execution>` of a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct PluginExecution {
    /// The `<id>`, `default` when absent.
    #[serde(default = "default_execution_id")]
    pub id: String,
    /// The `<phase>` the goals bind to; `None` for each goal's default
    /// phase.
    pub phase: Option<String>,
    /// The `<goals>`, in declaration order.
    #[serde(default, deserialize_with = "deserialize_goals")]
    pub goals: Vec<String>,
    /// The `<inherited>` text; absent means the plugin's.
    pub inherited: Option<String>,
    /// The execution's `<configuration>`, and in an [`EffectivePlugins`]
    /// the plugin's merged below it.
    pub configuration: Option<ConfigNode>,
}

fn default_execution_id() -> String {
    "default".to_string()
}

impl PluginExecution {
    /// An execution of `goals` with this id, bound to `phase`.
    pub fn new(id: &str, phase: Option<&str>, goals: &[&str]) -> Self {
        Self {
            id: id.to_string(),
            phase: phase.map(str::to_string),
            goals: goals.iter().map(|goal| goal.to_string()).collect(),
            inherited: None,
            configuration: None,
        }
    }

    /// Whether child POMs inherit the execution, given whether they inherit
    /// its plugin.
    fn is_inherited(&self, plugin_inherited: bool) -> bool {
        parse_boolean(self.inherited.as_deref(), plugin_inherited)
    }
}

/// An `<extension>` of a `<build><extensions>`, which Maven loads into the
/// project's build extensions with its dependencies.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Extension {
    /// The `<groupId>`, empty when absent.
    #[serde(default)]
    pub group_id: String,
    /// The `<artifactId>`, empty when absent.
    #[serde(default)]
    pub artifact_id: String,
    /// The `<version>`; `None` leaves it to Maven's plugin version resolver.
    pub version: Option<String>,
}

/// One compiler execution's `annotationProcessorPaths`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessorPaths {
    /// The entries, each once, in declaration order.
    pub paths: Vec<ProcessorPath>,
    /// `annotationProcessorPathsUseDepMgmt`.
    pub use_dep_mgmt: bool,
}

/// An entry of the compiler plugin's `annotationProcessorPaths`, which the
/// compiler plugin resolves with its dependencies when it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessorPath {
    /// The `<groupId>`, empty when absent.
    pub group_id: String,
    /// The `<artifactId>`, empty when absent.
    pub artifact_id: String,
    /// The `<version>`. maven-compiler-plugin 3.12 and later can take a
    /// missing one from the project's dependency management.
    pub version: Option<String>,
    /// The `<type>`, `jar` when absent.
    pub type_: String,
    /// The `<classifier>`.
    pub classifier: Option<String>,
    /// The `<exclusions>`.
    pub exclusions: Vec<Exclusion>,
}

impl ProcessorPath {
    fn from_node(node: &ConfigNode) -> Self {
        let text = |name: &str| node.child_value(name).map(str::to_string);
        let exclusions = node.child("exclusions").map_or_else(Vec::new, |list| {
            list.children
                .iter()
                .map(|exclusion| Exclusion {
                    group_id: exclusion.child_value("groupId").unwrap_or("").to_string(),
                    artifact_id: exclusion
                        .child_value("artifactId")
                        .unwrap_or("")
                        .to_string(),
                })
                .collect()
        });
        Self {
            group_id: text("groupId").unwrap_or_default(),
            artifact_id: text("artifactId").unwrap_or_default(),
            version: text("version"),
            type_: text("type").unwrap_or_else(|| "jar".to_string()),
            classifier: text("classifier"),
            exclusions,
        }
    }
}

/// What a POM or profile without plugin sections read has.
pub(crate) static NO_PLUGINS: BuildPlugins = BuildPlugins {
    plugins: Vec::new(),
    plugin_management: Vec::new(),
    extensions: Vec::new(),
    error: None,
};

/// The plugin sections of one `<build>` as a POM or profile declares them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BuildPlugins {
    pub(crate) plugins: Vec<Plugin>,
    pub(crate) plugin_management: Vec<Plugin>,
    /// `<build><extensions>`; a profile's `<build>` has none.
    pub(crate) extensions: Vec<Extension>,
    /// Why the plugin sections of a POM of the lineage could not be read.
    pub(crate) error: Option<String>,
}

impl BuildPlugins {
    pub(crate) fn trim_text(&mut self) {
        for plugin in self.plugins.iter_mut().chain(&mut self.plugin_management) {
            trim_plugin(plugin);
        }
        for extension in &mut self.extensions {
            crate::pom::trim_str(&mut extension.group_id);
            crate::pom::trim_str(&mut extension.artifact_id);
            crate::pom::trim_opt(&mut extension.version);
        }
    }
}

fn trim_plugin(plugin: &mut Plugin) {
    crate::pom::trim_str(&mut plugin.group_id);
    crate::pom::trim_str(&mut plugin.artifact_id);
    crate::pom::trim_opt(&mut plugin.version);
    crate::pom::trim_opt(&mut plugin.extensions);
    crate::pom::trim_opt(&mut plugin.inherited);
    crate::pom::trim_dependencies(&mut plugin.dependencies);
    for execution in &mut plugin.executions {
        crate::pom::trim_str(&mut execution.id);
        crate::pom::trim_opt(&mut execution.phase);
        crate::pom::trim_opt(&mut execution.inherited);
        execution.goals.iter_mut().for_each(crate::pom::trim_str);
    }
}

/// The effective plugin model of a project build, as Maven 3.9's model
/// builder leaves it: inherited from the parents and the super POM, the
/// active profiles injected, interpolated, plugin management applied, the
/// packaging's default lifecycle bindings added, and each execution's
/// configuration merged over its plugin's. `<reporting>` is not read: the
/// report plugins Maven writes into the site plugin's configuration are
/// resolved by that plugin when it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EffectivePlugins {
    /// The packaging the default lifecycle bindings were taken from.
    pub packaging: String,
    /// Whether Maven 3.9.12 maps `packaging` itself. A packaging only a
    /// build extension defines, such as `bundle`, gets its bindings from
    /// that extension, which this model does not read, so none are added.
    pub lifecycle_mapped: bool,
    /// `<build><plugins>` in the order Maven keeps them, the default
    /// lifecycle plugins it adds after the declared ones.
    pub plugins: Vec<Plugin>,
    /// `<build><pluginManagement>`, which only a plugin invoked by prefix or
    /// coordinate on the command line reads from here.
    pub plugin_management: Vec<Plugin>,
    /// `<build><extensions>`.
    pub extensions: Vec<Extension>,
    /// The `<pluginRepositories>` of the model and its active profiles,
    /// then the super POM's `central`, interpolated. Plugins, their
    /// dependencies and build extensions resolve from these, not from
    /// `<repositories>`.
    pub plugin_repositories: Vec<Repository>,
    /// `<build><defaultGoal>`, interpolated: the goals `mvn` runs when the
    /// command line names none, read from the reactor root only.
    pub default_goal: Option<String>,
    /// What interpolating the plugin model read from the host, outside the
    /// `<configuration>` parameters plugin resolution does not read (all
    /// but the `RESOLVED_PARAMETERS`) and the managed plugins no build
    /// plugin takes. These reads are not recorded in the environment the
    /// project was built in.
    pub host_reads: BTreeSet<HostInput>,
    /// What interpolating each managed plugin no build plugin takes read
    /// from the host, by `g:a`: an input only of a build that runs it from
    /// the command line or looks up a prefix.
    pub management_reads: BTreeMap<String, BTreeSet<HostInput>>,
    /// What interpolating the build extensions, the plugin repositories and
    /// the coordinates and `<extensions>` of each plugin that has one read
    /// from the host: what decides the extensions' handlers.
    pub extension_reads: BTreeSet<HostInput>,
}

impl EffectivePlugins {
    /// The plugins and extensions Maven loads into the project's build
    /// extensions, in its order: each `<build><extensions>` entry, then each
    /// plugin with `<extensions>true</extensions>`.
    pub fn build_extensions(&self) -> Vec<Plugin> {
        let declared = self.extensions.iter().map(|extension| {
            Plugin::new(
                &extension.group_id,
                &extension.artifact_id,
                extension.version.as_deref(),
            )
        });
        let plugins = self.plugins.iter().filter(|plugin| plugin.is_extensions());
        declared.chain(plugins.cloned()).collect()
    }

    /// [`Self::management_reads`] of the managed plugin `key`.
    pub fn managed_reads(&self, key: &str) -> impl Iterator<Item = HostInput> + '_ {
        self.management_reads
            .get(key)
            .into_iter()
            .flatten()
            .cloned()
    }

    /// The plugin with this key in [`Self::plugins`].
    pub fn plugin(&self, group_id: &str, artifact_id: &str) -> Option<&Plugin> {
        self.plugins
            .iter()
            .find(|plugin| plugin.group_id == group_id && plugin.artifact_id == artifact_id)
    }
}

impl crate::Pom {
    /// The build extensions this POM declares itself: each
    /// `<build><extensions>` entry, then each plugin of its `<build>` or of
    /// a profile's that a declaration or the plugin management of the POM,
    /// that profile or `inherited` marks `<extensions>true</extensions>`,
    /// once per key. `inherited` is the [`Self::inherited_plugin_management`]
    /// of the parents, nearest first. Nothing is interpolated, and every
    /// profile counts, active or not. Fails for a POM that
    /// [`Self::parse_with_plugins`] did not make.
    pub fn declared_build_extensions(
        &mut self,
        inherited: &[Plugin],
    ) -> Result<Vec<Plugin>, PomError> {
        self.load_plugins()?;
        let own = self.plugins.as_deref().cloned().unwrap_or_default();
        let mut found: Vec<Plugin> = (own.extensions.iter())
            .map(|extension| {
                Plugin::new(
                    &extension.group_id,
                    &extension.artifact_id,
                    extension.version.as_deref(),
                )
            })
            .collect();
        let sections = std::iter::once(&own)
            .chain((self.profiles.iter()).filter_map(|profile| profile.plugins.as_deref()));
        for section in sections {
            // The nearest management that sets `<extensions>` decides.
            let managed = |plugin: &Plugin| {
                (section.plugin_management.iter())
                    .chain(&own.plugin_management)
                    .chain(inherited)
                    .find(|managed| managed.key() == plugin.key() && managed.extensions.is_some())
                    .is_some_and(Plugin::is_extensions)
            };
            for plugin in &section.plugins {
                let extensions = match plugin.extensions {
                    Some(_) => plugin.is_extensions(),
                    None => managed(plugin),
                };
                if extensions && !found.iter().any(|known| known.key() == plugin.key()) {
                    found.push(plugin.clone());
                }
            }
        }
        Ok(found)
    }

    /// The plugin management of this POM and its profiles that a child
    /// inherits: every entry not `<inherited>false</inherited>`. Fails for
    /// a POM that [`Self::parse_with_plugins`] did not make.
    pub fn inherited_plugin_management(&mut self) -> Result<Vec<Plugin>, PomError> {
        self.load_plugins()?;
        let sections = self
            .plugins
            .as_deref()
            .into_iter()
            .chain((self.profiles.iter()).filter_map(|profile| profile.plugins.as_deref()));
        Ok(sections
            .flat_map(|section| &section.plugin_management)
            .filter(|plugin| plugin.is_inherited())
            .cloned()
            .collect())
    }
}

element_list!(fn deserialize_plugins, "plugin", Plugin);
element_list!(fn deserialize_executions, "execution", PluginExecution);
element_list!(fn deserialize_goals, "goal", String);
element_list!(fn deserialize_extensions, "extension", Extension);
element_list!(pub(crate) fn deserialize_plugin_repositories, "pluginRepository", Repository);

/// Where a POM's plugin sections come from: deserializing them costs more
/// than the rest of a POM, and keeping the text to read them from on demand
/// costs a copy of it, so only [`crate::Pom::parse_with_plugins`] keeps it.
/// It is no part of the model, so any two compare equal.
#[derive(Clone, Default)]
pub(crate) enum PluginSource {
    /// Parsed without them, or made by hand.
    #[default]
    Dropped,
    /// The root element text, not read yet.
    Kept(Arc<str>),
    /// Read into the POM.
    Read,
}

impl PartialEq for PluginSource {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for PluginSource {}

impl std::fmt::Debug for PluginSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PluginSource")
    }
}

/// The plugin sections and plugin repositories of a POM and of each of its
/// profiles, in the order of [`crate::Pom::profiles`], read from `source`.
pub(crate) fn read_sections(source: &str) -> Result<(Sections, Vec<Sections>), PomError> {
    let mut deserializer =
        quick_xml::de::Deserializer::from_str_with_resolver(source, crate::xml::MavenEntities);
    let document = PluginDocument::deserialize(&mut deserializer)?;
    let sections =
        |build: Option<BuildXml>, mut repositories: Vec<Repository>, extensions: bool| {
            let build = build.unwrap_or_default();
            let mut plugins = BuildPlugins {
                plugins: build.plugins,
                plugin_management: (build.plugin_management)
                    .map(|management| management.plugins)
                    .unwrap_or_default(),
                extensions: if extensions {
                    build.extensions
                } else {
                    Vec::new()
                },
                error: None,
            };
            plugins.trim_text();
            crate::pom::trim_repositories(&mut repositories);
            (plugins, repositories)
        };
    let profiles = (document.profiles.into_iter())
        .map(|profile| sections(profile.build, profile.plugin_repositories, false))
        .collect();
    Ok((
        sections(document.build, document.plugin_repositories, true),
        profiles,
    ))
}

/// A `<build>`'s plugin sections and the `<pluginRepositories>` beside it.
pub(crate) type Sections = (BuildPlugins, Vec<Repository>);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginDocument {
    #[serde(default)]
    build: Option<BuildXml>,
    #[serde(default, deserialize_with = "deserialize_plugin_repositories")]
    plugin_repositories: Vec<Repository>,
    #[serde(default, deserialize_with = "deserialize_profile_builds")]
    profiles: Vec<ProfileXml>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileXml {
    #[serde(default)]
    build: Option<BuildXml>,
    #[serde(default, deserialize_with = "deserialize_plugin_repositories")]
    plugin_repositories: Vec<Repository>,
}

/// A `<build>`'s plugin sections; a profile's `<build>` has no
/// `<extensions>`, which [`read_sections`] drops.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct BuildXml {
    #[serde(deserialize_with = "deserialize_plugins")]
    plugins: Vec<Plugin>,
    plugin_management: Option<PluginManagementXml>,
    #[serde(deserialize_with = "deserialize_extensions")]
    extensions: Vec<Extension>,
}

element_list!(fn deserialize_profile_builds, "profile", ProfileXml);

/// `<pluginManagement>`.
#[derive(Deserialize)]
struct PluginManagementXml {
    #[serde(default, deserialize_with = "deserialize_plugins")]
    plugins: Vec<Plugin>,
}
