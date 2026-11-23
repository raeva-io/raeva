//! The second half of Maven's model build for the plugin sections, run on
//! demand from what a project build kept: interpolation, plugin management,
//! the lifecycle bindings and the configuration expansion.

use std::collections::{BTreeMap, BTreeSet};

use super::{BuildPlugins, ConfigNode, EffectivePlugins, Extension, Plugin, PluginExecution};
use crate::HostInput;
use crate::properties::{ProjectInfo, PropertyMap};
use crate::{PomError, Project, Repository};

/// What a project build keeps for its plugin model: the plugin sections
/// and plugin repositories merged through the lineage and the active
/// profiles, and the coordinates and environment the model interpolates
/// with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PluginInputs {
    /// Whether the build keeps a plugin model, and not only the plugin
    /// repositories Maven 3.9 validates.
    pub(crate) model: bool,
    pub(crate) plugins: BuildPlugins,
    pub(crate) plugin_repositories: Vec<Repository>,
    pub(crate) info: ProjectInfo,
}

impl Project {
    /// The effective plugin model of this project build, as Maven 3.9's
    /// model builder gives it to the build: see [`EffectivePlugins`].
    /// `None` for the model of a dependency or an imported BOM, which keeps
    /// no plugins.
    ///
    /// The host values the interpolation reads where they can change what
    /// the build resolves are returned in [`EffectivePlugins::host_reads`]
    /// and [`EffectivePlugins::management_reads`] instead of being recorded
    /// in the environment the project was built in.
    pub fn plugins(&self) -> Result<Option<EffectivePlugins>, PomError> {
        self.plugins_with(|mode| super::lifecycle::lifecycle_plugins(&self.packaging, mode))
    }

    /// [`Self::plugins`] for a packaging a build extension maps: the
    /// default lifecycle bindings are `mapping`'s, the extension's
    /// `LifecycleMapping` for the packaging.
    pub fn plugins_with_mapping(
        &self,
        mapping: &[super::MappedMojo],
    ) -> Result<Option<EffectivePlugins>, PomError> {
        self.plugins_with(|mode| Some(super::lifecycle::mapped_lifecycle_plugins(mapping, mode)))
    }

    fn plugins_with(
        &self,
        defaults: impl FnOnce(rv_maven_types::MavenMode) -> Option<Vec<Plugin>>,
    ) -> Result<Option<EffectivePlugins>, PomError> {
        let Some(inputs) = (self.plugin_inputs.as_deref()).filter(|inputs| inputs.model) else {
            return Ok(None);
        };
        let defaults = defaults(inputs.info.environment.maven_mode());
        if let Some(error) = &inputs.plugins.error {
            return Err(PomError::InvalidModel(error.clone()));
        }
        let mut info = inputs.info.clone();
        info.environment = info.environment.detached();
        // A mojo's configuration does not change what the build resolves,
        // outside the parameters plugin resolution reads, so what the rest
        // reads from the host is no input of the plugin tables.
        let mut configuration_info = inputs.info.clone();
        configuration_info.environment = info.environment.detached();
        let interpolation = Interpolation {
            properties: &self.properties,
            info: &info,
            configuration_info: &configuration_info,
        };
        // What each plugin's coordinates and `<extensions>` read, by `g:a`.
        let mut coordinate_reads: BTreeMap<String, BTreeSet<HostInput>> = BTreeMap::new();
        let mut interpolated = |plugin: &Plugin| {
            interpolation.coordinates(plugin)?;
            let coordinates = info.environment.take_reads();
            let plugin = interpolation.plugin(plugin)?;
            (coordinate_reads.entry(plugin.key()).or_default()).extend(coordinates);
            Ok::<_, PomError>((plugin, info.environment.take_reads()))
        };
        let mut plugins = Vec::new();
        let mut host_reads = BTreeSet::new();
        for plugin in &inputs.plugins.plugins {
            let (plugin, reads) = interpolated(plugin)?;
            host_reads.extend(reads);
            plugins.push(plugin);
        }
        // A managed plugin no build plugin takes reads nothing the build
        // resolves unless the command line runs it.
        let mut management_reads: BTreeMap<String, BTreeSet<HostInput>> = BTreeMap::new();
        let mut management = Vec::new();
        for plugin in &inputs.plugins.plugin_management {
            let (plugin, reads) = interpolated(plugin)?;
            (management_reads.entry(plugin.key()).or_default()).extend(reads);
            management.push(plugin);
        }
        let extensions = (inputs.plugins.extensions.iter())
            .map(|extension| interpolation.extension(extension))
            .collect::<Result<Vec<_>, _>>()?;
        let plugin_repositories = crate::project::repositories::resolve_repositories(
            inputs.plugin_repositories.clone(),
            &self.properties,
            &info,
        )?;
        crate::file_transport::reject_hosts("plugin repository", &plugin_repositories, false)?;
        let mut extension_reads = info.environment.take_reads();
        host_reads.extend(extension_reads.iter().cloned());

        let default_goal = interpolation.opt(&inputs.info.build.default_goal)?;
        super::merge::inject_management(&mut plugins, &management);
        if let Some(defaults) = &defaults {
            super::merge::inject_lifecycle(&mut plugins, &management, defaults);
        }
        // Maven's refusal comes before what raeva cannot lock of a plugin.
        for plugin in &plugins {
            let prefix = format!(
                "build.plugins.plugin[{}].dependencies.dependency",
                plugin.key()
            );
            for dependency in &plugin.dependencies {
                if dependency.version.as_deref().is_none_or(str::is_empty) {
                    let field = format!("{prefix}.version");
                    return Err(PomError::InvalidProject(dependency.missing_message(&field)));
                }
                if let Some(problem) =
                    dependency.plugin_system_path_problem(&prefix, &info.environment)
                {
                    return Err(PomError::InvalidProject(problem));
                }
                let scope = dependency.scope.as_deref().unwrap_or_default();
                if !["", "compile", "runtime", "system"].contains(&scope) {
                    let problem = format!(
                        "must be one of [compile, runtime, system] but is '{}'",
                        rv_maven_types::bounded(scope)
                    );
                    let field = format!("{prefix}.scope");
                    return Err(PomError::InvalidProject(
                        dependency.problem(&field, &problem),
                    ));
                }
            }
        }
        host_reads.extend(info.environment.take_reads());
        // An `<extensions>` value that is not `true` decides too.
        for plugin in plugins.iter().filter(|plugin| plugin.extensions.is_some()) {
            extension_reads.extend(coordinate_reads.remove(&plugin.key()).into_iter().flatten());
        }
        for plugin in &plugins {
            host_reads.extend(management_reads.remove(&plugin.key()).into_iter().flatten());
        }
        super::merge::expand_configuration(&mut plugins);
        super::merge::expand_configuration(&mut management);
        Ok(Some(EffectivePlugins {
            packaging: self.packaging.clone(),
            lifecycle_mapped: defaults.is_some(),
            plugins,
            plugin_management: management,
            extensions,
            plugin_repositories,
            default_goal,
            host_reads,
            management_reads,
            extension_reads,
        }))
    }
}

/// Maven's model interpolation of the plugin sections, with the effective
/// properties and the project's coordinates, and the configurations through
/// an environment of their own.
struct Interpolation<'a> {
    properties: &'a PropertyMap,
    info: &'a ProjectInfo,
    configuration_info: &'a ProjectInfo,
}

impl Interpolation<'_> {
    fn text(&self, text: &str) -> Result<String, PomError> {
        self.properties.interpolate_str(text, self.info)
    }

    fn opt(&self, text: &Option<String>) -> Result<Option<String>, PomError> {
        self.properties.interpolate_opt(text.as_deref(), self.info)
    }

    /// A configuration's values. An expression the properties cannot
    /// expand stays as written, for the mojo's own expression evaluator.
    fn configuration(
        &self,
        configuration: &Option<ConfigNode>,
    ) -> Result<Option<ConfigNode>, PomError> {
        let Some(mut configuration) = configuration.clone() else {
            return Ok(None);
        };
        let mut children = std::mem::take(&mut configuration.children);
        configuration.interpolate_with(&mut |text| {
            (self.properties).interpolate_str(text, self.configuration_info)
        })?;
        for child in &mut children {
            let info = match super::RESOLVED_PARAMETERS.contains(&child.name.as_str()) {
                true => self.info,
                false => self.configuration_info,
            };
            child.interpolate_with(&mut |text| self.properties.interpolate_str(text, info))?;
        }
        configuration.children = children;
        Ok(Some(configuration))
    }

    fn coordinates(&self, plugin: &Plugin) -> Result<(), PomError> {
        self.refuse_secret(
            "plugin",
            &plugin.group_id,
            &plugin.artifact_id,
            &plugin.version,
        )?;
        self.text(&plugin.group_id)?;
        self.text(&plugin.artifact_id)?;
        self.opt(&plugin.version)?;
        self.opt(&plugin.extensions)?;
        Ok(())
    }

    fn plugin(&self, plugin: &Plugin) -> Result<Plugin, PomError> {
        let dependencies = (plugin.dependencies.iter().cloned())
            .map(|dependency| {
                crate::project::interpolate_dependency(dependency, self.properties, self.info, None)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let executions = (plugin.executions.iter())
            .map(|execution| {
                Ok(PluginExecution {
                    id: self.text(&execution.id)?,
                    phase: self.opt(&execution.phase)?,
                    goals: (execution.goals.iter())
                        .map(|goal| self.text(goal))
                        .collect::<Result<Vec<_>, _>>()?,
                    inherited: self.opt(&execution.inherited)?,
                    configuration: self.configuration(&execution.configuration)?,
                })
            })
            .collect::<Result<Vec<_>, PomError>>()?;
        Ok(Plugin {
            group_id: self.text(&plugin.group_id)?,
            artifact_id: self.text(&plugin.artifact_id)?,
            version: self.opt(&plugin.version)?,
            extensions: self.opt(&plugin.extensions)?,
            inherited: self.opt(&plugin.inherited)?,
            dependencies,
            executions,
            configuration: self.configuration(&plugin.configuration)?,
        })
    }

    /// Refuse a plugin's or build extension's coordinates when one reads a
    /// host input named like a secret, as a dependency's are.
    fn refuse_secret(
        &self,
        kind: &str,
        group_id: &str,
        artifact_id: &str,
        version: &Option<String>,
    ) -> Result<(), PomError> {
        let fields = [
            ("groupId", Some(group_id)),
            ("artifactId", Some(artifact_id)),
            ("version", version.as_deref()),
        ];
        crate::project::refuse_secret_coordinates(
            self.properties,
            fields.map(|(field, text)| (field, text, self.info)),
            || {
                let version = version.as_deref().unwrap_or_default();
                format!("{kind} {group_id}:{artifact_id}:{version}")
            },
        )
    }

    fn extension(&self, extension: &Extension) -> Result<Extension, PomError> {
        let (group_id, artifact_id) = (&extension.group_id, &extension.artifact_id);
        self.refuse_secret("build extension", group_id, artifact_id, &extension.version)?;
        Ok(Extension {
            group_id: self.text(&extension.group_id)?,
            artifact_id: self.text(&extension.artifact_id)?,
            version: self.opt(&extension.version)?,
        })
    }
}
