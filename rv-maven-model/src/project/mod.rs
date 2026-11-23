//! Effective Maven project model construction and orchestration.
//!
//! The `Project` type is the public entry point: it owns the assembled
//! group/artifact/version, properties, dependency management, dependencies,
//! repositories, modules, and any relocation. The submodules in
//! this directory implement the individual resolution steps.

mod bom;
mod dep_management;
pub(crate) mod profiles;
mod relocation;
pub(crate) mod repositories;

use crate::dependency::{Dependency, DependencyManagement};
use crate::properties::{ProjectInfo, PropertyMap};
use crate::repository::Repository;
use crate::source::{ModelPolicy, ModelSource};
use crate::{ActivationContext, Pom, PomError, Provenance, Relocation};

pub use bom::ImportedBom;
pub(crate) use bom::MAX_BOM_DEPTH;
use bom::resolve_bom_imports_blamed;
use dep_management::resolve_dependencies;
pub(crate) use dep_management::{interpolate_dependency, refuse_secret_coordinates};
use relocation::resolve_relocation;
use repositories::resolve_repositories;
use rv_maven_types::{MavenMode, bounded};

/// The effective Maven project model after applying parent inheritance, property
/// interpolation, profile activation, and BOM imports.
///
/// Built by [`Project::build`] from a raw `Pom`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Project {
    /// The interpolated, trimmed `groupId`, the parent's when the POM has
    /// none.
    pub group_id: String,
    /// The interpolated, trimmed `artifactId`.
    pub artifact_id: String,
    /// The interpolated, trimmed version, the parent's when the POM has
    /// none.
    pub version: String,
    /// The interpolated packaging, `jar` when absent.
    pub packaging: String,
    /// The effective properties: the parent chain's, the active profiles'
    /// and the user properties merged.
    pub properties: PropertyMap,
    /// The interpolated dependency management, with the BOM imports
    /// inlined. Entries the model declares win over imported ones.
    pub dependency_management: DependencyManagement,
    /// The interpolated dependencies, with what
    /// [`Self::dependency_management`] manages for them applied. A version
    /// can still be `None`, for an outer management to supply.
    pub dependencies: Vec<Dependency>,
    /// The interpolated repositories of the model and its active profiles.
    pub repositories: Vec<Repository>,
    /// The interpolated `<module>` entries of the input POM and its active
    /// profiles. Modules are never inherited.
    pub modules: Vec<String>,
    /// The interpolated `<distributionManagement><relocation>`.
    pub relocation: Option<Relocation>,
    /// The interpolated `<prerequisites><maven>` of the POM itself, which
    /// is never inherited; as written when it does not interpolate.
    pub prerequisites_maven: Option<String>,
    /// Where the POM this model was built from was read; see
    /// [`Provenance`]. Not serialized.
    pub provenance: Option<Provenance>,
    /// The interpolated `<parent>` coordinates.
    pub parent: Option<crate::Gav>,
    /// Remote parent ranges and the coordinates selected in this model's lineage.
    pub parent_ranges: std::collections::BTreeMap<String, String>,
    /// The `group:artifact:version` of each parent of the lineage that came
    /// from a repository, nearest first.
    pub parents: Vec<String>,
    /// For a project build, the model's own
    /// `os.detection.classifierWithLikes`, interpolated, which a user
    /// property does not override: os-maven-plugin reads it so from the
    /// first project of the reactor.
    pub classifier_with_likes: Option<String>,
    /// For a project build, the plugin repositories validation reads and,
    /// with [`crate::ModelPolicy::plugins`] or in the 3.10 mode, what
    /// [`Self::plugins`] builds the plugin model from.
    pub(crate) plugin_inputs: Option<Box<crate::plugin::PluginInputs>>,
    /// The interpolated ids of `<distributionManagement>`'s repositories,
    /// inherited and from active profiles, with the field Maven names.
    pub(crate) deployment_repository_ids: Vec<(&'static str, String)>,
}

impl Project {
    /// A model with these coordinates, `jar` packaging (Maven's default)
    /// and nothing else, for a model that does not come from a POM, such as
    /// a stub source. Nothing is validated.
    pub fn new(group_id: &str, artifact_id: &str, version: &str) -> Self {
        Self {
            group_id: group_id.to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
            packaging: "jar".to_string(),
            properties: PropertyMap::default(),
            dependency_management: DependencyManagement::default(),
            dependencies: Vec::new(),
            repositories: Vec::new(),
            modules: Vec::new(),
            relocation: None,
            prerequisites_maven: None,
            provenance: None,
            parent: None,
            parent_ranges: Default::default(),
            parents: Vec::new(),
            classifier_with_likes: None,
            plugin_inputs: None,
            deployment_repository_ids: Vec::new(),
        }
    }

    /// The coordinate checks Maven 3.9's `DefaultModelValidator` applies to
    /// the effective model of a project it builds: `groupId` and
    /// `artifactId` are non-empty and use only `A-Z`, `a-z`, `0-9`, `-`, `_`
    /// and `.`, and `version` is non-empty and holds no `${`. The messages
    /// are Maven's.
    ///
    /// Maven downgrades the version check to a warning when the model sets
    /// `maven.build.allowExpressionInEffectiveProjectVersion`; `raeva` cannot
    /// lock such a version, so it keeps the error.
    ///
    /// A dependency's version may not hold any of `\/:"<>|?*`, which also
    /// refuses the `[1.2.*]` range that a dependency POM may use.
    ///
    /// Maven 3.10 also refuses a `version` with any of `\/:"<>|?*` or one
    /// that ends in `SNAPSHOT` without `-SNAPSHOT`, and a repository, a
    /// `<distributionManagement>` repository or, in a project build, a
    /// plugin repository whose id has one of those characters or is
    /// `local`. Maven 3.9 warns of those ids and builds.
    pub fn validate_build_coordinates(&self, mode: MavenMode) -> Result<(), PomError> {
        const BANNED: &str = "\\/:\"<>|?*";
        for dependency in &self.dependencies {
            let Some(found) = (dependency.version.as_deref())
                .and_then(|version| version.chars().find(|c| BANNED.contains(*c)))
            else {
                continue;
            };
            let (group_id, artifact_id, type_, classifier) = dependency.management_key();
            let classifier = classifier.map(|c| format!(":{}", bounded(c)));
            return Err(PomError::InvalidModel(format!(
                "'dependencies.dependency.version' for {}:{}:{}{} must not contain any of \
                 these characters {BANNED} but found {found}",
                bounded(group_id),
                bounded(artifact_id),
                bounded(type_),
                classifier.unwrap_or_default(),
            )));
        }
        let model = [&self.group_id, &self.artifact_id, &self.version].map(|field| Some(&**field));
        crate::inheritance::reject_self_reference(
            "dependencies.dependency.",
            model,
            &self.dependencies,
        )?;
        for (field, id) in [
            ("groupId", &self.group_id),
            ("artifactId", &self.artifact_id),
        ] {
            if id.is_empty() {
                return Err(PomError::InvalidModel(format!("'{field}' is missing.")));
            }
            if !rv_maven_types::is_maven_id_text(id) {
                return Err(PomError::InvalidModel(format!(
                    "'{field}' with value '{}' does not match a valid id pattern.",
                    bounded(id)
                )));
            }
        }
        if self.version.is_empty() {
            return Err(PomError::InvalidModel("'version' is missing.".to_string()));
        }
        if mode == MavenMode::Maven310 {
            reject_banned_characters("version", &self.version, BANNED)?;
            if self.version.ends_with("SNAPSHOT") && !self.version.ends_with("-SNAPSHOT") {
                return Err(PomError::InvalidModel(
                    "'version' uses an unsupported snapshot version format, should be \
                     '*-SNAPSHOT' instead."
                        .to_string(),
                ));
            }
        }
        if self.version.contains("${") {
            return Err(PomError::InvalidModel(format!(
                "'version' must be a constant version but is '{}'.",
                bounded(&self.version)
            )));
        }
        let mut ids: Vec<(&str, String)> = (self.repositories.iter())
            .map(|repository| ("repositories.repository.id", repository_id(repository)))
            .collect();
        if let Some(inputs) = self.plugin_inputs.as_deref() {
            // Validation reads no host value into the build's record.
            let mut info = inputs.info.clone();
            info.environment = info.environment.detached();
            let plugin_ids: Vec<String> = match inputs.model {
                true => repositories::resolve_repositories(
                    inputs.plugin_repositories.clone(),
                    &self.properties,
                    &info,
                )?
                .iter()
                .map(repository_id)
                .collect(),
                // Kept for this check alone, which reads only their ids
                // and refuses nothing Maven 3.9 builds.
                false => (inputs.plugin_repositories.iter())
                    .filter(|repository| !repository.url.is_empty())
                    .filter_map(|repository| {
                        let id = repository.id.as_deref().unwrap_or_default();
                        self.properties.interpolate_str(id, &info).ok()
                    })
                    .collect(),
            };
            ids.extend(
                (plugin_ids.into_iter()).map(|id| ("pluginRepositories.pluginRepository.id", id)),
            );
        }
        ids.extend(self.deployment_repository_ids.iter().cloned());
        for (field, id) in ids {
            let Err(PomError::InvalidModel(problem)) = check_repository_id(field, &id) else {
                continue;
            };
            // Maven 3.9 warns and builds; the export it reads works.
            match mode {
                MavenMode::Maven310 => return Err(PomError::InvalidModel(problem)),
                MavenMode::Maven39 => tracing::warn!(
                    sec_code = "POM_PROBLEM",
                    "{}:{}:{}: {problem}",
                    bounded(&self.group_id),
                    bounded(&self.artifact_id),
                    bounded(&self.version),
                ),
            }
        }
        Ok(())
    }

    /// The effective model of `pom`: its parents from `source` merged in,
    /// its active profiles injected, its values interpolated and its BOM
    /// imports applied, in `ctx` and under `policy`. A failed lookup comes
    /// back as the source raised it.
    ///
    /// The host values a profile's activation tests count as read in
    /// `ctx`'s environment only when the profile brings something
    /// resolution reads: dependencies, managed dependencies, repositories,
    /// modules of a project build, or a property that one of those reads
    /// anywhere in the parent chain.
    pub async fn build<S: ModelSource>(
        pom: Pom,
        source: &S,
        policy: ModelPolicy,
        ctx: &ActivationContext,
    ) -> Result<Self, S::Error> {
        let lineage = crate::model::Lineage::build(pom, source, policy, ctx).await?;
        lineage.activate()?.with_imports(source, policy).await
    }
}

fn repository_id(repository: &Repository) -> String {
    repository.id.clone().unwrap_or_default()
}

/// Maven's check that a repository id of the effective model holds none of
/// `\/:"<>|?*` and is not `local`, which the local repository's own files
/// are named by. The messages are Maven's.
fn check_repository_id(field: &str, id: &str) -> Result<(), PomError> {
    reject_banned_characters(field, id, "\\/:\"<>|?*")?;
    if id == "local" {
        return Err(PomError::InvalidModel(format!(
            "'{field}' must not be 'local', this identifier is reserved for the local \
             repository, using it for other repositories will corrupt your repository \
             metadata."
        )));
    }
    Ok(())
}

/// Maven's check that `value`, the field `field`, holds none of `banned`;
/// it names the last one it finds.
pub(crate) fn reject_banned_characters(
    field: &str,
    value: &str,
    banned: &str,
) -> Result<(), PomError> {
    match value.chars().rev().find(|c| banned.contains(*c)) {
        Some(found) => Err(PomError::InvalidModel(format!(
            "'{field}' must not contain any of these characters {banned} but found {found}"
        ))),
        None => Ok(()),
    }
}

impl crate::model::Activated {
    /// The project model: the relocation, the repositories, the BOM imports
    /// applied to the dependency management, the dependencies and the
    /// modules, interpolated with the model's properties.
    pub(crate) async fn with_imports<S: ModelSource>(
        self,
        source: &S,
        policy: ModelPolicy,
    ) -> Result<Project, S::Error> {
        let Self {
            pom,
            ctx,
            properties: effective_properties,
            project: project_info,
            fetched,
        } = self;
        let blame = |error: PomError| fetched.blame(error);
        let ctx = &ctx;
        let provenance = pom.provenance.clone();
        let raw_relocation = pom
            .distribution_management
            .as_ref()
            .and_then(|dm| dm.relocation.clone());
        let relocation = resolve_relocation(raw_relocation, &effective_properties, &project_info)
            .map_err(blame)?;
        let deployment_repository_ids = {
            // Validation reads no host value into the build's record.
            let mut info = project_info.clone();
            info.environment = info.environment.detached();
            (pom.distribution_management.iter())
                .flat_map(crate::pom::DistributionManagement::repository_ids)
                .map(|(field, id)| {
                    let id = (effective_properties.interpolate_str(id, &info))
                        .unwrap_or_else(|_| id.to_string());
                    (field, id)
                })
                .collect()
        };

        let prerequisites_maven = (pom.prerequisites.as_ref())
            .and_then(|prerequisites| prerequisites.maven.clone())
            .map(|maven| {
                // Only a plugin's prerequisite is read, so none is a build input.
                let mut info = project_info.clone();
                info.environment = info.environment.detached();
                (effective_properties.interpolate_str(&maven, &info)).unwrap_or(maven)
            });

        // Expose interpolated repositories before importing BOMs. A BOM may
        // exist only in a parent-declared repository whose URL uses properties.
        let repositories =
            resolve_repositories(pom.repositories, &effective_properties, &project_info)
                .map_err(blame)?;
        if policy.root {
            crate::file_transport::reject_hosts("repository", &repositories, false)
                .map_err(blame)?;
        }
        if !repositories.is_empty() {
            source.observe_effective_repositories(&repositories)?;
        }

        // Resolve BOM imports with complete effective properties, as
        // Maven does after inheritance and interpolation: in declaration
        // order, the first import of a coordinate winning, and every entry the
        // model declares itself winning over imported ones. Each import
        // coordinate uses only the importer's own effective properties
        // (parent chain plus its own `<properties>`), never properties from
        // a sibling import, so one pass is enough. BOM properties and
        // profiles are NOT merged into the importer.
        let dependency_management = resolve_bom_imports_blamed(
            pom.dependency_management.unwrap_or_default(),
            &effective_properties,
            &project_info,
            source,
            policy,
            ctx,
            &blame,
        )
        .await?
        .management;
        let dependencies = resolve_dependencies(
            pom.dependencies,
            &dependency_management,
            &effective_properties,
            &project_info,
            !policy.root,
        )
        .map_err(blame)?;
        if policy.root {
            for dep in &dependency_management.dependencies {
                dep_management::warn_unknown_scope(
                    dep,
                    project_info.environment.maven_mode(),
                    true,
                );
            }
        }

        if let Some(dep) = dependency_management
            .dependencies
            .iter()
            .find(|dep| dep.type_.as_deref() == Some(""))
        {
            let (group_id, artifact_id, ..) = dep.management_key();
            return Err(blame(PomError::EmptyManagedType(format!(
                "{group_id}:{artifact_id}:"
            )))
            .into());
        }

        // Aggregation is never inherited: `pom.modules` holds the input POM's
        // own modules and those of its active profiles.
        let modules = pom
            .modules
            .into_iter()
            .map(|module| effective_properties.interpolate_str(&module, &project_info))
            .collect::<Result<Vec<_>, _>>()
            .map_err(blame)?;
        if policy.root && !modules.is_empty() && project_info.packaging != "pom" {
            return Err(blame(PomError::InvalidModel(format!(
                "'packaging' with value '{}' is invalid. Aggregator projects require 'pom' as \
                 packaging.",
                project_info.packaging
            )))
            .into());
        }

        let classifier_with_likes = if policy.root {
            const LIKES: &str = "os.detection.classifierWithLikes";
            // An active settings.xml profile's value is the model's, and a
            // `-D` value is not.
            let own = ctx.settings_properties.get(LIKES).or_else(|| {
                if pom.user_properties.get(LIKES).is_some() {
                    pom.shadowed_properties.get(LIKES)
                } else {
                    pom.properties.get(LIKES)
                }
            });
            own.map(|likes| effective_properties.interpolate_str(likes, &project_info))
                .transpose()
                .map_err(blame)?
        } else {
            None
        };
        // Maven validates the plugin repositories of a project build: 3.10
        // refuses an id 3.9 warns of.
        let model =
            policy.plugins.reads_plugins() || ctx.environment.maven_mode() == MavenMode::Maven310;
        let plugin_inputs = policy.root.then(|| {
            Box::new(crate::plugin::PluginInputs {
                model,
                plugins: pom.plugins.map(|plugins| *plugins).unwrap_or_default(),
                plugin_repositories: pom.plugin_repositories,
                info: project_info.clone(),
            })
        });
        let ProjectInfo {
            group_id,
            artifact_id,
            version,
            packaging,
            parent,
            ..
        } = project_info;

        Ok(Project {
            group_id,
            artifact_id,
            version,
            packaging,
            properties: effective_properties,
            dependency_management,
            dependencies,
            repositories,
            modules,
            relocation,
            prerequisites_maven,
            provenance,
            parent: parent.map(|parent| crate::Gav {
                group_id: parent.group_id,
                artifact_id: parent.artifact_id,
                version: parent.version,
            }),
            parent_ranges: fetched.parent_ranges,
            parents: fetched.parents,
            classifier_with_likes,
            plugin_inputs,
            deployment_repository_ids,
        })
    }
}

#[cfg(test)]
mod tests;
