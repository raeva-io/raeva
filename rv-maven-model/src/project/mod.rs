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
use relocation::resolve_relocation;
use repositories::resolve_repositories;
use rv_maven_types::bounded;

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
    /// Where the POM this model was built from was read; see
    /// [`Provenance`]. Not serialized.
    pub provenance: Option<Provenance>,
    /// The interpolated `<parent>` coordinates.
    pub parent: Option<crate::Gav>,
    /// Remote parent ranges and the coordinates selected in this model's lineage.
    pub parent_ranges: std::collections::BTreeMap<String, String>,
    /// For a project build, the model's own
    /// `os.detection.classifierWithLikes`, interpolated, which a user
    /// property does not override: os-maven-plugin reads it so from the
    /// first project of the reactor.
    pub classifier_with_likes: Option<String>,
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
            provenance: None,
            parent: None,
            parent_ranges: Default::default(),
            classifier_with_likes: None,
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
    pub fn validate_build_coordinates(&self) -> Result<(), PomError> {
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
        if self.version.contains("${") {
            return Err(PomError::InvalidModel(format!(
                "'version' must be a constant version but is '{}'.",
                bounded(&self.version)
            )));
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

        // Expose interpolated repositories before importing BOMs. A BOM may
        // exist only in a parent-declared repository whose URL uses properties.
        let repositories =
            resolve_repositories(pom.repositories, &effective_properties, &project_info)
                .map_err(blame)?;
        if !repositories.is_empty() {
            source.observe_effective_repositories(&repositories);
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
            provenance,
            parent: parent.map(|parent| crate::Gav {
                group_id: parent.group_id,
                artifact_id: parent.artifact_id,
                version: parent.version,
            }),
            parent_ranges: fetched.parent_ranges,
            classifier_with_likes,
        })
    }
}

#[cfg(test)]
mod tests;
