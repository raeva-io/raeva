//! The stages both effective models are built in: a [`Lineage`] merges a
//! POM's parents and injects their active profiles, and [`Lineage::activate`]
//! gives the [`Activated`] model its properties and coordinates. Reactor
//! discovery stops there with an [`crate::EffectiveDescriptor`]; resolution
//! goes on to import BOMs and manage dependencies into a [`crate::Project`].

use crate::inheritance::{FetchedProperties, apply_inheritance_tracked};
use crate::pom::Build;
use crate::properties::{ParentInfo, ProjectInfo, PropertyMap};
use crate::source::{ModelPolicy, ModelSource, ParentLookup};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::{ActivationContext, ModelEnvironment, Pom, PomError};

pub(crate) struct Lineage {
    pub(crate) pom: Pom,
    pub(crate) ctx: ActivationContext,
    pub(crate) fetched: FetchedProperties,
}

impl Lineage {
    /// Merge the parents of `pom` from `source`. The POM's own repositories
    /// reach the source before its parent is fetched, so a POM can name the
    /// repository that hosts its parent.
    pub(crate) async fn build<S: ModelSource>(
        pom: Pom,
        source: &S,
        policy: ModelPolicy,
        ctx: &ActivationContext,
    ) -> Result<Self, S::Error> {
        let ctx = ctx.with_input_packaging(&pom);
        let mut pom = pom;
        if policy.root {
            pom.mark_root_repositories();
        }
        crate::inheritance::observe_lineage_repositories(source, &pom, Some(&ctx))?;
        let (pom, fetched) =
            apply_inheritance_tracked(pom, source, policy, ParentLookup::Project, Some(&ctx))
                .await?;
        Ok(Self { pom, ctx, fetched })
    }

    pub(crate) fn activate(self) -> Result<Activated, PomError> {
        let Self {
            pom,
            ctx,
            mut fetched,
        } = self;
        let properties = ctx.model_properties(&pom.properties);
        // Maven injects active settings.xml profiles as external profiles
        // after the POM's own profiles, and reads `-D` user properties ahead
        // of the model's.
        for (key, _) in ctx.settings_properties.iter() {
            fetched.remove(key);
        }
        for key in ctx.properties.keys() {
            fetched.remove(key);
        }
        let project =
            project_info(&pom, &properties, &ctx).map_err(|error| fetched.blame(error))?;
        Ok(Activated {
            pom,
            ctx,
            properties,
            project,
            fetched,
        })
    }
}

pub(crate) struct Activated {
    pub(crate) pom: Pom,
    pub(crate) ctx: ActivationContext,
    pub(crate) properties: PropertyMap,
    pub(crate) project: ProjectInfo,
    pub(crate) fetched: FetchedProperties,
}

/// The interpolated coordinates of `pom`, in `ctx`. A child without its own
/// group or version takes its `<parent>`'s, as Maven's inheritance does.
pub(crate) fn project_info(
    pom: &Pom,
    properties: &PropertyMap,
    ctx: &ActivationContext,
) -> Result<ProjectInfo, PomError> {
    project_info_in(
        pom,
        properties,
        ctx.base_dir.clone(),
        ctx.interpolation_system_properties(),
        &ctx.model_environment(),
    )
}

/// [`project_info`] with the project directory, system properties and
/// environment given apart, as an imported BOM is built.
pub(crate) fn project_info_in(
    pom: &Pom,
    properties: &PropertyMap,
    basedir: Option<PathBuf>,
    system_properties: HashMap<String, String>,
    environment: &ModelEnvironment,
) -> Result<ProjectInfo, PomError> {
    let parent_field = |value: &str| {
        properties.interpolate_str_with_system_properties(value, &system_properties, environment)
    };
    let parent = pom
        .parent
        .as_ref()
        .map(|parent| -> Result<ParentInfo, PomError> {
            Ok(ParentInfo {
                group_id: parent_field(&parent.group_id)?,
                artifact_id: parent_field(&parent.artifact_id)?,
                version: parent_field(&parent.version)?,
            })
        })
        .transpose()?;

    let raw_group_id = pom
        .group_id
        .as_deref()
        .or_else(|| pom.parent.as_ref().map(|parent| parent.group_id.as_str()))
        .ok_or(PomError::MissingField("groupId"))?;
    let raw_artifact_id = pom
        .artifact_id
        .as_deref()
        .ok_or(PomError::MissingField("artifactId"))?;
    let raw_version = pom
        .version
        .as_deref()
        .or_else(|| pom.parent.as_ref().map(|parent| parent.version.as_str()))
        .ok_or(PomError::MissingField("version"))?;
    let raw_packaging = pom.packaging.as_deref().unwrap_or("jar");

    // Coordinates interpolate one field at a time. The field being expanded
    // is empty, so a reference to it reads the property of its name, as
    // Maven reads `<groupId>${project.groupId}</groupId>` (aliyun-sdk-mns
    // 2.0.0), and is refused without one; the others hold their raw
    // text, then the interpolated value once it is known, so
    // `${project.artifactId}` in `<version>` reads the artifactId. Maven
    // trims stray whitespace in the coordinates.
    let mut project = ProjectInfo {
        group_id: raw_group_id.trim().to_string(),
        artifact_id: raw_artifact_id.trim().to_string(),
        version: raw_version.trim().to_string(),
        packaging: raw_packaging.trim().to_string(),
        parent,
        basedir: basedir.clone(),
        build: Build::clone(&pom.build),
        system_properties,
        environment: environment.clone(),
        model_lookup: Some(Box::new(crate::properties::ModelLookup::new(
            pom,
            basedir.clone(),
        ))),
    };
    let interpolate = |raw: &str, project: &ProjectInfo| {
        properties
            .interpolate_str(raw, project)
            .map(|value| value.trim().to_string())
    };
    // What is left of a reference to the field being expanded, which no
    // property of its name defined.
    let names_itself = |value: &str, field: &str| {
        ["project.", "pom.", ""]
            .iter()
            .any(|prefix| value.contains(&format!("${{{prefix}{field}}}")))
    };
    project.group_id.clear();
    let group_id = interpolate(raw_group_id, &project)?;
    if group_id.is_empty() || names_itself(&group_id, "groupId") {
        return Err(PomError::InvalidModel(
            "groupId must not be empty".to_string(),
        ));
    }
    project.group_id = group_id;

    project.artifact_id.clear();
    let artifact_id = interpolate(raw_artifact_id, &project)?;
    if artifact_id.is_empty() || names_itself(&artifact_id, "artifactId") {
        return Err(PomError::InvalidModel(
            "artifactId must not be empty".to_string(),
        ));
    }
    project.artifact_id = artifact_id;

    project.version.clear();
    let version = interpolate(raw_version, &project)?;
    if version.is_empty() || names_itself(&version, "version") {
        return Err(PomError::InvalidModel(
            "version must not be empty".to_string(),
        ));
    }
    project.version = version;
    if let Some(lookup) = project.model_lookup.as_mut() {
        for (field, raw, value) in [
            ("groupId", raw_group_id, &project.group_id),
            ("artifactId", raw_artifact_id, &project.artifact_id),
            ("version", raw_version, &project.version),
        ] {
            if names_itself(raw, field) {
                lookup.keep_coordinate(field, value);
            }
        }
    }

    project.packaging.clear();
    project.packaging = interpolate(raw_packaging, &project)?;
    Ok(project)
}
