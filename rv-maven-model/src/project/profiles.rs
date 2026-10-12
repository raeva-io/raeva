//! Profile activation and interpolation for the effective project model.

use crate::dependency::DependencyManagement;
use crate::properties::{ProjectInfo, PropertyMap};
use crate::{Activation, PomError, Profile};

use super::dep_management::{
    build_managed_dep_index, find_managed_dependency_indexed, resolve_dependencies_with,
    resolve_dependency_management,
};
use super::repositories::resolve_repositories;

pub(super) fn resolve_profiles(
    profiles: Vec<Profile>,
    management: &DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Vec<Profile>, PomError> {
    // One base index serves every profile; with large BOM imports, rebuilding
    // it per profile dominated model building.
    let base_index = std::cell::OnceCell::new();
    profiles
        .into_iter()
        .map(|profile| {
            let id = properties.interpolate_str(&profile.id, project)?;
            let activation = profile
                .activation
                .map(|a| resolve_activation(a, properties, project))
                .transpose()?;
            let resolved_management = profile
                .dependency_management
                .map(|own| resolve_dependency_management(own, properties, project))
                .transpose()?;
            let dependencies = if profile.dependencies.is_empty() {
                Vec::new()
            } else {
                let base = base_index.get_or_init(|| build_managed_dep_index(management));
                let own = resolved_management.as_ref().map(build_managed_dep_index);
                // Base entries win over the profile's own management for the
                // same coordinate. Inactive profiles may omit `<systemPath>`,
                // so validation waits until an active profile is merged.
                resolve_dependencies_with(
                    profile.dependencies,
                    |dep| {
                        find_managed_dependency_indexed(dep, base).or_else(|| {
                            own.as_ref()
                                .and_then(|own| find_managed_dependency_indexed(dep, own))
                        })
                    },
                    properties,
                    project,
                    false,
                )?
            };
            Ok(Profile {
                id,
                activation,
                dependencies,
                repositories: resolve_repositories(profile.repositories, properties, project)?,
                modules: profile
                    .modules
                    .into_iter()
                    .map(|module| properties.interpolate_str(&module, project))
                    .collect::<Result<_, _>>()?,
                properties: profile.properties,
                dependency_management: resolved_management,
                origin_level: profile.origin_level,
            })
        })
        .collect()
}

pub(crate) fn resolve_profiles_for_activation(
    profiles: &[Profile],
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Vec<Profile>, PomError> {
    profiles
        .iter()
        .map(|profile| {
            Ok(Profile {
                id: properties.interpolate_str(&profile.id, project)?,
                activation: profile
                    .activation
                    .clone()
                    .map(|a| resolve_activation(a, properties, project))
                    .transpose()?,
                dependencies: profile.dependencies.clone(),
                repositories: profile.repositories.clone(),
                modules: profile.modules.clone(),
                properties: profile.properties.clone(),
                dependency_management: profile.dependency_management.clone(),
                origin_level: profile.origin_level,
            })
        })
        .collect()
}

pub(super) fn resolve_activation(
    activation: Activation,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Activation, PomError> {
    interpolate_activation(activation, |value| {
        properties.interpolate_str(value, project)
    })
}

/// Interpolate activation fields before profile selection, including while
/// reading raw lineage POMs whose parents have not been resolved yet.
pub(crate) fn interpolate_activation(
    activation: Activation,
    interpolate: impl Fn(&str) -> Result<String, PomError>,
) -> Result<Activation, PomError> {
    let interpolate_opt = |value: Option<&str>| value.map(&interpolate).transpose();
    use crate::activation::{ActivationFile, ActivationOs, ActivationProperty};

    let property = activation
        .property
        .map(|prop| -> Result<_, PomError> {
            Ok(ActivationProperty {
                name: interpolate_opt(prop.name.as_deref())?,
                value: interpolate_opt(prop.value.as_deref())?,
            })
        })
        .transpose()?;

    let os = activation
        .os
        .map(|os| -> Result<_, PomError> {
            Ok(ActivationOs {
                name: interpolate_opt(os.name.as_deref())?,
                family: interpolate_opt(os.family.as_deref())?,
                arch: interpolate_opt(os.arch.as_deref())?,
                version: interpolate_opt(os.version.as_deref())?,
            })
        })
        .transpose()?;

    let file = activation
        .file
        .map(|file| -> Result<_, PomError> {
            Ok(ActivationFile {
                exists: interpolate_opt(file.exists.as_deref())?,
                missing: interpolate_opt(file.missing.as_deref())?,
            })
        })
        .transpose()?;

    Ok(Activation {
        active_by_default: activation.active_by_default,
        property,
        os,
        jdk: interpolate_opt(activation.jdk.as_deref())?,
        file,
    })
}
