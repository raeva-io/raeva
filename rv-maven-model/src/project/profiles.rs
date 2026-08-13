//! Profile activation and interpolation for the effective project model.

use crate::dependency::DependencyManagement;
use crate::properties::{ProjectInfo, PropertyMap};
use crate::{Activation, PomError, Profile};

use super::dep_management::{resolve_dependencies, resolve_dependency_management};
use super::repositories::resolve_repositories;

pub(super) fn resolve_profiles(
    profiles: Vec<Profile>,
    management: &DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Vec<Profile>, PomError> {
    profiles
        .into_iter()
        .map(|profile| {
            let id = properties.interpolate_str(&profile.id, project)?;
            let activation = profile
                .activation
                .map(|a| resolve_activation(a, properties, project))
                .transpose()?;
            // Build active_management: base management + profile's resolved management (if any).
            // Use Cow-like pattern: only clone if we need to extend.
            let (active_management, resolved_management) =
                if let Some(profile_management) = profile.dependency_management {
                    let resolved =
                        resolve_dependency_management(profile_management, properties, project)?;
                    let mut active = management.clone();
                    // Move resolved.dependencies into active, keeping a clone for the return.
                    let resolved_deps_for_return = resolved.dependencies.clone();
                    active.dependencies.extend(resolved.dependencies);
                    (
                        std::borrow::Cow::Owned(active),
                        Some(DependencyManagement {
                            dependencies: resolved_deps_for_return,
                        }),
                    )
                } else {
                    (std::borrow::Cow::Borrowed(management), None)
                };
            Ok(Profile {
                id,
                activation,
                dependencies: resolve_dependencies(
                    profile.dependencies,
                    &active_management,
                    properties,
                    project,
                )?,
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
    use crate::activation::{ActivationFile, ActivationOs, ActivationProperty};

    let property = activation
        .property
        .map(|prop| -> Result<_, PomError> {
            Ok(ActivationProperty {
                name: properties.interpolate_opt(prop.name.as_deref(), project)?,
                value: properties.interpolate_opt(prop.value.as_deref(), project)?,
            })
        })
        .transpose()?;

    let os = activation
        .os
        .map(|os| -> Result<_, PomError> {
            Ok(ActivationOs {
                name: properties.interpolate_opt(os.name.as_deref(), project)?,
                family: properties.interpolate_opt(os.family.as_deref(), project)?,
                arch: properties.interpolate_opt(os.arch.as_deref(), project)?,
                version: properties.interpolate_opt(os.version.as_deref(), project)?,
            })
        })
        .transpose()?;

    let file = activation
        .file
        .map(|file| -> Result<_, PomError> {
            Ok(ActivationFile {
                exists: properties.interpolate_opt(file.exists.as_deref(), project)?,
                missing: properties.interpolate_opt(file.missing.as_deref(), project)?,
            })
        })
        .transpose()?;

    Ok(Activation {
        active_by_default: activation.active_by_default,
        property,
        os,
        jdk: properties.interpolate_opt(activation.jdk.as_deref(), project)?,
        file,
    })
}
