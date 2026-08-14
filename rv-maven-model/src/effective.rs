//! Lightweight effective identity and aggregation metadata.
//!
//! This module deliberately stops short of inheritance, dependency
//! management, parent fetching, and BOM resolution. Reactor discovery needs
//! only the current POM's interpolated identity and its active aggregation
//! declarations.

use std::fmt;

use crate::activation::evaluate_profiles;
use crate::inheritance::{ParentResolver, apply_inheritance};
use crate::project::profiles::resolve_profiles_for_activation;
use crate::properties::{ParentInfo, ProjectInfo, PropertyMap};
use crate::{ActivationContext, Pom, PomError};

/// An effective Maven group/artifact/version coordinate.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Gav {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

impl fmt::Display for Gav {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.group_id, self.artifact_id, self.version
        )
    }
}

/// The subset of an effective Maven model needed for reactor discovery.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EffectiveDescriptor {
    pub gav: Gav,
    pub active_profiles: Vec<String>,
    pub modules: Vec<String>,
}

impl EffectiveDescriptor {
    /// Compute effective identity and aggregation metadata from one raw POM.
    ///
    /// `ctx.properties` are Maven user/system properties and therefore
    /// override both base and active-profile `<properties>`. Parent
    /// coordinates supply a missing child groupId/version, but parent models
    /// and parent profiles are never loaded or inherited.
    pub fn from_pom(pom: &Pom, ctx: &ActivationContext) -> Result<Self, PomError> {
        Self::from_effective_pom(pom, ctx)
    }

    /// Compute a descriptor after resolving and applying the POM's parent
    /// chain.
    ///
    /// Reactor discovery normally avoids remote model construction, but local
    /// aggregator parents can contribute properties used by a child's
    /// effective GAV (for example `${revision}`). Callers provide the parent
    /// resolver so discovery can load trusted local parents without coupling
    /// this crate to a filesystem or repository implementation.
    pub fn from_pom_with_inheritance(
        pom: Pom,
        resolver: impl ParentResolver,
        ctx: &ActivationContext,
    ) -> Result<Self, PomError> {
        let effective_pom = apply_inheritance(pom, &resolver)?;
        Self::from_effective_pom(&effective_pom, ctx)
    }

    fn from_effective_pom(pom: &Pom, ctx: &ActivationContext) -> Result<Self, PomError> {
        let base_properties = properties_with_user_overrides(&pom.properties, ctx);
        let activation_project = project_info(pom, &base_properties, ctx)?;
        let activation_profiles =
            resolve_profiles_for_activation(&pom.profiles, &base_properties, &activation_project)?;
        let active_profiles = evaluate_profiles(&activation_profiles, ctx);

        let mut effective_properties = pom.properties.clone();
        for profile in &active_profiles {
            effective_properties.extend(&profile.properties);
        }
        apply_user_overrides(&mut effective_properties, ctx);

        let project = project_info(pom, &effective_properties, ctx)?;
        let mut modules = pom.modules.clone();
        for profile in &active_profiles {
            // Aggregation is never inherited. `origin_level == 0` identifies
            // profiles declared by the current POM both for raw descriptors
            // and for descriptors whose parent chain was applied first.
            if profile.origin_level == 0 {
                modules.extend_from_slice(&profile.modules);
            }
        }
        let modules = modules
            .into_iter()
            .map(|module| {
                effective_properties
                    .interpolate_str(&module, &project)
                    .map(|module| module.trim().to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            gav: Gav {
                group_id: project.group_id,
                artifact_id: project.artifact_id,
                version: project.version,
            },
            active_profiles: active_profiles
                .into_iter()
                .map(|profile| profile.id.clone())
                .collect(),
            modules,
        })
    }
}

impl Pom {
    /// Compute the lightweight effective descriptor used by reactor scanning.
    pub fn effective_descriptor(
        &self,
        ctx: &ActivationContext,
    ) -> Result<EffectiveDescriptor, PomError> {
        EffectiveDescriptor::from_pom(self, ctx)
    }

    /// Compute the lightweight effective descriptor after parent inheritance.
    pub fn effective_descriptor_with_inheritance(
        self,
        resolver: impl ParentResolver,
        ctx: &ActivationContext,
    ) -> Result<EffectiveDescriptor, PomError> {
        EffectiveDescriptor::from_pom_with_inheritance(self, resolver, ctx)
    }
}

fn properties_with_user_overrides(
    pom_properties: &PropertyMap,
    ctx: &ActivationContext,
) -> PropertyMap {
    let mut properties = pom_properties.clone();
    apply_user_overrides(&mut properties, ctx);
    properties
}

fn apply_user_overrides(properties: &mut PropertyMap, ctx: &ActivationContext) {
    for (key, value) in &ctx.properties {
        properties.insert(key, value);
    }
}

fn project_info(
    pom: &Pom,
    properties: &PropertyMap,
    ctx: &ActivationContext,
) -> Result<ProjectInfo, PomError> {
    let parent = pom
        .parent
        .as_ref()
        .map(|parent| -> Result<ParentInfo, PomError> {
            Ok(ParentInfo {
                group_id: properties.interpolate_str_no_project(&parent.group_id)?,
                artifact_id: properties.interpolate_str_no_project(&parent.artifact_id)?,
                version: properties.interpolate_str_no_project(&parent.version)?,
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

    let unresolved_project = ProjectInfo {
        group_id: String::new(),
        artifact_id: String::new(),
        version: String::new(),
        packaging: String::new(),
        parent: parent.clone(),
        basedir: ctx.base_dir.clone(),
        local_repository: ctx.local_repository.clone(),
    };
    let interpolate = |value: &str| {
        properties
            .interpolate_str(value, &unresolved_project)
            .map(|value| value.trim().to_string())
    };
    let group_id = interpolate(raw_group_id)?;
    let artifact_id = interpolate(raw_artifact_id)?;
    let version = interpolate(raw_version)?;
    let packaging = interpolate(raw_packaging)?;

    for (name, value) in [
        ("groupId", &group_id),
        ("artifactId", &artifact_id),
        ("version", &version),
    ] {
        if value.is_empty() {
            return Err(PomError::InvalidModel(format!("{name} must not be empty")));
        }
    }

    Ok(ProjectInfo {
        group_id,
        artifact_id,
        version,
        packaging,
        parent,
        basedir: ctx.base_dir.clone(),
        local_repository: ctx.local_repository.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> Pom {
        Pom::parse(xml).expect("parse POM")
    }

    #[test]
    fn computes_ci_friendly_gav_and_active_profile_modules() {
        let pom = parse(
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>reactor</artifactId>
              <version>${revision}${sha1}${changelist}</version>
              <modules><module>base</module></modules>
              <profiles>
                <profile>
                  <id>extras</id>
                  <modules><module>${module.dir}</module></modules>
                  <properties><module.dir>extra</module.dir></properties>
                </profile>
              </profiles>
            </project>
            "#,
        );
        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("revision".to_string(), "2.0.0".to_string());
        ctx.properties
            .insert("sha1".to_string(), "-abc".to_string());
        ctx.properties
            .insert("changelist".to_string(), "-SNAPSHOT".to_string());
        ctx.active_profiles.push("extras".to_string());

        let descriptor = pom.effective_descriptor(&ctx).expect("descriptor");

        assert_eq!(
            descriptor.gav,
            Gav {
                group_id: "com.example".to_string(),
                artifact_id: "reactor".to_string(),
                version: "2.0.0-abc-SNAPSHOT".to_string(),
            }
        );
        assert_eq!(descriptor.active_profiles, ["extras"]);
        assert_eq!(descriptor.modules, ["base", "extra"]);
    }

    #[test]
    fn inactive_profile_does_not_add_modules() {
        let pom = parse(
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>reactor</artifactId>
              <version>1</version>
              <modules><module>base</module></modules>
              <profiles>
                <profile>
                  <id>extras</id>
                  <modules><module>extra</module></modules>
                </profile>
              </profiles>
            </project>
            "#,
        );

        let descriptor = pom
            .effective_descriptor(&ActivationContext::default())
            .expect("descriptor");

        assert!(descriptor.active_profiles.is_empty());
        assert_eq!(descriptor.modules, ["base"]);
    }

    #[test]
    fn child_identity_falls_back_to_interpolated_parent_coordinates() {
        let pom = parse(
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <parent>
                <groupId>com.example</groupId>
                <artifactId>parent</artifactId>
                <version>${revision}</version>
              </parent>
              <artifactId>child</artifactId>
            </project>
            "#,
        );
        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("revision".to_string(), "3.1.4".to_string());

        let descriptor = pom.effective_descriptor(&ctx).expect("descriptor");

        assert_eq!(descriptor.gav.to_string(), "com.example:child:3.1.4");
    }

    #[test]
    fn user_property_overrides_profile_property_for_gav() {
        let pom = parse(
            r#"
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>reactor</artifactId>
              <version>${revision}</version>
              <profiles>
                <profile>
                  <id>override</id>
                  <properties><revision>profile</revision></properties>
                </profile>
              </profiles>
            </project>
            "#,
        );
        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("revision".to_string(), "user".to_string());
        ctx.active_profiles.push("override".to_string());

        let descriptor = pom.effective_descriptor(&ctx).expect("descriptor");

        assert_eq!(descriptor.gav.version, "user");
    }
}
