//! Effective Maven project model construction and orchestration.
//!
//! The `Project` type is the public entry point: it owns the assembled
//! group/artifact/version, properties, dependency management, dependencies,
//! repositories, profiles, modules, and any relocation. The submodules in
//! this directory implement the individual resolution steps.

mod bom;
mod dep_management;
pub(crate) mod profiles;
mod relocation;
mod repositories;

use crate::activation::evaluate_profiles;
use crate::dependency::{Dependency, DependencyManagement};
use crate::inheritance::{ParentResolver, apply_inheritance};
use crate::properties::{ParentInfo, ProjectInfo, PropertyMap};
use crate::repository::Repository;
use crate::{ActivationContext, Pom, PomError, Profile, Relocation, Scope};

use bom::resolve_bom_imports;
use dep_management::resolve_dependencies;
use profiles::{resolve_profiles, resolve_profiles_for_activation};
use relocation::resolve_relocation;
use repositories::resolve_repositories;

/// The effective Maven project model after applying parent inheritance, property
/// interpolation, profile activation, and BOM imports.
///
/// Constructed via `Project::from_pom()` from a raw `Pom`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Project {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub packaging: String,
    #[serde(default, skip_serializing_if = "PropertyMap::is_empty")]
    pub properties: PropertyMap,
    #[serde(default)]
    pub dependency_management: DependencyManagement,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<Repository>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<Profile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relocation: Option<Relocation>,
}

impl Project {
    /// Computes the effective project model from a raw POM using system-default activation.
    pub fn from_pom(pom: Pom, resolver: impl ParentResolver) -> Result<Self, PomError> {
        let ctx = ActivationContext::from_system();
        Self::from_pom_with_context(pom, resolver, &ctx)
    }

    /// Computes the effective project model from a raw POM with a custom activation context.
    pub fn from_pom_with_context(
        pom: Pom,
        resolver: impl ParentResolver,
        ctx: &ActivationContext,
    ) -> Result<Self, PomError> {
        // Step 0: Surface the POM's own <repositories> to the resolver before
        // we fetch the parent. A POM that declares a custom repository to
        // host its own parent would otherwise fail: the parent fetch runs
        // first, against the not-yet-extended repository list. The hook is
        // a no-op for resolvers that do not implement it.
        if !pom.repositories.is_empty() {
            resolver.observe_project_repositories(&pom.repositories);
        }

        // Step 1: Resolve full parent chain (inheritance merges parent properties)
        let pom = apply_inheritance(pom, &resolver)?;
        let project_info = project_info_from_pom(&pom, ctx)?;
        let raw_relocation = pom
            .distribution_management
            .as_ref()
            .and_then(|dm| dm.relocation.clone());

        // Step 2: Activate profiles. Maven's PropertyProfileActivator consults
        // ONLY user properties (-D) and system properties; POM `<properties>`
        // never drive `<property>` activation (a documented Maven gotcha, and
        // it cuts both ways: a `!prop` condition must not be defeated by a POM
        // defining that name). The POM property chain is still used to
        // interpolate `${...}` inside the activation blocks themselves.
        let activation_profiles =
            resolve_profiles_for_activation(&pom.profiles, &pom.properties, &project_info)?;

        // Compute the active profile set with Maven's POM-level suppression
        // rule for `<activeByDefault>` applied (see
        // `crate::activation::evaluate_profiles`). `activeByDefault` profiles
        // only contribute as a fallback when nothing else activated.
        let active_profiles: Vec<&Profile> = evaluate_profiles(&activation_profiles, ctx);

        // Step 3: Build effective properties = POM properties + active profile properties.
        // All properties are available before BOM resolution.
        let effective_properties = {
            let mut props = pom.properties.clone();
            for profile in &active_profiles {
                props.extend(&profile.properties);
            }
            if let Some(maven) = pom
                .prerequisites
                .as_ref()
                .and_then(|prerequisites| prerequisites.maven.as_ref())
            {
                // Maven exposes model fields through its expression evaluator.
                // These are synthesized model values, not ordinary user
                // properties, so they take precedence over same-named entries.
                props.insert("project.prerequisites.maven", maven);
                props.insert("pom.prerequisites.maven", maven);
            }
            props
        };
        let relocation = resolve_relocation(raw_relocation, &effective_properties, &project_info)?;

        // Step 4: Resolve BOM imports with complete effective properties.
        // Use fixed-point import resolution so imports that become resolvable
        // after earlier imports contribute properties are retried.
        // BOM properties and profiles are NOT merged into the importer.
        let dependency_management = pom.dependency_management.unwrap_or_default();
        let bom_result = resolve_bom_imports(
            dependency_management,
            &effective_properties,
            &project_info,
            &resolver,
        )?;
        let base_dependency_management = bom_result.management;

        // Build effective dependency management. Maven's DefaultProfileInjector
        // uses `sourceDominant=true`, so active-profile depMgmt entries override
        // base entries for the same coordinate. `build_managed_dep_index` uses
        // first-wins, so we prepend profile entries ahead of the base list to
        // give them precedence.
        let effective_dependency_management = {
            let mut profile_deps = Vec::new();
            for profile in &active_profiles {
                if let Some(profile_management) = &profile.dependency_management {
                    let resolved_profile_management = resolve_bom_imports(
                        profile_management.clone(),
                        &effective_properties,
                        &project_info,
                        &resolver,
                    )?;
                    profile_deps.extend(resolved_profile_management.management.dependencies);
                }
            }
            let mut mgmt = base_dependency_management.clone();
            // Prepend so first-wins index resolution picks profile entries first.
            profile_deps.extend(std::mem::take(&mut mgmt.dependencies));
            mgmt.dependencies = profile_deps;
            mgmt
        };

        // Combine dependencies from POM and active profiles
        // Move pom.dependencies since we own it
        let combined_dependencies = {
            let mut deps = pom.dependencies;
            for profile in &active_profiles {
                deps.extend_from_slice(&profile.dependencies);
            }
            deps
        };

        let dependencies = resolve_dependencies(
            combined_dependencies,
            &effective_dependency_management,
            &effective_properties,
            &project_info,
        )?;

        // Combine repositories from POM and active profiles
        // Move pom.repositories since we own it
        let combined_repositories = {
            let mut repos = pom.repositories;
            for profile in &active_profiles {
                repos.extend_from_slice(&profile.repositories);
            }
            repos
        };

        let repositories =
            resolve_repositories(combined_repositories, &effective_properties, &project_info)?;
        // Aggregation is never inherited. `apply_inheritance` already limits
        // base modules to the current raw POM. Only active profiles
        // originating in that same POM may add modules here.
        let combined_modules = {
            let mut modules = pom.modules;
            for profile in &active_profiles {
                if profile.origin_level == 0 {
                    modules.extend_from_slice(&profile.modules);
                }
            }
            modules
        };
        let modules = resolve_modules(combined_modules, &effective_properties, &project_info)?;
        let profiles = resolve_profiles(
            pom.profiles,
            &base_dependency_management,
            &effective_properties,
            &project_info,
        )?;

        let ProjectInfo {
            group_id,
            artifact_id,
            version,
            packaging,
            ..
        } = project_info;

        Ok(Project {
            group_id,
            artifact_id,
            version,
            packaging,
            properties: effective_properties,
            dependency_management: effective_dependency_management,
            dependencies,
            repositories,
            profiles,
            modules,
            relocation,
        })
    }

    pub fn dependencies(&self, scope: Scope) -> Vec<Dependency> {
        self.dependencies
            .iter()
            .filter(|dep| scope_includes(scope, dep.effective_scope()))
            .cloned()
            .collect()
    }
}

pub(super) fn project_info_from_pom(
    pom: &Pom,
    ctx: &ActivationContext,
) -> Result<ProjectInfo, PomError> {
    let raw_group_id = pom
        .group_id
        .as_deref()
        .ok_or(PomError::MissingField("groupId"))?;
    let raw_artifact_id = pom
        .artifact_id
        .as_deref()
        .ok_or(PomError::MissingField("artifactId"))?;
    let raw_version = pom
        .version
        .as_deref()
        .ok_or(PomError::MissingField("version"))?;
    let raw_packaging = pom.packaging.as_deref().unwrap_or("jar");

    let parent = pom
        .parent
        .as_ref()
        .map(|p| -> Result<ParentInfo, PomError> {
            Ok(ParentInfo {
                group_id: pom.properties.interpolate_str_no_project(&p.group_id)?,
                artifact_id: pom.properties.interpolate_str_no_project(&p.artifact_id)?,
                version: pom.properties.interpolate_str_no_project(&p.version)?,
            })
        })
        .transpose()?;

    let temp_project = ProjectInfo {
        group_id: String::new(),
        artifact_id: String::new(),
        version: String::new(),
        packaging: String::new(),
        parent: parent.clone(),
        basedir: ctx.base_dir.clone(),
        local_repository: ctx.local_repository.clone(),
    };

    let group_id = pom
        .properties
        .interpolate_str(raw_group_id, &temp_project)?;
    let artifact_id = pom
        .properties
        .interpolate_str(raw_artifact_id, &temp_project)?;
    let version = pom.properties.interpolate_str(raw_version, &temp_project)?;
    let packaging = pom
        .properties
        .interpolate_str(raw_packaging, &temp_project)?;

    // Trim whitespace from root project coordinates to match Maven's lenient parsing.
    // Stray whitespace in <groupId>, <artifactId>, or <version> can leak into the
    // final model if not trimmed here (dependency coordinates are already trimmed in
    // resolve_dependency).
    let trim = |s: String| {
        let trimmed = s.trim();
        if trimmed.len() == s.len() {
            s
        } else {
            trimmed.to_string()
        }
    };

    let group_id = trim(group_id);
    let artifact_id = trim(artifact_id);
    let version = trim(version);
    let packaging = trim(packaging);

    // `${project.groupId}` and `${project.version}` resolve via project-coordinate
    // shorthand against `temp_project`, which is initialized with empty strings.
    // A POM that uses these shortcuts in its own root coordinates would silently
    // produce an empty groupId/version. Reject the empty result explicitly.
    if group_id.is_empty() {
        return Err(PomError::InvalidModel(
            "groupId must not be empty".to_string(),
        ));
    }
    if artifact_id.is_empty() {
        return Err(PomError::InvalidModel(
            "artifactId must not be empty".to_string(),
        ));
    }
    if version.is_empty() {
        return Err(PomError::InvalidModel(
            "version must not be empty".to_string(),
        ));
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

fn resolve_modules(
    modules: Vec<String>,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Vec<String>, PomError> {
    modules
        .into_iter()
        .map(|module| properties.interpolate_str(&module, project))
        .collect()
}

/// Returns whether `dep_scope` contributes to the classpath named by `target`.
///
/// Mirrors Maven's classpath assembly rules (see Maven Reference, "Dependency
/// Scope" table): the *compile* classpath contains compile + provided +
/// system, the *runtime* classpath contains compile + runtime, and the
/// *test* classpath contains compile + runtime + test. These rules govern
/// which artifacts land on a given classpath at build time; they are NOT a
/// statement about which scopes propagate transitively when walking a
/// dependency graph.
///
/// Callers that perform transitive reachability (e.g. the resolver's graph
/// walk) must use the resolver's own scope-mapping table instead: `provided`
/// and `system` deps are not transitively visible to dependents even though
/// they appear on the consumer's compile classpath. Within this crate the
/// function is only used by [`Project::dependencies`] to enumerate the
/// project's own declared dependencies for the requested classpath, which
/// matches the intended classpath-inclusion semantics.
fn scope_includes(target: Scope, dep_scope: Scope) -> bool {
    match target {
        Scope::Compile => matches!(dep_scope, Scope::Compile | Scope::Provided | Scope::System),
        Scope::Runtime => matches!(dep_scope, Scope::Compile | Scope::Runtime),
        Scope::Test => matches!(dep_scope, Scope::Compile | Scope::Runtime | Scope::Test),
        Scope::Provided => dep_scope == Scope::Provided,
        Scope::System => dep_scope == Scope::System,
        Scope::Import => dep_scope == Scope::Import,
    }
}

#[cfg(test)]
mod tests;
