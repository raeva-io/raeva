use crate::dependency::{Dependency, DependencyManagement, Exclusion};
use crate::properties::{ProjectInfo, PropertyMap};
use crate::{HostInput, PomError};
use rv_maven_types::bounded;
use std::collections::hash_map;

/// `management` interpolated, and validated when `validate`: an inactive
/// profile's copy is not, as Maven validates the effective model only.
pub(super) fn resolve_dependency_management(
    management: DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
    validate: bool,
) -> Result<DependencyManagement, PomError> {
    let dependencies = management
        .dependencies
        .into_iter()
        .map(|dep| match validate {
            true => resolve_dependency(dep, properties, project),
            false => interpolate_dependency(dep, properties, project, None),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DependencyManagement { dependencies })
}

/// The dependencies of a model, managed and interpolated. A host value
/// that only the version or the exclusions of a dependency read counts as
/// read only when resolution can follow that dependency: always for a
/// project's own, and for a dependency's POM, when
/// [`Dependency::is_followed_transitively`] says so. The others never reach
/// the resolution, except an environment variable in a version, which can
/// make the POM invalid. With `transitive`, the versions and exclusions are
/// read through a detached environment, and what they read passes to
/// `project` only for a dependency resolution follows.
pub(super) fn resolve_dependencies(
    deps: Vec<Dependency>,
    management: &DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
    transitive: bool,
) -> Result<Vec<Dependency>, PomError> {
    if deps.is_empty() {
        return Ok(Vec::new());
    }
    let index = build_managed_dep_index(management);
    let deferred = transitive.then(|| ProjectInfo {
        environment: project.environment.detached(),
        ..project.clone()
    });
    let mut resolved = Vec::with_capacity(deps.len());
    for dep in deps {
        let mut dep = interpolate_dependency(dep, properties, project, deferred.as_ref())?;
        if let Some(managed) = find_managed_dependency_indexed(&dep, &index) {
            apply_managed_dependency(&mut dep, managed);
        }
        if let Some(deferred) = &deferred {
            let reads = deferred.environment.take_reads();
            if dep.is_followed_transitively() {
                for input in reads {
                    project.environment.record(input);
                }
            }
        }
        dep.validate_coordinates(false)?;
        dep.validate_system_scope()?;
        resolved.push(dep);
    }
    // A dependency's POM is a complete model: no outer management supplies
    // a version Maven's validation finds missing there, or empty.
    if transitive
        && let Some(dep) = resolved
            .iter()
            .find(|dep| dep.version.as_deref().is_none_or(str::is_empty))
    {
        return Err(dep.missing(false, "version"));
    }
    // Maven's project validation only warns of an incomplete exclusion,
    // which excludes nothing.
    if !transitive {
        for dep in &resolved {
            for exclusion in &dep.exclusions {
                let field = if exclusion.group_id.is_empty() {
                    "groupId"
                } else if exclusion.artifact_id.is_empty() {
                    "artifactId"
                } else {
                    continue;
                };
                let (group_id, artifact_id, type_, _) = dep.management_key();
                tracing::warn!(
                    sec_code = "POM_PROBLEM",
                    "'dependencies.dependency.exclusions.exclusion.{field}' for {}:{}:{} is missing",
                    bounded(group_id),
                    bounded(artifact_id),
                    bounded(type_)
                );
            }
        }
    }
    Ok(resolved)
}

/// Maven's validation of `deps`, the dependencies of a model whose
/// management alone is used, as an imported BOM's: managed by
/// `management`, they need their coordinates and a version.
pub(super) fn validate_dependencies(
    deps: &[Dependency],
    management: &DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<(), PomError> {
    resolve_dependencies(deps.to_vec(), management, properties, project, true).map(drop)
}

pub(super) fn resolve_dependency(
    dep: Dependency,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Dependency, PomError> {
    let resolved = interpolate_dependency(dep, properties, project, None)?;
    resolved.validate_coordinates(true)?;
    // Validate `<systemPath>` after interpolation so exporters cannot emit invalid entries.
    resolved.validate_system_scope()?;
    Ok(resolved)
}

/// `dep` interpolated, its version and exclusions through `deferred` when
/// given.
pub(super) fn interpolate_dependency(
    dep: Dependency,
    properties: &PropertyMap,
    project: &ProjectInfo,
    deferred: Option<&ProjectInfo>,
) -> Result<Dependency, PomError> {
    let version =
        properties.interpolate_opt(dep.version.as_deref(), deferred.unwrap_or(project))?;
    // An environment variable may be empty, which leaves the version missing
    // and a dependency's POM invalid, so it counts whether or not
    // resolution follows the dependency. No other host value is empty.
    if let Some(deferred) = deferred {
        for input in deferred.environment.take_reads() {
            match input {
                HostInput::Env(_) => project.environment.record(input),
                _ => deferred.environment.record(input),
            }
        }
    }
    let deferred = deferred.unwrap_or(project);
    // Trim whitespace from coordinate fields to match Maven's lenient parsing.
    // Some POMs have stray whitespace in <groupId>, <artifactId>, or <version>
    // (e.g. Quarkus `<groupId> jakarta.servlet</groupId>`).
    let trim_string = |s: String| {
        let trimmed = s.trim();
        if trimmed.len() == s.len() {
            s
        } else {
            trimmed.to_string()
        }
    };
    let trim_opt = |o: Option<String>| o.map(trim_string);
    Ok(Dependency {
        group_id: trim_string(properties.interpolate_str(&dep.group_id, project)?),
        artifact_id: trim_string(properties.interpolate_str(&dep.artifact_id, project)?),
        version: trim_opt(version),
        type_: properties.interpolate_opt(dep.type_.as_deref(), project)?,
        classifier: properties.interpolate_opt(dep.classifier.as_deref(), project)?,
        scope: properties.interpolate_opt(dep.scope.as_deref(), project)?,
        optional: properties.interpolate_opt(dep.optional.as_deref(), project)?,
        exclusions: dep
            .exclusions
            .into_iter()
            .map(|e| resolve_exclusion(e, properties, deferred))
            .collect::<Result<Vec<_>, _>>()?,
        system_path: properties.interpolate_opt(dep.system_path.as_deref(), project)?,
    })
}

fn resolve_exclusion(
    exclusion: Exclusion,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Exclusion, PomError> {
    Ok(Exclusion {
        group_id: properties.interpolate_str(&exclusion.group_id, project)?,
        artifact_id: properties.interpolate_str(&exclusion.artifact_id, project)?,
    })
}

/// Key for managed dependency lookup: (groupId, artifactId, effective_type, normalized_classifier)
type ManagedDepKey<'a> = (&'a str, &'a str, &'a str, Option<&'a str>);

/// Dependency management indexed by (groupId, artifactId, type, classifier).
/// Entries whose keys collide only after interpolation (a parent's
/// `${lib.name}` and a child's `foo`) merge as Maven's
/// DefaultDependencyManagementInjector applies them in turn: each field
/// comes from the first entry that sets it, and the exclusions from the
/// first entry that has any.
pub(super) struct ManagedIndex<'a> {
    index: foldhash::HashMap<ManagedDepKey<'a>, Slot<'a>>,
    merged: Vec<Dependency>,
}

#[derive(Clone, Copy)]
enum Slot<'a> {
    Entry(&'a Dependency),
    Merged(usize),
}

pub(super) fn build_managed_dep_index(management: &DependencyManagement) -> ManagedIndex<'_> {
    let mut index = foldhash::HashMap::with_capacity_and_hasher(
        management.dependencies.len(),
        Default::default(),
    );
    let mut merged = Vec::new();
    for dep in &management.dependencies {
        match index.entry(dep.management_key()) {
            hash_map::Entry::Vacant(slot) => {
                slot.insert(Slot::Entry(dep));
            }
            hash_map::Entry::Occupied(mut slot) => {
                let at = match *slot.get() {
                    Slot::Merged(at) => at,
                    Slot::Entry(first) => {
                        merged.push(first.clone());
                        slot.insert(Slot::Merged(merged.len() - 1));
                        merged.len() - 1
                    }
                };
                apply_managed_dependency(&mut merged[at], dep);
            }
        }
    }
    ManagedIndex { index, merged }
}

pub(super) fn find_managed_dependency_indexed<'i>(
    dep: &Dependency,
    index: &'i ManagedIndex<'_>,
) -> Option<&'i Dependency> {
    match *index.index.get(&dep.management_key())? {
        Slot::Entry(managed) => Some(managed),
        Slot::Merged(at) => Some(&index.merged[at]),
    }
}

pub(super) fn apply_managed_dependency(dep: &mut Dependency, managed: &Dependency) {
    if dep.version.is_none() {
        dep.version.clone_from(&managed.version);
    }
    // Maven semantics: dependency-management `scope` is a fill-in only. A
    // declared scope on the concrete dependency wins; the managed entry's
    // scope applies ONLY when the concrete dependency has no scope of its
    // own. Mirrors managed `version` behaviour (fills in a missing concrete
    // version, never overrides a declared one).
    if dep.scope.is_none() && managed.scope.is_some() {
        dep.scope.clone_from(&managed.scope);
    }
    // Maven manages version, scope, type, classifier, and exclusions, but not `<optional>`.
    if dep.type_.is_none() {
        dep.type_.clone_from(&managed.type_);
    }
    if dep.classifier.is_none() {
        dep.classifier.clone_from(&managed.classifier);
    }
    // Maven's model merger fills a missing `<systemPath>` from dependencyManagement.
    if dep.system_path.is_none() {
        dep.system_path.clone_from(&managed.system_path);
    }
    // Maven 3.9's DefaultDependencyManagementInjector copies the managed
    // exclusions only onto a dependency that declares none. The resolver
    // adds the root project's managed exclusions to every dependency.
    if dep.exclusions.is_empty() {
        dep.exclusions.clone_from(&managed.exclusions);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Management only fills in: a declared version, scope or exclusion list
    /// wins.
    #[test]
    fn managed_fields_only_fill_in_a_declaration() {
        let dep = |version: Option<&str>, scope: Option<&str>, excluded: &[&str]| Dependency {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: version.map(str::to_string),
            type_: None,
            classifier: None,
            scope: scope.map(str::to_string),
            optional: None,
            exclusions: excluded
                .iter()
                .map(|group| Exclusion {
                    group_id: group.to_string(),
                    artifact_id: "lib".to_string(),
                })
                .collect(),
            system_path: None,
        };
        for (declared, managed, expected) in [
            (
                dep(Some("1"), Some("compile"), &[]),
                dep(Some("2"), Some("runtime"), &[]),
                dep(Some("1"), Some("compile"), &[]),
            ),
            (
                dep(None, None, &[]),
                dep(Some("2"), Some("runtime"), &["x"]),
                dep(Some("2"), Some("runtime"), &["x"]),
            ),
            (
                dep(Some("1"), Some("test"), &["own"]),
                dep(None, None, &["managed", "own"]),
                dep(Some("1"), Some("test"), &["own"]),
            ),
        ] {
            let mut concrete = declared;
            apply_managed_dependency(&mut concrete, &managed);
            assert_eq!(concrete, expected);
        }
    }
}
