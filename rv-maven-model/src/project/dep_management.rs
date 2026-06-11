//! Dependency-management merging and concrete dependency resolution.

use crate::PomError;
use crate::dependency::{Dependency, DependencyManagement, Exclusion};
use crate::properties::{ProjectInfo, PropertyMap};
use std::collections::HashMap;

pub(super) fn resolve_dependency_management(
    management: DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<DependencyManagement, PomError> {
    let dependencies = management
        .dependencies
        .into_iter()
        .map(|dep| resolve_dependency(dep, properties, project))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DependencyManagement { dependencies })
}

pub(super) fn resolve_dependencies(
    deps: Vec<Dependency>,
    management: &DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Vec<Dependency>, PomError> {
    let mut resolved = Vec::new();
    let index = build_managed_dep_index(management);

    for dep in deps {
        let mut dep = resolve_dependency(dep, properties, project)?;
        if let Some(managed) = find_managed_dependency_indexed(&dep, &index) {
            apply_managed_dependency(&mut dep, managed);
        }
        if dep.version.is_none() {
            tracing::debug!(
                group_id = %dep.group_id,
                artifact_id = %dep.artifact_id,
                "dependency has no version after applying dependency management; \
                 the resolver will attempt to supply a version from outer management"
            );
        }
        resolved.push(dep);
    }

    Ok(resolved)
}

pub(super) fn resolve_dependency(
    dep: Dependency,
    properties: &PropertyMap,
    project: &ProjectInfo,
) -> Result<Dependency, PomError> {
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
    let resolved = Dependency {
        group_id: trim_string(properties.interpolate_str(&dep.group_id, project)?),
        artifact_id: trim_string(properties.interpolate_str(&dep.artifact_id, project)?),
        version: trim_opt(properties.interpolate_opt(dep.version.as_deref(), project)?),
        type_: properties.interpolate_opt(dep.type_.as_deref(), project)?,
        classifier: properties.interpolate_opt(dep.classifier.as_deref(), project)?,
        scope: properties.interpolate_opt(dep.scope.as_deref(), project)?,
        optional: properties.interpolate_opt(dep.optional.as_deref(), project)?,
        exclusions: dep
            .exclusions
            .into_iter()
            .map(|e| resolve_exclusion(e, properties, project))
            .collect::<Result<Vec<_>, _>>()?,
        system_path: properties.interpolate_opt(dep.system_path.as_deref(), project)?,
    };
    // After property interpolation, enforce Maven's systemPath requirement so
    // we fail loudly instead of letting downstream exporters emit broken
    // entries. Non-system deps short-circuit.
    resolved.validate_system_scope()?;
    Ok(resolved)
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

/// Build an index from dependency management for O(1) lookup.
/// The index maps (groupId, artifactId, type, classifier) -> &Dependency.
///
/// Uses "first wins" semantics: the first entry for a given key is kept,
/// later duplicates are ignored. This matches Maven's behavior where the
/// first `<dependencyManagement>` declaration for a given coordinate takes
/// precedence. Callers control precedence via list ordering (e.g., locals
/// before BOM imports so that local declarations override imported ones).
pub(super) fn build_managed_dep_index(
    management: &DependencyManagement,
) -> HashMap<ManagedDepKey<'_>, &Dependency> {
    let mut index = HashMap::with_capacity(management.dependencies.len());
    for dep in &management.dependencies {
        let key = (
            dep.group_id.as_str(),
            dep.artifact_id.as_str(),
            dep.effective_type(),
            dep.effective_classifier(),
        );
        index.entry(key).or_insert(dep);
    }
    index
}

pub(super) fn find_managed_dependency_indexed<'a>(
    dep: &Dependency,
    index: &HashMap<ManagedDepKey<'a>, &'a Dependency>,
) -> Option<&'a Dependency> {
    let key = (
        dep.group_id.as_str(),
        dep.artifact_id.as_str(),
        dep.effective_type(),
        dep.effective_classifier(),
    );
    index.get(&key).copied()
}

pub(super) fn normalize_classifier(classifier: &Option<String>) -> Option<&str> {
    classifier.as_deref().filter(|value| !value.is_empty())
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
    if dep.optional.is_none() {
        dep.optional.clone_from(&managed.optional);
    }
    if dep.type_.is_none() {
        dep.type_.clone_from(&managed.type_);
    }
    if dep.classifier.is_none() {
        dep.classifier.clone_from(&managed.classifier);
    }
    // Maven semantics: a managed entry's exclusions UNION with any exclusions
    // declared on the concrete dependency, so exclusions the BOM author intended
    // to enforce are kept even when the dep declares its own. Dedup by the
    // (groupId, artifactId) pair so duplicate declarations collapse cleanly.
    if !managed.exclusions.is_empty() {
        use std::collections::HashSet;
        let mut seen: HashSet<(String, String)> = dep
            .exclusions
            .iter()
            .map(|ex| (ex.group_id.clone(), ex.artifact_id.clone()))
            .collect();
        for ex in &managed.exclusions {
            let key = (ex.group_id.clone(), ex.artifact_id.clone());
            if seen.insert(key) {
                dep.exclusions.push(ex.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(group: &str, artifact: &str, version: Option<&str>, scope: Option<&str>) -> Dependency {
        Dependency {
            group_id: group.to_string(),
            artifact_id: artifact.to_string(),
            version: version.map(str::to_string),
            type_: None,
            classifier: None,
            scope: scope.map(str::to_string),
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        }
    }

    // Per Maven semantics, dependency-management scope is fill-in only: a
    // declared scope on the concrete dep wins; the managed scope only
    // applies when the concrete dep has no scope of its own.
    #[test]
    fn declared_scope_wins_over_managed_scope() {
        // BOM pins `runtime`; concrete declares `compile`. Concrete wins.
        let mut concrete = dep("g", "a", Some("1.0"), Some("compile"));
        let managed = dep("g", "a", Some("1.0"), Some("runtime"));
        apply_managed_dependency(&mut concrete, &managed);
        assert_eq!(
            concrete.scope.as_deref(),
            Some("compile"),
            "a declared scope on the concrete dependency must win over the managed scope"
        );
    }

    #[test]
    fn managed_scope_fills_in_when_concrete_has_none() {
        // Concrete dep has no scope, BOM pins `runtime`. Managed wins.
        let mut concrete = dep("g", "a", Some("1.0"), None);
        let managed = dep("g", "a", Some("1.0"), Some("runtime"));
        apply_managed_dependency(&mut concrete, &managed);
        assert_eq!(
            concrete.scope.as_deref(),
            Some("runtime"),
            "managed scope must fill in when the concrete dependency declares no scope"
        );
    }

    // Regression guard: when managed has no scope, declared scope is preserved.
    #[test]
    fn managed_scope_absent_preserves_declared_scope() {
        let mut concrete = dep("g", "a", Some("1.0"), Some("compile"));
        let managed = dep("g", "a", Some("1.0"), None);
        apply_managed_dependency(&mut concrete, &managed);
        assert_eq!(concrete.scope.as_deref(), Some("compile"));
    }

    fn exclusion(group: &str, artifact: &str) -> Exclusion {
        Exclusion {
            group_id: group.to_string(),
            artifact_id: artifact.to_string(),
        }
    }

    #[test]
    fn managed_exclusions_union_with_dep_exclusions() {
        // Maven unions managed and dep-level exclusions, so exclusions the BOM
        // author committed to survive even when the dep declares its own.
        let mut concrete = dep("g", "a", Some("1.0"), None);
        concrete.exclusions.push(exclusion("dep.only", "lib"));

        let mut managed = dep("g", "a", Some("1.0"), None);
        managed.exclusions.push(exclusion("managed.only", "lib"));
        // Overlap: should not be duplicated after the union.
        managed.exclusions.push(exclusion("dep.only", "lib"));

        apply_managed_dependency(&mut concrete, &managed);
        let pairs: Vec<(String, String)> = concrete
            .exclusions
            .iter()
            .map(|ex| (ex.group_id.clone(), ex.artifact_id.clone()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("dep.only".to_string(), "lib".to_string()),
                ("managed.only".to_string(), "lib".to_string()),
            ],
            "managed exclusions must be appended after dep exclusions, deduped"
        );
    }

    #[test]
    fn managed_exclusions_populate_when_dep_has_none() {
        let mut concrete = dep("g", "a", Some("1.0"), None);
        let mut managed = dep("g", "a", Some("1.0"), None);
        managed.exclusions.push(exclusion("x", "y"));

        apply_managed_dependency(&mut concrete, &managed);
        assert_eq!(concrete.exclusions.len(), 1);
        assert_eq!(concrete.exclusions[0].group_id, "x");
    }

    // Regression guard: declared version is NOT overridden by managed version.
    #[test]
    fn managed_version_does_not_override_declared_version() {
        let mut concrete = dep("g", "a", Some("1.0"), None);
        let managed = dep("g", "a", Some("2.0"), None);
        apply_managed_dependency(&mut concrete, &managed);
        assert_eq!(
            concrete.version.as_deref(),
            Some("1.0"),
            "declared version must be preserved; managed version only fills missing version"
        );
    }
}
