use std::collections::HashSet;

use indexmap::IndexMap;

use crate::dependency::{Dependency, DependencyManagement};
use crate::error::ParentCoordMismatch;
use crate::pom::{Build, Parent, Plugin, PluginManagement};
use crate::{Pom, PomError, PropertyMap};

/// Trait for resolving parent POMs and BOM imports during effective model computation.
pub trait ParentResolver {
    /// Resolves a parent POM by its coordinates. Returns `None` if unavailable.
    fn resolve_parent(&self, parent: &Parent) -> Result<Option<Pom>, PomError>;
    fn resolve_import_pom(
        &self,
        _group_id: &str,
        _artifact_id: &str,
        _version: &str,
        _type_: Option<&str>,
        _classifier: Option<&str>,
    ) -> Result<Option<Pom>, PomError> {
        Ok(None)
    }

    /// Controls whether missing parents should be treated as errors or warnings.
    /// When true, missing parents cause resolution to fail with ParentNotFound.
    /// When false, missing parents are logged as warnings and resolution continues.
    fn strict_parent_resolution(&self) -> bool {
        true
    }

    /// Controls whether missing BOM imports should cause errors.
    /// When true (default), missing BOMs cause resolution to fail.
    /// When false, missing BOMs are skipped (useful for local-only resolution).
    fn strict_bom_resolution(&self) -> bool {
        true
    }

    /// Hook called with a POM's own `<repositories>` before its parent is
    /// fetched. Implementations should merge the provided repositories into
    /// the active resolution context so a POM that declares a custom
    /// repository hosting its parent can resolve. The default is a no-op.
    ///
    /// Implementations must apply any cross-project trust policy themselves
    /// (e.g. the resolver's `allow_transitive_repositories` flag): the
    /// model crate only forwards the declarations.
    fn observe_project_repositories(&self, _repositories: &[crate::repository::Repository]) {}
}

/// Allow `&R` to satisfy `impl ParentResolver` so call sites can borrow a
/// resolver rather than consuming it. Useful when a single resolver instance
/// is reused for multiple `from_pom` calls (tests, BOM imports).
impl<R: ParentResolver + ?Sized> ParentResolver for &R {
    fn resolve_parent(&self, parent: &Parent) -> Result<Option<Pom>, PomError> {
        (*self).resolve_parent(parent)
    }

    fn resolve_import_pom(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        type_: Option<&str>,
        classifier: Option<&str>,
    ) -> Result<Option<Pom>, PomError> {
        (*self).resolve_import_pom(group_id, artifact_id, version, type_, classifier)
    }

    fn strict_parent_resolution(&self) -> bool {
        (*self).strict_parent_resolution()
    }

    fn strict_bom_resolution(&self) -> bool {
        (*self).strict_bom_resolution()
    }

    fn observe_project_repositories(&self, repositories: &[crate::repository::Repository]) {
        (*self).observe_project_repositories(repositories);
    }
}

/// Cap on parent-POM chain depth. Real-world POMs rarely chain past four
/// levels; 100 leaves room for unusual layouts without permitting an
/// infinite-loop POM to wedge resolution.
const MAX_INHERITANCE_DEPTH: usize = 100;

pub fn apply_inheritance(pom: Pom, resolver: &impl ParentResolver) -> Result<Pom, PomError> {
    let mut chain = Vec::new();
    let mut current_pom = pom;
    let mut visited = HashSet::new();

    loop {
        if chain.len() >= MAX_INHERITANCE_DEPTH {
            return Err(PomError::InvalidModel(format!(
                "inheritance depth exceeded limit of {}",
                MAX_INHERITANCE_DEPTH
            )));
        }

        let Some(raw_parent) = current_pom.parent.clone() else {
            chain.push(current_pom);
            break;
        };

        let parent = Parent {
            group_id: current_pom
                .properties
                .interpolate_str_no_project(&raw_parent.group_id)?,
            artifact_id: current_pom
                .properties
                .interpolate_str_no_project(&raw_parent.artifact_id)?,
            version: current_pom
                .properties
                .interpolate_str_no_project(&raw_parent.version)?,
            relative_path: raw_parent.relative_path.clone(),
        };
        current_pom.parent = Some(parent.clone());

        let parent_key = (
            parent.group_id.clone(),
            parent.artifact_id.clone(),
            parent.version.clone(),
        );

        if visited.contains(&parent_key) {
            return Err(PomError::InvalidModel("parent cycle detected".to_string()));
        }
        visited.insert(parent_key);

        chain.push(current_pom);

        match resolver.resolve_parent(&parent)? {
            Some(parent_pom) => {
                verify_parent_coord(&parent, &parent_pom)?;
                current_pom = parent_pom;
            }
            None => {
                if resolver.strict_parent_resolution() {
                    return Err(PomError::ParentNotFound(
                        parent.group_id,
                        parent.artifact_id,
                        parent.version,
                    ));
                }

                let Some(last_child) = chain.last_mut() else {
                    return Err(PomError::InvalidModel(
                        "empty inheritance chain".to_string(),
                    ));
                };
                if can_continue_without_parent(last_child, &parent) {
                    tracing::warn!(
                        parent_group_id = %parent.group_id,
                        parent_artifact_id = %parent.artifact_id,
                        parent_version = %parent.version,
                        "Parent POM not found, continuing without inheritance."
                    );
                    if last_child.group_id.is_none() && !parent.group_id.is_empty() {
                        last_child.group_id = Some(parent.group_id.clone());
                    }
                    if last_child.version.is_none() && !parent.version.is_empty() {
                        last_child.version = Some(parent.version.clone());
                    }
                    break;
                } else {
                    return Err(PomError::ParentNotFound(
                        parent.group_id,
                        parent.artifact_id,
                        parent.version,
                    ));
                }
            }
        }
    }

    let mut effective_pom = chain.pop().ok_or_else(|| {
        PomError::InvalidModel("empty inheritance chain: no root POM".to_string())
    })?;

    while let Some(mut child_pom) = chain.pop() {
        // Move the parent's property map out instead of cloning it (#32): the
        // parent (`effective_pom`) is overwritten by `child_pom` at the end of
        // this iteration, and none of the merges below read `parent.properties`,
        // so taking it here avoids a full-map clone at every inheritance level.
        let parent_properties = std::mem::take(&mut effective_pom.properties);
        let parent = &effective_pom;

        if child_pom.group_id.is_none() {
            child_pom.group_id = parent.group_id.clone();
        }
        if child_pom.version.is_none() {
            child_pom.version = parent.version.clone();
        }

        child_pom.properties = merge_properties(parent_properties, &child_pom.properties);

        // Merge dependencies by key (groupId:artifactId:type:classifier),
        // with child entries overriding parent entries (Maven behavior).
        {
            let mut dep_map: IndexMap<DependencyMergeKey, Dependency> = IndexMap::new();
            for dep in &parent.dependencies {
                let key = dependency_merge_key(dep);
                dep_map.insert(key, dep.clone());
            }
            for dep in child_pom.dependencies {
                let key = dependency_merge_key(&dep);
                dep_map.insert(key, dep);
            }
            child_pom.dependencies = dep_map.into_values().collect();
        }

        child_pom.dependency_management = merge_dependency_management(
            parent.dependency_management.clone(),
            child_pom.dependency_management,
        );

        // Merge build: apply parent's pluginManagement versions to child plugins that
        // have no version declared. This is standard Maven plugin version inheritance.
        child_pom.build = merge_build(parent.build.as_ref(), child_pom.build);

        // Build index set with owned strings to avoid borrow conflicts.
        // Maven merges repositories by ID only (not by URL).
        let child_repo_ids: HashSet<String> = child_pom
            .repositories
            .iter()
            .filter_map(|r| r.id.clone())
            .collect();

        // Start with child repositories, then add non-overridden parent repos
        let mut repositories = child_pom.repositories;
        repositories.reserve(parent.repositories.len());
        for repo in &parent.repositories {
            let id_overridden = repo
                .id
                .as_ref()
                .is_some_and(|id| child_repo_ids.contains(id));
            if !id_overridden {
                repositories.push(repo.clone());
            }
        }
        child_pom.repositories = repositories;

        // Build index set with owned strings to avoid borrow conflicts
        let child_profile_ids: HashSet<String> =
            child_pom.profiles.iter().map(|p| p.id.clone()).collect();

        // Start with child profiles, then add non-overridden parent profiles.
        // Parent-sourced profiles get their origin level shifted by one so
        // each lineage POM keeps a distinct level (the parent's own profiles
        // were level 0 relative to the parent); Maven applies the
        // `activeByDefault` suppression rule per POM, not over the merged
        // pool, and `evaluate_profiles` groups by this level to match.
        let mut merged_profiles = child_pom.profiles;
        merged_profiles.reserve(parent.profiles.len());
        for profile in &parent.profiles {
            if !child_profile_ids.contains(&profile.id) {
                let mut profile = profile.clone();
                profile.origin_level += 1;
                merged_profiles.push(profile);
            }
        }
        child_pom.profiles = merged_profiles;

        effective_pom = child_pom;
    }

    Ok(effective_pom)
}

/// Reject a fetched parent POM whose coordinates don't match what was
/// requested, blocking hostile or misrouted parent payloads. Falls back to the
/// POM's own `<parent>` for groupId/version it inherits but doesn't declare.
fn verify_parent_coord(requested: &Parent, fetched: &Pom) -> Result<(), PomError> {
    verify_pom_coord(
        &requested.group_id,
        &requested.artifact_id,
        &requested.version,
        fetched,
    )
}

/// Verifies that a fetched POM advertises the requested `(group, artifact, version)`
/// coordinates. Used both for parent POMs and for BOM `<scope>import</scope>` POMs
/// so a hostile or misrouted payload cannot impersonate a different artifact.
///
/// Maven permits a POM to omit `<groupId>` and `<version>` when those fields are
/// inherited from its own `<parent>` declaration; the helper falls back to that
/// inner declaration when those fields are missing from the served POM.
pub fn verify_pom_coord(
    requested_group: &str,
    requested_artifact: &str,
    requested_version: &str,
    fetched: &Pom,
) -> Result<(), PomError> {
    let actual_group = fetched
        .group_id
        .clone()
        .or_else(|| fetched.parent.as_ref().map(|p| p.group_id.clone()))
        .unwrap_or_default();
    let actual_artifact = fetched.artifact_id.clone().unwrap_or_default();
    let actual_version = fetched
        .version
        .clone()
        .or_else(|| fetched.parent.as_ref().map(|p| p.version.clone()))
        .unwrap_or_default();

    if actual_group != requested_group
        || actual_artifact != requested_artifact
        || actual_version != requested_version
    {
        return Err(PomError::ParentCoordMismatch(Box::new(
            ParentCoordMismatch {
                expected_group: requested_group.to_string(),
                expected_artifact: requested_artifact.to_string(),
                expected_version: requested_version.to_string(),
                actual_group,
                actual_artifact,
                actual_version,
            },
        )));
    }

    Ok(())
}

fn can_continue_without_parent(pom: &Pom, parent: &Parent) -> bool {
    let has_group_id = pom.group_id.is_some() || !parent.group_id.is_empty();
    let has_version = pom.version.is_some() || !parent.version.is_empty();

    if !has_group_id || !has_version {
        return false;
    }

    let has_versionless_deps = pom.dependencies.iter().any(|dep| dep.version.is_none());
    if has_versionless_deps && pom.dependency_management.is_none() {
        tracing::debug!(
            "POM has dependencies without versions and no dependency management; \
             these may fail later if parent was supposed to provide versions"
        );
    }

    true
}

fn merge_properties(mut parent: PropertyMap, child: &PropertyMap) -> PropertyMap {
    // Maven semantics: a child-declared property (even with an empty value)
    // overrides the parent. Absence means "inherit"; an explicit empty
    // declaration means "reset". `child.iter()` (via `extend`) only yields keys
    // actually declared in the child's `<properties>` block, so we copy every
    // entry as-is rather than treating empty values as "missing".
    //
    // The parent map is taken by value and reused as the merge accumulator,
    // avoiding a full clone of the parent property map at each inheritance
    // level (#32).
    parent.extend(child);
    parent
}

// Owned key type for dependency merge deduplication (groupId, artifactId, type, classifier)
type DependencyMergeKey = (String, String, String, Option<String>);

fn dependency_merge_key(dep: &Dependency) -> DependencyMergeKey {
    (
        dep.group_id.clone(),
        dep.artifact_id.clone(),
        dep.effective_type().to_string(),
        dep.effective_classifier().map(str::to_string),
    )
}

// Owned key type for dependency management deduplication
type DependencyManagementKey = (String, String, String, Option<String>);

fn dependency_management_key(dep: &Dependency) -> DependencyManagementKey {
    // Use effective_classifier() so test-jar type implies "tests" classifier in the key.
    (
        dep.group_id.clone(),
        dep.artifact_id.clone(),
        dep.effective_type().to_string(),
        dep.effective_classifier().map(str::to_string),
    )
}

fn merge_dependency_management(
    parent: Option<DependencyManagement>,
    child: Option<DependencyManagement>,
) -> Option<DependencyManagement> {
    match (parent, child) {
        (None, None) => None,
        (Some(parent), None) => Some(parent),
        (None, Some(child)) => Some(child),
        (Some(parent), Some(child)) => {
            // Use IndexMap to preserve insertion order and deduplicate by key
            let mut merged_map: IndexMap<DependencyManagementKey, Dependency> = IndexMap::new();

            // Insert parent dependencies first
            for dep in parent.dependencies {
                let key = dependency_management_key(&dep);
                merged_map.insert(key, dep);
            }

            // Insert child dependencies (overriding parent where keys match)
            for dep in child.dependencies {
                let key = dependency_management_key(&dep);
                merged_map.insert(key, dep);
            }

            // WHY: build the result with an explicit field list instead of
            // reusing `parent` as a mutable carrier. If a future
            // `DependencyManagement` field shows up only on `child`, the
            // mut-and-return pattern would silently drop it; this layout
            // forces the compiler to flag the missing field.
            Some(DependencyManagement {
                dependencies: merged_map.into_values().collect(),
            })
        }
    }
}

/// Merge parent build into child, filling versionless child plugins from
/// parent's `<pluginManagement>` (Maven's plugin inheritance rule).
///
/// NOTE (#22): the merged `<build>` is stored on the effective [`Pom`] but is
/// intentionally NOT propagated into the effective [`crate::Project`] model.
/// Raeva does not execute builds, so plugins/resources have no v1 consumer.
/// The merge stays in place to model plugin-version inheritance faithfully,
/// and because the `build` field is `pub(crate)` state a later effective-model
/// consumer may surface. See the `Pom::build` docs.
fn merge_build(parent: Option<&Build>, child: Option<Build>) -> Option<Build> {
    // Collect parent's pluginManagement plugins into a lookup vec.
    let parent_pm: Vec<&Plugin> = parent
        .and_then(|b| b.plugin_management.as_ref())
        .map(|pm| pm.plugins.iter().collect())
        .unwrap_or_default();

    match child {
        None => {
            // If child has no build section, inherit parent's build (including pluginManagement)
            // so grandchild plugins can still find managed versions.
            parent.cloned()
        }
        Some(mut child_build) => {
            // Backfill missing versions in child plugins from parent pluginManagement.
            for plugin in &mut child_build.plugins {
                if plugin.version.is_some() {
                    continue;
                }
                let managed_version = parent_pm
                    .iter()
                    .find(|pm_plugin| {
                        pm_plugin.artifact_id == plugin.artifact_id
                            && pm_plugin.group_id == plugin.group_id
                    })
                    .and_then(|pm_plugin| pm_plugin.version.as_deref());
                if let Some(version) = managed_version {
                    plugin.version = Some(version.to_string());
                }
            }

            // Merge parent pluginManagement into child: child entries override parent by
            // (groupId, artifactId) key, parent entries fill in any gaps.
            if let Some(parent_pm_section) = parent.and_then(|b| b.plugin_management.as_ref()) {
                let child_pm = child_build
                    .plugin_management
                    .get_or_insert_with(PluginManagement::default);
                let child_pm_keys: HashSet<(Option<String>, String)> = child_pm
                    .plugins
                    .iter()
                    .map(|p| (p.group_id.clone(), p.artifact_id.clone()))
                    .collect();
                for parent_plugin in &parent_pm_section.plugins {
                    let key = (
                        parent_plugin.group_id.clone(),
                        parent_plugin.artifact_id.clone(),
                    );
                    if !child_pm_keys.contains(&key) {
                        child_pm.plugins.push(parent_plugin.clone());
                    }
                }
                if child_pm.plugins.is_empty() {
                    child_build.plugin_management = None;
                }
            }

            Some(child_build)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::Dependency;
    use crate::pom::Pom;
    use crate::repository::Repository;

    struct TestResolver {
        parent: Pom,
    }

    impl ParentResolver for TestResolver {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            Ok(Some(self.parent.clone()))
        }
    }

    #[test]
    fn merge_properties_empty_child_value_resets_parent() {
        let mut parent = PropertyMap::new();
        parent.insert("scala.version", "2.13.12");

        let mut child = PropertyMap::new();
        child.insert("scala.version", "");

        let merged = merge_properties(parent, &child);
        // Per Maven semantics, a child-declared empty value is a deliberate
        // reset, not an inheritance signal. The parent's value must be
        // overridden with the empty string. Inheritance only happens when the
        // key is absent from the child entirely (see
        // `merge_properties_inherits_when_child_missing_key`).
        assert_eq!(merged.get("scala.version").map(String::as_str), Some(""));
    }

    #[test]
    fn merge_properties_inherits_when_child_missing_key() {
        let mut parent = PropertyMap::new();
        parent.insert("project.build.sourceEncoding", "UTF-8");
        parent.insert("java.version", "17");

        let mut child = PropertyMap::new();
        child.insert("java.version", "21");

        let merged = merge_properties(parent, &child);
        // Key not declared in child inherits unchanged from parent.
        assert_eq!(
            merged
                .get("project.build.sourceEncoding")
                .map(String::as_str),
            Some("UTF-8")
        );
        // Non-empty child value overrides parent (sanity).
        assert_eq!(merged.get("java.version").map(String::as_str), Some("21"));
    }

    #[test]
    fn merges_parent_fields() {
        let mut parent = Pom::default();
        parent.group_id = Some("com.base".to_string());
        parent.artifact_id = Some("parent".to_string());
        parent.version = Some("1.0.0".to_string());
        parent.properties.insert("k", "v");
        parent.dependencies.push(Dependency {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: Some("1".to_string()),
            type_: None,
            classifier: None,
            scope: None,
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        });

        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: "com.base".to_string(),
            artifact_id: "parent".to_string(),
            version: "1.0.0".to_string(),
            relative_path: None,
        });
        child.artifact_id = Some("child".to_string());
        child.properties.insert("child", "yes");

        let resolver = TestResolver { parent };
        let effective = apply_inheritance(child, &resolver).unwrap();

        assert_eq!(effective.group_id.as_deref(), Some("com.base"));
        assert_eq!(effective.version.as_deref(), Some("1.0.0"));
        assert_eq!(effective.properties.get("k").map(String::as_str), Some("v"));
        assert_eq!(
            effective.properties.get("child").map(String::as_str),
            Some("yes")
        );
        assert_eq!(effective.dependencies.len(), 1);
    }

    fn repo(id: Option<&str>, url: &str) -> Repository {
        Repository {
            id: id.map(str::to_string),
            url: url.to_string(),
            releases_enabled: true,
            snapshots_enabled: false,
            releases_update_policy: None,
            snapshots_update_policy: None,
        }
    }

    #[test]
    fn inherits_and_dedupes_parent_repositories() {
        let mut parent = Pom::default();
        parent.group_id = Some("com.base".to_string());
        parent.artifact_id = Some("parent".to_string());
        parent.version = Some("1.0.0".to_string());
        parent.repositories = vec![
            repo(Some("central"), "https://repo.maven.apache.org/maven2"),
            repo(Some("snapshots"), "https://snapshots.example/"),
        ];

        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: "com.base".to_string(),
            artifact_id: "parent".to_string(),
            version: "1.0.0".to_string(),
            relative_path: None,
        });
        child.repositories = vec![
            repo(Some("central"), "https://repo.maven.apache.org/maven2"),
            repo(Some("child"), "https://child.example/"),
        ];

        let resolver = TestResolver { parent };
        let effective = apply_inheritance(child, &resolver).unwrap();

        assert_eq!(effective.repositories.len(), 3);
        assert!(
            effective
                .repositories
                .iter()
                .any(|repo| repo.url == "https://repo.maven.apache.org/maven2")
        );
        assert!(
            effective
                .repositories
                .iter()
                .any(|repo| repo.url == "https://snapshots.example/")
        );
        assert!(
            effective
                .repositories
                .iter()
                .any(|repo| repo.url == "https://child.example/")
        );
    }

    #[test]
    fn child_repositories_override_parent_by_id() {
        let mut parent = Pom::default();
        parent.group_id = Some("com.base".to_string());
        parent.artifact_id = Some("parent".to_string());
        parent.version = Some("1.0.0".to_string());
        parent.repositories = vec![repo(Some("central"), "https://parent.example/")];

        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: "com.base".to_string(),
            artifact_id: "parent".to_string(),
            version: "1.0.0".to_string(),
            relative_path: None,
        });
        child.repositories = vec![repo(Some("central"), "https://child.example/")];

        let resolver = TestResolver { parent };
        let effective = apply_inheritance(child, &resolver).unwrap();

        let central = effective
            .repositories
            .iter()
            .find(|repo| repo.id.as_deref() == Some("central"))
            .unwrap();
        assert_eq!(central.url, "https://child.example/");
        assert_eq!(
            effective
                .repositories
                .iter()
                .filter(|repo| repo.id.as_deref() == Some("central"))
                .count(),
            1
        );
    }

    /// Resolver that returns None for all parents (simulates missing parent).
    struct MissingParentResolver {
        strict: bool,
    }

    impl ParentResolver for MissingParentResolver {
        fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
            Ok(None)
        }

        fn strict_parent_resolution(&self) -> bool {
            self.strict
        }
    }

    #[test]
    fn missing_parent_fails_in_strict_mode() {
        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: "org.sonatype.oss".to_string(),
            artifact_id: "oss-parent".to_string(),
            version: "9".to_string(),
            relative_path: Some(String::new()), // empty relative path skips local lookup
        });
        child.group_id = Some("io.netty".to_string());
        child.artifact_id = Some("netty-parent".to_string());
        child.version = Some("4.1.0".to_string());

        let resolver = MissingParentResolver { strict: true };
        let err =
            apply_inheritance(child, &resolver).expect_err("strict mode rejects missing parent");
        match err {
            PomError::ParentNotFound(g, a, v) => {
                assert_eq!(g, "org.sonatype.oss");
                assert_eq!(a, "oss-parent");
                assert_eq!(v, "9");
            }
            _ => panic!("Expected ParentNotFound error, got: {:?}", err),
        }
    }

    #[test]
    fn missing_parent_continues_gracefully_in_non_strict_mode() {
        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: "org.sonatype.oss".to_string(),
            artifact_id: "oss-parent".to_string(),
            version: "9".to_string(),
            relative_path: Some(String::new()), // empty relative path skips local lookup
        });
        // Child has all required fields - can continue without parent
        child.group_id = Some("io.netty".to_string());
        child.artifact_id = Some("netty-parent".to_string());
        child.version = Some("4.1.0".to_string());

        let resolver = MissingParentResolver { strict: false };
        let effective =
            apply_inheritance(child, &resolver).expect("non-strict allows missing parent");
        assert_eq!(effective.group_id.as_deref(), Some("io.netty"));
        assert_eq!(effective.artifact_id.as_deref(), Some("netty-parent"));
        assert_eq!(effective.version.as_deref(), Some("4.1.0"));
    }

    #[test]
    fn missing_parent_uses_parent_declaration_for_missing_fields() {
        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: "org.sonatype.oss".to_string(),
            artifact_id: "oss-parent".to_string(),
            version: "9".to_string(),
            relative_path: Some(String::new()),
        });
        // Child inherits groupId and version from parent declaration
        child.artifact_id = Some("child-artifact".to_string());
        // No groupId or version - should use parent declaration values

        let resolver = MissingParentResolver { strict: false };
        let effective = apply_inheritance(child, &resolver).expect("non-strict uses parent decl");
        // Uses values from parent declaration since parent POM wasn't found.
        assert_eq!(effective.group_id.as_deref(), Some("org.sonatype.oss"));
        assert_eq!(effective.artifact_id.as_deref(), Some("child-artifact"));
        assert_eq!(effective.version.as_deref(), Some("9"));
    }

    #[test]
    fn missing_parent_still_fails_if_child_cannot_stand_alone() {
        // Create a resolver that claims to be non-strict but the parent check still fails
        // because the child POM is malformed (no groupId source)
        struct BrokenResolver;

        impl ParentResolver for BrokenResolver {
            fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
                Ok(None)
            }

            fn strict_parent_resolution(&self) -> bool {
                false
            }
        }

        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: String::new(), // Empty - cannot provide groupId fallback
            artifact_id: "oss-parent".to_string(),
            version: "9".to_string(),
            relative_path: Some(String::new()),
        });
        child.artifact_id = Some("child".to_string());
        // No groupId in child and empty in parent declaration - should fail

        let resolver = BrokenResolver;
        let err = apply_inheritance(child, &resolver).expect_err("child cannot stand alone");
        assert!(
            matches!(&err, PomError::ParentNotFound(g, _, _) if g.is_empty()),
            "got {err:?}"
        );
    }

    #[test]
    fn can_continue_without_parent_returns_true_for_complete_pom() {
        let mut pom = Pom::default();
        pom.group_id = Some("com.example".to_string());
        pom.artifact_id = Some("app".to_string());
        pom.version = Some("1.0.0".to_string());

        let parent = Parent {
            group_id: "org.sonatype.oss".to_string(),
            artifact_id: "oss-parent".to_string(),
            version: "9".to_string(),
            relative_path: None,
        };

        assert!(can_continue_without_parent(&pom, &parent));
    }

    #[test]
    fn can_continue_without_parent_returns_true_when_parent_provides_fields() {
        let mut pom = Pom::default();
        // No groupId or version in POM
        pom.artifact_id = Some("app".to_string());

        let parent = Parent {
            group_id: "org.sonatype.oss".to_string(),
            artifact_id: "oss-parent".to_string(),
            version: "9".to_string(),
            relative_path: None,
        };

        // Should be OK because parent declaration provides groupId and version
        assert!(can_continue_without_parent(&pom, &parent));
    }

    #[test]
    fn can_continue_without_parent_returns_false_for_empty_parent_group_id() {
        let mut pom = Pom::default();
        // No groupId in POM
        pom.artifact_id = Some("app".to_string());
        pom.version = Some("1.0.0".to_string());

        let parent = Parent {
            group_id: String::new(), // Empty - cannot be fallback
            artifact_id: "oss-parent".to_string(),
            version: "9".to_string(),
            relative_path: None,
        };

        // Should fail because neither POM nor parent declaration provides groupId
        assert!(!can_continue_without_parent(&pom, &parent));
    }

    #[test]
    fn merge_dependency_management_preserves_different_classifiers() {
        // Entries that share a groupId:artifactId but differ in type/classifier
        // must stay distinct, not collapse into one.
        let parent_deps = vec![
            Dependency {
                group_id: "org.example".to_string(),
                artifact_id: "lib".to_string(),
                version: Some("1.0".to_string()),
                type_: None, // jar
                classifier: None,
                scope: None,
                optional: None,
                exclusions: vec![],
                system_path: None,
            },
            Dependency {
                group_id: "org.example".to_string(),
                artifact_id: "lib".to_string(),
                version: Some("1.0".to_string()),
                type_: Some("test-jar".to_string()),
                classifier: Some("tests".to_string()),
                scope: None,
                optional: None,
                exclusions: vec![],
                system_path: None,
            },
        ];
        let parent = DependencyManagement {
            dependencies: parent_deps,
        };

        // Merge with empty child
        let result = merge_dependency_management(Some(parent), None);
        assert!(result.is_some());
        let merged = result.unwrap();

        // Both entries should be preserved since they have different type/classifier
        assert_eq!(
            merged.dependencies.len(),
            2,
            "Expected 2 entries for same groupId:artifactId with different type/classifier"
        );

        // Check that we have both the jar and test-jar entries
        let has_jar = merged
            .dependencies
            .iter()
            .any(|d| d.artifact_id == "lib" && d.classifier.is_none());
        let has_test_jar = merged
            .dependencies
            .iter()
            .any(|d| d.artifact_id == "lib" && d.classifier.as_deref() == Some("tests"));

        assert!(has_jar, "Expected jar entry to be preserved");
        assert!(has_test_jar, "Expected test-jar entry to be preserved");
    }

    /// Regression test: an attacker-controlled remote endpoint returning a
    /// parent POM whose declared coordinates differ from what the child requested
    /// must be rejected, not silently accepted as the parent.
    #[test]
    fn mismatched_parent_coord_is_rejected() {
        struct MismatchedResolver {
            response: Pom,
        }

        impl ParentResolver for MismatchedResolver {
            fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
                Ok(Some(self.response.clone()))
            }
        }

        // Resolver pretends to return a parent for com.base:parent:1.0.0 but the
        // payload actually declares an entirely different coordinate.
        let mut malicious_parent = Pom::default();
        malicious_parent.group_id = Some("evil.attacker".to_string());
        malicious_parent.artifact_id = Some("backdoor".to_string());
        malicious_parent.version = Some("0.0.1".to_string());

        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: "com.base".to_string(),
            artifact_id: "parent".to_string(),
            version: "1.0.0".to_string(),
            relative_path: None,
        });
        child.artifact_id = Some("child".to_string());

        let resolver = MismatchedResolver {
            response: malicious_parent,
        };
        let result = apply_inheritance(child, &resolver);

        match result {
            Err(PomError::ParentCoordMismatch(mismatch)) => {
                assert_eq!(mismatch.expected_group, "com.base");
                assert_eq!(mismatch.expected_artifact, "parent");
                assert_eq!(mismatch.expected_version, "1.0.0");
                assert_eq!(mismatch.actual_group, "evil.attacker");
                assert_eq!(mismatch.actual_artifact, "backdoor");
                assert_eq!(mismatch.actual_version, "0.0.1");
            }
            other => panic!("Expected ParentCoordMismatch error, got: {:?}", other),
        }
    }

    /// A parent POM that inherits its own groupId/version from a grandparent
    /// declaration is still considered a coordinate match.
    #[test]
    fn parent_inheriting_from_grandparent_is_accepted() {
        use std::cell::Cell;

        struct InheritingResolver {
            parent: Pom,
            grandparent: Pom,
            calls: Cell<u32>,
        }

        impl ParentResolver for InheritingResolver {
            fn resolve_parent(&self, parent: &Parent) -> Result<Option<Pom>, PomError> {
                self.calls.set(self.calls.get() + 1);
                if parent.artifact_id == "parent" {
                    Ok(Some(self.parent.clone()))
                } else if parent.artifact_id == "grandparent" {
                    Ok(Some(self.grandparent.clone()))
                } else {
                    Ok(None)
                }
            }
        }

        // Parent POM omits its own group_id/version, instead pointing at a
        // grandparent that supplies them.
        let mut parent_pom = Pom::default();
        parent_pom.artifact_id = Some("parent".to_string());
        parent_pom.parent = Some(Parent {
            group_id: "com.base".to_string(),
            artifact_id: "grandparent".to_string(),
            version: "1.0.0".to_string(),
            relative_path: Some(String::new()),
        });

        let mut grandparent_pom = Pom::default();
        grandparent_pom.group_id = Some("com.base".to_string());
        grandparent_pom.artifact_id = Some("grandparent".to_string());
        grandparent_pom.version = Some("1.0.0".to_string());

        let mut child = Pom::default();
        child.parent = Some(Parent {
            group_id: "com.base".to_string(),
            artifact_id: "parent".to_string(),
            version: "1.0.0".to_string(),
            relative_path: None,
        });
        child.artifact_id = Some("child".to_string());

        let resolver = InheritingResolver {
            parent: parent_pom,
            grandparent: grandparent_pom,
            calls: Cell::new(0),
        };
        let result = apply_inheritance(child, &resolver);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }
}
