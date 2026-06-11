//! BOM (`import` scope) resolution with fixed-point property propagation.

use crate::dependency::{Dependency, DependencyManagement};
use crate::inheritance::{ParentResolver, apply_inheritance, verify_pom_coord};
use crate::properties::{ProjectInfo, PropertyMap};
use crate::{ActivationContext, PomError};
use indexmap::IndexSet;

use super::dep_management::{
    normalize_classifier, resolve_dependency, resolve_dependency_management,
};
use super::project_info_from_pom;

#[derive(Debug, Clone)]
pub(super) struct BomImportResult {
    pub(super) management: DependencyManagement,
    pub(super) properties: PropertyMap,
}

type BomImportKey = (String, String, String, String, Option<String>);

/// Cap on BOM import nesting depth. Cycle detection catches repeated
/// coordinates but not a DAG of N distinct BOMs; without a depth cap an
/// adversarial chain of unique BOMs would recurse until OS stack exhaustion.
const MAX_BOM_DEPTH: usize = 50;

#[derive(Debug, Clone)]
struct PendingBomImport {
    order: usize,
    dependency: Dependency,
}

#[derive(Debug, Clone)]
struct ResolvedBomImport {
    order: usize,
    management_dependencies: Vec<Dependency>,
    properties: PropertyMap,
}

fn build_imported_properties(resolved_imports: &[ResolvedBomImport]) -> PropertyMap {
    let mut ordered = resolved_imports.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|import| import.order);

    let mut imported = PropertyMap::new();
    for import in ordered {
        for (key, value) in import.properties.iter() {
            if imported.get(key).is_none() {
                imported.insert(key.clone(), value.clone());
            }
        }
    }

    imported
}

pub(super) fn resolve_bom_imports(
    management: DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
    resolver: &impl ParentResolver,
) -> Result<BomImportResult, PomError> {
    if !management
        .dependencies
        .iter()
        .any(|dep| dep.is_import_scope())
    {
        return Ok(BomImportResult {
            management: resolve_dependency_management(management, properties, project)?,
            properties: PropertyMap::new(),
        });
    }

    let mut stack: IndexSet<BomImportKey> = IndexSet::new();
    resolve_bom_imports_inner(
        management, properties, project, resolver, &mut stack, false, 0,
    )
}

fn resolve_bom_imports_inner(
    management: DependencyManagement,
    properties: &PropertyMap,
    project: &ProjectInfo,
    resolver: &impl ParentResolver,
    stack: &mut IndexSet<BomImportKey>,
    include_current: bool,
    depth: usize,
) -> Result<BomImportResult, PomError> {
    if depth >= MAX_BOM_DEPTH {
        return Err(PomError::InvalidModel(format!(
            "BOM nesting too deep (limit {MAX_BOM_DEPTH})"
        )));
    }
    let mut pending_imports = Vec::new();
    let mut locals = Vec::new();
    for (order, dep) in management.dependencies.into_iter().enumerate() {
        if dep.is_import_scope() {
            pending_imports.push(PendingBomImport {
                order,
                dependency: dep,
            });
        } else {
            locals.push(dep);
        }
    }

    let mut resolved_imports: Vec<ResolvedBomImport> = Vec::new();
    let mut unresolved_imports = Vec::new();

    // Maven resolves each import coordinate from the importer's OWN effective
    // properties (its parent chain plus its own `<properties>`), never from
    // properties contributed by a *sibling* imported BOM. We therefore resolve
    // every pending import coordinate against `properties` only. The internal
    // dependencies of each imported BOM are still interpolated with that BOM's
    // own properties below (see `bom_all_properties`). Because the coordinate
    // property set is fixed, a single pass is sufficient: an import whose
    // version still references `${...}` after interpolation cannot become
    // resolvable by processing other imports, so it is reported as unresolved.
    for pending in pending_imports {
        let mut dep = resolve_dependency(pending.dependency.clone(), properties, project)?;
        if dep
            .type_
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            dep.type_ = Some("pom".to_string());
        }
        if dep.effective_type() != "pom" {
            return Err(PomError::InvalidModel(format!(
                "import scope requires type=pom for {}:{}",
                dep.group_id, dep.artifact_id
            )));
        }

        let version = dep.version.as_ref().ok_or_else(|| {
            PomError::InvalidModel(format!(
                "import scope requires a version for {}:{}",
                dep.group_id, dep.artifact_id
            ))
        })?;

        if version.contains("${") {
            tracing::warn!(
                group_id = %dep.group_id,
                artifact_id = %dep.artifact_id,
                raw_version = %pending
                    .dependency
                    .version
                    .as_deref()
                    .unwrap_or("<none>"),
                interpolated_version = %version,
                "BOM import version property does not resolve from the importer's \
                 own properties; sibling BOMs cannot supply it"
            );
            unresolved_imports.push(pending);
            continue;
        }

        let type_ = dep.type_.as_deref().unwrap_or("pom");
        let classifier = normalize_classifier(&dep.classifier);
        let key = (
            dep.group_id.clone(),
            dep.artifact_id.clone(),
            version.clone(),
            type_.to_string(),
            classifier.map(str::to_string),
        );
        if stack.contains(&key) {
            return Err(PomError::InvalidModel(format!(
                "BOM import cycle detected for {}:{}:{}:{}{}",
                dep.group_id,
                dep.artifact_id,
                version,
                type_,
                classifier
                    .map(|value| format!(":{value}"))
                    .unwrap_or_default()
            )));
        }

        stack.insert(key.clone());
        let bom_pom_result = resolver.resolve_import_pom(
            &dep.group_id,
            &dep.artifact_id,
            version,
            dep.type_.as_deref(),
            dep.classifier.as_deref(),
        )?;

        match bom_pom_result {
            Some(bom_pom) => {
                // Verify the served BOM POM advertises the coordinates we requested.
                // Without this check, a hostile remote could swap in a payload with
                // unrelated dependencyManagement entries that would silently land in
                // the importing project's resolved version table.
                verify_pom_coord(&dep.group_id, &dep.artifact_id, version, &bom_pom)?;
                tracing::debug!(
                    group_id = %dep.group_id,
                    artifact_id = %dep.artifact_id,
                    version = %version,
                    "resolved BOM import"
                );
                let bom_effective = apply_inheritance(bom_pom, resolver)?;
                let bom_ctx = ActivationContext::default();
                let bom_info = project_info_from_pom(&bom_effective, &bom_ctx)?;
                let bom_result = resolve_bom_imports_inner(
                    bom_effective.dependency_management.unwrap_or_default(),
                    &bom_effective.properties,
                    &bom_info,
                    resolver,
                    stack,
                    true,
                    depth + 1,
                )?;

                // Pre-interpolate managed dependency versions using the BOM's
                // own effective properties (including parent-chain properties).
                // Without this, property references like ${lib.version} defined
                // in a BOM's parent POM would remain unresolved when returned
                // to the importing project, which doesn't have those properties.
                let bom_all_properties = bom_result.properties.merge_ref(&bom_effective.properties);
                let managed_deps = bom_result
                    .management
                    .dependencies
                    .into_iter()
                    .map(|dep| resolve_dependency(dep, &bom_all_properties, &bom_info))
                    .collect::<Result<Vec<_>, _>>()?;

                resolved_imports.push(ResolvedBomImport {
                    order: pending.order,
                    management_dependencies: managed_deps,
                    properties: bom_result.properties,
                });
            }
            None => {
                if resolver.strict_bom_resolution() {
                    return Err(PomError::InvalidModel(format!(
                        "BOM not found: {}:{}:{}",
                        dep.group_id, dep.artifact_id, version
                    )));
                }
                tracing::debug!(
                    group_id = %dep.group_id,
                    artifact_id = %dep.artifact_id,
                    version = %version,
                    "BOM import not found, skipping (non-strict mode)"
                );
            }
        }
        // Remove this iteration's guard precisely by key. `IndexSet::pop`
        // removes the most recently inserted entry, which is wrong when
        // recursive BOM resolution above also pushed and popped entries:
        // the topmost entry at this point may not be ours. `shift_remove`
        // targets the exact key we inserted, so the guard works under
        // nested recursion.
        stack.shift_remove(&key);
    }

    for pending in &unresolved_imports {
        let dep = resolve_dependency(pending.dependency.clone(), properties, project)?;
        let raw_version = pending.dependency.version.as_deref().unwrap_or("<none>");
        let version = dep.version.as_ref().ok_or_else(|| {
            PomError::InvalidModel(format!(
                "import scope requires a version for {}:{}",
                dep.group_id, dep.artifact_id
            ))
        })?;
        tracing::warn!(
            group_id = %dep.group_id,
            artifact_id = %dep.artifact_id,
            raw_version = %raw_version,
            interpolated_version = %version,
            "BOM import has unresolved version property"
        );
        if resolver.strict_bom_resolution() {
            return Err(PomError::InvalidModel(format!(
                "BOM import {}:{}:{} has unresolved version (raw: {})",
                dep.group_id, dep.artifact_id, version, raw_version
            )));
        }
    }

    // Preserve declaration order for imported BOM state regardless of which
    // order each import resolved in.
    resolved_imports.sort_by_key(|import| import.order);

    // Properties contributed upward to the importer. For a nested BOM
    // (`include_current`) this is the BOM's own effective properties plus the
    // properties of the BOMs it imported, so the importer can interpolate this
    // BOM's managed dependencies. It is NOT consulted when resolving sibling
    // import coordinates at this level.
    let mut imported_properties = build_imported_properties(&resolved_imports);
    if include_current {
        imported_properties.extend(properties);
    }

    let mut dependencies = Vec::new();

    // Locals come first so they take precedence over BOM imports in the
    // "first wins" index built by `build_managed_dep_index`. Within BOMs,
    // earlier-declared BOMs take precedence over later ones. Locals are this
    // level's own managed dependencies, so they interpolate against this
    // level's own effective properties.
    for dep in locals {
        dependencies.push(resolve_dependency(dep, properties, project)?);
    }

    for import in resolved_imports {
        dependencies.extend(import.management_dependencies);
    }

    Ok(BomImportResult {
        management: DependencyManagement { dependencies },
        properties: imported_properties,
    })
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::dependency::Dependency;
    use crate::inheritance::ParentResolver;
    use crate::pom::{Parent, Pom};

    /// Regression test for the BOM analog of the parent-coord-mismatch attack:
    /// a malicious remote returns a BOM POM whose declared coordinates do not
    /// match what the importing project requested. Resolution must reject the
    /// payload rather than fold its dependencyManagement entries into the
    /// effective model.
    #[test]
    fn mismatched_bom_coord_is_rejected() {
        struct MismatchedBomResolver {
            response: Pom,
        }

        impl ParentResolver for MismatchedBomResolver {
            fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
                Ok(None)
            }

            fn resolve_import_pom(
                &self,
                _group_id: &str,
                _artifact_id: &str,
                _version: &str,
                _type_: Option<&str>,
                _classifier: Option<&str>,
            ) -> Result<Option<Pom>, PomError> {
                Ok(Some(self.response.clone()))
            }
        }

        // Resolver claims to serve com.example:platform:1.0.0 but the served
        // POM actually advertises evil.attacker:backdoor:0.0.1.
        let mut malicious_bom = Pom::default();
        malicious_bom.group_id = Some("evil.attacker".to_string());
        malicious_bom.artifact_id = Some("backdoor".to_string());
        malicious_bom.version = Some("0.0.1".to_string());

        let mut management = DependencyManagement::default();
        management.dependencies.push(Dependency {
            group_id: "com.example".to_string(),
            artifact_id: "platform".to_string(),
            version: Some("1.0.0".to_string()),
            type_: Some("pom".to_string()),
            classifier: None,
            scope: Some("import".to_string()),
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        });

        let properties = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "com.importer".to_string(),
            artifact_id: "consumer".to_string(),
            version: "0.1.0".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let resolver = MismatchedBomResolver {
            response: malicious_bom,
        };
        let result = resolve_bom_imports(management, &properties, &project, &resolver);

        match result {
            Err(PomError::ParentCoordMismatch(mismatch)) => {
                assert_eq!(mismatch.expected_group, "com.example");
                assert_eq!(mismatch.expected_artifact, "platform");
                assert_eq!(mismatch.expected_version, "1.0.0");
                assert_eq!(mismatch.actual_group, "evil.attacker");
                assert_eq!(mismatch.actual_artifact, "backdoor");
                assert_eq!(mismatch.actual_version, "0.0.1");
            }
            other => panic!("expected ParentCoordMismatch error, got: {:?}", other),
        }
    }

    /// A DAG of N distinct BOMs (no repeated coordinates) must not be able to
    /// blow the OS stack. Cycle detection alone is not enough; we need a
    /// hard depth cap matching the parent-inheritance pattern.
    #[test]
    fn deep_bom_chain_is_rejected() {
        struct DeepChainResolver {
            chain_len: usize,
        }

        impl ParentResolver for DeepChainResolver {
            fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
                Ok(None)
            }

            fn resolve_import_pom(
                &self,
                _group_id: &str,
                artifact_id: &str,
                _version: &str,
                _type_: Option<&str>,
                _classifier: Option<&str>,
            ) -> Result<Option<Pom>, PomError> {
                let idx: usize = artifact_id
                    .strip_prefix("bom")
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                let mut pom = Pom::default();
                pom.group_id = Some("com.example".to_string());
                pom.artifact_id = Some(format!("bom{idx}"));
                pom.version = Some("1.0.0".to_string());
                if idx + 1 < self.chain_len {
                    let mut next_management = DependencyManagement::default();
                    next_management.dependencies.push(Dependency {
                        group_id: "com.example".to_string(),
                        artifact_id: format!("bom{}", idx + 1),
                        version: Some("1.0.0".to_string()),
                        type_: Some("pom".to_string()),
                        classifier: None,
                        scope: Some("import".to_string()),
                        optional: None,
                        exclusions: Vec::new(),
                        system_path: None,
                    });
                    pom.dependency_management = Some(next_management);
                }
                Ok(Some(pom))
            }
        }

        let mut management = DependencyManagement::default();
        management.dependencies.push(Dependency {
            group_id: "com.example".to_string(),
            artifact_id: "bom0".to_string(),
            version: Some("1.0.0".to_string()),
            type_: Some("pom".to_string()),
            classifier: None,
            scope: Some("import".to_string()),
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        });

        let properties = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "com.importer".to_string(),
            artifact_id: "consumer".to_string(),
            version: "0.1.0".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let resolver = DeepChainResolver { chain_len: 60 };
        let result = resolve_bom_imports(management, &properties, &project, &resolver);

        match result {
            Err(PomError::InvalidModel(msg)) => {
                assert!(
                    msg.contains("BOM nesting too deep"),
                    "expected depth-cap error, got: {msg}"
                );
            }
            other => panic!("expected depth-cap InvalidModel error, got: {:?}", other),
        }
    }

    /// Maven BOM import property precedence is "nearest wins": an earlier
    /// (lower declaration order) import contributes a property and a later
    /// import with the same key must NOT overwrite it.
    #[test]
    fn build_imported_properties_is_first_wins() {
        let mut earlier_props = PropertyMap::new();
        earlier_props.insert("shared.version", "1.0.0");
        earlier_props.insert("only.in.earlier", "alpha");

        let mut later_props = PropertyMap::new();
        later_props.insert("shared.version", "9.9.9");
        later_props.insert("only.in.later", "beta");

        let resolved = vec![
            ResolvedBomImport {
                order: 0,
                management_dependencies: Vec::new(),
                properties: earlier_props,
            },
            ResolvedBomImport {
                order: 1,
                management_dependencies: Vec::new(),
                properties: later_props,
            },
        ];

        let merged = build_imported_properties(&resolved);
        assert_eq!(
            merged.get("shared.version").map(String::as_str),
            Some("1.0.0")
        );
        assert_eq!(
            merged.get("only.in.earlier").map(String::as_str),
            Some("alpha")
        );
        assert_eq!(
            merged.get("only.in.later").map(String::as_str),
            Some("beta")
        );
    }

    /// Maven resolves each import coordinate from the IMPORTER's own effective
    /// properties, never from properties contributed by a sibling imported BOM.
    /// Here `pinned` imports `${shared.version}` (which the importer does not
    /// define) and `provider` contributes a `shared.version` property. The
    /// version reference must NOT resolve from `provider`'s property, so the
    /// `pinned` import stays unresolved in non-strict mode and contributes no
    /// managed dependencies.
    #[test]
    fn sibling_bom_property_does_not_resolve_other_import_coordinate() {
        struct SiblingResolver {
            boms: std::collections::HashMap<String, Pom>,
        }

        impl ParentResolver for SiblingResolver {
            fn resolve_parent(&self, _parent: &Parent) -> Result<Option<Pom>, PomError> {
                Ok(None)
            }

            fn strict_bom_resolution(&self) -> bool {
                false
            }

            fn resolve_import_pom(
                &self,
                _group_id: &str,
                artifact_id: &str,
                _version: &str,
                _type_: Option<&str>,
                _classifier: Option<&str>,
            ) -> Result<Option<Pom>, PomError> {
                Ok(self.boms.get(artifact_id).cloned())
            }
        }

        // `provider` BOM contributes a `shared.version` property and a managed
        // dependency. `pinned` BOM, if ever resolved, would contribute a
        // distinct managed dependency.
        let mut provider = Pom::default();
        provider.group_id = Some("com.example".to_string());
        provider.artifact_id = Some("provider".to_string());
        provider.version = Some("1.0.0".to_string());
        provider.properties.insert("shared.version", "9.9.9");
        let mut provider_mgmt = DependencyManagement::default();
        provider_mgmt.dependencies.push(Dependency {
            group_id: "com.example".to_string(),
            artifact_id: "from-provider".to_string(),
            version: Some("3.3.3".to_string()),
            type_: None,
            classifier: None,
            scope: None,
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        });
        provider.dependency_management = Some(provider_mgmt);

        let mut pinned = Pom::default();
        pinned.group_id = Some("com.example".to_string());
        pinned.artifact_id = Some("pinned".to_string());
        pinned.version = Some("9.9.9".to_string());
        let mut pinned_mgmt = DependencyManagement::default();
        pinned_mgmt.dependencies.push(Dependency {
            group_id: "com.example".to_string(),
            artifact_id: "from-pinned".to_string(),
            version: Some("4.4.4".to_string()),
            type_: None,
            classifier: None,
            scope: None,
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        });
        pinned.dependency_management = Some(pinned_mgmt);

        let mut boms = std::collections::HashMap::new();
        boms.insert("provider".to_string(), provider);
        boms.insert("pinned".to_string(), pinned);

        // The importer declares `provider` first (its `shared.version` property
        // must not leak to a sibling import coordinate) and then `pinned` whose
        // version is `${shared.version}`.
        let mut management = DependencyManagement::default();
        management.dependencies.push(Dependency {
            group_id: "com.example".to_string(),
            artifact_id: "provider".to_string(),
            version: Some("1.0.0".to_string()),
            type_: Some("pom".to_string()),
            classifier: None,
            scope: Some("import".to_string()),
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        });
        management.dependencies.push(Dependency {
            group_id: "com.example".to_string(),
            artifact_id: "pinned".to_string(),
            version: Some("${shared.version}".to_string()),
            type_: Some("pom".to_string()),
            classifier: None,
            scope: Some("import".to_string()),
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
        });

        let properties = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "com.importer".to_string(),
            artifact_id: "consumer".to_string(),
            version: "0.1.0".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let resolver = SiblingResolver { boms };
        let result = resolve_bom_imports(management, &properties, &project, &resolver)
            .expect("non-strict resolution should not error on the unresolved import");

        // `provider`'s managed dep must be present; `pinned` must NOT be
        // imported because its `${shared.version}` coordinate cannot resolve
        // from the importer's own (empty) properties.
        assert!(
            result
                .management
                .dependencies
                .iter()
                .any(|dep| dep.artifact_id == "from-provider"),
            "provider BOM's managed dependency should be imported"
        );
        assert!(
            !result
                .management
                .dependencies
                .iter()
                .any(|dep| dep.artifact_id == "from-pinned"),
            "pinned BOM must not resolve via a sibling BOM's property"
        );
    }
}
