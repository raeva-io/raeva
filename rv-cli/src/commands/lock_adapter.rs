use std::collections::{BTreeMap, BTreeSet};

use rv_config::{LockArtifact, LockCoordinate, LockModule, LockModulePackage, LockPlatform};
use rv_sbom::{Component, Hash, HashAlgorithm};
use rv_vuln::Dependency;

#[derive(Debug, thiserror::Error)]
pub(crate) enum LockAdapterError {
    #[error(transparent)]
    Purl(#[from] rv_vuln::VulnError),
    #[error("lockfile edge out of bounds: {from} -> {to} for {packages} packages")]
    InvalidEdge {
        from: usize,
        to: usize,
        packages: usize,
    },
}

pub(crate) struct VulnerabilityDependencies {
    pub dependencies: Vec<Dependency>,
    pub reachability: BTreeMap<String, Vec<String>>,
}

pub(crate) struct SbomDependencies {
    pub root: Component,
    pub components: Vec<Component>,
}

pub(crate) fn adapt_sbom_modules(
    platform: &LockPlatform,
    modules: &[&LockModule],
    fallback_root: Component,
) -> Result<SbomDependencies, LockAdapterError> {
    let root_module = modules
        .iter()
        .copied()
        .find(|module| module.path == "pom.xml")
        .or_else(|| modules.first().copied());
    let root = root_module
        .filter(|module| !module.is_legacy_placeholder())
        .map(module_component)
        .transpose()?
        .unwrap_or(fallback_root);

    let artifact_by_coordinate = platform
        .artifacts
        .iter()
        .map(|artifact| (&artifact.coordinate, artifact))
        .collect::<BTreeMap<_, _>>();
    let module_by_path = platform
        .modules
        .iter()
        .map(|module| (module.path.as_str(), module))
        .collect::<BTreeMap<_, _>>();
    let mut components = BTreeMap::<String, Component>::new();

    for module in modules {
        let graph_module = if module.is_legacy_placeholder()
            && root_module.is_some_and(|root_module| root_module.path == module.path)
        {
            root.clone()
        } else {
            module_component(module)?
        };
        let module_purl = graph_module.purl.clone();
        insert_component(&mut components, graph_module)?;
        let package_purls = module
            .packages
            .iter()
            .map(|package| package_purl(package, &module_by_path))
            .collect::<Result<Vec<_>, _>>()?;

        for (index, package) in module.packages.iter().enumerate() {
            let component = package_component(
                package,
                &artifact_by_coordinate,
                &module_by_path,
                package_purls[index].clone(),
            )?;
            insert_component(&mut components, component)?;
        }

        for edge in &module.edges {
            if edge.from >= module.packages.len() || edge.to >= module.packages.len() {
                return Err(LockAdapterError::InvalidEdge {
                    from: edge.from,
                    to: edge.to,
                    packages: module.packages.len(),
                });
            }
            add_dependency(
                &mut components,
                &package_purls[edge.from],
                package_purls[edge.to].clone(),
            )?;
        }

        let direct = root_package_indices(module);
        for index in direct {
            add_dependency(&mut components, &module_purl, package_purls[index].clone())?;
        }
    }

    let selected_paths = modules
        .iter()
        .map(|module| module.path.as_str())
        .collect::<BTreeSet<_>>();
    let reachable_workspace_paths = modules
        .iter()
        .flat_map(|module| &module.packages)
        .filter_map(|package| package.workspace_module.as_deref())
        .collect::<BTreeSet<_>>();
    for path in reachable_workspace_paths.difference(&selected_paths) {
        if let Some(module) = module_by_path.get(path) {
            insert_component(&mut components, module_component(module)?)?;
        }
    }

    let root_graph = components.remove(&root.purl);
    for component in components.values_mut() {
        component.dependencies.sort();
        component.dependencies.dedup();
    }
    let mut root = root;
    if let Some(component) = root_graph {
        root.dependencies = component.dependencies;
    }
    root.dependencies.sort();
    root.dependencies.dedup();

    Ok(SbomDependencies {
        root,
        components: components.into_values().collect(),
    })
}

fn root_package_indices(module: &LockModule) -> Vec<usize> {
    if module
        .packages
        .iter()
        .any(|package| package.direct_scope.is_some())
    {
        return module
            .packages
            .iter()
            .enumerate()
            .filter(|(_, package)| package.direct_scope.is_some())
            .map(|(index, _)| index)
            .collect();
    }
    let mut incoming = vec![false; module.packages.len()];
    for edge in &module.edges {
        if let Some(value) = incoming.get_mut(edge.to) {
            *value = true;
        }
    }
    let roots = incoming
        .iter()
        .enumerate()
        .filter(|(_, incoming)| !**incoming)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if roots.is_empty() && !module.packages.is_empty() {
        (0..module.packages.len()).collect()
    } else {
        roots
    }
}

fn package_component(
    package: &LockModulePackage,
    artifacts: &BTreeMap<&LockCoordinate, &LockArtifact>,
    modules: &BTreeMap<&str, &LockModule>,
    purl: String,
) -> Result<Component, LockAdapterError> {
    let (name, version, group) = if let Some(path) = package.workspace_module.as_deref() {
        let module = modules.get(path).copied();
        (
            module
                .map(|module| module.gav.artifact.clone())
                .unwrap_or_else(|| package.coordinate.artifact.clone()),
            module
                .map(|module| module.gav.version.clone())
                .unwrap_or_else(|| package.coordinate.version.clone()),
            Some(
                module
                    .map(|module| module.gav.group.clone())
                    .unwrap_or_else(|| package.coordinate.group.clone()),
            ),
        )
    } else {
        (
            package.coordinate.artifact.clone(),
            package.coordinate.version.clone(),
            Some(package.coordinate.group.clone()),
        )
    };
    let hashes = if package.workspace_module.is_some() || package.system_path.is_some() {
        Vec::new()
    } else {
        artifacts
            .get(&package.coordinate)
            .and_then(|artifact| {
                artifact
                    .checksums
                    .iter()
                    .find(|checksum| checksum.algorithm == "sha256")
            })
            .map(|checksum| {
                vec![Hash {
                    algorithm: HashAlgorithm::Sha256,
                    value: checksum.digest.clone(),
                }]
            })
            .unwrap_or_default()
    };
    Ok(Component {
        name,
        version,
        group,
        purl,
        license_expression: None,
        hashes,
        dependencies: Vec::new(),
    })
}

fn module_component(module: &LockModule) -> Result<Component, LockAdapterError> {
    Ok(Component {
        name: module.gav.artifact.clone(),
        version: module.gav.version.clone(),
        group: Some(module.gav.group.clone()),
        purl: maven_purl(
            &module.gav.group,
            &module.gav.artifact,
            &module.gav.version,
            &module.packaging,
        )?,
        license_expression: None,
        hashes: Vec::new(),
        dependencies: Vec::new(),
    })
}

fn coordinate_purl(coordinate: &LockCoordinate) -> Result<String, LockAdapterError> {
    Ok(dependency_from_coordinate(coordinate).purl()?)
}

fn package_purl(
    package: &LockModulePackage,
    modules: &BTreeMap<&str, &LockModule>,
) -> Result<String, LockAdapterError> {
    if let Some(path) = package.workspace_module.as_deref()
        && let Some(module) = modules.get(path)
    {
        return Ok(module_component(module)?.purl);
    }
    coordinate_purl(&package.coordinate)
}

fn insert_component(
    components: &mut BTreeMap<String, Component>,
    component: Component,
) -> Result<(), LockAdapterError> {
    components
        .entry(component.purl.clone())
        .and_modify(|existing| {
            existing.dependencies.extend(component.dependencies.clone());
            if existing.hashes.is_empty() {
                existing.hashes.clone_from(&component.hashes);
            }
        })
        .or_insert(component);
    Ok(())
}

fn add_dependency(
    components: &mut BTreeMap<String, Component>,
    source: &str,
    target: String,
) -> Result<(), LockAdapterError> {
    let component = components.get_mut(source).ok_or_else(|| {
        LockAdapterError::Purl(rv_vuln::VulnError::InvalidPurl(format!(
            "missing SBOM component for {source}"
        )))
    })?;
    component.dependencies.push(target);
    Ok(())
}

/// Build the OSV query set from module-local graphs.
///
/// The purl-keyed map deduplicates across modules before the scanner sees the
/// dependencies. The paired module-path set records every module that can
/// reach each external. Workspace and system nodes never enter the query set.
pub(crate) fn adapt_vulnerability_modules(
    modules: &[&LockModule],
) -> Result<VulnerabilityDependencies, LockAdapterError> {
    let mut by_purl = BTreeMap::<String, (Dependency, BTreeSet<String>)>::new();
    for module in modules {
        for package in &module.packages {
            if package.workspace_module.is_some() || package.system_path.is_some() {
                continue;
            }
            let dependency = dependency_from_coordinate(&package.coordinate);
            let purl = dependency.purl()?;
            by_purl
                .entry(purl)
                .and_modify(|(_, paths)| {
                    paths.insert(module.path.clone());
                })
                .or_insert_with(|| {
                    (
                        dependency,
                        BTreeSet::from_iter(std::iter::once(module.path.clone())),
                    )
                });
        }
    }

    let mut dependencies = Vec::with_capacity(by_purl.len());
    let mut reachability = BTreeMap::new();
    for (purl, (dependency, modules)) in by_purl {
        dependencies.push(dependency);
        reachability.insert(purl, modules.into_iter().collect());
    }
    Ok(VulnerabilityDependencies {
        dependencies,
        reachability,
    })
}

pub(crate) fn dependency_from_coordinate(coordinate: &LockCoordinate) -> Dependency {
    Dependency {
        group_id: coordinate.group.clone(),
        artifact_id: coordinate.artifact.clone(),
        version: coordinate.version.clone(),
        packaging: coordinate.packaging.clone(),
        classifier: coordinate
            .classifier
            .clone()
            .filter(|value| !value.is_empty()),
    }
}

pub(crate) fn maven_purl(
    group_id: impl Into<String>,
    artifact_id: impl Into<String>,
    version: impl Into<String>,
    packaging: impl Into<String>,
) -> Result<String, LockAdapterError> {
    let mut dependency = Dependency::new(group_id, artifact_id, version);
    dependency.packaging = packaging.into();
    Ok(dependency.purl()?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rv_config::{
        LockArtifact, LockCoordinate, LockEdge, LockGav, LockModule, LockModulePackage,
        LockPlatform, Platform,
    };
    use rv_sbom::Component;

    use super::adapt_sbom_modules;

    fn package(
        group: &str,
        artifact: &str,
        workspace_module: Option<&str>,
        direct: bool,
    ) -> LockModulePackage {
        LockModulePackage {
            coordinate: LockCoordinate::new(group, artifact, "1", "jar", None),
            direct_scope: direct.then(|| "compile".to_string()),
            workspace_module: workspace_module.map(str::to_string),
            system_path: None,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn workspace_package_uses_target_modules_canonical_purl() {
        let workspace = package("com.example", "lib", Some("lib/pom.xml"), true);
        let external = package("org.example", "shared", None, false);
        let app = LockModule {
            path: "app/pom.xml".to_string(),
            gav: LockGav::new("com.example", "app", "1"),
            packaging: "jar".to_string(),
            packages: vec![workspace, external.clone()],
            edges: vec![LockEdge {
                from: 0,
                to: 1,
                scope: Some("compile".to_string()),
                optional: false,
                extra: BTreeMap::new(),
            }],
            extra: BTreeMap::new(),
        };
        let lib = LockModule {
            path: "lib/pom.xml".to_string(),
            gav: LockGav::new("com.example", "lib", "1"),
            packaging: "bundle".to_string(),
            packages: vec![LockModulePackage {
                direct_scope: Some("compile".to_string()),
                ..external
            }],
            edges: Vec::new(),
            extra: BTreeMap::new(),
        };
        let platform = LockPlatform {
            platform: Platform::new("linux", "x86_64").expect("platform"),
            model_hash: "a".repeat(64),
            artifacts: vec![LockArtifact {
                coordinate: LockCoordinate::new("org.example", "shared", "1", "jar", None),
                repo_url: "https://repo.example/".to_string(),
                checksums: Vec::new(),
                snapshot: None,
                pom_sha256: None,
                extra: BTreeMap::new(),
            }],
            modules: vec![app, lib],
            extra: BTreeMap::new(),
        };
        let fallback = Component {
            name: "root".to_string(),
            version: "1".to_string(),
            group: Some("com.example".to_string()),
            purl: "pkg:maven/com.example/root@1".to_string(),
            license_expression: None,
            hashes: Vec::new(),
            dependencies: Vec::new(),
        };
        let selected = vec![&platform.modules[0]];
        let adapted =
            adapt_sbom_modules(&platform, &selected, fallback).expect("adapt selected module");

        let canonical = "pkg:maven/com.example/lib@1?type=bundle";
        let legacy_workspace_shape = "pkg:maven/com.example/lib@1";
        let lib = adapted
            .components
            .iter()
            .find(|component| component.purl == canonical)
            .expect("canonical sibling component");
        assert!(
            lib.dependencies
                .iter()
                .any(|dependency| dependency == "pkg:maven/org.example/shared@1")
        );
        assert!(
            adapted
                .components
                .iter()
                .all(|component| component.purl != legacy_workspace_shape),
            "workspace package must not create a second first-party component"
        );
    }
}
