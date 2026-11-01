use std::collections::{BTreeMap, BTreeSet};

use rv_lock::{LockArtifact, LockModule, LockModulePackage, LockPlatform, Scope};
use rv_maven_types::ArtifactCoord;
use rv_sbom::{Component, Hash, HashAlgorithm};
use rv_vuln::Dependency;

#[derive(Debug, thiserror::Error)]
pub(crate) enum LockAdapterError {
    #[error(transparent)]
    Purl(#[from] rv_vuln::VulnError),
    #[error("no module of the lockfile platform was selected")]
    NoModule,
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
    /// Every selected module identity, including variants on other targets.
    pub module_purls: BTreeSet<String>,
    /// Dependency purl to the module path and product purl that reach it.
    pub products: BTreeMap<String, Vec<(String, String)>>,
    /// Distinct purls that every module reaches only on its test classpath.
    pub test_only: usize,
}

pub(crate) struct SbomDependencies {
    pub root: Component,
    pub components: Vec<Component>,
    /// Each selected module's path, purl, and the purls of its packages.
    pub modules: Vec<(String, String, BTreeSet<String>)>,
}

pub(crate) fn adapt_sbom_modules(
    platform: &LockPlatform,
    modules: &[&LockModule],
) -> Result<SbomDependencies, LockAdapterError> {
    let root_module = modules
        .iter()
        .copied()
        .find(|module| module.path == "pom.xml")
        .or_else(|| modules.first().copied());
    let mut root = module_component(root_module.ok_or(LockAdapterError::NoModule)?)?;

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
    let mut module_packages = Vec::with_capacity(modules.len());

    for module in modules {
        let graph_module = module_component(module)?;
        let module_purl = graph_module.purl.clone();
        insert_component(&mut components, graph_module);
        let package_purls = module
            .packages
            .iter()
            .map(|package| package_purl(package, &module_by_path))
            .collect::<Result<Vec<_>, _>>()?;
        module_packages.push((
            module.path.clone(),
            module_purl.clone(),
            package_purls.iter().cloned().collect(),
        ));

        for (index, package) in module.packages.iter().enumerate() {
            let component = package_component(
                package,
                &artifact_by_coordinate,
                &module_by_path,
                package_purls[index].clone(),
            )?;
            insert_component(&mut components, component);
        }

        let mut incoming = vec![0; module.packages.len()];
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
            incoming[edge.to] += 1;
        }

        for index in crate::commands::util::module_roots(module, &incoming) {
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
            insert_component(&mut components, module_component(module)?);
        }
    }

    if let Some(component) = components.remove(&root.purl) {
        root.dependencies = component.dependencies;
    }
    for component in components.values_mut().chain([&mut root]) {
        component.dependencies.sort();
        component.dependencies.dedup();
    }

    Ok(SbomDependencies {
        root,
        components: components.into_values().collect(),
        modules: module_packages,
    })
}

fn package_component(
    package: &LockModulePackage,
    artifacts: &BTreeMap<&ArtifactCoord, &LockArtifact>,
    modules: &BTreeMap<&str, &LockModule>,
    purl: String,
) -> Result<Component, LockAdapterError> {
    let gav = package
        .workspace_module
        .as_deref()
        .and_then(|path| modules.get(path))
        .map_or(&package.coordinate.gav, |module| &module.gav);
    let sha256 = if package.workspace_module.is_some() {
        None
    } else if package.system_path.is_some() {
        package.system_sha256.as_ref().map(ToString::to_string)
    } else {
        artifacts
            .get(&package.coordinate)
            .and_then(|artifact| {
                artifact
                    .checksums
                    .iter()
                    .find_map(rv_maven_types::Digest::as_sha256)
            })
            .map(ToString::to_string)
    };
    let hashes = sha256
        .into_iter()
        .map(|value| Hash {
            algorithm: HashAlgorithm::Sha256,
            value,
        })
        .collect();
    Ok(Component {
        name: gav.artifact.to_string(),
        version: gav.version().to_string(),
        group: Some(gav.group.to_string()),
        purl,
        hashes,
        licenses: Vec::new(),
        dependencies: Vec::new(),
    })
}

fn module_component(module: &LockModule) -> Result<Component, LockAdapterError> {
    Ok(Component {
        name: module.gav.artifact.to_string(),
        version: module.gav.version().to_string(),
        group: Some(module.gav.group.to_string()),
        purl: maven_purl(
            module.gav.group.as_str(),
            module.gav.artifact.as_str(),
            module.gav.version(),
            &module.packaging,
        )?,
        hashes: Vec::new(),
        licenses: Vec::new(),
        dependencies: Vec::new(),
    })
}

fn package_purl(
    package: &LockModulePackage,
    modules: &BTreeMap<&str, &LockModule>,
) -> Result<String, LockAdapterError> {
    if let Some(path) = package.workspace_module.as_deref()
        && let Some(module) = modules.get(path)
    {
        // A classified artifact of the module, such as its test-jar, is
        // another component than the module.
        if package.coordinate.classifier().is_none() {
            return maven_purl(
                module.gav.group.as_str(),
                module.gav.artifact.as_str(),
                module.gav.version(),
                &module.packaging,
            );
        }
        let mut dependency = dependency_from_coordinate(&package.coordinate);
        dependency.group_id = module.gav.group.to_string();
        dependency.artifact_id = module.gav.artifact.to_string();
        dependency.version = module.gav.version().to_string();
        return Ok(dependency.purl()?);
    }
    Ok(dependency_from_coordinate(&package.coordinate).purl()?)
}

fn insert_component(components: &mut BTreeMap<String, Component>, component: Component) {
    components
        .entry(component.purl.clone())
        .and_modify(|existing| {
            existing.dependencies.extend(component.dependencies.clone());
            if existing.hashes.is_empty() {
                existing.hashes.clone_from(&component.hashes);
            }
        })
        .or_insert(component);
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
    // CycloneDX does not let a component depend on itself.
    if target != source {
        component.dependencies.push(target);
    }
    Ok(())
}

/// Build the OSV query set from module-local graphs.
///
/// The purl-keyed map deduplicates across modules before the scanner sees the
/// dependencies. The paired module-path set records every module in which
/// each external resolves to a scope other than test, unless `include_test`
/// includes every scope. Module identities stay separate across targets.
/// Workspace nodes never enter the query set; a system dependency does,
/// since its coordinate can still match an advisory.
pub(crate) fn adapt_vulnerability_modules(
    modules: &[&LockModule],
    include_test: bool,
) -> Result<VulnerabilityDependencies, LockAdapterError> {
    let mut by_purl = BTreeMap::<String, (Dependency, BTreeSet<(String, String)>)>::new();
    let mut module_purls = BTreeSet::new();
    for module in modules {
        let product = module_component(module)?.purl;
        module_purls.insert(product.clone());
        for package in &module.packages {
            if package.workspace_module.is_some() {
                continue;
            }
            let dependency = dependency_from_coordinate(&package.coordinate);
            let purl = dependency.purl()?;
            let entry = by_purl
                .entry(purl)
                .or_insert_with(|| (dependency, BTreeSet::new()));
            if include_test || package.scope != Scope::Test {
                entry.1.insert((module.path.clone(), product.clone()));
            }
        }
    }

    let mut dependencies = Vec::with_capacity(by_purl.len());
    let mut reachability = BTreeMap::new();
    let mut products = BTreeMap::new();
    let mut test_only = 0;
    for (purl, (dependency, modules)) in by_purl {
        if modules.is_empty() {
            test_only += 1;
            continue;
        }
        dependencies.push(dependency);
        reachability.insert(
            purl.clone(),
            modules
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        );
        products.insert(purl, modules.into_iter().collect());
    }
    Ok(VulnerabilityDependencies {
        dependencies,
        reachability,
        module_purls,
        products,
        test_only,
    })
}

pub(crate) fn dependency_from_coordinate(coordinate: &ArtifactCoord) -> Dependency {
    Dependency {
        group_id: coordinate.group_id().to_string(),
        artifact_id: coordinate.artifact_id().to_string(),
        version: coordinate.version().to_string(),
        packaging: coordinate.extension().to_string(),
        classifier: coordinate.classifier().map(str::to_string),
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

    use rv_lock::{LockArtifact, LockEdge, LockModule, LockModulePackage, LockPlatform, Platform};
    use rv_maven_types::{ArtifactCoord, Gav};

    use super::{adapt_sbom_modules, adapt_vulnerability_modules};

    fn package(
        group: &str,
        artifact: &str,
        workspace_module: Option<&str>,
        direct: bool,
    ) -> LockModulePackage {
        let mut package = LockModulePackage::new(
            ArtifactCoord::new(group, artifact, "1", "jar", None),
            direct.then_some(rv_lock::Scope::Compile),
        );
        package.workspace_module = workspace_module.map(str::to_string);
        package
    }

    #[test]
    fn workspace_package_uses_target_modules_canonical_purl() {
        let workspace = package("com.example", "lib", Some("lib/pom.xml"), true);
        let external = package("org.example", "shared", None, false);
        let mut app = LockModule::new(
            "app/pom.xml".to_string(),
            Gav::new("com.example", "app", "1"),
            "jar".to_string(),
        );
        app.packages = vec![workspace, external.clone()];
        app.edges = vec![LockEdge::new(0, 1, Some(rv_lock::Scope::Compile), false)];
        let mut lib = LockModule::new(
            "lib/pom.xml".to_string(),
            Gav::new("com.example", "lib", "1"),
            "bundle".to_string(),
        );
        lib.packages = vec![{
            let mut package = external;
            package.direct_scope = Some(rv_lock::Scope::Compile);
            package
        }];
        let mut platform = LockPlatform::new(
            Platform::new("linux", "x86_64").expect("platform"),
            "a".repeat(64),
        );
        platform.artifacts = vec![LockArtifact::new(
            ArtifactCoord::new("org.example", "shared", "1", "jar", None),
            "https://repo.example/".to_string(),
        )];
        platform.modules = vec![app, lib];
        let selected = vec![&platform.modules[0]];
        let adapted = adapt_sbom_modules(&platform, &selected).expect("adapt selected module");

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

    /// A module's test-jar is its own component, and no component depends
    /// on itself, even through a self edge.
    #[test]
    fn classified_workspace_packages_keep_their_classifier_and_no_self_edges() {
        let mut tests = LockModulePackage::new(
            ArtifactCoord::new("com.example", "lib", "1", "jar", Some("tests")),
            Some(rv_lock::Scope::Test),
        );
        tests.workspace_module = Some("lib/pom.xml".to_string());
        let mut app = LockModule::new(
            "pom.xml".to_string(),
            Gav::new("com.example", "app", "1"),
            "jar".to_string(),
        );
        app.packages = vec![
            package("com.example", "lib", Some("lib/pom.xml"), true),
            tests,
        ];
        app.edges = vec![
            LockEdge::new(1, 0, Some(rv_lock::Scope::Test), false),
            LockEdge::new(0, 0, Some(rv_lock::Scope::Compile), false),
        ];
        let lib = LockModule::new(
            "lib/pom.xml".to_string(),
            Gav::new("com.example", "lib", "1"),
            "jar".to_string(),
        );
        let mut platform = LockPlatform::new(
            Platform::new("linux", "x86_64").expect("platform"),
            "a".repeat(64),
        );
        platform.modules = vec![app, lib];
        let selected = vec![&platform.modules[0]];
        let adapted = adapt_sbom_modules(&platform, &selected).expect("adapt");

        let purls: Vec<&str> = adapted
            .components
            .iter()
            .map(|component| component.purl.as_str())
            .collect();
        assert_eq!(
            purls,
            [
                "pkg:maven/com.example/lib@1",
                "pkg:maven/com.example/lib@1?classifier=tests"
            ]
        );
        assert_eq!(
            adapted.root.dependencies,
            [
                "pkg:maven/com.example/lib@1",
                "pkg:maven/com.example/lib@1?classifier=tests"
            ]
        );
        assert_eq!(
            adapted.components[1].dependencies,
            ["pkg:maven/com.example/lib@1"]
        );
        for component in adapted.components.iter().chain([&adapted.root]) {
            assert!(
                !component.dependencies.contains(&component.purl),
                "{} depends on itself",
                component.purl
            );
        }
    }

    /// A package the module declares with `direct`, or reaches only through
    /// another when it is `None`, resolving to `scope`.
    fn scoped(
        artifact: &str,
        direct: Option<rv_lock::Scope>,
        scope: rv_lock::Scope,
    ) -> LockModulePackage {
        let mut package = LockModulePackage::new(
            ArtifactCoord::new("org.example", artifact, "1", "jar", None),
            direct,
        );
        package.scope = scope;
        package
    }

    fn scoped_module(
        path: &str,
        packages: Vec<LockModulePackage>,
        edges: &[(usize, usize, rv_lock::Scope)],
    ) -> LockModule {
        let mut module = LockModule::new(
            path.to_string(),
            Gav::new("com.example", path.trim_end_matches("/pom.xml"), "1"),
            "jar".to_string(),
        );
        module.packages = packages;
        module.edges = (edges.iter())
            .map(|&(from, to, scope)| LockEdge::new(from, to, Some(scope), false))
            .collect();
        module
    }

    /// Test-only packages are dropped per module before the union, and the
    /// other scopes stay.
    #[test]
    fn vulnerability_scan_drops_what_only_the_test_classpath_reaches() {
        use rv_lock::Scope::{Compile, Provided, Runtime, System, Test};
        let app = scoped_module(
            "app/pom.xml",
            vec![
                scoped("compiled", Some(Compile), Compile),
                scoped("junit", Some(Test), Test),
                scoped("hamcrest", None, Test),
                scoped("managed-to-test", None, Test),
                scoped("provided", Some(Provided), Provided),
                scoped("runtime", Some(Runtime), Runtime),
                scoped("system", Some(System), System),
                scoped("shared", Some(Test), Test),
            ],
            &[(1, 2, Test), (0, 3, Test)],
        );
        let lib = scoped_module(
            "lib/pom.xml",
            vec![scoped("shared", Some(Compile), Compile)],
            &[],
        );
        let adapted = adapt_vulnerability_modules(&[&app, &lib], false).expect("adapt");
        let reachability: Vec<(String, Vec<String>)> = adapted.reachability.into_iter().collect();
        let purl = |artifact: &str| format!("pkg:maven/org.example/{artifact}@1");
        let app_only = vec!["app/pom.xml".to_string()];
        assert_eq!(
            reachability,
            [
                (purl("compiled"), app_only.clone()),
                (purl("provided"), app_only.clone()),
                (purl("runtime"), app_only.clone()),
                (purl("shared"), vec!["lib/pom.xml".to_string()]),
                (purl("system"), app_only),
            ]
        );
        assert_eq!(adapted.dependencies.len(), 5);
        assert_eq!(adapted.test_only, 3, "junit, hamcrest and managed-to-test");
        assert!(adapted.module_purls.contains("pkg:maven/com.example/app@1"));
    }

    /// A package that a nearer test path reaches first and a compile path
    /// reaches too resolves to compile, as Maven widens it, and so does its
    /// own dependency `y`; the scan follows the scope the lock records, not
    /// the test edge. A direct test declaration still wins.
    #[test]
    fn a_package_a_compile_path_also_reaches_keeps_its_subtree() {
        use rv_lock::Scope::{Compile, Test};
        let module = scoped_module(
            "pom.xml",
            vec![
                scoped("testlib", Some(Test), Test),
                scoped("a", Some(Compile), Compile),
                scoped("b", None, Compile),
                scoped("x", None, Compile),
                scoped("y", None, Compile),
                scoped("direct-test", Some(Test), Test),
            ],
            &[
                (0, 3, Test),
                (1, 2, Compile),
                (2, 3, Compile),
                (3, 4, Compile),
                (2, 5, Compile),
            ],
        );
        let adapted = adapt_vulnerability_modules(&[&module], false).expect("adapt");
        let artifacts: Vec<&str> = (adapted.dependencies.iter())
            .map(|dependency| dependency.artifact_id.as_str())
            .collect();
        assert_eq!(artifacts, ["a", "b", "x", "y"]);
        assert_eq!(adapted.test_only, 2);
    }

    #[test]
    fn vulnerability_union_preserves_product_versions_and_test_reachability() {
        let mut app = LockModule::new("pom.xml", Gav::new("com.example", "app", "1"), "jar");
        app.packages = vec![scoped(
            "shared",
            Some(rv_lock::Scope::Test),
            rv_lock::Scope::Test,
        )];
        let mut other = app.clone();
        other.gav = Gav::new("com.example", "app", "2");
        other.packages[0].scope = rv_lock::Scope::Compile;
        other.packages[0].direct_scope = Some(rv_lock::Scope::Compile);
        let filtered = adapt_vulnerability_modules(&[&app, &other], false).unwrap();
        let purl = "pkg:maven/org.example/shared@1";
        assert_eq!(
            filtered.products[purl],
            [(
                "pom.xml".to_string(),
                "pkg:maven/com.example/app@2".to_string()
            )]
        );
        let all = adapt_vulnerability_modules(&[&app, &other], true).unwrap();
        assert_eq!(all.dependencies.len(), 1);
        assert_eq!(all.reachability[purl], ["pom.xml"]);
        assert_eq!(all.products[purl].len(), 2);
        assert_eq!(all.test_only, 0);
    }
}
