use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use rv_lock::{LockArtifact, LockModule, LockModulePackage, LockPlatform, PackageSource, Scope};
use rv_maven_types::ArtifactCoord;
use rv_sbom::{Component, ComponentScope, Hash, HashAlgorithm, Property};
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
    #[error(
        "{0} has different hashes in two selected modules; pass --module to write one \
         module's SBOM"
    )]
    DifferentHashes(String),
}

impl From<LockAdapterError> for crate::error::CliError {
    fn from(err: LockAdapterError) -> Self {
        match err {
            LockAdapterError::DifferentHashes(_) => Self::Usage(err.to_string()),
            err => Self::LockfileDefect {
                details: err.to_string(),
            },
        }
    }
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
    /// Sorted by [`Component::reference`].
    pub components: Vec<Component>,
    /// Each selected module's path, purl, and the components of its
    /// packages: each one's reference, with its purl.
    pub modules: Vec<(String, String, BTreeMap<String, String>)>,
    /// The model of each component, the root's included, by reference: a
    /// module and a repository file of its coordinates have their own.
    pub models: BTreeMap<String, ComponentModel>,
}

/// Where a component's model comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ComponentModel {
    /// The reactor module's POM at this path.
    Module(String),
    /// The POM raeva.lock pins for a repository file.
    Pinned,
    /// The POM raeva.lock pins for the repository file of the coordinates
    /// of the module that reads it. Maven builds that file with the
    /// module's model, so the lock holds neither the POM's parents nor
    /// their range selections.
    OwnPinned,
    /// None: a system-scoped file has no POM.
    System,
}

#[cfg(test)]
pub(crate) fn adapt_sbom_modules(
    platform: &LockPlatform,
    modules: &[&LockModule],
) -> Result<SbomDependencies, LockAdapterError> {
    let listed = listed_module_purls(platform, modules)?;
    adapt_sbom_modules_listing(platform, modules, &listed)
}

/// The purl of each module an SBOM of `modules` lists: the modules and the
/// reactor modules their packages name. A file of a listed module's
/// coordinates is a component of its own.
pub(crate) fn listed_module_purls(
    platform: &LockPlatform,
    modules: &[&LockModule],
) -> Result<BTreeSet<String>, LockAdapterError> {
    let module_by_path = (platform.modules.iter())
        .map(|module| (module.path.as_str(), module))
        .collect::<BTreeMap<_, _>>();
    let mut listed = BTreeSet::new();
    for module in modules {
        listed.insert(module_component(module)?.purl);
        for package in (module.packages.iter()).filter(|package| package.workspace_module.is_some())
        {
            listed.insert(package_purl(package, &module_by_path)?);
        }
    }
    Ok(listed)
}

/// `adapt_sbom_modules`, with `module_purls` the modules the whole
/// document lists, which the selection on other targets adds to.
pub(crate) fn adapt_sbom_modules_listing(
    platform: &LockPlatform,
    modules: &[&LockModule],
    module_purls: &BTreeSet<String>,
) -> Result<SbomDependencies, LockAdapterError> {
    let root_module = modules
        .iter()
        .copied()
        .find(|module| module.path == "pom.xml")
        .or_else(|| modules.first().copied());
    let root_module = root_module.ok_or(LockAdapterError::NoModule)?;
    let mut root = module_component(root_module)?;
    let mut models = BTreeMap::from([(
        root.reference().to_string(),
        ComponentModel::Module(root_module.path.clone()),
    )]);

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
    // Keyed by reference.
    let mut components = BTreeMap::<String, Component>::new();
    // Each component's resolved scope and optionality in each selected
    // module that reaches it.
    let mut scopes = BTreeMap::<String, BTreeSet<(&str, Scope, bool)>>::new();
    let mut module_packages = Vec::with_capacity(modules.len());

    for module in modules {
        let graph_module = module_component(module)?;
        let module_purl = graph_module.purl.clone();
        (models.entry(graph_module.reference().to_string()))
            .or_insert_with(|| ComponentModel::Module(module.path.clone()));
        insert_component(&mut components, graph_module)?;
        let package_purls = module
            .packages
            .iter()
            .map(|package| package_purl(package, &module_by_path))
            .collect::<Result<Vec<_>, _>>()?;
        let mut package_components = BTreeMap::new();
        let mut package_refs = Vec::with_capacity(module.packages.len());
        for (index, package) in module.packages.iter().enumerate() {
            let mut component = package_component(
                package,
                &artifact_by_coordinate,
                &module_by_path,
                package_purls[index].clone(),
            )?;
            let model = match package.source() {
                PackageSource::Module(path) => ComponentModel::Module(path.to_string()),
                PackageSource::Repository if module.owns(&package.coordinate.gav) => {
                    ComponentModel::OwnPinned
                }
                PackageSource::Repository => ComponentModel::Pinned,
                PackageSource::System(_) => ComponentModel::System,
            };
            // A file of a module's coordinates, such as the repository's
            // jar a module takes of itself, is a component of its own with
            // its own hash.
            if !matches!(model, ComponentModel::Module(_)) && module_purls.contains(&component.purl)
            {
                component.bom_ref = Some(format!("{}#file", component.purl));
            }
            let reference = component.reference().to_string();
            models.entry(reference.clone()).or_insert(model);
            package_components.insert(reference.clone(), component.purl.clone());
            insert_component(&mut components, component)?;
            scopes.entry(reference.clone()).or_default().insert((
                module.path.as_str(),
                package.scope,
                package.optional,
            ));
            package_refs.push(reference);
        }
        module_packages.push((module.path.clone(), module_purl.clone(), package_components));

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
                &package_refs[edge.from],
                package_refs[edge.to].clone(),
            )?;
            incoming[edge.to] += 1;
        }

        for index in crate::commands::util::module_roots(module, &incoming) {
            add_dependency(&mut components, &module_purl, package_refs[index].clone())?;
        }
    }

    if let Some(component) = components.remove(&root.purl) {
        root.dependencies = component.dependencies;
    }
    for component in components.values_mut().chain([&mut root]) {
        component.dependencies.sort();
        component.dependencies.dedup();
    }
    for (reference, component) in &mut components {
        match scopes.get(reference) {
            Some(scopes) => set_scope(component, scopes),
            // A reactor module no selected module resolves, which CycloneDX
            // would read as `required` too.
            None => component.scope = Some(ComponentScope::Required),
        }
    }

    Ok(SbomDependencies {
        root,
        components: components.into_values().collect(),
        modules: module_packages,
        models,
    })
}

/// Write the scope the modules resolve the component to: one property when
/// they agree, else one per module, so a large reactor does not repeat a
/// module list on every component. Test scope is `excluded`. Another scope
/// is `optional` where the module resolves the component as optional, as
/// the CycloneDX Maven plugin writes Maven's `isOptional()`, and `required`
/// otherwise. `scope` is `required` when any module needs it at runtime,
/// else `optional` when any module has it outside tests. A module that
/// resolves it to the empty scope adds no property.
fn set_scope(component: &mut Component, scopes: &BTreeSet<(&str, Scope, bool)>) {
    let mut outside_tests = (scopes.iter()).filter(|(_, scope, _)| *scope != Scope::Test);
    component.scope = Some(match outside_tests.next() {
        None => ComponentScope::Excluded,
        Some((.., true)) if outside_tests.all(|(.., optional)| *optional) => {
            ComponentScope::Optional
        }
        Some(_) => ComponentScope::Required,
    });
    if component.scope == Some(ComponentScope::Excluded) {
        // Registered in the CycloneDX property taxonomy.
        component.properties.push(Property {
            name: "cdx:maven:package:test".to_string(),
            value: "true".to_string(),
        });
    }
    let property = |value: String| Property {
        name: "raeva:maven:scope".to_string(),
        value,
    };
    let mut distinct = scopes.iter().map(|(_, scope, _)| scope);
    match distinct.next() {
        Some(first) if distinct.all(|scope| scope == first) => {
            if *first != Scope::Empty {
                component.properties.push(property(first.to_string()));
            }
        }
        _ => component.properties.extend(
            (scopes.iter())
                .filter(|(_, scope, _)| *scope != Scope::Empty)
                .map(|(path, scope, _)| property(format!("{scope} {path}"))),
        ),
    }
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
        bom_ref: None,
        hashes,
        licenses: Vec::new(),
        dependencies: Vec::new(),
        scope: None,
        properties: Vec::new(),
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
        bom_ref: None,
        hashes: Vec::new(),
        licenses: Vec::new(),
        dependencies: Vec::new(),
        scope: None,
        properties: Vec::new(),
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
        let mut dependency = dependency_of(package);
        dependency.group_id = module.gav.group.to_string();
        dependency.artifact_id = module.gav.artifact.to_string();
        dependency.version = module.gav.version().to_string();
        return Ok(dependency.purl()?);
    }
    Ok(dependency_of(package).purl()?)
}

fn insert_component(
    components: &mut BTreeMap<String, Component>,
    component: Component,
) -> Result<(), LockAdapterError> {
    match components.entry(component.reference().to_string()) {
        Entry::Occupied(mut entry) if entry.get().hashes == component.hashes => {
            entry.get_mut().dependencies.extend(component.dependencies);
        }
        Entry::Occupied(_) => return Err(LockAdapterError::DifferentHashes(component.purl)),
        Entry::Vacant(entry) => {
            entry.insert(component);
        }
    }
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
            let dependency = dependency_of(package);
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

/// The purl names the Maven type, as purl-spec's `maven` type and the
/// CycloneDX Maven plugin do, not the extension.
fn dependency_of(package: &LockModulePackage) -> Dependency {
    let coordinate = &package.coordinate;
    Dependency {
        group_id: coordinate.group_id().to_string(),
        artifact_id: coordinate.artifact_id().to_string(),
        version: coordinate.version().to_string(),
        packaging: package.maven_type().to_string(),
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

    use super::{ComponentScope, adapt_sbom_modules, adapt_vulnerability_modules};

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
        app.edges = vec![LockEdge::new(0, 1, rv_lock::Scope::Compile, false)];
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

    /// Two modules that lock other system files for one coordinate give
    /// its component two hashes, which one SBOM cannot hold.
    #[test]
    fn one_component_with_two_hashes_is_refused() {
        let mut platform = LockPlatform::new(
            Platform::new("linux", "x86_64").expect("platform"),
            "a".repeat(64),
        );
        for (name, digest) in [("app", 'a'), ("lib", 'b')] {
            let mut tools = package("com.acme", "tools", None, true);
            tools.system_path = Some("lib/tools.jar".to_string());
            tools.system_sha256 = Some(digest.to_string().repeat(64).parse().unwrap());
            let mut module = LockModule::new(
                format!("{name}/pom.xml"),
                Gav::new("com.example", name, "1"),
                "jar".to_string(),
            );
            module.packages = vec![tools];
            platform.modules.push(module);
        }
        let selected: Vec<_> = platform.modules.iter().collect();
        let err = adapt_sbom_modules(&platform, &selected)
            .err()
            .expect("two hashes");
        assert!(err.to_string().contains("different hashes"), "{err}");
        adapt_sbom_modules(&platform, &selected[..1]).expect("one module");
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
            LockEdge::new(1, 0, rv_lock::Scope::Test, false),
            LockEdge::new(0, 0, rv_lock::Scope::Compile, false),
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
            .map(|&(from, to, scope)| LockEdge::new(from, to, scope, false))
            .collect();
        module
    }

    /// A reactor module no selected module depends on is a library component
    /// with the scope CycloneDX assumes when none is given, `required`, and
    /// no `raeva:maven:scope`, since no module resolves it.
    #[test]
    fn a_module_nothing_depends_on_is_required() {
        let app = scoped_module("app/pom.xml", Vec::new(), &[]);
        let gwt = scoped_module("gwt/pom.xml", Vec::new(), &[]);
        let mut platform = LockPlatform::new(
            Platform::new("linux", "x86_64").expect("platform"),
            "a".repeat(64),
        );
        platform.modules = vec![app, gwt];
        let selected = platform.modules.iter().collect::<Vec<_>>();
        let adapted = adapt_sbom_modules(&platform, &selected).expect("adapt");
        let [gwt] = adapted.components.as_slice() else {
            panic!("{:?}", adapted.components);
        };
        assert_eq!(gwt.purl, "pkg:maven/com.example/gwt@1");
        assert_eq!(gwt.scope, Some(ComponentScope::Required));
        assert!(gwt.properties.is_empty(), "{:?}", gwt.properties);
    }

    /// The empty scope has no `raeva:maven:scope` value: Maven gives such a
    /// package none, so the property is left out, alone or per module.
    #[test]
    fn the_empty_scope_has_no_scope_property() {
        use rv_lock::Scope::{Compile, Empty};
        let app = scoped_module(
            "app/pom.xml",
            vec![scoped("none", None, Empty), scoped("mixed", None, Empty)],
            &[],
        );
        let lib = scoped_module("lib/pom.xml", vec![scoped("mixed", None, Compile)], &[]);
        let mut platform = LockPlatform::new(
            Platform::new("linux", "x86_64").expect("platform"),
            "a".repeat(64),
        );
        platform.artifacts = ["none", "mixed"]
            .map(|artifact| {
                LockArtifact::new(
                    ArtifactCoord::new("org.example", artifact, "1", "jar", None),
                    "https://repo.example/".to_string(),
                )
            })
            .into();
        platform.modules = vec![app, lib];
        let selected = platform.modules.iter().collect::<Vec<_>>();
        let adapted = adapt_sbom_modules(&platform, &selected).expect("adapt");
        let properties = |artifact: &str| {
            let purl = format!("pkg:maven/org.example/{artifact}@1");
            let component = (adapted.components.iter())
                .find(|component| component.purl == purl)
                .expect("component");
            assert_eq!(
                component.scope,
                Some(ComponentScope::Required),
                "{artifact}"
            );
            (component.properties.iter())
                .map(|property| format!("{}={}", property.name, property.value))
                .collect::<Vec<_>>()
        };
        assert_eq!(properties("none"), Vec::<String>::new());
        assert_eq!(
            properties("mixed"),
            ["raeva:maven:scope=compile lib/pom.xml"]
        );
    }

    /// Across modules, a component is `optional` only where every module
    /// that has it outside tests resolves it as optional: one module that
    /// needs it makes it `required`, and test scope elsewhere does not count.
    #[test]
    fn optional_across_modules_yields_to_required() {
        use rv_lock::Scope::{Compile, Test};
        let optional = |artifact: &str, scope| {
            let mut package = scoped(artifact, Some(scope), scope);
            package.optional = true;
            package
        };
        let app = scoped_module(
            "app/pom.xml",
            vec![
                optional("both", Compile),
                optional("everywhere", Compile),
                optional("tested", Compile),
            ],
            &[],
        );
        let lib = scoped_module(
            "lib/pom.xml",
            vec![
                scoped("both", Some(Compile), Compile),
                optional("everywhere", Compile),
                scoped("tested", Some(Test), Test),
            ],
            &[],
        );
        let mut platform = LockPlatform::new(
            Platform::new("linux", "x86_64").expect("platform"),
            "a".repeat(64),
        );
        platform.artifacts = ["both", "everywhere", "tested"]
            .map(|artifact| {
                LockArtifact::new(
                    ArtifactCoord::new("org.example", artifact, "1", "jar", None),
                    "https://repo.example/".to_string(),
                )
            })
            .into();
        platform.modules = vec![app, lib];
        let selected = platform.modules.iter().collect::<Vec<_>>();
        let adapted = adapt_sbom_modules(&platform, &selected).expect("adapt");
        let scope = |artifact: &str| {
            let purl = format!("pkg:maven/org.example/{artifact}@1");
            (adapted.components.iter())
                .find(|component| component.purl == purl)
                .expect("component")
                .scope
        };
        assert_eq!(scope("both"), Some(ComponentScope::Required));
        assert_eq!(scope("everywhere"), Some(ComponentScope::Optional));
        assert_eq!(scope("tested"), Some(ComponentScope::Optional));
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
