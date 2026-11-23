//! What Surefire and Failsafe 3 resolve while they run: the test framework
//! provider their `AbstractSurefireMojo` picks for the module's test class
//! path, each piece resolved as `SurefireDependencyResolver` resolves it, a
//! root-less request for one artifact at `runtime`.

use std::collections::{BTreeMap, BTreeSet};

use rv_lock::LockModule;
use rv_maven_model::{ArtifactTypes, ConfigNode, Dependency, Plugin};
use rv_maven_types::{Version, VersionReq};
use rv_repo::Repository;

use super::PluginRole;
use super::request::{PathResolution, Planner, SetRequest};
use crate::error::{ResolveError, Result};

const SUREFIRE_GROUP: &str = "org.apache.maven.surefire";
/// `junit.version` in Surefire 3.6.x's `surefire.junit.version.properties`.
const SUREFIRE_36_JUNIT: &str = "5.14.4";

impl Planner<'_> {
    /// The keys of the provider sets the plugin of `plugin_set`, Surefire
    /// or Failsafe with its version known, resolves for the module at
    /// `pom_path`, which declares `declared`, with the artifact handlers of
    /// the module's build extensions.
    pub(super) async fn test_providers(
        &mut self,
        pom_path: &str,
        declared: &[Dependency],
        plugin_set: &SetRequest,
        project_repos: &[Repository],
    ) -> Result<Vec<String>> {
        let (plugin, plugin_repos) = (&plugin_set.plugin, &plugin_set.repos);
        if plugin.group_id != rv_maven_model::DEFAULT_PLUGIN_GROUP
            || !matches!(
                plugin.artifact_id.as_str(),
                "maven-surefire-plugin" | "maven-failsafe-plugin"
            )
        {
            return Ok(Vec::new());
        }
        let Some(version) = plugin.version.as_deref() else {
            return Ok(Vec::new());
        };
        if !Version::parse(version)
            .is_ok_and(|parsed| parsed >= Version::parse("3.0.0-M1").expect("a version"))
        {
            return Ok(Vec::new());
        }
        let Some(module) = self.test_classpaths.get(pom_path) else {
            return Ok(Vec::new());
        };
        let types = ArtifactTypes::pending(self.resolver().ctx.config.lock.maven.mode);
        types.define((plugin_set.handlers.iter()).flat_map(|(_, defined)| defined.iter().cloned()));
        let (classpath, unordered) = test_classpath(module, declared, &types);
        // What Surefire finds in its realm only a plugin dependency brings.
        let realm = if plugin.dependencies.is_empty() {
            BTreeMap::new()
        } else {
            self.plugin_realm(plugin_set).await?
        };
        let pieces = provider_pieces(plugin, version, &classpath, &realm);
        // Refused only where the version Maven takes would change them.
        let mut choices = vec![classpath];
        let read = (unordered.iter()).filter(|(key, _)| PROVIDER_KEYS.contains(&key.as_str()));
        for (key, versions) in read {
            choices = (choices.iter())
                .flat_map(|choice| {
                    versions.iter().map(move |version| {
                        let mut choice = choice.clone();
                        choice.insert(key.clone(), version.clone());
                        choice
                    })
                })
                .collect();
            if (choices.iter())
                .any(|choice| provider_pieces(plugin, version, choice, &realm) != pieces)
            {
                return Err(ResolveError::Plugin {
                    plugin: format!("plugin {}:{version}", plugin.key()),
                    searched: Vec::new(),
                    error: Box::new(ResolveError::UnorderedTestClasspath {
                        coord: key.clone(),
                        versions: versions.join(", "),
                    }),
                });
            }
        }
        let mut keys = Vec::new();
        for (piece, from_plugin_repos) in pieces {
            let repos = if from_plugin_repos {
                plugin_repos
            } else {
                project_repos
            };
            let request = SetRequest {
                module: pom_path.to_string(),
                role: PluginRole::TestProvider,
                plugin: Plugin::new("rv.test-provider", "test-provider", Some("0")),
                paths: vec![piece],
                repos: repos.to_vec(),
                filtered: Vec::new(),
                handlers: plugin_set.handlers.clone(),
                paths_by: PathResolution::default(),
            };
            let key = request.key(&self.resolver().ctx.config.project_root);
            self.requests.entry(key.clone()).or_insert(request);
            keys.push(key);
        }
        Ok(keys)
    }
}

/// The `groupId:artifactId` of each artifact of the test class path whose
/// version or presence picks the providers.
const PROVIDER_KEYS: [&str; 9] = [
    "junit:junit",
    "junit:junit-dep",
    "org.junit.jupiter:junit-jupiter-api",
    "org.junit.jupiter:junit-jupiter-engine",
    "org.junit.platform:junit-platform-commons",
    "org.junit.platform:junit-platform-runner",
    "org.junit.support:testng-engine",
    "org.junit.vintage:junit-vintage-engine",
    "org.testng:testng",
];

/// The version of each `groupId:artifactId` of `module`'s test class path
/// Surefire's maps take, from Maven's `project.getArtifacts()`, where a
/// later one wins: a pre-order walk of the graph, which takes the direct
/// dependencies as the module declares them in `declared`, and each
/// dependency's own after it. raeva.lock keeps neither the order of a POM
/// below a direct dependency nor which declaration of a dependency Maven
/// kept, which is the nearest unless a version range picks another: a
/// package comes anywhere under the direct dependencies the graph reaches it
/// from, and a direct one other than at the version the module declares
/// may come under one of them too. The versions among which only that
/// decides come second, by `groupId:artifactId`, the first of them in the
/// map.
fn test_classpath(
    module: &LockModule,
    declared: &[Dependency],
    types: &ArtifactTypes,
) -> (BTreeMap<String, String>, BTreeMap<String, Vec<String>>) {
    let packages = &module.packages;
    // Whether a declaration of a package's file can hold the version Maven
    // took, `None` where not known.
    let mode = types.mode();
    let holds = |dependency: &Dependency, coordinate: &rv_maven_types::ArtifactCoord| {
        let declared = dependency.version.as_deref()?;
        if !declared.starts_with(['[', '(']) {
            return Some(declared == coordinate.version());
        }
        let range = VersionReq::parse_in(declared, mode).ok()?;
        let version = Version::parse(coordinate.version()).ok()?;
        Some(range.matches_in(&version, mode))
    };
    // The declaration of the file, else the first that holds its version
    // among the module's declarations of it, as Maven keeps the newest
    // and the first of equal ones.
    let declared_at = |coordinate: &rv_maven_types::ArtifactCoord| {
        let file: Vec<usize> = (declared.iter().enumerate())
            .filter(|(_, dependency)| {
                dependency.group_id == coordinate.group_id()
                    && dependency.artifact_id == coordinate.artifact_id()
                    && dependency.effective_type_in(types) == coordinate.extension()
                    && dependency.effective_classifier_in(types) == coordinate.classifier()
            })
            .map(|(index, _)| index)
            .collect();
        if let [index] = file.as_slice() {
            return Some(*index);
        }
        for index in file {
            if holds(&declared[index], coordinate)? {
                return Some(index);
            }
        }
        None
    };
    // The first and last place in the walk each package can take, by the
    // declared dependency it comes under and whether below it; `None`
    // where not known, and not set where the graph does not reach it.
    type Places = Option<((usize, bool), (usize, bool))>;
    let mut places: Vec<Option<Places>> = vec![None; packages.len()];
    let mut fixed = vec![false; packages.len()];
    for (index, package) in packages.iter().enumerate() {
        if package.direct_scope.is_some() {
            let at = declared_at(&package.coordinate);
            places[index] = Some(at.map(|at| ((at, false), (at, false))));
            // One declared at another version, which a range below
            // overrode, comes where that range is.
            fixed[index] =
                at.is_none_or(|at| holds(&declared[at], &package.coordinate) == Some(true));
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for edge in &module.edges {
            if fixed.get(edge.to) != Some(&false) {
                continue;
            }
            let Some(Some(from)) = places.get(edge.from).copied() else {
                continue;
            };
            let under = from.map(|((first, _), (last, _))| ((first, true), (last, true)));
            let merged = match (places[edge.to], under) {
                (None, under) => Some(under),
                (Some(None), _) | (_, None) => Some(None),
                (Some(Some((a, b))), Some((c, d))) => Some(Some((a.min(c), b.max(d)))),
            };
            if merged != places[edge.to] {
                places[edge.to] = merged;
                changed = true;
            }
        }
    }
    let mut by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, package) in packages.iter().enumerate() {
        let coordinate = &package.coordinate;
        let key = format!("{}:{}", coordinate.group_id(), coordinate.artifact_id());
        by_key.entry(key).or_default().push(index);
    }
    let (mut classpath, mut unordered) = (BTreeMap::new(), BTreeMap::new());
    for (key, indexes) in by_key {
        let version = |index: usize| packages[index].coordinate.version().to_string();
        // The first and last place in the walk the package can take.
        let span = |index: usize| places[index].flatten();
        // Last unless another surely comes after it.
        let may_be_last = |index: usize| {
            (indexes.iter().copied()).all(|other| {
                other == index
                    || match (span(index), span(other)) {
                        (Some((_, last)), Some((first, _))) => last >= first,
                        _ => true,
                    }
            })
        };
        let taken: BTreeSet<String> = (indexes.iter().copied())
            .filter(|&index| may_be_last(index))
            .map(version)
            .collect();
        let taken: Vec<String> = taken.into_iter().collect();
        if taken.len() > 1 {
            unordered.insert(key.clone(), taken.clone());
        }
        classpath.insert(key, taken[0].clone());
    }
    (classpath, unordered)
}

/// Each artifact the providers of `plugin` at `version` resolve, with
/// whether it comes from the plugin repositories rather than the project's:
/// those of each execution that runs the tests, with its configuration,
/// or of the plugin's configuration when none does.
fn provider_pieces(
    plugin: &Plugin,
    version: &str,
    classpath: &BTreeMap<String, String>,
    realm: &BTreeMap<String, String>,
) -> Vec<(Dependency, bool)> {
    let goal = match plugin.artifact_id.as_str() {
        "maven-failsafe-plugin" => "integration-test",
        _ => "test",
    };
    let mut runs: Vec<_> = (plugin.executions.iter())
        .filter(|execution| execution.goals.iter().any(|known| known == goal))
        .map(|execution| execution.configuration.as_ref())
        .collect();
    if runs.is_empty() {
        runs.push(plugin.configuration.as_ref());
    }
    let mut pieces = Vec::new();
    for (index, configuration) in runs.into_iter().enumerate() {
        for piece in run_pieces(plugin, version, classpath, realm, configuration) {
            if index == 0 || !pieces.contains(&piece) {
                pieces.push(piece);
            }
        }
    }
    pieces
}

/// Each artifact the provider of one run of `plugin` with `configuration`
/// resolves.
fn run_pieces(
    plugin: &Plugin,
    version: &str,
    classpath: &BTreeMap<String, String>,
    realm: &BTreeMap<String, String>,
    configuration: Option<&ConfigNode>,
) -> Vec<(Dependency, bool)> {
    let get = |ga: &str| {
        debug_assert!(PROVIDER_KEYS.contains(&ga), "{ga} is no provider key");
        classpath.get(ga).map(String::as_str)
    };
    let provider = |artifact_id: &str| (piece(SUREFIRE_GROUP, artifact_id, version), true);
    // From 3.6 the JUnit Platform provider is Surefire's only one: it also
    // runs JUnit 4 and TestNG tests, through engines it adds.
    let since_36 = Version::parse(version)
        .is_ok_and(|parsed| parsed >= Version::parse("3.6.0-M1").expect("a version"));
    let within = |ga: &str, floor: &str, ceiling: Option<&str>| {
        let bound = |text| Version::parse(text).expect("a version");
        (get(ga).and_then(|found| Version::parse(found).ok())).is_some_and(|found| {
            found >= bound(floor) && ceiling.is_none_or(|ceiling| found <= bound(ceiling))
        })
    };
    // Surefire fails the run before it resolves any provider, even one
    // among the plugin's dependencies, with a TestNG below its floor.
    let testng_floor = if since_36 { "6.14.3" } else { "4.7" };
    let testng_floor = Version::parse(testng_floor).expect("a version");
    if (get("org.testng:testng").and_then(|found| Version::parse(found).ok()))
        .is_some_and(|found| found < testng_floor)
    {
        return Vec::new();
    }
    // Surefire runs each provider among the plugin's dependencies: the
    // JUnit Platform one as below, another it knows at its own version, and
    // any other through each plugin dependency resolved apart.
    let declared: Vec<&str> = (plugin.dependencies.iter())
        .filter(|dependency| {
            dependency.group_id == SUREFIRE_GROUP && dependency.artifact_id.starts_with("surefire-")
        })
        .map(|dependency| dependency.artifact_id.as_str())
        .collect();
    let declared_platform = declared.contains(&"surefire-junit-platform");
    let known = |artifact_id: &str| {
        !since_36
            && matches!(
                artifact_id,
                "surefire-junit3" | "surefire-junit4" | "surefire-junit47" | "surefire-testng"
            )
    };
    let known_declared: Vec<_> = (declared.iter().copied())
        .filter(|id| known(id))
        .map(provider)
        .collect();
    if !declared.is_empty() && !declared_platform {
        let mut pieces = known_declared;
        if !declared.iter().all(|id| known(id)) {
            pieces
                .extend((plugin.dependencies.iter()).map(|dependency| (dependency.clone(), true)));
        }
        return pieces;
    }
    // Surefire's platform is the plugin realm's `junit-platform-engine`,
    // which only a plugin dependency brings, else the test class path's
    // `junit-platform-commons`. With the former it adds no engine.
    let in_realm = |ga: &str| realm.get(ga).map(String::as_str);
    let plugin_platform = in_realm("org.junit.platform:junit-platform-engine");
    let platform = plugin_platform.or_else(|| get("org.junit.platform:junit-platform-commons"));
    // Surefire 3.6 runs JUnit 4 from 4.12 on.
    let junit4 = within("junit:junit", "4.12", None);
    let testng = get("org.testng:testng").is_some();
    if declared_platform
        || (platform.is_some() && get("org.junit.platform:junit-platform-runner").is_none())
        || (since_36 && (junit4 || testng))
    {
        let mut pieces = vec![provider("surefire-junit-platform")];
        pieces.extend(known_declared);
        // It resolves each of the plugin's dependencies apart.
        pieces.extend((plugin.dependencies.iter()).map(|dependency| (dependency.clone(), true)));
        let declared = |ga: &str| get(ga).is_some() || in_realm(ga).is_some();
        let api = get("org.junit.jupiter:junit-jupiter-api");
        let jupiter = plugin_platform.is_none()
            && api.is_some()
            && get("org.junit.jupiter:junit-jupiter-engine").is_none();
        if let (true, Some(api)) = (jupiter, api) {
            pieces.push((
                piece("org.junit.jupiter", "junit-jupiter-engine", api),
                false,
            ));
        }
        // Without a platform engine among the plugin's dependencies,
        // Surefire 3.6 fails the run here with a JUnit of [4.0,4.11].
        if since_36 && plugin_platform.is_none() && within("junit:junit", "4.0", Some("4.11")) {
            return pieces;
        }
        // Before 3.6 only with the Jupiter engine it adds, at the API's
        // version; from 3.6 for `junit:junit`, at the API's version or the
        // JUnit version Surefire is built with.
        let vintage = if since_36 {
            get("junit:junit").is_some()
                && !declared("org.junit.vintage:junit-vintage-engine")
                && !configuration.is_some_and(junit_off)
        } else {
            jupiter
                && (get("junit:junit").is_some() || get("junit:junit-dep").is_some())
                && get("org.junit.vintage:junit-vintage-engine").is_none()
        };
        if vintage {
            pieces.push((
                piece(
                    "org.junit.vintage",
                    "junit-vintage-engine",
                    api.unwrap_or(SUREFIRE_36_JUNIT),
                ),
                false,
            ));
        }
        if since_36 && testng && !declared("org.junit.support:testng-engine") {
            pieces.push((piece("org.junit.support", "testng-engine", "1.1.0"), false));
        }
        // It aligns the launcher to the platform, from 3.6 to a Jupiter API
        // from 6 on.
        let six = api.filter(|api| {
            since_36
                && Version::parse(api)
                    .is_ok_and(|api| api >= Version::parse("6.0.0").expect("a version"))
        });
        if let Some(launcher) = platform.map(|platform| six.unwrap_or(platform)) {
            pieces.push((
                piece("org.junit.platform", "junit-platform-launcher", launcher),
                false,
            ));
        }
        return pieces;
    }
    if since_36 {
        return Vec::new();
    }
    if testng {
        return vec![provider("surefire-testng")];
    }
    // With no JUnit, the JUnit 3 provider runs plain test classes.
    let junit = get("junit:junit").or_else(|| get("junit:junit-dep"));
    let junit = junit.and_then(|junit| Version::parse(junit).ok());
    let at_least = |floor: &str| {
        (junit.as_ref()).is_some_and(|junit| *junit >= Version::parse(floor).expect("a version"))
    };
    // The run sets `parallel` to text, or sets `groups` or
    // `excludedGroups`.
    let concurrent_or_grouped = configuration.is_some_and(|config| {
        config
            .child_value("parallel")
            .is_some_and(|parallel| !parallel.trim().is_empty())
            || config.child("groups").is_some()
            || config.child("excludedGroups").is_some()
    });
    if at_least("4.7") && concurrent_or_grouped {
        vec![provider("surefire-junit47")]
    } else if at_least("4.0") {
        vec![provider("surefire-junit4")]
    } else {
        vec![provider("surefire-junit3")]
    }
}

/// Whether a run's configuration sets the `junit` property to other than
/// `true`, which stops Surefire 3.6 adding the Vintage engine to it.
fn junit_off(config: &ConfigNode) -> bool {
    (config.child("properties").into_iter())
        .flat_map(|properties| &properties.children)
        .filter_map(|property| match property.name.as_str() {
            "property" if property.child_value("name") == Some("junit") => {
                Some(property.child_value("value"))
            }
            "junit" => Some(property.value.as_deref()),
            _ => None,
        })
        .next_back()
        .flatten()
        .is_some_and(|value| !value.trim().is_empty() && !value.trim().eq_ignore_ascii_case("true"))
}

fn piece(group_id: &str, artifact_id: &str, version: &str) -> Dependency {
    Dependency {
        group_id: group_id.to_string(),
        artifact_id: artifact_id.to_string(),
        version: Some(version.to_string()),
        type_: None,
        classifier: None,
        scope: Some("runtime".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
        system_path_from_project: Default::default(),
        origin: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(plugin: &Plugin, classpath: &[(&str, &str)]) -> Vec<String> {
        summary_in(plugin, classpath, &[])
    }

    /// The pieces for a test class path and a plugin realm.
    fn summary_in(
        plugin: &Plugin,
        classpath: &[(&str, &str)],
        realm: &[(&str, &str)],
    ) -> Vec<String> {
        let map = |entries: &[(&str, &str)]| -> BTreeMap<String, String> {
            (entries.iter())
                .map(|(ga, version)| (ga.to_string(), version.to_string()))
                .collect()
        };
        let version = plugin.version.as_deref().expect("a version");
        provider_pieces(plugin, version, &map(classpath), &map(realm))
            .into_iter()
            .map(|(dependency, plugin_repos)| {
                format!(
                    "{}:{}{}",
                    dependency.artifact_id,
                    dependency.version.unwrap_or_default(),
                    if plugin_repos { " plugin" } else { "" }
                )
            })
            .collect()
    }

    /// The version Surefire takes is the last in Maven's order: the
    /// declared one of the file, the newest where the module declares the
    /// file twice. One under two direct dependencies at one depth may come
    /// under either, one below a direct dependency anywhere under it.
    #[test]
    fn takes_the_test_class_path_in_mavens_order() {
        use rv_lock::{LockEdge, LockModule, LockModulePackage, Scope};
        use rv_maven_types::{ArtifactCoord, Gav};
        let api = "org.junit.jupiter:junit-jupiter-api";
        let dependency =
            |artifact: &str, version: &str, type_: Option<&str>, classifier: Option<&str>| {
                let mut dependency = piece("org.junit.jupiter", artifact, version);
                dependency.type_ = type_.map(str::to_string);
                dependency.classifier = classifier.map(str::to_string);
                dependency
            };
        let coordinate = |artifact: &str, version: &str, classifier: Option<&str>| {
            ArtifactCoord::new("org.junit.jupiter", artifact, version, "jar", classifier)
        };
        let module = |packages: Vec<(ArtifactCoord, bool)>, edges: &[(usize, usize)]| {
            let mut module = LockModule::new("pom.xml", Gav::new("t", "app", "1"), "jar");
            for (coordinate, direct) in packages {
                let scope = direct.then_some(Scope::Test);
                module
                    .packages
                    .push(LockModulePackage::new(coordinate, scope));
            }
            for &(from, to) in edges {
                module
                    .edges
                    .push(LockEdge::new(from, to, Scope::Test, false));
            }
            module
        };
        let types = ArtifactTypes::pending(rv_maven_types::MavenMode::Maven39);
        let sources = || coordinate("junit-jupiter-api", "5.10.0", Some("sources"));
        let main = || coordinate("junit-jupiter-api", "5.11.0", None);
        let declared = [
            dependency("a", "1", None, None),
            dependency("junit-jupiter-api", "5.10.0", None, Some("sources")),
            dependency("b", "1", None, None),
        ];
        // `a` and `b` both reach the API: a range of `b`'s can keep it.
        let packages = vec![
            (coordinate("a", "1", None), true),
            (sources(), true),
            (coordinate("b", "1", None), true),
            (main(), false),
        ];
        let both = module(packages.clone(), &[(0, 3), (2, 3)]);
        let (classpath, unordered) = test_classpath(&both, &declared, &types);
        assert_eq!(unordered[api], ["5.10.0", "5.11.0"]);
        assert_eq!(classpath[api], "5.10.0");
        let under_b = module(packages.clone(), &[(2, 3)]);
        let (classpath, unordered) = test_classpath(&under_b, &declared, &types);
        assert!(unordered.is_empty());
        assert_eq!(classpath[api], "5.11.0");
        // Under either of `a` and `b`, the API comes before sources declared
        // after both.
        let declared = [
            dependency("a", "1", None, None),
            dependency("b", "1", None, None),
            dependency("junit-jupiter-api", "5.10.0", None, Some("sources")),
        ];
        let before = module(
            vec![
                (coordinate("a", "1", None), true),
                (coordinate("b", "1", None), true),
                (sources(), true),
                (main(), false),
            ],
            &[(0, 3), (1, 3)],
        );
        let (classpath, unordered) = test_classpath(&before, &declared, &types);
        assert!(unordered.is_empty());
        assert_eq!(classpath[api], "5.10.0");
        // A range can keep the API's deeper declaration, under `c`.
        let declared = [
            dependency("a", "1", None, None),
            dependency("junit-jupiter-api", "5.10.0", None, Some("sources")),
            dependency("c", "1", None, None),
        ];
        let deeper = module(
            vec![
                (coordinate("a", "1", None), true),
                (sources(), true),
                (coordinate("c", "1", None), true),
                (coordinate("x", "1", None), false),
                (main(), false),
            ],
            &[(0, 4), (2, 3), (3, 4)],
        );
        let (_, unordered) = test_classpath(&deeper, &declared, &types);
        assert_eq!(unordered[api], ["5.10.0", "5.11.0"]);
        // A direct API the module declares at the version it took, or as a
        // range that holds it, stays where it is declared; one declared at
        // another version, which a range below overrode, may come under
        // `params` too.
        let packages = vec![
            (main(), true),
            (sources(), true),
            (coordinate("junit-jupiter-params", "5.11.0", None), true),
        ];
        let reached = module(packages, &[(2, 0)]);
        for (declared_version, ordered) in [("5.11.0", true), ("[5.0,)", true), ("5.9.3", false)] {
            let declared = [
                dependency("junit-jupiter-api", declared_version, None, None),
                dependency("junit-jupiter-api", "5.10.0", None, Some("sources")),
                dependency("junit-jupiter-params", "5.11.0", None, None),
            ];
            let (classpath, unordered) = test_classpath(&reached, &declared, &types);
            assert_eq!(unordered.is_empty(), ordered, "{declared_version}");
            assert_eq!(classpath[api], "5.10.0");
        }
        // A `java-source` 5.9.3 and a `sources` 5.11.0 are one file, of
        // which Maven keeps the newer, declared last.
        let declared = [
            dependency("junit-jupiter-api", "5.9.3", Some("java-source"), None),
            dependency("junit-jupiter-api", "5.10.0", None, None),
            dependency("junit-jupiter-api", "5.11.0", None, Some("sources")),
        ];
        let twice = module(
            vec![
                (coordinate("junit-jupiter-api", "5.10.0", None), true),
                (
                    coordinate("junit-jupiter-api", "5.11.0", Some("sources")),
                    true,
                ),
            ],
            &[],
        );
        let (classpath, unordered) = test_classpath(&twice, &declared, &types);
        assert!(unordered.is_empty());
        assert_eq!(classpath[api], "5.11.0");
        // Of two declarations of the file at the version Maven took, it
        // keeps the first, which a range holding the version can be.
        for first in ["5.11.0", "[5.11.0]", "[5.0,)"] {
            let declared = [
                dependency("junit-jupiter-api", first, Some("java-source"), None),
                dependency("junit-jupiter-api", "5.10.0", None, None),
                dependency("junit-jupiter-api", "5.11.0", None, Some("sources")),
            ];
            let (classpath, unordered) = test_classpath(&twice, &declared, &types);
            assert!(unordered.is_empty(), "{first}");
            assert_eq!(classpath[api], "5.10.0", "{first}");
        }
    }

    /// The JUnit Platform provider adds the Jupiter engine the API needs
    /// and the launcher of the platform on the test class path.
    #[test]
    fn picks_the_junit_platform_provider_as_surefire_does() {
        let surefire = Plugin::new(
            "org.apache.maven.plugins",
            "maven-surefire-plugin",
            Some("3.5.6"),
        );
        assert_eq!(
            summary(
                &surefire,
                &[
                    ("org.junit.platform:junit-platform-commons", "6.0.3"),
                    ("org.junit.jupiter:junit-jupiter-api", "6.0.3"),
                    ("org.junit.jupiter:junit-jupiter-engine", "6.0.3"),
                ]
            ),
            [
                "surefire-junit-platform:3.5.6 plugin",
                "junit-platform-launcher:6.0.3"
            ]
        );
        assert_eq!(
            summary(
                &surefire,
                &[
                    ("org.junit.platform:junit-platform-commons", "1.10.0"),
                    ("org.junit.jupiter:junit-jupiter-api", "5.10.0"),
                    ("junit:junit", "4.13.2"),
                ]
            ),
            [
                "surefire-junit-platform:3.5.6 plugin",
                "junit-jupiter-engine:5.10.0",
                "junit-vintage-engine:5.10.0",
                "junit-platform-launcher:1.10.0"
            ]
        );
        assert_eq!(
            summary(&surefire, &[("junit:junit", "4.13.2")]),
            ["surefire-junit4:3.5.6 plugin"]
        );
        assert_eq!(
            summary(
                &surefire,
                &[("org.testng:testng", "7.10.2"), ("junit:junit", "4.13.2")]
            ),
            ["surefire-testng:3.5.6 plugin"]
        );
        assert_eq!(summary(&surefire, &[]), ["surefire-junit3:3.5.6 plugin"]);
    }

    /// With the Jupiter engine on the test class path, no Vintage engine;
    /// with a plugin dependency that brings `junit-platform-engine` into
    /// the plugin realm, at the version Surefire's dependency management
    /// gives it, those are resolved, no engine is added and the launcher
    /// takes the realm's platform; `parallel` in an execution's
    /// configuration picks the JUnit 4.7 provider.
    #[test]
    fn follows_surefire_for_engines_and_execution_configuration() {
        let mut surefire = Plugin::new(
            "org.apache.maven.plugins",
            "maven-surefire-plugin",
            Some("3.5.6"),
        );
        let platform = [
            ("org.junit.platform:junit-platform-commons", "1.10.0"),
            ("org.junit.jupiter:junit-jupiter-api", "5.10.0"),
            ("org.junit.jupiter:junit-jupiter-engine", "5.10.0"),
            ("junit:junit", "4.13.2"),
        ];
        assert_eq!(
            summary(&surefire, &platform),
            [
                "surefire-junit-platform:3.5.6 plugin",
                "junit-platform-launcher:1.10.0"
            ]
        );
        let mut engine = piece("org.junit.jupiter", "junit-jupiter-engine", "5.11.0");
        engine.scope = None;
        surefire.dependencies.push(engine);
        let realm = [
            ("org.junit.jupiter:junit-jupiter-engine", "5.11.0"),
            ("org.junit.platform:junit-platform-engine", "1.9.3"),
        ];
        assert_eq!(
            summary_in(&surefire, &platform[..2], &realm),
            [
                "surefire-junit-platform:3.5.6 plugin",
                "junit-jupiter-engine:5.11.0 plugin",
                "junit-platform-launcher:1.9.3"
            ]
        );
        surefire.dependencies.clear();
        let mut parallel = rv_maven_model::ConfigNode::default();
        parallel.name = "parallel".to_string();
        parallel.value = Some("classes".to_string());
        let mut configuration = rv_maven_model::ConfigNode::default();
        configuration.children.push(parallel);
        let mut execution =
            rv_maven_model::PluginExecution::new("default-test", Some("test"), &["test"]);
        execution.configuration = Some(configuration);
        surefire.executions.push(execution);
        assert_eq!(
            summary(&surefire, &[("junit:junit", "4.13.2")]),
            ["surefire-junit47:3.5.6 plugin"]
        );
    }

    /// Each execution that runs the tests picks its provider with its own
    /// configuration: one with `parallel` the JUnit 4.7 provider, the
    /// default one JUnit 4's, and Failsafe's `verify` none.
    #[test]
    fn picks_a_provider_for_each_execution() {
        let configured = |name: &str, value: &str| {
            let mut child = rv_maven_model::ConfigNode::default();
            child.name = name.to_string();
            child.value = Some(value.to_string());
            let mut configuration = rv_maven_model::ConfigNode::default();
            configuration.children.push(child);
            configuration
        };
        let mut surefire = Plugin::new(
            "org.apache.maven.plugins",
            "maven-surefire-plugin",
            Some("3.2.5"),
        );
        let mut parallel =
            rv_maven_model::PluginExecution::new("parallel-extra", Some("test"), &["test"]);
        parallel.configuration = Some(configured("parallel", "methods"));
        surefire.executions = vec![
            rv_maven_model::PluginExecution::new("default-test", Some("test"), &["test"]),
            parallel,
        ];
        assert_eq!(
            summary(&surefire, &[("junit:junit", "4.13.2")]),
            [
                "surefire-junit4:3.2.5 plugin",
                "surefire-junit47:3.2.5 plugin"
            ]
        );
        let mut failsafe = Plugin::new(
            "org.apache.maven.plugins",
            "maven-failsafe-plugin",
            Some("3.2.5"),
        );
        let mut tests = rv_maven_model::PluginExecution::new("it", None, &["integration-test"]);
        tests.configuration = Some(configured("groups", "slow"));
        let mut verify = rv_maven_model::PluginExecution::new("check", None, &["verify"]);
        verify.configuration = Some(configured("skip", "false"));
        failsafe.executions = vec![tests, verify];
        assert_eq!(
            summary(&failsafe, &[("junit:junit", "4.13.2")]),
            ["surefire-junit47:3.2.5 plugin"]
        );
    }

    /// A JUnit plugin dependency that brings no `junit-platform-engine`
    /// into the plugin realm, such as `junit-jupiter-params`, leaves the
    /// Jupiter engine to Surefire, before 3.6 and from it.
    #[test]
    fn adds_the_jupiter_engine_beside_a_plugin_dependency_without_the_platform_engine() {
        let classpath = [
            ("org.junit.platform:junit-platform-commons", "1.10.2"),
            ("org.junit.jupiter:junit-jupiter-api", "5.10.2"),
        ];
        let realm = [
            ("org.apache.maven.surefire:maven-surefire-common", "3.2.5"),
            ("org.junit.jupiter:junit-jupiter-params", "5.10.2"),
            ("org.junit.jupiter:junit-jupiter-api", "5.9.3"),
            ("org.junit.platform:junit-platform-commons", "1.9.3"),
        ];
        for version in ["3.2.5", "3.6.0"] {
            let mut surefire = Plugin::new(
                "org.apache.maven.plugins",
                "maven-surefire-plugin",
                Some(version),
            );
            let mut params = piece("org.junit.jupiter", "junit-jupiter-params", "5.10.2");
            params.scope = None;
            surefire.dependencies.push(params);
            assert_eq!(
                summary_in(&surefire, &classpath, &realm),
                [
                    format!("surefire-junit-platform:{version} plugin"),
                    "junit-jupiter-params:5.10.2 plugin".to_string(),
                    "junit-jupiter-engine:5.10.2".to_string(),
                    "junit-platform-launcher:1.10.2".to_string(),
                ]
            );
        }
    }

    /// Surefire and Failsafe 3.6 run JUnit 4 and TestNG on the JUnit
    /// Platform: Vintage at the Jupiter API's version or 5.14.4, the TestNG
    /// engine 1.1.0, and a launcher at a Jupiter API from 6 on.
    #[test]
    fn picks_the_junit_platform_for_every_framework_from_3_6() {
        let failsafe = Plugin::new(
            "org.apache.maven.plugins",
            "maven-failsafe-plugin",
            Some("3.6.1"),
        );
        assert_eq!(
            summary(&failsafe, &[("junit:junit", "4.13.2")]),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-vintage-engine:5.14.4"
            ]
        );
        assert_eq!(
            summary(
                &failsafe,
                &[
                    ("org.junit.platform:junit-platform-commons", "6.0.1"),
                    ("org.junit.jupiter:junit-jupiter-api", "6.1.3"),
                    ("org.junit.jupiter:junit-jupiter-engine", "6.1.3"),
                    ("junit:junit", "4.13.2"),
                ]
            ),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-vintage-engine:6.1.3",
                "junit-platform-launcher:6.1.3"
            ]
        );
        assert_eq!(
            summary(&failsafe, &[("org.testng:testng", "7.10.2")]),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "testng-engine:1.1.0"
            ]
        );
        assert!(summary(&failsafe, &[("junit:junit", "3.8.2")]).is_empty());
        // Surefire fails the run with a JUnit 4 below 4.12 after it resolved
        // the provider and the Jupiter engine, and with a TestNG below
        // 6.14.3 before it resolved any.
        assert_eq!(
            summary(
                &failsafe,
                &[
                    ("org.junit.platform:junit-platform-commons", "1.10.2"),
                    ("org.junit.jupiter:junit-jupiter-api", "5.10.2"),
                    ("junit:junit", "4.11"),
                ]
            ),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-jupiter-engine:5.10.2"
            ]
        );
        assert_eq!(
            summary(&failsafe, &[("junit:junit", "4.12")]),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-vintage-engine:5.14.4"
            ]
        );
        assert!(summary(&failsafe, &[("org.testng:testng", "6.14.2")]).is_empty());
        assert!(
            summary(
                &failsafe,
                &[("org.testng:testng", "6.11"), ("junit:junit", "4.13.2")]
            )
            .is_empty()
        );
        assert_eq!(
            summary(&failsafe, &[("org.testng:testng", "6.14.3")]),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "testng-engine:1.1.0"
            ]
        );
        // Below 4.12 JUnit alone finds no provider.
        assert!(summary(&failsafe, &[("junit:junit", "4.11")]).is_empty());
        assert!(summary(&failsafe, &[("junit:junit", "4.12-beta-1")]).is_empty());
        assert_eq!(
            summary(
                &failsafe,
                &[("org.testng:testng", "7.10.2"), ("junit:junit", "4.11")]
            ),
            ["surefire-junit-platform:3.6.1 plugin"]
        );
        assert_eq!(
            summary(
                &failsafe,
                &[
                    ("org.junit.platform:junit-platform-commons", "1.10.2"),
                    ("junit:junit", "4.12-beta-1"),
                ]
            ),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-vintage-engine:5.14.4",
                "junit-platform-launcher:1.10.2"
            ]
        );
        // A platform engine among the plugin's dependencies skips the JUnit
        // check.
        let mut engine = failsafe.clone();
        let mut platform_engine = piece("org.junit.platform", "junit-platform-engine", "1.14.4");
        platform_engine.scope = None;
        engine.dependencies.push(platform_engine);
        assert_eq!(
            summary_in(
                &engine,
                &[("junit:junit", "4.11")],
                &[("org.junit.platform:junit-platform-engine", "1.14.4")]
            ),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-platform-engine:1.14.4 plugin",
                "junit-vintage-engine:5.14.4",
                "junit-platform-launcher:1.14.4"
            ]
        );
        // The TestNG floor holds for a provider among the plugin's
        // dependencies too, and below 3.6 at 4.7.
        let mut declared = failsafe.clone();
        let mut junit4 = piece(SUREFIRE_GROUP, "surefire-junit4", "3.6.1");
        junit4.scope = None;
        declared.dependencies.push(junit4);
        assert!(summary(&declared, &[("org.testng:testng", "6.11")]).is_empty());
        let older = Plugin::new(
            "org.apache.maven.plugins",
            "maven-surefire-plugin",
            Some("3.5.6"),
        );
        assert!(summary(&older, &[("org.testng:testng", "4.6")]).is_empty());
        assert_eq!(
            summary(&older, &[("org.testng:testng", "6.11")]),
            ["surefire-testng:3.5.6 plugin"]
        );
        let mut vintage = piece("org.junit.vintage", "junit-vintage-engine", "5.10.0");
        vintage.scope = None;
        let mut surefire = Plugin::new(
            "org.apache.maven.plugins",
            "maven-surefire-plugin",
            Some("3.6.1"),
        );
        surefire.dependencies.push(vintage);
        let realm = [
            ("org.junit.vintage:junit-vintage-engine", "5.10.0"),
            ("org.junit.platform:junit-platform-engine", "1.10.0"),
        ];
        assert_eq!(
            summary_in(&surefire, &[("junit:junit", "4.13.2")], &realm),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-vintage-engine:5.10.0 plugin",
                "junit-platform-launcher:1.10.0"
            ]
        );
        surefire.dependencies.clear();
        let mut junit = rv_maven_model::ConfigNode::default();
        junit.name = "junit".to_string();
        junit.value = Some("false".to_string());
        let mut properties = rv_maven_model::ConfigNode::default();
        properties.name = "properties".to_string();
        properties.children.push(junit);
        let mut configuration = rv_maven_model::ConfigNode::default();
        configuration.children.push(properties);
        surefire.configuration = Some(configuration.clone());
        let mut execution =
            rv_maven_model::PluginExecution::new("default-test", Some("test"), &["test"]);
        execution.configuration = Some(configuration);
        surefire.executions.push(execution);
        assert_eq!(
            summary(
                &surefire,
                &[("org.testng:testng", "7.10.2"), ("junit:junit", "4.13.2")]
            ),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "testng-engine:1.1.0"
            ]
        );
        // An execution that turns it back on gets the Vintage engine.
        execution_properties(&mut surefire).children[0].value = Some("true".to_string());
        assert_eq!(
            summary(
                &surefire,
                &[("org.testng:testng", "7.10.2"), ("junit:junit", "4.13.2")]
            ),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-vintage-engine:5.14.4",
                "testng-engine:1.1.0"
            ]
        );
        // So does one whose last `junit` is empty.
        let properties = &mut execution_properties(&mut surefire).children;
        properties[0].value = Some("false".to_string());
        let mut empty = properties[0].clone();
        empty.value = None;
        properties.push(empty);
        assert_eq!(
            summary(
                &surefire,
                &[("org.testng:testng", "7.10.2"), ("junit:junit", "4.13.2")]
            ),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "junit-vintage-engine:5.14.4",
                "testng-engine:1.1.0"
            ]
        );
    }

    /// A provider among the plugin's dependencies: the JUnit Platform one
    /// still gets the engines and launcher Surefire adds, another known one
    /// resolves at the plugin's version before 3.6, and from 3.6, where
    /// Surefire knows it no more, each plugin dependency resolves apart.
    #[test]
    fn follows_surefire_for_a_provider_among_the_plugin_dependencies() {
        let classpath = [
            ("org.junit.platform:junit-platform-commons", "6.1.3"),
            ("org.junit.jupiter:junit-jupiter-api", "6.1.3"),
            ("junit:junit", "4.13.2"),
        ];
        let with = |version: &str, artifact_id: &str, provider_version: &str| {
            let mut surefire = Plugin::new(
                "org.apache.maven.plugins",
                "maven-surefire-plugin",
                Some(version),
            );
            let mut provider = piece(SUREFIRE_GROUP, artifact_id, provider_version);
            provider.scope = None;
            surefire.dependencies.push(provider);
            surefire
        };
        // The declared provider brings `junit-platform-engine` into the
        // realm, which sets the platform.
        let realm = |platform| [("org.junit.platform:junit-platform-engine", platform)];
        assert_eq!(
            summary_in(
                &with("3.6.1", "surefire-junit-platform", "3.6.1"),
                &classpath,
                &realm("1.14.4")
            ),
            [
                "surefire-junit-platform:3.6.1 plugin",
                "surefire-junit-platform:3.6.1 plugin",
                "junit-vintage-engine:6.1.3",
                "junit-platform-launcher:6.1.3"
            ]
        );
        assert_eq!(
            summary_in(
                &with("3.5.6", "surefire-junit-platform", "3.5.6"),
                &classpath,
                &realm("1.13.4")
            ),
            [
                "surefire-junit-platform:3.5.6 plugin",
                "surefire-junit-platform:3.5.6 plugin",
                "junit-platform-launcher:1.13.4"
            ]
        );
        assert_eq!(
            summary(&with("3.5.6", "surefire-junit47", "3.2.5"), &classpath),
            ["surefire-junit47:3.5.6 plugin"]
        );
        assert_eq!(
            summary(&with("3.6.1", "surefire-junit47", "3.5.6"), &classpath),
            ["surefire-junit47:3.5.6 plugin"]
        );
        let mut both = with("3.5.6", "surefire-junit-platform", "3.5.6");
        let mut junit47 = piece(SUREFIRE_GROUP, "surefire-junit47", "3.2.5");
        junit47.scope = None;
        let mut engine = piece("org.junit.platform", "junit-platform-engine", "1.14.4");
        engine.scope = None;
        both.dependencies.extend([junit47, engine]);
        assert_eq!(
            summary_in(&both, &classpath, &realm("1.14.4")),
            [
                "surefire-junit-platform:3.5.6 plugin",
                "surefire-junit47:3.5.6 plugin",
                "surefire-junit-platform:3.5.6 plugin",
                "surefire-junit47:3.2.5 plugin",
                "junit-platform-engine:1.14.4 plugin",
                "junit-platform-launcher:1.14.4"
            ]
        );
    }

    fn execution_properties(plugin: &mut Plugin) -> &mut rv_maven_model::ConfigNode {
        let configuration = plugin.executions[0].configuration.as_mut().expect("set");
        &mut configuration.children[0]
    }
}
