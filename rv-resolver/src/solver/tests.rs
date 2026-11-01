use std::collections::HashMap;
use std::sync::Arc;

use super::{Backend, Management, ResolvedProject, ResolvedVersion, Solver, SolverRoot};
use crate::context::RepoContext;
use crate::error::ResolveError;
use crate::graph::Graph;
use rv_maven_model::{Dependency, Exclusion, Project, Relocation, Scope};
use rv_maven_types::{Coord, Version, VersionReq};

#[derive(Default)]
struct MockBackend {
    fetches: std::sync::Mutex<Vec<String>>,
    prefetches: std::sync::Mutex<Vec<String>>,
    listings: std::sync::Mutex<Vec<String>>,
    projects: HashMap<String, Project>,
    versions: HashMap<String, Vec<Version>>,
    project_repos: HashMap<String, &'static str>,
}

impl MockBackend {
    fn with_project(mut self, coord: &Coord, deps: Vec<Dependency>) -> Self {
        let mut project = Project::new(
            &coord.group_id,
            &coord.artifact_id,
            &coord.version.to_string(),
        );
        project.dependencies = deps;
        self.projects.insert(coord.to_string(), project);
        self
    }

    fn with_relocated_project(
        mut self,
        coord: &Coord,
        relocation: Relocation,
        deps: Vec<Dependency>,
    ) -> Self {
        self = self.with_project(coord, deps);
        self.projects
            .get_mut(&coord.to_string())
            .unwrap()
            .relocation = Some(relocation);
        self
    }

    fn with_versions(mut self, group_id: &str, artifact_id: &str, versions: Vec<&str>) -> Self {
        let parsed = versions
            .into_iter()
            .map(|v| Version::parse(v).unwrap())
            .collect();
        self.versions
            .insert(format!("{group_id}:{artifact_id}"), parsed);
        self
    }
}

const SNAPSHOT_BUILDS: [&str; 2] = ["20261011.010101-1", "20261012.010101-2"];

impl Backend for MockBackend {
    fn prefetch_project(&self, coord: &Coord, _repos: &RepoContext) {
        self.prefetches.lock().unwrap().push(coord.to_string());
    }

    fn prefetch_range(
        &self,
        group_id: &str,
        artifact_id: &str,
        req: &VersionReq,
        _repos: &RepoContext,
    ) {
        let range = format!("{group_id}:{artifact_id}:{req}");
        self.listings.lock().unwrap().push(range);
    }

    fn resolve_snapshot_version<'a>(
        &'a self,
        coord: &'a Coord,
        _repos: &'a RepoContext,
    ) -> super::BoxFuture<'a, super::Result<ResolvedVersion>> {
        Box::pin(async move {
            let build = coord
                .version
                .as_str()
                .strip_suffix("SNAPSHOT")
                .and_then(|base| {
                    SNAPSHOT_BUILDS
                        .iter()
                        .rev()
                        .map(|build| Coord {
                            version: Version::parse(&format!("{base}{build}")).unwrap(),
                            ..coord.clone()
                        })
                        .find(|build| self.projects.contains_key(&build.to_string()))
                });
            // The metadata comes from the repository serving the build.
            let repo = build
                .as_ref()
                .and_then(|build| self.project_repos.get(&build.to_string()))
                .map(|&repo| crate::graph::RepoRef {
                    id: None,
                    url: Arc::from(repo),
                });
            Ok(ResolvedVersion {
                version: build.map_or_else(|| coord.version.clone(), |build| build.version),
                repo,
            })
        })
    }

    fn resolve_version<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
        _repos: &'a RepoContext,
    ) -> super::BoxFuture<'a, super::Result<ResolvedVersion>> {
        Box::pin(async move {
            let key = format!("{group_id}:{artifact_id}");
            let versions =
                self.versions
                    .get(&key)
                    .ok_or_else(|| ResolveError::ArtifactNotFound {
                        dropped_repos: Vec::new(),
                        coord: key.clone(),
                        searched: Vec::new(),
                        classifier_like: None,
                    })?;
            let dynamic = match req {
                VersionReq::Exact(version) | VersionReq::Soft(version) => {
                    crate::util::parse_dynamic_version_token(version.as_str())
                }
                VersionReq::Ranges(_) => None,
            };
            let version = versions
                .iter()
                .filter(|version| match dynamic {
                    Some(token) => token.admits(version.as_str()),
                    None => req.matches(version),
                })
                .max()
                .cloned()
                .ok_or_else(|| ResolveError::VersionNotFound {
                    coord: key,
                    requirement: req.to_string(),
                })?;
            Ok(ResolvedVersion {
                version,
                repo: None,
            })
        })
    }

    fn resolve_versions<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
        repos: &'a RepoContext,
    ) -> super::BoxFuture<'a, super::Result<Vec<ResolvedVersion>>> {
        Box::pin(async move {
            self.resolve_version(group_id, artifact_id, req, repos)
                .await?;
            let mut versions: Vec<_> = self.versions[&format!("{group_id}:{artifact_id}")]
                .iter()
                .filter(|version| req.matches(version))
                .map(|version| ResolvedVersion {
                    version: version.clone(),
                    repo: None,
                })
                .collect();
            Version::sort_by_key(&mut versions, |resolved| &resolved.version);
            Ok(versions)
        })
    }

    fn fetch_project<'a>(
        &'a self,
        coord: &'a Coord,
        _resolve_snapshot_pom: bool,
        _repos: &'a RepoContext,
    ) -> super::BoxFuture<'a, super::Result<ResolvedProject>> {
        Box::pin(async move {
            let key = coord.to_string();
            self.fetches.lock().unwrap().push(key.clone());
            let project =
                self.projects
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| ResolveError::ArtifactNotFound {
                        dropped_repos: Vec::new(),
                        coord: key.clone(),
                        searched: Vec::new(),
                        classifier_like: None,
                    })?;
            Ok(ResolvedProject {
                project: Arc::new(project),
                repo_url: Some(Arc::from(
                    self.project_repos
                        .get(&key)
                        .copied()
                        .unwrap_or("mock://repo"),
                )),
                workspace_module: None,
            })
        })
    }
}

fn dep(group_id: &str, artifact_id: &str, version: &str) -> Dependency {
    Dependency {
        group_id: group_id.to_string(),
        artifact_id: artifact_id.to_string(),
        version: Some(version.to_string()),
        type_: None,
        classifier: None,
        scope: Some("compile".to_string()),
        optional: None,
        exclusions: Vec::new(),
        system_path: None,
    }
}

fn coord(s: &str) -> Coord {
    Coord::parse(s).unwrap()
}

fn find_version(graph: &Graph, group_id: &str, artifact_id: &str) -> Option<String> {
    let reachable = graph.reachable();
    graph
        .node_indices()
        .filter(|idx| reachable.contains(idx))
        .filter_map(|idx| graph.node(idx))
        .find(|node| {
            node.coord.group_id.as_str() == group_id
                && node.coord.artifact_id.as_str() == artifact_id
        })
        .map(|node| node.coord.version.to_string())
}

/// Root management of `group:artifact` to `version`.
fn managed(group: &str, artifact: &str, version: &str) -> Management {
    let entry = Dependency {
        scope: None,
        ..dep(group, artifact, version)
    };
    Management::new(vec![entry])
}

const G: &str = "g";

/// `[group:]artifact:version`, `_` standing for an absent part.
fn gav(text: &str) -> [Option<String>; 3] {
    let parts: Vec<&str> = text.split(':').collect();
    let parts = match parts.as_slice() {
        [artifact, version] => [G, artifact, version],
        [group, artifact, version] => [*group, artifact, version],
        _ => panic!("bad coordinate {text}"),
    };
    parts.map(|part| (part != "_").then(|| part.to_string()))
}

/// A dependency written `[group:]artifact:version` and then any of
/// `@scope` (`@-` for none, compile otherwise), `?` (optional),
/// `!artifact` or `!group:artifact` (an exclusion), `#type`, `~classifier`
/// and `=systemPath`.
fn parse_dep(token: &str) -> Dependency {
    const MARKERS: [char; 6] = ['@', '?', '!', '#', '~', '='];
    let split = token.find(MARKERS).unwrap_or(token.len());
    let (coordinate, mut rest) = token.split_at(split);
    let [group, artifact, version] = gav(coordinate);
    let mut dependency = Dependency {
        version,
        ..dep(&group.unwrap(), &artifact.unwrap(), "")
    };
    while let Some(marker) = rest.chars().next() {
        let end = rest[1..].find(MARKERS).map_or(rest.len(), |end| end + 1);
        let value = rest[1..end].to_string();
        match marker {
            '@' => dependency.scope = (value != "-").then_some(value),
            '?' => dependency.optional = Some("true".to_string()),
            '!' => {
                let (group_id, artifact_id) = value.split_once(':').unwrap_or((G, &value));
                dependency.exclusions.push(Exclusion {
                    group_id: group_id.to_string(),
                    artifact_id: artifact_id.to_string(),
                });
            }
            '#' => dependency.type_ = Some(value),
            '~' => dependency.classifier = Some(value),
            _ => dependency.system_path = Some(value),
        }
        rest = &rest[end..];
    }
    dependency
}

fn parse_deps(text: &str) -> Vec<Dependency> {
    text.split_whitespace().map(parse_dep).collect()
}

fn management(tokens: &str) -> Management {
    let entries: Vec<_> = tokens
        .split_whitespace()
        .map(|token| Dependency {
            scope: parse_dep(token).scope.filter(|_| token.contains('@')),
            ..parse_dep(token)
        })
        .collect();
    Management::new(entries)
}

/// A backend from one line per project: `coordinate[~classifier]`, then
/// `> dependencies` and `| managed dependencies`, or `=> group:artifact:version` for a relocation. `versions
/// [group:]artifact v...` lists versions; otherwise those of the projects.
fn backend(lines: &[&str]) -> MockBackend {
    let mut backend = MockBackend::default();
    let mut listed = HashMap::<String, Vec<Version>>::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("versions ") {
            let mut words = rest.split_whitespace();
            let [group, artifact, _] = gav(&format!("{}:_", words.next().unwrap()));
            let key = format!("{}:{}", group.unwrap(), artifact.unwrap());
            let versions = words.map(|v| Version::parse(v).unwrap()).collect();
            backend.versions.insert(key, versions);
            continue;
        }
        let (head, relocation) = match line.split_once("=>") {
            Some((head, target)) => {
                let [group_id, artifact_id, version] = gav(target.trim());
                let relocation = Relocation {
                    group_id,
                    artifact_id,
                    version,
                    message: None,
                };
                (head, Some(relocation))
            }
            None => (*line, None),
        };
        let (head, managed) = head.split_once('|').unwrap_or((head, ""));
        let (head, deps) = head.split_once('>').unwrap_or((head, ""));
        let head = parse_dep(head.trim());
        let version = head.version.as_deref().unwrap();
        let coord = Coord {
            group_id: head.group_id.as_str().into(),
            artifact_id: head.artifact_id.as_str().into(),
            version: Version::parse(version).unwrap(),
            packaging: None,
            classifier: head.classifier,
        };
        let mut project = Project::new(&head.group_id, &head.artifact_id, version);
        project.dependencies = parse_deps(deps);
        project.dependency_management.dependencies = parse_deps(managed);
        project.relocation = relocation;
        listed
            .entry(format!("{}:{}", head.group_id, head.artifact_id))
            .or_default()
            .push(coord.version.clone());
        backend.projects.insert(coord.to_string(), project);
    }
    for (key, versions) in listed {
        backend.versions.entry(key).or_insert(versions);
    }
    backend
}

fn render(result: Result<Graph, ResolveError>) -> String {
    let graph = match result {
        Ok(graph) => graph,
        Err(err) => {
            let err = err.cause();
            let debug = format!("{err:?}");
            let variant = debug.split([' ', '(', '{']).next().unwrap_or_default();
            return format!("ERR {variant}: {err}");
        }
    };
    let mut seen = vec![graph.root()];
    let mut queue = vec![graph.root()];
    while let Some(node) = queue.pop() {
        for (_, target, _) in graph.edges(node) {
            if !seen.contains(&target) {
                seen.push(target);
                queue.push(target);
            }
        }
    }
    let mut labels: Vec<String> = seen[1..]
        .iter()
        .map(|idx| {
            let node = graph.node(*idx).unwrap();
            let c = &node.coord;
            let mut label = match c.group_id.as_str() {
                G => format!("{}:{}", c.artifact_id, c.version),
                group => format!("{group}:{}:{}", c.artifact_id, c.version),
            };
            for (marker, part) in [('#', &c.packaging), ('~', &c.classifier)] {
                if let Some(part) = part {
                    label.push_str(&format!("{marker}{part}"));
                }
            }
            if node.scope != Scope::Compile {
                label.push_str(&format!("@{}", node.scope));
            }
            if let Some(path) = &node.system_path {
                label.push_str(&format!("={path}"));
            }
            if node.local {
                label.push_str("+local");
            }
            label
        })
        .collect();
    labels.sort();
    labels.join(" ")
}

/// Root dependencies written as [`parse_dep`] reads them, after an optional
/// `@scope` of the root itself.
fn root(text: &str) -> SolverRoot {
    let (scope, deps) = match text.strip_prefix('@') {
        Some(rest) => {
            let (scope, deps) = rest.split_once(' ').unwrap();
            (Scope::parse(scope), deps)
        }
        None => (Scope::Compile, text),
    };
    SolverRoot {
        coord: coord("g:root:1.0"),
        dependencies: parse_deps(deps),
        scope,
    }
}

/// `(name, projects, root, root management, expected)`.
type Case<'a> = (&'a str, &'a [&'a str], &'a str, &'a str, &'a str);

async fn check(cases: &[Case<'_>]) {
    for (name, projects, root_deps, managed, expected) in cases {
        let backend = backend(projects);
        let solved = Solver::new(&backend)
            .with_management(management(managed))
            .solve(root(root_deps))
            .await;
        let actual = render(solved);
        assert!(
            actual.starts_with(expected) && (expected.starts_with("ERR") || actual == *expected),
            "{name}: got {actual}, expected {expected}"
        );
    }
}

#[tokio::test]
async fn nearest_wins_mediation() {
    let siblings: &[&str] = &["a:1 > c:1", "b:1 > c:2", "c:1", "c:2"];
    let deeper: &[&str] = &["a:1 > c:1", "b:1 > d:1", "d:1 > c:3", "c:1", "c:3"];
    let pins: &[&str] = &["a:1.5", "a:2.5", "b:1 > a:2.5"];
    #[rustfmt::skip]
    let cases: &[Case<'_>] = &[
        ("ties go to the first declared", siblings, "a:1 b:1", "", "a:1 b:1 c:1"),
        ("the shallower wins", deeper, "a:1 b:1", "", "a:1 b:1 c:1 d:1"),
        ("first declared wins in a diamond",
            &["a:1 > c:1", "b:1 > d:1", "c:1 > e:1", "d:1 > e:2", "e:1", "e:2"],
            "a:1 b:1", "", "a:1 b:1 c:1 d:1 e:1"),
        ("a direct declaration beats deeper ones",
            &["a:1 > b:1 o:bar:2.0", "b:1 > o:bar:3.0", "o:bar:1.0", "o:bar:2.0", "o:bar:3.0"],
            "o:bar:1.0 a:1", "", "a:1 b:1 o:bar:1.0"),
        ("a nearer version outside a deeper hard range loses",
            &["a:1 > x:1.0", "b:1 > c:1", "c:1 > x:[2.0,3.0)", "x:1.0", "x:2.5", "x:2.0",
                "versions x 1.0 2.0 2.5 3.0"],
            "a:1 b:1", "", "a:1 b:1 c:1 x:2.5"),
        ("a nearer version inside a deeper range stays",
            &["b:1 > c:1", "c:1 > x:[2.0,3.0)", "x:2.0", "x:2.5"],
            "x:2.0 b:1", "", "b:1 c:1 x:2.0"),
        ("disjoint hard ranges conflict",
            &["b:1 > c:1", "c:1 > x:[2.0,3.0)", "d:1 > e:1", "e:1 > x:[1.0,1.8)", "x:1.5", "x:2.5"],
            "b:1 d:1", "", "ERR VersionConflict"),
        ("a nearer hard pin outside a deeper range conflicts",
            &["a:1.5", "a:2.5", "a:2.0", "b:1 > a:[2,3)"],
            "a:[1.5] b:1", "", "ERR VersionConflict"),
        ("a nearer soft version inside a deeper range succeeds",
            &["a:2.5", "b:1 > a:[2,3)"], "a:2.5 b:1", "", "a:2.5 b:1"),
        ("a losing hard pin conflicts",
            &["a:1.5", "a:2.5", "b:1 > a:[2.5]"], "a:[1.5] b:1", "", "ERR VersionConflict"),
        ("a losing soft pin does not", pins, "a:1.5 b:1", "", "a:1.5 b:1"),
        ("a two-bound pin is the version as written",
            &["x:1.0", "x:1.0.0", "versions x 1.0.0"], "x:[1.0,1.0]", "", "x:1.0"),
        ("a pin takes its lower bound's spelling",
            &["x:1.0", "x:1.0.0", "versions x 1.0"], "x:[1.0.0,1.0]", "", "x:1.0.0"),
        ("a two-bound pin mediates as the short form",
            &["a:1 > x:[1,2]", "c:1 > x:[1,1]", "x:2 > d:1", "d:1", "x:1 => g:y:1", "y:1"],
            "a:1 c:1", "", "a:1 c:1 y:1"),
        ("cycles are cut", &["a:1 > b:1", "b:1 > a:1"], "a:1", "", "a:1 b:1"),
        ("classifiers are distinct nodes", &["lib:1.0", "lib:1.0~tests"],
            "lib:1.0 lib:1.0~tests", "", "lib:1.0 lib:1.0~tests"),
        ("a test-jar is the tests classifier", &["lib:1.0~tests"],
            "lib:1.0#test-jar", "", "lib:1.0~tests"),
        ("a test-jar keeps an explicit classifier", &["lib:1.0~custom"],
            "lib:1.0#test-jar~custom", "", "lib:1.0~custom"),
        ("a range takes its highest match", &["d:1.5", "d:1.0", "versions d 1.0 1.5 2.0"],
            "d:[1.0,2.0)", "", "d:1.5"),
        ("RELEASE skips snapshots",
            &["dyn:1.0.5", "dyn:1.1.0-SNAPSHOT", "versions dyn 1.0.0 1.0.5 1.1.0-SNAPSHOT"],
            "dyn:RELEASE", "", "dyn:1.0.5"),
        ("Gradle's latest.release is refused", &["dyn:1.0.5", "versions dyn 1.0.5"],
            "dyn:latest.release", "", "ERR InvalidVersionRequirement: invalid version requirement for g:dyn"),
        ("LATEST takes snapshots",
            &["dyn:1.0.5", "dyn:1.1.0-SNAPSHOT", "versions dyn 1.0.0 1.0.5 1.1.0-SNAPSHOT"],
            "dyn:LATEST", "", "dyn:1.1.0-SNAPSHOT"),
        ("Gradle's dynamic syntax is refused", &["dyn:1.0.5", "versions dyn 1.0.5"],
            "dyn:1.+", "", "ERR InvalidVersionRequirement: invalid version requirement for g:dyn"),
        ("a trailing plus is refused", &["dyn:1.0.5"],
            "dyn:+", "", "ERR InvalidVersionRequirement: invalid version requirement for g:dyn"),
        ("an inner plus is part of the version", &["dyn:1.0+b1"], "dyn:1.0+b1", "", "dyn:1.0+b1"),
        ("a version with an undefined property names it and its POM", &["a:1 > x:${undefined}"],
            "a:1", "", "ERR UndefinedProperty: property undefined is not defined: g:a:1 declares g:x:${undefined}"),
        ("a managed version with an undefined property names the root", &["a:1 > x:1"],
            "a:1", "x:${undefined}", "ERR UndefinedProperty: property undefined is not defined: g:root:1.0 declares g:x:${undefined}"),
        ("a managed version names the root though the declared one is undefined too",
            &["a:1 > x:${theirs}"], "a:1", "x:${ours}",
            "ERR UndefinedProperty: property ours is not defined: g:root:1.0 declares g:x:${ours}"),
        ("a group with an undefined property names it", &["a:1 > ${undefined}:x:1"],
            "a:1", "", "ERR UndefinedProperty: property undefined is not defined: g:a:1 declares ${undefined}:x:1"),
        ("a nested undefined property names the inner one", &["a:1 > x:${outer.${inner}}"],
            "a:1", "", "ERR UndefinedProperty: property inner is not defined: g:a:1 declares g:x:${outer.${inner}}"),
        ("a version-less dependency needs management", &[], "lib:_", "",
            "ERR MissingVersion"),
        ("a system dependency needs a version", &[], "native:_@system=/opt/n.jar", "",
            "ERR MissingVersion"),
        ("a system dependency resolves locally", &[], "native:1.2.3@system=/opt/n.jar", "",
            "native:1.2.3@system=/opt/n.jar+local"),
        ("a direct system dependency beats a transitive one", &["lib:1 > tools:2", "tools:2"],
            "lib:1 tools:1@system=/opt/t.jar", "", "lib:1 tools:1@system=/opt/t.jar+local"),
    ];
    check(cases).await;
}

/// A chain of relocations stops after 32 instead of being followed as far
/// as a repository serves it, counting the relocations a cached chain
/// adds.
#[tokio::test]
async fn an_endless_relocation_chain_fails() {
    let chain = |from: usize, to: usize| -> Vec<String> {
        (from..to)
            .map(|i| format!("c{i}:1 => g:c{}:1", i + 1))
            .chain([format!("c{to}:1")])
            .collect()
    };
    let at_most = chain(0, 32);
    let too_long = chain(0, 33);
    // `b` takes the cached chain of 31 from `c1`; `a` adds two in front.
    let mut cached = chain(1, 31);
    cached.extend(["b:1 => g:c1:1", "a:1 => g:x:1", "x:1 => g:b:1"].map(String::from));
    for (name, projects, root, expected) in [
        ("32 relocations", &at_most, "c0:1", "c32:1"),
        ("33 relocations", &too_long, "c0:1", "ERR RelocationCycle"),
        (
            "33 relocations through a cached chain",
            &cached,
            "b:1 a:1",
            "ERR RelocationCycle",
        ),
    ] {
        let projects: Vec<&str> = projects.iter().map(String::as_str).collect();
        check(&[(name, &projects, root, "", expected)]).await;
    }
}

/// Each new winner is progress, however many there are: only a winner that
/// comes back counts towards giving up. Maven 3.9.12 selects `x:300`.
#[tokio::test]
async fn many_winner_changes_still_converge() {
    let projects: Vec<String> = (1..=300)
        .flat_map(|i| [format!("a{i}:1 => g:x:{i}"), format!("x:{i}")])
        .collect();
    let projects: Vec<&str> = projects.iter().map(String::as_str).collect();
    let root: Vec<String> = (1..=300).map(|i| format!("a{i}:1")).collect();
    let root = root.join(" ");
    check(&[(
        "300 relocations onto rising versions",
        &projects,
        &root,
        "",
        "x:300",
    )])
    .await;
}

/// The ledger's probe graphs, where a hard range evicts an expanded node, a
/// relocation joins two conflict groups, or tree order decides a tie, with
/// Maven 3.9.12's answers.
#[tokio::test]
async fn mediation_after_evictions_and_relocations() {
    #[rustfmt::skip]
    let cases: &[Case<'_>] = &[
        ("relocation groups merge after an eviction",
            &["a:1 > u:1 v:1", "a:2", "u:1", "v:1", "p:1 > new:1", "q:1 > new:1",
                "c:1 > a:[2] old:2", "old:1", "old:2 => g:new:2", "new:1", "new:2"],
            "a:1 old:1 p:1 q:1 c:1", "", "a:2 c:1 old:1 p:1 q:1"),
        ("a managed relocation target that relocates again joins the group",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1", "b:2 => g:c:1", "c:1"],
            "b:1 p:1", "b:2", "b:1 p:1"),
        ("a relocation target managed to a range stops at its first relocation",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1", "b:2 => g:c:2", "b:3 => g:c:3", "c:2", "c:3"],
            "p:1", "b:[1,3]", "c:2 p:1"),
        ("a system dependency outlives one of its declarations",
            &["a:1 > s:1", "a:2 > s:1", "b:1 > s:1", "c:1 > x:1", "x:1 > a:[2]"],
            "a:1 b:1 c:1", "s:1@system=/opt/s.jar", "a:2 b:1 c:1 s:1@system=/opt/s.jar+local x:1"),
        ("a deeper declaration takes over from an evicted system one",
            &["a:1 > s:1", "a:2", "c:1 > x:1", "x:1 > a:[2]", "d:1 > e:1", "e:1 > s:1", "s:1"],
            "a:1 c:1 d:1", "s:1@system=/opt/s.jar", "a:2 c:1 d:1 e:1 s:1@system=/opt/s.jar+local x:1"),
        ("p3-s-b1",
            &["p:1 > m:1", "b:1 > c:1", "m:1 > x:1", "x:1", "p:2 > x:2", "x:2 > z:1", "z:1", "c:1 > d:1", "d:1 > p:[2,2]"],
            "p:1 b:1", "", "b:1 c:1 d:1 p:2 x:2 z:1"),
        ("p3-s-b1c",
            &["p:1 > x:1", "b:1 > c:1", "x:1 > y:1", "y:1 > x:1", "p:2 > x:2", "x:2 > z:1", "z:1", "c:1 > p:[2,2]"],
            "p:1 b:1", "", "b:1 c:1 p:2 x:2 z:1"),
        ("p3-s-b2",
            &["x:1 > y:1", "y:1", "a:1 > x:2", "x:2", "b:1 > y:2", "y:2", "c:1 > d:1", "d:1 > a:[2,2]", "a:2 > q:1", "q:1"],
            "x:1 a:1 b:1 c:1", "", "a:2 b:1 c:1 d:1 q:1 x:1 y:1"),
        ("p3-s-m1",
            &["a:1 > x:1", "x:1 > g2:y:1", "g2:y:1", "b:1 > x:1!g2:*", "c:1 > a:[2,2]", "a:2 > q:1", "q:1"],
            "a:1 b:1 c:1", "", "a:2 b:1 c:1 q:1 x:1"),
        ("p3-s-m2",
            &["d:1 > a:1", "a:1 > c:1", "c:1", "e:1 > f:1", "f:1 > a:[2,2]", "a:2 => g:b:2", "q:1", "b:2 > q:1"],
            "d:1 e:1", "", "a:1 c:1 d:1 e:1 f:1"),
        ("p3-s-n1",
            &["a:1", "d:1 > a:2", "a:2 > c:[2,2]", "b:1 > c:1", "c:1 > a:[2,2]", "c:2 > q:1", "q:1"],
            "a:1 d:1 b:1", "", "a:2 b:1 c:2 d:1 q:1"),
        ("p3-s-n2a",
            &["z:1", "x:1 > y:1", "y:1 > z:[2,2]", "d:1 > e:1", "e:1 > z:[3,3]", "a:1 > b:1", "b:1 > c:1", "c:1 > x:[2,2]", "x:2 > q:1", "q:1", "z:2 > q:1", "z:3 > q:1"],
            "z:1 x:1 d:1 a:1", "", "a:1 b:1 c:1 d:1 e:1 q:1 x:2 z:3"),
        ("p3-s-n2b",
            &["x:1 > y:1", "y:1 > z:[2,2]", "a:1 > b:1", "b:1 > c:1", "c:1 > x:[2,2]", "x:2 > q:1", "q:1", "z:2 > q:1", "z:1 > q:1"],
            "z:[1,1] x:1 a:1", "", "a:1 b:1 c:1 q:1 x:2 z:1"),
        ("p3-s-n3",
            &["a:1 > m:1!x", "b:1 > m:1", "m:1 > x:1", "x:1 > a:[2,2]", "a:2 > q:1", "q:1"],
            "a:1 b:1", "", "a:2 b:1 m:1 q:1 x:1"),
        ("p3-s-n3 with a pinned walk",
            &["a:1 > m:1!x", "b:1 > m:1", "m:1 > x:[1]", "x:1 > a:[2,2]", "a:2 > q:1", "q:1"],
            "a:1 b:1", "", "a:2 b:1 m:1 q:1 x:1"),
        ("p3-s-n3 with a range in the walk",
            &["a:1 > m:1!x", "b:1 > m:1", "m:1 > x:[1,1]", "x:1 > a:[2,2]", "a:2 > q:1", "q:1"],
            "a:1 b:1", "", "a:2 b:1 m:1 q:1 x:1"),
        ("p3-s-n3 with a lower relocation in the walk",
            &["a:1 > m:1!x", "b:1 > m:1", "m:1 > x:[1,2]", "x:1 => g:y:1", "x:2", "y:1 > a:[2,2]", "a:2 > q:1", "q:1"],
            "a:1 b:1", "", "a:2 b:1 m:1 q:1 y:1"),
        ("p3-s-n3 with a lower plain version in the walk",
            &["a:1 > m:1!x", "b:1 > m:1", "m:1 > x:[1,3]", "x:1 > a:[2,2]", "x:2 => g:y:1", "x:3", "y:1", "a:2 > q:1", "q:1"],
            "a:1 b:1", "", "a:2 b:1 m:1 q:1 x:1"),
        ("a range reads two spellings of a version in their listed order",
            &["a:1 > c:1", "c:1", "a:1.0 => g:b:2", "b:2 > d:1", "d:1"],
            "a:[1,2)", "", "a:1 c:1"),
        ("p3-s-n4",
            &["d:1 > a:2", "a:2 > k:1", "k:1", "c:1 > a:[1,2]", "e:1 > f:1", "f:1 > a:[1,1]", "b:1 > q:1", "q:1", "a:1 => g:b:1"],
            "d:1 c:1 e:1", "", "a:2 c:1 d:1 e:1 f:1 k:1"),
        ("p3-s-n5a",
            &["a:2 => g:b:2", "d:1 > a:1", "a:1 > c:1", "c:1", "b:2 > q:1", "q:1"],
            "a:2 d:1", "", "b:2 d:1 q:1"),
        ("p3-s-n5b",
            &["a:1 > c:1", "c:1", "d:1 > a:2", "a:2 => g:b:2", "b:2 > q:1", "q:1"],
            "a:1 d:1", "", "a:1 c:1 d:1"),
        ("p3-s4-grand",
            &["a:1 > p:1", "b:1 > r:1", "p:1 > q:1", "q:1", "r:1 > a:[2,2]", "a:2 > q:2", "q:2 > s:1", "s:1"],
            "a:1 b:1", "", "a:2 b:1 q:2 r:1 s:1"),
        ("p3-s4-flip",
            &["a:1 > x:1", "b:1 > x:[2,2]", "c:1 > x:1!g2:secret a:[2,2] b:[2,2]", "x:1 > g2:secret:1", "g2:secret:1", "x:2 > z:1", "z:1", "a:2 > qa:1", "qa:1", "b:2 > qb:1", "qb:1"],
            "a:1 b:1 c:1", "", "a:2 b:2 c:1 qa:1 qb:1 x:1"),
        ("p3-s4-detach",
            &["a:1 > x:[1,2]", "b:1 > x:3", "c:1 > x:[1,1]", "x:3 > e:1", "x:2 > d:1", "d:1", "e:1", "x:1 => g:y:1", "dummy:1", "y:1 > yy:1", "yy:1"],
            "a:1 b:1 c:1", "", "a:1 b:1 c:1 y:1 yy:1"),
        ("p3-s4-allreloc",
            &["a:1 > old:ox:[1,2]", "b:1 > c:1!child", "c:1 > new:nx:[1,1]", "new:nx:1 > child:1", "child:1", "new:nx:2 > z:1", "z:1", "old:ox:1 => new:nx:1", "dummy:1", "old:ox:2 => new:nx:2"],
            "a:1 b:1", "", "a:1 b:1 c:1 child:1 new:nx:1"),
        ("p3-s4-depth",
            &["a:1 > c:1 d:1", "p:2 > z:1", "z:1", "p:1 > d:[2,2]", "c:1 > p:[1,1]", "d:1 > x:[2,2]", "d:2 > z2:1", "z2:1", "x:1 > z3:1", "z3:1", "x:2 > z4:1", "z4:1"],
            "p:[1,2] x:[1,1] a:1", "", "a:1 c:1 d:2 p:1 x:1 z2:1 z3:1"),
        ("p3-s4-nearer",
            &["a:1 > old:ox:[1,2]", "b:1 > y:2", "c:1 > old:ox:[1,1]", "old:ox:1 => g:y:1", "old:ox:2 > z:1", "y:1 > y1c:1", "y:2 > y2c:1", "z:1", "y1c:1", "y2c:1"],
            "a:1 b:1 c:1", "", "a:1 b:1 c:1 y1c:1 y:1"),
        ("A1-1",
            &["a:1 > b:1", "p1:1 > p2:1", "b:1 > c:1", "c:1", "a:2 > c:2", "c:2 > leaf:1", "leaf:1", "p2:1 > p3:1", "p3:1 > a:[2]"],
            "a:1 p1:1", "", "a:2 c:2 leaf:1 p1:1 p2:1 p3:1"),
        ("A1-2",
            &["a:1 > b:1", "d:1 > a:[2]", "b:1 > x:2", "x:2", "a:2 > x:1", "x:1"],
            "a:1 d:1", "", "a:2 d:1 x:1"),
        ("A1-3",
            &["a:1 > b:1", "d:1 > a:[2]", "b:1 > x:[2]", "a:2 > x:1", "x:1", "x:2"],
            "a:1 d:1 x:[1]", "", "a:2 d:1 x:1"),
        ("A1-3 without the winner's soft x",
            &["a:1 > b:1", "b:1 > x:[2]", "d:1 > a:[2]", "a:2", "x:1", "x:2"],
            "a:1 d:1 x:[1]", "", "a:2 d:1 x:1"),
        ("A2",
            &["a:1", "b:1 > a:2", "c:1 > d:1", "e:1 > a:[2]", "a:2 > x:1", "x:1", "d:1 > x:2", "x:2"],
            "a:1 b:1 c:1 e:1", "", "a:2 b:1 c:1 d:1 e:1 x:1"),
        ("E3a",
            &["old:1.0", "old:2.0 => g:new:_", "new:2.0", "a:1 > old:[1.0,2.0]"],
            "a:1!new", "", "a:1 old:1.0"),
        ("E3b",
            &["old:1.0", "old:2.0 => g:new:_", "new:2.0", "a:1 > old:[1.0,2.0]", "b:1 > old:[1.0]"],
            "a:1 b:1", "", "a:1 b:1 old:1.0"),
        ("reloc-excl",
            &["m:mid:1 > old:lib:1", "old:lib:1 => new:lib:1", "new:lib:1 > t:trans:1", "t:trans:1"],
            "m:mid:1", "new:lib:1!t:trans", "m:mid:1 new:lib:1"),
        ("reloc-scope",
            &["m:mid:1 > old:lib:1", "old:lib:1 => new:lib:1", "new:lib:1 > t:trans:1", "t:trans:1"],
            "m:mid:1", "new:lib:1@provided", "m:mid:1 new:lib:1@provided t:trans:1@provided"),
        ("reloc-excl-transitive",
            &["m:mid:1 > old:lib:1", "old:lib:1 => new:lib:1", "new:lib:1 > t:trans:1", "t:trans:1"],
            "m:mid:1!new:lib", "", "m:mid:1"),
        ("visited-range-reloc-3",
            &["a:1", "a:2", "a:3 => g:new:1", "new:1", "new:2"],
            "a:[1,4) new:2", "", "a:2"),
        ("A7-guard",
            &["a:1 > b:[1,1]", "a:2 > b:[2,2]", "b:1 > a:[2,2]", "b:2 > a:[1,1]", "r:1 > a:[1,2]"],
            "r:1", "", "a:2 b:2 r:1"),
        ("managed relocation ranges that cycle fail",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1", "b:2 => g:c:1", "c:1", "c:2 => g:a:1"],
            "p:1", "b:[2,3) c:[2,3)", "ERR RelocationCycle"),
        ("managed relocations that cycle fail",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1", "b:2 => g:c:1", "c:1", "c:2 => g:a:1"],
            "p:1", "b:2 c:2", "ERR RelocationCycle"),
        ("a hard range overrides a nearer system declaration",
            &["p:1 > s:[2]", "s:2"],
            "s:1@system=/opt/s.jar p:1", "", "p:1 s:2@system"),
        ("a system file a range picks outranks the direct scope",
            &["p:1 > s:[2]@system=/opt/s.jar", "s:1"],
            "s:1 p:1", "", "p:1 s:2@system=/opt/s.jar+local"),
        ("a surviving system declaration keeps its own version",
            &["a:1 > s:1", "b:1 > s:2", "c:1 > a:[2]", "a:2"],
            "a:1 b:1 c:1", "s:_@system=/opt/s.jar", "a:2 b:1 c:1 s:2@system=/opt/s.jar+local"),
        ("a system declaration joins a relocation group",
            &["p:1 > old:2", "old:1", "old:2 => g:s:2", "s:2"],
            "s:1@system=/opt/s.jar old:1 p:1", "", "p:1 s:1@system=/opt/s.jar+local"),
        ("a relocation target managed to system is local",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1"],
            "p:1", "b:2@system=/opt/b.jar", "b:2@system=/opt/b.jar+local p:1"),
        ("a managed relocation keeps only the latest relocation's aliases",
            &["a:1", "b:1", "leaf:1", "p:1 > a:2", "a:2 => g:b:1", "b:2 => g:c:1", "c:1 > leaf:1"],
            "a:1 p:1", "b:2", "a:1 c:1 leaf:1 p:1"),
        ("a managed pin keeps only the latest relocation's aliases",
            &["a:1", "b:1", "leaf:1", "p:1 > a:2", "a:2 => g:b:1", "b:2 => g:c:1", "c:1 > leaf:1"],
            "a:1 p:1", "b:[2]", "a:1 c:1 leaf:1 p:1"),
        ("a managed range whose lowest version relocates takes no aliases",
            &["a:1", "b:1", "leaf:1", "p:1 > a:2", "a:2 => g:b:1", "b:2 => g:c:1", "c:1 > leaf:1"],
            "a:1 p:1", "b:[2,2]", "a:1 c:1 leaf:1 p:1"),
        ("a managed range whose lowest version stays keeps the aliases",
            &["a:1", "b:1", "leaf:1", "p:1 > a:2", "a:2 => g:b:1", "b:2", "b:3 => g:c:1", "c:1 > leaf:1"],
            "a:1 p:1", "b:[2,3]", "b:2 p:1"),
        ("a relocation onto a cyclic target is cut before its management",
            &["c:3 > e:3", "e:3 => g:x:1", "x:1", "x:2 => g:c:3"],
            "c:3", "x:[1,2]@test", "c:3"),
        ("a relocation onto a cyclic target keeps the relocations before it",
            &["y:2", "y:3 => g:c:3", "c:3 > e:3", "e:3 => g:x:1", "x:1", "x:2 => g:y:3"],
            "y:[2,3]", "x:[1,2]@test", "c:3"),
        ("a range goes on past a version that relocates onto its own path",
            &["p:1 > x:[2,3]", "x:2 => g:p:1", "x:3 => g:y:3", "y:3"],
            "p:1", "", "p:1 y:3"),
        ("a range keeps its constraint past a lowest version that relocates onto its own path",
            &["p:1 > x:[2,3]", "x:2 => g:p:1", "x:3"],
            "p:1", "", "p:1 x:3"),
        ("a relocation target managed to a system pin takes the pinned version",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1"],
            "p:1", "b:[2]@system=/opt/b.jar", "b:2@system=/opt/b.jar+local p:1"),
        ("a relocation target managed to a system range takes its highest version",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1", "b:2", "b:3"],
            "p:1", "b:[2,3]@system=/opt/b.jar", "b:3@system=/opt/b.jar+local p:1"),
        ("a pinned system dependency takes the pinned version",
            &["p:1 > s:1", "s:1"],
            "s:[2]@system=/opt/s.jar p:1", "", "p:1 s:2@system=/opt/s.jar+local"),
        ("a pinned system dependency conflicts with another pin",
            &["p:1 > s:[1]", "s:1"],
            "s:[2]@system=/opt/s.jar p:1", "", "ERR VersionConflict"),
        ("a system range backtracks over its local versions",
            &["p:1 > s:[1,2]", "s:1", "s:2 > leaf:1", "s:3", "leaf:1"],
            "s:[1,3]@system=/opt/s.jar p:1", "", "p:1 s:2@system=/opt/s.jar+local"),
        ("a relocation target managed to a system range offers its local versions",
            &["q:1 > p:1", "p:1 > s:[1,2]", "r:1 > a:1", "a:1 => g:s:1", "s:1", "s:2 > leaf:1",
                "s:3", "leaf:1"],
            "r:1 q:1", "s:[1,3]@system=/opt/s.jar", "p:1 q:1 r:1 s:3@system=/opt/s.jar+local"),
        ("a cyclic probe of a range can merge its group away",
            &["p:1 > x:[1,2]", "x:1 => g:h:1", "h:1 => g:t:1", "t:1", "t:2 => g:p:1", "x:2 => g:z:1",
                "z:1"],
            "p:1", "t:2", "p:1"),
        ("a relocation target managed to provided keeps its subtree",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1", "b:2 > c:1", "c:1"],
            "p:1", "b:2@provided", "b:2@provided c:1@provided p:1"),
        ("a relocation target managed to a provided pin keeps its subtree",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1", "b:2 > c:1", "c:1"],
            "p:1", "b:[2]@provided", "b:2@provided c:1@provided p:1"),
        ("a relocation target managed to test is pruned",
            &["p:1 > a:1", "a:1 => g:b:1", "b:1", "b:2 => g:c:1", "c:1 > child:1", "child:1"],
            "p:1", "b:2@test", "p:1"),
    ];
    check(cases).await;
}

/// Maven's scope inheritance and pruning, as `mvn dependency:list` reports it.
#[tokio::test]
async fn scopes_and_optional_dependencies() {
    let child: &[&str] = &["t:1 > c:1", "c:1"];
    let subtree: &[&str] = &["api:1 > impl:1", "impl:1 > util:1", "util:1"];
    #[rustfmt::skip]
    let cases: &[Case<'_>] = &[
        ("a direct optional dependency is traversed", &["a:1 > b:1", "b:1"], "a:1?", "",
            "a:1 b:1"),
        ("a transitive optional dependency is skipped", &["a:1 > b:1?"], "a:1", "", "a:1"),
        ("an optional child of an optional dependency is skipped", &["a:1 > b:1?"], "a:1?", "",
            "a:1"),
        ("exclusions prune", &["a:1 > b:1!c", "b:1 > c:1", "c:1"], "a:1", "", "a:1 b:1"),
        ("a test dependency's compile child is test", child, "t:1@test", "",
            "c:1@test t:1@test"),
        ("a test root keeps test scope", &["a:1 > b:1", "b:1"], "@test a:1", "",
            "a:1@test b:1@test"),
        ("a test dependency carries its compile subtree",
            &["testlib:1 > junit:1", "junit:1 > hamcrest:1", "hamcrest:1"], "testlib:1@test", "",
            "hamcrest:1@test junit:1@test testlib:1@test"),
        ("a provided dependency carries its compile subtree", subtree, "api:1@provided", "",
            "api:1@provided impl:1@provided util:1@provided"),
        ("test and provided grandchildren are dropped",
            &["t:1 > ck:1 tk:1@test pk:1@provided", "ck:1", "tk:1", "pk:1"], "t:1@test", "",
            "ck:1@test t:1@test"),
        ("a transitive system dependency is followed", &["a:1 > s:1@system=/opt/s.jar"],
            "a:1", "", "a:1 s:1@system=/opt/s.jar+local"),
        ("and stays system under a test parent", &["a:1 > s:1@system=/opt/s.jar"],
            "a:1@test", "", "a:1@test s:1@system=/opt/s.jar+local"),
        ("an optional system one is not", &["a:1 > s:1@system=/opt/s.jar?"], "a:1", "",
            "a:1"),
        ("a scope in other case is unknown and followed",
            &["a:1 > p:1@Provided s:1@SYSTEM", "p:1", "s:1"], "a:1", "", "a:1 p:1 s:1"),
    ];
    check(cases).await;
}

/// Maven's JavaScopeSelector: a package takes its direct declaration's
/// scope, else the widest of its paths, and its own dependencies derive
/// from the scope it took. `test-fixtures/maven-parity/dependency-scopes`
/// has these cases recorded from Maven.
#[tokio::test]
async fn the_widest_path_scope_wins() {
    let shared: &[&str] = &["b:1 > x:1", "x:1 > y:1", "y:1"];
    let via = |first: &'static str, second: &'static str| -> Vec<&'static str> {
        [first, second]
            .into_iter()
            .chain(shared.iter().copied())
            .collect()
    };
    let test_compile = via("t:1 > x:1", "a:1 > b:1");
    let provided_runtime = via("p:1 > x:1", "r:1 > b:1");
    let runtime_compile = via("r:1 > x:1", "a:1 > b:1");
    let optional = via("t:1 > x:1", "o:1 > b:1");
    #[rustfmt::skip]
    let cases: &[Case<'_>] = &[
        ("a nearer test path gives way to compile", &test_compile, "t:1@test a:1", "",
            "a:1 b:1 t:1@test x:1 y:1"),
        ("a nearer provided path gives way to runtime", &provided_runtime,
            "p:1@provided r:1@runtime", "",
            "b:1@runtime p:1@provided r:1@runtime x:1@runtime y:1@runtime"),
        ("a nearer runtime path gives way to compile", &runtime_compile, "r:1@runtime a:1", "",
            "a:1 b:1 r:1@runtime x:1 y:1"),
        ("an optional path counts", &optional, "t:1@test o:1?", "",
            "b:1 o:1 t:1@test x:1 y:1"),
        ("a direct scope wins over a wider path",
            &["a:1 > x:1 r:1", "x:1 > y:1", "r:1 > z:1", "y:1", "z:1"],
            "a:1 x:1@test r:1@runtime", "",
            "a:1 r:1@runtime x:1@test y:1@test z:1@runtime"),
        ("a managed scope is taken as it is",
            &["t:1 > x:1 w:1", "w:1 > v:1", "v:1", "a:1 > m:1 k:1", "x:1 > y:1",
                "m:1 > n:1", "k:1 > q:1", "y:1", "n:1", "q:1"],
            "t:1@test a:1", "x:_@runtime w:_@compile m:_@test k:_@provided",
            "a:1 k:1@provided m:1@test n:1@test q:1@provided t:1@test v:1 w:1 x:1@runtime \
             y:1@runtime"),
        ("a relocation target takes its scope as managed only by its own management",
            &["t:1 > old:1 old2:1", "old:1 => g:new:_", "old2:1 => g:new2:_", "new:1",
                "new2:1"],
            "t:1@test", "old:_@compile new2:_@compile", "new2:1 new:1@test t:1@test"),
        ("the first direct declaration of a node sets its scope",
            &["old:1 => g:new:_", "new:1 > y:1", "y:1"], "old:1 new:1@test", "", "new:1 y:1"),
        ("a cycle does not widen the node it returns to",
            &["t:1 > x:1", "x:1 > y:1", "y:1 > x:1"], "t:1@test", "y:_@compile",
            "t:1@test x:1@test y:1"),
        ("a relocation keeps the first direct declaration first",
            &["new:1 > leaf:1", "new:2 > leaf:1", "old:1", "old:2 => g:new:_", "leaf:1",
                "versions old 1 2"],
            "new:1 old:[1,2]@test", "", "leaf:1 new:2"),
        ("a cycle's gathering stops where a path returns to a node on it",
            &["u:1 > x:1", "t:1 > a:1", "x:1 > a:1", "a:1 > b:1 x:1", "b:1 > a:1"],
            "u:1@test t:1@test", "b:_@compile", "a:1@test b:1 t:1@test u:1@test x:1@test"),
        ("a cycle breaks at the node a depth-first walk finds first",
            &["t:1 > u:1 x:1", "a:1 > y:1", "u:1 > y:1", "x:1 > y:1", "y:1 > a:1 x:1"],
            "t:1@test a:1", "", "a:1 t:1@test u:1@test x:1 y:1"),
        ("a cycle gathers only through the groups of the cycles found through it",
            &["t:1 > x:1", "a:1 > y:1", "x:1 > z:1 y:1", "y:1 > z:1", "z:1 > x:1"],
            "t:1@test a:1", "", "a:1 t:1@test x:1@test y:1 z:1"),
        ("a resolved group is gathered through only below its winner",
            &["t:1 > x:1 y:1", "a:1 > b:1", "x:1 > a:1", "b:1 > y:1", "y:1 > b:1 x:1 z:1",
                "z:1 > a:1"],
            "t:1@test a:1", "", "a:1 b:1 t:1@test x:1 y:1 z:1"),
        ("a cycle broken at one node gathers the path through the other",
            &["t:1 > x:1", "a:1 > y:1", "x:1 > y:1", "y:1 > x:1"], "t:1@test a:1", "",
            "a:1 t:1@test x:1 y:1"),
        // Maven 3.9.12 (parity fixture m4): a2 excludes r, so the y below
        // it has no r, and r keeps the runtime of the paths below a.
        ("a cycle's gathering skips what an exclusion on the path removed",
            &["a:1 > r:1 y:1", "a2:1 > r:1 y:1", "r:1 > y:1", "y:1 > r:1"],
            "a:1@runtime a2:1!r", "", "a2:1 a:1@runtime r:1@runtime y:1"),
    ];
    check(cases).await;
}

/// Each left branch of a chain of diamonds below a cycle adds its own
/// exclusion, so the paths carry 2^levels exclusion sets. The gathering for
/// the broken node stops at a budget instead of running for hours.
#[tokio::test]
async fn a_cycle_gathering_through_too_many_exclusion_sets_stops() {
    const LEVELS: usize = 24;
    let mut lines = vec!["d:1 > t:1 x:1".to_string(), "t:1 > a0:1".to_string()];
    lines.push("x:1 > a0:1".to_string());
    for i in 0..LEVELS {
        let next = i + 1;
        lines.push(format!("a{i}:1 > l{i}:1!r{i} r{i}:1"));
        lines.push(format!("l{i}:1 > a{next}:1 t:1"));
        lines.push(format!("r{i}:1 > a{next}:1 t:1"));
    }
    lines.push(format!("a{LEVELS}:1"));
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    let solved = Solver::new(&backend(&lines)).solve(root("d:1")).await;
    let actual = render(solved);
    assert!(
        actual.starts_with("ERR GraphLimitExceeded: dependency graph exceeds 100000 states"),
        "got {actual}"
    );
}

#[tokio::test]
async fn dependency_management() {
    let relocated: &[&str] = &[
        "mid:1 > o:lib:6.0",
        "o:lib:6.0 => n:_:_",
        "n:lib:6.0",
        "n:lib:7.0",
    ];
    let pinned: &[&str] = &["lib:1.0", "versions lib 1.0 2.0"];
    let managed_child: &[&str] = &["lib:1 > child:1", "child:1"];
    #[rustfmt::skip]
    let cases: &[Case<'_>] = &[
        ("management fills a missing version", &["o:bar:3.0"], "o:bar:_", "o:bar:3.0",
            "o:bar:3.0"),
        ("a hard pin beats management", pinned, "lib:[1.0]", "lib:2.0", "lib:1.0"),
        ("a soft direct version beats management", pinned, "lib:1.0", "lib:2.0", "lib:1.0"),
        ("a managed two-bound pin conflicts as the short form does",
            &["e:1 => g:f:1", "e:3 => g:x:3", "f:1", "x:3 > e:3", "d:3 > f:[1] x:[3]"],
            "e:[3] d:3", "e:[1,1]", "ERR VersionConflict"),
        ("a test-jar entry does not manage the jar", &["lib:1.0"], "lib:1.0", "lib:2.0~tests",
            "lib:1.0"),
        ("jar and test-jar entries manage independently", &["lib:1.0", "lib:2.0~tests"],
            "lib:_ lib:_#test-jar", "lib:1.0 lib:2.0~tests", "lib:1.0 lib:2.0~tests"),
        ("managed exclusions prune transitive nodes",
            &["lib:1 > mid:1", "mid:1 > cl:cl:1.2", "cl:cl:1.2"], "lib:1", "mid:_!cl:cl",
            "lib:1 mid:1"),
        ("managed exclusions join a direct dependency's own",
            &["lib:1 > own:1 cl:1", "own:1", "cl:1"], "lib:1!own", "lib:_!cl", "lib:1"),
        ("entries for one key merge field by field and add up their exclusions",
            &["q:1 > foo:3", "foo:1 > unwanted:1 third:1", "foo:2 > unwanted:1 third:1",
                "foo:3 > unwanted:1 third:1", "unwanted:1", "third:1"],
            "q:1", "foo:2!third foo:1@runtime!unwanted", "foo:2@runtime q:1"),
        ("a transitive dependency managed to system takes the managed path",
            &["lib:1 > tools:1"], "lib:1", "tools:2@system=/opt/t.jar",
            "lib:1 tools:2@system=/opt/t.jar+local"),
        ("a system scope without a path is an error", &["lib:1 > tools:1"], "lib:1",
            "tools:_@system",
            "ERR Pom: pom error: invalid model: system-scoped dependency g:tools requires a non-empty <systemPath>"),
        ("management sets a transitive scope", managed_child, "lib:1", "child:_@test",
            "child:1@test lib:1"),
        ("a dependency managed to test keeps its subtree",
            &["lib:1 > extra:1@-", "extra:1 > leaf:1", "leaf:1"], "lib:1", "extra:_@test",
            "extra:1@test leaf:1@test lib:1"),
        ("under a runtime parent too",
            &["lib:1 > extra:1", "extra:1 > leaf:1", "leaf:1"], "lib:1@runtime", "extra:_@test",
            "extra:1@test leaf:1@test lib:1@runtime"),
        ("a test dependency's child managed to test stays",
            &["compress:1 > io:1@-", "io:1"], "compress:1@test", "io:_@test",
            "compress:1@test io:1@test"),
        ("a provided dependency's child managed to test stays",
            &["core:1 > guava:1", "guava:1"], "core:1@provided", "guava:_@test",
            "core:1@provided guava:1@test"),
        ("a declared test transitive stays dropped", &["lib:1 > extra:1@test", "extra:1"],
            "lib:1", "extra:_@compile", "lib:1"),
        ("a dependency's own management fills a version, not the scope",
            &["testlib:1 > junit:_ | junit:4.13.2@test", "junit:4.13.2 > hamcrest:1.3",
                "hamcrest:1.3"], "testlib:1@test", "",
            "hamcrest:1.3@test junit:4.13.2@test testlib:1@test"),
        ("an explicit child version beats its management",
            &["lib:1 > child:2 | child:1", "child:2"], "lib:1", "", "child:2 lib:1"),
        ("management applies to a relocated transitive", relocated, "mid:1", "n:lib:7.0",
            "mid:1 n:lib:7.0"),
        ("a direct relocated dependency keeps its version", &relocated[1..], "o:lib:6.0",
            "n:lib:7.0", "n:lib:6.0"),
    ];
    check(cases).await;
}

#[tokio::test]
async fn relocations() {
    #[rustfmt::skip]
    let cases: &[Case<'_>] = &[
        ("a relocation is followed",
            &["old:lib:1.0 => new:lib-new:2.0", "new:lib-new:2.0 > child:1", "child:1"],
            "old:lib:1.0", "", "child:1 new:lib-new:2.0"),
        ("a partial relocation keeps the rest", &["old:lib:1.0 => new:_:_", "new:lib:1.0"],
            "old:lib:1.0", "", "new:lib:1.0"),
        ("relocation cycles fail", &["a:1 => _:b:1", "b:1 => _:a:1"], "a:1", "",
            "ERR RelocationCycle"),
        ("a relocation onto a resolved node is no cycle",
            &["mid:1 > bc:ext:1.0", "bc:ext:1.0 => _:base:_", "bc:base:1.0"],
            "bc:base:1.0 mid:1", "", "bc:base:1.0 mid:1"),
    ];
    check(cases).await;

    // A relocation recorded for one spelling of a version is not replayed for
    // another that Maven's ordering calls equal, and one onto another
    // spelling of its own version is followed.
    let backend = backend(&[
        "old:lib:1.0 => new:_:2.0",
        "old:lib:1.0.0",
        "new:lib:2.0",
        "old:lib:1.1 => _:_:1.1.0",
        "old:lib:1.1.0",
    ]);
    let solver = Solver::new(&backend);
    let cache = std::sync::Mutex::new(Default::default());
    for (from, to) in [
        ("old:lib:1.0", "new:lib:2.0"),
        ("old:lib:1.0.0", "old:lib:1.0.0"),
        ("old:lib:1.1", "old:lib:1.1.0"),
    ] {
        let (resolved, _, _, _, _) = solver
            .fetch_project_with_relocation_cached(&coord(from), &RepoContext::default(), &cache)
            .await
            .unwrap();
        assert_eq!(resolved.to_string(), to);
    }

    // The node records the target's repository, not the one that listed
    // the relocating artifact's versions.
    let mut backend = self::backend(&["old:lib:1.0 => new:lib-new:2.0", "new:lib-new:2.0"]);
    backend
        .project_repos
        .insert("new:lib-new:2.0".to_string(), "mock://target");
    let graph = Solver::new(&backend)
        .solve(root("old:lib:[1.0,2.0)"))
        .await
        .unwrap();
    let target = graph
        .node_indices()
        .filter_map(|index| graph.node(index))
        .find(|node| node.coord.artifact_id.as_str() == "lib-new")
        .unwrap();
    assert_eq!(target.repo_url.as_deref(), Some("mock://target"));
}

/// A relocation without a version keeps the source's SNAPSHOT build, but
/// the target comes from the repository serving it, not from the one whose
/// metadata named the source's build.
#[tokio::test]
async fn a_kept_snapshot_build_takes_the_targets_repository() {
    let mut backend = backend(&[
        "old:1.1-20261011.010101-1 => g:lib:_",
        "lib:1.1-20261011.010101-1",
    ]);
    backend
        .project_repos
        .insert("g:old:1.1-20261011.010101-1".to_string(), "mock://old");
    backend
        .project_repos
        .insert("g:lib:1.1-20261011.010101-1".to_string(), "mock://lib");
    let graph = Solver::new(&backend)
        .solve(root("old:1.1-SNAPSHOT"))
        .await
        .unwrap();
    let target = graph
        .node_indices()
        .filter_map(|index| graph.node(index))
        .find(|node| node.coord.artifact_id.as_str() == "lib")
        .unwrap();
    assert_eq!(target.repo_url.as_deref(), Some("mock://lib"));
}

/// maven-resolver's root node has no dependency, so a transitive dependency
/// with the root's coordinates is collected and only a cycle through a
/// collected node is cut; the cut cycle edge stays in the graph.
/// A SNAPSHOT is mediated on its base version and locked as the build it
/// resolved to, also when a relocation or its management leads to it.
#[tokio::test]
async fn snapshots_mediate_on_their_base_version() {
    let build = "lib:1.1-20261011.010101-1";
    #[rustfmt::skip]
    let cases: &[Case<'_>] = &[
        ("a pinned SNAPSHOT", &[build], "lib:[1.1-SNAPSHOT]", "", build),
        ("a range up to a SNAPSHOT", &[build, "lib:1.0", "versions lib 1.0 1.1-SNAPSHOT"],
            "lib:[1.0,1.1-SNAPSHOT]", "", build),
        ("a range whose winner is a SNAPSHOT", &[build, "lib:1.0", "versions lib 1.0 1.1-SNAPSHOT"],
            "lib:[1.0,2.0]", "", build),
        ("a relocation to a SNAPSHOT", &["old:1 => g:lib:1.1-SNAPSHOT", build],
            "old:1", "", build),
        ("a relocation managed to a SNAPSHOT",
            &["p:1 > old:1", "old:1 => g:lib:1.0", "lib:1.0", build],
            "p:1", "lib:1.1-SNAPSHOT", "lib:1.1-20261011.010101-1 p:1"),
        ("a relocation without a version keeps the SNAPSHOT build",
            &["old:1.1-20261011.010101-1 => g:lib:_", build, "lib:1.1-20261012.010101-2"],
            "old:1.1-SNAPSHOT", "", build),
        ("a declaration of a relocation's target resolves its own build",
            &["p:1 > old:1.1-SNAPSHOT", "q:1 > old:1.1-SNAPSHOT", "r:1 > lib:1.1-SNAPSHOT",
                "old:1.1-20261011.010101-1 => g:lib:_", "lib:1.1-20261011.010101-1 > x:1",
                "lib:1.1-20261012.010101-2 > y:1", "x:1", "y:1"],
            "p:1!lib q:1!lib r:1", "", "lib:1.1-20261012.010101-2 p:1 q:1 r:1 y:1"),
        ("management resolves a relocation's SNAPSHOT target afresh",
            &["p:1 > old:1.1-SNAPSHOT", "old:1.1-20261011.010101-1 => g:lib:_",
                "lib:1.1-20261011.010101-1 > x:1", "lib:1.1-20261012.010101-2 > y:1", "x:1", "y:1"],
            "p:1", "lib:1.1-SNAPSHOT", "lib:1.1-20261012.010101-2 p:1 y:1"),
        ("a management pin resolves a relocation's SNAPSHOT target afresh",
            &["p:1 > old:1.1-SNAPSHOT", "old:1.1-20261011.010101-1 => g:lib:_",
                "lib:1.1-20261011.010101-1 > x:1", "lib:1.1-20261012.010101-2 > y:1", "x:1", "y:1"],
            "p:1", "lib:[1.1-SNAPSHOT]", "lib:1.1-20261012.010101-2 p:1 y:1"),
        ("a hop with a version ends the kept build",
            &["p:1 > old:1.1-SNAPSHOT", "q:1 > mid:1.1-SNAPSHOT",
                "old:1.1-20261011.010101-1 => g:mid:_", "mid:1.1-20261011.010101-1 => g:lib:1",
                "mid:1.1-20261012.010101-2 => g:lib:2", "lib:1", "lib:2"],
            "p:1!lib q:1", "", "lib:2 p:1 q:1"),
        // A relocation without a version names the resolved build, which
        // then mediates as that version.
        ("a kept build outranks an older sibling build",
            &["p:1 > moved:1.1-SNAPSHOT lib:1.1-20261011.010101-1",
                "moved:1.1-20261012.010101-2 => g:lib:_", "lib:1.1-20261011.010101-1 > x:1",
                "lib:1.1-20261012.010101-2 > y:1", "x:1", "y:1"],
            "p:1", "", "lib:1.1-20261012.010101-2 p:1 y:1"),
        ("a kept build outranks the release of its base",
            &["p:1 > lib:1.1 moved:1.1-SNAPSHOT", "lib:1.1 > z:1", "z:1",
                "moved:1.1-20261012.010101-2 => g:lib:_", "lib:1.1-20261012.010101-2 > y:1", "y:1"],
            "p:1", "", "lib:1.1-20261012.010101-2 p:1 y:1"),
        ("a kept build outranks a sibling SNAPSHOT",
            &["p:1 > lib:1.1-SNAPSHOT moved:1.1-SNAPSHOT", "moved:1.1-20261011.010101-1 => g:lib:_",
                "lib:1.1-20261011.010101-1 > x:1", "lib:1.1-20261012.010101-2 > y:1", "x:1", "y:1"],
            "p:1", "", "lib:1.1-20261011.010101-1 p:1 x:1"),
        ("a kept build managed to system keeps its version",
            &["p:1 > moved:1.1-SNAPSHOT lib:1.1", "lib:1.1 > z:1", "z:1",
                "moved:1.1-20261012.010101-2 => g:lib:_", "lib:1.1-20261012.010101-2 > y:1", "y:1"],
            "p:1", "lib:_@system=/opt/l.jar", "lib:1.1-20261012.010101-2@system=/opt/l.jar+local p:1"),
        ("a pinned SNAPSHOT rejects a kept build",
            &["p:1 > moved:1.1-SNAPSHOT q:1", "q:1 > lib:[1.1-SNAPSHOT]",
                "moved:1.1-20261011.010101-1 => g:lib:_", "lib:1.1-20261011.010101-1 > x:1",
                "lib:1.1-20261012.010101-2 > y:1", "x:1", "y:1"],
            "p:1", "", "lib:1.1-20261012.010101-2 p:1 q:1 y:1"),
        ("a range accepts a kept build",
            &["p:1 > moved:1.1-SNAPSHOT q:1", "q:1 > lib:[1.0,1.2)", "lib:1.0",
                "versions lib 1.0 1.1-SNAPSHOT", "moved:1.1-20261011.010101-1 => g:lib:_",
                "lib:1.1-20261011.010101-1 > x:1", "lib:1.1-20261012.010101-2 > y:1", "x:1", "y:1"],
            "p:1", "", "lib:1.1-20261011.010101-1 p:1 q:1 x:1"),
        ("a SNAPSHOT build kept along a relocation stays with its chain",
            &["old:1.1-20261011.010101-1 => g:mid:_", "mid:1.1-20261011.010101-1 => g:lib:_",
                "mid:1.1-20261012.010101-2 => g:lib:_", build, "lib:1.1-20261012.010101-2"],
            "mid:1.1-SNAPSHOT old:1.1-SNAPSHOT", "", "lib:1.1-20261012.010101-2"),
    ];
    check(cases).await;
}

#[tokio::test]
async fn cycle_edges_and_the_root_artifact() {
    let backend = backend(&[
        "text:1.0 > root:0.9",
        "root:0.9 > text:1.0 util:1.0",
        "util:1.0",
    ]);
    let graph = Solver::new(&backend).solve(root("text:1.0")).await;
    let graph = graph.unwrap();
    assert_eq!(graph.edge_count(), 4);
    assert_eq!(render(Ok(graph)), "root:0.9 text:1.0 util:1.0");
}

/// A chain 1000 deep resolves; one level deeper fails naming the bound.
#[tokio::test]
async fn depth_past_the_bound_fails() {
    let projects: Vec<String> = (1..=1001)
        .map(|i| format!("a{i}:1 > a{}:1", i + 1))
        .chain(["a1002:1".to_string()])
        .collect();
    let mut projects: Vec<&str> = projects.iter().map(String::as_str).collect();
    check(&[(
        "1001 deep",
        &projects,
        "a1:1",
        "",
        "ERR GraphLimitExceeded: dependency graph exceeds 1000 levels of depth at g:a1001",
    )])
    .await;
    projects[999] = "a1000:1";
    let solved = Solver::new(&backend(&projects)).solve(root("a1:1")).await;
    assert_eq!(solved.unwrap().node_count(), 1001);
}

/// Every project fetched was hinted first, a range by each of its versions,
/// and nothing the solver does not fetch is hinted: not a test
/// dependency of a dependency and not an excluded one.
#[tokio::test]
async fn queued_projects_are_hinted_before_they_are_fetched() {
    let backend = backend(&[
        "a:1.0 > c:1.0 tested:1.0@test ranged:[1.0,2.0)",
        "b:1.0 > excluded:1.0",
        "c:1.0",
        "ranged:1.0",
        "ranged:1.5",
    ]);
    Solver::new(&backend)
        .solve(root("a:1.0 b:1.0!excluded"))
        .await
        .unwrap();
    let prefetches: std::collections::BTreeSet<_> =
        backend.prefetches.lock().unwrap().iter().cloned().collect();
    let fetches = backend.fetches.lock().unwrap().clone();
    assert_eq!(
        prefetches.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "g:a:1.0",
            "g:b:1.0",
            "g:c:1.0",
            "g:ranged:1.0",
            "g:ranged:1.5"
        ]
    );
    for hinted in &prefetches {
        assert!(fetches.contains(hinted), "{hinted} hinted, not fetched");
    }
}

/// A range is hinted for listing as its declaration is queued, unless the
/// solver skips that declaration.
#[tokio::test]
async fn queued_ranges_are_hinted_for_listing() {
    let backend = backend(&[
        "a:1.0 > ranged:[1.0,2.0) tested:[1.0,2.0)@test",
        "ranged:1.0",
        "ranged:1.5",
    ]);
    let graph = Solver::new(&backend).solve(root("a:1.0")).await;
    assert_eq!(render(graph), "a:1.0 ranged:1.5");
    assert_eq!(*backend.listings.lock().unwrap(), ["g:ranged:[1.0,2.0)"]);
}

mod known_gaps;
mod nearest;
mod ranges;
