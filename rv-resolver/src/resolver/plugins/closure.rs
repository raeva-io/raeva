//! One set's files, as Maven 3.9's `DefaultPluginDependenciesResolver`
//! collects a plugin's class path: the plugin artifact at the root, the
//! plugin's own `<dependencies>` at `runtime` before its POM's (but `test`
//! and `provided` ones), managed by the plugin POM's dependency management
//! from depth 2, from the plugin repositories.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use rv_maven_model::{ArtifactHandler, ArtifactTypes, DefinedType, Dependency, PomError, Scope};
use rv_maven_types::{ArtifactCoord, Coord, Gav, MavenMode};
use rv_repo::{ArtifactRequest, Repository};

use super::request::{ExtensionDescriptors, ExtensionHandlers, PathResolution, SetRequest};
use super::{PluginRole, ResolvedPluginSet};
use crate::context::RepoContext;
use crate::error::{ResolveError, Result};
use crate::graph::Edge;
use crate::output::{ResolvedArtifact, ResolvedPackage};
use crate::resolver::backend::{ModelCache, ModelService, ReadModels, WorkspaceSupportPomBuffer};
use crate::resolver::extension_types::ExtensionTypes;
use crate::resolver::utils::{FetchError, fetch_artifact_from_repos, stored_in_first};
use crate::resolver::{PendingModuleResolution, PlatformResolver, complete_resolution};
use crate::solver::{Backend, Management, Solver, SolverRoot};
use crate::util::lock;
use crate::workspace::Workspace;
use crate::{ModuleResolution, SupportPomProvenance};

impl PlatformResolver {
    /// The files of `request`'s set: of a plugin or an extension, `jar` as
    /// its own when given, as a build extension's SNAPSHOT build is fetched.
    /// The POMs it reads go to `support_poms` when given.
    pub(super) async fn resolve_set(
        &self,
        request: &SetRequest,
        workspace: &Arc<Workspace>,
        models: ModelCache,
        support_poms: Option<&WorkspaceSupportPomBuffer>,
        jar: Option<ResolvedPackage>,
    ) -> Result<ResolvedPluginSet> {
        // A set gets its own model cache, as a module does: a model built
        // from another set's cache pins none of the parents and BOMs it read.
        let ctx = self.ctx.for_module(self.ctx.config.clone());
        // A processor path and a test provider are resolved by the plugin,
        // with none of the selectors Maven collects a plugin with.
        let plugin = !matches!(
            request.role,
            PluginRole::ProcessorPath | PluginRole::TestProvider
        );
        let mode = self.ctx.config.lock.maven.mode;
        let (paths, own) = processor_paths(request, mode);
        let extension_types = Arc::new(ExtensionTypes::known(mode, request.handlers.clone(), own));
        extension_types
            .meet_types(request.plugin.dependencies.iter().chain(&request.paths))
            .await?;
        // Maven's model cache serves each collection what the others read,
        // past what it held as the set started.
        let models = ReadModels::new(Mutex::new(models));
        let extension = matches!(
            request.role,
            PluginRole::BuildExtension | PluginRole::CoreExtension
        );
        let new_backend = || {
            let mut backend = ModelService::new(&ctx, request.repos.clone())
                .with_workspace(Arc::clone(workspace))
                .collecting_plugin(plugin)
                .with_extension_types(Arc::clone(&extension_types));
            if extension {
                backend = backend
                    .without_reactor_reader()
                    .in_extension_realm_of(&request.module);
            }
            if let Some(support_poms) = support_poms {
                backend = backend.with_workspace_support_poms(Arc::clone(support_poms));
            }
            backend.read_models = Arc::clone(&models);
            backend
        };
        let backend = new_backend();
        let types = extension_types.types();
        // Recorded as the backend searches them, the project's POM
        // repositories before Central, as Maven lists them.
        let repo_urls = (backend.root_effective_repos_snapshot().into_iter())
            .map(|repo| repo.url)
            .collect();
        let (root, collections, own) = match request.role {
            PluginRole::ProcessorPath | PluginRole::TestProvider => {
                let root: Coord = "rv.processor-path:processor-path:0:jar"
                    .parse()
                    .map_err(ResolveError::Version)?;
                (root, path_collections(request, paths, &types), None)
            }
            _ => {
                let plugin = &request.plugin;
                let version =
                    plugin
                        .version
                        .as_deref()
                        .ok_or_else(|| ResolveError::MissingVersion {
                            group_id: plugin.group_id.clone(),
                            artifact_id: plugin.artifact_id.clone(),
                        })?;
                let declared: Coord = format!("{}:{version}:jar", plugin.key())
                    .parse()
                    .map_err(ResolveError::Version)?;
                // Maven takes the plugin artifact its descriptor relocates to.
                let solver = Solver::new(&backend);
                let repos = RepoContext::default();
                let fetched = match mode {
                    MavenMode::Maven39 => {
                        let relocations = Default::default();
                        (solver.fetch_project_with_relocation_cached(
                            &declared,
                            &repos,
                            &relocations,
                        ))
                        .await?
                    }
                    MavenMode::Maven310 => {
                        solver
                            .fetch_project_with_relocation_310(&declared, &repos)
                            .await??
                    }
                };
                let (root, resolved) = (fetched.target, fetched.resolved);
                let project = &resolved.project;
                let managed = &project.dependency_management.dependencies;
                let dependencies = plugin_dependencies(
                    &project.dependencies,
                    &plugin.dependencies,
                    managed,
                    &types,
                );
                let management = Management::new(managed.clone(), types.clone());
                drop(resolved);
                let own = match jar {
                    Some(jar) => jar,
                    None => self.root_artifact(&backend, &root, &request.repos).await?,
                };
                let own = Some(own);
                (
                    root,
                    vec![Collection::Direct(dependencies, management)],
                    own,
                )
            }
        };
        let filtered: HashSet<&str> = request.filtered.iter().map(String::as_str).collect();
        // Maven resolves the collected class path but its `provided` and
        // `test` nodes and the artifacts the core or a build extension
        // exports, named by artifactId or groupId:artifactId, whose POMs stay
        // support POMs.
        let unfetched = |coord: &Coord, scope: Scope| {
            let artifact_id = coord.artifact_id.as_str();
            matches!(scope, Scope::Provided | Scope::Test)
                || filtered.contains(artifact_id)
                || filtered.contains(format!("{}:{artifact_id}", coord.group_id).as_str())
        };
        let mut artifacts: Vec<ResolvedPackage> = own.into_iter().collect();
        let mut kept_poms: HashSet<Gav> = HashSet::new();
        let mut poms: BTreeMap<String, SupportPomProvenance> = BTreeMap::new();
        let mut read_poms = Vec::new();
        let mut pom_reads = rv_lock::PomReads::default();
        let mut reactor_later = Vec::new();
        let mut repositories = Vec::new();
        let mut metadata_versions = Vec::new();
        let mut range_versions = Vec::new();
        let mut backend = Some(backend);
        for collection in collections {
            let backend = backend.take().unwrap_or_else(new_backend);
            let (dependencies, management) = match collection {
                Collection::Direct(dependencies, management) => (dependencies, management),
                Collection::Rooted {
                    root,
                    declared,
                    own,
                } => rooted(&backend, &types, &root, &declared, &own).await?,
            };
            let mut solver = (Solver::new(&backend).with_management(management))
                .breadth_first(!self.collects_depth_first(workspace)?);
            if plugin {
                solver = solver.unfetched(&unfetched);
            }
            let solver_root = SolverRoot {
                coord: root.clone(),
                dependencies,
                scope: Scope::Compile,
            };
            let mut graph = solver.solve(solver_root).await?;
            if plugin {
                // A node below one that the filter passes still resolves, so
                // it hangs from the root instead.
                let unused =
                    |idx| (graph.node(idx)).is_some_and(|node| unfetched(&node.coord, node.scope));
                let kept: Vec<_> = (graph.edge_references())
                    .filter(|&(from, to, _)| unused(from) && !unused(to))
                    .map(|(_, to, edge)| {
                        (
                            to,
                            Edge {
                                declared: None,
                                ..edge.clone()
                            },
                        )
                    })
                    .collect();
                let unused: Vec<_> = graph.node_indices().filter(|&idx| unused(idx)).collect();
                let root = graph.root();
                for (to, edge) in kept {
                    graph.add_edge(root, to, edge);
                }
                for idx in unused {
                    graph.clear_incoming(idx);
                }
            }
            self.populate_artifacts(&backend, &mut graph, None).await?;
            read_poms.extend(backend.read_poms(false));
            pom_reads.extend(backend.pom_reads());
            let resolution = complete_resolution(
                self.ctx.platform.clone(),
                PendingModuleResolution {
                    backend,
                    graph,
                    module_gav: Gav::new(
                        root.group_id.as_str(),
                        root.artifact_id.as_str(),
                        &root.version.to_string(),
                    ),
                    module_packaging: "jar".to_string(),
                    root_support_pom_provenance: Vec::new(),
                    root_parent_ranges: Vec::new(),
                    parents: Vec::new(),
                    losers: false,
                },
            )?;
            range_versions.extend(set_range_versions(&resolution, mode));
            if request.role == PluginRole::Plugin {
                reactor_later.extend(unordered_reactor_files(request, &resolution));
            }
            for package in resolution.packages {
                if package.workspace_module.is_some() || package.artifact.is_none() {
                    continue;
                }
                // A file another collection of the set already holds.
                if (artifacts.iter()).any(|known| known.coordinate == package.coordinate) {
                    continue;
                }
                kept_poms.insert(package.coordinate.gav.clone());
                artifacts.push(package);
            }
            poms.extend(resolution.support_pom_provenance);
            metadata_versions.extend(resolution.metadata_versions);
            for repository in resolution.repositories {
                if !repositories.contains(&repository) {
                    repositories.push(repository);
                }
            }
        }
        if let Some(own) = artifacts.first()
            && !matches!(
                request.role,
                PluginRole::ProcessorPath | PluginRole::TestProvider
            )
        {
            kept_poms.insert(own.coordinate.gav.clone());
        }
        for (gav, provenance) in read_poms {
            if !kept_poms.contains(&gav) {
                poms.entry(gav.to_string()).or_insert(provenance);
            }
        }
        Ok(ResolvedPluginSet {
            key: request.key(&self.ctx.config.project_root),
            role: request.role,
            coordinates: request.coordinates(),
            repo_urls,
            artifacts,
            poms: poms.into_iter().collect(),
            repositories,
            metadata_versions,
            range_versions,
            pom_reads,
            reactor_later,
        })
    }

    /// The plugin's own jar, with the POM the backend read for it.
    async fn root_artifact(
        &self,
        backend: &ModelService,
        root: &Coord,
        repos: &[Repository],
    ) -> Result<ResolvedPackage> {
        let client = self
            .ctx
            .client
            .as_ref()
            .ok_or(ResolveError::NoRepositories)?;
        let version = root.version.to_string();
        let jar = ArtifactRequest {
            group_id: root.group_id.to_string(),
            artifact_id: root.artifact_id.to_string(),
            version: version.clone(),
            packaging: "jar".to_string(),
            classifier: None,
        };
        let coordinate = ArtifactCoord::new(
            root.group_id.as_str(),
            root.artifact_id.as_str(),
            &version,
            "jar",
            None,
        );
        let store = &self.ctx.store;
        let stored = stored_in_first(client, store, &coordinate, repos).await?;
        let (blob, repo_url) =
            match stored {
                Some(found) => found,
                None => {
                    let (blob, origin) =
                        match fetch_artifact_from_repos(client, store, &jar, &coordinate, repos)
                            .await
                        {
                            Ok(found) => found,
                            Err(FetchError::NotFound { searched }) => {
                                return Err(ResolveError::ArtifactNotFound {
                                    dropped_repos: Vec::new(),
                                    coord: coordinate.to_string(),
                                    searched,
                                    classifier_like: None,
                                });
                            }
                            Err(FetchError::Failed { err, searched }) => {
                                return Err(ResolveError::Repo {
                                    coord: Some(coordinate.to_string()),
                                    source: Box::new(err),
                                    searched,
                                });
                            }
                        };
                    // The POM that named the jar may be one whose `.sha256` is
                    // still being checked.
                    (client.checked_so_far())
                        .await
                        .map_err(|source| ResolveError::Repo {
                            coord: Some(coordinate.to_string()),
                            source: Box::new(source),
                            searched: Vec::new(),
                        })?;
                    store
                        .add_artifacts(vec![(coordinate.clone(), blob.clone())])
                        .await?;
                    store
                        .record_origins(vec![(coordinate.clone(), blob.clone(), origin.clone())])
                        .await?;
                    (blob, origin.repo_url)
                }
            };
        let gav = (
            root.group_id.to_string(),
            root.artifact_id.to_string(),
            version.clone(),
        );
        let served = (backend.companion_pom_blobs.read())
            .expect("companion_pom_blobs lock poisoned")
            .get(&gav)
            .cloned()
            .flatten();
        let (pom, pom_repo) = match served {
            Some((blob, repo)) => (Some(blob), repo.map(|repo| repo.to_string())),
            None => (None, None),
        };
        Ok(ResolvedPackage {
            coordinate,
            direct_scope: None,
            scope: rv_lock::Scope::Runtime,
            workspace_module: None,
            system_path: None,
            managed: None,
            artifact: Some(ResolvedArtifact {
                version,
                snapshot: None,
                pom_snapshot: None,
                pom_base: false,
                pom_repo_url: pom_repo.filter(|repo| *repo != repo_url),
                repo_url,
                blob,
                companion_pom: pom,
            }),
        })
    }

    /// The jar of the build extension `request` names, a SNAPSHOT one at
    /// the build raeva.lock pins for the module.
    pub(super) async fn extension_jar(&self, request: &SetRequest) -> Result<ResolvedPackage> {
        let plugin = &request.plugin;
        let version = (plugin.version.as_deref()).ok_or_else(|| ResolveError::MissingVersion {
            group_id: plugin.group_id.clone(),
            artifact_id: plugin.artifact_id.clone(),
        })?;
        let mut root: Coord = format!("{}:{version}:jar", plugin.key())
            .parse()
            .map_err(ResolveError::Version)?;
        let backend = ModelService::new(&self.ctx, request.repos.clone());
        let mut repos = request.repos.clone();
        let mut in_turn = false;
        // A SNAPSHOT takes its build as a dependency does: the newest the
        // repositories name, or the one raeva.lock pins for the module.
        if rv_maven_types::resolves_through_snapshot_metadata(version) {
            let gav = rv_maven_types::Gav::new(&plugin.group_id, &plugin.artifact_id, version);
            let pinned = (self.ctx.client.as_ref()).and_then(|client| {
                client.pinned_extension(&self.ctx.platform, &request.module, &gav)
            });
            let context = RepoContext::default();
            let newest = match pinned {
                // The pinned build's jar is asked of the repository whose
                // metadata names it as the newest, as when it was locked.
                // After a newer deploy, or offline without the metadata, it
                // comes from the first repository that serves the pinned
                // bytes: an earlier one may serve that name in others.
                Some(build) => {
                    let pinned: Coord = (format!("{}:{build}:jar", plugin.key()).parse())
                        .map_err(ResolveError::Version)?;
                    let newest = backend.resolve_snapshot_version(&root, &context).await;
                    root = pinned;
                    let newest = newest.ok().filter(|newest| newest.version == root.version);
                    in_turn = newest.as_ref().is_none_or(|newest| newest.repo.is_none());
                    newest
                }
                None => {
                    let newest = backend.resolve_snapshot_version(&root, &context).await?;
                    root.version = newest.version.clone();
                    Some(newest)
                }
            };
            // As Maven's artifact resolver does, the build's jar is asked
            // only of the repository whose metadata named it.
            if let Some(build) = newest.and_then(|newest| newest.repo) {
                repos.retain(|repo| build.is(repo));
            }
        }
        if in_turn {
            for repo in &repos {
                let one = std::slice::from_ref(repo);
                if let Ok(jar) = self.root_artifact(&backend, &root, one).await {
                    return Ok(jar);
                }
            }
        }
        self.root_artifact(&backend, &root, &repos).await
    }

    /// The jars of a build extension's realm, `own` and then `closure`, the
    /// rest of the set Maven resolves for it, and the artifact handlers
    /// they define. Maven's realm takes each file of the set but those its
    /// core exports; raeva reads and pins the jars among them.
    pub(super) fn realm_handlers<'a>(
        &self,
        own: &'a ResolvedPackage,
        closure: impl IntoIterator<Item = &'a ResolvedPackage>,
        describe: &str,
    ) -> Result<ExtensionHandlers> {
        let exported = |package: &ResolvedPackage| {
            let coordinate = &package.coordinate;
            let ga = format!("{}:{}", coordinate.group_id(), coordinate.artifact_id());
            super::request::CORE_EXPORTS.contains(&ga.as_str())
        };
        let members = (closure.into_iter())
            .filter(|package| package.coordinate.extension() == "jar" && !exported(package));
        let mut jars = Vec::new();
        let mut files = Vec::new();
        let mut key = Vec::new();
        for package in std::iter::once(own).chain(members) {
            let Some(artifact) = &package.artifact else {
                continue;
            };
            let coordinate = &package.coordinate;
            // A SNAPSHOT jar is pinned at its build, which a frozen check
            // and an offline sync take again.
            let gav = match &artifact.snapshot {
                Some(_) if artifact.pom_snapshot.is_some() || artifact.pom_base => {
                    return Err(ResolveError::Plugin {
                        plugin: describe.to_string(),
                        searched: Vec::new(),
                        error: Box::new(ResolveError::Pom(PomError::Unlockable(format!(
                            "{coordinate} of its realm is a SNAPSHOT build whose POM is of \
                             another build, which raeva.lock cannot pin"
                        )))),
                    });
                }
                Some(_) => Gav::new(
                    coordinate.group_id(),
                    coordinate.artifact_id(),
                    &artifact.version,
                ),
                None => coordinate.gav.clone(),
            };
            let jar = rv_lock::ExtensionJar {
                gav,
                classifier: coordinate.classifier().map(str::to_string),
                sha256: artifact.blob.clone(),
            };
            let named = jar.to_string();
            files.push((self.ctx.store.get_path(&artifact.blob), named.clone()));
            key.push((artifact.blob.clone(), named));
            jars.push(jar);
        }
        // A reactor's modules share their extensions, whose jars are read
        // once.
        if let Some(handlers) = lock(&self.ctx.extension_realms).handlers.get(&key) {
            return Ok((jars, handlers.clone()));
        }
        let realm: Vec<_> = (files.iter())
            .map(|(path, coord)| (path.as_path(), coord.as_str()))
            .collect();
        let handlers =
            super::jar::realm_handlers(&realm).map_err(|error| ResolveError::Plugin {
                plugin: describe.to_string(),
                searched: Vec::new(),
                error: Box::new(error),
            })?;
        let mut realms = lock(&self.ctx.extension_realms);
        realms.handlers.insert(key, handlers.clone());
        Ok((jars, handlers))
    }

    /// What a build extension's jars export to the plugin class paths of
    /// its module and which packagings their lifecycle mappings define.
    pub(super) fn extension_descriptors(
        &self,
        set: &ResolvedPluginSet,
    ) -> Result<ExtensionDescriptors> {
        let mut descriptors = ExtensionDescriptors::default();
        let describe = format!("{} {}", set.role.as_str(), set.coordinates.join(","));
        if let Some(own) = (set.artifacts.first()).filter(|own| own.artifact.is_some()) {
            let closure = &set.artifacts[1..];
            (descriptors.handlers).push(self.realm_handlers(own, closure, &describe)?);
        }
        let mut mapped = BTreeSet::new();
        for package in &set.artifacts {
            let Some(artifact) = &package.artifact else {
                continue;
            };
            if package.coordinate.extension() != "jar" {
                continue;
            }
            let path = self.ctx.store.get_path(&artifact.blob);
            // A jar that does not read fails the set, as a descriptor
            // raeva skipped would change what the module resolves.
            let read = |name: &str| match super::jar::read_entry(&path, name) {
                Ok(bytes) => Ok(bytes.and_then(|bytes| String::from_utf8(bytes).ok())),
                Err(error) => Err(ResolveError::Plugin {
                    plugin: describe.clone(),
                    searched: Vec::new(),
                    error: Box::new(ResolveError::UnreadableJar {
                        coord: package.coordinate.gav.to_string(),
                        entry: Some(name.to_string()),
                        reason: error.to_string(),
                    }),
                }),
            };
            if let Some(text) = read("META-INF/maven/extension.xml")? {
                descriptors
                    .exported
                    .extend(rv_maven_model::parse_exported_artifacts(&text).unwrap_or_default());
            }
            if let Some(text) = read("META-INF/plexus/components.xml")? {
                for (hint, mojos) in rv_maven_model::parse_lifecycle_mappings(&text)? {
                    if mapped.insert(hint.clone()) {
                        descriptors.mappings.push((hint, mojos));
                    }
                }
            }
        }
        Ok(descriptors)
    }
}

/// The paths of `request`, and for a processor path the types they take.
/// maven-compiler-plugin gives the resolver each path by the extension its
/// type's handler names alone, with no classifier but the declared one.
/// From 3.11 its dependencies are walked; Maven's legacy resolver, which
/// the older ones use, keeps the type, and walks none for a handler that
/// says the file includes them.
fn processor_paths(request: &SetRequest, mode: MavenMode) -> (Vec<Dependency>, Vec<DefinedType>) {
    if request.role != PluginRole::ProcessorPath {
        return (request.paths.clone(), Vec::new());
    }
    let module = ArtifactTypes::pending(mode);
    module.define((request.handlers.iter()).flat_map(|(_, defined)| defined.iter().cloned()));
    let legacy = matches!(
        request.paths_by,
        PathResolution::Alone | PathResolution::UnderFirst
    );
    let mut own = Vec::new();
    let paths = (request.paths.iter())
        .map(|path| {
            let declared = path.type_.as_deref().unwrap_or("jar");
            let extension = module.extension(declared);
            let mut handler = ArtifactHandler::plain(extension);
            let type_ = if legacy {
                handler.includes_dependencies = module.includes_dependencies(declared);
                format!("{declared} (processor path)")
            } else {
                format!("{extension} (processor path)")
            };
            own.push((type_.clone(), Ok(handler)));
            Dependency {
                type_: Some(type_),
                ..path.clone()
            }
        })
        .collect();
    (paths, own)
}

/// A collection's direct dependencies and management, or the path whose POM
/// gives them, read in the collection's turn: the compiler plugin resolves
/// legacy paths one after another.
enum Collection {
    Direct(Vec<Dependency>, Management),
    Rooted {
        root: Dependency,
        declared: Vec<Dependency>,
        own: Vec<Dependency>,
    },
}

/// Each collection the compiler plugin makes for `request`'s processor
/// path, of `paths` as [`processor_paths`] types them; a test provider's one
/// collection.
fn path_collections(
    request: &SetRequest,
    paths: Vec<Dependency>,
    types: &ArtifactTypes,
) -> Vec<Collection> {
    match &request.paths_by {
        PathResolution::Together => vec![Collection::Direct(paths, Management::default())],
        PathResolution::Managed(managed) => vec![Collection::Direct(
            paths,
            Management::new(managed.clone(), types.clone()),
        )],
        PathResolution::UnderFirst => match paths.first() {
            Some(first) => vec![Collection::Rooted {
                root: first.clone(),
                declared: request.paths.clone(),
                own: paths,
            }],
            None => Vec::new(),
        },
        PathResolution::Alone => (paths.into_iter())
            .zip(&request.paths)
            .map(|(path, declared)| Collection::Rooted {
                root: path.clone(),
                declared: vec![declared.clone()],
                own: vec![path],
            })
            .collect(),
    }
}

/// The direct dependencies and management of a legacy request rooted at
/// `root`: beside it come the root POM's dependencies but `test` and
/// `provided` ones and those of a path's key, and its management applies
/// below them, as for a plugin.
async fn rooted(
    backend: &ModelService,
    types: &ArtifactTypes,
    root: &Dependency,
    declared: &[Dependency],
    own: &[Dependency],
) -> Result<(Vec<Dependency>, Management)> {
    let version = (root.version.as_deref()).ok_or_else(|| ResolveError::MissingVersion {
        group_id: root.group_id.clone(),
        artifact_id: root.artifact_id.clone(),
    })?;
    let coord: Coord = format!("{}:{}:{version}:jar", root.group_id, root.artifact_id)
        .parse()
        .map_err(ResolveError::Version)?;
    let resolved =
        crate::solver::Backend::fetch_project(backend, &coord, false, &RepoContext::default())
            .await?;
    let project = &resolved.project;
    let managed = &project.dependency_management.dependencies;
    let pom: &[Dependency] = match types.includes_dependencies(root.effective_type()) {
        true => &[],
        false => &project.dependencies,
    };
    // Keyed by the declared types, then given the types of the set.
    let mut dependencies = plugin_dependencies(pom, declared, managed, types);
    for (dependency, path) in dependencies.iter_mut().zip(own) {
        dependency.type_ = path.type_.clone();
    }
    // A root the reactor builds comes from there, with its POM's
    // dependencies beside it.
    if backend.workspace_module_for_coord(&coord).is_some() {
        dependencies.remove(0);
    }
    Ok((
        dependencies,
        Management::new(managed.clone(), types.clone()),
    ))
}

/// The direct dependencies of a plugin's closure. Maven's collector puts the
/// plugin's own `<dependencies>`, at `runtime` unless `system`, before the
/// plugin POM's, which lose `test` and `provided` ones and those of the same
/// key; so the plugin's own also win depth ties. The plugin POM's
/// management adds its exclusions to the plugin's own, as it does at every
/// depth.
fn plugin_dependencies(
    pom: &[Dependency],
    own: &[Dependency],
    managed: &[Dependency],
    types: &ArtifactTypes,
) -> Vec<Dependency> {
    let key = |dependency: &Dependency| {
        (
            dependency.group_id.clone(),
            dependency.artifact_id.clone(),
            dependency.effective_type_in(types).to_string(),
            dependency
                .effective_classifier_in(types)
                .map(str::to_string),
        )
    };
    let mut dependencies: Vec<Dependency> = (own.iter())
        .map(|own| {
            let mut own = own.clone();
            if own.effective_scope() != Scope::System {
                own.scope = Some("runtime".to_string());
            }
            let own_key = key(&own);
            for entry in managed.iter().filter(|entry| key(entry) == own_key) {
                for exclusion in &entry.exclusions {
                    if !own.exclusions.contains(exclusion) {
                        own.exclusions.push(exclusion.clone());
                    }
                }
            }
            own
        })
        .collect();
    let own = dependencies.iter().map(key).collect::<HashSet<_>>();
    dependencies.extend(
        (pom.iter())
            .filter(|dependency| {
                !matches!(dependency.effective_scope(), Scope::Test | Scope::Provided)
            })
            .filter(|dependency| !own.contains(&key(dependency)))
            .cloned(),
    );
    dependencies
}

/// The version each range of `resolution` took, by each repository whose
/// list named it: of a range the graph holds, of a parent range, and of one
/// that lost mediation, whose versions `mvn -o` lists too. The plugin
/// tables record no evicted ranges or parent ranges, so an export lists
/// these alone.
fn set_range_versions(
    resolution: &crate::ModuleResolution,
    mode: MavenMode,
) -> Vec<rv_lock::RangeVersion> {
    let mut taken = resolution.range_versions.clone();
    let mut evicted: BTreeMap<(&str, &str, &str), Vec<&rv_lock::EvictedRange>> = BTreeMap::new();
    for range in &resolution.evicted_ranges {
        (evicted
            .entry((&range.group, &range.artifact, &range.range))
            .or_default())
        .push(range);
    }
    for by_origin in evicted.values() {
        let mut versions: Vec<String> = (by_origin.iter())
            .flat_map(|range| range.versions.iter().cloned())
            .collect();
        versions.sort_unstable();
        versions.dedup();
        rv_lock::EvictedRange::sort_versions(&mut versions, mode);
        let Some(highest) = versions.last() else {
            continue;
        };
        taken.extend(
            (by_origin.iter())
                .filter(|range| range.versions.contains(highest))
                .map(|range| rv_lock::RangeVersion {
                    group: range.group.clone(),
                    artifact: range.artifact.clone(),
                    version: highest.clone(),
                    origin: range.origin.clone(),
                }),
        );
    }
    taken.sort();
    taken.dedup();
    taken
}

/// The reactor modules a plugin's class path reaches neither as a
/// dependency the project declares for the plugin nor below another
/// reactor module. Maven 3.9 orders the reactor by those alone, so such a
/// module may build after the plugin runs, which then reads its POM from
/// the reactor and its jar from a repository.
fn unordered_reactor_files(request: &SetRequest, resolution: &ModuleResolution) -> Vec<String> {
    let declared: HashSet<(&str, &str)> = (request.plugin.dependencies.iter())
        .map(|dependency| {
            (
                dependency.group_id.as_str(),
                dependency.artifact_id.as_str(),
            )
        })
        .collect();
    let packages = &resolution.packages;
    let reactor = |at: usize| {
        packages
            .get(at)
            .is_some_and(|package| package.workspace_module.is_some())
    };
    (packages.iter().enumerate())
        .filter(|(at, package)| {
            let coordinate = &package.coordinate;
            reactor(*at)
                && !(package.direct_scope.is_some()
                    && declared.contains(&(coordinate.group_id(), coordinate.artifact_id())))
                && !(resolution.edges.iter()).any(|edge| edge.to == *at && reactor(edge.from))
        })
        .map(|(_, package)| package.coordinate.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use rv_maven_model::Exclusion;

    use super::*;

    fn dependency(artifact_id: &str, version: &str, scope: Option<&str>) -> Dependency {
        Dependency {
            group_id: "g".to_string(),
            artifact_id: artifact_id.to_string(),
            version: Some(version.to_string()),
            type_: None,
            classifier: None,
            scope: scope.map(str::to_string),
            optional: None,
            exclusions: Vec::new(),
            system_path: None,
            system_path_from_project: Default::default(),
            origin: Default::default(),
        }
    }

    /// The plugin's own dependencies come first, at runtime, and replace the
    /// POM's of their key; the POM's test and provided ones are dropped.
    #[test]
    fn a_plugins_own_dependencies_come_first() {
        let pom = [
            dependency("doxia", "2", None),
            dependency("junit", "5", Some("test")),
            dependency("checkstyle", "9", None),
            dependency("api", "3", Some("provided")),
        ];
        let own = [
            dependency("checkstyle", "12", None),
            dependency("tools", "1", Some("system")),
        ];
        let summary: Vec<String> = plugin_dependencies(&pom, &own, &[], &ArtifactTypes::default())
            .iter()
            .map(|dependency| {
                format!(
                    "{}:{}:{}",
                    dependency.artifact_id,
                    dependency.version.as_deref().unwrap_or(""),
                    dependency.scope.as_deref().unwrap_or("")
                )
            })
            .collect();
        assert_eq!(
            summary,
            ["checkstyle:12:runtime", "tools:1:system", "doxia:2:"]
        );
    }

    /// Management exclusions reach the plugin's own dependencies, which
    /// management versions do not.
    #[test]
    fn management_excludes_below_a_plugins_own_dependency() {
        let mut managed = dependency("checkstyle", "9", None);
        managed.exclusions.push(Exclusion {
            group_id: "x".to_string(),
            artifact_id: "y".to_string(),
        });
        let own = [dependency("checkstyle", "12", None)];
        let dependencies = plugin_dependencies(&[], &own, &[managed], &ArtifactTypes::default());
        assert_eq!(dependencies[0].version.as_deref(), Some("12"));
        assert_eq!(dependencies[0].exclusions.len(), 1);
    }
}
