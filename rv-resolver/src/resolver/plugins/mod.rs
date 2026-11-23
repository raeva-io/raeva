//! Plugin locking: what Maven 3.9 resolves from repositories for the build
//! of each module besides its dependencies. Each plugin of the effective
//! plugin model (lifecycle defaults included), each build extension, each
//! plugin a goal names by prefix or coordinate, the compiler plugin's
//! `annotationProcessorPaths`, and the root's core extensions are resolved
//! as Maven's plugin dependency resolver collects them, into a set of files
//! per distinct request. Version-less plugins take their version from the
//! plugin repositories' metadata, as Maven's plugin version resolver does.
//!
//! What a mojo resolves while it runs is in no model; see
//! `docs/design/plugin-locking.md`.

mod closure;
pub(super) mod jar;
mod prefix;
mod providers;
mod request;
mod table;
mod versions;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use rv_lock::{Platform, PluginFiles, PluginRole};
use rv_maven_model::{ActivationContext, HostInput, HostReads, ModelPolicy, Project};
use rv_maven_types::Sha256;

use super::PlatformResolver;
use super::backend::{ModelCache, ReadModels, WorkspaceSupportPomBuffer};
use super::scope::ModelScope;
use crate::context::{ResolveContext, ResolveState};
use crate::error::{ResolveError, Result};
use crate::output::ResolvedPackage;
use crate::util::lock;
use crate::workspace::Workspace;
use crate::{Resolver, SupportPomProvenance};

/// How many sets resolve at once.
const SET_CONCURRENCY: usize = 8;

/// The goals the `plugin.xml` of the plugin jar at `path` lists, none
/// where raeva cannot read it.
pub fn plugin_goals(path: &std::path::Path) -> Vec<String> {
    (jar::read_entry(path, "META-INF/maven/plugin.xml")
        .ok()
        .flatten())
    .and_then(|bytes| String::from_utf8(bytes).ok())
    .and_then(|text| rv_maven_model::parse_plugin_descriptor(&text).ok())
    .map(|descriptor| descriptor.goals)
    .unwrap_or_default()
}

/// What a plugin resolution covers beyond the model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginRequest {
    /// The goals the build runs: a phase, `prefix:goal`,
    /// `prefix:version:goal`, `groupId:artifactId:goal` or
    /// `groupId:artifactId:version:goal`. The root's `<defaultGoal>` is
    /// read as well. Phases need nothing: every lifecycle plugin of the
    /// packaging is resolved.
    pub goals: Vec<String>,
    /// Each module's graph in raeva.lock, by POM path: its test class
    /// path, which decides the test framework provider.
    pub test_classpaths: BTreeMap<String, rv_lock::LockModule>,
}

impl PluginRequest {
    /// A request for `goals`.
    pub fn new(goals: Vec<String>) -> Self {
        Self {
            goals,
            test_classpaths: BTreeMap::new(),
        }
    }
}

/// What the builds of one platform's modules resolve besides their
/// dependencies.
#[derive(Debug)]
pub(crate) struct PluginResolution {
    /// Each distinct set, by key.
    pub(crate) sets: Vec<ResolvedPluginSet>,
    /// Each module, in workspace order, with the indexes of its sets.
    pub(crate) modules: Vec<ModulePluginSets>,
    /// Metadata `mvn -o` must find: the version lists of version-less
    /// plugins and the prefixes of the plugin groups goals were found in.
    pub(crate) metadata: Vec<PluginMetadata>,
    /// The versions version-less plugins and the sets took from
    /// repository metadata.
    pub(crate) metadata_versions: BTreeSet<rv_lock::MetadataVersion>,
    /// What the resolution read from the host.
    pub(crate) host_reads: BTreeSet<HostInput>,
}

/// The sets of one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModulePluginSets {
    /// The module's POM path, relative to the workspace root.
    pub(crate) pom_path: String,
    /// Indexes into [`PluginResolution::sets`], in the order Maven loads
    /// them.
    pub(crate) sets: Vec<usize>,
    /// The plugins and processor path entries a reactor module
    /// provides, as `groupId:artifactId`: Maven takes them from the reactor.
    pub(crate) built_in_reactor: Vec<String>,
}

/// What one plugin, extension or processor path read that raeva.lock does
/// not hold, for the Maven 3.9 checks.
#[derive(Debug, Clone)]
pub struct SetReads {
    /// Its role and coordinates, for errors.
    pub name: String,
    /// What it is for.
    pub role: PluginRole,
    /// Each `group:artifact:version` whose POM it read or looked for, and
    /// those it found none for.
    pub poms: rv_lock::PomReads,
    /// The reactor modules it reaches that Maven 3.9 may build after it.
    pub reactor_later: Vec<String>,
}

/// The files one plugin, extension or processor path resolves to.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedPluginSet {
    /// `sha256:` of the role, the coordinates, the plugin's own
    /// dependencies, the repositories and the filtered artifacts.
    pub(crate) key: String,
    /// What the set is for.
    pub(crate) role: PluginRole,
    /// `groupId:artifactId:version` of the plugin or extension, or each
    /// processor path entry as `groupId:artifactId:type[:classifier]:version`.
    pub(crate) coordinates: Vec<String>,
    /// The repositories it resolves from, in Maven's order.
    pub(crate) repo_urls: Vec<String>,
    /// The artifacts on its class path, the plugin's own first, each with
    /// its companion POM.
    pub(crate) artifacts: Vec<ResolvedPackage>,
    /// The POMs read for it besides the artifacts' own: parents, imported
    /// BOMs, and the POMs of versions mediation dropped. By `g:a:v`.
    pub(crate) poms: Vec<(String, SupportPomProvenance)>,
    /// The ids of the repositories that served it, by normalized URL.
    pub(crate) repositories: Vec<(String, String)>,
    /// The versions its collections took from repository metadata.
    pub(crate) metadata_versions: Vec<rv_lock::MetadataVersion>,
    /// The versions its collections' ranges took, by the repository whose
    /// list named each.
    pub(crate) range_versions: Vec<rv_lock::RangeVersion>,
    /// Each `group:artifact:version` whose POM it read or looked for, and
    /// those it found none for, losing versions and range candidates too.
    pub(crate) pom_reads: rv_lock::PomReads,
    /// The reactor modules a plugin reaches that Maven 3.9 does not build
    /// before it ([`closure::unordered_reactor_files`]).
    pub(crate) reactor_later: Vec<String>,
}

/// A plugin prefix a goal named, which `mvn -o` finds in the group
/// metadata the export writes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PluginMetadata {
    /// The plugin group.
    pub(crate) group_id: String,
    /// The repository whose group metadata listed it.
    pub(crate) repo_url: String,
    /// That repository's id.
    pub(crate) repo_id: String,
    /// The prefix.
    pub(crate) prefix: String,
    /// The plugin's `artifactId`.
    pub(crate) artifact_id: String,
}

impl Resolver {
    /// Resolve what the build of every module of `workspace` on `platform`
    /// reads from repositories besides its dependencies; see the module
    /// documentation. Also what that read from the host, apart from the
    /// record of the run: the models' host values and the profile
    /// conditions of the builds.
    pub async fn resolve_plugins(
        &self,
        workspace: &Workspace,
        platform: &Platform,
        request: &PluginRequest,
        inputs: Sha256,
    ) -> Result<(PluginFiles, BTreeSet<HostInput>, Vec<SetReads>)> {
        let reads = HostReads::default();
        let config =
            (self.config).for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
        let client = self.client.for_platform(&config);
        let mut ctx = ResolveContext::from_config_with_state(
            config,
            Arc::clone(&self.store),
            platform.clone(),
            Some(client),
            ResolveState::with_plugin_sections(),
        )
        .recording_only_into(reads.clone());
        ctx.version_caps = self.caps_of(platform);
        let misses = Arc::clone(&ctx.model_misses);
        let listings = Arc::clone(&ctx.id_listings);
        let mut resolution = PlatformResolver::new(ctx)
            .resolve_plugins(Arc::new(workspace.clone()), request)
            .await
            .map_err(|error| ResolveContext::naming_filtered_models(&misses, error))?;
        let mode = self.config.lock.maven.mode;
        super::backend::refuse_split_listings(&listings, mode)?;
        let split_id = workspace.split_repository_id(&self.config).is_some();
        resolution.refuse_descriptor_reads(mode == rv_maven_types::MavenMode::Maven39, split_id)?;
        let mut host_reads = std::mem::take(&mut resolution.host_reads);
        host_reads.extend(reads.take());
        let set_reads = (resolution.sets.iter())
            .map(|set| SetReads {
                name: format!("{} {}", set.role.as_str(), set.coordinates.join(", ")),
                role: set.role,
                poms: set.pom_reads.clone(),
                reactor_later: set.reactor_later.clone(),
            })
            .collect();
        Ok((resolution.into_files(inputs)?, host_reads, set_reads))
    }

    /// The `group:artifact` of each build plugin and build extension of
    /// `workspace`'s modules on `platform` that no POM gives a version,
    /// which Maven takes from the plugin repositories' metadata.
    pub async fn unversioned_plugins(
        &self,
        workspace: &Workspace,
        platform: &Platform,
    ) -> Result<BTreeSet<(String, String)>> {
        let config =
            (self.config).for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
        let client = self.client.for_platform(&config);
        let ctx = ResolveContext::from_config_with_state(
            config,
            Arc::clone(&self.store),
            platform.clone(),
            Some(client),
            ResolveState::with_plugin_sections(),
        )
        .recording_only_into(HostReads::default());
        let workspace = Arc::new(workspace.clone());
        let resolver = PlatformResolver::new(ctx);
        let lineages = resolver.read_lineages(&workspace, None, None, workspace.len(), |_| false);
        let (models, _) = lineages.await?;
        let mut unversioned = BTreeSet::new();
        for module in workspace.modules() {
            let path = workspace.root().join(&module.pom_path);
            let module_resolver =
                PlatformResolver::new(resolver.ctx.for_module(resolver.ctx.config.clone()));
            let (project, _) = (module_resolver.plugin_project(
                &path,
                Arc::clone(&workspace),
                ModelPolicy::PROJECT_PLUGINS,
                None,
                Some(Arc::clone(&models)),
            ))
            .await
            .map_err(|error| error.in_module(&module.pom_path))?;
            let Some(model) = project.plugins()? else {
                continue;
            };
            let plugins = (model.plugins.iter())
                .filter(|plugin| plugin.version.is_none())
                .map(|plugin| (plugin.group_id.clone(), plugin.artifact_id.clone()));
            let extensions = (model.extensions.iter())
                .filter(|extension| extension.version.is_none())
                .map(|extension| (extension.group_id.clone(), extension.artifact_id.clone()));
            unversioned.extend(plugins.chain(extensions));
        }
        Ok(unversioned)
    }
}

impl PlatformResolver {
    async fn resolve_plugins(
        &self,
        workspace: Arc<Workspace>,
        request: &PluginRequest,
    ) -> Result<PluginResolution> {
        let mut planner = request::Planner::new(self, &workspace, request);
        let mut modules = Vec::new();
        let mut host_reads = BTreeSet::new();
        // Maven builds the projects in turn with one model cache, after
        // every lineage, and resolves a project's build extensions as it
        // builds it.
        let lineages = self.read_lineages(&workspace, None, None, workspace.len(), |_| false);
        let (models, _) = lineages.await?;
        planner.models = Arc::clone(&models);
        for (index, module) in workspace.modules().iter().enumerate() {
            let path = workspace.root().join(&module.pom_path);
            // The module's own state: its repositories decide what is missing.
            let resolver = Self::new(self.ctx.for_module(self.ctx.config.clone()));
            let (project, activation) = resolver
                .plugin_project(
                    &path,
                    Arc::clone(&workspace),
                    ModelPolicy::PROJECT_PLUGINS,
                    None,
                    Some(Arc::clone(&models)),
                )
                .await
                .map_err(|error| error.in_module(&module.pom_path))?;
            let root = (index == 0).then_some(&activation);
            let (keys, reads) = planner
                .plan_module(&module.pom_path, &project, root)
                .await
                .map_err(|error| plugin_error(&module.pom_path, error))?;
            host_reads.extend(reads);
            modules.push(keys);
        }
        let (requests, metadata, resolved, mut metadata_versions) = planner.finish();
        let built = lock(&models).clone();
        let resolved_sets = futures::stream::iter(requests)
            .map(|(key, request)| {
                let workspace = &workspace;
                let resolved = &resolved;
                // Core extensions are resolved before any project is.
                let models = match request.role {
                    PluginRole::CoreExtension => ModelCache::default(),
                    _ => built.clone(),
                };
                async move {
                    let set = match resolved.get(&key) {
                        Some(set) => set.clone(),
                        None => self
                            .resolve_set(&request, workspace, models, None, None)
                            .await
                            .map_err(|error| {
                                plugin_error(&request.module, request.failed(error))
                            })?,
                    };
                    Ok::<_, ResolveError>((key, set))
                }
            })
            .buffer_unordered(SET_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        let mut by_key = BTreeMap::new();
        for set in resolved_sets {
            let (key, set) = set?;
            metadata_versions.extend(set.metadata_versions.iter().cloned());
            by_key.insert(key, set);
        }
        let index: BTreeMap<String, usize> = (by_key.keys().cloned())
            .enumerate()
            .map(|(index, key)| (key, index))
            .collect();
        let modules = (modules.into_iter())
            .map(|planned| ModulePluginSets {
                pom_path: planned.pom_path,
                sets: planned.keys.iter().map(|key| index[key]).collect(),
                built_in_reactor: planned.built_in_reactor,
            })
            .collect();
        Ok(PluginResolution {
            sets: by_key.into_values().collect(),
            modules,
            metadata,
            metadata_versions,
            host_reads,
        })
    }

    /// The jar and artifact handlers of each build extension of the module
    /// at `path`, in Maven's order, and the SNAPSHOT parents and BOMs their
    /// realms read; see [`request::Planner::extension_handlers`].
    pub(super) async fn extension_handlers(
        &self,
        path: &std::path::Path,
        pom_path: &str,
        workspace: Arc<Workspace>,
        support_poms: Option<&WorkspaceSupportPomBuffer>,
        models: Arc<ModelCache>,
    ) -> Result<(
        Vec<request::ExtensionHandlers>,
        Vec<(String, SupportPomProvenance)>,
    )> {
        // What decides the build extensions is an input of the dependency
        // graph, which their handlers change.
        let resolver = Self::new(self.ctx.with_plugin_sections());
        let models = ReadModels::new(Mutex::new(Arc::unwrap_or_clone(models)));
        let (project, _) = resolver
            .plugin_project(
                path,
                Arc::clone(&workspace),
                ModelPolicy::PROJECT_EXTENSIONS,
                support_poms,
                Some(Arc::clone(&models)),
            )
            .await?;
        let model = (project.plugins())
            .map_err(|error| super::project_model_error(error.into(), path))?
            .ok_or_else(|| {
                ResolveError::InternalError("a plugins build keeps a plugin model".to_string())
            })?;
        self.ctx
            .record_reads(&Arc::new(model.extension_reads.clone()));
        let request = PluginRequest::default();
        let mut planner = request::Planner::new(&resolver, &workspace, &request);
        planner.support_poms = support_poms.cloned();
        planner.models = models;
        planner.extension_handlers(pom_path, &model).await
    }

    /// The project at `path`, built as a sync builds it, with its plugin
    /// model kept.
    async fn plugin_project(
        &self,
        path: &std::path::Path,
        workspace: Arc<Workspace>,
        policy: ModelPolicy,
        support_poms: Option<&WorkspaceSupportPomBuffer>,
        models: Option<ReadModels>,
    ) -> Result<(Project, ActivationContext)> {
        let (pom, activation, mut backend, local_parents) = self
            .root_model_inputs(path, &self.ctx.repos, workspace, support_poms, None, None)
            .await?;
        if let Some(models) = models {
            backend.read_models = models;
        }
        let project = Project::build(
            pom,
            &ModelScope::root(&backend, local_parents),
            policy,
            &activation,
        )
        .await
        .map_err(|error| super::project_model_error(error, path))?;
        Ok((project, activation))
    }
}

fn plugin_error(module: &str, error: ResolveError) -> ResolveError {
    match error {
        // A failure below a dependency of the set names its path there.
        ResolveError::Plugin {
            plugin,
            searched,
            error,
        } if matches!(*error, ResolveError::Declared { .. }) => ResolveError::Plugin {
            plugin,
            searched,
            error: Box::new(error.in_module(module)),
        },
        ResolveError::Plugin { .. } => ResolveError::Declared {
            module: module.to_string(),
            via: Vec::new(),
            error: Box::new(error),
        },
        error => error.in_module(module),
    }
}
