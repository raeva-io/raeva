//! Maven reactor discovery and effective-GAV indexing.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rv_config::maven_config::CommandLine;
use rv_maven_model::{
    ActivationContext, EffectiveDescriptor, Gav, MissingParent, ModelPolicy, Pom, PomError,
    Provenance,
};
use rv_maven_types::bounded;
use thiserror::Error;

use crate::parent_resolver::{
    LocalParentCache, LocalParents, accepted_local_parents, local_parent_boundary,
};
use rv_maven_model::held::{Held, par_map_held};

/// One POM participating in a discovered Maven reactor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspaceModule {
    /// The POM's path relative to the reactor root, with `/` separators and
    /// any `..` parts first, as raeva.lock records it.
    pub pom_path: String,
    /// The canonical path of the POM file, which discovery read.
    file: PathBuf,
    /// The module's effective GAV, active profiles, `<module>` entries and
    /// repositories, as discovery computed them: from local parents only,
    /// with the reactor root's `.mvn/maven.config` `-D` values applied.
    pub descriptor: EffectiveDescriptor,
    pom: Pom,
    local_parents: Vec<PathBuf>,
}

impl WorkspaceModule {
    /// The module's effective, interpolated GAV.
    pub fn gav(&self) -> &Gav {
        &self.descriptor.gav
    }

    /// The canonical path of the module's POM file. Read the module through
    /// this, never by joining [`Self::pom_path`] to a directory.
    pub fn pom_file(&self) -> &Path {
        &self.file
    }

    /// Raw user-authored POM retained for workspace-aware model resolution.
    pub fn pom(&self) -> &Pom {
        &self.pom
    }

    /// The local `<relativePath>` parents resolution reads for this module,
    /// from its parent to the farthest ancestor read from disk, by their
    /// canonical paths. A parent that is itself a module is listed too.
    pub fn local_parents(&self) -> &[PathBuf] {
        &self.local_parents
    }
}

/// What `ProjectSorter` links one reactor project to: see
/// [`Workspace::sorter_edges`].
#[derive(Debug, Clone, Default)]
pub(crate) struct SorterEdges {
    /// Its dependencies, then in the 3.10 mode its imports.
    pub(crate) links: Vec<usize>,
    /// Its parent, a link that wins over one back.
    pub(crate) parents: Vec<usize>,
}

/// A recursively discovered Maven reactor and its effective-GAV index.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Workspace {
    root: PathBuf,
    modules: Vec<WorkspaceModule>,
    gav_index: HashMap<Gav, usize>,
    /// group_id → artifact_id → module indices. Nested so hot lookups take
    /// `&str` keys and do not allocate a `(String, String)` per call.
    ga_index: HashMap<String, HashMap<String, Vec<usize>>>,
    maven_config: MavenConfig,
    local_parent_poms: Vec<PathBuf>,
    /// Discovery's local parent lookups, which metadata builds read again.
    pub(crate) parents: Arc<LocalParentCache>,
}

/// One module's entry in [`Workspace::resolution_contexts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleContext {
    /// The public context its freshness record digests.
    pub values: Vec<Option<String>>,
    /// The POM paths of the other reactor modules whose models `values`
    /// covers, or `None` when it covers every module.
    pub covers: Option<BTreeSet<String>>,
}

impl Workspace {
    /// Discover a reactor for linux-x86_64, with no JDK and no environment
    /// variables, whatever the host.
    #[cfg(test)]
    pub(crate) fn discover(root: impl AsRef<Path>) -> Result<Self, WorkspaceError> {
        let environment = rv_maven_model::ModelEnvironment::builder()
            .platform("linux", "x86_64")
            .build();
        Self::discover_with_context(
            root,
            ActivationContext::new(environment),
            &CommandLine::default(),
        )
    }

    #[cfg(test)]
    pub(crate) fn without_modules(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            modules: Vec::new(),
            gav_index: HashMap::new(),
            ga_index: HashMap::new(),
            maven_config: MavenConfig::default(),
            local_parent_poms: Vec::new(),
            parents: Arc::default(),
        }
    }

    /// Discover the reactor of `config`'s project for `platform`, the host
    /// platform when `None`, with the profiles, `.mvn/maven.config`, command
    /// line and model environment `config` gives.
    pub fn discover_project(
        config: &rv_config::Config,
        platform: Option<&rv_lock::Platform>,
    ) -> Result<Self, WorkspaceError> {
        let activation = crate::parent_resolver::build_activation_context(
            Some(config.project_root.clone()),
            config,
            platform,
        );
        Self::discover_with_context(&config.project_root, activation, config.command_line())
    }

    /// Discover a reactor with an activation context supplied by the caller.
    ///
    /// Discovery still reads the reactor root's `.mvn/maven.config` exactly
    /// once, merges `command_line` with it and overlays both on this
    /// context. Their `-D` properties and `-P`/`-!P` profile selections then
    /// apply to every discovered POM.
    pub(crate) fn discover_with_context(
        root: impl AsRef<Path>,
        mut activation: ActivationContext,
        command_line: &CommandLine,
    ) -> Result<Self, WorkspaceError> {
        let (canonical_root, root_pom) = canonical_reactor_root(root.as_ref())?;
        let config = MavenConfig::read(&canonical_root, command_line, &activation)?;
        config.apply(&mut activation);

        // Every module reads the same parents, so their parses are shared.
        // Maven 3.10 validates the plugin sections of these POMs.
        let parsed = match activation.environment.maven_mode() {
            rv_maven_types::MavenMode::Maven310 => {
                Arc::new(crate::parsed_pom_cache::ParsedPomCache::with_plugin_sections())
            }
            _ => Arc::default(),
        };
        let parents = Arc::new(LocalParentCache::new(parsed));
        Self::scan(&canonical_root, &root_pom, activation, &config, &parents)
            .map(|workspace| workspace.with_local_parent_poms(&parents))
    }

    /// Record the local parent POMs resolution accepts for this reactor's
    /// modules, other than the modules themselves.
    fn with_local_parent_poms(mut self, parents: &LocalParentCache) -> Self {
        let boundary = self.local_parent_boundary();
        let mut seen: HashSet<PathBuf> = self
            .modules
            .iter()
            .map(|module| module.file.clone())
            .collect();
        let accepted = |module: &WorkspaceModule| -> Vec<PathBuf> {
            accepted_local_parents(&module.file, &module.pom, &boundary, Some(parents.parsed()))
                .into_iter()
                .map(|parent| fs::canonicalize(&parent).unwrap_or(parent))
                .collect()
        };
        let local_parents = par_map_held(&self.modules, accepted);
        for (module, (local_parents, held)) in self.modules.iter_mut().zip(local_parents) {
            held.show();
            module.local_parents = local_parents;
        }
        let mut modules: Vec<_> = self.modules.iter().collect();
        modules.sort_by(|left, right| left.pom_path.cmp(&right.pom_path));
        let mut parents = Vec::new();
        for module in modules {
            for parent in &module.local_parents {
                if seen.insert(parent.clone()) {
                    parents.push(parent.clone());
                }
            }
        }
        self.local_parent_poms = parents;
        self
    }

    fn scan(
        canonical_root: &Path,
        root_pom: &Path,
        activation: ActivationContext,
        config: &MavenConfig,
        parents: &Arc<LocalParentCache>,
    ) -> Result<Self, WorkspaceError> {
        let mut scanner = Scanner {
            parents: Arc::clone(parents),
            root: canonical_root.to_path_buf(),
            parent_boundary: local_parent_boundary(canonical_root),
            activation,
            maven_config: config.clone(),
            modules: Vec::new(),
            gav_index: HashMap::new(),
            ga_index: HashMap::new(),
            done: HashSet::new(),
            stack: Vec::new(),
            prepared: HashMap::new(),
        };
        scanner.prepare_tree(root_pom);
        scanner.visit(root_pom.to_path_buf())?;

        Ok(Self {
            root: canonical_root.to_path_buf(),
            modules: scanner.modules,
            gav_index: scanner.gav_index,
            ga_index: scanner.ga_index,
            maven_config: config.clone(),
            local_parent_poms: Vec::new(),
            parents: Arc::clone(parents),
        })
    }

    /// The profile ids `-P` selects and deselects, on the command line and
    /// in `.mvn/maven.config`.
    pub fn profile_options(&self) -> (&[String], &[String]) {
        let config = &self.maven_config;
        (&config.active_profiles, &config.inactive_profiles)
    }

    /// Canonical reactor root directory, `\\?\`-prefixed on Windows. Join
    /// module paths to it to read their files; show or interpolate it only
    /// through [`rv_fs::plain_path`].
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The canonical POM file of the module whose path is `pom_path`, or
    /// `pom_path` joined to the root when no module has that path.
    pub fn module_file(&self, pom_path: &str) -> PathBuf {
        (self.modules.iter())
            .find(|module| module.pom_path == pom_path)
            .map_or_else(|| self.root.join(pom_path), |module| module.file.clone())
    }

    /// Directory that this reactor's local `<relativePath>` parents must stay
    /// inside. See [`local_parent_boundary`].
    pub(crate) fn local_parent_boundary(&self) -> PathBuf {
        local_parent_boundary(&self.root)
    }

    /// Canonical paths of the POMs outside the reactor's modules that
    /// resolution reads as local `<relativePath>` parents of a module, each
    /// once. The walk is the one resolution uses, so a parent it would not
    /// load, such as one outside the containment boundary or one that
    /// declares other coordinates, is not listed.
    pub fn local_parent_poms(&self) -> &[PathBuf] {
        &self.local_parent_poms
    }

    /// The canonical paths of the project's POM files a build may read, each
    /// once: the modules, those a profile discovery did not activate lists,
    /// with theirs in any profile, and the local `<relativePath>` parents of
    /// each, wherever they are, as Maven reads them. `options` says the build
    /// takes options discovery did not read, which may set the properties a
    /// `<module>` entry reads or select other profiles.
    ///
    /// # Errors
    ///
    /// Such a module whose entry keeps a `${...}`, which discovery did not
    /// interpolate, does not resolve or whose POM cannot be read, or more
    /// than 100,000 of them; with `options`, any module entry that keeps a
    /// `${...}`.
    pub fn project_poms(&self, options: bool) -> Result<Vec<PathBuf>, WorkspaceError> {
        let anywhere = self.root.ancestors().last().unwrap_or(&self.root);
        let parsed = self.parents.parsed();
        let mut poms = BTreeSet::new();
        let mut queue: Vec<(PathBuf, Pom, Option<&[String]>)> = (self.modules.iter())
            .map(|module| {
                let active = module.descriptor.selected_profiles().first();
                (
                    module.file.clone(),
                    module.pom.clone(),
                    Some(active.map_or(&[][..], Vec::as_slice)),
                )
            })
            .collect();
        let mut seen: HashSet<PathBuf> = queue.iter().map(|(path, ..)| path.clone()).collect();
        while let Some((path, pom, active)) = queue.pop() {
            poms.extend(
                accepted_local_parents(&path, &pom, anywhere, Some(parsed))
                    .into_iter()
                    .map(|parent| fs::canonicalize(&parent).unwrap_or(parent)),
            );
            let listed = (pom.modules.iter()).map(|entry| (entry, active.is_none(), None));
            let profiles = (pom.profiles.iter()).flat_map(|profile| {
                let inactive = active.is_none_or(|active| !active.contains(&profile.id));
                (profile.modules.iter())
                    .map(move |entry| (entry, inactive, Some(profile.id.as_str())))
            });
            for (entry, unread, profile) in listed.chain(profiles) {
                let declaring_pom = normalized_relative_pom(&self.root, &path);
                if (unread || options) && entry.contains("${") {
                    return Err(WorkspaceError::InvalidModule {
                        module: entry.trim().to_string(),
                        declaring_pom,
                    });
                }
                if !unread {
                    continue;
                }
                let module = resolve_module(&self.root, &path, entry, profile)?;
                if !seen.insert(module.clone()) {
                    continue;
                }
                if seen.len() > MAX_PROJECT_POMS {
                    return Err(WorkspaceError::InvalidModule {
                        module: entry.trim().to_string(),
                        declaring_pom,
                    });
                }
                let bytes = read_project_input(&module)?;
                let module_pom = (parsed
                    .parse_project(&rv_maven_types::BlobId::from_bytes(&bytes), &bytes))
                .map_err(|source| WorkspaceError::InvalidPom {
                    path: normalized_relative_pom(&self.root, &module),
                    source,
                })?;
                queue.push((module, Arc::unwrap_or_clone(module_pom), None));
            }
            poms.insert(path);
        }
        Ok(poms.into_iter().collect())
    }

    /// Modules in deterministic depth-first discovery order, starting at the
    /// aggregator itself.
    pub fn modules(&self) -> &[WorkspaceModule] {
        &self.modules
    }

    /// A repository id that names one repository among the dependency
    /// repositories of the settings.xml profiles of `config` and the
    /// reactor's POMs and another, by URL after mirrors, among their plugin
    /// repositories: the id, then the two URLs. Maven 3.9 and 3.10 take a
    /// POM from the local repository for a request that lists the id it was
    /// downloaded under, so a module reads the POM an extension or plugin
    /// read there, which its own repository may lack. `central` is left
    /// out: a repository that takes Central's id serves what Central does.
    pub fn split_repository_id(
        &self,
        config: &rv_config::Config,
    ) -> Option<(String, String, String)> {
        let by_id = |declared: Vec<rv_repo::Repository>| {
            let mut ids: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for repo in declared {
                if repo.id.as_deref() == Some("central") {
                    continue;
                }
                let repo = rv_repo::mirrored_repository(config, &repo);
                if let Some(id) = repo.id {
                    ids.entry(id).or_default().insert(repo.url);
                }
            }
            ids
        };
        // raeva.toml and config.toml are no input of Maven's.
        let descriptors = self.modules.iter().map(|module| &module.descriptor);
        let repositories = by_id(
            (descriptors
                .clone()
                .flat_map(|descriptor| &descriptor.repositories))
            .map(rv_repo::Repository::from)
            .chain(
                config
                    .settings_repositories()
                    .iter()
                    .map(rv_repo::Repository::from),
            )
            .collect(),
        );
        let plugin_repositories = by_id(
            (descriptors.flat_map(|descriptor| &descriptor.plugin_repositories))
                .map(rv_repo::Repository::from)
                .chain(
                    config
                        .profile_plugin_repositories()
                        .iter()
                        .map(rv_repo::Repository::from),
                )
                .chain(
                    config
                        .named_plugin_repositories()
                        .iter()
                        .map(rv_repo::Repository::from),
                )
                .collect(),
        );
        repositories.iter().find_map(|(id, urls)| {
            let others = plugin_repositories.get(id)?;
            urls.iter().find_map(|url| {
                let other = others.iter().find(|other| *other != url)?;
                Some((id.clone(), url.clone(), other.clone()))
            })
        })
    }

    /// Number of modules, the aggregator included.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Whether the reactor has no modules. Discovery always records the
    /// root POM, so a discovered reactor is never empty.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub(crate) fn module_provenance(&self, path: &Path) -> Option<Provenance> {
        let relative = normalized_relative_pom(&self.root, path);
        self.modules
            .iter()
            .find(|module| module.pom_path == relative)
            .and_then(|module| module.pom.provenance().cloned())
    }

    /// Look up a reactor member by its effective interpolated GAV.
    pub fn get(&self, gav: &Gav) -> Option<&WorkspaceModule> {
        self.gav_index
            .get(gav)
            .and_then(|index| self.modules.get(*index))
    }

    /// Public local model context, including every reactor BOM and reactor
    /// dependency a module can reach. A reactor dependency's model, with its
    /// repositories, feeds the consumer's graph like a BOM's management does.
    /// This walks discovery's descriptors only; it never builds or fetches a model.
    pub fn resolution_contexts(&self) -> BTreeMap<String, ModuleContext> {
        // A remote parent can decide a provisional module's group or version
        // whatever discovery read, so only its artifact id is certain.
        let known = |module: &WorkspaceModule| {
            let gav = &module.descriptor.context_gav;
            !module.descriptor.gav_is_provisional()
                && ![&gav.group_id, &gav.artifact_id, &gav.version]
                    .iter()
                    .any(|part| part.contains("${"))
        };
        let by_gav: HashMap<_, _> = self
            .modules
            .iter()
            .enumerate()
            .filter(|(_, module)| known(module))
            .map(|(index, module)| (&module.descriptor.context_gav, index))
            .collect();
        let open = |part: &str| part.contains("${");
        let mut by_artifact: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut open_artifacts = Vec::new();
        for (index, module) in self.modules.iter().enumerate() {
            let artifact = &module.descriptor.context_gav.artifact_id;
            if open(artifact) {
                open_artifacts.push(index);
            } else {
                by_artifact.entry(artifact).or_default().push(index);
            }
        }
        let mut hidden: Vec<bool> = self
            .modules
            .iter()
            .map(|module| module.descriptor.has_unread_parent)
            .collect();
        let imports: Vec<Vec<usize>> = self
            .modules
            .iter()
            .enumerate()
            .map(|(index, module)| {
                let mut targets = BTreeSet::new();
                for import in &module.descriptor.bom_imports {
                    if let Some(&target) = by_gav.get(import) {
                        targets.insert(target);
                    } else {
                        // A remote or uncertain import can hide arbitrary local
                        // imports. Represent that once, without dense edges.
                        hidden[index] = true;
                    }
                }
                // An expression matches any value, on either side; an open
                // artifact id could name any module.
                for (group, artifact) in &module.descriptor.dependencies {
                    if open(artifact) {
                        hidden[index] = true;
                        continue;
                    }
                    let named = by_artifact.get(artifact.as_str()).into_iter().flatten();
                    targets.extend(named.chain(&open_artifacts).copied().filter(|&target| {
                        let other = &self.modules[target].descriptor;
                        target != index
                            && (open(group)
                                || other.gav_is_provisional()
                                || open(&other.context_gav.group_id)
                                || *group == other.context_gav.group_id)
                    }));
                }
                targets.into_iter().collect()
            })
            .collect();
        let mut digests = HashMap::new();
        let mut all_digest = None;
        self.modules
            .iter()
            .enumerate()
            .map(|(index, module)| {
                let mut pending = imports[index].clone();
                let mut seen = HashSet::new();
                let mut all = hidden[index];
                if !all {
                    while let Some(imported) = pending.pop() {
                        if hidden[imported] {
                            all = true;
                            break;
                        }
                        if seen.insert(imported) {
                            pending.extend(&imports[imported]);
                        }
                    }
                }
                let mut seen: Vec<usize> = seen.into_iter().collect();
                seen.sort_by_key(|&index| &self.modules[index].pom_path);
                let covers = (!all).then(|| {
                    (seen.iter())
                        .map(|&index| self.modules[index].pom_path.clone())
                        .collect()
                });
                let mut context = module.descriptor.resolution_context.clone();
                if all {
                    let digest = all_digest.get_or_insert_with(|| {
                        let mut modules: Vec<_> = self.modules.iter().enumerate().collect();
                        modules.sort_by_key(|(_, module)| &module.pom_path);
                        let mut inputs = Vec::with_capacity(modules.len() * 2);
                        for (index, module) in modules {
                            let digest = digests.entry(index).or_insert_with(|| {
                                rv_lock::inputs::resolution_context_hash(
                                    &module.descriptor.resolution_context,
                                )
                            });
                            inputs.push(Some(module.pom_path.clone()));
                            inputs.push(Some(digest.to_string()));
                        }
                        rv_lock::inputs::resolution_context_hash(&inputs)
                    });
                    context.push(Some("potential-local-boms".into()));
                    context.push(Some(digest.to_string()));
                } else if !seen.is_empty() {
                    context.push(Some("local-boms".into()));
                    context.push(Some(seen.len().to_string()));
                    for imported in seen {
                        let bom = &self.modules[imported];
                        let digest = digests.entry(imported).or_insert_with(|| {
                            rv_lock::inputs::resolution_context_hash(
                                &bom.descriptor.resolution_context,
                            )
                        });
                        context.push(Some(bom.pom_path.clone()));
                        context.push(Some(digest.to_string()));
                    }
                }
                (
                    module.pom_path.clone(),
                    ModuleContext {
                        values: context,
                        covers,
                    },
                )
            })
            .collect()
    }

    /// Reactor members with the requested group/artifact identity.
    ///
    /// Multiple versions of one GA may participate in a reactor. Range and
    /// dynamic resolution treat each effective version as an ordinary
    /// candidate alongside versions advertised by repositories.
    pub(crate) fn candidates<'a>(
        &'a self,
        group_id: &str,
        artifact_id: &str,
    ) -> impl Iterator<Item = &'a WorkspaceModule> + 'a {
        self.ga_index
            .get(group_id)
            .and_then(|by_artifact| by_artifact.get(artifact_id))
            .into_iter()
            .flatten()
            .filter_map(|index| self.modules.get(*index))
    }

    /// The modules Maven's `ProjectSorter` links the reactor project
    /// `project`, module `index`, to: those its dependencies name, in order,
    /// in the 3.10 mode then those its POM's own `import` entries name, and
    /// its parent. A version that is empty or a range names every version of
    /// the id in the reactor.
    pub(crate) fn sorter_edges(
        &self,
        index: usize,
        project: &rv_maven_model::Project,
        mode: rv_maven_types::MavenMode,
    ) -> SorterEdges {
        let dependencies = project.dependencies.iter().map(|dependency| {
            (
                &dependency.group_id,
                &dependency.artifact_id,
                dependency.version.clone(),
            )
        });
        // Maven 3.10 reads them from the original model, as written but for
        // a version that is `${project.version}` or one property.
        let imports = (self.modules[index].pom.dependency_management.iter())
            .flat_map(|management| &management.dependencies)
            .filter(|_| mode == rv_maven_types::MavenMode::Maven310)
            .filter(|dependency| {
                dependency.scope.as_deref() == Some("import")
                    && dependency.type_.as_deref() == Some("pom")
            })
            .map(|dependency| {
                let version = dependency.version.as_deref().map(|version| {
                    let name = (version.strip_prefix("${"))
                        .and_then(|v| v.strip_suffix('}'))
                        .map(rv_maven_types::expression_key);
                    match name {
                        Some("project.version" | "pom.version") => project.version.clone(),
                        Some(name) => (project.properties.get(name))
                            .and_then(|value| {
                                project.properties.interpolate_str_no_project(value).ok()
                            })
                            .unwrap_or_else(|| version.to_string()),
                        None => version.to_string(),
                    }
                });
                (&dependency.group_id, &dependency.artifact_id, version)
            });
        let parent = (project.parent.iter()).map(|parent| {
            (
                &parent.group_id,
                &parent.artifact_id,
                Some(parent.version.clone()),
            )
        });
        SorterEdges {
            links: self.edges_to(index, dependencies.chain(imports)),
            parents: self.edges_to(index, parent),
        }
    }

    /// The modules `ProjectSorter` links module `index` to through the
    /// build plugins of `plugins`, their dependencies, then its build
    /// extensions.
    pub(crate) fn plugin_edges(
        &self,
        index: usize,
        model: &rv_maven_model::EffectivePlugins,
    ) -> Vec<usize> {
        let plugins = model.plugins.iter().flat_map(|plugin| {
            let dependencies = plugin.dependencies.iter().map(|dependency| {
                (
                    &dependency.group_id,
                    &dependency.artifact_id,
                    dependency.version.as_deref(),
                )
            });
            std::iter::once((
                &plugin.group_id,
                &plugin.artifact_id,
                plugin.version.as_deref(),
            ))
            .chain(dependencies)
        });
        let extensions = (model.extensions.iter()).map(|extension| {
            (
                &extension.group_id,
                &extension.artifact_id,
                extension.version.as_deref(),
            )
        });
        self.edges_to(index, plugins.chain(extensions))
    }

    fn edges_to<'a, V: AsRef<str>>(
        &self,
        index: usize,
        ids: impl Iterator<Item = (&'a String, &'a String, Option<V>)>,
    ) -> Vec<usize> {
        let mut edges = Vec::new();
        for (group, artifact, version) in ids {
            let version = version.as_ref().map(AsRef::as_ref);
            let specific = version.filter(|v| !v.is_empty() && !v.starts_with(['[', '(']));
            let ids = (self.ga_index.get(group))
                .and_then(|by_artifact| by_artifact.get(artifact))
                .into_iter()
                .flatten();
            edges.extend(ids.copied().filter(|&target| {
                target != index
                    && specific.is_none_or(|version| version == self.modules[target].gav().version)
            }));
        }
        edges
    }

    /// The projects as Maven's project builder lists them, which
    /// `ProjectSorter` takes in turn: each aggregator after its modules.
    pub(crate) fn project_order(&self) -> Vec<usize> {
        fn listed(modules: &[WorkspaceModule], index: usize, out: &mut Vec<usize>) -> usize {
            let mut next = index + 1;
            for _ in &modules[index].descriptor.modules {
                if next < modules.len() {
                    next = listed(modules, next, out);
                }
            }
            out.push(index);
            next
        }
        let mut projects = Vec::with_capacity(self.modules.len());
        let mut next = 0;
        while next < self.modules.len() {
            next = listed(&self.modules, next, &mut projects);
        }
        projects
    }

    /// The modules in Maven's `ProjectSorter` order, which the reactor
    /// builds them in, given each module's [`Self::sorter_edges`]: a
    /// depth-first walk that puts a project after those it links to, over
    /// the [`Self::project_order`]. Maven adds each project's edges in that
    /// order: a parent link drops one back from the parent, and each
    /// module's [`Self::plugin_edges`] follow its others but for one that
    /// would close a cycle, which Maven leaves out. Any other link that
    /// closes one fails the reactor: the error holds the `group:artifact`
    /// of each module on the cycle, joined by ` -> `.
    pub(crate) fn sorted(
        &self,
        edges: &[SorterEdges],
        plugin_edges: &[Vec<usize>],
    ) -> Result<Vec<usize>, String> {
        /// The path from `from` to `to`, both included.
        fn path(edges: &[Vec<usize>], from: usize, to: usize) -> Option<Vec<usize>> {
            let mut came = vec![None; edges.len()];
            let mut next = vec![from];
            came[from] = Some(from);
            while let Some(index) = next.pop() {
                if index == to {
                    let mut path = vec![to];
                    while let Some(&last) = path.last().filter(|&&last| last != from) {
                        path.push(came[last].expect("a visited vertex"));
                    }
                    path.reverse();
                    return Some(path);
                }
                for &target in &edges[index] {
                    if came[target].is_none() {
                        came[target] = Some(index);
                        next.push(target);
                    }
                }
            }
            None
        }
        fn visit(index: usize, edges: &[Vec<usize>], seen: &mut [bool], out: &mut Vec<usize>) {
            seen[index] = true;
            for &target in edges.get(index).into_iter().flatten() {
                if !seen[target] {
                    visit(target, edges, seen, out);
                }
            }
            out.push(index);
        }
        let projects = self.project_order();
        let mut dag = vec![Vec::new(); self.modules.len()];
        let none = SorterEdges::default();
        for &index in &projects {
            let edges = edges.get(index).unwrap_or(&none);
            let parents = edges.parents.iter().map(|&parent| (parent, true));
            for (target, parent) in (edges.links.iter())
                .map(|&link| (link, false))
                .chain(parents)
            {
                let back = dag[target].iter().position(|&linked| linked == index);
                if let Some(back) = back.filter(|_| parent) {
                    dag[target].remove(back);
                }
                if let Some(path) = path(&dag, target, index) {
                    let ids = (path.iter().chain([&target])).map(|&module| {
                        let gav = self.modules[module].gav();
                        format!("{}:{}", gav.group_id, gav.artifact_id)
                    });
                    return Err(ids.collect::<Vec<_>>().join(" -> "));
                }
                dag[index].push(target);
            }
            for &target in plugin_edges.get(index).into_iter().flatten() {
                if path(&dag, target, index).is_none() {
                    dag[index].push(target);
                }
            }
        }
        let mut seen = vec![false; self.modules.len()];
        let mut sorted = Vec::with_capacity(self.modules.len());
        for index in projects {
            if !seen[index] {
                visit(index, &dag, &mut seen, &mut sorted);
            }
        }
        Ok(sorted)
    }

    /// Return the effective version for a unique reactor member with this group and artifact.
    /// Return `None` if no member matches or several do.
    pub(crate) fn unique_version(&self, group_id: &str, artifact_id: &str) -> Option<String> {
        let mut candidates = self.candidates(group_id, artifact_id);
        let module = candidates.next()?;
        candidates
            .next()
            .is_none()
            .then(|| module.gav().version.clone())
    }

    /// This reactor indexed with the modules at the indices of `gavs` under
    /// those effective GAVs, failing as discovery does on a duplicate.
    pub fn with_effective_gavs(&self, gavs: Vec<(usize, Gav)>) -> Result<Self, WorkspaceError> {
        let mut workspace = self.clone();
        for (index, gav) in gavs {
            workspace.modules[index].descriptor.gav = gav;
        }
        workspace.gav_index.clear();
        workspace.ga_index.clear();
        for (index, module) in workspace.modules.iter().enumerate() {
            let gav = module.gav().clone();
            if let Some(first) = workspace.gav_index.insert(gav.clone(), index) {
                return Err(WorkspaceError::DuplicateGav {
                    first_pom: workspace.modules[first].pom_path.clone(),
                    second_pom: module.pom_path.clone(),
                    gav,
                });
            }
            workspace
                .ga_index
                .entry(gav.group_id)
                .or_default()
                .entry(gav.artifact_id)
                .or_default()
                .push(index);
        }
        Ok(workspace)
    }

    /// The reactor root's `.mvn/maven.config` read for the platform
    /// `activation` targets: its `-D` values and `-P` selections join the
    /// context and overlay `pom`'s properties.
    pub(crate) fn apply_root_maven_config(
        &self,
        activation: &mut ActivationContext,
        pom: &mut Pom,
    ) {
        let config = self.maven_config.for_platform(activation);
        config.apply(activation);
        config.inject_properties(pom);
    }

    /// The reactor root's `-D` values, read for the platform `activation`
    /// targets, and the names of those expanded from a `${...}`.
    pub(crate) fn root_user_properties(
        &self,
        activation: &ActivationContext,
    ) -> (HashMap<String, String>, BTreeSet<String>) {
        let config = self.maven_config.for_platform(activation);
        (config.properties, config.expanded_properties)
    }

    /// Overlay the reactor root's `-D` values, read for the platform
    /// `activation` targets, on `pom`'s properties.
    pub(crate) fn inject_root_properties(&self, pom: &mut Pom, activation: &ActivationContext) {
        self.maven_config
            .for_platform(activation)
            .inject_properties(pom);
    }
}

fn path_cycle(paths: &[String]) -> String {
    const SHOWN: usize = 16;
    let mut out = paths
        .iter()
        .take(SHOWN)
        .map(|path| bounded(path).to_string())
        .collect::<Vec<_>>()
        .join(" -> ");
    if paths.len() > SHOWN {
        out.push_str(&format!(" -> ... ({} POMs)", paths.len()));
    }
    out
}

/// Reactor discovery failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WorkspaceError {
    /// The given root is neither a directory nor a file named `pom.xml`, or
    /// its `pom.xml` canonicalizes to something other than a `pom.xml` file
    /// inside the root directory.
    #[error("reactor root is neither a directory nor pom.xml: {path}")]
    InvalidRoot {
        /// The root as the caller gave it.
        path: String,
    },
    /// A root or module path could not be read or canonicalized.
    #[error("failed to access workspace path {}: {source}", bounded(path))]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A module POM could not be parsed or its effective descriptor built.
    #[error("invalid POM at {path}: {source}")]
    InvalidPom {
        /// The POM's path relative to the reactor root, with `/` separators.
        path: String,
        /// What is wrong with it.
        #[source]
        source: PomError,
    },
    /// A `<module>` entry canonicalizes, after following links, to a path
    /// outside the directory its `..` parts reach from the reactor root, or
    /// it names one on another drive, which raeva.lock cannot record
    /// relative to the root.
    #[error(
        "module `{}` declared by {declaring_pom} escapes {workspace_root}, the directory its path \
         reaches from the reactor root",
        bounded(module)
    )]
    ModuleEscapes {
        /// The `<module>` entry, interpolated and trimmed.
        module: String,
        /// Root-relative path of the POM that declares it.
        declaring_pom: String,
        /// The canonical directory the entry reaches, or the reactor root
        /// for one on another drive, without a Windows `\\?\` prefix.
        workspace_root: String,
    },
    /// A `<module>` entry is empty or does not name a POM file or a
    /// directory holding a `pom.xml`.
    #[error(
        "module `{}` declared by {declaring_pom} does not resolve to a POM file",
        bounded(module)
    )]
    InvalidModule {
        /// The `<module>` entry, interpolated and trimmed.
        module: String,
        /// Root-relative path of the POM that declares it.
        declaring_pom: String,
    },
    /// A `<module>` entry names a directory or file that does not exist,
    /// which Maven reports as a child module that does not exist.
    #[error(
        "child module `{}` ({}) declared by {declaring_pom}{} does not exist",
        bounded(module),
        bounded(module_pom),
        profile.as_deref().map(|id| format!(" in profile {}", bounded(id))).unwrap_or_default()
    )]
    MissingModule {
        /// The `<module>` entry, interpolated and trimmed.
        module: String,
        /// The POM file the entry names, relative to the reactor root.
        module_pom: String,
        /// Root-relative path of the POM that declares it.
        declaring_pom: String,
        /// The active profile whose `<modules>` list the entry, `None` for
        /// the POM's own `<modules>`.
        profile: Option<String>,
    },
    /// `<modules>` lead back to a POM that is still being visited.
    #[error("aggregation cycle detected: {}", path_cycle(.cycle))]
    AggregationCycle {
        /// Root-relative POM paths on the cycle, ending with the POM it
        /// returns to.
        cycle: Vec<String>,
    },
    /// Two modules have the same effective GAV.
    #[error(
        "duplicate effective GAV {}: declared by both {first_pom} and {second_pom}",
        bounded(&gav.to_string())
    )]
    DuplicateGav {
        /// The shared GAV.
        gav: Gav,
        /// Root-relative path of the module discovered first.
        first_pom: String,
        /// Root-relative path of the module discovered second.
        second_pom: String,
    },
    /// `<modules>` reach one POM more than once, which Maven reports as a
    /// project duplicated in the reactor.
    #[error("module {pom} is listed more than once in the reactor")]
    DuplicateModule {
        /// Root-relative path of the POM.
        pom: String,
    },
    /// The reactor root's `.mvn/maven.config` holds an entry Maven rejects.
    #[error("Unable to parse maven.config file options in {path}: {source}")]
    InvalidMavenConfig {
        /// Path of the `maven.config` file, without a Windows `\\?\`
        /// prefix.
        path: String,
        /// The rejected entry.
        #[source]
        source: rv_config::maven_config::MavenConfigError,
    },
    /// A module POM or `maven.config` is larger than
    /// [`rv_config::MAX_PROJECT_INPUT_SIZE`].
    #[error("{path} exceeds the {limit}-byte project input limit")]
    ProjectInputTooLarge {
        /// The file's path, without a Windows `\\?\` prefix.
        path: String,
        /// The limit in bytes.
        limit: usize,
    },
}

/// The most module POMs [`Workspace::project_poms`] reads, so a hostile
/// tree cannot keep it going.
const MAX_PROJECT_POMS: usize = 100_000;

const DISCOVERY_POLICY: ModelPolicy = ModelPolicy {
    root: true,
    plugins: rv_maven_model::PluginModel::Repositories,
    missing_parent: MissingParent::InheritDeclaredCoordinates,
};

struct Scanner {
    root: PathBuf,
    /// Containment boundary for `<relativePath>` parents; see
    /// [`local_parent_boundary`].
    parent_boundary: PathBuf,
    activation: ActivationContext,
    /// Reactor root `.mvn/maven.config`, overlaid on every module POM before
    /// inheritance exactly as resolution overlays it.
    maven_config: MavenConfig,
    modules: Vec<WorkspaceModule>,
    gav_index: HashMap<Gav, usize>,
    ga_index: HashMap<String, HashMap<String, Vec<usize>>>,
    done: HashSet<PathBuf>,
    stack: Vec<PathBuf>,
    parents: Arc<LocalParentCache>,
    /// Each POM [`Scanner::prepare_tree`] reached, read and built ahead of
    /// the walk.
    prepared: HashMap<PathBuf, (Result<Prepared, WorkspaceError>, Held)>,
}

/// A module POM read, parsed and described, with the POMs its `<module>`
/// entries name, before the walk reaches it.
struct Prepared {
    pom_path: String,
    pom: Pom,
    descriptor: EffectiveDescriptor,
    modules: Vec<Result<PathBuf, WorkspaceError>>,
}

impl Scanner {
    fn visit(&mut self, canonical_pom: PathBuf) -> Result<(), WorkspaceError> {
        if self.done.contains(&canonical_pom) {
            return Err(WorkspaceError::DuplicateModule {
                pom: normalized_relative_pom(&self.root, &canonical_pom),
            });
        }
        if let Some(start) = self.stack.iter().position(|path| path == &canonical_pom) {
            let cycle = self.stack[start..]
                .iter()
                .chain([&canonical_pom])
                .map(|path| normalized_relative_pom(&self.root, path))
                .collect();
            return Err(WorkspaceError::AggregationCycle { cycle });
        }
        self.stack.push(canonical_pom.clone());

        let Prepared {
            pom_path,
            pom,
            descriptor,
            modules,
        } = match self.prepared.remove(&canonical_pom) {
            Some((prepared, held)) => {
                held.show();
                prepared
            }
            None => self.prepare(&canonical_pom, self.modules.is_empty()),
        }?;

        let index = self.modules.len();
        match self.gav_index.get(&descriptor.gav) {
            // Coordinates a remote parent completes are compared once the
            // resolution knows them.
            Some(existing_index)
                if descriptor.gav_is_provisional()
                    || self.modules[*existing_index]
                        .descriptor
                        .gav_is_provisional() => {}
            Some(existing_index) => {
                let first_pom = self.modules[*existing_index].pom_path.clone();
                return Err(WorkspaceError::DuplicateGav {
                    gav: descriptor.gav,
                    first_pom,
                    second_pom: pom_path,
                });
            }
            None => {
                self.gav_index.insert(descriptor.gav.clone(), index);
            }
        }

        self.ga_index
            .entry(descriptor.gav.group_id.clone())
            .or_default()
            .entry(descriptor.gav.artifact_id.clone())
            .or_default()
            .push(index);
        self.modules.push(WorkspaceModule {
            pom_path,
            file: canonical_pom.clone(),
            descriptor,
            pom,
            local_parents: Vec::new(),
        });

        for module_pom in modules {
            self.visit(module_pom?)?;
        }

        self.stack.pop();
        self.done.insert(canonical_pom);
        Ok(())
    }

    /// Read the POMs of the reactor rooted at `root` ahead of the walk, the
    /// modules of each level of the tree in parallel. What a read logs is
    /// held until the walk reaches its POM, so the log stops where the walk
    /// fails.
    fn prepare_tree(&mut self, root: &Path) {
        let mut seen = HashSet::from([root.to_path_buf()]);
        let mut level = vec![root.to_path_buf()];
        while !level.is_empty() {
            let prepared = par_map_held(&level, |pom| self.prepare(pom, pom == root));
            let mut next = Vec::new();
            for (pom, prepared) in level.into_iter().zip(prepared) {
                if let (Ok(prepared), _) = &prepared {
                    for module in prepared.modules.iter().flatten() {
                        if seen.insert(module.clone()) {
                            next.push(module.clone());
                        }
                    }
                }
                self.prepared.insert(pom, prepared);
            }
            level = next;
        }
    }

    /// Read, parse and describe the module POM at `canonical_pom`, the
    /// reactor's root when `root`, and resolve its `<module>` entries.
    fn prepare(&self, canonical_pom: &Path, root: bool) -> Result<Prepared, WorkspaceError> {
        let pom_path = normalized_relative_pom(&self.root, canonical_pom);
        let bytes = read_project_input(canonical_pom)?;
        let mut pom = (self.parents.parsed())
            .parse_project(&rv_maven_types::BlobId::from_bytes(&bytes), &bytes)
            .map(Arc::unwrap_or_clone)
            .map_err(|source| WorkspaceError::InvalidPom {
                path: pom_path.clone(),
                source,
            })?;
        rv_maven_model::check_project_pom(&bytes, None).map_err(|source| {
            WorkspaceError::InvalidPom {
                path: pom_path.clone(),
                source,
            }
        })?;
        let path = canonical_pom.to_path_buf();
        pom.set_provenance(if root {
            Provenance::RootProject { path }
        } else {
            Provenance::ReactorModule { path }
        });
        let mut module_activation = self.activation.clone();
        module_activation.base_dir = canonical_pom.parent().map(rv_fs::plain_path);
        let local_parents = match canonical_pom.parent() {
            Some(dir) => LocalParents::new(dir.to_path_buf(), self.parent_boundary.clone())
                .cached_in(Arc::clone(&self.parents)),
            None => LocalParents::none(),
        };
        // Resolution overlays the reactor root's `-D` user properties on a
        // module POM before building its model; discovery has to as well, or
        // the GAVs it indexes differ from the ones resolution produces.
        let mut inherited_pom = pom.clone();
        self.maven_config.inject_properties(&mut inherited_pom);
        // Discovery reads local parents only and goes on without any other
        // parent: the full build checks the rest. The source never waits.
        let descriptor = rv_maven_model::ready(EffectiveDescriptor::build(
            inherited_pom,
            &local_parents,
            DISCOVERY_POLICY,
            &module_activation,
        ))
        .map_err(|source| WorkspaceError::InvalidPom {
            path: pom_path.clone(),
            source,
        })?;

        let modules = descriptor
            .modules
            .iter()
            .map(|entry| {
                let profile = (!pom.modules.contains(entry))
                    .then(|| {
                        (pom.profiles.iter()).find(|profile| {
                            profile.modules.contains(entry)
                                && descriptor.active_profiles.contains(&profile.id)
                        })
                    })
                    .flatten();
                let profile = profile.map(|profile| profile.id.as_str());
                resolve_module(&self.root, canonical_pom, entry, profile)
            })
            .collect();
        Ok(Prepared {
            pom_path,
            pom,
            descriptor,
            modules,
        })
    }
}

/// The canonical POM file the `<module>` entry `module_entry` of
/// `declaring_pom` names, which must stay inside `root`.
fn resolve_module(
    root: &Path,
    declaring_pom: &Path,
    module_entry: &str,
    profile: Option<&str>,
) -> Result<PathBuf, WorkspaceError> {
    let declaring_pom_relative = normalized_relative_pom(root, declaring_pom);
    let module_entry = module_entry.trim();
    if module_entry.is_empty() {
        return Err(WorkspaceError::InvalidModule {
            module: module_entry.to_string(),
            declaring_pom: declaring_pom_relative,
        });
    }

    // Accept either platform separator on every host, then canonicalize
    // so aliases and symlinks share one identity.
    let portable_entry = module_entry.replace('\\', "/");
    let declaring_dir = declaring_pom.parent().unwrap_or(root);
    let candidate = rv_fs::join_pom_entry(declaring_dir, &portable_entry);
    let (candidate, pom_entry) = match fs::metadata(&candidate) {
        Ok(metadata) if metadata.is_dir() => (
            rv_fs::join_pom_entry_pom_xml(declaring_dir, &portable_entry),
            format!("{portable_entry}/pom.xml"),
        ),
        Ok(_) => (candidate, portable_entry),
        Err(source) => {
            let pom_candidate = if candidate.extension().is_some() {
                candidate
            } else {
                candidate.join("pom.xml")
            };
            if source.kind() == std::io::ErrorKind::NotFound {
                return Err(WorkspaceError::MissingModule {
                    module: module_entry.to_string(),
                    module_pom: normalized_relative_pom(root, &pom_candidate),
                    declaring_pom: declaring_pom_relative,
                    profile: profile.map(str::to_string),
                });
            }
            return Err(WorkspaceError::Io {
                path: display_path(&pom_candidate),
                source,
            });
        }
    };
    let mut canonical = canonicalize(&candidate, display_path(&candidate))?;
    // Maven checks that this file exists but reads the module through its
    // canonical path, which on Windows can be a sibling.
    let read = rv_fs::join_module_pom(declaring_dir, &pom_entry);
    if read != candidate {
        canonical = canonicalize(&read, display_path(&read))?;
    }

    // Maven reads a module wherever its entry points. raeva reads one below
    // the directory the entry's `..` parts reach from the root, not through
    // a link to elsewhere, and records its path relative to the root.
    let reach = match canonical.starts_with(root) {
        true => Some(root.to_path_buf()),
        false => entry_reach(root, &candidate, |path| fs::canonicalize(path).ok()),
    };
    if !reach
        .as_deref()
        .is_some_and(|reach| canonical.starts_with(reach))
    {
        return Err(WorkspaceError::ModuleEscapes {
            module: module_entry.to_string(),
            declaring_pom: declaring_pom_relative,
            workspace_root: display_path(reach.as_deref().unwrap_or(root)),
        });
    }
    // As in Maven, an entry may name the module's POM file under any name.
    if !canonical.is_file() {
        return Err(WorkspaceError::InvalidModule {
            module: module_entry.to_string(),
            declaring_pom: declaring_pom_relative,
        });
    }

    Ok(canonical)
}

fn canonical_reactor_root(root: &Path) -> Result<(PathBuf, PathBuf), WorkspaceError> {
    let metadata = fs::metadata(root).map_err(|source| WorkspaceError::Io {
        path: root.display().to_string(),
        source,
    })?;
    let (root_dir, root_pom) = if metadata.is_dir() {
        (root.to_path_buf(), root.join("pom.xml"))
    } else if metadata.is_file()
        && root.file_name().and_then(|name| name.to_str()) == Some("pom.xml")
    {
        let Some(parent) = root.parent() else {
            return Err(WorkspaceError::InvalidRoot {
                path: root.display().to_string(),
            });
        };
        (parent.to_path_buf(), root.to_path_buf())
    } else {
        return Err(WorkspaceError::InvalidRoot {
            path: root.display().to_string(),
        });
    };

    // On Windows these keep the `\\?\` prefix at any length, as module POMs
    // below the root do, so `starts_with` compares one form and every read
    // opens the file that was canonicalized. Dropping the prefix would let
    // Windows trim a trailing dot and read a sibling directory instead.
    let canonical_root = canonicalize(&root_dir, root_dir.display().to_string())?;
    let canonical_pom = canonicalize(&root_pom, root_pom.display().to_string())?;
    if !canonical_pom.starts_with(&canonical_root)
        || canonical_pom.file_name().and_then(|name| name.to_str()) != Some("pom.xml")
        || !canonical_pom.is_file()
    {
        return Err(WorkspaceError::InvalidRoot {
            path: root.display().to_string(),
        });
    }
    Ok((canonical_root, canonical_pom))
}

/// Read a module POM under [`rv_config::MAX_PROJECT_INPUT_SIZE`] so a huge
/// file cannot drive an unbounded allocation during discovery.
fn read_project_input(path: &Path) -> Result<Vec<u8>, WorkspaceError> {
    rv_config::read_project_input(path).map_err(|error| workspace_input_error(path, error))
}

fn workspace_input_error(path: &Path, error: rv_config::ConfigError) -> WorkspaceError {
    let path = display_path(path);
    match error {
        rv_config::ConfigError::ProjectInputIo { source, .. } => {
            WorkspaceError::Io { path, source }
        }
        rv_config::ConfigError::ProjectInputTooLarge { limit, .. } => {
            WorkspaceError::ProjectInputTooLarge { path, limit }
        }
        // Matches what an unbounded `read_to_string` reported for non-UTF-8
        // input, so callers see no new failure shape.
        other => WorkspaceError::Io {
            path,
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
        },
    }
}

fn canonicalize(path: &Path, shown: String) -> Result<PathBuf, WorkspaceError> {
    fs::canonicalize(path).map_err(|source| WorkspaceError::Io {
        path: shown,
        source,
    })
}

fn display_path(path: &Path) -> String {
    rv_fs::plain_path(path).display().to_string()
}

/// `pom` relative to `root` with `/` between its parts, any `..` parts
/// first, as raeva.lock names a module, or the whole of `pom` when it is on
/// another drive. A Windows root is verbatim (`\\?\`), which a joined `/`
/// path takes `\` from.
pub(crate) fn normalized_relative_pom(root: &Path, pom: &Path) -> String {
    let parts = relative_parts(root, pom).unwrap_or_else(|| {
        (pom.components())
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect()
    });
    parts.join("/")
}

/// The parts of `path` relative to `root`, `..` first, `None` when the two
/// share no prefix or root. Both are canonical or lexically normal.
fn relative_parts(root: &Path, path: &Path) -> Option<Vec<String>> {
    let root: Vec<_> = root.components().collect();
    let path: Vec<_> = path.components().collect();
    let common = (root.iter().zip(&path))
        .take_while(|(left, right)| left == right)
        .count();
    if common == 0 {
        return None;
    }
    let up = std::iter::repeat_n("..".to_string(), root.len() - common);
    let down = path[common..]
        .iter()
        .map(|component| component.as_os_str().to_string_lossy().into_owned());
    Some(up.chain(down).collect())
}

/// `path` with its `.` parts dropped and each `..` part taking off the part
/// before it, without reading the file system.
pub(crate) fn lexically_normal(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    normal
}

/// The ancestor of `root` that the module path `candidate` reaches: the
/// deepest of the root's ancestors that `candidate`'s leading parts, read
/// lexically, pass through by `canonical` path, `root` itself for a path
/// below it. The canonical form settles any spelling: case on a file system
/// that ignores it, a link to one of the root's directories, `\\?\` or
/// not. A part whose canonical path is no deeper along the root's ancestors
/// ends the walk, so a link to an ancestor reaches no further than the
/// directory it sits in. `None` when not even the file system root of
/// `candidate` is one of `root`'s, as on another drive.
fn entry_reach(
    root: &Path,
    candidate: &Path,
    canonical: impl Fn(&Path) -> Option<PathBuf>,
) -> Option<PathBuf> {
    let mut prefix = PathBuf::new();
    let mut reach: Option<PathBuf> = None;
    for component in lexically_normal(candidate).components() {
        prefix.push(component);
        // A prefix alone names no directory: `C:` is the drive's current
        // directory and `\\?\C:` the volume itself.
        if matches!(component, std::path::Component::Prefix(_)) || !prefix.has_root() {
            continue;
        }
        let Some(next) = canonical(&prefix) else {
            break;
        };
        let deeper = reach.as_ref().is_none_or(|reach| {
            next.starts_with(reach) && next.components().count() > reach.components().count()
        });
        if !deeper || !root.starts_with(&next) {
            break;
        }
        reach = Some(next);
    }
    reach
}

#[derive(Debug, Clone, Default)]
struct MavenConfig {
    root: PathBuf,
    content: Option<String>,
    command_line: CommandLine,
    properties: HashMap<String, String>,
    expanded_properties: BTreeSet<String>,
    active_profiles: Vec<String>,
    inactive_profiles: Vec<String>,
}

impl MavenConfig {
    fn read(
        root: &Path,
        command_line: &CommandLine,
        activation: &ActivationContext,
    ) -> Result<Self, WorkspaceError> {
        // `mvn` reads the file in its project directory, the launcher's.
        let launcher = activation.environment.launcher_root().map(Path::new);
        let path = launcher.unwrap_or(root).join(".mvn").join("maven.config");
        let content = rv_config::read_optional_project_input_string(&path)
            .map_err(|error| workspace_input_error(&path, error))?;
        let root = rv_fs::plain_path(root);
        Self::parse_for(&root, content, command_line, activation).map_err(|source| {
            WorkspaceError::InvalidMavenConfig {
                path: display_path(&path),
                source,
            }
        })
    }

    #[cfg(test)]
    fn parse(content: &str) -> Result<Self, rv_config::maven_config::MavenConfigError> {
        Self::parse_for(
            Path::new("/project"),
            Some(content.to_string()),
            &CommandLine::default(),
            &ActivationContext::default(),
        )
    }

    /// `${...}` in `-D` and `-P` values sees the `os.*` system properties of
    /// the platform `activation` targets.
    fn parse_for(
        root: &Path,
        content: Option<String>,
        command_line: &CommandLine,
        activation: &ActivationContext,
    ) -> Result<Self, rv_config::maven_config::MavenConfigError> {
        let options = rv_config::maven_config::parse_for(
            content.as_deref(),
            command_line,
            &activation.environment,
            root,
        )?;
        Ok(Self {
            root: root.to_path_buf(),
            content,
            command_line: command_line.clone(),
            properties: options.properties,
            expanded_properties: options.expanded_properties,
            active_profiles: options.active_profiles,
            inactive_profiles: options.inactive_profiles,
        })
    }

    fn for_platform(&self, activation: &ActivationContext) -> Self {
        if self.content.is_none() && self.command_line == CommandLine::default() {
            return self.clone();
        }
        Self::parse_for(
            &self.root,
            self.content.clone(),
            &self.command_line,
            activation,
        )
        .unwrap_or_else(|_| self.clone())
    }

    /// Overlay the `-D` entries on a POM's own `<properties>`.
    ///
    /// Maven user properties sit above POM properties, so a same-named entry
    /// overwrites. Resolution does this to every POM it builds a model from,
    /// and discovery does it to every module POM so both see the same
    /// effective coordinates.
    fn inject_properties(&self, pom: &mut Pom) {
        pom.overlay_user_properties(&self.properties);
    }

    fn apply(&self, activation: &mut ActivationContext) {
        activation.properties.extend(self.properties.clone());
        activation
            .expanded_properties
            .extend(self.expanded_properties.iter().cloned());
        append_unique(
            &mut activation.active_profiles,
            self.active_profiles.clone(),
        );
        append_unique(
            &mut activation.inactive_profiles,
            self.inactive_profiles.clone(),
        );
    }
}

fn append_unique(destination: &mut Vec<String>, values: Vec<String>) {
    let mut seen: HashSet<String> = destination.iter().cloned().collect();
    for value in values {
        if seen.insert(value.clone()) {
            destination.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_test_support::fixtures;

    fn fixture(name: &str) -> PathBuf {
        fixtures::path("reactor-discovery").join(name)
    }

    /// Directories a `fixture` call below opens. A new directory must fail
    /// here until a test names it.
    fn reactor_discovery_dirs() -> Vec<String> {
        let mut names =
            fixtures::quoted_after(include_str!("workspace.rs"), concat!("fixture", "("));
        names.sort();
        names.dedup();
        names
    }

    #[test]
    fn every_reactor_discovery_directory_is_used() {
        let names = reactor_discovery_dirs();
        let dirs: Vec<&str> = names.iter().map(String::as_str).collect();
        let root = fixtures::path("reactor-discovery");
        fixtures::assert_children(&root, &dirs, &[]);
        for name in &names {
            assert!(
                root.join(name).join("pom.xml").is_file(),
                "{name}: pom.xml is missing"
            );
        }
    }

    fn gav(group_id: &str, artifact_id: &str, version: &str) -> Gav {
        Gav {
            group_id: group_id.to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
        }
    }

    #[test]
    fn local_bom_context_follows_nested_imports_and_ignores_metadata() {
        let dir = tempfile::tempdir().unwrap();
        write_pom(dir.path(), "root", &["a", "b", "c"]);
        for (name, imported) in [("a", "c"), ("b", "a")] {
            let module = dir.path().join(name);
            fs::create_dir_all(&module).unwrap();
            fs::write(module.join("pom.xml"), format!("<project><groupId>g</groupId><artifactId>{name}</artifactId><version>1</version><packaging>pom</packaging><dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>{imported}</artifactId><version>${{selected}}</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>")).unwrap();
        }
        let c = dir.path().join("c");
        fs::create_dir_all(&c).unwrap();
        let bom = "<project><groupId>g</groupId><artifactId>c</artifactId><version>1</version><packaging>pom</packaging><dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>1</version></dependency></dependencies></dependencyManagement></project>";
        fs::write(c.join("pom.xml"), bom).unwrap();
        let context = |value: &str| {
            let mut ctx = ActivationContext::default();
            ctx.properties.insert("selected".into(), value.into());
            Workspace::discover_with_context(dir.path(), ctx, &CommandLine::default())
                .unwrap()
                .resolution_contexts()
        };
        let base = context("private-one");
        assert_eq!(base, context("private-two"));
        fs::write(
            c.join("pom.xml"),
            bom.replace("</project>", "<description>edited</description></project>"),
        )
        .unwrap();
        assert_eq!(base, context("private-one"));
        fs::write(
            c.join("pom.xml"),
            bom.replace(
                "<artifactId>lib</artifactId><version>1</version>",
                "<artifactId>lib</artifactId><version>2</version>",
            ),
        )
        .unwrap();
        let changed = context("private-one");
        assert_ne!(base["a/pom.xml"], changed["a/pom.xml"]);
        assert_ne!(base["b/pom.xml"], changed["b/pom.xml"]);
        assert_eq!(base["pom.xml"], changed["pom.xml"]);
    }

    #[test]
    fn reactor_dependency_context_follows_the_dependency_chain() {
        let dir = tempfile::tempdir().unwrap();
        write_pom(dir.path(), "root", &["a", "b", "c", "d"]);
        let dependency = |artifact: &str| {
            format!(
                "<dependencies><dependency><groupId>${{project.groupId}}</groupId><artifactId>{artifact}</artifactId><version>${{project.version}}</version></dependency></dependencies>"
            )
        };
        for (name, body) in [
            ("a", dependency("c")),
            ("b", dependency("a")),
            ("c", String::new()),
            ("d", String::new()),
        ] {
            let module = dir.path().join(name);
            fs::create_dir_all(&module).unwrap();
            fs::write(module.join("pom.xml"), format!("<project><groupId>g</groupId><artifactId>{name}</artifactId><version>1</version>{body}</project>")).unwrap();
        }
        let contexts = || {
            Workspace::discover(dir.path())
                .unwrap()
                .resolution_contexts()
        };
        let base = contexts();
        let c = dir.path().join("c/pom.xml");
        let edit = |replacement: &str| {
            fs::write(&c, format!("<project><groupId>g</groupId><artifactId>c</artifactId><version>1</version>{replacement}</project>")).unwrap();
            contexts()
        };
        assert_eq!(base, edit("<description>edited</description>"));
        let changed = edit(
            "<repositories><repository><id>r</id><url>https://repo.example/</url></repository></repositories>",
        );
        for path in ["a/pom.xml", "b/pom.xml", "c/pom.xml"] {
            assert_ne!(base[path], changed[path], "{path}");
        }
        assert_eq!(base["d/pom.xml"], changed["d/pom.xml"]);
        assert_eq!(base["pom.xml"], changed["pom.xml"]);
    }

    #[test]
    fn uncertain_imports_share_one_global_context_instead_of_dense_closures() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..256).map(|index| format!("m{index}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        write_pom(dir.path(), "root", &refs);
        for name in &names {
            let module = dir.path().join(name);
            fs::create_dir_all(&module).unwrap();
            fs::write(module.join("pom.xml"), format!("<project><groupId>g</groupId><artifactId>{name}</artifactId><version>1</version><dependencyManagement><dependencies><dependency><groupId>${{group}}</groupId><artifactId>${{artifact}}</artifactId><version>${{version}}</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>")).unwrap();
        }
        let workspace = Workspace::discover(dir.path()).unwrap();
        let contexts = workspace.resolution_contexts();
        let mut global = None;
        for module in &workspace.modules[1..] {
            let context = &contexts[&module.pom_path].values;
            assert_eq!(
                context.len(),
                module.descriptor.resolution_context.len() + 2
            );
            let suffix = &context[context.len() - 2..];
            assert_eq!(suffix[0].as_deref(), Some("potential-local-boms"));
            if let Some(previous) = global {
                assert_eq!(previous, suffix);
            }
            global = Some(suffix);
        }
    }

    #[test]
    fn model_field_property_cannot_hide_the_actual_reactor_bom() {
        let dir = tempfile::tempdir().unwrap();
        write_pom(dir.path(), "root", &["a1", "a2", "b"]);
        for (name, version) in [("a1", "1"), ("a2", "2")] {
            let module = dir.path().join(name);
            fs::create_dir_all(&module).unwrap();
            fs::write(module.join("pom.xml"), format!("<project><groupId>g</groupId><artifactId>a</artifactId><version>{version}</version><packaging>pom</packaging></project>")).unwrap();
        }
        let b = dir.path().join("b");
        fs::create_dir_all(&b).unwrap();
        fs::write(b.join("pom.xml"), "<project><groupId>g</groupId><artifactId>b</artifactId><version>1</version><properties><project.version>2</project.version><alias>${project.version}</alias></properties><dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${alias}</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>").unwrap();
        let before = Workspace::discover(dir.path())
            .unwrap()
            .resolution_contexts();
        let a = dir.path().join("a1/pom.xml");
        let changed = fs::read_to_string(&a).unwrap().replace("</project>", "<dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId><version>2</version></dependency></dependencies></dependencyManagement></project>");
        fs::write(a, changed).unwrap();
        let after = Workspace::discover(dir.path())
            .unwrap()
            .resolution_contexts();
        assert_ne!(before["b/pom.xml"], after["b/pom.xml"]);
    }

    #[cfg(windows)]
    #[test]
    fn canonical_root_is_not_a_verbatim_path() {
        let workspace = Workspace::discover(fixture("profile-config")).expect("discover");
        let root = rv_fs::plain_path(workspace.root());
        let root = root.to_string_lossy();
        assert!(!root.starts_with(r"\\?\"), "verbatim workspace root {root}");
    }

    /// `ProjectSorter` adds each project's edges in turn and leaves out a
    /// build plugin edge that would close a cycle: `x` and `q` depend on
    /// `p`, whose build plugin `q` is, and Maven 3.9.12 sorts `p`, `x`, `q`.
    #[test]
    fn a_plugin_edge_that_closes_a_cycle_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        write_pom(dir.path(), "root", &["x", "q", "p"]);
        for name in ["x", "q", "p"] {
            write_pom(&dir.path().join(name), name, &[]);
        }
        let workspace = Workspace::discover(dir.path()).unwrap();
        let links = |links: Vec<usize>| SorterEdges {
            links,
            parents: Vec::new(),
        };
        let edges = [links(vec![]), links(vec![3]), links(vec![3]), links(vec![])];
        let plugins = [vec![], vec![], vec![], vec![2]];
        assert_eq!(workspace.sorted(&edges, &plugins), Ok(vec![3, 1, 2, 0]));
    }

    /// A parent link drops the parent's link back to the project, as
    /// `ProjectSorter` forces it, when the parent was taken first: `p`
    /// depends on `c`, whose parent it is, and Maven sorts `p`, `c`. Taken
    /// after its child, the parent's link closes a cycle.
    #[test]
    fn a_parent_link_wins_over_the_link_back() {
        let dir = tempfile::tempdir().unwrap();
        write_pom(dir.path(), "root", &["p", "c"]);
        for name in ["p", "c"] {
            write_pom(&dir.path().join(name), name, &[]);
        }
        let workspace = Workspace::discover(dir.path()).unwrap();
        let edges = |links: Vec<usize>, parents: Vec<usize>| SorterEdges { links, parents };
        let sorted = workspace.sorted(
            &[
                edges(vec![], vec![]),
                edges(vec![2], vec![]),
                edges(vec![], vec![1]),
            ],
            &[],
        );
        assert_eq!(sorted, Ok(vec![1, 2, 0]));
        let sorted = workspace.sorted(
            &[
                edges(vec![], vec![]),
                edges(vec![], vec![2]),
                edges(vec![1], vec![]),
            ],
            &[],
        );
        assert_eq!(
            sorted,
            Err("com.example:p -> com.example:c -> com.example:p".to_string())
        );
    }

    fn write_pom(dir: &Path, artifact_id: &str, modules: &[&str]) {
        let modules: String = modules
            .iter()
            .map(|module| format!("<module>{module}</module>"))
            .collect();
        fs::create_dir_all(dir).expect("create POM directory");
        fs::write(
            dir.join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                 <artifactId>{artifact_id}</artifactId><version>1</version>\
                 <packaging>pom</packaging><modules>{modules}</modules></project>"
            ),
        )
        .expect("write POM");
    }

    /// A reactor whose modules sit beside its root, as re3gistry's
    /// `Re3gistry2-build-helper` lists `../Re3gistry2Model`, is read as Maven
    /// reads it, each module path relative to the root with its `..` parts
    /// first. A module two levels up, one declared by such a module, and one
    /// an absolute entry names, as `${project.basedir}/../x` does, are too;
    /// each module POM is known by its canonical path.
    #[test]
    fn discovers_modules_beside_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sources = dir.path().join("checkout").join("sources");
        let helper = sources.join("helper");
        let absolute = format!("{}/../absolute", helper.display());
        write_pom(
            &helper,
            "helper",
            &["../model", "../base", "../../tools", &absolute],
        );
        write_pom(&sources.join("model"), "model", &[]);
        write_pom(&sources.join("base"), "base", &["../extra"]);
        write_pom(&sources.join("extra"), "extra", &[]);
        write_pom(&dir.path().join("checkout").join("tools"), "tools", &[]);
        write_pom(&sources.join("absolute"), "absolute", &[]);

        let workspace = Workspace::discover(&helper).expect("sibling reactor");
        assert_eq!(
            module_artifacts(&workspace),
            [
                ("pom.xml", "helper"),
                ("../model/pom.xml", "model"),
                ("../base/pom.xml", "base"),
                ("../extra/pom.xml", "extra"),
                ("../../tools/pom.xml", "tools"),
                ("../absolute/pom.xml", "absolute"),
            ]
        );
        let canonical = fs::canonicalize(sources.join("extra").join("pom.xml")).unwrap();
        assert_eq!(workspace.modules()[3].pom_file(), canonical);
    }

    /// A module beside the root that is a link to elsewhere, or to an
    /// ancestor, escapes the directory its `..` parts reach, as a link below
    /// the root does. On Windows the link is a junction.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_module_beside_the_root_stays_where_its_entry_points() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = fs::canonicalize(dir.path()).expect("canonical tempdir");
        let sources = dir.join("sources");
        let helper = sources.join("helper");
        write_pom(&dir, "top", &[]);
        write_pom(&dir.join("outside"), "outside", &[]);
        fs::create_dir_all(&sources).expect("sources");
        #[cfg(unix)]
        let link = |target: &Path, at: &Path| std::os::unix::fs::symlink(target, at).unwrap();
        #[cfg(windows)]
        let link = |target: &Path, at: &Path| rv_test_support::create_junction(at, target).unwrap();
        link(&dir.join("outside"), &sources.join("linked"));
        link(&dir, &sources.join("up"));
        for entry in ["../linked", "../up"] {
            write_pom(&helper, "helper", &[entry]);
            let error = Workspace::discover(&helper).expect_err(entry);
            assert!(
                matches!(&error, WorkspaceError::ModuleEscapes { workspace_root, .. }
                    if *workspace_root == display_path(&sources)),
                "{entry}: {error}"
            );
        }
    }

    /// An entry that spells the root's directories another way, through a
    /// link to one of them, reaches no further than the same entry spelled
    /// canonically: a link below the root to elsewhere still escapes. So
    /// does a link to an ancestor of the root, as a module or on the way to
    /// one.
    #[cfg(unix)]
    #[test]
    fn a_module_entry_reaches_no_further_by_another_spelling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = fs::canonicalize(dir.path()).expect("canonical tempdir");
        let root = dir.join("real").join("p").join("root");
        let link = |target: &Path, at: &Path| std::os::unix::fs::symlink(target, at).unwrap();
        write_pom(&dir.join("outside"), "outside", &[]);
        write_pom(&dir, "top", &[]);
        write_pom(&dir.join("real"), "real", &[]);
        fs::create_dir_all(&root).expect("root");
        link(&dir.join("real"), &dir.join("alias"));
        link(&dir.join("outside"), &root.join("linked"));
        link(&dir.join("real"), &root.join("up"));
        link(&dir, &dir.join("real").join("p").join("a"));
        let aliased = format!("{}/alias/p/root/linked", dir.display());
        for entry in [aliased.as_str(), "up", "../a"] {
            write_pom(&root, "root", &[entry]);
            let error = Workspace::discover(&root).expect_err(entry);
            assert!(
                matches!(error, WorkspaceError::ModuleEscapes { .. }),
                "{entry}: {error}"
            );
        }
    }

    /// The directory an entry reaches is the deepest of the root's own
    /// ancestors its parts pass through, by canonical path, as on a file
    /// system that ignores case, where `C:\work` is `C:\Work`.
    #[test]
    fn an_entry_reaches_the_root_ancestor_its_parts_pass_through() {
        let real = ["/", "/Work", "/Work/Root", "/Work/app", "/Other"];
        let canonical = |path: &Path| {
            let folded = path.to_string_lossy().replace('\\', "/").to_lowercase();
            let link = (folded == "/work/root/link").then(|| PathBuf::from("/Other"));
            link.or_else(|| {
                (real.iter())
                    .find(|real| real.to_lowercase() == folded)
                    .map(PathBuf::from)
            })
        };
        let root = Path::new("/Work/Root");
        for (candidate, reach) in [
            ("/work/Root/link/pom.xml", Some("/Work/Root")),
            ("/WORK/root/../app/pom.xml", Some("/Work")),
            ("/Work/Root/../app/pom.xml", Some("/Work")),
            ("/Other/pom.xml", Some("/")),
            ("/missing/pom.xml", Some("/")),
        ] {
            assert_eq!(
                entry_reach(root, Path::new(candidate), canonical).as_deref(),
                reach.map(Path::new),
                "{candidate}"
            );
        }
    }

    /// A UNC root, which canonical form spells `\\?\UNC\`, reaches a
    /// sibling on the same share that an absolute entry names plainly.
    #[cfg(windows)]
    #[test]
    fn a_unc_entry_reaches_its_share() {
        let canonical = |path: &Path| {
            let plain = path.to_string_lossy();
            let rest = plain.strip_prefix(r"\\server\share")?;
            Some(PathBuf::from(format!(r"\\?\UNC\server\share{rest}")))
        };
        let root = Path::new(r"\\?\UNC\server\share\helper");
        let candidate = Path::new(r"\\server\share\app\pom.xml");
        assert_eq!(
            entry_reach(root, candidate, canonical).as_deref(),
            Some(Path::new(r"\\?\UNC\server\share\"))
        );
    }

    /// A `\\?\` entry, as one joined to a canonical directory is, reaches
    /// past its prefix, which alone names the volume or share, not its root
    /// directory.
    #[cfg(windows)]
    #[test]
    fn a_verbatim_entry_reaches_past_its_prefix() {
        let canonical = |path: &Path| {
            let bare = [r"\\?\C:", r"\\?\UNC\server\share"].contains(&path.to_str()?);
            (!bare).then(|| path.to_path_buf())
        };
        for (root, candidate, reach) in [
            (
                r"\\?\C:\work\root",
                r"\\?\C:\work\app\pom.xml",
                r"\\?\C:\work",
            ),
            (
                r"\\?\UNC\server\share\root",
                r"\\?\UNC\server\share\app\pom.xml",
                r"\\?\UNC\server\share\",
            ),
        ] {
            assert_eq!(
                entry_reach(Path::new(root), Path::new(candidate), canonical).as_deref(),
                Some(Path::new(reach)),
                "{candidate}"
            );
        }
    }

    /// Discovery warns in walk order and not past the module it fails on,
    /// though it reads the modules ahead of the walk.
    #[test]
    fn discovery_warns_only_up_to_its_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_pom(dir.path(), "root", &["a", "b"]);
        write_pom(&dir.path().join("a"), "a", &[]);
        fs::create_dir_all(dir.path().join("b/parent")).expect("create parent");
        fs::write(dir.path().join("b/parent/pom.xml"), "<project>").expect("write parent");
        fs::write(
            dir.path().join("b/pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1</version>\
             <relativePath>parent/pom.xml</relativePath></parent><artifactId>b</artifactId>\
             </project>",
        )
        .expect("write b");
        let warnings = || {
            let mut found = false;
            let text = rv_test_support::capture_warnings(|| {
                found = Workspace::discover(dir.path()).is_ok();
            });
            (
                found,
                text.matches("cannot parse the local parent POM").count(),
            )
        };
        assert_eq!(warnings(), (true, 2));
        fs::write(dir.path().join("a/pom.xml"), "<project>").expect("break a");
        assert_eq!(warnings(), (false, 0));
    }

    /// A warning given once per run comes from the first module the walk
    /// reads that gives it, though the walk fails later and a module it
    /// never reaches was read ahead first.
    #[test]
    fn a_warning_once_per_run_follows_the_walk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let jdk_profile = |artifact_id: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                 <artifactId>{artifact_id}</artifactId><version>1</version><profiles><profile>\
                 <id>jdk</id><activation><jdk>17</jdk></activation><dependencies><dependency>\
                 <groupId>com.example</groupId><artifactId>lib</artifactId><version>1</version>\
                 </dependency></dependencies></profile></profiles></project>"
            )
        };
        write_pom(dir.path(), "root", &["a", "b"]);
        write_pom(&dir.path().join("a"), "a", &["c", "d"]);
        for (module, xml) in [
            ("b", jdk_profile("b")),
            ("a/c", jdk_profile("c")),
            ("a/d", "<project>".to_string()),
        ] {
            fs::create_dir_all(dir.path().join(module)).expect("create module");
            fs::write(dir.path().join(module).join("pom.xml"), xml).expect("write module");
        }
        let text = rv_test_support::capture_warnings(|| {
            assert!(Workspace::discover(dir.path()).is_err());
        });
        assert_eq!(text.matches("reads java.version").count(), 1, "{text}");
        assert!(text.contains("the POM of com.example:c:1 reads"), "{text}");
    }

    /// Write a reactor at `root` with one module nested so deep that its POM
    /// path passes 260 characters. Returns that module's root-relative path.
    #[cfg(windows)]
    fn write_deep_module_reactor(root: &Path) -> String {
        let module = format!("{}/{}/{}", "a".repeat(100), "b".repeat(100), "c".repeat(60));
        write_pom(root, "deep-root", &[&module]);
        write_pom(&root.join(&module), "deep", &[]);
        format!("{module}/pom.xml")
    }

    /// Write a POM whose `marked` profile, which manages a dependency, is
    /// active while `marker.txt` sits next to it, spelled through
    /// `${project.basedir}` with a forward slash.
    /// On Windows `\\?\C:\dir/marker.txt` names no file, so the profile is
    /// active only while the basedir has its plain form.
    fn write_marked_pom(dir: &Path, artifact_id: &str, modules: &[&str]) {
        let modules: String = modules
            .iter()
            .map(|module| format!("<module>{module}</module>"))
            .collect();
        fs::create_dir_all(dir).expect("create POM directory");
        fs::write(dir.join("marker.txt"), "").expect("write marker");
        fs::write(
            dir.join("pom.xml"),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                 <artifactId>{artifact_id}</artifactId><version>1</version>\
                 <packaging>pom</packaging><modules>{modules}</modules><profiles><profile>\
                 <id>marked</id><activation><file>\
                 <exists>${{project.basedir}}/marker.txt</exists></file></activation>\
                 <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
                 <artifactId>a</artifactId><version>1</version></dependency></dependencies>\
                 </dependencyManagement></profile></profiles></project>"
            ),
        )
        .expect("write POM");
    }

    /// A module whose POM path passes 260 characters is discovered, and
    /// `${project.basedir}` stays plain for it and for the root, so file
    /// activation finds `marker.txt`.
    #[test]
    fn discovers_a_deep_module_with_a_plain_basedir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let module = format!("{}/{}/{}", "a".repeat(100), "b".repeat(100), "c".repeat(60));
        write_marked_pom(temp.path(), "marked-root", &[&module]);
        write_marked_pom(&temp.path().join(&module), "marked-deep", &[]);
        let deep = format!("{module}/pom.xml");
        assert!(temp.path().join(&deep).as_os_str().len() > 260);

        let workspace = Workspace::discover(temp.path()).expect("discover deep reactor");
        assert_eq!(paths(&workspace), ["pom.xml", deep.as_str()]);
        assert!(
            workspace
                .get(&gav("com.example", "marked-deep", "1"))
                .is_some()
        );
        for module in workspace.modules() {
            assert_eq!(
                module.descriptor.active_profiles,
                ["marked"],
                "{}",
                module.pom_path
            );
        }
    }

    /// `dunce` strips `\\?\` only while the prefixed path is at most 260
    /// characters, so a root under that limit and a module POM over it used to
    /// canonicalize to different forms and fail containment.
    #[cfg(windows)]
    #[test]
    fn short_root_keeps_a_module_past_max_path_inside_the_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = rv_fs::plain_path(&fs::canonicalize(temp.path()).expect("canonical tempdir"));
        assert!(
            root.as_os_str().len() < 200,
            "tempdir {} is not short",
            root.display()
        );
        let module = write_deep_module_reactor(&root);

        let workspace = Workspace::discover(&root).expect("discover deep reactor");
        assert_eq!(rv_fs::plain_path(workspace.root()), root);
        assert!(
            workspace
                .modules()
                .iter()
                .any(|discovered| discovered.pom_path == module),
            "deep module missing from {:?}",
            workspace.modules()
        );
    }

    #[cfg(windows)]
    #[test]
    fn root_whose_pom_path_crosses_max_path_is_discovered() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = rv_fs::plain_path(&fs::canonicalize(temp.path()).expect("canonical tempdir"));
        // `\\?\` plus a 254-character root is 258 characters; adding
        // `\pom.xml` makes 266.
        let padding = 254 - base.as_os_str().len() - 1;
        let root = base.join("r".repeat(padding));
        assert_eq!(root.as_os_str().len(), 254);
        write_pom(&root, "threshold-root", &["module"]);
        write_pom(&root.join("module"), "threshold-module", &[]);

        let workspace = Workspace::discover(&root).expect("discover threshold reactor");
        assert_eq!(rv_fs::plain_path(workspace.root()), root);
        assert!(!root.to_string_lossy().starts_with(r"\\?\"));
        let paths: Vec<&str> = workspace
            .modules()
            .iter()
            .map(|module| module.pom_path.as_str())
            .collect();
        assert_eq!(paths, ["pom.xml", "module/pom.xml"]);
    }

    /// A junction can lead to a directory only `\\?\` syntax can spell, such
    /// as `project.` beside `project`. Discovery must read the POM in the
    /// directory it canonicalized, never the sibling Windows opens for the
    /// plain spelling once the trailing dot is trimmed.
    #[cfg(windows)]
    #[test]
    fn junction_to_a_trailing_dot_directory_reads_that_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = fs::canonicalize(temp.path()).expect("canonical tempdir");

        let dotted_root = base.join("project.");
        write_pom(&dotted_root, "dotted-root", &[]);
        write_pom(&base.join("project"), "sibling-root", &[]);
        let entry = base.join("entry");
        rv_test_support::create_junction(&entry, &dotted_root).expect("root junction");

        let workspace =
            Workspace::discover(rv_fs::plain_path(&entry)).expect("discover through junction");
        assert_eq!(workspace.root(), dotted_root);
        let artifacts: Vec<&str> = workspace
            .modules()
            .iter()
            .map(|module| module.gav().artifact_id.as_str())
            .collect();
        assert_eq!(artifacts, ["dotted-root"]);

        let reactor = base.join("reactor");
        write_pom(&reactor, "reactor", &["entry"]);
        write_pom(&reactor.join("module."), "dotted-module", &[]);
        write_pom(&reactor.join("module"), "sibling-module", &[]);
        rv_test_support::create_junction(&reactor.join("entry"), &reactor.join("module."))
            .expect("module junction");

        let workspace = Workspace::discover(&reactor).expect("discover junction module");
        let modules: Vec<(&str, &str)> = workspace
            .modules()
            .iter()
            .map(|module| (module.pom_path.as_str(), module.gav().artifact_id.as_str()))
            .collect();
        assert_eq!(
            modules,
            [("pom.xml", "reactor"), ("module./pom.xml", "dotted-module")]
        );
    }

    fn paths(workspace: &Workspace) -> Vec<&str> {
        workspace
            .modules()
            .iter()
            .map(|module| module.pom_path.as_str())
            .collect()
    }

    fn module_artifacts(workspace: &Workspace) -> Vec<(&str, &str)> {
        workspace
            .modules()
            .iter()
            .map(|module| (module.pom_path.as_str(), module.gav().artifact_id.as_str()))
            .collect()
    }

    /// Maven joins a `<module>` entry to a plain Windows path, which loses a
    /// trailing dot or space where Win32 normalization trims one, so
    /// `module.` is the directory `module` and keeps that module path.
    #[cfg(windows)]
    #[test]
    fn module_entry_is_trimmed_as_windows_trims_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let reactor = temp.path().join("reactor");
        write_pom(&reactor, "reactor", &["module.", r"nested.\sub. "]);
        write_pom(&reactor.join("module"), "module", &[]);
        write_pom(&reactor.join("nested").join("sub"), "sub", &[]);
        // Names only `\\?\` paths reach, which the entries must not select.
        let canonical = fs::canonicalize(&reactor).expect("canonical reactor");
        write_pom(&canonical.join("module."), "dotted", &[]);
        write_pom(&canonical.join("nested.").join("sub"), "dotted-sub", &[]);

        let workspace = Workspace::discover(&reactor).expect("discover trimmed modules");
        assert_eq!(
            module_artifacts(&workspace),
            [
                ("pom.xml", "reactor"),
                ("module/pom.xml", "module"),
                ("nested/sub/pom.xml", "sub"),
            ]
        );
    }

    /// `module..` names the directory `module`, but Maven then reads
    /// `module..\pom.xml`, which Win32 leaves alone, and reports the module
    /// as missing.
    #[cfg(windows)]
    #[test]
    fn module_entry_whose_pom_windows_does_not_trim_is_missing() {
        for entry in ["module..", "module .", "module. /"] {
            let temp = tempfile::tempdir().expect("tempdir");
            write_pom(temp.path(), "reactor", &[entry]);
            write_pom(&temp.path().join("module"), "module", &[]);

            let error = Workspace::discover(temp.path()).expect_err(entry);
            assert!(
                matches!(&error, WorkspaceError::Io { source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound),
                "{entry:?}: {error}"
            );
        }
    }

    /// Maven checks that `tail .\pom.xml`, which Win32 opens as
    /// `tail \pom.xml`, exists, but reads the module through
    /// `File.getCanonicalFile`, which looks each segment up with its trailing
    /// spaces trimmed. With `tail` beside `tail ` it reads `tail`, and a
    /// segment whose trimmed name does not exist is read as written. The JDK
    /// does not canonicalize `module..\pom.xml` or `dots..\sub\pom.xml`, so
    /// Maven reads those as written although `module` and `dots` exist.
    #[cfg(windows)]
    #[test]
    fn module_is_read_through_the_path_maven_canonicalizes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let reactor = fs::canonicalize(temp.path()).expect("canonical tempdir");
        write_pom(
            &reactor,
            "reactor",
            &["tail .", "lone .", "module..", "dots../sub"],
        );
        write_pom(&reactor.join("tail"), "tail", &[]);
        write_pom(&reactor.join("tail "), "spaced", &[]);
        fs::create_dir_all(reactor.join("lone")).expect("create lone");
        write_pom(&reactor.join("lone "), "lone-spaced", &[]);
        write_pom(&reactor.join("module"), "module", &[]);
        write_pom(&reactor.join("module.."), "dotted", &[]);
        write_pom(&reactor.join("dots").join("sub"), "plain-sub", &[]);
        write_pom(&reactor.join("dots..").join("sub"), "dots-sub", &[]);

        // `lone` exists without a POM, so `lone .` is read from `lone\pom.xml`
        // and fails, as it does for Maven.
        let error = Workspace::discover(&reactor).expect_err("lone has no POM");
        assert!(
            matches!(&error, WorkspaceError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound),
            "{error}"
        );

        write_pom(&reactor.join("lone"), "lone", &[]);
        let workspace = Workspace::discover(&reactor).expect("discover canonical modules");
        assert_eq!(
            module_artifacts(&workspace),
            [
                ("pom.xml", "reactor"),
                ("tail/pom.xml", "tail"),
                ("lone/pom.xml", "lone"),
                ("module../pom.xml", "dotted"),
                ("dots../sub/pom.xml", "dots-sub"),
            ]
        );
    }

    /// Outside Windows a trailing dot is part of the name, as it is for Maven.
    #[cfg(not(windows))]
    #[test]
    fn module_entry_keeps_a_trailing_dot_outside_windows() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_pom(temp.path(), "reactor", &["module."]);
        write_pom(&temp.path().join("module"), "module", &[]);
        let error = Workspace::discover(temp.path()).expect_err("module. is missing");
        assert!(
            matches!(&error, WorkspaceError::MissingModule { module, .. } if module == "module."),
            "{error}"
        );

        write_pom(&temp.path().join("module."), "dotted", &[]);
        let workspace = Workspace::discover(temp.path()).expect("discover module.");
        assert_eq!(
            module_artifacts(&workspace),
            [("pom.xml", "reactor"), ("module./pom.xml", "dotted")]
        );
    }

    /// Profile modules follow the root's `.mvn/maven.config`, whose
    /// `-Drevision` beats a module-local one, and nested aggregators naming
    /// one POM twice yield it once, with root or module provenance.
    #[test]
    fn discovers_profile_and_nested_modules() {
        let workspace = Workspace::discover(fixture("profile-config")).expect("discover workspace");
        assert_eq!(
            paths(&workspace),
            ["pom.xml", "module-a/pom.xml", "extra/pom.xml"]
        );
        assert_eq!(
            workspace.modules()[0].descriptor.active_profiles,
            ["extras"]
        );
        for artifact_id in ["module-a", "extra"] {
            assert!(
                workspace
                    .get(&gav("com.example", artifact_id, "2.5.0"))
                    .is_some()
            );
        }

        let workspace =
            Workspace::discover(fixture("nested-aggregator")).expect("discover workspace");
        assert_eq!(
            paths(&workspace),
            ["pom.xml", "aggregator/pom.xml", "leaf/pom.xml"]
        );
        let path = |relative: &str| workspace.root().join(relative);
        let provenance: Vec<_> = workspace
            .modules()
            .iter()
            .map(|module| module.pom().provenance().cloned())
            .collect();
        assert_eq!(
            provenance,
            [
                Some(Provenance::RootProject {
                    path: path("pom.xml")
                }),
                Some(Provenance::ReactorModule {
                    path: path("aggregator/pom.xml")
                }),
                Some(Provenance::ReactorModule {
                    path: path("leaf/pom.xml")
                }),
            ]
        );
        assert_eq!(
            workspace.module_provenance(&path("leaf/pom.xml")),
            provenance[2]
        );
    }

    /// The project's POMs are the modules discovery interpolates, those an
    /// inactive profile lists and the local parents of each, also one
    /// outside the reactor root; a POM at a parent's path with other
    /// coordinates is not one. An inactive profile's module that keeps a
    /// `${...}` or does not resolve fails, as does any module that keeps one
    /// when the build takes options discovery did not read.
    #[test]
    fn project_poms_follow_interpolated_and_inactive_modules() {
        let dir = tempfile::tempdir().unwrap();
        let outer = dir.path();
        let root = outer.join("project");
        let write = |path: &Path, xml: &str| {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(
                path,
                format!("<project><modelVersion>4.0.0</modelVersion>{xml}</project>"),
            )
            .unwrap();
        };
        write(
            &outer.join("pom.xml"),
            "<groupId>g</groupId><artifactId>outer</artifactId><version>1</version>",
        );
        let root_pom = |profile_module: &str| {
            format!(
                "<parent><groupId>g</groupId><artifactId>outer</artifactId><version>1</version>\
                 </parent><artifactId>root</artifactId><packaging>pom</packaging>\
                 <properties><module.path>child</module.path></properties>\
                 <modules><module>${{module.path}}</module></modules>\
                 <profiles><profile><id>off</id><modules><module>{profile_module}</module>\
                 </modules></profile></profiles>"
            )
        };
        write(&root.join("pom.xml"), &root_pom("extra"));
        let child = "<parent><groupId>g</groupId><artifactId>root</artifactId><version>1</version>\
                     </parent><artifactId>child</artifactId>";
        write(&root.join("child/pom.xml"), child);
        write(
            &root.join("extra/pom.xml"),
            "<parent><groupId>g</groupId><artifactId>other</artifactId><version>1</version>\
             </parent><artifactId>extra</artifactId>",
        );
        let workspace = Workspace::discover(&root).unwrap();
        let canonical = |path: PathBuf| fs::canonicalize(path).unwrap();
        let mut expected = vec![
            canonical(outer.join("pom.xml")),
            canonical(root.join("pom.xml")),
            canonical(root.join("child/pom.xml")),
            canonical(root.join("extra/pom.xml")),
        ];
        expected.sort();
        assert_eq!(workspace.project_poms(false).unwrap(), expected);
        assert!(workspace.project_poms(true).is_err());

        for profile_module in ["${module.path}", "missing"] {
            write(&root.join("pom.xml"), &root_pom(profile_module));
            let workspace = Workspace::discover(&root).unwrap();
            assert!(workspace.project_poms(false).is_err(), "{profile_module}");
        }
    }

    /// Module coordinates interpolate properties inherited from local
    /// parents, also for an aggregator whose parent is one of its modules,
    /// and from a lone selected module's immediate `../pom.xml`, the one
    /// parent outside the reactor root resolution accepts. Only that one is
    /// listed for hashing apart from the modules, and a parent whose
    /// coordinates differ from the declaration contributes nothing.
    /// Discovery builds models with `ready`, so it also works inside a
    /// current-thread runtime, where nothing could drive a pending future.
    #[test]
    fn module_coordinates_inherit_from_local_parents() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let reactor = runtime
            .block_on(async { Workspace::discover(fixture("inherited-properties")) })
            .expect("discover workspace");
        for artifact_id in ["revision-child", "reactor"] {
            assert!(
                reactor
                    .get(&gav("com.example", artifact_id, "2.5.0"))
                    .is_some()
            );
        }
        assert!(reactor.local_parent_poms().is_empty());

        let selected =
            Workspace::discover(fixture("external-parent").join("child")).expect("discover");
        assert_eq!(selected.len(), 1);
        assert!(
            selected
                .get(&gav("com.example", "selected-child", "2.5.0"))
                .is_some()
        );
        assert_eq!(
            selected.local_parent_poms(),
            [fs::canonicalize(fixture("external-parent").join("pom.xml")).unwrap()]
        );

        let mismatch = Workspace::discover(fixture("external-parent-mismatch").join("child"))
            .expect("discover selected module");
        assert_eq!(mismatch.modules()[0].gav().version, "${revision}");
    }

    /// Discovery fails where Maven refuses the reactor, instead of indexing
    /// a module Maven never builds. `<parent>` is matched as written, so a
    /// version only `.mvn/maven.config` supplies names no parent, and project
    /// inputs over the size limit are refused, not read whole.
    #[test]
    fn discovery_fails_where_maven_does() {
        assert!(matches!(
            Workspace::discover(fixture("cycle")).expect_err("cycle"),
            WorkspaceError::AggregationCycle { cycle } if cycle == ["pom.xml", "a/pom.xml", "pom.xml"]
        ));
        assert!(matches!(
            Workspace::discover(fixture("duplicate-gav")).expect_err("duplicate-gav"),
            WorkspaceError::DuplicateGav { gav, first_pom, second_pom }
                if gav.to_string() == "com.example:duplicate:1"
                    && first_pom == "a/pom.xml"
                    && second_pom == "b/pom.xml"
        ));

        let root = |rest: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                 <artifactId>root</artifactId><version>1.2.3</version>{rest}</project>"
            )
        };
        let aggregator =
            root("<packaging>pom</packaging><modules><module>child</module></modules>");
        let plain = root("");
        let child = "<project><modelVersion>4.0.0</modelVersion><parent>\
                     <groupId>com.example</groupId><artifactId>root</artifactId>\
                     <version>${parentVersion}</version><relativePath>../pom.xml</relativePath>\
                     </parent><artifactId>child</artifactId></project>";
        let big = "x".repeat(rv_config::MAX_PROJECT_INPUT_SIZE + 1);
        let too_large =
            |error: &WorkspaceError| matches!(error, WorkspaceError::ProjectInputTooLarge { .. });
        type Check = fn(&WorkspaceError) -> bool;
        let modules = |entries: &[&str]| {
            let entries: String = entries
                .iter()
                .map(|entry| format!("<module>{entry}</module>"))
                .collect();
            root(&format!(
                "<packaging>pom</packaging><modules>{entries}</modules>"
            ))
        };
        let twice = modules(&["child", "child"]);
        let respelled = modules(&["child", "./child/pom.xml"]);
        let diamond = modules(&["child", "other"]);
        let other = "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                     <artifactId>other</artifactId><version>1</version><packaging>pom</packaging>\
                     <modules><module>../child</module></modules></project>";
        let leaf = "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                    <artifactId>child</artifactId><version>1</version></project>";
        let duplicate = |error: &WorkspaceError| matches!(error, WorkspaceError::DuplicateModule { pom } if pom == "child/pom.xml");
        let cases: [(Vec<(&str, &str)>, Check); 7] = [
            (
                vec![("pom.xml", &twice), ("child/pom.xml", leaf)],
                duplicate,
            ),
            (
                vec![("pom.xml", &respelled), ("child/pom.xml", leaf)],
                duplicate,
            ),
            (
                vec![
                    ("pom.xml", &diamond),
                    ("child/pom.xml", leaf),
                    ("other/pom.xml", other),
                ],
                duplicate,
            ),
            (
                vec![
                    (".mvn/maven.config", "-DparentVersion=1.2.3\n"),
                    ("pom.xml", &aggregator),
                    ("child/pom.xml", child),
                ],
                |error| {
                    matches!(
                        error,
                        WorkspaceError::InvalidPom {
                            source: PomError::ParentExpression(_),
                            ..
                        }
                    )
                },
            ),
            (
                vec![("pom.xml", &aggregator), ("child/pom.xml", &big)],
                too_large,
            ),
            (
                vec![("pom.xml", &plain), (".mvn/maven.config", &big)],
                too_large,
            ),
            (
                vec![
                    ("pom.xml", &plain),
                    (".mvn/maven.config", "  -Drevision=1\n"),
                ],
                |error| {
                    matches!(error, WorkspaceError::InvalidMavenConfig { .. })
                        && error
                            .to_string()
                            .contains("Unrecognized maven.config file entries: [  -Drevision=1]")
                },
            ),
        ];
        for (files, expected) in cases {
            let temp = tempfile::tempdir().expect("tempdir");
            for (path, contents) in &files {
                let path = temp.path().join(path);
                fs::create_dir_all(path.parent().unwrap()).expect("create directory");
                fs::write(path, contents).expect("write file");
            }
            let error = Workspace::discover(temp.path()).expect_err("discovery must fail");
            assert!(expected(&error), "{error:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_real_symlink_escape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace_root = temp.path().join("workspace");
        write_pom(&temp.path().join("outside"), "outside", &[]);
        fs::create_dir_all(&workspace_root).expect("create workspace");
        fs::copy(
            fixture("symlink-escape").join("pom.xml"),
            workspace_root.join("pom.xml"),
        )
        .expect("copy fixture");
        std::os::unix::fs::symlink(temp.path().join("outside"), workspace_root.join("escape"))
            .expect("create real symlink");

        let error = Workspace::discover(&workspace_root).expect_err("escape must fail");
        assert!(matches!(error, WorkspaceError::ModuleEscapes { .. }));
    }

    /// Recorded with Maven 3.9.11's `help:active-profiles`. A whole line is
    /// one `-P` value, so `-!Plegacy` is part of a profile id.
    #[test]
    fn parses_profile_switches_like_maven() {
        for (content, active, inactive) in [
            (
                "-Palpha,beta,!off -!Plegacy,unused",
                &["alpha", "beta", "unused"][..],
                &["off -!Plegacy"][..],
            ),
            (
                "-P spring\n-Pa,-b,+c\n-P=d\n--activate-profiles=g",
                &["spring", "a", "c", "d", "g"][..],
                &["b"][..],
            ),
        ] {
            let config = MavenConfig::parse(content).unwrap();
            assert_eq!(config.active_profiles, active);
            assert_eq!(config.inactive_profiles, inactive);
        }
    }
}
