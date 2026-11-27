//! Which sets a module's build resolves: Maven's order of build extensions,
//! plugins (lifecycle defaults, declared, named by a goal) and processor
//! paths, with the versions and prefixes the model leaves open resolved
//! from the plugin repositories.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;

use rv_maven_model::{
    ActivationContext, DEFAULT_PLUGIN_GROUP, Dependency, EffectivePlugins, HostInput, MappedMojo,
    Plugin, Project, PropertyMap,
};
use rv_maven_types::{BlobId, Version};
use rv_repo::Repository;

use super::{PluginMetadata, PluginRequest, PluginRole, ResolvedPluginSet};
use crate::SupportPomProvenance;
use crate::context::RealmClosure;
use crate::error::{ResolveError, Result};
use crate::resolver::PlatformResolver;
use crate::resolver::backend::{ModelService, ReadModels, WorkspaceSupportPomBuffer};
use crate::resolver::utils::merge_project_repos;
use crate::util::lock;
use crate::workspace::Workspace;

/// Maven core's `exportedArtifacts`, the same in 3.9.12 and 3.10.0: a core
/// extension's closure reads their POMs but does not download their jars.
pub(super) const CORE_EXPORTS: &[&str] = &[
    "classworlds:classworlds",
    "org.codehaus.plexus:plexus-classworlds",
    "org.codehaus.plexus:plexus-component-api",
    "org.codehaus.plexus:plexus-container-default",
    "plexus:plexus-container-default",
    "org.sonatype.spice:spice-inject-plexus",
    "org.sonatype.sisu:sisu-inject-plexus",
    "org.eclipse.sisu:org.eclipse.sisu.plexus",
    "org.apache.maven:maven-artifact",
    "org.apache.maven:maven-aether-provider",
    "org.apache.maven:maven-resolver-provider",
    "org.apache.maven:maven-artifact-manager",
    "org.apache.maven:maven-compat",
    "org.apache.maven:maven-core",
    "org.apache.maven:maven-error-diagnostics",
    "org.apache.maven:maven-lifecycle",
    "org.apache.maven:maven-model",
    "org.apache.maven:maven-model-builder",
    "org.apache.maven:maven-monitor",
    "org.apache.maven:maven-plugin-api",
    "org.apache.maven:maven-plugin-descriptor",
    "org.apache.maven:maven-plugin-parameter-documenter",
    "org.apache.maven:maven-plugin-registry",
    "org.apache.maven:maven-profile",
    "org.apache.maven:maven-project",
    "org.apache.maven:maven-repository-metadata",
    "org.apache.maven:maven-settings",
    "org.apache.maven:maven-settings-builder",
    "org.apache.maven:maven-toolchain",
    "org.apache.maven.wagon:wagon-provider-api",
    "org.apache.maven.resolver:maven-resolver-api",
    "org.apache.maven.resolver:maven-resolver-spi",
    "org.apache.maven.resolver:maven-resolver-impl",
    "org.apache.maven.resolver:maven-resolver-util",
    "org.apache.maven.resolver:maven-resolver-connector-basic",
    "javax.inject:javax.inject",
    "javax.annotation:javax.annotation-api",
    "org.slf4j:slf4j-api",
    "org.fusesource.jansi:jansi",
    "org.sonatype.aether:aether-api",
    "org.sonatype.aether:aether-spi",
    "org.sonatype.aether:aether-impl",
    "org.eclipse.aether:aether-api",
    "org.eclipse.aether:aether-spi",
    "org.eclipse.aether:aether-impl",
    "org.eclipse.aether:aether-util",
    "org.eclipse.aether:aether-connector-basic",
];

/// The plugin groups Maven searches for a prefix after the project's own,
/// when the settings name none.
const DEFAULT_PLUGIN_GROUPS: [&str; 2] = [DEFAULT_PLUGIN_GROUP, "org.codehaus.mojo"];

/// One set to resolve.
#[derive(Debug, Clone)]
pub(crate) struct SetRequest {
    /// The first module that asked for it, for errors.
    pub(super) module: String,
    pub(super) role: PluginRole,
    /// The plugin or extension, its version known; for a processor path a
    /// placeholder.
    pub(super) plugin: Plugin,
    /// The processor path entries, for [`PluginRole::ProcessorPath`].
    pub(super) paths: Vec<Dependency>,
    pub(super) repos: Vec<Repository>,
    /// `groupId:artifactId` of artifacts whose jars the class path takes
    /// from elsewhere: Maven core's or a build extension's exports.
    pub(super) filtered: Vec<String>,
    /// The artifact handlers the module's build extensions define, in
    /// Maven's order, for a plugin or processor path: Maven resolves them
    /// with the types of the project's build.
    pub(super) handlers: Vec<ExtensionHandlers>,
    /// How the compiler plugin resolves [`Self::paths`].
    pub(super) paths_by: PathResolution,
}

/// How a maven-compiler-plugin version resolves its processor paths.
#[derive(Debug, Clone, Default)]
pub(crate) enum PathResolution {
    /// 3.11 and later: all paths in one collection.
    #[default]
    Together,
    /// 3.12 and later with `annotationProcessorPathsUseDepMgmt`: as
    /// [`Self::Together`], managed by the project's dependency management.
    Managed(Vec<Dependency>),
    /// 3.9.0 to 3.10.1: each path on its own through Maven's legacy
    /// resolver, its POM's dependencies beside it under its POM's
    /// management, the files of all of them in path order.
    Alone,
    /// Before 3.9.0: one legacy request rooted at the first path, every
    /// path beside the first one's POM dependencies, under its POM's
    /// management.
    UnderFirst,
}

impl SetRequest {
    /// `sha256:` of everything that decides the set's files. A repository
    /// or system path inside the project directory `root` counts as
    /// raeva.lock records it, so the key does not depend on where the
    /// project is checked out.
    pub(super) fn key(&self, root: &std::path::Path) -> String {
        let mut text = String::new();
        let _ = writeln!(text, "{}", self.role.as_str());
        for coordinate in self.coordinates() {
            let _ = writeln!(text, "coordinate {coordinate}");
        }
        let dependencies = || self.plugin.dependencies.iter().chain(&self.paths);
        // The root as given and as `${project.basedir}` spells it, through
        // links.
        let mut roots = vec![root.to_path_buf()];
        if dependencies().any(|dependency| dependency.system_path.is_some())
            && let Ok(canonical) = std::fs::canonicalize(root)
        {
            roots.push(rv_fs::plain_path(&canonical));
            roots.push(canonical);
        }
        for dependency in &self.plugin.dependencies {
            let _ = writeln!(
                text,
                "dependency {}{}",
                dependency_text(dependency, &roots),
                empty_classifier(dependency)
            );
        }
        for path in &self.paths {
            let _ = writeln!(text, "dependency {}", dependency_text(path, &roots));
        }
        let origins = (self.repos.iter())
            .any(|repo| repo.url.starts_with("file:"))
            .then(|| rv_lock::LockOrigins::for_root(root));
        for repo in &self.repos {
            let url = match &origins {
                Some(origins) if repo.url.starts_with("file:") => origins
                    .declared(&repo.url)
                    .unwrap_or_else(|| repo.url.clone()),
                _ => repo.url.clone(),
            };
            // Modules may list one id and URL with other policies.
            let _ = writeln!(
                text,
                "repository {} {url} {} {} {:?} {:?}",
                repo.id.as_deref().unwrap_or(""),
                repo.releases_enabled,
                repo.snapshots_enabled,
                repo.releases_checksum_policy,
                repo.snapshots_checksum_policy
            );
        }
        for filtered in &self.filtered {
            let _ = writeln!(text, "filtered {filtered}");
        }
        for (type_, handler) in (self.handlers.iter()).flat_map(|(_, defined)| defined) {
            let _ = match handler {
                Ok(handler) => writeln!(
                    text,
                    "handler {type_} {} {} {} {}",
                    handler.extension,
                    handler.classifier.as_deref().unwrap_or(""),
                    handler.includes_dependencies,
                    handler.added_to_classpath
                ),
                Err(reason) => writeln!(text, "handler {type_} unreadable {reason}"),
            };
        }
        match &self.paths_by {
            PathResolution::Together => {}
            PathResolution::Managed(managed) => {
                for dependency in managed {
                    let _ = writeln!(
                        text,
                        "managed {}{}",
                        dependency_text(dependency, &roots),
                        empty_classifier(dependency)
                    );
                }
            }
            PathResolution::Alone => text.push_str("paths alone\n"),
            PathResolution::UnderFirst => text.push_str("paths under the first\n"),
        }
        format!("sha256:{}", BlobId::from_bytes(text.as_bytes()))
    }

    pub(super) fn coordinates(&self) -> Vec<String> {
        match self.role {
            PluginRole::ProcessorPath | PluginRole::TestProvider => {
                self.paths.iter().map(path_coordinate).collect()
            }
            _ => vec![format!(
                "{}:{}",
                self.plugin.key(),
                self.plugin.version.as_deref().unwrap_or("")
            )],
        }
    }

    /// What the set is, for an error.
    pub(super) fn describe(&self) -> String {
        format!("{} {}", self.role.as_str(), self.coordinates().join(","))
    }

    /// `error`, which resolving the set met.
    pub(super) fn failed(&self, error: ResolveError) -> ResolveError {
        ResolveError::Plugin {
            plugin: self.describe(),
            searched: (self.repos.iter()).map(|repo| repo.url.clone()).collect(),
            error: Box::new(error),
        }
    }
}

/// The version of the entry of `managed` with the group, artifact, type and
/// classifier of `path`, as maven-compiler-plugin's `findManagedVersion`
/// compares them: a managed `<classifier/>` is apart from none, while the
/// configuration gives an empty one of the path as none.
fn managed_version(path: &Dependency, managed: &[Dependency]) -> Option<String> {
    let text = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
    let type_ = |dependency: &Dependency| text(&dependency.type_).unwrap_or_else(|| "jar".into());
    let classifier = text(&path.classifier);
    (managed.iter())
        .find(|entry| {
            entry.group_id == path.group_id
                && entry.artifact_id == path.artifact_id
                && type_(entry) == type_(path)
                && entry.classifier == classifier
        })
        .and_then(|entry| entry.version.clone())
}

/// The path as it is declared: what its type means depends on the module's
/// build extensions, which the set key holds.
fn path_coordinate(path: &Dependency) -> String {
    let mut coordinate = format!(
        "{}:{}:{}",
        path.group_id,
        path.artifact_id,
        path.type_.as_deref().unwrap_or("jar")
    );
    if let Some(classifier) = path.classifier.as_deref().filter(|value| !value.is_empty()) {
        let _ = write!(coordinate, ":{classifier}");
    }
    let _ = write!(coordinate, ":{}", path.version.as_deref().unwrap_or(""));
    coordinate
}

/// A mark for a declared empty `<classifier/>`, which Maven keeps apart
/// from none: with a type that implies a classifier, it takes the main
/// file. A processor path's reads as none, so it is not marked there.
fn empty_classifier(dependency: &Dependency) -> &'static str {
    match dependency.classifier.as_deref() {
        Some("") => " empty-classifier",
        _ => "",
    }
}

fn dependency_text(dependency: &Dependency, roots: &[std::path::PathBuf]) -> String {
    let mut text = format!(
        "{} {}",
        path_coordinate(dependency),
        dependency.scope.as_deref().unwrap_or("")
    );
    if dependency.effective_optional() {
        text.push_str(" optional");
    }
    for exclusion in &dependency.exclusions {
        let _ = write!(text, " -{}:{}", exclusion.group_id, exclusion.artifact_id);
    }
    if let Some(path) = &dependency.system_path {
        let mut plain = std::path::PathBuf::new();
        for part in std::path::Path::new(path).components() {
            match part {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    plain.pop();
                }
                part => plain.push(part),
            }
        }
        let relative = (roots.iter())
            .find_map(|root| plain.strip_prefix(root).ok())
            .map(|relative| {
                (relative.components())
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/")
            });
        let _ = write!(text, " {}", relative.as_deref().unwrap_or(path));
    }
    text
}

/// The sets of one module, by key, in Maven's order.
pub(super) struct PlannedModule {
    pub(super) pom_path: String,
    pub(super) keys: Vec<String>,
    pub(super) built_in_reactor: Vec<String>,
}

/// What [`Planner::finish`] hands back: the sets to resolve, the metadata
/// read, and the sets planning resolved already.
pub(super) type Planned = (
    BTreeMap<String, SetRequest>,
    Vec<PluginMetadata>,
    HashMap<String, ResolvedPluginSet>,
    BTreeSet<rv_lock::MetadataVersion>,
);

/// Plans the sets of each module in turn. Build extensions are resolved as
/// they are met, since they decide the packaging's lifecycle and filter the
/// module's plugin class paths.
pub(super) struct Planner<'r> {
    resolver: &'r PlatformResolver,
    /// Admits the POMs' plugin repositories as their repositories are
    /// admitted, reporting a refusal once.
    admission: ModelService,
    workspace: &'r Arc<Workspace>,
    goals: Vec<String>,
    pub(super) test_classpaths: BTreeMap<String, rv_lock::LockModule>,
    pub(super) requests: BTreeMap<String, SetRequest>,
    resolved: HashMap<String, ResolvedPluginSet>,
    /// What each resolved extension set exports and maps, by key.
    extensions: HashMap<String, ExtensionDescriptors>,
    pub(super) metadata: BTreeSet<PluginMetadata>,
    /// Selected versions of version-less plugins, by `g:a` and repositories.
    pub(super) versions: HashMap<String, String>,
    /// The version each of them took, as the export's `<release>`.
    pub(super) markers: BTreeSet<rv_lock::MetadataVersion>,
    /// The versions a frozen check holds each of them at, by module and
    /// `g:a`.
    pub(super) held: BTreeMap<(String, bool, String), Vec<String>>,
    /// The `g:a:v` the module being planned names itself: its plugins' and
    /// build extensions' own versions and its goals'.
    pub(super) named: BTreeSet<String>,
    /// Plugin prefixes found, by prefix and candidate groups.
    pub(super) prefixes: HashMap<String, (String, String)>,
    /// The plugin realms of Surefire and Failsafe read, by set key.
    realms: HashMap<String, BTreeMap<String, String>>,
    /// The parents and BOMs a graph pass reads, which the POMs read for
    /// a plugin version join.
    pub(super) support_poms: Option<WorkspaceSupportPomBuffer>,
    /// What Maven's model cache holds while the module planned builds:
    /// what its build extensions resolve with.
    pub(super) models: ReadModels,
}

pub(crate) use crate::resolver::extension_types::ExtensionHandlers;

/// The descriptors of a build extension's jars.
#[derive(Debug, Clone, Default)]
pub(super) struct ExtensionDescriptors {
    pub(super) exported: Vec<String>,
    pub(super) mappings: Vec<(String, Vec<MappedMojo>)>,
    /// The extension's own jar and the handlers it defines.
    pub(super) handlers: Vec<ExtensionHandlers>,
}

/// `plugin`'s `g:a:v`, when it names its version, a SNAPSHOT build as its
/// base version, as a hold holds it.
fn named(plugin: &Plugin) -> Option<String> {
    let version = plugin.version.as_ref()?;
    let version = rv_maven_types::snapshot_base_version(version).unwrap_or(version.clone());
    Some(format!("{}:{version}", plugin.key()))
}

/// The `g:a:v` the build extensions and plugins of `model` name.
fn own_versions(model: &EffectivePlugins) -> BTreeSet<String> {
    let extensions = model.build_extensions();
    (extensions.iter().chain(&model.plugins))
        .filter_map(named)
        .collect()
}

impl<'r> Planner<'r> {
    pub(super) fn new(
        resolver: &'r PlatformResolver,
        workspace: &'r Arc<Workspace>,
        request: &PluginRequest,
    ) -> Self {
        Self {
            resolver,
            admission: ModelService::new(&resolver.ctx, Vec::new()),
            workspace,
            goals: request.goals.clone(),
            test_classpaths: request.test_classpaths.clone(),
            requests: BTreeMap::new(),
            resolved: HashMap::new(),
            extensions: HashMap::new(),
            metadata: BTreeSet::new(),
            versions: HashMap::new(),
            markers: BTreeSet::new(),
            // A frozen check holds a plugin or build extension without a
            // version at the version the lock took for the module.
            held: (resolver.ctx.version_caps.as_deref())
                .map(|caps| caps.held.clone())
                .unwrap_or_default(),
            named: BTreeSet::new(),
            prefixes: HashMap::new(),
            realms: HashMap::new(),
            support_poms: None,
            models: ReadModels::default(),
        }
    }

    pub(super) fn finish(self) -> Planned {
        (
            self.requests,
            self.metadata.into_iter().collect(),
            self.resolved,
            self.markers,
        )
    }

    pub(super) fn resolver(&self) -> &'r PlatformResolver {
        self.resolver
    }

    /// Whether the reactor builds the plugin or path at `version`. Maven's
    /// reactor reader matches the version too, so another one comes from a
    /// repository, as does the version of a plugin that names none. Build
    /// extensions load before the reactor reader exists, so they always
    /// come from a repository.
    fn built_in_reactor(&self, group_id: &str, artifact_id: &str, version: Option<&str>) -> bool {
        (self.workspace.modules().iter()).any(|module| {
            let gav = module.gav();
            gav.group_id == group_id
                && gav.artifact_id == artifact_id
                && version.is_some_and(|version| gav.version == version)
        })
    }

    pub(super) async fn plan_module(
        &mut self,
        pom_path: &str,
        project: &Project,
        root: Option<&ActivationContext>,
    ) -> Result<(PlannedModule, BTreeSet<HostInput>)> {
        let invalid = |error: rv_maven_model::PomError| {
            let path = self.workspace.module_file(pom_path);
            super::super::project_model_error(error.into(), &path)
        };
        let mut model = project.plugins().map_err(invalid)?.ok_or_else(|| {
            ResolveError::InternalError("a plugins build keeps a plugin model".to_string())
        })?;
        let mut host_reads = std::mem::take(&mut model.host_reads);
        let mut planned = PlannedModule {
            pom_path: pom_path.to_string(),
            keys: Vec::new(),
            built_in_reactor: Vec::new(),
        };
        let repos = self.plugin_repos(&model.plugin_repositories);
        if let Some(activation) = root {
            if let Some(goals) = &model.default_goal {
                self.goals
                    .extend(goals.split_whitespace().map(str::to_string));
            }
            planned
                .keys
                .extend(self.core_extensions(pom_path, activation).await?);
        }
        self.named = own_versions(&model);

        let mut exported = Vec::new();
        let mut mappings = Vec::new();
        let mut handlers = Vec::new();
        for extension in model.build_extensions() {
            let extension = self.extension_version(pom_path, extension, &repos).await?;
            let request = SetRequest {
                module: pom_path.to_string(),
                role: PluginRole::BuildExtension,
                plugin: extension,
                paths: Vec::new(),
                repos: repos.clone(),
                filtered: Vec::new(),
                handlers: Vec::new(),
                paths_by: PathResolution::default(),
            };
            let key = request.key(&self.resolver().ctx.config.project_root);
            let descriptors = self.resolve_extension(key.clone(), request).await?;
            exported.extend(descriptors.exported);
            mappings.extend(descriptors.mappings);
            handlers.extend(descriptors.handlers);
            planned.keys.push(key);
        }
        if !model.lifecycle_mapped
            && let Some((_, mapping)) = (mappings.iter()).find(|(hint, _)| *hint == model.packaging)
        {
            model = (project.plugins_with_mapping(mapping).map_err(invalid)?).ok_or_else(|| {
                ResolveError::InternalError("a plugins build keeps a plugin model".to_string())
            })?;
            host_reads.append(&mut model.host_reads);
        }
        exported.sort();
        exported.dedup();

        let project_repos = self.project_repos(project);
        let mut plugins: Vec<(Plugin, CompilerRun)> = (model.plugins.iter())
            .map(|plugin| (plugin.clone(), CompilerRun::lifecycle()))
            .collect();
        for goal in self.goals.clone() {
            let Some(mut plugin) = self.goal_plugin(pom_path, &goal, &model, &repos).await? else {
                continue;
            };
            // A goal takes its plugin's managed entry, and a prefix is looked
            // up in the groups of every managed plugin.
            host_reads.extend(model.management_reads.values().flatten().cloned());
            // A compile goal takes the configuration of its execution,
            // `default-cli` unless it names one after `@`.
            let (task, execution) = goal.split_once('@').unwrap_or((&goal, "default-cli"));
            let mojo = task.rsplit(':').next().unwrap_or_default();
            let direct =
                (mojo == "compile" || mojo == "testCompile").then(|| execution.to_string());
            // The goal's run, whose configuration may pick a test provider
            // of its own.
            let mut goal_run = rv_maven_model::PluginExecution::new(execution, None, &[mojo]);
            goal_run.configuration = Some(plugin.configuration.clone().unwrap_or_default());
            // A goal's own version runs beside the module's declaration of
            // another.
            match (plugins.iter_mut())
                .find(|(known, _)| known.key() == plugin.key() && known.version == plugin.version)
            {
                Some((known, run)) => {
                    run.direct.extend(direct);
                    if !known.executions.contains(&goal_run) {
                        known.executions.push(goal_run);
                    }
                }
                None => {
                    plugin.executions.push(goal_run);
                    let direct = direct.into_iter().collect();
                    plugins.push((
                        plugin,
                        CompilerRun {
                            direct,
                            ..CompilerRun::default()
                        },
                    ));
                }
            }
        }
        // The goals' plugins, with the versions they name.
        self.named
            .extend(plugins.iter().filter_map(|(plugin, _)| named(plugin)));
        let mut compilers: Vec<CompilerRun> = Vec::new();
        for (plugin, mut run) in plugins {
            let plugin = self.with_version(pom_path, plugin, &model, &repos).await?;
            if self.built_in_reactor(
                &plugin.group_id,
                &plugin.artifact_id,
                plugin.version.as_deref(),
            ) {
                planned.built_in_reactor.push(plugin.key());
                continue;
            }
            // Each compiler version that runs, the module's or one a goal
            // names, resolves the module's processor paths as it does.
            if plugin.group_id == DEFAULT_PLUGIN_GROUP
                && plugin.artifact_id == "maven-compiler-plugin"
            {
                match compilers
                    .iter_mut()
                    .find(|known| known.version == plugin.version)
                {
                    Some(known) => {
                        known.lifecycle |= run.lifecycle;
                        known.direct.append(&mut run.direct);
                    }
                    None => compilers.push(CompilerRun {
                        version: plugin.version.clone(),
                        ..run
                    }),
                }
            }
            let request = SetRequest {
                module: pom_path.to_string(),
                role: PluginRole::Plugin,
                plugin,
                paths: Vec::new(),
                repos: repos.clone(),
                filtered: exported.clone(),
                handlers: handlers.clone(),
                paths_by: PathResolution::default(),
            };
            let key = request.key(&self.resolver().ctx.config.project_root);
            let providers = self
                .test_providers(pom_path, &project.dependencies, &request, &project_repos)
                .await?;
            self.requests.entry(key.clone()).or_insert(request);
            planned.keys.push(key);
            planned.keys.extend(providers);
        }
        if compilers.is_empty() {
            compilers.push(CompilerRun::lifecycle());
        }
        for compiler in &compilers {
            for key in
                self.processor_paths(pom_path, project, &model, compiler, &handlers, &mut planned)
            {
                if !planned.keys.contains(&key) {
                    planned.keys.push(key);
                }
            }
        }
        Ok((planned, host_reads))
    }

    /// The jar and artifact handlers of each build extension of `model`,
    /// in Maven's order, and the SNAPSHOT parents and BOMs their realms
    /// read.
    pub(super) async fn extension_handlers(
        &mut self,
        pom_path: &str,
        model: &EffectivePlugins,
    ) -> Result<(Vec<ExtensionHandlers>, Vec<(String, SupportPomProvenance)>)> {
        let repos = self.plugin_repos(&model.plugin_repositories);
        self.named = own_versions(model);
        let mut found = Vec::new();
        let mut poms = Vec::new();
        for extension in model.build_extensions() {
            let extension = self.extension_version(pom_path, extension, &repos).await?;
            let request = SetRequest {
                module: pom_path.to_string(),
                role: PluginRole::BuildExtension,
                plugin: extension,
                paths: Vec::new(),
                repos: repos.clone(),
                filtered: Vec::new(),
                handlers: Vec::new(),
                paths_by: PathResolution::default(),
            };
            let own = self.resolver().extension_jar(&request).await?;
            let closure = self.extension_closure(&request, &own).await?;
            let describe = request.describe();
            let jars = closure.jars.iter();
            found.push((self.resolver()).realm_handlers(&own, jars, &describe)?);
            poms.extend(closure.snapshot_poms.iter().cloned());
        }
        Ok((found, poms))
    }

    /// The set Maven resolves for the build extension `request` names, but
    /// `own`, its jar, resolved once for every module of the pass: a
    /// SNAPSHOT one's from the POM of the build `own` is. The jars Maven's
    /// core exports are not fetched, as the realm leaves them out. Of what
    /// it reads only the SNAPSHOT parents and BOMs are kept for the module,
    /// which pins them as its own, and the POMs go to the pass's buffer. A
    /// frozen check caps its ranges at the jars the modules' extensions
    /// lines pin, not at the dependencies' versions.
    async fn extension_closure(
        &self,
        request: &SetRequest,
        own: &crate::output::ResolvedPackage,
    ) -> Result<RealmClosure> {
        let resolver = self.resolver();
        let mut request = request.clone();
        if let Some(artifact) = &own.artifact {
            request.plugin.version = Some(artifact.version.clone());
        }
        request.filtered = CORE_EXPORTS.iter().map(|ga| ga.to_string()).collect();
        let key = request.key(&resolver.ctx.config.project_root);
        if let Some(closure) = lock(&resolver.ctx.extension_realms).closures.get(&key) {
            return Ok(closure.clone());
        }
        let mut ctx = resolver.ctx.apart();
        ctx.version_caps = (resolver.ctx.version_caps.as_deref())
            .and_then(crate::version_caps::VersionCaps::realms);
        let apart = PlatformResolver::new(ctx);
        let models = lock(&self.models).clone();
        let support_poms = self.support_poms.as_ref();
        // Boxed: resolving a set reads its types, which may read the
        // extensions of a module.
        let set = Box::pin(apart.resolve_set(
            &request,
            self.workspace,
            models,
            support_poms,
            Some(own.clone()),
        ))
        .await
        .map_err(|error| request.failed(error))?;
        let closure = RealmClosure {
            jars: set.artifacts.into_iter().skip(1).collect(),
            snapshot_poms: (set.poms.into_iter())
                .filter(|(coord, _)| {
                    coord
                        .rsplit(':')
                        .next()
                        .is_some_and(rv_maven_types::resolves_through_snapshot_metadata)
                })
                .collect(),
        };
        let mut realms = lock(&resolver.ctx.extension_realms);
        Ok(realms.closures.entry(key).or_insert(closure).clone())
    }

    /// A module's plugin repositories as Maven 3.9 orders them: those of the
    /// active settings.xml profiles, which Maven injects into the model
    /// before its own, then the model's, then those of Maven's request,
    /// each unless an earlier one has its id. A POM's is admitted as its
    /// `<repositories>` are; a refused one still holds its id.
    fn plugin_repos(&self, model: &[rv_maven_model::Repository]) -> Vec<Repository> {
        let config = &self.resolver.ctx.config;
        let mut repos: Vec<Repository> = Vec::new();
        let settings = config.profile_plugin_repositories().iter();
        let request = config.plugin_repositories().iter().map(Repository::from);
        let all = (settings.map(Repository::from))
            .chain(model.iter().map(Repository::from))
            .chain(request);
        for repo in all {
            if repo.id.is_none() || !repos.iter().any(|known| known.id == repo.id) {
                repos.push(repo);
            }
        }
        self.admission.admit_root_lineage(repos).0
    }

    /// The repositories a module's dependencies resolve from: the
    /// configured ones, then the POM's, admitted as its plugin repositories
    /// are.
    fn project_repos(&self, project: &Project) -> Vec<Repository> {
        let declared = project.repositories.iter().map(Repository::from);
        let admitted = self.admission.admit_root_lineage(declared).0;
        let config = &self.resolver.ctx.config;
        merge_project_repos(config, self.resolver.ctx.repos.clone(), admitted)
    }

    /// The compiler plugin's `annotationProcessorPaths` of a module that the
    /// compiler `run` uses, a set for each execution's, resolved from the
    /// project's repositories as the compiler plugin at its version
    /// resolves them. A goal's execution falls back to the managed compiler,
    /// as Maven configures a goal from the command line. A reactor module
    /// on a path comes from the reactor.
    fn processor_paths(
        &mut self,
        pom_path: &str,
        project: &Project,
        model: &EffectivePlugins,
        run: &CompilerRun,
        handlers: &[ExtensionHandlers],
        planned: &mut PlannedModule,
    ) -> Vec<String> {
        let declared = model.plugin(DEFAULT_PLUGIN_GROUP, "maven-compiler-plugin");
        let managed = (model.plugin_management.iter()).find(|plugin| {
            plugin.group_id == DEFAULT_PLUGIN_GROUP && plugin.artifact_id == "maven-compiler-plugin"
        });
        let Some(compiler) = declared.or(managed) else {
            return Vec::new();
        };
        let version = &run.version;
        let below = |floor: &str| {
            (version
                .as_deref()
                .and_then(|version| Version::parse(version).ok()))
            .is_some_and(|version| version < Version::parse(floor).expect("a version"))
        };
        let managed = &project.dependency_management.dependencies;
        let mut keys = Vec::new();
        for execution in compiler.processor_paths(run.lifecycle && declared.is_some(), &run.direct)
        {
            let mut paths = Vec::new();
            for (index, path) in execution.paths.into_iter().enumerate() {
                // maven-compiler-plugin 3.12 and later takes a missing version
                // from the project's dependency management, before the reactor
                // is asked for that version.
                let mut path = Dependency {
                    group_id: path.group_id,
                    artifact_id: path.artifact_id,
                    version: path.version,
                    type_: Some(path.type_),
                    classifier: path.classifier,
                    scope: None,
                    optional: None,
                    exclusions: path.exclusions,
                    system_path: None,
                    system_path_from_project: Default::default(),
                    origin: Default::default(),
                };
                if path.version.is_none() && !below("3.12.0") {
                    path.version = managed_version(&path, managed);
                }
                if self.built_in_reactor(&path.group_id, &path.artifact_id, path.version.as_deref())
                {
                    let key = format!("{}:{}", path.group_id, path.artifact_id);
                    if !planned.built_in_reactor.contains(&key) {
                        planned.built_in_reactor.push(key);
                    }
                    // Its POM's dependencies come in beside it, collected as
                    // the path's version collects them, not as the module's
                    // graph: before 3.9.0 only the first path's, at the root
                    // of the legacy request.
                    if index > 0 && below("3.9.0") {
                        continue;
                    }
                }
                paths.push(path);
            }
            if paths.is_empty() {
                continue;
            }
            let paths_by = if below("3.9.0") {
                PathResolution::UnderFirst
            } else if below("3.11.0") {
                PathResolution::Alone
            } else if execution.use_dep_mgmt && !below("3.12.0") {
                PathResolution::Managed(managed.clone())
            } else {
                PathResolution::Together
            };
            let request = SetRequest {
                module: pom_path.to_string(),
                role: PluginRole::ProcessorPath,
                plugin: Plugin::new("rv.processor-path", "processor-path", Some("0")),
                paths,
                repos: self.project_repos(project),
                filtered: Vec::new(),
                handlers: handlers.to_vec(),
                paths_by,
            };
            let key = request.key(&self.resolver().ctx.config.project_root);
            self.requests.entry(key.clone()).or_insert(request);
            keys.push(key);
        }
        keys
    }

    /// `.mvn/extensions.xml` of the launcher's project directory, which may
    /// be above the workspace root: each core extension resolved from the
    /// configured repositories, before any project is read, without the
    /// artifacts Maven's core exports.
    async fn core_extensions(
        &mut self,
        pom_path: &str,
        activation: &ActivationContext,
    ) -> Result<Vec<String>> {
        let launcher = (activation.environment.launcher_root()).map(std::path::Path::new);
        let path = (launcher.unwrap_or(self.workspace.root())).join(".mvn/extensions.xml");
        let Some(text) = rv_config::read_optional_project_input_string(&path)? else {
            return Ok(Vec::new());
        };
        let extensions = rv_maven_model::parse_core_extensions(&text).map_err(|source| {
            ResolveError::LocalPom {
                path: path.display().to_string(),
                source,
            }
        })?;
        // Maven expands them from the user and system properties alone.
        let mut properties = PropertyMap::new();
        for (name, value) in activation.activation_system_properties() {
            properties.insert_external(name, value);
        }
        for (name, value) in self.workspace.root_user_properties(activation).0 {
            properties.insert_external(name, value);
        }
        // The names it reads are inputs of the plugin tables.
        let expand = |value: &str| {
            let (expanded, names) =
                properties.interpolate_str_exact_names(value, &activation.environment);
            for name in names {
                activation.environment.record_user_property(&name);
            }
            expanded.map_err(|source| ResolveError::LocalPom {
                path: path.display().to_string(),
                source,
            })
        };
        let mut keys = Vec::new();
        for extension in extensions {
            let version = extension.version.as_deref().map(expand).transpose()?;
            let plugin = Plugin::new(
                &expand(&extension.group_id)?,
                &expand(&extension.artifact_id)?,
                version.as_deref(),
            );
            if plugin.version.is_none() {
                return Err(ResolveError::MissingVersion {
                    group_id: plugin.group_id,
                    artifact_id: plugin.artifact_id,
                });
            }
            let request = SetRequest {
                module: pom_path.to_string(),
                role: PluginRole::CoreExtension,
                plugin,
                paths: Vec::new(),
                repos: (self.resolver.ctx.config.plugin_repositories().iter())
                    .map(Repository::from)
                    .collect(),
                filtered: CORE_EXPORTS.iter().map(|ga| ga.to_string()).collect(),
                handlers: Vec::new(),
                paths_by: PathResolution::default(),
            };
            let key = request.key(&self.resolver().ctx.config.project_root);
            self.requests.entry(key.clone()).or_insert(request);
            keys.push(key);
        }
        Ok(keys)
    }

    /// Resolve a build extension now, and read what its jars export and
    /// which packagings they map.
    async fn resolve_extension(
        &mut self,
        key: String,
        request: SetRequest,
    ) -> Result<ExtensionDescriptors> {
        if let Some(descriptors) = self.extensions.get(&key) {
            return Ok(descriptors.clone());
        }
        let models = lock(&self.models).clone();
        let set = self
            .resolver
            .resolve_set(&request, self.workspace, models, None, None)
            .await
            .map_err(|error| request.failed(error))?;
        let descriptors = self.resolver.extension_descriptors(&set)?;
        self.extensions.insert(key.clone(), descriptors.clone());
        self.resolved.insert(key.clone(), set);
        self.requests.insert(key, request);
        Ok(descriptors)
    }

    /// The `g:a` and version of each artifact of the plugin realm
    /// `request` resolves. The set itself is resolved again after
    /// planning, with the model cache every module filled.
    pub(super) async fn plugin_realm(
        &mut self,
        request: &SetRequest,
    ) -> Result<BTreeMap<String, String>> {
        let key = request.key(&self.resolver.ctx.config.project_root);
        if let Some(realm) = self.realms.get(&key) {
            return Ok(realm.clone());
        }
        let models = lock(&self.models).clone();
        let set = (self
            .resolver
            .resolve_set(request, self.workspace, models, None, None))
        .await
        .map_err(|error| request.failed(error))?;
        let realm: BTreeMap<String, String> = (set.artifacts.iter())
            .map(|package| {
                let coordinate = &package.coordinate;
                let ga = format!("{}:{}", coordinate.group_id(), coordinate.artifact_id());
                (ga, coordinate.version().to_string())
            })
            .collect();
        self.realms.insert(key, realm.clone());
        Ok(realm)
    }

    /// `plugin` with the version Maven gives it: its own, else the build
    /// plugins', else plugin management's, else the plugin repositories'
    /// metadata.
    pub(super) async fn with_version(
        &mut self,
        module: &str,
        mut plugin: Plugin,
        model: &EffectivePlugins,
        repos: &[Repository],
    ) -> Result<Plugin> {
        if plugin.version.is_some() {
            return Ok(plugin);
        }
        let declared = (model.plugins.iter())
            .chain(&model.plugin_management)
            .find(|known| known.key() == plugin.key())
            .and_then(|known| known.version.clone());
        plugin.version = match declared {
            Some(version) => Some(version),
            None => Some(
                self.metadata_version(
                    (module, false),
                    &plugin.group_id,
                    &plugin.artifact_id,
                    repos,
                )
                .await?,
            ),
        };
        Ok(plugin)
    }

    /// `extension` with the version Maven gives a build extension: its own,
    /// else the plugin repositories' metadata. Maven asks neither the build
    /// plugins nor plugin management, which the model has merged into a
    /// plugin already (`DefaultMavenPluginManager.setupExtensionsRealm`).
    async fn extension_version(
        &mut self,
        module: &str,
        mut extension: Plugin,
        repos: &[Repository],
    ) -> Result<Plugin> {
        if extension.version.is_none() {
            let (group_id, artifact_id) = (&extension.group_id, &extension.artifact_id);
            let version =
                (self.metadata_version((module, true), group_id, artifact_id, repos)).await?;
            extension.version = Some(version);
        }
        Ok(extension)
    }

    /// The plugin a goal runs, `None` for a lifecycle phase. Its version,
    /// dependencies and configuration are the module's declaration's, as
    /// Maven injects them from the build plugins, then plugin management.
    async fn goal_plugin(
        &mut self,
        module: &str,
        goal: &str,
        model: &EffectivePlugins,
        repos: &[Repository],
    ) -> Result<Option<Plugin>> {
        let tokens: Vec<&str> = goal.split(':').collect();
        let (group_id, artifact_id, version) = match tokens[..] {
            [_] => return Ok(None),
            [group_id, artifact_id, version, _, ..] => {
                (group_id.to_string(), artifact_id.to_string(), Some(version))
            }
            [first, second, _] if first.contains('.') => {
                (first.to_string(), second.to_string(), None)
            }
            [prefix, version, _] => {
                let (group_id, artifact_id) =
                    self.resolve_prefix(module, prefix, model, repos).await?;
                (group_id, artifact_id, Some(version))
            }
            [prefix, _] => {
                let (group_id, artifact_id) =
                    self.resolve_prefix(module, prefix, model, repos).await?;
                (group_id, artifact_id, None)
            }
            [] => return Ok(None),
        };
        let mut plugin = Plugin::new(&group_id, &artifact_id, version);
        let declared = (model.plugins.iter())
            .chain(&model.plugin_management)
            .find(|known| known.key() == plugin.key());
        if let Some(declared) = declared {
            if plugin.version.is_none() {
                plugin.version.clone_from(&declared.version);
            }
            plugin.dependencies.clone_from(&declared.dependencies);
            // Configured as its execution, `default-cli` unless it names one
            // after `@`, else as the plugin.
            let id = goal.split_once('@').map_or("default-cli", |(_, id)| id);
            plugin.configuration = match declared.executions.iter().find(|run| run.id == id) {
                Some(execution) => execution.configuration.clone(),
                None => declared.configuration.clone(),
            };
        }
        Ok(Some(plugin))
    }

    /// The groups Maven searches for a prefix, in its order: those of the
    /// build plugins and plugin management not among the plugin groups,
    /// each limited to the plugins it names, then the plugin groups,
    /// unlimited: the settings.xml `groups`, then Maven's defaults.
    pub(super) fn prefix_candidates(
        model: &EffectivePlugins,
        groups: &[String],
    ) -> Vec<(String, Option<BTreeSet<String>>)> {
        let mut plugin_groups: Vec<&str> = Vec::new();
        for group in groups
            .iter()
            .map(String::as_str)
            .chain(DEFAULT_PLUGIN_GROUPS)
        {
            if !plugin_groups.contains(&group) {
                plugin_groups.push(group);
            }
        }
        let mut candidates: Vec<(String, Option<BTreeSet<String>>)> = Vec::new();
        for plugin in model.plugins.iter().chain(&model.plugin_management) {
            if plugin_groups.contains(&plugin.group_id.as_str()) {
                continue;
            }
            match candidates
                .iter_mut()
                .find(|(group, _)| *group == plugin.group_id)
            {
                Some((_, Some(artifacts))) => {
                    artifacts.insert(plugin.artifact_id.clone());
                }
                Some((_, None)) => {}
                None => candidates.push((
                    plugin.group_id.clone(),
                    Some(BTreeSet::from([plugin.artifact_id.clone()])),
                )),
            }
        }
        for group in plugin_groups {
            candidates.push((group.to_string(), None));
        }
        candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A version-less path takes the version of the managed entry of its
    /// type and classifier alone, as maven-compiler-plugin 3.12 does: one
    /// without the classifier leaves it without, and Maven fails.
    #[test]
    fn a_path_takes_the_managed_version_of_its_type_and_classifier() {
        let entry =
            |classifier: Option<&str>, type_: Option<&str>, version: Option<&str>| Dependency {
                group_id: "t".to_string(),
                artifact_id: "pk".to_string(),
                version: version.map(str::to_string),
                type_: type_.map(str::to_string),
                classifier: classifier.map(str::to_string),
                scope: None,
                optional: None,
                exclusions: Vec::new(),
                system_path: None,
                system_path_from_project: Default::default(),
                origin: Default::default(),
            };
        let path = |classifier| entry(classifier, Some("jar"), None);
        let managed = [
            entry(None, None, Some("1")),
            entry(Some("k"), Some("zip"), Some("2")),
            entry(Some("k"), None, Some("3")),
        ];
        assert_eq!(
            managed_version(&path(Some("k")), &managed).as_deref(),
            Some("3")
        );
        assert_eq!(managed_version(&path(None), &managed).as_deref(), Some("1"));
        assert_eq!(managed_version(&path(Some("k")), &managed[..1]), None);
        // The managed classifier compares as written, so an empty one is
        // apart from none; the path's, read from the configuration, is not.
        let managed = [
            entry(Some(""), None, Some("1")),
            entry(None, None, Some("2")),
        ];
        for classifier in [None, Some("")] {
            assert_eq!(
                managed_version(&path(classifier), &managed).as_deref(),
                Some("2")
            );
        }
        assert_eq!(managed_version(&path(None), &managed[..1]), None);
    }

    /// The handlers the module's build extensions define key a plugin's
    /// set, as they decide its files; a module without any keys it as
    /// before.
    #[test]
    fn extension_handlers_key_a_set() {
        let key = |handlers: Vec<ExtensionHandlers>| {
            let request = SetRequest {
                module: "pom.xml".to_string(),
                role: PluginRole::Plugin,
                plugin: Plugin::new("g", "p", Some("1")),
                paths: Vec::new(),
                repos: Vec::new(),
                filtered: Vec::new(),
                handlers,
                paths_by: PathResolution::default(),
            };
            request.key(std::path::Path::new("/project"))
        };
        let jar = rv_lock::ExtensionJar {
            gav: rv_maven_types::Gav::new("g", "ext", "1"),
            classifier: None,
            sha256: rv_maven_types::Sha256::from_bytes(b"ext"),
        };
        let defines = |extension: &str| {
            let handler = rv_maven_model::ArtifactHandler::plain(extension);
            vec![(vec![jar.clone()], vec![("hpi".to_string(), Ok(handler))])]
        };
        assert_eq!(key(vec![(vec![jar.clone()], Vec::new())]), key(Vec::new()));
        assert_ne!(key(defines("hpi")), key(Vec::new()));
        assert_ne!(key(defines("hpi")), key(defines("jar")));
    }

    /// A repository inside the project counts as raeva.lock records it, so
    /// two checkouts of the project at other paths key a set alike.
    #[test]
    fn a_set_key_does_not_depend_on_the_checkout_path() {
        let key = |root: &std::path::Path, repo: &std::path::Path| {
            let url = format!("file://{}/", repo.display());
            let request = SetRequest {
                module: "pom.xml".to_string(),
                role: PluginRole::Plugin,
                plugin: Plugin::new("g", "p", Some("1")),
                paths: Vec::new(),
                repos: vec![Repository::new(Some("local".into()), &url, true, false)],
                filtered: Vec::new(),
                handlers: Vec::new(),
                paths_by: PathResolution::default(),
            };
            request.key(root)
        };
        let (one, two) = (
            tempfile::TempDir::new().unwrap(),
            tempfile::TempDir::new().unwrap(),
        );
        let inside = |root: &std::path::Path| key(root, &root.join("repo"));
        assert_eq!(inside(one.path()), inside(two.path()));
        // One outside the project keeps its path.
        let outside = one.path().join("repo");
        assert_ne!(key(&one.path().join("sub"), &outside), inside(one.path()));
    }

    /// A plugin dependency's system path inside the project counts as
    /// relative to it, so two checkouts key the set alike.
    #[test]
    fn a_system_path_in_the_project_keys_relative_to_it() {
        let key = |root: &std::path::Path,
                   path: &dyn Fn(&std::path::Path) -> std::path::PathBuf| {
            let mut plugin = Plugin::new("g", "p", Some("1"));
            plugin.dependencies.push(Dependency {
                group_id: "g".to_string(),
                artifact_id: "local".to_string(),
                version: Some("1".to_string()),
                type_: None,
                classifier: None,
                scope: Some("system".to_string()),
                optional: None,
                exclusions: Vec::new(),
                system_path: Some(path(root).display().to_string()),
                system_path_from_project: Default::default(),
                origin: Default::default(),
            });
            let request = SetRequest {
                module: "pom.xml".to_string(),
                role: PluginRole::Plugin,
                plugin,
                paths: Vec::new(),
                repos: Vec::new(),
                filtered: Vec::new(),
                handlers: Vec::new(),
                paths_by: PathResolution::default(),
            };
            request.key(root)
        };
        let (one, two) = (
            tempfile::TempDir::new().unwrap(),
            tempfile::TempDir::new().unwrap(),
        );
        let lib = |root: &std::path::Path| root.join("lib").join("local.jar");
        assert_eq!(key(one.path(), &lib), key(two.path(), &lib));
        // Through `..` and through a link to the checkout, as
        // `${project.basedir}` spells it.
        let through = |root: &std::path::Path| root.join("sub").join("..").join("lib/local.jar");
        assert_eq!(key(one.path(), &through), key(two.path(), &lib));
        #[cfg(unix)]
        {
            let link = two.path().join("link");
            std::os::unix::fs::symlink(one.path(), &link).unwrap();
            let canonical = std::fs::canonicalize(one.path()).unwrap();
            let linked = key(&link, &|_: &std::path::Path| {
                canonical.join("lib/local.jar")
            });
            assert_eq!(linked, key(two.path(), &lib));
        }
        // Outside the project it stays as written.
        let outside = |root: &std::path::Path| root.join("..").join("local.jar");
        assert_ne!(key(one.path(), &outside), key(two.path(), &outside));
    }
}

/// A compiler plugin version that runs in a module: through the lifecycle
/// when the module declares it, and for the `direct` executions of the
/// compile goals that name it.
#[derive(Default)]
struct CompilerRun {
    version: Option<String>,
    lifecycle: bool,
    direct: Vec<String>,
}

impl CompilerRun {
    fn lifecycle() -> Self {
        CompilerRun {
            lifecycle: true,
            ..CompilerRun::default()
        }
    }
}
