//! Maven's model cache across the modules of one reactor resolution.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use rv_maven_model::Project;
use rv_maven_types::MavenMode;
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore, watch};

use crate::util::lock;
use crate::workspace::{SorterEdges, Workspace};

use super::backend::{ModelCache, PomGav, ReadModels};
use super::scope::KeptImport;

/// What the modules of a reactor resolution read into Maven's model cache.
///
/// Maven builds the reactor's projects in turn, each model's lineage first
/// and then, for every model, its imports, then collects the modules'
/// dependencies in `ProjectSorter` order, all with one model cache. Here
/// each module resolves on its own, so a model its build finds neither in
/// its repositories nor in what it read itself, or a parent range it has
/// not read, is looked for in what the lineages before it read; for its
/// imports, in what every lineage read, then in what the project builds
/// before it read; and for its dependencies in what every project build
/// read, then in what each module sorted before it read, the first that
/// has it winning. Only such a miss waits for the other modules.
pub(super) struct SessionModels {
    workspace: Arc<Workspace>,
    modules: Mutex<Vec<Module>>,
    changed: watch::Sender<()>,
    sorted: OnceCell<Vec<usize>>,
    /// What the project builds imported, the first in reactor order
    /// winning, once every module's project is built.
    project_imports: OnceCell<HashMap<PomGav, Arc<KeptImport>>>,
    plugin_edges: PluginEdges,
    /// One per module graph that may resolve at once.
    permits: Arc<Semaphore>,
}

/// The modules a module's build plugins and extensions link it to, given
/// what its project build read: see [`Workspace::plugin_edges`]. An error
/// is Maven's message refusing the module's effective build plugins.
pub(super) type PluginEdges =
    Box<dyn Fn(usize, Arc<ModelCache>) -> BoxFuture<'static, PluginLinks> + Send + Sync>;

type PluginLinks = Result<Vec<usize>, String>;

#[derive(Default)]
struct Module {
    /// What the module's lineage read, once read; `None` when it was not.
    lineage: Option<Option<Arc<ModelCache>>>,
    /// What the module's project build read and the modules it links to,
    /// once built; `None` when it failed or was not made.
    project: Option<Option<(Arc<ModelCache>, SorterEdges)>>,
    /// The module's model cache, from its project build on.
    models: Option<ReadModels>,
    /// The module's [`Workspace::plugin_edges`], read in the background
    /// from its project build on.
    plugins: Option<Shared<BoxFuture<'static, PluginLinks>>>,
    graph_done: bool,
}

impl SessionModels {
    pub(super) fn new(
        workspace: Arc<Workspace>,
        concurrency: usize,
        plugin_edges: PluginEdges,
    ) -> Arc<Self> {
        let modules = (0..workspace.len()).map(|_| Module::default()).collect();
        Arc::new(Self {
            workspace,
            modules: Mutex::new(modules),
            changed: watch::Sender::new(()),
            sorted: OnceCell::new(),
            project_imports: OnceCell::new(),
            plugin_edges,
            permits: Arc::new(Semaphore::new(concurrency)),
        })
    }

    /// Module `index`'s turn to resolve, once a slot is free.
    pub(super) async fn turn(self: &Arc<Self>, index: usize) -> Arc<ModuleTurn> {
        let permit = Arc::clone(&self.permits).acquire_owned().await.ok();
        Arc::new(ModuleTurn {
            session: Arc::clone(self),
            index,
            slot: Mutex::new(Slot {
                permit,
                ..Slot::default()
            }),
            lineage: Default::default(),
        })
    }

    fn update(&self, index: usize, update: impl FnOnce(&mut Module)) {
        update(&mut lock(&self.modules)[index]);
        self.changed.send_replace(());
    }

    async fn until<T>(&self, mut ready: impl FnMut(&[Module]) -> Option<T>) -> T {
        let mut changed = self.changed.subscribe();
        loop {
            if let Some(value) = ready(&lock(&self.modules)) {
                return value;
            }
            // `self` holds the sender.
            let _ = changed.changed().await;
        }
    }

    async fn find<T>(&self, index: usize, find: impl Fn(&ModelCache) -> Option<T>) -> Option<T> {
        let (lineage, project) = {
            let module = &lock(&self.modules)[index];
            (module.lineage.is_some(), module.project.is_some())
        };
        if !project {
            if lineage {
                let lineages = self
                    .until(|modules| {
                        (modules.iter())
                            .map(|module| module.lineage.clone())
                            .collect::<Option<Vec<_>>>()
                    })
                    .await;
                if let Some(found) = lineages.iter().flatten().find_map(|read| find(read)) {
                    return Some(found);
                }
            }
            for before in 0..index {
                let read = self
                    .until(|modules| match lineage {
                        true => {
                            (modules[before].project.clone()).map(|read| read.map(|(read, _)| read))
                        }
                        false => modules[before].lineage.clone(),
                    })
                    .await;
                if let Some(found) = read.and_then(|read| find(&read)) {
                    return Some(found);
                }
            }
            return None;
        }
        let projects = self
            .until(|modules| {
                (modules.iter())
                    .map(|module| module.project.clone())
                    .collect::<Option<Vec<_>>>()
            })
            .await;
        if let Some(found) = (projects.iter().flatten()).find_map(|(read, _)| find(read)) {
            return Some(found);
        }
        // Only a lookup that gets this far reads the build plugins.
        // A cycle fails the resolution: see [`Self::cycle`].
        let sorted = (self.sorted)
            .get_or_init(|| async move { self.sort(projects).await.unwrap_or_default() })
            .await;
        for &before in sorted.iter().take_while(|&&module| module != index) {
            let models = self
                .until(|modules| {
                    (modules[before].graph_done).then(|| modules[before].models.clone())
                })
                .await;
            if let Some(found) = models.and_then(|models| find(&lock(&models))) {
                return Some(found);
            }
        }
        None
    }
}

impl SessionModels {
    /// The cycle Maven's `ProjectSorter` refuses the reactor for, in the
    /// links of the projects that were built and of their build plugins:
    /// see [`Workspace::sorted`].
    pub(super) async fn cycle(&self) -> Option<String> {
        let projects: Vec<_> = (lock(&self.modules).iter())
            .map(|module| module.project.clone().flatten())
            .collect();
        self.sort(projects).await.err()
    }

    /// The first module, in reactor order, whose effective build plugins
    /// Maven's validation refuses, with its message.
    pub(super) async fn invalid_plugins(&self) -> Option<(usize, String)> {
        let plugins: Vec<_> = (lock(&self.modules).iter())
            .map(|module| module.plugins.clone())
            .collect();
        for (index, plugins) in plugins.into_iter().enumerate() {
            if let Some(Err(message)) = match plugins {
                Some(plugins) => Some(plugins.await),
                None => None,
            } {
                return Some((index, message));
            }
        }
        None
    }

    /// [`Workspace::sorted`] over the links of `projects` and of their
    /// build plugins.
    async fn sort(
        &self,
        projects: Vec<Option<(Arc<ModelCache>, SorterEdges)>>,
    ) -> Result<Vec<usize>, String> {
        let plugins: Vec<_> = (lock(&self.modules).iter())
            .map(|module| module.plugins.clone())
            .collect();
        let plugins = (plugins.into_iter()).map(|plugins| async move {
            match plugins {
                Some(plugins) => plugins.await.unwrap_or_default(),
                None => Vec::new(),
            }
        });
        let plugins = futures::future::join_all(plugins).await;
        let edges = projects.into_iter().map(|project| project.unzip().1);
        let edges = edges.map(Option::unwrap_or_default).collect::<Vec<_>>();
        self.workspace.sorted(&edges, &plugins)
    }

    /// What Maven 3.9's session cache holds for the import `bom` for module
    /// `index`: Maven builds every project before it collects a graph, so
    /// a project build sees the imports of the project builds before it,
    /// and anything later sees those of every project build. What a graph
    /// imports is not looked for.
    async fn import(&self, index: usize, bom: &PomGav) -> Option<Arc<KeptImport>> {
        if lock(&self.modules)[index].project.is_none() {
            for before in 0..index {
                let read = self.until(|modules| modules[before].project.clone()).await;
                if let Some(kept) = read.and_then(|(read, _)| read.imports.get(bom).cloned()) {
                    return Some(kept);
                }
            }
            return None;
        }
        self.project_imports().await.get(bom).cloned()
    }

    async fn project_imports(&self) -> &HashMap<PomGav, Arc<KeptImport>> {
        (self.project_imports)
            .get_or_init(|| async {
                let projects = self
                    .until(|modules| {
                        (modules.iter())
                            .map(|module| module.project.clone())
                            .collect::<Option<Vec<_>>>()
                    })
                    .await;
                let mut imports = HashMap::new();
                for (read, _) in projects.iter().flatten() {
                    for (bom, kept) in &read.imports {
                        (imports.entry(bom.clone())).or_insert_with(|| Arc::clone(kept));
                    }
                }
                imports
            })
            .await
    }
}

/// A module's place in [`SessionModels`] while its project and graph
/// build.
pub(super) struct ModuleTurn {
    session: Arc<SessionModels>,
    index: usize,
    slot: Mutex<Slot>,
    lineage: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct Slot {
    permit: Option<OwnedSemaphorePermit>,
    waits: usize,
    /// Whether a find that waited is taking a slot again, which the
    /// module's other finds then leave to it.
    resuming: bool,
    done: bool,
}

impl ModuleTurn {
    /// The module's lineage is read, its model cache holding what it read.
    pub(super) fn lineage_read(&self, models: &ReadModels) {
        if !self
            .lineage
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            let read = Arc::new(lock(models).clone());
            self.session
                .update(self.index, |module| module.lineage = Some(Some(read)));
        }
    }

    /// The module's project build read `read` into its model cache,
    /// `models`, and built `project`, in the `mode` it resolves as.
    pub(super) fn built(
        &self,
        read: Arc<ModelCache>,
        project: &Project,
        models: &ReadModels,
        mode: MavenMode,
    ) {
        let edges = (self.session.workspace).sorter_edges(self.index, project, mode);
        let plugins = tokio::spawn((self.session.plugin_edges)(self.index, Arc::clone(&read)));
        let plugins = async move { plugins.await.unwrap_or_else(|_| Ok(Vec::new())) };
        self.lineage
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.session.update(self.index, |module| {
            module
                .lineage
                .get_or_insert_with(|| Some(Arc::clone(&read)));
            module.project = Some(Some((read, edges)));
            module.models = Some(Arc::clone(models));
            module.plugins = Some(plugins.boxed().shared());
        });
    }

    /// The module's graph is in, or was not resolved.
    pub(super) fn finish(&self) {
        let permit = {
            let mut slot = lock(&self.slot);
            slot.done = true;
            slot.permit.take()
        };
        drop(permit);
        self.session.update(self.index, |module| {
            module.lineage.get_or_insert(None);
            module.project.get_or_insert(None);
            module.graph_done = true;
        });
    }

    /// What the session's model cache gives `find` for this module. The
    /// module holds no slot while it waits, so the modules it waits for can
    /// take one.
    pub(super) async fn find<T>(&self, find: impl Fn(&ModelCache) -> Option<T>) -> Option<T> {
        self.waiting(self.session.find(self.index, find)).await
    }

    /// What the reactor's project builds imported as `bom` for this module;
    /// see [`SessionModels::import`].
    pub(super) async fn import(&self, bom: &PomGav) -> Option<Arc<KeptImport>> {
        if lock(&self.session.modules)[self.index].project.is_some()
            && let Some(imports) = self.session.project_imports.get()
        {
            return imports.get(bom).cloned();
        }
        self.waiting(self.session.import(self.index, bom)).await
    }

    /// `wait`, with no slot held meanwhile.
    async fn waiting<T>(&self, wait: impl Future<Output = Option<T>>) -> Option<T> {
        let permit = {
            let mut slot = lock(&self.slot);
            if slot.done {
                return None;
            }
            slot.waits += 1;
            slot.permit.take()
        };
        drop(permit);
        let found = wait.await;
        let resume = {
            let mut slot = lock(&self.slot);
            slot.waits -= 1;
            let resume = slot.waits == 0 && !slot.done && !slot.resuming && slot.permit.is_none();
            slot.resuming |= resume;
            resume
        };
        if resume {
            let permit = Arc::clone(&self.session.permits).acquire_owned().await.ok();
            let mut slot = lock(&self.slot);
            slot.resuming = false;
            if slot.waits == 0 && !slot.done {
                slot.permit = permit;
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Two finds of one module that both waited take one slot back between
    /// them: the second may not queue for another while the module holds one.
    #[tokio::test]
    async fn finds_that_waited_take_one_slot_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let project = |artifact: &str, body: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
<artifactId>{artifact}</artifactId><version>1</version>{body}</project>"
            )
        };
        let modules = "<packaging>pom</packaging><modules><module>m</module></modules>";
        std::fs::write(dir.path().join("pom.xml"), project("app", modules)).expect("root");
        std::fs::create_dir(dir.path().join("m")).expect("mkdir");
        std::fs::write(dir.path().join("m/pom.xml"), project("m", "")).expect("module");
        let workspace = Workspace::discover(dir.path()).expect("workspace");
        let edges: PluginEdges = Box::new(|_, _| Box::pin(std::future::ready(Ok(Vec::new()))));
        let session = SessionModels::new(Arc::new(workspace), 1, edges);
        let module = session.turn(1).await;
        let find = |module: &Arc<ModuleTurn>| {
            let module = Arc::clone(module);
            tokio::spawn(async move { module.find(|_| None::<()>).await })
        };
        // It waits for the aggregator's project build, which then takes
        // the slot it gave up.
        let first = find(&module);
        tokio::task::yield_now().await;
        let aggregator = session.turn(0).await;
        let built = Project::new("t", "app", "1");
        let mode = MavenMode::Maven39;
        aggregator.built(Arc::default(), &built, &ReadModels::default(), mode);
        tokio::task::yield_now().await;
        let second = find(&module);
        tokio::task::yield_now().await;
        aggregator.finish();
        let both = async { (first.await, second.await) };
        let (first, second) = tokio::time::timeout(Duration::from_secs(10), both)
            .await
            .expect("neither find waits for a second slot");
        assert!(first.expect("first").is_none() && second.expect("second").is_none());
    }
}
