//! The artifact handlers a module's build extensions define. Maven loads a
//! project's build extensions before it resolves the project's
//! dependencies, so their handlers decide the extension, classifier and
//! traversal of every dependency type the core does not define (Jenkins'
//! `executable-war` and `hpi`, Felix's `bundle`). raeva reads them the
//! first time the module's resolution meets such a type, from every jar of
//! each extension's realm, the extension's own and those of the set Maven
//! resolves for it, and pins every jar it read: which one defines a type
//! depends on all of them, and Maven loads each. The types the solver
//! and its management hold are clones that see the handlers once they are
//! read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use rv_lock::ExtensionJar;
use rv_maven_model::{ArtifactTypes, DefinedType, Dependency, PomError, Project, is_core_type};
use rv_maven_types::{Gav, MavenMode, bounded};

use super::PlatformResolver;
use super::backend::{ModelCache, WorkspaceSupportPomBuffer};
use crate::SupportPomProvenance;
use crate::error::{ResolveError, Result};
use crate::util::lock;
use crate::workspace::Workspace;

pub(crate) struct ExtensionTypes {
    /// Where the module's extensions are read from; `None` when they were
    /// read before.
    source: Option<Source>,
    mode: MavenMode,
    /// The core handlers, then the extensions' once they are read.
    types: ArtifactTypes,
    loaded: OnceLock<Loaded>,
    loading: tokio::sync::Mutex<()>,
    /// The core types met before the extensions were read, which an
    /// extension may define otherwise.
    core_met: Mutex<BTreeSet<String>>,
}

struct Source {
    resolver: PlatformResolver,
    path: PathBuf,
    pom_path: String,
    workspace: Arc<Workspace>,
    support_poms: Option<WorkspaceSupportPomBuffer>,
    models: Arc<ModelCache>,
}

/// The jars of a build extension's realm, its own first, and the artifact
/// handlers they define.
pub(crate) type ExtensionHandlers = (Vec<ExtensionJar>, Vec<DefinedType>);

struct Loaded {
    /// The jars of the extensions' realms, each once.
    jars: Vec<ExtensionJar>,
    /// The SNAPSHOT parents and BOMs the realms read, which decide their
    /// jars.
    poms: Vec<(String, SupportPomProvenance)>,
    /// The extension whose handler counts for each type one defines.
    owners: BTreeMap<String, Gav>,
}

impl ExtensionTypes {
    /// The handlers of the module at `path`, `pom_path` in `workspace`,
    /// whose model reads go to `support_poms` as the module's own do, read
    /// with the model cache `models` its project build left.
    pub(super) fn new(
        resolver: PlatformResolver,
        path: PathBuf,
        pom_path: String,
        workspace: Arc<Workspace>,
        support_poms: Option<WorkspaceSupportPomBuffer>,
        models: Arc<ModelCache>,
    ) -> Self {
        let mode = resolver.ctx.config.lock.maven.mode;
        Self {
            source: Some(Source {
                resolver,
                path,
                pom_path,
                workspace,
                support_poms,
                models,
            }),
            mode,
            types: ArtifactTypes::pending(mode),
            loaded: OnceLock::new(),
            loading: tokio::sync::Mutex::new(()),
            core_met: Mutex::default(),
        }
    }

    /// The handlers of `mode`'s core, of the extensions `found` holds,
    /// read before, and the types `own` defines.
    pub(crate) fn known(
        mode: MavenMode,
        found: Vec<ExtensionHandlers>,
        own: Vec<DefinedType>,
    ) -> Self {
        let types = Self {
            source: None,
            mode,
            types: ArtifactTypes::pending(mode),
            loaded: OnceLock::new(),
            loading: tokio::sync::Mutex::new(()),
            core_met: Mutex::default(),
        };
        let loaded = types.define(found, own, Vec::new());
        let _ = types.loaded.set(loaded);
        types
    }

    /// The handlers: the core ones until a type needs more. A clone
    /// taken before sees the extensions' once they are read.
    pub(crate) fn types(&self) -> ArtifactTypes {
        self.types.clone()
    }

    /// Read the extensions' handlers when `project` declares or manages a
    /// type the core does not define, before the solver reads it, and fail
    /// on one whose handler cannot be read. Once they are read, a core type
    /// met, before or since, fails where an extension defines it otherwise.
    pub(crate) async fn meet(&self, project: &Project) -> Result<()> {
        let dependencies = project.dependencies.iter();
        self.meet_types(dependencies.chain(&project.dependency_management.dependencies))
            .await
    }

    /// [`Self::meet`] for the types of `dependencies`.
    pub(crate) async fn meet_types(
        &self,
        dependencies: impl IntoIterator<Item = &Dependency>,
    ) -> Result<()> {
        let met: BTreeSet<&str> = (dependencies.into_iter())
            .map(|dependency| dependency.type_.as_deref().unwrap_or("jar"))
            .filter(|type_| !type_.is_empty())
            .collect();
        if met.iter().all(|type_| is_core_type(type_, self.mode)) {
            let mut core_met = lock(&self.core_met);
            if self.loaded.get().is_none() {
                core_met.extend(met.into_iter().map(str::to_string));
                return Ok(());
            }
        }
        let loaded = self.load().await?;
        let before = std::mem::take(&mut *lock(&self.core_met));
        for type_ in met.into_iter().chain(before.iter().map(String::as_str)) {
            let Some(reason) = self.types.unreadable(type_) else {
                continue;
            };
            let defined_by = (loaded.owners.get(type_))
                .map(Gav::to_string)
                .unwrap_or_default();
            return Err(ResolveError::Plugin {
                plugin: format!("build-extension {defined_by}"),
                searched: Vec::new(),
                error: Box::new(ResolveError::Pom(PomError::Unlockable(format!(
                    "raeva cannot read the handler of dependency type '{}': {}",
                    bounded(type_),
                    bounded(reason)
                )))),
            });
        }
        Ok(())
    }

    async fn load(&self) -> Result<&Loaded> {
        if let Some(loaded) = self.loaded.get() {
            return Ok(loaded);
        }
        let _loading = self.loading.lock().await;
        if let Some(loaded) = self.loaded.get() {
            return Ok(loaded);
        }
        let source = (self.source.as_ref()).expect("handlers read before are loaded");
        let (found, poms) = (source.resolver)
            .extension_handlers(
                &source.path,
                &source.pom_path,
                Arc::clone(&source.workspace),
                source.support_poms.as_ref(),
                Arc::clone(&source.models),
            )
            .await?;
        let loaded = self.define(found, Vec::new(), poms);
        Ok(self.loaded.get_or_init(|| loaded))
    }

    fn define(
        &self,
        found: Vec<ExtensionHandlers>,
        mut handlers: Vec<DefinedType>,
        poms: Vec<(String, SupportPomProvenance)>,
    ) -> Loaded {
        let mut jars: Vec<ExtensionJar> = Vec::new();
        let mut owners = BTreeMap::new();
        for (realm, defined) in found {
            if let Some(own) = realm.first() {
                for (type_, _) in &defined {
                    owners
                        .entry(type_.clone())
                        .or_insert_with(|| own.gav.clone());
                }
            }
            for jar in realm {
                if !jars.contains(&jar) {
                    jars.push(jar);
                }
            }
            handlers.extend(defined);
        }
        self.types.define(handlers);
        Loaded { jars, poms, owners }
    }

    /// The jars of each extension's realm, once the resolution met a type
    /// that made it read them.
    pub(crate) fn read_jars(&self) -> Vec<ExtensionJar> {
        (self.loaded.get()).map_or_else(Vec::new, |loaded| loaded.jars.clone())
    }

    /// The SNAPSHOT parents and BOMs the realms of [`Self::read_jars`]
    /// read, which the module pins as it pins its own.
    pub(crate) fn read_poms(&self) -> Vec<(String, SupportPomProvenance)> {
        (self.loaded.get()).map_or_else(Vec::new, |loaded| loaded.poms.clone())
    }
}

/// The artifact types of a locked module: the core handlers of `mode`, then
/// those the extension jars it pins define, read from `store` as one realm,
/// since raeva.lock does not record which extension's realm holds a jar.
/// A jar the store lacks adds none, and none are added when one does not
/// read.
pub fn locked_artifact_types(
    store: &rv_store::Store,
    mode: MavenMode,
    jars: &[ExtensionJar],
) -> ArtifactTypes {
    let types = ArtifactTypes::pending(mode);
    let files: Vec<_> = (jars.iter())
        .map(|jar| (store.get_path(&jar.sha256), jar.to_string()))
        .filter(|(path, _)| path.is_file())
        .collect();
    let realm: Vec<_> = (files.iter())
        .map(|(path, coord)| (path.as_path(), coord.as_str()))
        .collect();
    types.define(super::plugins::jar::realm_handlers(&realm).unwrap_or_default());
    types
}
