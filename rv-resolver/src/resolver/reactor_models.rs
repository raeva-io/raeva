//! Models the modules of one reactor resolution build for each other.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use indexmap::{Equivalent, IndexMap};

use bytes::Bytes;
use rv_maven_model::Project;
use rv_maven_types::{BlobId, Coord};

use crate::graph::{ExactCoord, coord_text};
use crate::util::lock;

use super::backend::{PomProblem, SupportPom};
use super::scope::KeptImport;

/// The models of dependencies and reactor modules that a module's
/// resolution built, for the other modules of the reactor to reuse.
///
/// Most modules of a reactor depend on the same artifacts and siblings, and
/// building each model again in every module was most of a warm reactor
/// resolution. A model depends on the repositories the building module had
/// admitted, so it is kept under them, and only when its build left them as
/// they were. A module that reuses one records what that build recorded.
///
/// The imported BOMs the modules built are kept for each other too: most
/// modules of a reactor import the same BOMs through a shared parent.
#[derive(Default)]
pub(super) struct ReactorModels {
    models: Mutex<IndexMap<(ExactCoord, ContextId), Arc<ReactorModel>>>,
    /// The id of each repository context text a model was built under.
    contexts: Mutex<HashMap<String, ContextId>>,
    /// The context of a reactor module's own build, which starts from the
    /// configured repositories in every module.
    own_context: Mutex<Option<ContextId>>,
    pub(super) imports: Arc<KeptImports>,
}

/// Imported BOMs built so far, by coordinates and context, oldest first;
/// see `ModelScope::reuse_import`.
#[derive(Default)]
pub(super) struct KeptImports {
    pub(super) builds: Mutex<HashMap<String, Vec<Arc<KeptImport>>>>,
    /// Made on the first build, as each one costs a pass over every
    /// callsite.
    pub(super) holds: std::sync::OnceLock<rv_maven_model::held::Holds>,
}

impl KeptImports {
    /// Drop the builds that logged, for the next project to build again and
    /// log as its own.
    pub(super) fn forget_logged(&self) {
        lock(&self.builds).retain(|_, kept| {
            kept.retain(|kept| !kept.logged);
            !kept.is_empty()
        });
    }
}

/// The repositories a model's build read, by [`ReactorModels::context_id`].
pub(super) type ContextId = usize;

/// A `(ExactCoord, ContextId)` key borrowed for a lookup; it hashes as the
/// owned key.
#[derive(Hash)]
struct ModelKey<'a>(
    (&'a str, &'a str, &'a str, Option<&'a str>, Option<&'a str>),
    ContextId,
);

impl Equivalent<(ExactCoord, ContextId)> for ModelKey<'_> {
    fn equivalent(&self, key: &(ExactCoord, ContextId)) -> bool {
        self.1 == key.1 && self.0 == coord_text(&key.0.0)
    }
}

pub(super) struct ReactorModel {
    pub(super) project: Arc<Project>,
    pub(super) pom: Option<DependencyPom>,
    pub(super) support_poms: Vec<Arc<SupportPom>>,
    /// What its build read from the host.
    pub(super) reads: Arc<std::collections::BTreeSet<rv_maven_model::HostInput>>,
    /// Why the POM is invalid, for a module whose graph selects the model.
    pub(super) problem: Option<PomProblem>,
}

#[derive(Clone)]
pub(super) struct DependencyPom {
    pub(super) bytes: Bytes,
    pub(super) blob: BlobId,
    pub(super) repo_url: Arc<str>,
    /// The URL that served it for `repo_url`: the repository or its mirror.
    pub(super) endpoint_url: Arc<str>,
}

impl ReactorModels {
    /// The id of the repository context `context` describes.
    pub(super) fn context_id(&self, context: String) -> ContextId {
        let mut contexts = lock(&self.contexts);
        let next = contexts.len();
        *contexts.entry(context).or_insert(next)
    }

    /// The context of a reactor module's own build, from `context` the first
    /// time.
    pub(super) fn own_context(
        &self,
        context: impl FnOnce() -> Option<ContextId>,
    ) -> Option<ContextId> {
        let mut own = lock(&self.own_context);
        if own.is_none() {
            *own = context();
        }
        *own
    }

    pub(super) fn get(&self, coord: &Coord, context: ContextId) -> Option<Arc<ReactorModel>> {
        lock(&self.models)
            .get(&ModelKey(coord_text(coord), context))
            .cloned()
    }

    pub(super) fn insert(&self, coord: &Coord, context: ContextId, model: ReactorModel) {
        lock(&self.models).insert((ExactCoord(coord.clone()), context), Arc::new(model));
    }

    /// Drop the models once every module's graph is built.
    pub(super) fn clear(&self) {
        let models = std::mem::take(&mut *lock(&self.models));
        lock(&self.contexts).clear();
        *lock(&self.own_context) = None;
        let imports = std::mem::take(&mut *lock(&self.imports.builds));
        crate::util::drop_in_background((models, imports));
    }
}
