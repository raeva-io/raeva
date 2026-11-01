//! The interface through which model building reads the POMs a model needs
//! beyond its input: parents and imported BOMs.
//!
//! [`Project::build`] and [`EffectiveDescriptor::build`] read them from a
//! [`ModelSource`] under a [`ModelPolicy`]. A source whose futures complete
//! without waiting, such as one over local files, can drive a build with
//! [`ready`] instead of an executor.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

#[cfg(doc)]
use crate::{EffectiveDescriptor, Project};
use crate::{ImportedBom, Parent, Pom, PomError, Repository};

/// The bound on nested imports. A BOM the project imports is at level 1
/// and a BOM that one imports at level 2; a BOM at this level fails the
/// build, even one that imports nothing.
pub const MAX_IMPORT_DEPTH: usize = crate::project::MAX_BOM_DEPTH;

/// Where model building reads parents and imported BOMs from.
///
/// # Lookups
///
/// The builder asks for each `<parent>` of the input POM and of its
/// ancestors with [`ModelSource::parent`], up to
/// [`crate::MAX_PARENT_CHAIN_DEPTH`] hops, and for each `scope=import`
/// dependency with [`ModelSource::import`]. An imported BOM's own parents
/// come through `parent` with [`ParentLookup::Import`], and its own imports
/// through `import` again: imports nest fewer than [`MAX_IMPORT_DEPTH`]
/// levels, and a BOM that imports itself, directly or not, fails the build. The
/// builder verifies that a returned POM declares the requested coordinates.
///
/// # Results and errors
///
/// `Ok(None)` means the source has no such POM, as when every repository
/// answers not found; [`ModelPolicy`] says what the build does then. Any
/// other failure, such as a refused request, a timeout or a checksum
/// mismatch, is an `Err` of the source's own type, which the build returns
/// unchanged. A model error the builder finds itself becomes
/// `Self::Error` through `From<PomError>`.
///
/// # Observation order
///
/// While building a [`Project`], [`ModelSource::observe_repositories`]
/// receives the repositories a POM declares before the builder asks for
/// that POM's parent, so a parent can come from a repository its child
/// declares: first the input POM's, then each parent's in turn. Each list
/// holds the POM's active profiles' repositories ahead of its own, as Maven
/// injects them, and leaves out URLs that still hold a `${...}` after the
/// POM's own properties are applied. Once the parent chain is merged, the
/// effective model's interpolated repositories go to
/// [`ModelSource::observe_effective_repositories`] before any import is
/// requested; Maven lets those replace an earlier repository with the same
/// id, where a lineage list only adds ids not seen yet.
///
/// An imported BOM is built between [`ModelSource::enter_import`] and
/// [`ModelSource::leave_import`], as Maven builds it with a copy of the
/// importer's model resolver: its own list, then its parents' lists, then
/// its effective repositories are observed in between, before its parents
/// and nested imports are requested. What is observed there serves that
/// BOM's lookups only, never the importer's later lookups or the
/// resolution. A reactor descriptor observes only the parents' lists. A
/// source applies its own trust policy to what it observes; an empty list is
/// not reported.
///
/// # Futures
///
/// The returned futures are `Send`, so a build can run on a multi-threaded
/// runtime, and borrow the source and the arguments.
pub trait ModelSource: Sync {
    /// The source's error, carried through the build unchanged.
    type Error: From<PomError> + std::error::Error + Send + Sync + 'static;

    /// Range-resolving sources set `parent`'s version to the selected one.
    fn parent(
        &self,
        parent: &mut Parent,
        lookup: ParentLookup,
    ) -> impl Future<Output = Result<Option<Pom>, Self::Error>> + Send;

    /// A `scope=import` BOM.
    fn import(
        &self,
        bom: ImportCoord<'_>,
    ) -> impl Future<Output = Result<Option<Pom>, Self::Error>> + Send;

    /// Repositories a POM of the build declares; see the observation order
    /// above. The default ignores them.
    fn observe_repositories(&self, _repositories: &[Repository]) {}

    /// The interpolated repositories of an effective model; see the
    /// observation order above. The default passes them to
    /// [`ModelSource::observe_repositories`].
    fn observe_effective_repositories(&self, repositories: &[Repository]) {
        self.observe_repositories(repositories);
    }

    /// The imports [`ModelSource::import`] is about to be asked for, in
    /// order, so the source can start fetching them. A hint only: each
    /// still comes through `import`, and the build may stop before it
    /// asks for all of them. The default does nothing.
    fn prefetch_imports(&self, _imports: &[ImportCoord<'_>]) {}

    /// The build of `bom`, a reactor module, activated these profile ids,
    /// one list per POM of its lineage, its own first. Maven builds an
    /// import without the project's profile ids or directory, so they can
    /// differ from those of the module's own build. The default ignores
    /// them.
    fn imported_reactor_profiles(&self, _bom: ImportCoord<'_>, _active_profiles: &[Vec<String>]) {}

    /// The build of an imported BOM starts. Calls nest, one per BOM being
    /// built. The default does nothing.
    fn enter_import(&self) {}

    /// The build of the BOM [`ModelSource::enter_import`] last started ends,
    /// whether it succeeded or not. The default does nothing.
    fn leave_import(&self) {}

    /// What `bom` contributed to an earlier build under `policy`, kept with
    /// [`ModelSource::keep_import`], that `usable` accepts, when this source
    /// would answer every lookup of that BOM's build as it did then. The
    /// builder then uses it instead of building the BOM again; `usable`
    /// refuses one whose build's activation inputs differ or which would
    /// fail to build again. The source is asked nothing else about the BOM,
    /// so one that records lookups must have recorded that build's. The
    /// default keeps nothing.
    fn reuse_import(
        &self,
        _bom: ImportCoord<'_>,
        _policy: ModelPolicy,
        _usable: &dyn Fn(&ImportedBom) -> bool,
    ) -> Option<Arc<ImportedBom>> {
        None
    }

    /// What holds the log of a model's BOM imports, so that a source can
    /// tell from [`crate::held::logged_since`] whether a BOM's build logged
    /// anything. The default holds nothing, and nothing then tells.
    fn import_holds(&self) -> Option<&crate::held::Holds> {
        None
    }

    /// The builder used what the last [`ModelSource::reuse_import`]
    /// returned. The default does nothing.
    fn reused_import(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// What `bom` contributes, from the build that the last
    /// [`ModelSource::leave_import`] ended. The default drops it.
    fn keep_import(
        &self,
        _bom: ImportCoord<'_>,
        _policy: ModelPolicy,
        _imported: Arc<ImportedBom>,
    ) {
    }
}

/// Which model a parent lookup is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParentLookup {
    /// A parent of the project being built. Maven 3.9 reads these before it
    /// indexes the reactor, so the source does not answer with a reactor
    /// module unless the `<relativePath>` names it.
    Project,
    /// A parent of an imported BOM or of one of its ancestors, which may be
    /// a reactor module.
    Import,
}

/// The coordinates of a `scope=import` dependency, as interpolated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ImportCoord<'a> {
    /// The BOM's `groupId`.
    pub group_id: &'a str,
    /// The BOM's `artifactId`.
    pub artifact_id: &'a str,
    /// The BOM's version.
    pub version: &'a str,
    /// The `<type>` as written; Maven requires `pom`.
    pub type_: Option<&'a str>,
    /// The `<classifier>`, interpolated.
    pub classifier: Option<&'a str>,
}

/// What a build does with a lookup the source has no answer for, and
/// whether its input is a project the user owns. Fixed for one build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ModelPolicy {
    /// The input POM is a project POM from the working tree. Its
    /// repositories are marked as declared by the user, and Maven's project
    /// validation, such as unique profile ids, applies to it.
    pub root: bool,
    /// What to do when the source has no POM for a `<parent>`.
    pub missing_parent: MissingParent,
}

impl ModelPolicy {
    /// A project build: a missing parent fails it.
    pub const PROJECT: Self = Self {
        root: true,
        missing_parent: MissingParent::Fail,
    };

    /// A dependency's model: a missing parent fails it.
    pub const DEPENDENCY: Self = Self {
        root: false,
        missing_parent: MissingParent::Fail,
    };
}

/// What a build does when the source has no POM for a `<parent>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MissingParent {
    /// Fail with [`PomError::ParentNotFound`], as Maven does, or with
    /// [`PomError::ParentExpression`] when the `<parent>` holds a `${...}`.
    Fail,
    /// Go on without inheritance, taking a missing `groupId` or `version`
    /// from the `<parent>` declaration. Reactor discovery uses this, since
    /// it reads local parents only and the full build checks the rest. A
    /// child that names no `groupId` or `version` either way, or a
    /// `<parent>` holding a `${...}`, still fails as with
    /// [`MissingParent::Fail`].
    InheritDeclaredCoordinates,
}

/// Drive a future that completes without waiting, such as one of a source
/// reading local files.
///
/// # Panics
///
/// When the future is not ready on its first poll. A source that waits on
/// I/O needs an executor instead.
pub fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("rv_maven_model::ready: the future is not ready"),
    }
}

/// Test doubles.
#[cfg(test)]
mod memory {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    type Gav = (String, String, String);

    /// A [`ModelSource`] over POMs held in memory, for tests and for models
    /// whose POMs are already read. It records every lookup and every
    /// observed repository list, in order.
    #[derive(Debug, Default)]
    pub(crate) struct MemorySource {
        parents: HashMap<Gav, Pom>,
        imports: HashMap<Gav, Pom>,
        failures: HashMap<Gav, String>,
        gates: HashMap<String, String>,
        log: Mutex<Vec<String>>,
        observed: Mutex<Vec<Vec<Repository>>>,
    }

    #[derive(Debug, thiserror::Error)]
    #[non_exhaustive]
    pub(crate) enum MemorySourceError {
        #[error("{coord}: {message}")]
        Lookup { coord: String, message: String },
        #[error(transparent)]
        Model(#[from] PomError),
    }

    impl MemorySource {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Serve `pom` for a `<parent>` with these coordinates.
        pub(crate) fn with_parent(
            mut self,
            group_id: &str,
            artifact_id: &str,
            version: &str,
            pom: Pom,
        ) -> Self {
            self.parents
                .insert(gav(group_id, artifact_id, version), pom);
            self
        }

        /// Serve `pom` for an import with these coordinates.
        pub(crate) fn with_import(
            mut self,
            group_id: &str,
            artifact_id: &str,
            version: &str,
            pom: Pom,
        ) -> Self {
            self.imports
                .insert(gav(group_id, artifact_id, version), pom);
            self
        }

        /// Fail every lookup of these coordinates with `message`.
        pub(crate) fn with_failure(
            mut self,
            group_id: &str,
            artifact_id: &str,
            version: &str,
            message: &str,
        ) -> Self {
            self.failures
                .insert(gav(group_id, artifact_id, version), message.to_string());
            self
        }

        /// Answer every lookup of `artifact_id` with none until a repository
        /// with `url` has been observed.
        pub(crate) fn with_gate(mut self, artifact_id: &str, url: &str) -> Self {
            self.gates.insert(artifact_id.to_string(), url.to_string());
            self
        }

        pub(crate) fn lookups(&self) -> Vec<String> {
            let events = self.events();
            let lookup =
                |event: &String| event.starts_with("parent ") || event.starts_with("import ");
            events.into_iter().filter(lookup).collect()
        }

        pub(crate) fn events(&self) -> Vec<String> {
            self.log
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn record(&self, event: String) {
            self.log
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event);
        }

        fn observe(&self, kind: &str, repositories: &[Repository]) {
            let urls: Vec<&str> = repositories.iter().map(|repo| repo.url.as_str()).collect();
            self.record(format!("{kind} {}", urls.join(",")));
            self.observed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(repositories.to_vec());
        }

        pub(crate) fn observed(&self) -> Vec<Vec<Repository>> {
            self.observed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn answer(
            &self,
            entry: String,
            key: Gav,
            poms: &HashMap<Gav, Pom>,
        ) -> Result<Option<Pom>, MemorySourceError> {
            self.record(entry);
            if let Some(message) = self.failures.get(&key) {
                return Err(MemorySourceError::Lookup {
                    coord: format!("{}:{}:{}", key.0, key.1, key.2),
                    message: message.clone(),
                });
            }
            if let Some(url) = self.gates.get(&key.1) {
                let observed = self.observed();
                if !observed.iter().flatten().any(|repo| &repo.url == url) {
                    return Ok(None);
                }
            }
            Ok(poms.get(&key).cloned())
        }
    }

    fn gav(group_id: &str, artifact_id: &str, version: &str) -> Gav {
        (
            group_id.to_string(),
            artifact_id.to_string(),
            version.to_string(),
        )
    }

    impl ModelSource for MemorySource {
        type Error = MemorySourceError;

        fn parent(
            &self,
            parent: &mut Parent,
            lookup: ParentLookup,
        ) -> impl Future<Output = Result<Option<Pom>, Self::Error>> + Send {
            let entry = format!(
                "parent {}:{}:{} ({lookup:?})",
                parent.group_id, parent.artifact_id, parent.version
            );
            let key = gav(&parent.group_id, &parent.artifact_id, &parent.version);
            std::future::ready(self.answer(entry, key, &self.parents))
        }

        fn import(
            &self,
            bom: ImportCoord<'_>,
        ) -> impl Future<Output = Result<Option<Pom>, Self::Error>> + Send {
            let entry = format!(
                "import {}:{}:{}",
                bom.group_id, bom.artifact_id, bom.version
            );
            let key = gav(bom.group_id, bom.artifact_id, bom.version);
            std::future::ready(self.answer(entry, key, &self.imports))
        }

        fn observe_repositories(&self, repositories: &[Repository]) {
            self.observe("observe", repositories);
        }

        fn observe_effective_repositories(&self, repositories: &[Repository]) {
            self.observe("effective", repositories);
        }

        fn prefetch_imports(&self, imports: &[ImportCoord<'_>]) {
            let coords: Vec<String> = imports
                .iter()
                .map(|bom| format!("{}:{}:{}", bom.group_id, bom.artifact_id, bom.version))
                .collect();
            self.record(format!("prefetch {}", coords.join(" ")));
        }

        fn enter_import(&self) {
            self.record("enter".to_string());
        }

        fn leave_import(&self) {
            self.record("leave".to_string());
        }
    }
}

#[cfg(test)]
pub(crate) use memory::{MemorySource, MemorySourceError};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActivationContext, Project};

    fn pom(xml: &str) -> Pom {
        Pom::parse(xml).unwrap()
    }

    fn assert_send<T: Send>(_: &T) {}

    fn source() -> MemorySource {
        MemorySource::new()
            .with_parent(
                "g",
                "parent",
                "1",
                pom(r"<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>
                  <repositories><repository><id>parent-repo</id><url>https://parent.example/</url></repository></repositories>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>g</groupId><artifactId>outer</artifactId><version>1</version>
                      <type>pom</type><scope>import</scope></dependency>
                  </dependencies></dependencyManagement></project>"),
            )
            .with_import(
                "g",
                "outer",
                "1",
                pom(r"<project><groupId>g</groupId><artifactId>outer</artifactId><version>1</version>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>g</groupId><artifactId>inner</artifactId><version>1</version>
                      <type>pom</type><scope>import</scope></dependency>
                  </dependencies></dependencyManagement></project>"),
            )
            .with_import(
                "g",
                "inner",
                "1",
                pom(r"<project><groupId>g</groupId><artifactId>inner</artifactId><version>1</version>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>g</groupId><artifactId>lib</artifactId><version>3</version></dependency>
                  </dependencies></dependencyManagement></project>"),
            )
    }

    const CHILD: &str = r"<project>
      <parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version><relativePath/></parent>
      <artifactId>app</artifactId>
      <repositories><repository><id>child-repo</id><url>https://child.example/</url></repository></repositories>
      <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId></dependency></dependencies>
    </project>";

    #[test]
    fn builds_a_model_through_parents_and_nested_imports() {
        let source = source();
        let mut parent = Parent {
            group_id: "g".into(),
            artifact_id: "parent".into(),
            version: "1".into(),
            relative_path: None,
        };
        let future = source.parent(&mut parent, ParentLookup::Project);
        assert_send(&future);
        assert!(ready(future).unwrap().is_some());

        let project = ready(Project::build(
            pom(CHILD),
            &source,
            ModelPolicy::PROJECT,
            &ActivationContext::default(),
        ))
        .unwrap();
        assert_eq!(project.dependencies[0].version.as_deref(), Some("3"));
        assert_eq!(
            source.lookups(),
            [
                "parent g:parent:1 (Project)",
                "parent g:parent:1 (Project)",
                "import g:outer:1",
                "import g:inner:1"
            ]
        );
        let observed: Vec<Vec<Option<String>>> = source
            .observed()
            .into_iter()
            .map(|list| list.into_iter().map(|repo| repo.id).collect())
            .collect();
        // The child's repositories before its parent is asked for, the
        // parent's before the next hop, then the effective list.
        assert_eq!(
            observed[..2],
            [
                vec![Some("child-repo".to_string())],
                vec![Some("parent-repo".to_string())]
            ]
        );
        assert_eq!(
            observed.last().unwrap(),
            &[
                Some("child-repo".to_string()),
                Some("parent-repo".to_string())
            ]
        );
    }

    #[test]
    fn a_source_error_comes_back_as_raised() {
        let source = source().with_failure("g", "inner", "1", "refused");
        let error = ready(Project::build(
            pom(CHILD),
            &source,
            ModelPolicy::PROJECT,
            &ActivationContext::default(),
        ))
        .unwrap_err();
        assert!(
            matches!(&error, MemorySourceError::Lookup { coord, message }
                if coord == "g:inner:1" && message == "refused"),
            "{error:?}"
        );
    }

    #[test]
    fn imports_nest_only_to_the_limit() {
        // A chain of `levels` BOMs where the last one imports nothing.
        let chain = |levels: usize| {
            let mut source = MemorySource::new();
            for level in 1..=levels {
                let import = if level < levels {
                    format!(
                        "<dependencyManagement><dependencies><dependency><groupId>g</groupId>\
                         <artifactId>bom{}</artifactId><version>1</version><type>pom</type>\
                         <scope>import</scope></dependency></dependencies></dependencyManagement>",
                        level + 1
                    )
                } else {
                    String::new()
                };
                source = source.with_import(
                    "g",
                    &format!("bom{level}"),
                    "1",
                    pom(&format!(
                        "<project><groupId>g</groupId><artifactId>bom{level}</artifactId>\
                         <version>1</version>{import}</project>"
                    )),
                );
            }
            source
        };
        let root = || {
            pom(
                r"<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>
              <dependencyManagement><dependencies>
                <dependency><groupId>g</groupId><artifactId>bom1</artifactId><version>1</version>
                  <type>pom</type><scope>import</scope></dependency>
              </dependencies></dependencyManagement></project>",
            )
        };

        let deepest = chain(MAX_IMPORT_DEPTH - 1);
        ready(Project::build(
            root(),
            &deepest,
            ModelPolicy::PROJECT,
            &ActivationContext::default(),
        ))
        .unwrap();

        let too_deep = chain(MAX_IMPORT_DEPTH);
        let error = ready(Project::build(
            root(),
            &too_deep,
            ModelPolicy::PROJECT,
            &ActivationContext::default(),
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains("BOM nesting too deep"),
            "{error}"
        );
        assert_eq!(too_deep.lookups().len(), MAX_IMPORT_DEPTH);
    }
}
