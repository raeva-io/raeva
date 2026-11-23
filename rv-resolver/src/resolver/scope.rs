//! The model source one effective-model build reads its parents and
//! imported BOMs from.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use rv_maven_model::{
    ImportCoord, ImportedBom, ModelPolicy, ModelSource, Parent, ParentLookup, Pom, PomError,
    Project, Provenance, parent_has_expression,
};
use rv_maven_types::{Coord, MavenMode, Version, VersionReq};

use crate::context::{MissingParentKey, RepoContext};
use crate::error::ResolveError;
use crate::parent_resolver::LocalParents;
use crate::solver::Backend;
use crate::util::lock;

use super::ModelService;
use super::backend::{
    ModelCache, ModelKey, ModelTag, PomGav, RangeListing, SupportPom, pom_gav, repo_key,
};
use super::model_list::{self, Added, Entry, ModelBuild, Reach};
use super::reactor_models::{Flight, KeptImports};

/// Whether the POM's `<repositories>` bypass the security gate. Root POMs
/// are user-authored and always trusted; transitive POMs go through
/// `ModelService::extend_repos` (which honours `allow_transitive_repositories`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RepoTrust {
    Root,
    Transitive,
}

/// One build's view of the backend: its trust and the local parents it may
/// read.
///
/// A parent is read from its `<relativePath>` when `local` accepts it. A
/// project's own parents come next from the repositories, since Maven 3.9
/// reads them before it indexes the reactor; any other parent, and every
/// imported BOM, comes from a reactor module with those coordinates before
/// the repositories. A coordinate no repository serves is remembered as
/// missing for the rest of the resolution.
pub(super) struct ModelScope<'a> {
    backend: &'a ModelService,
    trust: RepoTrust,
    local: LocalParents,
    /// Admitted transitive repositories inherited along the dependency path.
    repo_ctx: RepoContext,
    /// The admitted repositories a transitive build has declared so far.
    /// Maven searches them for that build's parents and imports only; the
    /// resolution sees a POM's repositories once its model is valid.
    build_repos: Mutex<BuildRepos>,
    /// One list per imported BOM being built, innermost last: the admitted
    /// repositories its lineage declares. They serve that BOM's parents and
    /// nested imports only, as Maven's copy of the model resolver does.
    import_repos: Mutex<Vec<BuildRepos>>,
    /// The mirror routes of the build's repositories as written, then of
    /// each imported BOM's build, innermost last.
    routes: Mutex<Vec<Routes>>,
    /// One entry per imported BOM being built, innermost last: the context
    /// it started in and the local parent lookups its build made.
    import_builds: Mutex<Vec<ImportBuild>>,
    left_import: Mutex<Option<ImportBuild>>,
    /// The support POMs the build read, those of the imported BOMs it
    /// built or reused included, in reading order.
    reads: Mutex<Reads>,
    /// Where the BOM [`ModelSource::import`] last read starts in the reads
    /// of the innermost build.
    import_start: Mutex<usize>,
    /// The BOM [`ModelSource::cached_import`] or
    /// [`ModelSource::reuse_import`] last returned, and its coordinates.
    offered: Mutex<Option<(PomGav, Arc<KeptImport>)>>,
    /// Whether the BOM [`ModelSource::import`] last read came from Maven's
    /// model cache, for the build [`ModelSource::enter_import`] starts.
    import_borrowed: Mutex<bool>,
    /// The import builds this scope claimed; see `ModelScope::reuse_import`.
    claims: Claims,
}

/// The import builds a scope claimed in [`KeptImports`], by key, with the
/// depth of the build that imports each, outermost first. All land when
/// the scope is dropped, as when a failed or cancelled build drops it.
struct Claims {
    imports: Arc<KeptImports>,
    owner: usize,
    held: Mutex<Vec<(String, usize)>>,
}

impl Claims {
    fn new(imports: &Arc<KeptImports>) -> Self {
        static OWNERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        Self {
            imports: Arc::clone(imports),
            owner: OWNERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            held: Mutex::default(),
        }
    }

    /// Land the claims of the builds at `depth` or deeper, which have
    /// ended once the scope asks about another import at `depth`.
    fn land_from(&self, depth: usize) {
        let mut held = lock(&self.held);
        while let Some((key, _)) = held.pop_if(|(_, at)| *at >= depth) {
            self.imports.land(&key, self.owner);
        }
    }
}

impl Drop for Claims {
    fn drop(&mut self) {
        self.land_from(0);
    }
}

/// The local parent lookups a build made, each once however many nested
/// builds made it.
type LocalLookups = HashMap<Parent, Option<Pom>>;

/// Support POMs in reading order, each once. A build keeps its own list and
/// hands it to the build around it when it ends: one flat list with a start
/// per build either listed a POM once per import path, which grows
/// exponentially with the depth of shared imports, or left out of a kept
/// BOM's list what a build around it had read first.
#[derive(Default)]
struct Reads {
    poms: Vec<Arc<SupportPom>>,
    held: HashSet<usize>,
    /// See [`ModelScope::borrowed`].
    borrowed: bool,
}

impl Reads {
    fn add(&mut self, poms: impl IntoIterator<Item = Arc<SupportPom>>) {
        for pom in poms {
            if self.held.insert(Arc::as_ptr(&pom).addr()) {
                self.poms.push(pom);
            }
        }
    }
}

/// What an imported BOM's build depended on beyond its coordinates.
struct ImportBuild {
    context: String,
    /// The local parent lookups the build made, including those of nested
    /// BOMs, built or reused.
    local_lookups: LocalLookups,
    /// The BOM's own POM and those its build read.
    reads: Reads,
    /// Where the build's log starts; see [`rv_maven_model::held::mark`].
    logged_from: Option<usize>,
    /// Whether a nested BOM the build reused had logged anything.
    logged: bool,
    /// Where the build's own reads start in `reads`, after the BOM's POM.
    own_from: usize,
    /// Each support POM the build and its nested imports read, by
    /// `g:a:v`, with each repository an imported BOM declared that the
    /// read searched.
    searched: Vec<(String, rv_repo::Repository)>,
}

/// What a resolution keeps of an imported BOM: its contribution, the
/// local parent lookups its build made, which a build that reuses it must
/// find answered alike, and the support POMs it read.
pub(super) struct KeptImport {
    imported: Arc<ImportedBom>,
    local_lookups: LocalLookups,
    support_poms: Vec<Arc<SupportPom>>,
    /// Whether the build, or a nested build it reused, logged anything.
    pub(super) logged: bool,
    /// See [`ImportBuild::searched`].
    searched: Vec<(String, rv_repo::Repository)>,
}

impl<'a> ModelScope<'a> {
    pub(super) fn root(backend: &'a ModelService, local: LocalParents) -> Self {
        Self::with_trust(backend, local, RepoTrust::Root)
    }

    /// The scope of a POM read from a repository: only the local parents
    /// of reactor modules in its lineage, and its `<repositories>` go
    /// through the transitive-repository policy.
    pub(super) fn transitive(backend: &'a ModelService, repo_ctx: RepoContext) -> Self {
        let mut scope = Self::with_trust(backend, backend.reactor_parents(), RepoTrust::Transitive);
        scope.repo_ctx = repo_ctx;
        scope
    }

    pub(super) fn with_trust(
        backend: &'a ModelService,
        local: LocalParents,
        trust: RepoTrust,
    ) -> Self {
        Self {
            backend,
            trust,
            local,
            repo_ctx: RepoContext::default(),
            build_repos: Mutex::default(),
            import_repos: Mutex::default(),
            routes: Mutex::new(vec![Routes::default()]),
            import_builds: Mutex::default(),
            left_import: Mutex::default(),
            reads: Mutex::default(),
            import_start: Mutex::default(),
            offered: Mutex::default(),
            import_borrowed: Mutex::default(),
            claims: Claims::new(&backend.kept_imports),
        }
    }

    pub(super) fn into_reads(self) -> Vec<Arc<SupportPom>> {
        self.reads
            .into_inner()
            .unwrap_or_else(|e| e.into_inner())
            .poms
    }

    /// Add `poms` to the reads of the innermost build, or of the scope.
    fn add_reads(&self, poms: impl IntoIterator<Item = Arc<SupportPom>>) {
        match lock(&self.import_builds).last_mut() {
            Some(build) => build.reads.add(poms),
            None => lock(&self.reads).add(poms),
        }
    }

    fn policy(&self) -> ModelPolicy {
        match self.trust {
            RepoTrust::Root => ModelPolicy::PROJECT,
            RepoTrust::Transitive => ModelPolicy::DEPENDENCY,
        }
    }

    pub(super) async fn project(
        &self,
        pom: Pom,
        ctx: &rv_maven_model::ActivationContext,
    ) -> Result<Project, ResolveError> {
        Project::build(pom, self, self.policy(), ctx).await
    }

    /// A reactor module with `coord`'s effective coordinates, else the
    /// repositories. `inherited` is a parent an imported BOM names: a
    /// module's record omits the properties its own declarations do not
    /// read, which the BOM can.
    async fn fetch_with_workspace(
        &self,
        coord: Coord,
        inherited: bool,
        model: Option<ModelKey>,
    ) -> Result<Option<Pom>, ResolveError> {
        let reactor_side = self.trust == RepoTrust::Root;
        if let Some(pom) = self.backend.workspace_pom_for_coord(&coord, reactor_side) {
            if inherited || !reactor_side {
                self.backend.ctx.note_reactor_through_dependencies();
            }
            return Ok(Some(pom));
        }
        self.fetch_remote(coord, false, model).await
    }

    /// `coord`'s POM from the repositories, else from Maven's model cache
    /// under `model`. A parent of the project keeps its plugin sections,
    /// which a project build checks.
    async fn fetch_remote(
        &self,
        coord: Coord,
        project_parent: bool,
        model: Option<ModelKey>,
    ) -> Result<Option<Pom>, ResolveError> {
        let build = self.model_build();
        let entries = self.backend.model_entries(&self.repo_ctx, &build);
        let search = model_list::search(&entries, coord.version.as_str());
        let searched = search.before;
        if let Some(unread) = search.unread {
            let fetched =
                (self.before_unread(&coord, model, searched, unread, search.central)).await?;
            if let Some(refusal) = self.mirrored_import_refusal(&fetched) {
                return Err(refusal);
            }
            self.backend.learn_models(std::slice::from_ref(&fetched));
            return self
                .parse_fetched(&coord, fetched, project_parent)
                .map(Some);
        }
        let ctx = &self.backend.ctx;
        let search_ctx = self.backend.parent_search_context(&self.repo_ctx, &build);
        let missing_key = missing_key(&coord, &search_ctx);
        let mut failed = None;
        let fetched = if ctx.is_parent_missing(&missing_key) {
            tracing::debug!(
                group_id = %coord.group_id,
                artifact_id = %coord.artifact_id,
                version = %coord.version,
                "Parent POM known to be missing (cached)"
            );
            None
        } else {
            match self
                .backend
                .fetch_pom_bytes_from(&coord, searched, model.clone())
                .await
            {
                Ok(fetched) => Some(fetched),
                Err(ResolveError::ArtifactNotFound { searched, .. }) => {
                    ctx.mark_parent_missing(missing_key, searched);
                    tracing::debug!(
                        group_id = %coord.group_id,
                        artifact_id = %coord.artifact_id,
                        version = %coord.version,
                        "Parent POM not found, caching as missing"
                    );
                    None
                }
                // Maven looks in its model cache before it fetches.
                Err(error) => {
                    failed = Some(error);
                    None
                }
            }
        };
        let fetched = match fetched {
            Some(fetched) => {
                if let Some(refusal) = self.mirrored_import_refusal(&fetched) {
                    return Err(refusal);
                }
                self.backend.learn_models(std::slice::from_ref(&fetched));
                fetched
            }
            None => {
                let cached = match &model {
                    Some(key) => self.cached(key).await,
                    None => None,
                };
                let Some(fetched) = cached else {
                    return failed.map_or(Ok(None), Err);
                };
                self.note_borrowed();
                self.backend
                    .record_support_poms(std::slice::from_ref(&fetched))
                    .await?;
                fetched
            }
        };
        self.parse_fetched(&coord, fetched, project_parent)
            .map(Some)
    }

    /// Whether the build took a POM from Maven's model cache that its own
    /// repositories lack: what it built then depends on what this module
    /// read before.
    pub(super) fn borrowed(&self) -> bool {
        lock(&self.reads).borrowed
    }

    async fn cached(&self, key: &ModelKey) -> Option<Arc<SupportPom>> {
        let own = lock(&self.backend.read_models).poms.get(key).cloned();
        match own {
            Some(pom) => Some(pom),
            None => {
                self.session_model(|models| models.poms.get(key).cloned())
                    .await
            }
        }
    }

    /// What the reactor's model cache gives `find`. Another module may wait
    /// for an import build this scope claimed while this one waits for it.
    async fn session_model<T>(&self, find: impl Fn(&ModelCache) -> Option<T>) -> Option<T> {
        self.claims.land_from(0);
        self.backend.session_model(find).await
    }

    /// Keeps what this build makes, which depends on what the module read
    /// before, with the module.
    fn note_borrowed(&self) {
        for build in lock(&self.import_builds).iter_mut() {
            build.reads.borrowed = true;
        }
        lock(&self.reads).borrowed = true;
        *lock(&self.import_borrowed) = true;
    }
}

impl ModelScope<'_> {
    fn parse_fetched(
        &self,
        coord: &Coord,
        fetched: Arc<SupportPom>,
        project_parent: bool,
    ) -> Result<Pom, ResolveError> {
        let unparseable = |source: PomError| match source {
            _ if source.is_malformed_xml() => PomError::UnparseablePom {
                coord: coord.to_string(),
                source: Box::new(source),
            },
            PomError::UnsupportedEncoding(_) | PomError::Ebcdic(_) => source,
            _ => PomError::InvalidModel(format!("{coord}: {source}")),
        };
        let parsed_poms = self.backend.ctx.parsed_poms();
        let parsed = match project_parent {
            true => parsed_poms.parse_project(&fetched.blob, &fetched.bytes),
            false => parsed_poms.parse(&fetched.blob, &fetched.bytes),
        };
        let mut pom = parsed.map(Arc::unwrap_or_clone).map_err(unparseable)?;
        without_local_parent(&mut pom);
        self.add_reads([fetched]);
        Ok(pom)
    }

    /// Everything this scope's answers for an import's lookups depend on
    /// besides the import and the local parents: the trust its
    /// repositories get and the repositories it searches.
    fn import_context(&self) -> String {
        format!(
            "{:?}\n{:?}\n{:?}\n{:?}\n{:?}",
            self.trust,
            self.backend.root_repos_snapshot(),
            self.backend.root_repo_ids_snapshot(),
            self.repo_ctx.as_slice(),
            self.model_build()
        )
    }

    fn import_key(bom: ImportCoord<'_>, policy: ModelPolicy, context: &str) -> String {
        format!(
            "{}\n{}\n{}\n{:?}\n{:?}\n{policy:?}\n{context}",
            bom.group_id, bom.artifact_id, bom.version, bom.type_, bom.classifier
        )
    }

    /// The local parent at `parent`'s `<relativePath>`, recorded for the
    /// imported BOMs being built.
    fn load_local(&self, parent: &Parent) -> Option<Pom> {
        let found = self.local.load(parent);
        let mut builds = lock(&self.import_builds);
        if let Some(build) = builds.last_mut() {
            build.local_lookups.insert(parent.clone(), found.clone());
        }
        found
    }

    /// The coordinates of the highest version in `range` of `parent`, which
    /// Maven requires to have an upper bound. As in Maven, a project model's
    /// range sees the repositories only, since the reactor is not known yet,
    /// and a range of one version names it without a version list.
    /// The parent `range` takes, and what the repositories listed for it,
    /// unless the range names a single version, which reads no list.
    async fn range_coord(
        &self,
        parent: &Parent,
        range: &VersionReq,
    ) -> Result<(Coord, Option<RangeListing>), ResolveError> {
        let coord = |version| Coord {
            group_id: parent.group_id.clone().into(),
            artifact_id: parent.artifact_id.clone().into(),
            version,
            packaging: Some("pom".to_string()),
            classifier: None,
        };
        if let Some(version) = range.exact_version_in(self.backend.mode()) {
            return Ok((coord(version.clone()), None));
        }
        let not_found = || {
            let ctx = &self.backend.ctx;
            let (group, artifact) = (&parent.group_id, &parent.artifact_id);
            if let Some(searched) = ctx.listing_miss(group, artifact) {
                ctx.note_model_miss((group, artifact, &parent.version), searched);
            }
            PomError::ParentNotFound(
                parent.group_id.clone(),
                parent.artifact_id.clone(),
                parent.version.clone(),
            )
        };
        let unbounded = |range: &rv_maven_types::VersionRange| {
            let text = range.to_string();
            text.ends_with(",)") || text.ends_with(",]")
        };
        if let VersionReq::Ranges(ranges) = range
            && ranges.iter().any(unbounded)
        {
            return Err(PomError::UnboundedParentRange(
                parent.group_id.clone(),
                parent.artifact_id.clone(),
                parent.version.clone(),
            )
            .into());
        }
        // Maven lists the versions in every repository it searches, so one
        // raeva does not read ahead of one it reads may list another.
        let entries = (self.backend).model_entries(&self.repo_ctx, &self.model_build());
        if let Some(unread) = (["1", "1-SNAPSHOT"].into_iter())
            .find_map(|version| model_list::search(&entries, version).unread)
        {
            let (group, artifact) = (&parent.group_id, &parent.artifact_id);
            let pom = format!("{group}:{artifact}:{}", parent.version);
            return Err(self.unread_refusal(pom, unread));
        }
        let (version, listing) = self
            .backend
            .parent_range_version(
                &parent.group_id,
                &parent.artifact_id,
                range,
                &self.repo_ctx,
                &self.model_build(),
                self.trust == RepoTrust::Transitive,
            )
            .await?;
        let version = version.ok_or_else(not_found)?;
        Ok((coord(version), Some(listing)))
    }

    /// The declarations this build's model resolvers were handed: the
    /// build's own, then each imported BOM's being built.
    fn model_build(&self) -> ModelBuild {
        let mut added = lock(&self.build_repos).added.clone();
        added.extend((lock(&self.import_repos).iter()).flat_map(|list| list.added.iter().cloned()));
        ModelBuild {
            project: self.trust == RepoTrust::Root,
            added,
        }
    }

    /// Mark the innermost build's lineage read: Maven reads its imports
    /// through its effective model's repositories, which end with the super
    /// POM's `central`. A project's own are the root list's.
    fn end_lineage(&self) {
        match lock(&self.import_repos).last_mut() {
            Some(list) => list.effective(),
            None if self.trust == RepoTrust::Transitive => lock(&self.build_repos).effective(),
            None => {}
        }
    }
}

fn missing_key(coord: &Coord, repos: &RepoContext) -> MissingParentKey {
    (
        Arc::from(coord.group_id.as_str()),
        Arc::from(coord.artifact_id.as_str()),
        Arc::from(coord.version.as_str()),
        repos.clone(),
    )
}

fn parse_model_coord(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    packaging: Option<String>,
    classifier: Option<String>,
) -> Result<Coord, PomError> {
    let version = Version::parse(version).map_err(|err| PomError::InvalidModel(err.to_string()))?;
    Ok(Coord {
        group_id: group_id.into(),
        artifact_id: artifact_id.into(),
        version,
        packaging,
        classifier,
    })
}

pub(crate) fn parent_coord(parent: &Parent) -> Result<Coord, PomError> {
    parse_model_coord(
        &parent.group_id,
        &parent.artifact_id,
        &parent.version,
        Some("pom".to_string()),
        None,
    )
}

/// The key of a build of the import `key` under way: `key` and the
/// importer's properties, as a build for an importer with others would not
/// fit; see [`ModelSource::reuse_import`].
fn flight_key(key: &str, importer: &rv_maven_model::ActivationContext) -> String {
    let mut properties: Vec<_> = importer.properties.iter().collect();
    properties.sort_unstable();
    let mut system_properties: Vec<_> = importer.system_properties.iter().collect();
    system_properties.sort_unstable();
    format!("{key}\n{properties:?}\n{system_properties:?}")
}

/// Make `kept` the last of `builds`. A build that logged is dropped once
/// another is last, as only the last is reused whatever it logged.
fn keep_last(builds: &mut Vec<Arc<KeptImport>>, kept: Arc<KeptImport>) {
    builds.retain(|other| !other.logged);
    builds.push(kept);
}

/// The coordinates Maven's model cache keys `bom` by.
fn bom_gav(bom: ImportCoord<'_>) -> PomGav {
    (
        bom.group_id.to_string(),
        bom.artifact_id.to_string(),
        bom.version.to_string(),
    )
}

fn import_coord(bom: ImportCoord<'_>) -> Result<Coord, PomError> {
    parse_model_coord(
        bom.group_id,
        bom.artifact_id,
        bom.version,
        bom.type_
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        bom.classifier
            .filter(|value| !value.is_empty())
            .map(str::to_string),
    )
}

impl ModelSource for ModelScope<'_> {
    type Error = ResolveError;

    async fn parent(
        &self,
        parent: &mut Parent,
        lookup: ParentLookup,
    ) -> Result<Option<Pom>, ResolveError> {
        // Maven reads a POM from a repository, and so its parents' paths,
        // leniently.
        if (self.trust, lookup) == (RepoTrust::Root, ParentLookup::Project) {
            (self.local.check_strictly(parent, false))
                .map_err(|(path, source)| ResolveError::LocalPom { path, source })?;
        }
        if let Some(mut pom) = self.load_local(parent) {
            if self.trust == RepoTrust::Root {
                pom.mark_root_repositories();
            }
            return Ok(Some(pom));
        }
        if parent_has_expression(parent) {
            // Maven fetches these unexpanded text, which names no artifact;
            // the model layer reports why.
            return Ok(None);
        }
        let named = (
            parent.group_id.clone(),
            parent.artifact_id.clone(),
            parent.version.clone(),
        );
        let declared = parent.version.clone();
        let range = rv_maven_model::parent_version_range(parent, self.backend.mode());
        let ranged = range.is_some();
        let (coord, model) = match range {
            // Maven caches a ranged parent by the range text and looks there
            // before it resolves the range: the version this module read
            // first under it stays.
            Some(range) => {
                let key = (named, ModelTag::Parent);
                self.note_borrowed();
                let own = lock(&self.backend.read_models).range_version(&key);
                let cached = match own {
                    Some(version) => Some(version),
                    None => {
                        let version =
                            (self.session_model(|models| models.range_version(&key))).await;
                        // The list the session's read saw, which the lock
                        // records for this module too.
                        let listing = (self
                            .session_model(|models| models.range_listings.get(&key.0).cloned()))
                        .await;
                        if let Some(listing) = listing.filter(|_| version.is_some()) {
                            (lock(&self.backend.read_models).range_listings)
                                .entry(key.0.clone())
                                .or_insert(listing);
                        }
                        version
                    }
                };
                let coord = match cached {
                    Some(version) => {
                        parent.version = version;
                        parent_coord(parent)?
                    }
                    None => {
                        let (coord, listing) = self.range_coord(parent, &range).await?;
                        if let Some(listing) = listing {
                            (lock(&self.backend.read_models).range_listings)
                                .entry(key.0.clone())
                                .or_insert_with(|| Arc::new(listing));
                        }
                        parent.version = coord.version.to_string();
                        let workspace =
                            lookup == ParentLookup::Import || self.trust == RepoTrust::Transitive;
                        if workspace && self.backend.workspace_module_for_coord(&coord).is_some() {
                            (lock(&self.backend.read_models).reactor_ranges)
                                .entry(key.0.clone())
                                .or_insert_with(|| parent.version.clone());
                        }
                        coord
                    }
                };
                (coord, Some(key))
            }
            None => (parent_coord(parent)?, Some((named, ModelTag::Parent))),
        };
        let mirrored = lock(&self.routes).last().is_some_and(Routes::mirrored);
        let from_workspace = (self.trust, lookup) != (RepoTrust::Root, ParentLookup::Project)
            && self.backend.workspace_module_for_coord(&coord).is_some();
        if mirrored && !from_workspace {
            let ahead = match ranged {
                true => None,
                false => (self.ahead_of_kept_mirrors(&coord, model.clone(), false)).await?,
            };
            let provenance = match lookup {
                ParentLookup::Project => Provenance::Dependency,
                ParentLookup::Import => Provenance::BomImport,
            };
            if let Some(pom) = ahead {
                return Ok(fetched_from_repository(Some(pom), provenance));
            }
            if let Some(routes) = lock(&self.routes).last_mut() {
                routes.consult();
            }
        }
        let looked_up = coord.version.to_string();
        let (pom, provenance) = match (self.trust, lookup) {
            (RepoTrust::Root, ParentLookup::Project) => (
                self.fetch_remote(coord, true, model).await?,
                Provenance::RemoteParentOfRoot,
            ),
            (RepoTrust::Transitive, ParentLookup::Project) => {
                let pom = self.fetch_with_workspace(coord, false, model).await?;
                if pom.is_none()
                    && !from_workspace
                    && let Some(error) = (lock(&self.routes).last()).and_then(|routes| {
                        routes.parent_behind_mirror(
                            &self.backend.ctx.config,
                            format!("{}:{}:{declared}", parent.group_id, parent.artifact_id),
                        )
                    })
                {
                    return Err(error);
                }
                (pom, Provenance::Dependency)
            }
            (_, ParentLookup::Import) => (
                self.fetch_with_workspace(coord, true, model).await?,
                Provenance::BomImport,
            ),
        };
        // The error names the parent by the range it declares.
        if pom.is_none() && looked_up != declared {
            let ctx = &self.backend.ctx;
            let (group, artifact) = (&parent.group_id, &parent.artifact_id);
            if let Some(searched) = ctx.model_miss((group, artifact, &looked_up)) {
                ctx.note_model_miss((group, artifact, &declared), searched);
            }
        }
        Ok(fetched_from_repository(pom, provenance))
    }

    async fn import(&self, bom: ImportCoord<'_>) -> Result<Option<Pom>, ResolveError> {
        self.backend.lineage_read();
        self.end_lineage();
        let coord = import_coord(bom)?;
        *lock(&self.import_borrowed) = false;
        *lock(&self.import_start) = match lock(&self.import_builds).last() {
            Some(build) => build.reads.poms.len(),
            None => lock(&self.reads).poms.len(),
        };
        // Maven's workspace reader answers before any repository.
        if let Some(refusal) = self.split_route_refusal()
            && self.backend.workspace_module_for_coord(&coord).is_none()
        {
            let model = Some((pom_gav(&coord), ModelTag::Import));
            return match self.ahead_of_kept_mirrors(&coord, model, true).await? {
                Some(pom) => Ok(fetched_from_repository(Some(pom), Provenance::BomImport)),
                None => Err(refusal),
            };
        }
        Ok(fetched_from_repository(
            self.fetch_with_workspace(
                coord.clone(),
                false,
                Some((pom_gav(&coord), ModelTag::Import)),
            )
            .await?,
            Provenance::BomImport,
        ))
    }

    fn imported_reactor_profiles(&self, bom: ImportCoord<'_>, active_profiles: &[Vec<String>]) {
        // The module's record covers what its own build's profiles left, so
        // a local POM that activates other profiles in the import brings
        // declarations the record misses. Every active id counts, as which
        // ones resolution reads differs between the builds. POMs past the
        // local ones are pinned.
        let module = import_coord(bom)
            .ok()
            .and_then(|coord| self.backend.workspace_module_for_coord(&coord));
        if module.is_none_or(|module| {
            let own = module.descriptor.selected_profiles();
            own.len() > active_profiles.len()
                || own
                    .iter()
                    .zip(active_profiles)
                    .any(|(own, imported)| own != imported)
        }) {
            self.backend.ctx.note_reactor_through_dependencies();
        }
    }

    fn observe_repositories(&self, repositories: &[rv_maven_model::Repository]) {
        // Only an interpolated declaration is refused.
        let _ = self.observe(repositories, false);
    }

    fn observe_effective_repositories(
        &self,
        repositories: &[rv_maven_model::Repository],
    ) -> Result<(), ResolveError> {
        self.observe(repositories, true)
    }

    fn prefetch_imports(&self, imports: &[ImportCoord<'_>]) {
        self.end_lineage();
        let build = self.model_build();
        let search_ctx = self.backend.parent_search_context(&self.repo_ctx, &build);
        for bom in imports {
            let Ok(coord) = import_coord(*bom) else {
                continue;
            };
            if !self
                .backend
                .ctx
                .is_parent_missing(&missing_key(&coord, &search_ctx))
            {
                self.backend
                    .prefetch_pom(&coord, &self.repo_ctx, Some(&build), false);
            }
        }
    }

    fn enter_import(&self) {
        let context = self.import_context();
        let start = *lock(&self.import_start);
        let mut builds = lock(&self.import_builds);
        let mut reads = Reads {
            borrowed: std::mem::take(&mut *lock(&self.import_borrowed)),
            ..Reads::default()
        };
        match builds.last() {
            Some(outer) => reads.add(outer.reads.poms[start..].iter().cloned()),
            None => reads.add(lock(&self.reads).poms[start..].iter().cloned()),
        }
        let own_from = reads.poms.len();
        builds.push(ImportBuild {
            context,
            local_lookups: LocalLookups::new(),
            reads,
            logged_from: rv_maven_model::held::mark(),
            logged: false,
            own_from,
            searched: Vec::new(),
        });
        lock(&self.import_repos).push(BuildRepos::default());
        // The build's model resolver is a copy of the importer's, which has
        // reserved the importer's ids.
        let mut routes = lock(&self.routes);
        let written = (routes.last().into_iter())
            .flat_map(|outer| outer.written.keys().map(|id| (id.clone(), None)))
            .collect();
        routes.push(Routes {
            written,
            ..Routes::default()
        });
    }

    fn leave_import(&self) {
        // The build read its parents and imports through its own list and
        // those of the builds it is nested in.
        let searched: Vec<_> = {
            lock(&self.routes).pop();
            let mut lists = lock(&self.import_repos);
            let own = lists.pop().unwrap_or_default().admitted;
            (own.into_iter())
                .chain(lists.iter().flat_map(|list| list.admitted.iter().cloned()))
                .collect()
        };
        let mut builds = lock(&self.import_builds);
        let mut left = builds.pop();
        if let Some(left) = &mut left {
            let own = (left.reads.poms.iter().skip(left.own_from)).map(|pom| pom.name.clone());
            let pairs = own.flat_map(|name| {
                searched
                    .iter()
                    .map(move |repo| (name.clone(), repo.clone()))
            });
            add_searched(&mut left.searched, pairs.collect());
            self.backend.note_import_repositories(&left.searched);
            let poms = left.reads.poms.iter().cloned();
            match builds.last_mut() {
                Some(outer) => {
                    outer.local_lookups.extend(
                        (left.local_lookups.iter())
                            .map(|(parent, found)| (parent.clone(), found.clone())),
                    );
                    outer.logged |= left.logged;
                    outer.reads.add(poms);
                    add_searched(&mut outer.searched, left.searched.clone());
                }
                None => lock(&self.reads).add(poms),
            }
        }
        drop(builds);
        *lock(&self.left_import) = left;
    }

    /// A BOM is imported by many of a resolution's models, and building it
    /// again for each was most of a warm resolution's time. One kept under
    /// the same context is reused when the local parent lookups its build
    /// made find the same POMs from this build's directory. A reactor's
    /// modules share kept imports, and each records the support POMs the
    /// first build read when it reuses one.
    ///
    /// Importers of other packaging build a BOM with other activation
    /// inputs, so each build is kept beside the others. The last one kept
    /// or used is the one a single kept build would be, each build
    /// replacing the one before. Another is used only when its build logged
    /// nothing, as building it again would log nothing either; it is then
    /// the last. A build that logged is kept only while it is the last.
    ///
    /// A scope that finds none claims the build of the BOM for importers
    /// with the same properties, so the other modules wait for it instead
    /// of building the BOM at once beside it, then look again. A waiter
    /// that still finds a build to reuse only in one that logged, or none,
    /// as after a failed build, builds the BOM itself, logging as its own.
    /// The claim lands once the build is kept, and otherwise once the scope
    /// asks for another import at that depth or is dropped.
    async fn reuse_import(
        &self,
        bom: ImportCoord<'_>,
        policy: ModelPolicy,
        importer: &rv_maven_model::ActivationContext,
        usable: &(dyn Fn(&ImportedBom) -> bool + Sync),
    ) -> Option<Arc<ImportedBom>> {
        // Maven searches the repositories for each build, so one that may
        // reach a split route, or a repository raeva does not read, is not
        // shared.
        self.end_lineage();
        if self.split_route_refusal().is_some() || self.reads_ahead_of_unread() {
            return None;
        }
        self.backend.lineage_read();
        let depth = lock(&self.import_builds).len();
        self.claims.land_from(depth);
        let key = Self::import_key(bom, policy, &self.import_context());
        let imports = &self.backend.kept_imports;
        let mut flight = None;
        let mut waited = false;
        let kept = loop {
            if let Some(kept) = self.kept_import(&key, usable, !waited) {
                break kept;
            }
            let flight = flight.get_or_insert_with(|| flight_key(&key, importer));
            match imports.board(flight, self.claims.owner, !waited) {
                Flight::Lead => {
                    // The build it would wait for may have landed since.
                    if let Some(kept) = self.kept_import(&key, usable, !waited) {
                        imports.land(flight, self.claims.owner);
                        break kept;
                    }
                    lock(&self.claims.held).push((std::mem::take(flight), depth));
                    return None;
                }
                Flight::Wait(waiting) => {
                    waiting.landed().await;
                    waited = true;
                }
                Flight::Build => return None,
            }
        };
        Some(self.offer(bom_gav(bom), kept))
    }

    /// Maven 3.9 keeps the first build of a BOM in its session cache for
    /// every later import of the coordinates, whatever the importer, so a
    /// dependency's import takes what a project build with the user
    /// properties made. Maven 3.10 builds each import again.
    async fn cached_import(
        &self,
        bom: ImportCoord<'_>,
        fits: &(dyn Fn(&ImportedBom) -> bool + Sync),
    ) -> Option<Arc<ImportedBom>> {
        if self.backend.mode() != MavenMode::Maven39 {
            return None;
        }
        self.backend.lineage_read();
        let gav = bom_gav(bom);
        let own = lock(&self.backend.read_models).imports.get(&gav).cloned();
        let kept = match own {
            Some(kept) => kept,
            None => {
                self.claims.land_from(0);
                self.backend.session_import(&gav).await?
            }
        };
        fits(&kept.imported).then(|| self.offer(gav, kept))
    }

    fn reused_import(&self) -> Result<(), ResolveError> {
        let Some((gav, kept)) = lock(&self.offered).take() else {
            return Ok(());
        };
        self.backend.record_kept_support_poms(&kept.support_poms)?;
        self.backend.note_import_repositories(&kept.searched);
        self.add_reads(kept.support_poms.iter().cloned());
        // A project build may have built a reactor BOM this external POM
        // imports.
        if self.trust == RepoTrust::Transitive
            && (kept.imported.boms()).any(|(group, artifact, version)| {
                self.backend.is_reactor_module(group, artifact, version)
            })
        {
            self.backend.ctx.note_reactor_through_dependencies();
        }
        self.cache_import(gav, kept);
        Ok(())
    }

    fn keep_import(&self, bom: ImportCoord<'_>, policy: ModelPolicy, imported: Arc<ImportedBom>) {
        let Some(build) = lock(&self.left_import).take() else {
            return;
        };
        let depth = lock(&self.import_builds).len();
        let kept = Arc::new(KeptImport {
            imported,
            local_lookups: build.local_lookups,
            support_poms: build.reads.poms,
            logged: build.logged || rv_maven_model::held::logged_since(build.logged_from),
            searched: build.searched,
        });
        self.cache_import(bom_gav(bom), Arc::clone(&kept));
        if !build.reads.borrowed {
            let key = Self::import_key(bom, policy, &build.context);
            keep_last(
                lock(&self.backend.kept_imports.builds)
                    .entry(key)
                    .or_default(),
                kept,
            );
        }
        self.claims.land_from(depth);
    }

    fn import_holds(&self) -> Option<&rv_maven_model::held::Holds> {
        let holds = &self.backend.kept_imports.holds;
        Some(holds.get_or_init(rv_maven_model::held::Holds::default))
    }
}

impl ModelScope<'_> {
    /// Give the build `kept` for the import `bom`, which the build it is
    /// nested in then depends on as on its own lookups.
    fn offer(&self, bom: PomGav, kept: Arc<KeptImport>) -> Arc<ImportedBom> {
        if let Some(build) = lock(&self.import_builds).last_mut() {
            build.local_lookups.extend(
                (kept.local_lookups.iter()).map(|(parent, found)| (parent.clone(), found.clone())),
            );
            build.logged |= kept.logged;
            add_searched(&mut build.searched, kept.searched.clone());
        }
        let imported = Arc::clone(&kept.imported);
        *lock(&self.offered) = Some((bom, kept));
        imported
    }

    /// Keep what a project build imported as `bom` in the module's model
    /// cache, in the Maven 3.9 mode; see [`ModelSource::cached_import`].
    fn cache_import(&self, bom: PomGav, kept: Arc<KeptImport>) {
        if self.trust == RepoTrust::Root && self.backend.mode() == MavenMode::Maven39 {
            (lock(&self.backend.read_models).imports)
                .entry(bom)
                .or_insert(kept);
        }
    }

    /// The kept build of `key` to reuse, if one fits, one that logged only
    /// if `logged`; see [`ModelSource::reuse_import`].
    fn kept_import(
        &self,
        key: &str,
        usable: &(dyn Fn(&ImportedBom) -> bool + Sync),
        logged: bool,
    ) -> Option<Arc<KeptImport>> {
        let builds = lock(&self.backend.kept_imports.builds).get(key)?.clone();
        let fits = |kept: &&Arc<KeptImport>| {
            usable(&kept.imported)
                && (kept.local_lookups.iter())
                    .all(|(parent, found)| self.local.load(parent) == *found)
        };
        if let Some(last) = (builds.last())
            .filter(|last| logged || !last.logged)
            .filter(fits)
        {
            return Some(Arc::clone(last));
        }
        let kept = builds.iter().find(|kept| !kept.logged && fits(kept))?;
        let mut kept_imports = lock(&self.backend.kept_imports.builds);
        if let Some(builds) = kept_imports.get_mut(key)
            && let Some(at) = builds.iter().position(|other| Arc::ptr_eq(other, kept))
        {
            let kept = builds.remove(at);
            keep_last(builds, kept);
        }
        Some(Arc::clone(kept))
    }

    /// Merge declared `<repositories>` before the parent fetch runs. A POM
    /// that hosts its own parent on a custom repo needs the repo visible
    /// during inheritance, and post-resolution merging is too late.
    ///
    /// Inside an imported BOM's build they go to that BOM's list, with the
    /// trust a remote parent's repository gets in a project build and the
    /// transitive policy otherwise. Outside one, a project build adds them to
    /// the shared list, where a lineage declaration still holding an
    /// expression stands until its effective model's declaration replaces
    /// it, and a transitive build adds them to its own.
    fn observe(
        &self,
        repositories: &[rv_maven_model::Repository],
        replace: bool,
    ) -> Result<(), ResolveError> {
        // A lineage URL as written that holds an expression has no scheme
        // for the parent lookup, so it serves nothing without a mirror, but
        // holds its id as Maven's model resolver does.
        let config = &self.backend.ctx.config;
        // The project's own are refused before resolution starts, and an
        // imported BOM's are ignored as a dependency's are.
        if replace && self.trust == RepoTrust::Root && lock(&self.import_repos).is_empty() {
            let (secrets, names) = (config.secret_named_inputs(), config.secret_input_names());
            // One that takes a secret is ignored, as secrets are kept out of
            // messages and raeva.lock.
            let secret = |repo: &&rv_maven_model::Repository| {
                rv_repo::secret_url_refusal(&repo.url, &repo.url_reads, &secrets, &names).is_some()
                    || rv_repo::secret_id_refusal(
                        repo.id.as_deref(),
                        &repo.id_reads,
                        &secrets,
                        &names,
                    )
                    .is_some()
            };
            let fetched = repositories.iter().filter(|repo| !repo.root_declared);
            for repo in fetched.filter(|repo| !secret(repo)) {
                let id = rv_maven_types::bounded(repo.id.as_deref().unwrap_or_default());
                let read = rv_repo::Repository::from((*repo).clone());
                if let Some(refusal) = rv_repo::expression_id_refusal(config, &read) {
                    return Err(ResolveError::RepositoryIdUnfollowed {
                        id: id.to_string(),
                        declared_by: "a fetched parent of the project".to_string(),
                        refusal: refusal.to_string(),
                    });
                }
            }
        }
        // Maven's mirror selector routes a declaration whether or not
        // raeva admits it.
        if let Some(routes) = lock(&self.routes).last_mut().filter(|_| !replace) {
            routes.write(
                config,
                repositories.iter().cloned().map(rv_repo::Repository::from),
            );
        }
        let declared = repositories;
        // Nor does a layout as written that holds one name a layout.
        let (repositories, unserved): (Vec<_>, Vec<_>) = (repositories.iter()).partition(|repo| {
            let layout = (repo.layout.as_deref()).is_some_and(|layout| layout.contains("${"));
            replace
                || !repo.url.contains("${") && !layout
                || rv_repo::mirror_serves(config, &rv_repo::Repository::from((*repo).clone()))
        });
        let unserved: Vec<_> = (unserved.into_iter())
            .map(|repo| rv_repo::Repository::from(repo.clone()))
            .collect();
        let repos: Vec<_> = (repositories.iter())
            .map(|repo| rv_repo::Repository::from((*repo).clone()))
            .collect();
        // A project's model resolver searches a kept mirror ahead of the
        // configured repositories, so a split refuses its build even where
        // raeva drops the interpolated declaration. A dependency's searches
        // it after the repositories it was found through, where raeva only
        // misses what Maven reads, and so checks only what raeva reads.
        if replace && self.trust == RepoTrust::Root {
            self.split_route(&repos)?;
        }
        let importing = !lock(&self.import_repos).is_empty();
        let admitted = match self.trust {
            RepoTrust::Root if !importing => {
                if replace {
                    self.backend.extend_root_effective_repos(repos);
                } else {
                    self.backend
                        .extend_root_lineage_repos(repositories.iter().map(|repo| {
                            (
                                rv_repo::Repository::from((*repo).clone()),
                                repo.has_expression(),
                            )
                        }));
                    self.backend.hold_lineage_ids(&unserved);
                }
                return Ok(());
            }
            RepoTrust::Root => self.backend.admit_root_lineage(repos).0,
            RepoTrust::Transitive => self.backend.admit_transitive_model(repos).0,
        };
        if replace && self.trust == RepoTrust::Transitive {
            self.split_route(&admitted)?;
        }
        // Each declaration takes its place in Maven's list, raeva reading it
        // or not.
        let added = (declared.iter()).map(|declared| {
            let repo = rv_repo::Repository::from(declared.clone());
            if let Some(known) = admitted
                .iter()
                .find(|known| repo_key(known) == repo_key(&repo))
            {
                return (known.clone(), Reach::Read);
            }
            let unserved = unserved
                .iter()
                .any(|known| repo_key(known) == repo_key(&repo));
            let neither = unserved
                || model_list::blocked(config, &repo)
                || rv_repo::layout_refusal(config, &repo).is_some();
            match neither {
                true => (repo, Reach::Neither),
                false => (repo, Reach::Maven),
            }
        });
        let mut imports = lock(&self.import_repos);
        let mut own = lock(&self.build_repos);
        let list = match imports.last_mut() {
            Some(list) => list,
            None => &mut own,
        };
        list.add(added, replace);
        if replace {
            list.effective();
        }
        Ok(())
    }
}

impl ModelScope<'_> {
    /// The refusal of `fetched`, which a mirror served for a repository only
    /// the imported BOMs being built declare: the lock records that
    /// repository, which the project does not, and a sync cannot fetch the
    /// POM from it again.
    fn mirrored_import_refusal(&self, fetched: &SupportPom) -> Option<ResolveError> {
        let url = fetched.mirrored_from()?;
        let lists = lock(&self.import_repos);
        let (depth, repo) = (lists.iter().enumerate())
            .flat_map(|(depth, list)| list.admitted.iter().map(move |repo| (depth, repo)))
            .find(|(_, repo)| repo.url == url)?;
        if (self.backend.effective_repos_snapshot().iter()).any(|known| known.url == url) {
            return None;
        }
        // Each import build's reads start with its BOM's POM.
        let bom = (lock(&self.import_builds).get(depth))
            .and_then(|build| build.reads.poms.first())
            .map(|pom| pom.name.clone())
            .unwrap_or_default();
        let config = &self.backend.ctx.config;
        let secrets = config.secret_named_inputs();
        let names = config.secret_input_names();
        let id = repo.id.as_deref().unwrap_or_default();
        let mirror = rv_repo::matched_mirror(config, repo)?;
        Some(ResolveError::MirroredImportRepository {
            pom: fetched.name.clone(),
            bom,
            id: rv_maven_types::bounded(&rv_repo::shown_id(id, repo.id_reads(), &secrets, &names))
                .to_string(),
            mirror: rv_maven_types::bounded(mirror.id.as_deref().unwrap_or("default")).to_string(),
        })
    }

    /// `coord`'s POM from `searched`, the repositories Maven searches before
    /// `unread`, which raeva does not read, or the refusal where none holds
    /// it. Maven looks in its model cache before any repository.
    async fn before_unread(
        &self,
        coord: &Coord,
        model: Option<ModelKey>,
        searched: Vec<rv_repo::Repository>,
        unread: &Entry,
        central: Option<(Vec<rv_repo::Repository>, rv_repo::Repository)>,
    ) -> Result<Arc<SupportPom>, ResolveError> {
        if let Some(key) = &model
            && let Some(cached) = self.cached(key).await
        {
            self.note_borrowed();
            (self.backend)
                .record_support_poms(std::slice::from_ref(&cached))
                .await?;
            return Ok(cached);
        }
        let refusal = || self.unread_refusal(coord.to_string(), unread);
        match (self.backend)
            .fetch_pom_bytes_from(coord, searched, model.clone())
            .await
        {
            Err(ResolveError::ArtifactNotFound { .. }) => {}
            fetched => return fetched,
        }
        let Some((others, central)) = central else {
            return Err(refusal());
        };
        if !others.is_empty() {
            match (self.backend)
                .fetch_pom_bytes_from(coord, others, model.clone())
                .await
            {
                Err(ResolveError::ArtifactNotFound { .. }) => {}
                Err(error) => return Err(error),
                Ok(_) => return Err(refusal()),
            }
        }
        match (self.backend)
            .fetch_pom_bytes_from(coord, vec![central], model)
            .await
        {
            Err(ResolveError::ArtifactNotFound { .. }) => Err(refusal()),
            fetched => fetched,
        }
    }

    /// Whether a release POM the build reads now may be Maven's from a
    /// repository raeva does not read.
    fn reads_ahead_of_unread(&self) -> bool {
        let entries = (self.backend).model_entries(&self.repo_ctx, &self.model_build());
        model_list::search(&entries, "1").unread.is_some()
    }

    fn unread_refusal(&self, pom: String, unread: &Entry) -> ResolveError {
        let config = &self.backend.ctx.config;
        let id = unread.repo.id.as_deref().unwrap_or_default();
        let shown = rv_repo::shown_id(
            id,
            unread.repo.id_reads(),
            &config.secret_named_inputs(),
            &config.secret_input_names(),
        );
        let id = rv_maven_types::bounded(&shown).to_string();
        let maven = match self.backend.mode() {
            MavenMode::Maven39 => "Maven 3.9.12",
            MavenMode::Maven310 => "Maven 3.10.0",
        };
        match unread.displaced {
            true => ResolveError::RedeclaredRepository { id, maven },
            false => ResolveError::UnreadRepositoryAhead {
                pom: rv_maven_types::bounded(&pom).to_string(),
                id,
                maven,
            },
        }
    }

    /// Note the routes of the interpolated declarations the build reads,
    /// refusing it when a parent lookup may have read through a split one;
    /// see [`Routes`].
    fn split_route(&self, read: &[rv_repo::Repository]) -> Result<(), ResolveError> {
        let config = &self.backend.ctx.config;
        let mut routes = lock(&self.routes);
        let Some(routes) = routes.last_mut() else {
            return Ok(());
        };
        routes.interpolate(config, read);
        match (routes.splits.iter()).find(|split| routes.consulted.contains(&split.id)) {
            Some(split) => Err(split.refusal(config)),
            None => Ok(()),
        }
    }

    /// The refusal of a BOM read through a repository whose route split.
    fn split_route_refusal(&self) -> Option<ResolveError> {
        let routes = lock(&self.routes);
        let split = (routes.last().into_iter())
            .flat_map(|routes| routes.splits.iter())
            .find(|split| !split.replaced)?;
        Some(split.refusal(&self.backend.ctx.config))
    }

    /// `coord`'s POM when a repository Maven searches before every kept
    /// mirror entry serves it, so the build never reaches one. A
    /// dependency's model resolver starts from the repositories the
    /// dependency was resolved through and appends what its POMs declare,
    /// so those come first. A project's re-adds each declaration once
    /// interpolated, behind the mirror entries the declarations as written
    /// left and ahead of the configured repositories, so it has none; nor,
    /// here, does an imported BOM's build, or a range or snapshot, which
    /// reads every repository's metadata.
    async fn ahead_of_kept_mirrors(
        &self,
        coord: &Coord,
        model: Option<ModelKey>,
        interpolated: bool,
    ) -> Result<Option<Pom>, ResolveError> {
        let version = coord.version.to_string();
        if self.trust != RepoTrust::Transitive
            || !lock(&self.import_repos).is_empty()
            || rv_maven_types::resolves_through_snapshot_metadata(&version)
        {
            return Ok(None);
        }
        // In Maven 3.9.12 the interpolated declaration that takes a request
        // repository's id, which an imported BOM is read after, replaces
        // that entry; Maven 3.10.0 keeps the request's.
        let mut repos = (self.backend).parent_search_list(&self.repo_ctx, &ModelBuild::default());
        if interpolated
            && self.backend.mode() == MavenMode::Maven39
            && let Some(routes) = lock(&self.routes).last()
        {
            repos.retain(|repo| {
                !(repo.id.as_ref()).is_some_and(|id| routes.written.contains_key(id))
            });
        }
        match (self.backend)
            .fetch_pom_bytes_from(coord, repos, model)
            .await
        {
            Ok(fetched) => {
                self.backend.learn_models(std::slice::from_ref(&fetched));
                self.parse_fetched(coord, fetched, false).map(Some)
            }
            Err(ResolveError::ArtifactNotFound { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// A mirror's normalized URL and its id.
type Route = (String, String);

fn route(mirror: &rv_config::MirrorConfig) -> Route {
    let id = mirror.id.clone().unwrap_or_else(|| "default".to_string());
    (rv_repo::normalize_repo_url(&mirror.url), id)
}

/// A repository whose URL as written goes to mirror `written` and
/// interpolated to `interpolated`.
struct Split {
    id: String,
    /// The id as messages show it.
    shown: String,
    written: String,
    interpolated: Option<String>,
    /// Whether the mirror has the repository's id, so the interpolated
    /// declaration replaces it before the build imports a BOM, though not
    /// before the parent lookups that came first.
    replaced: bool,
}

impl Split {
    fn refusal(&self, config: &rv_config::Config) -> ResolveError {
        let secrets = config.secret_named_inputs();
        let shown = |text: &str| {
            rv_maven_types::bounded(rv_config::without_secret_values(text, &secrets)).to_string()
        };
        ResolveError::MirrorRouteSplit {
            id: rv_maven_types::bounded(&self.shown).to_string(),
            written: shown(&self.written),
            interpolated: self.interpolated.as_deref().map(shown),
        }
    }
}

/// The mirror routes of one build's repositories. Maven's model resolver
/// adds a declaration as written with the mirror it matches, under the
/// mirror's id, and the interpolated declaration replaces only entries
/// under the repository's own id. A mirror the URL as written reaches thus
/// stays in the list the build's parents and imported BOMs are read
/// through, ahead of the interpolated URL's route, which the dependencies
/// take. A build that reads a parent or a BOM through such a repository is
/// refused.
#[derive(Default)]
struct Routes {
    /// The mirror each id's first declaration as written reaches, `None`
    /// for one no mirror serves.
    written: HashMap<String, Option<Route>>,
    /// The ids a parent lookup may have read through: those with a mirror
    /// when the build looked a parent up.
    consulted: HashSet<String>,
    /// The ids whose first declaration as written holds an expression in
    /// its URL and reaches a mirror, which a dependency's parent lookup in
    /// raeva does not search.
    unsearched: BTreeMap<String, Route>,
    /// The repositories whose interpolated declaration, which the build
    /// reads, takes another route.
    splits: Vec<Split>,
}

impl Routes {
    fn write(
        &mut self,
        config: &rv_config::Config,
        repos: impl Iterator<Item = rv_repo::Repository>,
    ) {
        for repo in repos {
            let Some(id) = &repo.id else {
                continue;
            };
            if self.written.contains_key(id) {
                continue;
            }
            let written = rv_repo::matched_mirror(config, &repo)
                .filter(|mirror| !mirror.blocked)
                .map(route);
            if let Some(written) = (written.clone()).filter(|_| repo.declared_url().contains("${"))
            {
                self.unsearched.insert(id.clone(), written);
            }
            self.written.insert(id.clone(), written);
        }
    }

    /// A dependency's `parent` that none of the repositories raeva
    /// searches holds, which Maven also looks up through the mirror a
    /// declaration as written reaches that raeva does not search. `None`
    /// when none does.
    fn parent_behind_mirror(
        &self,
        config: &rv_config::Config,
        parent: String,
    ) -> Option<ResolveError> {
        let secrets = config.secret_named_inputs();
        let shown = |text: &str| {
            rv_maven_types::bounded(rv_config::without_secret_values(text, &secrets)).to_string()
        };
        let (id, (_, mirror)) = self.unsearched.iter().next()?;
        Some(ResolveError::ParentBehindWrittenMirror {
            parent: shown(&parent),
            id: shown(id),
            mirror: shown(mirror),
        })
    }

    /// Whether a declaration as written goes to a mirror.
    fn mirrored(&self) -> bool {
        self.written.values().any(Option::is_some)
    }

    fn consult(&mut self) {
        let served = (self.written.iter()).filter(|(_, mirror)| mirror.is_some());
        self.consulted.extend(served.map(|(id, _)| id.clone()));
    }

    fn interpolate(&mut self, config: &rv_config::Config, repos: &[rv_repo::Repository]) {
        for repo in repos {
            let Some(id) = &repo.id else {
                continue;
            };
            let Some(Some(written)) = self.written.get(id) else {
                continue;
            };
            let interpolated = rv_repo::matched_mirror(config, repo).map(route);
            // A mirror's id selects its `<server>`, so two at one URL are
            // one route only when neither is blocked and each sends the same
            // first request: at most a username and password, which Maven
            // sends only once challenged.
            let uncredentialed = |id: &str| {
                config.sends_only_challenged_credentials(id)
                    && !(config.mirrors().iter())
                        .any(|mirror| mirror.id.as_deref() == Some(id) && mirror.blocked)
            };
            let same = interpolated.as_ref().is_some_and(|(url, mirror)| {
                *url == written.0
                    && (*mirror == written.1
                        || uncredentialed(mirror) && uncredentialed(&written.1))
            });
            if !same && !self.splits.iter().any(|split| split.id == *id) {
                let shown = rv_repo::shown_id(
                    id,
                    repo.id_reads(),
                    &config.secret_named_inputs(),
                    &config.secret_input_names(),
                );
                self.splits.push(Split {
                    id: id.clone(),
                    shown,
                    written: written.1.clone(),
                    interpolated: interpolated.map(|(_, mirror)| mirror),
                    replaced: written.1 == *id,
                });
            }
        }
    }
}

/// The declarations one build's model resolver was handed.
#[derive(Default)]
struct BuildRepos {
    added: Vec<Added>,
    /// Every repository admitted.
    admitted: Vec<rv_repo::Repository>,
    /// Whether the build's lineage is read: its effective model's
    /// repositories, the super POM's `central` last, are added.
    effective: bool,
}

/// Add to `known` each of `pairs` it lacks.
fn add_searched(
    known: &mut Vec<(String, rv_repo::Repository)>,
    pairs: Vec<(String, rv_repo::Repository)>,
) {
    for pair in pairs {
        if !known.contains(&pair) {
            known.push(pair);
        }
    }
}

impl BuildRepos {
    /// Add `repos`, each with who reads it, as Maven's `addRepository`
    /// gets them.
    fn add(
        &mut self,
        repos: impl IntoIterator<Item = (rv_repo::Repository, Reach)>,
        replace: bool,
    ) {
        for (repo, reach) in repos {
            if reach == Reach::Read && !self.admitted.contains(&repo) {
                self.admitted.push(repo.clone());
            }
            self.added.push(Added {
                repo,
                replace,
                reach,
                implied: false,
            });
        }
    }

    /// End the lineage with the super POM's `central`, unless the effective
    /// model declares `central` itself.
    fn effective(&mut self) {
        if std::mem::replace(&mut self.effective, true) {
            return;
        }
        let declared = (self.added.iter())
            .any(|added| added.replace && added.repo.id.as_deref() == Some("central"));
        if !declared {
            self.added.push(Added {
                repo: model_list::super_central(),
                replace: true,
                reach: Reach::Read,
                implied: true,
            });
        }
    }
}

/// Maven reads a parent from a file only for a model read from a file, so
/// the lineage of a POM a repository served never comes back to the tree.
pub(super) fn without_local_parent(pom: &mut Pom) {
    if let Some(parent) = &mut pom.parent {
        parent.relative_path = Some(String::new());
    }
}

/// Record `provenance` on a POM a repository served. A reactor module
/// standing in for a parent or BOM keeps the provenance discovery gave it.
fn fetched_from_repository(pom: Option<Pom>, provenance: Provenance) -> Option<Pom> {
    pom.map(|mut pom| {
        if pom.provenance().is_none() {
            pom.set_provenance(provenance);
        }
        pom
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{ModelScope, RepoTrust};
    use crate::context::ResolveContext;
    use crate::parent_resolver::LocalParents;
    use crate::resolver::ModelService;
    use rv_config::{Config, ResolvedPaths};
    use rv_lock::Platform;
    use rv_maven_model::ModelSource as _;
    use rv_store::Store;

    fn backend(allow_transitive_repositories: bool) -> ModelService {
        let paths = ResolvedPaths::for_testing().expect("paths");
        let mut config =
            Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new());
        config.security.allow_transitive_repositories = allow_transitive_repositories;
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
        ModelService::new(&ctx, Vec::new())
    }

    /// A BOM built once is reused by the next model that imports it, also
    /// by one from whose directory the BOM's default `<relativePath>` names a
    /// local POM with its parent's coordinates: a repository POM's parents
    /// come from the repositories.
    #[tokio::test]
    async fn a_kept_bom_is_reused_from_any_directory() {
        use crate::resolver::pom_source::MemoryPomSource;
        use std::collections::HashMap;

        let managing = |artifact: &str, version: &str, body: &str| {
            format!(
                "<project><groupId>g</groupId><artifactId>{artifact}</artifactId>\
                 <version>{version}</version>{body}</project>"
            )
        };
        let bom = managing(
            "bom",
            "1",
            "<parent><groupId>g</groupId><artifactId>base</artifactId><version>1</version></parent>\
             <packaging>pom</packaging>\
             <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>lib</artifactId><version>${lib.version}</version></dependency>\
             </dependencies></dependencyManagement>",
        );
        let base = |lib: &str| {
            managing(
                "base",
                "1",
                &format!(
                    "<packaging>pom</packaging><properties><lib.version>{lib}</lib.version></properties>"
                ),
            )
        };
        let files = HashMap::from([
            ("g/bom/1/bom-1.pom".to_string(), bom.into_bytes()),
            ("g/base/1/base-1.pom".to_string(), base("1").into_bytes()),
        ]);
        let source = Arc::new(
            MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://repo.example/", &files),
        );
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config =
            Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new());
        let ctx = ResolveContext::new(
            config,
            Vec::new(),
            store,
            Platform::new("linux", "x86_64").unwrap(),
            None,
        )
        .with_pom_source(source.clone());
        let repo = rv_repo::Repository::new(None, "https://repo.example/", true, false);
        let backend = ModelService::new(&ctx, vec![repo]);

        // `local/module`'s `../pom.xml` is a POM with the BOM parent's
        // coordinates and another `lib.version`; `remote/module` has none.
        let tree = tempfile::tempdir().unwrap();
        for dir in ["local/module", "remote/module"] {
            std::fs::create_dir_all(tree.path().join(dir)).unwrap();
        }
        std::fs::write(tree.path().join("local/pom.xml"), base("2")).unwrap();
        let importer = rv_maven_model::Pom::parse(&managing(
            "app",
            "1",
            "<dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>bom</artifactId><version>1</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement>",
        ))
        .unwrap();
        let root = tree.path().to_path_buf();
        let lib_version = |dir: &str| {
            let local = LocalParents::new(root.join(dir), root.clone());
            let backend = &backend;
            let importer = importer.clone();
            async move {
                let scope = ModelScope::root(backend, local);
                let project = scope
                    .project(importer, &rv_maven_model::ActivationContext::default())
                    .await
                    .unwrap();
                project
                    .dependency_management
                    .dependencies
                    .iter()
                    .find(|dep| dep.artifact_id == "lib")
                    .and_then(|dep| dep.version.clone())
                    .unwrap()
            }
        };
        let bom_reads = || {
            source
                .requests()
                .iter()
                .filter(|request| request.ends_with("bom-1.pom"))
                .count()
        };

        assert_eq!(lib_version("remote/module").await, "1");
        assert_eq!(bom_reads(), 1);
        assert_eq!(lib_version("remote/module").await, "1");
        assert_eq!(bom_reads(), 1, "the kept BOM is reused");
        assert_eq!(lib_version("local/module").await, "1");
        assert_eq!(bom_reads(), 1, "the local POM is not its parent");
    }

    /// BOMs that import the same BOMs reuse the kept builds, and each
    /// support POM and local parent lookup is listed once, however many
    /// import paths reach it: copying a kept list once per path grew it
    /// exponentially with depth.
    #[tokio::test]
    async fn shared_imports_list_each_support_pom_once() {
        use crate::resolver::pom_source::MemoryPomSource;
        use std::collections::HashMap;

        const DEPTH: usize = 16;
        let imports = |level: usize| {
            if level == DEPTH {
                return String::new();
            }
            let deps: String = (0..2)
                .map(|i| {
                    format!(
                        "<dependency><groupId>g</groupId><artifactId>b{level}-{i}</artifactId>\
                         <version>1</version><type>pom</type><scope>import</scope></dependency>"
                    )
                })
                .collect();
            format!(
                "<dependencyManagement><dependencies>{deps}</dependencies></dependencyManagement>"
            )
        };
        let mut files: HashMap<_, _> = (0..DEPTH)
            .flat_map(|level| (0..2).map(move |i| (level, i)))
            .map(|(level, i)| {
                let pom = format!(
                    "<project><parent><groupId>g</groupId><artifactId>base</artifactId>\
                     <version>1</version></parent><artifactId>b{level}-{i}</artifactId>\
                     <packaging>pom</packaging>{}</project>",
                    imports(level + 1)
                );
                (
                    format!("g/b{level}-{i}/1/b{level}-{i}-1.pom"),
                    pom.into_bytes(),
                )
            })
            .collect();
        files.insert(
            "g/base/1/base-1.pom".to_string(),
            b"<project><groupId>g</groupId><artifactId>base</artifactId>\
              <version>1</version><packaging>pom</packaging></project>"
                .to_vec(),
        );
        let source = Arc::new(
            MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://repo.example/", &files),
        );
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config =
            Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new());
        let ctx = ResolveContext::new(
            config,
            Vec::new(),
            store,
            Platform::new("linux", "x86_64").unwrap(),
            None,
        )
        .with_pom_source(source);
        let repo = rv_repo::Repository::new(None, "https://repo.example/", true, false);
        let backend = ModelService::new(&ctx, vec![repo]);
        let importer = rv_maven_model::Pom::parse(&format!(
            "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>{}</project>",
            imports(0)
        ))
        .unwrap();
        let scope = ModelScope::root(&backend, LocalParents::none());
        scope
            .project(importer, &rv_maven_model::ActivationContext::default())
            .await
            .unwrap();
        // Each BOM and its parent's read, not one per import path.
        let reads = scope.into_reads().len();
        assert!(reads <= 4 * DEPTH, "{reads}");
        let kept = crate::util::lock(&backend.kept_imports.builds);
        assert!(!kept.is_empty());
        for builds in kept.values() {
            for build in builds {
                assert!(
                    build.local_lookups.len() <= 1,
                    "{}",
                    build.local_lookups.len()
                );
            }
        }
    }

    /// A reactor's modules share the BOMs their builds keep, and a module
    /// that reuses one records the support POMs its first build read.
    #[tokio::test]
    async fn a_reactors_modules_share_kept_boms() {
        use crate::resolver::pom_source::MemoryPomSource;
        use std::collections::HashMap;

        let files = HashMap::from([
            (
                "g/bom/1/bom-1.pom".to_string(),
                b"<project><parent><groupId>g</groupId><artifactId>base</artifactId>\
                  <version>1</version></parent><artifactId>bom</artifactId>\
                  <packaging>pom</packaging></project>"
                    .to_vec(),
            ),
            (
                "g/base/1/base-1.pom".to_string(),
                b"<project><groupId>g</groupId><artifactId>base</artifactId>\
                  <version>1</version><packaging>pom</packaging></project>"
                    .to_vec(),
            ),
        ]);
        let source = Arc::new(
            MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://repo.example/", &files),
        );
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config =
            Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new());
        let ctx = ResolveContext::new(
            config,
            Vec::new(),
            store,
            Platform::new("linux", "x86_64").unwrap(),
            None,
        )
        .with_pom_source(source.clone());
        let repo = rv_repo::Repository::new(None, "https://repo.example/", true, false);
        let importer = rv_maven_model::Pom::parse(
            "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
             <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
             <artifactId>bom</artifactId><version>1</version><type>pom</type>\
             <scope>import</scope></dependency></dependencies></dependencyManagement></project>",
        )
        .unwrap();
        let kept = Arc::<super::super::reactor_models::KeptImports>::default();
        let support_poms = super::super::backend::WorkspaceSupportPomBuffer::default();
        for module in ["a", "b"] {
            let backend = ModelService::new(&ctx, vec![repo.clone()])
                .with_workspace_support_poms(Arc::clone(&support_poms))
                .with_kept_imports(Arc::clone(&kept));
            ModelScope::root(&backend, LocalParents::none())
                .project(
                    importer.clone(),
                    &rv_maven_model::ActivationContext::default(),
                )
                .await
                .unwrap();
            let mut recorded: Vec<_> = backend
                .support_pom_provenance_snapshot()
                .into_iter()
                .map(|(coord, _)| coord)
                .collect();
            recorded.sort();
            assert_eq!(recorded, ["g:base:1", "g:bom:1"], "module {module}");
        }
        let bom_reads = source
            .requests()
            .iter()
            .filter(|request| request.ends_with("bom-1.pom"))
            .count();
        assert_eq!(bom_reads, 1, "module b reuses the BOM module a kept");

        // A module that read other bytes for a POM the kept BOM read fails as
        // a fetch of those bytes would.
        let backend = ModelService::new(&ctx, vec![repo.clone()])
            .with_workspace_support_poms(Arc::clone(&support_poms))
            .with_kept_imports(Arc::clone(&kept));
        let other = super::super::backend::SupportPomProvenance {
            repo_id: String::new(),
            repo_url: "https://repo.example/".to_string(),
            snapshot: None,
            sha256: "0".repeat(64),
        };
        backend
            .support_pom_provenance
            .write()
            .unwrap()
            .insert("g:base:1".to_string(), other);
        let error = ModelScope::root(&backend, LocalParents::none())
            .project(importer, &rv_maven_model::ActivationContext::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, crate::ResolveError::ConflictingResolvedPomBytes(ref pom) if pom.coord == "g:base:1"),
            "{error:?}"
        );
    }

    /// A BOM built for importers of each packaging in turn is built again,
    /// warnings and all, where its build logged anything, as it would be
    /// with one kept build cleared at each module's end; one that logged
    /// nothing is reused.
    #[test]
    fn a_bom_build_for_another_packaging_is_reused_only_when_it_logged_nothing() {
        use crate::resolver::pom_source::MemoryPomSource;
        use std::collections::HashMap;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let bom = |url: &str| {
            format!(
                "<project><groupId>g</groupId><artifactId>bom</artifactId><version>1</version>\
                 <packaging>pom</packaging><repositories><repository><id>r</id><url>{url}</url>\
                 </repository></repositories><profiles><profile><id>p</id><activation>\
                 <property><name>packaging</name><value>pom</value></property></activation>\
                 </profile></profiles></project>"
            )
            .into_bytes()
        };
        // Refusing a repository the BOM declares logs.
        for (url, reads, builds) in [("ftp://r.example/", 4, 1), ("https://r.example/", 2, 2)] {
            let files = HashMap::from([("g/bom/1/bom-1.pom".to_string(), bom(url))]);
            let source = Arc::new(
                MemoryPomSource::new(rv_config::SecurityConfig::default())
                    .with_files("https://repo.example/", &files),
            );
            let store_tmp = tempfile::tempdir().unwrap();
            let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
            let paths = ResolvedPaths::for_testing().expect("paths");
            let config =
                Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new());
            let ctx = ResolveContext::new(
                config,
                Vec::new(),
                store,
                Platform::new("linux", "x86_64").unwrap(),
                None,
            )
            .with_pom_source(source.clone());
            let repo = rv_repo::Repository::new(None, "https://repo.example/", true, false);
            let models = Arc::new(super::super::reactor_models::ReactorModels::default());
            // Each importer is a module of its own, with its own model cache.
            let module = || {
                ModelService::new(&ctx, vec![repo.clone()]).with_reactor_models(Arc::clone(&models))
            };
            rv_test_support::capture_warnings(|| {
                runtime.block_on(async {
                    for packaging in ["jar", "pom", "jar", "end", "jar"] {
                        if packaging == "end" {
                            module().release_graph_caches();
                            continue;
                        }
                        let importer = rv_maven_model::Pom::parse(&format!(
                            "<project><groupId>g</groupId><artifactId>app</artifactId>\
                         <version>1</version><packaging>{packaging}</packaging>\
                         <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
                         <artifactId>bom</artifactId><version>1</version><type>pom</type>\
                         <scope>import</scope></dependency></dependencies>\
                         </dependencyManagement></project>"
                        ))
                        .unwrap();
                        ModelScope::root(&module(), LocalParents::none())
                            .project(importer, &rv_maven_model::ActivationContext::default())
                            .await
                            .unwrap();
                    }
                })
            });
            let read = (source.requests().iter())
                .filter(|request| request.ends_with("bom-1.pom"))
                .count();
            assert_eq!(read, reads, "{url}");
            let kept = crate::util::lock(&models.imports.builds)
                .values()
                .map(Vec::len)
                .sum::<usize>();
            assert_eq!(kept, builds, "{url}");
        }
    }

    /// The POMs at `files` served from one repository, each path in
    /// `delays` answered 50 ms late, in a context over a store in the
    /// returned directory.
    fn delayed_context(
        files: &[(&str, &str)],
        delays: &[&str],
    ) -> (
        ResolveContext,
        Arc<crate::resolver::pom_source::MemoryPomSource>,
        tempfile::TempDir,
    ) {
        let files: std::collections::HashMap<String, Vec<u8>> = (files.iter())
            .map(|(path, pom)| (path.to_string(), pom.as_bytes().to_vec()))
            .collect();
        let mut source =
            crate::resolver::pom_source::MemoryPomSource::new(rv_config::SecurityConfig::default())
                .with_files("https://repo.example/", &files);
        for path in delays {
            source = source.with_delay(path, std::time::Duration::from_millis(50));
        }
        let source = Arc::new(source);
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config =
            Config::for_testing_with_repos(std::path::PathBuf::from("."), paths, Vec::new());
        let ctx = ResolveContext::new(
            config,
            Vec::new(),
            store,
            Platform::new("linux", "x86_64").unwrap(),
            None,
        )
        .with_pom_source(source.clone());
        (ctx, source, store_tmp)
    }

    /// A project that imports the BOM `g:<bom>:1`.
    fn bom_importer(bom: &str) -> rv_maven_model::Pom {
        rv_maven_model::Pom::parse(&format!(
            "<project><groupId>g</groupId><artifactId>app</artifactId><version>1</version>\
             <dependencyManagement><dependencies>\
             <dependency><groupId>g</groupId><artifactId>{bom}</artifactId><version>1</version>\
             <type>pom</type><scope>import</scope></dependency></dependencies>\
             </dependencyManagement></project>"
        ))
        .unwrap()
    }

    /// The model of `importer` as a reactor module builds it, sharing `kept`.
    async fn module_model(
        ctx: &ResolveContext,
        kept: &Arc<super::KeptImports>,
        importer: &rv_maven_model::Pom,
    ) -> Result<rv_maven_model::Project, crate::ResolveError> {
        let repo = rv_repo::Repository::new(None, "https://repo.example/", true, false);
        let backend = ModelService::new(ctx, vec![repo]).with_kept_imports(Arc::clone(kept));
        ModelScope::root(&backend, LocalParents::none())
            .project(
                importer.clone(),
                &rv_maven_model::ActivationContext::default(),
            )
            .await
    }

    fn kept_builds(kept: &super::KeptImports) -> usize {
        (crate::util::lock(&kept.builds).values())
            .map(Vec::len)
            .sum()
    }

    const SLOW_BOM: [(&str, &str); 2] = [
        (
            "g/bom/1/bom-1.pom",
            "<project><parent><groupId>g</groupId><artifactId>base</artifactId>\
             <version>1</version></parent><artifactId>bom</artifactId>\
             <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
             <groupId>g</groupId><artifactId>x</artifactId><version>1</version></dependency>\
             </dependencies></dependencyManagement></project>",
        ),
        (
            "g/base/1/base-1.pom",
            "<project><groupId>g</groupId><artifactId>base</artifactId>\
             <version>1</version><packaging>pom</packaging></project>",
        ),
    ];

    /// Modules that import a BOM another module is building wait for that
    /// build and reuse it instead of building the BOM beside it.
    #[tokio::test(start_paused = true)]
    async fn modules_wait_for_the_build_of_a_bom_under_way() {
        let (ctx, _, _store) = delayed_context(&SLOW_BOM, &["g/base/1/base-1.pom"]);
        let kept = Arc::<super::KeptImports>::default();
        let importer = bom_importer("bom");
        let modules = (0..4).map(|_| module_model(&ctx, &kept, &importer));
        let projects = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            futures::future::join_all(modules),
        )
        .await
        .expect("no module waits forever");
        for project in projects {
            let managed = project.unwrap().dependency_management.dependencies;
            assert_eq!(managed.len(), 1);
            assert_eq!(managed[0].artifact_id, "x");
        }
        assert_eq!(kept_builds(&kept), 1, "one build for four modules");
    }

    /// A module that waited for a BOM build that logged builds the BOM
    /// itself and logs as its own, as it would have without waiting.
    #[test]
    fn a_waiter_builds_again_a_bom_whose_build_logged() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let files = [(
            "g/bom/1/bom-1.pom",
            "<project><groupId>g</groupId><artifactId>bom</artifactId><version>1</version>\
             <packaging>pom</packaging><repositories><repository><id>r</id>\
             <url>ftp://r.example/</url></repository></repositories></project>",
        )];
        let (ctx, source, _store) = delayed_context(&files, &["g/bom/1/bom-1.pom"]);
        let kept = Arc::<super::KeptImports>::default();
        let importer = bom_importer("bom");
        let log = rv_test_support::capture_warnings(|| {
            runtime.block_on(async {
                let (first, second) = futures::future::join(
                    module_model(&ctx, &kept, &importer),
                    module_model(&ctx, &kept, &importer),
                )
                .await;
                first.unwrap();
                second.unwrap();
            })
        });
        let reads = (source.requests().iter())
            .filter(|request| request.ends_with("bom-1.pom"))
            .count();
        assert_eq!(reads, 2, "{log}");
    }

    /// A module whose build of a BOM is cancelled lands its claim, and the
    /// module waiting for it builds the BOM itself.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_bom_build_wakes_the_modules_waiting_for_it() {
        let (ctx, _, _store) = delayed_context(&SLOW_BOM, &["g/base/1/base-1.pom"]);
        let kept = Arc::<super::KeptImports>::default();
        let importer = bom_importer("bom");
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            module_model(&ctx, &kept, &importer),
        );
        let waiting = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            module_model(&ctx, &kept, &importer),
        );
        let (cancelled, waited) = tokio::join!(cancelled, waiting);
        assert!(cancelled.is_err(), "the first build is cancelled");
        let project = waited.expect("the waiter does not wait forever").unwrap();
        assert_eq!(project.dependency_management.dependencies.len(), 1);
        assert_eq!(kept_builds(&kept), 1);
    }

    /// A module waiting for a BOM build that fails builds the BOM again
    /// itself and fails as the first module did.
    #[tokio::test(start_paused = true)]
    async fn a_failed_bom_build_leaves_its_waiters_the_same_error() {
        let files = [(
            "g/bom/1/bom-1.pom",
            "<project><parent><groupId>g</groupId><artifactId>gone</artifactId>\
             <version>1</version></parent><artifactId>bom</artifactId>\
             <packaging>pom</packaging></project>",
        )];
        let (ctx, source, _store) = delayed_context(&files, &["g/gone/1/gone-1.pom"]);
        let kept = Arc::<super::KeptImports>::default();
        let importer = bom_importer("bom");
        let (first, second) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            futures::future::join(
                module_model(&ctx, &kept, &importer),
                module_model(&ctx, &kept, &importer),
            ),
        )
        .await
        .expect("no module waits forever");
        let first = first.unwrap_err().to_string();
        assert_eq!(first, second.unwrap_err().to_string());
        assert!(first.contains("g:gone:1"), "{first}");
        let parent_reads = (source.requests().iter())
            .filter(|path| path.ends_with("gone-1.pom"))
            .count();
        assert_eq!(parent_reads, 1, "the second module waited for the first");
        assert_eq!(kept_builds(&kept), 0);
    }

    /// Two modules each building a BOM the other's build imports do not
    /// wait for each other: the wait that would close the cycle is not made,
    /// and both fail on the import cycle as a lone module would.
    #[tokio::test(start_paused = true)]
    async fn a_wait_that_would_close_a_cycle_is_not_made() {
        let bom = |name: &str, imports: &str| {
            format!(
                "<project><groupId>g</groupId><artifactId>{name}</artifactId>\
                 <version>1</version><packaging>pom</packaging><dependencyManagement>\
                 <dependencies><dependency><groupId>g</groupId><artifactId>{imports}</artifactId>\
                 <version>1</version><type>pom</type><scope>import</scope></dependency>\
                 </dependencies></dependencyManagement></project>"
            )
        };
        let (x, y) = (bom("x", "y"), bom("y", "x"));
        let files = [("g/x/1/x-1.pom", x.as_str()), ("g/y/1/y-1.pom", y.as_str())];
        let (ctx, _, _store) = delayed_context(&files, &["g/x/1/x-1.pom", "g/y/1/y-1.pom"]);
        let kept = Arc::<super::KeptImports>::default();
        let (x, y) = (bom_importer("x"), bom_importer("y"));
        let (first, second) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            futures::future::join(module_model(&ctx, &kept, &x), module_model(&ctx, &kept, &y)),
        )
        .await
        .expect("the modules do not wait for each other forever");
        for error in [first.unwrap_err(), second.unwrap_err()] {
            assert!(error.to_string().contains("cycle"), "{error}");
        }
    }

    #[test]
    fn a_served_pom_keeps_the_provenance_discovery_recorded() {
        use rv_maven_model::{Pom, Provenance};

        let fetched = super::fetched_from_repository(
            Some(Pom::parse("<project/>").unwrap()),
            Provenance::BomImport,
        );
        assert_eq!(
            fetched.as_ref().and_then(Pom::provenance),
            Some(&Provenance::BomImport)
        );

        let mut module = Pom::parse("<project/>").unwrap();
        let path = std::path::PathBuf::from("module/pom.xml");
        module.set_provenance(Provenance::ReactorModule { path: path.clone() });
        let fetched = super::fetched_from_repository(Some(module), Provenance::Dependency);
        assert_eq!(
            fetched.as_ref().and_then(Pom::provenance),
            Some(&Provenance::ReactorModule { path })
        );
    }

    /// The repositories a build searches that the root list lacks.
    fn build_searched(scope: &ModelScope<'_>) -> Vec<rv_repo::Repository> {
        let root = scope.backend.root_repos_snapshot();
        let searched = (scope.backend).parent_search_list(&scope.repo_ctx, &scope.model_build());
        searched
            .into_iter()
            .filter(|repo| !root.contains(repo))
            .collect()
    }

    fn declared_repo(id: &str, url: &str) -> rv_maven_model::Repository {
        let mut repo = rv_maven_model::Repository::new(Some(id), url);
        repo.snapshots_enabled = false;
        repo
    }

    /// Test redirect authority through model observation and HTTP client selection.
    /// HTTP distinguishes authorized issuers rejected for transport from untrusted issuers,
    /// without TLS fixtures or external network access.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn root_model_redirect_grants_follow_provenance() {
        use rv_maven_model::{ActivationContext, Pom};
        use rv_repo::{RedirectRejectionKind, RepoClient, RepoError, Repository};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        for (trust, local_parent) in [
            (RepoTrust::Root, false),
            (RepoTrust::Root, true),
            (RepoTrust::Transitive, false),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let repo_url = format!("http://{}/repo/", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 8192];
                assert!(socket.read(&mut buffer).await.unwrap() > 0);
                socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://storage.example/artifact\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            });
            let paths = ResolvedPaths::from_raeva_home(tmp.path().join("raeva"));
            let mut config =
                Config::for_testing_with_repos(tmp.path().to_owned(), paths, Vec::new());
            config.security.allow_transitive_repositories = true;
            let client = RepoClient::new(&config).await.unwrap();
            let store = Arc::new(Store::open(&tmp.path().join("store")).unwrap());
            let ctx = ResolveContext::new(
                config,
                Vec::new(),
                store,
                Platform::new("linux", "x86_64").unwrap(),
                Some(client.clone()),
            );
            // Starting URLs, including lockfile-derived URLs, must not grant
            // redirect authority. Only model observation may grant it.
            let repo = Repository::new(None, &repo_url, true, false);
            let backend = ModelService::new(&ctx, vec![repo.clone()]);
            // Strict reading refuses the forged element in a local parent.
            let forged = if local_parent {
                ""
            } else {
                "<root_declared>true</root_declared>"
            };
            let declarations = format!(
                r#"
                <properties><registry>{repo_url}</registry></properties>
                <profiles><profile><id>active</id><activation><activeByDefault>true</activeByDefault></activation>
                <repositories><repository><id>root</id><url>${{registry}}</url>{forged}</repository></repositories>
                </profile></profiles>"#
            );
            let base = tmp.path().join("child");
            std::fs::create_dir(&base).unwrap();
            let xml = if local_parent {
                std::fs::write(tmp.path().join("pom.xml"), format!("<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>{declarations}</project>")).unwrap();
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId></project>".to_string()
            } else {
                format!(
                    "<project><groupId>g</groupId><artifactId>child</artifactId><version>1</version>{declarations}</project>"
                )
            };
            ModelScope::with_trust(
                &backend,
                LocalParents::new(base, tmp.path().to_owned()),
                trust,
            )
            .project(Pom::parse(&xml).unwrap(), &ActivationContext::default())
            .await
            .unwrap();
            let error = client
                .fetch_metadata(&repo, &"g:artifact:1".parse().unwrap())
                .await
                .unwrap_err();
            let expected = if trust == RepoTrust::Root {
                RedirectRejectionKind::InsecureOrigin
            } else {
                RedirectRejectionKind::OriginNotConfigured
            };
            assert!(
                matches!(error, RepoError::RedirectRejected { kind, .. } if kind == expected),
                "{trust:?}, local_parent={local_parent}: {error}"
            );
            server.await.unwrap();
        }
    }

    /// A root-trust scope merges declared repositories despite the
    /// default-deny policy, and a transitive one is gated by it. What the
    /// policy admits serves the declaring build only, until that model turns
    /// out valid. An imported BOM's lineage stays in that BOM's scope, which
    /// ends with the BOM, while a remote parent's joins the shared list.
    #[test]
    fn observed_repositories_follow_the_scope_trust() {
        let url = "https://declared.example/repo/";
        let shared = |backend: &ModelService, url: &str| {
            backend.repos_snapshot().iter().any(|repo| repo.url == url)
        };
        for (open, trust, merged) in [
            (false, Some(RepoTrust::Root), true),
            (false, Some(RepoTrust::Transitive), false),
            (false, None, false),
            (true, Some(RepoTrust::Transitive), false),
        ] {
            let backend = backend(open);
            let scope = match trust {
                Some(trust) => ModelScope::with_trust(&backend, LocalParents::none(), trust),
                None => ModelScope::transitive(&backend, super::RepoContext::default()),
            };
            scope.observe_repositories(&[declared_repo("declared", url)]);
            assert_eq!(shared(&backend, url), merged, "{open} {trust:?}");
            let in_build = (build_searched(&scope).iter()).any(|repo| repo.url == url);
            assert!(in_build || !open, "{trust:?}");
        }

        let backend = backend(false);
        let scope = ModelScope::with_trust(&backend, LocalParents::none(), RepoTrust::Root);
        scope.enter_import();
        scope.observe_repositories(&[declared_repo("bom", "https://bom.example/")]);
        assert_eq!(scope.import_repos.lock().unwrap()[0].added.len(), 1);
        scope.leave_import();
        assert!(scope.import_repos.lock().unwrap().is_empty());
        scope.observe_repositories(&[declared_repo("parent", "https://parent.example/")]);
        assert!(shared(&backend, "https://parent.example/"));
        assert!(!shared(&backend, "https://bom.example/"));
    }

    /// A refused declaration in an imported BOM or a transitive build keeps
    /// its id from the parent, as in the root lineage.
    #[test]
    fn a_refused_bom_repository_keeps_its_id_from_the_parent() {
        let (blocked, old) = ("http://new.example/", "https://old.example/");
        for (child_first, trust, import) in [true, false]
            .into_iter()
            .flat_map(|child_first| {
                [RepoTrust::Root, RepoTrust::Transitive].map(|trust| (child_first, trust))
            })
            .flat_map(|(child_first, trust)| {
                [true, false].map(|import| (child_first, trust, import))
            })
        {
            if trust == RepoTrust::Root && !import {
                continue;
            }
            let backend = backend(true);
            let scope = ModelScope::with_trust(&backend, LocalParents::none(), trust);
            if import {
                scope.enter_import();
            }
            if child_first {
                scope.observe_repositories(&[declared_repo("corp", blocked)]);
            }
            scope.observe_repositories(&[declared_repo("corp", old)]);
            scope
                .observe_effective_repositories(&[declared_repo("corp", blocked)])
                .unwrap();
            assert!(
                build_searched(&scope).is_empty(),
                "{child_first} {trust:?} {import}"
            );
        }
    }

    /// A declaration whose URL as written holds an expression serves no
    /// parent lookup without a mirror, but its id stays taken: a parent's
    /// declaration under it is not searched, as in Maven's model resolver.
    #[test]
    fn an_unserved_expression_repository_keeps_its_id() {
        let (written, alternate) = ("${corp.url}", "https://alternate.example/");
        let idless = |url: &str| {
            let mut repo = declared_repo("x", url);
            repo.id = None;
            repo
        };
        for import in [false, true] {
            let backend = backend(true);
            let scope =
                ModelScope::with_trust(&backend, LocalParents::none(), RepoTrust::Transitive);
            if import {
                scope.enter_import();
            }
            scope.observe_repositories(&[idless(written)]);
            scope.observe_repositories(&[idless(alternate)]);
            let mut empty = declared_repo("x", alternate);
            empty.id = Some(String::new());
            scope.observe_repositories(&[empty]);
            assert!(build_searched(&scope).is_empty(), "{import}");
        }
        for (trust, import) in [
            (RepoTrust::Root, false),
            (RepoTrust::Root, true),
            (RepoTrust::Transitive, false),
            (RepoTrust::Transitive, true),
        ] {
            let backend = backend(true);
            let scope = ModelScope::with_trust(&backend, LocalParents::none(), trust);
            if import {
                scope.enter_import();
            }
            scope.observe_repositories(&[declared_repo("corp", written)]);
            scope.observe_repositories(&[declared_repo("corp", alternate)]);
            let searched = |url: &str| {
                (build_searched(&scope).iter()).any(|repo| repo.url == url)
                    || (backend.repos_snapshot().iter()).any(|repo| repo.url == url)
            };
            assert!(!searched(alternate), "{trust:?} {import}");
            assert!(!searched(written), "{trust:?} {import}");
        }
    }
}
