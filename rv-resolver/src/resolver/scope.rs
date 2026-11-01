//! The model source one effective-model build reads its parents and
//! imported BOMs from.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use rv_maven_model::{
    ImportCoord, ImportedBom, ModelPolicy, ModelSource, Parent, ParentLookup, Pom, PomError,
    Project, Provenance, parent_has_expression,
};
use rv_maven_types::{Coord, Version, VersionReq};

use crate::context::{MissingParentKey, RepoContext};
use crate::error::ResolveError;
use crate::parent_resolver::LocalParents;
use crate::util::lock;

use super::ModelService;
use super::backend::SupportPom;

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
    /// The support POMs of the BOM [`ModelSource::reuse_import`] last
    /// returned.
    offered_reads: Mutex<Vec<Arc<SupportPom>>>,
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
            import_builds: Mutex::default(),
            left_import: Mutex::default(),
            reads: Mutex::default(),
            import_start: Mutex::default(),
            offered_reads: Mutex::default(),
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
    ) -> Result<Option<Pom>, ResolveError> {
        let reactor_side = self.trust == RepoTrust::Root;
        if let Some(pom) = self.backend.workspace_pom_for_coord(&coord, reactor_side) {
            if inherited || !reactor_side {
                self.backend.ctx.note_reactor_through_dependencies();
            }
            return Ok(Some(pom));
        }
        self.fetch_remote(coord).await
    }

    async fn fetch_remote(&self, coord: Coord) -> Result<Option<Pom>, ResolveError> {
        let ctx = &self.backend.ctx;
        let build_repos = self.build_repos();
        let search_ctx = self
            .backend
            .parent_search_context(&self.repo_ctx, &build_repos);
        let missing_key = missing_key(&coord, &search_ctx);
        if ctx.is_parent_missing(&missing_key) {
            tracing::debug!(
                group_id = %coord.group_id,
                artifact_id = %coord.artifact_id,
                version = %coord.version,
                "Parent POM known to be missing (cached)"
            );
            return Ok(None);
        }

        let fetched = match self
            .backend
            .fetch_pom_bytes(&coord, &self.repo_ctx, &build_repos)
            .await
        {
            Ok(fetched) => fetched,
            Err(ResolveError::ArtifactNotFound { .. }) => {
                ctx.mark_parent_missing(missing_key);
                tracing::debug!(
                    group_id = %coord.group_id,
                    artifact_id = %coord.artifact_id,
                    version = %coord.version,
                    "Parent POM not found, caching as missing"
                );
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let unparseable = |source: PomError| match source {
            _ if source.is_malformed_xml() => PomError::UnparseablePom {
                coord: coord.to_string(),
                source: Box::new(source),
            },
            PomError::UnsupportedEncoding(_) | PomError::Ebcdic(_) => source,
            _ => PomError::InvalidModel(format!("{coord}: {source}")),
        };
        let mut pom = ctx
            .parsed_poms()
            .parse(&fetched.blob, &fetched.bytes)
            .map(Arc::unwrap_or_clone)
            .map_err(unparseable)?;
        without_local_parent(&mut pom);
        self.add_reads([fetched]);
        Ok(Some(pom))
    }
}

impl ModelScope<'_> {
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
            self.build_repos()
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
    async fn range_coord(
        &self,
        parent: &Parent,
        range: &VersionReq,
    ) -> Result<Coord, ResolveError> {
        let coord = |version| Coord {
            group_id: parent.group_id.clone().into(),
            artifact_id: parent.artifact_id.clone().into(),
            version,
            packaging: Some("pom".to_string()),
            classifier: None,
        };
        if let Some(version) = range.exact_version() {
            return Ok(coord(version.clone()));
        }
        let not_found = || {
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
        let version = self
            .backend
            .parent_range_version(
                &parent.group_id,
                &parent.artifact_id,
                range,
                &self.repo_ctx,
                &self.build_repos(),
                self.trust == RepoTrust::Transitive,
            )
            .await?
            .ok_or_else(not_found)?;
        Ok(coord(version))
    }

    /// The repositories this build has declared, searched after the shared
    /// ones: the build's own, then each imported BOM's being built.
    fn build_repos(&self) -> Vec<rv_repo::Repository> {
        let mut build_repos = lock(&self.build_repos).repos.clone();
        build_repos.extend(
            lock(&self.import_repos)
                .iter()
                .flat_map(|list| list.repos.iter().cloned()),
        );
        build_repos
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

/// Make `kept` the last of `builds`. A build that logged is dropped once
/// another is last, as only the last is reused whatever it logged.
fn keep_last(builds: &mut Vec<Arc<KeptImport>>, kept: Arc<KeptImport>) {
    builds.retain(|other| !other.logged);
    builds.push(kept);
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
        let coord = match rv_maven_model::parent_version_range(parent) {
            Some(range) => {
                let coord = self.range_coord(parent, &range).await?;
                parent.version = coord.version.to_string();
                coord
            }
            None => parent_coord(parent)?,
        };
        let (pom, provenance) = match (self.trust, lookup) {
            (RepoTrust::Root, ParentLookup::Project) => (
                self.fetch_remote(coord).await?,
                Provenance::RemoteParentOfRoot,
            ),
            (RepoTrust::Transitive, ParentLookup::Project) => (
                self.fetch_with_workspace(coord, false).await?,
                Provenance::Dependency,
            ),
            (_, ParentLookup::Import) => (
                self.fetch_with_workspace(coord, true).await?,
                Provenance::BomImport,
            ),
        };
        Ok(fetched_from_repository(pom, provenance))
    }

    async fn import(&self, bom: ImportCoord<'_>) -> Result<Option<Pom>, ResolveError> {
        let coord = import_coord(bom)?;
        *lock(&self.import_start) = match lock(&self.import_builds).last() {
            Some(build) => build.reads.poms.len(),
            None => lock(&self.reads).poms.len(),
        };
        Ok(fetched_from_repository(
            self.fetch_with_workspace(coord, false).await?,
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
        self.observe(repositories, false);
    }

    fn observe_effective_repositories(&self, repositories: &[rv_maven_model::Repository]) {
        self.observe(repositories, true);
    }

    fn prefetch_imports(&self, imports: &[ImportCoord<'_>]) {
        let build_repos = self.build_repos();
        let search_ctx = self
            .backend
            .parent_search_context(&self.repo_ctx, &build_repos);
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
                    .prefetch_pom(&coord, &self.repo_ctx, Some(&build_repos), false);
            }
        }
    }

    fn enter_import(&self) {
        let context = self.import_context();
        let start = *lock(&self.import_start);
        let mut builds = lock(&self.import_builds);
        let mut reads = Reads::default();
        match builds.last() {
            Some(outer) => reads.add(outer.reads.poms[start..].iter().cloned()),
            None => reads.add(lock(&self.reads).poms[start..].iter().cloned()),
        }
        builds.push(ImportBuild {
            context,
            local_lookups: LocalLookups::new(),
            reads,
            logged_from: rv_maven_model::held::mark(),
            logged: false,
        });
        lock(&self.import_repos).push(BuildRepos::default());
    }

    fn leave_import(&self) {
        lock(&self.import_repos).pop();
        let mut builds = lock(&self.import_builds);
        let left = builds.pop();
        if let Some(left) = &left {
            let poms = left.reads.poms.iter().cloned();
            match builds.last_mut() {
                Some(outer) => {
                    outer.local_lookups.extend(
                        (left.local_lookups.iter())
                            .map(|(parent, found)| (parent.clone(), found.clone())),
                    );
                    outer.logged |= left.logged;
                    outer.reads.add(poms);
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
    fn reuse_import(
        &self,
        bom: ImportCoord<'_>,
        policy: ModelPolicy,
        usable: &dyn Fn(&ImportedBom) -> bool,
    ) -> Option<Arc<ImportedBom>> {
        let key = Self::import_key(bom, policy, &self.import_context());
        let builds = lock(&self.backend.kept_imports.builds).get(&key)?.clone();
        let fits = |kept: &&Arc<KeptImport>| {
            usable(&kept.imported)
                && (kept.local_lookups.iter())
                    .all(|(parent, found)| self.local.load(parent) == *found)
        };
        let kept = match builds.last().filter(fits) {
            Some(last) => Arc::clone(last),
            None => {
                let kept = builds.iter().find(|kept| !kept.logged && fits(kept))?;
                let mut kept_imports = lock(&self.backend.kept_imports.builds);
                if let Some(builds) = kept_imports.get_mut(&key)
                    && let Some(at) = builds.iter().position(|other| Arc::ptr_eq(other, kept))
                {
                    let kept = builds.remove(at);
                    keep_last(builds, kept);
                }
                Arc::clone(kept)
            }
        };
        let mut builds = lock(&self.import_builds);
        if let Some(build) = builds.last_mut() {
            build.local_lookups.extend(
                (kept.local_lookups.iter()).map(|(parent, found)| (parent.clone(), found.clone())),
            );
            build.logged |= kept.logged;
        }
        *lock(&self.offered_reads) = kept.support_poms.clone();
        Some(Arc::clone(&kept.imported))
    }

    fn reused_import(&self) -> Result<(), ResolveError> {
        let offered = std::mem::take(&mut *lock(&self.offered_reads));
        self.backend.record_kept_support_poms(&offered)?;
        self.add_reads(offered);
        Ok(())
    }

    fn keep_import(&self, bom: ImportCoord<'_>, policy: ModelPolicy, imported: Arc<ImportedBom>) {
        let Some(build) = lock(&self.left_import).take() else {
            return;
        };
        let key = Self::import_key(bom, policy, &build.context);
        let support_poms = build.reads.poms;
        let kept = Arc::new(KeptImport {
            imported,
            local_lookups: build.local_lookups,
            support_poms,
            logged: build.logged || rv_maven_model::held::logged_since(build.logged_from),
        });
        keep_last(
            lock(&self.backend.kept_imports.builds)
                .entry(key)
                .or_default(),
            kept,
        );
    }

    fn import_holds(&self) -> Option<&rv_maven_model::held::Holds> {
        let holds = &self.backend.kept_imports.holds;
        Some(holds.get_or_init(rv_maven_model::held::Holds::default))
    }
}

impl ModelScope<'_> {
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
    fn observe(&self, repositories: &[rv_maven_model::Repository], replace: bool) {
        let repos = repositories.iter().cloned().map(rv_repo::Repository::from);
        let mut imports = lock(&self.import_repos);
        if let Some(list) = imports.last_mut() {
            let (admitted, refused) = match self.trust {
                RepoTrust::Root => self.backend.admit_root_lineage(repos),
                RepoTrust::Transitive => self.backend.admit_transitive(repos, None),
            };
            list.add(admitted, replace);
            list.hold(&refused, replace);
            return;
        }
        drop(imports);
        match self.trust {
            RepoTrust::Root if replace => self.backend.extend_root_effective_repos(repos),
            RepoTrust::Root => self
                .backend
                .extend_root_lineage_repos(repositories.iter().map(|repo| {
                    (
                        rv_repo::Repository::from(repo.clone()),
                        repo.has_expression(),
                    )
                })),
            RepoTrust::Transitive => {
                let (admitted, refused) = self.backend.admit_transitive(repos, None);
                let mut build_repos = lock(&self.build_repos);
                build_repos.add(admitted, replace);
                build_repos.hold(&refused, replace);
            }
        }
    }
}

/// One build's repositories, as Maven's model resolver keeps them.
#[derive(Default)]
struct BuildRepos {
    repos: Vec<rv_repo::Repository>,
    /// Every id added so far, an absent id apart from an empty one.
    ids: HashSet<Option<String>>,
}

impl BuildRepos {
    /// Add `repos` as Maven's `addRepository` does. The list holds one
    /// repository per id, an absent id counting as the empty id, and keeps
    /// the one listed first. With `replace`, an id added before drops the
    /// repositories listed under it and the new one goes last; an absent id
    /// matches nothing there, so its first repository stays.
    fn add(&mut self, repos: Vec<rv_repo::Repository>, replace: bool) {
        for repo in repos {
            if !self.ids.insert(repo.id.clone()) {
                if !replace {
                    continue;
                }
                if let Some(id) = &repo.id {
                    self.repos
                        .retain(|known| known.id.as_deref().unwrap_or_default() != id);
                }
            }
            let key = repo.id.as_deref().unwrap_or_default();
            if !self
                .repos
                .iter()
                .any(|known| known.id.as_deref().unwrap_or_default() == key)
            {
                self.repos.push(repo);
            }
        }
    }

    /// Reserve the ids of `refused` declarations as [`Self::add`] would
    /// place them, without searching them: Maven's blocked mirror keeps the
    /// repository it replaces, so a declaration under that id elsewhere in
    /// the lineage is not searched instead. One model's declarations have
    /// distinct ids, so their order against the admitted ones is moot.
    fn hold(&mut self, refused: &[rv_repo::Repository], replace: bool) {
        for repo in refused {
            let Some(id) = repo.id.as_deref().filter(|id| !id.is_empty()) else {
                continue;
            };
            if !self.ids.insert(Some(id.to_string())) && replace {
                self.repos.retain(|known| known.id.as_deref() != Some(id));
            }
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
            matches!(error, crate::ResolveError::ConflictingResolvedPomBytes { ref coord, .. } if coord == "g:base:1"),
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
        let bom = |scope: &str| {
            format!(
                "<project><groupId>g</groupId><artifactId>bom</artifactId><version>1</version>\
                 <packaging>pom</packaging><dependencies><dependency><groupId>g</groupId>\
                 <artifactId>x</artifactId><version>1</version><scope>{scope}</scope>\
                 </dependency></dependencies><profiles><profile><id>p</id><activation>\
                 <property><name>packaging</name><value>pom</value></property></activation>\
                 </profile></profiles></project>"
            )
            .into_bytes()
        };
        for (scope, warnings, builds) in [("weird", 4, 1), ("test", 0, 2)] {
            let files = HashMap::from([("g/bom/1/bom-1.pom".to_string(), bom(scope))]);
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
            let backend = ModelService::new(&ctx, vec![repo])
                .with_reactor_models(Arc::new(Default::default()));
            let log = rv_test_support::capture_warnings(|| {
                runtime.block_on(async {
                    for packaging in ["jar", "pom", "jar", "end", "jar"] {
                        if packaging == "end" {
                            backend.release_graph_caches();
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
                        ModelScope::root(&backend, LocalParents::none())
                            .project(importer, &rv_maven_model::ActivationContext::default())
                            .await
                            .unwrap();
                    }
                })
            });
            let warned = log.matches("unknown dependency scope").count();
            assert_eq!(warned, warnings, "scope {scope}");
            let kept = crate::util::lock(&backend.kept_imports.builds)
                .values()
                .map(Vec::len)
                .sum::<usize>();
            assert_eq!(kept, builds, "scope {scope}");
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

    /// One repository per id in a build's list, an absent id counting as
    /// the empty id: a lineage list keeps the first, an effective model's
    /// replaces it unless its id is absent.
    #[test]
    fn a_builds_repositories_are_kept_one_per_id() {
        let repo = |id: Option<&str>, url: &str| {
            rv_repo::Repository::new(id.map(str::to_string), url, true, false)
        };
        let urls = |list: &super::BuildRepos| -> Vec<String> {
            list.repos.iter().map(|repo| repo.url.clone()).collect()
        };
        let mut list = super::BuildRepos::default();
        list.add(
            vec![
                repo(None, "https://first.example/"),
                repo(Some("a"), "https://a.example/"),
                repo(None, "https://second.example/"),
                repo(Some(""), "https://empty.example/"),
            ],
            false,
        );
        assert_eq!(
            urls(&list),
            ["https://first.example/", "https://a.example/"]
        );
        list.add(
            vec![
                repo(Some("a"), "https://a2.example/"),
                repo(None, "https://third.example/"),
            ],
            true,
        );
        assert_eq!(
            urls(&list),
            ["https://first.example/", "https://a2.example/"]
        );
        list.add(vec![repo(Some(""), "https://empty2.example/")], true);
        assert_eq!(
            urls(&list),
            ["https://a2.example/", "https://empty2.example/"]
        );
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
            let declarations = format!(
                r#"
                <properties><registry>{repo_url}</registry></properties>
                <profiles><profile><id>active</id><activation><activeByDefault>true</activeByDefault></activation>
                <repositories><repository><id>root</id><url>${{registry}}</url><root_declared>true</root_declared></repository></repositories>
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
            let in_build = scope
                .build_repos
                .lock()
                .unwrap()
                .repos
                .iter()
                .any(|repo| repo.url == url);
            assert!(in_build || !open, "{trust:?}");
        }

        let backend = backend(false);
        let scope = ModelScope::with_trust(&backend, LocalParents::none(), RepoTrust::Root);
        scope.enter_import();
        scope.observe_repositories(&[declared_repo("bom", "https://bom.example/")]);
        assert_eq!(scope.import_repos.lock().unwrap()[0].repos.len(), 1);
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
            scope.observe_effective_repositories(&[declared_repo("corp", blocked)]);
            assert!(
                scope.build_repos().is_empty(),
                "{child_first} {trust:?} {import}"
            );
        }
    }
}
