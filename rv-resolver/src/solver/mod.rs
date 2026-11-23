use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rv_maven_model::{ArtifactTypes, Dependency, DependencyManagement, PomError, Project, Scope};
use rv_maven_types::{BlobId, Coord, MavenMode, Version, VersionReq, bounded};

use crate::context::RepoContext;
use crate::error::{DroppedRepo, RepoSearchStatus, ResolveError, Result};
use crate::graph::{Graph, RepoRef};
use crate::util::{DynamicVersionToken, parse_dynamic_version_token};

mod bf;
mod management;
mod queue;
mod relocation;

pub(crate) use self::management::Management;
use self::management::resolve_version_str;
use self::queue::QueueItem;
pub(crate) use self::queue::{ExclusionKey, PathNode, excludes, is_legacy_core};

#[cfg(test)]
mod tests;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Whether the artifact pass leaves a file in a scope unfetched.
pub(crate) type Unfetched<'a> = dyn Fn(&Coord, Scope) -> bool + Sync + 'a;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedVersion {
    pub version: Version,
    /// The repository whose SNAPSHOT metadata named this version.
    pub repo: Option<RepoRef>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedProject {
    pub project: Arc<Project>,
    pub repo_url: Option<Arc<str>>,
    pub workspace_module: Option<String>,
}

pub(crate) trait Backend {
    /// The Maven line to resolve as.
    fn maven_mode(&self) -> MavenMode {
        MavenMode::Maven39
    }

    /// Order `versions`, a range's listing of `groupId:artifactId` sorted
    /// as Maven lists it, so a frozen replay takes the spelling each tie
    /// took, which the collector takes `first` of equal ones or last.
    fn order_taken(
        &self,
        _coordinate: (&str, &str),
        _versions: &mut [ResolvedVersion],
        _first: bool,
    ) {
    }

    /// The artifact handlers of the module being resolved.
    fn artifact_types(&self) -> ArtifactTypes {
        ArtifactTypes::core(self.maven_mode())
    }

    fn workspace_module(&self, _coord: &Coord) -> Option<String> {
        None
    }

    /// The digest of the POM the fetch of `coord` from `repos` read,
    /// `Some(None)` when it found none, and `None` without a record of the
    /// fetch. A backend without repository bytes reads none.
    fn pom_read(&self, _coord: &Coord, _repos: &RepoContext) -> Option<Option<BlobId>> {
        Some(None)
    }

    /// The repository failure met on the module's own coordinates, which a
    /// graph that takes the repository's artifact of them reports.
    fn take_own_failure(&self) -> Option<ResolveError> {
        None
    }

    /// The `<packaging>` of the reactor module `coord` names.
    fn workspace_packaging(&self, _coord: &Coord) -> Option<String> {
        None
    }

    /// Whether the selectors drop wagon providers below `coord`, as Maven
    /// does in a plugin's dependencies.
    fn drops_wagons_below(&self, _coord: &Coord) -> bool {
        false
    }

    /// Called for each reactor module read below an external dependency.
    fn note_transitive_selection(&self) {}

    fn is_reactor_module(&self, _group: &str, _artifact: &str, _version: &str) -> bool {
        false
    }

    fn resolve_version<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
        repos: &'a RepoContext,
    ) -> BoxFuture<'a, Result<ResolvedVersion>>;

    /// All matching versions in ascending Maven version order.
    /// Range alternatives are siblings and must survive until conflict mediation.
    fn resolve_versions<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
        repos: &'a RepoContext,
    ) -> BoxFuture<'a, Result<Vec<ResolvedVersion>>> {
        let resolution = self.resolve_version(group_id, artifact_id, req, repos);
        Box::pin(async move { resolution.await.map(|v| vec![v]) })
    }

    /// [`Self::resolve_versions`] for an artifact the reactor module
    /// `unbuilt` cannot serve: Maven lists a module only when it has the
    /// artifact, and the module being resolved has made none yet.
    fn resolve_versions_unbuilt<'a>(
        &'a self,
        group_id: &'a str,
        artifact_id: &'a str,
        req: &'a VersionReq,
        repos: &'a RepoContext,
        _unbuilt: &'a str,
    ) -> BoxFuture<'a, Result<Vec<ResolvedVersion>>> {
        self.resolve_versions(group_id, artifact_id, req, repos)
    }

    fn resolve_snapshot_version<'a>(
        &'a self,
        coord: &'a Coord,
        _repos: &'a RepoContext,
    ) -> BoxFuture<'a, Result<ResolvedVersion>> {
        Box::pin(async move {
            Ok(ResolvedVersion {
                version: coord.version.clone(),
                repo: None,
            })
        })
    }

    /// `resolve_snapshot_pom`: `coord` is a build SNAPSHOT metadata
    /// selected, whose POM build is resolved on its own.
    fn fetch_project<'a>(
        &'a self,
        coord: &'a Coord,
        resolve_snapshot_pom: bool,
        repos: &'a RepoContext,
    ) -> BoxFuture<'a, Result<ResolvedProject>>;

    /// Aggregate `project`'s admitted repositories onto `parent` for its
    /// children, Maven style (existing repository IDs win).
    fn extend_repo_context(
        &self,
        parent: &RepoContext,
        _coord: &Coord,
        _project: &Project,
    ) -> RepoContext {
        parent.clone()
    }

    /// Whether the backend acts on the `prefetch_*` hints, so the solver
    /// can skip working them out.
    fn prefetches(&self) -> bool {
        true
    }

    /// `coord` is queued and [`Backend::fetch_project`] will likely be
    /// asked for it, so the backend may start fetching. A hint only.
    fn prefetch_project(&self, _coord: &Coord, _repos: &RepoContext) {}

    /// `coord` is queued where the graph likely keeps it at that version,
    /// so its artifact will likely be fetched once its POM is read, and the
    /// backend may start downloading it then. A hint only.
    fn prefetch_kept_artifact(&self, _coord: &Coord, _repos: &RepoContext) {}

    /// `coord` is a version of a range the solver reads, and Maven reads
    /// each one up to the first that relocates, so the backend may fetch
    /// it ahead of the guesses [`Backend::prefetch_project`] names. A hint
    /// only.
    fn prefetch_range_version(&self, coord: &Coord, repos: &RepoContext) {
        self.prefetch_project(coord, repos);
    }

    /// A queued declaration reads the versions of `group_id:artifact_id`
    /// that `req` accepts, so the backend may list them and fetch each as
    /// [`Backend::prefetch_range_version`] does. A hint only.
    fn prefetch_range(
        &self,
        _group_id: &str,
        _artifact_id: &str,
        _req: &VersionReq,
        _repos: &RepoContext,
    ) {
    }

    /// `coord` entered the graph, served by `repo_url`, or built by
    /// `build_repo` alone, and its artifact will likely be fetched, so the
    /// backend may start downloading it. A hint only.
    fn prefetch_artifact(
        &self,
        _coord: &Coord,
        _build_repo: Option<&RepoRef>,
        _repo_url: Option<&str>,
        _repos: &RepoContext,
    ) {
    }

    /// Transitive repositories that were ignored but declared by a POM on
    /// `path` (`group:artifact:version`, root first) and could serve
    /// `version`.
    fn dropped_repos_on_path(
        &self,
        _path: &[String],
        _version: &str,
        _searched: &[RepoSearchStatus],
    ) -> Vec<DroppedRepo> {
        Vec::new()
    }

    /// Maven reads `coord`'s POM for a node that lost mediation, offline
    /// too.
    fn note_loser(&self, _coord: &Coord) {}

    /// `coord` won mediation through a declaration below `path`.
    fn note_winner(&self, _coord: &Coord, _path: &Arc<PathNode>) -> Result<()> {
        Ok(())
    }
}

pub(crate) struct Solver<'a, B: Backend> {
    backend: &'a B,
    management: Management,
    /// Whether Maven collects depth first, the default of Maven 3.9 only.
    depth_first: bool,
    /// Whether the artifact pass leaves out a node's file, by its
    /// coordinates and derived scope: no hint may fetch one.
    unfetched: Option<&'a Unfetched<'a>>,
}

#[derive(Debug, Clone)]
pub(crate) struct SolverRoot {
    pub coord: Coord,
    pub dependencies: Vec<Dependency>,
    pub scope: Scope,
}

impl<'a, B: Backend> Solver<'a, B> {
    pub(crate) fn new(backend: &'a B) -> Self {
        Self {
            backend,
            management: Management::default(),
            depth_first: backend.maven_mode() == MavenMode::Maven39,
            unfetched: None,
        }
    }

    /// Leave the files `unfetched` names unhinted, as the artifact pass
    /// leaves them out.
    pub(crate) fn unfetched(mut self, unfetched: &'a Unfetched<'a>) -> Self {
        self.unfetched = Some(unfetched);
        self
    }

    pub(crate) fn with_management(mut self, management: Management) -> Self {
        self.management = management;
        self
    }

    /// Collect breadth first, or depth first, whatever the Maven line, as
    /// `-Daether.dependencyCollector.impl=bf` or `df` makes Maven do.
    pub(crate) fn breadth_first(mut self, breadth_first: bool) -> Self {
        self.depth_first = !breadth_first;
        self
    }

    fn mode(&self) -> MavenMode {
        self.backend.maven_mode()
    }

    fn types(&self) -> ArtifactTypes {
        self.backend.artifact_types()
    }

    pub(crate) async fn solve(&self, root: SolverRoot) -> Result<Graph> {
        bf::solve(self, root).await
    }

    /// Fail where [`Self::solve`] fails on `root`'s own dependencies before
    /// it reads any of them.
    pub(crate) fn check_root(&self, root: SolverRoot) -> Result<()> {
        bf::check_root(self, root)
    }
}

#[derive(Debug, Clone)]
enum RequestedRequirement {
    Exact(Version),
    /// A range whose bounds are one version it does not admit, as `(1,1)`:
    /// Maven's range resolver takes that version, and mediation refuses it.
    Unadmitted(Version, VersionReq),
    /// A bare `<version>X</version>` that no management covered: a Maven
    /// soft pin, which mediation may move.
    Soft(Version),
    Ranges(VersionReq),
    Dynamic(DynamicVersionToken),
}

/// Apply the root management as Maven's ClassicDependencyManager does: its
/// exclusions join those of every dependency, direct ones included, while its
/// scope, optional and system path apply from depth 2, since the model layer
/// manages depth 1. The selectors test the declared values first, so a
/// dependency managed to `test` keeps its subtree, and a managed
/// `<optional>` only marks the edge.
fn apply_managed_metadata(management: &Management, mut item: QueueItem) -> QueueItem {
    let Some(managed) = management.managed(&item.dependency) else {
        return item;
    };
    if ((managed.scope.is_none() && managed.optional.is_none()) || item.depth <= 1)
        && managed.exclusions.is_empty()
    {
        return item;
    }
    item.managed_scope |= manage(managed, Arc::make_mut(&mut item.dependency), item.depth);
    item
}

/// Whether the scope was managed.
fn manage(managed: &Dependency, dep: &mut Dependency, depth: usize) -> bool {
    if depth > 1 && managed.optional.is_some() {
        dep.optional.clone_from(&managed.optional);
    }
    let scope = managed.scope.as_ref().filter(|_| depth > 1);
    if let Some(scope) = scope {
        dep.scope = Some(scope.clone());
        // A dependency managed to `system` takes the managed `<systemPath>`;
        // one managed elsewhere loses its own.
        if dep.declares_system_scope() {
            if managed.system_path.is_some() {
                dep.system_path.clone_from(&managed.system_path);
                dep.system_path_from_project = managed.system_path_from_project;
            }
        } else {
            dep.system_path = None;
        }
    }
    for exclusion in &managed.exclusions {
        if !dep.exclusions.contains(exclusion) {
            dep.exclusions.push(exclusion.clone());
        }
    }
    scope.is_some()
}

/// Whether Maven collects what `dependency` declares: not for a system
/// file, nor, by its FatArtifactTraverser, for a type whose handler says
/// it carries its dependencies inside, as `war`, `ear` and `rar` do.
fn follows(dependency: &Dependency, types: &ArtifactTypes) -> bool {
    !dependency.includes_dependencies_in(types) && dependency.effective_scope() != Scope::System
}

const MAX_RELOCATION_MANAGEMENT_PASSES: usize = 8;

fn coord_of(dependency: &Dependency, version: Version, types: &ArtifactTypes) -> Coord {
    let type_ = dependency.effective_type_in(types);
    Coord {
        group_id: dependency.group_id.as_str().into(),
        artifact_id: dependency.artifact_id.as_str().into(),
        version,
        packaging: (type_ != "jar").then(|| type_.to_string()),
        classifier: dependency
            .effective_classifier_in(types)
            .map(str::to_string),
    }
}

/// Whether a `${...}` is left in the group, artifact or version of `coord`.
fn names_property(coord: &Coord) -> bool {
    [
        coord.group_id.as_str(),
        coord.artifact_id.as_str(),
        coord.version.as_str(),
    ]
    .iter()
    .any(|part| part.contains("${"))
}

/// Fail on a `${...}` left in `item`'s coordinate, naming the POM that
/// declared it. Maven fails only on a dependency it keeps, and a module's
/// own dependency is always kept, so its type and classifier count too,
/// unless the reactor builds it; a transitive one's are checked once
/// mediation has kept it.
fn refuse_undefined_property<B: Backend>(
    solver: &Solver<'_, B>,
    item: &QueueItem,
    version_str: &str,
) -> Result<()> {
    let dependency = &item.dependency;
    let (group, artifact) = (&dependency.group_id, &dependency.artifact_id);
    let mut coord = format!("{group}:{artifact}:{version_str}");
    // A range or LATEST/RELEASE may select a reactor module, whose
    // artifact is never fetched, and a POM may relocate into one, whose POM
    // Maven's reactor serves whatever the classifier; those wait for the
    // selected node.
    let exact = !version_str.contains(['[', '('])
        && !matches!(version_str, "LATEST" | "RELEASE")
        && dependency.effective_type_in(&solver.types()) != "pom";
    if item.depth == 1
        && exact
        && !solver
            .backend
            .is_reactor_module(group, artifact, version_str)
    {
        let types = solver.types();
        let type_ = dependency.effective_type_in(&types);
        let packaging = if type_ == "jar" { "" } else { type_ };
        match dependency.effective_classifier_in(&types) {
            Some(classifier) => coord.push_str(&format!(":{packaging}:{classifier}")),
            None if !packaging.is_empty() => coord.push_str(&format!(":{packaging}")),
            None => {}
        }
    }
    let Some(property) = crate::error::undefined_property(&coord) else {
        return Ok(());
    };
    // A version the root's management gave is the root's.
    let managed = crate::error::undefined_property(&format!("{group}:{artifact}")).is_none()
        && dependency.version.as_deref() != Some(version_str);
    let mut declaring = item.path.as_ref();
    if managed {
        while let Some(parent) = declaring.parent.as_deref() {
            declaring = parent;
        }
    }
    let declared_by = declaring.coordinates().pop().unwrap_or_default();
    let module = Coord::parse(&declared_by)
        .ok()
        .and_then(|declaring| solver.backend.workspace_module(&declaring));
    Err(ResolveError::UndefinedProperty {
        property: property.to_string(),
        declared_by: module.unwrap_or(declared_by),
        coord,
    })
}

/// The requirement `version` states for `group_id:artifact_id`, the versions
/// it admits below the highest, and the highest. A range leaves out the
/// reactor module `unbuilt`.
async fn requested_versions<B: Backend>(
    solver: &Solver<'_, B>,
    group_id: &str,
    artifact_id: &str,
    version: &str,
    repos: &RepoContext,
    unbuilt: Option<&str>,
) -> Result<(RequestedRequirement, Vec<ResolvedVersion>, ResolvedVersion)> {
    let requirement = parse_requested_requirement(group_id, artifact_id, version, solver.mode())?;
    let mut versions =
        resolve_requirement_versions(solver, group_id, artifact_id, &requirement, repos, unbuilt)
            .await?;
    let highest = versions
        .pop()
        .ok_or_else(|| ResolveError::VersionNotFound {
            coord: format!("{group_id}:{artifact_id}"),
            requirement: version.to_string(),
        })?;
    Ok((requirement, versions, highest))
}

/// Refuse a system dependency without a path: raeva neither coins a version
/// nor locks a row with no file and no repository.
fn check_system_path(dependency: &Dependency) -> Result<()> {
    if (dependency.system_path.as_deref()).is_none_or(|path| path.trim().is_empty()) {
        return Err(PomError::InvalidSystemPath(format!(
            "system-scoped dependency {}:{} requires a non-empty <systemPath>",
            bounded(&dependency.group_id),
            bounded(&dependency.artifact_id)
        ))
        .into());
    }
    Ok(())
}

async fn resolve_requirement_versions<B: Backend>(
    solver: &Solver<'_, B>,
    group_id: &str,
    artifact_id: &str,
    requirement: &RequestedRequirement,
    repos: &RepoContext,
    unbuilt: Option<&str>,
) -> Result<Vec<ResolvedVersion>> {
    let marker = match requirement {
        RequestedRequirement::Exact(version)
        | RequestedRequirement::Soft(version)
        | RequestedRequirement::Unadmitted(version, _) => {
            return Ok(vec![ResolvedVersion {
                version: version.clone(),
                repo: None,
            }]);
        }
        RequestedRequirement::Ranges(req) => {
            let backend = &solver.backend;
            return match unbuilt {
                Some(module) => {
                    (backend.resolve_versions_unbuilt(group_id, artifact_id, req, repos, module))
                        .await
                }
                None => {
                    backend
                        .resolve_versions(group_id, artifact_id, req, repos)
                        .await
                }
            };
        }
        RequestedRequirement::Dynamic(token) => token.requirement_label(),
    };
    let req = VersionReq::Exact(Version::parse(marker)?);
    let resolved = solver
        .backend
        .resolve_version(group_id, artifact_id, &req, repos)
        .await?;
    Ok(vec![resolved])
}

/// `err`, from reading `coord` (`group:artifact:version`) below `path`. A
/// fault in the candidate's own model, such as a missing parent, does not
/// name the candidate, nor the relocation target whose model it is, which
/// the relocation fetch put below it.
fn load_error(path: &PathNode, coord: String, err: ResolveError) -> ResolveError {
    let (target, err) = match err {
        ResolveError::Declared { module, via, error } if module.is_empty() => (via, *error),
        err => (Vec::new(), err),
    };
    let own = matches!(err.cause(), ResolveError::Pom(_));
    let mut via = path.coordinates();
    via.remove(0);
    via.extend(own.then_some(coord));
    via.extend(target);
    err.declared_via(via)
}

/// `err`, for a dependency that the last POM on `path` declares.
fn declared_below(err: ResolveError, path: &PathNode) -> ResolveError {
    let mut via = path.coordinates();
    via.remove(0);
    err.declared_via(via)
}

/// Name the ignored transitive repositories that could have served a
/// not-found dependency: those declared by a POM on its path from the root.
fn attach_dropped_repos<B: Backend>(
    solver: &Solver<'_, B>,
    item: &QueueItem,
    coord: &Coord,
    err: ResolveError,
) -> ResolveError {
    let ResolveError::ArtifactNotFound {
        coord: failed,
        searched,
        mut dropped_repos,
        classifier_like,
    } = err
    else {
        return err;
    };
    dropped_repos.extend(solver.backend.dropped_repos_on_path(
        &item.path.coordinates(),
        &coord.version.to_string(),
        &searched,
    ));
    ResolveError::ArtifactNotFound {
        coord: failed,
        searched,
        dropped_repos,
        classifier_like,
    }
}

fn parse_requested_requirement(
    group_id: &str,
    artifact_id: &str,
    raw_version: &str,
    mode: MavenMode,
) -> Result<RequestedRequirement> {
    let trimmed = raw_version.trim();
    let invalid = || ResolveError::InvalidVersionRequirement {
        coord: format!("{group_id}:{artifact_id}"),
        value: trimmed.to_string(),
    };
    if let Some(token) = parse_dynamic_version_token(trimmed) {
        return Ok(RequestedRequirement::Dynamic(token));
    }
    // Gradle's dynamic versions; `1.0+b1` is a plain Maven version.
    if trimmed.ends_with('+') || trimmed.to_ascii_lowercase().starts_with("latest.") {
        return Err(invalid());
    }
    let req = VersionReq::parse_in(trimmed, mode).map_err(|_| invalid())?;
    // DefaultVersionRangeResolver takes a range whose bounds are equal, as
    // `[1,1]` or `[1]`, as that one version without reading metadata.
    if let Some(version) = req.exact_version_in(mode) {
        if !req.matches_in(version, mode) {
            return Ok(RequestedRequirement::Unadmitted(version.clone(), req));
        }
        return Ok(RequestedRequirement::Exact(version.clone()));
    }
    Ok(match req {
        VersionReq::Soft(version) => RequestedRequirement::Soft(version),
        req => RequestedRequirement::Ranges(req),
    })
}

/// The range or `[x]` pin `requirement` constrains its group to.
fn hard_constraint(requirement: &RequestedRequirement) -> Option<VersionReq> {
    match requirement {
        RequestedRequirement::Ranges(range) | RequestedRequirement::Unadmitted(_, range) => {
            Some(range.clone())
        }
        RequestedRequirement::Exact(version) => Some(VersionReq::Exact(version.clone())),
        _ => None,
    }
}

/// Fill a child dependency's missing version, and its scope when it has
/// none, from a resolved artifact's effective dependencyManagement, matched
/// by Maven's management key `(groupId, artifactId, type, classifier)` under
/// the handlers of `types`: the first matching entry that carries a version.
fn manage_child(mgmt: &DependencyManagement, dep: &mut Dependency, types: &ArtifactTypes) {
    let Some(managed) = mgmt.dependencies.iter().find(|managed| {
        managed.version.is_some()
            && managed.group_id == dep.group_id
            && managed.artifact_id == dep.artifact_id
            && managed.effective_type_in(types) == dep.effective_type_in(types)
            && managed.effective_classifier_in(types) == dep.effective_classifier_in(types)
    }) else {
        return;
    };
    dep.version.clone_from(&managed.version);
    if dep.scope.is_none() {
        dep.scope.clone_from(&managed.scope);
    }
}

fn fixed_coord(
    dependency: &Dependency,
    requirement: RequestedRequirement,
    types: &ArtifactTypes,
) -> Option<Coord> {
    let (RequestedRequirement::Exact(version)
    | RequestedRequirement::Soft(version)
    | RequestedRequirement::Unadmitted(version, _)) = requirement
    else {
        return None;
    };
    if rv_maven_types::resolves_through_snapshot_metadata(version.as_str()) {
        return None;
    }
    Some(coord_of(dependency, version, types))
}
