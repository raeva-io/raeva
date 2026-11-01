use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use indexmap::IndexMap;
use petgraph::graph::NodeIndex;
use rv_maven_model::{Dependency, DependencyManagement, PomError, Project, Scope};
use rv_maven_types::{Coord, Version, VersionReq, bounded};

use crate::context::RepoContext;
use crate::error::{DroppedRepo, RepoSearchStatus, ResolveError, Result};
use crate::graph::{CoordKey, Edge, Graph, Node, RepoRef, same_text};
use crate::util::{DynamicVersionToken, parse_dynamic_version_token};

mod management;
mod queue;
mod relocation;

pub(crate) use self::management::Management;
use self::management::resolve_version_str;
pub(crate) use self::queue::{ExclusionKey, PathNode, excludes};
use self::queue::{
    QueueItem, ShadowOrigin, SortKey, TreeOrder, extend_exclusions, is_excluded, push_queue,
};
use self::relocation::RelocationCache;

#[cfg(test)]
mod tests;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
    fn workspace_module(&self, _coord: &Coord) -> Option<String> {
        None
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

    /// `coord` entered the graph, served by `repo_url`, and its artifact
    /// will likely be fetched, so the backend may start downloading it. A
    /// hint only.
    fn prefetch_artifact(&self, _coord: &Coord, _repo_url: Option<&str>, _repos: &RepoContext) {}

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

    /// `coord` won mediation through a declaration below `path`.
    fn note_winner(&self, _coord: &Coord, _path: &Arc<PathNode>) -> Result<()> {
        Ok(())
    }
}

pub(crate) struct Solver<'a, B: Backend> {
    backend: &'a B,
    management: Management,
}

#[derive(Debug, Clone)]
pub(crate) struct SolverRoot {
    pub coord: Coord,
    pub dependencies: Vec<Dependency>,
    pub scope: Scope,
}

const MAX_WINNER_CHANGES: u32 = 256;

const ROOT_GENERATION: u64 = 1;

struct Walk {
    graph: Graph,
    /// The generation of each node's winner, by node index. A node takes a
    /// new one whenever its winner changes or it leaves the resolution,
    /// which makes the declarations of the previous winner stale.
    generations: Vec<u64>,
    next_generation: u64,
    selected: HashMap<CoordKey, Selected>,
    groups: HashMap<CoordKey, CoordKey>,
    declared: HashMap<NodeIndex, Vec<CoordKey>>,
    shadows: HashMap<CoordKey, Vec<CoordKey>>,
    /// Groups to mediate again, in declaration order.
    dirty: VecDeque<CoordKey>,
    /// Membership for [`Self::dirty`]. Keeps `contains` O(1).
    dirty_set: HashSet<CoordKey>,
    queue: BinaryHeap<QueueItem>,
    next_declared_at: u64,
    /// Range declarations of a shadow walk, to load and walk: each one's
    /// candidates, from the lowest version up.
    walk_loads: Vec<Vec<Arc<Candidate>>>,
    confirm: Vec<(CoordKey, Arc<Candidate>, usize)>,
    /// The highest candidates of range declarations whose versions are not
    /// loaded yet, in declaration order.
    unscanned: VecDeque<(CoordKey, Arc<Candidate>)>,
    /// Declarations before this one were hinted to the backend.
    hinted: u64,
    relocations: RelocationCache,
}

impl<'a, B: Backend> Solver<'a, B> {
    pub(crate) fn new(backend: &'a B) -> Self {
        Self {
            backend,
            management: Management::default(),
        }
    }

    pub(crate) fn with_management(mut self, management: Management) -> Self {
        self.management = management;
        self
    }

    pub(crate) async fn solve(&self, root: SolverRoot) -> Result<Graph> {
        let SolverRoot {
            coord,
            dependencies,
            scope,
        } = root;
        let path = PathNode::root(&coord);
        let mut walk = Walk::new(Graph::new(Node {
            workspace_module: self.backend.workspace_module(&coord),
            coord,
            scope,
            repo_url: None,
            build_repo: None,
            repos: RepoContext::default(),
            checksum: None,
            local: false,
            system_path: None,
            winner_parent: None,
        }));
        let exclusions: Arc<[ExclusionKey]> = Arc::from(Vec::new());
        for (index, dependency) in dependencies.into_iter().enumerate() {
            let item = QueueItem {
                parent: walk.graph.root(),
                parent_generation: ROOT_GENERATION,
                dependency: Arc::new(dependency),
                managed_scope: false,
                depth: 1,
                order: TreeOrder::default().child(index),
                declared_at: walk.declare(),
                exclusions: Arc::clone(&exclusions),
                path: Arc::clone(&path),
                shadow: None,
            };
            // Before any of them is read, so the module's dependencies
            // download nothing first.
            let managed = apply_managed_metadata(&self.management, item.clone());
            if managed.dependency.effective_scope() != Scope::Import {
                let version = resolve_version_str(&self.management, &managed.dependency, 1)?;
                refuse_undefined_property(self, &managed, version)?;
            }
            push_queue(&mut walk.queue, item)?;
        }
        // Items are read one at a time, in queue order, and each is mediated
        // before the next is read, as Maven collects: what a read records or
        // logs, and which reads happen at all, follow from the graph alone.
        // The backend prefetches the POMs of queued items concurrently.
        loop {
            self.hint_queued(&mut walk);
            let Some(item) = walk.queue.pop() else {
                if walk.walk_excluded_dependencies(self.backend)? {
                    continue;
                }
                return walk.finish(self.backend);
            };
            self.hint_queued(&mut walk);
            let outcome = resolve_item(self, item.clone(), &walk.relocations)
                .await
                .map_err(|err| declared_below(err, &item.path));
            self.mediate(&mut walk, item, outcome).await?;
        }
    }

    /// Tell the backend which POMs the items queued since the last hint will
    /// fetch, in the order the queue hands them out.
    fn hint_queued(&self, walk: &mut Walk) {
        if walk.hinted >= walk.next_declared_at || !self.backend.prefetches() {
            return;
        }
        let mut fresh: Vec<&QueueItem> = walk
            .queue
            .iter()
            .filter(|item| item.declared_at >= walk.hinted)
            .collect();
        fresh.sort_by(|a, b| b.cmp(a));
        for item in fresh {
            match prefetch_requirement(item, &self.management) {
                Some((dependency, RequestedRequirement::Ranges(req))) => {
                    self.backend.prefetch_range(
                        &dependency.group_id,
                        &dependency.artifact_id,
                        &req,
                        &item.path.repos,
                    )
                }
                Some((dependency, requirement)) => {
                    if let Some(coord) = fixed_coord(&dependency, requirement) {
                        self.backend.prefetch_project(&coord, &item.path.repos);
                    }
                }
                None => {}
            }
        }
        walk.hinted = walk.next_declared_at;
    }

    /// Tell the backend which POMs the children of `item` will fetch, as
    /// soon as its `project` is built: they are queued only once it wins.
    fn hint_children(&self, item: &QueueItem, coord: &Coord, project: &Project) {
        if !self.backend.prefetches() {
            return;
        }
        let child_repos = self
            .backend
            .extend_repo_context(&item.path.repos, coord, project);
        let exclusions = extend_exclusions(&item.exclusions, &item.dependency.exclusions);
        for dependency in &project.dependencies {
            let mut dependency = dependency.clone();
            if dependency.version.is_none() {
                dependency.version =
                    managed_child_version(&project.dependency_management, &dependency);
            }
            let child = QueueItem {
                dependency: Arc::new(dependency),
                depth: item.depth + 1,
                exclusions: Arc::clone(&exclusions),
                ..item.clone()
            };
            if let Some(coord) = prefetch_coord(&child, &self.management) {
                self.backend.prefetch_project(&coord, &child_repos);
            }
        }
    }

    async fn mediate(
        &self,
        walk: &mut Walk,
        item: QueueItem,
        outcome: Result<Option<Resolution>>,
    ) -> Result<()> {
        // An item that went stale while queued is read too: Maven reads the
        // subtree of a candidate that loses later. Its result is dropped,
        // failures included.
        if !walk.is_live(&item) {
            return Ok(());
        }
        match outcome? {
            None => {}
            Some(resolution) => walk.add_resolution(self.backend, resolution)?,
        }
        loop {
            if let Some((key, candidate)) = walk.unscanned.pop_front() {
                let key = walk.group_of(&key);
                if walk.holds(&key, &candidate) {
                    self.load(walk, &key, candidate).await?;
                }
            // Maven's dirty tree has a range's subtree too, so a walk reads
            // the range as a declaration does and walks each version it
            // reads.
            } else if let Some(probes) = walk.walk_loads.pop() {
                let loads = self.load_in_order(&probes, &walk.relocations).await;
                for loaded in loads {
                    match loaded? {
                        Load::Ready(candidate) => walk.add_resolution(
                            self.backend,
                            Resolution {
                                candidate,
                                alternatives: Vec::new(),
                                aliases: Vec::new(),
                            },
                        )?,
                        Load::Relocated(resolution) | Load::Cyclic(resolution) => {
                            walk.add_resolution(self.backend, resolution)?
                        }
                        Load::Excluded => {}
                    }
                }
            } else if !walk.confirm.is_empty() {
                for (key, candidate, from) in std::mem::take(&mut walk.confirm) {
                    self.confirm(walk, key, candidate, from).await?;
                }
            } else if let Some(key) = walk.take_dirty() {
                self.reconsider(walk, key).await?;
            } else {
                return Ok(());
            }
        }
    }

    /// Mediate a group again: the nearest candidate that every hard
    /// constraint accepts wins. A winner whose project is not loaded yet, a
    /// range's alternative, is loaded first and may relocate.
    async fn reconsider(&self, walk: &mut Walk, key: CoordKey) -> Result<()> {
        loop {
            let key = walk.group_of(&key);
            let Some(selection) = walk.selected.get_mut(&key) else {
                return Ok(());
            };
            selection.settled = None;
            if selection.candidates.iter().all(|c| c.item.shadow.is_some()) {
                walk.drop_group(&key);
                return Ok(());
            }
            let best = selection.best();
            // A range whose lowest version relocates has no hard constraint
            // left, so the ranges that decide the mediation load that first.
            let unconfirmed = selection.unconfirmed(best.as_deref());
            let dirty = best
                .as_ref()
                .map(|best| selection.dirty_ranges(best))
                .unwrap_or_default();
            if !unconfirmed.is_empty() {
                for candidate in unconfirmed {
                    let key = walk.group_of(&key);
                    if walk.holds(&key, &candidate) {
                        self.load(walk, &key, candidate).await?;
                    }
                }
                continue;
            }
            let Some(best) = best else {
                // Maven reports a conflict only once every candidate is in;
                // a later eviction may still remove the constraint.
                selection.note_conflict();
                return Ok(());
            };
            // Maven's dirty tree still reads a losing range's preferred
            // version when that range already accepts the nearer winner. A
            // Ready result is only a probe.
            if !dirty.is_empty() {
                let mut relocated = false;
                for candidate in dirty {
                    let key = walk.group_of(&key);
                    if !walk.holds(&key, &candidate) {
                        continue;
                    }
                    let declared_at = candidate.item.declared_at;
                    // Another declaration in the same repository context may
                    // already have loaded this version.
                    let already = walk.selected.get(&key).is_some_and(|selection| {
                        selection.candidates.iter().any(|c| {
                            same_text(&c.coord, &candidate.coord)
                                && c.item.path.repos == candidate.item.path.repos
                                && c.resolved_project.is_some()
                        })
                    });
                    if already {
                        if let Some(selection) = walk.selected.get_mut(&key) {
                            selection.dirty_checked.insert(declared_at);
                        }
                        continue;
                    }
                    match load_candidate(self, candidate.as_ref().clone(), &walk.relocations)
                        .await?
                    {
                        Load::Relocated(_) | Load::Cyclic(_) => {
                            self.load(walk, &key, candidate).await?;
                            relocated = true;
                        }
                        Load::Ready(_) | Load::Excluded => {
                            if let Some(selection) = walk.selected.get_mut(&key) {
                                selection.dirty_checked.insert(declared_at);
                            }
                        }
                    }
                }
                if relocated {
                    continue;
                }
            }
            let selection = walk.selected.get_mut(&key).expect("mediated group");
            selection.conflict = None;
            if let Some(winner) = &selection.winner
                && winner.same(&best)
            {
                // A declaration took the place of its own shadow.
                selection.winner = Some(best);
                selection.settle();
                walk.scan_losers(self.backend, &key, 0)?;
                return Ok(());
            }
            if best.resolved_project.is_none() {
                self.load(walk, &key, best).await?;
                continue;
            }
            walk.commit(self.backend, &key, best)?;
            if let Some(selection) = walk.selected.get_mut(&key) {
                selection.settle();
            }
            walk.scan_losers(self.backend, &key, 0)?;
            return Ok(());
        }
    }
}

impl<B: Backend> Solver<'_, B> {
    async fn confirm(
        &self,
        walk: &mut Walk,
        key: CoordKey,
        candidate: Arc<Candidate>,
        from: usize,
    ) -> Result<()> {
        let key = walk.group_of(&key);
        if let Some(index) = walk.pending(&key, &candidate, from)
            && let Load::Ready(loaded) =
                load_candidate(self, candidate.as_ref().clone(), &walk.relocations).await?
        {
            walk.selected.get_mut(&key).expect("pending").candidates[index] = Arc::new(loaded);
            return walk.scan_losers(self.backend, &key, from);
        }
        walk.mark_dirty(key);
        Ok(())
    }

    async fn load(&self, walk: &mut Walk, key: &CoordKey, candidate: Arc<Candidate>) -> Result<()> {
        let Some(relocated) = self.load_one(walk, key, candidate).await? else {
            return Ok(());
        };
        let others: Vec<_> = walk
            .selected
            .get(&walk.group_of(key))
            .into_iter()
            .flat_map(|selection| &selection.candidates)
            .filter(|c| c.resolved_project.is_none() && same_text(&c.coord, &relocated.coord))
            .cloned()
            .collect();
        for other in others {
            let key = walk.group_of(key);
            if walk.holds(&key, &other) {
                self.load_one(walk, &key, other).await?;
            }
        }
        Ok(())
    }

    /// Load a candidate of the group `key`, and return the candidate that
    /// relocated, if one did. Maven 3.9 reads every version of a range, from
    /// the lowest up, and stops at the first that relocates, so the versions
    /// of the range below this one are loaded first, in that order.
    async fn load_one(
        &self,
        walk: &mut Walk,
        key: &CoordKey,
        candidate: Arc<Candidate>,
    ) -> Result<Option<Arc<Candidate>>> {
        let prefix = &candidate.source[..candidate.source.len() - 1];
        let mut lower: Vec<Arc<Candidate>> = walk.selected[key]
            .candidates
            .iter()
            .filter(|c| {
                c.item.declared_at == candidate.item.declared_at
                    && c.resolved_project.is_none()
                    && c.source.len() == candidate.source.len()
                    && c.source[..c.source.len() - 1] == *prefix
                    && c.source < candidate.source
            })
            .cloned()
            .collect();
        lower.sort_by(|a, b| a.source.cmp(&b.source));
        lower.push(candidate);
        let loads = self.load_in_order(&lower, &walk.relocations).await;
        let complete = loads.len() == lower.len();
        let last = lower.len() - 1;
        for (index, (probe, loaded)) in lower.into_iter().zip(loads).enumerate() {
            // A cyclic load can merge the group into another or drop
            // candidates; the walk goes on with those left.
            let key = walk.group_of(key);
            if !walk.holds(&key, &probe) {
                if index == last {
                    walk.mark_dirty(key);
                }
                continue;
            }
            let loaded = loaded?;
            let relocated = !matches!(loaded, Load::Ready(_) | Load::Cyclic(_));
            walk.apply_load(self.backend, &key, &probe, loaded)?;
            if relocated {
                return Ok(Some(probe));
            }
        }
        // The load that stopped the rest was of a version no longer held,
        // so the group is mediated again with those left.
        if !complete {
            walk.mark_dirty(walk.group_of(key));
        }
        Ok(None)
    }

    /// Load a range's candidates, from the lowest version up, and return the
    /// results in order through the first that relocates, is excluded or
    /// fails. Maven reads no version above that one, and what a load reads
    /// goes into the lock, so they load one at a time; the range's POMs are
    /// already being fetched.
    async fn load_in_order(
        &self,
        probes: &[Arc<Candidate>],
        relocations: &RelocationCache,
    ) -> Vec<Result<Load>> {
        let mut results = Vec::new();
        for probe in probes {
            let loaded = load_candidate(self, probe.as_ref().clone(), relocations).await;
            let stops = !matches!(loaded, Ok(Load::Ready(_) | Load::Cyclic(_)));
            results.push(loaded);
            if stops {
                break;
            }
        }
        results
    }
}

enum ShadowRole {
    Candidate,
    Walk,
    Drop,
}

impl Walk {
    fn new(graph: Graph) -> Self {
        Self {
            graph,
            generations: vec![ROOT_GENERATION],
            next_generation: ROOT_GENERATION + 1,
            selected: HashMap::new(),
            groups: HashMap::new(),
            declared: HashMap::new(),
            shadows: HashMap::new(),
            dirty: VecDeque::new(),
            dirty_set: HashSet::new(),
            queue: BinaryHeap::new(),
            next_declared_at: 0,
            walk_loads: Vec::new(),
            confirm: Vec::new(),
            unscanned: VecDeque::new(),
            hinted: 0,
            relocations: Mutex::new(HashMap::new()),
        }
    }

    fn declare(&mut self) -> u64 {
        self.next_declared_at += 1;
        self.next_declared_at - 1
    }

    /// Enqueue `key` for mediation if it is not already queued.
    fn mark_dirty(&mut self, key: CoordKey) {
        if self.dirty_set.insert(key.clone()) {
            self.dirty.push_back(key);
        }
    }

    /// Take the next group that needs mediation.
    fn take_dirty(&mut self) -> Option<CoordKey> {
        let key = self.dirty.pop_front()?;
        self.dirty_set.remove(&key);
        Some(key)
    }

    fn is_dirty(&self, key: &CoordKey) -> bool {
        self.dirty_set.contains(key)
    }

    fn generation(&mut self) -> u64 {
        self.next_generation += 1;
        self.next_generation - 1
    }

    fn add_node(&mut self, node: Node) -> NodeIndex {
        let index = self.graph.insert_node(node);
        let generation = self.generation();
        self.generations.push(generation);
        debug_assert_eq!(self.generations.len(), index.index() + 1);
        index
    }

    fn group_of(&self, key: &CoordKey) -> CoordKey {
        let mut key = key;
        while let Some(next) = self.groups.get(key) {
            key = next;
        }
        key.clone()
    }

    fn is_live(&self, item: &QueueItem) -> bool {
        match &item.shadow {
            None => self.generations[item.parent.index()] == item.parent_generation,
            Some(origin) => self
                .selected
                .get(&self.group_of(&origin.group))
                .is_some_and(|selection| selection.instance(origin).is_some()),
        }
    }

    fn holds(&self, key: &CoordKey, candidate: &Arc<Candidate>) -> bool {
        self.selected.get(key).is_some_and(|selection| {
            selection
                .candidates
                .iter()
                .any(|c| Arc::ptr_eq(c, candidate))
        })
    }

    fn add_resolution<B: Backend>(&mut self, backend: &B, resolution: Resolution) -> Result<()> {
        let Resolution {
            candidate,
            alternatives,
            aliases,
        } = resolution;
        let item = candidate.item.clone();
        let target = CoordKey::from(&candidate.coord);
        if item.shadow.is_none()
            && let Some(module) = candidate
                .resolved_project
                .as_ref()
                .and_then(|p| p.workspace_module.as_deref())
            && let Some(cycle) = self.workspace_dependency_cycle(&item, module)
        {
            return Err(ResolveError::WorkspaceDependencyCycle { cycle });
        }
        // A cycle is cut on the artifact before a relocation counts, so a
        // cyclic target joins no group; nor does Maven gather a candidate of
        // a group below another of the group.
        let cyclic = item.path.contains(&target);
        if cyclic {
            for alias in candidate.inherited.iter() {
                self.union(alias, &target);
            }
        } else {
            // Maven's ConflictMarker puts a relocation's source, target and
            // the coordinates between them in one conflict group.
            for alias in &aliases {
                self.union(alias, &target);
            }
        }
        if cyclic || self.beneath_own_group(&item.path, &target) {
            if item.shadow.is_none()
                && let Some(existing) = self.selected.get(&self.group_of(&target))
            {
                let edge = edge(&item);
                self.graph.add_edge(item.parent, existing.node, edge);
            }
            tracing::debug!(
                cycle = %item.path.format_cycle(&target),
                "breaking cyclic dependency"
            );
            return Ok(());
        }
        let key = self.group_of(&target);
        let scope = candidate.scope();
        let mut candidates: Vec<_> = alternatives
            .into_iter()
            .enumerate()
            .map(|(position, resolved)| {
                Arc::new(Candidate {
                    coord: Coord {
                        version: resolved.version.clone(),
                        ..candidate.coord.clone()
                    },
                    source: {
                        let mut source = candidate.source.clone();
                        *source.last_mut().expect("a version") = position;
                        source
                    },
                    resolved,
                    // A system file has no descriptor to load.
                    resolved_project: candidate
                        .resolved_project
                        .clone()
                        .filter(|_| candidate.scope() == Scope::System),
                    ..candidate.clone()
                })
            })
            .collect();
        candidates.push(Arc::new(candidate));
        if let Some(origin) = &item.shadow {
            match self.shadow_role(origin, &key, &target) {
                ShadowRole::Candidate => {}
                ShadowRole::Walk => {
                    let highest = candidates.last().expect("a candidate");
                    if highest.resolved_project.is_some() {
                        let root = self.graph.root();
                        self.queue_children(backend, highest, root, 0, Some(Arc::clone(origin)))?;
                    } else {
                        self.walk_loads.push(candidates);
                    }
                    return Ok(());
                }
                ShadowRole::Drop => return Ok(()),
            }
        }
        if candidates.len() > 1
            && let Some(highest) = candidates.last().filter(|c| c.resolved_project.is_none())
        {
            self.unscanned.push_back((key.clone(), Arc::clone(highest)));
        }
        // A declaration ranked behind a settled winner that its constraint
        // accepts changes nothing but the losers to scan, once a range that
        // rejects a nearer candidate has its lowest version confirmed.
        let mut settled = None;
        let node = match self.selected.get_mut(&key) {
            Some(selection) => {
                let before = selection.candidates.len();
                if item.shadow.is_some() {
                    if selection
                        .candidates
                        .iter()
                        .any(|c| c.item.order == item.order)
                    {
                        return Ok(());
                    }
                } else {
                    // A declaration takes the place of its own shadow.
                    selection
                        .candidates
                        .retain(|c| c.item.shadow.is_none() || c.item.order != item.order);
                    if selection.candidates.len() == before
                        && let Some(winner) = &selection.winner
                        && let Some(state) = &mut selection.settled
                        && candidates.iter().all(|c| {
                            c.rank() > winner.rank()
                                && c.hard
                                    .as_ref()
                                    .is_none_or(|hard| hard.req.matches(&winner.coord.version))
                        })
                    {
                        let lowest = candidates
                            .iter()
                            .filter(|c| c.hard.as_ref().is_some_and(|hard| state.rejects(hard)))
                            .min_by(|a, b| a.source.cmp(&b.source))
                            .filter(|c| c.resolved_project.is_none())
                            .cloned();
                        settled = Some((before, lowest));
                    }
                }
                selection.candidates.extend(candidates);
                selection.node
            }
            None if item.shadow.is_some() => return Ok(()),
            None => {
                let coord = candidates.last().expect("declared").coord.clone();
                let node = self.add_node(Node {
                    coord,
                    scope,
                    repo_url: None,
                    build_repo: None,
                    repos: RepoContext::default(),
                    checksum: None,
                    workspace_module: None,
                    local: false,
                    system_path: None,
                    winner_parent: None,
                });
                self.selected
                    .insert(key.clone(), Selected::new(node, candidates));
                node
            }
        };
        match &item.shadow {
            None => {
                self.graph.add_edge(item.parent, node, edge(&item));
                self.declared
                    .entry(item.parent)
                    .or_default()
                    .push(key.clone());
            }
            Some(origin) => {
                let origin = self.group_of(&origin.group);
                self.shadows.entry(origin).or_default().push(key.clone());
            }
        }
        match settled {
            Some((from, None)) if !self.is_dirty(&key) => {
                // A losing range that already accepts the winner still has a
                // preferred version Maven's dirty tree reads for relocation.
                let dirty = self.selected.get(&key).is_some_and(|selection| {
                    selection
                        .winner
                        .as_ref()
                        .is_some_and(|winner| !selection.dirty_ranges(winner).is_empty())
                });
                if dirty {
                    self.mark_dirty(key);
                    Ok(())
                } else {
                    self.scan_losers(backend, &key, from)
                }
            }
            Some((from, Some(lowest))) if !self.is_dirty(&key) => {
                self.confirm.push((key, lowest, from));
                Ok(())
            }
            _ => {
                self.mark_dirty(key);
                Ok(())
            }
        }
    }

    fn pending(&self, key: &CoordKey, candidate: &Arc<Candidate>, from: usize) -> Option<usize> {
        if self.is_dirty(key) {
            return None;
        }
        let selection = self.selected.get(key).filter(|s| s.settled.is_some())?;
        let index = selection
            .candidates
            .get(from..)?
            .iter()
            .position(|c| Arc::ptr_eq(c, candidate))?;
        Some(from + index)
    }

    /// What a shadow declaration of `target` is: a candidate where Maven
    /// gathers it, a step of a walk below its origin through keys nothing
    /// selected, or nothing.
    fn shadow_role(&self, origin: &ShadowOrigin, key: &CoordKey, target: &CoordKey) -> ShadowRole {
        let Some(selection) = self.selected.get(&self.group_of(&origin.group)) else {
            return ShadowRole::Drop;
        };
        let Some(instance) = selection.instance(origin) else {
            return ShadowRole::Drop;
        };
        let selected = self.selected.contains_key(key);
        if selection.winner.as_ref().is_some_and(|w| w.same(instance)) {
            // The origin won since: its own declarations are on their way.
            return match selected {
                true => ShadowRole::Candidate,
                false => ShadowRole::Drop,
            };
        }
        match (selection.on_winner_path(target), selected) {
            (true, true) if self.mediated_before(key, &origin.group) => ShadowRole::Candidate,
            (false, false) => ShadowRole::Walk,
            _ => ShadowRole::Drop,
        }
    }

    /// Merge the group of a relocation's target into its source's.
    fn union(&mut self, source: &CoordKey, target: &CoordKey) {
        let (into, from) = (self.group_of(source), self.group_of(target));
        if into == from {
            return;
        }
        self.groups.insert(from.clone(), into.clone());
        if let Some(shadows) = self.shadows.remove(&from) {
            self.shadows
                .entry(into.clone())
                .or_default()
                .extend(shadows);
        }
        let Some(moved) = self.selected.remove(&from) else {
            return;
        };
        match self.selected.get_mut(&into) {
            None => {
                self.selected.insert(into.clone(), moved);
            }
            Some(selection) => {
                selection.settled = None;
                selection.candidates.extend(moved.candidates);
                let (dead, alive) = (moved.node, selection.node);
                self.graph.retarget_incoming(dead, alive);
                self.retire(dead, None);
            }
        }
        if let Some(mut selection) = self.selected.remove(&into) {
            selection
                .candidates
                .retain(|c| !self.beneath_own_group(&c.item.path, &into));
            self.selected.insert(into.clone(), selection);
        }
        self.mark_dirty(into);
    }

    fn beneath_own_group(&self, path: &PathNode, key: &CoordKey) -> bool {
        if self.groups.is_empty() {
            return path.contains(key);
        }
        let group = self.group_of(key);
        path.keys().any(|k| self.group_of(k) == group)
    }

    fn drop_group(&mut self, key: &CoordKey) {
        if let Some(selection) = self.selected.remove(key) {
            self.graph.clear_incoming(selection.node);
            self.retire(selection.node, None);
            self.revalidate_shadows(key);
        }
    }

    /// Retire what `node`'s winner declared: the node's generation moves on,
    /// so its queued declarations go stale, and its candidates leave their
    /// groups. `convert` keeps those of the keys on the new winner's path as
    /// shadows of the former winner, which stays a candidate: Maven mediated
    /// those keys first, gathering what lies below every candidate of this
    /// group.
    fn retire(&mut self, node: NodeIndex, convert: Option<(&Arc<ShadowOrigin>, &PathNode)>) {
        let old = self.generations[node.index()];
        self.generations[node.index()] = self.generation();
        self.graph.clear_outgoing(node);
        let mut touched: Vec<CoordKey> = Vec::new();
        for key in self.declared.remove(&node).unwrap_or_default() {
            let key = self.group_of(&key);
            if touched.contains(&key) {
                continue;
            }
            let convert = convert.filter(|(origin, _)| self.mediated_before(&key, &origin.group));
            let Some(selection) = self.selected.get_mut(&key) else {
                continue;
            };
            let mut changed = false;
            let mut converted = false;
            selection.candidates.retain_mut(|candidate| {
                let item = &candidate.item;
                if item.shadow.is_some() || item.parent != node || item.parent_generation != old {
                    return true;
                }
                changed = true;
                if let Some((origin, path)) = convert
                    && path.contains(&CoordKey::from(&candidate.coord))
                {
                    let mut shadow = candidate.as_ref().clone();
                    shadow.item.shadow = Some(Arc::clone(origin));
                    *candidate = Arc::new(shadow);
                    converted = true;
                    return true;
                }
                false
            });
            if converted && let Some((origin, _)) = convert {
                let origin = self.group_of(&origin.group);
                self.shadows.entry(origin).or_default().push(key.clone());
            }
            if changed {
                touched.push(key);
            }
        }
        for key in touched {
            self.revalidate_shadows(&key);
            self.mark_dirty(key);
        }
    }

    /// Drop the shadows that originate in `group` and no longer hold.
    fn revalidate_shadows(&mut self, group: &CoordKey) {
        let Some(targets) = self.shadows.remove(group) else {
            return;
        };
        let mut kept: Vec<CoordKey> = Vec::new();
        for key in targets {
            let key = self.group_of(&key);
            if kept.contains(&key) {
                continue;
            }
            let Some(selection) = self.selected.get(&key) else {
                continue;
            };
            let mut stale = Vec::new();
            let mut live = false;
            for candidate in &selection.candidates {
                let Some(origin) = &candidate.item.shadow else {
                    continue;
                };
                if self.group_of(&origin.group) != *group {
                    continue;
                }
                if self.shadow_holds(origin, &CoordKey::from(&candidate.coord)) {
                    live = true;
                } else {
                    stale.push(Arc::clone(candidate));
                }
            }
            if !stale.is_empty() {
                let selection = self.selected.get_mut(&key).expect("checked above");
                selection
                    .candidates
                    .retain(|c| !stale.iter().any(|s| Arc::ptr_eq(s, c)));
                self.mark_dirty(key.clone());
            }
            if live {
                kept.push(key);
            }
        }
        if !kept.is_empty() {
            self.shadows.insert(group.clone(), kept);
        }
    }

    fn shadow_holds(&self, origin: &ShadowOrigin, target: &CoordKey) -> bool {
        let Some(selection) = self.selected.get(&self.group_of(&origin.group)) else {
            return false;
        };
        let Some(instance) = selection.instance(origin) else {
            return false;
        };
        selection.winner.as_ref().is_some_and(|w| w.same(instance))
            || (selection.on_winner_path(target) && self.mediated_before(target, &origin.group))
    }

    /// Whether Maven mediates `key` before `other`, both in one cycle: the
    /// nearer first, as its ConflictIdSorter breaks a cycle. Mediating
    /// `key` then gathers what lies below every candidate of `other`.
    fn mediated_before(&self, key: &CoordKey, other: &CoordKey) -> bool {
        let first = |key: &CoordKey| {
            self.selected
                .get(&self.group_of(key))
                .and_then(|selection| {
                    selection
                        .candidates
                        .iter()
                        .map(|c| (c.item.depth, &c.item.order))
                        .min()
                })
        };
        match (first(key), first(other)) {
            (Some(key), Some(other)) => key < other,
            _ => false,
        }
    }

    /// Put a loaded project in place of the candidate it was loaded for. When
    /// it relocates, Maven's walk up a range stops at the version that
    /// relocates: the candidates of that declaration from this version up
    /// give way to the relocation's target. A cyclic one gives way alone.
    fn apply_load<B: Backend>(
        &mut self,
        backend: &B,
        key: &CoordKey,
        best: &Arc<Candidate>,
        loaded: Load,
    ) -> Result<()> {
        let selection = self.selected.get_mut(key).expect("mediated group");
        let resolution = match loaded {
            Load::Ready(candidate) => {
                let candidate = Arc::new(candidate);
                for retained in &mut selection.candidates {
                    if Arc::ptr_eq(retained, best) {
                        *retained = Arc::clone(&candidate);
                    }
                }
                return Ok(());
            }
            Load::Relocated(resolution) => (Some(resolution), true),
            Load::Cyclic(resolution) => (Some(resolution), false),
            Load::Excluded => (None, true),
        };
        let (resolution, stops) = resolution;
        let item = &best.item;
        selection.candidates.retain(|c| {
            !Arc::ptr_eq(c, best)
                && (!stops || c.item.declared_at != item.declared_at || c.source < best.source)
        });
        let remaining = selection
            .candidates
            .iter()
            .any(|c| c.item.declared_at == item.declared_at);
        if item.shadow.is_none() && !remaining {
            let node = selection.node;
            self.graph.remove_edge(item.parent, node, &edge(item));
        }
        self.revalidate_shadows(key);
        self.mark_dirty(key.clone());
        match resolution {
            Some(resolution) => self.add_resolution(backend, resolution),
            None => Ok(()),
        }
    }

    /// Make `winner` the group's winner: the node takes its coordinate and a
    /// new generation, and the winner's dependencies are queued.
    fn commit<B: Backend>(
        &mut self,
        backend: &B,
        key: &CoordKey,
        winner: Arc<Candidate>,
    ) -> Result<()> {
        let project = winner.resolved_project.as_ref().expect("winner loaded");
        if winner.item.shadow.is_none()
            && let Some(module) = project.workspace_module.as_deref()
            && let Some(cycle) = self.workspace_dependency_cycle(&winner.item, module)
        {
            return Err(ResolveError::WorkspaceDependencyCycle { cycle });
        }
        let selection = self.selected.get_mut(key).expect("mediated group");
        // A winner never seen before is progress; one that comes back may be
        // an oscillation.
        if !selection
            .winners
            .insert((winner.item.order.clone(), winner.coord.to_string()))
        {
            selection.changes += 1;
        }
        if selection.changes > MAX_WINNER_CHANGES {
            return Err(ResolveError::MediationDiverged {
                coord: format!("{}:{}", winner.coord.group_id, winner.coord.artifact_id),
                changes: MAX_WINNER_CHANGES,
            });
        }
        let previous = selection.winner.replace(Arc::clone(&winner));
        let child_repos =
            backend.extend_repo_context(&winner.item.path.repos, &winner.coord, &project.project);
        let path = PathNode::extend(
            &winner.item.path,
            &winner.coord,
            &winner.resolved.version,
            child_repos,
        );
        selection.winner_path = Some(Arc::clone(&path));
        selection.scanned.clear();
        selection.walked.clear();
        selection.dirty_checked.clear();
        let node = selection.node;
        let convert = previous
            .and_then(|previous| selection.instance_of(&previous).cloned())
            .map(|previous| {
                Arc::new(ShadowOrigin {
                    group: key.clone(),
                    instance: previous.item.declared_at,
                    coord: previous.coord.clone(),
                })
            });
        self.retire(node, convert.as_ref().map(|origin| (origin, path.as_ref())));
        let generation = self.generations[node.index()];
        if let Some(target) = self.graph.node_mut(node) {
            target.coord = Coord {
                version: winner.resolved.version.clone(),
                ..winner.coord.clone()
            };
            target.scope = winner.scope();
            target.winner_parent = winner.item.shadow.is_none().then_some(winner.item.parent);
            target.local = winner.scope() == Scope::System;
            target.system_path = winner.item.dependency.system_path.clone();
            target.build_repo = winner.resolved.repo.clone().filter(|_| !target.local);
            target.repo_url = target
                .build_repo
                .as_ref()
                .map(|repo| Arc::clone(&repo.url))
                .or_else(|| project.repo_url.clone())
                .filter(|_| !target.local);
            target.repos = winner.item.path.repos.clone();
            target.workspace_module = project.workspace_module.clone();
            // A classifier still naming a property fails once the graph is
            // in, and names no file to fetch.
            let unread = (target.coord.classifier.as_deref()).is_some_and(|c| c.contains("${"));
            if target.workspace_module.is_none() && !target.local && !unread {
                backend.prefetch_artifact(&target.coord, target.repo_url.as_deref(), &target.repos);
            }
        }
        self.revalidate_shadows(key);
        self.queue_children(backend, &winner, node, generation, None)
    }

    /// Queue what `winner` declares, below `parent` at `generation`, or as
    /// shadows of `shadow`. One with no `<version>` takes it from the
    /// winner's own effective dependencyManagement, as Maven does for every
    /// artifact; the declared scope is left alone.
    fn queue_children<B: Backend>(
        &mut self,
        backend: &B,
        winner: &Candidate,
        parent: NodeIndex,
        generation: u64,
        shadow: Option<Arc<ShadowOrigin>>,
    ) -> Result<()> {
        if !winner.follows() {
            return Ok(());
        }
        let project = &winner.resolved_project.as_ref().expect("loaded").project;
        let item = &winner.item;
        let child_repos = backend.extend_repo_context(&item.path.repos, &winner.coord, project);
        let path = PathNode::extend(
            &item.path,
            &winner.coord,
            &winner.resolved.version,
            child_repos,
        );
        let exclusions = extend_exclusions(&item.exclusions, &item.dependency.exclusions);
        for (index, mut dependency) in project.dependencies.iter().cloned().enumerate() {
            if dependency.version.is_none() {
                dependency.version =
                    managed_child_version(&project.dependency_management, &dependency);
            }
            let child = QueueItem {
                parent,
                parent_generation: generation,
                dependency: Arc::new(dependency),
                managed_scope: false,
                depth: item.depth + 1,
                order: item.order.child(index),
                declared_at: self.declare(),
                exclusions: Arc::clone(&exclusions),
                path: Arc::clone(&path),
                shadow: shadow.clone(),
            };
            push_queue(&mut self.queue, child)?;
        }
        Ok(())
    }

    /// Queue a shadow of the `index`th declaration of `of`'s project.
    fn queue_shadow<B: Backend>(
        &mut self,
        backend: &B,
        of: &Candidate,
        project: &Project,
        index: usize,
        origin: &Arc<ShadowOrigin>,
    ) -> Result<()> {
        if !of.follows() {
            return Ok(());
        }
        let mut dependency = project.dependencies[index].clone();
        if dependency.version.is_none() {
            dependency.version = managed_child_version(&project.dependency_management, &dependency);
        }
        let item = &of.item;
        let child_repos = backend.extend_repo_context(&item.path.repos, &of.coord, project);
        let shadow = QueueItem {
            parent: self.graph.root(),
            parent_generation: 0,
            dependency: Arc::new(dependency),
            managed_scope: false,
            depth: item.depth + 1,
            order: item.order.child(index),
            declared_at: self.declare(),
            exclusions: extend_exclusions(&item.exclusions, &item.dependency.exclusions),
            path: PathNode::extend(&item.path, &of.coord, &of.resolved.version, child_repos),
            shadow: Some(Arc::clone(origin)),
        };
        push_queue(&mut self.queue, shadow)
    }

    /// Queue shadows of what the group's losers declare for keys on its
    /// winner's path, which Maven gathers through them (see
    /// [`ShadowOrigin`]).
    fn scan_losers<B: Backend>(&mut self, backend: &B, key: &CoordKey, from: usize) -> Result<()> {
        let Some(selection) = self.selected.get_mut(key) else {
            return Ok(());
        };
        let (Some(winner), Some(path)) = (selection.winner.clone(), selection.winner_path.clone())
        else {
            return Ok(());
        };
        let losers: Vec<_> = selection.candidates[from..]
            .iter()
            .filter(|c| {
                c.item.shadow.is_none()
                    && c.resolved_project.is_some()
                    && c.follows()
                    && !c.same(&winner)
            })
            .filter(|c| selection.scanned.insert(c.item.declared_at))
            .cloned()
            .collect();
        // GA membership on the winner path, built once for every loser×dep check.
        let path_ga: HashSet<(&str, &str)> = path
            .keys()
            .map(|k| (k.group_id.as_str(), k.artifact_id.as_str()))
            .collect();
        for loser in losers {
            let project = Arc::clone(&loser.resolved_project.as_ref().expect("loaded").project);
            let own = PathNode::extend(
                &loser.item.path,
                &loser.coord,
                &loser.resolved.version,
                loser.item.path.repos.clone(),
            );
            let exclusions =
                extend_exclusions(&loser.item.exclusions, &loser.item.dependency.exclusions);
            let origin = Arc::new(ShadowOrigin {
                group: key.clone(),
                instance: loser.item.declared_at,
                coord: loser.coord.clone(),
            });
            for (index, dependency) in project.dependencies.iter().enumerate() {
                let on_path = path_ga.contains(&(
                    dependency.group_id.as_str(),
                    dependency.artifact_id.as_str(),
                ));
                if !on_path {
                    continue;
                }
                let target = key_of(dependency);
                if !path.contains(&target)
                    || !self.mediated_before(&target, key)
                    || own.contains(&target)
                    || !dependency.is_followed_transitively()
                    || is_excluded(dependency, &exclusions)
                {
                    continue;
                }
                self.queue_shadow(backend, &loser, &project, index, &origin)?;
            }
        }
        Ok(())
    }

    /// Once the queue drains, walk below what a loser with the winner's
    /// version declares and the winner's path excludes, through keys nothing
    /// selected: Maven gathers that subtree too, and it can reach back to a
    /// key on the winner's path. Whether anything was queued.
    fn walk_excluded_dependencies<B: Backend>(&mut self, backend: &B) -> Result<bool> {
        let mut keys: Vec<CoordKey> = self.selected.keys().cloned().collect();
        keys.sort_by(|a, b| {
            (
                a.group_id.as_str(),
                a.artifact_id.as_str(),
                &a.packaging,
                &a.classifier,
            )
                .cmp(&(
                    b.group_id.as_str(),
                    b.artifact_id.as_str(),
                    &b.packaging,
                    &b.classifier,
                ))
        });
        let mut queued = false;
        for key in keys {
            let Some(selection) = self.selected.get_mut(&key) else {
                continue;
            };
            let Some(winner) = selection.winner.clone() else {
                continue;
            };
            let excluded =
                extend_exclusions(&winner.item.exclusions, &winner.item.dependency.exclusions);
            let Some(resolved) = winner
                .resolved_project
                .as_ref()
                .filter(|_| !excluded.is_empty())
            else {
                continue;
            };
            let project = Arc::clone(&resolved.project);
            let losers: Vec<_> = selection
                .candidates
                .iter()
                .filter(|c| {
                    c.item.shadow.is_none()
                        && same_text(&c.coord, &winner.coord)
                        && c.follows()
                        && !c.same(&winner)
                })
                .filter(|c| selection.walked.insert(c.item.declared_at))
                .cloned()
                .collect();
            for loser in losers {
                let allowed =
                    extend_exclusions(&loser.item.exclusions, &loser.item.dependency.exclusions);
                let own = PathNode::extend(
                    &loser.item.path,
                    &loser.coord,
                    &loser.resolved.version,
                    loser.item.path.repos.clone(),
                );
                let origin = Arc::new(ShadowOrigin {
                    group: key.clone(),
                    instance: loser.item.declared_at,
                    coord: loser.coord.clone(),
                });
                for (index, dependency) in project.dependencies.iter().enumerate() {
                    if !dependency.is_followed_transitively()
                        || !is_excluded(dependency, &excluded)
                        || is_excluded(dependency, &allowed)
                    {
                        continue;
                    }
                    let target = key_of(dependency);
                    if own.contains(&target) || self.selected.contains_key(&self.group_of(&target))
                    {
                        continue;
                    }
                    self.queue_shadow(backend, &loser, &project, index, &origin)?;
                    queued = true;
                }
            }
        }
        Ok(queued)
    }

    fn workspace_dependency_cycle(&self, item: &QueueItem, target_module: &str) -> Option<String> {
        let mut coordinates = Vec::new();
        let mut current = Some(item.path.as_ref());
        while let Some(path) = current {
            let node = match path.parent {
                None => self.graph.root(),
                Some(_) => self.selected.get(&self.group_of(&path.key))?.node,
            };
            let node = self.graph.node(node)?;
            let workspace_module = node.workspace_module.as_deref()?;
            coordinates.push(format!(
                "{}:{}",
                node.coord.group_id, node.coord.artifact_id
            ));
            if workspace_module == target_module {
                coordinates.reverse();
                coordinates.push(coordinates.first().expect("cycle contains target").clone());
                return Some(coordinates.join(" -> "));
            }
            current = path.parent.as_deref();
        }
        None
    }

    fn finish<B: Backend>(mut self, backend: &B) -> Result<Graph> {
        self.graph.select_scopes()?;
        for selection in self.selected.values() {
            if let (Some(winner), Some(node)) = (&selection.winner, self.graph.node(selection.node))
            {
                backend.note_winner(&node.coord, &winner.item.path)?;
            }
        }
        let conflict = self
            .selected
            .into_values()
            .filter_map(|selection| selection.conflict)
            .min_by(|a, b| a.at.cmp(&b.at));
        match conflict {
            Some(conflict) => Err(ResolveError::VersionConflict {
                coord: conflict.coord,
                requested: conflict.requested,
                selected: conflict.selected,
            }),
            None => Ok(self.graph),
        }
    }
}

fn edge(item: &QueueItem) -> Edge {
    Edge {
        scope: item.dependency.effective_scope(),
        managed_scope: item.managed_scope,
        declared: (item.depth == 1).then_some(item.declared_at),
        optional: item.dependency.effective_optional(),
        exclusions: item.dependency.exclusions.clone(),
        requested: item.dependency.version.clone(),
    }
}

fn key_of(dependency: &Dependency) -> CoordKey {
    CoordKey {
        group_id: dependency.group_id.as_str().into(),
        artifact_id: dependency.artifact_id.as_str().into(),
        packaging: match dependency.effective_type() {
            "jar" => None,
            other => Some(other.to_string()),
        },
        classifier: dependency.effective_classifier().map(str::to_string),
    }
}

struct Resolution {
    candidate: Candidate,
    alternatives: Vec<ResolvedVersion>,
    /// When the candidate is the target of the declared artifact's
    /// relocation, the keys it relocated from.
    aliases: Vec<CoordKey>,
}

#[allow(clippy::large_enum_variant)] // short-lived and stack-local
enum Load {
    Ready(Candidate),
    Relocated(Resolution),
    /// The project relocates onto an artifact on its own path. Maven cuts
    /// the cycle there and goes on to the range's next version.
    Cyclic(Resolution),
    Excluded,
}

#[derive(Debug, Clone)]
enum RequestedRequirement {
    Exact(Version),
    /// A bare `<version>X</version>` that no management covered: a Maven
    /// soft pin, which mediation may move.
    Soft(Version),
    Ranges(VersionReq),
    Dynamic(DynamicVersionToken),
}

/// Apply the root management as Maven's ClassicDependencyManager does: its
/// exclusions join those of every dependency, direct ones included, while its
/// scope and system path apply from depth 2, since the model layer manages
/// depth 1. It overrides the declared scope but ignores a managed
/// `<optional>`, and `resolve_item` prunes on the declared values first, so a
/// dependency managed to `test` keeps its subtree.
fn apply_managed_metadata(management: &Management, mut item: QueueItem) -> QueueItem {
    let Some(managed) = management.managed(&item.dependency) else {
        return item;
    };
    if (managed.scope.is_none() || item.depth <= 1) && managed.exclusions.is_empty() {
        return item;
    }
    item.managed_scope |= manage(managed, Arc::make_mut(&mut item.dependency), item.depth);
    item
}

/// Whether the scope was managed.
fn manage(managed: &Dependency, dep: &mut Dependency, depth: usize) -> bool {
    let scope = managed.scope.as_ref().filter(|_| depth > 1);
    if let Some(scope) = scope {
        dep.scope = Some(scope.clone());
        // A dependency managed to `system` takes the managed `<systemPath>`;
        // one managed elsewhere loses its own.
        if dep.effective_scope() == Scope::System {
            if managed.system_path.is_some() {
                dep.system_path.clone_from(&managed.system_path);
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
/// file, nor, by its FatArtifactTraverser, for a `war`, `ear` or `rar`,
/// which carries its dependencies inside.
fn follows(dependency: &Dependency) -> bool {
    !dependency.includes_dependencies() && dependency.effective_scope() != Scope::System
}

const MAX_RELOCATION_MANAGEMENT_PASSES: usize = 8;

fn coord_of(dependency: &Dependency, version: Version) -> Coord {
    let type_ = dependency.effective_type();
    Coord {
        group_id: dependency.group_id.as_str().into(),
        artifact_id: dependency.artifact_id.as_str().into(),
        version,
        packaging: (type_ != "jar").then(|| type_.to_string()),
        classifier: dependency.effective_classifier().map(str::to_string),
    }
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
        && dependency.effective_type() != "pom";
    if item.depth == 1
        && exact
        && !solver
            .backend
            .is_reactor_module(group, artifact, version_str)
    {
        let type_ = dependency.effective_type();
        let packaging = if type_ == "jar" { "" } else { type_ };
        match dependency.effective_classifier() {
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

async fn resolve_item<B: Backend>(
    solver: &Solver<'_, B>,
    item: QueueItem,
    relocations: &RelocationCache,
) -> Result<Option<Resolution>> {
    // Maven's scope and optional selectors prune transitive dependencies on
    // the declared values, before management applies.
    let followed = item.dependency.is_followed_transitively();
    let item = apply_managed_metadata(&solver.management, item);
    let dep_scope = item.dependency.effective_scope();
    if is_excluded(&item.dependency, &item.exclusions)
        || (item.depth > 1 && !followed)
        || dep_scope == Scope::Import
    {
        return Ok(None);
    }
    let version_str = resolve_version_str(&solver.management, &item.dependency, item.depth)?;
    refuse_undefined_property(solver, &item, version_str)?;
    let dependency = &item.dependency;
    let (requirement, versions, resolved) = requested_versions(
        solver,
        &dependency.group_id,
        &dependency.artifact_id,
        version_str,
        &item.path.repos,
    )
    .await?;
    if dep_scope == Scope::System {
        let coord = coord_of(dependency, resolved.version);
        let candidate = Candidate {
            hard: hard_constraint(&requirement),
            source: vec![versions.len()],
            ..system_candidate(item, coord)?
        };
        return Ok(Some(Resolution {
            candidate,
            alternatives: versions,
            aliases: Vec::new(),
        }));
    }

    let coord = coord_of(dependency, resolved.version.clone());
    // Mediation reads a range's versions one at a time, from the lowest up,
    // so start their fetches now.
    if matches!(requirement, RequestedRequirement::Ranges(_)) {
        for version in &versions {
            let lower = coord_of(dependency, version.version.clone());
            solver
                .backend
                .prefetch_range_version(&lower, &item.path.repos);
        }
        solver
            .backend
            .prefetch_range_version(&coord, &item.path.repos);
    }
    let candidate = Candidate {
        hard: hard_constraint(&requirement),
        source: vec![versions.len()],
        inherited: Arc::from([]),
        item,
        coord,
        resolved,
        resolved_project: None,
    };
    if matches!(requirement, RequestedRequirement::Ranges(_)) {
        return Ok(Some(Resolution {
            candidate,
            alternatives: versions,
            aliases: Vec::new(),
        }));
    }
    Ok(
        match load_candidate(solver, candidate, relocations).await? {
            Load::Ready(candidate) => Some(Resolution {
                candidate,
                alternatives: Vec::new(),
                aliases: Vec::new(),
            }),
            Load::Relocated(resolution) | Load::Cyclic(resolution) => Some(resolution),
            Load::Excluded => None,
        },
    )
}

/// The requirement `version` states for `group_id:artifact_id`, the versions
/// it admits below the highest, and the highest.
async fn requested_versions<B: Backend>(
    solver: &Solver<'_, B>,
    group_id: &str,
    artifact_id: &str,
    version: &str,
    repos: &RepoContext,
) -> Result<(RequestedRequirement, Vec<ResolvedVersion>, ResolvedVersion)> {
    let requirement = parse_requested_requirement(group_id, artifact_id, version)?;
    let mut versions =
        resolve_requirement_versions(solver, group_id, artifact_id, &requirement, repos).await?;
    let highest = versions
        .pop()
        .ok_or_else(|| ResolveError::VersionNotFound {
            coord: format!("{group_id}:{artifact_id}"),
            requirement: version.to_string(),
        })?;
    Ok((requirement, versions, highest))
}

fn system_candidate(item: QueueItem, coord: Coord) -> Result<Candidate> {
    // raeva neither coins a version nor locks a row with no file and no
    // repository.
    if item
        .dependency
        .system_path
        .as_deref()
        .is_none_or(|path| path.trim().is_empty())
    {
        return Err(PomError::InvalidSystemPath(format!(
            "system-scoped dependency {}:{} requires a non-empty <systemPath>",
            bounded(&item.dependency.group_id),
            bounded(&item.dependency.artifact_id)
        ))
        .into());
    }
    let project = Project::new(
        &coord.group_id,
        &coord.artifact_id,
        &coord.version.to_string(),
    );
    Ok(Candidate {
        resolved: ResolvedVersion {
            version: coord.version.clone(),
            repo: None,
        },
        resolved_project: Some(ResolvedProject {
            project: Arc::new(project),
            repo_url: None,
            workspace_module: None,
        }),
        hard: None,
        source: vec![0],
        inherited: Arc::from([]),
        item,
        coord,
    })
}

async fn resolve_requirement_versions<B: Backend>(
    solver: &Solver<'_, B>,
    group_id: &str,
    artifact_id: &str,
    requirement: &RequestedRequirement,
    repos: &RepoContext,
) -> Result<Vec<ResolvedVersion>> {
    let marker = match requirement {
        RequestedRequirement::Exact(version) | RequestedRequirement::Soft(version) => {
            return Ok(vec![ResolvedVersion {
                version: version.clone(),
                repo: None,
            }]);
        }
        RequestedRequirement::Ranges(req) => {
            return solver
                .backend
                .resolve_versions(group_id, artifact_id, req, repos)
                .await;
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

/// Fetch a candidate's project. A SNAPSHOT keeps its base version for
/// mediation and records the build it resolved to. A relocation restarts the
/// declaration as Maven's DfDependencyCollector does: the target is excluded
/// and managed as itself, and its version is a soft preference of its own
/// unless management sets one.
async fn load_candidate<B: Backend>(
    solver: &Solver<'_, B>,
    candidate: Candidate,
    relocations: &RelocationCache,
) -> Result<Load> {
    let path = Arc::clone(&candidate.item.path);
    let coord = format!(
        "{}:{}:{}",
        candidate.coord.group_id, candidate.coord.artifact_id, candidate.coord.version
    );
    (load_declared(solver, candidate, relocations).await).map_err(|err| {
        // A fault in the candidate's own model, such as a missing parent,
        // does not name the candidate, nor the relocation target whose
        // model it is, which the relocation fetch put below it.
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
    })
}

/// `err`, for a dependency that the last POM on `path` declares.
fn declared_below(err: ResolveError, path: &PathNode) -> ResolveError {
    let mut via = path.coordinates();
    via.remove(0);
    err.declared_via(via)
}

async fn load_declared<B: Backend>(
    solver: &Solver<'_, B>,
    candidate: Candidate,
    relocations: &RelocationCache,
) -> Result<Load> {
    let Candidate {
        item,
        coord,
        mut resolved,
        hard,
        source,
        inherited,
        ..
    } = candidate;
    let item_ref = &item;
    let requested = &coord;
    let relocated = !inherited.is_empty();
    let fetch = move |coord: Coord| async move {
        let (mut target, project, snapshot, between, inherited_build) = solver
            .fetch_project_with_relocation_cached(&coord, &item_ref.path.repos, relocations)
            .await
            .map_err(|err| attach_dropped_repos(solver, item_ref, &coord, err))
            // A management or range target is a model of its own.
            .map_err(|err| match same_text(&coord, requested) {
                true => err,
                false => err.in_model_of(&coord),
            })?;
        // A build kept along a relocation without a version is the target's
        // version itself: Maven mediates and constrains it as that build.
        if let Some(build) = snapshot.as_ref().filter(|_| inherited_build) {
            target.version = build.version.clone();
        }
        // A reactor module reached through an external POM, winning or not,
        // is no edge of the module's own record. Only an external POM
        // relocates, and a candidate that carries relocations, as a managed
        // range after one does, was reached through one.
        if project.workspace_module.is_some()
            && (relocated
                || !same_text(&target, requested)
                || (item_ref.path.below_root()).any(|(key, version)| {
                    let backend = &solver.backend;
                    !backend.is_reactor_module(&key.group_id, &key.artifact_id, version)
                }))
        {
            solver.backend.note_transitive_selection();
        }
        Ok::<_, ResolveError>((target, project, snapshot, between))
    };
    let (mut target, mut project, mut snapshot, between) = fetch(coord.clone()).await?;
    if same_text(&target, &coord) {
        if let Some(snapshot) = snapshot {
            resolved.version = snapshot.version;
            resolved.repo = snapshot.repo;
        }
        if follows(&item.dependency) {
            solver.hint_children(&item, &coord, &project.project);
        }
        return Ok(Load::Ready(Candidate {
            item,
            coord,
            resolved,
            resolved_project: Some(project),
            hard,
            source,
            inherited,
        }));
    }
    let mut inherited = inherited;
    let mut dependency = (*item.dependency).clone();
    let mut managed_scope = item.managed_scope;
    let mut hard = None;
    let mut alternatives = Vec::new();
    // The coordinate whose versions `resolved` was listed among.
    let mut listed_for = None;
    let mut aliases: Vec<CoordKey> = std::iter::once(&coord)
        .chain(&between)
        .map(CoordKey::from)
        .collect();
    let mut previous = coord.clone();
    let mut cyclic = false;
    for pass in 0.. {
        // Maven recurses without end on a managed chain that comes back.
        if pass == MAX_RELOCATION_MANAGEMENT_PASSES {
            return Err(ResolveError::RelocationCycle(format!(
                "{coord} -> {target} (more than {MAX_RELOCATION_MANAGEMENT_PASSES} managed relocations)"
            )));
        }
        // A cyclic target is cut before anything else applies to it.
        if item.path.contains(&CoordKey::from(&target)) {
            cyclic = true;
            break;
        }
        if excludes(
            &item.exclusions,
            target.group_id.as_str(),
            target.artifact_id.as_str(),
        ) {
            return Ok(Load::Excluded);
        }
        // Maven runs its dependency selector again on each relocation
        // target, with the management applied so far.
        if item.depth > 1 && !dependency.is_followed_transitively() {
            return Ok(Load::Excluded);
        }
        if target.group_id == previous.group_id && target.artifact_id == previous.artifact_id {
            break;
        }
        // Maven manages the target as a dependency of its own, and a
        // managed target may relocate again. Only the target's own
        // management makes Maven take its scope as it is.
        let Some(managed) = solver.management.entry(
            target.group_id.as_str(),
            target.artifact_id.as_str(),
            &item.dependency,
        ) else {
            managed_scope = false;
            break;
        };
        managed_scope = manage(managed, &mut dependency, item.depth);
        let version = managed.version.clone().filter(|_| item.depth > 1);
        if dependency.effective_scope() == Scope::System {
            let (versions, version, hard) = match version {
                Some(version) => {
                    let (group_id, artifact_id) =
                        (target.group_id.as_str(), target.artifact_id.as_str());
                    let repos = &item.path.repos;
                    let (requirement, versions, highest) =
                        requested_versions(solver, group_id, artifact_id, &version, repos).await?;
                    (versions, highest.version, hard_constraint(&requirement))
                }
                None => (Vec::new(), target.version.clone(), None),
            };
            let item = QueueItem {
                dependency: Arc::new(dependency),
                managed_scope,
                ..item
            };
            let coord = Coord { version, ..target };
            return Ok(Load::Relocated(Resolution {
                candidate: Candidate {
                    hard,
                    source: vec![versions.len()],
                    ..system_candidate(item, coord)?
                },
                alternatives: versions,
                aliases,
            }));
        }
        let Some(version) = version else {
            break;
        };
        let (group_id, artifact_id) = (target.group_id.as_str(), target.artifact_id.as_str());
        let (requirement, mut versions, highest) =
            requested_versions(solver, group_id, artifact_id, &version, &item.path.repos).await?;
        resolved = highest;
        let mut managed = Coord {
            version: resolved.version.clone(),
            ..target.clone()
        };
        // Maven walks a range up from its lowest version and stops at the
        // first that relocates. The versions below it keep this chain's
        // relocations as aliases, so whether the lowest relocates decides
        // them.
        let lowest = match &requirement {
            RequestedRequirement::Ranges(_) => {
                let lowest = versions.first().unwrap_or(&resolved).clone();
                let coord = Coord {
                    version: lowest.version.clone(),
                    ..target.clone()
                };
                let (end, ..) = fetch(coord.clone()).await?;
                let stops = !same_text(&end, &coord) && !item.path.contains(&CoordKey::from(&end));
                stops.then_some((lowest, coord))
            }
            _ => None,
        };
        if let Some((lowest, coord)) = lowest {
            resolved = lowest;
            managed = coord;
            versions.clear();
        } else if matches!(requirement, RequestedRequirement::Ranges(_)) {
            // A managed range is walked like a declared one, so it is
            // mediated lazily as one.
            let item = QueueItem {
                dependency: Arc::new(dependency),
                managed_scope,
                ..item
            };
            // Each lazy range starts a new load, so the budget is the
            // length of the chain of ranges.
            if source.len() >= MAX_RELOCATION_MANAGEMENT_PASSES {
                return Err(ResolveError::RelocationCycle(format!(
                    "{coord} -> {managed} (more than {MAX_RELOCATION_MANAGEMENT_PASSES} managed relocations)"
                )));
            }
            let mut source = source;
            source.push(versions.len());
            return Ok(Load::Relocated(Resolution {
                candidate: Candidate {
                    item,
                    coord: managed,
                    resolved,
                    resolved_project: None,
                    hard: hard_constraint(&requirement),
                    source,
                    inherited: aliases.clone().into(),
                },
                alternatives: versions,
                aliases,
            }));
        }
        hard = hard_constraint(&requirement);
        alternatives = versions;
        listed_for = Some(managed.clone());
        if same_text(&managed, &target) {
            break;
        }
        previous = managed.clone();
        let between;
        (target, project, snapshot, between) = fetch(managed.clone()).await?;
        if same_text(&target, &managed) {
            // Nothing applies again to a managed version that stays.
            break;
        }
        // Maven's collector replaces the relocations it carries with those
        // of the latest descriptor that relocates.
        let relocated = std::iter::once(&managed)
            .chain(&between)
            .map(CoordKey::from)
            .collect();
        inherited = std::mem::replace(&mut aliases, relocated).into();
        hard = None;
        alternatives.clear();
    }
    if listed_for.is_none_or(|listed| !same_text(&listed, &target)) {
        // Maven fetches a relocation target from the requesting node's
        // repositories, so the repository that listed the source's versions
        // says nothing about where the target comes from.
        resolved = ResolvedVersion {
            version: target.version.clone(),
            repo: None,
        };
    }
    if let Some(snapshot) = snapshot {
        resolved.version = snapshot.version;
        resolved.repo = snapshot.repo;
    }
    let item = QueueItem {
        dependency: Arc::new(dependency),
        managed_scope,
        ..item
    };
    tracing::debug!(from = %coord, to = %target, depth = item.depth, "relocated dependency");
    if follows(&item.dependency) {
        solver.hint_children(&item, &target, &project.project);
    }
    let resolution = Resolution {
        candidate: Candidate {
            item,
            coord: target,
            resolved,
            resolved_project: Some(project),
            hard,
            source,
            inherited,
        },
        alternatives,
        aliases,
    };
    Ok(if cyclic {
        Load::Cyclic(resolution)
    } else {
        Load::Relocated(resolution)
    })
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
    let req = VersionReq::parse(trimmed).map_err(|_| invalid())?;
    // DefaultVersionRangeResolver takes a range whose bounds are equal, as
    // `[1,1]` or `[1]`, as that one version without reading metadata.
    if let Some(version) = req.exact_version() {
        return Ok(RequestedRequirement::Exact(version.clone()));
    }
    Ok(match req {
        VersionReq::Soft(version) => RequestedRequirement::Soft(version),
        req => RequestedRequirement::Ranges(req),
    })
}

fn hard_constraint(requirement: &RequestedRequirement) -> Option<Arc<Hard>> {
    let req = match requirement {
        RequestedRequirement::Ranges(range) => range.clone(),
        RequestedRequirement::Exact(version) => VersionReq::Exact(version.clone()),
        _ => return None,
    };
    Some(Arc::new(Hard {
        text: req.to_string().into(),
        req,
    }))
}

#[derive(Debug)]
struct Hard {
    req: VersionReq,
    text: Box<str>,
}

#[derive(Debug, Clone)]
struct Conflict {
    coord: String,
    requested: String,
    selected: String,
    at: SortKey,
}

#[derive(Debug)]
struct Selected {
    node: NodeIndex,
    candidates: Vec<Arc<Candidate>>,
    winner: Option<Arc<Candidate>>,
    winner_path: Option<Arc<PathNode>>,
    /// Losers already scanned for shadows under this winner.
    scanned: HashSet<u64>,
    /// Losers already walked below what the winner's path excludes.
    walked: HashSet<u64>,
    /// Losing range declarations whose preferred version was probed for a
    /// dirty-tree relocation and did not relocate.
    dirty_checked: HashSet<u64>,
    conflict: Option<Conflict>,
    winners: HashSet<(TreeOrder, String)>,
    /// How often a winner came back.
    changes: u32,
    settled: Option<Settled>,
}

/// The candidates nearer than a settled winner, which some constraint
/// rejects.
#[derive(Debug)]
struct Settled {
    nearer: Vec<Arc<Candidate>>,
    rejects: HashMap<Box<str>, bool>,
}

impl Settled {
    fn rejects(&mut self, hard: &Hard) -> bool {
        if let Some(&known) = self.rejects.get(&hard.text) {
            return known;
        }
        let rejects = self
            .nearer
            .iter()
            .any(|c| !hard.req.matches(&c.coord.version));
        self.rejects.insert(hard.text.clone(), rejects);
        rejects
    }
}

impl Selected {
    fn new(node: NodeIndex, candidates: Vec<Arc<Candidate>>) -> Self {
        Self {
            node,
            candidates,
            winner: None,
            winner_path: None,
            scanned: HashSet::new(),
            walked: HashSet::new(),
            dirty_checked: HashSet::new(),
            conflict: None,
            winners: HashSet::new(),
            changes: 0,
            settled: None,
        }
    }

    fn settle(&mut self) {
        self.settled = self.winner.as_ref().map(|winner| {
            let rank = winner.rank();
            Settled {
                nearer: self
                    .candidates
                    .iter()
                    .filter(|c| c.rank() < rank)
                    .cloned()
                    .collect(),
                rejects: HashMap::new(),
            }
        });
    }

    /// Maven's NearestVersionSelector: every hard constraint must accept the
    /// winner, which is the nearest candidate, the first in depth-first
    /// order among equally near ones unless a sibling has a higher version.
    fn best(&self) -> Option<Arc<Candidate>> {
        let hard = self.constraints();
        self.candidates
            .iter()
            .filter(|c| hard.iter().all(|h| h.req.matches(&c.coord.version)))
            .min_by(|a, b| a.rank().cmp(&b.rank()))
            .cloned()
    }

    fn constraints(&self) -> Vec<&Hard> {
        let mut seen = HashSet::new();
        self.candidates
            .iter()
            .filter_map(|c| c.hard.as_deref())
            .filter(|hard| seen.insert(&*hard.text))
            .collect()
    }

    /// The unloaded highest candidate of each losing range whose constraint
    /// already accepts `best`. Only ranges from another declaration count:
    /// alternatives of the winner's own range are not a dirty-tree read.
    /// Maven still reads that preferred version, so a relocation there can
    /// join this conflict group.
    fn dirty_ranges(&self, best: &Candidate) -> Vec<Arc<Candidate>> {
        let mut highest: IndexMap<u64, &Arc<Candidate>> = IndexMap::new();
        for candidate in &self.candidates {
            if candidate.item.shadow.is_some()
                || candidate.same(best)
                || candidate.item.declared_at == best.item.declared_at
            {
                continue;
            }
            let Some(hard) = candidate.hard.as_deref() else {
                continue;
            };
            if !matches!(hard.req, VersionReq::Ranges(_)) {
                continue;
            }
            if self.dirty_checked.contains(&candidate.item.declared_at) {
                continue;
            }
            if !hard.req.matches(&best.coord.version) || candidate.resolved_project.is_some() {
                continue;
            }
            let entry = highest
                .entry(candidate.item.declared_at)
                .or_insert(candidate);
            if candidate.source > entry.source {
                *entry = candidate;
            }
        }
        highest.into_values().cloned().collect()
    }

    /// The unloaded lowest candidates of the ranges whose constraint
    /// rejects a candidate nearer than `best`, or any candidate when there
    /// is no `best`.
    fn unconfirmed(&self, best: Option<&Candidate>) -> Vec<Arc<Candidate>> {
        let nearer: Vec<&Arc<Candidate>> = self
            .candidates
            .iter()
            .filter(|c| best.is_none_or(|best| c.rank() < best.rank()))
            .collect();
        if nearer.is_empty() {
            return Vec::new();
        }
        let rejecting: HashSet<&str> = self
            .constraints()
            .into_iter()
            .filter(|h| nearer.iter().any(|c| !h.req.matches(&c.coord.version)))
            .map(|h| &*h.text)
            .collect();
        let mut lowest: IndexMap<(u64, &str), &Arc<Candidate>> = IndexMap::new();
        for candidate in &self.candidates {
            let Some(hard) = candidate.hard.as_deref() else {
                continue;
            };
            if !rejecting.contains(&*hard.text) {
                continue;
            }
            let entry = lowest
                .entry((candidate.item.declared_at, &*hard.text))
                .or_insert(candidate);
            if candidate.source < entry.source {
                *entry = candidate;
            }
        }
        lowest
            .into_values()
            .filter(|c| c.resolved_project.is_none())
            .cloned()
            .collect()
    }

    fn note_conflict(&mut self) {
        let selected = self.winner.as_ref().map(|winner| &winner.coord.version);
        let rejecting = |c: &&Arc<Candidate>| {
            c.hard
                .as_ref()
                .is_some_and(|hard| selected.is_none_or(|version| !hard.req.matches(version)))
        };
        let Some(culprit) = self
            .candidates
            .iter()
            .filter(rejecting)
            .max_by_key(|c| c.item.declared_at)
            .or_else(|| self.candidates.first())
        else {
            return;
        };
        let requested = match culprit.hard.as_deref().map(|hard| &hard.req) {
            Some(VersionReq::Exact(version)) => version.to_string(),
            Some(hard) => hard.to_string(),
            None => culprit.coord.version.to_string(),
        };
        self.conflict = Some(Conflict {
            coord: format!("{}:{}", culprit.coord.group_id, culprit.coord.artifact_id),
            requested,
            selected: selected.unwrap_or(&culprit.coord.version).to_string(),
            at: culprit.item.sort_key(),
        });
    }

    fn instance(&self, origin: &ShadowOrigin) -> Option<&Arc<Candidate>> {
        self.candidates.iter().find(|c| {
            c.item.shadow.is_none()
                && c.item.declared_at == origin.instance
                && same_text(&c.coord, &origin.coord)
        })
    }

    fn instance_of(&self, candidate: &Candidate) -> Option<&Arc<Candidate>> {
        self.candidates.iter().find(|c| {
            c.item.shadow.is_none()
                && candidate.item.shadow.is_none()
                && c.item.declared_at == candidate.item.declared_at
                && same_text(&c.coord, &candidate.coord)
        })
    }

    fn on_winner_path(&self, key: &CoordKey) -> bool {
        self.winner_path
            .as_ref()
            .is_some_and(|path| path.contains(key))
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    item: QueueItem,
    /// The coordinate mediation compares; a SNAPSHOT keeps its base version.
    coord: Coord,
    /// The version of the file, a SNAPSHOT's timestamped build, and the
    /// repository that listed it.
    resolved: ResolvedVersion,
    resolved_project: Option<ResolvedProject>,
    hard: Option<Arc<Hard>>,
    /// The positions, in the listed order, of the versions of the ranges on
    /// the way to this candidate: the declared artifact's, then, where a
    /// relocation's target is managed to a range, the target's. A range
    /// stops at the first version that relocates. Two spellings of one
    /// version keep their own positions.
    source: Vec<usize>,
    /// The relocations Maven's collector carries into this candidate's
    /// descriptor read, which a relocation onto a cyclic target keeps.
    inherited: Arc<[CoordKey]>,
}

impl Candidate {
    /// Nearest first; then depth-first order of the parents, so that
    /// siblings compare by version, highest first; then depth-first order.
    fn rank(&self) -> (usize, &TreeOrder, Reverse<&Version>, &TreeOrder, u64) {
        (
            self.item.depth,
            self.item.order.parent(),
            Reverse(&self.coord.version),
            &self.item.order,
            self.item.declared_at,
        )
    }

    fn same(&self, other: &Self) -> bool {
        self.item.order == other.item.order && same_text(&self.coord, &other.coord)
    }

    /// The declared scope, or the one management set.
    fn scope(&self) -> Scope {
        self.item.dependency.effective_scope()
    }

    fn follows(&self) -> bool {
        follows(&self.item.dependency)
    }
}

/// Find the version a resolved artifact's effective dependencyManagement
/// supplies for one of its child dependencies, matched by Maven's management
/// key `(groupId, artifactId, type, classifier)`: the first matching entry
/// that carries one.
fn managed_child_version(mgmt: &DependencyManagement, dep: &Dependency) -> Option<String> {
    mgmt.dependencies
        .iter()
        .filter(|managed| {
            managed.group_id == dep.group_id
                && managed.artifact_id == dep.artifact_id
                && managed.effective_type() == dep.effective_type()
                && managed.effective_classifier() == dep.effective_classifier()
        })
        .find_map(|managed| managed.version.clone())
}

/// The managed dependency and the requirement [`resolve_item`] resolves
/// for `item`, unless it skips the item: the same skips, in the same order.
fn prefetch_requirement(
    item: &QueueItem,
    management: &Management,
) -> Option<(Arc<Dependency>, RequestedRequirement)> {
    let followed = item.dependency.is_followed_transitively();
    let item = apply_managed_metadata(management, item.clone());
    let dependency = &item.dependency;
    if is_excluded(dependency, &item.exclusions)
        || (item.depth > 1 && !followed)
        || matches!(dependency.effective_scope(), Scope::Import | Scope::System)
    {
        return None;
    }
    let version_str = resolve_version_str(management, dependency, item.depth).ok()?;
    let requirement =
        parse_requested_requirement(&dependency.group_id, &dependency.artifact_id, version_str)
            .ok()?;
    Some((item.dependency, requirement))
}

/// The coordinates [`resolve_item`] fetches the project of for `item`, when
/// it fetches one by a fixed, non-snapshot version.
fn prefetch_coord(item: &QueueItem, management: &Management) -> Option<Coord> {
    let (dependency, requirement) = prefetch_requirement(item, management)?;
    fixed_coord(&dependency, requirement)
}

fn fixed_coord(dependency: &Dependency, requirement: RequestedRequirement) -> Option<Coord> {
    let (RequestedRequirement::Exact(version) | RequestedRequirement::Soft(version)) = requirement
    else {
        return None;
    };
    if rv_maven_types::resolves_through_snapshot_metadata(version.as_str()) {
        return None;
    }
    Some(coord_of(dependency, version))
}
