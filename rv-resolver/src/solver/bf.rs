//! Maven's dependency collection, ported from maven-resolver: for Maven
//! 3.10, 2.0.24's BfDependencyCollector with its
//! DependencyResolutionSkipper, which reads every version of a range, the
//! highest first, and reads but does not expand a node the skipper takes
//! for a loser; for Maven 3.9, 1.9.25's DfDependencyCollector, which
//! expands every node depth first and reads a range from its lowest
//! version up, or its BfDependencyCollector where
//! `aether.dependencyCollector.impl` selects it. [`conflict`] then
//! resolves the tree it built, and the winners become the solver's
//! [`Graph`].

mod conflict;

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use rv_maven_model::{ArtifactTypes, Dependency, Project, Scope, is_core_type};
use rv_maven_types::{Coord, MavenMode, Version, VersionReq};

use self::conflict::{Entry, Tree, TreeNode};
use super::management::version_origin;
use super::queue::{QueueItem, check_bounds, extend_exclusions, is_excluded};
use super::relocation::{self, HopPom, HopRead, RelocationCache};
use super::{
    Backend, ExclusionKey, MAX_RELOCATION_MANAGEMENT_PASSES, PathNode, RequestedRequirement,
    ResolvedProject, ResolvedVersion, Solver, SolverRoot, apply_managed_metadata,
    attach_dropped_repos, check_system_path, coord_of, declared_below, excludes, fixed_coord,
    follows, hard_constraint, load_error, manage, manage_child, names_property,
    parse_requested_requirement, refuse_undefined_property, requested_versions,
    resolve_version_str,
};
use crate::context::RepoContext;
use crate::error::{ResolveError, Result};
use crate::graph::{CoordKey, DescriptorKey, Edge, Graph, Node, PomReading, same_text};

const ROOT: usize = 0;

/// Collect the graph of `root` as the solver's Maven does.
pub(super) async fn solve<B: Backend>(solver: &Solver<'_, B>, root: SolverRoot) -> Result<Graph> {
    let mut walk = Walk::start(solver, root)?;
    for pending in &walk.queue {
        walk.hint(pending);
    }
    walk.hinting = true;
    while let Some(pending) = walk.queue.pop_front() {
        walk.process(pending).await?;
    }
    walk.finish()
}

/// Fail where [`solve`] fails on `root`'s own dependencies before it reads
/// any of them.
pub(super) fn check_root<B: Backend>(solver: &Solver<'_, B>, root: SolverRoot) -> Result<()> {
    Walk::start(solver, root).map(drop)
}

/// A dependency to read, as maven-resolver's DependencyProcessingContext
/// carries it.
#[derive(Clone)]
struct Pending {
    /// The dependency with the root's scope, system path and exclusions
    /// management applied.
    item: QueueItem,
    /// The version requested once management applied.
    version: Arc<str>,
    /// The `<version>` the POM declared.
    requested: Option<String>,
    /// The tree nodes from the root down to the declaring one.
    parents: Arc<[usize]>,
}

/// maven-resolver's `ArtifactIdUtils.toId` of a requested artifact, by
/// which its descriptor reads are shared, and whether the read is for a
/// system dependency, which raeva reads on its own. The depth-first
/// collector lists the versions for each set of repositories, as its
/// DataPool keys constraints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReadKey {
    key: CoordKey,
    version: Arc<str>,
    system: bool,
    repos: Option<RepoContext>,
}

enum Reads {
    /// Asked for by this declaration, the first, whose repositories serve
    /// the reads.
    Asked(Box<Pending>),
    Read(Arc<Listing>),
}

/// A requested artifact's versions, each with its descriptor: highest
/// first, or for the depth-first collector lowest first.
struct Listing {
    hard: Option<VersionReq>,
    versions: Vec<Listed>,
}

#[derive(Clone)]
struct Listed {
    resolved: ResolvedVersion,
    /// `None` until the depth-first collector reaches the version.
    read: Option<Read>,
}

/// A descriptor, or the error reading it, in [`Walk::errors`].
type Read = std::result::Result<Arc<Fetched>, (Coord, usize)>;

/// A descriptor read that failed, and the declaration it was read for.
struct Unread {
    error: ResolveError,
    item: QueueItem,
    coord: Coord,
    /// Whether Maven reads it too, rather than raeva alone, for a file.
    maven: bool,
}

struct Fetched {
    /// The artifact read, at the end of any relocation.
    target: Coord,
    project: ResolvedProject,
    snapshot: Option<ResolvedVersion>,
    /// The artifacts it relocated from, the requested one first.
    relocations: Vec<CoordKey>,
    /// Each artifact of the chain as its fetch read it, the requested one
    /// first and `target` last; none for an artifact a property names.
    reads: Vec<HopRead>,
}

/// What Maven 3.9 pools for an artifact read as `fetched`: nothing for a
/// reactor module or an artifact a property names, else each POM along any
/// relocation, as its fetch read it.
fn reading(fetched: &Fetched) -> Result<Option<PomReading>> {
    let digest = |read: &HopRead| match &read.pom {
        HopPom::Read(blob) => Ok(Some(blob.clone())),
        HopPom::Missing => Ok(None),
        HopPom::Reactor | HopPom::Unrecorded => Err(ResolveError::InternalError(format!(
            "no POM recorded for {}",
            read.coord
        ))),
    };
    match fetched.reads.as_slice() {
        [] => Ok(None),
        [first, ..] if first.pom == HopPom::Reactor => Ok(None),
        [only] => {
            let Some(blob) = digest(only)? else {
                return Ok(Some(PomReading::Empty));
            };
            let project = &fetched.project.project;
            let empty = project.dependencies.is_empty()
                && project.dependency_management.dependencies.is_empty()
                && project.repositories.is_empty();
            Ok(Some(match empty {
                true => PomReading::Empty,
                false => PomReading::Bytes(vec![Some(blob)]),
            }))
        }
        // A reactor module along the chain has no repository bytes.
        reads => Ok(Some(PomReading::Bytes(
            (reads.iter().filter(|read| read.pom != HopPom::Reactor))
                .map(digest)
                .collect::<Result<_>>()?,
        ))),
    }
}

/// What raeva keeps of a tree node beside its [`Entry`].
struct Dep {
    item: QueueItem,
    requested: Option<String>,
    coord: Coord,
    resolved: ResolvedVersion,
    project: Option<ResolvedProject>,
    error: Option<usize>,
    /// Whether the node keeps no dependency of its descriptor.
    childless: bool,
    parents: Arc<[usize]>,
    /// Whether it is a system dependency.
    local: bool,
}

impl Dep {
    fn parent(&self) -> usize {
        *self.parents.last().expect("below the root")
    }

    /// The artifact as maven-resolver compares two: its coordinates and the
    /// properties its type and system path give it.
    fn artifact(&self) -> ArtifactKey {
        let dependency = &self.item.dependency;
        ArtifactKey {
            key: CoordKey::from(&self.coord),
            version: Arc::from(self.coord.version.as_str()),
            type_: Arc::from(dependency.type_.as_deref().unwrap_or("jar")),
            system_path: dependency.system_path.clone().filter(|_| self.local),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ArtifactKey {
    key: CoordKey,
    version: Arc<str>,
    type_: Arc<str>,
    system_path: Option<String>,
}

/// DataPool's key for a node's children. The selectors and the
/// ClassicDependencyManager below a dependency are the same for every
/// node, so the exclusions stand for them.
#[derive(Debug, PartialEq, Eq, Hash)]
struct PoolKey {
    artifact: ArtifactKey,
    repos: RepoContext,
    exclusions: Vec<ExclusionKey>,
}

/// DependencyResolutionSkipper with its default GACE key: the first node
/// of an artifact expanded is taken to win, a later one at another version
/// is not expanded, and one at the same version only where it is further
/// left than the one expanded.
#[derive(Default)]
struct Skipper {
    coordinates: HashMap<usize, (usize, usize)>,
    sequences: HashMap<usize, usize>,
    forced: HashSet<usize>,
    leftmost: HashMap<ArtifactKey, (usize, usize)>,
    winners: HashSet<ArtifactKey>,
    winner_versions: HashMap<CoordKey, Arc<str>>,
}

impl Skipper {
    /// Whether to skip `node` of `artifact`, below `parents`.
    fn skip(&mut self, node: usize, artifact: &ArtifactKey, parents: &[usize]) -> bool {
        let depth = parents.len() + 1;
        let sequence = self.sequences.entry(depth).or_default();
        *sequence += 1;
        let coordinate = (depth, *sequence);
        self.coordinates.insert(node, coordinate);
        let conflict = (self.winner_versions.get(&artifact.key))
            .is_some_and(|version| *version != artifact.version);
        let resolve = if conflict {
            false
        } else if self.winners.contains(artifact) {
            let leftmost = self
                .leftmost
                .get(artifact)
                .is_some_and(|&(depth, sequence)| {
                    depth <= parents.len()
                        && (self.coordinates.get(&parents[depth - 1]))
                            .is_some_and(|&(_, at)| at < sequence)
                });
            if leftmost {
                self.forced.insert(node);
            }
            leftmost
        } else {
            true
        };
        if resolve {
            self.leftmost.insert(artifact.clone(), coordinate);
        }
        !resolve
    }

    /// Take `artifact`, at the end of `path`, for the winner, unless it is
    /// below a node expanded only as a duplicate; whether it took it.
    fn cache(&mut self, artifact: &ArtifactKey, path: &[usize]) -> bool {
        if path.iter().any(|node| self.forced.contains(node)) {
            return false;
        }
        self.winners.insert(artifact.clone());
        (self.winner_versions).insert(artifact.key.clone(), Arc::clone(&artifact.version));
        true
    }
}

/// A node [`Walk::add_node`] adds.
struct NewNode {
    coord: Coord,
    resolved: ResolvedVersion,
    project: Option<ResolvedProject>,
    hard: Option<VersionReq>,
    relocations: Vec<CoordKey>,
    error: Option<usize>,
    childless: bool,
}

struct Walk<'s, 'a, B: Backend> {
    solver: &'s Solver<'a, B>,
    mode: MavenMode,
    types: ArtifactTypes,
    depth_first: bool,
    root: Node,
    tree: Tree,
    deps: Vec<Option<Dep>>,
    queue: VecDeque<Pending>,
    reads: HashMap<ReadKey, Reads>,
    /// maven-resolver 1.9's DataPool of descriptors: each artifact is read
    /// once, from the repositories of the first node to ask.
    descriptors: HashMap<DescriptorKey, Read>,
    /// What the Maven 3.9 mode read into that pool from repositories.
    readings: BTreeMap<DescriptorKey, PomReading>,
    relocations: RelocationCache,
    /// Whether the first declaration to ask for each artifact was a system
    /// one, by the artifact's [`ReadKey`] for a declaration that is not.
    first_system: HashMap<ReadKey, bool>,
    errors: Vec<Option<Unread>>,
    pool: HashMap<PoolKey, usize>,
    skipper: Skipper,
    next_declared_at: u64,
    /// Whether to hint each read as it is asked for.
    hinting: bool,
    hinted_artifacts: HashSet<usize>,
    /// The `group:artifact` of each of the root's own dependencies, and
    /// what they exclude.
    root_declared: HashSet<(String, String)>,
    root_excludes: Vec<ExclusionKey>,
}

impl<'s, 'a, B: Backend> Walk<'s, 'a, B> {
    fn start(solver: &'s Solver<'a, B>, root: SolverRoot) -> Result<Self> {
        let SolverRoot {
            coord,
            dependencies,
            scope,
        } = root;
        let path = PathNode::root(&coord);
        let mode = solver.mode();
        let mut walk = Self {
            solver,
            mode,
            types: solver.types(),
            depth_first: solver.depth_first,
            root: Node {
                workspace_module: solver.backend.workspace_module(&coord),
                coord,
                type_: None,
                scope,
                optional: false,
                repo_url: None,
                build_repo: None,
                repos: RepoContext::default(),
                checksum: None,
                local: false,
                system_path: None,
                winner_parent: None,
                version_origin: Default::default(),
            },
            tree: Tree {
                nodes: vec![TreeNode {
                    children: 0,
                    entry: None,
                }],
                lists: vec![Vec::new()],
            },
            deps: vec![None],
            queue: VecDeque::new(),
            reads: HashMap::new(),
            descriptors: HashMap::new(),
            readings: BTreeMap::new(),
            relocations: RelocationCache::default(),
            first_system: HashMap::new(),
            errors: Vec::new(),
            pool: HashMap::new(),
            skipper: Skipper::default(),
            next_declared_at: 0,
            hinting: false,
            hinted_artifacts: HashSet::new(),
            root_declared: HashSet::new(),
            root_excludes: Vec::new(),
        };
        let parents: Arc<[usize]> = Arc::from([ROOT]);
        let exclusions: Arc<[ExclusionKey]> = Arc::from(Vec::new());
        for dependency in dependencies {
            let item = QueueItem {
                dependency: Arc::new(dependency),
                managed_scope: false,
                depth: 1,
                declared_at: walk.declare(),
                exclusions: Arc::clone(&exclusions),
                path: Arc::clone(&path),
            };
            let Some(pending) = walk.select(item, &parents, false)? else {
                continue;
            };
            // Before any of them is read, so the module's dependencies
            // download nothing first.
            let version = &pending.version;
            refuse_undefined_property(solver, &pending.item, version)?;
            let dependency = &pending.item.dependency;
            let (group, artifact) = (&dependency.group_id, &dependency.artifact_id);
            parse_requested_requirement(group, artifact, version, solver.mode())?;
            walk.root_declared.insert((group.clone(), artifact.clone()));
            (walk.root_excludes).extend(dependency.exclusions.iter().map(ExclusionKey::from));
            walk.submit(pending)?;
        }
        Ok(walk)
    }

    fn declare(&mut self) -> u64 {
        let at = self.next_declared_at;
        self.next_declared_at += 1;
        at
    }

    /// `item`, declared below `parents`, to read, unless the selectors drop
    /// it: they test the dependency as declared, and drop `test`,
    /// `provided` and optional ones only below the root's own. Then the
    /// root's management applies, its version unless `keep_version`.
    fn select(
        &self,
        item: QueueItem,
        parents: &Arc<[usize]>,
        keep_version: bool,
    ) -> Result<Option<Pending>> {
        let dependency = &item.dependency;
        if is_excluded(dependency, &item.exclusions)
            || (item.depth > 1 && !dependency.is_followed_transitively())
        {
            return Ok(None);
        }
        let requested = dependency.version.clone();
        let management = &self.solver.management;
        let mut item = apply_managed_metadata(management, item);
        let dependency = &item.dependency;
        let (version, origin) = match keep_version {
            true => (
                (dependency.version.as_deref()).ok_or_else(|| ResolveError::MissingVersion {
                    group_id: dependency.group_id.clone(),
                    artifact_id: dependency.artifact_id.clone(),
                })?,
                Default::default(),
            ),
            false => (
                resolve_version_str(management, dependency, item.depth)?,
                version_origin(
                    management,
                    dependency,
                    item.depth,
                    (&dependency.group_id, &dependency.artifact_id),
                ),
            ),
        };
        let version = Arc::from(version);
        // The origin goes with the item, through any relocation, to its node.
        if origin.0.is_some() || item.dependency.origin.0.is_some() {
            Arc::make_mut(&mut item.dependency).origin = origin;
        }
        Ok(Some(Pending {
            version,
            item,
            requested,
            parents: Arc::clone(parents),
        }))
    }

    fn read_key(&self, pending: &Pending, system: bool) -> ReadKey {
        let coord = coord_of(
            &pending.item.dependency,
            Version::unresolved(""),
            &self.types,
        );
        ReadKey {
            key: CoordKey::from(&coord),
            version: Arc::clone(&pending.version),
            system,
            repos: (self.depth_first).then(|| pending.item.path.repos.clone()),
        }
    }

    /// Queue `pending`, and ask for its reads, as maven-resolver does when
    /// it queues a dependency.
    fn submit(&mut self, pending: Pending) -> Result<()> {
        check_bounds(self.queue.len(), pending.item.declared_at, &pending.item)?;
        self.ask(&pending);
        self.queue.push_back(pending);
        Ok(())
    }

    /// Ask for the reads of what `pending` requests. The first to ask
    /// fixes the repositories they come from.
    fn ask(&mut self, pending: &Pending) {
        let system = self.is_system(&pending.item);
        let first = self.read_key(pending, false);
        self.first_system.entry(first).or_insert(system);
        let key = self.read_key(pending, system);
        if self.reads.contains_key(&key) {
            return;
        }
        if self.hinting {
            self.hint(pending);
        }
        self.reads
            .insert(key, Reads::Asked(Box::new(pending.clone())));
    }

    /// Tell the backend which POMs `pending` will read.
    fn hint(&self, pending: &Pending) {
        let backend = self.solver.backend;
        let dependency = &pending.item.dependency;
        if !backend.prefetches() || dependency.effective_scope() == Scope::System {
            return;
        }
        let (group, artifact) = (&dependency.group_id, &dependency.artifact_id);
        let repos = &pending.item.path.repos;
        match parse_requested_requirement(group, artifact, &pending.version, self.solver.mode()) {
            Ok(RequestedRequirement::Ranges(req)) => {
                backend.prefetch_range(group, artifact, &req, repos);
            }
            Ok(requirement) => {
                if let Some(coord) = fixed_coord(dependency, requirement, &self.types) {
                    backend.prefetch_project(&coord, repos);
                    let scope = self.derived_scope(&pending.parents, &pending.item);
                    if self.kept_artifact(pending)
                        && !names_property(&coord)
                        && !self.unfetched(&coord, scope)
                    {
                        backend.prefetch_kept_artifact(&coord, repos);
                    }
                }
            }
            Err(_) => {}
        }
    }

    /// Whether the graph likely keeps `pending` at the version it requests:
    /// one of the root's own dependencies, which a depth-first walk places
    /// only once the whole graph is in, or one [`Self::managed_version`]
    /// fixes. A breadth-first walk places the root's own at once.
    fn kept_artifact(&self, pending: &Pending) -> bool {
        (self.depth_first && pending.item.depth == 1) || self.managed_version(pending)
    }

    /// Whether the root's management fixes the version `pending` requests,
    /// below the root's own dependencies, so that every declaration of it
    /// requests that version, and the graph likely keeps it: it is not
    /// optional, test or provided, and the root neither declares it, which
    /// would win, nor excludes it below one of its own dependencies, where
    /// a declaration below another may lose.
    fn managed_version(&self, pending: &Pending) -> bool {
        let dependency = &pending.item.dependency;
        let (group, artifact) = (&dependency.group_id, &dependency.artifact_id);
        let managed =
            (self.solver.management.managed(dependency)).and_then(|entry| entry.version.as_deref());
        pending.item.depth > 1
            && managed == Some(&*pending.version)
            && dependency.is_followed_transitively()
            && !(self.root_declared).contains(&(group.clone(), artifact.clone()))
            && !excludes(&self.root_excludes, group, artifact)
    }

    /// The versions and descriptors of what `pending` requests, and
    /// whether its nodes keep none of their dependencies. Maven reads one
    /// descriptor for every declaration of an artifact, as the first to ask
    /// for it does: none for a system dependency, which a later declaration
    /// that is not system then takes for its own. raeva still reads that
    /// one's POM, for where its file is, but keeps none of its
    /// dependencies; a later system declaration takes the first one's.
    /// The depth-first collector reads none for a system dependency and
    /// its own for every other.
    async fn descriptors(&mut self, pending: &Pending) -> Result<(Arc<Listing>, bool)> {
        let system = self.is_system(&pending.item);
        if self.depth_first {
            return Ok((self.listing(pending, system).await?, false));
        }
        let first = (self.first_system.get(&self.read_key(pending, false)))
            .copied()
            .unwrap_or(system);
        if system && !first {
            check_system_path(&pending.item.dependency)?;
        }
        let listing = self.listing(pending, system && first).await?;
        Ok((listing, first && !system))
    }

    /// The versions and descriptors of what `pending` requests, read once
    /// for every declaration that requests the same.
    async fn listing(&mut self, pending: &Pending, system: bool) -> Result<Arc<Listing>> {
        let key = self.read_key(pending, system);
        let asked = match self.reads.remove(&key) {
            Some(Reads::Read(listing)) => {
                self.reads.insert(key, Reads::Read(Arc::clone(&listing)));
                return Ok(listing);
            }
            Some(Reads::Asked(asked)) => *asked,
            None => pending.clone(),
        };
        // Maven reads nothing for an artifact a system declaration asked
        // for first.
        let maven = system || self.first_system.get(&key) != Some(&true);
        let listing = Arc::new(self.read_listing(&asked, maven).await?);
        // The breadth-first collector keeps each version of a range it read
        // for a declaration of that version that has not asked yet.
        if !self.depth_first && listing.versions.len() > 1 {
            for listed in &listing.versions {
                let version = ReadKey {
                    version: Arc::from(listed.resolved.version.as_str()),
                    system: false,
                    ..key.clone()
                };
                (self.reads.entry(version)).or_insert_with(|| {
                    Reads::Read(Arc::new(Listing {
                        hard: None,
                        versions: vec![listed.clone()],
                    }))
                });
            }
        }
        self.reads.insert(key, Reads::Read(Arc::clone(&listing)));
        Ok(listing)
    }

    async fn read_listing(&mut self, asked: &Pending, maven: bool) -> Result<Listing> {
        let solver = self.solver;
        let item = &asked.item;
        let dependency = &item.dependency;
        let version = &*asked.version;
        // Maven finds no POM for a dependency whose coordinate names an
        // undefined property, and fails on it only once it wins.
        if let Err(error) = refuse_undefined_property(solver, item, version) {
            if item.depth == 1
                || dependency.effective_scope() == Scope::System
                || version.starts_with(['[', '('])
            {
                return Err(error);
            }
            let coord = coord_of(dependency, Version::unresolved(version), &self.types);
            return Ok(Listing {
                hard: None,
                versions: vec![Listed {
                    resolved: ResolvedVersion {
                        version: coord.version.clone(),
                        repo: None,
                    },
                    read: Some(Ok(Arc::new(Self::empty(coord)))),
                }],
            });
        }
        let (group, artifact) = (&dependency.group_id, &dependency.artifact_id);
        let unbuilt =
            (self.root.workspace_module.as_deref()).filter(|_| !self.takes_pom(dependency));
        let (requirement, mut versions, highest) =
            requested_versions(solver, group, artifact, version, &item.path.repos, unbuilt)
                .await
                .map_err(|err| declared_below(err, &item.path))?;
        versions.push(highest);
        // The depth-first collector takes the first of equal spellings.
        (solver.backend).order_taken((group, artifact), &mut versions, self.depth_first);
        let mode = self.mode;
        if !self.depth_first {
            versions.reverse();
            // Maven keys the versions of a range by their value: two
            // spellings of one version read once, as the first in
            // highest-first order.
            versions.dedup_by(|later, kept| later.version.cmp_in(&kept.version, mode).is_eq());
        }
        let hard = hard_constraint(&requirement);
        let system = self.is_system(item);
        if !system && matches!(requirement, RequestedRequirement::Ranges(_)) {
            self.refuse_reactor_artifact(item, version, &versions)?;
        }
        if !system && matches!(requirement, RequestedRequirement::Ranges(_)) {
            for resolved in &versions {
                let coord = coord_of(dependency, resolved.version.clone(), &self.types);
                solver
                    .backend
                    .prefetch_range_version(&coord, &item.path.repos);
            }
        }
        let mut listed = Vec::with_capacity(versions.len());
        for resolved in versions {
            let coord = coord_of(dependency, resolved.version.clone(), &self.types);
            let read = if system {
                check_system_path(dependency)?;
                Some(Ok(Arc::new(Self::empty(coord))))
            } else if self.depth_first {
                None
            } else {
                Some(self.descriptor(item, coord, maven).await?)
            };
            listed.push(Listed { resolved, read });
        }
        Ok(Listing {
            hard,
            versions: listed,
        })
    }

    /// Refuses a range over a reactor module for an artifact other than its
    /// POM or main artifact. Maven lists the module only when the module
    /// has that artifact, which depends on what its build has run. Maven
    /// 3.10 takes a POM with a classifier for such another artifact. A
    /// packaging the consumer has no handler for, or one an expression
    /// names, is taken to make the main artifact asked for.
    fn refuse_reactor_artifact(
        &self,
        item: &QueueItem,
        requested: &str,
        versions: &[ResolvedVersion],
    ) -> Result<()> {
        let dependency = &item.dependency;
        let extension = dependency.effective_type_in(&self.types);
        let classified = dependency.effective_classifier_in(&self.types).is_some();
        let pom = self.takes_pom(dependency);
        let modules: Vec<String> = (versions.iter())
            .filter_map(|resolved| {
                let coord = coord_of(dependency, resolved.version.clone(), &self.types);
                let packaging = self.solver.backend.workspace_packaging(&coord)?;
                let known = !packaging.contains("${")
                    && (is_core_type(&packaging, self.mode)
                        || self.types.extension(&packaging) != packaging
                        || self.types.classifier(&packaging).is_some());
                let main = !classified && (!known || extension == self.types.extension(&packaging));
                (!pom && !main).then(|| self.solver.backend.workspace_module(&coord))?
            })
            // The module being resolved has made none, so its version comes
            // from a repository.
            .filter(|module| self.root.workspace_module.as_ref() != Some(module))
            .collect();
        if modules.is_empty() {
            return Ok(());
        }
        let error = ResolveError::ReactorChoice {
            coord: format!("{}:{}", dependency.group_id, dependency.artifact_id),
            requested: requested.trim().to_string(),
            modules,
            reason: "Maven lists a module only when its build has made the artifact asked for"
                .to_string(),
        };
        Err(declared_below(error, &item.path))
    }

    /// The descriptor of `coord`, as `item` requests it, or in the Maven 3.9
    /// mode as the first node to request it did, by artifact type: a
    /// `maven-plugin` and a `jar` share a conflict group, not a descriptor.
    async fn descriptor(&mut self, item: &QueueItem, coord: Coord, maven: bool) -> Result<Read> {
        let key = DescriptorKey::of(&coord, &item.dependency);
        if let Some(read) = self.descriptors.get(&key) {
            return Ok(read.clone());
        }
        let read = match self.read(item, coord.clone()).await? {
            Ok(fetched) => {
                if self.mode == MavenMode::Maven39
                    && maven
                    && let Some(reading) = reading(&fetched)?
                {
                    self.readings.insert(key.clone(), reading);
                }
                Ok(Arc::new(fetched))
            }
            Err(err) => {
                let item = item.clone();
                let unread = Unread {
                    error: err,
                    item,
                    coord: coord.clone(),
                    maven,
                };
                self.errors.push(Some(unread));
                Err((coord, self.errors.len() - 1))
            }
        };
        if self.mode == MavenMode::Maven39 {
            self.descriptors.insert(key, read.clone());
        }
        Ok(read)
    }

    /// What Maven reads for an artifact without a descriptor.
    fn empty(coord: Coord) -> Fetched {
        let project = Project::new(&coord.group_id, &coord.artifact_id, coord.version.as_str());
        Fetched {
            target: coord,
            project: ResolvedProject {
                project: Arc::new(project),
                repo_url: None,
                workspace_module: None,
            },
            snapshot: None,
            relocations: Vec::new(),
            reads: Vec::new(),
        }
    }

    /// The descriptor of `coord`, as `item` requests it. The outer error
    /// fails the build whether or not the artifact wins; [`Walk::finish`]
    /// names the winner's path in the inner one.
    async fn read(&self, item: &QueueItem, coord: Coord) -> Result<Result<Fetched>> {
        let solver = self.solver;
        if names_property(&coord) {
            return Ok(Ok(Self::empty(coord)));
        }
        let repos = &item.path.repos;
        let fetched = match self.mode {
            MavenMode::Maven39 => {
                (solver.fetch_project_with_relocation_cached(&coord, repos, &self.relocations))
                    .await
            }
            MavenMode::Maven310 => {
                let gav = format!("{}:{}:{}", coord.group_id, coord.artifact_id, coord.version);
                (solver
                    .fetch_project_with_relocation_310(&coord, repos)
                    .await)
                    .map_err(|err| load_error(&item.path, gav, err))?
            }
        };
        let relocation::Fetched {
            mut target,
            resolved: project,
            snapshot,
            inherited_build,
            reads,
        } = match fetched {
            Ok(fetched) => fetched,
            Err(err) => return Ok(Err(err)),
        };
        // A build kept along a relocation without a version is the target's
        // version itself: Maven 3.9 mediates and constrains it as that build.
        if let Some(build) = snapshot.as_ref().filter(|_| inherited_build) {
            target.version = build.version.clone();
        }
        let relocations = match !same_text(&target, &coord) {
            true => (reads.split_last().map_or(&[][..], |(_, from)| from).iter())
                .map(|read| CoordKey::from(&read.coord))
                .collect(),
            false => Vec::new(),
        };
        Ok(Ok(Fetched {
            target,
            project,
            snapshot,
            relocations,
            reads,
        }))
    }

    /// maven-resolver's processDependency: a node for each version. A
    /// version that relocates is processed again as its target, right away;
    /// resolver 2 still counts the versions after it, and 1.9 does not.
    /// The depth-first collector processes the dependencies of each node
    /// before the next version.
    async fn process(&mut self, pending: Pending) -> Result<()> {
        struct Frame {
            pending: Pending,
            listing: Arc<Listing>,
            childless: bool,
            next: usize,
            relocations: Vec<CoordKey>,
            keep_version: bool,
            passes: usize,
        }
        enum Step {
            Versions(Frame),
            Dependencies(VecDeque<Pending>),
        }
        let mut steps = vec![Step::Dependencies(VecDeque::from([pending]))];
        while let Some(step) = steps.last_mut() {
            let frame = match step {
                Step::Versions(frame) => frame,
                Step::Dependencies(queued) => {
                    let Some(pending) = queued.pop_front() else {
                        steps.pop();
                        continue;
                    };
                    let (listing, childless) = self.descriptors(&pending).await?;
                    steps.push(Step::Versions(Frame {
                        pending,
                        listing,
                        childless,
                        next: 0,
                        relocations: Vec::new(),
                        keep_version: false,
                        passes: 0,
                    }));
                    continue;
                }
            };
            let Some(listed) = frame.listing.versions.get(frame.next).cloned() else {
                steps.pop();
                continue;
            };
            frame.next += 1;
            let hard = frame.listing.hard.clone();
            let (keep_version, relocations) = (frame.keep_version, frame.relocations.clone());
            let (childless, passes) = (frame.childless, frame.passes);
            let pending = frame.pending.clone();
            let read = match listed.read {
                Some(read) => read,
                None => {
                    let version = listed.resolved.version.clone();
                    let coord = coord_of(&pending.item.dependency, version, &self.types);
                    self.descriptor(&pending.item, coord, true).await?
                }
            };
            let fetched = match read {
                Ok(fetched) => fetched,
                Err((coord, error)) => {
                    let new = NewNode {
                        coord,
                        resolved: listed.resolved,
                        project: None,
                        hard,
                        relocations,
                        error: Some(error),
                        childless,
                    };
                    self.add_node(&pending, new)?;
                    continue;
                }
            };
            // A reactor module reached through an external POM, winning or
            // not, is no edge of the module's own record, however its
            // descriptor was read first.
            if fetched.project.workspace_module.is_some()
                && (!fetched.relocations.is_empty()
                    || (pending.item.path.below_root()).any(|(key, version)| {
                        !(self.solver.backend).is_reactor_module(
                            &key.group_id,
                            &key.artifact_id,
                            version,
                        )
                    }))
            {
                self.solver.backend.note_transitive_selection();
            }
            // The descriptor the node takes in Maven relocates nowhere.
            let fetched = match childless && !fetched.relocations.is_empty() {
                true => {
                    let version = listed.resolved.version.clone();
                    Arc::new(Self::empty(coord_of(
                        &pending.item.dependency,
                        version,
                        &self.types,
                    )))
                }
                false => fetched,
            };
            let target = &fetched.target;
            // A reactor module is its base version, whatever build a
            // repository has of the module being resolved.
            let reactor =
                (self.reactor_module_of(&fetched.project, &pending.item.dependency)).is_some();
            let resolved = (fetched.snapshot.clone())
                .filter(|_| !reactor)
                .unwrap_or_else(|| listed.resolved.clone());
            let new = NewNode {
                coord: target.clone(),
                resolved,
                project: Some(fetched.project.clone()),
                hard,
                relocations,
                error: None,
                childless,
            };
            // A cycle is cut at the nearest ancestor of the same artifact,
            // whose children the new node shares.
            let key = CoordKey::from(target);
            let cycle = (pending.parents.iter().rev())
                .take_while(|&&node| node != ROOT)
                .find(|&&node| (self.deps[node].as_ref()).is_some_and(|dep| dep.key() == key))
                .copied();
            if let Some(ancestor) = cycle {
                tracing::debug!(
                    cycle = %pending.item.path.format_cycle(&key),
                    "breaking cyclic dependency"
                );
                let node = self.add_node(&pending, new)?;
                self.tree.nodes[node].children = self.tree.nodes[ancestor].children;
                continue;
            }
            if fetched.relocations.is_empty() {
                let node = self.add_node(&pending, new)?;
                if let Some(dependencies) = self.expand(node, keep_version)? {
                    steps.push(Step::Dependencies(dependencies));
                }
                continue;
            }
            // Maven recurses without end on a managed chain that comes back.
            if passes >= MAX_RELOCATION_MANAGEMENT_PASSES {
                let from = &pending.item.dependency;
                return Err(ResolveError::RelocationCycle(format!(
                    "{}:{} -> {target} (more than {MAX_RELOCATION_MANAGEMENT_PASSES} managed \
                     relocations)",
                    from.group_id, from.artifact_id
                )));
            }
            let source = coord_of(
                &pending.item.dependency,
                listed.resolved.version,
                &self.types,
            );
            let relocated = self.relocate(&pending, &source, target)?;
            if self.mode == MavenMode::Maven39 {
                steps.pop();
            }
            let Some((relocated, keep_version)) = relocated else {
                continue;
            };
            self.ask(&relocated);
            let (listing, childless) = self.descriptors(&relocated).await?;
            steps.push(Step::Versions(Frame {
                pending: relocated,
                listing,
                childless,
                next: 0,
                relocations: fetched.relocations.clone(),
                keep_version,
                passes: passes + 1,
            }));
        }
        Ok(())
    }

    /// `from` requesting its relocation `target` instead, below the
    /// `source` POM that relocates, unless the selectors drop that, and
    /// whether the target and its dependencies keep their versions, as
    /// within one group and artifact: the root's management applies again,
    /// to the target.
    fn relocate(
        &self,
        from: &Pending,
        source: &Coord,
        target: &Coord,
    ) -> Result<Option<(Pending, bool)>> {
        let item = &from.item;
        let (group, artifact) = (target.group_id.as_str(), target.artifact_id.as_str());
        if excludes(&item.exclusions, group, artifact)
            || (item.depth > 1 && !item.dependency.is_followed_transitively())
        {
            return Ok(None);
        }
        let keep_version =
            group == item.dependency.group_id && artifact == item.dependency.artifact_id;
        let management = &self.solver.management;
        let origin = match keep_version {
            true => item.dependency.origin.clone(),
            false => version_origin(management, &item.dependency, item.depth, (group, artifact)),
        };
        let mut dependency = Dependency {
            group_id: group.to_string(),
            artifact_id: artifact.to_string(),
            version: Some(target.version.to_string()),
            origin,
            ..(*item.dependency).clone()
        };
        let managed_scope = (management.managed(&dependency).cloned())
            .is_some_and(|managed| manage(&managed, &mut dependency, item.depth));
        let version: Arc<str> = match keep_version {
            true => Arc::from(target.version.as_str()),
            false => Arc::from(resolve_version_str(management, &dependency, item.depth)?),
        };
        let repos = item.path.repos.clone();
        let item = QueueItem {
            dependency: Arc::new(dependency),
            managed_scope,
            path: PathNode::extend(&item.path, source, &source.version, repos),
            ..item.clone()
        };
        let pending = Pending {
            item,
            version,
            requested: from.requested.clone(),
            parents: Arc::clone(&from.parents),
        };
        Ok(Some((pending, keep_version)))
    }

    fn add_node(&mut self, pending: &Pending, new: NewNode) -> Result<usize> {
        check_bounds(0, self.tree.nodes.len() as u64, &pending.item)?;
        let dependency = &pending.item.dependency;
        let entry = Entry {
            key: CoordKey::from(&new.coord),
            relocations: new.relocations,
            version: new.coord.version.clone(),
            hard: new.hard,
            scope: dependency.effective_scope(),
            optional: dependency.effective_optional(),
            managed_scope: pending.item.managed_scope,
        };
        let local = self.is_system(&pending.item);
        let node = self.tree.nodes.len();
        self.tree.lists.push(Vec::new());
        self.tree.nodes.push(TreeNode {
            children: self.tree.lists.len() - 1,
            entry: Some(entry),
        });
        let parent = *pending.parents.last().expect("below the root");
        let list = self.tree.nodes[parent].children;
        self.tree.lists[list].push(node);
        self.deps.push(Some(Dep {
            item: pending.item.clone(),
            requested: pending.requested.clone(),
            coord: new.coord,
            resolved: new.resolved,
            project: new.project,
            error: new.error,
            childless: new.childless,
            parents: Arc::clone(&pending.parents),
            local,
        }));
        Ok(node)
    }

    /// maven-resolver's doRecurse: share the children of an equal node
    /// already expanded, or else, unless the skipper skips the node, queue
    /// its dependencies, or return them for the depth-first collector to
    /// process next. Only the breadth-first collector leaves their versions
    /// unmanaged below a relocation within one group and artifact.
    fn expand(&mut self, node: usize, keep_version: bool) -> Result<Option<VecDeque<Pending>>> {
        let dep = self.deps[node].as_ref().expect("a dependency");
        let artifact = dep.artifact();
        let parents = Arc::clone(&dep.parents);
        let with_node: Arc<[usize]> = parents.iter().copied().chain([node]).collect();
        let project = (dep.project.as_ref())
            .filter(|project| {
                !dep.childless
                    && follows(&dep.item.dependency, &self.types)
                    && !project.project.dependencies.is_empty()
            })
            .map(|project| Arc::clone(&project.project));
        let Some(project) = project else {
            if !self.depth_first
                && !self.skipper.skip(node, &artifact, &parents)
                && self.skipper.cache(&artifact, &with_node)
            {
                self.hint_artifact(node, None);
            }
            return Ok(None);
        };
        let item = dep.item.clone();
        let (coord, version) = (dep.coord.clone(), dep.resolved.version.clone());
        let repos = (self.solver.backend).extend_repo_context(&item.path.repos, &coord, &project);
        let exclusions = extend_exclusions(
            &item.exclusions,
            &item.dependency.exclusions,
            self.solver.backend.drops_wagons_below(&coord),
        );
        let mut sorted = exclusions.to_vec();
        sorted.sort();
        sorted.dedup();
        let key = PoolKey {
            artifact: artifact.clone(),
            repos: repos.clone(),
            exclusions: sorted,
        };
        if let Some(&list) = self.pool.get(&key) {
            self.tree.nodes[node].children = list;
            return Ok(None);
        }
        if !self.depth_first && self.skipper.skip(node, &artifact, &parents) {
            return Ok(None);
        }
        let path = PathNode::extend(&item.path, &coord, &version, repos);
        let keep_version = keep_version && !self.depth_first;
        let mut dependencies = VecDeque::new();
        for dependency in &project.dependencies {
            let mut dependency = dependency.clone();
            if dependency.version.is_none() {
                manage_child(&project.dependency_management, &mut dependency, &self.types);
            }
            let child = QueueItem {
                dependency: Arc::new(dependency),
                managed_scope: false,
                depth: item.depth + 1,
                declared_at: self.declare(),
                exclusions: Arc::clone(&exclusions),
                path: Arc::clone(&path),
            };
            let Some(pending) = self.select(child, &with_node, keep_version)? else {
                continue;
            };
            if !self.depth_first {
                self.submit(pending)?;
                continue;
            }
            check_bounds(0, pending.item.declared_at, &pending.item)?;
            if self.hinting {
                self.hint(&pending);
            }
            dependencies.push_back(pending);
        }
        self.pool.insert(key, self.tree.nodes[node].children);
        if self.depth_first {
            return Ok(Some(dependencies));
        }
        if self.skipper.cache(&artifact, &with_node) {
            self.hint_artifact(node, None);
        }
        Ok(None)
    }

    /// Whether the artifact pass leaves out the file of `coord` at `scope`.
    fn unfetched(&self, coord: &Coord, scope: Scope) -> bool {
        (self.solver.unfetched).is_some_and(|unfetched| unfetched(coord, scope))
    }

    /// The scope `item` below `parents` derives, as far as it matters to
    /// [`Self::unfetched`]: below a `provided` or `test` node every node
    /// derives that scope.
    fn derived_scope(&self, parents: &[usize], item: &QueueItem) -> Scope {
        (parents.iter())
            .filter_map(|&at| self.deps[at].as_ref())
            .map(|dep| &dep.item)
            .chain([item])
            .map(|item| item.dependency.effective_scope())
            .find(|scope| matches!(scope, Scope::Provided | Scope::Test))
            .unwrap_or(Scope::Compile)
    }

    /// Start downloading the artifact of `node`, which the skipper takes
    /// for the winner, or which won, with its `scope` once known.
    fn hint_artifact(&mut self, node: usize, scope: Option<Scope>) {
        let Some(dep) = self.deps[node].as_ref() else {
            return;
        };
        let Some(project) = &dep.project else {
            return;
        };
        let coord = Coord {
            version: dep.resolved.version.clone(),
            ..dep.coord.clone()
        };
        let scope = scope.unwrap_or_else(|| self.derived_scope(&dep.parents, &dep.item));
        if self.unfetched(&coord, scope) || !self.hinted_artifacts.insert(node) {
            return;
        }
        let unread = (coord.classifier.as_deref()).is_some_and(|c| c.contains("${"))
            || names_property(&coord);
        if dep.local || unread || project.workspace_module.is_some() {
            return;
        }
        let build_repo = dep.resolved.repo.as_ref();
        let repos = &dep.item.path.repos;
        (self.solver.backend).prefetch_artifact(
            &coord,
            build_repo,
            project.repo_url.as_deref(),
            repos,
        );
    }

    /// The reactor modules from the one `module` (`coord`) is declared in
    /// up to `module` itself, if `module` is among those on the way down to
    /// it.
    fn workspace_cycle(&self, parents: &[usize], coord: &Coord, module: &str) -> Option<String> {
        let name = |coord: &Coord| format!("{}:{}", coord.group_id, coord.artifact_id);
        let mut cycle = vec![name(coord)];
        for &node in parents.iter().rev() {
            let (own, at) = match &self.deps[node] {
                None => (self.root.workspace_module.as_deref(), &self.root.coord),
                Some(dep) => (
                    dep.project.as_ref()?.workspace_module.as_deref(),
                    &dep.coord,
                ),
            };
            cycle.push(name(at));
            if own? == module {
                cycle.reverse();
                return Some(cycle.join(" -> "));
            }
        }
        None
    }

    /// The reactor module that serves `dep`. The module being resolved has
    /// built nothing when Maven resolves its dependencies, so it serves
    /// only its POM, which Maven 3.10 takes without a classifier; another
    /// artifact of its own comes from a repository, its model from the
    /// module.
    fn reactor_module<'d>(&self, dep: &'d Dep) -> Option<&'d str> {
        self.reactor_module_of(dep.project.as_ref()?, &dep.item.dependency)
    }

    fn reactor_module_of<'p>(
        &self,
        project: &'p ResolvedProject,
        dependency: &Dependency,
    ) -> Option<&'p str> {
        let module = project.workspace_module.as_deref()?;
        (self.root.workspace_module.as_deref() != Some(module) || self.takes_pom(dependency))
            .then_some(module)
    }

    /// Whether `dependency` asks for a POM that Maven's reactor reader
    /// serves from the module's file: in Maven 3.10 one without a
    /// classifier.
    fn takes_pom(&self, dependency: &Dependency) -> bool {
        let classified = dependency.effective_classifier_in(&self.types).is_some();
        dependency.effective_type_in(&self.types) == "pom"
            && (self.mode == MavenMode::Maven39 || !classified)
    }

    fn finish(mut self) -> Result<Graph> {
        let declared = self.tree.lists.clone();
        let mut resolved = match conflict::resolve(&mut self.tree, self.root.scope, self.mode) {
            Ok(resolved) => resolved,
            Err(unsolvable) => return Err(self.conflict(unsolvable)),
        };
        // The winners left in the tree, depth first from the root, each
        // below the winner whose children it is among. A node shares the
        // children of an equal one, which may have lost.
        let mut winners = Vec::new();
        let mut via = vec![ROOT; self.tree.nodes.len()];
        let mut seen = vec![false; self.tree.nodes.len()];
        let mut stack = vec![(ROOT, 0usize)];
        while let Some((node, next)) = stack.last_mut() {
            let list = &self.tree.lists[self.tree.nodes[*node].children];
            let Some(&child) = list.get(*next) else {
                stack.pop();
                continue;
            };
            *next += 1;
            resolved.stand_in(child);
            if resolved.winner_of(child) == Some(child)
                && !std::mem::replace(&mut seen[child], true)
            {
                via[child] = *node;
                winners.push(child);
                stack.push((child, 0));
            }
        }
        // A module that mediation keeps fails when its path leads from
        // itself. The check waits for mediation, since a range over a
        // module collects the module beside the versions that may beat it.
        // Maven's sorter links no module to itself, so the module's own
        // dependency on its own coordinates is no cycle.
        for &winner in &winners {
            let dep = self.deps[winner].as_ref().expect("a dependency");
            if let Some(module) = (dep.project.as_ref()).and_then(|p| p.workspace_module.as_deref())
                && dep.parent() != ROOT
                && let Some(cycle) = self.workspace_cycle(&dep.parents, &dep.coord, module)
            {
                return Err(ResolveError::WorkspaceDependencyCycle { cycle });
            }
        }
        let mut paths: Vec<Option<Arc<PathNode>>> = vec![None; self.tree.nodes.len()];
        let mut rerouted = vec![false; self.tree.nodes.len()];
        for &winner in &winners {
            let dep = self.deps[winner].as_ref().expect("a dependency");
            let parent = via[winner];
            let moved =
                (self.deps[parent].as_ref()).filter(|_| parent != dep.parent() || rerouted[parent]);
            let path = match (moved, paths[parent].as_ref()) {
                (Some(by), Some(above)) => {
                    rerouted[winner] = true;
                    let repos = dep.item.path.repos.clone();
                    PathNode::extend(above, &by.coord, &by.resolved.version, repos)
                }
                _ => Arc::clone(&dep.item.path),
            };
            paths[winner] = Some(path);
        }
        let item_of = |winner: usize| {
            let dep = self.deps[winner].as_ref().expect("a dependency");
            let path = paths[winner].clone().expect("a winner");
            QueueItem {
                path,
                ..dep.item.clone()
            }
        };
        // Maven fails on a descriptor it could not read, winning or not; a
        // winner's names the winner's path.
        let unread = (winners.iter())
            .find_map(|&winner| {
                let dep = self.deps[winner].as_ref().expect("a dependency");
                let unread = dep.error.and_then(|at| self.errors[at].take())?;
                Some((unread.error, item_of(winner), dep.coord.clone()))
            })
            .or_else(|| {
                let unread = (self.errors.iter_mut())
                    .find_map(|unread| unread.take_if(|unread| unread.maven))?;
                Some((unread.error, unread.item, unread.coord))
            });
        if let Some((error, item, coord)) = unread {
            let gav = format!("{}:{}:{}", coord.group_id, coord.artifact_id, coord.version);
            let error = attach_dropped_repos(self.solver, &item, &coord, error);
            return Err(load_error(&item.path, gav, error));
        }
        for &winner in &winners {
            let dep = self.deps[winner].as_ref().expect("a dependency");
            if names_property(&dep.coord) {
                let item = item_of(winner);
                refuse_undefined_property(self.solver, &item, dep.coord.version.as_str())
                    .map_err(|err| declared_below(err, &item.path))?;
            }
        }
        // The module's own artifact from a repository that failed.
        let own_artifact = (winners.iter()).any(|&winner| {
            let dep = self.deps[winner].as_ref().expect("a dependency");
            let own = dep
                .project
                .as_ref()
                .and_then(|p| p.workspace_module.as_deref());
            own.is_some()
                && own == self.root.workspace_module.as_deref()
                && self.reactor_module(dep).is_none()
        });
        if own_artifact && let Some(error) = self.solver.backend.take_own_failure() {
            return Err(error);
        }
        let mut graph = Graph::new(self.root.clone());
        graph.descriptors = std::mem::take(&mut self.readings);

        let mut at = vec![None; self.tree.nodes.len()];
        at[ROOT] = Some(graph.root());
        for &winner in &winners {
            let dep = self.deps[winner].as_ref().expect("a dependency");
            let entry = self.tree.nodes[winner]
                .entry
                .as_ref()
                .expect("a dependency");
            let local = dep.local;
            let project = dep.project.as_ref();
            let build_repo = dep.resolved.repo.clone().filter(|_| !local);
            let repo_url = (build_repo.as_ref().map(|repo| Arc::clone(&repo.url)))
                .or_else(|| project.and_then(|p| p.repo_url.clone()))
                .filter(|_| !local);
            let type_ = (dep.item.dependency.type_.as_deref())
                .filter(|type_| !type_.is_empty())
                .unwrap_or("jar");
            let extension = dep.coord.packaging.as_deref().unwrap_or("jar");
            let node = graph.insert_node(Node {
                coord: Coord {
                    version: dep.resolved.version.clone(),
                    ..dep.coord.clone()
                },
                type_: (type_ != extension).then(|| type_.to_string()),
                scope: entry.scope,
                optional: entry.optional,
                repo_url,
                build_repo,
                repos: dep.item.path.repos.clone(),
                checksum: None,
                workspace_module: self.reactor_module(dep).map(str::to_string),
                local,
                system_path: dep.item.dependency.system_path.clone(),
                winner_parent: at[via[winner]],
                version_origin: dep.item.dependency.origin.clone(),
            });
            at[winner] = Some(node);
        }
        // Each winner's declarations, losing ones included, point at their
        // group's winner.
        for from in std::iter::once(ROOT).chain(winners.iter().copied()) {
            let source = at[from].expect("a winner");
            for &child in &declared[self.tree.nodes[from].children] {
                let Some(target) = resolved.winner_of(child).and_then(|winner| at[winner]) else {
                    continue;
                };
                let dep = self.deps[child].as_ref().expect("a dependency");
                let item = &dep.item;
                let edge = Edge {
                    scope: item.dependency.effective_scope(),
                    managed_scope: item.managed_scope,
                    declared: (item.depth == 1).then_some(item.declared_at),
                    optional: item.dependency.effective_optional(),
                    exclusions: item.dependency.exclusions.clone(),
                    requested: dep.requested.clone(),
                };
                graph.add_edge(source, target, edge);
            }
        }
        // Offline, a range lists the versions the lock pins: its winners' and
        // the POMs of losing nodes pinned here. Maven reads nothing at or below
        // any other version of a range. A node shares the children of an equal
        // one, wherever that one was. A version spelled apart from the winner's
        // loses, however they compare: its POM is another one. A `[1.0]` range
        // reads no listing, so its loser is pinned as an exact one is.
        let won: HashMap<CoordKey, &str> = (winners.iter())
            .filter_map(|&winner| self.deps[winner].as_ref())
            .map(|dep| (dep.key(), dep.resolved.version.as_str()))
            .collect();
        fn pom(dep: &Dep) -> (&str, &str, String) {
            let coord = &dep.coord;
            (
                coord.group_id.as_str(),
                coord.artifact_id.as_str(),
                coord.version.to_string(),
            )
        }
        let mut pinned: HashMap<_, &Coord> = HashMap::new();
        loop {
            let mut unlisted = Vec::new();
            let mut seen = vec![false; self.tree.nodes.len()];
            let mut stack = vec![ROOT];
            while let Some(node) = stack.pop() {
                for &child in &declared[self.tree.nodes[node].children] {
                    let dep = self.deps[child].as_ref().expect("a dependency");
                    let lost = won.get(&dep.key()) != Some(&dep.resolved.version.as_str());
                    let ranged = (self.tree.nodes[child].entry.as_ref())
                        .is_some_and(|entry| matches!(entry.hard, Some(VersionReq::Ranges(_))));
                    if lost && ranged && !pinned.contains_key(&pom(dep)) {
                        unlisted.push(dep);
                        continue;
                    }
                    if std::mem::replace(&mut seen[child], true) {
                        continue;
                    }
                    if lost && dep.project.is_some() && !dep.childless && !dep.local {
                        pinned.insert(pom(dep), &dep.coord);
                    }
                    stack.push(child);
                }
            }
            if !unlisted.iter().any(|dep| pinned.contains_key(&pom(dep))) {
                break;
            }
        }
        for coord in pinned.values() {
            self.solver.backend.note_loser(coord);
        }
        for &winner in &winners {
            let node = graph.node(at[winner].expect("a winner")).expect("inserted");
            self.hint_artifact(winner, Some(node.scope));
            let path = paths[winner].as_ref().expect("a winner");
            self.solver.backend.note_winner(&node.coord, path)?;
        }
        Ok(graph)
    }

    fn conflict(&self, unsolvable: conflict::Unsolvable) -> ResolveError {
        let dep = self.deps[unsolvable.node].as_ref().expect("a dependency");
        let entry = (self.tree.nodes[unsolvable.node].entry.as_ref()).expect("a dependency");
        let requested = match &entry.hard {
            Some(hard) => hard.to_string(),
            None => dep.coord.version.to_string(),
        };
        let selected = (unsolvable
            .selected
            .and_then(|node| self.deps[node].as_ref()))
        .map_or_else(
            || dep.coord.version.to_string(),
            |d| d.coord.version.to_string(),
        );
        ResolveError::VersionConflict {
            coord: format!("{}:{}", dep.coord.group_id, dep.coord.artifact_id),
            requested,
            selected,
        }
    }
}

impl<B: Backend> Walk<'_, '_, B> {
    fn is_system(&self, item: &QueueItem) -> bool {
        item.dependency.effective_scope() == Scope::System
    }
}

impl Dep {
    fn key(&self) -> CoordKey {
        CoordKey::from(&self.coord)
    }
}
