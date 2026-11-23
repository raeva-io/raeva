use std::sync::Mutex;

use foldhash::HashMap;
use indexmap::IndexSet;
use rv_maven_model::Relocation;
use rv_maven_types::{BlobId, Coord, Version};

use crate::context::RepoContext;
use crate::error::{ResolveError, Result};
use crate::graph::ExactCoord;
use crate::util::lock;

use super::{Backend, ResolvedProject, ResolvedVersion, Solver};

/// Relocations followed from one coordinate. Real chains have one or two;
/// a repository that serves an endless one would otherwise be followed
/// without end, each step caching the rest of the chain.
const MAX_RELOCATIONS: usize = 32;

/// Each coordinate seen on a relocation chain (within a repository context),
/// mapped to the end of the chain and the reads from it up to the end.
pub(crate) type RelocationCache = Mutex<HashMap<(ExactCoord, RepoContext), (Coord, Vec<HopRead>)>>;

/// One coordinate of a relocation chain as its fetch read it.
#[derive(Clone, Debug)]
pub(crate) struct HopRead {
    pub coord: Coord,
    pub pom: HopPom,
}

/// The POM a fetch read for one coordinate.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum HopPom {
    /// A reactor module's, which no repository serves.
    Reactor,
    /// None in any repository.
    Missing,
    /// The bytes of the build fetched.
    Read(BlobId),
    /// The backend kept no record of it.
    Unrecorded,
}

/// Caches every coordinate of `reads`, a whole chain, as mapping to its end.
fn cache_chain(cache: &RelocationCache, reads: &[HopRead], repos: &RepoContext) {
    let (last, before) = reads.split_last().expect("a relocation chain is not empty");
    let mut guard = lock(cache);
    for (index, read) in reads.iter().enumerate() {
        guard.insert(
            (ExactCoord(read.coord.clone()), repos.clone()),
            (
                last.coord.clone(),
                before.get(index..).unwrap_or(&[]).to_vec(),
            ),
        );
    }
}

/// The end of a relocation chain: its coordinate, which keeps a SNAPSHOT's
/// base version, its project, the build a SNAPSHOT resolved to, and whether
/// that build came down a relocation without a version instead of from the
/// end's own metadata.
pub(crate) struct Fetched {
    pub target: Coord,
    pub resolved: ResolvedProject,
    pub snapshot: Option<ResolvedVersion>,
    pub inherited_build: bool,
    /// Each coordinate of the chain as read, the requested one first and
    /// the end last.
    pub reads: Vec<HopRead>,
}

impl<B: Backend> Solver<'_, B> {
    /// The project of `coord`, following its relocations to the end of the
    /// chain, which every coordinate on the chain is cached as mapping to.
    /// Each SNAPSHOT on the chain is fetched as the build its metadata names.
    pub(crate) async fn fetch_project_with_relocation_cached(
        &self,
        coord: &Coord,
        repos: &RepoContext,
        relocation_cache: &RelocationCache,
    ) -> Result<Fetched> {
        let mut chain: IndexSet<ExactCoord> = IndexSet::new();
        let mut reads: Vec<HopRead> = Vec::new();
        let mut current = coord.clone();
        // Maven relocates a SNAPSHOT to the build it resolved, so a
        // relocation without a version keeps that build. A chain that did
        // is not cached: declared directly, its coordinates resolve their own
        // metadata.
        let mut inherited: Option<ResolvedVersion> = None;
        let mut cacheable = true;
        // A fault in a relocation target's own model names each hop after
        // `coord`, the last of `chain` being the target whose model failed.
        let at_hop = |chain: &IndexSet<ExactCoord>, err: ResolveError| {
            (chain.iter().skip(1).rev()).fold(err, |err, hop| err.in_model_of(&hop.0))
        };
        loop {
            if !chain.insert(ExactCoord(current.clone())) {
                return Err(cycle(&chain, &current));
            }
            too_long(&chain, coord)?;
            let cached = match inherited {
                Some(_) => None,
                None => lock(relocation_cache)
                    .get(&(ExactCoord(current.clone()), repos.clone()))
                    .cloned(),
            };
            if let Some((mapped, cached_reads)) = cached {
                // The first is `current`, already on the chain.
                for (index, read) in cached_reads.iter().enumerate() {
                    if index > 0 && !chain.insert(ExactCoord(read.coord.clone())) {
                        return Err(cycle(&chain, &read.coord));
                    }
                }
                reads.extend(cached_reads);
                // The end of a chain maps to itself, which is no cycle.
                let terminal = ExactCoord(mapped.clone()) == ExactCoord(current.clone());
                current = mapped;
                if !terminal && !chain.insert(ExactCoord(current.clone())) {
                    return Err(cycle(&chain, &current));
                }
                too_long(&chain, coord)?;
                let (resolved, snapshot) = (self.fetch_build(&current, None, repos).await)
                    .map_err(|err| at_hop(&chain, err))?;
                reads.push(self.hop_read(&current, &resolved, snapshot.as_ref(), repos));
                if cacheable {
                    cache_chain(relocation_cache, &reads, repos);
                }
                return Ok(Fetched {
                    target: current,
                    resolved,
                    snapshot,
                    inherited_build: false,
                    reads,
                });
            }
            let pinned = inherited.is_some();
            let (resolved, snapshot) = (self.fetch_build(&current, inherited.take(), repos).await)
                .map_err(|err| at_hop(&chain, err))?;
            reads.push(self.hop_read(&current, &resolved, snapshot.as_ref(), repos));
            // Maven reads a reactor module's model from the reactor, which
            // never follows its relocation.
            let next = match &resolved.project.relocation {
                Some(relocation) if resolved.workspace_module.is_none() => {
                    relocation_coord(&current, relocation)?
                }
                _ => current.clone(),
            };
            if ExactCoord(next.clone()) == ExactCoord(current.clone()) {
                if cacheable {
                    cache_chain(relocation_cache, &reads, repos);
                }
                return Ok(Fetched {
                    target: current,
                    resolved,
                    snapshot,
                    inherited_build: pinned,
                    reads,
                });
            }
            let keeps_version = resolved
                .project
                .relocation
                .as_ref()
                .is_some_and(|relocation| non_empty(&relocation.version).is_none());
            if keeps_version && let Some(build) = snapshot {
                // The build, not the repository whose metadata named it.
                inherited = Some(ResolvedVersion {
                    version: build.version,
                    repo: None,
                });
                cacheable = false;
            }
            current = next;
        }
    }

    /// The project of `coord` as Maven 3.10 reads its descriptor: a
    /// relocation takes the fields it leaves out from `coord` itself, not
    /// from the previous hop, a relocation onto the version that relocates
    /// is none, and each SNAPSHOT on the chain resolves its own build. The
    /// outer error is one Maven fails the build on whether or not the
    /// artifact is used: a relocation component that is no coordinate.
    pub(crate) async fn fetch_project_with_relocation_310(
        &self,
        coord: &Coord,
        repos: &RepoContext,
    ) -> Result<Result<Fetched>> {
        let mut chain: IndexSet<ExactCoord> = IndexSet::new();
        let mut reads: Vec<HopRead> = Vec::new();
        let mut current = coord.clone();
        let at_hop = |chain: &IndexSet<ExactCoord>, err: ResolveError| {
            (chain.iter().skip(1).rev()).fold(err, |err, hop| err.in_model_of(&hop.0))
        };
        loop {
            if !chain.insert(ExactCoord(current.clone())) {
                return Ok(Err(cycle(&chain, &current)));
            }
            if let Err(err) = too_long(&chain, coord) {
                return Ok(Err(err));
            }
            let (resolved, snapshot) = match self.fetch_build(&current, None, repos).await {
                Ok(fetched) => fetched,
                Err(err) => return Ok(Err(at_hop(&chain, err))),
            };
            reads.push(self.hop_read(&current, &resolved, snapshot.as_ref(), repos));
            let relocation = (resolved.project.relocation.as_ref())
                .filter(|_| resolved.workspace_module.is_none());
            let Some(relocation) = relocation else {
                return Ok(Ok(Fetched {
                    target: current,
                    resolved,
                    snapshot,
                    inherited_build: false,
                    reads,
                }));
            };
            for (component, value) in [
                ("groupId", &relocation.group_id),
                ("artifactId", &relocation.artifact_id),
                ("version", &relocation.version),
            ] {
                if let Some(value) = non_empty(value).filter(|value| invalid_component(value)) {
                    return Err(rv_maven_model::PomError::InvalidModel(format!(
                        "invalid relocation {component} {} in the POM of {current}: not a valid \
                         artifact coordinate component",
                        rv_maven_types::quoted(value)
                    ))
                    .into());
                }
            }
            let next = match relocation_coord(coord, relocation) {
                Ok(next) => next,
                Err(err) => return Ok(Err(at_hop(&chain, err))),
            };
            if next.group_id == current.group_id
                && next.artifact_id == current.artifact_id
                && next.version.as_str() == current.version.as_str()
            {
                return Ok(Ok(Fetched {
                    target: current,
                    resolved,
                    snapshot,
                    inherited_build: false,
                    reads,
                }));
            }
            current = next;
        }
    }

    /// What the fetch of `coord` as `resolved`, at `build` for a SNAPSHOT,
    /// read: taken right after it, from the backend's record of that build.
    fn hop_read(
        &self,
        coord: &Coord,
        resolved: &ResolvedProject,
        build: Option<&ResolvedVersion>,
        repos: &RepoContext,
    ) -> HopRead {
        let pom = match resolved.workspace_module {
            Some(_) => HopPom::Reactor,
            None => {
                let read = build.map(|build| Coord {
                    version: build.version.clone(),
                    ..coord.clone()
                });
                match self.backend.pom_read(read.as_ref().unwrap_or(coord), repos) {
                    Some(Some(blob)) => HopPom::Read(blob),
                    Some(None) => HopPom::Missing,
                    None => HopPom::Unrecorded,
                }
            }
        };
        HopRead {
            coord: coord.clone(),
            pom,
        }
    }

    /// Fetch `coord`, a SNAPSHOT as the build `pinned` names or, without
    /// one, as the build its metadata names.
    async fn fetch_build(
        &self,
        coord: &Coord,
        pinned: Option<ResolvedVersion>,
        repos: &RepoContext,
    ) -> Result<(ResolvedProject, Option<ResolvedVersion>)> {
        if !rv_maven_types::resolves_through_snapshot_metadata(coord.version.as_str()) {
            return Ok((self.backend.fetch_project(coord, false, repos).await?, None));
        }
        let selected = pinned.is_none();
        let snapshot = match pinned {
            Some(build) => build,
            None => self.backend.resolve_snapshot_version(coord, repos).await?,
        };
        let build = Coord {
            version: snapshot.version.clone(),
            ..coord.clone()
        };
        let resolved = self.backend.fetch_project(&build, selected, repos).await?;
        Ok((resolved, Some(snapshot)))
    }
}

/// Fails a chain of more than [`MAX_RELOCATIONS`] relocations, including
/// the cached ones it took on.
fn too_long(chain: &IndexSet<ExactCoord>, coord: &Coord) -> Result<()> {
    if chain.len() <= MAX_RELOCATIONS + 1 {
        return Ok(());
    }
    Err(ResolveError::RelocationCycle(format!(
        "{coord} -> {} (more than {MAX_RELOCATIONS} relocations)",
        chain
            .last()
            .map_or_else(String::new, |last| last.0.to_string())
    )))
}

fn cycle(chain: &IndexSet<ExactCoord>, next: &Coord) -> ResolveError {
    const SHOWN: usize = 16;
    let mut parts: Vec<String> = chain.iter().take(SHOWN).map(|c| c.0.to_string()).collect();
    if chain.len() > SHOWN {
        parts.push(format!("... ({} coordinates)", chain.len() + 1));
    }
    parts.push(next.to_string());
    ResolveError::RelocationCycle(parts.join(" -> "))
}

/// What Maven 3.10 refuses as a relocation's group, artifact or version.
fn invalid_component(value: &str) -> bool {
    value == ".." || value.contains(['/', '\\', ':']) || value.chars().any(|c| c.is_control())
}

fn non_empty(opt: &Option<String>) -> Option<&str> {
    opt.as_deref().filter(|s| !s.is_empty())
}

fn relocation_coord(coord: &Coord, relocation: &Relocation) -> Result<Coord> {
    let group_id = non_empty(&relocation.group_id).unwrap_or(coord.group_id.as_str());
    let artifact_id = non_empty(&relocation.artifact_id).unwrap_or(coord.artifact_id.as_str());
    let version = non_empty(&relocation.version)
        .map(Version::parse)
        .transpose()?
        .unwrap_or_else(|| coord.version.clone());

    Ok(Coord {
        group_id: group_id.into(),
        artifact_id: artifact_id.into(),
        version,
        packaging: coord.packaging.clone(),
        classifier: coord.classifier.clone(),
    })
}
