use std::sync::Mutex;

use foldhash::HashMap;
use indexmap::IndexSet;
use rv_maven_model::Relocation;
use rv_maven_types::{Coord, Version};

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
/// mapped to the end of the chain and the coordinates between them.
pub(crate) type RelocationCache = Mutex<HashMap<(ExactCoord, RepoContext), (Coord, Vec<Coord>)>>;

fn cache_chain(
    cache: &RelocationCache,
    chain: &IndexSet<ExactCoord>,
    repos: &RepoContext,
) -> Vec<Coord> {
    let hops = chain_between(chain);
    let last = chain.last().expect("a relocation chain is not empty");
    let mut guard = lock(cache);
    for (index, seen) in chain.iter().enumerate() {
        guard.insert(
            (seen.clone(), repos.clone()),
            (last.0.clone(), hops.get(index..).unwrap_or(&[]).to_vec()),
        );
    }
    hops
}

fn chain_between(chain: &IndexSet<ExactCoord>) -> Vec<Coord> {
    let last = chain.len().saturating_sub(1);
    chain
        .iter()
        .skip(1)
        .take(last.saturating_sub(1))
        .map(|seen| seen.0.clone())
        .collect()
}

/// The end of a relocation chain: its coordinate, which keeps a SNAPSHOT's
/// base version, its project, the build a SNAPSHOT resolved to, the
/// coordinates the chain passed through on the way, and whether that build
/// came down a relocation without a version instead of from the end's own
/// metadata.
pub(crate) type Fetched = (
    Coord,
    ResolvedProject,
    Option<ResolvedVersion>,
    Vec<Coord>,
    bool,
);

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
            if let Some((mapped, between)) = cached {
                for hop in between {
                    if !chain.insert(ExactCoord(hop.clone())) {
                        return Err(cycle(&chain, &hop));
                    }
                }
                // The end of a chain maps to itself, which is no cycle.
                let terminal = ExactCoord(mapped.clone()) == ExactCoord(current.clone());
                current = mapped;
                if !terminal && !chain.insert(ExactCoord(current.clone())) {
                    return Err(cycle(&chain, &current));
                }
                too_long(&chain, coord)?;
                let (resolved, snapshot) = (self.fetch_build(&current, None, repos).await)
                    .map_err(|err| at_hop(&chain, err))?;
                let between = match cacheable {
                    true => cache_chain(relocation_cache, &chain, repos),
                    false => chain_between(&chain),
                };
                return Ok((current, resolved, snapshot, between, false));
            }
            let pinned = inherited.is_some();
            let (resolved, snapshot) = (self.fetch_build(&current, inherited.take(), repos).await)
                .map_err(|err| at_hop(&chain, err))?;
            // Maven reads a reactor module's model from the reactor, which
            // never follows its relocation.
            let next = match &resolved.project.relocation {
                Some(relocation) if resolved.workspace_module.is_none() => {
                    relocation_coord(&current, relocation)?
                }
                _ => current.clone(),
            };
            if ExactCoord(next.clone()) == ExactCoord(current.clone()) {
                let between = match cacheable {
                    true => cache_chain(relocation_cache, &chain, repos),
                    false => chain_between(&chain),
                };
                return Ok((current, resolved, snapshot, between, pinned));
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
