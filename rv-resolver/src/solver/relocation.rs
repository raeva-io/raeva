use std::collections::HashMap;
use std::sync::Mutex;

use indexmap::IndexSet;
use rv_maven_model::{Relocation, Scope};
use rv_version::{Coord, Version};

use crate::error::{ResolveError, Result};

use super::{Backend, ResolvedProject, Solver};

fn cache_chain(cache: &Mutex<HashMap<Coord, Coord>>, chain: &IndexSet<Coord>, target: &Coord) {
    let mut guard = cache.lock().expect("relocation cache poisoned");
    for seen in chain {
        guard.insert(seen.clone(), target.clone());
    }
}

impl<'a, B: Backend> Solver<'a, B> {
    pub(crate) async fn fetch_project_with_relocation_cached(
        &self,
        coord: &Coord,
        scope: Scope,
        relocation_cache: &Mutex<HashMap<Coord, Coord>>,
    ) -> Result<(Coord, ResolvedProject)> {
        let cached = relocation_cache
            .lock()
            .expect("relocation cache poisoned")
            .get(coord)
            .cloned();
        if let Some(mapped) = cached {
            let resolved_project = self.backend.fetch_project(&mapped, scope).await?;
            return Ok((mapped, resolved_project));
        }

        let mut chain: IndexSet<Coord> = IndexSet::new();
        let mut current = coord.clone();

        loop {
            // IndexSet::insert returns false if element was already present (cycle detected)
            if !chain.insert(current.clone()) {
                return Err(ResolveError::RelocationCycle(format_relocation_cycle(
                    &chain, &current,
                )));
            }

            let cached = relocation_cache
                .lock()
                .expect("relocation cache poisoned")
                .get(&current)
                .cloned();

            // Single fetch per loop iteration. On a cache hit, jump straight
            // to the mapped coord, fetch it once, and return. Breaking out of
            // the loop and refetching `current` below would double the
            // network/parse cost on every cache hit.
            let resolved_project = match cached {
                Some(mapped) => {
                    current = mapped;
                    if !chain.insert(current.clone()) {
                        return Err(ResolveError::RelocationCycle(format_relocation_cycle(
                            &chain, &current,
                        )));
                    }
                    let resolved = self.backend.fetch_project(&current, scope).await?;
                    cache_chain(relocation_cache, &chain, &current);
                    return Ok((current, resolved));
                }
                None => self.backend.fetch_project(&current, scope).await?,
            };

            let Some(relocation) = resolved_project.project.relocation.as_ref() else {
                cache_chain(relocation_cache, &chain, &current);
                return Ok((current, resolved_project));
            };

            if !has_relocation_target(relocation) {
                cache_chain(relocation_cache, &chain, &current);
                return Ok((current, resolved_project));
            }

            let next = relocation_coord(&current, relocation)?;
            if next == current {
                cache_chain(relocation_cache, &chain, &current);
                return Ok((current, resolved_project));
            }

            current = next;
        }
    }
}

fn format_relocation_cycle(path: &IndexSet<Coord>, next: &Coord) -> String {
    // IndexSet preserves insertion order, so no sorting needed for deterministic output
    let mut parts: Vec<String> = path.iter().map(|c| c.to_string()).collect();
    parts.push(next.to_string());
    parts.join(" -> ")
}

fn non_empty(opt: &Option<String>) -> Option<&str> {
    opt.as_deref().filter(|s| !s.is_empty())
}

fn has_relocation_target(relocation: &Relocation) -> bool {
    non_empty(&relocation.group_id).is_some()
        || non_empty(&relocation.artifact_id).is_some()
        || non_empty(&relocation.version).is_some()
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
