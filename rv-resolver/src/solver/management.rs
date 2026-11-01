use indexmap::{Equivalent, IndexMap};
use rv_maven_model::Dependency;
use rv_maven_types::bounded;

use crate::error::{ResolveError, Result};

/// Maven's management key: `(groupId, artifactId, type, classifier)`, with
/// the effective type and classifier, so a managed `test-jar` (type `jar`,
/// classifier `tests`) does not manage the plain jar.
type ManagementKey = (String, String, String, Option<String>);

/// A [`ManagementKey`] borrowed for a lookup; it hashes as the owned key.
#[derive(Hash)]
struct KeyRef<'a>(&'a str, &'a str, &'a str, Option<&'a str>);

impl Equivalent<ManagementKey> for KeyRef<'_> {
    fn equivalent(&self, key: &ManagementKey) -> bool {
        self.0 == key.0 && self.1 == key.1 && self.2 == key.2 && self.3 == key.3.as_deref()
    }
}

/// The root project's effective dependencyManagement (parents merged and BOMs
/// imported by the model layer). Entries sharing a key merge as in Maven's
/// ClassicDependencyManager: each field comes from the first entry that sets
/// it, and the exclusions of all of them add up.
#[derive(Debug, Clone, Default)]
pub(crate) struct Management(IndexMap<ManagementKey, Dependency, foldhash::fast::RandomState>);

impl Management {
    pub(crate) fn new(entries: Vec<Dependency>) -> Self {
        let mut map = IndexMap::with_capacity_and_hasher(entries.len(), Default::default());
        for entry in entries {
            // A version-less entry may still manage scope or exclusions.
            if entry.version.is_none() && entry.scope.is_none() && entry.exclusions.is_empty() {
                continue;
            }
            let key = KeyRef(
                &entry.group_id,
                &entry.artifact_id,
                entry.effective_type(),
                entry.effective_classifier(),
            );
            let Some(managed) = map.get_mut(&key) else {
                let key = (
                    key.0.to_owned(),
                    key.1.to_owned(),
                    key.2.to_owned(),
                    key.3.map(str::to_owned),
                );
                map.insert(key, entry);
                continue;
            };
            if managed.version.is_none() {
                managed.version = entry.version;
            }
            if managed.scope.is_none() {
                managed.scope = entry.scope;
            }
            if managed.system_path.is_none() {
                managed.system_path = entry.system_path;
            }
            for exclusion in entry.exclusions {
                if !managed.exclusions.contains(&exclusion) {
                    managed.exclusions.push(exclusion);
                }
            }
        }
        Self(map)
    }

    pub(crate) fn managed(&self, dependency: &Dependency) -> Option<&Dependency> {
        self.entry(&dependency.group_id, &dependency.artifact_id, dependency)
    }

    pub(crate) fn entry(
        &self,
        group_id: &str,
        artifact_id: &str,
        like: &Dependency,
    ) -> Option<&Dependency> {
        self.0.get(&KeyRef(
            group_id,
            artifact_id,
            like.effective_type(),
            like.effective_classifier(),
        ))
    }
}

/// The version to request for `dependency` at `depth`. Like Maven's
/// ClassicDependencyManager, management only fills a missing version of the
/// root's own dependencies but overrides the declared version from depth 2.
pub(crate) fn resolve_version_str<'a>(
    management: &'a Management,
    dependency: &'a Dependency,
    depth: usize,
) -> Result<&'a str> {
    if depth > 1 || dependency.version.is_none() {
        let managed = management
            .managed(dependency)
            .and_then(|entry| entry.version.as_deref());
        if let Some(version) = managed {
            tracing::debug!(
                group_id = %bounded(&dependency.group_id),
                artifact_id = %bounded(&dependency.artifact_id),
                version = %bounded(version),
                depth,
                "applied managed version"
            );
            return Ok(version);
        }
    }
    dependency
        .version
        .as_deref()
        .ok_or_else(|| ResolveError::MissingVersion {
            group_id: dependency.group_id.clone(),
            artifact_id: dependency.artifact_id.clone(),
        })
}
