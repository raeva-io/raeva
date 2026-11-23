use indexmap::{Equivalent, IndexMap};
use rv_maven_model::{ArtifactTypes, Dependency, ManagedOrigin};
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
/// it to a non-empty value, and the exclusions of all of them add up.
#[derive(Debug, Clone, Default)]
pub(crate) struct Management {
    entries: IndexMap<ManagementKey, Dependency, foldhash::fast::RandomState>,
    types: ArtifactTypes,
}

impl Management {
    /// The management of `entries`, keyed by the artifact handlers of
    /// `types`.
    pub(crate) fn new(entries: Vec<Dependency>, types: ArtifactTypes) -> Self {
        let mut map = IndexMap::with_capacity_and_hasher(entries.len(), Default::default());
        let unset = |value: &Option<String>| value.as_deref().is_none_or(str::is_empty);
        for mut entry in entries {
            if unset(&entry.version) {
                entry.version = None;
            }
            if unset(&entry.scope) {
                entry.scope = None;
            }
            // A version-less entry may still manage scope, optional or
            // exclusions.
            if entry.version.is_none()
                && entry.scope.is_none()
                && entry.optional.is_none()
                && entry.exclusions.is_empty()
            {
                continue;
            }
            let key = KeyRef(
                &entry.group_id,
                &entry.artifact_id,
                entry.effective_type_in(&types),
                entry.effective_classifier_in(&types),
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
            // The origin follows the version it names.
            if managed.version.is_none() && entry.version.is_some() {
                managed.version = entry.version;
                managed.origin = entry.origin;
            }
            if managed.scope.is_none() {
                managed.scope = entry.scope;
            }
            if managed.optional.is_none() {
                managed.optional = entry.optional;
            }
            if managed.system_path.is_none() {
                managed.system_path = entry.system_path;
                managed.system_path_from_project = entry.system_path_from_project;
            }
            for exclusion in entry.exclusions {
                if !managed.exclusions.contains(&exclusion) {
                    managed.exclusions.push(exclusion);
                }
            }
        }
        Self {
            entries: map,
            types,
        }
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
        self.entries.get(&KeyRef(
            group_id,
            artifact_id,
            like.effective_type_in(&self.types),
            like.effective_classifier_in(&self.types),
        ))
    }
}

/// Where the version requested for `dependency` at `depth` comes from, when
/// management supplied it, for a request that resolved to `group:artifact`:
/// as [`resolve_version_str`] picks it, the management of a relocation
/// target first, then the last management a chain of relocations applied
/// on the way, which the caller keeps in the origin of a transitive
/// `dependency` it relocates.
pub(crate) fn version_origin(
    management: &Management,
    dependency: &Dependency,
    depth: usize,
    (group_id, artifact_id): (&str, &str),
) -> ManagedOrigin {
    let versioned = |entry: &&Dependency| entry.version.is_some();
    let relocated = group_id != dependency.group_id || artifact_id != dependency.artifact_id;
    if depth > 1 {
        let target = relocated
            .then(|| management.entry(group_id, artifact_id, dependency))
            .flatten()
            .filter(versioned);
        if let Some(entry) = target {
            return entry.origin.clone();
        }
        if relocated && dependency.origin.0.is_some() {
            return dependency.origin.clone();
        }
        if let Some(entry) = management.managed(dependency).filter(versioned) {
            return entry.origin.clone();
        }
        return ManagedOrigin::default();
    }
    // The model applied the management of a direct dependency.
    dependency.origin.clone()
}

/// The version to request for `dependency` at `depth`. Like Maven's
/// ClassicDependencyManager, management overrides the declared version from
/// depth 2 only: the model already filled the root's own dependencies, and
/// one it left without a version stays without.
pub(crate) fn resolve_version_str<'a>(
    management: &'a Management,
    dependency: &'a Dependency,
    depth: usize,
) -> Result<&'a str> {
    if depth > 1 {
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
