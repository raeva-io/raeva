//! What a lockfile is checked against: the inputs `config_hash` and
//! `model_hash` cover, the recipes that hash them, and whether a recorded
//! lockfile still matches them.
//!
//! Everything here is a pure function of plain data. The caller gathers the
//! inputs (reads `.mvn/maven.config`, walks the reactor and its local
//! parents) and passes them in, so the recipes cannot depend on where or how
//! that happened.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use rv_maven_types::MavenMode;
use sha2::{Digest, Sha256};

use crate::ambient::AmbientInput;
use crate::lock::{LockModule, LockModulePackage, Lockfile};
use crate::lock_origin::normalize_repo_url;
use crate::platform::Platform;

/// Every input `config_hash` covers, in the form the recipe hashes it.
///
/// Only settings that can change what resolution selects or what raeva.lock
/// records belong here. `[network]` settings, mirrors, proxies, credentials,
/// TLS roots, and size limits decide only where a request goes and whether
/// it succeeds, so changing them must not make `--frozen` report drift. The
/// local repository is only where `export-m2` writes, so it is left out too. A
/// lock records the repository a POM or the configuration declares, never
/// the mirror that served it. POM bytes and effective reactor identity are
/// per-platform `model_hash` inputs and never appear here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionInputs {
    /// Effective `-P` selections from the command line and `.mvn/maven.config`,
    /// in target order. User-property values belong only to `ambient` lookups.
    pub profile_selections: Vec<String>,
    /// Resolved active configuration profile ids.
    pub active_profiles: Vec<String>,
    /// Resolved inactive configuration profile ids.
    pub inactive_profiles: Vec<String>,
    /// Configured repositories in precedence order.
    pub repositories: Vec<RepositoryInputs>,
    /// The settings.xml plugin repositories of the active profiles, then
    /// those of Maven's request, which serve the build extensions that map
    /// a dependency's type. Hashed only when not empty, so a configuration
    /// without them keeps its hash.
    pub plugin_repositories: Vec<RepositoryInputs>,
    /// `[security] allow_transitive_repositories`.
    pub allow_transitive_repositories: bool,
    /// `-itr` in `.mvn/maven.config`, which turns every transitive
    /// repository off. Hashed only when set, so a configuration without it
    /// keeps its hash.
    pub ignore_transitive_repositories: bool,
    /// `[security] allow_env_substitution`.
    pub allow_env_substitution: Vec<String>,
    /// `[security] transitive_repository_allowlist`.
    pub transitive_repository_allowlist: Vec<String>,
    /// `[lock] jdks`, in configured order. Hashed only when not empty, so a
    /// configuration without it keeps its hash.
    pub jdks: Vec<String>,
    /// The Maven line resolution follows. Hashed only when not 3.9, so a
    /// configuration that selects none keeps its hash.
    pub maven: MavenMode,
    /// The settings.xml profiles whose activation depends on a condition,
    /// in settings order. Which of them apply is decided per target
    /// platform, so their content, not the outcome on this host, is the
    /// input. Hashed only when not empty, so a configuration without such
    /// profiles keeps its hash.
    pub settings_profiles: Vec<SettingsProfileInput>,
    /// The settings.xml profile repositories a project's model fills in, as
    /// written, of every profile in settings order. Hashed only when not
    /// empty, so a configuration without them keeps its hash.
    pub settings_model_repositories: Vec<String>,
    /// The host and user-property inputs consulted, each with its current
    /// value (`None` when unset). Hashed by name and value only when not
    /// empty. The names are what raeva.lock records in
    /// `[resolution] ambient_inputs`.
    pub ambient: BTreeMap<AmbientInput, Option<String>>,
    /// Maven's remote repository filters: the digests of their rule files
    /// and the values of the properties `ambient` cannot name, as the
    /// caller writes them. Hashed only when set, so a configuration without
    /// filters keeps its hash.
    pub repository_filters: Option<String>,
}

/// One conditionally activated settings.xml profile as `config_hash` covers
/// it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsProfileInput {
    /// The profile id.
    pub id: String,
    /// The caller's canonical text for the profile's activation and
    /// content. The recipe hashes it as given.
    pub content: String,
}

/// One configured repository as `config_hash` covers it.
///
/// The policy fields are the text the recipe hashes, with the caller's
/// defaults already applied, so the same configuration always yields the same
/// text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepositoryInputs {
    /// The repository id; `None` hashes as the empty string.
    pub id: Option<String>,
    /// Hashed in its [`normalize_repo_url`] form.
    pub url: String,
    /// Whether releases are enabled, `None` when the configuration leaves
    /// it unset. Unset, `false` and `true` hash apart.
    pub releases: Option<bool>,
    /// Whether snapshots are enabled, `None` when unset, hashed like `releases`.
    pub snapshots: Option<bool>,
    /// The update policy for snapshots.
    pub snapshots_update_policy: String,
    /// The update policy for releases.
    pub releases_update_policy: String,
    /// The checksum policy for releases.
    pub releases_checksum_policy: String,
    /// The checksum policy for snapshots.
    pub snapshots_checksum_policy: String,
}

/// Compute the lockfile's top-level configuration hash.
///
/// Exact recipe (framed with labels and lengths):
///
/// 1. effective `-P` selections from both option sources, in target order;
/// 2. resolved active and inactive configuration profile ids;
/// 3. configured repositories in precedence order: id, URL, release and
///    snapshot flags, update policies, and checksum policies, then, when
///    there are any, the settings.xml plugin repositories the same way;
/// 4. the `[security]` settings, which decide what a POM may read from the
///    environment and which transitive repositories are searched;
/// 5. the Maven mode, when it is not 3.9;
/// 6. when there are any, the conditionally activated settings profiles in
///    settings order, each framed with its id and content;
/// 7. when there are any, the consulted host values in name order, each
///    framed with its name and its value or an unset marker, except an unset
///    one that [`AmbientInput::is_property_name`]: each graph that read
///    such a name lists it in its module record, which a lock must list
///    too, so it needs no marker, and a branch that only consults another
///    unset name leaves the hash, and every graph digest bound to it,
///    unchanged;
/// 8. when set, the remote repository filter text.
pub fn config_hash(inputs: &ResolutionInputs) -> String {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, "rv-config-hash-v7");
    if !inputs.profile_selections.is_empty() {
        hasher.update(b"profile_selections:");
        hasher.update((inputs.profile_selections.len() as u64).to_le_bytes());
        for argument in &inputs.profile_selections {
            hash_str(&mut hasher, argument);
        }
    }

    hash_sorted_strings(&mut hasher, "active_profiles", &inputs.active_profiles);
    hash_sorted_strings(&mut hasher, "inactive_profiles", &inputs.inactive_profiles);

    hash_repositories(&mut hasher, "repositories:", &inputs.repositories);
    if !inputs.plugin_repositories.is_empty() {
        hash_repositories(
            &mut hasher,
            "plugin_repositories:",
            &inputs.plugin_repositories,
        );
    }

    hasher.update(b"security:");
    hasher.update([u8::from(inputs.allow_transitive_repositories)]);
    hash_sorted_strings(
        &mut hasher,
        "allow_env_substitution",
        &inputs.allow_env_substitution,
    );
    hash_sorted_strings(
        &mut hasher,
        "transitive_repository_allowlist",
        &inputs.transitive_repository_allowlist,
    );

    if inputs.ignore_transitive_repositories {
        hasher.update(b"ignore_transitive_repositories:");
    }

    if !inputs.jdks.is_empty() {
        hasher.update(b"jdks:");
        hasher.update((inputs.jdks.len() as u64).to_le_bytes());
        for jdk in &inputs.jdks {
            hash_str(&mut hasher, jdk);
        }
    }

    if inputs.maven != MavenMode::Maven39 {
        hasher.update(b"maven:");
        hash_str(&mut hasher, inputs.maven.as_str());
    }

    if !inputs.settings_profiles.is_empty() {
        hasher.update(b"settings_profiles:");
        hasher.update((inputs.settings_profiles.len() as u64).to_le_bytes());
        for profile in &inputs.settings_profiles {
            hash_str(&mut hasher, &profile.id);
            hash_str(&mut hasher, &profile.content);
        }
    }
    if !inputs.settings_model_repositories.is_empty() {
        hasher.update(b"settings_model_repositories:");
        hasher.update((inputs.settings_model_repositories.len() as u64).to_le_bytes());
        for repository in &inputs.settings_model_repositories {
            hash_str(&mut hasher, repository);
        }
    }
    let counted: Vec<_> = (inputs.ambient.iter())
        .filter(|(name, value)| value.is_some() || !name.is_property_name())
        .collect();
    if !counted.is_empty() {
        hasher.update(b"ambient:");
        hasher.update((counted.len() as u64).to_le_bytes());
        for (name, value) in counted {
            hash_str(&mut hasher, &name.to_string());
            match value {
                Some(value) => hash_str(&mut hasher, value),
                // No string has this length.
                None => hasher.update(u64::MAX.to_le_bytes()),
            }
        }
    }
    if let Some(filters) = &inputs.repository_filters {
        hasher.update(b"repository_filters:");
        hash_str(&mut hasher, filters);
    }

    hex::encode(hasher.finalize())
}

fn hash_repositories(hasher: &mut Sha256, label: &str, repos: &[RepositoryInputs]) {
    hasher.update(label.as_bytes());
    hasher.update((repos.len() as u64).to_le_bytes());
    for repo in repos {
        hash_str(hasher, repo.id.as_deref().unwrap_or(""));
        hash_str(hasher, &normalize_repo_url(&repo.url));
        hasher.update([tristate(repo.releases), tristate(repo.snapshots)]);
        hash_str(hasher, &repo.snapshots_update_policy);
        hash_str(hasher, &repo.releases_update_policy);
        hash_str(hasher, &repo.releases_checksum_policy);
        hash_str(hasher, &repo.snapshots_checksum_policy);
    }
}

/// Everything `model_hash` covers for one platform's reactor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReactorInputs {
    /// Every active reactor module.
    pub modules: Vec<ModuleInput>,
    /// The union of the explicitly active profile ids and the modules'
    /// active profile ids.
    pub active_profiles: Vec<String>,
    /// Every accepted local parent POM that is not itself an active module,
    /// once each.
    pub local_parents: Vec<LocalParentInput>,
}

/// One active reactor module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleInput {
    /// Root-relative POM path, with `/` separators.
    pub path: String,
    /// Effective, interpolated group id.
    pub group: String,
    /// Effective, interpolated artifact id.
    pub artifact: String,
    /// Effective, interpolated version.
    pub version: String,
    /// Exact POM bytes.
    pub pom: Vec<u8>,
    /// The ids of the profiles active in this module's lineage.
    pub active_profiles: Vec<String>,
    /// Resolution-bearing local model declarations and the public POM values
    /// their interpolation reads. Never includes user-property values.
    pub resolution_context: Vec<Option<String>>,
}

/// One accepted local parent POM.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalParentInput {
    /// Root-relative label, with `/` separators.
    pub label: String,
    /// Exact POM bytes.
    pub pom: Vec<u8>,
}

/// A platform's `model_hash` and the per-POM digests it was computed from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ModelHash {
    /// The `model_hash`, as 64 lowercase hex characters.
    pub hash: String,
    /// Contextual digests of module and local parent POMs, keyed by path.
    /// Module digests include effective coordinates, active profile ids and
    /// local inheritance/interpolation context.
    pub pom_hashes: BTreeMap<String, rv_maven_types::Sha256>,
    /// `pom_hashes` with each module digest also covering `hash`, so every
    /// module record covers the whole reactor. A platform records these
    /// when a dependency's model read a reactor POM, which no module's
    /// declarations show.
    pub whole_reactor_pom_hashes: BTreeMap<String, rv_maven_types::Sha256>,
    /// The `model_hash` of `whole_reactor_pom_hashes`.
    pub whole_reactor_hash: String,
}

/// Hash one platform's reactor model.
///
/// Each module record covers its role, effective GAV, LF-normalized POM
/// bytes, sorted active profile ids and resolution-bearing local model
/// context. Each local-parent record covers its
/// role and LF-normalized bytes. The aggregate frames the sorted path/digest
/// pairs and active profile ids. Only those records are stored on disk, so
/// independent module edits merge without editing a shared aggregate.
///
/// The hash excludes repository configuration, which belongs to the top-level
/// `config_hash`. It also excludes every external parent and BOM byte stream,
/// which is locked support POM content rather than a local model input.
/// POM bytes are hashed with CRLF line endings turned into LF.
pub fn model_hash(inputs: &ReactorInputs) -> ModelHash {
    let mut modules: Vec<&ModuleInput> = inputs.modules.iter().collect();
    modules.sort_by(|left, right| left.path.cmp(&right.path));
    let mut parents: Vec<&LocalParentInput> = inputs.local_parents.iter().collect();
    parents.sort_by(|left, right| left.label.cmp(&right.label));

    let mut pom_hashes = BTreeMap::new();
    for module in modules {
        let mut hasher = Sha256::new();
        hash_str(&mut hasher, "module");
        hash_str(&mut hasher, &module.group);
        hash_str(&mut hasher, &module.artifact);
        hash_str(&mut hasher, &module.version);
        hash_labelled_pom(&mut hasher, "pom", &module.pom);
        hash_sorted_strings(&mut hasher, "profiles", &module.active_profiles);
        if !module.resolution_context.is_empty() {
            hash_resolution_context(&mut hasher, &module.resolution_context);
        }
        pom_hashes.insert(
            module.path.clone(),
            hex::encode(hasher.finalize()).parse().expect("SHA-256 hex"),
        );
    }
    for parent in parents {
        let mut hasher = Sha256::new();
        hash_labelled_pom(&mut hasher, "local-parent-pom", &parent.pom);
        pom_hashes.insert(
            parent.label.clone(),
            hex::encode(hasher.finalize()).parse().expect("SHA-256 hex"),
        );
    }
    let hash = model_records_hash(&inputs.active_profiles, &pom_hashes);
    let mut whole_reactor_pom_hashes = pom_hashes.clone();
    for module in &inputs.modules {
        let digest = whole_reactor_pom_hashes
            .get_mut(&module.path)
            .expect("module record");
        let mut hasher = Sha256::new();
        hash_str(&mut hasher, "whole-reactor");
        hash_str(&mut hasher, &hash);
        hash_str(&mut hasher, digest.as_ref());
        *digest = hex::encode(hasher.finalize()).parse().expect("SHA-256 hex");
    }
    ModelHash {
        whole_reactor_hash: model_records_hash(&inputs.active_profiles, &whole_reactor_pom_hashes),
        whole_reactor_pom_hashes,
        hash,
        pom_hashes,
    }
}

/// Digest public POM context for reuse by consumers of a local reactor BOM.
/// Callers must exclude external values, as for [`ModuleInput::resolution_context`].
pub fn resolution_context_hash(context: &[Option<String>]) -> rv_maven_types::Sha256 {
    let mut hasher = Sha256::new();
    hash_resolution_context(&mut hasher, context);
    hex::encode(hasher.finalize()).parse().expect("SHA-256 hex")
}

fn hash_resolution_context(hasher: &mut Sha256, context: &[Option<String>]) {
    hash_str(hasher, "resolution-context");
    hasher.update((context.len() as u64).to_le_bytes());
    for value in context {
        hasher.update([u8::from(value.is_some())]);
        if let Some(value) = value {
            hash_str(hasher, value);
        }
    }
}

/// Recompute a model hash from independently mergeable POM records.
pub fn model_records_hash(
    profiles: &[String],
    poms: &BTreeMap<String, rv_maven_types::Sha256>,
) -> String {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, "rv-model-hash-v3");
    hash_sorted_strings(&mut hasher, "profiles", profiles);
    for (path, digest) in poms {
        hash_str(&mut hasher, path);
        hash_str(&mut hasher, digest.as_ref());
    }
    hex::encode(hasher.finalize())
}

/// What every graph of a target shares: the lock's `config_hash`, the Maven
/// mode, the property and variable names every graph of the target read,
/// and the repository ids and the conditions and host values it read
/// (`reads`).
fn target_context(
    inputs: &crate::ModelInputs,
    config_hash: Option<&str>,
    maven: MavenMode,
    reads: &crate::TargetReads,
) -> String {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, "target-context");
    hash_str(&mut hasher, config_hash.unwrap_or(""));
    hash_str(&mut hasher, maven.as_str());
    hash_str(&mut hasher, "ambient_inputs");
    hash_str(&mut hasher, &read_names_digest(&inputs.ambient_inputs));
    // What the platform read, so a merge or an edit that changes the
    // repository ids or conditions without the graphs fails.
    hash_str(&mut hasher, "repo_ids");
    hasher.update((reads.repo_ids.len() as u64).to_le_bytes());
    for (origin, ids) in &reads.repo_ids {
        hash_str(&mut hasher, origin);
        hasher.update((ids.len() as u64).to_le_bytes());
        for id in ids {
            hash_str(&mut hasher, id);
        }
    }
    hash_str(&mut hasher, "host_inputs");
    hash_str(&mut hasher, &read_names_digest(&reads.host_inputs));
    hex::encode(hasher.finalize())
}

fn read_names_digest(names: &BTreeSet<crate::AmbientInput>) -> String {
    let mut hasher = Sha256::new();
    hasher.update((names.len() as u64).to_le_bytes());
    for name in names {
        hash_str(&mut hasher, &name.to_string());
    }
    hex::encode(hasher.finalize())
}

/// Each module's graph digest in `platform`, stored as
/// [`crate::ModelInputs::graphs`]: what every graph of the target shares
/// (the lock's `config_hash`, the Maven mode `maven`, the names every graph
/// read and what the target read, `reads`), the module's input record in
/// `inputs`, its path, coordinates and row, the names it read, the pin of
/// each support POM it read and the POM pin of each external package, and
/// the path and version of each reactor module whose `group:artifact` the
/// module itself, a package, a support POM or a parent range of its row
/// names, and the rows of each reactor module the graph depends on. Other
/// modules are left out, so adding a module that no graph names leaves the
/// other graph digests as they are.
///
/// A branch that resolves upstream data again changes the digest of each
/// graph it changes, as an edit to the module's POM does, so merging the two
/// conflicts in Git, and a lock whose rows and records come from different
/// resolutions fails [`crate::LockPlatform::graphs_match`]: a graph that
/// names a `group:artifact` the other branch made a reactor module, or
/// whose version that branch changed, does not match.
pub fn graph_digests(
    platform: &crate::lock::LockPlatform,
    inputs: &crate::ModelInputs,
    config_hash: Option<&str>,
    maven: MavenMode,
    reads: &crate::TargetReads,
) -> BTreeMap<String, rv_maven_types::Sha256> {
    let context = target_context(inputs, config_hash, maven, reads);
    let empty = BTreeSet::new();
    let mut reactor: HashMap<(&str, &str), Vec<(&str, &str)>> = HashMap::new();
    for module in &platform.modules {
        reactor
            .entry((module.gav.group.as_str(), module.gav.artifact.as_str()))
            .or_default()
            .push((module.path.as_str(), module.gav.version()));
    }
    for modules in reactor.values_mut() {
        modules.sort_unstable();
    }
    let pins: HashMap<_, _> = (platform.artifacts.iter())
        .map(|artifact| (&artifact.coordinate, artifact.pom_sha256.as_ref()))
        .collect();
    // A canonical copy when the row needs one, its packages, edges and
    // managed sources, and their digest.
    type Encoded = (Option<LockModule>, String, String, String, String, [u8; 32]);
    // One pass canonicalizes a row that needs it and encodes it.
    let encoded = rv_maven_types::par_map(&platform.modules, |module| -> Encoded {
        let canonical = (!crate::lock::is_canonical_module(module)).then(|| {
            let mut row = module.clone();
            crate::lock::canonicalize_module(&mut row);
            row
        });
        let row = canonical.as_ref().unwrap_or(module);
        let packages = crate::codec::encode_packages(row);
        let edges = crate::codec::encode_edges(row);
        let managed = crate::codec::encode_managed(row);
        let optional = crate::codec::encode_optional(row);
        let mut hasher = Sha256::new();
        hash_str(&mut hasher, &packages);
        hash_str(&mut hasher, &edges);
        // Left out when empty, so a module whose versions management did
        // not supply keeps its digest.
        if !managed.is_empty() {
            hash_str(&mut hasher, &managed);
        }
        if !optional.is_empty() {
            hash_str(&mut hasher, "optional");
            hash_str(&mut hasher, &optional);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        (canonical, packages, edges, managed, optional, digest)
    });
    let rows: Vec<&LockModule> = (platform.modules.iter())
        .zip(&encoded)
        .map(|(module, (row, ..))| row.as_ref().unwrap_or(module))
        .collect();
    let row_digests: HashMap<&str, &[u8; 32]> = (rows.iter())
        .zip(&encoded)
        .map(|(row, (.., digest))| (row.path.as_str(), digest))
        .collect();
    let digest = |&(row, (_, packages, edges, managed, optional, _)): &(&LockModule, &Encoded)| {
        let mut hasher = Sha256::new();
        hash_str(&mut hasher, "graph");
        hash_str(&mut hasher, &context);
        let record = inputs.pom_hashes.get(&row.path);
        hash_str(&mut hasher, record.map_or("", AsRef::as_ref));
        hash_str(&mut hasher, &row.path);
        hash_str(&mut hasher, &row.gav.to_string());
        hash_str(&mut hasher, &row.packaging);
        hash_str(&mut hasher, packages);
        hash_str(&mut hasher, edges);
        if !managed.is_empty() {
            hash_str(&mut hasher, "managed");
            hash_str(&mut hasher, managed);
        }
        if !optional.is_empty() {
            hash_str(&mut hasher, "optional");
            hash_str(&mut hasher, optional);
        }
        for range in &row.parent_ranges {
            hash_str(&mut hasher, &range.model);
            hash_str(&mut hasher, &range.parent);
            hash_str(&mut hasher, &range.selected);
        }
        for coord in &row.support_poms {
            hash_str(&mut hasher, coord);
            let pin = platform.support_poms.get(coord);
            hash_str(&mut hasher, pin.map_or("", |pin| pin.sha256.as_ref()));
        }
        if !row.extensions.is_empty() {
            hash_str(&mut hasher, "extensions");
            hash_str(&mut hasher, &crate::codec::encode_extensions(row));
        }
        if !row.parents.is_empty() {
            hash_str(&mut hasher, "parents");
            hash_str(&mut hasher, &row.parents.join("\n"));
        }
        if !row.evicted_ranges.is_empty() {
            hash_str(&mut hasher, "evicted_ranges");
            hash_str(&mut hasher, &crate::codec::encode_evicted_ranges(row));
        }
        if !row.metadata_versions.is_empty() {
            hash_str(&mut hasher, "metadata_versions");
            hash_str(
                &mut hasher,
                &crate::codec::encode_metadata_versions(&row.metadata_versions),
            );
        }
        hash_str(&mut hasher, "ambient_inputs");
        hash_str(
            &mut hasher,
            &read_names_digest(
                inputs
                    .module_ambient_inputs
                    .get(&row.path)
                    .unwrap_or(&empty),
            ),
        );
        for coordinate in row
            .packages
            .iter()
            .filter_map(LockModulePackage::repository_file)
        {
            let pin = pins.get(coordinate).copied().flatten();
            hash_str(&mut hasher, pin.map_or("", AsRef::as_ref));
        }
        // The reactor modules this graph can name: a reactor module with a
        // named `group:artifact` would have been a candidate for it.
        let mut named: BTreeSet<(&str, &str)> = BTreeSet::new();
        named.insert((row.gav.group.as_str(), row.gav.artifact.as_str()));
        for package in &row.packages {
            let gav = &package.coordinate.gav;
            named.insert((gav.group.as_str(), gav.artifact.as_str()));
        }
        for range in &row.evicted_ranges {
            named.insert((range.group.as_str(), range.artifact.as_str()));
        }
        for marker in &row.metadata_versions {
            named.insert((marker.group.as_str(), marker.artifact.as_str()));
        }
        let coords = (row.support_poms.iter().map(String::as_str)).chain(
            row.parent_ranges.iter().flat_map(|range| {
                [
                    range.model.as_str(),
                    range.parent.as_str(),
                    range.selected.as_str(),
                ]
            }),
        );
        for coord in coords {
            if let Some((group, artifact, _)) = crate::lock::split_reactor_gav(coord) {
                named.insert((group, artifact));
            }
        }
        hash_str(&mut hasher, "reactor");
        for ga in named {
            let Some(modules) = reactor.get(&ga) else {
                continue;
            };
            hash_str(&mut hasher, ga.0);
            hash_str(&mut hasher, ga.1);
            hasher.update((modules.len() as u64).to_le_bytes());
            for (path, version) in modules {
                hash_str(&mut hasher, path);
                hash_str(&mut hasher, version);
            }
        }
        // A reactor dependency's resolution reaches this graph without its
        // POM changing, as after `--update`.
        hash_str(&mut hasher, "workspace");
        for package in &row.packages {
            if let Some(path) =
                (package.workspace_module.as_deref()).filter(|path| *path != row.path)
            {
                hash_str(&mut hasher, path);
                hasher.update(row_digests.get(path).map_or(&[0; 32], |digest| *digest));
            }
        }
        hex::encode(hasher.finalize()).parse().expect("SHA-256 hex")
    };
    let rows: Vec<_> = rows.into_iter().zip(&encoded).collect();
    let digests = rv_maven_types::par_map(&rows, digest);
    (platform.modules.iter().map(|module| module.path.clone()))
        .zip(digests)
        .collect()
}

/// SHA-256 of a project text file with CRLF line endings turned into LF.
pub fn text_sha256(bytes: &[u8]) -> rv_maven_types::Sha256 {
    rv_maven_types::Sha256::from_bytes(&lf_line_endings(bytes))
}

/// One platform's reactor model as discovered now, for comparing with what a
/// lockfile recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentModel {
    /// The platform the model was discovered for.
    pub platform: Platform,
    /// The `model_hash`, as 64 lowercase hex characters.
    pub model_hash: String,
    /// The sorted, deduplicated active profile ids `model_hash` covers.
    pub active_profiles: Vec<String>,
    /// Every active module.
    pub modules: Vec<CurrentModule>,
    /// See [`ModelHash::pom_hashes`].
    pub pom_hashes: BTreeMap<String, rv_maven_types::Sha256>,
}

/// One active module of a [`CurrentModel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentModule {
    /// Root-relative POM path.
    pub path: String,
    /// Effective, interpolated group id.
    pub group: String,
    /// Effective, interpolated artifact id.
    pub artifact: String,
    /// Effective, interpolated version.
    pub version: String,
}

/// The first way a lockfile's recorded reactor model differs from the
/// current one, most specific first. `Display` is the reason as raeva reports
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelDrift {
    /// The active profile ids differ.
    Profiles {
        /// The platform whose profiles differ.
        platform: Platform,
        /// The ids raeva.lock records in `inputs.profiles`.
        locked: Vec<String>,
        /// The ids active now.
        current: Vec<String>,
    },
    /// A module POM the lock does not record.
    ModuleAdded {
        /// The module's root-relative POM path.
        path: String,
    },
    /// A module POM the lock records that is no longer active.
    ModuleRemoved {
        /// The module's root-relative POM path.
        path: String,
    },
    /// A module's effective `group:artifact:version` differs.
    ModuleGav {
        /// The module's root-relative POM path.
        path: String,
        /// The GAV raeva.lock records for the module.
        locked: String,
        /// The module's GAV now.
        current: String,
    },
    /// A module or local parent POM's bytes differ.
    PomChanged {
        /// The POM's path or label, as `inputs.poms` names it.
        path: String,
        /// Whether the POM is a local parent rather than an active module.
        local_parent: bool,
    },
    /// The hash differs and the recorded inputs do not say why.
    Model {
        /// The platform whose `model_hash` differs.
        platform: Platform,
    },
}

impl fmt::Display for ModelDrift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profiles {
                platform,
                locked,
                current,
            } => write!(
                f,
                "active Maven profiles changed for platform {platform} (locked: [{}], current: [{}])",
                locked.join(", "),
                current.join(", ")
            ),
            Self::ModuleAdded { path } => write!(f, "reactor module added: {path}"),
            Self::ModuleRemoved { path } => write!(f, "reactor module removed: {path}"),
            Self::ModuleGav {
                path,
                locked,
                current,
            } => write!(
                f,
                "effective GAV changed for module {path} (locked {locked}, current {current})"
            ),
            Self::PomChanged { path, local_parent } => {
                let kind = if *local_parent {
                    "local parent POM"
                } else {
                    "module POM"
                };
                write!(f, "{kind} changed: {path}")
            }
            Self::Model { platform } => write!(f, "reactor model changed for platform {platform}"),
        }
    }
}

/// How a lockfile's `config_hash` fails to match the current configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDrift {
    /// The lock records another hash.
    Changed,
    /// The lock records no hash, so it cannot be tied to its inputs.
    Unrecorded,
}

fn same_gav(locked: &crate::LockModule, current: &CurrentModule) -> bool {
    locked.gav.group.as_str() == current.group
        && locked.gav.artifact.as_str() == current.artifact
        && locked.gav.version() == current.version
}

impl Lockfile {
    /// The first difference between the reactor model each recorded platform
    /// was locked with and `current`. A platform `current` does not describe
    /// is not compared.
    pub fn model_drift(&self, current: &[CurrentModel]) -> Option<ModelDrift> {
        for platform in &self.platforms {
            let Some(model) = current
                .iter()
                .find(|model| model.platform == platform.platform)
            else {
                continue;
            };
            if let Some(stored) = platform
                .model_inputs
                .as_ref()
                .map(|inputs| &inputs.profiles)
                && *stored != model.active_profiles
            {
                return Some(ModelDrift::Profiles {
                    platform: platform.platform.clone(),
                    locked: stored.clone(),
                    current: model.active_profiles.clone(),
                });
            }

            let locked_paths: BTreeSet<&str> = platform
                .modules
                .iter()
                .map(|module| module.path.as_str())
                .collect();
            let current_paths: BTreeSet<&str> = model
                .modules
                .iter()
                .map(|module| module.path.as_str())
                .collect();
            if let Some(added) = current_paths.difference(&locked_paths).next() {
                return Some(ModelDrift::ModuleAdded {
                    path: added.to_string(),
                });
            }
            if let Some(removed) = locked_paths.difference(&current_paths).next() {
                return Some(ModelDrift::ModuleRemoved {
                    path: removed.to_string(),
                });
            }

            for locked in &platform.modules {
                let Some(current) = model
                    .modules
                    .iter()
                    .find(|module| module.path == locked.path)
                else {
                    continue;
                };
                if !same_gav(locked, current) {
                    return Some(ModelDrift::ModuleGav {
                        path: locked.path.clone(),
                        locked: locked.gav.to_string(),
                        current: format!(
                            "{}:{}:{}",
                            current.group, current.artifact, current.version
                        ),
                    });
                }
            }
            if model.model_hash == platform.model_hash {
                continue;
            }

            if let Some(stored) = platform
                .model_inputs
                .as_ref()
                .map(|inputs| &inputs.pom_hashes)
            {
                for (path, digest) in &model.pom_hashes {
                    if stored.get(path).is_some_and(|old| old != digest) {
                        return Some(ModelDrift::PomChanged {
                            path: path.clone(),
                            local_parent: !current_paths.contains(path.as_str()),
                        });
                    }
                }
            }

            return Some(ModelDrift::Model {
                platform: platform.platform.clone(),
            });
        }
        None
    }

    /// Whether every recorded platform `current` describes has the model hash
    /// it was locked with and graphs for exactly its modules, at their
    /// effective coordinates.
    pub fn models_match(&self, current: &[CurrentModel]) -> bool {
        self.platforms.iter().all(|platform| {
            current
                .iter()
                .find(|model| model.platform == platform.platform)
                .is_none_or(|model| {
                    let modules: HashMap<&str, &CurrentModule> = (model.modules.iter())
                        .map(|module| (module.path.as_str(), module))
                        .collect();
                    model.model_hash == platform.model_hash
                        && modules.len() == platform.modules.len()
                        && platform.modules.iter().all(|locked| {
                            (modules.get(locked.path.as_str()))
                                .is_some_and(|current| same_gav(locked, current))
                        })
                })
        })
    }

    /// How the recorded `config_hash` fails to match `current`, if it does.
    pub fn config_drift(&self, current: &str) -> Option<ConfigDrift> {
        match self.config_hash.as_deref() {
            Some(stored) if stored == current => None,
            Some(_) => Some(ConfigDrift::Changed),
            None => Some(ConfigDrift::Unrecorded),
        }
    }
}

fn hash_sorted_strings(hasher: &mut Sha256, label: &str, values: &[String]) {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    hasher.update(label.as_bytes());
    hasher.update(b":");
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        hash_str(hasher, &value);
    }
}

/// Fold a labelled, length-prefixed string into `hasher`.
fn hash_str(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u64).to_le_bytes());
    hasher.update(s.as_bytes());
}

/// Stable 3-state encoding of an `Option<bool>` so the hash distinguishes
/// "unset" from an explicit `false`/`true` without baking in a default.
fn tristate(value: Option<bool>) -> u8 {
    match value {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    }
}

fn hash_labelled_pom(hasher: &mut Sha256, label: &str, bytes: &[u8]) {
    let normalized = lf_line_endings(bytes);
    hasher.update(label.as_bytes());
    hasher.update(b":");
    hasher.update(b"present:");
    hasher.update((normalized.len() as u64).to_le_bytes());
    hasher.update(&normalized);
}

/// Hashed project inputs are text files, and a Git checkout with
/// `core.autocrlf=true` gives them CRLF line endings. Hash them with LF so a
/// lockfile written on one side of that conversion stays valid on the other.
fn lf_line_endings(bytes: &[u8]) -> Cow<'_, [u8]> {
    if !bytes.windows(2).any(|pair| pair == b"\r\n") {
        return Cow::Borrowed(bytes);
    }
    let mut normalized = Vec::with_capacity(bytes.len());
    for (index, &byte) in bytes.iter().enumerate() {
        if byte != b'\r' || bytes.get(index + 1) != Some(&b'\n') {
            normalized.push(byte);
        }
    }
    Cow::Owned(normalized)
}

#[cfg(test)]
mod tests;
