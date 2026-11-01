//! Whether a recorded lockfile still describes what resolution would
//! produce: the comparison `--frozen` makes with a fresh resolution, and the
//! checks that decide whether a lockfile may be reused without resolving.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::Path;

use rv_maven_types::{ArtifactCoord, Gav, is_snapshot_version, resolves_through_snapshot_metadata};

use crate::ambient::AmbientInput;
use crate::lock::{
    LockArtifact, LockModule, LockPlatform, Lockfile, SupportPom, canonicalize_module,
    split_support_pom_coord,
};
use crate::lock_origin::{
    LockOrigins, OriginIdentity, is_project_relative_origin, origin_identity, recorded_key,
};
use crate::platform::Platform;
use crate::system::SystemFile;

/// The first way a fresh resolution differs from a recorded lockfile.
/// `Display` is the reason as raeva reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolutionDrift {
    /// One of the two lockfiles cannot be put in canonical form.
    Invalid,
    /// The two hold other platforms.
    Platforms,
    /// Configuration or resolution settings differ.
    Inputs,
    /// The recorded active profiles differ.
    Profiles {
        /// The platform whose active profiles differ.
        platform: Platform,
    },
    /// Repository labels used by exports differ.
    RepositoryIds,
    /// A module's graph differs on `platform`, or the module set does.
    Module {
        /// The platform whose graph differs.
        platform: Platform,
        /// The module's POM path, as raeva.lock records it.
        path: String,
    },
    /// An artifact row differs on `platform`, or the artifact set does.
    Artifact {
        /// The platform whose artifact table differs.
        platform: Platform,
        /// The artifact's coordinate as text.
        coord: String,
    },
    /// A support POM of `platform` is pinned otherwise, or not at all.
    SupportPom {
        /// The platform whose support POMs differ.
        platform: Platform,
        /// The support POM's `group:artifact:version`.
        coord: String,
    },
    /// A system-scoped file has other bytes than raeva.lock records, or is gone
    /// or unreadable.
    SystemFile {
        /// The file's path relative to the directory that holds raeva.lock.
        path: String,
    },
}

impl fmt::Display for ResolutionDrift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("a lockfile could not be put in canonical form"),
            Self::Platforms => f.write_str("the platforms differ"),
            Self::Inputs => f.write_str("the configuration or resolution settings differ"),
            Self::Profiles { platform } => {
                write!(f, "the active profiles changed on platform {platform}")
            }
            Self::RepositoryIds => f.write_str("the repository ids differ"),
            Self::Module { platform, path } => {
                write!(
                    f,
                    "the graph of module {path} changed on platform {platform}"
                )
            }
            Self::Artifact { platform, coord } => {
                write!(f, "artifact {coord} changed on platform {platform}")
            }
            Self::SupportPom { platform, coord } => {
                write!(
                    f,
                    "the POM pinned for {coord} changed on platform {platform}"
                )
            }
            Self::SystemFile { path } => {
                write!(f, "the system-scoped file {path} changed or cannot be read")
            }
        }
    }
}

impl LockPlatform {
    /// [`Lockfile::system_file_drift`] for this platform alone.
    pub fn system_file_drift(&self, lock_root: &Path) -> Option<ResolutionDrift> {
        // [`SystemFile::record`] requires an absolute file path. A relative
        // `lock_root` such as `.` must still name the project directory.
        let lock_root = std::path::absolute(lock_root).unwrap_or_else(|_| lock_root.to_path_buf());
        let mut checked = BTreeSet::new();
        for package in self.modules.iter().flat_map(|module| &module.packages) {
            let (Some(path), Some(sha256)) = (&package.system_path, &package.system_sha256) else {
                continue;
            };
            if !checked.insert((path, sha256)) {
                continue;
            }
            let current = SystemFile::record(&lock_root, &lock_root.join(path));
            if !current.is_ok_and(|file| &file.path == path && &file.sha256 == sha256) {
                return Some(ResolutionDrift::SystemFile { path: path.clone() });
            }
        }
        None
    }
}

impl Lockfile {
    /// The first system-scoped file whose bytes no longer match the digest
    /// this lockfile records, or that is gone or unreadable, with the
    /// lockfile in `lock_root`. This needs no resolution, so `--frozen`
    /// checks it even when it checks the local inputs only.
    pub fn system_file_drift(&self, lock_root: &Path) -> Option<ResolutionDrift> {
        let mut platforms = self.platforms.iter();
        platforms.find_map(|platform| platform.system_file_drift(lock_root))
    }

    /// The first difference between this lockfile and `fresh`, a lockfile
    /// just resolved from the same inputs.
    ///
    /// The comparison is semantic: both sides are canonicalized, so traversal
    /// order alone cannot make a freshly resolved graph differ from the
    /// sorted, edge-remapped form on disk. Local model and POM hashes are
    /// ignored, and so are the host inputs only one side consulted: the
    /// caller has checked this lockfile's `config_hash` against the inputs
    /// it records, and an edited model may consult others, which changes
    /// only the hash. Recorded profiles, the outcome of a
    /// condition both sides record, modules, artifacts and global export
    /// metadata are compared. For a partial resolution, the caller must
    /// carry forward the other platforms' global metadata before comparing.
    ///
    /// Snapshot artifacts keep a logical `-SNAPSHOT` coordinate in both module
    /// graphs and the aggregate artifact table. Their timestamp/build identity is
    /// compared separately: unchanged repository metadata is frozen-valid, while
    /// a newly published snapshot is drift.
    ///
    /// A release row or support POM that names another repository than
    /// `fresh` is not drift when its pin proves the same file and `declared`
    /// accepts the repository this lockfile records: a mirror that serves
    /// several repositories answers for the first one searched, so the same
    /// file can be recorded under another repository with and without it.
    /// `declared` decides, for each platform, which recorded repositories the current
    /// configuration and resolution may use, so a recorded origin nothing
    /// declares stays drift.
    pub fn resolution_drift(
        &self,
        fresh: &Lockfile,
        declared: impl Fn(&Platform, &str) -> bool,
    ) -> Option<ResolutionDrift> {
        // The canonical form sorts platforms, modules and rows, so the two
        // sides zip in order.
        let (Ok(a), Ok(b)) = (self.canonical(), fresh.canonical()) else {
            return Some(ResolutionDrift::Invalid);
        };
        if inputs_drifted(&a, &b) {
            return Some(ResolutionDrift::Inputs);
        }
        if a.repo_ids != b.repo_ids {
            return Some(ResolutionDrift::RepositoryIds);
        }
        if a.platforms.len() != b.platforms.len() {
            return Some(ResolutionDrift::Platforms);
        }
        for (lhs, rhs) in a.platforms.iter().zip(&b.platforms) {
            if lhs.platform != rhs.platform {
                return Some(ResolutionDrift::Platforms);
            }
            if lhs.model_inputs.as_ref().is_some_and(|inputs| {
                rhs.model_inputs
                    .as_ref()
                    .is_none_or(|fresh| inputs.profiles != fresh.profiles)
            }) {
                return Some(ResolutionDrift::Profiles {
                    platform: lhs.platform.clone(),
                });
            }
            if let Some(drift) = module_drift(lhs, rhs) {
                return Some(drift);
            }
            if let Some(drift) = artifact_drift(lhs, rhs, &|url| declared(&lhs.platform, url)) {
                return Some(drift);
            }
            if let Some(drift) = support_pom_drift(lhs, rhs, &|url| declared(&lhs.platform, url)) {
                return Some(drift);
            }
        }
        None
    }

    /// Whether a locked SNAPSHOT, an artifact or a support POM, is due for a
    /// refresh: the lockfile is at least as old as the shortest update
    /// interval of the snapshot repositories, since Maven checks each by its
    /// own policy and a newer build in any of them replaces the locked one.
    ///
    /// `policies` pairs the URL of each snapshot-enabled repository with its
    /// update interval in seconds. An origin no policy names adds
    /// `default_ttl_secs`.
    pub fn snapshot_refresh_due(
        &self,
        origins: &LockOrigins,
        lock_age_secs: i64,
        default_ttl_secs: i64,
        policies: &[(String, i64)],
    ) -> bool {
        snapshot_refresh_due(
            self.platforms.iter().flat_map(LockPlatform::locked_files),
            origins,
            lock_age_secs,
            default_ttl_secs,
            policies,
        )
    }

    /// The first recorded origin no declaration names: neither one of
    /// `configured` nor one of the URLs `declared` lists for that platform.
    /// Artifact rows and support POMs both count. An empty artifact origin is
    /// skipped (system-scoped rows name no repository). An empty support POM
    /// origin is undeclared: a support POM always comes from a repository. A
    /// project-relative origin that two distinct URLs map to is ambiguous and
    /// declares nothing.
    pub fn undeclared_origin(
        &self,
        origins: &LockOrigins,
        configured: &[String],
        declared: &[(Platform, Vec<String>)],
    ) -> Option<String> {
        // Each declared origin key, with the distinct directories or URLs
        // that map to it.
        let declare = |keys: &mut HashMap<String, BTreeSet<OriginIdentity>>, url: &str| {
            if let Some(key) = origins.declared(url) {
                keys.entry(key).or_default().insert(origin_identity(url));
            }
        };
        let undeclared = |url: &str, keys: &HashMap<String, BTreeSet<OriginIdentity>>| {
            let key = recorded_key(url);
            match keys.get(&key) {
                None => true,
                Some(urls) => is_project_relative_origin(&key) && urls.len() > 1,
            }
        };
        let mut configured_keys: HashMap<String, BTreeSet<OriginIdentity>> = HashMap::new();
        for url in configured {
            declare(&mut configured_keys, url);
        }
        for platform in &self.platforms {
            let mut keys = configured_keys.clone();
            for url in declared
                .iter()
                .filter(|(declared_for, _)| *declared_for == platform.platform)
                .flat_map(|(_, urls)| urls)
            {
                declare(&mut keys, url);
            }
            let artifact = platform
                .artifacts
                .iter()
                .flat_map(LockArtifact::origins)
                .filter(|origin| !origin.is_empty())
                .find(|origin| undeclared(origin, &keys));
            let support = platform
                .support_poms
                .values()
                .map(|pin| pin.repo_url.as_str())
                .find(|url| url.is_empty() || undeclared(url, &keys));
            if let Some(url) = artifact.or(support) {
                return Some(url.to_string());
            }
        }
        None
    }
}

impl LockPlatform {
    /// The requested version and each recorded origin of every file this
    /// platform pins from a repository: each artifact row and each support
    /// POM.
    pub fn locked_files(&self) -> impl Iterator<Item = (&str, &str)> {
        let artifacts = self
            .artifacts
            .iter()
            .flat_map(LockArtifact::versioned_origins);
        artifacts.chain(self.support_files())
    }

    /// [`Self::locked_files`] of the support POMs alone.
    pub fn support_files(&self) -> impl Iterator<Item = (&str, &str)> {
        self.support_poms.iter().filter_map(|(coord, pin)| {
            let (_, _, version) = crate::lock::split_support_pom_coord(coord)?;
            Some((version, pin.repo_url.as_str()))
        })
    }
}

/// Whether any of `files`, requested versions with their recorded origins,
/// is due under these repository policies. Only a version ending in
/// `SNAPSHOT` reads metadata, as in Maven. Like [`Lockfile::snapshot_refresh_due`],
/// restricted to the supplied files.
pub fn snapshot_refresh_due<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a str)>,
    origins: &LockOrigins,
    lock_age_secs: i64,
    default_ttl_secs: i64,
    policies: &[(String, i64)],
) -> bool {
    let mut ttls: HashMap<String, i64> = HashMap::new();
    for (url, ttl) in policies {
        let Some(key) = origins.declared(url) else {
            continue;
        };
        ttls.entry(key)
            .and_modify(|current| *current = (*current).min(*ttl))
            .or_insert(*ttl);
    }
    let shortest = ttls.values().copied().min();
    files.into_iter().any(|(version, repo_url)| {
        if !resolves_through_snapshot_metadata(version) {
            return false;
        }
        let ttl = if repo_url.is_empty() {
            default_ttl_secs
        } else if ttls.contains_key(&recorded_key(repo_url)) {
            shortest.unwrap_or(default_ttl_secs)
        } else {
            shortest.map_or(default_ttl_secs, |ttl| ttl.min(default_ttl_secs))
        };
        lock_age_secs >= ttl
    })
}

fn module_drift(lhs: &LockPlatform, rhs: &LockPlatform) -> Option<ResolutionDrift> {
    let drift = |path: &str| {
        Some(ResolutionDrift::Module {
            platform: lhs.platform.clone(),
            path: path.to_string(),
        })
    };
    if lhs.modules.len() != rhs.modules.len() {
        let paths = |modules: &[LockModule]| -> BTreeSet<String> {
            modules.iter().map(|module| module.path.clone()).collect()
        };
        let (left, right) = (paths(&lhs.modules), paths(&rhs.modules));
        let path = left.symmetric_difference(&right).next().cloned();
        return drift(&path.unwrap_or_default());
    }
    let (lhs_versions, rhs_versions) =
        (module_versions(&lhs.modules), module_versions(&rhs.modules));
    for (left, right) in lhs.modules.iter().zip(&rhs.modules) {
        if left.path != right.path {
            return drift(&left.path);
        }
        if left.packages.len() == right.packages.len()
            && let Some(path) = left
                .packages
                .iter()
                .zip(&right.packages)
                .find_map(|(l, r)| {
                    (l.system_path == r.system_path && l.system_sha256 != r.system_sha256)
                        .then(|| l.system_path.clone())
                        .flatten()
                })
        {
            return Some(ResolutionDrift::SystemFile { path });
        }
        // A bump of the reactor's own versions, as `versions:set` makes, is
        // not drift when everything else is equal.
        if left != right
            && with_module_versions(left, &lhs_versions, &HashMap::new())
                != with_module_versions(right, &rhs_versions, &HashMap::new())
        {
            return drift(&left.path);
        }
    }
    None
}

/// Each module's version, by path.
fn module_versions(modules: &[LockModule]) -> HashMap<&str, &str> {
    (modules.iter())
        .map(|module| (module.path.as_str(), module.gav.version()))
        .collect()
}

/// `module` with the reactor's own versions replaced: its version, and that
/// of each workspace package at the version `own` records for the module it
/// names, become the version `versions` gives that module, or the empty
/// string. Workspace packages then compare by module path. Only these
/// substitutions of a reactor version change: an external coordinate that
/// happens to carry the same version stays as it is.
fn with_module_versions(
    module: &LockModule,
    own: &HashMap<&str, &str>,
    versions: &HashMap<&str, &str>,
) -> LockModule {
    let version = |path: &str| versions.get(path).copied().unwrap_or_default();
    let mut module = module.clone();
    let previous_gav = module.gav.to_string();
    module.gav = Gav::new(
        module.gav.group.as_str(),
        module.gav.artifact.as_str(),
        version(&module.path),
    );
    for selection in &mut module.parent_ranges {
        if selection.model == previous_gav {
            selection.model = module.gav.to_string();
        }
    }
    for package in &mut module.packages {
        let Some(path) = package.workspace_module.as_deref() else {
            continue;
        };
        if own.get(path) == Some(&package.coordinate.version()) {
            let gav = Gav::new(
                package.coordinate.group_id(),
                package.coordinate.artifact_id(),
                version(path),
            );
            let previous_gav = package.coordinate.gav.to_string();
            for selection in &mut module.parent_ranges {
                if selection.model == previous_gav {
                    selection.model = gav.to_string();
                }
            }
            package.coordinate = ArtifactCoord::of(
                gav,
                package.coordinate.extension(),
                package.coordinate.classifier(),
            );
        }
    }
    canonicalize_module(&mut module);
    module
}

impl Lockfile {
    /// Take each module's version, and that of each workspace package naming
    /// it, from `fresh`'s module at the same path on the same platform. After
    /// [`Self::resolution_drift`] found none, this lock then names the
    /// reactor's versions as `fresh` resolved them, as a plain sync records
    /// a version bump.
    pub fn adopt_module_versions(&mut self, fresh: &Lockfile) {
        for platform in &mut self.platforms {
            let Some(found) =
                (fresh.platforms.iter()).find(|entry| entry.platform == platform.platform)
            else {
                continue;
            };
            let own = module_versions(&platform.modules);
            let mut versions = module_versions(&found.modules);
            for (path, version) in &own {
                versions.entry(path).or_insert(version);
            }
            let modules = (platform.modules.iter())
                .map(|module| with_module_versions(module, &own, &versions))
                .collect();
            platform.modules = modules;
        }
    }
}

fn artifact_drift<'a>(
    lhs: &'a LockPlatform,
    rhs: &'a LockPlatform,
    declared: &dyn Fn(&str) -> bool,
) -> Option<ResolutionDrift> {
    let drift = |coord: String| {
        Some(ResolutionDrift::Artifact {
            platform: lhs.platform.clone(),
            coord,
        })
    };
    let by_coordinate = |platform: &'a LockPlatform| -> BTreeMap<_, _> {
        let rows = platform.artifacts.iter();
        rows.map(|artifact| (&artifact.coordinate, artifact))
            .collect()
    };
    let (lhs_artifacts, rhs_artifacts) = (by_coordinate(lhs), by_coordinate(rhs));
    if let Some(added) = rhs_artifacts
        .keys()
        .find(|coordinate| !lhs_artifacts.contains_key(*coordinate))
    {
        return drift(added.to_string());
    }
    for (coordinate, left) in lhs_artifacts {
        let Some(right) = rhs_artifacts.get(coordinate) else {
            return drift(coordinate.to_string());
        };
        // `pom_sha256` is part of what the lockfile guarantees: a
        // republished companion POM can change bytes without changing a
        // single edge (a parent bumping plugin configuration, say), and a
        // plain `raeva sync` would rewrite the pin. Frozen has to report that
        // rather than call the lockfile up to date.
        if origin_drifted(left, right, declared)
            || left.snapshot != right.snapshot
            || left.pom_build() != right.pom_build()
            || left.pom_sha256 != right.pom_sha256
            || checksum_drifted(left, right)
        {
            return drift(coordinate.to_string());
        }
    }
    None
}

/// Whether the configuration differs, or a condition both lockfiles record
/// has another outcome. `config_hash` covers the host inputs too, so it is
/// compared only when both record the same ones.
fn inputs_drifted(on_disk: &Lockfile, fresh: &Lockfile) -> bool {
    let (lhs, rhs) = (&on_disk.resolution, &fresh.resolution);
    let outcome = |inputs: &'_ BTreeSet<AmbientInput>| -> HashMap<String, bool> {
        inputs
            .iter()
            .filter_map(|input| match input {
                AmbientInput::Condition { condition, holds } => {
                    Some((condition.to_string(), *holds))
                }
                _ => None,
            })
            .collect()
    };
    let fresh_outcomes = outcome(&rhs.ambient_inputs);
    (lhs.ambient_inputs == rhs.ambient_inputs && on_disk.config_hash != fresh.config_hash)
        || outcome(&lhs.ambient_inputs)
            .iter()
            .any(|(condition, holds)| {
                fresh_outcomes
                    .get(condition)
                    .is_some_and(|now| now != holds)
            })
}

/// Compare every support POM of one platform, including removed pins. A
/// release POM recorded under another repository is drift on the terms of
/// [`origin_drifted`].
fn support_pom_drift(
    lhs: &LockPlatform,
    rhs: &LockPlatform,
    declared: &dyn Fn(&str) -> bool,
) -> Option<ResolutionDrift> {
    let differ = |coord: &str, l: Option<&SupportPom>, r: Option<&SupportPom>| match (l, r) {
        (Some(l), Some(r)) => {
            l.sha256 != r.sha256
                || l.snapshot != r.snapshot
                || (l.repo_url != r.repo_url
                    && (!declared(&l.repo_url)
                        || split_support_pom_coord(coord)
                            .is_none_or(|(_, _, version)| is_snapshot_version(version))))
        }
        _ => true,
    };
    lhs.support_poms
        .keys()
        .chain(rhs.support_poms.keys())
        .find(|coord| {
            differ(
                coord,
                lhs.support_poms.get(*coord),
                rhs.support_poms.get(*coord),
            )
        })
        .map(|coord| ResolutionDrift::SupportPom {
            platform: lhs.platform.clone(),
            coord: coord.clone(),
        })
}

/// True when two rows for one coordinate name different repositories and
/// nothing proves they pin the same file from a repository `declared`
/// accepts. A release whose pins use one algorithm and agree is the same
/// file either way. A snapshot is identified by its build, not its bytes,
/// and a mixed-algorithm pair proves nothing, so for those a different
/// repository is drift. Changes to the other file origins or companion POM
/// origins are drift too: export labels files with their repository ids,
/// and frozen resolution routes POMs through their recorded origins.
fn origin_drifted(l: &LockArtifact, r: &LockArtifact, declared: &dyn Fn(&str) -> bool) -> bool {
    if l.other_repo_urls != r.other_repo_urls || l.pom_repo_urls != r.pom_repo_urls {
        return true;
    }
    if l.repo_url == r.repo_url {
        return false;
    }
    if !declared(&l.repo_url)
        || is_snapshot_version(&l.file_version())
        || is_snapshot_version(&r.file_version())
    {
        return true;
    }
    !matches!((l.pin(), r.pin()), (Some(lhs), Some(rhs)) if lhs == rhs)
}

/// Whether a coordinate's recorded artifact checksums would change.
/// This includes algorithm changes and checksums for the same SNAPSHOT build.
pub fn checksum_drifted(l: &LockArtifact, r: &LockArtifact) -> bool {
    l.checksums != r.checksums
}

#[cfg(test)]
mod tests;
