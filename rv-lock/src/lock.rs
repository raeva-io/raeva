use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;

use rv_fs::{NewFileAccess, write_file_atomic};
use rv_maven_types::{
    ArtifactCoord, CoordinateField, Digest, Gav, HashAlgorithm, MavenMode, Sha256, SnapshotStamp,
    is_snapshot_version, is_terminal_safe, validate_coordinate_component, validate_reactor_version,
};

use crate::Scope;
use crate::ambient::AmbientInput;
use crate::codec::{self, is_sha256_hex};
use crate::error::LockError;
use crate::lock_origin::{
    LockOrigins, PARENT_ORIGIN_PREFIX, encode_repo_id_lines, is_project_relative_origin,
    record_repo_ids, redact_origin, validate_project_relative_origin,
};
use crate::platform::Platform;

/// The only schema this build reads and writes. A lock of any other schema
/// is refused, and a plain `raeva sync` regenerates it.
pub const LOCKFILE_SCHEMA_VERSION: u32 = 9;

/// Model hash given to a platform built in memory without one (see
/// [`LockPlatform::single_module`]). `raeva sync` always records the real hash.
const PLACEHOLDER_MODEL_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Maximum size [`Lockfile::read`] will load. Real lockfiles run a few KiB
/// to a few MiB; the cap is deliberately generous and exists only so a
/// runaway or hostile raeva.lock cannot OOM the process.
pub const MAX_LOCKFILE_BYTES: u64 = 256 * 1024 * 1024;

/// [`Lockfile::repo_ids`]: the ids each recorded origin is declared under.
pub type RepoIds = BTreeMap<String, BTreeSet<String>>;

fn repo_id_lines(ids: &RepoIds) -> impl Iterator<Item = (&String, &String)> {
    (ids.iter()).flat_map(|(origin, ids)| ids.iter().map(move |id| (origin, id)))
}

/// The names of `ambient` other than property and variable names.
fn host_inputs(ambient: &BTreeSet<AmbientInput>) -> BTreeSet<AmbientInput> {
    (ambient.iter())
        .filter(|input| !input.is_property_name())
        .cloned()
        .collect()
}

/// What one platform of a lockfile read, as [`Lockfile::target_reads`]
/// gives it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TargetReads {
    /// The lines of [`Lockfile::repo_ids`] its resolution used.
    pub repo_ids: RepoIds,
    /// The names of `[resolution] ambient_inputs` other than property and
    /// variable names that it consulted: conditions and host values.
    pub host_inputs: BTreeSet<AmbientInput>,
}

/// A raeva.lock of schema [`LOCKFILE_SCHEMA_VERSION`].
///
/// The schema is strict: a key this raeva does not write, at any level, makes
/// the lockfile invalid, so a field added later needs a schema bump. A value
/// read from a file or decoded through serde has passed every check that
/// [`Lockfile::write_atomic`] applies; a value built in memory is checked
/// when it is written or put in canonical form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lockfile {
    /// The [`crate::inputs::config_hash`] of the configuration the lock was
    /// resolved under. Written as the top-level `config_hash`, omitted when
    /// `None`.
    pub config_hash: Option<String>,
    /// The Maven line the lock was resolved as, which `config_hash` and
    /// every graph digest cover. Written as the top-level `maven`, left out
    /// for Maven 3.9.
    pub maven: MavenMode,
    /// The host inputs the resolution consulted. Written as the
    /// `[resolution]` table, omitted when empty.
    pub resolution: LockResolution,
    /// One entry per resolved target, sorted by platform and JDK.
    /// The disk codec groups identical graphs under their target lists.
    pub platforms: Vec<LockPlatform>,
    /// Origin -> ids of each repository with an id that backed resolution,
    /// so `raeva export-m2` can label `_remote.repositories` markers for
    /// repositories only a POM declares. An origin is spelled as an artifact
    /// row's `repo_url` is, and one declared under several ids has them all.
    /// The ids are labels and grant no access. Written as `[metadata]
    /// repo_ids`, one line per id.
    pub repo_ids: RepoIds,
}

/// The `[resolution]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockResolution {
    /// The host values the resolution consulted, by name. `config_hash`
    /// covers their values, so a sync reads the same names again and
    /// compares the hash to tell whether the lock is current.
    pub ambient_inputs: BTreeSet<AmbientInput>,
    /// The command line's options by name, without values: `-DNAME` for
    /// each `-D` and `-PID` for each id a `-P` lists, as written. Any
    /// machine can then name an option added or removed since the lock was
    /// written. `config_hash` covers the values.
    pub command_line: BTreeSet<String>,
}

impl Lockfile {
    /// An empty lockfile: no `config_hash`, no resolution settings, no
    /// platforms.
    pub fn new() -> Self {
        Self::default()
    }

    /// The digest this lockfile pins for each file, by the file's path below
    /// a Maven repository root: every artifact row, its companion POM,
    /// every support POM and every release build extension jar. With it,
    /// the origins the lockfile records as serving the file, spelled as
    /// `repo_url` is. A file a row pins only by SHA-1 is held to that,
    /// unless another row pins it by SHA-256.
    pub fn pinned_paths(&self) -> HashMap<String, (Digest, BTreeSet<String>)> {
        let mut files: HashMap<String, (Digest, BTreeSet<String>)> = (self.sha256_pins())
            .into_iter()
            .map(|(path, (pin, origins))| (path, (Digest::Sha256(pin), origins)))
            .collect();
        for (path, pin) in self.sha1_pins() {
            files.entry(path).or_insert(pin);
        }
        files
    }

    fn sha1_pins(&self) -> HashMap<String, (Digest, BTreeSet<String>)> {
        let mut sha1: HashMap<String, (Digest, BTreeSet<String>)> = HashMap::new();
        for file in self.platforms.iter().flat_map(LockPlatform::pinned_files) {
            if let Digest::Sha1(_) = file.pin {
                let entry = (sha1.entry(file.path()))
                    .or_insert_with(|| (file.pin.clone(), BTreeSet::new()));
                entry.1.extend(file.origins.into_iter().map(str::to_string));
            }
        }
        sha1
    }

    fn sha256_pins(&self) -> HashMap<String, (Sha256, BTreeSet<String>)> {
        let mut files: HashMap<String, (Sha256, BTreeSet<String>)> = HashMap::new();
        for (path, pin, served) in self.sha256_files() {
            let file = files
                .entry(path)
                .or_insert_with(|| (pin.clone(), BTreeSet::new()));
            file.0 = pin;
            file.1.extend(served.into_iter().map(str::to_string));
        }
        files
    }

    /// Each release file or timestamped snapshot build `fresh` pins that
    /// this lockfile pins too, by path, with this lockfile's pin and then
    /// `fresh`'s, when the two may name other bytes: a SHA-256 pin that
    /// differs, or a pin by another algorithm, which only the bytes can
    /// settle. Other bytes under the same path are a replaced file. Only
    /// non-unique snapshot filenames can be redeployed and are left out. A
    /// SHA-1 pin is listed even when another row pins the file by SHA-256,
    /// as a conflict side or a platform of a lock may.
    pub fn repinned_releases(&self, fresh: &Lockfile) -> Vec<(String, Digest, Sha256)> {
        let pinned = self.pinned_paths();
        let sha1 = self.sha1_pins();
        let mut repinned: Vec<_> = fresh
            .sha256_files()
            .filter(|(path, ..)| !rv_maven_types::layout::is_mutable_snapshot_path(path))
            .flat_map(|(path, pin, _)| {
                let changed = (pinned.get(&path))
                    .filter(|(locked, _)| locked.as_sha256() != Some(&pin))
                    .map(|(locked, _)| locked);
                let sha1 = sha1.get(&path).map(|(locked, _)| locked);
                (changed.into_iter().chain(sha1))
                    .map(|locked| (path.clone(), locked.clone(), pin.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        repinned.sort_by(|a, b| a.0.cmp(&b.0));
        repinned.dedup_by(|a, b| a.0 == b.0);
        repinned
    }

    /// Each file the platforms pin by SHA-256, by path, as often as rows
    /// pin it, and each release build extension jar.
    fn sha256_files(&self) -> impl Iterator<Item = (String, Sha256, Vec<&str>)> {
        let rows =
            (self.platforms.iter().flat_map(LockPlatform::pinned_files)).filter_map(|file| {
                let Digest::Sha256(pin) = &file.pin else {
                    return None;
                };
                Some((file.path(), pin.clone(), file.origins))
            });
        // A build extension's jar records no origin.
        let extensions = (self.platforms.iter().flat_map(LockPlatform::extension_jars))
            .map(|(path, jar)| (path, jar.sha256.clone(), Vec::new()));
        rows.chain(extensions)
    }

    /// The path below a Maven repository root of each companion POM the
    /// lock records as missing: no repository had it, so the artifact has
    /// no dependency information.
    pub fn missing_pom_paths(&self) -> HashSet<String> {
        self.platforms
            .iter()
            .flat_map(|platform| &platform.artifacts)
            .filter(|artifact| artifact.pom_sha256.is_none() && !artifact.is_own_pom())
            .map(|artifact| {
                let file = artifact.pom_gav().version().to_string();
                let coord = ArtifactCoord::of(artifact.pom_gav(), "pom", None);
                rv_maven_types::layout::artifact_path(&coord, &artifact.directory_version(), &file)
            })
            .collect()
    }

    /// The snapshot builds raeva.lock pins for each `-SNAPSHOT` GAV, keyed by
    /// that GAV. Platforms read at other times can pin several.
    pub fn pinned_snapshots(&self) -> HashMap<Gav, BTreeSet<PinnedSnapshot>> {
        let mut builds: HashMap<Gav, BTreeSet<_>> = HashMap::new();
        for platform in &self.platforms {
            for artifact in &platform.artifacts {
                let row = &artifact.coordinate;
                if is_snapshot_version(row.version()) {
                    let gav = Gav::new(row.group_id(), row.artifact_id(), row.version());
                    let file_origins: Vec<String> =
                        artifact.file_origins().map(str::to_string).collect();
                    builds.entry(gav).or_default().insert(PinnedSnapshot {
                        build: artifact.snapshot.clone(),
                        pom: artifact.pom_build().cloned(),
                        pom_origins: if artifact.pom_repo_urls.is_empty() {
                            file_origins.clone()
                        } else {
                            artifact.pom_repo_urls.clone()
                        },
                        file_origins,
                        file: Some((
                            row.extension().to_string(),
                            row.classifier().map(str::to_string),
                        )),
                    });
                }
            }
            for (coord, pin) in &platform.support_poms {
                if let Some((group, artifact, version)) = split_support_pom_coord(coord)
                    && is_snapshot_version(version)
                {
                    let gav = Gav::new(group, artifact, version);
                    builds.entry(gav).or_default().insert(PinnedSnapshot {
                        build: pin.snapshot.clone(),
                        pom: pin.snapshot.clone(),
                        file_origins: vec![pin.repo_url.clone()],
                        pom_origins: vec![pin.repo_url.clone()],
                        file: None,
                    });
                }
            }
        }
        builds
    }

    /// Every platform's support POMs, by coordinate. A coordinate several
    /// platforms record has one pin, so the first platform's row stands for
    /// them all.
    pub fn support_poms(&self) -> BTreeMap<String, SupportPom> {
        let mut poms = BTreeMap::new();
        for platform in &self.platforms {
            for (coord, pin) in &platform.support_poms {
                poms.entry(coord.clone()).or_insert_with(|| pin.clone());
            }
        }
        poms
    }

    /// This lockfile with only the entries for `platforms`, in that order,
    /// each with its own support POMs, borrowed when those are its entries.
    /// Every lockfile-level field is kept. Fails with the first platform the
    /// lockfile has no entry for.
    pub fn select_platforms(&self, platforms: &[Platform]) -> Result<Cow<'_, Lockfile>, Platform> {
        if self
            .platforms
            .iter()
            .map(|entry| &entry.platform)
            .eq(platforms)
        {
            return Ok(Cow::Borrowed(self));
        }
        let selected = platforms
            .iter()
            .map(|platform| {
                self.platforms
                    .iter()
                    .find(|entry| entry.platform == *platform)
                    .cloned()
                    .ok_or_else(|| platform.clone())
            })
            .collect::<Result<_, _>>()?;
        Ok(Cow::Owned(Lockfile {
            config_hash: self.config_hash.clone(),
            maven: self.maven,
            resolution: self.resolution.clone(),
            platforms: selected,
            repo_ids: self.repo_ids.clone(),
        }))
    }

    /// Set [`Self::repo_ids`] after checking that raeva.lock can record every
    /// entry, so a value no lockfile can hold fails where it is built.
    pub fn set_repo_ids(&mut self, ids: RepoIds) -> Result<(), LockError> {
        check_repo_ids(&ids)?;
        self.repo_ids = ids;
        Ok(())
    }

    /// The lockfile exactly as it would be written: sorted, with each
    /// module's edge indices remapped to its sorted package table. A fresh
    /// resolution is still in traversal order, so comparing it with a lock
    /// read from disk needs this form.
    pub(crate) fn canonical(&self) -> Result<Self, LockError> {
        let mut canonical = self.clone();
        canonical
            .platforms
            .sort_by_key(|entry| entry.platform.to_string());
        let config_hash = canonical.config_hash.clone();
        let maven = canonical.maven;
        let repo_ids = canonical.repo_ids.clone();
        let ambient = canonical.resolution.ambient_inputs.clone();
        for platform in &mut canonical.platforms {
            if let Some(inputs) = &platform.model_inputs {
                platform.model_hash =
                    crate::inputs::model_records_hash(&inputs.profiles, &inputs.pom_hashes);
            } else if platform.model_hash.is_empty() {
                platform.model_hash = PLACEHOLDER_MODEL_HASH.to_string();
            }
            platform.canonicalize();
            if let Some(inputs) = &mut platform.model_inputs {
                inputs
                    .module_ambient_inputs
                    .retain(|_, names| !names.is_empty());
            }
            if let Some(inputs) = &platform.model_inputs {
                let reads = platform.reads(&repo_ids, &ambient);
                let graphs = crate::inputs::graph_digests(
                    platform,
                    inputs,
                    config_hash.as_deref(),
                    maven,
                    &reads,
                );
                (platform.model_inputs.as_mut())
                    .expect("model inputs")
                    .graphs = graphs;
            }
        }
        canonical.check()?;
        Ok(canonical)
    }

    /// Record every `file:` origin inside the project directory `origins`
    /// describes as a project-relative origin, in artifact rows and in the
    /// `repo_ids` block, so a checkout at another path records the same
    /// lock. `raeva sync` applies this to a freshly resolved lock; an origin
    /// outside the project keeps its spelling.
    ///
    /// A file, POM or version list origin no declaration could match, a
    /// repository URL that does not parse which only a mirror serves,
    /// becomes the empty origin: the mirror's URL is not recorded, and the
    /// repository's own names nothing a later run could fetch from.
    pub fn relativize_origins(&mut self, origins: &LockOrigins) -> Result<(), LockError> {
        let or_none = |origin: &mut String| {
            if !origins.records_declaration(origin) {
                origin.clear();
            }
        };
        for artifact in self
            .platforms
            .iter_mut()
            .flat_map(|platform| platform.artifacts.iter_mut())
        {
            or_none(&mut artifact.repo_url);
            for origin in (artifact.other_repo_urls.iter_mut()).chain(&mut artifact.pom_repo_urls) {
                or_none(origin);
            }
            let own = artifact.repo_url.clone();
            artifact.other_repo_urls.retain(|origin| *origin != own);
            artifact.other_repo_urls.sort();
            artifact.other_repo_urls.dedup();
            artifact.pom_repo_urls.sort();
            artifact.pom_repo_urls.dedup();
            artifact.repo_url = origins.recorded(&artifact.repo_url)?;
            for origin in artifact
                .other_repo_urls
                .iter_mut()
                .chain(artifact.pom_repo_urls.iter_mut())
            {
                *origin = origins.recorded(origin)?;
            }
        }
        for pin in self
            .platforms
            .iter_mut()
            .flat_map(|platform| platform.support_poms.values_mut())
        {
            or_none(&mut pin.repo_url);
            pin.repo_url = origins.recorded(&pin.repo_url)?;
        }
        let mode = self.maven;
        for module in (self.platforms.iter_mut()).flat_map(|platform| &mut platform.modules) {
            let ranges = (module
                .evicted_ranges
                .iter_mut()
                .map(|range| &mut range.origin))
            .chain(
                module
                    .range_versions
                    .iter_mut()
                    .map(|read| &mut read.origin),
            );
            ranges.for_each(or_none);
            // Two spellings of one directory are one origin.
            let mut merged: BTreeMap<(String, String, String, String), BTreeSet<String>> =
                BTreeMap::new();
            for range in std::mem::take(&mut module.evicted_ranges) {
                let origin = origins.recorded(&range.origin)?;
                (merged
                    .entry((range.group, range.artifact, range.range, origin))
                    .or_default())
                .extend(range.versions);
            }
            module.evicted_ranges = (merged.into_iter())
                .map(|((group, artifact, range, origin), versions)| {
                    let mut versions: Vec<String> = versions.into_iter().collect();
                    EvictedRange::sort_versions(&mut versions, mode);
                    EvictedRange {
                        group,
                        artifact,
                        range,
                        versions,
                        origin,
                    }
                })
                .collect();
            for read in &mut module.range_versions {
                read.origin = origins.recorded(&read.origin)?;
            }
            module.range_versions.sort();
            module.range_versions.dedup();
        }
        let record_ids = |mut ids: RepoIds| {
            ids.retain(|origin, _| origins.records_declaration(origin));
            record_repo_ids(origins, ids)
        };
        self.repo_ids = record_ids(std::mem::take(&mut self.repo_ids))?;
        for platform in &mut self.platforms {
            if let Some(ids) = platform.repo_ids.take() {
                platform.repo_ids = Some(record_ids(ids)?);
            }
        }
        Ok(())
    }

    /// Check that every origin is spelled as a lock for the project directory
    /// `origins` describes records it: a project-relative origin is valid, and
    /// no absolute `file:` origin names a directory inside the project. One
    /// outside it that a lock written here would record with `../` matches no
    /// declaration, which `--frozen` reports as drift: whether it has such a
    /// spelling depends on where the checkout is.
    pub(crate) fn check_origins(&self, origins: &LockOrigins) -> Result<(), LockError> {
        let artifact_origins = self
            .platforms
            .iter()
            .flat_map(|platform| platform.artifacts.iter())
            .flat_map(LockArtifact::origins)
            .map(str::to_string);
        let support_origins = self
            .platforms
            .iter()
            .flat_map(|platform| platform.support_poms.values())
            .map(|pin| pin.repo_url.clone());
        let id_origins = self.repo_ids.keys().cloned();
        let plugin_origins = (self.platforms.iter())
            .flat_map(|platform| &platform.plugins)
            .flat_map(|tables| tables.origins().map(|(origin, _)| origin.to_string()));
        let range_origins = (self.platforms.iter())
            .flat_map(LockPlatform::range_origins)
            .map(str::to_string);
        for origin in (artifact_origins.chain(support_origins).chain(id_origins))
            .chain(plugin_origins)
            .chain(range_origins)
        {
            let recorded = origins.recorded(&origin)?;
            if recorded != origin && !recorded.starts_with(PARENT_ORIGIN_PREFIX) {
                return Err(LockError::Invalid(format!(
                    "repository origin {:?} names a directory inside the project, \
                     which raeva.lock records as {recorded:?}",
                    redact_origin(&origin)
                )));
            }
        }
        Ok(())
    }

    /// Every check a written lockfile passes. The field checks run first, so
    /// the messages of the later ones can quote those values as they are.
    pub(crate) fn check(&self) -> Result<(), LockError> {
        check_lock_fields(self)?;
        self.check_no_secret_origins()?;
        self.validate()
    }

    fn validate(&self) -> Result<(), LockError> {
        check_repo_ids(&self.repo_ids)?;
        // Two entries for one platform would overwrite each other in any
        // platform-keyed consumer.
        let mut seen = HashSet::new();
        if let Some(duplicate) = self.platforms.iter().find(|p| !seen.insert(&p.platform)) {
            return Err(LockError::Invalid(format!(
                "duplicate platform '{}' in lockfile; each platform may appear at most once",
                duplicate.platform
            )));
        }
        if self.platforms.iter().any(|p| p.platform.jdk().is_some())
            && self.platforms.iter().any(|p| p.platform.jdk().is_none())
        {
            return Err(LockError::Invalid(
                "lockfile mixes platform sections with and without jdk".to_string(),
            ));
        }
        let support_origins = self
            .platforms
            .iter()
            .flat_map(|platform| platform.support_poms.values())
            .map(|pin| pin.repo_url.as_str());
        let artifact_origins = self
            .platforms
            .iter()
            .flat_map(|platform| platform.artifacts.iter())
            .flat_map(LockArtifact::origins);
        let range_origins = self.platforms.iter().flat_map(LockPlatform::range_origins);
        for origin in (artifact_origins.chain(support_origins)).chain(range_origins) {
            if is_project_relative_origin(origin) {
                validate_project_relative_origin(origin)?;
            }
        }
        for platform in &self.platforms {
            validate_platform(platform)?;
            self.check_target_reads(platform)?;
        }
        self.check_read_unions()?;
        check_cross_platform_pins(&self.platforms)?;
        check_pom_pins(&self.platforms)?;
        Ok(())
    }

    /// What each of [`Self::platforms`] read: its own lists, or all of
    /// [`Self::repo_ids`] and of the conditions and host values of
    /// `[resolution] ambient_inputs` where it lists none.
    pub fn target_reads(&self) -> Vec<TargetReads> {
        (self.platforms.iter())
            .map(|platform| platform.reads(&self.repo_ids, &self.resolution.ambient_inputs))
            .collect()
    }

    /// Set what each of [`Self::platforms`] read, `reads` in the same order:
    /// [`Self::repo_ids`] and the names of `[resolution] ambient_inputs`
    /// other than property and variable names become their union, and a
    /// platform that did not read all of it lists what it read. Fails when
    /// `reads` does not hold one entry per platform.
    pub fn set_target_reads(&mut self, reads: &[TargetReads]) -> Result<(), LockError> {
        if reads.len() != self.platforms.len() {
            return Err(LockError::Invalid(format!(
                "{} target reads for {} platforms",
                reads.len(),
                self.platforms.len()
            )));
        }
        let mut ids = RepoIds::new();
        for (origin, id) in reads.iter().flat_map(|read| repo_id_lines(&read.repo_ids)) {
            ids.entry(origin.clone()).or_default().insert(id.clone());
        }
        let ambient = &mut self.resolution.ambient_inputs;
        ambient.retain(AmbientInput::is_property_name);
        ambient.extend(
            reads
                .iter()
                .flat_map(|read| read.host_inputs.iter().cloned()),
        );
        let host_inputs = self.host_inputs();
        for (platform, read) in self.platforms.iter_mut().zip(reads) {
            platform.repo_ids = (read.repo_ids != ids).then(|| read.repo_ids.clone());
            platform.host_inputs =
                (read.host_inputs != host_inputs).then(|| read.host_inputs.clone());
        }
        self.set_repo_ids(ids)
    }

    /// A property or variable name `[resolution] ambient_inputs` lists that
    /// no platform's records list as read, which a sync never writes: it
    /// lists a name only while a graph read it. `None` also when a platform
    /// has no records to tell.
    pub fn unread_property_name(&self) -> Option<&AmbientInput> {
        let mut read = HashSet::new();
        for platform in &self.platforms {
            read.extend(platform.model_inputs.as_ref()?.read_names());
        }
        (self.resolution.ambient_inputs.iter())
            .find(|input| input.is_property_name() && !read.contains(input))
    }

    /// The names of `[resolution] ambient_inputs` other than property and
    /// variable names.
    fn host_inputs(&self) -> BTreeSet<AmbientInput> {
        host_inputs(&self.resolution.ambient_inputs)
    }

    /// Every line and name the lock lists is one a platform read, so a merge
    /// of branches that each dropped a platform's last reader is refused.
    fn check_read_unions(&self) -> Result<(), LockError> {
        if self.platforms.is_empty() {
            return Ok(());
        }
        let reads = self.target_reads();
        let ids: HashSet<(&String, &String)> = (reads.iter())
            .flat_map(|read| repo_id_lines(&read.repo_ids))
            .collect();
        if let Some((origin, id)) = repo_id_lines(&self.repo_ids).find(|line| !ids.contains(line)) {
            return Err(LockError::Invalid(format!(
                "metadata.repo_ids lists repository id {:?} of {:?}, which no target's inputs list",
                crate::error::printable(id),
                redact_origin(origin)
            )));
        }
        let inputs: HashSet<&AmbientInput> =
            reads.iter().flat_map(|read| &read.host_inputs).collect();
        if let Some(input) = (self.host_inputs().iter()).find(|input| !inputs.contains(input)) {
            return Err(LockError::Invalid(format!(
                "resolution.ambient_inputs lists host input {:?}, which no target's inputs list",
                input.to_string()
            )));
        }
        Ok(())
    }

    /// A platform lists only lines and names the lock lists.
    fn check_target_reads(&self, platform: &LockPlatform) -> Result<(), LockError> {
        let target = &platform.platform;
        let ids = platform.repo_ids.iter().flat_map(repo_id_lines);
        if let Some((origin, id)) = ids
            .into_iter()
            .find(|(origin, id)| !(self.repo_ids.get(*origin)).is_some_and(|ids| ids.contains(*id)))
        {
            return Err(LockError::Invalid(format!(
                "the inputs of target '{target}' list repository id {:?} of {:?}, which \
                 metadata.repo_ids does not",
                crate::error::printable(id),
                redact_origin(origin)
            )));
        }
        if let Some(input) = (platform.host_inputs.iter().flatten()).find(|input| {
            input.is_property_name() || !self.resolution.ambient_inputs.contains(*input)
        }) {
            return Err(LockError::Invalid(format!(
                "the inputs of target '{target}' list host input {:?}, which is a property or \
                 variable name or which resolution.ambient_inputs does not list",
                input.to_string()
            )));
        }
        Ok(())
    }

    /// Read and check the lockfile at `path`. A file over 256 MiB, one that
    /// is not UTF-8, one of another schema, and one that breaks a rule of
    /// the schema are refused, as is an origin not spelled as the project
    /// directory holding `path` records it.
    pub fn read(path: &Path) -> Result<Self, LockError> {
        Self::read_with_limit(path, MAX_LOCKFILE_BYTES)
    }

    fn read_with_limit(path: &Path, max_bytes: u64) -> Result<Self, LockError> {
        let context = || format!("failed to read lockfile {}", path.display());
        // `Read::take` enforces the cap at the read site so a file that grows
        // (or is replaced) after open still fails closed; `metadata` +
        // `fs::read` would leak a TOCTOU bypass.
        let file = fs::File::open(path).map_err(|err| LockError::io(context(), err))?;
        // Read up to max_bytes + 1 so we can distinguish "exactly at the
        // limit" (allowed) from "over the limit" (rejected).
        let mut bytes = Vec::with_capacity((max_bytes as usize).min(64 * 1024));
        file.take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|err| LockError::io(context(), err))?;
        if bytes.len() as u64 > max_bytes {
            return Err(LockError::TooLarge {
                path: path.to_path_buf(),
                size: bytes.len() as u64,
                limit: max_bytes,
            });
        }
        // Bytes that are not UTF-8 are a broken lockfile, not a failed read,
        // so a plain sync replaces them.
        let contents = String::from_utf8(bytes).map_err(|err| {
            LockError::Invalid(format!(
                "lockfile {} is not valid UTF-8: {}",
                path.display(),
                err.utf8_error()
            ))
        })?;
        if contents.trim().is_empty() {
            return Err(LockError::Empty {
                path: path.to_path_buf(),
            });
        }
        let lock = codec::decode(&contents, path)?;
        // Origins are relative to the directory the lock is named in, not to
        // a symlink's target: that is the project the lock belongs to.
        lock.check_origins(&LockOrigins::for_lock_path(path))?;
        Ok(lock)
    }

    /// Parse the text of a lockfile. Runs every check [`Lockfile::read`]
    /// runs except the origin check, which needs the lockfile's location.
    pub fn from_toml(contents: &str) -> Result<Self, LockError> {
        codec::decode(contents, Path::new("raeva.lock"))
    }

    /// The canonical text [`Lockfile::write_atomic`] writes.
    pub fn to_toml(&self) -> Result<String, LockError> {
        let raw = codec::encode(&self.canonical()?)?;
        toml::to_string_pretty(&raw)
            .map(|text| format!("{HEADER}{text}"))
            .map_err(|err| LockError::Invalid(format!("failed to encode lockfile: {err}")))
    }

    /// Whether the file at `path` holds the text [`Lockfile::write_atomic`]
    /// writes for this lock, or it with CRLF line endings.
    pub fn is_written_at(&self, path: &Path) -> Result<bool, LockError> {
        Ok(rewrite_unneeded(path, self.to_toml()?.as_bytes()))
    }

    /// Write the canonical form to `path`, replacing the file so a reader
    /// sees the old contents or the new ones. Writes nothing if the lockfile
    /// breaks a rule of the schema or an origin is not spelled as the
    /// project directory holding `path` records it
    /// ([`Lockfile::relativize_origins`]). A file that already holds exactly
    /// these bytes is left as it is, also through a symbolic link.
    ///
    /// Other bytes for a symbolic link at `path` are refused: the rename
    /// would replace the link and leave the file it names stale, and writing
    /// through it would let a link a checkout holds point the write at any
    /// file.
    pub fn write_atomic(&self, path: &Path) -> Result<(), LockError> {
        let contents = self.to_toml()?;
        self.check_origins(&LockOrigins::for_lock_path(path))?;
        if rewrite_unneeded(path, contents.as_bytes()) {
            return Ok(());
        }
        let failed =
            |err| LockError::io(format!("failed to write lockfile {}", path.display()), err);
        if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(failed(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "it is a symbolic link, which raeva does not write through; replace it with a \
                 copy of the file it names",
            )));
        }
        write_file_atomic(path, contents.as_bytes(), NewFileAccess::Shared).map_err(failed)
    }

    /// Refuse an origin with userinfo, a query or a fragment, which may hold
    /// a credential, in a lock read or written. Configuration and POM
    /// repositories with one are refused before resolution; this keeps a
    /// carried-forward row from writing one either. The message names the
    /// row, never the URL.
    fn check_no_secret_origins(&self) -> Result<(), LockError> {
        let rows = self.platforms.iter().flat_map(|platform| {
            platform.artifacts.iter().flat_map(move |artifact| {
                artifact.origins().map(move |origin| {
                    (
                        origin,
                        format!(
                            "repo_url of artifact '{}' on platform '{}'",
                            artifact.coordinate, platform.platform
                        ),
                    )
                })
            })
        });
        let support = self.platforms.iter().flat_map(|platform| {
            platform.support_poms.iter().map(move |(coord, pin)| {
                (
                    pin.repo_url.as_str(),
                    format!(
                        "repo_url of support POM '{coord}' on platform '{}'",
                        platform.platform
                    ),
                )
            })
        });
        let ids = self
            .repo_ids
            .keys()
            .map(|origin| (origin.as_str(), "an origin in repo_ids".to_string()));
        let evicted = self.platforms.iter().flat_map(|platform| {
            platform.range_origins().map(move |origin| {
                (
                    origin,
                    format!("a range origin on platform '{}'", platform.platform),
                )
            })
        });
        for (origin, what) in rows.chain(support).chain(ids).chain(evicted) {
            if is_project_relative_origin(origin) {
                continue;
            }
            if let Some(part) = rv_config::secret_url_part(origin) {
                return Err(LockError::Invalid(format!(
                    "{what} has {part}, which may hold a credential; raeva.lock never records one"
                )));
            }
        }
        Ok(())
    }
}

/// Whether `path` is, or links to, a regular file holding exactly
/// `contents`, or them with CRLF line endings as a Git checkout on Windows
/// may have.
fn rewrite_unneeded(path: &Path, contents: &[u8]) -> bool {
    // CRLF line endings at most double the size, so a longer file differs
    // without being read whole.
    let limit = 2 * contents.len() as u64;
    let read = || -> std::io::Result<Vec<u8>> {
        let mut existing = Vec::new();
        fs::File::open(path)?
            .take(limit + 1)
            .read_to_end(&mut existing)?;
        Ok(existing)
    };
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() <= limit)
        && read().is_ok_and(|existing| {
            existing == contents
                || (existing.len() > contents.len()
                    && String::from_utf8(existing)
                        .is_ok_and(|text| text.replace("\r\n", "\n").as_bytes() == contents))
        })
}

fn check_repo_ids(ids: &RepoIds) -> Result<(), LockError> {
    encode_repo_id_lines(ids)?;
    ids.keys()
        .filter(|origin| is_project_relative_origin(origin))
        .try_for_each(|origin| validate_project_relative_origin(origin))
}

/// Every platform's row for one coordinate must pin the same file, and
/// every row naming one local-repository file, under any coordinate and on
/// any platform, must pin the same bytes: Maven keeps one file per path, so
/// two pins describe a `~/.m2` that cannot exist, and `export-m2`,
/// `export-checksums` and `lock verify` would each act on whichever row they
/// met first.
fn check_cross_platform_pins(platforms: &[LockPlatform]) -> Result<(), LockError> {
    // Every pair is compared: rows that each agree with a first row can
    // still disagree with each other on an algorithm the first lacks.
    let mut files: HashMap<String, Vec<(&LockArtifact, &Platform)>> = HashMap::new();
    for platform in platforms {
        for artifact in &platform.artifacts {
            let file = artifact.repository_path();
            let seen_rows = files.entry(file.clone()).or_default();
            if let Some((seen, seen_platform)) = seen_rows
                .iter()
                .find(|(seen, _)| seen.bytes_differ(artifact))
            {
                return Err(LockError::Invalid(format!(
                    "conflicting pins for the local-repository file {file:?}: \
                     '{}' on platform '{}' and '{}' on platform '{}' record \
                     different checksums",
                    seen.coordinate, seen_platform, artifact.coordinate, platform.platform
                )));
            }
            seen_rows.push((artifact, &platform.platform));
        }
    }
    if let Some(coordinate) = conflicting_extension_jar(platforms) {
        return Err(LockError::Invalid(format!(
            "conflicting pins for build extension '{coordinate}': two rows record different \
             checksums for its jar; one Maven local repository holds one file per path"
        )));
    }
    // A parent or BOM several platforms read is one file in a local
    // repository, so it has one build and one digest. A `-SNAPSHOT` row and
    // a row naming its timestamped build name one file too.
    let mut support: HashMap<&str, (&SupportPom, &Platform)> = HashMap::new();
    let mut support_files: HashMap<Gav, (&Sha256, &str)> = HashMap::new();
    for platform in platforms {
        for (coord, pin) in &platform.support_poms {
            let (seen, first) = *support
                .entry(coord.as_str())
                .or_insert((pin, &platform.platform));
            if seen.snapshot != pin.snapshot || seen.sha256 != pin.sha256 {
                return Err(LockError::Invalid(format!(
                    "conflicting pins for support POM '{coord}': platforms '{first}' and '{}' \
                     record different checksums or snapshot builds; one Maven local repository \
                     holds one file per coordinate",
                    platform.platform
                )));
            }
            let Some(file) = pin.file_gav(coord) else {
                continue;
            };
            let (digest, other) = *support_files
                .entry(file)
                .or_insert((&pin.sha256, coord.as_str()));
            if *digest != pin.sha256 {
                return Err(LockError::Invalid(format!(
                    "conflicting pins for support POMs '{other}' and '{coord}': they name one \
                     file with different checksums"
                )));
            }
        }
    }
    // Rows for one coordinate that name other snapshot builds name other
    // files, so only the build is left to compare.
    let mut builds: HashMap<&ArtifactCoord, (&Option<SnapshotStamp>, &Platform)> = HashMap::new();
    for platform in platforms {
        for artifact in &platform.artifacts {
            let (build, first) = *builds
                .entry(&artifact.coordinate)
                .or_insert((&artifact.snapshot, &platform.platform));
            if *build != artifact.snapshot {
                return Err(LockError::Invalid(format!(
                    "conflicting pins for '{}': platforms '{first}' and '{}' record different \
                     checksums or snapshot builds; one Maven local repository holds one \
                     file per coordinate",
                    artifact.coordinate, platform.platform
                )));
            }
        }
    }
    Ok(())
}

/// The first build extension of `platforms` whose jar a module or an
/// artifact row pins to other bytes, by SHA-256, than one of theirs.
fn conflicting_extension_jar<P: std::borrow::Borrow<LockPlatform>>(
    platforms: &[P],
) -> Option<String> {
    let platforms = || platforms.iter().map(std::borrow::Borrow::borrow);
    let mut jars: HashMap<String, &ExtensionJar> = HashMap::new();
    for (path, jar) in platforms().flat_map(LockPlatform::extension_jars) {
        if jars.entry(path).or_insert(jar).sha256 != jar.sha256 {
            return Some(jar.to_string());
        }
    }
    let rows = platforms().flat_map(|platform| &platform.artifacts);
    rows.filter_map(|row| match row.pin() {
        Some(Digest::Sha256(pin)) => jars
            .get(&row.repository_path())
            .filter(|jar| jar.sha256 != *pin),
        _ => None,
    })
    .map(ToString::to_string)
    .next()
}

/// Every artifact row naming one `group:artifact:version` must pin the same
/// companion POM, or none, across classifiers and across platforms, and a
/// support POM naming that file must pin it too, unless the rows pin none:
/// a plugin may read the POM from a repository the rows' lacks.
///
/// Maven has exactly one local-repository path per GAV, so `raeva export-m2`
/// writes one `.pom` there, or none for a dependency no repository has a POM
/// for. Two answers describe a `~/.m2` that cannot exist: export would ship
/// whichever it met first while another row attests something else was
/// resolved. `raeva sync` refuses to write such a lockfile; this catches a
/// hand-edited one, and the carry-forward merge that could construct one,
/// for every consumer at once.
fn check_pom_pins(platforms: &[LockPlatform]) -> Result<(), LockError> {
    let support: HashMap<Gav, (&str, &SupportPom)> = platforms
        .iter()
        .flat_map(|platform| &platform.support_poms)
        .filter_map(|(coord, pin)| Some((pin.file_gav(coord)?, (coord.as_str(), pin))))
        .collect();
    let text =
        |digest: Option<&Sha256>| digest.map_or_else(|| "none".to_string(), Sha256::to_string);
    let mut pinned: HashMap<Gav, (Option<&Sha256>, &Platform)> = HashMap::new();
    let mut builds: HashMap<&Gav, Gav> = HashMap::new();
    for platform in platforms {
        for artifact in &platform.artifacts {
            let digest = artifact.pom_sha256.as_ref();
            let gav = artifact.pom_gav();
            let seen = builds
                .entry(&artifact.coordinate.gav)
                .or_insert_with(|| gav.clone());
            if *seen != gav {
                return Err(LockError::Invalid(format!(
                    "conflicting companion POM builds for {}: {seen} and {gav}",
                    artifact.coordinate.gav
                )));
            }
            let (seen, seen_platform) = *pinned
                .entry(gav.clone())
                .or_insert((digest, &platform.platform));
            if seen != digest {
                return Err(LockError::Invalid(format!(
                    "conflicting pom_sha256 for '{gav}': {} on platform '{seen_platform}' \
                     and {} on platform '{}'; one Maven local repository cannot hold both",
                    text(seen),
                    text(digest),
                    platform.platform
                )));
            }
            // A row read without a POM, from a repository that lacks it,
            // beside a support POM another repository served: Maven's local
            // repository holds that one.
            if let Some((coord, support)) = support.get(&gav)
                && digest.is_some_and(|digest| *digest != support.sha256)
            {
                return Err(LockError::Invalid(format!(
                    "conflicting POM digests for '{gav}': support POM '{coord}' pins {} \
                     but artifact '{}' on platform '{}' pins pom_sha256 {}; \
                     one Maven local repository cannot hold both",
                    support.sha256,
                    artifact.coordinate,
                    platform.platform,
                    text(digest)
                )));
            }
        }
    }
    for platform in platforms {
        if let Some(coord) =
            crate::merge::conflicting_snapshot_pom(&platform.support_poms, platforms)
        {
            return Err(LockError::Invalid(format!(
                "conflicting POM digests for '{coord}': its support POM and an artifact row \
                 pin different bytes; one Maven local repository holds one -SNAPSHOT.pom"
            )));
        }
    }
    Ok(())
}

/// The first lines of every raeva.lock. License checks such as Apache RAT
/// accept a file that says it is `@generated`, as Cargo.lock does.
const HEADER: &str =
    "# This file is automatically @generated by raeva.\n# It is not intended for manual editing.\n";

/// Refuse every schema but the current one. An older lock was written by an
/// earlier raeva and a newer one by a later raeva; neither is migrated in place.
pub(crate) fn check_schema_version(found: u32) -> Result<(), LockError> {
    if found == LOCKFILE_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(LockError::UnsupportedSchema {
            found,
            expected: LOCKFILE_SCHEMA_VERSION,
        })
    }
}

fn validate_platform(platform: &LockPlatform) -> Result<(), LockError> {
    if !is_sha256_hex(&platform.model_hash) {
        return Err(LockError::Invalid(format!(
            "model_hash on platform '{}' must be 64 lowercase hex characters",
            platform.platform
        )));
    }
    if platform.modules.is_empty() {
        return Err(LockError::Invalid(format!(
            "platform '{}' has no modules",
            platform.platform
        )));
    }

    let mut module_paths = HashMap::with_capacity(platform.modules.len());
    let mut module_gavs = HashSet::with_capacity(platform.modules.len());
    for module in &platform.modules {
        if module_paths.insert(module.path.as_str(), module).is_some() {
            return Err(LockError::Invalid(format!(
                "duplicate module path '{}' on platform '{}'",
                module.path, platform.platform
            )));
        }
        if !module_gavs.insert(&module.gav) {
            return Err(LockError::Invalid(format!(
                "duplicate effective module GAV '{}:{}:{}' on platform '{}'",
                module.gav.group,
                module.gav.artifact,
                module.gav.version(),
                platform.platform
            )));
        }
    }

    let mut artifact_by_coordinate =
        foldhash::HashMap::with_capacity_and_hasher(platform.artifacts.len(), Default::default());
    for (index, artifact) in platform.artifacts.iter().enumerate() {
        if artifact_by_coordinate
            .insert(&artifact.coordinate, index)
            .is_some()
        {
            return Err(LockError::Invalid(format!(
                "duplicate artifact '{}' on platform '{}'",
                artifact.coordinate, platform.platform
            )));
        }
        if artifact.checksums.is_empty() {
            return Err(LockError::Invalid(format!(
                "artifact '{}' on platform '{}' has no checksum",
                artifact.coordinate, platform.platform
            )));
        }
        let own_pom = artifact.is_own_pom();
        if let Some(stamp) = &artifact.pom_snapshot
            && (!rv_maven_types::resolves_through_snapshot_metadata(artifact.coordinate.version())
                || Some(stamp) == artifact.snapshot.as_ref()
                || own_pom)
        {
            return Err(LockError::Invalid(format!(
                "invalid pom_snapshot for '{}': requires a SNAPSHOT with a different companion POM build",
                artifact.coordinate
            )));
        }
        if artifact.pom_base
            && (artifact.snapshot.is_none() || artifact.pom_snapshot.is_some() || own_pom)
        {
            return Err(LockError::Invalid(format!(
                "invalid pom_base for '{}': requires a snapshot build and no pom_snapshot",
                artifact.coordinate
            )));
        }
        let mut algorithms = HashSet::with_capacity(artifact.checksums.len());
        for checksum in &artifact.checksums {
            if checksum.algorithm() == HashAlgorithm::Md5 {
                return Err(LockError::Invalid(format!(
                    "md5 checksum for artifact '{}' on platform '{}'; raeva.lock records sha256 \
                     and sha1 checksums only",
                    artifact.coordinate, platform.platform
                )));
            }
            if !algorithms.insert(checksum.algorithm()) {
                return Err(LockError::Invalid(format!(
                    "duplicate {} checksum for artifact '{}' on platform '{}'",
                    checksum.algorithm(),
                    artifact.coordinate,
                    platform.platform
                )));
            }
        }
        // A `packaging = "pom"` row's payload IS its companion POM: one file
        // in the repository, one path in `~/.m2`, and `raeva export-m2` exports
        // it as the primary artifact. Two digests describe a file that cannot
        // exist, and export would ship the payload while the lock claims the
        // pin. `raeva sync` refuses to write such a row; this catches a
        // hand-edited one. Only the classifier-less row names that file (a
        // classified `.pom` is its own artifact). The graph digests cover
        // `pom_sha256` alone, so the payload must be that one sha256: a sha1
        // pin, or none in `pom_sha256`, would let an edit choose the bytes.
        let pom_digest = artifact.pom_sha256.as_ref();
        if own_pom
            && pom_digest.is_none_or(|pom| artifact.checksums != [Digest::Sha256(pom.clone())])
        {
            let payload: Vec<_> = artifact.checksums.iter().map(ToString::to_string).collect();
            return Err(LockError::Invalid(format!(
                "pom-packaged artifact '{}' on platform '{}' pins payload {} but \
                 pom_sha256 {}; for packaging=pom those name the same file, pinned by one sha256",
                artifact.coordinate,
                platform.platform,
                payload.join(", "),
                pom_digest.map_or_else(|| "none".to_string(), Sha256::to_string)
            )));
        }
    }

    let mut used_artifacts = vec![false; platform.artifacts.len()];
    if let Some(tables) = &platform.plugins {
        for index in crate::plugins::check(tables, platform)? {
            used_artifacts[index] = true;
        }
    }
    // Modules check apart; the first failure in module order is reported.
    let checked = rv_maven_types::par_map(&platform.modules, |module| {
        validate_module(platform, module, &module_paths, &artifact_by_coordinate)
    });
    let mut shared = Vec::new();
    for checked in checked {
        let (used, rows) = checked?;
        for index in used {
            used_artifacts[index] = true;
        }
        shared.extend(rows);
    }
    // A workspace or system package shares its coordinates with a row only
    // when another use holds it: an extension takes the repository's file,
    // and so does a module that names its own coordinates.
    if let Some(shared) = shared.iter().find(|shared| !used_artifacts[shared.row]) {
        return Err(LockError::Invalid(format!(
            "{} package '{}' must not have an artifact-table row",
            shared.kind, shared.package
        )));
    }
    for (artifact, used) in platform.artifacts.iter().zip(used_artifacts) {
        if !used {
            return Err(LockError::Invalid(format!(
                "orphan artifact row '{}' on platform '{}'",
                artifact.coordinate, platform.platform
            )));
        }
    }
    Ok(())
}

/// A row that shares the coordinates of a workspace or system package.
struct SharedRow {
    package: ArtifactCoord,
    row: usize,
    kind: &'static str,
}

/// [`validate_platform`] for the rows of `module`: the indices of the
/// artifact rows its packages use, and the rows its workspace and system
/// packages share coordinates with.
fn validate_module(
    platform: &LockPlatform,
    module: &LockModule,
    module_paths: &HashMap<&str, &LockModule>,
    artifact_by_coordinate: &foldhash::HashMap<&ArtifactCoord, usize>,
) -> Result<(Vec<usize>, Vec<SharedRow>), LockError> {
    let mut used = Vec::with_capacity(module.packages.len());
    let mut shared = Vec::new();
    let mut package_coordinates =
        foldhash::HashSet::with_capacity_and_hasher(module.packages.len(), Default::default());
    for package in &module.packages {
        if !package_coordinates.insert(&package.coordinate) {
            return Err(LockError::Invalid(format!(
                "duplicate package '{}' in module '{}' on platform '{}'",
                package.coordinate, module.path, platform.platform
            )));
        }
    }

    for edge in &module.edges {
        if edge.from >= module.packages.len() || edge.to >= module.packages.len() {
            return Err(LockError::Invalid(format!(
                "edge ({} -> {}) is out of bounds for {} packages in module '{}' \
                 on platform {}",
                edge.from,
                edge.to,
                module.packages.len(),
                module.path,
                platform.platform,
            )));
        }
    }

    for package in &module.packages {
        if package.workspace_module.is_some() && package.system_path.is_some() {
            return Err(LockError::Invalid(format!(
                "package '{}' in module '{}' cannot be both workspace and system scoped",
                package.coordinate, module.path
            )));
        }
        check_system_package(package, &module.path)?;

        if let Some(workspace_path) = package.workspace_module.as_deref() {
            let target = module_paths.get(workspace_path).ok_or_else(|| {
                LockError::Invalid(format!(
                    "workspace_module '{}' referenced by package '{}' in module '{}' \
                     does not resolve to a module row",
                    workspace_path, package.coordinate, module.path
                ))
            })?;
            if package.coordinate.gav != target.gav {
                return Err(LockError::Invalid(format!(
                    "workspace_module '{}' GAV '{}' does not match package '{}'",
                    workspace_path, target.gav, package.coordinate
                )));
            }
            if let Some(&row) = artifact_by_coordinate.get(&package.coordinate) {
                shared.push(SharedRow {
                    package: package.coordinate.clone(),
                    row,
                    kind: "workspace",
                });
            }
        } else if package.system_path.is_some() {
            if let Some(&row) = artifact_by_coordinate.get(&package.coordinate) {
                shared.push(SharedRow {
                    package: package.coordinate.clone(),
                    row,
                    kind: "system-scoped",
                });
            }
        } else {
            let Some(&index) = artifact_by_coordinate.get(&package.coordinate) else {
                return Err(LockError::Invalid(format!(
                    "external package '{}' in module '{}' has no artifact-table row",
                    package.coordinate, module.path
                )));
            };
            used.push(index);
        }
    }
    for coord in &module.support_poms {
        if !platform.support_poms.contains_key(coord) {
            return Err(LockError::Invalid(format!(
                "support POM '{coord}' of module '{}' on platform '{}' has no \
                 support_poms row",
                module.path, platform.platform
            )));
        }
    }
    for (at, coord) in module.parents.iter().enumerate() {
        if !module.support_poms.contains(coord) || module.parents[..at].contains(coord) {
            return Err(LockError::Invalid(format!(
                "parent '{coord}' of module '{}' on platform '{}' is not one of its \
                 support POMs, or is named twice",
                module.path, platform.platform
            )));
        }
    }
    Ok((used, shared))
}

/// Check every string in `lock` that a later check, a path, a URL or a
/// message could use: coordinate components, module and workspace paths,
/// system paths, origins and model inputs. It runs before anything else
/// reads the lock, so the messages of every later check can quote these
/// values as they are.
fn check_lock_fields(lock: &Lockfile) -> Result<(), LockError> {
    if let Some(hash) = lock.config_hash.as_deref() {
        check_text(hash, "config_hash")?;
    }
    for platform in &lock.platforms {
        if let Some(jdk) = platform.platform.jdk()
            && !rv_config::is_valid_jdk(jdk)
        {
            return Err(LockError::Invalid(format!(
                "invalid jdk {:?} on platform '{}': must be 1 to 32 ASCII letters, \
                 digits, '.', '_', '-' or '+'",
                crate::error::printable(jdk),
                platform.platform.os_arch()
            )));
        }
        let on = format!("on platform '{}'", platform.platform);
        if let Some(inputs) = platform.model_inputs.as_ref() {
            check_model_inputs(inputs, &platform.platform)?;
        }
        for artifact in &platform.artifacts {
            validate_coordinate(
                &artifact.coordinate,
                &|| format!("artifact table {on}"),
                false,
            )?;
            let row = || format!("artifact '{}' {on}", artifact.coordinate);
            for origin in artifact.origins() {
                check_origin_text(origin, &row)?;
            }
            if artifact.snapshot.is_some()
                && !rv_maven_types::resolves_through_snapshot_metadata(
                    artifact.coordinate.version(),
                )
            {
                return Err(LockError::Invalid(format!(
                    "{} records a snapshot build, but its version is not a SNAPSHOT",
                    row()
                )));
            }
        }
        for (coord, pin) in &platform.support_poms {
            check_support_pom(coord, pin, &on)?;
        }
        for checked in rv_maven_types::par_map(&platform.modules, |module| {
            check_module_fields(module, lock.maven, &on)
        }) {
            checked?;
        }
    }
    Ok(())
}

/// [`check_lock_fields`] for the support POM row `coord` on the platform
/// `on` names. A lock that does not read passes it too before its pins are
/// kept, as one that fails it pins no file.
pub(crate) fn check_support_pom(coord: &str, pin: &SupportPom, on: &str) -> Result<(), LockError> {
    validate_support_pom_coord(coord)?;
    let row = || format!("support POM '{coord}' {on}");
    check_origin_text(&pin.repo_url, &row)?;
    if pin.snapshot.is_some() && pin.file_gav(coord).is_none() {
        return Err(LockError::Invalid(format!(
            "{} records a snapshot build, but its version is not a SNAPSHOT",
            row()
        )));
    }
    Ok(())
}

/// [`check_lock_fields`] for the strings of `module`, on the platform `on`
/// names.
fn check_module_fields(module: &LockModule, mode: MavenMode, on: &str) -> Result<(), LockError> {
    validate_module_path(&module.path, "module")?;
    let row = format!("module '{}' {on}", module.path);
    let key = |jar: &ExtensionJar| (jar.gav.clone(), jar.classifier.clone());
    for (index, jar) in module.extensions.iter().enumerate() {
        let earlier = index
            .checked_sub(1)
            .map(|index| key(&module.extensions[index]));
        if jar.coord().validate().is_err()
            || jar.classifier.as_deref() == Some("")
            || earlier.is_some_and(|earlier| earlier >= key(jar))
        {
            return Err(LockError::Invalid(format!(
                "{row} lists build extension {} out of order, twice or invalid",
                crate::error::printable(&jar.to_string())
            )));
        }
    }
    let mut ranges = HashSet::new();
    for range in &module.evicted_ranges {
        check_evicted_range(range, mode, &row)?;
        if !ranges.insert((&range.group, &range.artifact, &range.range, &range.origin)) {
            return Err(LockError::Invalid(format!(
                "{row} records the evicted range {}:{} {} of one origin twice",
                range.group, range.artifact, range.range
            )));
        }
    }
    if !module
        .range_versions
        .is_sorted_by(|left, right| left < right)
    {
        return Err(LockError::Invalid(format!(
            "{row} lists its range versions out of order or twice"
        )));
    }
    for read in &module.range_versions {
        check_range_version(read, &row)?;
    }
    let mut selections = HashSet::new();
    for selection in &module.parent_ranges {
        let invalid = || LockError::Invalid(format!("invalid parent range selection in {row}"));
        let (group, artifact, version) = split_reactor_gav(&selection.model).ok_or_else(invalid)?;
        validate_coordinate_component(CoordinateField::Group, group).map_err(|_| invalid())?;
        validate_coordinate_component(CoordinateField::Artifact, artifact)
            .map_err(|_| invalid())?;
        validate_reactor_version(version).map_err(|_| invalid())?;
        let (group, artifact, range) =
            split_support_pom_coord(&selection.parent).ok_or_else(invalid)?;
        validate_coordinate_component(CoordinateField::Group, group).map_err(|_| invalid())?;
        validate_coordinate_component(CoordinateField::Artifact, artifact)
            .map_err(|_| invalid())?;
        validate_reactor_version(range).map_err(|_| invalid())?;
        if !range.trim_start().starts_with(['[', '(']) {
            return Err(invalid());
        }
        let range = rv_maven_types::VersionReq::parse_in(range, mode).map_err(|_| invalid())?;
        validate_support_pom_coord(&selection.selected)?;
        let (selected_group, selected_artifact, version) =
            split_support_pom_coord(&selection.selected).ok_or_else(invalid)?;
        if group != selected_group
            || artifact != selected_artifact
            || !rv_maven_types::Version::parse(version)
                .is_ok_and(|version| range.matches_in(&version, mode))
            || !selections.insert((&selection.model, &selection.parent))
        {
            return Err(invalid());
        }
    }
    for (field, value) in [
        (CoordinateField::Group, module.gav.group.as_str()),
        (CoordinateField::Artifact, module.gav.artifact.as_str()),
    ] {
        validate_coordinate_component(field, value).map_err(|err| invalid_lock_field(&row, err))?;
    }
    validate_reactor_version(module.gav.version()).map_err(|err| invalid_lock_field(&row, err))?;
    validate_coordinate_component(CoordinateField::Extension, &module.packaging)
        .map_err(|err| invalid_lock_field(&row, err))?;
    for package in &module.packages {
        let reactor = package.workspace_module.is_some();
        validate_coordinate(
            &package.coordinate,
            &|| format!("package of {row}"),
            reactor,
        )?;
        if let Some(workspace_path) = package.workspace_module.as_deref() {
            validate_module_path(workspace_path, "workspace_module")?;
        }
        if let Some(system_path) = package.system_path.as_deref() {
            check_text(
                system_path,
                &format!("system_path of package '{}' in {row}", package.coordinate),
            )?;
        }
    }
    Ok(())
}

/// The rules for a system-scoped package row: `system_path` and
/// `system_sha256` come together, the path is a normalized path inside the
/// directory that holds raeva.lock, and the package resolves to `system`,
/// whatever its direct scope. A `system` row without a path is a repository
/// artifact a range moved a direct `system` declaration to, which keeps the
/// declared scope.
fn check_system_package(package: &LockModulePackage, module: &str) -> Result<(), LockError> {
    if package.system_path.is_none() && package.system_sha256.is_none() {
        return Ok(());
    }
    let row = format!("package '{}' in module '{module}'", package.coordinate);
    match (&package.system_path, &package.system_sha256) {
        (Some(path), Some(_)) => {
            crate::system::check_system_path(path).map_err(|reason| {
                LockError::Invalid(format!(
                    "system_path {:?} of {row} must be relative to the directory that holds \
                     raeva.lock: {reason}",
                    crate::error::printable(path)
                ))
            })?;
            if package.scope != Scope::System {
                return Err(LockError::Invalid(format!(
                    "{row} has a system_path but scope {:?}; expected \"system\"",
                    package.scope.as_str()
                )));
            }
        }
        (Some(_), None) => {
            return Err(LockError::Invalid(format!(
                "{row} has a system_path but no system_sha256"
            )));
        }
        (None, Some(_)) => {
            return Err(LockError::Invalid(format!(
                "{row} has a system_sha256 but no system_path"
            )));
        }
        (None, None) => {}
    }
    Ok(())
}

fn invalid_lock_field(row: &str, err: impl std::fmt::Display) -> LockError {
    LockError::Invalid(format!("invalid {row}: {err}"))
}

/// `reactor` for a reactor module's coordinate, as a workspace package names
/// it: its version gets [`validate_reactor_version`] instead of the full rule.
pub(crate) fn validate_coordinate(
    coordinate: &ArtifactCoord,
    row: &dyn Fn() -> String,
    reactor: bool,
) -> Result<(), LockError> {
    if reactor {
        validate_reactor_version(coordinate.version())
            .map_err(|err| invalid_lock_field(&row(), err))?;
    } else {
        validate_coordinate_component(CoordinateField::Version, coordinate.version())
            .map_err(|err| invalid_lock_field(&row(), err))?;
    }
    let classifier = coordinate
        .classifier()
        .map(|classifier| (CoordinateField::Classifier, classifier));
    [
        (CoordinateField::Group, coordinate.group_id()),
        (CoordinateField::Artifact, coordinate.artifact_id()),
        (CoordinateField::Extension, coordinate.extension()),
    ]
    .into_iter()
    .chain(classifier)
    .try_for_each(|(field, value)| {
        validate_coordinate_component(field, value).map_err(|err| invalid_lock_field(&row(), err))
    })
}

fn check_text(value: &str, what: &str) -> Result<(), LockError> {
    if is_terminal_safe(value) {
        Ok(())
    } else {
        Err(LockError::Invalid(format!(
            "{what} {value:?} contains control or invisible characters"
        )))
    }
}

pub(crate) fn check_origin_text(origin: &str, row: &dyn Fn() -> String) -> Result<(), LockError> {
    if is_terminal_safe(origin) && !origin.contains(char::is_whitespace) {
        Ok(())
    } else {
        Err(LockError::Invalid(format!(
            "repo_url of {} contains whitespace, control or invisible characters",
            row()
        )))
    }
}

/// The profile ids and POM paths [`LockPlatform::set_model_inputs`]
/// recorded end up in `--frozen` messages.
fn check_model_inputs(inputs: &ModelInputs, platform: &Platform) -> Result<(), LockError> {
    let profiles = inputs
        .profiles
        .iter()
        .map(|id| ("profile id", LOCK_MODEL_PROFILES_KEY, id));
    let poms = inputs
        .pom_hashes
        .keys()
        .map(|path| ("POM path", LOCK_MODEL_POM_HASHES_KEY, path));
    profiles.chain(poms).try_for_each(|(what, key, value)| {
        check_text(value, &format!("{what} in {key} on platform '{platform}'"))
    })
}

pub(crate) fn validate_module_path(path: &str, field: &str) -> Result<(), LockError> {
    let invalid = path.is_empty()
        || !is_terminal_safe(path)
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        // `C:/x/pom.xml` would replace the root it is joined to on Windows.
        || path.contains(':')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..");
    // A `<module>` entry may name its POM file under any name, as in Maven.
    if invalid {
        return Err(LockError::Invalid(format!(
            "{field} path {path:?} must be a normalized root-relative POM path"
        )));
    }
    Ok(())
}

impl Lockfile {
    /// Warn, without failing, for each coordinate, path or repository URL
    /// field that holds one of `values`, the values of the `${env.*}`
    /// variables POMs were allowed to read. Such a field means a variable's
    /// value, possibly a secret, ended up in a tracked file. Values shorter
    /// than 4 bytes are skipped, since they match version numbers. The
    /// warning names the field and its row, with the value masked, never
    /// the URL.
    pub fn warn_on_env_values(&self, values: &BTreeMap<String, String>) {
        for hit in self.env_value_hits(values) {
            tracing::warn!(
                target: "raeva::sec::warn_collect",
                sec_code = "ENV_VALUE_IN_LOCKFILE",
                env_var = %hit.env_var,
                field = hit.field,
                row = %hit.row,
                platform = hit.platform.map(tracing::field::display),
                "lockfile field contains the resolved value of an allowlisted ${{env.X}} \
                 substitution; the secret may have leaked into a tracked artifact"
            );
        }
    }

    fn env_value_hits<'a>(&'a self, values: &'a BTreeMap<String, String>) -> Vec<EnvValueHit<'a>> {
        let mut hits = Vec::new();
        // Shorter values match version numbers.
        let values: Vec<_> = (values.iter())
            .filter(|(_, value)| value.len() >= 4)
            .collect();
        if values.is_empty() {
            return hits;
        }
        let mut scan = |platform, row: &dyn Fn() -> String, fields: &[(&'static str, &str)]| {
            scan_fields(&values, platform, row, fields, &mut hits);
        };
        let origins = (self.repo_ids.keys()).map(|origin| ("origin", origin.as_str()));
        scan(
            None,
            &|| "metadata.repo_ids".to_string(),
            &origins.collect::<Vec<_>>(),
        );
        for platform in &self.platforms {
            let on = Some(&platform.platform);
            for artifact in &platform.artifacts {
                let coord = artifact.coord();
                let mut fields = coord_fields(&coord).to_vec();
                fields.push(("repo_url", &artifact.repo_url));
                fields.extend(
                    (artifact.other_repo_urls.iter()).map(|url| ("other_repo_urls", &**url)),
                );
                fields.extend((artifact.pom_repo_urls.iter()).map(|url| ("pom_repo_urls", &**url)));
                scan(on, &|| coord.to_string(), &fields);
            }
            for (key, pin) in &platform.support_poms {
                let mut fields: Vec<_> = ["group_id", "artifact_id", "version"]
                    .into_iter()
                    .zip(key.splitn(3, ':'))
                    .collect();
                fields.push(("repo_url", &pin.repo_url));
                scan(on, &|| format!("support POM {key}"), &fields);
            }
            for module in &platform.modules {
                for package in &module.packages {
                    let (workspace, system) = (&package.workspace_module, &package.system_path);
                    if workspace.is_none() && system.is_none() {
                        continue;
                    }
                    let mut fields = coord_fields(&package.coordinate).to_vec();
                    fields.push(("workspace_module", workspace.as_deref().unwrap_or_default()));
                    fields.push(("system_path", system.as_deref().unwrap_or_default()));
                    scan(on, &|| package.coordinate.to_string(), &fields);
                }
                for range in &module.evicted_ranges {
                    let fields = [
                        ("group_id", range.group.as_str()),
                        ("artifact_id", &range.artifact),
                        ("range", &range.range),
                        ("origin", &range.origin),
                    ];
                    let row = || {
                        let (group, artifact) = (&range.group, &range.artifact);
                        format!(
                            "evicted range {group}:{artifact} {} of {}",
                            range.range, module.path
                        )
                    };
                    scan(on, &row, &fields);
                }
                let row = || format!("metadata_versions of {}", module.path);
                scan_metadata_versions(&mut scan, on, &row, &module.metadata_versions);
                let row = || format!("range_versions of {}", module.path);
                scan_range_versions(&mut scan, on, &row, &module.range_versions);
            }
            if let Some(tables) = &platform.plugins {
                let row = || "the metadata_versions of the plugin tables".to_string();
                scan_metadata_versions(&mut scan, on, &row, &tables.metadata_versions);
                let row = || "the range_versions of the plugin tables".to_string();
                scan_range_versions(&mut scan, on, &row, &tables.range_versions);
                for set in &tables.sets {
                    let fields: Vec<_> = (set.repo_urls.iter())
                        .map(|url| ("repo_urls", &**url))
                        .collect();
                    scan(on, &|| format!("plugin set {}", set.key), &fields);
                }
                for prefix in &tables.prefixes {
                    let fields = [("repo_url", prefix.repo_url.as_str())];
                    scan(
                        on,
                        &|| format!("the prefix list of plugin group {}", prefix.group),
                        &fields,
                    );
                }
                let origins = (tables.repo_ids.keys()).map(|origin| ("origin", origin.as_str()));
                scan(
                    on,
                    &|| "plugins.repo_ids".to_string(),
                    &origins.collect::<Vec<_>>(),
                );
                let shared = (tables.shared_origins.values().flatten())
                    .map(|origin| ("origin", origin.as_str()));
                scan(
                    on,
                    &|| "plugins.shared_origins".to_string(),
                    &shared.collect::<Vec<_>>(),
                );
            }
        }
        hits
    }
}

fn scan_metadata_versions<'a>(
    scan: &mut impl FnMut(Option<&'a Platform>, &dyn Fn() -> String, &[(&'static str, &'a str)]),
    platform: Option<&'a Platform>,
    row: &dyn Fn() -> String,
    markers: &'a [MetadataVersion],
) {
    for marker in markers {
        let fields = [
            ("group_id", marker.group.as_str()),
            ("artifact_id", marker.artifact.as_str()),
            ("version", marker.version.as_str()),
        ];
        scan(platform, row, &fields);
    }
}

fn scan_range_versions<'a>(
    scan: &mut impl FnMut(Option<&'a Platform>, &dyn Fn() -> String, &[(&'static str, &'a str)]),
    platform: Option<&'a Platform>,
    row: &dyn Fn() -> String,
    reads: &'a [RangeVersion],
) {
    for read in reads {
        let fields = [
            ("group_id", read.group.as_str()),
            ("artifact_id", read.artifact.as_str()),
            ("version", read.version.as_str()),
            ("origin", read.origin.as_str()),
        ];
        scan(platform, row, &fields);
    }
}

/// A lockfile field holding the value of an allowlisted environment variable.
#[derive(Debug, PartialEq, Eq)]
struct EnvValueHit<'a> {
    env_var: &'a str,
    field: &'static str,
    /// What names the row, with the value masked.
    row: String,
    /// `None` for the lock's metadata.
    platform: Option<&'a Platform>,
}

fn coord_fields(coord: &ArtifactCoord) -> [(&'static str, &str); 5] {
    [
        ("group_id", coord.group_id()),
        ("artifact_id", coord.artifact_id()),
        ("version", coord.version()),
        ("packaging", coord.extension()),
        ("classifier", coord.classifier().unwrap_or_default()),
    ]
}

fn scan_fields<'a>(
    values: &[(&'a String, &'a String)],
    platform: Option<&'a Platform>,
    row: &dyn Fn() -> String,
    fields: &[(&'static str, &str)],
    hits: &mut Vec<EnvValueHit<'a>>,
) {
    for &(name, value) in values {
        for &(field, content) in fields {
            if content.contains(value.as_str()) {
                hits.push(EnvValueHit {
                    env_var: name,
                    field,
                    row: row().replace(value.as_str(), "***"),
                    platform,
                });
            }
        }
    }
}

/// Platform key holding the active profile ids `model_hash` covers.
pub(crate) const LOCK_MODEL_PROFILES_KEY: &str = "inputs.profiles";
/// Platform key holding the digest of each POM `model_hash` covers.
pub(crate) const LOCK_MODEL_POM_HASHES_KEY: &str = "inputs.poms";

/// What a platform's `model_hash` was computed from, recorded so a
/// `--frozen` mismatch can name what changed. The aggregate `model_hash`
/// is recomputed from these records when a lock is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ModelInputs {
    /// The active profile ids, except a profile that a host value (the
    /// JDK, `java.home` or an environment variable) activated and that
    /// cannot change the resolution. Written as `inputs.profiles`.
    pub profiles: Vec<String>,
    /// Contextual digests of modules and local parents, by POM path.
    /// Written as separate `inputs.poms` tables.
    pub pom_hashes: BTreeMap<String, Sha256>,
    /// Each module's graph digest, by POM path, as read from a lock
    /// ([`crate::inputs::graph_digests`]). Written as `graph` in the
    /// module's `inputs.poms` table, computed afresh on every write.
    pub graphs: BTreeMap<String, Sha256>,
    /// The property and variable names of `[resolution] ambient_inputs`
    /// every graph of the platform read, outside any one module's build.
    /// Written as `inputs.ambient_inputs`.
    pub ambient_inputs: BTreeSet<AmbientInput>,
    /// The other names each module's graph read, by POM path. Written as
    /// `ambient_inputs` in the module's `inputs.poms` table.
    pub module_ambient_inputs: BTreeMap<String, BTreeSet<AmbientInput>>,
}

impl ModelInputs {
    /// Every name a graph of the platform read.
    pub fn read_names(&self) -> impl Iterator<Item = &AmbientInput> {
        (self.ambient_inputs.iter()).chain(self.module_ambient_inputs.values().flatten())
    }
}

/// The resolution for one platform: the artifact table its modules share
/// and each module's graph. Identical graphs share one disk section;
/// the codec expands its target list back into these public entries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockPlatform {
    /// The target, recorded in `platforms.targets` and `inputs.target`.
    pub platform: Platform,
    /// Hash of this platform's reactor model: every active module's path,
    /// effective GAV, and POM bytes, the active profile ids, and the bytes of
    /// each local parent POM the resolver accepts (inside the reactor's parent
    /// boundary and carrying the declared parent coordinates). Repository
    /// configuration is deliberately absent and belongs to the top-level
    /// `config_hash`.
    pub model_hash: String,
    /// Every external file the platform's modules use, one row per
    /// coordinate. Written as `[[platforms.artifacts]]`, sorted by
    /// coordinate.
    pub artifacts: Vec<LockArtifact>,
    /// Every reactor module's graph. Written as `[[platforms.modules]]`,
    /// sorted by path.
    pub modules: Vec<LockModule>,
    /// `group:artifact:version` -> pin of each support POM (a parent or an
    /// imported BOM) this platform's resolution read. Written as
    /// `[[platforms.support_poms]]`, in the order of this map.
    pub support_poms: BTreeMap<String, SupportPom>,
    /// Inputs used to recompute `model_hash`, written under `[[inputs]]`.
    /// Without these, the codec preserves the opaque hash supplied by the caller.
    pub model_inputs: Option<ModelInputs>,
    /// The lines of [`Lockfile::repo_ids`] this platform's resolution
    /// used, when that is not all of them. Written as `repo_ids` in the
    /// target's `[[inputs]]`, which every graph digest of the target covers.
    pub repo_ids: Option<RepoIds>,
    /// The names of `[resolution] ambient_inputs` other than property and
    /// variable names that this platform consulted, when that is not all of
    /// them. Written as `host_inputs` in the target's `[[inputs]]`, which
    /// every graph digest of the target covers.
    pub host_inputs: Option<BTreeSet<AmbientInput>>,
    /// The plugin tables, written as `[platforms.plugins]`. Their files
    /// are rows of [`Self::artifacts`] and [`Self::support_poms`].
    pub plugins: Option<crate::PluginTables>,
}

impl LockPlatform {
    /// Each release or timestamped snapshot build extension jar the modules
    /// record, with its path; a plain `-SNAPSHOT` one is left out, as its
    /// file can be redeployed.
    pub fn extension_jars(&self) -> impl Iterator<Item = (String, &ExtensionJar)> {
        (self.modules.iter())
            .flat_map(|module| &module.extensions)
            .filter(|jar| !rv_maven_types::resolves_through_snapshot_metadata(jar.gav.version()))
            .map(|jar| {
                let coord = jar.coord();
                let version = jar.gav.version();
                let directory = rv_maven_types::snapshot_base_version(version);
                let directory = directory.as_deref().unwrap_or(version);
                let path = rv_maven_types::layout::artifact_path(&coord, directory, version);
                (path, jar)
            })
    }

    /// The coordinates of the artifact rows the modules read from a
    /// repository: not those of a reactor module or a system file, though
    /// a row of the same coordinates may serve a plugin.
    pub fn module_rows(&self) -> BTreeSet<&ArtifactCoord> {
        (self.modules.iter())
            .flat_map(|module| &module.packages)
            .filter_map(LockModulePackage::repository_file)
            .collect()
    }

    /// A platform with this model hash and no artifacts or modules yet.
    pub fn new(platform: Platform, model_hash: impl Into<String>) -> Self {
        Self {
            platform,
            model_hash: model_hash.into(),
            artifacts: Vec::new(),
            modules: Vec::new(),
            support_poms: BTreeMap::new(),
            model_inputs: None,
            repo_ids: None,
            host_inputs: None,
            plugins: None,
        }
    }

    /// A platform with a placeholder model hash and one module, `pom.xml`
    /// with `gav` and `packaging`, that declares each of `artifacts` with
    /// scope `compile`. A starting point for a lockfile built in memory;
    /// change the fields for anything else.
    pub fn single_module(
        platform: Platform,
        gav: Gav,
        packaging: impl Into<String>,
        artifacts: Vec<LockArtifact>,
    ) -> Self {
        let packages = artifacts
            .iter()
            .map(|artifact| {
                LockModulePackage::new(artifact.coordinate.clone(), Some(Scope::Compile))
            })
            .collect();
        let mut value = Self {
            platform,
            model_hash: PLACEHOLDER_MODEL_HASH.to_string(),
            artifacts,
            modules: vec![LockModule {
                path: "pom.xml".to_string(),
                gav,
                packaging: packaging.into(),
                packages,
                edges: Vec::new(),
                parent_ranges: Vec::new(),
                support_poms: Vec::new(),
                parents: Vec::new(),
                evicted_ranges: Vec::new(),
                extensions: Vec::new(),
                metadata_versions: Vec::new(),
                range_versions: Vec::new(),
            }],
            support_poms: BTreeMap::new(),
            model_inputs: None,
            repo_ids: None,
            host_inputs: None,
            plugins: None,
        };
        value.canonicalize();
        value
    }

    /// The origins of every module's evicted ranges and range versions.
    pub fn range_origins(&self) -> impl Iterator<Item = &str> {
        (self.modules.iter()).flat_map(|module| {
            (module
                .evicted_ranges
                .iter()
                .map(|range| range.origin.as_str()))
            .chain(
                module
                    .range_versions
                    .iter()
                    .map(|read| read.origin.as_str()),
            )
        })
    }

    /// Record profile ids and per-POM digests, then recompute `model_hash`.
    /// The lock computes the graph digests when it writes them.
    pub fn set_model_inputs(&mut self, profiles: &[String], pom_hashes: &BTreeMap<String, Sha256>) {
        self.model_hash = crate::inputs::model_records_hash(profiles, pom_hashes);
        self.model_inputs = Some(ModelInputs {
            profiles: profiles.to_vec(),
            pom_hashes: pom_hashes.clone(),
            ..ModelInputs::default()
        });
    }

    /// What this platform read: its own lists, or all of `repo_ids`, a
    /// lock's `[metadata] repo_ids`, and of the conditions and host values
    /// of `ambient`, its `[resolution] ambient_inputs`, where it lists none.
    pub fn reads(&self, repo_ids: &RepoIds, ambient: &BTreeSet<AmbientInput>) -> TargetReads {
        TargetReads {
            repo_ids: (self.repo_ids.clone()).unwrap_or_else(|| repo_ids.clone()),
            host_inputs: (self.host_inputs.clone()).unwrap_or_else(|| host_inputs(ambient)),
        }
    }

    /// Whether the graph digests read from a lock whose `config_hash`,
    /// Maven mode and `[metadata] repo_ids` are `config_hash`, `maven` and
    /// `repo_ids` match the rows and records this platform holds, and
    /// `ambient`, the lock's `[resolution] ambient_inputs`, lists every name
    /// a graph read, and a module read each support POM: false when they
    /// come from different resolutions, as after a merge of two branches
    /// that each changed a module's graph, its POM or the configuration. A
    /// platform with only a `model_hash` has no graph digests, so it never
    /// matches.
    pub fn graphs_match(
        &self,
        config_hash: Option<&str>,
        maven: MavenMode,
        ambient: &BTreeSet<AmbientInput>,
        repo_ids: &RepoIds,
    ) -> bool {
        let reads = self.reads(repo_ids, ambient);
        let read: HashSet<&String> = (self.modules.iter())
            .flat_map(|module| &module.support_poms)
            .chain(
                self.plugins
                    .iter()
                    .flat_map(|tables| &tables.sets)
                    .flat_map(|set| &set.poms),
            )
            .collect();
        (self.model_inputs.as_ref()).is_some_and(|inputs| {
            inputs.read_names().all(|name| ambient.contains(name))
                && self.support_poms.keys().all(|coord| read.contains(coord))
                && inputs.graphs
                    == crate::inputs::graph_digests(self, inputs, config_hash, maven, &reads)
        })
    }

    /// The first coordinate whose row here pins a different file than
    /// `other`'s row for it does ([`LockArtifact::conflicts_with`]), or other
    /// bytes than `other`'s row or build extension jar for the same
    /// local-repository file.
    pub(crate) fn conflicting_artifact_pin(&self, other: &LockPlatform) -> Option<String> {
        let theirs: HashMap<&ArtifactCoord, &LockArtifact> = other
            .artifacts
            .iter()
            .map(|artifact| (&artifact.coordinate, artifact))
            .collect();
        let mut their_files: HashMap<String, Vec<&LockArtifact>> = HashMap::new();
        for artifact in &other.artifacts {
            their_files
                .entry(artifact.repository_path())
                .or_default()
                .push(artifact);
        }
        self.artifacts
            .iter()
            .find(|artifact| {
                theirs
                    .get(&artifact.coordinate)
                    .is_some_and(|other| artifact.conflicts_with(other))
                    || their_files
                        .get(&artifact.repository_path())
                        .is_some_and(|rows| rows.iter().any(|other| artifact.bytes_differ(other)))
            })
            .map(|artifact| artifact.coordinate.to_string())
            .or_else(|| conflicting_extension_jar(&[self, other]))
    }

    fn canonicalize(&mut self) {
        self.modules
            .sort_by(|left, right| left.path.cmp(&right.path));
        for module in &mut self.modules {
            canonicalize_module(module);
        }
        self.artifacts
            .sort_by(|left, right| left.coordinate.cmp(&right.coordinate));
        for artifact in &mut self.artifacts {
            artifact.checksums.sort();
            artifact.checksums.dedup();
            // Relativizing project origins can reorder or merge them.
            let repo_url = &artifact.repo_url;
            artifact.other_repo_urls.retain(|origin| origin != repo_url);
            artifact.other_repo_urls.sort();
            artifact.other_repo_urls.dedup();
            artifact.pom_repo_urls.sort();
            artifact.pom_repo_urls.dedup();
            if artifact
                .pom_repo_urls
                .iter()
                .map(String::as_str)
                .eq(sorted(artifact.file_origins()))
            {
                artifact.pom_repo_urls.clear();
            }
        }
    }
}

/// One file a platform's resolution pinned, shared by every module that
/// uses it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockArtifact {
    /// The coordinate, with the `-SNAPSHOT` version of a snapshot build.
    /// raeva.lock calls the extension `packaging`.
    pub coordinate: ArtifactCoord,
    /// The origin of the repository that served the file: a
    /// project-relative token for a `file:` repository inside the project
    /// ([`LockOrigins`]), otherwise the URL as declared. Empty when no
    /// repository is recorded. Written as `repo_url`.
    pub repo_url: String,
    /// The origins, spelled as `repo_url` is, of the other repositories that
    /// served this file to a module, sorted. Maven records each in
    /// `_remote.repositories`. Written as `other_repo_urls` when not empty.
    pub other_repo_urls: Vec<String>,
    /// The file's digests, at most one per algorithm (`sha256`, `sha1`).
    /// Written as `checksums`, a sorted list of `algorithm` and `digest`
    /// pairs.
    pub checksums: Vec<Digest>,
    /// The deployed build a `SNAPSHOT` coordinate resolved to.
    pub snapshot: Option<SnapshotStamp>,
    /// The companion POM build, recorded only when it differs from `snapshot`.
    pub pom_snapshot: Option<SnapshotStamp>,
    /// Whether the companion POM is the base `-SNAPSHOT.pom` of a
    /// timestamped file: the snapshot metadata names a build for the file
    /// but none for the POM, so Maven reads the base file. Written as
    /// `pom_base` when true.
    pub pom_base: bool,
    /// SHA-256 of the companion `.pom` bytes `raeva sync` put in the content
    /// store for this coordinate. `None` when no repository has the POM, as
    /// for a jar deployed without one: Maven then resolves the artifact
    /// without dependency information, and no `.pom` is restored or
    /// exported.
    ///
    /// `checksums` pins the artifact payload; this pins the POM shipped
    /// beside it. The store's coordinate index maps a key to whichever blob
    /// was written last, so a later sync of another project sharing the store
    /// can repoint `(g, a, v, pom)` at different bytes. `raeva export-m2` fetches
    /// this digest from the content-addressed store directly, so an exported
    /// POM is always the one this lockfile was resolved against.
    pub pom_sha256: Option<Sha256>,
    /// The origins that served the companion POM to a module, spelled as
    /// `repo_url` is and sorted, when they are not the file's own: a
    /// SNAPSHOT POM resolves on its own, and a release POM may come from a
    /// repository that lacks the file. A frozen check takes the pinned POM
    /// only from these. Written as `pom_repo_urls` when not
    /// empty.
    pub pom_repo_urls: Vec<String>,
    /// Whether the file was accepted without a checksum file from its
    /// repository, under `--allow-missing-checksums`, and no download since
    /// verified it against one. Written as `missing_checksum` when true.
    pub missing_checksum: bool,
    /// [`Self::missing_checksum`] for the companion POM. Written as
    /// `pom_missing_checksum` when true.
    pub pom_missing_checksum: bool,
}

impl LockArtifact {
    /// A row for `coordinate` served by `repo_url`, with no checksum,
    /// snapshot build or POM pin yet.
    pub fn new(coordinate: ArtifactCoord, repo_url: impl Into<String>) -> Self {
        Self {
            coordinate,
            repo_url: repo_url.into(),
            other_repo_urls: Vec::new(),
            checksums: Vec::new(),
            snapshot: None,
            pom_snapshot: None,
            pom_base: false,
            pom_sha256: None,
            pom_repo_urls: Vec::new(),
            missing_checksum: false,
            pom_missing_checksum: false,
        }
    }

    /// `repo_url`, then `other_repo_urls`: the origins that served the file.
    pub fn file_origins(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.repo_url.as_str())
            .chain(self.other_repo_urls.iter().map(String::as_str))
    }

    /// The origins that served the companion POM: `pom_repo_urls`, or
    /// [`Self::file_origins`] when it is empty.
    pub fn pom_origins(&self) -> impl Iterator<Item = &str> {
        (self.file_origins())
            .filter(|_| self.pom_repo_urls.is_empty())
            .chain(self.pom_repo_urls.iter().map(String::as_str))
    }

    /// [`Self::file_origins`], then the `pom_repo_urls` they do not list.
    /// `other_repo_urls` is sorted, so each lookup is a binary search; on an
    /// unsorted list an origin can repeat, never go missing.
    pub fn origins(&self) -> impl Iterator<Item = &str> {
        let pom_only = (self.pom_repo_urls.iter())
            .filter(|origin| {
                **origin != self.repo_url && self.other_repo_urls.binary_search(origin).is_err()
            })
            .map(String::as_str);
        self.file_origins().chain(pom_only)
    }

    /// Each of [`Self::origins`] with the requested version, as the
    /// SNAPSHOT refresh checks take them.
    pub fn versioned_origins(&self) -> impl Iterator<Item = (&str, &str)> {
        let version = self.coordinate.version();
        self.origins().map(move |origin| (version, origin))
    }

    /// Whether `other`, a row for the same coordinate, names another file:
    /// another snapshot build, another [`LockArtifact::pin`], or another
    /// digest for an algorithm both rows record.
    pub(crate) fn conflicts_with(&self, other: &LockArtifact) -> bool {
        self.snapshot != other.snapshot || self.bytes_differ(other)
    }

    fn bytes_differ(&self, other: &LockArtifact) -> bool {
        self.pin() != other.pin()
            || self.checksums.iter().any(|mine| {
                other
                    .checksums
                    .iter()
                    .any(|theirs| theirs.algorithm() == mine.algorithm() && theirs != mine)
            })
    }

    /// Whether the row records the one SHA-256 a resolution writes, which
    /// a frozen check compares the checksums with.
    pub fn checksums_as_resolved(&self) -> bool {
        matches!(self.checksums.as_slice(), [Digest::Sha256(_)])
    }

    /// The checksum a download of this file is checked against: the
    /// SHA-256 when the row records one, otherwise its first checksum.
    pub fn pin(&self) -> Option<&Digest> {
        self.checksums
            .iter()
            .find(|checksum| checksum.algorithm() == HashAlgorithm::Sha256)
            .or_else(|| self.checksums.first())
    }

    /// The version in the file name: the timestamped build of a snapshot,
    /// otherwise the coordinate's version.
    pub fn file_version(&self) -> String {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.resolved_version(self.coordinate.version()))
            .unwrap_or_else(|| self.coordinate.version().to_string())
    }

    /// The version of the file's directory in a Maven repository: the
    /// `-SNAPSHOT` version of a timestamped file version, otherwise the file
    /// version.
    pub fn directory_version(&self) -> String {
        let file_version = self.file_version();
        rv_maven_types::snapshot_base_version(&file_version).unwrap_or(file_version)
    }

    /// Whether the row is a `SNAPSHOT`: it records a snapshot build or its
    /// file version is a snapshot version.
    pub fn is_snapshot(&self) -> bool {
        self.snapshot.is_some() || rv_maven_types::is_snapshot_version(&self.file_version())
    }

    /// The file this row names, with the timestamped version for a
    /// snapshot.
    pub fn coord(&self) -> ArtifactCoord {
        ArtifactCoord::of(
            Gav::new(
                self.coordinate.group_id(),
                self.coordinate.artifact_id(),
                &self.file_version(),
            ),
            self.coordinate.extension(),
            self.coordinate.classifier(),
        )
    }

    /// The companion POM's build: `None` for the base `-SNAPSHOT.pom`.
    pub fn pom_build(&self) -> Option<&SnapshotStamp> {
        if self.pom_base {
            None
        } else {
            self.pom_snapshot.as_ref().or(self.snapshot.as_ref())
        }
    }

    /// Whether the row is a POM that is its coordinate's companion POM.
    pub fn is_own_pom(&self) -> bool {
        self.coordinate.extension() == "pom" && self.coordinate.classifier().is_none()
    }

    /// The GAV of the companion POM the row's `pom_sha256` pins.
    pub fn pom_gav(&self) -> Gav {
        let version = self
            .pom_build()
            .and_then(|stamp| stamp.resolved_version(self.coordinate.version()))
            .unwrap_or_else(|| self.coordinate.version().to_string());
        Gav::new(
            self.coordinate.group_id(),
            self.coordinate.artifact_id(),
            &version,
        )
    }

    /// The row's file below a Maven repository root, as `export-m2` and
    /// `export-checksums` lay it out. Two coordinates can name one file:
    /// classifier `x.tar` with packaging `gz` and classifier `x` with
    /// packaging `tar.gz`, or a timestamped version and the `-SNAPSHOT`
    /// version resolved to that build.
    pub(crate) fn repository_path(&self) -> String {
        rv_maven_types::layout::artifact_path(
            &self.coord(),
            &self.directory_version(),
            &self.file_version(),
        )
    }

    /// The path below a Maven repository root of the companion POM.
    pub(crate) fn pom_path(&self) -> String {
        let version = self.pom_gav().version().to_string();
        rv_maven_types::layout::artifact_path(
            &self.coord().pom(),
            &self.directory_version(),
            &version,
        )
    }
}

/// One reactor module's graph on one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockModule {
    /// The module's `pom.xml`, relative to the directory that holds raeva.lock,
    /// with `/` separators. Written as `path`.
    pub path: String,
    /// The module's effective coordinates. Written as `gav`,
    /// `group:artifact:version`.
    pub gav: Gav,
    /// The module's `<packaging>`. Written as `packaging`.
    pub packaging: String,
    /// The nodes of the graph. Written as `packages`, one sorted line
    /// each; [`LockEdge`] refers to them by index.
    pub packages: Vec<LockModulePackage>,
    /// The dependencies between packages. Written as `edges`, one sorted
    /// line each.
    pub edges: Vec<LockEdge>,
    /// Remote parent range selections, scoped to each selected model this module built.
    pub parent_ranges: Vec<ParentRange>,
    /// The coordinates of every parent and BOM this module's resolution read,
    /// each a key of [`LockPlatform::support_poms`], sorted. The module's
    /// graph digest covers their pins ([`crate::inputs::graph_digests`]).
    /// Written as `support_poms`, one per line, omitted when empty.
    pub support_poms: Vec<String>,
    /// The parents of the module's lineage that came from a repository,
    /// nearest first, each one of [`Self::support_poms`]. Written as
    /// `parents`, one per line, omitted when empty.
    pub parents: Vec<String>,
    /// The version ranges this module's resolution listed whose highest
    /// listed version its graph does not hold, sorted. Written as
    /// `evicted_ranges`, one per line, omitted when empty.
    pub evicted_ranges: Vec<EvictedRange>,
    /// The build extensions whose artifact handlers this module's
    /// resolution read to type a dependency, sorted. Written as `extensions`, one
    /// per line, omitted when empty.
    pub extensions: Vec<ExtensionJar>,
    /// The versions this module's resolution took from repository metadata
    /// that the pins alone do not give `mvn -o`, sorted. Written as
    /// `metadata_versions`, one per line, omitted when empty.
    pub metadata_versions: Vec<MetadataVersion>,
    /// The version each range this module's graph holds took, by the
    /// repository whose list named it, sorted: what an export lists for
    /// `mvn -o`, where `evicted_ranges` gives the ranges that lost. Written
    /// as `range_versions`, one per line, omitted when empty.
    pub range_versions: Vec<RangeVersion>,
}

/// A version a range took from the version list of one repository. Written
/// as `group:artifact`, the version and the repository's origin, separated
/// by tabs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RangeVersion {
    /// The ranged dependency's groupId.
    pub group: String,
    /// The ranged dependency's artifactId.
    pub artifact: String,
    /// The version as the list spells it.
    pub version: String,
    /// The repository whose list named the version, spelled as `repo_url`
    /// is.
    pub origin: String,
}

/// The rules for a range version of `row`: a valid coordinate and an origin,
/// the empty one for a repository whose URL the lock cannot record.
pub(crate) fn check_range_version(read: &RangeVersion, row: &str) -> Result<(), LockError> {
    let invalid = || {
        LockError::Invalid(format!(
            "invalid range version {}:{}:{} of {row}",
            crate::error::printable(&read.group),
            crate::error::printable(&read.artifact),
            crate::error::printable(&read.version),
        ))
    };
    for (field, value) in [
        (CoordinateField::Group, read.group.as_str()),
        (CoordinateField::Artifact, read.artifact.as_str()),
        (CoordinateField::Version, read.version.as_str()),
    ] {
        validate_coordinate_component(field, value).map_err(|_| invalid())?;
    }
    rv_maven_types::Version::parse(&read.version).map_err(|_| invalid())?;
    check_origin_text(&read.origin, &|| format!("a range version of {row}"))
}

/// A version Maven took from repository metadata that the lock's pins
/// alone do not give `mvn -o`. Written as `group:artifact`, the kind and
/// the version, separated by tabs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetadataVersion {
    /// The artifact's groupId.
    pub group: String,
    /// The artifact's artifactId.
    pub artifact: String,
    /// What read it.
    pub kind: MetadataVersionKind,
    /// The version as the metadata spells it.
    pub version: String,
}

/// How a [`MetadataVersion`] was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetadataVersionKind {
    /// The version a `RELEASE`, or a plugin without a version, took. An
    /// export writes it as `<release>`.
    Release,
    /// The version a `LATEST` took, from `<latest>` or else `<release>`. An
    /// export writes it as `<latest>`.
    Latest,
    /// The spelling a range took among listed versions that compare equal,
    /// which the order of the whole listing decides.
    Range,
}

impl MetadataVersionKind {
    /// The name raeva.lock writes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Latest => "latest",
            Self::Range => "range",
        }
    }
}

impl std::str::FromStr for MetadataVersionKind {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, ()> {
        [Self::Release, Self::Latest, Self::Range]
            .into_iter()
            .find(|kind| kind.as_str() == text)
            .ok_or(())
    }
}

/// The jar of a build extension whose artifact handlers raeva read, which
/// the module's graph digest covers. Written as `group:artifact:version`,
/// then `:classifier` for a classified jar, and the jar's SHA-256,
/// separated by a tab.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtensionJar {
    /// The extension's coordinates.
    pub gav: Gav,
    /// The jar's classifier, which a jar of the extension's dependencies
    /// may have.
    pub classifier: Option<String>,
    /// The SHA-256 of its jar.
    pub sha256: Sha256,
}

impl ExtensionJar {
    /// The jar's coordinates.
    pub fn coord(&self) -> ArtifactCoord {
        ArtifactCoord::of(self.gav.clone(), "jar", self.classifier.as_deref())
    }
}

/// `group:artifact:version[:classifier]`.
impl std::fmt::Display for ExtensionJar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.gav)?;
        if let Some(classifier) = &self.classifier {
            write!(f, ":{classifier}")?;
        }
        Ok(())
    }
}

/// A version range a module's resolution listed whose highest version the
/// module's graph does not hold: a range that lost to a nearer declaration,
/// or one below a version that lost. Maven still reads the versions of such
/// a range, so a frozen check offers it the versions it listed when
/// raeva.lock was written, and an export lists one under the ids of the
/// repository that listed them. One line per range and repository, of
/// tab-separated columns: `group:artifact`, the range, the repository's
/// origin, and the versions its list offered, separated by spaces.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvictedRange {
    /// The ranged dependency's groupId.
    pub group: String,
    /// The ranged dependency's artifactId.
    pub artifact: String,
    /// The range as raeva writes a parsed range.
    pub range: String,
    /// The repository whose list named the versions, spelled as `repo_url`
    /// is.
    pub origin: String,
    /// The listed versions the range matched, lowest first in the lock's
    /// Maven order, two that compare equal by their text.
    pub versions: Vec<String>,
}

impl EvictedRange {
    /// `versions` sorted as raeva.lock writes them, in `mode`'s order.
    pub fn sort_versions(versions: &mut [String], mode: MavenMode) {
        versions.sort_by(|left, right| version_order(left, right, mode));
    }
}

fn version_order(left: &str, right: &str, mode: MavenMode) -> std::cmp::Ordering {
    let parse = |text| rv_maven_types::Version::parse(text).ok();
    match (parse(left), parse(right)) {
        (Some(a), Some(b)) => a.cmp_in(&b, mode).then_with(|| left.cmp(right)),
        _ => left.cmp(right),
    }
}

/// The rules for an evicted range of `row`: valid coordinates, a range as
/// raeva writes one, and versions it matches, sorted, each once.
fn check_evicted_range(range: &EvictedRange, mode: MavenMode, row: &str) -> Result<(), LockError> {
    let invalid = |what: &str| {
        LockError::Invalid(format!(
            "invalid evicted range {}:{} {:?} of {row}: {what}",
            crate::error::printable(&range.group),
            crate::error::printable(&range.artifact),
            crate::error::printable(&range.range),
        ))
    };
    for (field, value) in [
        (CoordinateField::Group, range.group.as_str()),
        (CoordinateField::Artifact, range.artifact.as_str()),
    ] {
        validate_coordinate_component(field, value).map_err(|_| invalid("not a coordinate"))?;
    }
    let req = rv_maven_types::VersionReq::parse_in(&range.range, mode)
        .ok()
        .filter(|req| matches!(req, rv_maven_types::VersionReq::Ranges(_)))
        .filter(|req| req.to_string() == range.range)
        .ok_or_else(|| invalid("not a range as raeva writes it"))?;
    if range.versions.is_empty() {
        return Err(invalid("it lists no version"));
    }
    for version in &range.versions {
        validate_coordinate_component(CoordinateField::Version, version)
            .ok()
            .and_then(|()| rv_maven_types::Version::parse(version).ok())
            .filter(|parsed| req.matches_in(parsed, mode))
            .ok_or_else(|| invalid("a version is not one the range matches"))?;
    }
    if !(range.versions.windows(2)).all(|pair| version_order(&pair[0], &pair[1], mode).is_lt()) {
        return Err(invalid("the versions must be sorted, each once"));
    }
    check_origin_text(&range.origin, &|| format!("an evicted range of {row}"))
}

/// One remote parent range selected while building a model's parent lineage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentRange {
    /// The model's locked coordinates, using the SNAPSHOT base version.
    pub model: String,
    /// The declared parent coordinates, with the range as version.
    pub parent: String,
    /// The selected parent coordinates, before SNAPSHOT file expansion.
    pub selected: String,
}

/// A node of a module's graph: an external artifact (which has an artifact
/// row), another reactor module, or a system-scoped file. Rows sort by their
/// fields in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct LockModulePackage {
    /// The node's coordinate. Written as the line's first two columns,
    /// `group:artifact:version` and `packaging[:classifier]`.
    pub coordinate: ArtifactCoord,
    /// For another reactor module, its POM path, which names a
    /// [`LockModule`] of the same platform. Written as the fifth column.
    pub workspace_module: Option<String>,
    /// For a system-scoped file, its path relative to the directory that
    /// holds raeva.lock ([`crate::SystemFile`]). Set together with
    /// `system_sha256`.
    pub system_path: Option<String>,
    /// For a system-scoped file, the SHA-256 of its bytes.
    pub system_sha256: Option<Sha256>,
    /// The scope the module declares the node with, `None` for a node it
    /// reaches only through another package. Written as the third column.
    pub direct_scope: Option<Scope>,
    /// The scope the node resolves to, as Maven's JavaScopeSelector picks it.
    /// Written as the fourth column, left empty when it is the direct scope
    /// or, for a node reached only through another package, compile.
    pub scope: Scope,
    /// Where the module's dependency management declares the version it
    /// supplied, when it did: a POM of the module's lineage or a BOM it
    /// imports, and the property the version is written as. Written in the
    /// module's `managed` lines, which name the package by its index.
    pub managed: Option<std::sync::Arc<rv_maven_types::ManagedSource>>,
}

impl LockModule {
    /// Whether `gav` names the module's own artifacts, which its graph
    /// takes from a repository: its coordinates, or a build of its
    /// `SNAPSHOT` Maven reads as a release, `1.020240101.010101-1` of
    /// `1.0SNAPSHOT`.
    pub fn owns(&self, gav: &Gav) -> bool {
        gav.group == self.gav.group
            && gav.artifact == self.gav.artifact
            && (gav.version() == self.gav.version()
                || SnapshotStamp::of_file_version(self.gav.version(), gav.version()).is_some())
    }

    /// The module at `path` (its `pom.xml`, relative to the lockfile's
    /// directory) with no packages or edges yet.
    pub fn new(path: impl Into<String>, gav: Gav, packaging: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            gav,
            packaging: packaging.into(),
            packages: Vec::new(),
            edges: Vec::new(),
            parent_ranges: Vec::new(),
            support_poms: Vec::new(),
            parents: Vec::new(),
            evicted_ranges: Vec::new(),
            extensions: Vec::new(),
            metadata_versions: Vec::new(),
            range_versions: Vec::new(),
        }
    }
}

impl LockModulePackage {
    /// A package for `coordinate` that the module declares with
    /// `direct_scope`, or reaches through another package when it is `None`,
    /// resolving to that scope or compile.
    pub fn new(coordinate: ArtifactCoord, direct_scope: Option<Scope>) -> Self {
        Self {
            coordinate,
            direct_scope,
            scope: direct_scope.unwrap_or(Scope::Compile),
            workspace_module: None,
            system_path: None,
            system_sha256: None,
            managed: None,
        }
    }

    /// Where the package comes from.
    pub fn source(&self) -> PackageSource<'_> {
        match (&self.workspace_module, &self.system_path) {
            (Some(path), _) => PackageSource::Module(path),
            (None, Some(path)) => PackageSource::System(path),
            (None, None) => PackageSource::Repository,
        }
    }

    /// The coordinate of the artifact row the package reads, when it comes
    /// from a repository.
    pub fn repository_file(&self) -> Option<&ArtifactCoord> {
        matches!(self.source(), PackageSource::Repository).then_some(&self.coordinate)
    }
}

/// Where a module's package comes from. One coordinate may name a package
/// of each source in one lock: a module that takes its own jar from a
/// repository reads a file of the coordinates other modules build it as,
/// and a build extension may read that file too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageSource<'a> {
    /// A file from a repository, which the artifact row of its coordinate
    /// pins.
    Repository,
    /// Another reactor module, by its POM path.
    Module(&'a str),
    /// A system-scoped file, by its path.
    System(&'a str),
}

fn sorted<'a>(items: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut items: Vec<&str> = items.collect();
    items.sort_unstable();
    items.dedup();
    items
}

/// Whether [`canonicalize_module`] would leave `module` as it is.
pub(crate) fn is_canonical_module(module: &LockModule) -> bool {
    module.packages.is_sorted()
        && module.edges.is_sorted()
        && module.parent_ranges.is_sorted()
        && (module.support_poms).is_sorted_by(|left, right| left < right)
        && (module.evicted_ranges).is_sorted_by(|left, right| {
            (&left.group, &left.artifact, &left.range, &left.origin)
                < (&right.group, &right.artifact, &right.range, &right.origin)
        })
        && (module.extensions).is_sorted_by(|left, right| left < right)
        && (module.metadata_versions).is_sorted_by(|left, right| left < right)
        && (module.range_versions).is_sorted_by(|left, right| left < right)
}

pub(crate) fn canonicalize_module(module: &mut LockModule) {
    let mut indexed: Vec<(usize, LockModulePackage)> = std::mem::take(&mut module.packages)
        .into_iter()
        .enumerate()
        .collect();
    indexed.sort_by(|(_, left), (_, right)| left.cmp(right));
    let mut remap = vec![0; indexed.len()];
    for (new_index, (old_index, _)) in indexed.iter().enumerate() {
        remap[*old_index] = new_index;
    }
    module.packages = indexed.into_iter().map(|(_, package)| package).collect();
    for edge in &mut module.edges {
        edge.from = remap.get(edge.from).copied().unwrap_or(edge.from);
        edge.to = remap.get(edge.to).copied().unwrap_or(edge.to);
    }
    module.edges.sort();
    module.parent_ranges.sort();
    module.support_poms.sort();
    module.support_poms.dedup();
    module.evicted_ranges.sort();
    module.extensions.sort();
    module.extensions.dedup();
    module.metadata_versions.sort();
    module.metadata_versions.dedup();
    module.range_versions.sort();
    module.range_versions.dedup();
}

/// A dependency edge between two packages of one module, by index. Edges
/// sort by their fields in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct LockEdge {
    /// Index of the depending package in [`LockModule::packages`], the
    /// line's first field.
    pub from: usize,
    /// Index of the package depended on, the second field.
    pub to: usize,
    /// The scope the dependency has below `from`: the scope management
    /// gives it, else the one Maven's JavaScopeDeriver derives from its
    /// declared scope and the scope `from` resolves to
    /// ([`LockModulePackage::scope`]). Written next.
    pub scope: Scope,
    /// Whether the dependency is optional. Written last as `optional`, and
    /// read as `false` when absent.
    pub optional: bool,
}

impl LockEdge {
    /// An edge from package `from` to package `to`, both indexes into the
    /// module's packages, with the scope and optional flag the dependency
    /// has below `from`.
    pub fn new(from: usize, to: usize, scope: Scope, optional: bool) -> Self {
        Self {
            from,
            to,
            scope,
            optional,
        }
    }
}

/// A file build raeva.lock pins under its `-SNAPSHOT` GAV, from
/// [`Lockfile::pinned_snapshots`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PinnedSnapshot {
    /// The file's build, or `None` for a plain `-SNAPSHOT` file.
    pub build: Option<SnapshotStamp>,
    /// The build of the file's companion POM, or `None` for the base
    /// `-SNAPSHOT.pom`.
    pub pom: Option<SnapshotStamp>,
    /// The origins the lock records for the file.
    pub file_origins: Vec<String>,
    /// The origins the lock records for the companion POM.
    pub pom_origins: Vec<String>,
    /// The file's extension and classifier, or `None` for a support POM.
    pub file: Option<(String, Option<String>)>,
}

/// The pin of one support POM.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SupportPom {
    /// The origin of the repository that served the POM, spelled as an
    /// artifact row's `repo_url` is. Written as `repo_url`.
    pub repo_url: String,
    /// SHA-256 of the exact bytes. Written as `sha256`.
    pub sha256: Sha256,
    /// The deployed build a `SNAPSHOT` version resolved to. Written as
    /// `snapshot`, omitted when `None`.
    pub snapshot: Option<SnapshotStamp>,
    /// Whether the POM was accepted without a checksum file, as
    /// [`LockArtifact::missing_checksum`] says of a file. Written as
    /// `missing_checksum` when true.
    pub missing_checksum: bool,
}

impl SupportPom {
    /// The pin of a support POM served by the repository `repo_url`.
    pub fn new(repo_url: impl Into<String>, sha256: Sha256) -> Self {
        Self {
            repo_url: repo_url.into(),
            sha256,
            snapshot: None,
            missing_checksum: false,
        }
    }

    /// The GAV of the file this pin names for the support POM `coord`, with
    /// the timestamped version of a snapshot build. `None` when `coord` is
    /// not `group:artifact:version` or the build is not one of its version.
    pub fn file_gav(&self, coord: &str) -> Option<Gav> {
        let (group, artifact, version) = split_support_pom_coord(coord)?;
        let file_version = match &self.snapshot {
            Some(stamp) => stamp.resolved_version(version)?,
            None => version.to_string(),
        };
        Some(Gav::new(group, artifact, &file_version))
    }

    /// The file below a Maven repository root this pin names for `coord`.
    pub(crate) fn repository_path(&self, coord: &str) -> Option<String> {
        let gav = self.file_gav(coord)?;
        let file = gav.version();
        let dir = rv_maven_types::snapshot_base_version(file).unwrap_or_else(|| file.to_string());
        Some(rv_maven_types::layout::artifact_path_from_parts(
            &gav.group,
            &gav.artifact,
            &dir,
            file,
            "pom",
            None,
        ))
    }
}

/// `group:artifact:version` of a reactor module, whose version may hold `:`.
pub(crate) fn split_reactor_gav(gav: &str) -> Option<(&str, &str, &str)> {
    let mut parts = gav.splitn(3, ':');
    let (group, artifact, version) = (parts.next()?, parts.next()?, parts.next()?);
    (!group.is_empty() && !artifact.is_empty() && !version.is_empty())
        .then_some((group, artifact, version))
}

/// Split a support-POM coordinate into group, artifact and version. `None`
/// unless it has exactly three non-empty `:`-separated parts, which is every
/// key [`Lockfile::support_poms`] returns: the codec refuses any other on the
/// way in and out of the lockfile.
pub fn split_support_pom_coord(coord: &str) -> Option<(&str, &str, &str)> {
    let mut parts = coord.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(group), Some(artifact), Some(version), None)
            if !group.is_empty() && !artifact.is_empty() && !version.is_empty() =>
        {
            Some((group, artifact, version))
        }
        _ => None,
    }
}

pub(crate) fn validate_support_pom_coord(coord: &str) -> Result<(), LockError> {
    let Some((group, artifact, version)) = split_support_pom_coord(coord) else {
        return Err(LockError::Invalid(format!(
            "support POM coordinate {coord:?} must be 'group:artifact:version'"
        )));
    };
    for (field, value) in [
        (CoordinateField::Group, group),
        (CoordinateField::Artifact, artifact),
        (CoordinateField::Version, version),
    ] {
        validate_coordinate_component(field, value).map_err(|err| {
            LockError::Invalid(format!("invalid support POM coordinate {coord:?}: {err}"))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use rv_maven_types::ArtifactCoord;

    use super::{
        EnvValueHit, EvictedRange, LockArtifact, LockModulePackage, Lockfile, MetadataVersion,
        MetadataVersionKind, Scope, SupportPom,
    };
    use crate::error::LockError;
    use crate::platform::Platform;
    use crate::plugins::{PluginFiles, PluginPrefix, PluginRole, PluginSet, PluginTables};
    use crate::test_lock::{lock, locked_platform, package, platform};

    /// Each coordinate, path and repository URL field raeva.lock records is
    /// scanned: a field that holds an allowlisted variable's value is
    /// reported by field and row, with the value masked, and the warning
    /// never shows it. A value shorter than 4 bytes would match version
    /// numbers and is skipped.
    #[test]
    fn env_values_are_found_in_every_field_that_records_them() {
        const LEAK: &str = "leaked-v4lue";
        let url = format!("https://repo.example/{LEAK}/");
        let values = BTreeMap::from([
            ("RAEVA_TOKEN".to_string(), LEAK.to_string()),
            ("RAEVA_SHORT".to_string(), "com".to_string()),
        ]);
        let linux = platform("linux-x86_64");
        let base = || {
            lock(vec![locked_platform(
                "linux-x86_64",
                vec![package("demo", "1.0", 'a')],
                'b',
            )])
        };
        let demo = "com.example:demo:1.0:jar";
        let sha = || "d".repeat(64).parse().expect("digest");
        let tables = |edit: &dyn Fn(&mut PluginTables)| {
            let mut tables = PluginFiles::new(sha()).tables;
            edit(&mut tables);
            tables
        };
        type Edit<'e> = Box<dyn Fn(&mut Lockfile) + 'e>;
        let cases: Vec<(&str, &str, Option<&Platform>, Edit<'_>)> = vec![
            (
                "artifact_id",
                "com.example:***:1.0:jar",
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].artifacts[0] = package(LEAK, "1.0", 'a');
                }),
            ),
            (
                "system_path",
                "org.example:tool:1.0.0:jar",
                Some(&linux),
                Box::new(|lock| {
                    let tool = ArtifactCoord::new("org.example", "tool", "1.0.0", "jar", None);
                    let mut system = LockModulePackage::new(tool, Some(Scope::System));
                    system.system_path = Some(format!("{LEAK}/tool.jar"));
                    lock.platforms[0].modules[0].packages.push(system);
                }),
            ),
            (
                "repo_url",
                demo,
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].artifacts[0].repo_url = url.clone();
                }),
            ),
            (
                "other_repo_urls",
                demo,
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].artifacts[0].other_repo_urls = vec![url.clone()];
                }),
            ),
            (
                "pom_repo_urls",
                demo,
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].artifacts[0].pom_repo_urls = vec![url.clone()];
                }),
            ),
            (
                "repo_url",
                "support POM com.example:parent:1",
                Some(&linux),
                Box::new(|lock| {
                    let pin = SupportPom::new(url.clone(), sha());
                    lock.platforms[0]
                        .support_poms
                        .insert("com.example:parent:1".to_string(), pin);
                }),
            ),
            (
                "artifact_id",
                "support POM com.example:***-bom:1",
                Some(&linux),
                Box::new(|lock| {
                    let pin = SupportPom::new("https://repo.example/", sha());
                    let key = format!("com.example:{LEAK}-bom:1");
                    lock.platforms[0].support_poms.insert(key, pin);
                }),
            ),
            (
                "origin",
                "evicted range com.example:lib [2,3) of pom.xml",
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].modules[0]
                        .evicted_ranges
                        .push(EvictedRange {
                            group: "com.example".to_string(),
                            artifact: "lib".to_string(),
                            range: "[2,3)".to_string(),
                            origin: url.clone(),
                            versions: vec!["2.0".to_string()],
                        });
                }),
            ),
            (
                "origin",
                "metadata.repo_ids",
                None,
                Box::new(|lock| {
                    lock.repo_ids
                        .insert(url.clone(), BTreeSet::from(["corp".to_string()]));
                }),
            ),
            (
                "repo_urls",
                "plugin set sha256:p",
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].plugins = Some(tables(&|tables| {
                        let mut set = PluginSet::new("sha256:p", PluginRole::Plugin);
                        set.repo_urls = vec![url.clone()];
                        tables.sets.push(set);
                    }));
                }),
            ),
            (
                "repo_url",
                "the prefix list of plugin group org.example",
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].plugins = Some(tables(&|tables| {
                        let prefix =
                            PluginPrefix::new("org.example", &url, "demo", "demo-maven-plugin");
                        tables.prefixes.push(prefix);
                    }));
                }),
            ),
            (
                "artifact_id",
                "metadata_versions of pom.xml",
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].modules[0]
                        .metadata_versions
                        .push(MetadataVersion {
                            group: "com.example".to_string(),
                            artifact: LEAK.to_string(),
                            kind: MetadataVersionKind::Release,
                            version: "1.0".to_string(),
                        });
                }),
            ),
            (
                "group_id",
                "the metadata_versions of the plugin tables",
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].plugins = Some(tables(&|tables| {
                        tables.metadata_versions.push(MetadataVersion {
                            group: LEAK.to_string(),
                            artifact: "demo-maven-plugin".to_string(),
                            kind: MetadataVersionKind::Release,
                            version: "1.0".to_string(),
                        });
                    }));
                }),
            ),
            (
                "origin",
                "plugins.repo_ids",
                Some(&linux),
                Box::new(|lock| {
                    lock.platforms[0].plugins = Some(tables(&|tables| {
                        tables
                            .repo_ids
                            .insert(url.clone(), BTreeSet::from(["corp".to_string()]));
                    }));
                }),
            ),
        ];
        assert_eq!(base().env_value_hits(&values), []);
        for (field, row, platform, edit) in cases {
            let mut lock = base();
            edit(&mut lock);
            let hit = EnvValueHit {
                env_var: "RAEVA_TOKEN",
                field,
                row: row.to_string(),
                platform,
            };
            assert_eq!(lock.env_value_hits(&values), [hit], "{field} of {row}");
            let log = rv_test_support::capture_warnings(|| lock.warn_on_env_values(&values));
            assert!(
                log.contains("ENV_VALUE_IN_LOCKFILE") && !log.contains(LEAK),
                "{log}"
            );
        }
    }

    /// One map holds every pin: SHA-256 where any row has one, else the
    /// SHA-1 a row pins.
    #[test]
    fn pinned_paths_hold_sha1_pins_under_sha256_ones() {
        let sha1 = |digest: char| {
            rv_maven_types::Digest::parse("sha1", &digest.to_string().repeat(40)).expect("sha1")
        };
        let mut shared = package("shared", "1.0", 'a');
        shared.checksums.push(sha1('d'));
        let mut only = package("only", "1.0", 'a');
        only.checksums = vec![sha1('e')];
        let mut weak = package("shared", "1.0", 'a');
        weak.checksums = vec![sha1('f')];
        let lock = lock(vec![
            locked_platform("linux-x86_64", vec![shared, only], 'b'),
            locked_platform("macos-aarch64", vec![weak], 'b'),
        ]);
        let pins = lock.pinned_paths();
        let pin = |path: &str| pins.get(path).map(|(pin, _)| pin.clone());
        let sha256 = |digest: char| {
            rv_maven_types::Digest::parse("sha256", &digest.to_string().repeat(64)).expect("sha256")
        };
        assert_eq!(
            pin("com/example/shared/1.0/shared-1.0.jar"),
            Some(sha256('a'))
        );
        assert_eq!(pin("com/example/only/1.0/only-1.0.jar"), Some(sha1('e')));
        assert_eq!(pin("com/example/only/1.0/only-1.0.pom"), Some(sha256('b')));
    }

    /// A release build extension's jar is pinned; a lock lists each
    /// extension of a module once.
    #[test]
    fn build_extension_jars_are_pinned_once() {
        let jar = |artifact: &str, version: &str, digest: char| super::ExtensionJar {
            gav: rv_maven_types::Gav::new("t", artifact, version),
            classifier: None,
            sha256: digest.to_string().repeat(64).parse().unwrap(),
        };
        let mut entry = locked_platform("linux-x86_64", vec![package("demo", "1.0", 'a')], 'b');
        entry.modules[0].extensions = vec![jar("ext", "1", 'c'), jar("snap", "1-SNAPSHOT", 'd')];
        let pins = lock(vec![entry.clone()]).pinned_paths();
        assert!(pins.contains_key("t/ext/1/ext-1.jar"));
        assert!(!pins.keys().any(|path| path.contains("snap")));
        lock(vec![entry.clone()]).check().unwrap();
        let mut other = entry.clone();
        other.platform = "macos-aarch64".parse().unwrap();
        other.modules[0].extensions = vec![jar("ext", "1", 'e')];
        assert!(
            lock(vec![entry.clone(), other]).check().is_err(),
            "another platform's jar"
        );
        let mut row = package("ext", "1", 'e');
        row.coordinate = rv_maven_types::ArtifactCoord::new("t", "ext", "1", "jar", None);
        row.pom_sha256 = entry.artifacts[0].pom_sha256.clone();
        let mut rows = entry.clone();
        rows.artifacts.push(row);
        assert!(lock(vec![rows]).check().is_err(), "a row of the jar");
        entry.modules[0].extensions = vec![jar("ext", "1", 'c'), jar("ext", "1", 'e')];
        assert!(lock(vec![entry]).check().is_err());
    }

    /// A classified jar of an extension's realm is pinned at its own path
    /// and written with its classifier after the jar of the same version
    /// without one; a line with an empty or invalid classifier, or a jar
    /// listed twice, is refused.
    #[test]
    fn classified_extension_jars_round_trip() {
        let jar = |classifier: Option<&str>, digest: char| super::ExtensionJar {
            gav: rv_maven_types::Gav::new("t", "guice", "4"),
            classifier: classifier.map(str::to_string),
            sha256: digest.to_string().repeat(64).parse().unwrap(),
        };
        let mut entry = locked_platform("linux-x86_64", vec![package("demo", "1.0", 'a')], 'b');
        entry.modules[0].extensions = vec![jar(None, 'c'), jar(Some("no_aop"), 'd')];
        let pins = lock(vec![entry.clone()]).pinned_paths();
        assert!(pins.contains_key("t/guice/4/guice-4.jar"));
        assert!(pins.contains_key("t/guice/4/guice-4-no_aop.jar"));
        let toml = lock(vec![entry.clone()]).to_toml().unwrap();
        let (c, d) = ("c".repeat(64), "d".repeat(64));
        let written = format!("t:guice:4\\t{c}\nt:guice:4:no_aop\\t{d}");
        assert!(toml.contains(&written), "{toml}");
        let decoded = Lockfile::from_toml(&toml).unwrap();
        assert_eq!(
            decoded.platforms[0].modules[0].extensions,
            entry.modules[0].extensions
        );
        for edited in [
            format!("t:guice:4:no_aop\\t{d}\nt:guice:4\\t{c}"),
            format!("t:guice:4\\t{c}\nt:guice:4:\\t{d}"),
            format!("t:guice:4\\t{c}\nt:guice:4:no/aop\\t{d}"),
            format!("t:guice:4\\t{c}\nt:guice:4:no_aop:x\\t{d}"),
            format!("t:guice:4:no_aop\\t{c}\nt:guice:4:no_aop\\t{d}"),
        ] {
            let toml = toml.replace(&written, &edited);
            assert!(Lockfile::from_toml(&toml).is_err(), "{edited}");
        }
    }

    /// A module's metadata versions round-trip, and a line raeva would not
    /// write, out of order or of another kind, is refused.
    #[test]
    fn metadata_versions_round_trip_sorted() {
        let read = |artifact: &str, kind, version: &str| super::MetadataVersion {
            group: "t".to_string(),
            artifact: artifact.to_string(),
            kind,
            version: version.to_string(),
        };
        let mut entry = locked_platform("linux-x86_64", vec![package("demo", "1.0", 'a')], 'b');
        entry.modules[0].metadata_versions = vec![
            read("lib", super::MetadataVersionKind::Release, "1.0"),
            read("lib", super::MetadataVersionKind::Latest, "2-SNAPSHOT"),
        ];
        let toml = lock(vec![entry.clone()]).to_toml().unwrap();
        let written = "t:lib\\trelease\\t1.0\nt:lib\\tlatest\\t2-SNAPSHOT";
        assert!(toml.contains(written), "{toml}");
        let decoded = Lockfile::from_toml(&toml).unwrap();
        assert_eq!(decoded.platforms[0].modules[0].metadata_versions.len(), 2);
        for edited in [
            "t:lib\\tlatest\\t2-SNAPSHOT\nt:lib\\trelease\\t1.0",
            "t:lib\\tRELEASE\\t1.0",
            "t:lib\\trelease\\t1.0\nt:lib\\trelease\\t1.0",
            "t:lib\\trelease\\t../1",
        ] {
            let toml = toml.replace(written, edited);
            assert!(Lockfile::from_toml(&toml).is_err(), "{edited}");
        }
    }

    /// A module's range versions round-trip, also with the empty origin, and
    /// a line raeva would not write, out of order, twice, or with an origin
    /// that may hold a credential, is refused.
    #[test]
    fn range_versions_round_trip_sorted() {
        let read = |version: &str, origin: &str| super::RangeVersion {
            group: "t".to_string(),
            artifact: "lib".to_string(),
            version: version.to_string(),
            origin: origin.to_string(),
        };
        let mut entry = locked_platform("linux-x86_64", vec![package("demo", "1.0", 'a')], 'b');
        entry.modules[0].range_versions = vec![
            read("2", "https://b.example/"),
            read("1-SNAPSHOT", "https://a.example/"),
        ];
        let toml = lock(vec![entry.clone()]).to_toml().unwrap();
        let written = "t:lib\\t1-SNAPSHOT\\thttps://a.example/\nt:lib\\t2\\thttps://b.example/";
        assert!(toml.contains(written), "{toml}");
        let decoded = Lockfile::from_toml(&toml).unwrap();
        assert_eq!(decoded.platforms[0].modules[0].range_versions.len(), 2);
        for edited in [
            "t:lib\\t2\\thttps://b.example/\nt:lib\\t1-SNAPSHOT\\thttps://a.example/",
            "t:lib\\t2\\thttps://b.example/\nt:lib\\t2\\thttps://b.example/",
            "t:lib\\t2",
            "t:lib\\t../2\\thttps://b.example/",
            "t:lib\\t2\\thttps://user:secret@b.example/",
        ] {
            let toml = toml.replace(written, edited);
            assert!(Lockfile::from_toml(&toml).is_err(), "{edited}");
        }
        // The empty origin names a mirrored repository the lock cannot record.
        let toml = toml.replace(written, "t:lib\\t2\\t");
        let decoded = Lockfile::from_toml(&toml).unwrap();
        assert_eq!(
            decoded.platforms[0].modules[0].range_versions,
            [read("2", "")]
        );
    }

    #[test]
    fn an_oversized_lockfile_is_refused_after_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raeva.lock");
        std::fs::write(&path, "schema_version = 5\n").unwrap();
        let err = Lockfile::read_with_limit(&path, 4).unwrap_err();
        let message = err.to_string();
        match err {
            LockError::TooLarge { size, limit, .. } => {
                assert_eq!(limit, 4);
                assert!(size > 4, "size={size}");
            }
            other => panic!("expected TooLarge, got {other}"),
        }
        assert!(message.contains("exceeds the 4 byte limit"), "{message}");
    }

    #[test]
    fn jdk_sections_round_trip_and_reject_duplicates_or_mixing() {
        let mut jdk17 = locked_platform("linux-x86_64", vec![package("demo", "1.0", 'a')], 'b');
        jdk17.platform = jdk17.platform.with_jdk("17");
        let mut jdk21 = locked_platform("linux-x86_64", vec![package("demo", "1.0", 'a')], 'b');
        jdk21.platform = jdk21.platform.with_jdk("21");

        jdk17.set_model_inputs(
            &["jdk17".to_string()],
            &BTreeMap::from([("pom.xml".to_string(), "a".repeat(64).parse().unwrap())]),
        );
        jdk21.set_model_inputs(
            &["jdk21".to_string()],
            &BTreeMap::from([("pom.xml".to_string(), "b".repeat(64).parse().unwrap())]),
        );
        let lockfile = lock(vec![jdk17.clone(), jdk21.clone()]);
        let toml = lockfile.to_toml().unwrap();
        assert_eq!(toml.matches("[[platforms]]").count(), 1, "{toml}");
        assert_eq!(toml.matches("[[inputs]]").count(), 2, "{toml}");
        assert!(!toml.contains("model_hash"), "{toml}");
        assert!(toml.contains("linux-x86_64@17"), "{toml}");
        assert!(toml.contains("linux-x86_64@21"), "{toml}");
        let decoded = Lockfile::from_toml(&toml).unwrap();
        assert_eq!(decoded, lockfile.canonical().unwrap());

        // The Maven mode is written once, and only when it is not 3.9.
        assert!(!toml.contains("maven ="), "{toml}");
        let mut maven310 = lockfile.clone();
        maven310.maven = rv_maven_types::MavenMode::Maven310;
        let toml310 = maven310.to_toml().unwrap();
        assert_eq!(
            toml310.matches("\nmaven = \"3.10\"\n").count(),
            1,
            "{toml310}"
        );
        let decoded = Lockfile::from_toml(&toml310).unwrap();
        assert_eq!(decoded, maven310.canonical().unwrap());
        assert_ne!(
            decoded.platforms[0].model_inputs,
            lockfile.canonical().unwrap().platforms[0].model_inputs
        );

        // Duplicate (platform, jdk) is rejected.
        let dup_err = lock(vec![jdk17.clone(), jdk17.clone()])
            .to_toml()
            .unwrap_err()
            .to_string();
        assert!(
            dup_err.contains("duplicate platform 'linux-x86_64 (JDK 17)'"),
            "{dup_err}"
        );

        // Mixing sections with and without jdk is rejected.
        let plain = locked_platform("darwin-aarch64", vec![package("demo", "1.0", 'a')], 'b');
        let mix_err = lock(vec![jdk17, plain]).to_toml().unwrap_err().to_string();
        assert!(
            mix_err.contains("mixes platform sections with and without jdk"),
            "{mix_err}"
        );

        // Invalid jdk in TOML is rejected on decode.
        let bad_toml = toml.replace("linux-x86_64@21", "linux-x86_64@[21,)");
        let bad_err = Lockfile::from_toml(&bad_toml).unwrap_err().to_string();
        assert!(bad_err.contains("invalid jdk"), "{bad_err}");
    }

    /// Long disjoint file and POM origin lists cost a binary search per POM
    /// origin, not a scan of the file origins.
    #[test]
    fn origins_of_long_disjoint_lists_are_each_listed_once() {
        let mut artifact = LockArtifact::new(
            ArtifactCoord::new("org.test", "snap", "1.0-SNAPSHOT", "jar", None),
            "https://a.example/",
        );
        let urls = |prefix: &str| -> Vec<String> {
            (0..50_000)
                .map(|n| format!("https://{prefix}{n:05}.example/"))
                .collect()
        };
        artifact.other_repo_urls = urls("f");
        artifact.pom_repo_urls = urls("p");
        artifact
            .pom_repo_urls
            .push("https://a.example/".to_string());
        artifact
            .pom_repo_urls
            .push("https://f00007.example/".to_string());
        assert_eq!(artifact.origins().count(), 100_001);
    }
}
