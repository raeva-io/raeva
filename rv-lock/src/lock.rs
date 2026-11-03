use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;

use rv_fs::{NewFileAccess, write_file_atomic};
use rv_maven_types::{
    ArtifactCoord, CoordinateField, Digest, Gav, HashAlgorithm, Sha256, SnapshotStamp,
    is_snapshot_version, is_terminal_safe, validate_coordinate_component, validate_reactor_version,
};

use crate::ambient::AmbientInput;
use crate::codec::{self, is_sha256_hex};
use crate::error::LockError;
use crate::lock_origin::{
    LockOrigins, encode_repo_id_lines, is_project_relative_origin, record_repo_ids, redact_origin,
    validate_project_relative_origin,
};
use crate::platform::Platform;
use crate::scope::Scope;

/// The only schema this build reads and writes. A lock of any other schema
/// is refused, and a plain `raeva sync` regenerates it.
pub const LOCKFILE_SCHEMA_VERSION: u32 = 8;

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
    /// covers their values, so `--frozen` reads the same names again and
    /// compares the hash without resolving.
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
    /// a Maven repository root: every artifact row, its companion POM and
    /// every support POM. With it, the origins the lockfile records as
    /// serving the file, spelled as `repo_url` is. A file a row pins only by
    /// SHA-1 is held to that, unless another row pins it by SHA-256.
    pub fn pinned_paths(&self) -> HashMap<String, (Digest, BTreeSet<String>)> {
        let mut files: HashMap<String, (Digest, BTreeSet<String>)> = (self.sha256_pins())
            .into_iter()
            .map(|(path, (pin, origins))| (path, (Digest::Sha256(pin), origins)))
            .collect();
        let mut sha1: HashMap<String, (Digest, BTreeSet<String>)> = HashMap::new();
        for artifact in self
            .platforms
            .iter()
            .flat_map(|platform| &platform.artifacts)
        {
            if let Some(pin @ Digest::Sha1(_)) = artifact.pin() {
                let file = (sha1.entry(artifact.repository_path()))
                    .or_insert_with(|| (pin.clone(), BTreeSet::new()));
                file.1.extend(artifact.file_origins().map(str::to_string));
            }
        }
        for (path, pin) in sha1 {
            files.entry(path).or_insert(pin);
        }
        files
    }

    fn sha256_pins(&self) -> HashMap<String, (Sha256, BTreeSet<String>)> {
        let mut files: HashMap<String, (Sha256, BTreeSet<String>)> = HashMap::new();
        for (path, pin, served) in self.pinned_files() {
            let file = files
                .entry(path)
                .or_insert_with(|| (pin.clone(), BTreeSet::new()));
            file.0.clone_from(pin);
            file.1.extend(served.into_iter().map(str::to_string));
        }
        files
    }

    /// Each release file or timestamped snapshot build `fresh` pins to other
    /// bytes than this lockfile, by path, with this lockfile's pin and then
    /// `fresh`'s. Other bytes under the same path are a replaced file.
    /// Only non-unique snapshot filenames can be redeployed and are left out.
    pub fn repinned_releases(&self, fresh: &Lockfile) -> Vec<(String, Sha256, Sha256)> {
        let pinned = self.sha256_pins();
        let mut repinned: Vec<_> = fresh
            .pinned_files()
            .filter(|(path, ..)| !rv_maven_types::layout::is_mutable_snapshot_path(path))
            .filter_map(|(path, pin, _)| {
                let (locked, _) = pinned.get(&path)?;
                (locked != pin).then(|| (path, locked.clone(), pin.clone()))
            })
            .collect();
        repinned.sort_by(|a, b| a.0.cmp(&b.0));
        repinned.dedup_by(|a, b| a.0 == b.0);
        repinned
    }

    fn pinned_files(&self) -> impl Iterator<Item = (String, &Sha256, Vec<&str>)> {
        let artifacts = (self.platforms.iter())
            .flat_map(|platform| &platform.artifacts)
            .flat_map(|artifact| {
                let file = match artifact.pin() {
                    Some(Digest::Sha256(pin)) => Some((
                        artifact.repository_path(),
                        pin,
                        artifact.file_origins().collect(),
                    )),
                    _ => None,
                };
                let pom = artifact.pom_sha256.as_ref().map(|pom| {
                    let (dir, version) = (
                        artifact.directory_version(),
                        artifact.pom_gav().version().to_string(),
                    );
                    let path = rv_maven_types::layout::artifact_path(
                        &artifact.coord().pom(),
                        &dir,
                        &version,
                    );
                    let origins = if artifact.pom_repo_urls.is_empty() {
                        artifact.file_origins().collect()
                    } else {
                        artifact.pom_repo_urls.iter().map(String::as_str).collect()
                    };
                    (path, pom, origins)
                });
                file.into_iter().chain(pom)
            });
        let support = (self.platforms.iter())
            .flat_map(|platform| &platform.support_poms)
            .filter_map(|(coord, pin)| {
                Some((
                    pin.repository_path(coord)?,
                    &pin.sha256,
                    vec![pin.repo_url.as_str()],
                ))
            });
        artifacts.chain(support)
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
                let graphs =
                    crate::inputs::graph_digests(platform, inputs, config_hash.as_deref(), &reads);
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
    pub fn relativize_origins(&mut self, origins: &LockOrigins) -> Result<(), LockError> {
        for artifact in self
            .platforms
            .iter_mut()
            .flat_map(|platform| platform.artifacts.iter_mut())
        {
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
            pin.repo_url = origins.recorded(&pin.repo_url)?;
        }
        let ids = std::mem::take(&mut self.repo_ids);
        self.repo_ids = record_repo_ids(origins, ids)?;
        for platform in &mut self.platforms {
            if let Some(ids) = platform.repo_ids.take() {
                platform.repo_ids = Some(record_repo_ids(origins, ids)?);
            }
        }
        Ok(())
    }

    /// Check that every origin is spelled as a lock for the project directory
    /// `origins` describes records it: a project-relative origin is valid, and
    /// no absolute `file:` origin names a directory inside the project.
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
        for origin in artifact_origins.chain(support_origins).chain(id_origins) {
            let recorded = origins.recorded(&origin)?;
            if recorded != origin {
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
        for origin in artifact_origins.chain(support_origins) {
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
    /// platform that did not read all of it lists what it read.
    pub fn set_target_reads(&mut self, reads: &[TargetReads]) -> Result<(), LockError> {
        assert_eq!(reads.len(), self.platforms.len(), "one entry per platform");
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
            .map_err(|err| LockError::Invalid(format!("failed to encode lockfile: {err}")))
    }

    /// Write the canonical form to `path`, replacing the file so a reader
    /// sees the old contents or the new ones. Writes nothing if the lockfile
    /// breaks a rule of the schema or an origin is not spelled as the
    /// project directory holding `path` records it
    /// ([`Lockfile::relativize_origins`]). A file that already holds exactly
    /// these bytes is kept, with its modification time set to now.
    pub fn write_atomic(&self, path: &Path) -> Result<(), LockError> {
        let contents = self.to_toml()?;
        self.check_origins(&LockOrigins::for_lock_path(path))?;
        if rewrite_unneeded(path, contents.as_bytes()) {
            return Ok(());
        }
        write_file_atomic(path, contents.as_bytes(), NewFileAccess::Shared).map_err(|err| {
            LockError::io(format!("failed to write lockfile {}", path.display()), err)
        })
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
        for (origin, what) in rows.chain(support).chain(ids) {
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

/// Whether `path` is a regular file holding exactly `contents`, or them with
/// CRLF line endings as a Git checkout on Windows may have, now with its
/// modification time set to the present. `raeva sync` reads that time as
/// when SNAPSHOTs were last refreshed, so a refresh that changed nothing
/// still has to move it.
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
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() <= limit)
        && read().is_ok_and(|existing| {
            existing == contents
                || (existing.len() > contents.len()
                    && String::from_utf8(existing)
                        .is_ok_and(|text| text.replace("\r\n", "\n").as_bytes() == contents))
        })
        && fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.set_modified(std::time::SystemTime::now()))
            .is_ok()
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

/// Every artifact row naming one `group:artifact:version` must pin the same
/// companion POM, or none, across classifiers and across platforms, and a
/// support POM naming that file must pin it too.
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
            if let Some((coord, support)) = support.get(&gav)
                && Some(&support.sha256) != digest
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

    // Modules check apart; the first failure in module order is reported.
    let mut used_artifacts = vec![false; platform.artifacts.len()];
    let checked = rv_maven_types::par_map(&platform.modules, |module| {
        validate_module(platform, module, &module_paths, &artifact_by_coordinate)
    });
    for used in checked {
        for index in used? {
            used_artifacts[index] = true;
        }
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

/// [`validate_platform`] for the rows of `module`: the indices of the
/// artifact rows its packages use.
fn validate_module(
    platform: &LockPlatform,
    module: &LockModule,
    module_paths: &HashMap<&str, &LockModule>,
    artifact_by_coordinate: &foldhash::HashMap<&ArtifactCoord, usize>,
) -> Result<Vec<usize>, LockError> {
    let mut used = Vec::with_capacity(module.packages.len());
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
            if artifact_by_coordinate.contains_key(&package.coordinate) {
                return Err(LockError::Invalid(format!(
                    "workspace package '{}' must not have an artifact-table row",
                    package.coordinate
                )));
            }
        } else if package.system_path.is_some() {
            if artifact_by_coordinate.contains_key(&package.coordinate) {
                return Err(LockError::Invalid(format!(
                    "system-scoped package '{}' must not have an artifact-table row",
                    package.coordinate
                )));
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
    Ok(used)
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
        }
        for (coord, pin) in &platform.support_poms {
            validate_support_pom_coord(coord)?;
            let row = || format!("support POM '{coord}' {on}");
            check_origin_text(&pin.repo_url, &row)?;
            if pin.snapshot.is_some() && pin.file_gav(coord).is_none() {
                return Err(LockError::Invalid(format!(
                    "{} records a snapshot build, but its version is not a SNAPSHOT",
                    row()
                )));
            }
        }
        for checked in
            rv_maven_types::par_map(&platform.modules, |module| check_module_fields(module, &on))
        {
            checked?;
        }
    }
    Ok(())
}

/// [`check_lock_fields`] for the strings of `module`, on the platform `on`
/// names.
fn check_module_fields(module: &LockModule, on: &str) -> Result<(), LockError> {
    validate_module_path(&module.path, "module")?;
    let row = format!("module '{}' {on}", module.path);
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
        let range = rv_maven_types::VersionReq::parse(range).map_err(|_| invalid())?;
        validate_support_pom_coord(&selection.selected)?;
        let (selected_group, selected_artifact, version) =
            split_support_pom_coord(&selection.selected).ok_or_else(invalid)?;
        if group != selected_group
            || artifact != selected_artifact
            || !rv_maven_types::Version::parse(version).is_ok_and(|version| range.matches(&version))
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
fn validate_coordinate(
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

fn check_origin_text(origin: &str, row: &dyn Fn() -> String) -> Result<(), LockError> {
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

fn validate_module_path(path: &str, field: &str) -> Result<(), LockError> {
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
    // The published `pomPath` pattern ends in an exact `pom.xml` component; a
    // plain suffix test would also accept `app/mypom.xml`.
    if invalid || path.rsplit('/').next() != Some("pom.xml") {
        return Err(LockError::Invalid(format!(
            "{field} path {path:?} must be a normalized root-relative pom.xml path"
        )));
    }
    Ok(())
}

impl Lockfile {
    /// Warn, without failing, for each coordinate-bearing field that holds
    /// one of `values`, the values of the `${env.*}` variables POMs were
    /// allowed to read. Such a field means a variable's value, possibly a
    /// secret, ended up in a tracked file. Values shorter than 4 bytes are
    /// skipped, since they match version numbers.
    pub fn warn_on_env_values(&self, values: &BTreeMap<String, String>) {
        for hit in self.env_value_hits(values) {
            tracing::warn!(
                target: "raeva::sec::warn_collect",
                sec_code = "ENV_VALUE_IN_LOCKFILE",
                env_var = %hit.env_var,
                field = hit.field,
                coord = %hit.coord,
                platform = %hit.platform,
                "lockfile field contains the resolved value of an allowlisted ${{env.X}} \
                 substitution; the secret may have leaked into a tracked artifact"
            );
        }
    }

    fn env_value_hits<'a>(&'a self, values: &'a BTreeMap<String, String>) -> Vec<EnvValueHit<'a>> {
        let mut hits = Vec::new();
        for platform in &self.platforms {
            let on = &platform.platform;
            for artifact in &platform.artifacts {
                let extra: Vec<_> = artifact
                    .origins()
                    .map(|origin| ("repo_url", origin))
                    .collect();
                scan_fields(&artifact.coord(), &extra, values, on, &mut hits);
            }
            for package in platform.modules.iter().flat_map(|module| &module.packages) {
                let (workspace, system) = (&package.workspace_module, &package.system_path);
                if workspace.is_none() && system.is_none() {
                    continue;
                }
                let extra = [
                    ("workspace_module", workspace.as_deref().unwrap_or_default()),
                    ("system_path", system.as_deref().unwrap_or_default()),
                ];
                scan_fields(&package.coordinate, &extra, values, on, &mut hits);
            }
        }
        hits
    }
}

/// A lockfile field holding the value of an allowlisted environment variable.
#[derive(Debug, PartialEq, Eq)]
struct EnvValueHit<'a> {
    env_var: &'a str,
    field: &'static str,
    coord: ArtifactCoord,
    platform: &'a Platform,
}

fn scan_fields<'a>(
    coord: &ArtifactCoord,
    extra: &[(&'static str, &str)],
    values: &'a BTreeMap<String, String>,
    platform: &'a Platform,
    hits: &mut Vec<EnvValueHit<'a>>,
) {
    let fields = [
        ("group_id", coord.group_id()),
        ("artifact_id", coord.artifact_id()),
        ("version", coord.version()),
        ("packaging", coord.extension()),
        ("classifier", coord.classifier().unwrap_or_default()),
    ];
    // Shorter values match version numbers.
    for (name, value) in values.iter().filter(|(_, value)| value.len() >= 4) {
        for &(field, content) in fields.iter().chain(extra) {
            if content.contains(value.as_str()) {
                hits.push(EnvValueHit {
                    env_var: name,
                    field,
                    coord: coord.clone(),
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
}

impl LockPlatform {
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
            }],
            support_poms: BTreeMap::new(),
            model_inputs: None,
            repo_ids: None,
            host_inputs: None,
        };
        value.canonicalize();
        value
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

    /// Whether the graph digests read from a lock whose `config_hash` is
    /// `config_hash` and whose `[metadata] repo_ids` are `repo_ids` match the
    /// rows and records this platform holds, and `ambient`, the lock's
    /// `[resolution] ambient_inputs`, lists every name a graph read, and a
    /// module read each support POM: false when they
    /// come from different resolutions, as after a merge of two branches
    /// that each changed a module's graph, its POM or the configuration. A
    /// platform with only a `model_hash` has no graph digests, so it never
    /// matches.
    pub fn graphs_match(
        &self,
        config_hash: Option<&str>,
        ambient: &BTreeSet<AmbientInput>,
        repo_ids: &RepoIds,
    ) -> bool {
        let reads = self.reads(repo_ids, ambient);
        let read: HashSet<&String> = (self.modules.iter())
            .flat_map(|module| &module.support_poms)
            .collect();
        (self.model_inputs.as_ref()).is_some_and(|inputs| {
            inputs.read_names().all(|name| ambient.contains(name))
                && self.support_poms.keys().all(|coord| read.contains(coord))
                && inputs.graphs == crate::inputs::graph_digests(self, inputs, config_hash, &reads)
        })
    }

    /// The first coordinate whose row here pins a different file than
    /// `other`'s row for it does ([`LockArtifact::conflicts_with`]), or other
    /// bytes than `other`'s row for the same local-repository file under
    /// another coordinate.
    pub(crate) fn conflicting_artifact_pin(&self, other: &LockPlatform) -> Option<&ArtifactCoord> {
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
            .map(|artifact| &artifact.coordinate)
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
}

impl LockModule {
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
        }
    }
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
    /// The scope the dependency has below `from`, `None` when none is
    /// recorded: the scope management gives it, else the one Maven's
    /// JavaScopeDeriver derives from its declared scope and the scope `from`
    /// resolves to ([`LockModulePackage::scope`]). Written next, omitted
    /// when `None`.
    pub scope: Option<Scope>,
    /// Whether the dependency is optional. Written last as `optional`, and
    /// read as `false` when absent.
    pub optional: bool,
}

impl LockEdge {
    /// An edge from package `from` to package `to`, both indexes into the
    /// module's packages, with the scope and optional flag the dependency
    /// has below `from`.
    pub fn new(from: usize, to: usize, scope: Option<Scope>, optional: bool) -> Self {
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
}

impl SupportPom {
    /// The pin of a support POM served by the repository `repo_url`.
    pub fn new(repo_url: impl Into<String>, sha256: Sha256) -> Self {
        Self {
            repo_url: repo_url.into(),
            sha256,
            snapshot: None,
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
    use std::collections::BTreeMap;

    use rv_maven_types::ArtifactCoord;

    use super::{EnvValueHit, LockArtifact, LockModulePackage, Lockfile, Scope};
    use crate::error::LockError;
    use crate::test_lock::{lock, locked_platform, package, platform};

    /// A coordinate or path field that holds an allowlisted variable's value
    /// is reported by field; a short value would match version numbers and
    /// is skipped.
    #[test]
    fn env_values_are_found_in_coordinates_and_paths() {
        let values = BTreeMap::from([
            ("RAEVA_GROUP".to_string(), "com.example".to_string()),
            ("RAEVA_SYSTEM_DIR".to_string(), "leaked-system".to_string()),
            ("RAEVA_SHORT".to_string(), "app".to_string()),
        ]);
        let mut entry = locked_platform("linux-x86_64", vec![package("demo", "1.0", 'a')], 'b');
        let tool = ArtifactCoord::new("org.example", "tool", "1.0.0", "jar", None);
        let mut system = LockModulePackage::new(tool.clone(), Some(Scope::System));
        system.system_path = Some("leaked-system/tool.jar".to_string());
        entry.modules[0].packages.push(system);
        let lock = lock(vec![entry]);
        let linux = platform("linux-x86_64");
        let hit = |env_var, field, coord| EnvValueHit {
            env_var,
            field,
            coord,
            platform: &linux,
        };
        let demo = ArtifactCoord::new("com.example", "demo", "1.0", "jar", None);
        assert_eq!(
            lock.env_value_hits(&values),
            [
                hit("RAEVA_GROUP", "group_id", demo),
                hit("RAEVA_SYSTEM_DIR", "system_path", tool),
            ]
        );
        lock.warn_on_env_values(&values);
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
