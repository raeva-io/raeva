use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use fs2::FileExt;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::{
    ConfigError, io_error_with_context, toml_de_error_with_context, toml_ser_error_with_context,
};
use crate::platform::Platform;

pub const LOCKFILE_SCHEMA_VERSION: u32 = 4;

/// Stable placeholder used only when a legacy lock is serialized directly
/// without going through `rv sync`. A normal sync always replaces this with
/// the reactor model hash it computes for the platform.
const LEGACY_MODEL_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Sentinel GAV parts stamped on the synthetic root module minted when a
/// schema 1-3 lockfile is adapted into the schema-4 reactor view. Legacy locks
/// record no module identity, so there is nothing truthful to put here; the
/// sentinel only keeps the module row well-formed.
///
/// Nothing may render these to users or resolve them as a coordinate — test
/// with [`LockGav::is_legacy_placeholder`] / [`LockModule::is_legacy_placeholder`]
/// and show the module's POM path instead.
pub const LEGACY_ROOT_GROUP: &str = "__legacy__";
pub const LEGACY_ROOT_ARTIFACT: &str = "__root__";
pub const LEGACY_ROOT_VERSION: &str = "0";

/// Subdirectory under the user cache dir that holds the advisory lock files
/// guarding each project's `rv.lock`. The lock lives OUTSIDE the project
/// working tree (so it never appears in `git status`) at a path derived from
/// the canonicalized project root, so every concurrent `rv sync` on the same
/// checkout contends on the same inode.
const LOCKFILE_GUARD_SUBDIR: &str = "locks";

/// Sleep between try-lock attempts in [`LockfileGuard::acquire`]. This guard
/// polls at a fixed interval; `rv-store::store::StoreLock` is a separate lock
/// with its own jittered exponential backoff, so the two are not expected to
/// match.
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Maximum size [`Lockfile::read`] will load. Real lockfiles run a few KiB
/// to a few MiB; the cap is deliberately generous and exists only so a
/// runaway or hostile rv.lock cannot OOM the process.
const MAX_LOCKFILE_BYTES: u64 = 256 * 1024 * 1024;

/// RAII guard backed by an exclusive `fs2` advisory file lock on a sidecar
/// next to `rv.lock`. Two concurrent `rv sync` runs that resolve disjoint
/// platform sets would otherwise read-modify-write `rv.lock` in a
/// last-writer-wins race; holding this guard around the full read-resolve-
/// write sequence serializes them so neither drops the other's entries.
///
/// The lock is released when this value is dropped.
#[derive(Debug)]
pub struct LockfileGuard {
    /// Path of the sidecar guard file; kept for diagnostics on unlock.
    path: PathBuf,
    /// Open handle holding the advisory lock; `None` after an explicit
    /// `release()` so `Drop` becomes a no-op.
    file: Option<File>,
}

impl LockfileGuard {
    /// Acquire an exclusive advisory lock guarding `rv.lock` in
    /// `project_root`, polling until `timeout` elapses. The lock file lives
    /// under `lock_root` (the user cache dir), not in the project working
    /// tree, at a path derived from the canonicalized project root.
    ///
    /// Polls instead of blocking so a stale guard from a crashed `rv sync`
    /// surfaces as `io::ErrorKind::TimedOut` rather than wedging forever.
    pub fn acquire(lock_root: &Path, project_root: &Path, timeout: Duration) -> io::Result<Self> {
        let path = guard_path(lock_root, project_root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;

        let deadline = Instant::now() + timeout;
        loop {
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "timed out waiting for lockfile guard at {} after {:?}; \
                                 another `rv sync` may be holding it (or the previous \
                                 holder crashed without releasing the lock)",
                                path.display(),
                                timeout
                            ),
                        ));
                    }
                    thread::sleep(LOCK_RETRY_INTERVAL);
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Async wrapper around [`Self::acquire`]; runs the poll on the tokio
    /// blocking pool so the executor is not pinned during contention.
    pub async fn acquire_async(
        lock_root: &Path,
        project_root: &Path,
        timeout: Duration,
    ) -> io::Result<Self> {
        let lock_root = lock_root.to_path_buf();
        let project_root = project_root.to_path_buf();
        tokio::task::spawn_blocking(move || Self::acquire(&lock_root, &project_root, timeout))
            .await
            .map_err(|e| io::Error::other(format!("lockfile-guard acquire task panicked: {e}")))?
    }

    /// Path of the sidecar guard file held by this guard.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly release the lock. Equivalent to dropping the guard but
    /// surfaces unlock errors instead of swallowing them.
    pub fn release(mut self) -> io::Result<()> {
        if let Some(file) = self.file.take() {
            FileExt::unlock(&file)?;
        }
        // Deliberately do NOT unlink the lock file. Removing an
        // advisory-lock file after unlocking is unsound: a contender that
        // opened the same inode *before* the unlink keeps polling it and can
        // acquire it, while a later arrival creates and locks a *fresh* inode
        // at the same path, leaving two processes inside the rv.lock
        // critical section at once. The file is a stable anchor in the cache
        // dir (not the working tree), so leaving it costs nothing.
        Ok(())
    }
}

impl Drop for LockfileGuard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take()
            && let Err(err) = FileExt::unlock(&file)
        {
            tracing::debug!(
                path = %self.path.display(),
                error = %err,
                "LockfileGuard: failed to release advisory lock on drop"
            );
        }
        // Intentionally NOT removing the lock file. See `release()` for why
        // unlinking an advisory-lock file reintroduces a split-brain race.
    }
}

/// Deterministic, stable path for the advisory lock guarding `rv.lock` in
/// `project_root`. Lives under `lock_root/locks` (the user cache dir, never
/// the project working tree) and is keyed by the canonicalized project root
/// so every concurrent `rv sync` on the same checkout contends on the same
/// inode. Created once and never unlinked.
fn guard_path(lock_root: &Path, project_root: &Path) -> PathBuf {
    let canonical =
        dunce::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest = hex::encode(hasher.finalize());
    lock_root
        .join(LOCKFILE_GUARD_SUBDIR)
        .join(format!("{digest}.lock"))
}

/// On-disk lockfile schema.
///
/// Field additions use serde defaults (forward-compatible); field removals or
/// semantic changes must bump `LOCKFILE_SCHEMA_VERSION` and add a read-side
/// migration. Unknown top-level keys round-trip through `extra` so older
/// readers do not strip data written by newer writers.
#[derive(Debug, Clone, PartialEq)]
pub struct Lockfile {
    pub schema_version: u32,
    pub config_hash: Option<String>,
    /// Resolution settings that produced this lockfile and that are not
    /// derivable from `config_hash`. `None` for schema 1-3 locks and for
    /// schema-4 locks written before the field existed; readers that gate on
    /// resolution inputs (the `rv sync` fast path, `--frozen`) must treat
    /// `None` as "unknown" and re-resolve rather than assume a default.
    pub resolution: Option<LockResolution>,
    pub platforms: Vec<LockPlatform>,
    /// Stable key-value metadata for the lockfile. Values MUST be deterministic
    /// (no timestamps, PIDs, UUIDs, or other nonce data); non-deterministic values
    /// would break `--frozen` checks and byte-level diff comparisons.
    pub metadata: BTreeMap<String, String>,
    /// Preserve unrecognized top-level fields so they survive a read-write
    /// round-trip. Pre-v1 lockfiles wrote a `[variants]` table; that
    /// content is captured here and re-serialized verbatim so v1 does not
    /// strip data from existing lockfiles on the first re-write.
    pub extra: BTreeMap<String, toml::Value>,
}

/// Version-mediation strategy the resolver used, recorded so a later run can
/// tell whether a lockfile was produced under the same mediation rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockResolutionStrategy {
    #[default]
    Nearest,
    Highest,
}

impl LockResolutionStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nearest => "nearest",
            Self::Highest => "highest",
        }
    }
}

impl std::fmt::Display for LockResolutionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Schema-4 `[resolution]` table: the resolution-affecting settings that live
/// outside `config_hash` because they come from the command line rather than
/// from configuration files.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LockResolution {
    pub strategy: LockResolutionStrategy,
    /// Unknown `[resolution]` keys written by a newer Raeva, preserved across
    /// a read/write round-trip.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

impl LockResolution {
    pub fn new(strategy: LockResolutionStrategy) -> Self {
        Self {
            strategy,
            extra: BTreeMap::new(),
        }
    }
}

/// Deserialization envelope that accepts both the legacy flat platform shape
/// (schema 1-3) and the schema-4 reactor shape.
///
/// `Lockfile` implements serde manually so serialization can never
/// accidentally write the legacy `packages` / `edges` fields.
#[derive(Serialize, Deserialize)]
struct RawLockfile {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<LockResolution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<RawLockPlatform>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

#[derive(Serialize, Deserialize)]
struct RawLockPlatform {
    pub platform: Platform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hash: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<LockArtifact>,
    #[serde(default)]
    pub modules: Vec<LockModule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<LockPackage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<LockEdge>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

impl Serialize for Lockfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let canonical = self
            .canonical_v4()
            .map_err(<S::Error as serde::ser::Error>::custom)?;
        canonical.as_raw_v4().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Lockfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawLockfile::deserialize(deserializer)?;
        Self::from_raw(raw).map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl Lockfile {
    pub fn new() -> Self {
        Self {
            schema_version: LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    fn from_raw(raw: RawLockfile) -> Result<Self, ConfigError> {
        if raw.schema_version > LOCKFILE_SCHEMA_VERSION || raw.schema_version < 1 {
            return Err(ConfigError::UnsupportedSchema {
                found: raw.schema_version,
                expected: LOCKFILE_SCHEMA_VERSION,
            });
        }

        let source_schema = raw.schema_version;
        let mut platforms = Vec::with_capacity(raw.platforms.len());
        for raw_platform in raw.platforms {
            let platform = if source_schema == LOCKFILE_SCHEMA_VERSION {
                if !raw_platform.packages.is_empty() || !raw_platform.edges.is_empty() {
                    return Err(ConfigError::InvalidLockfile(format!(
                        "schema 4 platform '{}' uses legacy flat packages/edges; \
                         schema 4 requires modules-only dependency graphs",
                        raw_platform.platform
                    )));
                }
                let model_hash = raw_platform.model_hash.ok_or_else(|| {
                    ConfigError::InvalidLockfile(format!(
                        "schema 4 platform '{}' is missing model_hash",
                        raw_platform.platform
                    ))
                })?;
                LockPlatform::from_v4(
                    raw_platform.platform,
                    model_hash,
                    raw_platform.artifacts,
                    raw_platform.modules,
                    raw_platform.extra,
                )
            } else {
                if !raw_platform.modules.is_empty() || !raw_platform.artifacts.is_empty() {
                    return Err(ConfigError::InvalidLockfile(format!(
                        "legacy schema {source_schema} platform '{}' mixes flat packages/edges \
                         with schema 4 modules/artifacts",
                        raw_platform.platform
                    )));
                }
                LockPlatform::from_legacy(
                    raw_platform.platform,
                    raw_platform.packages,
                    raw_platform.edges,
                    raw_platform.extra,
                )
            };
            platforms.push(platform);
        }

        Ok(Self {
            schema_version: source_schema,
            config_hash: raw.config_hash,
            resolution: raw.resolution,
            platforms,
            metadata: raw.metadata,
            extra: raw.extra,
        })
    }

    fn as_raw_v4(&self) -> RawLockfile {
        RawLockfile {
            schema_version: LOCKFILE_SCHEMA_VERSION,
            config_hash: self.config_hash.clone(),
            resolution: self.resolution.clone(),
            platforms: self
                .platforms
                .iter()
                .map(|platform| RawLockPlatform {
                    platform: platform.platform.clone(),
                    model_hash: Some(platform.model_hash.clone()),
                    artifacts: platform.artifacts.clone(),
                    modules: platform.modules.clone(),
                    packages: Vec::new(),
                    edges: Vec::new(),
                    extra: platform.extra.clone(),
                })
                .collect(),
            metadata: self.metadata.clone(),
            extra: self.extra.clone(),
        }
    }

    fn canonical_v4(&self) -> Result<Self, ConfigError> {
        let mut canonical = self.clone();
        canonical.schema_version = LOCKFILE_SCHEMA_VERSION;
        canonical
            .platforms
            .sort_by(|left, right| left.platform.to_string().cmp(&right.platform.to_string()));
        for platform in &mut canonical.platforms {
            if platform.model_hash.is_empty() {
                platform.model_hash = LEGACY_MODEL_HASH.to_string();
            }
            platform.canonicalize();
        }
        normalize_lockfile_checksums(&mut canonical, "lockfile being written")?;
        canonical.validate()?;
        Ok(canonical)
    }

    /// Return the schema-4 representation exactly as it would be written.
    ///
    /// Besides deterministic sorting, this remaps each module's edge indices
    /// after sorting its package table. Callers comparing an in-memory
    /// resolution with an on-disk lockfile must use this representation:
    /// the freshly resolved graph is still in traversal order, while the
    /// lockfile read from disk is already canonical.
    pub fn canonicalized(&self) -> Result<Self, ConfigError> {
        self.canonical_v4()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        check_duplicate_platforms(&self.platforms)?;
        for platform in &self.platforms {
            validate_platform(platform, self.schema_version)?;
        }
        let support_poms = match self.metadata.get(LOCK_SUPPORT_POMS_KEY) {
            Some(encoded) => decode_support_pom_lines(encoded)?,
            None => BTreeMap::new(),
        };
        check_companion_pom_pins(&self.platforms)?;
        check_support_companion_pins(&support_poms, &self.platforms)?;
        Ok(())
    }

    /// Acquire an exclusive advisory lock around the lockfile's
    /// read-resolve-write sequence for the given project root.
    ///
    /// See [`LockfileGuard`] for the rationale. The returned guard releases
    /// the lock on drop. `timeout` bounds how long the call waits for a
    /// contending `rv sync` (or a stale lock from a crashed process) before
    /// surfacing [`io::ErrorKind::TimedOut`].
    pub fn acquire_guard(
        lock_root: &Path,
        project_root: &Path,
        timeout: Duration,
    ) -> io::Result<LockfileGuard> {
        LockfileGuard::acquire(lock_root, project_root, timeout)
    }

    pub fn read(path: &Path) -> Result<Self, ConfigError> {
        Self::read_with_limit(path, MAX_LOCKFILE_BYTES)
    }

    fn read_with_limit(path: &Path, max_bytes: u64) -> Result<Self, ConfigError> {
        // Bound the read before slurping the file so a runaway rv.lock
        // cannot exhaust memory before the TOML parser even runs.
        let size = fs::metadata(path)
            .with_context(|| format!("failed to read lockfile {}", path.display()))
            .map_err(|err| ConfigError::Io(io_error_with_context(err)))?
            .len();
        if size > max_bytes {
            return Err(ConfigError::InvalidLockfile(format!(
                "lockfile {} is {size} bytes, which exceeds the {max_bytes} byte limit",
                path.display()
            )));
        }
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read lockfile {}", path.display()))
            .map_err(|err| ConfigError::Io(io_error_with_context(err)))?;
        // An empty (or whitespace-only) lockfile yields `schema_version = 0`
        // when fed to `toml::from_str`, which then surfaces as
        // `UnsupportedSchema { found: 0 }`. That message wrongly hints at a
        // version-skew problem; the real cause is almost always an aborted
        // first sync or a manual `truncate`. Detect this up front so the user
        // gets an actionable hint.
        if contents.trim().is_empty() {
            return Err(ConfigError::InvalidLockfile(format!(
                "lockfile {} is empty (zero bytes); run `rv sync` to populate it",
                path.display()
            )));
        }
        #[derive(Deserialize)]
        struct SchemaHeader {
            schema_version: u32,
        }
        let header: SchemaHeader = toml::from_str(&contents)
            .with_context(|| format!("failed to parse lockfile {}", path.display()))
            .map_err(|err| ConfigError::TomlDeserialize(toml_de_error_with_context(err)))?;
        if header.schema_version > LOCKFILE_SCHEMA_VERSION || header.schema_version < 1 {
            return Err(ConfigError::UnsupportedSchema {
                found: header.schema_version,
                expected: LOCKFILE_SCHEMA_VERSION,
            });
        }
        let mut lock: Lockfile = toml::from_str(&contents)
            .with_context(|| format!("failed to parse lockfile {}", path.display()))
            .map_err(|err| ConfigError::TomlDeserialize(toml_de_error_with_context(err)))?;
        // Normalize and validate checksum algorithms on every package up
        // front so downstream consumers can rely on a canonical spelling
        // and never silently drop a pin with a non-canonical algorithm.
        let display = path.display().to_string();
        normalize_lockfile_checksums(&mut lock, &display)?;
        lock.validate()?;
        Ok(lock)
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), ConfigError> {
        let lock_to_write = self.canonical_v4()?;

        // Walk every coordinate-bearing string field on every package
        // and warn (without blocking) if an allowlisted `${env.X}` value has
        // ended up baked into the lockfile. We can't undo it here (the
        // proper fix lives in the interpolation layer), but emitting a
        // structured warning gives operators a visible signal that a secret
        // may have leaked into a tracked artifact.
        warn_on_env_value_in_lockfile(&lock_to_write);

        let contents = toml::to_string_pretty(&lock_to_write)
            .with_context(|| format!("failed to serialize lockfile {}", path.display()))
            .map_err(|err| ConfigError::TomlSerialize(toml_ser_error_with_context(err)))?;
        let tmp_path = temp_path_for(path);
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| format!("failed to create temp lockfile {}", tmp_path.display()))
            .map_err(|err| ConfigError::Io(io_error_with_context(err)))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("failed to write temp lockfile {}", tmp_path.display()))
            .map_err(|err| ConfigError::Io(io_error_with_context(err)))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temp lockfile {}", tmp_path.display()))
            .map_err(|err| ConfigError::Io(io_error_with_context(err)))?;
        match atomic_replace(&tmp_path, path)
            .with_context(|| {
                format!(
                    "failed to replace lockfile {} with {}",
                    path.display(),
                    tmp_path.display()
                )
            })
            .map_err(|err| ConfigError::Io(io_error_with_context(err)))
        {
            Ok(()) => {
                // Persist the parent directory entry so the rename survives a
                // power loss: the temp file's data was synced via `sync_all`
                // above, but the directory metadata that links the new name
                // can still be lost on crash without an explicit fsync.
                if let Some(parent) = path.parent()
                    && let Ok(handle) = fs::File::open(parent)
                {
                    let _ = handle.sync_all();
                }
                Ok(())
            }
            Err(err) => {
                if let Err(e) = fs::remove_file(&tmp_path) {
                    tracing::debug!(path = %tmp_path.display(), error = %e, "failed to remove temp file");
                }
                Err(err)
            }
        }
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

// Two same-platform entries would silently overwrite each other through any
// platform-keyed consumer, masking a hand-edit mistake or a resolver bug.
fn check_duplicate_platforms(platforms: &[LockPlatform]) -> Result<(), ConfigError> {
    let mut seen: HashSet<&Platform> = HashSet::with_capacity(platforms.len());
    for platform in platforms {
        if !seen.insert(&platform.platform) {
            return Err(ConfigError::InvalidLockfile(format!(
                "duplicate platform '{}' in lockfile; \
                 each platform may appear at most once",
                platform.platform
            )));
        }
    }
    Ok(())
}

/// Every artifact row naming one `group:artifact:version` must pin the same
/// companion POM, across classifiers and across platforms.
///
/// Maven has exactly one local-repository path per GAV, so `rv export-m2`
/// writes one `.pom` there. A lockfile holding two digests for one GAV
/// therefore describes a `~/.m2` that cannot exist: whichever row export
/// happened to read first would decide, and the other platform's build would
/// run against a POM it never resolved. `rv sync` refuses to write such a
/// lockfile; this catches a hand-edited one on the way in, for every consumer
/// at once.
fn check_companion_pom_pins(platforms: &[LockPlatform]) -> Result<(), ConfigError> {
    let mut pinned: HashMap<(String, String, String), (&str, &Platform)> = HashMap::new();
    for platform in platforms {
        for artifact in &platform.artifacts {
            let Some(digest) = artifact.pom_sha256.as_deref() else {
                continue;
            };
            let package = artifact.as_package();
            let gav = (package.group_id, package.artifact_id, package.version);
            match pinned.get(&gav) {
                Some((seen, seen_platform)) if *seen != digest => {
                    return Err(ConfigError::InvalidLockfile(format!(
                        "conflicting pom_sha256 for '{}:{}:{}': {seen} on platform '{}' and \
                         {digest} on platform '{}'; one Maven local repository cannot hold both",
                        gav.0, gav.1, gav.2, seen_platform, platform.platform
                    )));
                }
                Some(_) => {}
                None => {
                    pinned.insert(gav, (digest, &platform.platform));
                }
            }
        }
    }
    Ok(())
}

/// A support POM and an artifact row's companion POM naming the same
/// `group:artifact:version` must pin the same bytes.
///
/// The two pins are recorded by independent observations — the support-POM
/// closure `rv sync` walked, and the `pom_sha256` of the row whose payload that
/// POM describes — but they name the one `.pom` Maven keeps for the
/// coordinate. `rv export-m2` queues the support POM first, so a lockfile
/// holding two digests would ship the support pin's bytes while the artifact
/// row attests the other digest is what was resolved. `rv sync` refuses to
/// write such a lockfile; this catches a hand-edited one, and the
/// carry-forward merge that could construct one, for every consumer at once.
///
/// Only a pinned support line participates: a legacy two-field line records no
/// digest, so there is nothing to disagree with.
fn check_support_companion_pins(
    support_poms: &BTreeMap<String, SupportPomLine>,
    platforms: &[LockPlatform],
) -> Result<(), ConfigError> {
    if support_poms.is_empty() {
        return Ok(());
    }
    for platform in platforms {
        for artifact in &platform.artifacts {
            let Some(companion) = artifact.pom_sha256.as_deref() else {
                continue;
            };
            let package = artifact.as_package();
            let gav = format!(
                "{}:{}:{}",
                package.group_id, package.artifact_id, package.version
            );
            let Some(support) = support_poms
                .get(&gav)
                .and_then(|line| line.sha256.as_deref())
            else {
                continue;
            };
            if support != companion {
                return Err(ConfigError::InvalidLockfile(format!(
                    "conflicting POM digests for '{gav}': {LOCK_SUPPORT_POMS_KEY} pins {support} \
                     but artifact '{}' on platform '{}' pins pom_sha256 {companion}; \
                     one Maven local repository cannot hold both",
                    artifact.coordinate.format_coord(),
                    platform.platform
                )));
            }
        }
    }
    Ok(())
}

/// True for a canonical SHA-256 digest: 64 lowercase hex characters.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_platform(platform: &LockPlatform, schema_version: u32) -> Result<(), ConfigError> {
    if schema_version == LOCKFILE_SCHEMA_VERSION && !is_sha256_hex(&platform.model_hash) {
        return Err(ConfigError::InvalidLockfile(format!(
            "model_hash on platform '{}' must be 64 lowercase hex characters",
            platform.platform
        )));
    }
    if platform.modules.is_empty() {
        return Err(ConfigError::InvalidLockfile(format!(
            "platform '{}' has no modules; schema 4 requires a modules-only reactor view",
            platform.platform
        )));
    }

    let mut module_paths = HashMap::with_capacity(platform.modules.len());
    let mut module_gavs = HashSet::with_capacity(platform.modules.len());
    for module in &platform.modules {
        validate_module_path(&module.path, "module")?;
        if module.gav.group.is_empty()
            || module.gav.artifact.is_empty()
            || module.gav.version.is_empty()
            || module.packaging.is_empty()
        {
            return Err(ConfigError::InvalidLockfile(format!(
                "module '{}' must have a non-empty effective GAV and packaging",
                module.path
            )));
        }
        if module_paths.insert(module.path.as_str(), module).is_some() {
            return Err(ConfigError::InvalidLockfile(format!(
                "duplicate module path '{}' on platform '{}'",
                module.path, platform.platform
            )));
        }
        if !module_gavs.insert(&module.gav) {
            return Err(ConfigError::InvalidLockfile(format!(
                "duplicate effective module GAV '{}:{}:{}' on platform '{}'",
                module.gav.group, module.gav.artifact, module.gav.version, platform.platform
            )));
        }
    }

    let mut artifact_by_coordinate = HashMap::with_capacity(platform.artifacts.len());
    for artifact in &platform.artifacts {
        validate_coordinate(&artifact.coordinate)?;
        if artifact_by_coordinate
            .insert(&artifact.coordinate, artifact)
            .is_some()
        {
            return Err(ConfigError::InvalidLockfile(format!(
                "duplicate artifact '{}' on platform '{}'",
                artifact.coordinate.format_coord(),
                platform.platform
            )));
        }
        let mut algorithms = HashSet::with_capacity(artifact.checksums.len());
        for checksum in &artifact.checksums {
            if !algorithms.insert(checksum.algorithm.as_str()) {
                return Err(ConfigError::InvalidLockfile(format!(
                    "duplicate {} checksum for artifact '{}' on platform '{}'",
                    checksum.algorithm,
                    artifact.coordinate.format_coord(),
                    platform.platform
                )));
            }
        }
        if let Some(snapshot) = artifact.snapshot.as_ref()
            && !is_snapshot_timestamp_str(&snapshot.timestamp)
        {
            return Err(ConfigError::InvalidLockfile(format!(
                "snapshot timestamp '{}' for artifact '{}' must use YYYYMMDD.HHMMSS",
                snapshot.timestamp,
                artifact.coordinate.format_coord()
            )));
        }
        // The companion-POM pin addresses a content-store blob directly, so a
        // malformed digest can never name one. Reject it here rather than
        // letting `rv export-m2` discover it as a missing blob.
        if let Some(digest) = artifact.pom_sha256.as_deref()
            && !is_sha256_hex(digest)
        {
            return Err(ConfigError::InvalidLockfile(format!(
                "pom_sha256 '{digest}' for artifact '{}' on platform '{}' must be 64 \
                 lowercase hex characters",
                artifact.coordinate.format_coord(),
                platform.platform
            )));
        }
        // A `packaging = "pom"` row's payload IS its companion POM: one file
        // in the repository, one path in `~/.m2`, and `rv export-m2` exports
        // it as the primary artifact. Two digests describe a file that cannot
        // exist, and export would ship the payload while the lock claims the
        // pin. `rv sync` refuses to write such a row; this catches a
        // hand-edited one. Only the classifier-less row names that file — a
        // classified `.pom` is its own artifact — and only a sha256 payload
        // pin is comparable at all (a sha1-only row has nothing to compare).
        if let Some(pom_digest) = artifact.pom_sha256.as_deref()
            && artifact.coordinate.packaging == "pom"
            && artifact
                .coordinate
                .classifier
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            && let Some(payload) = artifact
                .checksums
                .iter()
                .find(|checksum| checksum.algorithm == "sha256")
            && payload.digest != pom_digest
        {
            return Err(ConfigError::InvalidLockfile(format!(
                "pom-packaged artifact '{}' on platform '{}' pins payload sha256 {} but \
                 pom_sha256 {pom_digest}; for packaging=pom those name the same file",
                artifact.coordinate.format_coord(),
                platform.platform,
                payload.digest
            )));
        }
    }

    let mut used_artifacts: BTreeSet<&LockCoordinate> = BTreeSet::new();
    for module in &platform.modules {
        let mut package_coordinates = HashSet::with_capacity(module.packages.len());
        for package in &module.packages {
            validate_coordinate(&package.coordinate)?;
            if !package_coordinates.insert(&package.coordinate) {
                return Err(ConfigError::InvalidLockfile(format!(
                    "duplicate package '{}' in module '{}' on platform '{}'",
                    package.coordinate.format_coord(),
                    module.path,
                    platform.platform
                )));
            }
        }

        for edge in &module.edges {
            if edge.from >= module.packages.len() || edge.to >= module.packages.len() {
                return Err(ConfigError::InvalidLockfile(format!(
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
            for forbidden in [
                "repo_url",
                "checksum",
                "checksums",
                "snapshot",
                "snapshot_timestamp",
            ] {
                if package.extra.contains_key(forbidden) {
                    return Err(ConfigError::InvalidLockfile(format!(
                        "module package '{}' contains forbidden field '{forbidden}'; \
                         repository pins and snapshot details belong in the artifact table",
                        package.coordinate.format_coord()
                    )));
                }
            }
            if package.workspace_module.is_some() && package.system_path.is_some() {
                return Err(ConfigError::InvalidLockfile(format!(
                    "package '{}' in module '{}' cannot be both workspace and system scoped",
                    package.coordinate.format_coord(),
                    module.path
                )));
            }

            if let Some(workspace_path) = package.workspace_module.as_deref() {
                validate_module_path(workspace_path, "workspace_module")?;
                let target = module_paths.get(workspace_path).ok_or_else(|| {
                    ConfigError::InvalidLockfile(format!(
                        "workspace_module '{}' referenced by package '{}' in module '{}' \
                         does not resolve to a module row",
                        workspace_path,
                        package.coordinate.format_coord(),
                        module.path
                    ))
                })?;
                if package.coordinate.group != target.gav.group
                    || package.coordinate.artifact != target.gav.artifact
                    || package.coordinate.version != target.gav.version
                {
                    return Err(ConfigError::InvalidLockfile(format!(
                        "workspace_module '{}' GAV '{}:{}:{}' does not match package '{}'",
                        workspace_path,
                        target.gav.group,
                        target.gav.artifact,
                        target.gav.version,
                        package.coordinate.format_coord()
                    )));
                }
                if artifact_by_coordinate.contains_key(&package.coordinate) {
                    return Err(ConfigError::InvalidLockfile(format!(
                        "workspace package '{}' must not have an artifact-table row",
                        package.coordinate.format_coord()
                    )));
                }
            } else if package.system_path.is_some() {
                if artifact_by_coordinate.contains_key(&package.coordinate) {
                    return Err(ConfigError::InvalidLockfile(format!(
                        "system-scoped package '{}' must not have an artifact-table row",
                        package.coordinate.format_coord()
                    )));
                }
            } else {
                let artifact =
                    artifact_by_coordinate
                        .get(&package.coordinate)
                        .ok_or_else(|| {
                            ConfigError::InvalidLockfile(format!(
                                "external package '{}' in module '{}' has no artifact-table row",
                                package.coordinate.format_coord(),
                                module.path
                            ))
                        })?;
                used_artifacts.insert(&package.coordinate);
                if artifact.repo_url.is_empty() {
                    tracing::warn!(
                        coord = %package.coordinate.format_coord(),
                        "lockfile artifact has an empty repo_url; the artifact may not be fetchable"
                    );
                }
            }
        }
    }

    for artifact in &platform.artifacts {
        if !used_artifacts.contains(&artifact.coordinate) {
            return Err(ConfigError::InvalidLockfile(format!(
                "orphan artifact row '{}' on platform '{}'",
                artifact.coordinate.format_coord(),
                platform.platform
            )));
        }
    }
    Ok(())
}

fn validate_coordinate(coordinate: &LockCoordinate) -> Result<(), ConfigError> {
    if coordinate.group.is_empty()
        || coordinate.artifact.is_empty()
        || coordinate.version.is_empty()
        || coordinate.packaging.is_empty()
    {
        return Err(ConfigError::InvalidLockfile(format!(
            "artifact coordinate '{}' has an empty group, artifact, version, or packaging field",
            coordinate.format_coord()
        )));
    }
    Ok(())
}

fn validate_module_path(path: &str, field: &str) -> Result<(), ConfigError> {
    let invalid = path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..");
    // The published `pomPath` pattern ends in an exact `pom.xml` component; a
    // plain suffix test would also accept `app/mypom.xml`.
    if invalid || path.rsplit('/').next() != Some("pom.xml") {
        return Err(ConfigError::InvalidLockfile(format!(
            "{field} path '{path}' must be a normalized root-relative pom.xml path"
        )));
    }
    Ok(())
}

// Warn (not block) when an allowlisted `${env.X}` value has been baked into a
// coordinate-bearing field on disk: blocking mid-CI would risk corruption,
// and the proper fix lives in the interpolation layer.
fn warn_on_env_value_in_lockfile(lock: &Lockfile) {
    let Some(allowlist) = rv_maven_model::env_substitution_allowlist() else {
        return;
    };
    if allowlist.is_empty() {
        return;
    }

    // Empty values would substring-match everywhere; skip them.
    let resolved: Vec<(String, String)> = allowlist
        .iter()
        .filter_map(|name| {
            let value = std::env::var(name).ok()?;
            if value.is_empty() {
                return None;
            }
            Some((name.clone(), value))
        })
        .collect();
    if resolved.is_empty() {
        return;
    }

    for platform in &lock.platforms {
        let platform_id = platform.platform.to_string();
        for artifact in &platform.artifacts {
            scan_lock_package(&artifact.as_package(), &resolved, &platform_id);
        }
        for module in &platform.modules {
            for package in &module.packages {
                if package.workspace_module.is_none() && package.system_path.is_none() {
                    continue;
                }
                scan_lock_package(
                    &LockPackage {
                        group_id: package.coordinate.group.clone(),
                        artifact_id: package.coordinate.artifact.clone(),
                        version: package.coordinate.version.clone(),
                        snapshot_timestamp: None,
                        packaging: package.coordinate.packaging.clone(),
                        classifier: package.coordinate.classifier.clone(),
                        repo_url: package.workspace_module.clone().unwrap_or_default(),
                        checksum: None,
                        system_path: package.system_path.clone(),
                        direct_scope: package.direct_scope.clone(),
                        extra: package.extra.clone(),
                    },
                    &resolved,
                    &platform_id,
                );
            }
        }
    }
}

fn scan_lock_package(pkg: &LockPackage, resolved: &[(String, String)], platform: &str) {
    let fields: [(&str, &str); 7] = [
        ("group_id", pkg.group_id.as_str()),
        ("artifact_id", pkg.artifact_id.as_str()),
        ("version", pkg.version.as_str()),
        ("packaging", pkg.packaging.as_str()),
        ("classifier", pkg.classifier.as_deref().unwrap_or("")),
        ("repo_url", pkg.repo_url.as_str()),
        ("system_path", pkg.system_path.as_deref().unwrap_or("")),
    ];

    for (name, value) in resolved {
        // Short env values false-positive on version numbers; 4 bytes is the
        // empirically chosen floor.
        if value.len() < 4 {
            continue;
        }
        for (field, content) in fields {
            if content.is_empty() {
                continue;
            }
            if content.contains(value.as_str()) {
                tracing::warn!(
                    target: "rv::sec::warn_collect",
                    sec_code = "ENV_VALUE_IN_LOCKFILE",
                    env_var = %name,
                    field = field,
                    coord = %pkg.format_coord(),
                    platform = platform,
                    "lockfile field contains the resolved value of an allowlisted ${{env.X}} \
                     substitution; the secret may have leaked into a tracked artifact"
                );
            }
        }
    }
}

/// Walk every package's checksum and either rewrite the algorithm field to
/// its canonical spelling or return a precise error pointing at the
/// offending entry. Also validates that the digest is the correct length
/// and contains only hex characters for the detected algorithm, so a
/// hand-edited lockfile with a truncated digest fails here rather than
/// later with a cryptic "invalid blob id length" message. Uppercase hex is
/// accepted and canonicalized to lowercase, since downstream comparisons
/// (lockfile equality, the `--frozen` match) are byte-wise.
fn normalize_lockfile_checksums(lock: &mut Lockfile, source: &str) -> Result<(), ConfigError> {
    for platform in &mut lock.platforms {
        let platform_id = platform.platform.to_string();
        for artifact in &mut platform.artifacts {
            let coord = artifact.coordinate.format_coord();
            for checksum in &mut artifact.checksums {
                normalize_checksum(checksum, &coord, &platform_id, source)?;
            }
            // Same canonicalization the checksum digests get: uppercase hex
            // is accepted on the way in and lowered, since every downstream
            // comparison (blob id, lockfile equality) is byte-wise.
            if let Some(digest) = artifact.pom_sha256.as_mut() {
                digest.make_ascii_lowercase();
            }
        }
    }
    Ok(())
}

fn normalize_checksum(
    checksum: &mut Checksum,
    coord: &str,
    platform_id: &str,
    source: &str,
) -> Result<(), ConfigError> {
    match normalize_checksum_algorithm(&checksum.algorithm) {
        Some(canonical) => {
            if checksum.algorithm != canonical {
                checksum.algorithm = canonical.to_string();
            }
            let expected_len = if canonical == "sha256" { 64 } else { 40 };
            if checksum.digest.len() != expected_len
                || !checksum.digest.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(ConfigError::InvalidLockfile(format!(
                    "invalid {canonical} digest for {coord} \
                     (platform {platform_id}) in {source}: \
                     expected {expected_len} hex characters, got {:?}",
                    checksum.digest,
                )));
            }
            checksum.digest.make_ascii_lowercase();
            Ok(())
        }
        None => Err(ConfigError::InvalidLockfile(format!(
            "unsupported checksum algorithm '{algo}' on {coord} \
             (platform {platform_id}) in {source}; \
             supported algorithms are sha256 and sha1",
            algo = checksum.algorithm,
        ))),
    }
}

// `Eq` is intentionally not derived: the `extra` field's `toml::Value`
// values can hold floats, which only implement `PartialEq`.
#[derive(Debug, Clone, PartialEq)]
pub struct LockPlatform {
    pub platform: Platform,
    /// Hash of this platform's reactor model: every active module's path,
    /// effective GAV, and POM bytes, the active profile ids, and the bytes of
    /// each local parent POM the resolver accepts (inside the reactor's parent
    /// boundary and carrying the declared parent coordinates). Repository
    /// configuration is deliberately absent and belongs to the top-level
    /// `config_hash`.
    pub model_hash: String,
    pub artifacts: Vec<LockArtifact>,
    pub modules: Vec<LockModule>,
    pub extra: BTreeMap<String, toml::Value>,
}

impl LockPlatform {
    pub fn single_module(
        platform: Platform,
        model_hash: impl Into<String>,
        pom_path: impl Into<String>,
        gav: LockGav,
        packaging: impl Into<String>,
        packages: Vec<LockPackage>,
        edges: Vec<LockEdge>,
    ) -> Self {
        let model_hash = model_hash.into();
        let (module_packages, artifacts) = split_flat_packages(&packages);
        let mut value = Self {
            platform,
            model_hash: if model_hash.is_empty() {
                LEGACY_MODEL_HASH.to_string()
            } else {
                model_hash
            },
            artifacts,
            modules: vec![LockModule {
                path: pom_path.into(),
                gav,
                packaging: packaging.into(),
                packages: module_packages,
                edges,
                extra: BTreeMap::new(),
            }],
            extra: BTreeMap::new(),
        };
        value.canonicalize();
        value
    }

    /// Return the platform's aggregated external artifacts in the package
    /// shape that download and export consumers expect.
    pub fn external_packages(&self) -> Vec<LockPackage> {
        self.artifacts
            .iter()
            .map(LockArtifact::as_package)
            .collect()
    }

    fn from_v4(
        platform: Platform,
        model_hash: String,
        artifacts: Vec<LockArtifact>,
        modules: Vec<LockModule>,
        extra: BTreeMap<String, toml::Value>,
    ) -> Self {
        Self {
            platform,
            model_hash,
            artifacts,
            modules,
            extra,
        }
    }

    fn from_legacy(
        platform: Platform,
        packages: Vec<LockPackage>,
        edges: Vec<LockEdge>,
        extra: BTreeMap<String, toml::Value>,
    ) -> Self {
        let mut value = Self::single_module(
            platform,
            LEGACY_MODEL_HASH,
            "pom.xml",
            LockGav::legacy_root(),
            "pom",
            packages,
            edges,
        );
        value.extra = extra;
        value
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
            artifact.checksums.sort_by(|left, right| {
                left.algorithm
                    .cmp(&right.algorithm)
                    .then(left.digest.cmp(&right.digest))
            });
            artifact.checksums.dedup();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockCoordinate {
    pub group: String,
    pub artifact: String,
    pub version: String,
    pub packaging: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier: Option<String>,
}

impl LockCoordinate {
    pub fn new(
        group: impl Into<String>,
        artifact: impl Into<String>,
        version: impl Into<String>,
        packaging: impl Into<String>,
        classifier: Option<String>,
    ) -> Self {
        Self {
            group: group.into(),
            artifact: artifact.into(),
            version: version.into(),
            packaging: packaging.into(),
            classifier,
        }
    }

    pub fn format_coord(&self) -> String {
        let mut coord = format!(
            "{}:{}:{}:{}",
            self.group, self.artifact, self.version, self.packaging
        );
        if let Some(classifier) = self.classifier.as_deref()
            && !classifier.is_empty()
        {
            coord.push(':');
            coord.push_str(classifier);
        }
        coord
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockGav {
    pub group: String,
    pub artifact: String,
    pub version: String,
}

impl LockGav {
    pub fn new(
        group: impl Into<String>,
        artifact: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            group: group.into(),
            artifact: artifact.into(),
            version: version.into(),
        }
    }

    /// Synthetic GAV stamped on the single module minted when a schema 1-3
    /// lockfile is adapted into the schema-4 reactor view.
    pub fn legacy_root() -> Self {
        Self::new(LEGACY_ROOT_GROUP, LEGACY_ROOT_ARTIFACT, LEGACY_ROOT_VERSION)
    }

    /// True for the placeholder minted by legacy-lock adaptation. Callers that
    /// show a GAV to users must check this first: the value is a sentinel, not
    /// a coordinate anything can resolve.
    pub fn is_legacy_placeholder(&self) -> bool {
        self.group == LEGACY_ROOT_GROUP
            && self.artifact == LEGACY_ROOT_ARTIFACT
            && self.version == LEGACY_ROOT_VERSION
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LockArtifact {
    pub coordinate: LockCoordinate,
    pub repo_url: String,
    pub checksums: Vec<Checksum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<LockSnapshot>,
    /// SHA-256 of the companion `.pom` bytes `rv sync` put in the content
    /// store for this coordinate, when it has one.
    ///
    /// `checksums` pins the artifact payload; this pins the POM shipped
    /// beside it. The store's coordinate index maps a key to whichever blob
    /// was written last, so a later sync of another project sharing the store
    /// can repoint `(g, a, v, pom)` at different bytes. `rv export-m2` fetches
    /// this digest from the content-addressed store directly, so an exported
    /// POM is always the one this lockfile was resolved against.
    ///
    /// `None` on locks written before the field existed (and on any
    /// coordinate whose POM the store does not hold): export falls back to the
    /// coordinate index, unpinned, exactly as it behaved before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pom_sha256: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

impl LockArtifact {
    /// Convert an aggregate schema-4 artifact row to the legacy package form
    /// understood by repository/export code.
    pub fn as_package(&self) -> LockPackage {
        let version = match self.snapshot.as_ref() {
            Some(snapshot) => snapshot.resolved_version(&self.coordinate.version),
            None => self.coordinate.version.clone(),
        };
        LockPackage {
            group_id: self.coordinate.group.clone(),
            artifact_id: self.coordinate.artifact.clone(),
            version,
            snapshot_timestamp: self.snapshot.as_ref().map(LockSnapshot::legacy_value),
            packaging: self.coordinate.packaging.clone(),
            classifier: self.coordinate.classifier.clone(),
            repo_url: self.repo_url.clone(),
            checksum: preferred_checksum(&self.checksums),
            system_path: None,
            direct_scope: None,
            extra: self.extra.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockSnapshot {
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_number: Option<u32>,
}

impl LockSnapshot {
    fn from_legacy(value: &str) -> Self {
        if let Some((timestamp, build)) = value.rsplit_once('-')
            && is_snapshot_timestamp_str(timestamp)
            && let Ok(build_number) = build.parse::<u32>()
        {
            return Self {
                timestamp: timestamp.to_string(),
                build_number: Some(build_number),
            };
        }
        Self {
            timestamp: value.to_string(),
            build_number: None,
        }
    }

    fn legacy_value(&self) -> String {
        match self.build_number {
            Some(build) => format!("{}-{build}", self.timestamp),
            None => self.timestamp.clone(),
        }
    }

    fn resolved_version(&self, base_version: &str) -> String {
        let Some(build_number) = self.build_number else {
            return base_version.to_string();
        };
        let Some(base) = base_version.strip_suffix("-SNAPSHOT") else {
            return base_version.to_string();
        };
        format!("{base}-{}-{build_number}", self.timestamp)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LockModule {
    pub path: String,
    pub gav: LockGav,
    pub packaging: String,
    pub packages: Vec<LockModulePackage>,
    pub edges: Vec<LockEdge>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

impl LockModule {
    /// True when this is the synthetic root minted for a schema 1-3 lockfile:
    /// its GAV is [`LockGav::legacy_root`], a placeholder rather than a real
    /// coordinate. Display and module-selection code must not present it as
    /// one; name [`LockModule::path`] instead.
    pub fn is_legacy_placeholder(&self) -> bool {
        self.gav.is_legacy_placeholder()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LockModulePackage {
    pub coordinate: LockCoordinate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_path: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

fn split_flat_packages(packages: &[LockPackage]) -> (Vec<LockModulePackage>, Vec<LockArtifact>) {
    let module_packages = packages
        .iter()
        .map(|package| LockModulePackage {
            coordinate: LockCoordinate::new(
                &package.group_id,
                &package.artifact_id,
                &package.version,
                &package.packaging,
                package.classifier.clone(),
            ),
            direct_scope: package.direct_scope.clone(),
            workspace_module: None,
            system_path: package.system_path.clone(),
            extra: package.extra.clone(),
        })
        .collect();

    let mut artifacts = BTreeMap::new();
    for package in packages {
        if package.system_path.is_some() {
            continue;
        }
        let coordinate = LockCoordinate::new(
            &package.group_id,
            &package.artifact_id,
            &package.version,
            &package.packaging,
            package.classifier.clone(),
        );
        artifacts.entry(coordinate.clone()).or_insert_with(|| {
            let snapshot = package.snapshot_timestamp.as_deref().map(|value| {
                let mut snapshot = LockSnapshot::from_legacy(value);
                if snapshot.build_number.is_none() {
                    snapshot.build_number = snapshot_build_number(&package.version);
                }
                snapshot
            });
            LockArtifact {
                coordinate,
                repo_url: package.repo_url.clone(),
                checksums: package.checksum.clone().into_iter().collect(),
                snapshot,
                pom_sha256: None,
                extra: BTreeMap::new(),
            }
        });
    }

    (module_packages, artifacts.into_values().collect())
}

fn snapshot_build_number(version: &str) -> Option<u32> {
    let mut parts = version.rsplitn(3, '-');
    let build = parts.next()?;
    let timestamp = parts.next()?;
    let _base = parts.next()?;
    if !is_snapshot_timestamp_str(timestamp) {
        return None;
    }
    build.parse().ok()
}

fn preferred_checksum(checksums: &[Checksum]) -> Option<Checksum> {
    checksums
        .iter()
        .find(|checksum| checksum.algorithm == "sha256")
        .or_else(|| checksums.first())
        .cloned()
}

fn canonicalize_module(module: &mut LockModule) {
    let mut indexed: Vec<(usize, LockModulePackage)> = std::mem::take(&mut module.packages)
        .into_iter()
        .enumerate()
        .collect();
    indexed.sort_by(|(_, left), (_, right)| {
        left.coordinate
            .cmp(&right.coordinate)
            .then(left.workspace_module.cmp(&right.workspace_module))
            .then(left.system_path.cmp(&right.system_path))
            .then(left.direct_scope.cmp(&right.direct_scope))
    });

    let mut remap = vec![0; indexed.len()];
    let mut packages = Vec::with_capacity(indexed.len());
    for (new_index, (old_index, package)) in indexed.into_iter().enumerate() {
        remap[old_index] = new_index;
        packages.push(package);
    }
    module.packages = packages;
    for edge in &mut module.edges {
        if let Some(mapped) = remap.get(edge.from) {
            edge.from = *mapped;
        }
        if let Some(mapped) = remap.get(edge.to) {
            edge.to = *mapped;
        }
    }
    module.edges.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then(left.to.cmp(&right.to))
            .then(left.scope.cmp(&right.scope))
            .then(left.optional.cmp(&right.optional))
    });
}

// `Eq` is intentionally not derived: the `extra` field's `toml::Value`
// values can hold floats, which only implement `PartialEq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LockPackage {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_timestamp: Option<String>,
    pub packaging: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<Checksum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_scope: Option<String>,
    /// Preserve unrecognized nested fields so they survive a read-write
    /// round-trip when a newer Raeva adds package-level keys.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

impl LockPackage {
    pub fn format_coord(&self) -> String {
        let mut coord = format!(
            "{}:{}:{}:{}",
            self.group_id, self.artifact_id, self.version, self.packaging
        );
        if let Some(classifier) = self.classifier.as_deref()
            && !classifier.is_empty()
        {
            coord.push(':');
            coord.push_str(classifier);
        }
        coord
    }

    /// Returns true when the package refers to a Maven SNAPSHOT, either via an
    /// explicit `-SNAPSHOT` suffix on the version or via a recorded
    /// `snapshot_timestamp` field (the timestamped form `1.0-20240101.010101-7`).
    pub fn is_snapshot(&self) -> bool {
        self.snapshot_timestamp.is_some()
            || self.version.ends_with("-SNAPSHOT")
            || is_timestamped_snapshot_version(&self.version)
    }

    /// Returns the base snapshot version used as the on-disk directory name
    /// in a Maven local repository.
    ///
    /// * For release versions this is the version verbatim (e.g. `1.0`).
    /// * For `-SNAPSHOT` versions this is the version verbatim (e.g.
    ///   `1.0-SNAPSHOT`).
    /// * For timestamped snapshot versions such as `1.0-20240101.010101-7`
    ///   this strips the timestamp suffix and appends `-SNAPSHOT`, returning
    ///   `1.0-SNAPSHOT`.
    pub fn base_snapshot_version(&self) -> String {
        if self.version.ends_with("-SNAPSHOT") {
            return self.version.clone();
        }
        if let Some(base) = strip_timestamp_suffix(&self.version) {
            return format!("{base}-SNAPSHOT");
        }
        self.version.clone()
    }
}

fn is_timestamped_snapshot_version(version: &str) -> bool {
    strip_timestamp_suffix(version).is_some()
}

// `<base>-YYYYMMDD.HHMMSS-N` -> `<base>`.
fn strip_timestamp_suffix(version: &str) -> Option<&str> {
    let mut parts = version.rsplitn(3, '-');
    let build = parts.next()?;
    let timestamp = parts.next()?;
    let base = parts.next()?;
    if base.is_empty() {
        return None;
    }
    if build.is_empty() || !build.as_bytes().iter().all(u8::is_ascii_digit) {
        return None;
    }
    if !is_snapshot_timestamp_str(timestamp) {
        return None;
    }
    Some(base)
}

fn is_snapshot_timestamp_str(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 15 || bytes[8] != b'.' {
        return false;
    }
    for (idx, byte) in bytes.iter().enumerate() {
        if idx == 8 {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
    }
    true
}

// `Eq` is intentionally not derived: the `extra` field's `toml::Value`
// values can hold floats, which only implement `PartialEq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LockEdge {
    pub from: usize,
    pub to: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default)]
    pub optional: bool,
    /// Preserve unrecognized nested fields so they survive a read-write
    /// round-trip when a newer Raeva adds edge-level keys.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum {
    pub algorithm: String,
    pub digest: String,
}

impl Checksum {
    pub fn new(algorithm: impl Into<String>, digest: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            digest: digest.into(),
        }
    }
}

/// Normalize a lockfile checksum algorithm string to a canonical form.
///
/// Accepts case-insensitive `sha256`, `sha-256`, `sha1`, `sha-1` and returns
/// the canonical lowercase, dash-free form. Returns `None` for anything else
/// so the caller can raise a clear error pointing at the offending entry.
///
/// Normalizing once at parse time means downstream consumers (`rv-repo::sync`,
/// `rv-cli` commands, `rv-resolver::policy`) do not silently drop a perfectly
/// valid pin written as `"sha-256"`.
pub fn normalize_checksum_algorithm(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("sha256") || trimmed.eq_ignore_ascii_case("sha-256") {
        Some("sha256")
    } else if trimmed.eq_ignore_ascii_case("sha1") || trimmed.eq_ignore_ascii_case("sha-1") {
        Some("sha1")
    } else {
        None
    }
}

/// Lockfile `[metadata]` key under which `rv sync` records one line per
/// support POM (a parent or an imported BOM): the id of the repository that
/// served it, so `rv export-m2` labels its `_remote.repositories` marker
/// correctly even when a parent/BOM resolves from a different repository than
/// its child, and the SHA-256 of its bytes, so export ships that exact blob
/// instead of whatever the store's coordinate index points at later.
///
/// The key name predates the digest field and is kept for on-disk stability.
pub const LOCK_SUPPORT_POMS_KEY: &str = "support_repo_ids";

/// One decoded `[metadata]` support-POM line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportPomLine {
    /// Id of the repository that served the POM. Empty when that repository
    /// carries no id of its own, which says only that the POM's
    /// `_remote.repositories` marker has no id to name.
    pub repo_id: String,
    /// SHA-256 of the exact bytes to export. `None` on a two-field line,
    /// written before the digest existed; such a POM stays unpinned and is
    /// looked up through the store's coordinate index.
    pub sha256: Option<String>,
}

/// Encode support-POM provenance as the deterministic `g:a:v\tid[\tsha256]`
/// block `rv sync` stores under [`LOCK_SUPPORT_POMS_KEY`].
///
/// This is the write half of the codec [`decode_support_pom_lines`] reads.
/// Both halves live here so `rv sync` and `rv export-m2` cannot drift apart
/// on what a line means. Encoding rejects anything the strict decoder would
/// refuse, so a lockfile can never be written with lines that later read back
/// as a weakened pin.
pub fn encode_support_pom_lines(
    entries: &BTreeMap<String, SupportPomLine>,
) -> Result<String, ConfigError> {
    let mut out = String::new();
    for (coord, line) in entries {
        validate_support_pom_coord(coord)?;
        if line.repo_id.contains('\t') || line.repo_id.contains('\n') {
            return Err(ConfigError::InvalidLockfile(format!(
                "repository id for support POM '{coord}' must not contain a tab or newline"
            )));
        }
        if let Some(digest) = line.sha256.as_deref()
            && !is_sha256_hex(digest)
        {
            return Err(ConfigError::InvalidLockfile(format!(
                "sha256 '{digest}' for support POM '{coord}' must be 64 lowercase hex characters"
            )));
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(coord);
        out.push('\t');
        out.push_str(&line.repo_id);
        if let Some(digest) = line.sha256.as_deref() {
            out.push('\t');
            out.push_str(digest);
        }
    }
    Ok(out)
}

/// Decode the [`LOCK_SUPPORT_POMS_KEY`] block, strictly.
///
/// A line carries exactly two tab-separated fields (`g:a:v\tid`, the legacy
/// unpinned form) or exactly three (`g:a:v\tid\tsha256`). Anything else — a
/// stray field, a blank line, a digest that is not 64 lowercase hex
/// characters, a coordinate that is not `g:a:v`, or the same coordinate twice
/// — is a lockfile error rather than a line quietly skipped or a pin quietly
/// dropped. A weakened pin is the failure mode this codec exists to prevent:
/// export addresses these blobs by content precisely because the store's
/// coordinate index is last-writer-wins, so falling back to the index on a
/// malformed line would export a POM the lockfile was never resolved against.
///
/// This mirrors the read-time validation [`LockArtifact::pom_sha256`] gets.
pub fn decode_support_pom_lines(
    encoded: &str,
) -> Result<BTreeMap<String, SupportPomLine>, ConfigError> {
    let mut decoded: BTreeMap<String, SupportPomLine> = BTreeMap::new();
    for raw in encoded.lines() {
        let mut fields = raw.split('\t');
        let coord = fields.next().unwrap_or_default();
        let Some(repo_id) = fields.next() else {
            return Err(ConfigError::InvalidLockfile(format!(
                "malformed {LOCK_SUPPORT_POMS_KEY} entry {raw:?}: expected \
                 'g:a:v<TAB>repo_id' or 'g:a:v<TAB>repo_id<TAB>sha256'"
            )));
        };
        let sha256 = fields.next();
        if fields.next().is_some() {
            return Err(ConfigError::InvalidLockfile(format!(
                "malformed {LOCK_SUPPORT_POMS_KEY} entry {raw:?}: too many tab-separated fields"
            )));
        }
        validate_support_pom_coord(coord)?;
        if let Some(digest) = sha256
            && !is_sha256_hex(digest)
        {
            return Err(ConfigError::InvalidLockfile(format!(
                "sha256 '{digest}' for support POM '{coord}' must be 64 lowercase hex characters"
            )));
        }
        let line = SupportPomLine {
            repo_id: repo_id.to_string(),
            sha256: sha256.map(str::to_string),
        };
        if decoded.insert(coord.to_string(), line).is_some() {
            return Err(ConfigError::InvalidLockfile(format!(
                "duplicate {LOCK_SUPPORT_POMS_KEY} entry for support POM '{coord}'"
            )));
        }
    }
    Ok(decoded)
}

fn validate_support_pom_coord(coord: &str) -> Result<(), ConfigError> {
    let mut parts = coord.split(':');
    let well_formed = matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(group), Some(artifact), Some(version), None)
            if !group.is_empty() && !artifact.is_empty() && !version.is_empty()
    );
    if !well_formed {
        return Err(ConfigError::InvalidLockfile(format!(
            "support POM coordinate {coord:?} in {LOCK_SUPPORT_POMS_KEY} must be 'group:artifact:version'"
        )));
    }
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let base_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rv.lock");
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut rand_bytes = [0u8; 6];
    OsRng.fill_bytes(&mut rand_bytes);
    let rand_hex = hex::encode(rand_bytes);
    let file_name = format!("{base_name}.tmp.{pid}.{nanos}.{rand_hex}");
    path.with_file_name(file_name)
}

/// Atomically replace a file, handling Windows limitations.
///
/// On Unix, `fs::rename()` atomically replaces the destination; no special handling needed.
///
/// On Windows, `fs::rename()` fails if the destination already exists.  A naive
/// remove-then-rename approach loses the lockfile if the rename fails after the
/// remove.  Instead we:
///
/// 1. Rename the existing destination to a `.bak` sidecar (if it exists).
/// 2. Rename `src` → `dst`.
/// 3. On success: delete the `.bak` sidecar (best-effort).
///    On failure: attempt to rename `.bak` back to `dst` to restore the original.
fn atomic_replace(src: &Path, dst: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::rename(src, dst)
    }
    #[cfg(not(unix))]
    {
        // Build a sidecar path for the existing destination, e.g. `rv.lock.bak`.
        let bak_path = {
            let mut p = dst.as_os_str().to_os_string();
            p.push(".bak");
            std::path::PathBuf::from(p)
        };

        // Step 1: move the existing destination aside (ignore errors if it
        // doesn't exist yet).
        let had_bak = if dst.exists() {
            fs::rename(dst, &bak_path)?;
            true
        } else {
            false
        };

        // Step 2: promote the temp file to the final destination.
        match fs::rename(src, dst) {
            Ok(()) => {
                // Step 3 (success): remove the sidecar.
                if had_bak {
                    let _ = fs::remove_file(&bak_path);
                }
                Ok(())
            }
            Err(rename_err) => {
                // Step 3 (failure): try to restore the previous lockfile.
                if had_bak {
                    if let Err(restore_err) = fs::rename(&bak_path, dst) {
                        // Log but still return the original rename error so
                        // callers see the real problem.
                        tracing::warn!(
                            bak = %bak_path.display(),
                            dst = %dst.display(),
                            error = %restore_err,
                            "atomic_replace: rename failed and backup restore also failed;                              lockfile may be missing"
                        );
                    }
                }
                Err(rename_err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Checksum, LOCKFILE_SCHEMA_VERSION, LockEdge, LockGav, LockPackage, LockPlatform, Lockfile,
    };
    use crate::error::ConfigError;
    use crate::platform::Platform;
    use std::collections::BTreeMap;
    use std::fs;

    fn platform_from_flat(
        platform: Platform,
        packages: Vec<LockPackage>,
        edges: Vec<LockEdge>,
    ) -> LockPlatform {
        LockPlatform::single_module(
            platform,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "pom.xml",
            LockGav::new("org.example", "root", "1.0.0"),
            "jar",
            packages,
            edges,
        )
    }

    #[test]
    fn write_and_read_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");

        let platform = Platform::new("linux", "x86_64").unwrap();
        let package = LockPackage {
            group_id: "org.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(Checksum::new(
                "sha256",
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )),
            system_path: None,
            direct_scope: None,
            extra: BTreeMap::new(),
        };
        let lock = Lockfile {
            schema_version: LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![platform_from_flat(
                platform,
                vec![package],
                vec![LockEdge {
                    from: 0,
                    to: 0,
                    scope: Some("compile".to_string()),
                    optional: false,
                    extra: BTreeMap::new(),
                }],
            )],
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        };

        lock.write_atomic(&path).unwrap();
        let loaded = Lockfile::read(&path).unwrap();
        assert_eq!(loaded, lock);
    }

    #[test]
    fn rejects_unsupported_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        fs::write(
            &path,
            format!("schema_version = {}\n", LOCKFILE_SCHEMA_VERSION + 1),
        )
        .unwrap();
        assert!(matches!(
            Lockfile::read(&path),
            Err(ConfigError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn round_trip_all_field_combinations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-roundtrip.lock");

        let platform = Platform::new("macos", "aarch64").unwrap();

        let pkg_minimal = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "lib-a".to_string(),
            version: "2.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: Some("sources".to_string()),
            repo_url: "https://central.example/".to_string(),
            checksum: None,
            system_path: None,
            direct_scope: None,
            extra: BTreeMap::new(),
        };

        let pkg_with_checksum = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "lib-b".to_string(),
            version: "3.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://central.example/".to_string(),
            checksum: Some(Checksum::new(
                "sha1",
                "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            )),
            system_path: None,
            direct_scope: Some("compile".to_string()),
            extra: BTreeMap::new(),
        };

        let pkg_with_system_path = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "lib-c".to_string(),
            version: "4.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://central.example/".to_string(),
            checksum: Some(Checksum::new(
                "sha256",
                "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
            )),
            system_path: Some("/opt/libs/lib-c.jar".to_string()),
            direct_scope: None,
            extra: BTreeMap::new(),
        };

        let lock = Lockfile {
            schema_version: LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![platform_from_flat(
                platform,
                vec![pkg_minimal, pkg_with_checksum, pkg_with_system_path],
                vec![
                    LockEdge {
                        from: 0,
                        to: 1,
                        scope: Some("compile".to_string()),
                        optional: false,
                        extra: BTreeMap::new(),
                    },
                    LockEdge {
                        from: 1,
                        to: 2,
                        scope: Some("runtime".to_string()),
                        optional: true,
                        extra: BTreeMap::new(),
                    },
                ],
            )],
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        };

        lock.write_atomic(&path).unwrap();
        let loaded = Lockfile::read(&path).unwrap();
        assert_eq!(loaded, lock);
    }

    #[test]
    fn parse_v1_lockfile() {
        let v1_format = r#"
schema_version = 1

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/maven2/"

[platforms.packages.checksum]
algorithm = "sha256"
digest = "deadbeef"
"#;

        let lock: Lockfile = toml::from_str(v1_format).unwrap();
        assert_eq!(lock.schema_version, 1);
        assert_eq!(lock.platforms.len(), 1);
    }

    #[test]
    fn lockfile_default_has_v4_schema() {
        let lock = Lockfile::new();
        assert_eq!(lock.schema_version, LOCKFILE_SCHEMA_VERSION);
        assert!(lock.platforms.is_empty());
        assert!(lock.metadata.is_empty());
    }

    #[test]
    fn parse_v2_lockfile_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-v2.lock");
        let v2_lock = r#"
schema_version = 2

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.2.3"
packaging = "jar"
repo_url = "https://repo.example/maven2/"
"#;

        fs::write(&path, v2_lock).unwrap();
        let lock = Lockfile::read(&path).unwrap();

        assert_eq!(lock.schema_version, 2);
        assert_eq!(lock.platforms.len(), 1);
        assert_eq!(lock.platforms[0].modules[0].packages.len(), 1);
        let coordinate = &lock.platforms[0].modules[0].packages[0].coordinate;
        assert_eq!(coordinate.group, "org.example");
        assert_eq!(coordinate.artifact, "demo");
        assert_eq!(coordinate.version, "1.2.3");
    }

    #[test]
    fn parse_v3_lockfile_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-v3.lock");
        let v3_lock = r#"
schema_version = 3
config_hash = "abc123"

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.2.3"
packaging = "jar"
repo_url = "https://repo.example/maven2/"
"#;

        fs::write(&path, v3_lock).unwrap();
        let lock = Lockfile::read(&path).unwrap();

        assert_eq!(lock.schema_version, 3);
        assert_eq!(lock.config_hash.as_deref(), Some("abc123"));
        assert_eq!(lock.platforms.len(), 1);
    }

    #[test]
    fn write_atomic_upgrades_schema_to_v4() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-upgrade.lock");
        let mut lock = Lockfile::new();
        lock.schema_version = 2;
        lock.platforms.push(platform_from_flat(
            Platform::new("linux", "x86_64").unwrap(),
            vec![LockPackage {
                group_id: "org.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.2.3".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                checksum: None,
                system_path: None,
                direct_scope: None,
                extra: BTreeMap::new(),
            }],
            vec![],
        ));

        lock.write_atomic(&path).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("schema_version = 4"));
        assert!(!raw.contains("schema_version = 2"));

        let parsed = Lockfile::read(&path).unwrap();
        assert_eq!(parsed.schema_version, LOCKFILE_SCHEMA_VERSION);
        assert_eq!(
            parsed.platforms[0].modules[0].packages[0]
                .coordinate
                .artifact,
            "demo"
        );
    }

    #[test]
    fn parse_lockfile_with_unknown_future_fields_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-future-fields.lock");
        let future_lock = r#"
schema_version = 3
future_flag = true

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.2.3"
packaging = "jar"
repo_url = "https://repo.example/maven2/"
future_package_field = "ignored"
"#;

        fs::write(&path, future_lock).unwrap();
        let lock = Lockfile::read(&path).unwrap();

        assert_eq!(lock.schema_version, 3);
        assert_eq!(lock.platforms.len(), 1);
        assert_eq!(
            lock.platforms[0].modules[0].packages[0].coordinate.artifact,
            "demo"
        );
    }

    #[test]
    fn parse_schema_version_99_returns_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-v99.lock");
        let unsupported_lock = r#"
schema_version = 99
"#;

        fs::write(&path, unsupported_lock).unwrap();
        let err = Lockfile::read(&path).unwrap_err();
        let err_message = err.to_string();

        match &err {
            ConfigError::UnsupportedSchema { found, expected } => {
                assert_eq!(*found, 99);
                assert_eq!(*expected, LOCKFILE_SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchema error, got {other}"),
        }

        assert!(
            err_message.contains("unsupported lockfile schema version 99"),
            "unexpected error message: {err_message}"
        );
    }

    /// Verify that `write_atomic` safely replaces an existing lockfile without
    /// losing it: after the write the file must contain the *new* data, and no
    /// stale `.bak` sidecar should remain.
    ///
    /// This test is meaningful on all platforms.  On Windows it exercises the
    /// rename-to-bak path; on Unix it exercises the single atomic rename path.
    #[test]
    fn write_atomic_replaces_existing_lockfile_safely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");

        // Write an initial lockfile.
        let initial = Lockfile::new();
        initial.write_atomic(&path).unwrap();

        // Write a second lockfile with a distinguishable config_hash.
        let mut updated = Lockfile::new();
        updated.config_hash = Some("updated-hash-abc123".to_string());
        updated.write_atomic(&path).unwrap();

        // The file must exist and contain the new data.
        let loaded = Lockfile::read(&path).unwrap();
        assert_eq!(
            loaded.config_hash.as_deref(),
            Some("updated-hash-abc123"),
            "lockfile should contain updated content"
        );

        // No stale `.bak` sidecar should remain on the filesystem.
        let bak = path.with_extension("lock.bak");
        assert!(
            !bak.exists(),
            "stale .bak sidecar should have been removed after successful write"
        );
    }

    fn mk_pkg(version: &str, snapshot_timestamp: Option<&str>) -> LockPackage {
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "foo".to_string(),
            version: version.to_string(),
            snapshot_timestamp: snapshot_timestamp.map(str::to_string),
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: String::new(),
            checksum: None,
            system_path: None,
            direct_scope: None,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn base_snapshot_version_for_release_returns_version_verbatim() {
        let pkg = mk_pkg("1.0", None);
        assert_eq!(pkg.base_snapshot_version(), "1.0");
        assert!(!pkg.is_snapshot());
    }

    #[test]
    fn base_snapshot_version_for_qualifier_release_is_verbatim() {
        // "rc1" is a qualifier, not a timestamp: must not be treated as a snapshot.
        let pkg = mk_pkg("1.0-rc1", None);
        assert_eq!(pkg.base_snapshot_version(), "1.0-rc1");
        assert!(!pkg.is_snapshot());
    }

    #[test]
    fn base_snapshot_version_for_snapshot_suffix_returns_verbatim() {
        let pkg = mk_pkg("1.0-SNAPSHOT", None);
        assert_eq!(pkg.base_snapshot_version(), "1.0-SNAPSHOT");
        assert!(pkg.is_snapshot());
    }

    #[test]
    fn base_snapshot_version_for_timestamped_strips_timestamp() {
        let pkg = mk_pkg("1.0-20240101.010101-7", Some("20240101.010101"));
        assert_eq!(pkg.base_snapshot_version(), "1.0-SNAPSHOT");
        assert!(pkg.is_snapshot());
    }

    #[test]
    fn base_snapshot_version_detects_timestamp_without_explicit_field() {
        // Even if snapshot_timestamp is missing, a `1.0-YYYYMMDD.HHMMSS-N`
        // version pattern should still be detected as a snapshot.
        let pkg = mk_pkg("2.3.4-20240501.123456-12", None);
        assert!(pkg.is_snapshot());
        assert_eq!(pkg.base_snapshot_version(), "2.3.4-SNAPSHOT");
    }

    /// Verify that `write_atomic` works correctly when the destination does
    /// not yet exist (first-write case).
    #[test]
    fn write_atomic_creates_new_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-new.lock");

        // File must not exist before the write.
        assert!(!path.exists());

        let lock = Lockfile::new();
        lock.write_atomic(&path).unwrap();

        assert!(path.exists(), "lockfile should have been created");
        let loaded = Lockfile::read(&path).unwrap();
        assert_eq!(loaded.schema_version, LOCKFILE_SCHEMA_VERSION);

        // No sidecar created when target didn't previously exist.
        let bak = path.with_extension("lock.bak");
        assert!(!bak.exists(), "no .bak should be created on first write");
    }

    /// A lockfile with `algorithm = "sha-256"` (dash form) must load
    /// without error and be normalized to the canonical `"sha256"`. The
    /// previous code did an exact `eq_ignore_ascii_case("sha256")` compare
    /// in `sync.rs`, so the dash form silently dropped the pin.
    #[test]
    fn loads_sha_dash_256_and_normalizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-dash.lock");
        let raw = r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"

[platforms.packages.checksum]
algorithm = "sha-256"
digest = "0000000000000000000000000000000000000000000000000000000000000001"
"#;
        fs::write(&path, raw).unwrap();
        let lock = Lockfile::read(&path).expect("dash form should load");
        let cs = lock.platforms[0].artifacts[0]
            .checksums
            .first()
            .expect("checksum present");
        assert_eq!(
            cs.algorithm, "sha256",
            "algorithm must be normalized to canonical form"
        );
    }

    /// An `algorithm = "md5"` pin must be rejected at load time with a
    /// clear error pointing at the offending entry, so the user never sees
    /// a sync that silently accepts an unverifiable pin.
    #[test]
    fn rejects_unsupported_checksum_algorithm_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-md5.lock");
        let raw = r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"

[platforms.packages.checksum]
algorithm = "md5"
digest = "1234567890abcdef1234567890abcdef"
"#;
        fs::write(&path, raw).unwrap();
        let err = Lockfile::read(&path).expect_err("md5 must be rejected");
        match &err {
            ConfigError::InvalidLockfile(msg) => {
                assert!(
                    msg.contains("md5"),
                    "error must name the offending algorithm: {msg}"
                );
                assert!(
                    msg.contains("com.example:demo"),
                    "error must point at the offending coordinate: {msg}"
                );
                assert!(
                    msg.contains("sha256") && msg.contains("sha1"),
                    "error must list the supported algorithms: {msg}"
                );
            }
            other => panic!("expected InvalidLockfile, got {other}"),
        }
    }

    /// A sha256 digest that is too short must be rejected at read time
    /// with a clear error pointing at the offending package, not later with a
    /// cryptic "invalid blob id length" from the store layer.
    #[test]
    fn rejects_truncated_sha256_digest_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-short-sha256.lock");
        let raw = r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "short-digest"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"

[platforms.packages.checksum]
algorithm = "sha256"
digest = "deadbeef"
"#;
        fs::write(&path, raw).unwrap();
        let err = Lockfile::read(&path).expect_err("truncated sha256 digest must be rejected");
        match &err {
            ConfigError::InvalidLockfile(msg) => {
                assert!(
                    msg.contains("sha256"),
                    "error must name the algorithm: {msg}"
                );
                assert!(
                    msg.contains("com.example:short-digest"),
                    "error must name the coordinate: {msg}"
                );
                assert!(
                    msg.contains("64"),
                    "error must state expected length: {msg}"
                );
            }
            other => panic!("expected InvalidLockfile, got {other}"),
        }
    }

    /// A sha1 digest that is too short must also be rejected at read time.
    #[test]
    fn rejects_truncated_sha1_digest_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-short-sha1.lock");
        let raw = r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "short-sha1"
version = "2.0.0"
packaging = "jar"
repo_url = "https://repo.example/"

[platforms.packages.checksum]
algorithm = "sha1"
digest = "aabbcc"
"#;
        fs::write(&path, raw).unwrap();
        let err = Lockfile::read(&path).expect_err("truncated sha1 digest must be rejected");
        match &err {
            ConfigError::InvalidLockfile(msg) => {
                assert!(msg.contains("sha1"), "error must name the algorithm: {msg}");
                assert!(
                    msg.contains("com.example:short-sha1"),
                    "error must name the coordinate: {msg}"
                );
                assert!(
                    msg.contains("40"),
                    "error must state expected length: {msg}"
                );
            }
            other => panic!("expected InvalidLockfile, got {other}"),
        }
    }

    /// A lockfile with populated `extra` fields must serialize to byte-identical
    /// output on repeated writes (BTreeMap guarantees deterministic key order).
    #[test]
    fn extra_fields_serialize_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("rv-extra-first.lock");
        let second = dir.path().join("rv-extra-second.lock");

        // Construct a lockfile with several `extra` keys in non-alphabetical insertion
        // order; BTreeMap will sort them and produce stable output.
        let mut top_extra = BTreeMap::new();
        top_extra.insert("zzz_future".to_string(), toml::Value::Boolean(true));
        top_extra.insert("aaa_flag".to_string(), toml::Value::Integer(42));

        let mut pkg_extra = BTreeMap::new();
        pkg_extra.insert("pkg_z".to_string(), toml::Value::String("z".to_string()));
        pkg_extra.insert("pkg_a".to_string(), toml::Value::String("a".to_string()));

        let mut meta = BTreeMap::new();
        meta.insert("build".to_string(), "stable".to_string());
        meta.insert("arch".to_string(), "x86_64".to_string());

        let lock = Lockfile {
            schema_version: LOCKFILE_SCHEMA_VERSION,
            config_hash: Some("abc".to_string()),
            resolution: None,
            platforms: vec![platform_from_flat(
                Platform::new("linux", "x86_64").unwrap(),
                vec![LockPackage {
                    group_id: "com.example".to_string(),
                    artifact_id: "lib".to_string(),
                    version: "1.0.0".to_string(),
                    snapshot_timestamp: None,
                    packaging: "jar".to_string(),
                    classifier: None,
                    repo_url: "https://repo.example/".to_string(),
                    checksum: None,
                    system_path: None,
                    direct_scope: None,
                    extra: pkg_extra,
                }],
                vec![],
            )],
            metadata: meta,
            extra: top_extra,
        };

        lock.write_atomic(&first).unwrap();
        lock.write_atomic(&second).unwrap();
        let bytes_first = fs::read(&first).unwrap();
        let bytes_second = fs::read(&second).unwrap();
        assert_eq!(
            bytes_first, bytes_second,
            "repeated writes with populated extra fields must be byte-identical"
        );
    }

    /// the leak scan must warn (not fail) when a coordinate field on
    /// a lockfile package contains the resolved value of an allowlisted
    /// `${env.X}` substitution. The write itself must still succeed: a
    /// blocking error here would risk a half-written lockfile in CI.
    #[test]
    fn write_atomic_emits_no_error_when_env_value_present_in_field() {
        // Install an allowlist containing a synthetic var, set it in the
        // process env, and bake the resolved value into a repo_url. The
        // scan should warn (we cannot easily capture log output without a
        // new dependency) but the write must still complete.
        temp_env::with_var(
            "RAEVA_FIX4_TEST_TOKEN",
            Some("super-secret-fix4-token-12345"),
            || {
                // Mutate the process-global allowlist INSIDE the temp_env guard
                // so it is serialized with other allowlist-dependent tests
                // (temp_env holds a process-wide lock for the closure's duration).
                rv_maven_model::set_env_substitution_allowlist(vec![
                    "RAEVA_FIX4_TEST_TOKEN".to_string(),
                ]);
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("rv-fix4.lock");
                let lock = Lockfile {
                    schema_version: LOCKFILE_SCHEMA_VERSION,
                    config_hash: None,
                    resolution: None,
                    platforms: vec![platform_from_flat(
                        Platform::new("linux", "x86_64").unwrap(),
                        vec![LockPackage {
                            group_id: "org.example".to_string(),
                            artifact_id: "demo".to_string(),
                            version: "1.0.0".to_string(),
                            snapshot_timestamp: None,
                            packaging: "jar".to_string(),
                            classifier: None,
                            // Resolved env value baked into the URL; this
                            // is what we want the scan to surface.
                            repo_url:
                                "https://internal.example/super-secret-fix4-token-12345/maven2/"
                                    .to_string(),
                            checksum: None,
                            system_path: None,
                            direct_scope: None,
                            extra: BTreeMap::new(),
                        }],
                        vec![],
                    )],
                    metadata: BTreeMap::new(),
                    extra: BTreeMap::new(),
                };
                lock.write_atomic(&path)
                    .expect("write must succeed even with a leak");
                // Round-trip still works.
                let loaded = Lockfile::read(&path).unwrap();
                assert_eq!(
                    loaded.platforms[0].modules[0].packages[0]
                        .coordinate
                        .artifact,
                    "demo"
                );
            },
        );
    }

    /// an env var that is unset or has a very short value (< 4 bytes)
    /// must not trip the scan; otherwise legitimate short version strings
    /// would spam false positives.
    #[test]
    fn write_atomic_does_not_warn_when_env_unset() {
        // Belt and braces: clear the variable in case it leaked in from
        // the test environment.
        temp_env::with_var("RAEVA_FIX4_DEFINITELY_UNSET_VAR", None::<&str>, || {
            // Mutate the process-global allowlist INSIDE the temp_env guard so
            // it is serialized with other allowlist-dependent tests.
            rv_maven_model::set_env_substitution_allowlist(vec![
                "RAEVA_FIX4_DEFINITELY_UNSET_VAR".to_string(),
            ]);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("rv-fix4-unset.lock");
            let lock = Lockfile::new();
            lock.write_atomic(&path)
                .expect("write must succeed when env is unset");
        });
    }

    /// a lockfile that lists the same package twice on a single
    /// platform must be rejected at load time. Two entries with the same
    /// `(group, artifact, version, classifier, packaging)` mask resolver
    /// bugs and hand-edit mistakes that downstream coord-keyed consumers
    /// would otherwise silently dedupe.
    #[test]
    fn rejects_duplicate_package_in_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-dup-pkg.lock");
        let raw = r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"
"#;
        fs::write(&path, raw).unwrap();
        let err = Lockfile::read(&path).expect_err("duplicate package must be rejected");
        match &err {
            ConfigError::InvalidLockfile(msg) => {
                assert!(msg.contains("duplicate package"), "msg: {msg}");
                assert!(msg.contains("org.example:demo"), "msg: {msg}");
            }
            other => panic!("expected InvalidLockfile, got {other}"),
        }
    }

    /// A duplicate package across distinct classifiers is NOT a
    /// duplicate: `:sources` and `:javadoc` are legitimate sibling pins.
    #[test]
    fn accepts_packages_distinguished_by_classifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-classifier.lock");
        let raw = r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
classifier = "sources"
repo_url = "https://repo.example/"
"#;
        fs::write(&path, raw).unwrap();
        let lock = Lockfile::read(&path).expect("classifier-distinct entries must load");
        assert_eq!(lock.platforms[0].modules[0].packages.len(), 2);
    }

    /// two `[[platforms]]` entries for the same `Platform` must be
    /// rejected; a `(variant, platform)` tuple is unique by construction.
    #[test]
    fn rejects_duplicate_platform_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-dup-plat.lock");
        let raw = r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms]]
platform = "linux-x86_64"
"#;
        fs::write(&path, raw).unwrap();
        let err = Lockfile::read(&path).expect_err("duplicate platform must be rejected");
        match &err {
            ConfigError::InvalidLockfile(msg) => {
                assert!(msg.contains("duplicate platform"), "msg: {msg}");
                assert!(msg.contains("linux-x86_64"), "msg: {msg}");
            }
            other => panic!("expected InvalidLockfile, got {other}"),
        }
    }

    /// The lock file lives under the cache dir, NOT the project working tree,
    /// so it never shows up in `git status`. And it must NOT be unlinked on
    /// drop/release: removing an advisory-lock file after unlocking is the
    /// split-brain race this guard exists to prevent. The file persists; only
    /// the lock is released so the next acquirer can take it.
    #[test]
    fn lockfile_guard_lives_outside_tree_and_persists() {
        use super::LockfileGuard;
        use std::time::Duration;

        let cache = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let lock_path = super::guard_path(cache.path(), project.path());
        {
            let guard =
                LockfileGuard::acquire(cache.path(), project.path(), Duration::from_secs(1))
                    .unwrap();
            assert!(lock_path.exists(), "guard should create the lock file");
            assert!(
                lock_path.starts_with(cache.path()),
                "lock file must live under the cache dir, not the project tree"
            );
            // The project working tree stays clean.
            assert!(
                std::fs::read_dir(project.path()).unwrap().next().is_none(),
                "project root must not gain a guard file"
            );
            drop(guard);
        }
        // Dropping releases the lock but does NOT remove the file.
        assert!(
            lock_path.exists(),
            "lock file must persist after drop (no unlink race)"
        );

        // The lock is free now: a fresh acquire must succeed immediately.
        let again = LockfileGuard::acquire(cache.path(), project.path(), Duration::from_secs(1))
            .expect("re-acquire after drop");
        again.release().unwrap();
        assert!(lock_path.exists(), "lock file persists after release() too");
    }

    /// While one guard is held, a second `acquire` on the same project must
    /// block and time out, proving mutual exclusion across holders.
    #[test]
    fn lockfile_guard_excludes_concurrent_acquire() {
        use super::LockfileGuard;
        use std::time::Duration;

        let cache = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();

        let held =
            LockfileGuard::acquire(cache.path(), project.path(), Duration::from_secs(1)).unwrap();
        let err = LockfileGuard::acquire(cache.path(), project.path(), Duration::from_millis(150))
            .expect_err("a second acquire must not succeed while the first is held");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        held.release().unwrap();
        // Once released, the contender can take it.
        LockfileGuard::acquire(cache.path(), project.path(), Duration::from_secs(1))
            .expect("acquire after release");
    }

    /// a zero-byte lockfile must produce a clear `InvalidLockfile`
    /// pointing at the empty-file cause rather than the misleading
    /// `UnsupportedSchema { found: 0 }` that `toml::from_str` of an empty
    /// document would otherwise yield.
    #[test]
    fn empty_lockfile_returns_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-empty.lock");
        fs::write(&path, "").unwrap();
        let err = Lockfile::read(&path).expect_err("empty lockfile must error");
        match &err {
            ConfigError::InvalidLockfile(msg) => {
                assert!(
                    msg.contains("empty") && msg.contains("rv sync"),
                    "error must explain the empty-lockfile case: {msg}"
                );
            }
            other => panic!("expected InvalidLockfile, got {other}"),
        }
    }

    /// whitespace-only lockfile (a newline, spaces, etc.) must be treated
    /// the same as the zero-byte case.
    #[test]
    fn whitespace_only_lockfile_returns_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-ws.lock");
        fs::write(&path, "\n  \n").unwrap();
        let err = Lockfile::read(&path).expect_err("whitespace-only lockfile must error");
        assert!(matches!(err, ConfigError::InvalidLockfile(_)));
    }

    /// A Lockfile written twice in succession with `write_atomic` must
    /// produce byte-identical files. Determinism here is a hard
    /// requirement: a diff-only-on-rewrite would defeat `--frozen` and
    /// the `print_lock_diff` UX, and silently spam git diffs on every
    /// re-sync. Catch any future drift introduced by serializer
    /// instability or hash-map key ordering.
    #[test]
    fn write_atomic_byte_identical_on_repeated_write() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("rv-first.lock");
        let second = dir.path().join("rv-second.lock");

        let mut lock = Lockfile::new();
        lock.platforms.push(platform_from_flat(
            Platform::new("linux", "x86_64").unwrap(),
            vec![
                LockPackage {
                    group_id: "org.example".to_string(),
                    artifact_id: "alpha".to_string(),
                    version: "1.0.0".to_string(),
                    snapshot_timestamp: None,
                    packaging: "jar".to_string(),
                    classifier: None,
                    repo_url: "https://repo.example/maven2/".to_string(),
                    checksum: Some(Checksum::new(
                        "sha256",
                        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    )),
                    system_path: None,
                    direct_scope: Some("compile".to_string()),
                    extra: BTreeMap::new(),
                },
                LockPackage {
                    group_id: "org.example".to_string(),
                    artifact_id: "beta".to_string(),
                    version: "2.0.0".to_string(),
                    snapshot_timestamp: None,
                    packaging: "jar".to_string(),
                    classifier: Some("sources".to_string()),
                    repo_url: "https://repo.example/maven2/".to_string(),
                    checksum: None,
                    system_path: None,
                    direct_scope: None,
                    extra: BTreeMap::new(),
                },
            ],
            vec![LockEdge {
                from: 0,
                to: 1,
                scope: Some("compile".to_string()),
                optional: false,
                extra: BTreeMap::new(),
            }],
        ));
        lock.config_hash = Some("abc123".to_string());

        lock.write_atomic(&first).unwrap();
        lock.write_atomic(&second).unwrap();
        let bytes_first = fs::read(&first).unwrap();
        let bytes_second = fs::read(&second).unwrap();
        assert_eq!(
            bytes_first, bytes_second,
            "two writes of the same Lockfile must produce byte-identical files"
        );
    }

    /// A hand-edited uppercase sha256 digest must be accepted, canonicalized
    /// to lowercase on read, and round-trip equal to its lowercase twin so
    /// the case-sensitive comparisons downstream (lockfile `PartialEq`, the
    /// `--frozen` match) never see a spurious mismatch.
    #[test]
    fn uppercase_digest_canonicalized_to_lowercase_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-upper.lock");
        let upper = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        let raw = format!(
            r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/"

[platforms.packages.checksum]
algorithm = "sha256"
digest = "{upper}"
"#
        );
        fs::write(&path, raw).unwrap();
        let lock = Lockfile::read(&path).expect("uppercase digest must load");
        let cs = lock.platforms[0].artifacts[0]
            .checksums
            .first()
            .expect("checksum present");
        assert_eq!(cs.digest, upper.to_ascii_lowercase());

        // Round trip: re-writing upgrades the legacy source to schema 4 and
        // retains the lowercase canonical digest.
        lock.write_atomic(&path).unwrap();
        let reread = Lockfile::read(&path).unwrap();
        assert_eq!(reread.schema_version, LOCKFILE_SCHEMA_VERSION);
        assert_eq!(
            reread.platforms[0].artifacts[0]
                .checksums
                .first()
                .expect("checksum present")
                .digest,
            upper.to_ascii_lowercase()
        );
        let raw_bytes = fs::read_to_string(&path).unwrap();
        assert!(
            !raw_bytes.contains(upper),
            "re-written lockfile must not carry the uppercase digest"
        );
    }

    /// A lockfile larger than the read limit must fail with a clear typed
    /// error naming the limit instead of being slurped into memory. The
    /// production cap is deliberately huge, so the test injects a small one.
    #[test]
    fn oversized_lockfile_rejected_with_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-huge.lock");
        fs::write(&path, "schema_version = 3\n").unwrap();
        let err = Lockfile::read_with_limit(&path, 4).expect_err("over the limit must error");
        match &err {
            ConfigError::InvalidLockfile(msg) => {
                assert!(
                    msg.contains("exceeds") && msg.contains("4 byte limit"),
                    "error must name the limit: {msg}"
                );
            }
            other => panic!("expected InvalidLockfile, got {other}"),
        }
        // The same file loads fine under the real cap.
        Lockfile::read(&path).expect("small lockfile must load under the default cap");
    }

    /// Uppercase `"SHA-256"` / `"SHA-1"` must normalize to lowercase canonical.
    #[test]
    fn loads_uppercase_and_dash_variants() {
        use super::normalize_checksum_algorithm;
        assert_eq!(normalize_checksum_algorithm("SHA-256"), Some("sha256"));
        assert_eq!(normalize_checksum_algorithm("Sha256"), Some("sha256"));
        assert_eq!(normalize_checksum_algorithm("sha-256"), Some("sha256"));
        assert_eq!(normalize_checksum_algorithm("SHA-1"), Some("sha1"));
        assert_eq!(normalize_checksum_algorithm("sha1"), Some("sha1"));
        assert_eq!(normalize_checksum_algorithm("md5"), None);
        assert_eq!(normalize_checksum_algorithm("sha512"), None);
        assert_eq!(normalize_checksum_algorithm(""), None);
    }

    /// The accepted set must be exactly what the published `pomPath` pattern
    /// in `schemas/rv-lock.json` accepts: the final component is `pom.xml`,
    /// not merely a name ending in it.
    #[test]
    fn module_path_requires_an_exact_pom_xml_component() {
        use super::validate_module_path;
        validate_module_path("pom.xml", "module").expect("root pom");
        validate_module_path("app/pom.xml", "module").expect("nested pom");
        validate_module_path("a/b/pom.xml", "module").expect("deeply nested pom");

        for rejected in [
            "app/mypom.xml",
            "mypom.xml",
            "app/pom.xml.bak",
            "app/pom.xml/",
            "app\\pom.xml",
            "/app/pom.xml",
            "../pom.xml",
            "app/./pom.xml",
            "",
        ] {
            let Err(err) = validate_module_path(rejected, "module") else {
                panic!("'{rejected}' must be rejected to match the published schema");
            };
            match err {
                ConfigError::InvalidLockfile(msg) => {
                    assert!(msg.contains(rejected), "error must name the path: {msg}");
                }
                other => panic!("expected InvalidLockfile for '{rejected}', got {other}"),
            }
        }
    }

    /// The legacy sentinel has exactly one owner; nothing may re-spell it.
    #[test]
    fn legacy_root_gav_is_recognized_as_a_placeholder() {
        use super::{LEGACY_ROOT_ARTIFACT, LEGACY_ROOT_GROUP, LEGACY_ROOT_VERSION, LockModule};

        let placeholder = LockGav::legacy_root();
        assert_eq!(placeholder.group, LEGACY_ROOT_GROUP);
        assert_eq!(placeholder.artifact, LEGACY_ROOT_ARTIFACT);
        assert_eq!(placeholder.version, LEGACY_ROOT_VERSION);
        assert!(placeholder.is_legacy_placeholder());
        assert!(!LockGav::new("com.example", "app", "1").is_legacy_placeholder());

        let module = LockModule {
            path: "pom.xml".to_string(),
            gav: placeholder,
            packaging: "pom".to_string(),
            packages: Vec::new(),
            edges: Vec::new(),
            extra: BTreeMap::new(),
        };
        assert!(module.is_legacy_placeholder());
        assert!(
            !LockModule {
                gav: LockGav::new("com.example", "app", "1"),
                ..module
            }
            .is_legacy_placeholder()
        );
    }

    /// A lockfile adapted from schema 1-3 is the only producer of the
    /// sentinel, and it always lands on the synthetic root module.
    #[test]
    fn legacy_adaptation_stamps_the_placeholder_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-legacy.lock");
        fs::write(
            &path,
            r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.example"
artifact_id = "demo"
version = "1.2.3"
packaging = "jar"
repo_url = "https://repo.example/maven2/"
"#,
        )
        .unwrap();

        let lock = Lockfile::read(&path).expect("legacy lockfile");
        let module = &lock.platforms[0].modules[0];
        assert_eq!(module.path, "pom.xml");
        assert!(module.is_legacy_placeholder());
    }
}

#[cfg(test)]
mod support_pom_codec_tests {
    use super::{
        LOCK_SUPPORT_POMS_KEY, LockGav, LockPackage, LockPlatform, Lockfile, SupportPomLine,
        decode_support_pom_lines, encode_support_pom_lines,
    };
    use crate::platform::Platform;
    use std::collections::BTreeMap;

    fn line(repo_id: &str, sha256: Option<&str>) -> SupportPomLine {
        SupportPomLine {
            repo_id: repo_id.to_string(),
            sha256: sha256.map(str::to_string),
        }
    }

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    /// The write and read halves are one codec: whatever `rv sync` encodes,
    /// `rv export-m2` must decode to the same pins, including the legacy
    /// two-field form that carries no digest.
    #[test]
    fn support_pom_lines_round_trip() {
        let entries = BTreeMap::from([
            (
                "com.example:pinned:1.0".to_string(),
                line("corp", Some(&digest('a'))),
            ),
            ("com.example:legacy:2.0".to_string(), line("central", None)),
            (
                "com.example:idless:3.0".to_string(),
                line("", Some(&digest('b'))),
            ),
        ]);
        let encoded = encode_support_pom_lines(&entries).expect("encode");
        assert_eq!(decode_support_pom_lines(&encoded).expect("decode"), entries);
    }

    /// Every malformed shape is a typed error. Skipping the line, or keeping
    /// its repo id while dropping the digest, would send the export back to
    /// the store's last-writer-wins coordinate index for a POM the lockfile
    /// pinned by content — a weakened pin, silently.
    #[test]
    fn malformed_support_pom_lines_are_rejected() {
        let good = digest('a');
        for (encoded, why) in [
            ("com.example:a:1.0".to_string(), "single field"),
            (
                format!("com.example:a:1.0\tcorp\t{good}\textra"),
                "four fields",
            ),
            ("com.example:a:1.0\tcorp\tshort".to_string(), "short digest"),
            (
                format!("com.example:a:1.0\tcorp\t{}", good.to_uppercase()),
                "uppercase digest",
            ),
            (
                "com.example:a\tcorp".to_string(),
                "coordinate missing version",
            ),
            ("\tcorp".to_string(), "empty coordinate"),
            (
                format!("com.example:a:1.0\tcorp\t{good}\n\ncom.example:b:1.0\tcorp\t{good}"),
                "blank line",
            ),
            (
                format!("com.example:a:1.0\tcorp\t{good}\ncom.example:a:1.0\tcorp\t{good}"),
                "duplicate coordinate",
            ),
        ] {
            assert!(
                decode_support_pom_lines(&encoded).is_err(),
                "{why} must be rejected"
            );
        }
    }

    /// Encoding refuses anything the strict decoder would reject, so a
    /// lockfile can never be written with lines that read back weakened.
    #[test]
    fn encoding_rejects_undecodable_entries() {
        let bad_id = BTreeMap::from([(
            "com.example:a:1.0".to_string(),
            line("corp\tsneaky", Some(&digest('a'))),
        )]);
        assert!(encode_support_pom_lines(&bad_id).is_err());

        let bad_digest = BTreeMap::from([(
            "com.example:a:1.0".to_string(),
            line("corp", Some("not-a-digest")),
        )]);
        assert!(encode_support_pom_lines(&bad_digest).is_err());
    }

    fn artifact_platform(platform: Platform, pom_sha256: &str) -> LockPlatform {
        let package = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "app".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(super::Checksum::new("sha256", digest('f'))),
            system_path: None,
            direct_scope: None,
            extra: BTreeMap::new(),
        };
        let mut entry = LockPlatform::single_module(
            platform,
            digest('e'),
            "pom.xml",
            LockGav::new("com.example", "root", "1.0"),
            "jar",
            vec![package],
            Vec::new(),
        );
        entry.artifacts[0].pom_sha256 = Some(pom_sha256.to_string());
        entry
    }

    /// Maven reads one `.pom` per GAV, so a lockfile pinning two different
    /// POMs for one coordinate describes a local repository that cannot
    /// exist. Rejecting it at read time means no consumer has to decide which
    /// of the two to believe.
    #[test]
    fn conflicting_companion_pom_pins_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let lock = Lockfile {
            schema_version: super::LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![
                artifact_platform(Platform::new("linux", "x86_64").unwrap(), &digest('a')),
                artifact_platform(Platform::new("darwin", "aarch64").unwrap(), &digest('b')),
            ],
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        };
        let error = lock
            .write_atomic(&path)
            .expect_err("a lockfile with conflicting POM pins must not be written");
        assert!(
            error.to_string().contains("com.example:app:1.0"),
            "the error must name the coordinate, got {error}"
        );
    }

    /// Negative control: the same digest on both platforms is the normal
    /// cross-platform case and must round-trip.
    #[test]
    fn agreeing_companion_pom_pins_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let lock = Lockfile {
            schema_version: super::LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![
                artifact_platform(Platform::new("linux", "x86_64").unwrap(), &digest('a')),
                artifact_platform(Platform::new("darwin", "aarch64").unwrap(), &digest('a')),
            ],
            metadata: BTreeMap::from([(
                LOCK_SUPPORT_POMS_KEY.to_string(),
                format!("com.example:parent:1.0\tcorp\t{}", digest('c')),
            )]),
            extra: BTreeMap::new(),
        };
        lock.write_atomic(&path).expect("write");
        let read = Lockfile::read(&path).expect("read");
        assert_eq!(
            read.platforms[0].artifacts[0].pom_sha256.as_deref(),
            Some(digest('a').as_str())
        );
    }

    /// A lockfile whose support-POM block and whose artifact row name the same
    /// GAV must pin the same `.pom`: Maven has one path for it, and
    /// `rv export-m2` queues the support closure first, so a disagreement
    /// ships the support pin's bytes while the artifact row attests the other
    /// digest is what was resolved. The row here is a `jar`, the case the
    /// per-row `packaging = "pom"` check cannot see.
    #[test]
    fn support_pin_conflicting_with_a_companion_pin_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let lock = Lockfile {
            schema_version: super::LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![artifact_platform(
                Platform::new("linux", "x86_64").unwrap(),
                &digest('a'),
            )],
            metadata: BTreeMap::from([(
                LOCK_SUPPORT_POMS_KEY.to_string(),
                format!("com.example:app:1.0\tcorp\t{}", digest('b')),
            )]),
            extra: BTreeMap::new(),
        };
        let error = lock
            .write_atomic(&path)
            .expect_err("a lockfile pinning one POM two ways must not be written");
        let message = error.to_string();
        for expected in ["com.example:app:1.0", &digest('a'), &digest('b')] {
            assert!(
                message.contains(expected),
                "the error must name the coordinate and both digests, missing {expected} in \
                 {message}"
            );
        }
        assert!(!path.exists(), "nothing must be written, found {path:?}");
    }

    /// The same disagreement arriving on disk — a hand edit, or a lockfile
    /// written before the check existed — fails the read, so no consumer has
    /// to decide which of the two digests to believe.
    #[test]
    fn support_pin_conflicting_with_a_companion_pin_fails_the_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let lock = Lockfile {
            schema_version: super::LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![artifact_platform(
                Platform::new("linux", "x86_64").unwrap(),
                &digest('a'),
            )],
            metadata: BTreeMap::from([(
                LOCK_SUPPORT_POMS_KEY.to_string(),
                format!("com.example:app:1.0\tcorp\t{}", digest('a')),
            )]),
            extra: BTreeMap::new(),
        };
        lock.write_atomic(&path).expect("agreeing pins write");

        // Repoint only the support-POM line: it is the one line naming the
        // coordinate, so the artifact row keeps its own digest.
        let edited: String = std::fs::read_to_string(&path)
            .expect("read back")
            .lines()
            .map(|line| {
                if line.contains("com.example:app:1.0") {
                    line.replace(&digest('a'), &digest('b'))
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, edited).expect("hand-edit the lockfile");

        let error = Lockfile::read(&path).expect_err("two POM digests for one GAV must not load");
        assert!(
            error.to_string().contains("com.example:app:1.0"),
            "the error must name the coordinate, got {error}"
        );
    }

    /// Negative control: a support POM the artifact rows also pin, with both
    /// recordings naming the same bytes, is the healthy shape and round-trips.
    #[test]
    fn support_pin_agreeing_with_a_companion_pin_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let lock = Lockfile {
            schema_version: super::LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![artifact_platform(
                Platform::new("linux", "x86_64").unwrap(),
                &digest('a'),
            )],
            metadata: BTreeMap::from([(
                LOCK_SUPPORT_POMS_KEY.to_string(),
                format!("com.example:app:1.0\tcorp\t{}", digest('a')),
            )]),
            extra: BTreeMap::new(),
        };
        lock.write_atomic(&path).expect("write");
        let read = Lockfile::read(&path).expect("read");
        assert_eq!(
            read.platforms[0].artifacts[0].pom_sha256.as_deref(),
            Some(digest('a').as_str())
        );
    }

    /// A legacy two-field support line records no digest, so it cannot
    /// disagree with anything and must stay readable.
    #[test]
    fn unpinned_support_line_never_conflicts_with_a_companion_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let lock = Lockfile {
            schema_version: super::LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![artifact_platform(
                Platform::new("linux", "x86_64").unwrap(),
                &digest('a'),
            )],
            metadata: BTreeMap::from([(
                LOCK_SUPPORT_POMS_KEY.to_string(),
                "com.example:app:1.0\tcorp".to_string(),
            )]),
            extra: BTreeMap::new(),
        };
        lock.write_atomic(&path).expect("write");
        Lockfile::read(&path).expect("an unpinned support line stays readable");
    }

    /// A `packaging = "pom"` platform whose single artifact pins `payload` as
    /// its bytes and `pom_sha256` as its companion POM.
    fn pom_packaged_platform(platform: Platform, payload: &str, pom_sha256: &str) -> LockPlatform {
        let package = LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: "platform-bom".to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: "pom".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2/".to_string(),
            checksum: Some(super::Checksum::new("sha256", payload)),
            system_path: None,
            direct_scope: None,
            extra: BTreeMap::new(),
        };
        let mut entry = LockPlatform::single_module(
            platform,
            digest('e'),
            "pom.xml",
            LockGav::new("com.example", "root", "1.0"),
            "jar",
            vec![package],
            Vec::new(),
        );
        entry.artifacts[0].pom_sha256 = Some(pom_sha256.to_string());
        entry
    }

    /// For `packaging = "pom"` the payload and the companion POM are one
    /// Maven file. A row pinning two digests describes a file that cannot
    /// exist, and `rv export-m2` — which exports a POM package as the primary
    /// artifact — would ship the payload while the lock claims the other
    /// digest is what is pinned. `rv sync` cannot write such a row, so this is
    /// the hand-edited case, caught for every consumer at read time.
    #[test]
    fn hand_edited_pom_packaged_row_with_two_digests_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let lock = Lockfile {
            schema_version: super::LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![pom_packaged_platform(
                Platform::new("linux", "x86_64").unwrap(),
                &digest('a'),
                &digest('a'),
            )],
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        };
        lock.write_atomic(&path).expect("agreeing pins write");

        let edited = std::fs::read_to_string(&path)
            .expect("read back")
            .replace(&digest('a'), &digest('b'))
            // Repoint only the companion-POM pin; the payload keeps its own
            // digest, which is exactly the disagreement export cannot resolve.
            .replacen(&digest('b'), &digest('a'), 1);
        std::fs::write(&path, edited).expect("hand-edit the lockfile");

        let error = Lockfile::read(&path).expect_err("a two-digest pom row must not load");
        let message = error.to_string();
        assert!(
            message.contains("com.example:platform-bom:1.0") && message.contains("packaging=pom"),
            "the error must name the coordinate and the reason, got {message}"
        );
    }

    /// Negative control: one file, one digest, recorded in both fields.
    #[test]
    fn pom_packaged_row_with_agreeing_digests_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let lock = Lockfile {
            schema_version: super::LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            resolution: None,
            platforms: vec![pom_packaged_platform(
                Platform::new("linux", "x86_64").unwrap(),
                &digest('a'),
                &digest('a'),
            )],
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        };
        lock.write_atomic(&path).expect("write");
        let read = Lockfile::read(&path).expect("read");
        assert_eq!(
            read.platforms[0].artifacts[0].pom_sha256.as_deref(),
            Some(digest('a').as_str())
        );
    }

    /// A malformed support-POM block fails the lockfile read outright, so no
    /// consumer ever sees a partially decoded provenance map.
    #[test]
    fn malformed_support_metadata_fails_the_lockfile_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv.lock");
        let mut lock = Lockfile::new();
        lock.platforms.push(artifact_platform(
            Platform::new("linux", "x86_64").unwrap(),
            &digest('a'),
        ));
        lock.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            "com.example:parent:1.0\tcorp\tnot-a-digest".to_string(),
        );
        assert!(lock.write_atomic(&path).is_err());
    }
}
