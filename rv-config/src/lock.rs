use std::collections::{BTreeMap, HashSet};
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{
    ConfigError, io_error_with_context, toml_de_error_with_context, toml_ser_error_with_context,
};
use crate::platform::Platform;

pub const LOCKFILE_SCHEMA_VERSION: u32 = 3;

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lockfile {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<LockPlatform>,
    /// Stable key-value metadata for the lockfile. Values MUST be deterministic
    /// (no timestamps, PIDs, UUIDs, or other nonce data); non-deterministic values
    /// would break `--frozen` checks and byte-level diff comparisons.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Preserve unrecognized top-level fields so they survive a read-write
    /// round-trip. Pre-v1 lockfiles wrote a `[variants]` table; that
    /// content is captured here and re-serialized verbatim so v1 does not
    /// strip data from existing lockfiles on the first re-write.
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
}

impl Lockfile {
    pub fn new() -> Self {
        Self {
            schema_version: LOCKFILE_SCHEMA_VERSION,
            config_hash: None,
            platforms: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
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
        let mut lock: Lockfile = toml::from_str(&contents)
            .with_context(|| format!("failed to parse lockfile {}", path.display()))
            .map_err(|err| ConfigError::TomlDeserialize(toml_de_error_with_context(err)))?;
        if lock.schema_version > LOCKFILE_SCHEMA_VERSION || lock.schema_version < 1 {
            return Err(ConfigError::UnsupportedSchema {
                found: lock.schema_version,
                expected: LOCKFILE_SCHEMA_VERSION,
            });
        }
        // Normalize and validate checksum algorithms on every package up
        // front so downstream consumers can rely on a canonical spelling
        // and never silently drop a pin with a non-canonical algorithm.
        let display = path.display().to_string();
        normalize_lockfile_checksums(&mut lock, &display)?;

        // Reject duplicate platforms in the top-level `[[platforms]]` list:
        // two entries for the same `Platform` would silently shadow each
        // other through any `(platform)`-keyed consumer.
        check_duplicate_platforms(&lock.platforms)?;

        for platform in &lock.platforms {
            let pkg_count = platform.packages.len();
            for edge in &platform.edges {
                if edge.from >= pkg_count || edge.to >= pkg_count {
                    return Err(ConfigError::InvalidLockfile(format!(
                        "edge ({} -> {}) is out of bounds for {} packages on platform {}",
                        edge.from, edge.to, pkg_count, platform.platform,
                    )));
                }
            }
            // Reject duplicate packages keyed on the full coordinate tuple
            // (group, artifact, version, classifier, packaging). A duplicate
            // is always a resolver bug or hand-edit gone wrong: downstream
            // consumers `format_coord()`-key these on the same tuple and
            // would silently drop one entry, which has historically masked
            // version-conflict diagnostics.
            check_duplicate_packages(platform)?;
            // Warn on packages with empty repo_url.
            for pkg in &platform.packages {
                if pkg.repo_url.is_empty() && pkg.system_path.is_none() {
                    tracing::warn!(
                        coord = %pkg.format_coord(),
                        "lockfile package has an empty repo_url; the artifact may not be fetchable"
                    );
                }
            }
        }
        Ok(lock)
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), ConfigError> {
        let mut lock_to_write = self.clone();
        lock_to_write.schema_version = LOCKFILE_SCHEMA_VERSION;

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

// Dedup key is the full coordinate tuple `(group, artifact, version,
// classifier, packaging)`; a duplicate masks version-conflict diagnostics.
fn check_duplicate_packages(platform: &LockPlatform) -> Result<(), ConfigError> {
    let mut seen: HashSet<(&str, &str, &str, &str, &str)> =
        HashSet::with_capacity(platform.packages.len());
    for pkg in &platform.packages {
        let key = (
            pkg.group_id.as_str(),
            pkg.artifact_id.as_str(),
            pkg.version.as_str(),
            pkg.classifier.as_deref().unwrap_or(""),
            pkg.packaging.as_str(),
        );
        if !seen.insert(key) {
            return Err(ConfigError::InvalidLockfile(format!(
                "duplicate package '{}' on platform '{}'; \
                 each (group, artifact, version, classifier, packaging) tuple \
                 may appear at most once per platform",
                pkg.format_coord(),
                platform.platform,
            )));
        }
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
        for pkg in &platform.packages {
            scan_lock_package(pkg, &resolved, &platform.platform.to_string());
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
        for pkg in &mut platform.packages {
            let coord = pkg.format_coord();
            if let Some(checksum) = pkg.checksum.as_mut() {
                match normalize_checksum_algorithm(&checksum.algorithm) {
                    Some(canonical) => {
                        if checksum.algorithm != canonical {
                            checksum.algorithm = canonical.to_string();
                        }
                        // Validate digest length and hex character set.
                        let expected_len = if canonical == "sha256" { 64 } else { 40 };
                        if checksum.digest.len() != expected_len
                            || !checksum.digest.chars().all(|c| c.is_ascii_hexdigit())
                        {
                            return Err(ConfigError::InvalidLockfile(format!(
                                "invalid {canonical} digest for {coord} \
                                 (platform {platform_id}) in {source}: \
                                 expected {expected_len} hex characters, \
                                 got {:?}",
                                checksum.digest,
                            )));
                        }
                        // Canonicalize on ingest: hand-edited uppercase hex
                        // would otherwise survive into the case-sensitive
                        // comparisons downstream.
                        checksum.digest.make_ascii_lowercase();
                    }
                    None => {
                        return Err(ConfigError::InvalidLockfile(format!(
                            "unsupported checksum algorithm '{algo}' on {coord} \
                             (platform {platform_id}) in {source}; \
                             supported algorithms are sha256 and sha1",
                            algo = checksum.algorithm,
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

// `Eq` is intentionally not derived: the `extra` field's `toml::Value`
// values can hold floats, which only implement `PartialEq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LockPlatform {
    pub platform: Platform,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<LockPackage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<LockEdge>,
    /// Preserve unrecognized nested fields so they survive a read-write
    /// round-trip when a newer Raeva adds platform-level keys.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, toml::Value>,
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
    use super::{Checksum, LOCKFILE_SCHEMA_VERSION, LockEdge, LockPackage, LockPlatform, Lockfile};
    use crate::error::ConfigError;
    use crate::platform::Platform;
    use std::collections::BTreeMap;
    use std::fs;

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
            platforms: vec![LockPlatform {
                platform,
                packages: vec![package],
                edges: vec![LockEdge {
                    from: 0,
                    to: 0,
                    scope: Some("compile".to_string()),
                    optional: false,
                    extra: BTreeMap::new(),
                }],
                extra: BTreeMap::new(),
            }],
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
        let mut lock = Lockfile::new();
        lock.schema_version = LOCKFILE_SCHEMA_VERSION + 1;
        fs::write(&path, toml::to_string(&lock).unwrap()).unwrap();
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
            platforms: vec![LockPlatform {
                platform,
                packages: vec![pkg_minimal, pkg_with_checksum, pkg_with_system_path],
                edges: vec![
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
                extra: BTreeMap::new(),
            }],
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
    fn lockfile_default_has_v3_schema() {
        let lock = Lockfile::new();
        assert_eq!(lock.schema_version, 3);
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
        assert_eq!(lock.platforms[0].packages.len(), 1);
        let pkg = &lock.platforms[0].packages[0];
        assert_eq!(pkg.group_id, "org.example");
        assert_eq!(pkg.artifact_id, "demo");
        assert_eq!(pkg.version, "1.2.3");
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
    fn write_atomic_upgrades_schema_to_v3() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rv-upgrade.lock");
        let mut lock = Lockfile::new();
        lock.schema_version = 2;
        lock.platforms.push(LockPlatform {
            platform: Platform::new("linux", "x86_64").unwrap(),
            packages: vec![LockPackage {
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
            edges: vec![],
            extra: BTreeMap::new(),
        });

        lock.write_atomic(&path).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("schema_version = 3"));
        assert!(!raw.contains("schema_version = 2"));

        let parsed = Lockfile::read(&path).unwrap();
        assert_eq!(parsed.schema_version, LOCKFILE_SCHEMA_VERSION);
        assert_eq!(parsed.platforms[0].packages[0].artifact_id, "demo");
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
        assert_eq!(lock.platforms[0].packages[0].artifact_id, "demo");
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
        let pkg = &lock.platforms[0].packages[0];
        let cs = pkg.checksum.as_ref().expect("checksum present");
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
            platforms: vec![LockPlatform {
                platform: Platform::new("linux", "x86_64").unwrap(),
                packages: vec![LockPackage {
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
                edges: vec![],
                extra: BTreeMap::new(),
            }],
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
                    platforms: vec![LockPlatform {
                        platform: Platform::new("linux", "x86_64").unwrap(),
                        packages: vec![LockPackage {
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
                        edges: vec![],
                        extra: BTreeMap::new(),
                    }],
                    metadata: BTreeMap::new(),
                    extra: BTreeMap::new(),
                };
                lock.write_atomic(&path)
                    .expect("write must succeed even with a leak");
                // Round-trip still works.
                let loaded = Lockfile::read(&path).unwrap();
                assert_eq!(loaded.platforms[0].packages[0].artifact_id, "demo");
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
        assert_eq!(lock.platforms[0].packages.len(), 2);
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
        lock.platforms.push(LockPlatform {
            platform: Platform::new("linux", "x86_64").unwrap(),
            packages: vec![
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
            edges: vec![LockEdge {
                from: 0,
                to: 1,
                scope: Some("compile".to_string()),
                optional: false,
                extra: BTreeMap::new(),
            }],
            extra: BTreeMap::new(),
        });
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
        let cs = lock.platforms[0].packages[0]
            .checksum
            .as_ref()
            .expect("checksum present");
        assert_eq!(cs.digest, upper.to_ascii_lowercase());

        // Round trip: re-writing and re-reading yields the lowercase form
        // and compares equal to the in-memory canonicalized lockfile.
        lock.write_atomic(&path).unwrap();
        let reread = Lockfile::read(&path).unwrap();
        assert_eq!(reread, lock);
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
}
