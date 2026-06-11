use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use futures::stream::{self, StreamExt};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::task::spawn_blocking;
use tracing::{debug, warn};

use rv_config::{Checksum, LockPackage, Lockfile};
use rv_store::{ArtifactKey, BlobId, Store};

use super::error::{ExportError, Result};
use super::link::{LinkStrategy, link_with_fallback};
use super::metadata::{
    ArtifactMetaKey, ArtifactMetaState, ArtifactMetadata, MetadataAccumulator,
    RemoteRepositoriesAccumulator, SnapshotMetaKey, SnapshotMetaState, SnapshotVersionEntry,
    VersionedMetadata, build_number_from_version, compact_updated, parse_snapshot_timestamp,
    render_artifact_metadata, render_versioned_metadata, write_atomic as write_metadata_atomic,
};

#[derive(Debug, Clone)]
pub(crate) struct ExportOptions {
    pub dry_run: bool,
    pub overwrite: bool,
    pub link_strategy: LinkStrategy,
    pub m2_path: PathBuf,
}

impl Default for ExportOptions {
    fn default() -> Self {
        let m2_path = default_m2_path().unwrap_or_else(|| PathBuf::from(".m2").join("repository"));
        Self {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Hardlink,
            m2_path,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ExportStats {
    pub exported_count: usize,
    pub skipped_count: usize,
    pub copied_count: usize,
    pub linked_count: usize,
}

/// One file to materialize into the Maven local repository. The `package` is
/// a stand-in used only for path/layout decisions (snapshot directory
/// handling); parent POMs carry a synthetic one keyed off their own
/// coordinate. `repo_id` is the repository id recorded in
/// `_remote.repositories` next to the file.
struct ExportUnit {
    key: ArtifactKey,
    package: LockPackage,
    blob: BlobId,
    repo_id: String,
}

pub(crate) struct Exporter<'a> {
    options: ExportOptions,
    store: &'a Store,
    /// Maps a normalized repository URL to its configured repository id, used
    /// to fill in the `_remote.repositories` markers Maven Resolver expects.
    /// Unknown URLs fall back to `central`.
    repo_ids: HashMap<String, String>,
    /// Maps a support POM's `"g:a:v"` to the id of the repository that served
    /// it during resolution. Takes precedence over `repo_ids` for parent/BOM
    /// POMs, which may come from a different repo than the child that
    /// referenced them.
    support_repo_ids: HashMap<String, String>,
}

impl<'a> Exporter<'a> {
    pub(crate) fn new(options: ExportOptions, store: &'a Store) -> Self {
        Self {
            options,
            store,
            repo_ids: HashMap::new(),
            support_repo_ids: HashMap::new(),
        }
    }

    /// Supply the normalized-URL -> repository-id map used to label
    /// `_remote.repositories` entries. The keys must already be normalized
    /// via `rv_repo::normalize_repo_url` so lookups match the lockfile's
    /// `repo_url` after the same normalization.
    pub(crate) fn with_repo_ids(mut self, repo_ids: HashMap<String, String>) -> Self {
        self.repo_ids = repo_ids;
        self
    }

    /// Supply the support-POM `"g:a:v" -> repo-id` provenance map recorded by
    /// `rv sync`, so a parent/BOM that resolved from a different repository
    /// than its child is labelled with its own source repo id.
    pub(crate) fn with_support_repo_ids(mut self, ids: HashMap<String, String>) -> Self {
        self.support_repo_ids = ids;
        self
    }

    /// Resolve the Maven repository id for a package's `repo_url`. Defaults
    /// to `central`. Maven Central is the overwhelmingly common source and is
    /// the id `mvn` itself records for it, so an unmapped URL labelled
    /// `central` keeps strict offline resolution working for the common case.
    fn repo_id_for(&self, repo_url: &str) -> String {
        let normalized = rv_repo::normalize_repo_url(repo_url);
        self.repo_ids
            .get(&normalized)
            .cloned()
            .unwrap_or_else(|| "central".to_string())
    }

    pub(crate) async fn export_lock(
        &self,
        lock: &Lockfile,
        root_pom: Option<&Path>,
    ) -> Result<ExportStats> {
        let mut stats = ExportStats::default();
        let mut system_scoped: Vec<String> = Vec::new();
        let mut meta = MetadataAccumulator::default();

        // First pass: do all the per-package work that requires sequential
        // access to shared state (system_path collection, metadata
        // accumulation) and resolve each package's blob ids. Blob lookups
        // are async-cheap (an SQLite read), but the index can't be safely
        // fanned out to multiple writers, so we batch them here. Each
        // `ExportUnit` (defined at module scope so `enqueue_pom_closure` can
        // build them too) is one file we will materialize.
        let mut units: Vec<ExportUnit> = Vec::new();
        // Dedupe sets keyed off the package coordinate triple.
        //
        // `enqueued_poms` collapses the per-classifier POM re-exports: every
        // (jar, jar:sources, jar:javadoc) classifier for the same g:a:v shares
        // a single POM, so without deduping we would queue and ship the same
        // POM bytes three times. It is also the dedupe key for the parent-POM
        // walk so a parent shared by many children is only exported once.
        //
        // `accumulated` guards `accumulate_metadata` against being called more
        // than once for the same (g, a, v, packaging, classifier) tuple,
        // which is otherwise repeated once per platform: quadratic-ish work
        // for nothing.
        let mut enqueued_poms: HashSet<(String, String, String)> = HashSet::new();
        let mut accumulated: HashSet<(String, String, String, String, Option<String>)> =
            HashSet::new();

        // The root project's own pom.xml lives on disk (not in the lock), but
        // its `<parent>` and imported BOMs must also be in ~/.m2 for `mvn -o`
        // to build the root model. That is the single most common shape ("no
        // parent, import spring-boot-dependencies/junit-bom" or "inherit
        // spring-boot-starter-parent"). Walk that closure first. Only the
        // primary export passes a root pom; the sources/javadocs passes reuse
        // the same per-call dedupe set and skip it.
        if let Some(root_pom) = root_pom {
            let refs = read_support_refs(root_pom).unwrap_or_default();
            // Support POMs are overwhelmingly on Central; an unmapped repo_url
            // falls back to the `central` marker id. Bias toward the project's
            // primary repo when it has one.
            let root_repo_url = lock
                .platforms
                .first()
                .and_then(|p| p.packages.first())
                .map(|pkg| pkg.repo_url.clone())
                .unwrap_or_default();
            self.enqueue_support_closure(refs, &root_repo_url, &mut enqueued_poms, &mut units)
                .await?;
        }

        for platform in &lock.platforms {
            for package in &platform.packages {
                if package.system_path.is_some() {
                    system_scoped.push(format!(
                        "{}:{}:{}",
                        package.group_id, package.artifact_id, package.version
                    ));
                    continue;
                }

                let key = ArtifactKey::new(
                    package.group_id.clone(),
                    package.artifact_id.clone(),
                    package.version.clone(),
                    package.packaging.clone(),
                    package.classifier.clone(),
                );

                let blob = self.blob_id_for_package(&key, package).await?;
                let repo_id = self.repo_id_for(&package.repo_url);

                if package.packaging != "pom" {
                    let pom_coord = (
                        package.group_id.clone(),
                        package.artifact_id.clone(),
                        package.version.clone(),
                    );
                    // Sibling classifier already queued the POM for this
                    // g:a:v; skip the duplicate so we don't pay for hashing
                    // and writing the same POM bytes again.
                    if !enqueued_poms.contains(&pom_coord) {
                        // Some Maven artifacts ship without a companion POM
                        // (relocations, sources-only jars). Don't fail the
                        // whole export over a missing POM: warn and ship the
                        // primary artifact alone, matching Maven's behaviour.
                        let pom_key = ArtifactKey::new(
                            package.group_id.clone(),
                            package.artifact_id.clone(),
                            package.version.clone(),
                            "pom",
                            None,
                        );
                        match self.store.lookup_artifact_locked(&pom_key).await? {
                            Some(pom_blob) => {
                                enqueued_poms.insert(pom_coord);
                                let pom_pkg = pom_package_from(package);
                                // Walk this POM's support closure (its
                                // `<parent>` ancestry and import-scoped BOMs)
                                // so `mvn -o` does not fail with
                                // "Non-resolvable parent/import POM". Each
                                // support POM found in the store is queued.
                                let refs = read_support_refs(&self.store.get_path(&pom_blob))
                                    .unwrap_or_default();
                                self.enqueue_support_closure(
                                    refs,
                                    &package.repo_url,
                                    &mut enqueued_poms,
                                    &mut units,
                                )
                                .await?;
                                units.push(ExportUnit {
                                    key: pom_key,
                                    package: pom_pkg,
                                    blob: pom_blob,
                                    repo_id: repo_id.clone(),
                                });
                            }
                            None => {
                                warn!(
                                    group_id = %package.group_id,
                                    artifact_id = %package.artifact_id,
                                    version = %package.version,
                                    "no POM in store for non-POM artifact; exporting payload only"
                                );
                            }
                        }
                    }
                } else {
                    // A lockfile package that is itself a POM still needs its
                    // parent ancestry materialized for offline builds.
                    let pom_coord = (
                        package.group_id.clone(),
                        package.artifact_id.clone(),
                        package.version.clone(),
                    );
                    enqueued_poms.insert(pom_coord);
                    let refs = read_support_refs(&self.store.get_path(&blob)).unwrap_or_default();
                    self.enqueue_support_closure(
                        refs,
                        &package.repo_url,
                        &mut enqueued_poms,
                        &mut units,
                    )
                    .await?;
                }

                // Queue the lockfile package's own file last so its parent
                // ancestry (queued above) sits ahead of it. Ordering is
                // cosmetic for the export but keeps related files adjacent in
                // the unit list.
                units.push(ExportUnit {
                    key,
                    package: package.clone(),
                    blob,
                    repo_id,
                });

                let accum_key = (
                    package.group_id.clone(),
                    package.artifact_id.clone(),
                    package.version.clone(),
                    package.packaging.clone(),
                    package.classifier.clone(),
                );
                if accumulated.insert(accum_key) {
                    self.accumulate_metadata(package, &mut meta);
                }
            }
        }

        // Second pass: fan out the actual export work. Each entry only
        // touches the filesystem (link/copy/hash), with no shared mutable
        // state between tasks, so we can run several concurrently. The work
        // is mostly file I/O dispatched through `spawn_blocking`, which
        // already throttles via the tokio blocking-thread pool, so we just
        // need a ceiling that's high enough not to be the bottleneck on
        // multi-core boxes. 64 keeps us well under any sensible
        // blocking-thread count while still leaving room for fan out on big
        // lockfiles.
        let parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 64);

        // Build per-unit futures up front so the closure only captures
        // already-owned data; `self` is borrowed immutably across the
        // stream and the spawn_blocking work inside `export_artifact_async`
        // doesn't need a unique reference. Each future yields the outcome
        // plus the materialized path + repo id so the caller can both update
        // stats and accumulate the `_remote.repositories` markers.
        type UnitResult = (ExportOutcome, PathBuf, String);
        let outcomes: Vec<Result<UnitResult>> = stream::iter(units.into_iter())
            .map(|item| async move {
                let (outcome, dest) = self
                    .export_artifact_async(&item.key, &item.package, &item.blob)
                    .await?;
                Ok::<_, ExportError>((outcome, dest, item.repo_id))
            })
            .buffer_unordered(parallelism)
            .collect()
            .await;

        let mut markers = RemoteRepositoriesAccumulator::default();
        for outcome in outcomes {
            let (entry, dest, repo_id) = outcome?;
            stats.record(entry);
            // Record the marker for every materialized file. Maven needs the
            // `_remote.repositories` entry whether we wrote the file just now
            // or skipped an already-identical copy.
            if let (Some(dir), Some(filename)) =
                (dest.parent(), dest.file_name().and_then(|n| n.to_str()))
            {
                markers.record(dir, filename, &repo_id);
            }
        }

        if !self.options.dry_run {
            // `write_metadata` opens, writes, fsyncs, and renames a handful
            // of XML files: blocking I/O that has no business running on the
            // async runtime. Hand it off so other tasks can progress while
            // the disk catches up. The `_remote.repositories` markers ride
            // along in the same blocking hop.
            let m2_path = self.options.m2_path.clone();
            spawn_blocking(move || {
                let mut meta = meta;
                write_metadata_blocking(&m2_path, &mut meta)?;
                if !markers.is_empty() {
                    markers.write_all()?;
                }
                Ok::<_, ExportError>(())
            })
            .await
            .map_err(|e| ExportError::IoError(std::io::Error::other(e.to_string())))??;
        }

        if !system_scoped.is_empty() {
            // Structured fields let subscribers format these (and ship the
            // raw list to log aggregators) instead of being stuck with a
            // pre-baked message. The human-readable summary lives in the
            // log message itself; the raw list rides in the structured
            // `coords` field rather than a comma-joined string.
            warn!(
                count = system_scoped.len(),
                coords = ?system_scoped,
                "system-scoped dependencies not exported (systemPath artifacts are not in the content-addressed store)"
            );
        }

        Ok(stats)
    }

    /// Update the metadata accumulator with one package's coordinates.
    fn accumulate_metadata(&self, package: &LockPackage, meta: &mut MetadataAccumulator) {
        // Artifact-level metadata: always include the base version so
        // `mvn -o` can find it via the `<versions>` list.
        let base = package.base_snapshot_version();
        let artifact_key = ArtifactMetaKey {
            group_id: package.group_id.clone(),
            artifact_id: package.artifact_id.clone(),
        };
        let artifact_state = meta.artifacts.entry(artifact_key).or_default();
        artifact_state.add_version(&base);
        // Track last_updated using whatever timestamp signal we have.
        if let Some(stamp) = derived_last_updated(package) {
            artifact_state.last_updated = Some(stamp);
        }

        // Snapshot metadata: only relevant when the package is a snapshot.
        if !package.is_snapshot() {
            return;
        }

        let snapshot_key = SnapshotMetaKey {
            group_id: package.group_id.clone(),
            artifact_id: package.artifact_id.clone(),
            base_version: base.clone(),
        };
        let state = meta.snapshots.entry(snapshot_key).or_default();

        if let Some((timestamp, build_number)) = resolve_snapshot_stamp(package) {
            state.timestamp = Some(timestamp.clone());
            state.build_number = state.build_number.or(build_number);
            if let Some(updated) = compact_updated(&timestamp) {
                state.last_updated = Some(updated);
            }
        }

        let updated = state
            .last_updated
            .clone()
            .unwrap_or_else(|| "00000000000000".to_string());

        // Main artifact entry.
        push_snapshot_entry(
            &mut state.entries,
            SnapshotVersionEntry {
                extension: package.packaging.clone(),
                classifier: package.classifier.clone(),
                value: package.version.clone(),
                updated: updated.clone(),
            },
        );
        // Maven also lists the POM as a snapshot version entry when present.
        if package.packaging != "pom" {
            push_snapshot_entry(
                &mut state.entries,
                SnapshotVersionEntry {
                    extension: "pom".to_string(),
                    classifier: None,
                    value: package.version.clone(),
                    updated,
                },
            );
        }
    }

    /// Async wrapper that moves blocking file I/O to a background thread.
    ///
    /// `safe_artifact_path` itself probes the filesystem during
    /// canonicalisation, and `export_artifact_blocking` runs the rest of
    /// the blocking work (hash, link, sidecar writes); folding both into
    /// the same `spawn_blocking` keeps blocking syscalls off the async
    /// runtime thread. Returns the outcome alongside the destination path so
    /// the caller can record the `_remote.repositories` marker for it.
    async fn export_artifact_async(
        &self,
        key: &ArtifactKey,
        package: &LockPackage,
        blob_id: &BlobId,
    ) -> Result<(ExportOutcome, PathBuf)> {
        let src = self.store.get_path(blob_id);
        let options = self.options.clone();
        let key_str = key.to_string();
        let blob_id = blob_id.clone();
        let key = key.clone();
        let package = package.clone();

        spawn_blocking(move || {
            let dest = safe_artifact_path(&options, &key, &package)?;
            let outcome = export_artifact_blocking(&src, &dest, &options, &key_str, &blob_id)?;
            Ok((outcome, dest))
        })
        .await
        .map_err(|e| ExportError::IoError(std::io::Error::other(e.to_string())))?
    }

    /// Walk a POM's support closure (its `<parent>` ancestry and any
    /// import-scoped `<dependencyManagement>` BOMs) and queue every support
    /// POM present in the content store for export.
    ///
    /// `mvn -o` refuses to build when it cannot resolve a dependency's parent
    /// POM ("Non-resolvable parent POM") or an imported BOM ("Non-resolvable
    /// import POM") offline. Parents and import BOMs are not recorded as
    /// lockfile packages (pom-only nodes are dropped from the lock), so we
    /// rediscover them here by parsing each POM and following both `<parent>`
    /// links and `scope=import,type=pom` dependencyManagement entries, looking
    /// each up by its `(g, a, v, pom)` coordinate in the store. `rv sync`
    /// persists this closure during resolution (see
    /// `RepoBackend::persist_support_pom`).
    ///
    /// Best-effort: a support POM missing from the store is skipped with a
    /// warning rather than failing the export. An import whose version is a
    /// property defined only in a parent (not the importing POM) is likewise
    /// skipped with a warning (see `read_support_refs`); that case almost
    /// always arrives via a `<parent>` chain, which IS walked.
    async fn enqueue_support_closure(
        &self,
        initial_refs: Vec<(String, String, String)>,
        repo_url: &str,
        enqueued: &mut HashSet<(String, String, String)>,
        units: &mut Vec<ExportUnit>,
    ) -> Result<()> {
        // Parents form a chain but import BOMs form a tree (a POM can import
        // several BOMs, each with its own parents/imports), so walk a worklist
        // of coordinates. The dedupe set breaks cycles/sharing; the node cap is
        // a belt-and-braces guard against malformed input.
        const MAX_NODES: usize = 512;
        let mut worklist = initial_refs;
        let mut processed = 0usize;
        while let Some((group_id, artifact_id, version)) = worklist.pop() {
            processed += 1;
            if processed > MAX_NODES {
                return Ok(());
            }
            let coord = (group_id.clone(), artifact_id.clone(), version.clone());
            if !enqueued.insert(coord) {
                continue;
            }
            let key = ArtifactKey::new(
                group_id.clone(),
                artifact_id.clone(),
                version.clone(),
                "pom",
                None,
            );
            match self.store.lookup_artifact_locked(&key).await? {
                Some(support_blob) => {
                    // Recurse into this support POM's own parents/imports.
                    if let Some(more) = read_support_refs(&self.store.get_path(&support_blob)) {
                        worklist.extend(more);
                    }
                    // Prefer this support POM's own recorded source-repo id
                    // (it may differ from the child's repo) over the guessed
                    // caller `repo_url`.
                    let coord_key = format!("{group_id}:{artifact_id}:{version}");
                    let repo_id = self
                        .support_repo_ids
                        .get(&coord_key)
                        .cloned()
                        .unwrap_or_else(|| self.repo_id_for(repo_url));
                    let pkg = synthetic_pom_package(&group_id, &artifact_id, &version, repo_url);
                    units.push(ExportUnit {
                        key,
                        package: pkg,
                        blob: support_blob,
                        repo_id,
                    });
                }
                None => {
                    warn!(
                        group_id = %group_id,
                        artifact_id = %artifact_id,
                        version = %version,
                        "support POM (parent or imported BOM) not in store; offline build may fail to resolve it; run `rv sync`"
                    );
                }
            }
        }
        Ok(())
    }

    async fn blob_id_for_package(
        &self,
        key: &ArtifactKey,
        package: &LockPackage,
    ) -> Result<BlobId> {
        // Use the locked variant so a concurrent GC sweep cannot delete
        // the blob between the index hit and the downstream open.
        if let Some(blob) = self.store.lookup_artifact_locked(key).await? {
            // When the global Raeva store is shared across projects,
            // Project A's `sync` populates the index with A's blob. If
            // Project B then runs `export-m2` without first syncing its own
            // lockfile, we would happily ship A's bytes labelled as B's
            // coordinate. Re-verify against B's pin so the mismatch is
            // caught with a clear "run `rv sync` first" message instead of
            // silently exporting the wrong artifact.
            if let Some(checksum) = package.checksum.as_ref() {
                verify_pin_against_blob(self.store, key, &blob, checksum).await?;
            }
            return Ok(blob);
        }

        let Some(checksum) = package.checksum.as_ref() else {
            return Err(ExportError::MissingBlob {
                key: key.to_string(),
            });
        };

        // The store is SHA-256 keyed; `resolve_pin` short-circuits SHA-1
        // pins into `UnsupportedChecksum`, so the only variant we have to
        // handle here is `Sha256`.
        let ResolvedPin::Sha256(blob) = resolve_pin(key, checksum)?;
        if !self.store.exists_async(&blob).await {
            return Err(ExportError::MissingBlob {
                key: key.to_string(),
            });
        }
        Ok(blob)
    }

    /// Thin async-side wrapper for `safe_artifact_path` so existing tests
    /// (which call `exporter.safe_artifact_path(...)`) keep working.
    #[cfg(test)]
    fn safe_artifact_path(&self, key: &ArtifactKey, package: &LockPackage) -> Result<PathBuf> {
        safe_artifact_path(&self.options, key, package)
    }
}

/// Blocking sister of `write_metadata`: writes every accumulated
/// `maven-metadata-local.xml` underneath `m2_path`. Called from
/// `spawn_blocking` so the fsync chain doesn't stall the async runtime.
fn write_metadata_blocking(m2_path: &Path, meta: &mut MetadataAccumulator) -> Result<()> {
    for (key, state) in &meta.snapshots {
        write_snapshot_metadata_blocking(m2_path, key, state)?;
    }
    // Sort each artifact's version list with Maven's `ComparableVersion`
    // before rendering so `<latest>` / `<release>` pick the right values
    // rather than whatever happens to sort lexicographically last.
    for (key, state) in meta.artifacts.iter_mut() {
        state.finalize();
        write_artifact_metadata_blocking(m2_path, key, state)?;
    }
    Ok(())
}

fn write_snapshot_metadata_blocking(
    m2_path: &Path,
    key: &SnapshotMetaKey,
    state: &SnapshotMetaState,
) -> Result<()> {
    let Some(timestamp) = state.timestamp.as_deref() else {
        debug!(
            group = %key.group_id,
            artifact = %key.artifact_id,
            base = %key.base_version,
            "no snapshot timestamp available; skipping maven-metadata-local.xml"
        );
        return Ok(());
    };
    let build_number = state.build_number.unwrap_or(0);
    let last_updated = state
        .last_updated
        .clone()
        .unwrap_or_else(|| compact_updated(timestamp).unwrap_or_default());
    let xml = render_versioned_metadata(&VersionedMetadata {
        group_id: &key.group_id,
        artifact_id: &key.artifact_id,
        base_snapshot_version: &key.base_version,
        timestamp,
        build_number,
        last_updated: &last_updated,
        entries: state.entries.clone(),
    });
    let group_path = validate_group_path(&key.group_id)?;
    validate_path_segment(&key.artifact_id, "artifact_id")?;
    validate_path_segment(&key.base_version, "version")?;
    let dir = m2_path
        .join(group_path)
        .join(&key.artifact_id)
        .join(&key.base_version);
    let dest = dir.join("maven-metadata-local.xml");
    write_metadata_atomic(&dest, &xml)?;
    Ok(())
}

fn write_artifact_metadata_blocking(
    m2_path: &Path,
    key: &ArtifactMetaKey,
    state: &ArtifactMetaState,
) -> Result<()> {
    let group_path = validate_group_path(&key.group_id)?;
    validate_path_segment(&key.artifact_id, "artifact_id")?;
    let dir = m2_path.join(&group_path).join(&key.artifact_id);
    let last_updated = state
        .last_updated
        .clone()
        .unwrap_or_else(|| "00000000000000".to_string());

    if state.is_empty() {
        return Ok(());
    }
    // `latest`/`release` honour Maven's `ComparableVersion` ordering, not
    // lexicographic. Without this `9.0.0` sorts higher than `10.0.0`.
    let latest = state.latest().expect("non-empty");
    let release = state.release();

    let xml = render_artifact_metadata(&ArtifactMetadata {
        group_id: &key.group_id,
        artifact_id: &key.artifact_id,
        latest,
        release,
        versions: state.versions.clone(),
        last_updated: &last_updated,
    });
    let dest = dir.join("maven-metadata-local.xml");
    write_metadata_atomic(&dest, &xml)?;
    Ok(())
}

/// Compute the m2 repository path for an artifact, with path traversal protection.
///
/// Returns an error if the coordinate contains path traversal sequences or
/// if the resulting path would escape the m2 directory. Packaging and
/// classifier are validated alongside group/artifact/version. This is pure
/// path math: the caller (`export_artifact_blocking`) is responsible for
/// `create_dir_all` on the artifact parent when it's actually about to
/// write into it.
fn safe_artifact_path(
    options: &ExportOptions,
    key: &ArtifactKey,
    package: &LockPackage,
) -> Result<PathBuf> {
    let fields: &[(&str, &str)] = &[
        ("group_id", &key.group_id),
        ("artifact_id", &key.artifact_id),
        ("version", &key.version),
        ("packaging", &key.packaging),
    ];
    for (field_name, value) in fields {
        if value.contains("..") || value.contains('/') || value.contains('\\') {
            return Err(ExportError::InvalidCoordinate(format!(
                "{}:{}:{} (invalid {})",
                key.group_id, key.artifact_id, key.version, field_name
            )));
        }
    }
    if let Some(classifier) = key.classifier.as_deref()
        && (classifier.contains("..") || classifier.contains('/') || classifier.contains('\\'))
    {
        return Err(ExportError::InvalidCoordinate(format!(
            "{}:{}:{} (invalid classifier)",
            key.group_id, key.artifact_id, key.version
        )));
    }

    // Snapshots: directory uses the base `-SNAPSHOT` version while the
    // filename keeps the timestamped form. Releases use the version
    // verbatim for both.
    let dir_version = package.base_snapshot_version();
    validate_path_segment(&dir_version, "version")?;

    let group_path = key.group_id.replace('.', "/");
    let filename = match key.classifier.as_deref() {
        Some(classifier) => format!(
            "{}-{}-{}.{}",
            key.artifact_id, key.version, classifier, key.packaging
        ),
        None => format!("{}-{}.{}", key.artifact_id, key.version, key.packaging),
    };
    let dest = options
        .m2_path
        .join(&group_path)
        .join(&key.artifact_id)
        .join(&dir_version)
        .join(filename);

    let m2_canonical =
        rv_config::canonicalize_existing_prefix(&options.m2_path).map_err(map_config_err)?;
    let dest_canonical = rv_config::canonicalize_existing_prefix(&dest).map_err(map_config_err)?;
    let m2_normalized = lexical_normalize(&m2_canonical);
    let dest_normalized = lexical_normalize(&dest_canonical);

    if !dest_normalized.starts_with(&m2_normalized) {
        return Err(ExportError::PathTraversal(dest));
    }

    // `safe_artifact_path` is path math only. `export_artifact_blocking`
    // is the single caller responsible for actually creating the artifact
    // parent directory (and only when we're about to write into it), so
    // doing it here too just duplicates a syscall per artifact.

    Ok(dest)
}

/// Collapse `.` and `..` segments lexically (no filesystem touches). Used
/// to harden the containment check after `canonicalize_existing_prefix`,
/// which leaves the non-existent tail un-normalised.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // Only pop a real directory segment; never go above the
                // root prefix (which `pop` would no-op on anyway).
                if !out.pop() {
                    out.push(component);
                }
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// Convert a `rv_config::ConfigError` (only ever an io::Error from the
/// `canonicalize_existing_prefix` helper) into an `ExportError`.
fn map_config_err(err: rv_config::ConfigError) -> ExportError {
    match err {
        rv_config::ConfigError::Io(io) => ExportError::IoError(io),
        other => ExportError::IoError(std::io::Error::other(other.to_string())),
    }
}

/// Atomically replace a file, handling platform differences.
///
/// On Unix, `fs::rename` atomically replaces the destination.
/// On Windows, `fs::rename` fails if the destination exists, so we
/// remove it first (ignoring NotFound errors) and then rename.
fn atomic_replace(src: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::rename(src, dest)
    }

    #[cfg(not(unix))]
    {
        // On Windows, remove the destination first if it exists
        match fs::remove_file(dest) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        fs::rename(src, dest)
    }
}

/// On non-Unix, `export_artifact_blocking`'s `dest.exists()` probe and the
/// subsequent `atomic_replace` are not atomic together: the
/// `remove_file` + `rename` pair inside `atomic_replace` can interleave
/// with another exporter's identical sequence, publishing partial bytes
/// (or losing the rename to ERROR_ALREADY_EXISTS). Take a process-local
/// mutex keyed on the destination path so the probe + replace pair runs
/// serially for any given destination. Unix is already atomic via
/// `rename(2)` so no lock is needed.
#[cfg(not(unix))]
fn dest_lock_registry() -> &'static std::sync::Mutex<
    std::collections::HashMap<PathBuf, std::sync::Arc<std::sync::Mutex<()>>>,
> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex as StdMutex, OnceLock};
    static REGISTRY: OnceLock<StdMutex<HashMap<PathBuf, Arc<StdMutex<()>>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// Acquire a per-destination mutex on non-Unix so the
/// `exists`-then-`replace` pair runs serially for the same dest. Returns
/// `None` on Unix, where atomic `rename(2)` makes the lock unnecessary.
#[cfg(not(unix))]
fn lock_destination(dest: &Path) -> std::sync::Arc<std::sync::Mutex<()>> {
    let key = dest.to_path_buf();
    let mut registry = dest_lock_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry
        .entry(key)
        .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(())))
        .clone()
}

/// Re-hash the source blob and compare against the recorded `BlobId` so an
/// on-disk tampered file cannot make it into the user's `.m2`. Computed
/// alongside the SHA-1 sidecar in a single streaming pass to keep memory
/// flat for large artifacts.
fn verify_and_hash(src: &Path, blob_id: &BlobId) -> Result<(String, String)> {
    use std::io::Read;
    let mut file = fs::File::open(src).map_err(ExportError::IoError)?;
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(ExportError::IoError)?;
        if n == 0 {
            break;
        }
        sha256.update(&buf[..n]);
        sha1.update(&buf[..n]);
    }
    let sha256_bytes: [u8; 32] = sha256.finalize().into();
    let sha256_hex = hex::encode(sha256_bytes);
    let sha1_bytes: [u8; 20] = sha1.finalize().into();
    let sha1_hex = hex::encode(sha1_bytes);
    if !ct_eq_hex_sha256(&sha256_hex, blob_id.as_str()) {
        return Err(ExportError::IoError(std::io::Error::other(format!(
            "store corruption: blob at {} has SHA-256 {} but index recorded {}",
            src.display(),
            sha256_hex,
            blob_id.as_str()
        ))));
    }
    Ok((sha256_hex, sha1_hex))
}

/// Constant-time SHA-256 hex equality: decode both sides to a fixed
/// `[u8; 32]` and feed them through `subtle::ConstantTimeEq` so the
/// comparison runs in time independent of the digest content. Hex
/// equality with `==` short-circuits at the first byte difference and is
/// observable by a process that can time exports against attacker-chosen
/// blobs.
///
/// Returns `false` (not an error) when either side fails to decode; the
/// caller treats that the same as a mismatch.
fn ct_eq_hex_sha256(a: &str, b: &str) -> bool {
    let mut a_bytes = [0u8; 32];
    let mut b_bytes = [0u8; 32];
    if hex::decode_to_slice(a, &mut a_bytes).is_err() {
        return false;
    }
    if hex::decode_to_slice(b, &mut b_bytes).is_err() {
        return false;
    }
    a_bytes.ct_eq(&b_bytes).into()
}

/// Constant-time SHA-1 hex equality, same shape as `ct_eq_hex_sha256`
/// but for 20-byte digests (Maven's `.sha1` sidecars and SHA-1 pins).
fn ct_eq_hex_sha1(a: &str, b: &str) -> bool {
    let mut a_bytes = [0u8; 20];
    let mut b_bytes = [0u8; 20];
    if hex::decode_to_slice(a, &mut a_bytes).is_err() {
        return false;
    }
    if hex::decode_to_slice(b, &mut b_bytes).is_err() {
        return false;
    }
    a_bytes.ct_eq(&b_bytes).into()
}

/// Standalone blocking function for exporting a single artifact.
/// Called from spawn_blocking to avoid blocking the async runtime. Verifies
/// blob integrity before linking/copying, attempts the link directly to avoid
/// a TOCTOU window, and skips filesystem mutations when `dry_run` is set.
fn export_artifact_blocking(
    src: &Path,
    dest: &Path,
    options: &ExportOptions,
    key_str: &str,
    blob_id: &BlobId,
) -> Result<ExportOutcome> {
    // Check src existence here for a useful error, but the link attempt
    // itself is the authoritative check; if src disappears between here and
    // the link we get a clear OS error rather than a panic or silent bad link.
    if !src.is_file() {
        return Err(ExportError::MissingBlob {
            key: key_str.to_string(),
        });
    }

    // On non-Unix the rename below isn't atomic across exporters; serialise
    // via a per-destination mutex. Keep the mutex `Arc` alive on the stack
    // so the `MutexGuard` borrow stays valid for the rest of the function.
    #[cfg(not(unix))]
    let _dest_mtx = lock_destination(dest);
    #[cfg(not(unix))]
    let _dest_guard = _dest_mtx
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // In dry_run mode, skip all filesystem mutations entirely. We still
    // accept the call for any source that exists.
    if options.dry_run {
        return Ok(ExportOutcome::Exported(options.link_strategy));
    }

    // We're about to publish bytes, so hash the source now to both verify
    // CAS integrity and write the sidecars.
    let (_sha256_hex, sha1_hex) = verify_and_hash(src, blob_id)?;

    let Some(parent) = dest.parent() else {
        return Err(ExportError::IoError(std::io::Error::other(
            "missing parent directory for artifact path",
        )));
    };
    fs::create_dir_all(parent)?;

    // Stage the link in a unique temp path in the same directory so the
    // final rename is atomic. `NamedTempFile::new_in` already encodes the
    // process-id + counter dance and removes itself on drop if we don't
    // persist, so no manual `format!(".{}.{}.tmp", pid, counter)` plus
    // `remove_file` cleanup is needed.
    let temp = tempfile::NamedTempFile::new_in(parent)?;
    // The link helper wants to create the file itself, so we close (and
    // delete) the empty file the tempfile crate just opened, then keep
    // ownership of the path so it's still reserved.
    let (_, temp_path) = temp.keep().map_err(|e| ExportError::IoError(e.error))?;
    // `keep()` leaves the empty file in place; remove it so the link
    // syscalls below get a clean target. The unique name is still reserved
    // for us because no other process knows about it.
    let _ = fs::remove_file(&temp_path);

    // Attempt the link directly; map source-not-found to MissingBlob below.
    let used_strategy = match link_with_fallback(src, &temp_path, options.link_strategy) {
        Ok(strategy) => strategy,
        Err(e) => {
            let _ = fs::remove_file(&temp_path);
            // Surface source-not-found as a MissingBlob error for cleaner diagnostics.
            match &e {
                super::error::LinkError::SourceMissing { .. } => {
                    return Err(ExportError::MissingBlob {
                        key: key_str.to_string(),
                    });
                }
                super::error::LinkError::IoError { source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    return Err(ExportError::MissingBlob {
                        key: key_str.to_string(),
                    });
                }
                _ => return Err(e.into()),
            }
        }
    };

    // Check the destination immediately before the rename so the
    // overwrite / identical-skip decision uses the freshest state. An
    // up-front `dest.exists()` probe would open a TOCTOU window where a
    // concurrent exporter could publish (or remove) the artifact in between.
    match fs::symlink_metadata(dest) {
        Ok(_) => {
            if is_identical_blocking(src, dest, blob_id)? {
                debug!(path = %dest.display(), "skipping identical artifact");
                let _ = fs::remove_file(&temp_path);
                ensure_sidecars(dest, blob_id, &sha1_hex)?;
                return Ok(ExportOutcome::Skipped);
            }
            if !options.overwrite {
                let actual = BlobId::from_file(dest)
                    .map(|b| b.as_str().to_string())
                    .unwrap_or_else(|_| "<unreadable>".to_string());
                let _ = fs::remove_file(&temp_path);
                return Err(ExportError::DestinationMismatch {
                    key: key_str.to_string(),
                    path: dest.to_path_buf(),
                    expected: blob_id.as_str().to_string(),
                    actual,
                });
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            let _ = fs::remove_file(&temp_path);
            return Err(ExportError::IoError(e));
        }
    }

    // Normalise perms on the staged tempfile (Copy only). The file came out
    // of the CAS as a read-only 0o444 blob, but Maven's offline resolver
    // (and plugins like the shade/assembly steps that rewrite artifacts in
    // place) expect a writable-by-owner 0o644 file in the local repository.
    // Hardlink destinations share the CAS inode, so we must NOT chmod them
    // here (that would strip write bits from the shared blob), and symlinks
    // have no meaningful perms of their own.
    if let LinkStrategy::Copy = used_strategy
        && let Err(e) = set_artifact_perms(&temp_path)
    {
        warn!(path = %temp_path.display(), error = %e, "failed to set artifact permissions");
    }

    // Stage sidecars as tempfiles before publishing the artifact. Then
    // rename the sidecars FIRST and the artifact LAST: a crash never leaves
    // a (new) artifact visible without its checksum sidecars next to it.
    let dest_str = dest.as_os_str().to_string_lossy();
    let sha256_path = PathBuf::from(format!("{}.sha256", dest_str));
    let sha1_path = PathBuf::from(format!("{}.sha1", dest_str));
    let sha256_temp = stage_sidecar_tempfile(&sha256_path, blob_id.as_str()).inspect_err(|_| {
        let _ = fs::remove_file(&temp_path);
    })?;
    let sha1_temp = stage_sidecar_tempfile(&sha1_path, &sha1_hex).inspect_err(|_| {
        let _ = fs::remove_file(&temp_path);
    })?;

    if let Err(e) = sha256_temp.persist(&sha256_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(ExportError::IoError(e.error));
    }
    if let Err(e) = sha1_temp.persist(&sha1_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(ExportError::IoError(e.error));
    }

    if let Err(e) = atomic_replace(&temp_path, dest) {
        let _ = fs::remove_file(&temp_path);
        return Err(ExportError::IoError(e));
    }

    // Persist the parent directory entry so the renames survive a power
    // loss. Data was already synced inside `stage_sidecar_tempfile` and
    // (for copy) inside `copy_file`.
    if let Some(parent) = dest.parent() {
        fsync_dir(parent);
    }

    Ok(ExportOutcome::Exported(used_strategy))
}

/// Stage a sidecar's content in a sibling tempfile, write + fsync, but do
/// not publish it. Returned `NamedTempFile` is the staged file; call
/// `persist` to rename it into place.
fn stage_sidecar_tempfile(target: &Path, content: &str) -> Result<tempfile::NamedTempFile> {
    let parent = target.parent().ok_or_else(|| {
        ExportError::IoError(std::io::Error::other("sidecar path missing parent"))
    })?;
    fs::create_dir_all(parent).map_err(ExportError::IoError)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(ExportError::IoError)?;
    temp.as_file_mut()
        .write_all(content.as_bytes())
        .map_err(ExportError::IoError)?;
    temp.as_file().sync_all().map_err(ExportError::IoError)?;
    Ok(temp)
}

/// Write a single sidecar file via a temp file + rename so observers never
/// see partial content. Routes through `tempfile::NamedTempFile::persist`
/// so the temp create + atomic-replace dance is platform-correct (on
/// Windows it goes through `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`
/// internally) and the temp file is cleaned up on error via `Drop`.
fn write_sidecar_atomic(path: &Path, content: &str) -> Result<()> {
    let Some(parent) = path.parent() else {
        // No parent: degrade to a direct write, but still fsync so a crash
        // doesn't leave a zero-byte sidecar.
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        return Ok(());
    };
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    // Crash-safe write: write + fsync on the temp file BEFORE persist. The
    // rename without the data fsync can publish an empty sidecar after a
    // power loss because the directory entry is durable before the bytes.
    temp.as_file_mut().write_all(content.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|e| ExportError::IoError(e.error))?;
    fsync_dir(parent);
    Ok(())
}

/// Best-effort fsync of a directory after a rename, so the new entry survives
/// a power loss. Silently ignored on platforms where opening a directory for
/// `sync_all` is unsupported (some Windows configurations).
fn fsync_dir(dir: &Path) {
    if let Ok(handle) = fs::File::open(dir)
        && let Err(err) = handle.sync_all()
    {
        debug!(
            path = %dir.display(),
            error = %err,
            "failed to fsync directory after rename"
        );
    }
}

/// Make sure the `.sha256` and `.sha1` sidecars next to `dest` exist and hold
/// the expected digests. Repairs missing or stale sidecars in-place.
fn ensure_sidecars(dest: &Path, blob_id: &BlobId, sha1_hex: &str) -> Result<()> {
    let dest_str = dest.as_os_str().to_string_lossy();
    let sha256_path = PathBuf::from(format!("{}.sha256", dest_str));
    let sha1_path = PathBuf::from(format!("{}.sha1", dest_str));

    // Constant-time digest equality: `==` on hex strings short-circuits at
    // the first differing byte and would leak the digest-bytes-already-OK
    // count to an attacker who can race the repair path.
    let sha256_ok = fs::read_to_string(&sha256_path)
        .map(|s| ct_eq_hex_sha256(s.trim(), blob_id.as_str()))
        .unwrap_or(false);
    if !sha256_ok {
        debug!(path = %sha256_path.display(), "repairing sha256 sidecar");
        write_sidecar_atomic(&sha256_path, blob_id.as_str())?;
    }

    let sha1_ok = fs::read_to_string(&sha1_path)
        .map(|s| ct_eq_hex_sha1(s.trim(), sha1_hex))
        .unwrap_or(false);
    if !sha1_ok {
        debug!(path = %sha1_path.display(), "repairing sha1 sidecar");
        write_sidecar_atomic(&sha1_path, sha1_hex)?;
    }

    Ok(())
}

/// Check if destination file is identical to the blob in the store.
fn is_identical_blocking(src: &Path, dest: &Path, blob_id: &BlobId) -> Result<bool> {
    let (dest_meta, src_meta) = match (fs::metadata(dest), fs::metadata(src)) {
        (Ok(d), Ok(s)) => (d, s),
        _ => return Ok(false),
    };

    if dest_meta.len() != src_meta.len() {
        return Ok(false);
    }

    // For hardlinks: same device + same inode means identical file
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if dest_meta.dev() == src_meta.dev() && dest_meta.ino() == src_meta.ino() {
            return Ok(true);
        }
    }

    // Same size but different inode (or non-Unix): compute hash only for dest
    // We already know the source's hash (it's the blob_id), so no need to hash it again.
    // Use the constant-time hex comparator: `BlobId`'s derived `PartialEq`
    // ultimately runs `==` on the hex string, which short-circuits on
    // first-differing byte. Decode both sides to a fixed `[u8; 32]` and
    // compare via `subtle::ConstantTimeEq` instead.
    let existing = BlobId::from_file(dest)?;
    Ok(ct_eq_hex_sha256(existing.as_str(), blob_id.as_str()))
}

#[derive(Debug, Clone, Copy)]
enum ExportOutcome {
    Exported(LinkStrategy),
    Skipped,
}

impl ExportStats {
    fn record(&mut self, outcome: ExportOutcome) {
        match outcome {
            ExportOutcome::Exported(strategy) => {
                self.exported_count += 1;
                match strategy {
                    LinkStrategy::Copy => self.copied_count += 1,
                    LinkStrategy::Hardlink | LinkStrategy::Symlink => self.linked_count += 1,
                }
            }
            ExportOutcome::Skipped => {
                self.skipped_count += 1;
            }
        }
    }
}

/// Compare the indexed blob for `key` against the lockfile pin. The indexed
/// blob is whatever Project A's `sync` populated into the shared store; if
/// the current project's lockfile pins something else, we must refuse the
/// export instead of shipping the wrong bytes.
///
/// - For an SHA-256 pin we compare the indexed `BlobId` directly with the
///   pin digest, since `BlobId` *is* the SHA-256.
/// - For an SHA-1 pin we re-hash the existing blob on disk with SHA-1 and
///   compare against the pin.
async fn verify_pin_against_blob(
    store: &Store,
    key: &ArtifactKey,
    indexed: &BlobId,
    checksum: &Checksum,
) -> Result<()> {
    let Some(algorithm) = rv_config::normalize_checksum_algorithm(&checksum.algorithm) else {
        return Err(ExportError::UnsupportedChecksum {
            key: key.to_string(),
            algorithm: checksum.algorithm.clone(),
        });
    };
    let expected = checksum.digest.trim().to_ascii_lowercase();
    match algorithm {
        "sha256" => {
            // BlobId is canonical lowercase hex already. Use the
            // constant-time comparator: `!=` would short-circuit at the
            // first differing byte and leak a timing oracle to an
            // attacker who can race builds against chosen blobs.
            if !ct_eq_hex_sha256(indexed.as_str(), &expected) {
                return Err(ExportError::PinMismatch {
                    key: key.to_string(),
                    algorithm: algorithm.to_string(),
                    expected,
                    actual: indexed.as_str().to_string(),
                });
            }
        }
        "sha1" => {
            let path = store.get_path(indexed);
            let key_display = key.to_string();
            let actual = spawn_blocking(move || rv_repo::sha1_hex_file(&path))
                .await
                .map_err(|e| ExportError::IoError(std::io::Error::other(e.to_string())))?
                .map_err(|e| ExportError::IoError(std::io::Error::other(e.to_string())))?;
            if !ct_eq_hex_sha1(&actual, &expected) {
                return Err(ExportError::PinMismatch {
                    key: key_display,
                    algorithm: algorithm.to_string(),
                    expected,
                    actual,
                });
            }
        }
        other => {
            return Err(ExportError::UnsupportedChecksum {
                key: key.to_string(),
                algorithm: other.to_string(),
            });
        }
    }
    Ok(())
}

/// Parsed lockfile pin for a single artifact.
///
/// The on-disk store is SHA-256 keyed; SHA-1 pins cannot address a blob
/// directly and are short-circuited in [`resolve_pin`] to
/// [`ExportError::UnsupportedChecksum`].
enum ResolvedPin {
    Sha256(BlobId),
}

fn resolve_pin(key: &ArtifactKey, checksum: &Checksum) -> Result<ResolvedPin> {
    let canonical =
        rv_config::normalize_checksum_algorithm(&checksum.algorithm).ok_or_else(|| {
            ExportError::UnsupportedChecksum {
                key: key.to_string(),
                algorithm: checksum.algorithm.clone(),
            }
        })?;
    match canonical {
        "sha256" => {
            let blob =
                BlobId::from_str(&checksum.digest).map_err(|err| ExportError::InvalidChecksum {
                    key: key.to_string(),
                    reason: err.to_string(),
                })?;
            Ok(ResolvedPin::Sha256(blob))
        }
        other => Err(ExportError::UnsupportedChecksum {
            key: key.to_string(),
            algorithm: other.to_string(),
        }),
    }
}

/// Validate a single path segment (no `..`, `/`, or `\`).
fn validate_path_segment(value: &str, field_name: &str) -> Result<()> {
    if value.is_empty() || value.contains("..") || value.contains('/') || value.contains('\\') {
        return Err(ExportError::InvalidCoordinate(format!(
            "invalid {field_name}: {value:?}"
        )));
    }
    Ok(())
}

/// Validate a group_id and return its slash-separated path form.
fn validate_group_path(group_id: &str) -> Result<String> {
    if group_id.is_empty()
        || group_id.contains("..")
        || group_id.contains('/')
        || group_id.contains('\\')
    {
        return Err(ExportError::InvalidCoordinate(format!(
            "invalid group_id: {group_id:?}"
        )));
    }
    Ok(group_id.replace('.', "/"))
}

/// Build the companion-POM `LockPackage` for a non-POM package. The POM
/// shares the artifact's coordinate and snapshot timestamp (so it lands in
/// the same versioned directory) but is recorded as `packaging = "pom"`.
fn pom_package_from(package: &LockPackage) -> LockPackage {
    LockPackage {
        group_id: package.group_id.clone(),
        artifact_id: package.artifact_id.clone(),
        version: package.version.clone(),
        snapshot_timestamp: package.snapshot_timestamp.clone(),
        packaging: "pom".to_string(),
        classifier: None,
        repo_url: package.repo_url.clone(),
        checksum: None,
        system_path: None,
        direct_scope: None,
        extra: std::collections::BTreeMap::new(),
    }
}

/// Build a synthetic `LockPackage` for a parent POM discovered by walking the
/// `<parent>` chain. Parent POMs are not lockfile packages, so we only know
/// their coordinate; that is enough for the layout math in
/// `safe_artifact_path`. The `snapshot_timestamp` is derived from the version
/// so timestamped-snapshot parents still route to their `-SNAPSHOT` directory.
fn synthetic_pom_package(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    repo_url: &str,
) -> LockPackage {
    LockPackage {
        group_id: group_id.to_string(),
        artifact_id: artifact_id.to_string(),
        version: version.to_string(),
        snapshot_timestamp: None,
        packaging: "pom".to_string(),
        classifier: None,
        repo_url: repo_url.to_string(),
        checksum: None,
        system_path: None,
        direct_scope: None,
        extra: std::collections::BTreeMap::new(),
    }
}

/// Read a POM blob from disk and return its support-POM coordinates: the
/// `<parent>` (if any) plus every import-scoped (`scope=import`, `type=pom`)
/// `<dependencyManagement>` BOM. Parse failures yield an empty set, so a
/// malformed POM simply ends that branch of the walk rather than failing the
/// export.
///
/// Import versions that are a `${property}` are resolved against the POM's own
/// properties (the common same-POM case); a version still containing `${` after
/// that (a parent-defined property) is skipped *with a warning*, since such
/// imports almost always arrive via a `<parent>` chain that is walked anyway.
fn read_support_refs(path: &Path) -> Option<Vec<(String, String, String)>> {
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let pom = rv_maven_model::Pom::parse(&text).ok()?;

    let mut refs: Vec<(String, String, String)> = Vec::new();
    if let Some(parent) = pom.parent.as_ref() {
        refs.push((
            parent.group_id.clone(),
            parent.artifact_id.clone(),
            parent.version.clone(),
        ));
    }
    if let Some(dm) = pom.dependency_management.as_ref() {
        for dep in &dm.dependencies {
            let is_import =
                dep.scope.as_deref() == Some("import") && dep.type_.as_deref() == Some("pom");
            if !is_import {
                continue;
            }
            let Some(raw_version) = dep.version.as_deref() else {
                continue;
            };
            let version = pom
                .properties
                .interpolate_str_no_project(raw_version)
                .unwrap_or_else(|_| raw_version.to_string());
            if version.contains("${") {
                // Unresolved after same-POM interpolation: the version property
                // is defined elsewhere (almost always an inherited `<parent>`).
                // We can't resolve the BOM coordinate from this POM alone, so we
                // can't emit its `_remote.repositories` marker. Warn rather than
                // skip silently so an incomplete offline export is diagnosable.
                warn!(
                    group_id = %dep.group_id,
                    artifact_id = %dep.artifact_id,
                    version = %raw_version,
                    "import-scoped BOM version is an unresolved property (likely defined in a parent POM); \
                     its `_remote.repositories` marker was not emitted and an offline build may fail to \
                     resolve it; re-run `rv sync` to confirm it is present in ~/.m2"
                );
                continue;
            }
            refs.push((dep.group_id.clone(), dep.artifact_id.clone(), version));
        }
    }
    Some(refs)
}

/// Best-effort extraction of (timestamp, build_number) for a package's
/// snapshot metadata. Falls back to parsing the version string when
/// `snapshot_timestamp` is missing the build-number component.
fn resolve_snapshot_stamp(package: &LockPackage) -> Option<(String, Option<u32>)> {
    if let Some(raw) = package.snapshot_timestamp.as_deref()
        && let Some((ts, build)) = parse_snapshot_timestamp(raw)
    {
        let build = build.or_else(|| build_number_from_version(&package.version));
        return Some((ts, build));
    }
    // Try to infer from the version string itself.
    let mut parts = package.version.rsplitn(3, '-');
    let build_str = parts.next()?;
    let ts = parts.next()?;
    let _base = parts.next()?;
    let build = build_str.parse::<u32>().ok();
    let (ts, parsed_build) = parse_snapshot_timestamp(ts)?;
    Some((ts, build.or(parsed_build)))
}

/// Derive the `lastUpdated` stamp for artifact-level metadata. Prefers the
/// snapshot timestamp when present (for reproducibility) and otherwise
/// returns `None` so the caller can fall back to a placeholder.
fn derived_last_updated(package: &LockPackage) -> Option<String> {
    if let Some(raw) = package.snapshot_timestamp.as_deref()
        && let Some((ts, _)) = parse_snapshot_timestamp(raw)
        && let Some(updated) = compact_updated(&ts)
    {
        return Some(updated);
    }
    None
}

/// Insert a snapshot entry into the list, replacing any existing entry that
/// matches on (extension, classifier).
fn push_snapshot_entry(entries: &mut Vec<SnapshotVersionEntry>, entry: SnapshotVersionEntry) {
    if let Some(existing) = entries
        .iter_mut()
        .find(|e| e.extension == entry.extension && e.classifier == entry.classifier)
    {
        *existing = entry;
    } else {
        entries.push(entry);
    }
}

fn default_m2_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".m2").join("repository"))
}

/// Make the exported artifact writable-by-owner and world-readable. On Unix
/// this hard-codes mode `0o644`: the file came out of the CAS as a read-only
/// `0o444` blob, but a Maven local repository entry must stay writable by its
/// owner. Strict offline Maven (and in-place rewriters such as the shade /
/// assembly plugins) treat a `0o444` artifact as un-writable and fail; CI and
/// shared-store users running `mvn` under a different uid still need group /
/// world read, which `set_readonly(false)` alone would not guarantee. The
/// umask is a *write* mask and does not apply to `set_permissions`, so we set
/// the mode explicitly. On non-Unix we clear the read-only attribute because
/// mode bits don't translate.
///
/// Hardlinks must never reach this function; see the comment at the call
/// site. Mutating perms here would rewrite the shared CAS inode and quietly
/// break future readers/writers.
fn set_artifact_perms(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
    }
    #[cfg(not(unix))]
    {
        let metadata = fs::metadata(path)?;
        let mut perms = metadata.permissions();
        perms.set_readonly(false);
        fs::set_permissions(path, perms)
    }
}

#[cfg(test)]
mod tests {
    use super::super::error::ExportError;
    use super::super::link::LinkStrategy;
    use super::{ExportOptions, Exporter, lexical_normalize};
    use rv_config::{Checksum, LockPackage, LockPlatform, Lockfile, Platform};
    use rv_store::{ArtifactKey, Store};
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    /// Regression: a path that lexically contains `..` segments
    /// must be collapsed before the containment check runs, otherwise
    /// `dest.starts_with(root)` returns true for paths that resolve
    /// outside the root once `..` is honoured.
    #[test]
    fn lexical_normalize_collapses_parent_dir() {
        let normalised = lexical_normalize(std::path::Path::new("/m2/com/example/../escape"));
        assert_eq!(normalised, std::path::Path::new("/m2/com/escape"));
        let still_inside = lexical_normalize(std::path::Path::new("/m2/com/./example"));
        assert_eq!(still_inside, std::path::Path::new("/m2/com/example"));
    }

    /// `read_support_refs` returns the `<parent>` and every import-scoped BOM
    /// whose version resolves against the POM's own properties, and *omits* an
    /// import whose version stays an unresolved `${property}` (the parent-only
    /// -property residual, skipped with a warning rather than mis-resolved).
    #[test]
    fn read_support_refs_resolves_same_pom_props_and_skips_parent_only() {
        let dir = tempdir().expect("dir");
        let pom_path = dir.path().join("pom.xml");
        let pom = "<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>the-parent</artifactId>\
<version>9.9.9</version></parent>\
<groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>\
<properties><bom.version>2.2.2</bom.version></properties>\
<dependencyManagement><dependencies>\
<dependency><groupId>com.example</groupId><artifactId>resolvable-bom</artifactId>\
<version>${bom.version}</version><type>pom</type><scope>import</scope></dependency>\
<dependency><groupId>com.example</groupId><artifactId>parent-prop-bom</artifactId>\
<version>${parent.only.version}</version><type>pom</type><scope>import</scope></dependency>\
</dependencies></dependencyManagement></project>";
        fs::write(&pom_path, pom).expect("write pom");

        let refs = super::read_support_refs(&pom_path).expect("parse");

        assert!(
            refs.contains(&(
                "com.example".to_string(),
                "the-parent".to_string(),
                "9.9.9".to_string(),
            )),
            "parent must be a support ref: {refs:?}"
        );
        assert!(
            refs.contains(&(
                "com.example".to_string(),
                "resolvable-bom".to_string(),
                "2.2.2".to_string(),
            )),
            "same-POM-property import BOM must resolve: {refs:?}"
        );
        assert!(
            !refs.iter().any(|(_, a, _)| a == "parent-prop-bom"),
            "parent-only-property import BOM must be skipped: {refs:?}"
        );
    }

    #[tokio::test]
    async fn export_rejects_pin_mismatch_against_indexed_blob_sha256() {
        // Shared global store. Project A's sync populated the index
        // with blob_a for key K; Project B's lockfile pins blob_b for K.
        // export-m2 must NOT silently ship A's bytes; it must fail with a
        // clear "run `rv sync` first" hint.
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let blob_a = store.put_bytes(b"project-a-bytes").await.expect("put a");
        let _blob_b = store
            .put_bytes(b"project-b-different-bytes")
            .await
            .expect("put b");

        let key = ArtifactKey::new("com.example", "shared", "1.0.0", "jar", None);
        // Index points at A's blob (as if `rv sync` ran for project A first).
        store.add_artifact(&key, &blob_a).await.expect("add a");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "shared".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                // Project B's lockfile pins B's digest, NOT A's.
                checksum: Some(Checksum::new(
                    "sha256",
                    rv_config::BlobId::from_bytes(b"project-b-different-bytes").as_str(),
                )),
                system_path: None,
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2_dir.path().join("repository"),
        };
        let exporter = Exporter::new(options, &store);

        let err = exporter
            .export_lock(&lock, None)
            .await
            .expect_err("must reject pin mismatch");
        let msg = err.to_string();
        assert!(
            msg.contains("does not match") && msg.contains("rv sync"),
            "expected pin-mismatch hint, got: {msg}"
        );
    }

    #[tokio::test]
    async fn export_rejects_pin_mismatch_against_indexed_blob_sha1() {
        // Same scenario as above, but the lockfile pins SHA-1.
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let blob_a = store.put_bytes(b"project-a-bytes").await.expect("put a");

        let key = ArtifactKey::new("com.example", "shared", "1.0.0", "jar", None);
        store.add_artifact(&key, &blob_a).await.expect("add a");

        // A bogus 40-char hex digest that cannot match SHA-1 of A's bytes.
        let bogus_sha1 = "0".repeat(40);

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "shared".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                checksum: Some(Checksum::new("sha1", bogus_sha1)),
                system_path: None,
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2_dir.path().join("repository"),
        };
        let exporter = Exporter::new(options, &store);

        let err = exporter
            .export_lock(&lock, None)
            .await
            .expect_err("must reject sha1 pin mismatch");
        let msg = err.to_string();
        assert!(
            msg.contains("does not match") && msg.contains("sha1"),
            "expected sha1 pin-mismatch hint, got: {msg}"
        );
    }

    #[test]
    fn write_sidecar_atomic_writes_full_content_and_no_temp_leftover() {
        // The temp file must be opened, written, fsynced, then renamed.
        // Verifying the well-known idiom by asserting end-state: the final
        // file holds the full content and no `.tmp` leftovers remain.
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("artifact.jar.sha256");
        super::write_sidecar_atomic(&target, "deadbeef").expect("write sidecar");
        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            "deadbeef",
            "sidecar must contain the exact digest"
        );
        let leftover = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".sidecar."));
        assert!(!leftover, "no temp sidecar file should remain after rename");
    }

    #[tokio::test]
    async fn export_lock_exports_jar_and_pom() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_id = store.put_bytes(b"jar").await.expect("jar");
        let pom_id = store.put_bytes(b"pom").await.expect("pom");

        let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        store
            .add_artifact(&jar_key, &jar_id)
            .await
            .expect("add jar");

        let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
        store
            .add_artifact(&pom_key, &pom_id)
            .await
            .expect("add pom");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2_dir.path().join("repository"),
        };
        let exporter = Exporter::new(options, &store);

        let stats = exporter.export_lock(&lock, None).await.expect("export");
        assert_eq!(stats.exported_count, 2);
        assert_eq!(stats.copied_count, 2);
        assert_eq!(stats.linked_count, 0);
        assert_eq!(stats.skipped_count, 0);

        let jar_path = m2_dir
            .path()
            .join("repository")
            .join("com")
            .join("example")
            .join("demo")
            .join("1.0.0")
            .join("demo-1.0.0.jar");
        let pom_path = m2_dir
            .path()
            .join("repository")
            .join("com")
            .join("example")
            .join("demo")
            .join("1.0.0")
            .join("demo-1.0.0.pom");

        assert_eq!(fs::read(&jar_path).expect("jar read"), b"jar");
        assert_eq!(fs::read(&pom_path).expect("pom read"), b"pom");
    }

    #[tokio::test]
    async fn export_lock_skips_identical_files() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_id = store.put_bytes(b"jar").await.expect("jar");
        let pom_id = store.put_bytes(b"pom").await.expect("pom");

        let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        store
            .add_artifact(&jar_key, &jar_id)
            .await
            .expect("add jar");

        let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
        store
            .add_artifact(&pom_key, &pom_id)
            .await
            .expect("add pom");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2_dir.path().join("repository"),
        };
        let exporter = Exporter::new(options, &store);

        let stats = exporter.export_lock(&lock, None).await.expect("export");
        assert_eq!(stats.exported_count, 2);

        let stats = exporter.export_lock(&lock, None).await.expect("export");
        assert_eq!(stats.exported_count, 0);
        assert_eq!(stats.skipped_count, 2);
    }

    /// Build a `LockPackage` mirroring an `ArtifactKey` for use in tests that
    /// exercise path-construction without an actual lockfile round-trip.
    fn pkg_from_key(key: &ArtifactKey) -> LockPackage {
        LockPackage {
            group_id: key.group_id.clone(),
            artifact_id: key.artifact_id.clone(),
            version: key.version.clone(),
            snapshot_timestamp: None,
            packaging: key.packaging.clone(),
            classifier: key.classifier.clone(),
            repo_url: String::new(),
            checksum: None,
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn rejects_path_traversal_in_group_id() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let m2_dir = tempdir().expect("m2 dir");
        fs::create_dir_all(m2_dir.path().join("repository")).expect("create m2");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2_dir.path().join("repository"),
        };
        let exporter = Exporter::new(options, &store);

        let cases = [
            ArtifactKey::new("../../etc", "passwd", "1.0.0", "jar", None),
            ArtifactKey::new("com/example", "demo", "1.0.0", "jar", None),
            ArtifactKey::new("com.example", "demo\\..\\etc", "1.0.0", "jar", None),
            ArtifactKey::new("com.example", "demo", "../../../etc", "jar", None),
            ArtifactKey::new("com.example", "demo", "1.0.0", "../evil", None),
            ArtifactKey::new(
                "com.example",
                "demo",
                "1.0.0",
                "jar",
                Some("foo/bar".to_string()),
            ),
        ];
        for key in &cases {
            let err = exporter
                .safe_artifact_path(key, &pkg_from_key(key))
                .expect_err("path traversal must be rejected");
            assert!(
                matches!(err, ExportError::InvalidCoordinate(_)),
                "expected InvalidCoordinate, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn accepts_valid_coordinates() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let m2_dir = tempdir().expect("m2 dir");
        fs::create_dir_all(m2_dir.path().join("repository")).expect("create m2");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2_dir.path().join("repository"),
        };
        let exporter = Exporter::new(options, &store);

        // Valid coordinate should work
        let valid_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        let path = exporter
            .safe_artifact_path(&valid_key, &pkg_from_key(&valid_key))
            .expect("valid coordinate must produce a path");
        let expected = m2_dir
            .path()
            .join("repository")
            .join("com")
            .join("example")
            .join("demo")
            .join("1.0.0")
            .join("demo-1.0.0.jar");
        assert_eq!(path, expected);

        // Dots in group_id are fine (they get converted to path separators)
        let valid_key = ArtifactKey::new("org.apache.maven", "maven-core", "3.9.0", "jar", None);
        let path = exporter
            .safe_artifact_path(&valid_key, &pkg_from_key(&valid_key))
            .expect("dotted group_id must produce a path");
        let expected = m2_dir
            .path()
            .join("repository")
            .join("org")
            .join("apache")
            .join("maven")
            .join("maven-core")
            .join("3.9.0")
            .join("maven-core-3.9.0.jar");
        assert_eq!(path, expected);
    }

    #[tokio::test]
    async fn dry_run_does_not_create_directories() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let m2_dir = tempdir().expect("m2 dir");
        let m2_path = m2_dir.path().join("repository");
        // Do NOT pre-create the repository dir; dry_run must not create it.
        let options = ExportOptions {
            dry_run: true,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2_path.clone(),
        };
        // We need m2_path to exist for canonicalize to work; create only the root.
        fs::create_dir_all(&m2_path).expect("create m2 root");

        let exporter = Exporter::new(options, &store);
        let valid_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        let path = exporter
            .safe_artifact_path(&valid_key, &pkg_from_key(&valid_key))
            .expect("dry_run path resolution must succeed");
        let expected_parent = m2_path
            .join("com")
            .join("example")
            .join("demo")
            .join("1.0.0");
        assert_eq!(path, expected_parent.join("demo-1.0.0.jar"));
        // The artifact's parent directory must NOT have been created.
        assert!(
            !expected_parent.exists(),
            "dry_run must not create directories, but {:?} was created",
            expected_parent
        );
    }

    /// Cross-repo provenance: a support POM (parent/BOM) that resolved from a
    /// DIFFERENT repository than its child must get its OWN source-repo id in
    /// `_remote.repositories`, not the child's. `rv sync` records this
    /// provenance (support_repo_ids); export must honour it over the guessed
    /// child repo_url.
    #[tokio::test]
    async fn support_pom_marker_uses_its_own_source_repo_id() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let child_pom: &[u8] = br#"<project><modelVersion>4.0.0</modelVersion>
            <parent><groupId>com.example</groupId><artifactId>theparent</artifactId><version>2.0</version></parent>
            <artifactId>child</artifactId></project>"#;
        let parent_pom: &[u8] = br#"<project><modelVersion>4.0.0</modelVersion>
            <groupId>com.example</groupId><artifactId>theparent</artifactId><version>2.0</version><packaging>pom</packaging></project>"#;
        let jar_id = store.put_bytes(b"child-jar").await.expect("jar");
        let child_pom_id = store.put_bytes(child_pom).await.expect("child pom");
        let parent_pom_id = store.put_bytes(parent_pom).await.expect("parent pom");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "child", "1.0", "jar", None),
                &jar_id,
            )
            .await
            .unwrap();
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "child", "1.0", "pom", None),
                &child_pom_id,
            )
            .await
            .unwrap();
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "theparent", "2.0", "pom", None),
                &parent_pom_id,
            )
            .await
            .unwrap();

        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform: Platform::new("linux", "x86_64").unwrap(),
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "child".to_string(),
                version: "1.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo-a.example/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let m2_dir = tempdir().unwrap();
        let m2 = m2_dir.path().join("repository");
        fs::create_dir_all(&m2).unwrap();
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };

        let mut repo_ids = HashMap::new();
        repo_ids.insert("https://repo-a.example/".to_string(), "repo-a".to_string());
        let mut support = HashMap::new();
        support.insert(
            "com.example:theparent:2.0".to_string(),
            "repo-b".to_string(),
        );

        let exporter = Exporter::new(options, &store)
            .with_repo_ids(repo_ids)
            .with_support_repo_ids(support);
        exporter.export_lock(&lock, None).await.expect("export");

        let parent_marker = m2.join("com/example/theparent/2.0/_remote.repositories");
        let body = fs::read_to_string(&parent_marker).expect("parent marker");
        assert!(
            body.contains("theparent-2.0.pom>repo-b="),
            "parent marker must use its OWN source repo id (repo-b), got: {body}"
        );

        let child_marker = m2.join("com/example/child/1.0/_remote.repositories");
        let cbody = fs::read_to_string(&child_marker).expect("child marker");
        assert!(
            cbody.contains(">repo-a="),
            "child marker must use the child's repo id (repo-a), got: {cbody}"
        );
    }

    /// Exporting a timestamped snapshot must:
    ///
    /// 1. Place the jar at `<base-snapshot-version>/<artifact>-<timestamped>.jar`
    ///    (matching `mvn -o`'s expected layout).
    /// 2. Write a `maven-metadata-local.xml` next to it that pins the
    ///    timestamp, build number, and snapshotVersion entries.
    /// 3. Write a group-level `maven-metadata-local.xml` listing the
    ///    `<base-snapshot-version>` under `<versioning><versions>`.
    #[tokio::test]
    async fn export_lock_routes_timestamped_snapshot_to_base_dir() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_bytes: &[u8] = b"jar-snapshot";
        let pom_bytes: &[u8] = b"pom-snapshot";
        let jar_id = store.put_bytes(jar_bytes).await.expect("jar");
        let pom_id = store.put_bytes(pom_bytes).await.expect("pom");

        let timestamped = "1.0-20240101.010101-7";
        let jar_key = ArtifactKey::new("com.example", "foo", timestamped, "jar", None);
        store.add_artifact(&jar_key, &jar_id).await.expect("add");
        let pom_key = ArtifactKey::new("com.example", "foo", timestamped, "pom", None);
        store.add_artifact(&pom_key, &pom_id).await.expect("add");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "foo".to_string(),
                version: timestamped.to_string(),
                snapshot_timestamp: Some("20240101.010101".to_string()),
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        fs::create_dir_all(&m2).expect("create repository");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };
        let exporter = Exporter::new(options, &store);
        exporter.export_lock(&lock, None).await.expect("export");

        // Directory uses the base SNAPSHOT version.
        let base_dir = m2
            .join("com")
            .join("example")
            .join("foo")
            .join("1.0-SNAPSHOT");

        // Filename uses the timestamped form.
        let jar = base_dir.join("foo-1.0-20240101.010101-7.jar");
        let pom = base_dir.join("foo-1.0-20240101.010101-7.pom");
        assert!(jar.exists(), "expected jar at {:?}", jar);
        assert!(pom.exists(), "expected pom at {:?}", pom);
        assert_eq!(fs::read(&jar).expect("read jar"), jar_bytes);
        assert_eq!(fs::read(&pom).expect("read pom"), pom_bytes);

        // The OLD (buggy) layout must NOT exist.
        let buggy_dir = m2
            .join("com")
            .join("example")
            .join("foo")
            .join("1.0-20240101.010101-7");
        assert!(
            !buggy_dir.exists(),
            "timestamped directory must not be created at {:?}",
            buggy_dir
        );

        // Versioned maven-metadata-local.xml must be present and parseable.
        let versioned_meta = base_dir.join("maven-metadata-local.xml");
        let raw = fs::read_to_string(&versioned_meta).expect("read versioned meta");
        let parsed = parse_simple_xml(&raw);
        assert_eq!(
            parsed.get("groupId").map(String::as_str),
            Some("com.example")
        );
        assert_eq!(parsed.get("artifactId").map(String::as_str), Some("foo"));
        assert_eq!(
            parsed.get("version").map(String::as_str),
            Some("1.0-SNAPSHOT")
        );
        assert_eq!(
            parsed.get("timestamp").map(String::as_str),
            Some("20240101.010101")
        );
        assert_eq!(parsed.get("buildNumber").map(String::as_str), Some("7"));
        assert_eq!(parsed.get("localCopy").map(String::as_str), Some("true"));
        assert!(raw.contains("<value>1.0-20240101.010101-7</value>"));
        assert!(raw.contains("<extension>jar</extension>"));
        assert!(raw.contains("<extension>pom</extension>"));

        // Artifact-level metadata at <groupId>/<artifactId>/.
        let artifact_meta = m2
            .join("com")
            .join("example")
            .join("foo")
            .join("maven-metadata-local.xml");
        let raw = fs::read_to_string(&artifact_meta).expect("read artifact meta");
        assert!(raw.contains("<version>1.0-SNAPSHOT</version>"));
    }

    /// Mixing a release and a snapshot should generate the snapshot-style
    /// metadata only for the snapshot. Releases must not get a
    /// `maven-metadata-local.xml` inside their versioned directory.
    #[tokio::test]
    async fn export_lock_release_does_not_emit_snapshot_metadata() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_id = store.put_bytes(b"jar").await.expect("jar");
        let pom_id = store.put_bytes(b"pom").await.expect("pom");

        let jar_key = ArtifactKey::new("com.example", "demo", "2.0.0", "jar", None);
        store.add_artifact(&jar_key, &jar_id).await.expect("add");
        let pom_key = ArtifactKey::new("com.example", "demo", "2.0.0", "pom", None);
        store.add_artifact(&pom_key, &pom_id).await.expect("add");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "2.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: std::collections::BTreeMap::new(),
            }],
            edges: vec![],
            extra: std::collections::BTreeMap::new(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        fs::create_dir_all(&m2).expect("create");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };
        let exporter = Exporter::new(options, &store);
        exporter.export_lock(&lock, None).await.expect("export");

        // No versioned maven-metadata-local.xml for releases.
        let versioned = m2
            .join("com")
            .join("example")
            .join("demo")
            .join("2.0.0")
            .join("maven-metadata-local.xml");
        assert!(
            !versioned.exists(),
            "releases must not get a versioned maven-metadata-local.xml"
        );

        // The artifact-level metadata still lists the release version.
        let artifact = m2
            .join("com")
            .join("example")
            .join("demo")
            .join("maven-metadata-local.xml");
        assert!(artifact.exists());
        let raw = fs::read_to_string(&artifact).expect("read");
        assert!(raw.contains("<version>2.0.0</version>"));
        assert!(raw.contains("<release>2.0.0</release>"));
    }

    /// Lockfile-only test: write a fixture that mirrors a `rv sync` output for
    /// a snapshot, then call `Lockfile::read` + `export_lock` and verify the
    /// resulting layout end-to-end. This exercises the read path of the
    /// lockfile schema alongside the exporter.
    #[tokio::test]
    async fn lockfile_snapshot_round_trip_through_exporter() {
        use rv_config::Lockfile;

        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_id = store.put_bytes(b"jar-bytes").await.expect("jar");
        let pom_id = store.put_bytes(b"pom-bytes").await.expect("pom");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "foo", "1.0-20240101.010101-7", "jar", None),
                &jar_id,
            )
            .await
            .expect("add jar");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "foo", "1.0-20240101.010101-7", "pom", None),
                &pom_id,
            )
            .await
            .expect("add pom");

        let lock_dir = tempdir().expect("lock dir");
        let lock_path = lock_dir.path().join("rv.lock");
        let toml_lock = format!(
            r#"
schema_version = 3

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "foo"
version = "1.0-20240101.010101-7"
snapshot_timestamp = "20240101.010101"
packaging = "jar"
repo_url = "https://repo.example/maven2/"

[platforms.packages.checksum]
algorithm = "sha256"
digest = "{}"
"#,
            jar_id.as_str()
        );
        fs::write(&lock_path, toml_lock).expect("write lock");
        let lock = Lockfile::read(&lock_path).expect("read lockfile");

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        fs::create_dir_all(&m2).expect("create");
        let exporter = Exporter::new(
            ExportOptions {
                dry_run: false,
                overwrite: false,
                link_strategy: LinkStrategy::Copy,
                m2_path: m2.clone(),
            },
            &store,
        );
        exporter.export_lock(&lock, None).await.expect("export");

        let jar = m2
            .join("com")
            .join("example")
            .join("foo")
            .join("1.0-SNAPSHOT")
            .join("foo-1.0-20240101.010101-7.jar");
        assert!(jar.exists());
    }

    /// Regression: a symlinked ancestor inside the m2 root that
    /// points outside the m2 tree must be rejected by the containment
    /// check. A purely lexical check would accept this and let the export
    /// write into the symlink's real target.
    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinked_ancestor_inside_m2_root() {
        use std::os::unix::fs::symlink;

        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let m2_dir = tempdir().expect("m2 dir");
        let outside_dir = tempdir().expect("outside dir");
        let m2_path = m2_dir.path().join("repository");
        fs::create_dir_all(&m2_path).expect("create m2");

        // The group_id resolves to com/example. Plant a symlink at
        // <m2>/com that points outside the m2 tree so a write at
        // <m2>/com/example/... would escape via the symlink.
        symlink(outside_dir.path(), m2_path.join("com")).expect("create symlink");

        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2_path.clone(),
        };
        let exporter = Exporter::new(options, &store);

        let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        let result = exporter.safe_artifact_path(&key, &pkg_from_key(&key));
        let err = result.expect_err("symlinked ancestor must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("path traversal") || msg.contains("Path traversal"),
            "expected path traversal error, got: {msg}"
        );
    }

    /// An m2 path whose ancestors don't yet exist must not be rejected by
    /// the containment check (canonicalize would leave the root relative
    /// while the dest was absolute, spuriously breaking lexical comparison).
    #[tokio::test]
    async fn accepts_nonexistent_m2_path() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let parent = tempdir().expect("parent");
        // Build/m2repo does NOT exist yet; the bug fired in exactly this
        // configuration when the path was passed in relative form.
        let m2 = parent.path().join("build").join("m2repo");
        assert!(!m2.exists());

        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };
        let exporter = Exporter::new(options, &store);
        let key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        let path = exporter
            .safe_artifact_path(&key, &pkg_from_key(&key))
            .expect("non-existent m2 path must succeed");
        // `safe_artifact_path` is now pure path math: it must NOT create
        // directories on the filesystem. The artifact-publish call site
        // does the `create_dir_all` only when it's about to write.
        assert!(
            !path.parent().expect("parent").exists(),
            "safe_artifact_path must not create directories"
        );
        // The returned path must end in the expected coordinate layout.
        assert!(path.ends_with("com/example/demo/1.0.0/demo-1.0.0.jar"));
    }

    /// Same regression but with a relative path, which is the form the
    /// CLI actually passes through. We resolve it against the current
    /// working directory rather than mutating cwd (which would race with
    /// other parallel tests).
    #[tokio::test]
    async fn accepts_nonexistent_relative_m2_path_via_canonicalize_helper() {
        // Pick a name that's unlikely to exist beneath the current cwd.
        let relative = PathBuf::from("rv-m2-export-l2-nonexistent-xyz").join("repository");
        assert!(!relative.exists());
        let resolved = rv_config::canonicalize_existing_prefix(&relative).expect("resolve");
        // The helper must produce an absolute path even when nothing along
        // the chain exists yet.
        assert!(resolved.is_absolute(), "got: {:?}", resolved);
        // And the original tail components must still be present at the
        // end of the resolved path.
        assert!(resolved.ends_with(&relative), "got: {:?}", resolved);
    }

    /// Regression: if the JAR is already in place (e.g. a prior run
    /// was Ctrl+C-killed between the artifact rename and the sidecar writes)
    /// the export must still leave both `.sha1` and `.sha256` sidecars on
    /// disk with the correct digests.
    #[tokio::test]
    async fn export_repairs_missing_sidecars_on_identical_skip() {
        use sha1::Sha1;
        use sha2::{Digest, Sha256};

        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_bytes: &[u8] = b"jar-payload";
        let pom_bytes: &[u8] = b"pom-payload";
        let jar_id = store.put_bytes(jar_bytes).await.expect("jar");
        let pom_id = store.put_bytes(pom_bytes).await.expect("pom");

        let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        store
            .add_artifact(&jar_key, &jar_id)
            .await
            .expect("add jar");
        let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
        store
            .add_artifact(&pom_key, &pom_id)
            .await
            .expect("add pom");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo.example/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            }],
            edges: vec![],
            extra: Default::default(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };

        let jar_path = m2
            .join("com")
            .join("example")
            .join("demo")
            .join("1.0.0")
            .join("demo-1.0.0.jar");
        let sha1_path = jar_path.with_extension("jar.sha1");
        let sha256_path = jar_path.with_extension("jar.sha256");

        // Pre-populate the destination JAR (and its POM) so the exporter
        // takes the identical-skip path, but DELETE the sidecars to mimic
        // an interrupted previous run.
        fs::create_dir_all(jar_path.parent().unwrap()).expect("mkdir");
        fs::write(&jar_path, jar_bytes).expect("seed jar");
        let pom_path = jar_path.with_extension("pom");
        fs::write(&pom_path, pom_bytes).expect("seed pom");
        assert!(!sha1_path.exists());
        assert!(!sha256_path.exists());

        let exporter = Exporter::new(options, &store);
        let stats = exporter.export_lock(&lock, None).await.expect("export");
        // Both artifacts are reported as skipped, but the sidecars must
        // still be on disk now.
        assert_eq!(stats.skipped_count, 2);
        assert_eq!(stats.exported_count, 0);

        let sha1_content = fs::read_to_string(&sha1_path).expect("read sha1 sidecar");
        let sha256_content = fs::read_to_string(&sha256_path).expect("read sha256 sidecar");

        let mut hasher = Sha1::new();
        hasher.update(jar_bytes);
        let expected_sha1 = hex::encode(hasher.finalize());
        let mut hasher = Sha256::new();
        hasher.update(jar_bytes);
        let expected_sha256 = hex::encode(hasher.finalize());

        assert_eq!(sha1_content.trim(), expected_sha1);
        assert_eq!(sha256_content.trim(), expected_sha256);

        // A stale sidecar should also be repaired. Corrupt one and re-run.
        fs::write(&sha1_path, "deadbeef").expect("clobber sha1");
        let _ = exporter.export_lock(&lock, None).await.expect("export 2");
        let repaired = fs::read_to_string(&sha1_path).expect("read repaired sha1");
        assert_eq!(repaired.trim(), expected_sha1);
    }

    /// exporting an artifact must drop a `_remote.repositories` marker
    /// next to it listing each materialized filename against its repository
    /// id, so strict offline `mvn -o` treats the files as resolvable.
    #[tokio::test]
    async fn export_writes_remote_repositories_marker() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_id = store.put_bytes(b"jar").await.expect("jar");
        // A real POM (no parent) so the parent walk is exercised and yields
        // nothing extra.
        let pom_xml = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>demo</artifactId>\
<version>1.0.0</version></project>";
        let pom_id = store.put_bytes(pom_xml).await.expect("pom");

        let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        store.add_artifact(&jar_key, &jar_id).await.expect("jar");
        let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
        store.add_artifact(&pom_key, &pom_id).await.expect("pom");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo1.maven.org/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            }],
            edges: vec![],
            extra: Default::default(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };
        // No repo-id map supplied: the URL falls back to `central`, the id
        // Maven itself records for Central.
        let exporter = Exporter::new(options, &store);
        exporter.export_lock(&lock, None).await.expect("export");

        let dir = m2.join("com").join("example").join("demo").join("1.0.0");
        let marker = fs::read_to_string(dir.join("_remote.repositories")).expect("read marker");
        assert!(
            marker.contains(
                "#NOTE: This is a Maven Resolver internal implementation file, \
its format can be changed without prior notice."
            ),
            "marker must carry Maven's NOTE header, got:\n{marker}"
        );
        assert!(
            marker.contains("demo-1.0.0.jar>central="),
            "jar must be tracked against central, got:\n{marker}"
        );
        assert!(
            marker.contains("demo-1.0.0.pom>central="),
            "pom must be tracked against central, got:\n{marker}"
        );
    }

    /// The repo-id map must override the `central` default when the lockfile
    /// repo_url maps to a configured repository.
    #[tokio::test]
    async fn export_marker_uses_configured_repo_id() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let jar_id = store.put_bytes(b"jar").await.expect("jar");
        let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        store.add_artifact(&jar_key, &jar_id).await.expect("jar");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://nexus.corp.example/repo/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            }],
            edges: vec![],
            extra: Default::default(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };
        let mut repo_ids = HashMap::new();
        repo_ids.insert(
            rv_repo::normalize_repo_url("https://nexus.corp.example/repo/"),
            "corp".to_string(),
        );
        let exporter = Exporter::new(options, &store).with_repo_ids(repo_ids);
        exporter.export_lock(&lock, None).await.expect("export");

        let dir = m2.join("com").join("example").join("demo").join("1.0.0");
        let marker = fs::read_to_string(dir.join("_remote.repositories")).expect("read marker");
        assert!(
            marker.contains("demo-1.0.0.jar>corp="),
            "jar must be tracked against the configured id, got:\n{marker}"
        );
    }

    /// copied artifacts must be writable-by-owner (0644), not the
    /// CAS blob's 0444, so strict offline Maven (and in-place rewriters) can
    /// operate on the local-repo entry.
    #[cfg(unix)]
    #[tokio::test]
    async fn exported_artifacts_are_owner_writable() {
        use std::os::unix::fs::PermissionsExt;

        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let jar_id = store.put_bytes(b"jar").await.expect("jar");
        let pom_id = store.put_bytes(b"pom").await.expect("pom");
        let jar_key = ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None);
        store.add_artifact(&jar_key, &jar_id).await.expect("jar");
        let pom_key = ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None);
        store.add_artifact(&pom_key, &pom_id).await.expect("pom");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo1.maven.org/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            }],
            edges: vec![],
            extra: Default::default(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };
        let exporter = Exporter::new(options, &store);
        exporter.export_lock(&lock, None).await.expect("export");

        let dir = m2.join("com").join("example").join("demo").join("1.0.0");
        for name in ["demo-1.0.0.jar", "demo-1.0.0.pom"] {
            let mode = fs::metadata(dir.join(name))
                .expect("stat")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o644,
                "{name} must be 0644 (owner-writable, world-readable), got {mode:o}"
            );
        }
    }

    /// the `<parent>` ancestry of an exported POM must be materialized
    /// so `mvn -o` does not fail with "Non-resolvable parent POM". Parent POMs
    /// are not lockfile packages, so the exporter discovers them by parsing
    /// the child POM and looking the parent up in the store.
    #[tokio::test]
    async fn export_materializes_parent_pom_chain() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_id = store.put_bytes(b"jar").await.expect("jar");
        // Child POM references a parent; parent POM references a grandparent.
        let child_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>parent</artifactId>\
<version>2.0.0</version></parent>\
<artifactId>demo</artifactId></project>";
        let parent_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>grandparent</artifactId>\
<version>3.0.0</version></parent>\
<groupId>com.example</groupId><artifactId>parent</artifactId>\
<version>2.0.0</version><packaging>pom</packaging></project>";
        let grandparent_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>com.example</groupId><artifactId>grandparent</artifactId>\
<version>3.0.0</version><packaging>pom</packaging></project>";

        let child_pom_id = store.put_bytes(child_pom).await.expect("child pom");
        let parent_pom_id = store.put_bytes(parent_pom).await.expect("parent pom");
        let grandparent_pom_id = store.put_bytes(grandparent_pom).await.expect("gp pom");

        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None),
                &jar_id,
            )
            .await
            .expect("jar");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None),
                &child_pom_id,
            )
            .await
            .expect("child");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "parent", "2.0.0", "pom", None),
                &parent_pom_id,
            )
            .await
            .expect("parent");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "grandparent", "3.0.0", "pom", None),
                &grandparent_pom_id,
            )
            .await
            .expect("grandparent");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo1.maven.org/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            }],
            edges: vec![],
            extra: Default::default(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };
        let exporter = Exporter::new(options, &store);
        exporter.export_lock(&lock, None).await.expect("export");

        // The whole ancestry must be on disk.
        let parent = m2
            .join("com")
            .join("example")
            .join("parent")
            .join("2.0.0")
            .join("parent-2.0.0.pom");
        let grandparent = m2
            .join("com")
            .join("example")
            .join("grandparent")
            .join("3.0.0")
            .join("grandparent-3.0.0.pom");
        assert!(parent.exists(), "parent POM must be exported at {parent:?}");
        assert!(
            grandparent.exists(),
            "grandparent POM must be exported at {grandparent:?}"
        );
        assert_eq!(fs::read(&parent).expect("read parent"), parent_pom);
        assert_eq!(
            fs::read(&grandparent).expect("read grandparent"),
            grandparent_pom
        );

        // Parent dirs must also carry their own `_remote.repositories` markers.
        let parent_marker = m2
            .join("com")
            .join("example")
            .join("parent")
            .join("2.0.0")
            .join("_remote.repositories");
        let body = fs::read_to_string(&parent_marker).expect("parent marker");
        assert!(body.contains("parent-2.0.0.pom>central="));
    }

    /// A parent named by a POM but absent from the store must NOT fail the
    /// export; it's logged and skipped, and the rest still ships.
    #[tokio::test]
    async fn missing_parent_pom_does_not_fail_export() {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");

        let jar_id = store.put_bytes(b"jar").await.expect("jar");
        let child_pom = b"<project><modelVersion>4.0.0</modelVersion>\
<parent><groupId>com.example</groupId><artifactId>absent</artifactId>\
<version>9.9.9</version></parent>\
<artifactId>demo</artifactId></project>";
        let child_pom_id = store.put_bytes(child_pom).await.expect("child pom");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", "1.0.0", "jar", None),
                &jar_id,
            )
            .await
            .expect("jar");
        store
            .add_artifact(
                &ArtifactKey::new("com.example", "demo", "1.0.0", "pom", None),
                &child_pom_id,
            )
            .await
            .expect("child");

        let platform = Platform::new("linux", "x86_64").expect("platform");
        let mut lock = Lockfile::new();
        lock.platforms = vec![LockPlatform {
            platform,
            packages: vec![LockPackage {
                group_id: "com.example".to_string(),
                artifact_id: "demo".to_string(),
                version: "1.0.0".to_string(),
                snapshot_timestamp: None,
                packaging: "jar".to_string(),
                classifier: None,
                repo_url: "https://repo1.maven.org/maven2/".to_string(),
                checksum: Some(Checksum::new("sha256", jar_id.as_str())),
                system_path: None,
                direct_scope: None,
                extra: Default::default(),
            }],
            edges: vec![],
            extra: Default::default(),
        }];

        let m2_dir = tempdir().expect("m2 dir");
        let m2 = m2_dir.path().join("repository");
        let options = ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: m2.clone(),
        };
        let exporter = Exporter::new(options, &store);
        // The absent parent is skipped; the child jar + pom still export.
        let stats = exporter
            .export_lock(&lock, None)
            .await
            .expect("export must succeed");
        assert_eq!(stats.exported_count, 2);
        let jar = m2
            .join("com")
            .join("example")
            .join("demo")
            .join("1.0.0")
            .join("demo-1.0.0.jar");
        assert!(jar.exists());
    }

    /// Parse a flat collection of `<tag>text</tag>` occurrences out of a
    /// well-formed XML document. Used only by the unit tests above; the
    /// production code goes through quick-xml-friendly emission.
    fn parse_simple_xml(xml: &str) -> std::collections::HashMap<String, String> {
        use quick_xml::Reader;
        use quick_xml::escape::unescape;
        use quick_xml::events::Event;

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let mut out = std::collections::HashMap::new();
        let mut buf = Vec::new();
        let mut current: Option<String> = None;
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current = Some(String::from_utf8_lossy(e.name().as_ref()).into_owned());
                }
                Ok(Event::Text(t)) => {
                    if let Some(name) = current.as_deref() {
                        let raw = String::from_utf8_lossy(t.as_ref());
                        let text = unescape(&raw).unwrap_or_default().into_owned();
                        out.entry(name.to_string()).or_insert(text);
                    }
                }
                Ok(Event::End(_)) => current = None,
                Ok(Event::Eof) => break,
                Err(e) => panic!("xml parse error: {e}"),
                _ => {}
            }
            buf.clear();
        }
        out
    }
}
