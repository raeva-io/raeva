use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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

use super::aggregate_external_packages;
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

/// Ceiling on the number of *unique* support POMs (parent ancestries and
/// imported BOMs) a single export may walk.
///
/// Nothing in the lock bounds this closure. Parents and import BOMs are not
/// lockfile packages (pom-only nodes are dropped from the lock), and the walk
/// discovers them by parsing POM bytes out of the content store, so the lock
/// has no count the budget could be sized from. The cap is therefore a fixed
/// guard against a pathological POM graph, set an order of magnitude above the
/// largest real reactors. Exceeding it is an error, never a truncated closure:
/// a short export produces a `~/.m2` that fails `mvn -o` later with nothing
/// pointing back at the export that caused it.
const MAX_SUPPORT_POM_NODES: usize = 10_000;

/// Environment override for [`MAX_SUPPORT_POM_NODES`], named in the error so a
/// build that genuinely needs a bigger closure has a way forward.
const MAX_SUPPORT_POM_NODES_ENV: &str = "RAEVA_EXPORT_M2_MAX_SUPPORT_POMS";

/// Recovery instruction for [`ExportError::MissingSupportPom`]. A frozen sync
/// only checks the lockfile against the resolved graph; it is a plain `rv sync`
/// that re-fetches and re-persists the support-POM closure, so the hint has to
/// say which one.
const MISSING_SUPPORT_POM_HINT: &str =
    "Run `rv sync` (without --frozen) to repopulate the content store, then retry the export";

/// Recovery instruction for [`ExportError::MissingPinnedPom`]. The pinned bytes
/// are gone from the content store (pruned, or never written on this machine),
/// and only a fresh resolve can put the recorded digest back or record a new
/// one, so the hint names the same command for the same reason.
const MISSING_PINNED_POM_HINT: &str =
    "Run `rv sync` (without --frozen) to repopulate the content store, then retry the export";

fn max_support_pom_nodes_from_env() -> usize {
    parse_max_support_pom_nodes(std::env::var(MAX_SUPPORT_POM_NODES_ENV).ok().as_deref())
}

/// Parse the override. Anything unusable (non-numeric, zero) falls back to the
/// default rather than shrinking the budget, so a typo in the environment can
/// never be the reason an export stops early.
fn parse_max_support_pom_nodes(raw: Option<&str>) -> usize {
    let Some(raw) = raw else {
        return MAX_SUPPORT_POM_NODES;
    };
    match raw.trim().parse::<usize>() {
        Ok(limit) if limit > 0 => limit,
        _ => {
            warn!(
                variable = MAX_SUPPORT_POM_NODES_ENV,
                value = %raw,
                default = MAX_SUPPORT_POM_NODES,
                "ignoring unparseable support-POM node limit; using the default"
            );
            MAX_SUPPORT_POM_NODES
        }
    }
}

/// What `rv sync` recorded for one support POM (parent or imported BOM).
#[derive(Clone, Debug)]
pub(crate) struct SupportPomPin {
    /// Id of the repository that served the POM. Empty when that repository
    /// carries no id: the POM is still exported, it just gets no
    /// `_remote.repositories` marker, since inventing `central` would claim it
    /// came from a repository it did not.
    pub(crate) repo_id: String,
    /// SHA-256 of the bytes to export. `None` on a lockfile written before the
    /// digest was recorded; the POM is then looked up through the store's
    /// coordinate index, unpinned, as it was before.
    pub(crate) sha256: Option<BlobId>,
}

/// Which pass of the queueing phase produced a unit. Two passes can name the
/// same Maven file from two independently recorded pins, so the source is what
/// the conflict error points the user at.
#[derive(Clone, Copy)]
enum UnitSource {
    /// A lockfile `artifacts[]` row: pinned by that row's checksum.
    Package,
    /// The companion POM of a lockfile row: pinned by the row's `pom_sha256`,
    /// or resolved through the store's coordinate index when there is no pin.
    CompanionPom,
    /// A node of the support-POM closure: pinned by the provenance `rv sync`
    /// recorded for that coordinate, or resolved through the coordinate index
    /// when the closure only inferred it from POM text.
    SupportPom,
}

impl UnitSource {
    fn label(self) -> &'static str {
        match self {
            Self::Package => "the lockfile package row",
            Self::CompanionPom => "its lockfile row's companion POM",
            Self::SupportPom => "the recorded support-POM closure",
        }
    }
}

/// One file to materialize into the Maven local repository. The `package` is
/// a stand-in used only for path/layout decisions (snapshot directory
/// handling); parent POMs carry a synthetic one keyed off their own
/// coordinate. `repo_id` is the repository id recorded in
/// `_remote.repositories` next to the file; empty means the file gets no
/// marker (see `repo_id_recorded`).
struct ExportUnit {
    key: ArtifactKey,
    package: LockPackage,
    blob: BlobId,
    /// Queueing pass this unit came from, used only to name the two sides of a
    /// [`ExportError::ConflictingExportSources`].
    source: UnitSource,
    repo_id: String,
    /// True when `repo_id` came from the support-POM provenance `rv sync`
    /// recorded for this exact coordinate, rather than being derived from the
    /// `repo_url` of whichever package referenced it. Decides the winner when
    /// the same POM is queued as both support metadata and a lockfile package;
    /// a recorded but empty id wins too, because "the serving repository has no
    /// id" is knowledge, and the guess it displaces is not.
    repo_id_recorded: bool,
}

/// The work one export accumulates before fanning out: the coordinate dedupe
/// set shared by every support-POM walk, the running unique-support-node
/// budget, and the deduplicated list of files to materialize.
#[derive(Default)]
struct ExportQueue {
    /// Dedupe set keyed off the package coordinate triple.
    ///
    /// It collapses the per-classifier POM re-exports: every (jar,
    /// jar:sources, jar:javadoc) classifier for the same g:a:v shares a single
    /// POM, so without deduping we would queue and ship the same POM bytes
    /// three times. It is also the dedupe key for the support-POM walk, so a
    /// parent shared by many children is visited once.
    enqueued_poms: HashSet<(String, String, String)>,
    units: Vec<ExportUnit>,
    /// Positions in `units` by artifact key, so a coordinate reached both as
    /// support metadata and as an explicit lockfile package collapses into one.
    by_key: HashMap<ArtifactKey, usize>,
    /// Unique support-POM nodes walked so far, against [`MAX_SUPPORT_POM_NODES`].
    support_nodes: usize,
}

impl ExportQueue {
    /// Whether a unit is already queued for `key`, i.e. whether [`Self::push`]
    /// would compare a pin against queued bytes rather than queue a new file.
    /// A caller that only wants the comparison — one holding a pin for a
    /// coordinate another pass already resolved — checks this first, so it
    /// never queues bytes nothing has confirmed are in the store.
    fn holds(&self, key: &ArtifactKey) -> bool {
        self.by_key.contains_key(key)
    }

    /// Queue one file, collapsing a coordinate that is both support metadata
    /// and an explicit lockfile package into a single unit.
    ///
    /// `safe_artifact_path` derives the destination purely from the
    /// `ArtifactKey` (the directory uses `version`'s base-snapshot form), so two
    /// units sharing a key name the same file. Letting both through would write
    /// that file twice from `buffer_unordered`, double it in the stats, and
    /// leave its `_remote.repositories` marker to whichever unit finished last.
    /// On collision the recorded support-POM repository id wins: it names the
    /// repository the POM actually came from, rather than one inferred from a
    /// referencing package's `repo_url`.
    ///
    /// Collapsing is only legitimate when both units name the same bytes. One
    /// coordinate can be pinned by three independent recordings — an
    /// `artifacts[]` row's checksum, that row's `pom_sha256`, and the
    /// support-POM provenance — and every pair of them describes the same
    /// Maven path. Keeping whichever arrived first would export bytes the
    /// other pin attests are wrong, silently: the substitution
    /// [`ExportError::ConflictingPinnedPom`] and
    /// [`ExportError::ConflictingPomPackagedPin`] exist to refuse, reached
    /// across two sources instead of within one. So a disagreement fails the
    /// export here, in the queueing pass, before anything is written.
    fn push(&mut self, unit: ExportUnit) -> Result<()> {
        let Some(&existing) = self.by_key.get(&unit.key) else {
            self.by_key.insert(unit.key.clone(), self.units.len());
            self.units.push(unit);
            return Ok(());
        };
        let previous = &mut self.units[existing];
        if previous.blob != unit.blob {
            return Err(ExportError::ConflictingExportSources {
                coordinate: unit.key.to_string(),
                first_source: previous.source.label(),
                first: previous.blob.to_string(),
                second_source: unit.source.label(),
                second: unit.blob.to_string(),
            });
        }
        if unit.repo_id_recorded && !previous.repo_id_recorded {
            previous.repo_id = unit.repo_id;
            previous.repo_id_recorded = true;
        }
        Ok(())
    }
}

pub(crate) struct Exporter<'a> {
    options: ExportOptions,
    store: &'a Store,
    /// Maps a normalized repository URL to its configured repository id, used
    /// to fill in the `_remote.repositories` markers Maven Resolver expects.
    /// Unknown URLs fall back to `central`.
    repo_ids: HashMap<String, String>,
    /// Maps a support POM's `"g:a:v"` to what `rv sync` recorded for it.
    ///
    /// Every remotely fetched support POM is a key here. Key presence is what
    /// makes a coordinate's absence from the store fatal, so an id-less
    /// repository's POMs are covered by that check too.
    support_poms: HashMap<String, SupportPomPin>,
    /// Maps an artifact's `(group, artifact, resolved version)` to the SHA-256
    /// of the companion POM `rv sync` recorded for it, from the lockfile's
    /// artifact rows. Absent for a coordinate whose lockfile row carries no
    /// digest, which is how locks written before the field behave.
    pom_digests: HashMap<(String, String, String), BlobId>,
    /// Ceiling on unique support-POM nodes for one export. Resolved once at
    /// construction so every pass of a run shares one stable budget.
    max_support_pom_nodes: usize,
}

impl<'a> Exporter<'a> {
    pub(crate) fn new(options: ExportOptions, store: &'a Store) -> Self {
        Self {
            options,
            store,
            repo_ids: HashMap::new(),
            support_poms: HashMap::new(),
            pom_digests: HashMap::new(),
            max_support_pom_nodes: max_support_pom_nodes_from_env(),
        }
    }

    /// Override the support-POM node budget. Tests use this to exercise the
    /// limit without materializing ten thousand POMs; production reads it from
    /// the environment in `new`.
    #[cfg(test)]
    fn with_max_support_pom_nodes(mut self, limit: usize) -> Self {
        self.max_support_pom_nodes = limit;
        self
    }

    /// Supply the normalized-URL -> repository-id map used to label
    /// `_remote.repositories` entries. The keys must already be normalized
    /// via `rv_repo::normalize_repo_url` so lookups match the lockfile's
    /// `repo_url` after the same normalization.
    pub(crate) fn with_repo_ids(mut self, repo_ids: HashMap<String, String>) -> Self {
        self.repo_ids = repo_ids;
        self
    }

    /// Supply the support-POM `"g:a:v" -> pin` provenance map recorded by
    /// `rv sync`, so a parent/BOM that resolved from a different repository
    /// than its child is labelled with its own source repo id and exported
    /// from the bytes that repository served.
    pub(crate) fn with_support_poms(mut self, poms: HashMap<String, SupportPomPin>) -> Self {
        self.support_poms = poms;
        self
    }

    /// Supply the companion-POM digests the lockfile's artifact rows pin.
    pub(crate) fn with_pom_digests(
        mut self,
        digests: HashMap<(String, String, String), BlobId>,
    ) -> Self {
        self.pom_digests = digests;
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
        let project_poms: Vec<PathBuf> = root_pom.map(Path::to_path_buf).into_iter().collect();
        self.export_lock_with_project_poms(lock, &project_poms)
            .await
    }

    /// Export the aggregate external union plus the support-POM closure
    /// referenced by every active reactor module POM.
    pub(crate) async fn export_lock_with_project_poms(
        &self,
        lock: &Lockfile,
        project_poms: &[PathBuf],
    ) -> Result<ExportStats> {
        let mut stats = ExportStats::default();
        let system_scoped = system_scoped_coordinates(lock);
        let mut meta = MetadataAccumulator::default();

        // Collect blob IDs, deduplicate files and validate pins before any
        // concurrent exports; the index cannot be fanned out to concurrent
        // writers. This pass also accumulates shared metadata.
        let mut queue = ExportQueue::default();
        // Accumulate metadata once per coordinate across platforms.
        let mut accumulated: HashSet<(String, String, String, String, Option<String>)> =
            HashSet::new();

        // Support POMs are overwhelmingly on Central; an unmapped repo_url
        // falls back to the `central` marker id. Prefer the project's primary
        // repo when it has one.
        let external_packages = aggregate_external_packages(lock);
        let root_repo_url = external_packages
            .first()
            .map(|pkg| pkg.repo_url.clone())
            .unwrap_or_default();

        // Seed the closure with the coordinates `rv sync` recorded for every
        // support POM it fetched (each dependency's `<parent>` ancestry and
        // import-scoped BOMs). We can't always re-derive an import BOM's
        // coordinate from a POM alone: a transitive dep may import a BOM whose
        // version is a `${property}` defined in that dep's parent, which
        // `read_support_refs` can't resolve from the child POM and so skips,
        // dropping the BOM and breaking offline `mvn -o`. The recorded
        // provenance already holds the resolved coordinate, so seeding from it
        // (then letting `enqueue_support_closure` recurse into each POM's own
        // parents and imports) materializes the whole transitive closure. The
        // sources/javadocs passes re-seed idempotently.
        if !self.support_poms.is_empty() {
            // Sort the seeds: `support_poms` is a `HashMap`, and the walk
            // order decides which node trips the closure limit. An export that
            // fails on one run has to fail on every run.
            let mut coords: Vec<&str> = self.support_poms.keys().map(String::as_str).collect();
            coords.sort_unstable();
            let seed_refs: Vec<(String, String, String)> =
                coords.into_iter().filter_map(parse_gav).collect();
            self.enqueue_support_closure(seed_refs, &root_repo_url, &mut queue)
                .await?;
        }

        // The root project's own pom.xml lives on disk (not in the lock), but
        // its `<parent>` and imported BOMs must also be in ~/.m2 for `mvn -o`
        // to build the root model (e.g. inheriting spring-boot-starter-parent
        // or importing spring-boot-dependencies). Walk that closure too. Only
        // the primary export passes a root pom; the sources/javadocs passes
        // reuse the same dedupe set and skip it.
        for project_pom in project_poms {
            let refs = read_support_refs(project_pom).unwrap_or_default();
            self.enqueue_support_closure(refs, &root_repo_url, &mut queue)
                .await?;
        }

        for package in &external_packages {
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
                let pom_key = ArtifactKey::new(
                    package.group_id.clone(),
                    package.artifact_id.clone(),
                    package.version.clone(),
                    "pom",
                    None,
                );
                // A sibling classifier may have queued this g:a:v POM
                // already; re-queuing it hashes and writes the same
                // bytes twice. So may the support-POM closure, which runs
                // first — and skipping outright on that account would skip
                // the only comparison between the two independent
                // recordings of this one Maven path, the closure's
                // provenance pin and this row's `pom_sha256`. Submit the
                // pin instead, so `ExportQueue::push` stays the single
                // place that collapses an agreement and refuses a
                // disagreement, exactly as it does for a `packaging =
                // "pom"` row. Only a recorded pin is submitted: the
                // store's coordinate index attests nothing about what this
                // lockfile resolved, so falling back to it here could
                // manufacture a conflict out of another project's sync.
                if queue.holds(&pom_key) {
                    if let Some(pinned) = self.pom_digests.get(&pom_coord) {
                        queue.push(ExportUnit {
                            key: pom_key,
                            package: pom_package_from(package),
                            blob: pinned.clone(),
                            source: UnitSource::CompanionPom,
                            repo_id: repo_id.clone(),
                            repo_id_recorded: false,
                        })?;
                    }
                } else if !queue.enqueued_poms.contains(&pom_coord) {
                    // Some Maven artifacts ship without a companion POM,
                    // for example relocations and sources-only jars.
                    // Maven tolerates that, so a missing POM warns and
                    // exports the primary artifact alone instead of
                    // failing the whole export.
                    match self.companion_pom_blob(&pom_key, &pom_coord).await? {
                        Some(pom_blob) => {
                            queue.enqueued_poms.insert(pom_coord);
                            let pom_pkg = pom_package_from(package);
                            // `mvn -o` fails with "Non-resolvable
                            // parent/import POM" unless this POM's
                            // `<parent>` ancestry and import-scoped BOMs
                            // are exported alongside it.
                            let refs = read_support_refs(&self.store.get_path(&pom_blob))
                                .unwrap_or_default();
                            self.enqueue_support_closure(refs, &package.repo_url, &mut queue)
                                .await?;
                            queue.push(ExportUnit {
                                key: pom_key,
                                package: pom_pkg,
                                blob: pom_blob,
                                source: UnitSource::CompanionPom,
                                repo_id: repo_id.clone(),
                                repo_id_recorded: false,
                            })?;
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
                // This package IS the `.pom` at that path, so the row's own
                // payload pin and its companion-POM pin have to name the same
                // blob. They are written by two independent observations
                // during resolution, and `rv sync` and `Lockfile::read` both
                // reject a disagreement; failing here as well means no export
                // can silently write the payload while the lockfile claims the
                // other digest is what was resolved. A classified `.pom` is a
                // separate file from the coordinate's companion POM and keeps
                // its own bytes.
                if package.classifier.as_deref().unwrap_or_default().is_empty()
                    && let Some(pinned) = self.pom_digests.get(&pom_coord)
                    && *pinned != blob
                {
                    return Err(ExportError::ConflictingPomPackagedPin {
                        coordinate: format!("{}:{}:{}", pom_coord.0, pom_coord.1, pom_coord.2),
                        artifact: blob.to_string(),
                        pom: pinned.to_string(),
                    });
                }
                // The insert may report the coordinate as already queued: this
                // POM can also be support metadata for another package. That
                // is fine, `queue.push` below collapses the two into one unit.
                queue.enqueued_poms.insert(pom_coord);
                let refs = read_support_refs(&self.store.get_path(&blob)).unwrap_or_default();
                self.enqueue_support_closure(refs, &package.repo_url, &mut queue)
                    .await?;
            }

            // Export order is cosmetic. Queueing the package after its
            // ancestry only keeps related files adjacent in the unit list;
            // duplicates are collapsed by key rather than by arrival order.
            queue.push(ExportUnit {
                key,
                package: package.clone(),
                blob,
                source: UnitSource::Package,
                repo_id,
                repo_id_recorded: false,
            })?;

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

        // Each task owns an export unit and borrows `self` immutably.
        type UnitResult = (ExportOutcome, PathBuf, String);
        let outcomes: Vec<Result<UnitResult>> = stream::iter(queue.units.into_iter())
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
            //
            // An empty id is the one exception: it is a support POM whose
            // recorded provenance names a repository without an id, and a
            // marker line has nowhere to put "unknown". The file is still
            // exported; only its marker is left out.
            if let (Some(dir), Some(filename)) =
                (dest.parent(), dest.file_name().and_then(|n| n.to_str()))
                && !repo_id.is_empty()
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
            //
            // Warn after the export rather than before it: the export still
            // succeeds, and the point of the message is that the `mvn -o`
            // build these files were written for will look for something this
            // `~/.m2` cannot hold.
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
        if let Some(stamp) = derived_last_updated(package) {
            artifact_state.last_updated = Some(stamp);
        }

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
    /// A recorded coordinate whose provenance carries a digest is resolved from
    /// the content-addressed store, not from the coordinate index, and pinned
    /// bytes that are gone fail the export with
    /// [`ExportError::MissingPinnedPom`].
    ///
    /// A support POM the recorded provenance names but the store does not hold
    /// fails the export with [`ExportError::MissingSupportPom`]: `rv sync` said
    /// it fetched that POM, so its absence is a known-incomplete offline
    /// repository, not a POM Maven will not ask for. Coordinates only inferred
    /// from POM text stay best-effort and are skipped with a warning, as is an
    /// import whose version is a property defined only in a parent (not the
    /// importing POM; see `read_support_refs`) — that case almost always
    /// arrives via a `<parent>` chain, which IS walked.
    ///
    /// A closure larger than [`MAX_SUPPORT_POM_NODES`] unique POMs also fails
    /// the export outright, for the same reason: the alternative is a `~/.m2`
    /// that reports success and is missing parents.
    ///
    /// Both failures are raised here, during queueing, so nothing has been
    /// written to `~/.m2` when the export aborts.
    async fn enqueue_support_closure(
        &self,
        initial_refs: Vec<(String, String, String)>,
        repo_url: &str,
        queue: &mut ExportQueue,
    ) -> Result<()> {
        // Parents form a chain but import BOMs form a tree (a POM can import
        // several BOMs, each with its own parents/imports), so walk a worklist
        // of coordinates. Breadth-first from the caller's seed order, which is
        // itself deterministic, so the traversal is reproducible run to run.
        //
        // The dedupe set breaks cycles and sharing, and it gates the budget:
        // only a coordinate we have not seen before counts against
        // `max_support_pom_nodes`, so a parent named by two hundred children
        // is one node rather than two hundred.
        let mut worklist: VecDeque<(String, String, String)> = initial_refs.into();
        while let Some((group_id, artifact_id, version)) = worklist.pop_front() {
            let coord = (group_id.clone(), artifact_id.clone(), version.clone());
            if !queue.enqueued_poms.insert(coord) {
                continue;
            }
            queue.support_nodes += 1;
            if queue.support_nodes > self.max_support_pom_nodes {
                // Never return early with a partial closure: the resulting
                // `~/.m2` would look successful and then fail `mvn -o`.
                return Err(ExportError::SupportClosureTooLarge {
                    limit: self.max_support_pom_nodes,
                    variable: MAX_SUPPORT_POM_NODES_ENV,
                });
            }
            let key = ArtifactKey::new(
                group_id.clone(),
                artifact_id.clone(),
                version.clone(),
                "pom",
                None,
            );
            let coord_key = format!("{group_id}:{artifact_id}:{version}");
            let recorded = self.support_poms.get(&coord_key);
            // A recorded digest addresses the blob directly. The store's
            // coordinate index is last-writer-wins, so a later sync of another
            // project sharing the store can point `(g, a, v, pom)` at other
            // bytes; following it would export a POM this lockfile was never
            // resolved against. Pinned bytes that are gone are fatal, for the
            // same reason a recorded coordinate missing from the store is.
            let support_blob = match recorded.and_then(|pin| pin.sha256.as_ref()) {
                Some(pinned) if self.store.exists_async(pinned).await => Some(pinned.clone()),
                Some(pinned) => {
                    return Err(ExportError::MissingPinnedPom {
                        coordinate: coord_key,
                        digest: pinned.to_string(),
                        hint: MISSING_PINNED_POM_HINT,
                    });
                }
                None => self.store.lookup_artifact_locked(&key).await?,
            };
            match support_blob {
                Some(support_blob) => {
                    // Recurse into this support POM's own parents/imports.
                    if let Some(more) = read_support_refs(&self.store.get_path(&support_blob)) {
                        worklist.extend(more);
                    }
                    // Prefer this support POM's own recorded source-repo id
                    // (it may differ from the child's repo) over the guessed
                    // caller `repo_url`. An empty recorded id is provenance
                    // for a repository that carries no id: it still beats the
                    // guess, and it carries through to the marker pass as
                    // "write no `_remote.repositories` entry", since there is
                    // no id to name and inventing `central` would claim the POM
                    // came from a repository it did not.
                    let repo_id_recorded = recorded.is_some();
                    let repo_id = recorded
                        .map(|pin| pin.repo_id.clone())
                        .unwrap_or_else(|| self.repo_id_for(repo_url));
                    let pkg = synthetic_pom_package(&group_id, &artifact_id, &version, repo_url);
                    queue.push(ExportUnit {
                        key,
                        package: pkg,
                        blob: support_blob,
                        source: UnitSource::SupportPom,
                        repo_id,
                        repo_id_recorded,
                    })?;
                }
                None => {
                    // Two different kinds of miss share this branch. A
                    // coordinate carried by the recorded provenance is one
                    // `rv sync` says it fetched: its absence means the
                    // content-store write was lost, and exporting anyway
                    // produces a `~/.m2` that reports success and then fails
                    // `mvn -o` on a non-resolvable parent/import POM. That is
                    // the same incomplete-repository condition the node budget
                    // treats as fatal, so treat it the same way — and do it
                    // here, in the queueing pass, before any file is
                    // materialized. A coordinate merely *inferred* from POM
                    // text stays best-effort: `read_support_refs` can name
                    // POMs that were never fetched because no active profile
                    // needed them, and failing on those would break exports
                    // that build fine offline.
                    if recorded.is_some() {
                        return Err(ExportError::MissingSupportPom {
                            coordinate: coord_key,
                            hint: MISSING_SUPPORT_POM_HINT,
                        });
                    }
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

    /// Resolve the companion POM to export for one artifact coordinate.
    ///
    /// When the lockfile pins a digest, the blob is addressed by that digest
    /// and the store's coordinate index is not consulted at all: the index is
    /// last-writer-wins, so a later sync of a different project sharing the
    /// store can have repointed `(g, a, v, pom)` at other bytes, and following
    /// it would export a POM this lockfile was never resolved against. A pin
    /// whose bytes are gone is fatal — the alternative is exporting the
    /// replacement, silently.
    ///
    /// Without a pin (a lockfile written before the digest existed, or a
    /// coordinate whose POM the store did not hold at sync time) the lookup
    /// falls back to the index, unpinned, exactly as it behaved before.
    async fn companion_pom_blob(
        &self,
        pom_key: &ArtifactKey,
        pom_coord: &(String, String, String),
    ) -> Result<Option<BlobId>> {
        let Some(pinned) = self.pom_digests.get(pom_coord) else {
            // Use the locked variant so a concurrent GC sweep cannot delete
            // the blob between the index hit and the downstream open.
            return Ok(self.store.lookup_artifact_locked(pom_key).await?);
        };
        if self.store.exists_async(pinned).await {
            return Ok(Some(pinned.clone()));
        }
        Err(ExportError::MissingPinnedPom {
            coordinate: format!("{}:{}:{}", pom_coord.0, pom_coord.1, pom_coord.2),
            digest: pinned.to_string(),
            hint: MISSING_PINNED_POM_HINT,
        })
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

    #[cfg(test)]
    fn safe_artifact_path(&self, key: &ArtifactKey, package: &LockPackage) -> Result<PathBuf> {
        safe_artifact_path(&self.options, key, package)
    }
}

/// Collect the `"g:a:v"` of every system-scoped dependency the lock records,
/// deduplicated and ordered so one lock always warns about the same list.
///
/// A `systemPath` dependency resolves from an absolute path on the building
/// machine, so `rv sync` puts no bytes in the content store for it and writes
/// it no `artifacts[]` row (`Lockfile::read` rejects a lock that gives one
/// both). The per-module package graphs are therefore the only place the lock
/// records these coordinates at all, and the only place export can see them:
/// the aggregate view it otherwise works from is built from artifact rows, and
/// `LockArtifact::as_package` has no system path to carry.
///
/// This covers legacy locks too — the schema adapter routes their flat package
/// list through the same module packages, `system_path` included.
fn system_scoped_coordinates(lock: &Lockfile) -> Vec<String> {
    let mut coords = BTreeSet::new();
    for platform in &lock.platforms {
        for module in &platform.modules {
            for package in &module.packages {
                if package.system_path.is_some() {
                    coords.insert(format!(
                        "{}:{}:{}",
                        package.coordinate.group,
                        package.coordinate.artifact,
                        package.coordinate.version
                    ));
                }
            }
        }
    }
    coords.into_iter().collect()
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

/// Split a bare `"group:artifact:version"` (as recorded in the support-POM
/// provenance) into its three parts. Returns `None` unless there are exactly
/// three non-empty colon-separated segments. Maven coordinates never contain a
/// `:` inside a part, so `splitn(3)` is unambiguous.
fn parse_gav(coord: &str) -> Option<(String, String, String)> {
    let mut parts = coord.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(g), Some(a), Some(v)) if !g.is_empty() && !a.is_empty() && !v.is_empty() => {
            Some((g.to_string(), a.to_string(), v.to_string()))
        }
        _ => None,
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
mod tests;
