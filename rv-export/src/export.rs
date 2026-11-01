use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use futures::stream::{self, StreamExt};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use tokio::task::spawn_blocking;

use rv_lock::LockArtifact;
use rv_maven_types::{
    ArtifactCoord, CoordinateField, Digest, Gav, TimestampedSnapshot, Version, VersionReq, layout,
    validate_coordinate_component,
};
use rv_store::{BlobId, PinCheck, Store};

use super::error::{ExportError, ExportFailure, LinkError, Result};
use super::link::{LinkStrategy, link_with_fallback};
use super::metadata::{
    ArtifactMetaKey, ArtifactMetaState, ArtifactMetadata, MetadataAccumulator,
    RemoteRepositoriesAccumulator, SnapshotMetaKey, SnapshotMetaState, SnapshotVersionEntry,
    VersionedMetadata, compact_updated, later_stamp, merge_snapshot_entries,
    read_existing_metadata, render_artifact_metadata, render_empty_metadata,
    render_versioned_metadata, write_atomic as write_metadata_atomic,
};
use crate::plan::{ExportPlan, Reactor};
use crate::warning::ExportWarning;

/// Where and how an [`Exporter`] writes.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Check the plan and the store without writing anything. Every artifact
    /// whose blob exists counts as exported with [`Self::link_strategy`];
    /// no metadata, sidecar or marker is written.
    pub dry_run: bool,
    /// Replace a destination file that holds other bytes than the locked
    /// blob. Without it such a file fails the export with
    /// [`ExportError::DestinationMismatch`](crate::ExportError::DestinationMismatch).
    pub overwrite: bool,
    /// How to put each blob in place. A failed attempt falls back along
    /// hard link, symbolic link, copy, starting at this one.
    pub link_strategy: LinkStrategy,
    /// The local repository root that every written path must stay under.
    pub m2_path: PathBuf,
    /// `m2_path` is the Maven local repository other builds share. The
    /// locked metadata is written, but no `maven-metadata-*.xml` is removed
    /// and an artifact's version list keeps the versions it already lists,
    /// so `mvn install` output and other projects' listings survive.
    pub shared: bool,
}

/// What one export wrote, skipped and survived. Counts are per file:
/// artifacts, companion POMs and support POMs, not checksum sidecars or
/// metadata.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ExportStats {
    /// Artifact and POM files written, `copied_count + linked_count`.
    pub exported_count: usize,
    /// Files left alone because the destination already held the locked
    /// bytes.
    pub skipped_count: usize,
    /// Of `skipped_count`, the files of coordinates with a classifier, such
    /// as sources jars.
    pub skipped_classified_count: usize,
    /// Files written by copying, including fallbacks to a copy.
    pub copied_count: usize,
    /// Files written as a hard or symbolic link.
    pub linked_count: usize,
    /// What the export survived but the caller should report, in the order
    /// found. A run that cannot say so would hide an incomplete offline
    /// repository, so nothing here is logged.
    pub warnings: Vec<ExportWarning>,
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

/// Environment variable whose value the caller passes to
/// [`Exporter::with_support_pom_limit`]. The limit error and the warning for
/// an unusable value name it, so a build that genuinely needs a bigger
/// closure has a way forward. rv-export does not read it.
pub const MAX_SUPPORT_POM_NODES_ENV: &str = "RAEVA_EXPORT_M2_MAX_SUPPORT_POMS";

/// Parse the override. Anything unusable (non-numeric, zero) falls back to the
/// default rather than shrinking the budget, so a typo in the environment can
/// never be the reason an export stops early. The fallback comes with the
/// warning that says so.
fn parse_max_support_pom_nodes(raw: Option<&str>) -> (usize, Option<ExportWarning>) {
    let Some(raw) = raw else {
        return (MAX_SUPPORT_POM_NODES, None);
    };
    match raw.trim().parse::<usize>() {
        Ok(limit) if limit > 0 => (limit, None),
        _ => (
            MAX_SUPPORT_POM_NODES,
            Some(ExportWarning::SupportPomLimitIgnored {
                variable: MAX_SUPPORT_POM_NODES_ENV,
                value: raw.to_string(),
            }),
        ),
    }
}

/// What `raeva sync` recorded for one support POM (parent or imported BOM).
#[derive(Clone, Debug)]
pub(crate) struct SupportPomPin {
    /// Ids of the repository that served the POM. Empty when that
    /// repository carries no id: the POM is still exported, it just gets no
    /// `_remote.repositories` marker, since inventing `central` would claim it
    /// came from a repository it did not.
    pub(crate) repo_ids: Vec<String>,
    /// The lock keys of the repositories the platforms' pins record.
    pub(crate) origins: HashSet<String>,
    pub(crate) sha256: BlobId,
    /// The timestamped version of the build a `-SNAPSHOT` POM was pinned to.
    pub(crate) build: Option<String>,
}

/// Which pass of the queueing phase produced a unit. Two passes can name the
/// same Maven file from two independently recorded pins, so the source is what
/// the conflict error points the user at.
#[derive(Clone, Copy)]
enum UnitSource {
    /// A lockfile `artifacts[]` row: pinned by that row's checksum.
    Package,
    /// The companion POM of a lockfile row: pinned by the row's `pom_sha256`.
    CompanionPom,
    /// A node of the support-POM closure: pinned by the provenance `raeva sync`
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

/// One file to materialize into the Maven local repository, at the path
/// `key` names. `repo_ids` are the repository ids recorded in
/// `_remote.repositories` next to the file; none means the file gets no
/// marker (see `repo_id_recorded`).
struct ExportUnit {
    key: ArtifactCoord,
    blob: BlobId,
    /// Queueing pass this unit came from, used only to name the two sides of a
    /// [`ExportError::ConflictingExportSources`].
    source: UnitSource,
    repo_ids: Vec<String>,
    /// True when `repo_ids` came from the support-POM provenance `raeva sync`
    /// recorded for this exact coordinate, rather than being derived from the
    /// origins of whichever package referenced it. Decides the winner when
    /// the same POM is queued as both support metadata and a companion POM;
    /// a recorded but empty id wins too, because "the serving repository has no
    /// id" is knowledge, and the guess it displaces is not.
    repo_id_recorded: bool,
    /// A plain `-SNAPSHOT` copy, which Maven rewrites on every snapshot
    /// update: other bytes there are an earlier copy, replaced without
    /// `--overwrite`.
    replace: bool,
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
    by_key: HashMap<ArtifactCoord, usize>,
    support_nodes: usize,
    warnings: Vec<ExportWarning>,
    blobs: StoreFacts,
}

/// The pinned blobs the queueing pass checks, looked up in one parallel
/// pass on the blocking pool instead of one at a time.
#[derive(Default)]
struct StoreFacts {
    present: HashSet<BlobId>,
    /// The `<parent>` each present POM blob names.
    parents: HashMap<BlobId, Option<(String, String, String)>>,
}

impl StoreFacts {
    async fn gather(store: &Store, poms: HashSet<BlobId>, others: HashSet<BlobId>) -> Self {
        let jobs: Vec<(BlobId, PathBuf, bool)> = (poms.into_iter().map(|blob| (blob, true)))
            .chain(others.into_iter().map(|blob| (blob, false)))
            .map(|(blob, pom)| {
                let path = store.get_path(&blob);
                (blob, path, pom)
            })
            .collect();
        let chunk = jobs.len().div_ceil(export_parallelism()).max(1);
        let tasks: Vec<_> = jobs
            .chunks(chunk)
            .map(|jobs| {
                let jobs = jobs.to_vec();
                spawn_blocking(move || {
                    jobs.into_iter()
                        .filter_map(|(blob, path, pom)| {
                            if !pom {
                                return fs::metadata(&path)
                                    .is_ok_and(|meta| meta.is_file())
                                    .then_some((blob, None));
                            }
                            let bytes = fs::read(&path).ok()?;
                            let parent = stored_parent(&bytes, &blob);
                            Some((blob, Some(parent)))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut facts = Self::default();
        for task in tasks {
            // A lookup that did not finish is made again where it is needed.
            for (blob, parent) in task.await.unwrap_or_default() {
                if let Some(parent) = parent {
                    facts.parents.insert(blob.clone(), parent);
                }
                facts.present.insert(blob);
            }
        }
        facts
    }

    async fn exists(&self, store: &Store, blob: &BlobId) -> bool {
        self.present.contains(blob) || store.exists_async(blob).await
    }

    fn parent(&self, store: &Store, blob: &BlobId) -> Option<(String, String, String)> {
        match self.parents.get(blob) {
            Some(parent) => parent.clone(),
            None => stored_parent(&fs::read(store.get_path(blob)).ok()?, blob),
        }
    }
}

fn export_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 64)
}

impl ExportQueue {
    /// Whether a unit is already queued for `key`, i.e. whether [`Self::push`]
    /// would compare a pin against queued bytes rather than queue a new file.
    /// A caller that only wants the comparison (one holding a pin for a
    /// coordinate another pass already resolved) checks this first, so it
    /// never queues bytes nothing has confirmed are in the store.
    fn holds(&self, key: &ArtifactCoord) -> bool {
        self.by_key.contains_key(key)
    }

    /// Queue one file, collapsing a coordinate that is both support metadata
    /// and an explicit lockfile package into a single unit.
    ///
    /// `safe_artifact_path` derives the destination purely from the
    /// `ArtifactCoord` (the directory uses `version`'s base-snapshot form), so two
    /// units sharing a key name the same file. Letting both through would write
    /// that file twice from `buffer_unordered`, double it in the stats, and
    /// leave its `_remote.repositories` marker to whichever unit finished last.
    /// On collision the recorded support-POM repository id replaces the ids
    /// of a companion POM, which are inferred from the referencing package's
    /// origins; every other pair of ids is merged.
    ///
    /// Collapsing is only legitimate when both units name the same bytes. One
    /// coordinate can be pinned by three independent recordings: an
    /// `artifacts[]` row's checksum, that row's `pom_sha256`, and the
    /// support-POM provenance. Every pair of them describes the same
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
        let guessed = |unit: &ExportUnit| {
            matches!(unit.source, UnitSource::CompanionPom) && !unit.repo_id_recorded
        };
        if unit.repo_id_recorded && guessed(previous) {
            previous.repo_ids = unit.repo_ids;
            previous.repo_id_recorded = true;
        } else if !(previous.repo_id_recorded && guessed(&unit)) {
            // One file served to different modules or platforms by different
            // repositories, such as a POM a jar and its classifier jar share,
            // or a BOM one module imports and another depends on, is
            // labelled with each.
            previous.repo_ids.extend(unit.repo_ids);
            previous.repo_ids.sort();
            previous.repo_ids.dedup();
            previous.repo_id_recorded |= unit.repo_id_recorded;
        }
        Ok(())
    }
}

/// Writes an [`ExportPlan`]'s artifacts, and the POMs around them, into a
/// Maven local repository.
pub struct Exporter<'a> {
    options: ExportOptions,
    store: &'a Store,
    /// The lock's pins and repository ids. Unknown repository URLs fall back
    /// to `central` in the `_remote.repositories` markers.
    plan: ExportPlan,
    /// Ceiling on unique support-POM nodes for one export. Resolved once at
    /// construction so every pass of a run shares one stable budget.
    max_support_pom_nodes: usize,
    /// Warnings found while constructing, reported with the first export.
    startup_warnings: Mutex<Vec<ExportWarning>>,
}

impl<'a> Exporter<'a> {
    /// An exporter that writes `plan` from `store` as `options` say, with the
    /// default support-POM limit of 10,000 unique POMs.
    pub fn new(options: ExportOptions, store: &'a Store, plan: ExportPlan) -> Self {
        Self {
            options,
            store,
            plan,
            max_support_pom_nodes: MAX_SUPPORT_POM_NODES,
            startup_warnings: Mutex::new(Vec::new()),
        }
    }

    /// Override the support-POM node budget with `raw`, the value of
    /// [`MAX_SUPPORT_POM_NODES_ENV`] as the caller read it. A value that is
    /// not a positive number keeps the default and is reported as a warning
    /// with the first export; `None` keeps the default silently.
    pub fn with_support_pom_limit(mut self, raw: Option<&str>) -> Self {
        let (limit, warning) = parse_max_support_pom_nodes(raw);
        self.max_support_pom_nodes = limit;
        self.startup_warnings
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(warning);
        self
    }

    /// The plan this exporter was given.
    pub fn plan(&self) -> &ExportPlan {
        &self.plan
    }

    /// The Maven repository ids of the repositories that served a package,
    /// sorted. An origin without one is labelled `central`: Maven Central is
    /// the overwhelmingly common source and is the id `mvn` itself records
    /// for it, so strict offline resolution keeps working for the common
    /// case.
    fn repo_ids_for(&self, artifact: &LockArtifact) -> Vec<String> {
        let mut ids = BTreeSet::new();
        for origin in artifact.origins() {
            match self.plan.repo_ids.get(&rv_lock::recorded_key(origin)) {
                Some(known) => ids.extend(known.iter().cloned()),
                None => {
                    ids.insert("central".to_string());
                }
            }
        }
        ids.into_iter().collect()
    }

    /// Export the plan's artifacts plus the support-POM closure referenced by
    /// every POM of `reactor`. A failure carries the warnings found before
    /// it.
    pub async fn export(
        &self,
        reactor: &Reactor,
    ) -> std::result::Result<ExportStats, ExportFailure> {
        self.export_inner(&self.plan.items, &self.plan.system_scoped, reactor, true)
            .await
    }

    /// Export `items` with the plan's POM pins and repository ids, and no
    /// project POMs. For artifacts the plan does not list, such as the
    /// classifier jars a caller fetched for locked coordinates.
    ///
    /// The items are ordered and deduplicated by coordinate first, as the
    /// plan's are, so the output does not depend on the order a caller
    /// collected them in: the first item's repository labels the support
    /// POMs that no pin covers, and the last one written decides shared
    /// snapshot metadata.
    pub async fn export_items(
        &self,
        items: &[LockArtifact],
    ) -> std::result::Result<ExportStats, ExportFailure> {
        let mut by_coordinate = BTreeMap::new();
        for item in items {
            by_coordinate.entry(item.coord()).or_insert(item);
        }
        let ordered: Vec<LockArtifact> = by_coordinate.into_values().cloned().collect();
        self.export_inner(&ordered, &[], &Reactor::default(), false)
            .await
    }

    /// `version_lists` writes the artifact-level metadata, which lists every
    /// locked version and so comes from the whole plan, never from a pass
    /// over some of its files.
    async fn export_inner(
        &self,
        items: &[LockArtifact],
        system_scoped: &[String],
        reactor: &Reactor,
        version_lists: bool,
    ) -> std::result::Result<ExportStats, ExportFailure> {
        let mut stats = ExportStats {
            warnings: std::mem::take(
                &mut *self
                    .startup_warnings
                    .lock()
                    .unwrap_or_else(|err| err.into_inner()),
            ),
            ..ExportStats::default()
        };
        let mut queue = ExportQueue::default();
        let outcome = self
            .export_queue(items, reactor, version_lists, &mut queue, &mut stats)
            .await;
        if outcome.is_err() {
            stats.warnings.append(&mut queue.warnings);
        }
        if !system_scoped.is_empty() {
            // Reported after the export rather than before it: the point of
            // the message is that the `mvn -o` build these files were
            // written for will look for something this `~/.m2` cannot hold.
            stats.warnings.push(ExportWarning::SystemScopedSkipped {
                coordinates: system_scoped.to_vec(),
            });
        }
        match outcome {
            Ok(()) => Ok(stats),
            Err(error) => Err(ExportFailure {
                error,
                warnings: stats.warnings,
            }),
        }
    }

    /// The body of [`Self::export_inner`]. Warnings go to `queue` while
    /// queueing and to `stats` after, so a failure can still return them.
    async fn export_queue(
        &self,
        items: &[LockArtifact],
        reactor: &Reactor,
        version_lists: bool,
        queue: &mut ExportQueue,
        stats: &mut ExportStats,
    ) -> Result<()> {
        let mut meta = MetadataAccumulator {
            replaces_listings: version_lists,
            empty_list_ids: if self.options.shared {
                BTreeSet::new()
            } else {
                (self.plan.query_ids.iter().map(String::as_str))
                    .chain(["local"])
                    .filter(|id| is_metadata_repo_id(id))
                    .map(str::to_string)
                    .collect()
            },
            shared: self.options.shared,
            ..MetadataAccumulator::default()
        };
        let mut poms: HashSet<BlobId> = (self.plan.support_poms.values())
            .map(|pin| pin.sha256.clone())
            .chain(self.plan.pom_digests.values().cloned())
            .collect();
        let mut others = HashSet::new();
        for artifact in items {
            if let Some(Digest::Sha256(blob)) = artifact.pin() {
                if artifact.coordinate.extension() == "pom" {
                    poms.insert(blob.clone());
                } else {
                    others.insert(blob.clone());
                }
            }
        }
        queue.blobs = StoreFacts::gather(self.store, poms, others).await;

        // Collect blob IDs, deduplicate files and validate pins before any
        // concurrent exports; the index cannot be fanned out to concurrent
        // writers. This pass also accumulates shared metadata.
        // Accumulate metadata once per coordinate across platforms.
        let mut accumulated: HashSet<ArtifactCoord> = HashSet::new();

        // Seed the closure with the coordinates `raeva sync` recorded for every
        // support POM it fetched: each model's `<parent>` ancestry and the
        // BOMs its effective model imports, nested imports and their parents
        // included. Imports are taken only from these records. The text of
        // a POM cannot say which BOM it imports: the version may come from a
        // child's property, a parent's, or `${project.*}`, which only the
        // model `raeva sync` built interpolates as Maven does. The sources and
        // javadocs passes re-seed idempotently.
        if !self.plan.support_poms.is_empty() {
            // Sort the seeds: `support_poms` is a `HashMap`, and the walk
            // order decides which node trips the closure limit. An export that
            // fails on one run has to fail on every run.
            let mut coords: Vec<&str> = self.plan.support_poms.keys().map(String::as_str).collect();
            coords.sort_unstable();
            let seed_refs: Vec<(String, String, String)> =
                coords.into_iter().filter_map(parse_gav).collect();
            self.enqueue_support_closure(seed_refs, reactor, queue)
                .await?;
        }
        for (coord, pin) in &self.plan.support_poms {
            let Some((group_id, artifact_id, version)) = parse_gav(coord) else {
                continue;
            };
            let file_version = pin.build.as_ref().unwrap_or(&version);
            if version_lists && file_version.ends_with("SNAPSHOT") {
                meta.plain_snapshots.insert((
                    group_id.clone(),
                    artifact_id.clone(),
                    version.clone(),
                ));
            }
            let base = rv_maven_types::snapshot_base_version(file_version);
            for repo_id in &pin.repo_ids {
                let listing_id = version_list_repo_id(repo_id);
                if let (Some(snapshot), Some(base)) =
                    (TimestampedSnapshot::parse(file_version), &base)
                    && (pin.build.is_some()
                        || self.is_latest_support_build(&group_id, &artifact_id, file_version))
                {
                    // A SNAPSHOT pinned to a build, or a relocated SNAPSHOT
                    // dependency recorded by its build. `mvn -o` takes the build
                    // these lists name over the plain file, so one an earlier run
                    // left must not stay listed. An
                    // artifact row of the same SNAPSHOT, accumulated later, wins.
                    let state = meta
                        .snapshots
                        .entry(SnapshotMetaKey {
                            group_id: group_id.clone(),
                            artifact_id: artifact_id.clone(),
                            base_version: base.clone(),
                            repo_id: listing_id.clone(),
                        })
                        .or_default();
                    let updated = compact_updated(snapshot.timestamp())
                        .unwrap_or_else(|| "00000000000000".to_string());
                    state.timestamp = Some(snapshot.timestamp().to_string());
                    state.build_number = snapshot.build_number();
                    state.last_updated = Some(updated.clone());
                    push_snapshot_entry(
                        &mut state.entries,
                        SnapshotVersionEntry {
                            extension: "pom".to_string(),
                            classifier: None,
                            value: file_version.clone(),
                            updated,
                        },
                    );
                }
                if version_lists {
                    // A parent, an import or a relocated dependency may be named
                    // by a range, which `mvn -o` resolves from these lists too.
                    meta.artifacts
                        .entry(ArtifactMetaKey {
                            group_id: group_id.clone(),
                            artifact_id: artifact_id.clone(),
                        })
                        .or_default()
                        .entry(listing_id)
                        .or_default()
                        .add_version(base.as_deref().unwrap_or(&version));
                }
            }
        }

        // The project's own POMs live on disk, not in the lock, but their
        // remote `<parent>` must also be in ~/.m2 for `mvn -o` to build the
        // reactor. raeva.lock records it, as it records the BOMs those POMs
        // import; the walk only adds a parent the records lack. Only the
        // primary export passes the reactor; the sources and javadocs passes
        // reuse the same dedupe set and skip it. A parent read from disk or
        // a reactor module is no support POM: Maven takes it from the
        // reactor.
        for project_pom in &reactor.poms {
            if project_pom.local_parent {
                continue;
            }
            let refs: Vec<_> = read_support_parent(&project_pom.path).into_iter().collect();
            self.enqueue_support_closure(refs, reactor, queue).await?;
        }

        for artifact in items {
            let key = artifact.coord();
            // A SNAPSHOT a repository serves without builds changes in
            // place, as Maven rewrites it.
            let plain_snapshot = key.version().ends_with("SNAPSHOT");
            if plain_snapshot {
                meta.plain_snapshots.insert((
                    key.group_id().to_string(),
                    key.artifact_id().to_string(),
                    key.version().to_string(),
                ));
            }

            let blob = self
                .blob_id_for_package(&key, artifact, &queue.blobs)
                .await?;
            let repo_ids = self.repo_ids_for(artifact);
            let pom_gav = artifact.pom_gav();
            let pom_coord = (
                pom_gav.group.to_string(),
                pom_gav.artifact.to_string(),
                pom_gav.version().to_string(),
            );

            if key.extension() != "pom" {
                let pom_key = ArtifactCoord::of(pom_gav, "pom", None);
                // A sibling classifier may have queued this g:a:v POM
                // already; re-queuing it hashes and writes the same
                // bytes twice. So may the support-POM closure, which runs
                // first, and skipping outright on that account would skip
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
                    if let Some(pinned) = self.plan.pom_digests.get(&pom_coord) {
                        queue.push(ExportUnit {
                            key: pom_key,
                            blob: pinned.clone(),
                            source: UnitSource::CompanionPom,
                            repo_ids: repo_ids.clone(),
                            repo_id_recorded: false,
                            replace: plain_snapshot || artifact.pom_base,
                        })?;
                    }
                } else if !queue.enqueued_poms.contains(&pom_coord)
                    && let Some(pom_blob) =
                        self.companion_pom_blob(&pom_coord, &queue.blobs).await?
                {
                    queue.enqueued_poms.insert(pom_coord);
                    // `mvn -o` fails with "Non-resolvable parent POM" unless
                    // this POM's `<parent>` ancestry is exported alongside it.
                    let refs = queue
                        .blobs
                        .parent(self.store, &pom_blob)
                        .into_iter()
                        .collect();
                    self.enqueue_support_closure(refs, reactor, queue).await?;
                    queue.push(ExportUnit {
                        key: pom_key,
                        blob: pom_blob,
                        source: UnitSource::CompanionPom,
                        repo_ids: repo_ids.clone(),
                        repo_id_recorded: false,
                        replace: plain_snapshot || artifact.pom_base,
                    })?;
                }
            } else {
                // A lockfile package that is itself a POM still needs its
                // parent ancestry materialized for offline builds.
                // This package IS the `.pom` at that path, so the row's own
                // payload pin and its companion-POM pin have to name the same
                // blob. They are written by two independent observations
                // during resolution, and `raeva sync` and `Lockfile::read` both
                // reject a disagreement; failing here as well means no export
                // can silently write the payload while the lockfile claims the
                // other digest is what was resolved. A classified `.pom` is a
                // separate file from the coordinate's companion POM and keeps
                // its own bytes.
                if key.classifier().is_none()
                    && let Some(pinned) = self.plan.pom_digests.get(&pom_coord)
                    && *pinned != blob
                {
                    return Err(ExportError::ConflictingPomPackagedPin {
                        coordinate: key.gav.to_string(),
                        artifact: blob.to_string(),
                        pom: pinned.to_string(),
                    });
                }
                // The insert may report the coordinate as already queued: this
                // POM can also be support metadata for another package. That
                // is fine, `queue.push` below collapses the two into one unit.
                queue.enqueued_poms.insert(pom_coord);
                let refs = queue.blobs.parent(self.store, &blob).into_iter().collect();
                self.enqueue_support_closure(refs, reactor, queue).await?;
            }

            // Export order is cosmetic. Queueing the package after its
            // ancestry only keeps related files adjacent in the unit list;
            // duplicates are collapsed by key rather than by arrival order.
            queue.push(ExportUnit {
                key: key.clone(),
                blob,
                source: UnitSource::Package,
                repo_ids,
                repo_id_recorded: false,
                replace: plain_snapshot,
            })?;

            if accumulated.insert(key) {
                self.accumulate_metadata(artifact, version_lists, &mut meta);
            }
        }

        queue_plain_snapshot_copies(items, queue)?;
        reject_case_folded_collisions(&self.options, &queue.units)?;
        stats.warnings.append(&mut queue.warnings);

        // Exports to one local repository take turns: each judges the files
        // it finds there and merges the metadata and markers they share.
        // Every blocking writer holds the turn too, since one keeps running
        // when an interrupt drops this future.
        let turn = match self.options.dry_run {
            true => None,
            false => Some(Arc::new(
                lock_destination(&self.options.m2_path, EXPORT_LOCK_TIMEOUT).await?,
            )),
        };

        // Second pass: fan out the actual export work. Each entry only
        // touches the filesystem (link/copy/hash), with no shared mutable
        // state between tasks, so we can run several concurrently. The work
        // is mostly file I/O dispatched through `spawn_blocking`, which
        // already throttles via the tokio blocking-thread pool, so we just
        // need a ceiling that's high enough not to be the bottleneck on
        // multi-core boxes. 64 keeps us well under any sensible
        // blocking-thread count while still leaving room for fan out on big
        // lockfiles.
        let parallelism = export_parallelism();

        // Each task owns an export unit and borrows `self` immutably.
        type UnitResult = (
            ExportOutcome,
            Option<ExportWarning>,
            PathBuf,
            Vec<String>,
            bool,
        );
        let mut outcomes: Vec<(usize, Result<UnitResult>)> =
            stream::iter(std::mem::take(&mut queue.units).into_iter().enumerate())
                .map(|(index, item)| {
                    let turn = turn.clone();
                    async move {
                        let outcome = self
                            .export_artifact_async(&item.key, &item.blob, item.replace, turn)
                            .await
                            .map(|(outcome, warning, dest)| {
                                let classified = item.key.classifier().is_some();
                                (outcome, warning, dest, item.repo_ids, classified)
                            });
                        (index, outcome)
                    }
                })
                .buffer_unordered(parallelism)
                .collect()
                .await;
        // Units finish in any order; the warnings and the reported failure
        // follow the queue instead.
        outcomes.sort_unstable_by_key(|(index, _)| *index);

        let mut markers = RemoteRepositoriesAccumulator::default();
        // Every unit has run by now; keep the warnings of the ones that
        // succeeded even when another failed.
        let mut failed = None;
        for (_, outcome) in outcomes {
            let (entry, warning, dest, repo_ids, classified) = match outcome {
                Ok(done) => done,
                Err(err) => {
                    failed.get_or_insert(err);
                    continue;
                }
            };
            stats.record(entry);
            if classified && matches!(entry, ExportOutcome::Skipped) {
                stats.skipped_classified_count += 1;
            }
            stats.warnings.extend(warning);
            // Record the marker for every materialized file. Maven needs the
            // `_remote.repositories` entry whether we wrote the file just now
            // or skipped an already-identical copy.
            //
            // No id is the one exception: it is a support POM whose
            // recorded provenance names a repository without an id, and a
            // marker line has nowhere to put "unknown". The file is still
            // exported; only its marker is left out.
            if let (Some(dir), Some(filename)) =
                (dest.parent(), dest.file_name().and_then(|n| n.to_str()))
            {
                for repo_id in &repo_ids {
                    // An empty recorded id has nowhere to put "unknown" on a
                    // marker line; leave the file unmarked.
                    if repo_id.is_empty() {
                        continue;
                    }
                    markers.record(dir, filename, repo_id);
                }
            }
        }
        if let Some(err) = failed {
            return Err(err);
        }

        if !self.options.dry_run {
            // `write_metadata_blocking` opens, writes, fsyncs, and renames a handful
            // of XML files: blocking I/O that has no business running on the
            // async runtime. Hand it off so other tasks can progress while
            // the disk catches up. The `_remote.repositories` markers ride
            // along in the same blocking hop.
            let m2_path = self.options.m2_path.clone();
            spawn_blocking(move || {
                let _turn = turn;
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

        Ok(())
    }

    fn accumulate_metadata(
        &self,
        artifact: &LockArtifact,
        version_lists: bool,
        meta: &mut MetadataAccumulator,
    ) {
        let base = artifact.directory_version();
        let file_version = artifact.file_version();
        let coordinate = &artifact.coordinate;
        let repo_ids = self.repo_ids_for(artifact);
        if version_lists {
            // Listed under each id the files' markers name, so `mvn -o`
            // reads the list for the repository it would fetch them from.
            let artifact_key = ArtifactMetaKey {
                group_id: coordinate.group_id().to_string(),
                artifact_id: coordinate.artifact_id().to_string(),
            };
            let lists = meta.artifacts.entry(artifact_key).or_default();
            for repo_id in &repo_ids {
                let artifact_state = lists.entry(version_list_repo_id(repo_id)).or_default();
                artifact_state.add_version(&base);
                if let Some(stamp) = artifact
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| compact_updated(snapshot.timestamp()))
                {
                    artifact_state.last_updated = Some(stamp);
                }
            }
        }

        if !artifact.is_snapshot() {
            return;
        }

        // Maven keeps one snapshot metadata file per repository it read.
        for repo_id in repo_ids {
            let snapshot_key = SnapshotMetaKey {
                group_id: coordinate.group_id().to_string(),
                artifact_id: coordinate.artifact_id().to_string(),
                base_version: base.clone(),
                repo_id: version_list_repo_id(&repo_id),
            };
            let state = meta.snapshots.entry(snapshot_key).or_default();
            state.pom_base |= artifact.pom_base;

            // Timestamp and build number from the snapshot build, or from the
            // build the version names.
            let stamp = if let Some(snapshot) = &artifact.snapshot {
                Some((snapshot.timestamp().to_string(), Some(snapshot.build())))
            } else {
                TimestampedSnapshot::parse(artifact.coordinate.version())
                    .map(|snapshot| (snapshot.timestamp().to_string(), snapshot.build_number()))
            };
            if let Some((timestamp, build_number)) = stamp {
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
                    extension: coordinate.extension().to_string(),
                    classifier: coordinate.classifier().map(str::to_string),
                    value: file_version.clone(),
                    updated: updated.clone(),
                },
            );
            // Maven also lists the POM as a snapshot version entry when the
            // repository listed one.
            if coordinate.extension() != "pom" && !artifact.pom_base {
                push_snapshot_entry(
                    &mut state.entries,
                    SnapshotVersionEntry {
                        extension: "pom".to_string(),
                        classifier: None,
                        value: artifact.pom_gav().version().to_string(),
                        updated: artifact
                            .pom_snapshot
                            .as_ref()
                            .and_then(|stamp| compact_updated(stamp.timestamp()))
                            .unwrap_or(updated),
                    },
                );
            }
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
        key: &ArtifactCoord,
        blob_id: &BlobId,
        replace: bool,
        turn: Option<Arc<fs::File>>,
    ) -> Result<(ExportOutcome, Option<ExportWarning>, PathBuf)> {
        let src = self.store.get_path(blob_id);
        let store = self.store.clone();
        let mut options = self.options.clone();
        options.overwrite |= replace;
        let key_str = key.to_string();
        let blob_id = blob_id.clone();
        let key = key.clone();

        spawn_blocking(move || {
            let _turn = turn;
            let dest = safe_artifact_path(&options, &key)?;
            let (outcome, warning) =
                export_artifact_blocking(&store, &src, &dest, &options, &key_str, &blob_id)?;
            Ok((outcome, warning, dest))
        })
        .await
        .map_err(|e| ExportError::IoError(std::io::Error::other(e.to_string())))?
    }

    /// Queue the support POMs in `initial_refs` and the `<parent>` ancestry
    /// of each for export.
    ///
    /// `mvn -o` refuses to build when it cannot resolve a parent POM
    /// ("Non-resolvable parent POM") or an imported BOM ("Non-resolvable
    /// import POM") offline. Neither is a lockfile package; raeva.lock records
    /// them as support POMs, each one `raeva sync` fetched while it built a
    /// model (see `RepoBackend::persist_support_pom`). The walk follows the
    /// literal `<parent>` of each POM as well, rejecting any remote parent
    /// whose digest the lock does not record.
    ///
    /// A recorded coordinate is resolved from the content-addressed store by
    /// its digest, not from the coordinate index, and pinned bytes that are
    /// gone fail the export with [`ExportError::MissingPinnedPom`]: `raeva sync`
    /// said it fetched that POM, so its absence is a known-incomplete offline
    /// repository, not a POM Maven will not ask for.
    ///
    /// A closure larger than [`MAX_SUPPORT_POM_NODES`] unique POMs also fails
    /// the export outright, for the same reason: the alternative is a `~/.m2`
    /// that reports success and is missing parents.
    ///
    /// Both failures are raised here, during queueing, so nothing has been
    /// written to `~/.m2` when the export aborts.
    /// Exact support pin, or the highest recorded pin whose version matches
    /// a parent version range. Soft versions that are not recorded stay
    /// unresolved so the caller can treat them as reactor modules.
    fn support_pom_for(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
    ) -> Option<(String, &SupportPomPin)> {
        let exact = format!("{group_id}:{artifact_id}:{version}");
        if let Some(pin) = self.plan.support_poms.get(&exact) {
            return Some((version.to_string(), pin));
        }
        let req = VersionReq::parse(version).ok()?;
        if matches!(req, VersionReq::Soft(_)) {
            return None;
        }
        let (_, pinned, pin) = self
            .plan
            .support_poms
            .iter()
            .filter_map(|(coord, pin)| {
                let (group, artifact, pinned) = parse_gav(coord)?;
                if group != group_id || artifact != artifact_id {
                    return None;
                }
                let parsed = Version::parse(&pinned).ok()?;
                req.matches(&parsed).then_some((parsed, pinned, pin))
            })
            .max_by(|a, b| a.0.cmp(&b.0))?;
        Some((pinned, pin))
    }

    async fn enqueue_support_closure(
        &self,
        initial_refs: Vec<(String, String, String)>,
        reactor: &Reactor,
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
            let requested = format!("{group_id}:{artifact_id}:{version}");
            // A `<parent>` version range must export the pin sync recorded
            // (e.g. `parent:[1,2)` → `parent:1`), not fail as unpinned.
            let Some((version, recorded)) = self.support_pom_for(&group_id, &artifact_id, &version)
            else {
                // Maven takes a reactor module's POM from the reactor, unless a
                // module's `<relativePath>` misses it and it is fetched as a
                // parent, which `raeva sync` then recorded.
                if reactor
                    .modules
                    .contains(&Gav::new(&group_id, &artifact_id, &version))
                {
                    continue;
                }
                return Err(ExportError::UnpinnedPom {
                    coordinate: requested,
                });
            };
            let coord_key = format!("{group_id}:{artifact_id}:{version}");
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
            let key = ArtifactCoord::new(&group_id, &artifact_id, &version, "pom", None);
            let support_blob = &recorded.sha256;
            // Evidence is kept under the file read: a SNAPSHOT parent's build.
            let file = recorded.build.as_deref().unwrap_or(&version);
            let read = ArtifactCoord::new(&group_id, &artifact_id, file, "pom", None);
            if !queue.blobs.exists(self.store, support_blob).await
                || !(self.plan)
                    .admits_support_pom(recorded, &self.store.served_by(&read, support_blob).await?)
            {
                return Err(ExportError::MissingPinnedPom {
                    coordinate: coord_key,
                    digest: support_blob.to_string(),
                });
            }
            worklist.extend(queue.blobs.parent(self.store, support_blob));
            if let Some(build) = &recorded.build {
                // Maven keeps a build it downloads under its timestamped name,
                // tracked and listed in the version metadata, and a plain
                // `-SNAPSHOT` copy that any repository's build may read.
                queue
                    .enqueued_poms
                    .insert((group_id.clone(), artifact_id.clone(), build.clone()));
                for (version, repo_ids, replace) in [
                    (build.as_str(), recorded.repo_ids.clone(), false),
                    (version.as_str(), Vec::new(), true),
                ] {
                    queue.push(ExportUnit {
                        key: ArtifactCoord::new(&group_id, &artifact_id, version, "pom", None),
                        blob: support_blob.clone(),
                        source: UnitSource::SupportPom,
                        repo_ids,
                        repo_id_recorded: true,
                        replace,
                    })?;
                }
                continue;
            }
            // A relocated SNAPSHOT dependency is recorded by its build. With
            // no snapshot metadata, `mvn -o` reads the plain `-SNAPSHOT`
            // file, which Maven rewrites on every update.
            let plain = TimestampedSnapshot::parse(&version)
                .and_then(|_| rv_maven_types::snapshot_base_version(&version))
                .filter(|_| self.is_latest_support_build(&group_id, &artifact_id, &version))
                .filter(|base| {
                    queue.enqueued_poms.insert((
                        group_id.clone(),
                        artifact_id.clone(),
                        base.clone(),
                    ))
                });
            let repo_ids = recorded.repo_ids.clone();
            queue.push(ExportUnit {
                key,
                blob: support_blob.clone(),
                source: UnitSource::SupportPom,
                repo_ids: repo_ids.clone(),
                repo_id_recorded: true,
                // A plain `-SNAPSHOT` parent or BOM changes with each update.
                replace: version.ends_with("SNAPSHOT"),
            })?;
            if let Some(base) = plain {
                queue.push(ExportUnit {
                    key: ArtifactCoord::new(&group_id, &artifact_id, &base, "pom", None),
                    blob: support_blob.clone(),
                    source: UnitSource::SupportPom,
                    repo_ids,
                    repo_id_recorded: true,
                    replace: true,
                })?;
            }
        }
        Ok(())
    }

    /// Whether `version`, a SNAPSHOT build of a support POM, is the one a
    /// `-SNAPSHOT` request resolves to: the latest build the lock records,
    /// unless the lock pins the `-SNAPSHOT` POM itself, as a parent or BOM.
    fn is_latest_support_build(&self, group_id: &str, artifact_id: &str, version: &str) -> bool {
        let build = |version: &str| {
            let snapshot = TimestampedSnapshot::parse(version)?;
            let base = rv_maven_types::snapshot_base_version(version)?;
            Some((
                base,
                snapshot.timestamp().to_string(),
                snapshot.build_number(),
            ))
        };
        let Some(this) = build(version) else {
            return false;
        };
        let plain = format!("{group_id}:{artifact_id}:{}", this.0);
        !self.plan.support_poms.contains_key(&plain)
            && !self.plan.support_poms.keys().any(|coord| {
                parse_gav(coord).is_some_and(|(group, artifact, other)| {
                    group == group_id
                        && artifact == artifact_id
                        && build(&other).is_some_and(|other| other.0 == this.0 && other > this)
                })
            })
    }

    /// The companion POM the lockfile pins for one artifact coordinate. The
    /// The companion POM the lockfile pins for one artifact coordinate,
    /// `None` when it pins none because no repository has one. The blob is
    /// addressed by that digest, never through the store's last-writer-wins
    /// coordinate index, and pinned bytes that are gone fail the export
    /// rather than let another project's POM stand in.
    async fn companion_pom_blob(
        &self,
        pom_coord: &(String, String, String),
        blobs: &StoreFacts,
    ) -> Result<Option<BlobId>> {
        let Some(pinned) = self.plan.pom_digests.get(pom_coord) else {
            return Ok(None);
        };
        let (group, artifact, version) = pom_coord;
        let key = ArtifactCoord::new(group, artifact, version, "pom", None);
        if blobs.exists(self.store, pinned).await
            && (self.plan).admits_pom(pom_coord, &self.store.served_by(&key, pinned).await?)
        {
            return Ok(Some(pinned.clone()));
        }
        Err(ExportError::MissingPinnedPom {
            coordinate: format!("{}:{}:{}", pom_coord.0, pom_coord.1, pom_coord.2),
            digest: pinned.to_string(),
        })
    }

    async fn blob_id_for_package(
        &self,
        key: &ArtifactCoord,
        artifact: &LockArtifact,
        blobs: &StoreFacts,
    ) -> Result<BlobId> {
        // A stored file stands in for this coordinate only when a repository
        // the configuration or the row names served it for this coordinate.
        // The index names whatever the last project fetched, so an edited
        // pin could otherwise name another repository's bytes, or an older
        // release's jar.
        let served = async |blob| -> Result<bool> {
            Ok((self.plan).admits(artifact, &self.store.served_by(key, blob).await?))
        };
        if let Some(Digest::Sha256(blob)) = artifact.pin()
            && blobs.exists(self.store, blob).await
            && served(blob).await?
        {
            return Ok(blob.clone());
        }
        // The locked lookup also checks that the blob file exists.
        if let Some(blob) = self.store.lookup_artifact_locked(key).await?
            && served(&blob).await?
        {
            // When the global Raeva store is shared across projects,
            // Project A's `sync` populates the index with A's blob. If
            // Project B then runs `export-m2` without first syncing its own
            // lockfile, we would happily ship A's bytes labelled as B's
            // coordinate. Re-verify against B's pin so the mismatch is
            // caught with a clear "run `raeva sync` first" message instead of
            // silently exporting the wrong artifact.
            if let Some(checksum) = artifact.pin() {
                verify_pin_against_blob(self.store, key, &blob, checksum).await?;
            }
            return Ok(blob);
        }

        let Some(checksum) = artifact.pin() else {
            return Err(ExportError::MissingBlob {
                key: key.to_string(),
            });
        };

        // The store is SHA-256 keyed, so a SHA-1 or MD5 pin cannot address a
        // blob and is reported as unsupported.
        match checksum {
            Digest::Sha256(_) => Err(ExportError::MissingBlob {
                key: key.to_string(),
            }),
            Digest::Sha1(_) | Digest::Md5(_) => Err(ExportError::UnsupportedChecksum {
                key: key.to_string(),
                algorithm: checksum.algorithm().to_string(),
            }),
        }
    }
}

/// Queue a plain `-SNAPSHOT` copy of each timestamped file of a row that
/// asks for a `-SNAPSHOT` version, and of its companion POM, as Maven 3.9
/// leaves one next to every snapshot it downloads. The copies get no
/// `_remote.repositories` entry, so `mvn -o` accepts them whichever
/// repository or mirror id its settings use, and needs no metadata to find
/// them.
fn queue_plain_snapshot_copies(items: &[LockArtifact], queue: &mut ExportQueue) -> Result<()> {
    let requested: HashSet<(&str, &str, String)> = items
        .iter()
        .filter(|artifact| {
            artifact.snapshot.is_some()
                && rv_maven_types::is_snapshot_version(artifact.coordinate.version())
                && TimestampedSnapshot::parse(artifact.coordinate.version()).is_none()
        })
        .flat_map(|artifact| {
            [
                artifact.file_version(),
                artifact.pom_gav().version().to_string(),
            ]
            .map(|version| {
                (
                    artifact.coordinate.group_id(),
                    artifact.coordinate.artifact_id(),
                    version,
                )
            })
        })
        .collect();
    if requested.is_empty() {
        return Ok(());
    }
    let copies: Vec<ExportUnit> = queue
        .units
        .iter()
        .filter(|unit| {
            requested.contains(&(
                unit.key.group_id(),
                unit.key.artifact_id(),
                unit.key.version().to_string(),
            ))
        })
        .filter_map(|unit| {
            let base = rv_maven_types::snapshot_base_version(unit.key.version())?;
            Some(ExportUnit {
                key: ArtifactCoord::of(
                    Gav::new(unit.key.group_id(), unit.key.artifact_id(), &base),
                    unit.key.extension(),
                    unit.key.classifier(),
                ),
                blob: unit.blob.clone(),
                source: unit.source,
                repo_ids: Vec::new(),
                repo_id_recorded: false,
                replace: true,
            })
        })
        .collect();
    for copy in copies {
        queue.push(copy)?;
    }
    Ok(())
}

/// The classifier and extension a `<snapshotVersion>` names.
type EntryKey = (Option<String>, String);

/// Writes every accumulated metadata file underneath `m2_path`. Called from
/// `spawn_blocking` so the fsync chain doesn't stall the async runtime.
fn write_metadata_blocking(m2_path: &Path, meta: &mut MetadataAccumulator) -> Result<()> {
    // Files one repository serves for a SNAPSHOT may come from another
    // repository's build on disk; Maven merges every repository's entries,
    // so an entry this export writes for any repository replaces the one an
    // earlier run left in every repository's metadata.
    let mut exported: HashMap<(&str, &str, &str), HashSet<EntryKey>> = HashMap::new();
    for (key, state) in &meta.snapshots {
        exported
            .entry((&key.group_id, &key.artifact_id, &key.base_version))
            .or_default()
            .extend(
                (state.entries.iter())
                    .map(|entry| (entry.classifier.clone(), entry.extension.clone()))
                    .chain(state.pom_base.then(|| (None, "pom".to_string()))),
            );
    }
    for (key, state) in &meta.snapshots {
        let exported = &exported[&(
            key.group_id.as_str(),
            key.artifact_id.as_str(),
            key.base_version.as_str(),
        )];
        write_snapshot_metadata_blocking(m2_path, key, state, exported)?;
    }
    // `mvn -o` takes the latest build the metadata of a version directory
    // names, of any repository, over the plain file. So the main pass
    // removes another repository's metadata, and metadata an earlier run
    // left for a SNAPSHOT whose build the lock does not name goes too.
    let mut written: BTreeMap<(&str, &str, &str), HashSet<&str>> = BTreeMap::new();
    for (key, state) in &meta.snapshots {
        if state.timestamp.is_some() && is_metadata_repo_id(&key.repo_id) {
            written
                .entry((&key.group_id, &key.artifact_id, &key.base_version))
                .or_default()
                .insert(&key.repo_id);
        }
    }
    // The other ids get an empty list, so the tail's does not stand in.
    // Only the main pass writes them: a later pass's ids may be fewer.
    let empty_ids: HashSet<&str> = meta.empty_list_ids.iter().map(String::as_str).collect();
    let empty_lists = meta.replaces_listings && !meta.shared;
    if empty_lists {
        for ((group_id, artifact_id, version), ids) in &written {
            let others: Vec<&str> = empty_ids.difference(ids).copied().collect();
            let keep = ids.union(&empty_ids).copied().collect();
            remove_version_metadata(m2_path, group_id, artifact_id, version, &keep)?;
            let listed: Vec<&str> = ids.iter().copied().collect();
            write_empty_lists(
                m2_path,
                group_id,
                artifact_id,
                Some(version),
                &others,
                &listed,
            )?;
        }
    }
    for (group_id, artifact_id, version) in &meta.plain_snapshots {
        if !meta.shared
            && !written.contains_key(&(group_id.as_str(), artifact_id.as_str(), version.as_str()))
        {
            remove_version_metadata(m2_path, group_id, artifact_id, version, &empty_ids)?;
            if empty_lists {
                let ids: Vec<&str> = empty_ids.iter().copied().collect();
                write_empty_lists(m2_path, group_id, artifact_id, Some(version), &ids, &[])?;
            }
        }
    }
    for (key, state) in meta.artifacts.iter_mut() {
        write_artifact_metadata_blocking(m2_path, key, state, &empty_ids, meta.shared)?;
    }
    Ok(())
}

/// Write a `maven-metadata-<id>.xml` that lists nothing for each of `ids`,
/// in the artifact directory or, with `version`, that version's.
///
/// `mvn -o` reads the list of each repository the build uses, and of the
/// local repository, from the head local repository and, only where the
/// head has no such file, from a `-Dmaven.repo.local.tail`. An online run
/// that filled the tail leaves lists there that name versions or SNAPSHOT
/// builds the lock does not. An empty list hides each: listing the locked
/// versions instead would let an id the lock did not take them from, or the
/// local repository, claim them, and `mvn -o` then looks for their files
/// there only.
///
/// `listed` are the ids whose lists were just written there. On a volume
/// that folds case an id differing from one of them only in case names the
/// same file, which keeps its list.
fn write_empty_lists(
    m2_path: &Path,
    group_id: &str,
    artifact_id: &str,
    version: Option<&str>,
    ids: &[&str],
    listed: &[&str],
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let group_path = validate_group_path(group_id)?;
    validate_path_segment(CoordinateField::Artifact, artifact_id)?;
    let mut dir = m2_path.join(group_path).join(artifact_id);
    if let Some(version) = version {
        validate_path_segment(CoordinateField::Version, version)?;
        dir.push(version);
    }
    let dir = confined_dir(m2_path, dir)?;
    let xml = render_empty_metadata(group_id, artifact_id, version);
    let file = |id: &str| dir.join(format!("maven-metadata-{id}.xml"));
    for id in ids {
        let dest = file(id);
        let lower = id.to_lowercase();
        if (listed.iter())
            .any(|other| other.to_lowercase() == lower && same_file(&dest, &file(other)))
        {
            continue;
        }
        if write_metadata_atomic(&dest, &xml)? {
            remove_checksums(&dest)?;
        }
        // An online run takes a local list's modification time as the last
        // check of every repository for a SNAPSHOT, RELEASE or LATEST; Java
        // reads the epoch as no time. Another id the volume folds onto
        // `local` may have written the file. A FAT volume keeps no time
        // before 1980; 2 January 1980 is as old to Maven.
        let fat_epoch = UNIX_EPOCH + std::time::Duration::from_secs(315_619_200);
        if *id == "local"
            && (fs::symlink_metadata(&dest)?.modified()).is_ok_and(|time| time > fat_epoch)
        {
            let _ = (fs::File::options().write(true).open(&dest)).and_then(|file| {
                file.set_modified(UNIX_EPOCH)
                    .or_else(|_| file.set_modified(fat_epoch))
            });
        }
    }
    Ok(())
}

fn write_snapshot_metadata_blocking(
    m2_path: &Path,
    key: &SnapshotMetaKey,
    state: &SnapshotMetaState,
    exported: &HashSet<EntryKey>,
) -> Result<()> {
    // The id becomes part of a file name. Without a usable one Maven still
    // finds the plain `-SNAPSHOT` copies, which need no metadata.
    let Some(timestamp) = state.timestamp.as_deref() else {
        return Ok(());
    };
    if !is_metadata_repo_id(&key.repo_id) {
        return Ok(());
    }
    let build_number = state.build_number.unwrap_or(0);
    let group_path = validate_group_path(&key.group_id)?;
    validate_path_segment(CoordinateField::Artifact, &key.artifact_id)?;
    validate_path_segment(CoordinateField::Version, &key.base_version)?;
    let dir = confined_dir(
        m2_path,
        m2_path
            .join(group_path)
            .join(&key.artifact_id)
            .join(&key.base_version),
    )?;
    let dest = dir.join(format!("maven-metadata-{}.xml", key.repo_id));
    let existing = read_existing_metadata(&dest);
    let last_updated = later_stamp(
        state
            .last_updated
            .clone()
            .unwrap_or_else(|| compact_updated(timestamp).unwrap_or_default()),
        existing.last_updated,
    );
    let xml = render_versioned_metadata(&VersionedMetadata {
        group_id: &key.group_id,
        artifact_id: &key.artifact_id,
        base_snapshot_version: &key.base_version,
        timestamp,
        build_number,
        last_updated: &last_updated,
        entries: merge_snapshot_entries(
            &state.entries,
            (existing.snapshot_versions.into_iter())
                .filter(|entry| {
                    !exported.contains(&(entry.classifier.clone(), entry.extension.clone()))
                })
                .collect(),
        ),
    });
    if write_metadata_atomic(&dest, &xml)? {
        remove_checksums(&dest)?;
    }
    Ok(())
}

/// Repository id used in artifact-level and snapshot version lists.
///
/// An empty recorded id has no remote `maven-metadata-<id>.xml`. Offline
/// ranges still need a list, so use the local one Maven reserves for
/// installs. Marker lines keep the empty id and omit the entry instead.
fn version_list_repo_id(id: &str) -> String {
    if id.is_empty() {
        "local".to_string()
    } else {
        id.to_string()
    }
}

/// Whether `id` can name `maven-metadata-<id>.xml` safely: one Maven
/// accepts, which bans only the characters file systems reject.
///
/// `local` is allowed: a pin or row with no repository id lists its
/// versions there so `mvn -o` can resolve a parent or import range. A
/// case-insensitive file system still collides with Maven's install
/// listing; that collision is the same one an empty id would force by
/// remapping to `local`.
fn is_metadata_repo_id(id: &str) -> bool {
    !id.is_empty()
        && !id
            .chars()
            .any(|c| c.is_control() || "\\/:\"<>|?*".contains(c))
        && rv_fs::plain_name_is_safe(std::ffi::OsStr::new(&format!("maven-metadata-{id}.xml")))
}

/// Write the artifact-level `maven-metadata-<id>.xml` of each repository
/// id the lock takes versions of the artifact from, listing those versions
/// only, and remove the artifact's other `maven-metadata-*.xml` files.
///
/// `mvn -o` resolves a version range from these files: the one of each
/// repository the build uses, as an online run left it, and
/// `maven-metadata-local.xml` for what was installed. A version any of them
/// lists beyond the locked ones, from an earlier online build, another
/// module or another project, is one an offline range can resolve to
/// instead of the lock's. An online build fetches a removed file again.
///
/// In a `shared` repository nothing is removed and each list keeps the
/// versions it holds: there the other builds' listings matter more than a
/// locked `mvn -o`.
fn write_artifact_metadata_blocking(
    m2_path: &Path,
    key: &ArtifactMetaKey,
    by_repo: &mut BTreeMap<String, ArtifactMetaState>,
    empty_ids: &HashSet<&str>,
    shared: bool,
) -> Result<()> {
    let group_path = validate_group_path(&key.group_id)?;
    validate_path_segment(CoordinateField::Artifact, &key.artifact_id)?;
    let dir = confined_dir(m2_path, m2_path.join(&group_path).join(&key.artifact_id))?;
    let listed: Vec<String> = (by_repo.iter())
        .filter(|(_, state)| !state.is_empty())
        .map(|(id, _)| id.clone())
        .collect();
    let others: Vec<&str> = (empty_ids.iter().copied())
        .filter(|id| !listed.iter().any(|listed| listed == id))
        .collect();
    let keep: HashSet<String> = (by_repo.keys().map(String::as_str))
        .chain(others.iter().copied())
        .filter(|id| is_metadata_repo_id(id))
        .map(|id| format!("maven-metadata-{id}.xml"))
        .collect();
    let listings = if shared {
        None
    } else {
        fs::read_dir(&dir).ok()
    };
    for entry in listings.into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("maven-metadata-") && name.ends_with(".xml") && !keep.contains(name) {
            remove_metadata_file(&dir.join(name))?;
        }
    }
    for (repo_id, state) in by_repo.iter_mut() {
        if !is_metadata_repo_id(repo_id) || state.is_empty() {
            continue;
        }
        let dest = dir.join(format!("maven-metadata-{repo_id}.xml"));
        let existing = read_existing_metadata(&dest);
        if shared {
            for version in &existing.versions {
                state.add_version(version);
            }
        }
        let last_updated = later_stamp(
            state
                .last_updated
                .clone()
                .unwrap_or_else(|| "00000000000000".to_string()),
            existing.last_updated,
        );
        // Sort in Maven version order before rendering, so
        // `<latest>` and `<release>` are not picked lexicographically, where
        // `9.0.0` sorts after `10.0.0`.
        state.finalize();
        let latest = state.latest().expect("non-empty");
        let release = state.release();
        let xml = render_artifact_metadata(&ArtifactMetadata {
            group_id: &key.group_id,
            artifact_id: &key.artifact_id,
            latest,
            release,
            versions: state.versions().map(str::to_string).collect(),
            last_updated: &last_updated,
        });
        if write_metadata_atomic(&dest, &xml)? {
            // A checksum Maven saved with the file it downloaded no longer
            // matches it.
            remove_checksums(&dest)?;
        }
    }
    let listed: Vec<&str> = listed.iter().map(String::as_str).collect();
    write_empty_lists(
        m2_path,
        &key.group_id,
        &key.artifact_id,
        None,
        &others,
        &listed,
    )
}

/// Remove the `maven-metadata-<id>.xml` files of one version directory,
/// but those of the ids in `keep`.
fn remove_version_metadata(
    m2_path: &Path,
    group_id: &str,
    artifact_id: &str,
    version: &str,
    keep: &HashSet<&str>,
) -> Result<()> {
    let group_path = validate_group_path(group_id)?;
    validate_path_segment(CoordinateField::Artifact, artifact_id)?;
    validate_path_segment(CoordinateField::Version, version)?;
    let dir = confined_dir(
        m2_path,
        m2_path.join(group_path).join(artifact_id).join(version),
    )?;
    for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let id = name
            .to_str()
            .and_then(|name| name.strip_prefix("maven-metadata-")?.strip_suffix(".xml"));
        if id.is_some_and(|id| !keep.contains(id)) {
            remove_metadata_file(&dir.join(name))?;
        }
    }
    Ok(())
}

/// Remove a metadata file and its checksums, if present.
fn remove_metadata_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    remove_checksums(path)
}

fn remove_checksums(path: &Path) -> Result<()> {
    let path = path.as_os_str().to_string_lossy();
    for extension in ["md5", "sha1", "sha256", "sha512"] {
        match fs::remove_file(format!("{path}.{extension}")) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
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
fn safe_artifact_path(options: &ExportOptions, key: &ArtifactCoord) -> Result<PathBuf> {
    let dest = options.m2_path.join(artifact_relative_path(key)?);
    // The directories decide where the file lands. The file itself may be a
    // link into the store that an earlier `--link symlink` export left,
    // which the export replaces or keeps but never writes through.
    let dir = dest.parent().unwrap_or(&dest);
    if !is_confined(&options.m2_path, dir)? {
        return Err(ExportError::PathTraversal(dest));
    }

    // `safe_artifact_path` is path math only. `export_artifact_blocking`
    // is the single caller responsible for actually creating the artifact
    // parent directory (and only when we're about to write into it), so
    // doing it here too just duplicates a syscall per artifact.

    Ok(dest)
}

/// Whether `dir`, after the links that exist on its way, stays below
/// `m2_path`.
fn is_confined(m2_path: &Path, dir: &Path) -> Result<bool> {
    let m2 = lexical_normalize(&rv_fs::canonicalize_existing_prefix(m2_path)?);
    let dir = lexical_normalize(&rv_fs::canonicalize_existing_prefix(dir)?);
    Ok(dir.starts_with(&m2))
}

/// `dir`, a metadata directory below `m2_path`, refused like an artifact
/// path when a link on its way leads out of the local repository.
fn confined_dir(m2_path: &Path, dir: PathBuf) -> Result<PathBuf> {
    if is_confined(m2_path, &dir)? {
        Ok(dir)
    } else {
        Err(ExportError::PathTraversal(dir))
    }
}

/// The artifact's path below the local repository root, after rejecting
/// coordinate fields that could escape it or alias another file, with the
/// rule raeva.lock is read with.
fn artifact_relative_path(key: &ArtifactCoord) -> Result<PathBuf> {
    let fields = [
        (CoordinateField::Group, key.group_id()),
        (CoordinateField::Artifact, key.artifact_id()),
        (CoordinateField::Version, key.version()),
        (CoordinateField::Extension, key.extension()),
    ];
    let classifier = key
        .classifier()
        .map(|classifier| (CoordinateField::Classifier, classifier));
    for (field, value) in fields.into_iter().chain(classifier) {
        validate_coordinate_component(field, value).map_err(|err| {
            ExportError::InvalidCoordinate(format!(
                "{:?}:{:?}:{:?} ({err})",
                key.group_id(),
                key.artifact_id(),
                key.version()
            ))
        })?;
    }

    // Snapshots: directory uses the base `-SNAPSHOT` version while the
    // filename keeps the timestamped form. Releases use the version
    // verbatim for both.
    let dir_version = rv_maven_types::snapshot_base_version(key.version())
        .unwrap_or_else(|| key.version().to_string());
    validate_path_segment(CoordinateField::Version, &dir_version)?;

    let relative = PathBuf::from(layout::artifact_path_from_parts(
        key.group_id(),
        key.artifact_id(),
        &dir_version,
        key.version(),
        key.extension(),
        key.classifier(),
    ));
    reject_windows_hostile_names(key, &relative)?;
    Ok(relative)
}

/// Refuse a path with a segment Windows would rewrite, redirect or alias.
///
/// A segment that is a DOS device name (`con`, `nul.jar`), ends in a dot or
/// space, holds a reserved character or is over 255 UTF-16 units cannot be
/// stored as written on NTFS or FAT, and Win32 resolves some of them to a
/// device instead of a file. A segment shaped like an 8.3 short name
/// (`LONGAR~1`) can name another file of its directory on a volume that
/// generates short names. Both rules apply on every platform and to every
/// destination: the destination volume cannot be told reliably, and a
/// repository written here is routinely read on Windows later (a mounted or
/// copied `~/.m2`). The cost is that a coordinate with such a segment cannot
/// be exported anywhere, which Maven itself cannot do on Windows either.
fn reject_windows_hostile_names(key: &ArtifactCoord, relative: &Path) -> Result<()> {
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        if !rv_fs::plain_name_is_safe(name) {
            return Err(ExportError::WindowsUnsafeName {
                coordinate: key.to_string(),
                name: name.to_string_lossy().into_owned(),
            });
        }
        if name.to_str().is_some_and(rv_fs::is_short_name_alias) {
            return Err(ExportError::ShortNameAlias {
                coordinate: key.to_string(),
                name: name.to_string_lossy().into_owned(),
            });
        }
    }
    Ok(())
}

/// Refuse two units whose files, or artifact and version directories, differ
/// only in letter case when the local repository's file system folds case,
/// as APFS and NTFS do by default: both would be written to one file,
/// leaving one coordinate holding the other's bytes while the export reports
/// success. Directories count because Maven metadata is written per artifact
/// directory; group directories hold no files of their own, so `org.Acme:a`
/// and `org.acme:b` can share one. Every path segment is printable ASCII by
/// the coordinate rule, so ASCII case is the whole comparison.
fn reject_case_folded_collisions(options: &ExportOptions, units: &[ExportUnit]) -> Result<()> {
    let Some((first, second, relative)) = case_folded_collision(units)? else {
        return Ok(());
    };
    let root = options
        .m2_path
        .ancestors()
        .find(|ancestor| ancestor.is_dir())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let folds = if options.dry_run {
        folds_case_without_writing(&root)
    } else {
        folds_case(&root)?
    };
    if !folds {
        return Ok(());
    }
    Err(ExportError::CaseCollision {
        first,
        second,
        path: options.m2_path.join(relative),
    })
}

/// The first two units, by coordinate, whose files or artifact or version
/// directories differ only in letter case, and the colliding relative path.
fn case_folded_collision(units: &[ExportUnit]) -> Result<Option<(String, String, PathBuf)>> {
    let mut seen: HashMap<String, (PathBuf, &ExportUnit)> = HashMap::new();
    for unit in units {
        let relative = artifact_relative_path(&unit.key)?;
        let group_depth = unit.key.group_id().split('.').count();
        let mut prefix = PathBuf::new();
        for (depth, component) in relative.components().enumerate() {
            prefix.push(component);
            if depth < group_depth {
                continue;
            }
            let caseless = prefix.to_string_lossy().to_ascii_lowercase();
            match seen.get(&caseless) {
                None => {
                    seen.insert(caseless, (prefix.clone(), unit));
                }
                Some((existing, first)) if *existing != prefix => {
                    return Ok(Some((first.key.to_string(), unit.key.to_string(), prefix)));
                }
                Some(_) => {}
            }
        }
    }
    Ok(None)
}

/// Whether `dir` resolves a name that differs from an existing entry only in
/// letter case to that entry.
fn folds_case(dir: &Path) -> Result<bool> {
    let probe = tempfile::Builder::new()
        .prefix(".raeva-case-probe-")
        .tempfile_in(dir)?;
    let Some(name) = probe.path().file_name().and_then(|name| name.to_str()) else {
        return Ok(false);
    };
    let upper = probe.path().with_file_name(name.to_uppercase());
    Ok(fs::symlink_metadata(upper).is_ok())
}

/// [`folds_case`] for a dry run, which must not write: look up an entry of
/// `dir` with its ASCII letter case swapped. Other letters are left alone,
/// since swapping them one by one need not give an equivalent name (`ß`
/// uppercases to `SS`). `dir` itself is not tried, since its parent,
/// possibly another file system, decides that lookup. Without an entry to
/// try, the answer is unknown and counts as folding, so the collision is
/// reported.
fn folds_case_without_writing(dir: &Path) -> bool {
    let dir = dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let entries = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path());
    for path in entries {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let swapped: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        if swapped == name {
            continue;
        }
        return same_file(&path, &path.with_file_name(swapped));
    }
    true
}

/// Whether two existing paths name one file. A case-sensitive volume can
/// hold `Repo` and `rEPO` side by side.
fn same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (fs::symlink_metadata(a), fs::symlink_metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        // Canonical paths carry the name as stored, whatever case was asked.
        match (dunce::canonicalize(a), dunce::canonicalize(b)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
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

/// The digests of the regular file at `path`, through a link. Anything
/// else, such as a device, fails rather than being read without end.
fn hash_file(path: &Path) -> Result<(String, String)> {
    use std::io::Read;
    if !fs::metadata(path)?.is_file() {
        return Err(std::io::Error::other("not a regular file").into());
    }
    let mut file = fs::File::open(path).map_err(ExportError::IoError)?;
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
    let sha1_bytes: [u8; 20] = sha1.finalize().into();
    Ok((hex::encode(sha256_bytes), hex::encode(sha1_bytes)))
}

/// Re-hash the source blob and compare against the recorded `BlobId` so an
/// on-disk tampered file cannot make it into the user's `.m2`. Returns the
/// SHA-1 for the sidecar.
fn verify_and_hash(src: &Path, blob_id: &BlobId) -> Result<String> {
    let (sha256_hex, sha1_hex) = hash_file(src)?;
    if sha256_hex != blob_id.as_str() {
        return Err(ExportError::CorruptBlob {
            path: src.to_path_buf(),
            actual: sha256_hex,
            expected: blob_id.to_string(),
        });
    }
    Ok(sha1_hex)
}

/// What the destination of one file holds before the export writes it.
enum Existing {
    Absent,
    UpToDate {
        sha1: String,
    },
    /// Nothing worth keeping: a link into the store where a copy was asked
    /// for, or a link whose target is gone.
    Replace,
    /// Other bytes, with their SHA-256 for the error.
    Differs {
        actual: String,
    },
}

/// Look at `dest` without writing anything. A file that shares the store
/// blob's inode, a hard link or a link to it, is checked by hashing the
/// blob, which verifies the store too; a separate file is hashed itself.
/// A shared file is not read when an earlier export left it, its sidecars
/// name the blob, and the store's checked stamp shows no write to the blob
/// since it last hashed right.
fn existing_file(
    store: &Store,
    src: &Path,
    dest: &Path,
    blob_id: &BlobId,
    strategy: LinkStrategy,
) -> Result<Existing> {
    let linked = match fs::symlink_metadata(dest) {
        Ok(linked) => linked,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Existing::Absent),
        Err(err) => return Err(ExportError::IoError(err)),
    };
    let is_link = linked.file_type().is_symlink();
    if fs::metadata(dest).is_err() {
        return Ok(if is_link {
            Existing::Replace
        } else {
            Existing::Differs {
                actual: "<unreadable>".to_string(),
            }
        });
    }
    let same_target = match (dunce::canonicalize(src), dunce::canonicalize(dest)) {
        (Ok(src), Ok(dest)) => src == dest,
        _ => false,
    };
    let shares_blob =
        same_file::is_same_file(src, dest).unwrap_or(false) || (is_link && same_target);
    if shares_blob {
        if strategy == LinkStrategy::Copy {
            return Ok(Existing::Replace);
        }
        let pin = Digest::Sha256(blob_id.clone());
        if matches!(
            store.check_pin_unless_unchanged(blob_id, &pin),
            Ok(PinCheck::Match)
        ) && let Some(sha1) = exported_sha1(dest, blob_id)
        {
            return Ok(Existing::UpToDate { sha1 });
        }
        let sha1 = verify_and_hash(src, blob_id)?;
        return Ok(Existing::UpToDate { sha1 });
    }
    let (sha256, sha1) = match hash_file(dest) {
        Ok(digests) => digests,
        Err(_) => {
            return Ok(Existing::Differs {
                actual: "<unreadable>".to_string(),
            });
        }
    };
    if sha256 != blob_id.as_str() {
        return Ok(Existing::Differs { actual: sha256 });
    }
    // Symlinks that share the store blob returned above. Any other symlink
    // still hashes through its target, so matching bytes here can point at a
    // foreign path. A hard link to a foreign path is the same threat: another
    // name for this inode can change what `mvn -o` reads without touching the
    // store. Replace both. A separate file that only happens to match the
    // digest stays; it does not share an inode with anything else.
    if is_link || has_other_names(dest, &linked) {
        return Ok(Existing::Replace);
    }
    Ok(Existing::UpToDate { sha1 })
}

/// Whether another directory entry names the file at `path`, whose
/// metadata is `meta`. False when the platform reports no link count.
fn has_other_names(path: &Path, meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        meta.nlink() > 1
    }
    // std's `number_of_links` is unstable; winapi-util reads the same
    // `GetFileInformationByHandle` field. A failed query, as some network
    // file systems give, counts as shared so the file is rewritten.
    #[cfg(windows)]
    {
        let _ = meta;
        fs::File::open(path)
            .and_then(|file| winapi_util::file::information(&file))
            .map_or(true, |info| info.number_of_links() > 1)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, meta);
        false
    }
}

/// The SHA-1 the sidecars an export wrote next to `dest` give, when its
/// `.sha256` names `blob_id`.
fn exported_sha1(dest: &Path, blob_id: &BlobId) -> Option<String> {
    let sidecar = |extension: &str| {
        let path = format!("{}.{extension}", dest.as_os_str().to_string_lossy());
        crate::metadata::read_regular_text(Path::new(&path)).map(|text| text.trim().to_string())
    };
    if sidecar("sha256")? != blob_id.as_str() {
        return None;
    }
    let sha1 = sidecar("sha1")?;
    (sha1.len() == 40 && sha1.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(sha1)
}

/// Settle a destination the export does not have to write: skip one that
/// is up to date, refuse other bytes without `--overwrite`. `None` means
/// write it.
fn settle_existing(
    existing: Existing,
    dest: &Path,
    options: &ExportOptions,
    key_str: &str,
    blob_id: &BlobId,
) -> Result<Option<ExportOutcome>> {
    match existing {
        Existing::Absent | Existing::Replace => Ok(None),
        Existing::UpToDate { sha1 } => {
            ensure_sidecars(dest, blob_id, &sha1)?;
            Ok(Some(ExportOutcome::Skipped))
        }
        Existing::Differs { .. } if options.overwrite => Ok(None),
        Existing::Differs { actual } => Err(ExportError::DestinationMismatch {
            key: key_str.to_string(),
            path: dest.to_path_buf(),
            expected: blob_id.as_str().to_string(),
            actual,
        }),
    }
}

/// Standalone blocking function for exporting a single artifact.
/// Called from spawn_blocking to avoid blocking the async runtime. Verifies
/// blob integrity before linking/copying, and skips filesystem mutations
/// when `dry_run` is set.
fn export_artifact_blocking(
    store: &Store,
    src: &Path,
    dest: &Path,
    options: &ExportOptions,
    key_str: &str,
    blob_id: &BlobId,
) -> Result<(ExportOutcome, Option<ExportWarning>)> {
    // Check src existence here for a useful error, but the link attempt
    // itself is the authoritative check; if src disappears between here and
    // the link we get a clear OS error rather than a panic or silent bad link.
    if !src.is_file() {
        return Err(ExportError::MissingBlob {
            key: key_str.to_string(),
        });
    }

    // In dry_run mode, skip all filesystem mutations entirely. We still
    // accept the call for any source that exists.
    if options.dry_run {
        return Ok((ExportOutcome::Exported(options.link_strategy), None));
    }

    // A repeated export finds most files in place, so look before staging:
    // a staged copy costs a full read and a sync even when it is thrown away.
    let existing = existing_file(store, src, dest, blob_id, options.link_strategy)?;
    let was_absent = matches!(existing, Existing::Absent);
    if let Some(outcome) = settle_existing(existing, dest, options, key_str, blob_id)? {
        return Ok((outcome, None));
    }

    let sha1_hex = verify_and_hash(src, blob_id)?;

    let Some(parent) = dest.parent() else {
        return Err(ExportError::IoError(std::io::Error::other(
            "missing parent directory for artifact path",
        )));
    };
    fs::create_dir_all(parent)?;

    // Stage the link at a unique path in the same directory, so the final
    // rename is atomic. The link helpers create the file themselves, so the
    // reserved name is emptied first; the guard removes it on any failure.
    let temp_path = tempfile::NamedTempFile::new_in(parent)?.into_temp_path();
    let _ = fs::remove_file(&temp_path);
    let missing = || ExportError::MissingBlob {
        key: key_str.to_string(),
    };
    let used_strategy =
        link_with_fallback(src, &temp_path, options.link_strategy).map_err(|e| match e {
            LinkError::SourceMissing { .. } => missing(),
            LinkError::IoError { ref source, .. }
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                missing()
            }
            e => e.into(),
        })?;

    // A file that appeared while the link was staged, such as one another
    // export wrote, is judged like one that was there before.
    if was_absent {
        let existing = existing_file(store, src, dest, blob_id, options.link_strategy)?;
        if let Some(outcome) = settle_existing(existing, dest, options, key_str, blob_id)? {
            return Ok((outcome, None));
        }
    }

    // Normalise perms on the staged tempfile (Copy only). The file came out
    // of the CAS as a read-only 0o444 blob, but Maven's offline resolver
    // (and plugins like the shade/assembly steps that rewrite artifacts in
    // place) expect a writable-by-owner 0o644 file in the local repository.
    // Hardlink destinations share the CAS inode, so we must NOT chmod them
    // here (that would strip write bits from the shared blob), and symlinks
    // have no meaningful perms of their own.
    let mut permissions_warning = None;
    if let LinkStrategy::Copy = used_strategy
        && let Err(e) = set_artifact_perms(&temp_path)
    {
        permissions_warning = Some(ExportWarning::PermissionsNotSet {
            path: dest.to_path_buf(),
            reason: e.to_string(),
        });
    }

    // Publish the sidecars before the artifact, so a crash never leaves a new
    // artifact visible without its checksums next to it.
    let dest_str = dest.as_os_str().to_string_lossy();
    write_sidecar_atomic(Path::new(&format!("{dest_str}.sha256")), blob_id.as_str())?;
    write_sidecar_atomic(Path::new(&format!("{dest_str}.sha1")), &sha1_hex)?;
    // `rename` replaces a file or symlink, not a directory. `--overwrite`
    // already chose to discard whatever occupied the path; clear a directory
    // so the staged artifact can land.
    if options.overwrite && fs::symlink_metadata(dest).is_ok_and(|meta| meta.file_type().is_dir()) {
        fs::remove_dir_all(dest).map_err(ExportError::IoError)?;
    }
    // No directory sync: an entry a crash loses is written again by the
    // next export.
    temp_path
        .persist(dest)
        .map_err(|e| ExportError::IoError(e.error))?;

    Ok((ExportOutcome::Exported(used_strategy), permissions_warning))
}

/// How long an export waits for another one into the same local
/// repository, as long as the store and `raeva.lock` locks wait.
const EXPORT_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Hold `.raeva-export.lock` in `m2`, creating both, until the file drops.
/// A holder that keeps it past `timeout` fails the export instead of
/// hanging it.
async fn lock_destination(m2: &Path, timeout: std::time::Duration) -> Result<fs::File> {
    let path = m2.join(".raeva-export.lock");
    let m2 = m2.to_path_buf();
    // What the destination itself causes; disk full and the like stay I/O
    // errors.
    let unusable = move |source: std::io::Error| {
        use std::io::ErrorKind::*;
        match source.kind() {
            PermissionDenied | NotFound | AlreadyExists | NotADirectory | IsADirectory
            | ReadOnlyFilesystem => ExportError::Destination {
                path: m2.clone(),
                source,
            },
            _ => ExportError::IoError(source),
        }
    };
    tokio::task::spawn_blocking(move || {
        fs::create_dir_all(path.parent().unwrap_or(&path)).map_err(&unusable)?;
        // A link would create or lock a file wherever it points, and
        // opening a FIFO waits for a reader past any deadline.
        if fs::symlink_metadata(&path).is_ok_and(|meta| !meta.is_file()) {
            return Err(ExportError::IoError(std::io::Error::other(format!(
                "{} is not a regular file; remove it",
                path.display()
            ))));
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(&unusable)?;
        match rv_fs::lock_exclusive_until(&mut file, std::time::Instant::now() + timeout) {
            Ok(()) => Ok(file),
            Err(fs::TryLockError::WouldBlock) => Err(ExportError::IoError(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "timed out after {timeout:?} waiting for {}; another export into this \
                     local repository holds it",
                    path.display()
                ),
            ))),
            Err(fs::TryLockError::Error(err)) => Err(err.into()),
        }
    })
    .await
    .map_err(|err| ExportError::IoError(std::io::Error::other(err)))?
}

/// Write a single sidecar file so observers never see partial content.
fn write_sidecar_atomic(path: &Path, content: &str) -> Result<()> {
    crate::metadata::replace_file(path, content.as_bytes())?;
    Ok(())
}

/// Make sure the `.sha256` and `.sha1` sidecars next to `dest` exist and hold
/// the expected digests. Repairs missing or stale sidecars in-place.
fn ensure_sidecars(dest: &Path, blob_id: &BlobId, sha1_hex: &str) -> Result<()> {
    let dest_str = dest.as_os_str().to_string_lossy();
    for (extension, digest) in [("sha256", blob_id.as_str()), ("sha1", sha1_hex)] {
        let path = PathBuf::from(format!("{dest_str}.{extension}"));
        if crate::metadata::read_regular_text(&path).is_none_or(|s| s.trim() != digest) {
            write_sidecar_atomic(&path, digest)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ExportOutcome {
    Exported(LinkStrategy),
    Skipped,
}

impl ExportStats {
    fn record(&mut self, outcome: ExportOutcome) {
        match outcome {
            ExportOutcome::Exported(LinkStrategy::Copy) => self.copied_count += 1,
            ExportOutcome::Exported(_) => self.linked_count += 1,
            ExportOutcome::Skipped => self.skipped_count += 1,
        }
        if let ExportOutcome::Exported(_) = outcome {
            self.exported_count += 1;
        }
    }
}

/// Compare the indexed blob for `key` against the lockfile pin. The indexed
/// blob is whatever Project A's `sync` populated into the shared store; if
/// the current project's lockfile pins something else, we must refuse the
/// export instead of shipping the wrong bytes.
///
/// A SHA-256 pin is compared with the indexed `BlobId`, which is the
/// SHA-256; `verify_and_hash` re-hashes the file when it is copied. A SHA-1
/// pin needs the file re-hashed here.
async fn verify_pin_against_blob(
    store: &Store,
    key: &ArtifactCoord,
    indexed: &BlobId,
    pin: &Digest,
) -> Result<()> {
    let (algorithm, actual) = match pin {
        Digest::Sha256(expected) if expected == indexed => return Ok(()),
        Digest::Sha256(_) => ("sha256", indexed.to_string()),
        Digest::Sha1(_) | Digest::Md5(_) => match store.check_pin_async(indexed, pin).await? {
            PinCheck::Match => return Ok(()),
            PinCheck::Mismatch { actual } => (pin.algorithm().as_str(), actual),
            PinCheck::Missing => {
                return Err(ExportError::MissingBlob {
                    key: key.to_string(),
                });
            }
        },
    };
    Err(ExportError::PinMismatch {
        key: key.to_string(),
        algorithm: algorithm.to_string(),
        expected: pin.hex().to_string(),
        actual,
    })
}

fn validate_path_segment(field: CoordinateField, value: &str) -> Result<()> {
    validate_coordinate_component(field, value)
        .map_err(|err| ExportError::InvalidCoordinate(err.to_string()))
}

fn validate_group_path(group_id: &str) -> Result<String> {
    validate_path_segment(CoordinateField::Group, group_id)?;
    Ok(group_id.replace('.', "/"))
}

/// Split a support-POM coordinate from the lockfile into owned parts.
fn parse_gav(coord: &str) -> Option<(String, String, String)> {
    rv_lock::split_support_pom_coord(coord).map(|(group, artifact, version)| {
        (group.to_string(), artifact.to_string(), version.to_string())
    })
}

/// The literal `<parent>` coordinates of the POM at `path`. A POM that
/// cannot be read or parsed has none, which ends that branch of the walk
/// rather than failing the export. A parent whose GAV still contains
/// `${...}` is skipped: Maven never fetches that text, and `raeva sync`
/// records the interpolated coordinates instead.
fn read_support_parent(path: &Path) -> Option<(String, String, String)> {
    pom_parent(&fs::read(path).ok()?)
}

/// The `<parent>` of the stored POM `blob` holds. Bytes that are not the
/// blob's have none: the export of the POM itself reports the damage.
fn stored_parent(bytes: &[u8], blob: &BlobId) -> Option<(String, String, String)> {
    (BlobId::from_bytes(bytes) == *blob)
        .then(|| pom_parent(bytes))
        .flatten()
}

fn pom_parent(bytes: &[u8]) -> Option<(String, String, String)> {
    let text = rv_maven_model::decode_pom(bytes).ok()?;
    let pom = rv_maven_model::Pom::parse(&text).ok()?;
    let parent = pom.parent?;
    if parent.group_id.is_empty()
        || parent.artifact_id.is_empty()
        || parent.version.is_empty()
        || rv_maven_model::parent_has_expression(&parent)
    {
        return None;
    }
    Some((parent.group_id, parent.artifact_id, parent.version))
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
#[cfg_attr(not(unix), allow(clippy::permissions_set_readonly_false))]
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
