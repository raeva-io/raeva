use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use chrono::DateTime;
use clap::{Args, Subcommand};
use futures::stream::{self, StreamExt};

use rv_config::{
    Checksum, Config, LOCKFILE_SCHEMA_VERSION, LockCoordinate, LockPackage, Lockfile,
    normalize_checksum_algorithm,
};
use rv_repo::{ArtifactRequest, RepoClient, Repository, normalize_repo_url, sha1_hex_file};
use rv_store::{ArtifactKey, BlobId, Store};

use crate::commands::module_selector::ModuleSelector;
use crate::commands::{path_to_forward_slashes, read_lockfile};
use crate::error::{CliError, Result};
use crate::output::{
    ProgressReporter, Spinner, Table, heading, is_json_mode, json_result, quiet_enabled, success,
    warning,
};

#[derive(Debug, Args)]
#[command(about = "Inspect and verify lockfile artifacts")]
pub struct LockArgs {
    #[command(subcommand)]
    pub command: LockCommand,
}

#[derive(Debug, Subcommand)]
pub enum LockCommand {
    /// Verify that artifacts in rv.lock exist in the store
    Verify(LockVerifyArgs),
    /// Show lockfile metadata and statistics
    Info,
}

#[derive(Debug, Args)]
pub struct LockVerifyArgs {
    /// Re-download missing or corrupted blobs
    #[arg(long)]
    pub download: bool,

    #[command(flatten)]
    pub(crate) module: ModuleSelector,
}

pub async fn run(args: &LockArgs, project_root: &Path) -> Result<()> {
    match &args.command {
        LockCommand::Verify(verify_args) => verify(verify_args, project_root).await,
        LockCommand::Info => lock_info(project_root),
    }
}

fn lock_info(project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;

    // Route through the shared `read_lockfile` helper so a non-file at the
    // lockfile path (a directory, FIFO, etc.) reports the precise
    // `LockfileNotAFile` diagnostic instead of the bespoke `is_file()` check
    // that collapsed every non-regular-file case into "missing".
    let lock = read_lockfile(&config)?;
    let metadata = fs::metadata(&config.lock_path)?;
    // `as i64` wraps past year 2554; fall back to "unknown" instead.
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .and_then(|secs| DateTime::from_timestamp(secs, 0))
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let platform_count = lock.platforms.len();
    let mut total_packages = 0usize;
    let mut unique_coords: HashSet<String> = HashSet::new();

    for platform in &lock.platforms {
        total_packages += platform
            .modules
            .iter()
            .map(|module| module.packages.len())
            .sum::<usize>();
        for artifact in &platform.artifacts {
            unique_coords.insert(artifact.coordinate.format_coord());
        }
    }

    if is_json_mode() {
        let platforms: Vec<_> = lock
            .platforms
            .iter()
            .map(|p| {
                serde_json::json!({
                    "platform": p.platform.to_string(),
                    "packages": p.modules.iter().map(|module| module.packages.len()).sum::<usize>(),
                    "modules": p.modules.len(),
                    "external_artifacts": p.artifacts.len(),
                })
            })
            .collect();
        json_result(
            true,
            serde_json::json!({
                "path": path_to_forward_slashes(&config.lock_path),
                "schema_version": lock.schema_version,
                "latest_schema_version": LOCKFILE_SCHEMA_VERSION,
                "last_modified": modified,
                "platform_count": platform_count,
                "total_packages": total_packages,
                "unique_artifacts": unique_coords.len(),
                "platforms": platforms,
            }),
        );
        return Ok(());
    }

    // Heading is decorative chatter -> stderr; the table is the structured
    // human payload -> stdout.
    if !quiet_enabled() {
        eprintln!("{}", heading("Lockfile info"));
    }

    let mut table = Table::new(["Property", "Value"]);
    table.add_row(["Path", &config.lock_path.display().to_string()]);
    table.add_row(["Schema version", &lock.schema_version.to_string()]);
    table.add_row([
        "Latest schema version",
        &LOCKFILE_SCHEMA_VERSION.to_string(),
    ]);
    table.add_row(["Last modified", &modified]);
    table.add_row(["Platforms", &platform_count.to_string()]);

    table.add_row(["Total packages", &total_packages.to_string()]);
    table.add_row(["Unique artifacts", &unique_coords.len().to_string()]);

    if !lock.platforms.is_empty() {
        table.add_row(["", ""]);
        table.add_row(["Platform breakdown", ""]);
        for platform in &lock.platforms {
            let key = format!("  {}", platform.platform);
            let packages = platform
                .modules
                .iter()
                .map(|module| module.packages.len())
                .sum::<usize>();
            let value = format!(
                "{} packages, {} modules, {} external artifacts",
                packages,
                platform.modules.len(),
                platform.artifacts.len()
            );
            table.add_row([&key, &value]);
        }
    }

    println!("{}", table.render());
    Ok(())
}

async fn verify(args: &LockVerifyArgs, project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;
    verify_inner(args, &config).await?;
    Ok(())
}

async fn verify_inner(args: &LockVerifyArgs, config: &Config) -> Result<()> {
    let lock = read_lockfile(config)?;
    // Open the store once into an Arc and share that single Arc
    // through both the verification fan-out and the optional download
    // fan-out. Re-cloning the underlying `Store` into two distinct
    // `Arc<Store>` containers would defeat the Arc (each worker would
    // still hold its own clone of the inner state).
    let store: Arc<Store> = Arc::new(Store::open(&config.paths.store_dir)?);

    // Each `verify_blob` is a SHA-256 over the on-disk blob, a synchronous
    // CPU+IO call. Doing them sequentially burns multi-seconds on real
    // lockfiles. Fan them out across spawn_blocking workers, capped by the
    // user's configured network concurrency (with a sane floor) so a small
    // setting still gets some parallelism.
    let parallelism = config.network.concurrency.max(4);

    // Pre-compute the per-package verification inputs so the parallel stage
    // is pure work, with no Config / Lockfile access needed.
    //
    // The lockfile parser accepts both `sha256` and `sha1` pins. By default
    // `rv sync` verifies against the sha256 sidecar when the repository
    // publishes one and otherwise falls back to the sha1 sidecar (emitting
    // the WEAK_HASH_FALLBACK warning), so a lockfile produced against a
    // SHA-1-only repository legitimately carries SHA-1 pins. Verify must
    // accept the same set or it falsely rejects those lockfiles.
    let prepared = prepare_targets(&lock, &args.module)?;
    let workspace_skipped = prepared.workspace_skipped;
    let no_checksum = prepared.no_checksum;

    let results: Vec<Result<(PreparedTarget, VerifyStatus)>> =
        stream::iter(prepared.targets.into_iter())
            .map(|target| {
                // Share the single Arc opened above instead of
                // building a fresh `Arc<Store>` wrapping yet another
                // inner clone.
                let store = Arc::clone(&store);
                async move {
                    // For SHA-1 pins the on-disk lookup needs the
                    // async index API; resolve the BlobId here, then let
                    // the blocking task focus on the hash pass.
                    let resolved_blob = match &target.expected {
                        ExpectedPin::Sha256(id) => Some(id.clone()),
                        ExpectedPin::Sha1(_) => store.lookup_artifact(&target.key).await?,
                    };
                    let expected_for_task = target.expected.clone();
                    let status = tokio::task::spawn_blocking(move || {
                        verify_pin(&store, resolved_blob.as_ref(), &expected_for_task)
                    })
                    .await
                    .map_err(|e| CliError::Message(format!("verify task panicked: {e}")))??;
                    Ok((target, status))
                }
            })
            .buffer_unordered(parallelism)
            .collect()
            .await;

    let mut verified = 0usize;
    let mut missing = Vec::new();
    let mut corrupt = Vec::new();
    for entry in results {
        let (target, status) = entry?;
        match status {
            VerifyStatus::Ok => {
                verified = verified.saturating_add(1);
            }
            VerifyStatus::Missing => missing.push(VerifyTarget {
                target,
                actual: None,
            }),
            VerifyStatus::Corrupt { actual } => corrupt.push(VerifyTarget {
                target,
                actual: Some(actual),
            }),
        }
    }

    let mut downloaded = 0usize;
    let mut untrusted_origin: Vec<VerifyTarget> = Vec::new();
    let mut pin_mismatch: Vec<VerifyTarget> = Vec::new();
    if args.download && (!missing.is_empty() || !corrupt.is_empty()) {
        let mut targets = Vec::new();
        targets.append(&mut missing);
        targets.append(&mut corrupt);

        // Pre-resolve the repository for each target before the fan-out so
        // the parallel task body only needs &self captures (Config is not
        // Clone, and pinning it inside an Arc would require threading it
        // through everything).
        //
        // Resolution is also the trust gate, and it runs ahead of every
        // other step — before the HTTP client is even built: an artifact
        // whose recorded origin is not declared in `rv.toml` never gets
        // contacted at all, it becomes a finding. That is the same refusal
        // `rv sync` raises as `RepoError::UntrustedRepoUrl`, downgraded from
        // a hard error to a per-artifact finding so the rest of the batch is
        // still repaired.
        let mut dispatch: Vec<(VerifyTarget, Repository)> = Vec::new();
        for target in targets {
            match repository_for_package(config, &target.target.package) {
                Some(repo) => dispatch.push((target, repo)),
                None => untrusted_origin.push(target),
            }
        }

        if !dispatch.is_empty() {
            let progress = std::sync::Arc::new(ProgressReporter::new());
            let client = RepoClient::new(config).await?.with_progress(progress);

            let spinner = Spinner::start("lock verify: downloading artifacts");
            let client = Arc::new(client);
            // Keep using the single Arc<Store> from verify_inner.
            let store_arc = Arc::clone(&store);
            // Fan downloads out the same way verification did: each fetch is
            // independent and bottlenecked on the network, so a sequential
            // await chain would leave bandwidth on the floor.
            let download_results: Vec<Result<(VerifyTarget, DownloadOutcome)>> =
                stream::iter(dispatch.into_iter())
                    .map(|(target, repo)| {
                        let client = Arc::clone(&client);
                        let store = Arc::clone(&store_arc);
                        async move {
                            let outcome =
                                download_and_verify(&client, &store, &repo, &target.target).await?;
                            Ok((target, outcome))
                        }
                    })
                    .buffer_unordered(parallelism)
                    .collect()
                    .await;
            for result in download_results {
                let (target, outcome) = result?;
                match outcome {
                    DownloadOutcome::Repaired => downloaded = downloaded.saturating_add(1),
                    DownloadOutcome::PinMismatch { actual } => pin_mismatch.push(VerifyTarget {
                        target: target.target,
                        actual: Some(actual),
                    }),
                }
            }
            spinner.finish(success("done"));
            verified += downloaded;
        }
    }

    if missing.is_empty()
        && corrupt.is_empty()
        && no_checksum.is_empty()
        && untrusted_origin.is_empty()
        && pin_mismatch.is_empty()
    {
        if is_json_mode() {
            json_result(
                true,
                serde_json::json!({
                    "verified": verified,
                    "missing": 0,
                    "corrupt": 0,
                    "no_checksum": 0,
                    "untrusted_origin": 0,
                    "pin_mismatch": 0,
                    "downloaded": downloaded,
                    "workspace_skipped": workspace_skipped.len(),
                    "workspace_entries": workspace_json(&workspace_skipped),
                }),
            );
        } else if downloaded > 0 {
            eprintln!("{}", success(format!("verified {} artifacts", verified)));
        } else if !quiet_enabled() {
            eprintln!("{}", success("lockfile verified"));
        }
        report_workspace_skips(&workspace_skipped);
        return Ok(());
    }

    let summary = failure_summary(&FailureCounts {
        missing: missing.len(),
        corrupt: corrupt.len(),
        no_checksum: no_checksum.len(),
        untrusted_origin: untrusted_origin.len(),
        pin_mismatch: pin_mismatch.len(),
    });
    if is_json_mode() {
        // Emit a structured failure envelope (matching the success-path
        // shape) so JSON consumers see the same `data.{verified,missing,
        // corrupt,no_checksum}` fields on a failed verify as on a passing
        // one. Then return `AlreadyReported` so the top-level handler exits
        // with `LOCKFILE_MISMATCH` without printing a second envelope.
        json_result(
            false,
            serde_json::json!({
                "verified": verified,
                "missing": missing.len(),
                "corrupt": corrupt.len(),
                "no_checksum": no_checksum.len(),
                "untrusted_origin": untrusted_origin.len(),
                "pin_mismatch": pin_mismatch.len(),
                "downloaded": downloaded,
                "workspace_skipped": workspace_skipped.len(),
                "workspace_entries": workspace_json(&workspace_skipped),
                "missing_artifacts": verify_targets_json(&missing),
                "corrupt_artifacts": verify_targets_json(&corrupt),
                "no_checksum_artifacts": unpinned_targets_json(&no_checksum),
                "untrusted_origin_artifacts": untrusted_origin_json(&untrusted_origin),
                "pin_mismatch_artifacts": verify_targets_json(&pin_mismatch),
                "exit_code": crate::error::ExitCodes::LOCKFILE_MISMATCH,
                "error": summary,
            }),
        );
        return Err(CliError::AlreadyReported {
            exit_code: crate::error::ExitCodes::LOCKFILE_MISMATCH,
        });
    }

    if !quiet_enabled() {
        eprintln!("{}", heading("Lock verification failed"));
        for target in &missing {
            eprintln!(
                "  {}",
                warning(format!(
                    "missing {} ({})",
                    target.target.key,
                    module_attribution(&target.target.modules)
                ))
            );
        }
        for target in &corrupt {
            if let Some(actual) = &target.actual {
                eprintln!(
                    "  {}",
                    warning(format!(
                        "corrupt {} (found {}; {})",
                        target.target.key,
                        actual,
                        module_attribution(&target.target.modules)
                    ))
                );
            } else {
                eprintln!(
                    "  {}",
                    warning(format!(
                        "corrupt {} ({})",
                        target.target.key,
                        module_attribution(&target.target.modules)
                    ))
                );
            }
        }
        for target in &no_checksum {
            eprintln!(
                "  {}",
                warning(format!(
                    "no checksum recorded for {} ({})",
                    target.key,
                    module_attribution(&target.modules)
                ))
            );
        }
        for target in &untrusted_origin {
            eprintln!(
                "  {}",
                warning(format!(
                    "untrusted origin {} recorded for {}; not downloaded \
                     (declare it under [[repositories]] in rv.toml; {})",
                    target.target.package.repo_url,
                    target.target.key,
                    module_attribution(&target.target.modules)
                ))
            );
        }
        for target in &pin_mismatch {
            eprintln!(
                "  {}",
                warning(format!(
                    "downloaded bytes for {} do not match the recorded checksum{}; \
                     discarded, store left unchanged ({})",
                    target.target.key,
                    target
                        .actual
                        .as_ref()
                        .map(|actual| format!(" (got {actual})"))
                        .unwrap_or_default(),
                    module_attribution(&target.target.modules)
                ))
            );
        }
    }
    report_workspace_skips(&workspace_skipped);
    Err(CliError::LockfileMismatch { details: summary })
}

#[derive(Debug, Default)]
struct FailureCounts {
    missing: usize,
    corrupt: usize,
    no_checksum: usize,
    untrusted_origin: usize,
    pin_mismatch: usize,
}

/// Human/JSON summary line for a failed verify. The trailing clauses are
/// only appended when present so the established "X missing, Y corrupt"
/// message stays stable for the common cases.
fn failure_summary(counts: &FailureCounts) -> String {
    let mut summary = format!("{} missing, {} corrupt", counts.missing, counts.corrupt);
    if counts.no_checksum > 0 {
        summary.push_str(&format!(
            ", {} with no checksum recorded",
            counts.no_checksum
        ));
    }
    if counts.untrusted_origin > 0 {
        summary.push_str(&format!(
            ", {} from an untrusted origin",
            counts.untrusted_origin
        ));
    }
    if counts.pin_mismatch > 0 {
        summary.push_str(&format!(
            ", {} whose download did not match the recorded checksum",
            counts.pin_mismatch
        ));
    }
    summary
}

/// Pre-compute the per-package verification inputs for the parallel stage.
///
/// Inputs come from the canonical schema-4 artifact table. Module graphs only
/// restrict that union and attach reachability diagnostics; workspace and
/// system nodes never become store lookups.
fn prepare_targets(lock: &Lockfile, selector: &ModuleSelector) -> Result<PreparedTargets> {
    let mut artifacts = BTreeMap::<LockCoordinate, ArtifactReachability>::new();
    let mut workspace_skipped = BTreeSet::new();

    for platform in &lock.platforms {
        let selection = selector.select(platform)?;
        let mut reachable = BTreeMap::<LockCoordinate, BTreeSet<String>>::new();
        for module in selection.modules() {
            for package in &module.packages {
                if let Some(workspace_module) = package.workspace_module.as_deref() {
                    workspace_skipped.insert(WorkspaceSkip {
                        module: module.path.clone(),
                        workspace_module: workspace_module.to_string(),
                        coordinate: package.coordinate.format_coord(),
                    });
                    continue;
                }
                if package.system_path.is_some() {
                    continue;
                }
                reachable
                    .entry(package.coordinate.clone())
                    .or_default()
                    .insert(module.path.clone());
            }
        }

        for artifact in &platform.artifacts {
            let Some(modules) = reachable.get(&artifact.coordinate) else {
                continue;
            };
            // `pom` packaging is verified like any other row. Only an explicit
            // `<type>pom</type>` dependency reaches the artifact table;
            // imported BOMs and parent POMs are support material with no row,
            // so they stay out of the verification set on their own.
            let package = artifact.as_package();
            match artifacts.entry(artifact.coordinate.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(ArtifactReachability {
                        package,
                        modules: modules.clone(),
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let existing = entry.get_mut();
                    if existing.package.checksum != package.checksum
                        || existing.package.snapshot_timestamp != package.snapshot_timestamp
                    {
                        return Err(CliError::LockfileMismatch {
                            details: format!(
                                "conflicting integrity records for {} across locked platforms",
                                artifact.coordinate.format_coord()
                            ),
                        });
                    }
                    existing.modules.extend(modules.iter().cloned());
                }
            }
        }
    }

    let mut targets = Vec::new();
    let mut no_checksum = Vec::new();
    for artifact in artifacts.into_values() {
        let key = artifact_key(&artifact.package);
        let modules = artifact.modules.into_iter().collect();
        let Some(checksum) = artifact.package.checksum.as_ref() else {
            no_checksum.push(UnpinnedTarget { key, modules });
            continue;
        };
        let expected = expected_pin(&key, checksum)?;
        targets.push(PreparedTarget {
            package: artifact.package,
            key,
            expected,
            modules,
        });
    }

    Ok(PreparedTargets {
        targets,
        no_checksum,
        workspace_skipped: workspace_skipped.into_iter().collect(),
    })
}

fn artifact_request(package: &LockPackage) -> ArtifactRequest {
    let request = ArtifactRequest::new(&package.group_id, &package.artifact_id, &package.version)
        .with_packaging(package.packaging.clone());
    if let Some(classifier) = &package.classifier {
        request.with_classifier(classifier.clone())
    } else {
        request
    }
}

fn artifact_key(package: &LockPackage) -> ArtifactKey {
    ArtifactKey::new(
        package.group_id.clone(),
        package.artifact_id.clone(),
        package.version.clone(),
        package.packaging.clone(),
        package.classifier.clone(),
    )
}

/// Resolve a lockfile `repo_url` against the configured `[[repositories]]`
/// and `[[mirrors]]`, returning `None` for an origin the current `rv.toml`
/// does not declare.
///
/// Same policy as `rv_repo::sync`'s own `repository_for_package`, which
/// refuses an unknown origin with `RepoError::UntrustedRepoUrl`: the
/// lockfile is not a trust root, so a tampered `rv.lock` must not be able to
/// redirect a download at an attacker-controlled repository. This used to
/// synthesize `Repository::new(None, wanted, ..)` for the no-match case,
/// which trusted the lockfile URL outright — the exact redirect `rv sync`
/// refuses.
///
/// The rv-repo resolver is private to `rv_repo::sync`; if it is exported,
/// call it here instead of restating the policy. (Its `trusted_repositories`
/// argument carries origins rediscovered by the current resolution pass,
/// which verify never runs, so verify's set is config + mirrors only.)
fn repository_for_package(config: &Config, package: &LockPackage) -> Option<Repository> {
    let wanted = normalize_repo_url(&package.repo_url);
    for repo in config.repositories() {
        if normalize_repo_url(&repo.url) == wanted {
            return Some(Repository::from(repo));
        }
    }
    for mirror in config.mirrors() {
        if normalize_repo_url(&mirror.url) == wanted {
            return Some(Repository::new(
                mirror.id.clone(),
                mirror.url.clone(),
                true,
                true,
            ));
        }
    }
    None
}

/// Fetch one artifact and check the downloaded bytes against the lockfile pin
/// *before* anything in the store points at them.
///
/// [`RepoClient::fetch_artifact_to_store`] lands the bytes in the
/// content-addressed store but writes no index row, so until the pin check
/// passes the blob is unrooted: the artifact key still resolves to exactly
/// what it resolved to before (the original blob, or nothing). Only a blob
/// that matches the pin is indexed. This used to call the atomic
/// `fetch_artifact_to_store_and_index`, which repointed the coordinate at the
/// fetched bytes *before* the comparison, so a failed pin check still left
/// the shared store redirected at whatever the origin served.
///
/// The two-step persist-then-index does reopen the GC window that
/// `Store::put_stream_and_index` closes: a concurrent `prune_blobs` can reap
/// the still-unrooted blob before `add_artifact` runs. That loss is
/// fail-safe — `add_artifact` refuses to index a blob whose file is gone,
/// and verify reports the artifact as unrepaired — whereas indexing first is
/// fail-open. An index that can never point at unverified bytes is worth the
/// rarer race.
///
/// Mismatched bytes are dropped in the only sense that is safe for a
/// content-addressed store: no row ever references them, so they are
/// unreachable through the artifact index and are reclaimed by the store's
/// blob GC. Unlinking the CAS file here would be wrong — the store dedups,
/// so that same digest may already be rooted by another coordinate.
async fn download_and_verify(
    client: &RepoClient,
    store: &Store,
    repo: &Repository,
    target: &PreparedTarget,
) -> Result<DownloadOutcome> {
    let request = artifact_request(&target.package);
    let blob = client
        .fetch_artifact_to_store(repo, &request, store)
        .await?;

    // Compare against the lockfile pin under whichever algorithm the
    // lockfile recorded. For SHA-256 the BlobId already *is* the digest.
    // For SHA-1 we re-hash the persisted blob (the store is SHA-256 keyed,
    // so there is no shortcut).
    match &target.expected {
        ExpectedPin::Sha256(expected) => {
            if &blob != expected {
                return Ok(DownloadOutcome::PinMismatch {
                    actual: blob.as_str().to_string(),
                });
            }
        }
        ExpectedPin::Sha1(expected) => {
            let path = store.get_path(&blob);
            let expected = expected.clone();
            let actual = tokio::task::spawn_blocking(move || sha1_hex_file(&path))
                .await
                .map_err(|e| CliError::Message(format!("sha1 verify task panicked: {e}")))??;
            if actual != expected {
                return Ok(DownloadOutcome::PinMismatch { actual });
            }
        }
    }

    store.add_artifact(&target.key, &blob).await?;
    Ok(DownloadOutcome::Repaired)
}

#[derive(Debug)]
enum DownloadOutcome {
    /// Bytes matched the pin and the coordinate now points at them.
    Repaired,
    /// Bytes did not match the pin; nothing was indexed.
    PinMismatch { actual: String },
}

#[derive(Debug)]
struct PreparedTargets {
    targets: Vec<PreparedTarget>,
    no_checksum: Vec<UnpinnedTarget>,
    workspace_skipped: Vec<WorkspaceSkip>,
}

#[derive(Debug)]
struct ArtifactReachability {
    package: LockPackage,
    modules: BTreeSet<String>,
}

#[derive(Debug)]
struct PreparedTarget {
    package: LockPackage,
    key: ArtifactKey,
    expected: ExpectedPin,
    modules: Vec<String>,
}

#[derive(Debug)]
struct UnpinnedTarget {
    key: ArtifactKey,
    modules: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct WorkspaceSkip {
    module: String,
    workspace_module: String,
    coordinate: String,
}

fn module_attribution(modules: &[String]) -> String {
    format!("reachable from {}", modules.join(", "))
}

fn report_workspace_skips(skipped: &[WorkspaceSkip]) {
    if skipped.is_empty() || quiet_enabled() || is_json_mode() {
        return;
    }
    eprintln!(
        "  skipped {} workspace {} by design",
        skipped.len(),
        if skipped.len() == 1 {
            "entry"
        } else {
            "entries"
        }
    );
    for entry in skipped {
        eprintln!(
            "    {} -> {} ({})",
            entry.module, entry.workspace_module, entry.coordinate
        );
    }
}

fn workspace_json(skipped: &[WorkspaceSkip]) -> Vec<serde_json::Value> {
    skipped
        .iter()
        .map(|entry| {
            serde_json::json!({
                "module": entry.module,
                "workspace_module": entry.workspace_module,
                "coordinate": entry.coordinate,
                "reason": "workspace module; skipped by design",
            })
        })
        .collect()
}

fn verify_targets_json(targets: &[VerifyTarget]) -> Vec<serde_json::Value> {
    targets
        .iter()
        .map(|target| {
            serde_json::json!({
                "coordinate": target.target.key.to_string(),
                "affected_modules": target.target.modules,
                "actual": target.actual,
            })
        })
        .collect()
}

/// Untrusted-origin findings carry the offending `repo_url` so the operator
/// can tell whether the lockfile records a repository they dropped from
/// `rv.toml` or one they have never seen.
fn untrusted_origin_json(targets: &[VerifyTarget]) -> Vec<serde_json::Value> {
    targets
        .iter()
        .map(|target| {
            serde_json::json!({
                "coordinate": target.target.key.to_string(),
                "repo_url": target.target.package.repo_url,
                "affected_modules": target.target.modules,
            })
        })
        .collect()
}

fn unpinned_targets_json(targets: &[UnpinnedTarget]) -> Vec<serde_json::Value> {
    targets
        .iter()
        .map(|target| {
            serde_json::json!({
                "coordinate": target.key.to_string(),
                "affected_modules": target.modules,
            })
        })
        .collect()
}

/// Parsed lockfile pin for a single package.
///
/// The lockfile parser canonicalises both `sha256` and `sha1` (see
/// `rv_config::normalize_checksum_algorithm`). By default `rv sync` falls
/// back to verifying the SHA-1 sidecar when a repository only publishes
/// SHA-1 (emitting the WEAK_HASH_FALLBACK warning), so it can write SHA-1
/// pins. Verify and the downstream consumers must accept the same set or
/// they reject lockfiles the sync path happily produced.
#[derive(Debug, Clone)]
enum ExpectedPin {
    /// Maps directly to a `BlobId`, so the store CAS path is a cheap
    /// identity check (no second hash pass needed).
    Sha256(BlobId),
    /// 40-char lowercase hex SHA-1 digest. The store is SHA-256 keyed,
    /// so verification requires re-hashing the on-disk blob with SHA-1.
    Sha1(String),
}

fn expected_pin(key: &ArtifactKey, checksum: &Checksum) -> Result<ExpectedPin> {
    let canonical = normalize_checksum_algorithm(&checksum.algorithm).ok_or_else(|| {
        CliError::LockfileMismatch {
            details: format!("unsupported checksum {} for {key}", checksum.algorithm),
        }
    })?;
    match canonical {
        "sha256" => {
            let id =
                BlobId::from_str(&checksum.digest).map_err(|e| CliError::Message(e.to_string()))?;
            Ok(ExpectedPin::Sha256(id))
        }
        "sha1" => {
            let digest = checksum.digest.trim().to_ascii_lowercase();
            if digest.len() != 40 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CliError::LockfileMismatch {
                    details: format!(
                        "sha1 digest for {key} must be 40 hex chars, got {:?}",
                        checksum.digest
                    ),
                });
            }
            Ok(ExpectedPin::Sha1(digest))
        }
        // `normalize_checksum_algorithm` only returns the two canonical
        // spellings above, so this arm is unreachable in practice.
        other => Err(CliError::LockfileMismatch {
            details: format!("unsupported checksum {other} for {key}"),
        }),
    }
}

fn verify_pin(
    store: &Store,
    resolved_blob: Option<&BlobId>,
    expected: &ExpectedPin,
) -> Result<VerifyStatus> {
    match expected {
        ExpectedPin::Sha256(expected) => {
            let path = store.get_path(expected);
            if !path.is_file() {
                return Ok(VerifyStatus::Missing);
            }
            let actual = BlobId::from_file(&path)?;
            if &actual != expected {
                return Ok(VerifyStatus::Corrupt {
                    actual: actual.as_str().to_string(),
                });
            }
            Ok(VerifyStatus::Ok)
        }
        ExpectedPin::Sha1(expected) => {
            // The store is SHA-256 keyed, so we cannot derive the BlobId
            // from a SHA-1 digest. The caller resolved the BlobId via the
            // artifact-key index; missing means the user has never synced
            // this package against this store.
            let Some(blob) = resolved_blob else {
                return Ok(VerifyStatus::Missing);
            };
            let path = store.get_path(blob);
            if !path.is_file() {
                return Ok(VerifyStatus::Missing);
            }
            let actual = sha1_hex_file(&path)?;
            if &actual != expected {
                return Ok(VerifyStatus::Corrupt { actual });
            }
            Ok(VerifyStatus::Ok)
        }
    }
}

#[derive(Debug)]
struct VerifyTarget {
    target: PreparedTarget,
    actual: Option<String>,
}

#[derive(Debug)]
enum VerifyStatus {
    Ok,
    Missing,
    Corrupt { actual: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest as _, Sha1};
    use tempfile::TempDir;

    #[tokio::test]
    async fn verify_pin_returns_ok_when_blob_exists() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let bytes = b"test content";
        let blob_id = store.put_bytes(bytes).await.expect("put bytes");

        let status = verify_pin(&store, None, &ExpectedPin::Sha256(blob_id)).expect("verify");
        assert!(matches!(status, VerifyStatus::Ok));
    }

    #[tokio::test]
    async fn verify_pin_returns_missing_when_blob_not_found() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let missing_id = BlobId::from_bytes(b"nonexistent");

        let status = verify_pin(&store, None, &ExpectedPin::Sha256(missing_id)).expect("verify");
        assert!(matches!(status, VerifyStatus::Missing));
    }

    #[tokio::test]
    async fn verify_pin_returns_corrupt_when_hash_mismatch() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");

        // Put a blob
        let bytes = b"original content";
        let blob_id = store.put_bytes(bytes).await.expect("put bytes");

        // Corrupt it by overwriting with different content.
        // CAS blobs land at 0o444 post-publish; rewind the bit so this
        // simulated tamper isn't blocked by the read-only mode.
        let path = store.get_path(&blob_id);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).expect("stat blob").permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&path, perms).expect("chmod blob");
        }
        std::fs::write(&path, b"corrupted").expect("corrupt file");

        let status = verify_pin(&store, None, &ExpectedPin::Sha256(blob_id)).expect("verify");
        assert!(matches!(status, VerifyStatus::Corrupt { .. }));
    }

    /// A SHA-1 pin should verify against the on-disk blob by
    /// SHA-1-hashing it. The store is SHA-256 keyed, so the caller must
    /// pre-resolve the BlobId via the artifact-key index.
    #[tokio::test]
    async fn verify_pin_sha1_ok_when_digest_matches() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let bytes = b"sha1-pinned content";
        let blob_id = store.put_bytes(bytes).await.expect("put bytes");

        // Compute the actual SHA-1 of the bytes to use as the pin.
        let mut hasher = Sha1::new();
        hasher.update(bytes);
        let sha1_hex = hex::encode(hasher.finalize());

        let status =
            verify_pin(&store, Some(&blob_id), &ExpectedPin::Sha1(sha1_hex)).expect("verify");
        assert!(matches!(status, VerifyStatus::Ok));
    }

    #[tokio::test]
    async fn verify_pin_sha1_missing_when_not_indexed() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let status = verify_pin(&store, None, &ExpectedPin::Sha1("a".repeat(40))).expect("verify");
        assert!(matches!(status, VerifyStatus::Missing));
    }

    #[tokio::test]
    async fn verify_pin_sha1_corrupt_when_digest_mismatches() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let blob_id = store
            .put_bytes(b"original content")
            .await
            .expect("put bytes");
        // A 40-char hex digest that cannot match the real SHA-1.
        let bad_sha1 = "0".repeat(40);
        let status =
            verify_pin(&store, Some(&blob_id), &ExpectedPin::Sha1(bad_sha1)).expect("verify");
        assert!(matches!(status, VerifyStatus::Corrupt { .. }));
    }

    fn lock_with_packages(packages: Vec<LockPackage>) -> Lockfile {
        let platform = rv_config::Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms = vec![rv_config::LockPlatform::single_module(
            platform,
            "",
            "pom.xml",
            rv_config::LockGav::new("com.example", "demo", "1"),
            "jar",
            packages,
            vec![],
        )];
        lock
    }

    fn lock_package(
        artifact: &str,
        packaging: &str,
        checksum: Option<Checksum>,
        system_path: Option<&str>,
    ) -> LockPackage {
        LockPackage {
            group_id: "com.example".to_string(),
            artifact_id: artifact.to_string(),
            version: "1.0".to_string(),
            snapshot_timestamp: None,
            packaging: packaging.to_string(),
            classifier: None,
            repo_url: "https://repo.example/m2/".to_string(),
            checksum,
            system_path: system_path.map(str::to_string),
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    const SHA256_A: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    /// Packages without a recorded checksum become per-package findings; the
    /// rest of the batch is still prepared instead of aborting on the first.
    #[test]
    fn prepare_targets_collects_checksumless_packages_and_continues() {
        let lock = lock_with_packages(vec![
            lock_package("no-pin-1", "jar", None, None),
            lock_package(
                "pinned",
                "jar",
                Some(Checksum::new("sha256", SHA256_A)),
                None,
            ),
            lock_package("no-pin-2", "jar", None, None),
        ]);
        let prepared = prepare_targets(&lock, &ModuleSelector::default()).expect("prepare targets");
        assert_eq!(
            prepared.targets.len(),
            1,
            "the pinned package must still verify"
        );
        assert_eq!(prepared.targets[0].package.artifact_id, "pinned");
        assert_eq!(
            prepared.no_checksum.len(),
            2,
            "both checksum-less packages reported"
        );
    }

    /// An explicit `<type>pom</type>` dependency owns an artifact-table row and
    /// is pinned like any other artifact, so it must be verified rather than
    /// skipped: a deleted or corrupted explicit POM otherwise survives verify
    /// and only surfaces when `rv export-m2` trips over it. System-path
    /// packages are still skipped; they are never stored.
    #[test]
    fn prepare_targets_verifies_pom_packaging_and_skips_system_path_packages() {
        let lock = lock_with_packages(vec![
            lock_package(
                "pom-dep",
                "pom",
                Some(Checksum::new("sha256", SHA256_A)),
                None,
            ),
            lock_package("pom-no-pin", "pom", None, None),
            lock_package("local", "jar", None, Some("/opt/local.jar")),
            lock_package("real", "jar", Some(Checksum::new("sha256", SHA256_A)), None),
        ]);
        let prepared = prepare_targets(&lock, &ModuleSelector::default()).expect("prepare targets");
        let verified: Vec<&str> = prepared
            .targets
            .iter()
            .map(|target| target.package.artifact_id.as_str())
            .collect();
        assert_eq!(verified, vec!["pom-dep", "real"]);
        let unpinned: Vec<String> = prepared
            .no_checksum
            .iter()
            .map(|target| target.key.to_string())
            .collect();
        assert_eq!(
            unpinned.len(),
            1,
            "the unpinned POM row is a finding, the system-path package is not: {unpinned:?}"
        );
        assert!(unpinned[0].contains("pom-no-pin"));
    }

    /// A corrupted explicit-POM blob must be flagged. Verification runs off the
    /// same `prepare_targets` -> `verify_pin` pair as the real command, so this
    /// also pins that a POM row survives target preparation.
    #[tokio::test]
    async fn verify_flags_corrupt_explicit_pom_blob() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");
        let pom_bytes = b"<project><modelVersion>4.0.0</modelVersion></project>";
        let blob_id = store.put_bytes(pom_bytes).await.expect("put pom");

        let lock = lock_with_packages(vec![lock_package(
            "pom-dep",
            "pom",
            Some(Checksum::new("sha256", blob_id.as_str())),
            None,
        )]);
        let prepared = prepare_targets(&lock, &ModuleSelector::default()).expect("prepare targets");
        assert_eq!(prepared.targets.len(), 1, "the POM row must be verified");
        let target = &prepared.targets[0];
        assert_eq!(target.key.packaging, "pom");

        let status = verify_pin(&store, Some(&blob_id), &target.expected).expect("verify intact");
        assert!(matches!(status, VerifyStatus::Ok));

        // CAS blobs are published read-only; re-grant write before tampering.
        let path = store.get_path(&blob_id);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).expect("stat blob").permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&path, perms).expect("chmod blob");
        }
        std::fs::write(&path, b"<project>tampered</project>").expect("corrupt pom");

        let status = verify_pin(&store, Some(&blob_id), &target.expected).expect("verify corrupt");
        assert!(
            matches!(status, VerifyStatus::Corrupt { .. }),
            "a corrupted explicit POM must be reported, got {status:?}"
        );
    }

    fn config_with_repo(url: &str) -> (TempDir, Config) {
        let temp = TempDir::new().expect("temp dir");
        let paths = rv_config::ResolvedPaths::discover().expect("paths");
        let repo = rv_config::RepoConfig {
            id: Some("configured".to_string()),
            url: url.to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: Some(rv_config::UpdatePolicy::Daily),
        };
        let config = Config::for_testing_with_repos(temp.path().to_path_buf(), paths, vec![repo]);
        (temp, config)
    }

    /// The lockfile is not a trust root. An origin the current `rv.toml`
    /// does not declare must not resolve to a `Repository` at all, so the
    /// download stage cannot be redirected at it — the same refusal
    /// `rv_repo::sync` raises as `RepoError::UntrustedRepoUrl`.
    #[test]
    fn repository_for_package_refuses_origin_outside_the_trust_roots() {
        let (_temp, config) = config_with_repo("https://repo.example/m2/");
        let mut package = lock_package("demo", "jar", None, None);
        package.repo_url = "https://attacker.example/m2/".to_string();
        assert!(
            repository_for_package(&config, &package).is_none(),
            "an unconfigured lockfile origin must be refused, not synthesized"
        );
    }

    /// Happy path, including the trailing-slash normalization that
    /// `normalize_repo_url` applies on both sides.
    #[test]
    fn repository_for_package_accepts_configured_origin() {
        let (_temp, config) = config_with_repo("https://repo.example/m2/");
        let mut package = lock_package("demo", "jar", None, None);
        package.repo_url = "https://repo.example/m2".to_string();
        let repo = repository_for_package(&config, &package).expect("configured origin resolves");
        assert_eq!(repo.id.as_deref(), Some("configured"));
    }

    #[test]
    fn failure_summary_appends_optional_clauses_only_when_present() {
        assert_eq!(
            failure_summary(&FailureCounts {
                missing: 2,
                corrupt: 1,
                ..FailureCounts::default()
            }),
            "2 missing, 1 corrupt"
        );
        assert_eq!(
            failure_summary(&FailureCounts {
                no_checksum: 3,
                ..FailureCounts::default()
            }),
            "0 missing, 0 corrupt, 3 with no checksum recorded"
        );
        assert_eq!(
            failure_summary(&FailureCounts {
                missing: 1,
                untrusted_origin: 2,
                pin_mismatch: 1,
                ..FailureCounts::default()
            }),
            "1 missing, 0 corrupt, 2 from an untrusted origin, \
             1 whose download did not match the recorded checksum"
        );
    }

    #[test]
    fn expected_pin_parses_sha256() {
        let key = ArtifactKey::new("g", "a", "1", "jar", None);
        // Use a valid 64-char hex digest (SHA256 length)
        let digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let checksum = rv_config::Checksum::new("sha256", digest);
        let result = expected_pin(&key, &checksum).expect("pin");
        match result {
            ExpectedPin::Sha256(id) => assert_eq!(id.as_str(), digest),
            other => panic!("expected sha256, got {other:?}"),
        }
    }

    /// The lockfile parser and sync path both accept SHA-1 pins, so verify
    /// must accept them too: a 40-char hex SHA-1 digest must parse to
    /// `ExpectedPin::Sha1`.
    #[test]
    fn expected_pin_parses_sha1() {
        let key = ArtifactKey::new("g", "a", "1", "jar", None);
        let digest = "aabbccddeeff00112233445566778899aabbccdd";
        let checksum = rv_config::Checksum::new("sha1", digest);
        let result = expected_pin(&key, &checksum).expect("pin");
        match result {
            ExpectedPin::Sha1(d) => assert_eq!(d, digest),
            other => panic!("expected sha1, got {other:?}"),
        }
    }

    #[test]
    fn expected_pin_rejects_unsupported_algorithm() {
        let key = ArtifactKey::new("g", "a", "1", "jar", None);
        let checksum = rv_config::Checksum::new("md5", "abc123");
        let err = expected_pin(&key, &checksum).expect_err("md5 must be rejected");
        assert!(matches!(err, CliError::LockfileMismatch { .. }));
    }

    /// Regression for the verify fan-out: 50 small blobs all verify Ok when
    /// processed through the same `stream + spawn_blocking + buffer_unordered`
    /// pattern that `verify_inner` uses. This asserts only correctness, not
    /// wall-clock speedup: a wall-clock comparison against a serial baseline
    /// is inherently flaky on single-core CI runners and container-capped
    /// hosts, where a tight serial loop over tiny blobs frequently beats the
    /// task-spawn overhead. Correctness is what the fan-out must guarantee.
    #[tokio::test]
    async fn parallel_verify_handles_many_blobs() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).expect("open store");

        // 50 unique small blobs.
        let mut ids = Vec::with_capacity(50);
        for i in 0..50u32 {
            let payload = format!("blob-{i:08}").repeat(64).into_bytes();
            let id = store.put_bytes(&payload).await.expect("put");
            ids.push(id);
        }

        // Parallel fan-out matching verify_inner's pattern.
        let store_arc = Arc::new(store.clone());
        let results: Vec<Result<VerifyStatus>> = stream::iter(ids.into_iter())
            .map(|id| {
                let store = Arc::clone(&store_arc);
                async move {
                    tokio::task::spawn_blocking(move || {
                        verify_pin(&store, None, &ExpectedPin::Sha256(id))
                    })
                    .await
                    .map_err(|e| CliError::Message(format!("panic: {e}")))?
                }
            })
            .buffer_unordered(8)
            .collect()
            .await;

        for r in results {
            assert!(matches!(r.expect("parallel"), VerifyStatus::Ok));
        }
    }
}
