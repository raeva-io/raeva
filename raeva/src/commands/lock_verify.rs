use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io;
use std::sync::Arc;

use chrono::DateTime;
use clap::{Args, Subcommand};
use futures::stream::{self, StreamExt};
use serde::Serialize;

use rv_config::Config;
use rv_lock::{LOCKFILE_SCHEMA_VERSION, LockArtifact, Lockfile, Platform, SupportPom};
use rv_maven_types::{ArtifactCoord, Digest};
use rv_repo::{IntegritySource, RepoError};
use rv_store::{PinCheck, Store};

use crate::commands::lock_inputs::{
    check_recorded_freshness, discover_reactor_models, frozen_models_match,
};
use crate::commands::module_selector::ModuleSelector;
use crate::commands::{path_to_forward_slashes, read_lockfile};
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Output, Report, Table};
use crate::session::Session;

#[derive(Debug, Args)]
#[command(after_long_help = crate::commands::util::help_examples(&[
    ("lock verify", "Check the store against every pin"),
    ("lock diff old.lock", "Compare old.lock with raeva.lock"),
    ("lock info", "Show the schema, platforms and package counts"),
]))]
pub(crate) struct LockArgs {
    #[command(subcommand)]
    pub command: LockCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum LockCommand {
    /// Check that the store holds every locked artifact with its pinned checksum
    Verify(LockVerifyArgs),
    /// Show lockfile metadata and statistics
    #[command(after_long_help = crate::commands::util::help_examples(&[
        ("lock info", "Show the schema, platforms and package counts"),
        ("--json lock info", "Output as JSON"),
    ]))]
    Info,
    /// Compare two lockfiles without resolving or downloading
    Diff(super::lock_diff::LockDiffArgs),
}

#[derive(Debug, Args)]
#[command(after_long_help = crate::commands::util::help_examples(&[
    ("lock verify", "Check the store against every pin"),
    ("lock verify --download", "Download what the store lacks and an offline sync --frozen reads"),
    ("lock verify --module app/pom.xml", "Check one module"),
]))]
pub(crate) struct LockVerifyArgs {
    /// Download missing or corrupt artifacts again, and, unless --module
    /// narrows the check, what an offline `sync --frozen` reads
    #[arg(long)]
    pub download: bool,

    #[command(flatten)]
    pub(crate) module: ModuleSelector,
}

pub(crate) async fn run(args: &LockArgs, session: &Session) -> Result<Report> {
    match &args.command {
        LockCommand::Diff(args) => {
            let args = args.clone();
            session
                .blocking("lock diff", move |session| {
                    super::lock_diff::run(&args, session)
                })
                .await
        }
        LockCommand::Verify(verify_args) => verify(verify_args, session).await,
        LockCommand::Info => session.blocking("lock info", lock_info).await,
    }
}

fn lock_info(session: &Session) -> Result<Report> {
    let config = session.lock_config()?;

    // Route through the shared `read_lockfile` helper so a non-file at the
    // lockfile path (a directory, FIFO, etc.) reports the precise
    // `LockfileNotAFile` diagnostic instead of the bespoke `is_file()` check
    // that collapsed every non-regular-file case into "missing".
    let lock = read_lockfile(&config)?;
    let metadata = fs::metadata(&config.lock_path)?;
    // `as i64` wraps past year 2554; fall back to "unknown" instead.
    let last_modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .and_then(|secs| DateTime::from_timestamp(secs, 0))
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut unique_coords: HashSet<String> = HashSet::new();
    let platforms: Vec<PlatformInfo> = lock
        .platforms
        .iter()
        .map(|platform| {
            for artifact in &platform.artifacts {
                unique_coords.insert(artifact.coordinate.to_string());
            }
            PlatformInfo {
                platform: platform.platform.os_arch(),
                jdk: platform.platform.jdk().map(str::to_string),
                display: platform.platform.to_string(),
                packages: platform
                    .modules
                    .iter()
                    .map(|module| module.packages.len())
                    .sum(),
                modules: platform.modules.len(),
                external_artifacts: platform.artifacts.len(),
            }
        })
        .collect();

    Ok(Report::data(LockInfoReport {
        path: path_to_forward_slashes(&config.lock_path),
        display_path: config.lock_path.display().to_string(),
        schema_version: LOCKFILE_SCHEMA_VERSION,
        last_modified,
        platform_count: platforms.len(),
        total_packages: platforms.iter().map(|platform| platform.packages).sum(),
        unique_artifacts: unique_coords.len(),
        platforms,
    }))
}

#[derive(Serialize)]
struct LockInfoReport {
    path: String,
    #[serde(skip)]
    display_path: String,
    schema_version: u32,
    last_modified: String,
    platform_count: usize,
    total_packages: usize,
    unique_artifacts: usize,
    platforms: Vec<PlatformInfo>,
}

#[derive(Serialize)]
struct PlatformInfo {
    platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jdk: Option<String>,
    #[serde(skip)]
    display: String,
    packages: usize,
    modules: usize,
    external_artifacts: usize,
}

impl CommandOutput for LockInfoReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(self)
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        human.heading("Lockfile info")?;
        let mut table = Table::new(["Property", "Value"]);
        table.add_row(["Path", &self.display_path]);
        table.add_row(["Schema version", &self.schema_version.to_string()]);
        table.add_row(["Last modified", &self.last_modified]);
        table.add_row(["Platforms", &self.platform_count.to_string()]);
        table.add_row([
            "Module dependency entries",
            &self.total_packages.to_string(),
        ]);
        table.add_row(["Unique artifacts", &self.unique_artifacts.to_string()]);
        if !self.platforms.is_empty() {
            table.add_row(["", ""]);
            table.add_row(["Platform breakdown", ""]);
            for platform in &self.platforms {
                table.add_row([
                    format!("  {}", platform.display),
                    format!(
                        "{} external artifacts, {} modules with {} dependency entries",
                        platform.external_artifacts, platform.modules, platform.packages
                    ),
                ]);
            }
        }
        human.table(&table)
    }
}

async fn verify(args: &LockVerifyArgs, session: &Session) -> Result<Report> {
    // Only `--download` contacts a repository.
    let config = if args.download {
        session.config_async().await?
    } else {
        session
            .blocking("config load", Session::lock_config)
            .await?
    };
    let mut report = verify_inner(args, &config, session.offline(), session.output()).await?;
    report.list_workspace = session.output().is_verbose();
    if report.has_findings() {
        let details = format!(
            "the store does not hold what raeva.lock pins: {}",
            report.summary()
        );
        let mut hint = report.hint();
        if let Some(first) = hint.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        let hint = Some(hint);
        Ok(Report::data(report).failed(CliError::LockfileMismatch { details, hint }))
    } else {
        Ok(Report::data(report))
    }
}

async fn verify_inner(
    args: &LockVerifyArgs,
    config: &Config,
    offline: bool,
    output: &Output,
) -> Result<LockVerifyReport> {
    // The plugin tables' files are hashed as the dependencies' are; their
    // repair is the resolution `--download` runs as `sync --frozen` does,
    // which knows the repositories they come from.
    let mut lock = read_lockfile(config)?;
    let written = crate::commands::util::check_written(&lock, &config.lock_path);
    let held = (lock.platforms.iter())
        .any(|entry| entry.plugins.is_some())
        .then(|| lock.clone());
    lock.platforms
        .iter_mut()
        .for_each(rv_lock::LockPlatform::remove_plugins);
    // Open the store once into an Arc and share that single Arc
    // through both the verification fan-out and the optional download
    // fan-out. Re-cloning the underlying `Store` into two distinct
    // `Arc<Store>` containers would defeat the Arc (each worker would
    // still hold its own clone of the inner state).
    let store: Arc<Store> = Arc::new(Store::open(&config.paths.store_dir)?);

    // Each pin check re-hashes the on-disk blob, a synchronous CPU and IO
    // call. Doing them sequentially burns multi-seconds on real
    // lockfiles. Fan them out across spawn_blocking workers, capped by the
    // user's configured network concurrency.
    let parallelism = config.network.fetch_concurrency();

    // Pre-compute the per-package verification inputs so the parallel stage
    // is pure work, with no Config / Lockfile access needed.
    //
    // The lockfile parser accepts both `sha256` and `sha1` pins. By default
    // `raeva sync` verifies against the sha256 sidecar when the repository
    // publishes one and otherwise falls back to the sha1 sidecar (emitting
    // the WEAK_HASH_FALLBACK warning), so a lockfile produced against a
    // SHA-1-only repository legitimately carries SHA-1 pins. Verify must
    // accept the same set or it falsely rejects those lockfiles.
    let (targets, no_checksum, workspace_skipped) =
        prepare_targets(held.as_ref().unwrap_or(&lock), &args.module)?;

    let mut verified = 0usize;
    let mut missing = Vec::new();
    let mut corrupt = Vec::new();
    let checked = check_pins(&store, targets, parallelism).await?;
    verified += sort_checks(checked, &mut missing, &mut corrupt);

    let mut downloaded = 0usize;
    // An offline `sync --frozen` resolves again, which reads more than the
    // pinned files: version listings, the POMs of versions the lock does not
    // pin, and the answers of repositories that lack a file. The same
    // resolution online caches all of it, and downloads the pinned files it
    // reaches as it goes.
    // Only the resolution of the plugin tables, which a frozen sync runs,
    // fetches a plugin file or build extension jar again from the plugin
    // repositories, so a module's repair runs it for one.
    let platforms = &held.as_ref().unwrap_or(&lock).platforms;
    let plugin_files: BTreeSet<ArtifactCoord> = (platforms.iter())
        .filter_map(rv_lock::LockPlatform::plugin_files)
        .flat_map(|files| {
            files
                .pinned_files()
                .map(|file| file.key)
                .collect::<Vec<_>>()
        })
        .chain(
            (platforms
                .iter()
                .flat_map(rv_lock::LockPlatform::extension_jars))
            .map(|(_, jar)| jar.coord()),
        )
        .collect();
    let repairs_plugins =
        (missing.iter().chain(&corrupt)).any(|finding| plugin_files.contains(&finding.target.key));
    // The files only the plugin tables pin, which the dependencies' repair
    // and trust never vouch for.
    let dependency_files: BTreeSet<ArtifactCoord> = (lock.platforms.iter())
        .flat_map(|platform| platform.pinned_files().map(|file| file.key))
        .collect();
    let plugin_only =
        |key: &ArtifactCoord| plugin_files.contains(key) && !dependency_files.contains(key);
    if args.download
        && !offline
        && (args.module.is_all() || repairs_plugins)
        && config.project_root.join("pom.xml").is_file()
    {
        match resolve_frozen(config, Arc::clone(&store), &lock, held.as_ref(), output).await {
            // The lock is the resolution's result, so each file it stored
            // came from where the lock's model allows.
            Ok(()) => {
                let again: Vec<_> = (missing.drain(..).chain(corrupt.drain(..)))
                    .map(|finding| finding.target)
                    .collect();
                let checked = check_pins(&store, again, parallelism).await?;
                downloaded = sort_checks(checked, &mut missing, &mut corrupt);
                verified += downloaded;
            }
            Err(err) => {
                let reason = err.to_string();
                let reason = (reason.lines().next().unwrap_or_default()).trim_end_matches(':');
                output.warn(crate::output::Warning::new(
                    crate::output::WarningCode::FrozenResolutionFailed,
                    format!(
                        "raeva.lock did not resolve again as 'raeva sync --frozen' resolves \
                         it: {reason}; 'raeva --offline sync --frozen' fails until it does"
                    ),
                ));
            }
        }
    }

    let mut untrusted_origin: Vec<VerifyTarget> = Vec::new();
    let mut pin_mismatch: Vec<VerifyTarget> = Vec::new();
    if args.download && (!missing.is_empty() || !corrupt.is_empty()) {
        let mut targets = Vec::new();
        let was_corrupt: HashSet<ArtifactCoord> = (corrupt.iter())
            .map(|finding| finding.target.key.clone())
            .collect();
        targets.append(&mut missing);
        targets.append(&mut corrupt);

        let mut contexts = Vec::new();
        let mut undiscovered = Vec::new();
        for entry in &lock.platforms {
            let mine = || {
                (targets.iter().flat_map(|target| &target.target.origins))
                    .filter(|origin| *origin.platform() == entry.platform)
            };
            if mine().next().is_none() {
                continue;
            }
            let mut context = crate::commands::sync::LockDownloadContext::new(
                config,
                held.as_ref().unwrap_or(&lock),
                &entry.platform,
                output,
                &crate::commands::sync::Mode::check(offline),
            )
            .await?;
            // Trust discovery must inspect only repairs: a verified row's
            // transitive origin must not force an unrelated resolution.
            let mut repairs = lock
                .select_platforms(std::slice::from_ref(&entry.platform))
                .expect("recorded platform")
                .into_owned();
            let repair = &mut repairs.platforms[0];
            repair.artifacts.clear();
            repair.support_poms.clear();
            // The dependencies' trust never vouches for a plugin file.
            let dependencies = (targets.iter())
                .filter(|target| !plugin_only(&target.target.key))
                .flat_map(|target| &target.target.origins)
                .filter(|origin| *origin.platform() == entry.platform);
            for origin in dependencies {
                match origin {
                    Origin::Row(artifact, _) => repair.artifacts.push(artifact.clone()),
                    Origin::Support(coord, pin, _) => {
                        repair.support_poms.insert(coord.clone(), pin.clone());
                    }
                    Origin::Extension(..) => {}
                }
            }
            let resolved =
                rv_repo::restore_needs_discovery(&store, &repairs, &[context.as_restore()]).await?
                    && context
                        .discover_trust(Arc::clone(&store), &repairs, false)
                        .await?;
            if !resolved {
                context.trust_local_model();
            }
            undiscovered.push((!resolved).then_some(repairs));
            contexts.push(context);
        }

        output.step("Downloading artifacts...");
        let mut download_results =
            download_targets(&store, &lock, &contexts, targets, parallelism).await;
        // A file can have moved to a repository only a remote parent
        // declares, which Maven searches too: resolve the trust of each
        // platform owning a file not verified and retry those. A file the
        // retry does not verify keeps its first finding.
        let failed = |outcome: &Result<Downloaded>| !matches!(outcome, Ok(Downloaded::Verified));
        let owners: HashSet<Platform> = (download_results.iter())
            .filter(|(outcome, target)| failed(outcome) && !plugin_only(&target.target.key))
            .flat_map(|(_, target)| &target.target.origins)
            .map(|origin| origin.platform().clone())
            .collect();
        let mut retry = false;
        if !offline {
            for (context, repairs) in contexts.iter_mut().zip(&undiscovered) {
                if let Some(repairs) = repairs
                    && context
                        .platforms
                        .iter()
                        .any(|platform| owners.contains(platform))
                    && (context.discover_trust(Arc::clone(&store), repairs, true))
                        .await
                        .is_ok_and(|resolved| resolved)
                {
                    retry = true;
                }
            }
        }
        if retry {
            let (again, done): (Vec<_>, Vec<_>) = download_results
                .into_iter()
                .partition(|(outcome, _)| failed(outcome));
            let (first, again): (Vec<_>, Vec<_>) = again.into_iter().unzip();
            download_results = done;
            let retried = download_targets(&store, &lock, &contexts, again, parallelism).await;
            download_results.extend(first.into_iter().zip(retried).map(
                |(first, (retried, target))| match retried {
                    Ok(Downloaded::Verified) => (retried, target),
                    _ => (first, target),
                },
            ));
        }
        let mut repaired = 0;
        for (outcome, target) in download_results {
            match outcome? {
                Downloaded::Verified => repaired += 1,
                // This repair knows only the dependencies' repositories; a
                // plugin file is the frozen resolution's to repair.
                Downloaded::Untrusted
                    if plugin_only(&target.target.key) || target.target.extension_only() =>
                {
                    match was_corrupt.contains(&target.target.key) {
                        true => corrupt.push(target),
                        false => missing.push(target),
                    }
                }
                Downloaded::Untrusted => untrusted_origin.push(target),
                Downloaded::Mismatch(actual) => pin_mismatch.push(VerifyTarget {
                    target: target.target,
                    actual,
                }),
            }
        }
        downloaded += repaired;
        verified += repaired;
    }

    // The fan-outs above finish in any order; reports list findings by
    // coordinate so two runs over the same store print the same thing.
    for findings in [
        &mut missing,
        &mut corrupt,
        &mut untrusted_origin,
        &mut pin_mismatch,
    ] {
        findings.sort_by_cached_key(|finding| finding.target.key.to_string());
    }
    crate::commands::util::not_written(written)?;

    Ok(LockVerifyReport {
        verified,
        downloaded,
        missing,
        corrupt,
        no_checksum,
        untrusted_origin,
        pin_mismatch,
        workspace_skipped,
        list_workspace: false,
    })
}

/// [`Store::check_pin`] for every target, `parallelism` at a time, in lock
/// order, so the error reported is the first in lock order, while a large
/// file holds only its own slot.
async fn check_pins(
    store: &Arc<Store>,
    targets: Vec<PreparedTarget>,
    parallelism: usize,
) -> Result<Vec<(PreparedTarget, PinCheck)>> {
    let mut results: Vec<(usize, Result<(PreparedTarget, PinCheck)>)> =
        stream::iter(targets.into_iter().enumerate())
            .map(|(index, target)| {
                let store = Arc::clone(store);
                async move {
                    let result = async {
                        // The store is SHA-256 keyed, so another pin names its blob
                        // through the artifact-key index; none means this package was
                        // never synced into this store.
                        let blob = match &target.expected {
                            Digest::Sha256(id) => Some(id.clone()),
                            Digest::Sha1(_) | Digest::Md5(_) => {
                                store.lookup_artifact(&target.key).await?
                            }
                        };
                        let Some(blob) = blob else {
                            return Ok((target, PinCheck::Missing));
                        };
                        let digests = target.digests();
                        let status = tokio::task::spawn_blocking(move || {
                            for digest in &digests {
                                match store.check_pin(&blob, digest)? {
                                    PinCheck::Match => {}
                                    other => return Ok(other),
                                }
                            }
                            Ok::<_, rv_store::StoreError>(PinCheck::Match)
                        })
                        .await
                        .map_err(|e| CliError::task_failed("verify", e))??;
                        Ok((target, status))
                    };
                    (index, result.await)
                }
            })
            .buffer_unordered(parallelism)
            .collect()
            .await;
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

/// Sort pin checks into `missing` and `corrupt`, returning how many matched.
fn sort_checks(
    checked: Vec<(PreparedTarget, PinCheck)>,
    missing: &mut Vec<VerifyTarget>,
    corrupt: &mut Vec<VerifyTarget>,
) -> usize {
    let mut matched = 0;
    for (target, status) in checked {
        match status {
            PinCheck::Match => matched += 1,
            PinCheck::Missing => missing.push(VerifyTarget {
                target,
                actual: None,
            }),
            PinCheck::Mismatch { actual } => corrupt.push(VerifyTarget {
                target,
                actual: Some(actual),
            }),
        }
    }
    matched
}

/// Resolve every platform `lock` records, online, as `sync --frozen` does,
/// with the plugins of `held`, the lock with its plugin tables, and fail
/// where it would.
async fn resolve_frozen(
    config: &Config,
    store: Arc<Store>,
    lock: &Lockfile,
    held: Option<&Lockfile>,
    output: &Output,
) -> Result<()> {
    let platforms: Vec<Platform> = (lock.platforms.iter())
        .map(|entry| entry.platform.clone())
        .collect();
    let config = config.for_platforms(
        (platforms.iter()).map(|platform| (platform.os(), platform.arch(), platform.jdk())),
    );
    config.settings_activation()?;
    let models = discover_reactor_models(&config, &platforms)?;
    let models_match = frozen_models_match(lock, &models);
    check_recorded_freshness(
        &config,
        lock,
        &models,
        models_match,
        true,
        "raeva.lock has no config_hash, so --frozen cannot check it against the configuration",
    )?;
    let client = (crate::commands::sync::Mode::check(false).client(&config))
        .await?
        .with_progress(output.progress())
        .with_lock_pins(lock);
    output.step("Resolving dependencies...");
    crate::commands::sync::validate_frozen_resolution(
        &config,
        Arc::clone(&store),
        client.clone(),
        lock,
        &models,
        models_match,
        output,
    )
    .await?;
    crate::commands::sync::check_frozen_plugins(
        &config,
        store,
        client.clone(),
        held,
        &models,
        &platforms,
    )
    .await?;
    let checked = held.unwrap_or(lock);
    crate::commands::sync::record_checked(&config, &client, &platforms, Some(checked));
    Ok(())
}

/// What `raeva lock verify` found. Any finding fails the command with
/// `LOCKFILE_MISMATCH`.
struct LockVerifyReport {
    verified: usize,
    downloaded: usize,
    missing: Vec<VerifyTarget>,
    corrupt: Vec<VerifyTarget>,
    no_checksum: Vec<UnpinnedTarget>,
    untrusted_origin: Vec<VerifyTarget>,
    pin_mismatch: Vec<VerifyTarget>,
    workspace_skipped: Vec<WorkspaceSkip>,
    /// `-v`: text lists each skipped workspace entry, not only their count.
    list_workspace: bool,
}

impl LockVerifyReport {
    fn has_findings(&self) -> bool {
        !(self.missing.is_empty()
            && self.corrupt.is_empty()
            && self.no_checksum.is_empty()
            && self.untrusted_origin.is_empty()
            && self.pin_mismatch.is_empty())
    }

    /// The trailing clauses appear only when present, so the common
    /// "X missing, Y corrupt" summary stays as it is.
    fn summary(&self) -> String {
        let mut summary = format!(
            "{} missing, {} corrupt",
            self.missing.len(),
            self.corrupt.len()
        );
        for (count, what) in [
            (self.no_checksum.len(), "with no checksum recorded"),
            (self.untrusted_origin.len(), "from an untrusted origin"),
            (
                self.pin_mismatch.len(),
                "whose download did not match the recorded checksum",
            ),
        ] {
            if count > 0 {
                summary.push_str(&format!(", {count} {what}"));
            }
        }
        summary
    }

    /// What to do about the findings. Missing and corrupt files are a store
    /// problem that a download repairs; an untrusted origin or an unpinned
    /// row is a stale lock; a pin mismatch is the repository's.
    fn hint(&self) -> String {
        let mut hints = Vec::new();
        if !(self.missing.is_empty() && self.corrupt.is_empty()) {
            hints.push(format!(
                "run '{}' or '{}' to fetch them",
                crate::output::command_line("lock verify --download"),
                crate::output::command_line("sync")
            ));
        }
        if !(self.untrusted_origin.is_empty() && self.no_checksum.is_empty()) {
            hints.push(format!(
                "run '{}' to update raeva.lock",
                crate::output::command_line("sync")
            ));
        }
        if !self.pin_mismatch.is_empty() {
            hints.push(
                "a repository served other bytes than raeva.lock pins; the store is unchanged. \
                 Ask the publisher or the mirror's operator why before running 'raeva sync --update'"
                    .to_string(),
            );
        }
        hints.join("; ")
    }

    fn render_findings(&self, human: &mut Human<'_>) -> io::Result<()> {
        human.heading("Lock verification failed")?;
        for target in &self.missing {
            human.warning(format!(
                "  missing {} ({})",
                target.target.key,
                module_attribution(&target.target.modules)
            ))?;
        }
        for target in &self.corrupt {
            let found = target
                .actual
                .as_ref()
                .map(|actual| format!("found {actual}; "))
                .unwrap_or_default();
            human.warning(format!(
                "  corrupt {} ({found}{})",
                target.target.key,
                module_attribution(&target.target.modules)
            ))?;
        }
        for target in &self.no_checksum {
            human.warning(format!(
                "  no checksum recorded for {} ({})",
                target.key,
                module_attribution(&target.modules)
            ))?;
        }
        for target in &self.untrusted_origin {
            human.warning(format!(
                "  untrusted origin {} recorded for {}; not downloaded, since neither the \
                 configuration nor the project's POMs declare it ({})",
                rv_lock::redact_origin(target.target.repo_url()),
                target.target.key,
                module_attribution(&target.target.modules)
            ))?;
        }
        for target in &self.pin_mismatch {
            human.warning(format!(
                "  downloaded bytes for {} do not match the recorded checksum{}; \
                 discarded, store left unchanged ({})",
                target.target.key,
                target
                    .actual
                    .as_ref()
                    .map(|actual| format!(" (got {actual})"))
                    .unwrap_or_default(),
                module_attribution(&target.target.modules)
            ))?;
        }
        Ok(())
    }

    fn render_workspace_skips(&self, human: &mut Human<'_>) -> io::Result<()> {
        let skipped = &self.workspace_skipped;
        if skipped.is_empty() {
            return Ok(());
        }
        let entries = crate::commands::util::plural(skipped.len(), "entry", "entries");
        let more = if self.list_workspace {
            ""
        } else {
            " (-v lists them)"
        };
        human.note(format!(
            "  skipped {entries} for reactor modules, which the build makes{more}"
        ))?;
        if !self.list_workspace {
            return Ok(());
        }
        for entry in skipped {
            human.note(format!(
                "    {} -> {} ({})",
                entry.module, entry.workspace_module, entry.coordinate
            ))?;
        }
        Ok(())
    }
}

impl CommandOutput for LockVerifyReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "verified": self.verified,
            "missing": self.missing.len(),
            "corrupt": self.corrupt.len(),
            "no_checksum": self.no_checksum.len(),
            "untrusted_origin": self.untrusted_origin.len(),
            "pin_mismatch": self.pin_mismatch.len(),
            "downloaded": self.downloaded,
            "workspace_skipped": self.workspace_skipped.len(),
            "workspace_entries": workspace_json(&self.workspace_skipped),
            "missing_artifacts": verify_targets_json(&self.missing),
            "corrupt_artifacts": verify_targets_json(&self.corrupt),
            "no_checksum_artifacts": unpinned_targets_json(&self.no_checksum),
            "untrusted_origin_artifacts": untrusted_origin_json(&self.untrusted_origin),
            "pin_mismatch_artifacts": verify_targets_json(&self.pin_mismatch),
        }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        if self.has_findings() {
            self.render_findings(human)?;
        } else if self.downloaded > 0 {
            human.success(format!("verified {} files", self.verified))?;
        } else {
            human.success("lockfile verified")?;
        }
        self.render_workspace_skips(human)
    }
}

/// Pre-compute the per-package verification inputs for the parallel stage.
///
/// Inputs come from the canonical artifact table. Module graphs only
/// restrict that union and attach reachability diagnostics; workspace and
/// system nodes never become store lookups.
fn prepare_targets(
    lock: &Lockfile,
    selector: &ModuleSelector,
) -> Result<(Vec<PreparedTarget>, Vec<UnpinnedTarget>, Vec<WorkspaceSkip>)> {
    let mut artifacts = BTreeMap::<ArtifactCoord, (Vec<Origin>, BTreeSet<String>)>::new();
    let mut workspace_skipped = BTreeSet::new();

    for platform in &lock.platforms {
        let selection = selector.select(platform)?;
        let mut reachable = BTreeMap::<ArtifactCoord, BTreeSet<String>>::new();
        for module in selection.modules() {
            for package in &module.packages {
                if let Some(workspace_module) = package.workspace_module.as_deref() {
                    workspace_skipped.insert(WorkspaceSkip {
                        module: module.path.clone(),
                        workspace_module: workspace_module.to_string(),
                        coordinate: package.coordinate.to_string(),
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
        // A plugin table's files are those of the modules that build with
        // them; a set that names none, as a trace, is the whole build's.
        for set in platform.plugins.iter().flat_map(|tables| &tables.sets) {
            for module in (selection.modules().iter())
                .filter(|module| set.modules.is_empty() || set.modules.contains(&module.path))
            {
                for coordinate in &set.artifacts {
                    (reachable.entry(coordinate.clone()).or_default()).insert(module.path.clone());
                }
            }
        }

        for artifact in &platform.artifacts {
            let Some(modules) = reachable.get(&artifact.coordinate) else {
                continue;
            };
            // `pom` packaging is verified like any other row. Only an explicit
            // `<type>pom</type>` dependency reaches the artifact table;
            // imported BOMs and parent POMs are support material with no row,
            // added below. `Lockfile::read` refuses platforms that pin one
            // coordinate to different files, so the rows agree. Export also
            // needs the companion POM each row pins, fetched from the
            // origins that served it.
            let pom = artifact.pom_sha256.as_ref().map(|sha256| {
                let mut origins = artifact.pom_origins();
                let first = origins.next().unwrap_or(&artifact.repo_url);
                let mut pom = LockArtifact::new(artifact.coordinate.pom(), first);
                pom.other_repo_urls = origins.map(str::to_string).collect();
                pom.checksums = vec![Digest::Sha256(sha256.clone())];
                pom.snapshot = artifact.pom_build().cloned();
                pom
            });
            for artifact in std::iter::once(artifact.clone()).chain(pom) {
                let (origins, owners) = artifacts.entry(artifact.coord()).or_default();
                origins.push(Origin::Row(artifact, platform.platform.clone()));
                owners.extend(modules.iter().cloned());
            }
        }

        // A build extension's jar records no repository, so only the
        // resolution fetches it again.
        for module in selection.modules() {
            let jars = (module.extensions.iter()).filter(|jar| {
                !rv_maven_types::resolves_through_snapshot_metadata(jar.gav.version())
            });
            for jar in jars {
                let key = jar.coord();
                let (origins, owners) = artifacts.entry(key).or_default();
                origins.push(Origin::Extension(
                    jar.sha256.clone(),
                    platform.platform.clone(),
                ));
                owners.insert(module.path.clone());
            }
        }

        // Export needs the parent POMs and imported BOMs the lock pins. They
        // are attributed to no module, so every selection checks them.
        for (coord, pin) in &platform.support_poms {
            let Some(gav) = pin.file_gav(coord) else {
                continue;
            };
            let origin = Origin::Support(coord.clone(), pin.clone(), platform.platform.clone());
            (artifacts
                .entry(ArtifactCoord::of(gav, "pom", None))
                .or_default()
                .0)
                .push(origin);
        }
    }

    let mut targets = Vec::new();
    let mut no_checksum = Vec::new();
    for (key, (origins, modules)) in artifacts {
        let modules = modules.into_iter().collect();
        let expected = match &origins[0] {
            Origin::Row(artifact, _) => artifact.pin().cloned(),
            Origin::Support(_, pin, _) => Some(Digest::Sha256(pin.sha256.clone())),
            Origin::Extension(sha256, _) => Some(Digest::Sha256(sha256.clone())),
        };
        let Some(expected) = expected else {
            no_checksum.push(UnpinnedTarget { key, modules });
            continue;
        };
        targets.push(PreparedTarget {
            origins,
            key,
            expected,
            modules,
        });
    }
    Ok((
        targets,
        no_checksum,
        workspace_skipped.into_iter().collect(),
    ))
}

/// What [`download_and_verify`] did with one file.
enum Downloaded {
    Verified,
    Mismatch(Option<String>),
    Untrusted,
}

/// [`download_from_owners`] for every target, `parallelism` at a time.
async fn download_targets(
    store: &Store,
    lock: &Lockfile,
    contexts: &[crate::commands::sync::LockDownloadContext],
    targets: Vec<VerifyTarget>,
    parallelism: usize,
) -> Vec<(Result<Downloaded>, VerifyTarget)> {
    let contexts: Vec<_> = contexts
        .iter()
        .map(|context| context.as_restore())
        .collect();
    // In the targets' order, while a slow download holds only its own slot.
    let mut downloads: Vec<_> = stream::iter(targets.into_iter().enumerate())
        .map(|(index, target)| {
            let contexts = &contexts;
            async move {
                let outcome = download_from_owners(store, lock, contexts, &target.target).await;
                (index, (outcome, target))
            }
        })
        .buffer_unordered(parallelism)
        .collect()
        .await;
    downloads.sort_unstable_by_key(|(index, _)| *index);
    downloads
        .into_iter()
        .map(|(_, download)| download)
        .collect()
}

/// [`download_and_verify`] through each platform that pins the file until
/// one restores it. A mismatch is reported first, then a failure, then an
/// untrusted origin.
async fn download_from_owners(
    store: &Store,
    lock: &Lockfile,
    contexts: &[rv_repo::RestoreContext<'_>],
    target: &PreparedTarget,
) -> Result<Downloaded> {
    let context = |origin: &Origin| {
        contexts
            .iter()
            .find(|context| context.platforms.contains(origin.platform()))
            .expect("target platform has a download context")
    };
    let mut outcomes = Vec::new();
    for (index, origin) in target.origins.iter().enumerate() {
        match download_and_verify(store, context(origin), origin, target).await {
            Ok(Downloaded::Verified) => {
                // The stored file is indexed under each other platform's
                // repository too, for its offline resolution, as a sync
                // restore indexes it.
                for (other, origin) in target.origins.iter().enumerate() {
                    if other == index {
                        continue;
                    }
                    let owner = context(origin);
                    let _ = match origin {
                        Origin::Support(coord, pin, _) => {
                            let owner = std::slice::from_ref(owner);
                            rv_repo::ensure_support_pom(store, owner, coord, pin).await
                        }
                        Origin::Row(artifact, _) => {
                            rv_repo::index_restored(store, lock, owner, artifact).await
                        }
                        Origin::Extension(..) => Ok(()),
                    };
                }
                return Ok(Downloaded::Verified);
            }
            outcome => outcomes.push(outcome),
        }
    }
    let rank = |outcome: &Result<Downloaded>| match outcome {
        Ok(Downloaded::Mismatch(_)) => 0,
        Err(_) => 1,
        _ => 2,
    };
    outcomes.sort_by_key(rank);
    outcomes.into_iter().next().expect("a target has an origin")
}

/// Fetch one file as a restore does, checking the bytes against the
/// lockfile pin while they stream. Only bytes that match the pin enter the
/// store, and the index row is written under the same store lock that
/// publishes them, so a failed pin check leaves the artifact key resolving to
/// exactly what it resolved to before (the original blob, or nothing) and no
/// new blob on disk.
async fn download_and_verify(
    store: &Store,
    context: &rv_repo::RestoreContext<'_>,
    origin: &Origin,
    target: &PreparedTarget,
) -> Result<Downloaded> {
    let fetched = match origin {
        Origin::Support(coord, pin, _) => {
            rv_repo::ensure_support_pom(store, std::slice::from_ref(context), coord, pin).await
        }
        Origin::Row(artifact, _) => {
            rv_repo::restore_pinned(
                store,
                context,
                artifact.file_origins(),
                &target.key,
                &target.expected,
            )
            .await
        }
        Origin::Extension(..) => return Ok(Downloaded::Untrusted),
    };
    match fetched {
        Ok(()) => {
            let blob = match &target.expected {
                Digest::Sha256(blob) => Some(blob.clone()),
                _ => store.lookup_artifact(&target.key).await?,
            };
            let Some(blob) = blob else {
                return Err(RepoError::NotFound(target.key.to_string().into()).into());
            };
            for digest in target.digests() {
                match store.check_pin_async(&blob, &digest).await? {
                    PinCheck::Match => {}
                    PinCheck::Mismatch { actual } => return Ok(Downloaded::Mismatch(Some(actual))),
                    PinCheck::Missing => {
                        return Err(RepoError::NotFound(target.key.to_string().into()).into());
                    }
                }
            }
            Ok(Downloaded::Verified)
        }
        Err(RepoError::ChecksumMismatch {
            check: IntegritySource::LockPin,
            actual,
            ..
        }) => Ok(Downloaded::Mismatch(Some(actual.hex().to_string()))),
        Err(RepoError::UntrustedRepoUrl(_)) => Ok(Downloaded::Untrusted),
        Err(err) => Err(err.into()),
    }
}

#[derive(Debug)]
struct PreparedTarget {
    /// Every platform row that pins the file, in lock order. The pins
    /// agree; the recorded repositories need not.
    origins: Vec<Origin>,
    key: ArtifactCoord,
    expected: Digest,
    modules: Vec<String>,
}

impl PreparedTarget {
    /// The pin, then each other digest a row records, which must name the
    /// file too.
    fn digests(&self) -> Vec<Digest> {
        let mut digests = vec![self.expected.clone()];
        for origin in &self.origins {
            let Origin::Row(artifact, _) = origin else {
                continue;
            };
            for digest in &artifact.checksums {
                if !digests.contains(digest) {
                    digests.push(digest.clone());
                }
            }
        }
        digests
    }

    fn repo_url(&self) -> &str {
        (self.origins.iter())
            .find_map(|origin| match origin {
                Origin::Row(artifact, _) => Some(artifact.repo_url.as_str()),
                Origin::Support(_, pin, _) => Some(pin.repo_url.as_str()),
                Origin::Extension(..) => None,
            })
            .unwrap_or_default()
    }

    /// Whether only build extensions pin the file, which records no origin
    /// a download could take.
    fn extension_only(&self) -> bool {
        (self.origins.iter()).all(|origin| matches!(origin, Origin::Extension(..)))
    }
}

/// Where a file comes from: an artifact row (or its companion POM), a
/// support POM with its coordinate, or a build extension jar with its pin,
/// on the platform that records it.
#[derive(Debug)]
enum Origin {
    Row(LockArtifact, Platform),
    Support(String, SupportPom, Platform),
    Extension(rv_maven_types::Sha256, Platform),
}

impl Origin {
    fn platform(&self) -> &Platform {
        match self {
            Self::Row(_, platform)
            | Self::Support(_, _, platform)
            | Self::Extension(_, platform) => platform,
        }
    }
}

#[derive(Debug)]
struct UnpinnedTarget {
    key: ArtifactCoord,
    modules: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct WorkspaceSkip {
    module: String,
    workspace_module: String,
    coordinate: String,
}

fn module_attribution(modules: &[String]) -> String {
    if modules.is_empty() {
        return "a parent POM or imported BOM".to_string();
    }
    format!("reachable from {}", modules.join(", "))
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

/// Untrusted-origin findings carry the offending `repo_url`, redacted, so the
/// operator can tell whether the lockfile records a repository they dropped
/// from `raeva.toml` or one they have never seen.
fn untrusted_origin_json(targets: &[VerifyTarget]) -> Vec<serde_json::Value> {
    targets
        .iter()
        .map(|target| {
            serde_json::json!({
                "coordinate": target.target.key.to_string(),
                "repo_url": rv_lock::redact_origin(target.target.repo_url()),
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

#[derive(Debug)]
struct VerifyTarget {
    target: PreparedTarget,
    actual: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A reactor's workspace entries are counted, and listed only at `-v`.
    #[test]
    fn workspace_entries_are_listed_only_when_verbose() {
        let mut report = LockVerifyReport {
            verified: 1,
            downloaded: 0,
            missing: Vec::new(),
            corrupt: Vec::new(),
            no_checksum: Vec::new(),
            untrusted_origin: Vec::new(),
            pin_mismatch: Vec::new(),
            workspace_skipped: vec![WorkspaceSkip {
                module: "app/pom.xml".to_string(),
                workspace_module: "lib/pom.xml".to_string(),
                coordinate: "com.example:lib:jar:1".to_string(),
            }],
            list_workspace: false,
        };
        let render = |report: &LockVerifyReport| {
            crate::output::testing::render(false, |human| report.render_human(human)).1
        };
        assert_eq!(
            render(&report),
            "lockfile verified\n  skipped 1 entry for reactor modules, which the build makes \
             (-v lists them)\n"
        );
        report.list_workspace = true;
        assert!(
            render(&report).ends_with(
                "which the build makes\n    app/pom.xml -> lib/pom.xml (com.example:lib:jar:1)\n"
            ),
            "{}",
            render(&report)
        );
    }

    fn publish(root: &std::path::Path, coord: &ArtifactCoord, bytes: &[u8]) {
        let path = root.join(format!(
            "com/example/{}/1.0/{}-1.0.{}",
            coord.artifact_id(),
            coord.artifact_id(),
            coord.extension()
        ));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn repair_lock(url: &str) -> Lockfile {
        let mut row = lock_package(
            "demo",
            "jar",
            Some(Digest::Sha256(rv_maven_types::BlobId::from_bytes(b"jar"))),
        );
        row.repo_url = url.to_string();
        row.pom_sha256 = Some(rv_maven_types::BlobId::from_bytes(b"pom"));
        let mut lock = lock_with_packages(vec![row]);
        lock.platforms[0].support_poms.insert(
            "com.example:parent:1.0".to_string(),
            SupportPom::new(url, rv_maven_types::BlobId::from_bytes(b"parent")),
        );
        lock
    }

    async fn repair(config: &Config) -> LockVerifyReport {
        verify_inner(
            &LockVerifyArgs {
                download: true,
                module: ModuleSelector::default(),
            },
            config,
            false,
            &Output::for_tests(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn download_from_configured_repository_ignores_missing_reactor_module() {
        let repo = TempDir::new().unwrap();
        let url = url::Url::from_directory_path(repo.path()).unwrap();
        let (project, config) = config_with_repo(url.as_str());
        fs::write(
            project.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
             <artifactId>demo</artifactId><version>1</version><packaging>pom</packaging>\
             <modules><module>missing</module></modules></project>",
        )
        .unwrap();
        let mut row = lock_package(
            "demo",
            "jar",
            Some(Digest::Sha256(rv_maven_types::BlobId::from_bytes(b"jar"))),
        );
        row.repo_url = url.to_string();
        row.pom_sha256 = Some(rv_maven_types::BlobId::from_bytes(b"pom"));
        publish(repo.path(), &row.coord(), b"jar");
        let lock = lock_with_packages(vec![row]);
        write_lock(lock, &config);
        let store = Store::open(&config.paths.store_dir).unwrap();
        store.put_bytes(b"pom").await.unwrap();
        let blob = store.put_bytes(b"jar").await.unwrap();
        fs::remove_file(store.get_path(&blob)).unwrap();

        let report = repair(&config).await;
        assert!(!report.has_findings(), "{}", report.summary());
        assert_eq!((report.downloaded, report.verified), (1, 2));
        assert_eq!(
            store
                .check_pin(&blob, &Digest::Sha256(blob.clone()))
                .unwrap(),
            PinCheck::Match
        );
    }

    #[tokio::test]
    async fn download_offline_discovers_trust_only_for_repair_targets() {
        let repo = TempDir::new().unwrap();
        let url = url::Url::from_directory_path(repo.path()).unwrap();
        for pom_declared in [false, true] {
            let (project, config) = config_with_repo(if pom_declared {
                "https://configured.example/m2/"
            } else {
                url.as_str()
            });
            fs::write(
                project.path().join("pom.xml"),
                format!(
                    "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
                     <artifactId>demo</artifactId><version>1</version>\
                     <repositories><repository><id>local</id><url>{url}</url></repository></repositories>\
                     <dependencies><dependency><groupId>com.example</groupId>\
                     <artifactId>uncached</artifactId><version>1.0</version></dependency></dependencies>\
                     </project>"
                ),
            )
            .unwrap();
            let mut row = lock_package(
                "demo",
                "jar",
                Some(Digest::Sha256(rv_maven_types::BlobId::from_bytes(b"jar"))),
            );
            row.repo_url = url.to_string();
            row.pom_sha256 = Some(rv_maven_types::BlobId::from_bytes(b"pom"));
            publish(repo.path(), &row.coord(), b"jar");
            let mut verified = lock_package(
                "verified",
                "jar",
                Some(Digest::Sha256(rv_maven_types::BlobId::from_bytes(
                    b"verified",
                ))),
            );
            verified.repo_url = "https://transitive.example/m2/".to_string();
            verified.pom_sha256 = row.pom_sha256.clone();
            write_lock(lock_with_packages(vec![row, verified]), &config);
            let store = Store::open(&config.paths.store_dir).unwrap();
            store.put_bytes(b"pom").await.unwrap();
            store.put_bytes(b"verified").await.unwrap();

            let report = verify_inner(
                &LockVerifyArgs {
                    download: true,
                    module: ModuleSelector::default(),
                },
                &config,
                true,
                &Output::for_tests(),
            )
            .await
            .unwrap();
            assert!(!report.has_findings(), "{}", report.summary());
            assert_eq!((report.downloaded, report.verified), (1, 4));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_repairs_rows_and_support_poms_with_unchanged_stamps() {
        use std::os::unix::fs::MetadataExt;

        let repo = TempDir::new().unwrap();
        let url = url::Url::from_directory_path(repo.path()).unwrap();
        for sha1 in [false, true] {
            let (_temp, config) = config_with_repo(url.as_str());
            let mut lock = repair_lock(url.as_str());
            if sha1 {
                lock.platforms[0].artifacts[0].checksums = vec![Digest::of_bytes(
                    rv_maven_types::HashAlgorithm::Sha1,
                    b"jar",
                )];
            }
            let lock = write_lock(lock, &config);
            let store = Store::open(&config.paths.store_dir).unwrap();
            let (targets, _, _) = prepare_targets(&lock, &ModuleSelector::default()).unwrap();
            for (target, bytes) in targets.iter().zip([b"jar".as_slice(), b"pom", b"parent"]) {
                publish(repo.path(), &target.key, bytes);
                let blob = store.put_bytes(bytes).await.unwrap();
                store.add_artifact(&target.key, &blob).await.unwrap();
                let path = store.get_path(&blob);
                fs::remove_file(&path).unwrap();
                fs::write(&path, vec![b'x'; bytes.len()]).unwrap();
                let meta = fs::metadata(&path).unwrap();
                // Model bit rot by retaining a checked stamp for the corrupt bytes.
                let stamp = format!(
                    "{} {} {} {}.{} {}.{}",
                    meta.dev(),
                    meta.ino(),
                    meta.size(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                    meta.ctime(),
                    meta.ctime_nsec()
                );
                rusqlite::Connection::open(config.paths.store_dir.join("index.sqlite"))
                    .unwrap()
                    .execute(
                        "INSERT OR REPLACE INTO checked_blobs (blob_id, stamp) VALUES (?1, ?2)",
                        rusqlite::params![blob.as_str(), stamp],
                    )
                    .unwrap();
                if !sha1 || target.key.extension() == "pom" {
                    assert_eq!(
                        store
                            .check_pin_unless_unchanged(&blob, &target.expected)
                            .unwrap(),
                        PinCheck::Match
                    );
                }
            }
            let report = repair(&config).await;
            assert!(!report.has_findings(), "{}", report.summary());
            assert_eq!((report.downloaded, report.verified), (3, 3));
            for target in targets {
                let blob = store.lookup_artifact(&target.key).await.unwrap().unwrap();
                assert_eq!(
                    store.check_pin(&blob, &target.expected).unwrap(),
                    PinCheck::Match
                );
            }
        }
    }

    /// A download that matches the pin but not a row's other digest does
    /// not count as a repair.
    #[tokio::test]
    async fn download_checks_every_digest_a_row_records() {
        let repo = TempDir::new().unwrap();
        let url = url::Url::from_directory_path(repo.path()).unwrap();
        let (_temp, config) = config_with_repo(url.as_str());
        let mut lock = repair_lock(url.as_str());
        let sha1 = Digest::of_bytes(rv_maven_types::HashAlgorithm::Sha1, b"other");
        lock.platforms[0].artifacts[0].checksums.push(sha1);
        let lock = write_lock(lock, &config);
        let (targets, _, _) = prepare_targets(&lock, &ModuleSelector::default()).unwrap();
        for (target, bytes) in targets.iter().zip([b"jar".as_slice(), b"pom", b"parent"]) {
            publish(repo.path(), &target.key, bytes);
        }
        let report = repair(&config).await;
        assert!(report.has_findings(), "{}", report.summary());
        assert_eq!(report.downloaded, 2, "{}", report.summary());
    }

    #[tokio::test]
    async fn download_uses_foreign_platform_settings_for_rows_and_support_poms() {
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let repo = TempDir::new().unwrap();
        let empty = TempDir::new().unwrap();
        let url = url::Url::from_directory_path(repo.path()).unwrap();
        let empty_url = url::Url::from_directory_path(empty.path()).unwrap();
        let (family, other, checked_family) = if cfg!(windows) {
            ("unix", "linux", "windows")
        } else {
            ("windows", "windows", "unix")
        };
        fs::create_dir(home.path().join(".m2")).unwrap();
        fs::write(home.path().join(".m2/settings.xml"), format!(
            "<settings><profiles><profile><id>other</id><activation><os><family>{family}</family></os></activation><repositories><repository><id>configured</id><url>{url}</url></repository></repositories></profile><profile><id>checked</id><activation><os><family>{checked_family}</family></os></activation><repositories><repository><id>configured</id><url>{empty_url}</url></repository></repositories></profile></profiles></settings>"
        )).unwrap();
        let config = temp_env::with_vars(
            [
                ("RAEVA_HOME", Some(home.path())),
                (rv_config::MAVEN_USER_HOME_TEST_ENV, Some(home.path())),
            ],
            || Config::load(project.path()).unwrap(),
        );
        assert!(
            config
                .repositories()
                .iter()
                .all(|repo| repo.url != url.as_str())
        );
        let mut lock = repair_lock(url.as_str());
        lock.platforms[0].platform = Platform::new(other, "x86_64").unwrap();
        lock.platforms.push(rv_lock::LockPlatform::single_module(
            Platform::current().unwrap(),
            rv_maven_types::Gav::new("com.example", "demo", "1"),
            "jar",
            Vec::new(),
        ));
        let lock = write_lock(lock, &config);
        let (targets, _, _) = prepare_targets(&lock, &ModuleSelector::default()).unwrap();
        for (target, bytes) in targets.iter().zip([b"jar".as_slice(), b"pom", b"parent"]) {
            publish(repo.path(), &target.key, bytes);
        }
        let report = repair(&config).await;
        assert!(!report.has_findings(), "{}", report.summary());
        assert_eq!((report.downloaded, report.verified), (3, 3));
    }

    fn lock_with_packages(packages: Vec<LockArtifact>) -> Lockfile {
        let platform = rv_lock::Platform::new("linux", "x86_64").unwrap();
        let mut lock = Lockfile::new();
        lock.platforms = vec![rv_lock::LockPlatform::single_module(
            platform,
            rv_maven_types::Gav::new("com.example", "demo", "1"),
            "jar",
            packages,
        )];
        lock
    }

    fn lock_package(artifact: &str, packaging: &str, checksum: Option<Digest>) -> LockArtifact {
        let mut artifact = LockArtifact::new(
            ArtifactCoord::new("com.example", artifact, "1.0", packaging, None),
            "https://repo.example/m2/",
        );
        artifact.checksums = checksum.into_iter().collect();
        artifact
    }

    const SHA256_A: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    /// A row's SHA-1 beside its SHA-256 must name the file too.
    #[tokio::test]
    async fn every_digest_a_row_records_is_checked() {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let blob = store.put_bytes(b"jar").await.unwrap();
        for (bytes, matched) in [(b"jar".as_slice(), true), (b"other", false)] {
            let mut row = lock_package("demo", "jar", Some(Digest::Sha256(blob.clone())));
            let sha1 = Digest::of_bytes(rv_maven_types::HashAlgorithm::Sha1, bytes);
            row.checksums.push(sha1);
            let lock = lock_with_packages(vec![row]);
            let (targets, _, _) = prepare_targets(&lock, &ModuleSelector::default()).unwrap();
            let checked = check_pins(&store, targets, 1).await.unwrap();
            assert_eq!(
                checked[0].1 == PinCheck::Match,
                matched,
                "{:?}",
                checked[0].1
            );
        }
    }

    #[test]
    fn snapshot_pom_verification_uses_its_own_build() {
        let mut row = lock_package(
            "nat",
            "jar",
            Some(Digest::parse("sha256", SHA256_A).unwrap()),
        );
        row.coordinate =
            ArtifactCoord::new("com.example", "nat", "1.0-SNAPSHOT", "jar", Some("linux"));
        row.snapshot = rv_maven_types::SnapshotStamp::new("20261012.010101", 2);
        row.pom_snapshot = rv_maven_types::SnapshotStamp::new("20261012.010101", 1);
        row.pom_sha256 = Some(SHA256_A.parse().unwrap());
        let lock = lock_with_packages(vec![row]);
        let (targets, no_checksum, _) = prepare_targets(&lock, &ModuleSelector::default()).unwrap();
        assert!(no_checksum.is_empty());
        assert_eq!(targets.len(), 2);
        let pom = targets
            .iter()
            .find(|target| target.key.extension() == "pom")
            .unwrap();
        assert_eq!(pom.key.version(), "1.0-20261012.010101-1");
        let jar = targets
            .iter()
            .find(|target| target.key.extension() == "jar")
            .unwrap();
        assert_eq!(jar.key.version(), "1.0-20261012.010101-2");
    }

    /// An explicit `<type>pom</type>` dependency owns an artifact-table row and
    /// is pinned like any other artifact, so it must be verified rather than
    /// skipped: a deleted or corrupted explicit POM otherwise survives verify
    /// and only surfaces when `raeva export-m2` trips over it. System-path
    /// packages are still skipped; they are never stored.
    #[test]
    fn prepare_targets_verifies_pom_packaging_and_skips_system_path_packages() {
        let mut lock = lock_with_packages(vec![
            lock_package(
                "pom-dep",
                "pom",
                Some(rv_maven_types::Digest::parse("sha256", SHA256_A).unwrap()),
            ),
            lock_package("pom-no-pin", "pom", None),
            lock_package(
                "real",
                "jar",
                Some(rv_maven_types::Digest::parse("sha256", SHA256_A).unwrap()),
            ),
        ]);
        let mut local = rv_lock::LockModulePackage::new(
            ArtifactCoord::new("com.example", "local", "1.0", "jar", None),
            Some(rv_lock::Scope::System),
        );
        local.system_path = Some("/opt/local.jar".to_string());
        lock.platforms[0].modules[0].packages.push(local);
        let (targets, no_checksum, _) =
            prepare_targets(&lock, &ModuleSelector::default()).expect("prepare targets");
        let verified: Vec<&str> = targets
            .iter()
            .map(|target| target.key.artifact_id())
            .collect();
        assert_eq!(verified, vec!["pom-dep", "real"]);
        let unpinned: Vec<String> = no_checksum
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

    /// Write `lock` with its origins as a sync of `config`'s project records
    /// them.
    fn write_lock(mut lock: Lockfile, config: &Config) -> Lockfile {
        let origins = rv_lock::LockOrigins::for_root(&config.project_root);
        lock.relativize_origins(&origins).unwrap();
        lock.write_atomic(&config.lock_path).unwrap();
        lock
    }

    fn config_with_repo(url: &str) -> (TempDir, Config) {
        let temp = TempDir::new().expect("temp dir");
        let paths = rv_config::ResolvedPaths::for_testing().expect("paths");
        let mut repo = rv_config::RepoConfig::new(Some("configured"), url);
        repo.releases = Some(true);
        repo.snapshots = Some(false);
        repo.snapshots_update_policy = Some(rv_config::UpdatePolicy::Daily);
        let config = Config::for_testing_with_repos(temp.path().to_path_buf(), paths, vec![repo]);
        (temp, config)
    }

    /// `skip_serializing_if` fields are absent from the json-payloads
    /// snapshots. Serializing a full report still requires them in the docs.
    /// Serialize structs in this file are the lock-info payload.
    #[test]
    fn the_docs_name_every_lock_info_field() {
        let keys =
            rv_test_support::fixtures::serde_serialize_fields(include_str!("lock_verify.rs"));
        let docs = rv_test_support::fixtures::workspace_file("docs/json-output.md");
        let section = rv_test_support::fixtures::markdown_section(&docs, "## `raeva lock info`");
        rv_test_support::fixtures::assert_markdown_names(
            section,
            "docs/json-output.md lock info section",
            &keys,
        );
    }
}
