mod disk;
mod download;
mod drift;
mod merge;
mod mode;
mod plugins;
mod regenerate;
mod resolve;
mod trace;
pub(crate) use drift::lock_needs_fresh_resolution;
use mode::Intent;
pub(crate) use mode::Mode;
pub(crate) use plugins::{
    check_frozen as check_frozen_plugins, check_held as check_plugin_tables,
    check_resolved as check_resolved_plugins, check_traced as check_plugin_trace,
};
pub(crate) use resolve::{
    WORKSPACE_STALL_TIMEOUT_ENV, count_stored, platform_clients, platform_configs,
    resolution_trust, restore_contexts, validate_frozen_resolution,
};
pub(crate) use trace::traced_on;
#[cfg(test)]
pub(crate) use {plugins::inputs_digest, trace::trace_key};
mod system_scope;
#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use clap::{ArgAction, Args};

use rv_config::Config;
use rv_lock::{LockOrigins, Lockfile, LockfileGuard, Platform};
use rv_repo::{RepoClient, Repository, RestoreContext};
use rv_store::Store;
use rv_store::metadata_cache::SnapshotCheck;

use crate::commands::util::{count_dependencies, read_lockfile_at};
use crate::commands::{lock_diff as diff, read_lockfile};
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Output, Report};
use crate::session::Session;

use self::diff::lock_diff;
use self::disk::check_disk_space;
use self::download::ensure_artifacts;
use self::drift::{lock_references_unconfigured_origin, lock_requires_snapshot_refresh};
use self::merge::merge_previous;
use self::resolve::{ResolvedReactorLock, check_origin_aliases, resolve_reactor_lock};
use self::system_scope::warn_system_scope_from_lock;
use crate::commands::lock_inputs::{
    ReactorModel, check_recorded_freshness, command_line_names, declared_repository_urls,
    discover_reactor_models, frozen_models_match, hides_host_directories, reads_hidden_env,
    recorded_ambient, resolution_config_hash,
};

#[derive(Debug, Args)]
#[command(
    after_long_help = crate::commands::util::help_examples(&[
        ("sync", "Resolve and lock dependencies"),
        ("sync --frozen", "CI mode: resolve again and fail on any difference"),
        ("sync --update", "Force fresh resolution"),
        ("sync --offline", "Use cached data and file repositories"),
        ("sync --platforms linux-x86_64,macos-aarch64", ""),
    ])
)]
pub(crate) struct SyncArgs {
    #[arg(
        long,
        short = 'f',
        help = "Resolve again and fail if the result differs from raeva.lock, keeping the locked \
                SNAPSHOT builds (CI mode)"
    )]
    pub frozen: bool,
    #[arg(
        long,
        short = 'u',
        conflicts_with = "frozen",
        help = "Re-resolve all dependencies, taking newer SNAPSHOT builds, and update raeva.lock"
    )]
    pub update: bool,
    #[arg(
        long,
        value_name = "OS-ARCH",
        action = ArgAction::Append,
        value_delimiter = ',',
        value_parser = crate::commands::parse_platform,
        help = "Resolve these os-arch pairs instead of the ones raeva.lock records, keeping other recorded platforms that still match (e.g., linux-x86_64,macos-aarch64)"
    )]
    pub platforms: Vec<Platform>,
    #[arg(
        long,
        help = "Accept files that have no server-published checksum sidecar and that raeva.lock does not pin (SUPPLY-CHAIN RISK: a hostile or misconfigured mirror could serve unverified bytes; off by default)"
    )]
    pub allow_missing_checksums: bool,
}

/// Refuse `raeva sync` run without `-C` in a directory that an enclosing
/// pom.xml lists as a module: it would write a second raeva.lock, which CI at
/// the reactor root never checks.
pub(crate) fn refuse_module_directory(root: &Path) -> Result<()> {
    let Some(reactor) = enclosing_reactor(root) else {
        return Ok(());
    };
    Err(CliError::Usage(format!(
        "this directory is a module of the Maven project in {}, whose raeva.lock covers \
         every module: run 'raeva -C {} sync', or 'raeva -C . sync' to lock this \
         directory on its own",
        reactor.display(),
        crate::commands::util::shell_word(&reactor.display().to_string())
    )))
}

/// The topmost directory whose pom.xml lists `root`'s pom.xml as a module,
/// directly or through the module POMs of the directories between them,
/// unless a raeva.lock or raeva.toml in `root` means it is locked on its own
/// on purpose.
pub(crate) fn enclosing_reactor(root: &Path) -> Option<PathBuf> {
    if ["raeva.lock", "raeva.toml"]
        .iter()
        .any(|name| root.join(name).exists())
        || !root.join("pom.xml").is_file()
    {
        return None;
    }
    let start = std::fs::canonicalize(root).ok()?;
    let member = start.join("pom.xml");
    // The POM files the literal top-level entries of `pom` name, with either
    // separator, as discovery reads them. A profile, even one active by
    // default, and a property may be switched off or overridden from outside
    // the POM, and a refusal must never be wrong; a miss only writes the
    // second lock.
    let entries = |pom: &Path| -> Vec<PathBuf> {
        // As discovery reads a POM: a regular file, of a bounded size.
        let read = || {
            pom.is_file()
                .then(|| rv_config::read_project_input(pom).ok())?
        };
        let (Some(dir), Some(bytes)) = (pom.parent(), read()) else {
            return Vec::new();
        };
        let Some(pom) = rv_maven_model::decode_pom(&bytes)
            .ok()
            .and_then(|text| rv_maven_model::Pom::parse(&text).ok())
        else {
            return Vec::new();
        };
        (pom.modules.iter())
            .map(|entry| entry.trim().replace('\\', "/"))
            .filter(|entry| !entry.contains("${"))
            .filter_map(|entry| std::fs::canonicalize(rv_fs::join_pom_entry(dir, &entry)).ok())
            .map(|path| {
                if path.is_dir() {
                    path.join("pom.xml")
                } else {
                    path
                }
            })
            .collect()
    };
    // An entry may skip a directory without a pom.xml, as `modules/io` does,
    // or name a module's POM file under another name, which may list
    // `member` in turn; only POM files in the directories above `member`
    // can.
    let reaches = |pom: PathBuf| {
        let mut seen = std::collections::HashSet::new();
        let mut pending = vec![pom];
        while let Some(pom) = pending.pop() {
            if !seen.insert(pom.clone()) {
                continue;
            }
            for listed in entries(&pom) {
                if listed == member {
                    return true;
                }
                if listed.parent().is_some_and(|dir| start.starts_with(dir)) {
                    pending.push(listed);
                }
            }
        }
        false
    };
    (start.ancestors().skip(1))
        .filter(|dir| reaches(dir.join("pom.xml")))
        .last()
        .map(rv_fs::plain_path)
}

pub(crate) async fn run(args: &SyncArgs, session: &Session) -> Result<Report> {
    let config = session.config_async().await?;
    // One timer for the whole run, so the JSON `duration_ms` and the
    // durations in text mode agree.
    let start = Instant::now();
    if let Some(trace) = config.plugin_trace() {
        trace.launcher(&config.project_root)?;
        if !args.frozen && !session.offline() {
            trace::check_forwarded(&config)?;
        }
    }
    let mut outcome = run_inner(
        args,
        session.offline(),
        session.project_root(),
        &config,
        start,
        session.output(),
    )
    .await?;
    // A failed trace may put back the lock the sync found, which the
    // SNAPSHOT check is not of.
    let mut record = outcome.snapshot_check.take();
    if (outcome.trace.as_ref()).is_none_or(|start| start.previous.is_none())
        && let Some(record) = record.take()
    {
        record();
    }
    // The trace runs the project's build, so never to check a lock.
    if !args.frozen && config.plugin_trace().is_some() {
        if let Some(start) = outcome.trace.take() {
            // `--update` drops the trace before it runs it again, so its
            // changes are those from the lock it found.
            let found = (start.previous.clone()).and_then(|bytes| {
                let lock = Lockfile::from_toml(&String::from_utf8_lossy(&bytes)).ok()?;
                Some((bytes, lock))
            });
            let before = lock_bytes(&config.lock_path);
            let traced = trace::trace(
                session,
                &config,
                start,
                args.update,
                args.allow_missing_checksums,
            )
            .await?;
            if let Some(written) = &traced {
                record_traced(&config, before.as_deref(), written).await;
            }
            match (traced, found) {
                (None, _) => {}
                (Some(written), Some((bytes, _)))
                    if written.to_toml().is_ok_and(|text| text.as_bytes() == bytes) =>
                {
                    outcome.headline = Headline::UpToDate;
                    outcome.changes.clear();
                }
                // The trace's platform may be one the sync did not resolve.
                (Some(written), Some((_, found))) => {
                    let platforms: Vec<Platform> = (found.platforms.iter())
                        .chain(&written.platforms)
                        .map(|entry| entry.platform.clone())
                        .collect();
                    let verbose = session.output().is_verbose();
                    outcome.headline = Headline::Updated;
                    outcome.changes = lock_diff(&found, &written, &platforms, verbose);
                }
                (Some(_), None) => {
                    outcome.headline = match outcome.headline {
                        Headline::Wrote => Headline::Wrote,
                        _ => Headline::Updated,
                    };
                    outcome.changes.push("  plugin trace added".to_string());
                }
            }
        } else if !trace::traced_here(&config, &read_lockfile_at(&config.lock_path)?.platforms)? {
            session.output().note(
                "raeva.lock has no trace of the build [plugins] trace names, which runs online \
                 only: run 'raeva sync' online",
            );
        }
    }
    if let Some(record) = record {
        record();
    }
    Ok(Report::data(SyncReport {
        outcome,
        elapsed: start.elapsed(),
    }))
}

struct SyncOutcome {
    dep_count: usize,
    /// The platforms this run checked or resolved.
    platforms: Vec<Platform>,
    changes: Vec<String>,
    headline: Headline,
    /// What the trace after an online sync starts from.
    trace: Option<trace::Start>,
    /// Records the SNAPSHOT check of the resolution.
    snapshot_check: Option<Box<dyn FnOnce() + Send>>,
}

enum Headline {
    /// `--frozen` resolved again and raeva.lock already held the result, or
    /// a plain sync reused it as written.
    Checked,
    /// `--frozen --offline`: the lock is current and the store has its
    /// files, this many, unhashed.
    CheckedStored(usize),
    /// Resolved, and raeva.lock already held the result.
    UpToDate,
    /// Resolved, and there was no raeva.lock.
    Wrote,
    Updated,
}

struct SyncReport {
    outcome: SyncOutcome,
    elapsed: std::time::Duration,
}

impl CommandOutput for SyncReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "resolved": self.outcome.dep_count,
            "platforms": (self.outcome.platforms.iter())
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "duration_ms": u64::try_from(self.elapsed.as_millis()).unwrap_or(u64::MAX),
        }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        let count = self.outcome.dep_count;
        let seconds = self.elapsed.as_secs_f32();
        let done = format!(
            "{} for {} in {seconds:.1}s",
            crate::commands::util::plural(count, "dependency", "dependencies"),
            platform_list(&self.outcome.platforms)
        );
        let changes = &self.outcome.changes;
        human.success(match self.outcome.headline {
            Headline::Checked => format!("Checked {done}; raeva.lock is up to date"),
            Headline::CheckedStored(files) => format!(
                "Checked {done}; raeva.lock is up to date and its {} are in the store \
                 ('raeva lock verify' hashes them)",
                crate::commands::util::plural(files, "pinned file", "pinned files")
            ),
            Headline::UpToDate => format!("Resolved {done}; raeva.lock is up to date"),
            Headline::Wrote => format!("Resolved {done} and wrote raeva.lock"),
            Headline::Updated if changes.is_empty() => {
                format!("Resolved {done} and updated raeva.lock")
            }
            Headline::Updated => format!("Resolved {done} and updated raeva.lock:"),
        })?;
        for line in changes {
            human.note(line)?;
        }
        if matches!(self.outcome.headline, Headline::Wrote) {
            human.note("Commit raeva.lock. CI checks it with 'raeva sync --frozen'.")?;
        }
        Ok(())
    }
}

async fn run_inner(
    args: &SyncArgs,
    offline: bool,
    project_root: &Path,
    config: &Config,
    start: Instant,
    output: &Output,
) -> Result<SyncOutcome> {
    let mode = Mode::sync(args, offline);
    tracing::info!(
        path = %project_root.display(),
        mode = match mode.intent() {
            Intent::Plain => "normal",
            Intent::Update => "update",
            Intent::Frozen => "frozen",
        },
        offline,
        "sync started"
    );

    let pom_path = config.project_root.join("pom.xml");
    let pom_exists = pom_path.is_file();

    // Held for the entire read-resolve-write sequence, and acquired before
    // the local --frozen checks so those checks read the same raeva.lock a
    // concurrent writer cannot rewrite. --frozen never writes raeva.lock;
    // the race is another process writing while this one keeps a pre-guard
    // snapshot. Local frozen checks still run before the store or metadata
    // cache open.
    let _lockfile_guard = lockfile_guard(config, project_root, output).await?;
    // `--update` drops the trace it runs again, which a failed build would
    // leave raeva.lock without.
    let previous = (args.update && config.plugin_trace().is_some())
        .then(|| lock_bytes(&config.lock_path))
        .flatten();
    let frozen = (args.frozen)
        .then(|| check_frozen_local(config, args, pom_exists, true))
        .transpose()?;
    // raeva.lock as it is under the guard: a plain sync takes the recorded
    // platforms from it, so it keeps a platform a concurrent sync just added,
    // and starts from it.
    let mut on_disk = (!args.frozen).then(|| read_lockfile_at(&config.lock_path));
    // A lock reused as it is is still written when its text is not raeva's.
    let written = match &on_disk {
        Some(Ok(lock)) if !args.update => Some(crate::commands::util::check_written(
            lock,
            &config.lock_path,
        )),
        _ => None,
    };
    // The dependency resolution neither reads nor writes the plugin tables.
    let held = match on_disk.as_mut() {
        Some(Ok(lock)) => plugins::strip(lock),
        _ => None,
    };
    let unreadable = match &on_disk {
        Some(Err(CliError::LockfileTooNew { found, expected })) => {
            return Err(CliError::LockfileTooNew {
                found: *found,
                expected: *expected,
            });
        }
        Some(Err(CliError::LockfileIncompatible { reason, .. })) => Some(
            regenerate::Unreadable::read(&config.lock_path, reason, args.update)?,
        ),
        _ => None,
    };
    let scoped;
    // Whether the run's client allows more than `platforms` need.
    let mut widened = false;
    let (platforms, config) = if let Some(checked) = frozen.as_ref() {
        // A changed model resolves every recorded platform, through the
        // repositories each one's settings allow.
        widened = offline || !checked.models_match;
        let grants: Vec<&Platform> = if widened {
            checked
                .lock
                .platforms
                .iter()
                .map(|entry| &entry.platform)
                .collect()
        } else {
            checked.platforms.iter().collect()
        };
        scoped = config.for_platforms(
            grants
                .iter()
                .map(|platform| (platform.os(), platform.arch(), platform.jdk())),
        );
        scoped.settings_activation()?;
        (checked.platforms.clone(), &scoped)
    } else {
        let mut requested = args.platforms.clone();
        let recorded = match (on_disk.as_ref(), unreadable.as_ref()) {
            (Some(Ok(lock)), _) => recorded_platforms(lock),
            // Nothing carries forward from a lock it cannot read, so the
            // platforms it records are resolved alongside `--platforms`.
            (_, Some(unreadable)) => {
                if !requested.is_empty() {
                    requested.extend(unreadable.platforms.iter().cloned());
                }
                unreadable.platforms.clone()
            }
            _ => Vec::new(),
        };
        let platforms = resolve_platforms(&requested, &recorded, &config.lock.jdks)?;
        // The recorded platforms this run keeps without resolving them fail
        // as the ones it resolves do.
        (config.for_platforms(
            (platforms.iter().chain(&recorded))
                .map(|platform| (platform.os(), platform.arch(), platform.jdk())),
        ))
        .settings_activation()?;
        scoped = config.for_platforms(
            platforms
                .iter()
                .map(|platform| (platform.os(), platform.arch(), platform.jdk())),
        );
        (platforms, &scoped)
    };

    let store = Arc::new(Store::open(&config.paths.store_dir)?);
    check_disk_space(&config.paths.store_dir);
    let client = mode.client(config).await?.with_progress(output.progress());
    let mut run = SyncRun {
        args,
        mode,
        config,
        platforms,
        store,
        client,
        widened,
        start,
        output,
    };

    if let Some(mut checked) = frozen {
        run.client = (run.client).with_lock_pins(checked.held.as_ref().unwrap_or(&checked.lock));
        let unverified = (checked.held.as_ref().unwrap_or(&checked.lock)).missing_checksum_files();
        let validated = checked.held.clone().unwrap_or_else(|| checked.lock.clone());
        let held = checked.held.take();
        let written = checked.written.take();
        let (models, platforms) = (checked.models.clone(), checked.platforms.clone());
        let mut outcome = run.frozen(checked).await?;
        plugins::check_frozen(
            config,
            run.store.clone(),
            run.client.clone(),
            held.as_ref(),
            &models,
            &platforms,
        )
        .await?;
        // The plugin tables' files are in the store too, as checked against
        // their pins.
        if let (Headline::CheckedStored(files), Some(held)) = (&mut outcome.headline, &held) {
            *files = pinned_count(held, &platforms);
        }
        written.map_or(Ok(()), crate::commands::util::not_written)?;
        record_checked(config, &run.client, &platforms, Some(&validated));
        if !args.allow_missing_checksums {
            warn_locked_missing_checksums(&unverified, output);
        }
        return Ok(outcome);
    }

    if !pom_exists {
        return Err(CliError::ProjectFileMissing {
            path: pom_path.clone(),
        });
    }
    if !config.lock.jdks.is_empty() {
        let listed = config.lock.jdks.join(", ");
        match config.host().named_java_version() {
            None => tracing::warn!(
                sec_code = "JDK_NOT_LOCKED",
                "[lock] jdks ({listed}) cannot be checked, as the version of this JDK is \
                 unknown: {}; resolving the listed JDKs",
                unnamed_jdk(config)
            ),
            Some(host_jdk)
                if !(config.lock.jdks.iter())
                    .any(|jdk| rv_config::jdk_matches_target(jdk, host_jdk)) =>
            {
                tracing::warn!(
                    sec_code = "JDK_NOT_LOCKED",
                    jdk = %host_jdk,
                    "[lock] jdks ({listed}) does not include this JDK ({host_jdk}); resolving the listed JDKs"
                );
            }
            Some(_) => {}
        }
    }
    let models = discover_reactor_models(config, &run.platforms)?;

    check_origin_aliases(config, declared_repository_urls(config, &models))?;
    plugins::refuse_split_repository_id(config, &models)?;
    // Read once: an incompatible lockfile is replaced whole, so it neither
    // short-circuits this run nor carries platforms or metadata forward. Its
    // pins still hold.
    let previous_lock = match on_disk {
        Some(Ok(lock)) => Some(lock),
        Some(Err(CliError::LockfileMissing { .. } | CliError::LockfileIncompatible { .. }))
        | None => None,
        Some(Err(err)) => return Err(err),
    };
    // The plugin rows too, which a resolution of the plugin tables fetches.
    let pins = (held.as_ref().or(previous_lock.as_ref())).or_else(|| {
        unreadable
            .as_ref()
            .and_then(|unreadable| unreadable.pins.as_ref())
    });
    if let Some(lock) = pins {
        run.client = run.client.with_lock_pins(lock);
    }

    let reused = match previous_lock.as_ref() {
        Some(lock) if !args.update => run.reuse(lock, held.as_ref(), &models, written).await?,
        _ => None,
    };
    let mut outcome = match reused {
        Some(outcome) => outcome,
        None => {
            run.resolve_and_write(
                &models,
                previous_lock.as_ref(),
                held.as_ref(),
                pins,
                unreadable.as_ref(),
            )
            .await?
        }
    };
    // Under the guard: a lock another sync writes once it is released is
    // not this one's to put back.
    if config.plugin_trace().is_some() && !offline {
        outcome.trace = Some(trace::Start {
            models,
            written: lock_bytes(&config.lock_path),
            previous,
        });
    }
    Ok(outcome)
}

/// How many files `lock` pins on `platforms`, its plugin tables' included,
/// each once, as `raeva lock verify` hashes them.
fn pinned_count(lock: &Lockfile, platforms: &[Platform]) -> usize {
    let mut files = std::collections::BTreeSet::new();
    for entry in (lock.platforms.iter()).filter(|entry| platforms.contains(&entry.platform)) {
        files.extend((entry.pinned_files()).map(|file| (file.key, file.pin)));
        if let Some(plugins) = entry.plugin_files() {
            files.extend((plugins.pinned_files()).map(|file| (file.key, file.pin)));
        }
    }
    files.len()
}

/// Hold an exclusive advisory lock on the project-level lockfile guard,
/// which keeps two concurrent `raeva sync` runs with disjoint --platform
/// sets from racing on raeva.lock, where the last writer would win and drop
/// the other's platform entries. It lives in the cache directory, so only
/// runs that share it take turns.
///
/// The wait is on the blocking pool, so it does not pin a tokio worker, and
/// gives up after 60 s, as `rv-store`'s `StoreLock` does, so a wedged
/// holder surfaces as an error.
async fn lockfile_guard(
    config: &Config,
    project_root: &Path,
    output: &Output,
) -> Result<LockfileGuard> {
    LockfileGuard::acquire_async(
        &config.paths.cache_dir,
        project_root,
        std::time::Duration::from_secs(60),
        {
            let output = output.clone();
            move || output.step("Waiting for another raeva sync of this project to finish...")
        },
    )
    .await
    .map_err(|err| {
        if err.kind() == std::io::ErrorKind::TimedOut {
            CliError::LockfileBusy {
                project_root: project_root.to_path_buf(),
                source: err,
            }
        } else {
            CliError::io_at(&config.paths.cache_dir)(err)
        }
    })
}

/// How many files [`warn_locked_missing_checksums`] names.
const SHOWN_UNVERIFIED: usize = 5;

/// Warn that raeva.lock pins files a repository published no checksum file
/// for, which `--allow-missing-checksums` accepted when they were locked.
fn warn_locked_missing_checksums(
    files: &std::collections::BTreeMap<String, rv_maven_types::Digest>,
    output: &Output,
) {
    if files.is_empty() {
        return;
    }
    let paths: Vec<&str> = files.keys().map(String::as_str).collect();
    let mut named = paths[..paths.len().min(SHOWN_UNVERIFIED)].join(", ");
    if paths.len() > SHOWN_UNVERIFIED {
        named.push_str(&format!(" and {} more", paths.len() - SHOWN_UNVERIFIED));
    }
    output.warn(
        crate::output::Warning::new(
            crate::output::WarningCode::ChecksumMissingLocked,
            format!(
                "raeva.lock pins {} that no repository checksum file verified \
                 (--allow-missing-checksums accepted them): {named}. The pins check the bytes; \
                 pass --allow-missing-checksums to accept them without this warning",
                crate::commands::util::plural(paths.len(), "file", "files")
            ),
        )
        .with_context(serde_json::json!({ "files": paths })),
    );
}

pub(crate) struct LockDownloadContext {
    pub config: Config,
    pub client: RepoClient,
    pub platforms: Vec<Platform>,
    pub trusted: Vec<Repository>,
}

impl LockDownloadContext {
    pub(crate) async fn new(
        config: &Config,
        lock: &Lockfile,
        platform: &Platform,
        output: &Output,
        mode: &Mode,
    ) -> Result<Self> {
        let config = config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
        let client = (mode.restore_client(&config).await?)
            .with_progress(output.progress())
            .with_lock_pins(lock);
        Ok(Self::from_client(config, client, platform.clone()))
    }

    pub(crate) fn from_client(config: Config, client: RepoClient, platform: Platform) -> Self {
        let client = client.for_platform(&config);
        Self {
            config,
            client,
            platforms: vec![platform],
            trusted: Vec::new(),
        }
    }

    /// Admit what the local POMs declare, and resolve this context's
    /// transitive trust when `always` or when a file to restore needs it.
    /// Returns whether it resolved.
    pub(crate) async fn discover_trust(
        &mut self,
        store: Arc<Store>,
        lock: &Lockfile,
        always: bool,
    ) -> Result<bool> {
        if !self.config.project_root.join("pom.xml").is_file() {
            return Ok(false);
        }
        let models = discover_reactor_models(&self.config, &self.platforms)?;
        let selected = lock
            .select_platforms(&self.platforms)
            .expect("recorded platform");
        self.trust_model(&models);
        self.restore_trust(store, &selected, &models, always).await
    }

    /// Admit the repositories the project's POMs declare, for a repair to
    /// fall back to when every recorded origin is declared. A reactor that
    /// cannot be read adds none: the recorded origins need no model.
    pub(crate) fn trust_local_model(&mut self) {
        if self.config.project_root.join("pom.xml").is_file()
            && let Ok(models) = discover_reactor_models(&self.config, &self.platforms)
        {
            self.trust_model(&models);
        }
    }

    fn trust_model(&mut self, models: &[ReactorModel]) {
        self.trusted = self
            .client
            .policy()
            .admit(
                models.iter().flat_map(ReactorModel::declared_repositories),
                rv_repo::Declaration::LocalPom,
            )
            .admitted;
    }

    /// Resolve only this context's platforms to establish transitive trust,
    /// when `always` or when a file to restore comes from a repository
    /// neither the configuration nor the local POMs declare. Returns
    /// whether it resolved.
    async fn restore_trust(
        &mut self,
        store: Arc<Store>,
        lock: &Lockfile,
        models: &[ReactorModel],
        always: bool,
    ) -> Result<bool> {
        let resolve = always
            || rv_repo::restore_needs_discovery(store.as_ref(), lock, &[self.as_restore()]).await?;
        if resolve {
            // The restore after it fetches what the lock pins: fetch that
            // beside the resolution.
            let (_prefetch, observer) =
                download::prefetch_pinned(&self.config, &self.client, &store, lock, models);
            self.trusted = resolve_reactor_lock(
                &self.config,
                store,
                self.client.clone(),
                &self.platforms,
                models,
                None,
                observer,
            )
            .await?
            .trusted_repositories;
        }
        Ok(resolve)
    }

    /// Whether every artifact row and support POM of `lock` names a
    /// repository this context's configuration, model or resolution declares.
    fn declares_rows(&self, lock: &Lockfile) -> bool {
        let origins = LockOrigins::for_root(&self.config.project_root);
        let selector = rv_repo::LockRepositorySelector::new(&self.config, &origins, &self.trusted);
        let declared = |repo_url: &str| selector.select(repo_url, None).declared().is_some();
        (lock.platforms.iter()).all(|platform| {
            platform
                .artifacts
                .iter()
                .all(|artifact| artifact.origins().all(declared))
                && platform
                    .support_poms
                    .values()
                    .all(|pin| declared(&pin.repo_url))
        })
    }

    pub(crate) fn as_restore(&self) -> RestoreContext<'_> {
        RestoreContext {
            config: &self.config,
            client: &self.client,
            platforms: &self.platforms,
            trusted_repositories: &self.trusted,
        }
    }
}

struct SyncRun<'a> {
    args: &'a SyncArgs,
    mode: Mode,
    config: &'a Config,
    platforms: Vec<Platform>,
    store: Arc<Store>,
    client: RepoClient,
    /// The client also allows the repositories of platforms not selected,
    /// so a restore builds its own.
    widened: bool,
    start: Instant,
    output: &'a Output,
}

impl SyncRun<'_> {
    /// `--frozen` after [`check_frozen_local`]: resolve again and compare the
    /// result with the lock, without writing it, then download what it pins.
    /// Unchanged inputs replay the lock's version choices, so only an edit of
    /// the lock itself, or bytes that changed under a pin, can make them
    /// differ.
    async fn frozen(&self, checked: FrozenLocal) -> Result<SyncOutcome> {
        let config = self.config;
        let FrozenLocal {
            lock,
            held: _,
            models,
            platforms,
            models_match,
            unselected,
            written: _,
        } = checked;
        let selected = lock
            .select_platforms(&platforms)
            .expect("recorded platform");
        if self.mode.offline() {
            // Offline the resolution reads only the store, the metadata cache
            // and local repositories, and nothing is downloaded, so then
            // check that the store has what an offline build needs.
            self.output.step("Resolving dependencies...");
            let (fresh, resolved) = validate_frozen_resolution(
                config,
                self.store.clone(),
                self.client.clone(),
                &lock,
                &models,
                models_match,
                self.output,
            )
            .await?;
            // The repositories a resolution trusts, a remote parent's
            // included: files they served count as stored.
            let mut trusted = (self.client.policy())
                .admit(
                    models.iter().flat_map(ReactorModel::declared_repositories),
                    rv_repo::Declaration::LocalPom,
                )
                .admitted;
            trusted.extend(resolved);
            // A file another platform's repository served for a row of these
            // counts as well, as the online check fetches it there.
            trusted.extend(
                rv_repo::RepositoryPolicy::screen(
                    config,
                    unselected
                        .iter()
                        .flat_map(ReactorModel::declared_repositories),
                    rv_repo::Declaration::LocalPom,
                )
                .admitted,
            );
            // A support POM counts under the repository the resolution read
            // it from, as online it is downloaded from there: the lock's may
            // be one only an imported BOM declares, which a mirror replaces.
            let counted = with_origins_of(&selected, &fresh, true);
            let (missing, files) = count_stored(
                config,
                self.store.clone(),
                &self.client,
                &counted,
                &platforms,
                &mut trusted,
                None,
            )
            .await?;
            if missing > 0 {
                return Err(CliError::lockfile_mismatch_with(
                    format!(
                        "raeva.lock is up to date, but the store lacks {missing} of the {} it pins",
                        crate::commands::util::plural(files, "file", "files")
                    ),
                    "Run 'raeva sync --frozen' with network access, or 'raeva lock verify \
                     --download', to download them",
                ));
            }
            return Ok(self.finish(&selected, Vec::new(), Headline::CheckedStored(files)));
        }
        self.output.step("Resolving dependencies...");
        let resolved = match resolve::recompute(
            config,
            self.store.clone(),
            self.client.clone(),
            &lock,
            &models,
            models_match,
            self.output,
        )
        .await
        {
            Ok(resolved) => resolved,
            // A pinned file gone from its repository, or replaced there,
            // fails the resolution among every repository searched; the
            // restore of the lock as written names it as such.
            Err(err) if models_match && !matches!(err, CliError::LockfileMismatch { .. }) => {
                self.output.step("Downloading the locked artifacts...");
                self.download_lock(&selected, &models, None, None).await?;
                return Err(err);
            }
            Err(err) => return Err(err),
        };
        let downloads = with_origins_of(&selected, &resolved.lock, false);
        self.output.step("Downloading the locked artifacts...");
        self.download_lock(
            &downloads,
            &models,
            Some(&resolved),
            Some((&lock, &unselected)),
        )
        .await?;
        Ok(self.finish(&selected, Vec::new(), Headline::Checked))
    }

    /// A plain sync's reuse of `previous` as written, when its inputs are
    /// unchanged and no SNAPSHOT check is due.
    async fn reuse(
        &self,
        previous: &Lockfile,
        held: Option<&Lockfile>,
        models: &[ReactorModel],
        written: Option<std::thread::JoinHandle<bool>>,
    ) -> Result<Option<SyncOutcome>> {
        let config = self.config;
        let ambient = recorded_ambient(previous);
        let config_hash = resolution_config_hash(config, &ambient)?;
        // The option names too, which a frozen check compares.
        if crate::commands::lock_inputs::reads_unnamed_jdk(config, &ambient)
            || previous.config_hash.as_deref() != Some(config_hash.as_str())
            || previous.maven != config.lock.maven.mode
            || previous.resolution.command_line != command_line_names(config, &ambient)
            || previous.unread_property_name().is_some()
            || reads_hidden_env(config, previous)
        {
            return Ok(None);
        }
        // The hash reads the project and home directories as markers, so a
        // copy keeps it while a value a POM compares names another
        // directory: the lock stands only where this home wrote or checked
        // it with the directories as they are here.
        if hides_host_directories(config, previous)?
            && !checked_here(config, &self.client, &self.platforms)
        {
            return Ok(None);
        }
        // A requested platform missing from the lockfile is a cache miss:
        // fall through to resolution instead of erroring.
        let Ok(selected) = previous.select_platforms(&self.platforms) else {
            return Ok(None);
        };
        // Online, a lock whose origins only a remote POM declares is
        // restored, establishing that trust while it restores; offline it
        // is resolved to check them. Newer SNAPSHOT builds are looked for
        // once their update policy expires. A changed system file drops the
        // platform that records it, selected or not.
        // A row whose checksums a resolution would not write is written
        // again, as a frozen check refuses it.
        let rows = (selected.platforms.iter()).flat_map(|entry| &entry.artifacts);
        if previous.system_file_drift(&config.project_root).is_some()
            || !rows
                .clone()
                .all(rv_lock::LockArtifact::checksums_as_resolved)
            || !frozen_models_match(&selected, models)
            || lock_requires_snapshot_refresh(&selected, config, models, self.checked())
            || (self.mode.offline()
                && lock_references_unconfigured_origin(&selected, config, models))
        {
            return Ok(None);
        }
        // A platform not selected is kept only with plugin tables that hold;
        // the resolution drops one without.
        let unselected =
            (previous.platforms.iter()).filter(|entry| !self.platforms.contains(&entry.platform));
        for entry in unselected {
            if !plugins::kept(config, held.unwrap_or(previous), &entry.platform)? {
                return Ok(None);
            }
        }
        // raeva.lock records no repository for a build extension's jars, so
        // only a resolution fetches them: one the store lacks is fetched by
        // the frozen check's, and a lock that check does not reproduce is
        // resolved again.
        let resolved = if extension_jars_stored(config, &self.store, &selected, models).await? {
            None
        } else {
            self.output.step("Resolving dependencies...");
            let (store, client) = (self.store.clone(), self.client.clone());
            let resolved =
                resolve::recompute(config, store, client, &selected, models, true, self.output);
            match resolved.await {
                Ok(resolved) => Some(resolved),
                Err(CliError::LockfileMismatch { .. }) => return Ok(None),
                Err(err) => return Err(err),
            }
        };
        // Offline, the restore reads only the store and local repositories,
        // and fails on a file they lack.
        if !self.mode.offline() {
            self.output.step("Downloading the locked artifacts...");
        }
        let restored = match &resolved {
            Some(resolved) => {
                let downloads = with_origins_of(&selected, &resolved.lock, false);
                (self.download_lock(&downloads, models, Some(resolved), None)).await?
            }
            None => self.download_lock(&selected, models, None, None).await?,
        };
        if !restored {
            return Ok(None);
        }
        let written = written.is_some_and(|written| written.join().unwrap_or(false));
        let found = held.unwrap_or(previous);
        let (store, client) = (self.store.clone(), self.client.clone());
        // The plugin tables of a lock this home neither wrote nor checked
        // stay only once the frozen check of them passes.
        let recorded = self.recorded();
        let mut failed = recorded.then(Vec::new);
        let keep = match held.filter(|_| plugins::wanted(config)) {
            Some(held)
                if plugins::fresh(config, client.policy(), held, models, &self.platforms)? =>
            {
                if !recorded {
                    self.output.step("Checking plugins...");
                    let checking = self.mode.restoring(client.clone());
                    let platforms = &self.platforms;
                    failed = Some(
                        plugins::checked(config, store.clone(), checking, held, models, platforms)
                            .await,
                    );
                }
                failed.as_ref().is_some_and(Vec::is_empty)
            }
            _ => false,
        };
        let (mut lock, kept) = match (plugins::wanted(config), held) {
            (false, None) => (previous.clone(), written),
            (true, Some(held)) if keep => {
                plugins::fetch(config, store, client, held, models, &self.platforms, &[]).await?;
                (held.clone(), written)
            }
            // The Maven 3.9 checks of new plugin tables read what the
            // modules' resolution reads, which raeva.lock does not hold.
            (true, _) if config.lock.maven.mode == rv_maven_types::MavenMode::Maven39 => {
                return Ok(None);
            }
            (true, held) => {
                let mut lock = found.clone();
                (self.attach_plugins(&mut lock, models, held, None, failed, None)).await?;
                (lock, false)
            }
            (false, Some(_)) => (previous.clone(), false),
        };
        // A file downloaded again drops the marker a checksum file now
        // verifies.
        lock.mark_missing_checksums(&self.client.admissions(), Some(found));
        if kept && lock == *found {
            if !recorded && keep {
                record_checked(config, &self.client, &self.platforms, Some(found));
            }
            return Ok(Some(self.finish(&selected, Vec::new(), Headline::Checked)));
        }
        let before = lock_bytes(&config.lock_path);
        self.write(&lock)?;
        record_checked(config, &self.client, &self.platforms, None);
        // Plugin tables resolved again can come out as they were.
        if before.is_some() && lock_bytes(&config.lock_path) == before {
            return Ok(Some(self.finish(&selected, Vec::new(), Headline::UpToDate)));
        }
        let changes = lock_diff(found, &lock, &self.platforms, self.output.is_verbose());
        Ok(Some(self.finish(&selected, changes, Headline::Updated)))
    }

    /// `pins` holds the pins of `previous`, or of `unreadable`, which other
    /// bytes must not replace without `--update`.
    async fn resolve_and_write(
        &self,
        models: &[ReactorModel],
        previous: Option<&Lockfile>,
        held: Option<&Lockfile>,
        pins: Option<&Lockfile>,
        unreadable: Option<&regenerate::Unreadable>,
    ) -> Result<SyncOutcome> {
        let config = self.config;
        self.output.step("Resolving dependencies...");
        let resolved = resolve_reactor_lock(
            self.config,
            self.store.clone(),
            self.client.clone(),
            &self.platforms,
            models,
            None,
            None,
        )
        .await?;
        if !self.args.update
            && let Some(pins) = pins
        {
            download::check_repinned(pins, &resolved.lock, &self.store).await?;
        }
        self.output.step("Downloading artifacts...");
        self.download_lock(&resolved.lock, models, Some(&resolved), None)
            .await?;
        let mut resolved = resolved;
        let fetched: std::collections::BTreeSet<_> =
            resolved.lock.pinned_files().into_keys().collect();
        let mut lock = std::mem::take(&mut resolved.lock);
        merge_previous(
            config,
            &mut lock,
            previous,
            held.or(previous),
            models,
            &resolved.reads,
            &resolved.trusted_repositories,
        )?;
        self.download_merged(&lock, &fetched, models, &resolved)
            .await?;
        warn_system_scope_from_lock(&lock);
        if plugins::wanted(config) {
            let carried = unreadable.and_then(|unreadable| unreadable.pins.as_ref());
            let failed = self.recorded().then(Vec::new);
            let reads = Some(&resolved.pom_reads);
            self.attach_plugins(&mut lock, models, held, carried, failed, reads)
                .await?;
        }
        // After the merge and the plugin tables, so a platform kept from the
        // previous lock and a plugin file take what this run learned of the
        // same file too.
        lock.mark_missing_checksums(&self.client.admissions(), pins);
        let before = lock_bytes(&config.lock_path);
        self.write(&lock)?;
        record_checked(config, &self.client, &self.platforms, None);
        let (client, project) = (self.client.clone(), project_key(config));
        let (checked, started) = (
            self.snapshot_checks(previous, &lock, models),
            self.mode.started(),
        );
        let others: Vec<_> = (self.platforms.iter())
            .map(ToString::to_string)
            .filter(|platform| !checked.contains(platform))
            .collect();
        let record = move || client.record_snapshot_check(&project, &checked, &others, started);
        let headline = match before {
            None => Headline::Wrote,
            Some(before) if lock_bytes(&config.lock_path).as_deref() == Some(&before[..]) => {
                Headline::UpToDate
            }
            Some(_) => Headline::Updated,
        };
        // A regenerated lock lists its changes against the one git has.
        let baseline = unreadable.and_then(|unreadable| unreadable.head.as_ref());
        let changes = match (&headline, held.or(previous).or(baseline)) {
            (Headline::Updated, Some(previous)) => {
                lock_diff(previous, &lock, &self.platforms, self.output.is_verbose())
            }
            _ => Vec::new(),
        };

        let mut outcome = self.finish(&lock, changes, headline);
        outcome.snapshot_check = Some(Box::new(record));
        tracing::info!(
            artifacts = outcome.dep_count,
            elapsed_ms = self.start.elapsed().as_millis() as u64,
            "sync complete"
        );
        Ok(outcome)
    }

    /// Give `lock` the plugin tables of its platforms.
    async fn attach_plugins(
        &self,
        lock: &mut Lockfile,
        models: &[ReactorModel],
        held: Option<&Lockfile>,
        carried: Option<&Lockfile>,
        failed: Option<Vec<Platform>>,
        pom_reads: Option<&resolve::ModulePomReads>,
    ) -> Result<()> {
        let (store, client) = (self.store.clone(), self.client.clone());
        let output = self.output;
        plugins::attach(
            self.config,
            store,
            client,
            lock,
            models,
            held,
            carried,
            failed,
            output,
            pom_reads,
        )
        .await
    }

    /// Whether raeva.lock as it is now is one this home wrote, or checked,
    /// for every platform of this run.
    fn recorded(&self) -> bool {
        let Some(bytes) = lock_bytes(&self.config.lock_path) else {
            return false;
        };
        let sha256 = lock_digest(&bytes);
        (self.client.checked_lock(&checked_key(self.config, &bytes))).is_some_and(
            |(recorded, platforms)| {
                recorded == sha256
                    && (self.platforms.iter())
                        .all(|platform| platforms.lines().any(|line| line == platform.to_string()))
            },
        )
    }

    /// Write `lock`, after warning of each field that holds an allowlisted
    /// variable's value, plugin tables included.
    fn write(&self, lock: &Lockfile) -> Result<()> {
        lock.warn_on_env_values(self.config.host().env_values());
        let path = &self.config.lock_path;
        lock.write_atomic(path).map_err(|err| match err {
            rv_lock::LockError::Io { source, .. } => CliError::io_at(path)(source),
            other => other.into(),
        })
    }

    /// Restore each platform with its own settings, declarations and policies.
    /// Without `resolved`, a platform whose rows name a repository only a
    /// remote POM declares is resolved first to establish that trust, and
    /// the result is false, with nothing restored, when a row or a file to
    /// restore still names a repository no declaration of its platform
    /// does: the lock must be resolved again.
    ///
    /// With `resolved`, `unselected` holds the recorded lock and the models
    /// of the platforms the run does not check, whose trust the restore
    /// takes too; see [`Self::trust_unselected`].
    async fn download_lock(
        &self,
        lock: &Lockfile,
        models: &[ReactorModel],
        resolved: Option<&ResolvedReactorLock>,
        unselected: Option<(&Lockfile, &[ReactorModel])>,
    ) -> Result<bool> {
        let mut contexts = Vec::new();
        for entry in &lock.platforms {
            let platform = &entry.platform;
            // One platform matches this sync's scope: keep the run's clients.
            // Another platform needs its own settings-scoped RepoClient.
            let mut context = if !self.widened
                && self.platforms.len() == 1
                && self.platforms[0] == *platform
            {
                LockDownloadContext::from_client(
                    self.config
                        .for_platforms([(platform.os(), platform.arch(), platform.jdk())]),
                    self.mode.restoring(self.client.clone()),
                    platform.clone(),
                )
            } else {
                LockDownloadContext::new(self.config, lock, platform, self.output, &self.mode)
                    .await?
            };
            if let Some(resolved) = resolved {
                // A platform's own client trusts what the run's resolution
                // admitted, as the run's client does.
                context.trusted = resolved.repositories_for(platform).to_vec();
                context.client.policy().grant_admitted(&context.trusted);
            } else {
                context.trust_model(std::slice::from_ref(model_for(models, platform)));
            }
            contexts.push(context);
        }
        if let (Some(_), Some(unselected)) = (resolved, unselected) {
            self.trust_unselected(&mut contexts, lock, unselected.1)
                .await?;
        }
        // Each context's lock, model, and whether its trust was resolved.
        let mut undiscovered = Vec::new();
        if resolved.is_none() {
            for context in &mut contexts {
                let selected = lock
                    .select_platforms(&context.platforms)
                    .expect("recorded platform");
                let model = std::slice::from_ref(model_for(models, &context.platforms[0]));
                let unconfigured =
                    lock_references_unconfigured_origin(&selected, self.config, model);
                let discovered = context
                    .restore_trust(self.store.clone(), &selected, model, unconfigured)
                    .await?;
                undiscovered.push((!discovered).then_some((selected.clone(), model)));
                if (unconfigured && !context.declares_rows(&selected))
                    || rv_repo::restore_needs_discovery(
                        self.store.as_ref(),
                        &selected,
                        &[context.as_restore()],
                    )
                    .await?
                {
                    return Ok(false);
                }
            }
        }
        let restored = {
            let restore: Vec<_> = contexts
                .iter()
                .map(LockDownloadContext::as_restore)
                .collect();
            ensure_artifacts(lock, self.store.as_ref(), &restore).await
        };
        // A file can have moved to a repository only a remote parent
        // declares, which Maven searches too: resolve the trust of each
        // platform still missing a file and retry. A resolution that fails
        // leaves the restore error to report.
        let Err(err) = restored else {
            return Ok(true);
        };
        let err = match unselected {
            Some((recorded, others)) if !others.is_empty() => {
                other_platform_origin(err, lock, recorded)
            }
            _ => err,
        };
        if self.mode.offline() {
            return Err(err);
        }
        let mut retry = false;
        for (context, pending) in contexts.iter_mut().zip(undiscovered) {
            let Some((selected, model)) = pending else {
                continue;
            };
            if !rv_repo::restore_complete(self.store.as_ref(), &selected, &context.as_restore())
                .await?
                && (context.restore_trust(self.store.clone(), &selected, model, true))
                    .await
                    .is_ok()
            {
                retry = true;
            }
        }
        if !retry {
            return Err(err);
        }
        let restore: Vec<_> = contexts
            .iter()
            .map(LockDownloadContext::as_restore)
            .collect();
        ensure_artifacts(lock, self.store.as_ref(), &restore).await?;
        Ok(true)
    }

    /// Let `contexts`, of a run that checks only some of the platforms
    /// `recorded` holds, also fetch the files `lock` pins from the
    /// repositories the POMs of the platforms it does not check declare,
    /// their `others` models: a row can take the POM another platform read
    /// from its repository. The pins decide the bytes, and nothing this run
    /// checks is resolved through these repositories: a context that takes
    /// one gets its own client. A file to restore whose repository only
    /// another platform's resolution trusts, as a remote parent's profile
    /// declares it, fails the restore; see [`other_platform_origin`].
    async fn trust_unselected(
        &self,
        contexts: &mut [LockDownloadContext],
        lock: &Lockfile,
        others: &[ReactorModel],
    ) -> Result<()> {
        if others.is_empty() {
            return Ok(());
        }
        let found = rv_repo::RepositoryPolicy::screen(
            self.config,
            others.iter().flat_map(ReactorModel::declared_repositories),
            rv_repo::Declaration::LocalPom,
        )
        .admitted;
        for context in contexts.iter_mut() {
            let mut extra: Vec<Repository> = Vec::new();
            for repo in &found {
                if !context.trusted.contains(repo) && !extra.contains(repo) {
                    extra.push(repo.clone());
                }
            }
            if extra.is_empty() {
                continue;
            }
            let platform = &context.platforms[0];
            context.client =
                (LockDownloadContext::new(self.config, lock, platform, self.output, &self.mode))
                    .await?
                    .client;
            context.client.policy().grant_admitted(&context.trusted);
            context.client.policy().grant_admitted(&extra);
            context.trusted.extend(extra);
        }
        Ok(())
    }

    /// Download the files the merge of `lock` added to the platforms this
    /// run resolved, beside the `fetched` ones: a row can take the pin of
    /// the POM a platform it keeps read, which a later offline check needs.
    /// They come through the repositories the kept platforms' POMs declare
    /// too, as `--frozen` of the platforms fetches them.
    async fn download_merged(
        &self,
        lock: &Lockfile,
        fetched: &std::collections::BTreeSet<(
            rv_maven_types::ArtifactCoord,
            rv_maven_types::Digest,
        )>,
        models: &[ReactorModel],
        resolved: &ResolvedReactorLock,
    ) -> Result<()> {
        let Ok(selected) = lock.select_platforms(&self.platforms) else {
            return Ok(());
        };
        if (selected.pinned_files().keys()).all(|key| fetched.contains(key)) {
            return Ok(());
        }
        let kept: Vec<Platform> = (lock.platforms.iter())
            .map(|entry| entry.platform.clone())
            .filter(|platform| !self.platforms.contains(platform))
            .collect();
        let others = if kept.is_empty() {
            Vec::new()
        } else {
            let config = self.config.for_platforms(
                (kept.iter()).map(|platform| (platform.os(), platform.arch(), platform.jdk())),
            );
            discover_reactor_models(&config, &kept)?
        };
        self.download_lock(&selected, models, Some(resolved), Some((lock, &others)))
            .await?;
        Ok(())
    }

    /// When the SNAPSHOT builds of a platform were last checked.
    fn checked(&self) -> impl Fn(&Platform) -> Option<SnapshotCheck> {
        let project = project_key(self.config);
        move |platform| (self.client).snapshot_check(&project, &platform.to_string())
    }

    /// The platforms whose SNAPSHOT builds a resolution of this run checked:
    /// under `--update` every one, else those whose check was due in
    /// `previous` or in the `written` lock, or that `previous` lacks.
    /// Another one read the metadata cached by its last check, which stays
    /// its time.
    fn snapshot_checks(
        &self,
        previous: Option<&Lockfile>,
        written: &Lockfile,
        models: &[ReactorModel],
    ) -> Vec<String> {
        let checked = self.checked();
        let due = |lock: &Lockfile, platform: &Platform| match lock
            .select_platforms(std::slice::from_ref(platform))
        {
            Ok(selected) => {
                lock_requires_snapshot_refresh(&selected, self.config, models, &checked)
            }
            Err(_) => true,
        };
        (self.platforms.iter())
            .filter(|platform| {
                self.mode.intent() == Intent::Update
                    || previous.is_none_or(|lock| due(lock, platform))
                    || due(written, platform)
            })
            .map(ToString::to_string)
            .collect()
    }

    /// What every successful mode ends with.
    fn finish(&self, lock: &Lockfile, changes: Vec<String>, headline: Headline) -> SyncOutcome {
        SyncOutcome {
            dep_count: count_dependencies(
                (lock.platforms.iter()).filter(|entry| self.platforms.contains(&entry.platform)),
            ),
            platforms: self.platforms.clone(),
            changes,
            headline,
            trace: None,
            snapshot_check: None,
        }
    }
}

/// A lockfile that passed the checks of `--frozen` that need no store,
/// network or cache.
struct FrozenLocal {
    /// The lock without its plugin tables.
    lock: Lockfile,
    /// The lock as written, when it has plugin tables.
    held: Option<Lockfile>,
    models: Vec<ReactorModel>,
    platforms: Vec<Platform>,
    /// [`frozen_models_match`] of `lock` and `models`.
    models_match: bool,
    /// The models of the recorded platforms not checked.
    unselected: Vec<ReactorModel>,
    /// Whether raeva.lock holds the text raeva writes for it, which the
    /// run checks last.
    written: Option<std::thread::JoinHandle<bool>>,
}

/// The `[lock] jdks` entry that covers `host_jdk`: its feature release, as
/// `25` covers `25.0.1` and `1.8` covers `1.8.0_442`.
fn jdk_entry(host_jdk: &str) -> String {
    let host = host_jdk.trim();
    let mut parts = host.split(['.', '_', '-', '+']);
    let entry = match (parts.next(), parts.next()) {
        (Some("1"), Some(feature)) => format!("1.{feature}"),
        (Some(major), _) => major.to_string(),
        (None, _) => String::new(),
    };
    match rv_config::is_valid_jdk(&entry) && rv_config::jdk_matches_target(&entry, host) {
        true => entry,
        false => crate::output::inline_text(host).into_owned(),
    }
}

/// The checks `sync --frozen` makes before it reads a repository, for a
/// command that relies on one having passed.
pub(crate) fn check_frozen_inputs(config: &Config) -> Result<()> {
    let args = SyncArgs {
        frozen: true,
        update: false,
        platforms: Vec::new(),
        allow_missing_checksums: false,
    };
    let pom_exists = config.project_root.join("pom.xml").is_file();
    check_frozen_local(config, &args, pom_exists, false).map(drop)
}

/// Discover the current models and check `config_hash` and the recorded
/// system files without resolving.
/// `warn` warns of the lock's system-scoped files.
fn check_frozen_local(
    config: &Config,
    args: &SyncArgs,
    pom_exists: bool,
    warn: bool,
) -> Result<FrozenLocal> {
    let mut lock = read_lockfile(config)?;
    let written = crate::commands::util::check_written(&lock, &config.lock_path);
    // `config_hash` does not cover the name of a property no target reads,
    // which a hand edit can add. A lock raeva derives for one platform, as a
    // trace exports, keeps the other platforms' names, so only the lock as
    // written is checked.
    if let Some(input) = lock.unread_property_name() {
        return Err(CliError::lockfile_mismatch(format!(
            "raeva.lock lists {} under [resolution] ambient_inputs, which no target's inputs \
             list as read; run 'raeva sync' to write it again",
            rv_maven_types::bounded(&input.to_string())
        )));
    }
    let held = plugins::strip(&mut lock);
    if !pom_exists {
        return Err(CliError::ProjectFileMissing {
            path: config.project_root.join("pom.xml"),
        });
    }
    let recorded = recorded_platforms(&lock);
    let platforms = resolve_platforms(&args.platforms, &recorded, &config.lock.jdks)?;
    let missing = |os_arch: String| {
        let mut recorded: Vec<String> = (lock.platforms.iter())
            .map(|entry| entry.platform.os_arch())
            .collect();
        recorded.sort();
        recorded.dedup();
        CliError::PlatformMissing {
            platform: os_arch,
            recorded,
            frozen: true,
        }
    };
    // A build on this machine needs its own section, as export-m2 does; a
    // gate that passed without one would pass a lock it cannot build from.
    // `--platforms` names the platforms to check instead.
    let host = Platform::current()?.os_arch();
    if args.platforms.is_empty() && !recorded.iter().any(|entry| entry.os_arch() == host) {
        return Err(missing(host));
    }
    let selected = lock.select_platforms(&platforms).map_err(|platform| {
        let os_arch = platform.os_arch();
        if lock
            .platforms
            .iter()
            .any(|entry| entry.platform.os_arch() == os_arch)
        {
            return crate::commands::lock_inputs::config_mismatch(config, &lock, &[]);
        }
        missing(os_arch)
    })?;
    if warn {
        warn_system_scope_from_lock(&selected);
    }
    let config = &config.for_platforms(
        recorded
            .iter()
            .map(|platform| (platform.os(), platform.arch(), platform.jdk())),
    );
    config.settings_activation()?;
    let mut models = discover_reactor_models(config, &recorded)?;
    let models_match = frozen_models_match(&lock, &models);
    // A changed model resolves every recorded platform, as a plain --frozen
    // does: a platform not selected cannot be kept without resolving it.
    let mut unselected = Vec::new();
    if models_match {
        (models, unselected) =
            (models.into_iter()).partition(|model| platforms.contains(&model.platform));
    }
    check_origin_aliases(config, declared_repository_urls(config, &models))?;
    plugins::refuse_split_repository_id(config, &models)?;
    crate::commands::lock_inputs::refuse_unnamed_jdk_reads(config, &recorded_ambient(&lock))?;
    check_recorded_freshness(
        config,
        &lock,
        &models,
        models_match,
        true,
        "raeva.lock has no config_hash, so --frozen cannot check it against the configuration",
    )?;
    if let Some((reason, hint)) = unlisted_host_jdk(config) {
        return Err(CliError::lockfile_mismatch_with(reason, hint));
    }
    Ok(FrozenLocal {
        lock,
        held,
        models,
        platforms,
        models_match,
        unselected,
        written: Some(written),
    })
}

/// `err`, a restore of `lock`, a selection of `recorded`, that refused a
/// repository no configuration or declaration of its platforms names, as
/// [`CliError::OtherPlatformOrigin`] when a platform `lock` leaves out
/// records a file from it: only that platform's build declares it.
fn other_platform_origin(err: CliError, lock: &Lockfile, recorded: &Lockfile) -> CliError {
    let CliError::Download {
        failures,
        first: rv_repo::RepoError::UntrustedRepoUrl(repo),
    } = &err
    else {
        return err;
    };
    let platforms: Vec<String> = (recorded.platforms.iter())
        .filter(|entry| !(lock.platforms.iter()).any(|kept| kept.platform == entry.platform))
        .filter(|entry| {
            (entry.pinned_files()).any(|file| {
                (file.origins.iter()).any(|origin| rv_lock::redact_origin(origin) == *repo)
            })
        })
        .map(|entry| entry.platform.to_string())
        .collect();
    if platforms.is_empty() {
        return err;
    }
    let file = (failures.first())
        .and_then(|failure| failure.split_once(": "))
        .map_or_else(String::new, |(package, _)| package.to_string());
    CliError::OtherPlatformOrigin {
        file,
        repo: repo.clone(),
        platforms,
    }
}

/// Why `--frozen` refuses this JDK, and what to do, when raeva.toml sets
/// `[lock] jdks` and this JDK's version is unknown or matches none of them.
pub(crate) fn unlisted_host_jdk(config: &Config) -> Option<(String, String)> {
    if config.lock.jdks.is_empty() {
        return None;
    }
    let jdks = config.lock.jdks.join(", ");
    let Some(host_jdk) = config.host().named_java_version() else {
        return Some((
            format!(
                "raeva.lock covers the JDKs in [lock] jdks ({jdks}), and the version of this JDK \
                 is unknown: {}",
                unnamed_jdk(config)
            ),
            "Set JAVA_HOME to the JDK the build uses, or JAVA_VERSION to its version".to_string(),
        ));
    };
    (!(config.lock.jdks.iter()).any(|jdk| rv_config::jdk_matches_target(jdk, host_jdk))).then(
        || {
            (
                format!(
                    "raeva.lock covers the JDKs in [lock] jdks ({jdks}), not this JDK ({host_jdk})"
                ),
                format!(
                    "Run on a listed JDK, or add {} to [lock] jdks in raeva.toml and run \
                     'raeva sync'",
                    jdk_entry(host_jdk)
                ),
            )
        },
    )
}

/// Where raeva looked for the version of a JDK that names none.
fn unnamed_jdk(config: &Config) -> String {
    match config.host().value(&rv_maven_model::HostInput::JavaHome) {
        Some(home) => format!(
            "the JDK at {home} has no release file that names a version, and JAVA_VERSION is unset"
        ),
        None => "JAVA_HOME is unset, no java on PATH has a JDK release file beside it, and \
                 JAVA_VERSION is unset"
            .to_string(),
    }
}

/// Whether the store holds each build extension jar `lock` pins where a
/// resolution reads it. A restore of the same coordinates as a dependency,
/// of this project or another sharing the store, may have stored one from
/// a repository the extension does not resolve from, so a jar counts only
/// as a plugin repository served it: one the settings' profiles, the POMs
/// (the super POM's included) or Maven's request declare, each unless an
/// earlier one has its id, as Maven orders them. A plugin repository only
/// a remote parent declares is not among them, so its jars resolve again.
async fn extension_jars_stored(
    config: &Config,
    store: &Store,
    lock: &Lockfile,
    models: &[ReactorModel],
) -> Result<bool> {
    let declared = (config.profile_plugin_repositories().iter())
        .map(Repository::from)
        .chain(
            models
                .iter()
                .flat_map(ReactorModel::declared_plugin_repositories),
        )
        .chain(config.plugin_repositories().iter().map(Repository::from));
    let mut plugin_repositories: Vec<Repository> = Vec::new();
    for repo in declared {
        if repo.id.is_none() || !(plugin_repositories.iter()).any(|known| known.id == repo.id) {
            plugin_repositories.push(repo);
        }
    }
    let from_plugin_repository = |served: &[(String, String)]| {
        (served.iter()).any(|(url, _)| {
            (plugin_repositories.iter()).any(|known| {
                plugins::same_repository(url, rv_config::stored_repository(&known.url))
            })
        })
    };
    for (_, jar) in (lock.platforms.iter()).flat_map(rv_lock::LockPlatform::extension_jars) {
        let (indexed, served) = store.indexed_and_served(&jar.coord(), &jar.sha256).await?;
        if !indexed || !from_plugin_repository(&served) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `lock` with each artifact row's and support POM's repository taken from
/// `fresh`'s for the same platform and coordinate, where it has one, or the
/// support POMs' alone with `support_poms_only`. Pins, snapshot builds and
/// everything else stay `lock`'s.
fn with_origins_of(lock: &Lockfile, fresh: &Lockfile, support_poms_only: bool) -> Lockfile {
    let mut lock = lock.clone();
    for platform in &mut lock.platforms {
        let Some(found) = fresh
            .platforms
            .iter()
            .find(|entry| entry.platform == platform.platform)
        else {
            continue;
        };
        for artifact in (platform.artifacts.iter_mut()).filter(|_| !support_poms_only) {
            if let Some(row) = found
                .artifacts
                .iter()
                .find(|row| row.coordinate == artifact.coordinate)
            {
                artifact.repo_url.clone_from(&row.repo_url);
            }
        }
        for (coord, pin) in &mut platform.support_poms {
            if let Some(fresh_pin) = found.support_poms.get(coord) {
                pin.repo_url.clone_from(&fresh_pin.repo_url);
            }
        }
    }
    lock
}

/// `platforms` for a message, such as `linux-x86_64 and macos-aarch64`.
pub(crate) fn platform_list(platforms: &[Platform]) -> String {
    crate::commands::util::join_and(platforms.iter().map(ToString::to_string))
}

/// The bytes of the lock at `path`, up to one past raeva.lock's size limit,
/// so one over it reads as different from any lock this run writes.
fn lock_bytes(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    (std::fs::File::open(path).ok()?)
        .take(rv_lock::MAX_LOCKFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// Record that raeva.lock passed a full check of `platforms`, which read
/// it as `checked`, or is what a sync just wrote for them, so a plain sync
/// keeps its plugin tables without checking them again. A file replaced
/// since the check is not recorded, and a check of other platforms of the
/// same bytes stands.
pub(crate) fn record_checked(
    config: &Config,
    client: &RepoClient,
    platforms: &[Platform],
    checked: Option<&Lockfile>,
) {
    let Some(bytes) = lock_bytes(&config.lock_path) else {
        return;
    };
    if checked.is_some_and(|checked| !reads_as(&bytes, checked)) {
        return;
    }
    let (project, sha256) = (checked_key(config, &bytes), lock_digest(&bytes));
    let mut covered: Vec<String> = platforms.iter().map(ToString::to_string).collect();
    if let Some((_, held)) = client
        .checked_lock(&project)
        .filter(|(at, _)| *at == sha256)
    {
        covered.extend(held.lines().map(str::to_string));
    }
    covered.sort();
    covered.dedup();
    client.record_checked_lock(&project, &sha256, &covered.join("\n"));
}

/// Whether the home of `client` wrote or checked raeva.lock as it reads,
/// for each of `platforms`.
pub(crate) fn checked_here(config: &Config, client: &RepoClient, platforms: &[Platform]) -> bool {
    let Some(bytes) = lock_bytes(&config.lock_path) else {
        return false;
    };
    (client.checked_lock(&checked_key(config, &bytes))).is_some_and(|(recorded, covered)| {
        recorded == lock_digest(&bytes)
            && (platforms.iter())
                .all(|platform| covered.lines().any(|line| line == platform.to_string()))
    })
}

/// Carry the record of `before`, the raeva.lock a trace started from, to
/// `written`, the lock the trace wrote from it, while the file reads as it.
async fn record_traced(config: &Config, before: Option<&[u8]>, written: &Lockfile) {
    let (Some(before), Some(after)) = (before, lock_bytes(&config.lock_path)) else {
        return;
    };
    if !reads_as(&after, written) {
        return;
    }
    let Ok(client) = RepoClient::new(config).await else {
        return;
    };
    if let Some((_, platforms)) = (client.checked_lock(&checked_key(config, before)))
        .filter(|(at, _)| *at == lock_digest(before))
    {
        let project = checked_key(config, &after);
        client.record_checked_lock(&project, &lock_digest(&after), &platforms);
    }
}

fn reads_as(bytes: &[u8], lock: &Lockfile) -> bool {
    (std::str::from_utf8(bytes).ok())
        .and_then(|text| Lockfile::from_toml(text).ok())
        .as_ref()
        == Some(lock)
}

fn lock_digest(bytes: &[u8]) -> String {
    rv_maven_types::Sha256::from_bytes(bytes).to_string()
}

/// The project a checked raeva.lock is recorded for: its canonical root,
/// and the lock hash of `lock`'s inputs with the host's directories as they
/// are, which the lock's own hash reads as markers.
fn checked_key(config: &Config, lock: &[u8]) -> String {
    let raw = (std::str::from_utf8(lock).ok())
        .and_then(|text| Lockfile::from_toml(text).ok())
        .and_then(|lock| {
            resolution_config_hash(&config.with_host_paths(), &recorded_ambient(&lock)).ok()
        });
    format!("{}\n{}", project_key(config), raw.unwrap_or_default())
}

/// The project a SNAPSHOT check is recorded for: its canonical root.
fn project_key(config: &Config) -> String {
    let root = &config.project_root;
    (dunce::canonicalize(root).unwrap_or_else(|_| root.clone()))
        .to_string_lossy()
        .into_owned()
}

fn recorded_platforms(lock: &Lockfile) -> Vec<Platform> {
    (lock.platforms.iter())
        .map(|entry| entry.platform.clone())
        .collect()
}

fn model_for<'a>(models: &'a [ReactorModel], platform: &Platform) -> &'a ReactorModel {
    models
        .iter()
        .find(|model| model.platform == *platform)
        .expect("model discovered for every requested platform")
}

/// The platforms this run resolves: the ones `--platforms` names, else every
/// platform raeva.lock records, else, with no lock yet, the current platform.
/// A lock is never extended to the current platform unasked, so a machine on
/// another OS checks and rewrites the lock it was given.
fn resolve_platforms(
    requested: &[Platform],
    recorded: &[Platform],
    jdks: &[String],
) -> Result<Vec<Platform>> {
    let requested = if !requested.is_empty() {
        requested.to_vec()
    } else if !recorded.is_empty() {
        recorded.to_vec()
    } else {
        vec![Platform::current()?]
    };
    let mut base_platforms = Vec::new();
    for platform in requested {
        let base = platform.without_jdk();
        if !base_platforms.contains(&base) {
            base_platforms.push(base);
        }
    }
    if jdks.is_empty() {
        return Ok(base_platforms);
    }
    let mut platforms = Vec::with_capacity(base_platforms.len() * jdks.len());
    for base in base_platforms {
        for jdk in jdks {
            platforms.push(base.clone().with_jdk(jdk.clone()));
        }
    }
    Ok(platforms)
}
