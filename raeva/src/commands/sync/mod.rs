mod disk;
mod download;
mod drift;
mod merge;
mod regenerate;
mod resolve;
pub(crate) use drift::lock_needs_fresh_resolution;
pub(crate) use resolve::{WORKSPACE_STALL_TIMEOUT_ENV, count_stored, validate_frozen_resolution};
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
use self::resolve::{
    ResolvedReactorLock, check_origin_aliases, check_resolution, resolve_reactor_lock,
};
use self::system_scope::warn_system_scope_from_lock;
use crate::commands::lock_inputs::{
    ReactorModel, check_recorded_freshness, declared_repository_urls, discover_reactor_models,
    frozen_models_match, recorded_ambient, resolution_config_hash,
};

#[derive(Debug, Args)]
#[command(
    after_long_help = crate::commands::util::help_examples(&[
        ("sync", "Resolve and lock dependencies"),
        ("sync --frozen", "CI mode: fail if lockfile would change"),
        ("sync --update", "Force fresh resolution"),
        ("sync --offline", "Use cached data and file repositories"),
        ("sync --platforms linux-x86_64,macos-aarch64", ""),
    ])
)]
pub(crate) struct SyncArgs {
    #[arg(
        long,
        short = 'f',
        help = "Fail if raeva.lock would change, using the locked SNAPSHOT builds (CI mode)"
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

/// The topmost directory whose pom.xml lists `root` as a module, unless a
/// raeva.lock or raeva.toml in `root` means it is locked on its own on purpose.
pub(crate) fn enclosing_reactor(root: &Path) -> Option<PathBuf> {
    if ["raeva.lock", "raeva.toml"]
        .iter()
        .any(|name| root.join(name).exists())
        || !root.join("pom.xml").is_file()
    {
        return None;
    }
    let start = std::fs::canonicalize(root).ok()?;
    let lists = |dir: &Path, member: &Path| {
        let Ok(bytes) = std::fs::read(dir.join("pom.xml")) else {
            return false;
        };
        let pom = rv_maven_model::decode_pom(&bytes)
            .ok()
            .and_then(|text| rv_maven_model::Pom::parse(&text).ok());
        // Only the literal top-level entries, with either separator, as
        // discovery reads them. A profile, even one active by default, and a
        // property may be switched off or overridden from outside the POM, and
        // a refusal must never be wrong; a miss only writes the second lock.
        pom.is_some_and(|pom| {
            pom.modules.iter().any(|entry| {
                let entry = entry.trim().replace('\\', "/");
                !entry.contains("${")
                    && std::fs::canonicalize(rv_fs::join_pom_entry(dir, &entry))
                        .is_ok_and(|path| path == member || path == member.join("pom.xml"))
            })
        })
    };
    // An entry may skip a directory without a pom.xml, as `modules/io` does.
    let mut reactor: Option<&Path> = None;
    for dir in start.ancestors().skip(1) {
        if lists(dir, reactor.unwrap_or(&start)) {
            reactor = Some(dir);
        }
    }
    reactor.map(rv_fs::plain_path)
}

pub(crate) async fn run(args: &SyncArgs, session: &Session) -> Result<Report> {
    let config = session.config_async().await?;
    // One timer for the whole run, so the JSON `duration_ms` and the
    // durations in text mode agree.
    let start = Instant::now();
    let outcome = run_inner(
        args,
        session.offline(),
        session.project_root(),
        &config,
        start,
        session.output(),
    )
    .await?;
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
}

enum Headline {
    /// `--frozen`, or a lock reused as written: nothing was resolved.
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
    let mode = if args.frozen {
        "frozen"
    } else if args.update {
        "update"
    } else {
        "normal"
    };
    tracing::info!(
        path = %project_root.display(),
        mode,
        offline,
        "sync started"
    );

    let pom_path = config.project_root.join("pom.xml");
    let pom_exists = pom_path.is_file();

    // Hold an exclusive advisory lock on the project-level lockfile guard
    // for the entire read-resolve-write sequence. It keeps two concurrent
    // `raeva sync` runs with disjoint --platform sets from racing on raeva.lock,
    // where the last writer would win and drop the other's platform
    // entries. It lives in the cache directory, so only runs that share it
    // take turns. The guard is released when this binding goes out of scope.
    //
    // The async variant waits on the blocking pool, so the wait does not pin
    // a tokio worker, and gives up after 60 s, as `rv-store`'s
    // `StoreLock` does, so a wedged holder surfaces as an error.
    //
    // Acquire before the local --frozen checks so those checks read the same
    // raeva.lock a concurrent writer cannot rewrite. --frozen never writes
    // raeva.lock; the race is another process writing while this one keeps a
    // pre-guard snapshot. Local frozen checks still run before the store or
    // metadata cache open.
    let _lockfile_guard = LockfileGuard::acquire_async(
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
    })?;
    let frozen = (args.frozen)
        .then(|| check_frozen_local(config, args, pom_exists))
        .transpose()?;
    // raeva.lock as it is under the guard: a plain sync takes the recorded
    // platforms from it, so it keeps a platform a concurrent sync just added,
    // and starts from it.
    let on_disk = (!args.frozen).then(|| read_lockfile_at(&config.lock_path));
    let unreadable = match &on_disk {
        Some(Err(CliError::LockfileTooNew { found, expected })) => {
            return Err(CliError::LockfileTooNew {
                found: *found,
                expected: *expected,
            });
        }
        Some(Err(CliError::LockfileIncompatible { reason, .. })) => Some(
            regenerate::Unreadable::read(&config.lock_path, reason).ok_or_else(|| {
                CliError::InvalidProjectInput {
                    path: config.lock_path.clone(),
                    reason: format!(
                        "{reason}; a sync cannot read it whole to keep the platforms it names, \
                         so delete it and run 'raeva sync'"
                    ),
                }
            })?,
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
        (checked.platforms.clone(), &scoped)
    } else {
        let recorded = match (on_disk.as_ref(), unreadable.as_ref()) {
            (Some(Ok(lock)), _) => recorded_platforms(lock),
            (_, Some(unreadable)) => unreadable.platforms.clone(),
            _ => Vec::new(),
        };
        let platforms = resolve_platforms(args, &recorded, &config.lock.jdks)?;
        scoped = config.for_platforms(
            platforms
                .iter()
                .map(|platform| (platform.os(), platform.arch(), platform.jdk())),
        );
        (platforms, &scoped)
    };

    let store = Arc::new(Store::open(&config.paths.store_dir)?);
    check_disk_space(&config.paths.store_dir);
    let client = RepoClient::new(config)
        .await?
        .with_progress(output.progress())
        .with_offline(offline)
        .with_update(args.update)
        .with_pinned_snapshots(args.frozen)
        .with_allow_missing_checksums(args.allow_missing_checksums);
    let mut run = SyncRun {
        args,
        offline,
        config,
        platforms,
        store,
        client,
        widened,
        start,
        output,
    };

    if let Some(checked) = frozen {
        run.client = run.client.with_lock_pins(&checked.lock);
        return run.frozen(checked).await;
    }

    if !pom_exists {
        return Err(CliError::ProjectFileMissing {
            path: pom_path.clone(),
        });
    }
    if !config.lock.jdks.is_empty() {
        let host_jdk = config.host().java_version();
        if !config
            .lock
            .jdks
            .iter()
            .any(|jdk| rv_config::jdk_matches_target(jdk, host_jdk))
        {
            let listed = config.lock.jdks.join(", ");
            tracing::warn!(
                sec_code = "JDK_NOT_LOCKED",
                jdk = %host_jdk,
                "[lock] jdks ({listed}) does not include this JDK ({host_jdk}); resolving the listed JDKs"
            );
        }
    }
    let models = discover_reactor_models(config, &run.platforms)?;

    check_origin_aliases(config, declared_repository_urls(config, &models))?;
    // Read once: an incompatible lockfile is replaced whole, so it neither
    // short-circuits this run nor carries pins or metadata forward.
    let previous_lock = match on_disk {
        Some(Ok(lock)) => Some(lock),
        Some(Err(CliError::LockfileMissing { .. } | CliError::LockfileIncompatible { .. }))
        | None => None,
        Some(Err(err)) => return Err(err),
    };
    if let Some(lock) = previous_lock.as_ref() {
        run.client = run.client.with_lock_pins(lock);
    }

    if !args.update
        && let Some(lock) = previous_lock.as_ref()
        && let Some(outcome) = run.reuse(lock, &models, false).await?
    {
        return Ok(outcome);
    }
    let baseline = unreadable.and_then(|unreadable| unreadable.head);
    run.resolve_and_write(&models, previous_lock.as_ref(), baseline.as_ref())
        .await
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
        offline: bool,
        allow_missing_checksums: bool,
        update: bool,
    ) -> Result<Self> {
        let config = config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
        let client = RepoClient::new(&config)
            .await?
            .with_progress(output.progress())
            .with_offline(offline)
            .with_update(update)
            .with_pinned_snapshots(!update)
            .with_allow_missing_checksums(allow_missing_checksums)
            .with_lock_pins(lock);
        Ok(Self::from_client(config, client, platform.clone()))
    }

    pub(crate) fn from_client(config: Config, client: RepoClient, platform: Platform) -> Self {
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
            self.trusted = resolve_reactor_lock(
                &self.config,
                store,
                self.client.clone(),
                &self.platforms,
                models,
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
    offline: bool,
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
    /// `--frozen` after [`check_frozen_local`]: reuse current pins or compare a
    /// fresh resolution, without writing the lockfile.
    async fn frozen(&self, checked: FrozenLocal) -> Result<SyncOutcome> {
        let config = self.config;
        let FrozenLocal {
            lock,
            models,
            platforms,
            models_match,
        } = checked;
        let selected = lock
            .select_platforms(&platforms)
            .expect("recorded platform");
        if self.offline {
            // Offline freshness checks keep their existing model scope and
            // do not refresh SNAPSHOTs or restore artifacts.
            // The repositories a resolution trusts, a remote parent's
            // included: files they served count as stored.
            let mut resolved = None;
            if !models_match || lock_references_unconfigured_origin(&selected, config, &models) {
                resolved = Some(
                    validate_frozen_resolution(
                        config,
                        self.store.clone(),
                        self.client.clone(),
                        &lock,
                        &models,
                        self.output,
                    )
                    .await?
                    .1,
                );
            }
            // Offline nothing is downloaded, so check that the store has
            // what an offline build needs, apart from whether the lock is
            // current.
            let mut trusted = (self.client.policy())
                .admit(
                    models.iter().flat_map(ReactorModel::declared_repositories),
                    rv_repo::Declaration::LocalPom,
                )
                .admitted;
            let resolve = resolved.is_none().then_some(models.as_slice());
            trusted.extend(resolved.unwrap_or_default());
            let store = self.store.clone();
            let (missing, files) = count_stored(
                config,
                store,
                &self.client,
                &selected,
                &platforms,
                &mut trusted,
                resolve,
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
        } else {
            // Use the same reuse decision and restoration as plain sync. A
            // changed model of a platform not selected resolves them all.
            if models_match && let Some(outcome) = self.reuse(&lock, &models, models_match).await? {
                return Ok(outcome);
            }
            let resolving: Vec<_> = models.iter().map(|model| model.platform.clone()).collect();
            let mut resolved = resolve_reactor_lock(
                self.config,
                self.store.clone(),
                self.client.clone(),
                &resolving,
                &models,
            )
            .await?;
            let downloads = with_origins_of(&selected, &resolved.lock);
            merge_previous(
                config,
                &mut resolved.lock,
                Some(&lock),
                &models,
                &resolved.reads,
                &resolved.trusted_repositories,
            )?;
            check_resolution(config, &lock, &resolved, &models, self.output)?;
            self.download_lock(&downloads, &models, Some(&resolved))
                .await?;
        }
        Ok(self.finish(&selected, Vec::new(), Headline::Checked))
    }

    /// `matched` when [`frozen_models_match`] already holds for `previous`
    /// and `models`: it then holds for any selection of their platforms.
    async fn reuse(
        &self,
        previous: &Lockfile,
        models: &[ReactorModel],
        matched: bool,
    ) -> Result<Option<SyncOutcome>> {
        let config = self.config;
        let config_hash = resolution_config_hash(config, &recorded_ambient(previous))?;
        if previous.config_hash.as_deref() != Some(config_hash.as_str()) {
            return Ok(None);
        }
        // A requested platform missing from the lockfile is a cache miss:
        // fall through to resolution instead of erroring.
        let Ok(selected) = previous.select_platforms(&self.platforms) else {
            return Ok(None);
        };
        // A plain online sync restores a lock whose origins only a remote
        // POM declares, establishing that trust while it restores;
        // `--frozen` and `--offline` resolve to check them.
        let check_origins = self.args.frozen || self.offline;
        // Only a plain sync looks for newer SNAPSHOT builds once their update
        // policy expires; `--frozen` restores the locked ones. A changed
        // system file drops the platform that records it, selected or not.
        if previous.system_file_drift(&config.project_root).is_some()
            || !(matched || frozen_models_match(&selected, models))
            || (!self.args.frozen && lock_requires_snapshot_refresh(&selected, config, models))
            || (check_origins && lock_references_unconfigured_origin(&selected, config, models))
        {
            return Ok(None);
        }
        // `--offline` opts out of any network call; treat the fast-path
        // as resolution-only and skip the artifact download.
        if !self.offline {
            self.output.step("Downloading the locked artifacts...");
            if !self.download_lock(&selected, models, None).await? {
                return Ok(None);
            }
        }
        Ok(Some(self.finish(&selected, Vec::new(), Headline::Checked)))
    }

    async fn resolve_and_write(
        &self,
        models: &[ReactorModel],
        previous: Option<&Lockfile>,
        baseline: Option<&Lockfile>,
    ) -> Result<SyncOutcome> {
        let config = self.config;
        self.output.step("Resolving dependencies...");
        let resolved = resolve_reactor_lock(
            self.config,
            self.store.clone(),
            self.client.clone(),
            &self.platforms,
            models,
        )
        .await?;
        if !self.args.update
            && let Some(previous) = previous
        {
            download::check_repinned(previous, &resolved.lock)?;
        }
        self.output.step("Downloading artifacts...");
        self.download_lock(&resolved.lock, models, Some(&resolved))
            .await?;
        let mut lock = resolved.lock;
        merge_previous(
            config,
            &mut lock,
            previous,
            models,
            &resolved.reads,
            &resolved.trusted_repositories,
        )?;
        warn_system_scope_from_lock(&lock);
        lock.warn_on_env_values(config.host().env_values());
        let before = lock_bytes(&config.lock_path);
        lock.write_atomic(&config.lock_path)
            .map_err(|err| match err {
                rv_lock::LockError::Io { source, .. } => CliError::io_at(&config.lock_path)(source),
                other => other.into(),
            })?;
        let headline = match before {
            None => Headline::Wrote,
            Some(before) if lock_bytes(&config.lock_path).as_deref() == Some(&before[..]) => {
                Headline::UpToDate
            }
            Some(_) => Headline::Updated,
        };
        // A regenerated lock lists its changes against the one git has.
        let changes = match (&headline, previous.or(baseline)) {
            (Headline::Updated, Some(previous)) => {
                lock_diff(previous, &lock, &self.platforms, self.output.is_verbose())
            }
            _ => Vec::new(),
        };

        let outcome = self.finish(&lock, changes, headline);
        tracing::info!(
            artifacts = outcome.dep_count,
            elapsed_ms = self.start.elapsed().as_millis() as u64,
            "sync complete"
        );
        Ok(outcome)
    }

    /// Restore each platform with its own settings, declarations and policies.
    /// Without `resolved`, a platform whose rows name a repository only a
    /// remote POM declares is resolved first to establish that trust, and
    /// the result is false, with nothing restored, when a row or a file to
    /// restore still names a repository no declaration of its platform
    /// does: the lock must be resolved again.
    async fn download_lock(
        &self,
        lock: &Lockfile,
        models: &[ReactorModel],
        resolved: Option<&ResolvedReactorLock>,
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
                    self.client.clone(),
                    platform.clone(),
                )
            } else {
                LockDownloadContext::new(
                    self.config,
                    lock,
                    platform,
                    self.output,
                    self.offline,
                    self.args.allow_missing_checksums,
                    self.args.update,
                )
                .await?
            };
            if let Some(resolved) = resolved {
                context.trusted = resolved.repositories_for(platform).to_vec();
            } else {
                context.trust_model(std::slice::from_ref(model_for(models, platform)));
            }
            contexts.push(context);
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
        if self.offline {
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

    /// What every successful mode ends with.
    fn finish(&self, lock: &Lockfile, changes: Vec<String>, headline: Headline) -> SyncOutcome {
        SyncOutcome {
            dep_count: count_dependencies(lock),
            platforms: self.platforms.clone(),
            changes,
            headline,
        }
    }
}

/// A lockfile that passed the checks of `--frozen` that need no store,
/// network or cache.
struct FrozenLocal {
    lock: Lockfile,
    models: Vec<ReactorModel>,
    platforms: Vec<Platform>,
    /// [`frozen_models_match`] of `lock` and `models`.
    models_match: bool,
}

/// The `[lock] jdks` entry that covers `host_jdk`: its feature release, as
/// `25` covers `25.0.1`.
fn jdk_entry(host_jdk: &str) -> String {
    let host = host_jdk.trim();
    match host.split(['.', '_', '-', '+']).next() {
        Some(major) if major != "1" && rv_config::is_valid_jdk(major) => major.to_string(),
        _ => crate::output::inline_text(host).into_owned(),
    }
}

/// Discover the current models and check `config_hash` and the recorded
/// system files without resolving.
fn check_frozen_local(config: &Config, args: &SyncArgs, pom_exists: bool) -> Result<FrozenLocal> {
    let lock = read_lockfile(config)?;
    if !pom_exists {
        return Err(CliError::ProjectFileMissing {
            path: config.project_root.join("pom.xml"),
        });
    }
    let recorded = recorded_platforms(&lock);
    let platforms = resolve_platforms(args, &recorded, &config.lock.jdks)?;
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
    warn_system_scope_from_lock(&selected);
    let config = &config.for_platforms(
        recorded
            .iter()
            .map(|platform| (platform.os(), platform.arch(), platform.jdk())),
    );
    let mut models = discover_reactor_models(config, &recorded)?;
    let models_match = frozen_models_match(&lock, &models);
    // A changed model resolves every recorded platform, as a plain --frozen
    // does: a platform not selected cannot be kept without resolving it.
    if models_match {
        models.retain(|model| platforms.contains(&model.platform));
    }
    check_origin_aliases(config, declared_repository_urls(config, &models))?;
    check_recorded_freshness(
        config,
        &lock,
        &models,
        models_match,
        "raeva.lock has no config_hash, so --frozen cannot check it against the configuration",
    )?;
    if !config.lock.jdks.is_empty() {
        let host_jdk = config.host().java_version();
        if !config
            .lock
            .jdks
            .iter()
            .any(|jdk| rv_config::jdk_matches_target(jdk, host_jdk))
        {
            return Err(CliError::lockfile_mismatch_with(
                format!(
                    "raeva.lock covers the JDKs in [lock] jdks ({}), not this JDK ({host_jdk})",
                    config.lock.jdks.join(", ")
                ),
                format!(
                    "Run on a listed JDK, or add {} to [lock] jdks in raeva.toml and run \
                     'raeva sync'",
                    jdk_entry(host_jdk)
                ),
            ));
        }
    }
    Ok(FrozenLocal {
        lock,
        models,
        platforms,
        models_match,
    })
}

/// `lock` with each artifact row's repository taken from `fresh`'s row for
/// the same platform and coordinate, where it has one. Pins, snapshot
/// builds and everything else stay `lock`'s.
fn with_origins_of(lock: &Lockfile, fresh: &Lockfile) -> Lockfile {
    let mut lock = lock.clone();
    for platform in &mut lock.platforms {
        let Some(found) = fresh
            .platforms
            .iter()
            .find(|entry| entry.platform == platform.platform)
        else {
            continue;
        };
        for artifact in &mut platform.artifacts {
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
    args: &SyncArgs,
    recorded: &[Platform],
    jdks: &[String],
) -> Result<Vec<Platform>> {
    let requested = if !args.platforms.is_empty() {
        args.platforms.clone()
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
