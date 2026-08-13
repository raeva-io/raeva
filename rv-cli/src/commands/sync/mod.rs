//! `rv sync` orchestrator: arg parsing plus the high-level run loop.
//!
//! Submodules house focused concerns:
//! - [`diff`]: lockfile diff rendering
//! - [`system_scope`]: system-scope policy enforcement and warnings
//! - [`disk`]: free-space sanity check on the store volume

mod diff;
mod disk;
mod system_scope;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{ArgAction, Args, ValueEnum};
use sha2::{Digest, Sha256};
use strum::{AsRefStr, Display, EnumString};

use rv_config::{
    BlobId, Config, LOCK_SUPPORT_POMS_KEY, LockArtifact, LockCoordinate, LockModule,
    LockModulePackage, LockPackage, LockPlatform, LockResolution, LockResolutionStrategy,
    LockSnapshot, Lockfile, LockfileGuard, Platform, SupportPomLine, UpdatePolicy,
    decode_support_pom_lines, encode_support_pom_lines,
};
use rv_repo::{RepoClient, Repository, is_snapshot_version, normalize_repo_url};
use rv_resolver::{
    ResolutionResult, ResolutionStrategy, ResolveContext, ResolveState, Resolver,
    SupportPomProvenance, Workspace, accepted_local_parents, build_activation_context,
    local_parent_boundary, parse_maven_config,
};
use rv_store::Store;

use crate::commands::module_selector::LockModuleExt;
use crate::commands::read_lockfile;
use crate::error::{CliError, Result};
use crate::output::{
    ProgressReporter, action, heading, is_json_mode, json_result, quiet_enabled, result, success,
};

use self::diff::{format_frozen_diff, print_lock_diff};
use self::disk::check_disk_space;
use self::system_scope::{enforce_system_scope_policy, warn_system_scope_from_lock};

#[derive(Debug, Args)]
#[command(
    about = "Resolve dependencies, download artifacts, and update rv.lock",
    long_about = "Resolve dependencies, download artifacts, and update rv.lock.\n\n\
                  At a Maven reactor root, rv recursively discovers active modules and writes \
                  one schema-4 rv.lock containing every module graph plus a deduplicated external \
                  artifact union. --frozen rediscovers that reactor model, resolves the graph \
                  again, and fails on profile, module, GAV, POM, configuration, strategy, or \
                  graph drift. --frozen --offline checks the local inputs only and does not \
                  detect upstream drift, except when the lockfile records an artifact origin \
                  the configuration no longer declares: that is resolved again offline, from \
                  cached repository data, so the POMs decide whether the origin is authorized.",
    after_long_help = "\
Examples:
  rv sync                          # Resolve and lock dependencies
  rv sync --frozen                 # CI mode: fail if lockfile would change
  rv sync --update                 # Force fresh resolution
  rv sync --offline                # Use only cached metadata
  rv sync --platforms linux-x86_64,darwin-aarch64
"
)]
pub struct SyncArgs {
    #[arg(long, short = 'f', help = "Fail if rv.lock would change (CI mode)")]
    pub frozen: bool,
    #[arg(
        long,
        short = 'u',
        conflicts_with = "frozen",
        help = "Re-resolve all dependencies and update rv.lock"
    )]
    pub update: bool,
    #[arg(long, help = "Work offline using only cached data (no network)")]
    pub offline: bool,
    #[arg(
        long,
        value_name = "OS-ARCH",
        action = ArgAction::Append,
        value_delimiter = ',',
        value_parser = crate::commands::parse_platform,
        help = "Generate lockfile for specific os-arch pairs (e.g., linux-x86_64, darwin-aarch64)"
    )]
    pub platforms: Vec<Platform>,
    #[arg(
        long,
        value_enum,
        default_value = "nearest",
        help = "How to choose between conflicting versions"
    )]
    pub strategy: StrategyArg,
    #[arg(
        long,
        help = "Accept artifacts without a server-published checksum sidecar (SUPPLY-CHAIN RISK: a hostile or misconfigured mirror could serve unverified bytes; off by default)"
    )]
    pub allow_missing_checksums: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "lowercase")]
pub enum StrategyArg {
    #[default]
    Nearest,
    Highest,
}

impl From<StrategyArg> for ResolutionStrategy {
    fn from(arg: StrategyArg) -> Self {
        match arg {
            StrategyArg::Nearest => ResolutionStrategy::NearestWins,
            StrategyArg::Highest => ResolutionStrategy::HighestWins,
        }
    }
}

impl From<StrategyArg> for LockResolutionStrategy {
    fn from(arg: StrategyArg) -> Self {
        match arg {
            StrategyArg::Nearest => LockResolutionStrategy::Nearest,
            StrategyArg::Highest => LockResolutionStrategy::Highest,
        }
    }
}

/// Returns the elapsed duration since `start`, clamped to zero if the
/// monotonic clock somehow reports a regression.
fn elapsed_saturating(start: Instant) -> Duration {
    Instant::now()
        .checked_duration_since(start)
        .unwrap_or(Duration::ZERO)
}

pub async fn run(args: &SyncArgs, project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;
    // Single timer owned by `run` and threaded into `run_inner`. Minting
    // a second `Instant::now()` inside `run_inner` after acquiring the
    // lockfile guard would let the JSON `duration_ms` reported here and
    // the human-mode "Completed in Xs" inside `run_inner` disagree by
    // tens of milliseconds, more under heavy lock contention.
    let start = Instant::now();
    let outcome = run_inner(args, project_root, &config, start).await;
    match outcome {
        Ok(dep_count) => {
            if is_json_mode() {
                json_result(
                    true,
                    serde_json::json!({
                        "resolved": dep_count,
                        "duration_ms": start.elapsed().as_millis() as u64,
                    }),
                );
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
}

async fn run_inner(
    args: &SyncArgs,
    project_root: &Path,
    config: &Config,
    start: Instant,
) -> Result<usize> {
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
        offline = args.offline,
        "sync started"
    );

    // Hold an exclusive advisory lock on the project-level lockfile guard
    // for the entire read-resolve-write sequence. It keeps two concurrent
    // `rv sync` runs with disjoint --platform sets from racing on rv.lock,
    // where the last writer would win and drop the other's platform
    // entries. The guard is released when this binding goes out of scope.
    //
    // Use the async, polling-with-deadline variant so a stale guard from
    // a crashed `rv sync` cannot wedge subsequent invocations and the
    // 50 ms poll loop does not pin a tokio worker. The 60 s budget
    // matches `rv-store::store::StoreLock`'s `LOCK_TIMEOUT`.
    let _lockfile_guard = LockfileGuard::acquire_async(
        &config.paths.cache_dir,
        project_root,
        std::time::Duration::from_secs(60),
    )
    .await
    .map_err(|err| {
        CliError::Message(format!(
            "failed to acquire rv.lock guard in {}: {err}",
            project_root.display()
        ))
    })?;

    let platforms = resolve_platforms(args)?;
    let strategy: ResolutionStrategy = args.strategy.into();
    // `--strategy` changes version mediation without touching any hashed
    // configuration file, so it is recorded in the lockfile in its own right.
    let lock_strategy: LockResolutionStrategy = args.strategy.into();

    let pom_path = config.project_root.join("pom.xml");
    let pom_exists = pom_path.is_file();
    let config_hash = compute_resolution_config_hash(config)?;

    let store = Arc::new(Store::open(&config.paths.store_dir)?);
    check_disk_space(&config.paths.store_dir);
    let progress = Arc::new(ProgressReporter::new());
    let client = RepoClient::new(config)
        .await?
        .with_progress(progress)
        .with_offline(args.offline)
        .with_allow_missing_checksums(args.allow_missing_checksums);

    if args.frozen {
        let lock = read_lockfile(config)?;
        let selected = require_lock_for_platforms(&lock, &platforms)?;
        warn_system_scope_from_lock(&selected);
        let snapshot_refresh = lock_requires_snapshot_refresh(&selected, config);
        let rediscover_repositories = lock_references_unconfigured_origin(&selected, config);
        let models = if lock.schema_version == rv_config::LOCKFILE_SCHEMA_VERSION {
            if !pom_exists {
                check_frozen_config_hash(None, lock.config_hash.as_deref())?;
                unreachable!("missing manifest must fail the frozen hash gate");
            }
            let models = discover_reactor_models(config, &platforms)?;
            validate_frozen_models(&selected, &models)?;
            check_frozen_config_hash(Some(&config_hash), lock.config_hash.as_deref())?;
            check_frozen_strategy(lock.resolution.as_ref(), lock_strategy)?;
            Some(models)
        } else {
            // Schema 1-3 folded the root and local-parent POM bytes into
            // `config_hash`. A valid v3 single-module lock must still pass
            // `--frozen` without being rewritten, so fall back to that recipe.
            let legacy_hash = if pom_exists {
                Some(compute_config_hash(config, &pom_path)?)
            } else {
                None
            };
            if lock.config_hash.as_deref() != Some(config_hash.as_str()) {
                check_frozen_config_hash(legacy_hash.as_deref(), lock.config_hash.as_deref())?;
            }
            check_legacy_frozen_strategy(lock_strategy)?;
            None
        };
        if frozen_checks_local_inputs_only(
            args.offline,
            models.is_none(),
            snapshot_refresh,
            rediscover_repositories,
        ) {
            if !args.offline {
                ensure_artifacts(&selected, config, store.as_ref(), &client, &platforms, &[])
                    .await?;
            }
            let dep_count = count_dependencies(&selected);
            print_summary(dep_count, elapsed_saturating(start));
            if !is_json_mode() && !quiet_enabled() {
                eprintln!("{}", success("lockfile is up to date"));
            }
            print_completed(elapsed_saturating(start));
            return Ok(dep_count);
        }
        // Only a schema-4 lock reaches here, and that branch already proved the
        // manifest exists before discovering the models.
        let Some(models) = models else {
            unreachable!("a schema 1-3 lock is validated from local inputs alone");
        };
        enforce_workspace_system_scope_policy(&models)?;
        let resolved = resolve_reactor_lock(
            config,
            store.clone(),
            client.clone(),
            &platforms,
            &models,
            strategy,
            args.frozen,
        )
        .await?;
        if !lock_resolution_matches(&selected, &resolved.lock) {
            let diff = format_frozen_diff(&selected, &resolved.lock);
            let details = if diff.is_empty() {
                "dependencies would change from current lockfile. Run 'rv sync' to update rv.lock, or remove --frozen flag".to_string()
            } else {
                format!(
                    "dependencies would change from current lockfile. Run 'rv sync' to update rv.lock, or remove --frozen flag.\n\nChanged entries:\n{diff}"
                )
            };
            return Err(CliError::LockfileMismatch { details });
        }
        if !args.offline {
            ensure_artifacts(
                &selected,
                config,
                store.as_ref(),
                &client,
                &platforms,
                &resolved.trusted_repositories,
            )
            .await?;
        }
        let dep_count = count_dependencies(&selected);
        print_summary(dep_count, elapsed_saturating(start));
        if !is_json_mode() && !quiet_enabled() {
            eprintln!("{}", success("lockfile is up to date"));
        }
        print_completed(elapsed_saturating(start));
        return Ok(dep_count);
    }

    if !pom_exists {
        return Err(CliError::ProjectFileMissing {
            path: pom_path.clone(),
        });
    }
    let models = discover_reactor_models(config, &platforms)?;

    if !args.update && config.lock_path.is_file() {
        let lock = read_lockfile(config)?;
        if lock.schema_version == rv_config::LOCKFILE_SCHEMA_VERSION
            && lock.config_hash.as_deref() == Some(config_hash.as_str())
            // A lock resolved under a different (or unrecorded) strategy
            // mediated conflicting versions by other rules; reusing it would
            // silently ignore `--strategy`.
            && lock.resolution.as_ref().map(|resolution| resolution.strategy) == Some(lock_strategy)
            // `filter_lock` returns `Ok(None)` when any requested platform
            // is missing from the lockfile; treat that as a cache miss so
            // we fall through to resolution instead of erroring.
            && let Some(selected) = filter_lock(&lock, &platforms)?
            && frozen_models_match(&selected, &models)
            && !lock_requires_snapshot_refresh(&selected, config)
            && !lock_references_unconfigured_origin(&selected, config)
            // Schema 4 accepts the pre-pin shape so an existing lock keeps
            // working, but reusing it forever would leave those coordinates on
            // the store's mutable index — the thing schema 4's pins exist to
            // stop depending on. Falling through migrates the lock once, the
            // same way a schema-3 lock is rewritten on the next plain sync.
            && !lock_pins_incomplete(&selected)
        {
            // `--offline` opts out of any network call; treat the fast-path
            // as resolution-only and skip the artifact download.
            if !args.offline {
                action("Downloading", "artifacts from lockfile...");
                ensure_artifacts(&selected, config, store.as_ref(), &client, &platforms, &[])
                    .await?;
                result("Downloaded", "artifacts from lockfile");
            }
            // Diff the lockfile against itself so the human UX is the
            // same as the resolve path: a "no changes" section that
            // makes it obvious sync did inspect the graph. Otherwise an
            // unchanged sync goes silent and looks indistinguishable from
            // a no-op cache hit.
            print_lock_diff(&selected, &selected, &platforms);
            let dep_count = count_dependencies(&selected);
            print_summary(dep_count, elapsed_saturating(start));
            print_completed(elapsed_saturating(start));
            return Ok(dep_count);
        }
    }

    let previous_lock = if config.lock_path.is_file() {
        Some(Lockfile::read(&config.lock_path)?)
    } else {
        None
    };

    enforce_workspace_system_scope_policy(&models)?;
    action("Resolving", "dependencies...");
    let resolved = resolve_reactor_lock(
        config,
        store.clone(),
        client.clone(),
        &platforms,
        &models,
        strategy,
        args.frozen,
    )
    .await?;
    let mut lock = resolved.lock;
    lock.config_hash = Some(config_hash.clone());
    lock.resolution = Some(LockResolution::new(lock_strategy));

    action("Downloading", "artifacts...");
    ensure_artifacts(
        &lock,
        config,
        store.as_ref(),
        &client,
        &platforms,
        &resolved.trusted_repositories,
    )
    .await?;
    result("Downloaded", "artifacts");

    // Preserve platform entries from the previous lockfile that we did not
    // re-resolve this run. `rv sync --platforms linux-x86_64` would otherwise
    // overwrite the on-disk lockfile with only the requested platform and
    // silently drop every other platform's pins (data loss for cross-platform
    // CI matrices that sync each platform from its own runner).
    if let Some(previous) = previous_lock.as_ref() {
        let resolved: HashSet<Platform> =
            lock.platforms.iter().map(|p| p.platform.clone()).collect();
        // Carrying a platform forward republishes its graph under this run's
        // resolution inputs. An equal `model_hash` only says the local reactor
        // model is unchanged; if the configuration or the strategy changed,
        // that graph was never resolved against the inputs the new top-level
        // `config_hash` claims, so it has to be dropped and re-synced.
        let resolution_inputs_unchanged = previous.config_hash.as_deref()
            == Some(config_hash.as_str())
            && previous.resolution.as_ref().map(|r| r.strategy) == Some(lock_strategy);
        // Support-POM provenance is one global metadata block, not per-platform
        // data, so a preserved platform cannot keep its own copy. If this run
        // resolved a parent or BOM to different bytes than the previous
        // lockfile recorded, no preserved platform can be carried forward
        // truthfully: the surviving block would pin bytes half the lockfile was
        // never resolved against.
        let support_conflict = conflicting_support_pom_digest(previous, &lock)?;
        let fresh_pom_pins = companion_pom_pins(&lock);
        let fresh_support_poms = support_pom_pins(&lock)?;
        // Preserving any platform merges the previous lockfile's whole
        // support-POM block back in, including coordinates this run never
        // reached. One of those pinning a POM a freshly resolved artifact row
        // pins differently would be written into a lockfile the fresh
        // resolution contradicts, and the block is global rather than
        // per-platform, so — as with a support-vs-support disagreement — no
        // platform can be carried forward at all.
        let carried_support_conflict =
            conflicting_support_companion_pin(&support_pom_pins(previous)?, &fresh_pom_pins);
        let mut preserved_platforms = false;
        for prev_platform in &previous.platforms {
            if resolved.contains(&prev_platform.platform) {
                continue;
            }
            if !resolution_inputs_unchanged {
                report_dropped_reconfigured_platform(&prev_platform.platform);
                continue;
            }
            if let Some(coord) = support_conflict.as_deref() {
                report_dropped_conflicting_pom_platform(&prev_platform.platform, coord);
                continue;
            }
            if let Some(coord) = carried_support_conflict.as_deref() {
                report_dropped_conflicting_pom_platform(&prev_platform.platform, coord);
                continue;
            }
            // Maven has one local-repository path per GAV, so a preserved
            // platform pinning a different POM than a freshly resolved one
            // describes a `~/.m2` that cannot exist. Export would silently pick
            // one of them; drop the stale platform instead, with the same
            // restoration guidance a reconfigured platform gets.
            if let Some(coord) = conflicting_companion_pom_pin(&fresh_pom_pins, prev_platform) {
                report_dropped_conflicting_pom_platform(&prev_platform.platform, &coord);
                continue;
            }
            // The same one-path-per-GAV rule across the two maps: a preserved
            // platform's artifact row and this run's support-POM closure can
            // name the same `.pom` from independent observations.
            if let Some(coord) = conflicting_support_companion_pin(
                &fresh_support_poms,
                &platform_companion_pom_pins(prev_platform),
            ) {
                report_dropped_conflicting_pom_platform(&prev_platform.platform, &coord);
                continue;
            }
            match discover_reactor_model(config, &prev_platform.platform) {
                Ok(model) if prev_platform.model_hash == model.model_hash => {
                    lock.platforms.push(prev_platform.clone());
                    preserved_platforms = true;
                }
                Ok(_) => report_dropped_stale_platform(&prev_platform.platform),
                Err(err) => {
                    if !is_json_mode() && !quiet_enabled() {
                        eprintln!(
                            "Dropping stale platform {}: reactor model could not be rediscovered ({err})",
                            prev_platform.platform
                        );
                    }
                }
            }
        }
        lock.platforms
            .sort_by(|a, b| a.platform.to_string().cmp(&b.platform.to_string()));
        carry_forward_lock_data(&mut lock, previous, preserved_platforms)?;
    }

    // Last gate before the write, over the lockfile as it will be recorded:
    // the platform-dropping passes above cover a disagreement one preserved
    // platform is responsible for, and the merge is meant to leave none
    // behind, but a coordinate that is both a support POM and an artifact row
    // *within this run's own resolution* has no platform to drop.
    check_support_companion_agreement(&lock)?;
    lock.write_atomic(&config.lock_path)?;
    if let Some(previous) = previous_lock.as_ref() {
        print_lock_diff(previous, &lock, &platforms);
    }

    let dep_count = count_dependencies(&lock);
    print_summary(dep_count, elapsed_saturating(start));
    if !is_json_mode() && !quiet_enabled() {
        eprintln!("{}", heading("rv.lock updated"));
    }
    print_completed(elapsed_saturating(start));

    tracing::info!(
        artifacts = dep_count,
        elapsed_ms = elapsed_saturating(start).as_millis() as u64,
        "sync complete"
    );

    Ok(dep_count)
}

/// The `--frozen` gate on the recorded config hash. Every combination of a
/// present/absent manifest and a present/absent stored hash must either
/// verify or fail; falling through unverified would let the CI gate pass on
/// a lockfile that cannot be tied to its inputs.
fn check_frozen_config_hash(manifest_hash: Option<&str>, stored_hash: Option<&str>) -> Result<()> {
    match (manifest_hash, stored_hash) {
        (Some(current), Some(stored)) if current != stored => Err(CliError::LockfileMismatch {
            details:
                "rv.lock is out of date (pom.xml changed). Run 'rv sync' without --frozen to update"
                    .to_string(),
        }),
        (Some(_), Some(_)) => Ok(()),
        (Some(_), None) => {
            // pom.xml is present but the lockfile carries no config_hash,
            // so there is nothing to verify against. Deleting the
            // config_hash line from rv.lock must not defeat the CI gate.
            Err(CliError::LockfileMismatch {
                details: "rv.lock has no config_hash (it predates config_hash \
                     verification), so --frozen cannot verify it matches pom.xml. \
                     Run 'rv sync' without --frozen to update"
                    .to_string(),
            })
        }
        (None, Some(_)) => {
            // The lockfile was produced against a manifest that is now
            // missing; --frozen forbids a fresh resolve, so surface
            // this as a typed mismatch instead of falling through.
            Err(CliError::LockfileMismatch {
                details:
                    "rv.lock references a pom.xml that is missing. Run 'rv sync' without --frozen to update"
                        .to_string(),
            })
        }
        (None, None) => {
            // No pom.xml present and the lockfile has no config_hash.
            // --frozen is a CI gate; silently passing here means we
            // cannot verify the lockfile matches any inputs, which is
            // exactly what --frozen is supposed to prevent.
            Err(CliError::LockfileMismatch {
                details: "no pom.xml present and lockfile has no config_hash; \
                     cannot verify lockfile matches inputs. \
                     Run 'rv sync' from a directory containing pom.xml to update"
                    .to_string(),
            })
        }
    }
}

/// The `--frozen` gate on the recorded resolution strategy.
///
/// `--strategy` selects version mediation from the command line, so it leaves
/// no trace in `config_hash` or `model_hash`. A schema-4 lockfile that does
/// not name the strategy it was resolved under cannot be verified against the
/// requested one, which is exactly the ambiguity `--frozen` must refuse.
fn check_frozen_strategy(
    stored: Option<&LockResolution>,
    current: LockResolutionStrategy,
) -> Result<()> {
    match stored {
        Some(resolution) if resolution.strategy == current => Ok(()),
        Some(resolution) => Err(CliError::LockfileMismatch {
            details: format!(
                "rv.lock was resolved with --strategy {}, but this run requested \
                 --strategy {current}. Run 'rv sync --strategy {current}' to update rv.lock",
                resolution.strategy
            ),
        }),
        None => Err(CliError::LockfileMismatch {
            details: "rv.lock does not record the resolution strategy it was built with, \
                      so --frozen cannot verify it against --strategy. \
                      Run 'rv sync' without --frozen to update"
                .to_string(),
        }),
    }
}

/// The same gate for a schema 1-3 lockfile, which has no field to record a
/// strategy in at all.
///
/// That lock is validated from local inputs alone, and `--strategy` touches
/// none of them, so accepting a non-default one would report "lockfile is up
/// to date" for a run whose mediation rules the lock was never resolved under
/// — the ambiguity the schema-4 branch refuses through
/// [`check_frozen_strategy`]. A request for the default strategy is the one
/// case that stays verifiable: it is what any legacy lock was written with.
fn check_legacy_frozen_strategy(current: LockResolutionStrategy) -> Result<()> {
    if current == LockResolutionStrategy::from(StrategyArg::default()) {
        return Ok(());
    }
    Err(CliError::LockfileMismatch {
        details: format!(
            "rv.lock predates the schema that records the resolution strategy, so --frozen \
             cannot verify it against --strategy {current}. \
             Run 'rv sync' without --frozen to migrate rv.lock to the current schema"
        ),
    })
}

/// Compute the `config_hash` recorded in rv.lock and compared by `--frozen`
/// and the resolve fast-path.
///
/// The hash must cover every local input that can change the resolved graph,
/// otherwise `--frozen` and the fast-path silently reuse a stale lockfile.
/// That means the root `pom.xml`, the local parent-POM chain,
/// `.mvn/maven.config`, `rv.toml`, and the active settings/profiles. Each
/// input is folded in with a labelled, length-prefixed framing so two
/// distinct input sets cannot collide.
pub(crate) fn compute_config_hash(config: &Config, pom_path: &Path) -> Result<String> {
    let pom_xml = rv_config::read_project_input_string(pom_path)?;
    compute_config_hash_with_pom(config, pom_path, &pom_xml)
}

pub(crate) fn compute_config_hash_with_pom(
    config: &Config,
    pom_path: &Path,
    pom_xml: &str,
) -> Result<String> {
    let mut hasher = Sha256::new();

    // 1. Root pom.xml (always present at this call site).
    hash_labelled_bytes(&mut hasher, "pom.xml", pom_xml.as_bytes());

    // 2. The local parent-POM chain, walked by the resolver so this hash
    //    covers exactly the parents resolution accepts. `pom_path` is the
    //    project's own root POM, so it gets the lone-module boundary, and the
    //    `.mvn/maven.config` `-D` entries resolution overlays on it — a parent
    //    version interpolated from one of those names a POM this hash has to
    //    cover like any other.
    let parent_boundary =
        local_parent_boundary(pom_path.parent().unwrap_or_else(|| Path::new(".")), 1);
    let user_properties = parse_maven_config(&config.project_root);
    for (idx, parent_path) in
        accepted_local_parents(pom_path, pom_xml, &parent_boundary, &user_properties)
            .into_iter()
            .enumerate()
    {
        hash_labelled_file(&mut hasher, &format!("parent[{idx}]"), &parent_path)?;
    }

    // 3. `.mvn/maven.config`: CLI args (profiles, properties) Maven applies on
    //    every invocation.
    let maven_config = config.project_root.join(".mvn").join("maven.config");
    hash_labelled_file(&mut hasher, ".mvn/maven.config", &maven_config)?;

    // 4. Project rv.toml. `project_config_path` may be absent for a
    //    pom-only project; `hash_labelled_file` folds in a stable "missing"
    //    marker in that case.
    hash_labelled_file(&mut hasher, "rv.toml", &config.project_config_path)?;

    // 5. Active settings/profiles. The resolved active-profile id set is the
    //    load-bearing output of settings.xml + profile activation; folding it
    //    in means flipping `-P`/`<activeProfiles>` or an `activeByDefault`
    //    profile invalidates the lockfile.
    config.ensure_maven_settings_loaded();
    let mut profiles: Vec<&str> = config
        .active_profiles()
        .iter()
        .map(String::as_str)
        .collect();
    profiles.sort_unstable();
    profiles.dedup();
    hasher.update(b"active_profiles:");
    hasher.update((profiles.len() as u64).to_le_bytes());
    for profile in profiles {
        hasher.update((profile.len() as u64).to_le_bytes());
        hasher.update(profile.as_bytes());
    }

    // 6. User-level config.toml. Like the project rv.toml it can declare
    //    repositories/mirrors, so editing it must invalidate the lockfile.
    hash_labelled_file(&mut hasher, "user-config.toml", &config.user_config_path)?;

    // 7. Resolved repository set (id + url + release/snapshot policy), in
    //    order. Resolution is order-sensitive, and adding or retargeting a
    //    repository (via settings.xml, rv.toml, or a mirror) changes where
    //    artifacts resolve from even when the active-profile id set is
    //    unchanged, which the profile hash above would miss.
    let repos = config.repositories();
    hasher.update(b"repositories:");
    hasher.update((repos.len() as u64).to_le_bytes());
    for repo in repos {
        hash_str(&mut hasher, repo.id.as_deref().unwrap_or(""));
        hash_str(&mut hasher, &repo.url);
        hasher.update([tristate(repo.releases), tristate(repo.snapshots)]);
    }

    // 8. Mirror mappings (id + url + mirrorOf). A mirror change reroutes
    //    fetches without touching the active-profile set.
    let mirrors = config.mirrors();
    hasher.update(b"mirrors:");
    hasher.update((mirrors.len() as u64).to_le_bytes());
    for mirror in mirrors {
        hash_str(&mut hasher, mirror.id.as_deref().unwrap_or(""));
        hash_str(&mut hasher, &mirror.url);
        hasher.update((mirror.mirror_of.len() as u64).to_le_bytes());
        for entry in &mirror.mirror_of {
            hash_str(&mut hasher, entry);
        }
    }

    // NOTE: proxy and auth definitions are intentionally NOT folded in. They
    // affect transport and credentials, not which artifacts resolve, so a
    // credential rotation should not churn the lockfile. config_hash is also
    // written to the committed rv.lock, so hashing secrets would risk leaking
    // them via an offline dictionary attack on the digest.

    Ok(hex::encode(hasher.finalize()))
}

/// Compute schema 4's top-level configuration hash.
///
/// Exact recipe (framed with labels and lengths):
///
/// 1. `.mvn/maven.config` bytes (or a missing marker);
/// 2. resolved active and inactive configuration profile ids;
/// 3. configured repositories in precedence order, including release /
///    snapshot flags and snapshot update policy;
/// 4. mirror mappings in precedence order;
/// 5. resolution-affecting security policy and non-secret network settings;
/// 6. the configured local-repository path, when present.
///
/// POM bytes and effective reactor identity are per-platform `model_hash`
/// inputs and never appear here. Authentication and proxy credentials appear
/// in neither hash, so credential rotation cannot churn a committed lockfile
/// or leak through a digest.
pub(crate) fn compute_resolution_config_hash(config: &Config) -> Result<String> {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, "rv-config-hash-v2");
    hash_labelled_file(
        &mut hasher,
        ".mvn/maven.config",
        &config.project_root.join(".mvn").join("maven.config"),
    )?;

    config.ensure_maven_settings_loaded();
    hash_sorted_strings(&mut hasher, "active_profiles", config.active_profiles());
    hash_sorted_strings(&mut hasher, "inactive_profiles", &config.inactive_profiles);

    let repos = config.repositories();
    hasher.update(b"repositories:");
    hasher.update((repos.len() as u64).to_le_bytes());
    for repo in repos {
        hash_str(&mut hasher, repo.id.as_deref().unwrap_or(""));
        hash_str(&mut hasher, &normalize_repo_url(&repo.url));
        hasher.update([tristate(repo.releases), tristate(repo.snapshots)]);
        hash_str(
            &mut hasher,
            &repo.snapshots_update_policy.unwrap_or_default().to_string(),
        );
    }

    let mirrors = config.mirrors();
    hasher.update(b"mirrors:");
    hasher.update((mirrors.len() as u64).to_le_bytes());
    for mirror in mirrors {
        hash_str(&mut hasher, mirror.id.as_deref().unwrap_or(""));
        hash_str(&mut hasher, &normalize_repo_url(&mirror.url));
        hasher.update((mirror.mirror_of.len() as u64).to_le_bytes());
        for entry in &mirror.mirror_of {
            hash_str(&mut hasher, entry);
        }
    }

    hasher.update(b"network:");
    hasher.update(config.network.timeout.to_le_bytes());
    hasher.update((config.network.retries as u64).to_le_bytes());
    hasher.update((config.network.concurrency as u64).to_le_bytes());
    hasher.update(b"security:");
    hasher.update([u8::from(config.security.allow_transitive_repositories)]);
    hash_sorted_strings(
        &mut hasher,
        "allow_env_substitution",
        &config.security.allow_env_substitution,
    );
    hash_sorted_strings(
        &mut hasher,
        "transitive_repository_allowlist",
        &config.security.transitive_repository_allowlist,
    );
    hash_str(
        &mut hasher,
        config
            .local_repository()
            .and_then(Path::to_str)
            .unwrap_or_default(),
    );

    Ok(hex::encode(hasher.finalize()))
}

fn hash_sorted_strings(hasher: &mut Sha256, label: &str, values: &[String]) {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    hasher.update(label.as_bytes());
    hasher.update(b":");
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        hash_str(hasher, &value);
    }
}

#[derive(Debug, Clone)]
struct ReactorModel {
    platform: Platform,
    workspace: Workspace,
    model_hash: String,
    active_profiles: Vec<String>,
    pom_hashes: BTreeMap<String, String>,
}

/// Discover and hash one platform's reactor model without repository access.
///
/// Exact `model_hash` recipe:
///
/// 1. every active module in canonical root-relative path order, framed with
///    its path, effective interpolated GAV, and exact POM bytes;
/// 2. the sorted union of active settings/POM profile ids;
/// 3. exact bytes of every *accepted* local relative-path parent POM used by
///    an active module but not itself an active reactor module, deduplicated
///    by canonical path and labeled root-relatively. Accepted means the same
///    thing resolution means by it (see [`accepted_local_parents`]): inside
///    the reactor's parent boundary and carrying the declared parent
///    coordinates, expanded with the reactor's `.mvn/maven.config` `-D`
///    properties layered over the module's own, the way resolution expands
///    them. A parent resolution refuses is not a local model input, so it is
///    neither read nor hashed.
///
/// The hash excludes repository configuration, which belongs to the top-level
/// `config_hash`. It also excludes every external parent and BOM byte stream,
/// which is locked support POM content rather than a local model input.
fn discover_reactor_model(config: &Config, platform: &Platform) -> Result<ReactorModel> {
    let activation =
        build_activation_context(Some(config.project_root.clone()), config, Some(platform));
    let workspace = Workspace::discover_with_context(&config.project_root, activation)
        .map_err(|err| CliError::Message(format!("failed to discover Maven reactor: {err}")))?;

    let mut modules: Vec<_> = workspace.modules().iter().collect();
    modules.sort_by(|left, right| left.pom_path.cmp(&right.pom_path));
    let module_paths: HashSet<PathBuf> = modules
        .iter()
        .filter_map(|module| workspace.root().join(&module.pom_path).canonicalize().ok())
        .collect();

    let parent_boundary = workspace.local_parent_boundary();
    // The reactor root's `.mvn/maven.config` `-D` entries, which resolution
    // overlays on every module POM: without them the walk below expands a
    // `<parent>` version to different coordinates than resolution does, and
    // the parent it loads goes unhashed.
    let user_properties = workspace.user_properties();
    let mut active_profiles: BTreeSet<String> = config.active_profiles().iter().cloned().collect();
    let mut pom_hashes = BTreeMap::new();
    let mut local_parents: BTreeMap<PathBuf, (String, Vec<u8>)> = BTreeMap::new();
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, "rv-model-hash-v1");

    for module in modules {
        let gav = module.gav();
        let absolute = workspace.root().join(&module.pom_path);
        let bytes = rv_config::read_project_input(&absolute)?;
        hash_str(&mut hasher, &module.pom_path);
        hash_str(&mut hasher, &gav.group_id);
        hash_str(&mut hasher, &gav.artifact_id);
        hash_str(&mut hasher, &gav.version);
        hash_labelled_bytes(&mut hasher, "module-pom", &bytes);
        pom_hashes.insert(module.pom_path.clone(), sha256_hex(&bytes));
        active_profiles.extend(module.descriptor.active_profiles.iter().cloned());

        let xml = std::str::from_utf8(&bytes).map_err(|err| {
            CliError::Message(format!(
                "POM {} is not valid UTF-8: {err}",
                absolute.display()
            ))
        })?;
        for parent in accepted_local_parents(&absolute, xml, &parent_boundary, user_properties) {
            let canonical = parent.canonicalize().unwrap_or_else(|_| parent.clone());
            if module_paths.contains(&canonical) || local_parents.contains_key(&canonical) {
                continue;
            }
            let parent_bytes = rv_config::read_project_input(&parent)?;
            let label_path =
                pathdiff::diff_paths(&canonical, workspace.root()).unwrap_or(canonical.clone());
            let label = label_path.to_string_lossy().replace('\\', "/");
            local_parents.insert(canonical, (label, parent_bytes));
        }
    }

    let active_profiles: Vec<String> = active_profiles.into_iter().collect();
    hash_sorted_strings(&mut hasher, "active_profiles", &active_profiles);
    let mut parents: Vec<_> = local_parents.into_values().collect();
    parents.sort_by(|left, right| left.0.cmp(&right.0));
    for (path, bytes) in parents {
        hash_str(&mut hasher, &path);
        hash_labelled_bytes(&mut hasher, "local-parent-pom", &bytes);
        pom_hashes.insert(path, sha256_hex(&bytes));
    }

    Ok(ReactorModel {
        platform: platform.clone(),
        workspace,
        model_hash: hex::encode(hasher.finalize()),
        active_profiles,
        pom_hashes,
    })
}

fn discover_reactor_models(config: &Config, platforms: &[Platform]) -> Result<Vec<ReactorModel>> {
    platforms
        .iter()
        .map(|platform| discover_reactor_model(config, platform))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

const MODEL_PROFILES_EXTRA_KEY: &str = "rv_model_profiles";
const MODEL_POM_HASHES_EXTRA_KEY: &str = "rv_model_pom_hashes";

fn record_model_inputs(platform: &mut LockPlatform, model: &ReactorModel) {
    platform.extra.insert(
        MODEL_PROFILES_EXTRA_KEY.to_string(),
        toml::Value::Array(
            model
                .active_profiles
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    platform.extra.insert(
        MODEL_POM_HASHES_EXTRA_KEY.to_string(),
        toml::Value::Table(
            model
                .pom_hashes
                .iter()
                .map(|(path, digest)| (path.clone(), toml::Value::String(digest.clone())))
                .collect(),
        ),
    );
}

fn stored_model_profiles(platform: &LockPlatform) -> Option<Vec<String>> {
    let values = platform.extra.get(MODEL_PROFILES_EXTRA_KEY)?.as_array()?;
    values
        .iter()
        .map(|value| value.as_str().map(str::to_string))
        .collect()
}

fn stored_pom_hashes(platform: &LockPlatform) -> Option<BTreeMap<String, String>> {
    let table = platform.extra.get(MODEL_POM_HASHES_EXTRA_KEY)?.as_table()?;
    table
        .iter()
        .map(|(path, value)| Some((path.clone(), value.as_str()?.to_string())))
        .collect()
}

fn validate_frozen_models(lock: &Lockfile, models: &[ReactorModel]) -> Result<()> {
    for platform in &lock.platforms {
        let Some(model) = models
            .iter()
            .find(|model| model.platform == platform.platform)
        else {
            continue;
        };
        if platform.model_hash == model.model_hash {
            continue;
        }

        if let Some(stored) = stored_model_profiles(platform)
            && stored != model.active_profiles
        {
            return Err(model_mismatch(format!(
                "active Maven profiles changed for platform {} (locked: [{}], current: [{}])",
                platform.platform,
                stored.join(", "),
                model.active_profiles.join(", ")
            )));
        }

        let locked_paths: BTreeSet<&str> = platform
            .modules
            .iter()
            .map(|module| module.path.as_str())
            .collect();
        let current_paths: BTreeSet<&str> = model
            .workspace
            .modules()
            .iter()
            .map(|module| module.pom_path.as_str())
            .collect();
        if let Some(added) = current_paths.difference(&locked_paths).next() {
            return Err(model_mismatch(format!("reactor module added: {added}")));
        }
        if let Some(removed) = locked_paths.difference(&current_paths).next() {
            return Err(model_mismatch(format!("reactor module removed: {removed}")));
        }

        for locked in &platform.modules {
            let Some(current) = model
                .workspace
                .modules()
                .iter()
                .find(|module| module.pom_path == locked.path)
            else {
                continue;
            };
            let gav = current.gav();
            if locked.gav.group != gav.group_id
                || locked.gav.artifact != gav.artifact_id
                || locked.gav.version != gav.version
            {
                return Err(model_mismatch(format!(
                    "effective GAV changed for module {} (locked {}, current {})",
                    locked.path,
                    locked.display_gav(),
                    gav
                )));
            }
        }

        if let Some(stored) = stored_pom_hashes(platform) {
            for (path, digest) in &model.pom_hashes {
                if stored.get(path).is_some_and(|old| old != digest) {
                    let kind = if current_paths.contains(path.as_str()) {
                        "module POM"
                    } else {
                        "local parent POM"
                    };
                    return Err(model_mismatch(format!("{kind} changed: {path}")));
                }
            }
        }

        return Err(model_mismatch(format!(
            "reactor model changed for platform {}",
            platform.platform
        )));
    }
    Ok(())
}

fn model_mismatch(reason: String) -> CliError {
    CliError::LockfileMismatch {
        details: format!("rv.lock is out of date ({reason})"),
    }
}

fn frozen_models_match(lock: &Lockfile, models: &[ReactorModel]) -> bool {
    validate_frozen_models(lock, models).is_ok()
}

pub(crate) fn validate_current_models(config: &Config, lock: &Lockfile) -> Result<()> {
    let platforms: Vec<Platform> = lock
        .platforms
        .iter()
        .map(|platform| platform.platform.clone())
        .collect();
    let models = discover_reactor_models(config, &platforms)?;
    validate_frozen_models(lock, &models)
}

fn enforce_workspace_system_scope_policy(models: &[ReactorModel]) -> Result<()> {
    let mut seen = HashSet::new();
    for model in models {
        for module in model.workspace.modules() {
            if seen.insert(module.pom_path.clone()) {
                enforce_system_scope_policy(&model.workspace.root().join(&module.pom_path))?;
            }
        }
    }
    Ok(())
}

fn report_dropped_stale_platform(platform: &Platform) {
    if !is_json_mode() && !quiet_enabled() {
        eprintln!(
            "Dropping stale platform {platform}: reactor model changed; run `rv sync --platforms {platform}` to restore it"
        );
    }
}

fn report_dropped_reconfigured_platform(platform: &Platform) {
    if !is_json_mode() && !quiet_enabled() {
        eprintln!(
            "Dropping stale platform {platform}: resolution configuration changed since it was locked; run `rv sync --platforms {platform}` to re-sync it"
        );
    }
}

fn report_dropped_conflicting_pom_platform(platform: &Platform, coord: &str) {
    if !is_json_mode() && !quiet_enabled() {
        eprintln!(
            "Dropping stale platform {platform}: it pins a different POM for {coord} than this run resolved, and Maven has one local-repository path per coordinate; run `rv sync --platforms {platform}` to re-sync it"
        );
    }
}

#[cfg(test)]
fn hash_model_inputs(pom: &[u8], active_profiles: &[String]) -> String {
    let mut profiles = active_profiles.to_vec();
    profiles.sort();
    profiles.dedup();

    let mut hasher = Sha256::new();
    hash_labelled_bytes(&mut hasher, "module:pom.xml", pom);
    hasher.update(b"active_profiles:");
    hasher.update((profiles.len() as u64).to_le_bytes());
    for profile in profiles {
        hash_str(&mut hasher, &profile);
    }
    hex::encode(hasher.finalize())
}

/// Fold a labelled, length-prefixed string into `hasher`.
fn hash_str(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u64).to_le_bytes());
    hasher.update(s.as_bytes());
}

/// Stable 3-state encoding of an `Option<bool>` so the hash distinguishes
/// "unset" from an explicit `false`/`true` without baking in a default.
fn tristate(value: Option<bool>) -> u8 {
    match value {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    }
}

/// Fold a labelled, length-prefixed file (or a "missing" marker) into `hasher`.
/// The label + length framing keeps inputs unambiguous so two different sets of
/// files cannot hash to the same digest.
fn hash_labelled_file(hasher: &mut Sha256, label: &str, path: &Path) -> Result<()> {
    hasher.update(label.as_bytes());
    hasher.update(b":");
    match rv_config::read_optional_project_input(path)? {
        Some(bytes) => hash_present_bytes(hasher, &bytes),
        None => {
            hasher.update(b"missing");
        }
    }
    Ok(())
}

fn hash_labelled_bytes(hasher: &mut Sha256, label: &str, bytes: &[u8]) {
    hasher.update(label.as_bytes());
    hasher.update(b":");
    hash_present_bytes(hasher, bytes);
}

fn hash_present_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(b"present:");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn count_dependencies(lock: &Lockfile) -> usize {
    // Count unique coordinates across platforms rather than summing
    // per-platform package lists. A 2-platform lockfile that resolved
    // the same dep set would otherwise report 2× the real number,
    // misleading users about how many distinct artifacts `rv sync`
    // resolved. Platform-specific (e.g. native binary) packages still
    // count once each because their classifier/coord differs.
    let mut seen: HashSet<(String, String, String, String, Option<String>)> = HashSet::new();
    for platform in &lock.platforms {
        for package in platform
            .modules
            .iter()
            .flat_map(|module| module.packages.iter())
        {
            seen.insert((
                package.coordinate.group.clone(),
                package.coordinate.artifact.clone(),
                package.coordinate.version.clone(),
                package.coordinate.packaging.clone(),
                package.coordinate.classifier.clone(),
            ));
        }
    }
    seen.len()
}

fn print_summary(count: usize, elapsed: std::time::Duration) {
    let deps_word = if count == 1 {
        "dependency"
    } else {
        "dependencies"
    };
    result(
        "Resolved",
        format!("{} {} in {:.1}s", count, deps_word, elapsed.as_secs_f32()),
    );
}

fn print_completed(elapsed: std::time::Duration) {
    if is_json_mode() || quiet_enabled() {
        return;
    }
    eprintln!(
        "{}",
        success(format!("Completed in {:.1}s", elapsed.as_secs_f32()))
    );
}

fn resolve_platforms(args: &SyncArgs) -> Result<Vec<Platform>> {
    if args.platforms.is_empty() {
        return Ok(vec![Platform::current()?]);
    }
    let mut seen = HashSet::new();
    let mut platforms = Vec::new();
    for platform in &args.platforms {
        let key = platform.to_string();
        if seen.insert(key) {
            platforms.push(platform.clone());
        }
    }
    Ok(platforms)
}

/// Project the lockfile onto the requested platforms.
///
/// Returns `Ok(None)` when any requested platform is absent so callers
/// (notably the fast-path in `run_inner`) can treat the situation as a
/// cache miss and fall through to a full re-resolve. The strict
/// `--frozen` path turns this into a hard `PlatformMissing` error via
/// [`require_lock_for_platforms`].
fn filter_lock(lock: &Lockfile, platforms: &[Platform]) -> Result<Option<Lockfile>> {
    let mut filtered = Lockfile::new();
    for platform in platforms {
        match lock
            .platforms
            .iter()
            .find(|entry| entry.platform == *platform)
        {
            Some(entry) => filtered.platforms.push(entry.clone()),
            None => return Ok(None),
        }
    }
    // Preserve lockfile-level metadata so downstream consumers (config
    // hash checks, diff renderers, etc.) keep their existing inputs. The
    // `[metadata]` map comes along because support-POM provenance lives there
    // and is not per-platform data: dropping it would make `--frozen` read
    // every support-POM pin as newly added.
    filtered.config_hash = lock.config_hash.clone();
    filtered.resolution = lock.resolution.clone();
    filtered.metadata = lock.metadata.clone();
    Ok(Some(filtered))
}

/// `--frozen` variant of [`filter_lock`]: an absent platform is an error,
/// not a fallthrough signal, because `--frozen` forbids re-resolution.
fn require_lock_for_platforms(lock: &Lockfile, platforms: &[Platform]) -> Result<Lockfile> {
    for platform in platforms {
        if !lock
            .platforms
            .iter()
            .any(|entry| entry.platform == *platform)
        {
            return Err(CliError::PlatformMissing {
                platform: platform.to_string(),
            });
        }
    }
    // Safe to unwrap: we just verified every platform is present.
    Ok(filter_lock(lock, platforms)?.expect("all platforms present"))
}

/// Semantic equality for the `--frozen` mismatch check.
///
/// `Lockfile`'s derived `PartialEq` compares fields that legitimately
/// differ between a freshly-resolved value and a value read off disk
/// (e.g. `config_hash`, `metadata`, `extra`, and per-package
/// `config_hash`, `metadata`, and `extra`). This compares the canonical
/// dependency set and edges instead, so traversal order alone cannot make a
/// freshly resolved graph differ from the sorted, edge-remapped form on disk.
///
/// Snapshot artifacts keep a logical `-SNAPSHOT` coordinate in both module
/// graphs and the aggregate artifact table. Their timestamp/build identity is
/// compared separately: unchanged repository metadata is frozen-valid, while
/// a newly published snapshot is lockfile drift.
fn lock_resolution_matches(a: &Lockfile, b: &Lockfile) -> bool {
    let (Ok(a), Ok(b)) = (a.canonicalized(), b.canonicalized()) else {
        return false;
    };
    if a.platforms.len() != b.platforms.len() {
        return false;
    }
    // The on-disk selection carries platforms in CLI argument order while a
    // fresh resolve sorts them by name; key both sides identically before
    // zipping so ordering alone cannot register as drift.
    let mut a_platforms: Vec<&LockPlatform> = a.platforms.iter().collect();
    let mut b_platforms: Vec<&LockPlatform> = b.platforms.iter().collect();
    a_platforms.sort_by_key(|p| p.platform.to_string());
    b_platforms.sort_by_key(|p| p.platform.to_string());
    for (lhs, rhs) in a_platforms.into_iter().zip(b_platforms) {
        if lhs.platform != rhs.platform || lhs.modules.len() != rhs.modules.len() {
            return false;
        }
        let mut lhs_modules: Vec<_> = lhs.modules.iter().collect();
        let mut rhs_modules: Vec<_> = rhs.modules.iter().collect();
        lhs_modules.sort_by(|left, right| left.path.cmp(&right.path));
        rhs_modules.sort_by(|left, right| left.path.cmp(&right.path));
        for (left, right) in lhs_modules.into_iter().zip(rhs_modules) {
            if left.path != right.path
                || left.gav != right.gav
                || left.packaging != right.packaging
                || left.edges != right.edges
                || left.packages.len() != right.packages.len()
            {
                return false;
            }
            for (left_package, right_package) in left.packages.iter().zip(&right.packages) {
                if left_package.coordinate != right_package.coordinate
                    || left_package.direct_scope != right_package.direct_scope
                    || left_package.workspace_module != right_package.workspace_module
                    || left_package.system_path != right_package.system_path
                {
                    return false;
                }
            }
        }

        if lhs.artifacts.len() != rhs.artifacts.len() {
            return false;
        }
        let lhs_artifacts: BTreeMap<_, _> = lhs
            .artifacts
            .iter()
            .map(|artifact| (&artifact.coordinate, artifact))
            .collect();
        let rhs_artifacts: BTreeMap<_, _> = rhs
            .artifacts
            .iter()
            .map(|artifact| (&artifact.coordinate, artifact))
            .collect();
        for (coordinate, left) in lhs_artifacts {
            let Some(right) = rhs_artifacts.get(coordinate) else {
                return false;
            };
            // `pom_sha256` is part of what the lockfile guarantees: a
            // republished companion POM can change bytes without changing a
            // single edge (a parent bumping plugin configuration, say), and a
            // plain `rv sync` would rewrite the pin. Frozen has to report that
            // rather than call the lockfile up to date.
            if left.repo_url != right.repo_url
                || left.snapshot != right.snapshot
                || left.pom_sha256 != right.pom_sha256
                || checksum_drifted(&left.as_package(), &right.as_package())
            {
                return false;
            }
        }
    }

    support_pom_pins_match(&a, &b)
}

/// Compare the support-POM digests two lockfiles record.
///
/// Parent and imported-BOM POMs never become lockfile packages, so this
/// metadata block is the only place their bytes are pinned — and a parent POM
/// can be republished with different bytes and identical edges, which is
/// exactly the drift `--frozen` exists to catch.
///
/// Only coordinates the fresh resolution reached are compared, and a
/// coordinate it reached that the lockfile does not record counts as drift.
/// The on-disk block is a union across every platform in the file, including
/// ones a `--platforms` run did not re-resolve, so an entry present only on
/// disk is expected and says nothing.
fn support_pom_pins_match(on_disk: &Lockfile, fresh: &Lockfile) -> bool {
    let Some(fresh_encoded) = fresh.metadata.get(LOCK_SUPPORT_POMS_KEY) else {
        return true;
    };
    let (Ok(fresh_lines), Ok(disk_lines)) = (
        decode_support_pom_lines(fresh_encoded),
        decode_support_pom_lines(
            on_disk
                .metadata
                .get(LOCK_SUPPORT_POMS_KEY)
                .map(String::as_str)
                .unwrap_or_default(),
        ),
    ) else {
        return false;
    };
    fresh_lines.iter().all(|(coord, fresh_line)| {
        disk_lines
            .get(coord)
            .is_some_and(|disk_line| disk_line.sha256 == fresh_line.sha256)
    })
}

/// True when two pins for the same coordinate disagree on checksum in a way
/// `--frozen` treats as drift.
///
/// [`lock_resolution_matches`] compares a SNAPSHOT's timestamp and build
/// identity, so snapshots never drift on checksum alone. Release pins compare
/// digests only when both sides use the same algorithm. A lockfile holding a
/// sha1 fallback pin, written when the repository publishes no sha256 sidecar,
/// has no digest-for-digest comparison against a freshly resolved sha256 pin,
/// so a mixed-algorithm pair is inconclusive rather than a mismatch. The
/// coordinate and version checks still apply.
fn checksum_drifted(l: &LockPackage, r: &LockPackage) -> bool {
    if is_snapshot_version(&l.version) || is_snapshot_version(&r.version) {
        return false;
    }
    match (l.checksum.as_ref(), r.checksum.as_ref()) {
        (Some(lhs), Some(rhs)) => lhs.algorithm == rhs.algorithm && lhs.digest != rhs.digest,
        (None, None) => false,
        // One side pinned and the other not is a real change to what the
        // lockfile guarantees.
        _ => true,
    }
}

/// Decide whether a `--frozen` run may validate the lockfile from local inputs
/// alone instead of resolving the graph again.
///
/// Online `--frozen` on a schema-4 lock always resolves afresh. A version
/// range, `LATEST`/`RELEASE`, or a republished release POM changes the resolved
/// graph without changing any local input, so local hashes alone cannot decide
/// whether rv.lock would change.
///
/// Two cases keep the weaker local-inputs-only contract:
///
/// - A schema 1-3 lock, always. It carries no reactor identity to resolve
///   against: the adapter gives its single module a sentinel GAV, which no
///   real module can equal, so a fresh comparison reports drift for every
///   valid legacy lock. The exemption has to be unconditional, because a
///   stale SNAPSHOT or an unconfigured recorded origin would otherwise force
///   exactly that comparison. Such a lock passes the hash and strategy checks
///   (see [`check_legacy_frozen_strategy`]) and is validated no further; the
///   next non-frozen sync rewrites it to schema 4, after which the full
///   contract applies.
/// - `--offline`, which cannot reach a repository at all — with one exception:
///   a lockfile origin that only the current POM can authorize still forces a
///   re-resolve, because repository trust comes from the model, never from
///   lockfile metadata, and that question is answerable from the local model
///   and the cached POMs a previous sync left behind.
///
/// An expired SNAPSHOT update policy is deliberately NOT such an exception
/// offline. The cached `maven-metadata.xml` a re-resolve would need carries
/// exactly the TTL that decided the pins were stale (`update_policy_ttl`), so
/// the condition that would force the resolve also guarantees the cache entry
/// behind it has expired: the run could only ever abort with
/// `OfflineNotCached`, never report drift. Refusing to verify is the honest
/// outcome, and it is what the local-inputs-only contract already says.
fn frozen_checks_local_inputs_only(
    offline: bool,
    legacy_lock: bool,
    snapshot_refresh: bool,
    rediscover_repositories: bool,
) -> bool {
    legacy_lock || (offline && (snapshot_refresh || !rediscover_repositories))
}

/// True when a schema-4 lock still carries POM references the current format
/// pins by digest: an artifact row without `pom_sha256`, or a support-POM line
/// in the two-field form.
///
/// Both shapes are accepted on read for back-compat, and both leave the POM
/// they name to the content store's coordinate index, which is
/// last-writer-wins across every project sharing the store. Schema 4's
/// guarantee is that the POM a build sees is the one the lock was resolved
/// against, so a lock in that state has to be rewritten rather than reused
/// indefinitely.
///
/// Only the plain `rv sync` fast path consults this. `--frozen` writes no
/// lockfile, so it must not gain a migration trigger; what an unpinned lock
/// does there is decided by frozen's own comparison, unchanged. Offline (and
/// on a schema 1-3 lock) frozen validates from local inputs and accepts it; an
/// online frozen run resolves and reports the absent pins as drift through
/// [`lock_resolution_matches`], which is the truthful answer to "would rv.lock
/// change?" once a plain sync rewrites them.
///
/// The empty-versus-absent question the metadata block raises answers itself,
/// so no format marker is recorded for it. `resolve_reactor_lock` writes
/// [`LOCK_SUPPORT_POMS_KEY`] whenever the resolution reached any support POM,
/// and has done since before the digest field existed; the digest only widened
/// each line from two fields to three. An absent key therefore means "this
/// resolution has no parents or imported BOMs", which is nothing to migrate
/// under either format, and a present key states its own format per line.
///
/// A block that will not decode counts as incomplete: `Lockfile::read` already
/// rejects one, so this can only be reached by a caller holding a lockfile
/// built in memory, and re-resolving is the conservative answer either way.
fn lock_pins_incomplete(lock: &Lockfile) -> bool {
    let artifacts_unpinned = lock
        .platforms
        .iter()
        .flat_map(|platform| platform.artifacts.iter())
        .any(|artifact| artifact.pom_sha256.is_none());
    if artifacts_unpinned {
        return true;
    }
    let Some(encoded) = lock.metadata.get(LOCK_SUPPORT_POMS_KEY) else {
        return false;
    };
    match decode_support_pom_lines(encoded) {
        Ok(lines) => lines.values().any(|line| line.sha256.is_none()),
        Err(_) => true,
    }
}

fn lock_requires_snapshot_refresh(lock: &Lockfile, config: &Config) -> bool {
    let lockfile_age_secs = config
        .lock_path
        .metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .map(|elapsed| elapsed.as_secs() as i64)
        // Treat missing/unreadable mtime as "infinitely old" so a configured
        // TTL fires and we re-fetch SNAPSHOT metadata.
        .unwrap_or(i64::MAX);

    let mut policies: HashMap<String, UpdatePolicy> = HashMap::new();
    let default_policy = UpdatePolicy::default();

    for repo in config.repositories() {
        let policy = repo.snapshots_update_policy.unwrap_or(default_policy);
        policies.insert(normalize_repo_url(&repo.url), policy);
    }

    lock.platforms
        .iter()
        .flat_map(LockPlatform::external_packages)
        .any(|package| {
            if package.system_path.is_some() {
                return false;
            }
            if !is_snapshot_version(&package.version) {
                return false;
            }

            let policy = if package.repo_url.is_empty() {
                default_policy
            } else {
                let normalized = normalize_repo_url(&package.repo_url);
                policies.get(&normalized).copied().unwrap_or(default_policy)
            };

            let ttl = policy.ttl_secs();
            lockfile_age_secs >= ttl
        })
}

fn lock_references_unconfigured_origin(lock: &Lockfile, config: &Config) -> bool {
    let configured: HashSet<String> = config
        .repositories()
        .iter()
        .map(|repo| normalize_repo_url(&repo.url))
        .collect();
    lock.platforms
        .iter()
        .flat_map(LockPlatform::external_packages)
        .filter(|package| package.system_path.is_none() && !package.repo_url.is_empty())
        .any(|package| !configured.contains(&normalize_repo_url(&package.repo_url)))
}

async fn resolve_reactor_lock(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    platforms: &[Platform],
    models: &[ReactorModel],
    strategy: ResolutionStrategy,
    strict_parents: bool,
) -> Result<ResolvedReactorLock> {
    // The LRU caches are shared across the platform loop. Each platform pass
    // resolves the same dependency surface (BOMs, parent POMs, metadata
    // files), so a per-iteration `from_config` call would discard tens of
    // MB of warm cache between consecutive platforms.
    let shared_state = ResolveState::new();

    // Fan the per-platform resolution out via `try_join_all`, sharing the
    // same `Arc<ResolveState>`. Awaiting each platform serially would make
    // a two-platform matrix pay 2× the wall time even though both
    // resolutions hit the same warm caches independently.
    let futures: Vec<_> = platforms
        .iter()
        .map(|platform| {
            let model = models
                .iter()
                .find(|model| model.platform == *platform)
                .expect("model discovered for every requested platform")
                .clone();
            let ctx = ResolveContext::from_config_with_state(
                config.clone(),
                store.clone(),
                platform.clone(),
                Some(client.clone()),
                Arc::clone(&shared_state),
            );
            let resolver = Resolver::with_strategy(ctx, strategy).with_strict(strict_parents);
            async move {
                let resolution = resolver.resolve_workspace(&model.workspace).await?;
                Ok::<_, rv_resolver::ResolveError>((model, resolution))
            }
        })
        .collect();

    let resolved = futures::future::try_join_all(futures).await?;

    let mut lock = Lockfile::new();
    // Collect the id'd repositories that backed resolution (config + any
    // POM-declared ones discovered during the solve) across all platforms so
    // `rv export-m2` can label `_remote.repositories` markers with the correct
    // repository id for repos it cannot otherwise see, instead of defaulting
    // to `central`. Stored in the existing deterministic metadata map.
    let mut repo_ids: BTreeMap<String, String> = BTreeMap::new();
    for mirror in config.mirrors() {
        if let Some(id) = mirror.id.as_deref() {
            repo_ids.insert(normalize_repo_url(&mirror.url), id.to_string());
        }
    }
    let mut trusted_repositories: BTreeMap<String, Repository> = BTreeMap::new();
    // Support POM "g:a:v" -> serving repo id plus the SHA-256 of its bytes (a
    // parent/BOM can come from a different repo than its child), alongside the
    // module that contributed the entry so a byte-level disagreement between
    // two modules can name both of them.
    let mut support_poms: BTreeMap<String, AggregateSupportPom> = BTreeMap::new();
    // Companion-POM pins, keyed by the GAV whose single `.pom` they name, and
    // checked across every module of every platform: `rv export-m2` writes one
    // file per GAV into `~/.m2`, so two different digests for one GAV describe
    // a local repository that cannot exist.
    let mut companion_poms: BTreeMap<(String, String, String), AggregateCompanionPom> =
        BTreeMap::new();
    let repo_precedence: HashMap<String, usize> = config
        .repositories()
        .iter()
        .enumerate()
        .map(|(index, repo)| (normalize_repo_url(&repo.url), index))
        .collect();
    for (model, result) in resolved {
        let mut modules = Vec::with_capacity(result.modules.len());
        let mut artifacts: BTreeMap<LockCoordinate, AggregateArtifact> = BTreeMap::new();
        let result_platform = result.platform;

        for module in result.modules {
            let resolution = module.resolution;
            for repo in &resolution.trusted_repositories {
                trusted_repositories
                    .entry(normalize_repo_url(&repo.url))
                    .or_insert_with(|| repo.clone());
            }
            for (url, id) in &resolution.repositories {
                repo_ids.entry(url.clone()).or_insert_with(|| id.clone());
            }
            for (coord, provenance) in &resolution.support_pom_provenance {
                merge_support_pom(&mut support_poms, coord, provenance, &module.pom_path)?;
            }

            let mut packages = Vec::with_capacity(resolution.packages.len());
            for package in &resolution.packages {
                let resolved_coordinate = LockCoordinate::new(
                    &package.group_id,
                    &package.artifact_id,
                    &package.version,
                    &package.packaging,
                    package.classifier.clone(),
                );
                let coordinate = lock_coordinate(package);
                let workspace_module = workspace_module_for_package(&resolution, package);
                packages.push(LockModulePackage {
                    coordinate: coordinate.clone(),
                    direct_scope: package.direct_scope.clone(),
                    workspace_module: workspace_module.clone(),
                    system_path: package.system_path.clone(),
                    extra: package.extra.clone(),
                });

                if workspace_module.is_some() || package.system_path.is_some() {
                    continue;
                }
                let blob = resolution
                    .artifact_blobs
                    .get(&resolved_coordinate)
                    .ok_or_else(|| {
                    CliError::Message(format!(
                        "resolved external artifact {} for module {} has no content-store identity",
                        coordinate.format_coord(),
                        module.pom_path
                    ))
                })?;
                let pom_blob = resolution
                    .companion_pom_blobs
                    .get(&resolved_coordinate)
                    .ok_or_else(|| {
                        CliError::Message(format!(
                            "resolved external artifact {} for module {} has no companion POM identity",
                            coordinate.format_coord(),
                            module.pom_path
                        ))
                    })?;
                merge_companion_pom(
                    &mut companion_poms,
                    package,
                    pom_blob,
                    &result_platform,
                    &module.pom_path,
                )?;
                let artifact = lock_artifact(package, coordinate.clone(), pom_blob);
                let rank = repo_precedence
                    .get(&normalize_repo_url(&package.repo_url))
                    .copied()
                    .unwrap_or(usize::MAX);
                match artifacts.get_mut(&coordinate) {
                    Some(existing) if existing.blob != *blob => {
                        return Err(CliError::Resolve(
                            rv_resolver::ResolveError::ConflictingArtifactBytes {
                                coord: coordinate.format_coord(),
                                first_module: existing.module_path.clone(),
                                second_module: module.pom_path.clone(),
                                first_blob: existing.blob.to_string(),
                                second_blob: blob.to_string(),
                            },
                        ));
                    }
                    Some(existing)
                        if (rank, normalize_repo_url(&artifact.repo_url))
                            < (
                                existing.repo_rank,
                                normalize_repo_url(&existing.artifact.repo_url),
                            ) =>
                    {
                        existing.artifact = artifact;
                        existing.repo_rank = rank;
                    }
                    Some(_) => {}
                    None => {
                        artifacts.insert(
                            coordinate,
                            AggregateArtifact {
                                artifact,
                                blob: blob.clone(),
                                module_path: module.pom_path.clone(),
                                repo_rank: rank,
                            },
                        );
                    }
                }
            }

            modules.push(LockModule {
                path: module.pom_path,
                gav: resolution.module_gav,
                packaging: resolution.module_packaging,
                packages,
                edges: resolution.edges,
                extra: BTreeMap::new(),
            });
        }

        let mut platform = LockPlatform {
            platform: result_platform,
            model_hash: model.model_hash.clone(),
            artifacts: artifacts
                .into_values()
                .map(|aggregate| aggregate.artifact)
                .collect(),
            modules,
            extra: BTreeMap::new(),
        };
        record_model_inputs(&mut platform, &model);
        lock.platforms.push(platform);
    }

    lock.platforms
        .sort_by(|a, b| a.platform.to_string().cmp(&b.platform.to_string()));

    if !repo_ids.is_empty() {
        // Deterministic `url\tid` lines (BTreeMap is sorted), one per repo.
        let encoded = repo_ids
            .iter()
            .map(|(url, id)| format!("{url}\t{id}"))
            .collect::<Vec<_>>()
            .join("\n");
        lock.metadata.insert(LOCK_REPO_IDS_KEY.to_string(), encoded);
    }
    if !support_poms.is_empty() {
        let lines = support_poms
            .iter()
            .map(|(coord, entry)| {
                (
                    coord.clone(),
                    SupportPomLine {
                        repo_id: entry.provenance.repo_id.clone(),
                        sha256: Some(entry.provenance.sha256.clone()),
                    },
                )
            })
            .collect();
        lock.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            encode_support_pom_lines(&lines)?,
        );
    }

    Ok(ResolvedReactorLock {
        lock,
        trusted_repositories: trusted_repositories.into_values().collect(),
    })
}

struct ResolvedReactorLock {
    lock: Lockfile,
    trusted_repositories: Vec<Repository>,
}

struct AggregateArtifact {
    artifact: LockArtifact,
    blob: BlobId,
    module_path: String,
    repo_rank: usize,
}

/// One support POM's aggregated provenance, plus the module that contributed
/// it so a byte-level conflict can name where each side came from.
struct AggregateSupportPom {
    provenance: SupportPomProvenance,
    module_path: String,
}

/// One GAV's companion-POM pin, plus where it was first seen.
struct AggregateCompanionPom {
    blob: BlobId,
    origin: String,
}

/// Fold one resolved package's companion-POM pin into the reactor-wide map.
///
/// A GAV has exactly one companion `.pom`, and `rv export-m2` writes it to
/// exactly one path in `~/.m2`. Two modules — or two platforms — that resolved
/// different bytes for it therefore cannot both be honoured: the lockfile would
/// pin one and the other's build would compile against a POM it never resolved
/// against. Caught here, before the lockfile is written, so the run fails with
/// both origins named rather than producing a lockfile export has to reject.
fn merge_companion_pom(
    aggregate: &mut BTreeMap<(String, String, String), AggregateCompanionPom>,
    package: &LockPackage,
    blob: &BlobId,
    platform: &Platform,
    module_path: &str,
) -> Result<()> {
    let gav = (
        package.group_id.clone(),
        package.artifact_id.clone(),
        package.version.clone(),
    );
    let origin = format!("{platform}/{module_path}");
    match aggregate.get(&gav) {
        Some(existing) if existing.blob != *blob => Err(CliError::Resolve(
            rv_resolver::ResolveError::ConflictingCompanionPomBytes(Box::new(
                rv_resolver::ConflictingPom {
                    coord: format!("{}:{}:{}", gav.0, gav.1, gav.2),
                    first_origin: existing.origin.clone(),
                    second_origin: origin,
                    first_sha256: existing.blob.to_string(),
                    second_sha256: blob.to_string(),
                },
            )),
        )),
        Some(_) => Ok(()),
        None => {
            aggregate.insert(
                gav,
                AggregateCompanionPom {
                    blob: blob.clone(),
                    origin,
                },
            );
            Ok(())
        }
    }
}

/// Fold one module's record for a support POM into the reactor-wide map.
///
/// Two rules, both about not losing information the lockfile cannot recover:
///
/// - An empty repo id is a placeholder ("served by a repository with no id"),
///   not an answer. A module that contributed the placeholder first must not
///   keep a later module's real id out, or the exported POM loses its
///   `_remote.repositories` marker. This mirrors the resolver-level merge in
///   `merge_support_pom_provenance`, and like it applies only between records
///   of the same bytes, so it decides a label and never which POM is exported.
/// - Two modules that fetched *different bytes* for one coordinate are a hard
///   error. The lockfile records a single digest per support POM, so silently
///   keeping one module's bytes would mean the other module's build is
///   exported against a POM it never resolved against. Each module's own
///   resolution already rejects that disagreement internally; this is the
///   cross-module backstop, where the two sides are separate resolutions and
///   nothing below could have seen both.
fn merge_support_pom(
    aggregate: &mut BTreeMap<String, AggregateSupportPom>,
    coord: &str,
    provenance: &SupportPomProvenance,
    module_path: &str,
) -> Result<()> {
    match aggregate.get_mut(coord) {
        Some(existing) if existing.provenance.sha256 != provenance.sha256 => Err(
            CliError::Resolve(rv_resolver::ResolveError::ConflictingSupportPomBytes(
                Box::new(rv_resolver::ConflictingPom {
                    coord: coord.to_string(),
                    first_origin: existing.module_path.clone(),
                    second_origin: module_path.to_string(),
                    first_sha256: existing.provenance.sha256.clone(),
                    second_sha256: provenance.sha256.clone(),
                }),
            )),
        ),
        Some(existing) => {
            if existing.provenance.repo_id.is_empty() && !provenance.repo_id.is_empty() {
                existing.provenance.repo_id = provenance.repo_id.clone();
                existing.module_path = module_path.to_string();
            }
            Ok(())
        }
        None => {
            aggregate.insert(
                coord.to_string(),
                AggregateSupportPom {
                    provenance: provenance.clone(),
                    module_path: module_path.to_string(),
                },
            );
            Ok(())
        }
    }
}

fn lock_coordinate(package: &LockPackage) -> LockCoordinate {
    let version = if package.is_snapshot() {
        package.base_snapshot_version()
    } else {
        package.version.clone()
    };
    LockCoordinate::new(
        &package.group_id,
        &package.artifact_id,
        version,
        &package.packaging,
        package.classifier.clone(),
    )
}

fn lock_artifact(
    package: &LockPackage,
    coordinate: LockCoordinate,
    pom_blob: &BlobId,
) -> LockArtifact {
    let snapshot = package.snapshot_timestamp.as_ref().map(|timestamp| {
        let build_number = package
            .version
            .rsplit_once('-')
            .and_then(|(_, build)| build.parse().ok());
        LockSnapshot {
            timestamp: timestamp.clone(),
            build_number,
        }
    });
    LockArtifact {
        coordinate,
        repo_url: package.repo_url.clone(),
        checksums: package.checksum.clone().into_iter().collect(),
        snapshot,
        // Pinned from the resolution that produced this row, never from the
        // store's coordinate index: the index is last-writer-wins across every
        // project sharing the store, so by the time the lock is written it can
        // name a POM this graph was never built from.
        pom_sha256: Some(pom_blob.to_string()),
        extra: BTreeMap::new(),
    }
}

fn workspace_module_for_package(
    resolution: &ResolutionResult,
    package: &LockPackage,
) -> Option<String> {
    resolution.graph.node_indices().find_map(|index| {
        let node = resolution.graph.node(index)?;
        let packaging = node.coord.packaging.as_deref().unwrap_or("jar");
        (node.coord.group_id.as_str() == package.group_id
            && node.coord.artifact_id.as_str() == package.artifact_id
            && node.coord.version.as_str() == package.version
            && packaging == package.packaging
            && node.coord.classifier == package.classifier)
            .then(|| node.workspace_module.clone())
            .flatten()
    })
}

/// Carry forward lockfile data a fresh resolve does not regenerate.
///
/// Unknown top-level fields (`extra`) and metadata keys rv does not own
/// round-trip read-to-write, but a resolve builds a new Lockfile from
/// scratch; without this step every successful sync would strip data a
/// future rv version or an external tool recorded. When platforms were
/// preserved from the previous lockfile, the rv-owned provenance entries are
/// merged as well: the preserved platforms' packages stay in the lockfile, so
/// dropping their repository ids would make `rv export-m2` mislabel their
/// `_remote.repositories` markers as `central`, and dropping their support-POM
/// digests would send those POMs back to the store's coordinate index.
fn carry_forward_lock_data(
    lock: &mut Lockfile,
    previous: &Lockfile,
    preserved_platforms: bool,
) -> Result<()> {
    if lock.extra.is_empty() && !previous.extra.is_empty() {
        lock.extra = previous.extra.clone();
    }
    for (key, value) in &previous.metadata {
        if key != LOCK_REPO_IDS_KEY && key != LOCK_SUPPORT_POMS_KEY {
            lock.metadata
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
    if !preserved_platforms {
        return Ok(());
    }
    if let Some(prev_encoded) = previous.metadata.get(LOCK_REPO_IDS_KEY) {
        let merged = merge_id_lines(
            prev_encoded,
            lock.metadata.get(LOCK_REPO_IDS_KEY).map(String::as_str),
        );
        if !merged.is_empty() {
            lock.metadata.insert(LOCK_REPO_IDS_KEY.to_string(), merged);
        }
    }
    // Support-POM lines merge through the shared codec, not line-wise: the
    // digest field is load-bearing, so a coordinate the two sides disagree on
    // must not be resolved by "fresh wins". The preservation pass has already
    // refused to keep any platform in that case, so reaching a disagreement
    // here would mean the lockfile is about to record a pin one half of it was
    // never resolved against.
    if let Some(prev_encoded) = previous.metadata.get(LOCK_SUPPORT_POMS_KEY) {
        let mut merged = decode_support_pom_lines(prev_encoded)?;
        if let Some(fresh_encoded) = lock.metadata.get(LOCK_SUPPORT_POMS_KEY) {
            for (coord, line) in decode_support_pom_lines(fresh_encoded)? {
                merged.insert(coord, line);
            }
        }
        if !merged.is_empty() {
            lock.metadata.insert(
                LOCK_SUPPORT_POMS_KEY.to_string(),
                encode_support_pom_lines(&merged)?,
            );
        }
    }
    Ok(())
}

/// The first support POM the previous lockfile and this run's resolution pin to
/// different bytes, if any.
///
/// Only coordinates both sides recorded are compared. A coordinate the fresh
/// resolution did not reach says nothing about drift — a platform that was not
/// re-resolved contributes its own parents and BOMs to the previous block.
fn conflicting_support_pom_digest(previous: &Lockfile, fresh: &Lockfile) -> Result<Option<String>> {
    let (Some(previous_encoded), Some(fresh_encoded)) = (
        previous.metadata.get(LOCK_SUPPORT_POMS_KEY),
        fresh.metadata.get(LOCK_SUPPORT_POMS_KEY),
    ) else {
        return Ok(None);
    };
    let previous_lines = decode_support_pom_lines(previous_encoded)?;
    for (coord, fresh_line) in decode_support_pom_lines(fresh_encoded)? {
        if let Some(previous_line) = previous_lines.get(&coord)
            && previous_line.sha256 != fresh_line.sha256
        {
            return Ok(Some(coord));
        }
    }
    Ok(None)
}

/// Companion-POM pins from a lockfile's artifact rows, keyed by the GAV whose
/// single `.pom` they name.
fn companion_pom_pins(lock: &Lockfile) -> HashMap<(String, String, String), String> {
    let mut pins = HashMap::new();
    for platform in &lock.platforms {
        pins.extend(platform_companion_pom_pins(platform));
    }
    pins
}

/// Companion-POM pins from one platform's artifact rows, keyed the same way.
fn platform_companion_pom_pins(
    platform: &LockPlatform,
) -> HashMap<(String, String, String), String> {
    let mut pins = HashMap::new();
    for artifact in &platform.artifacts {
        let Some(digest) = artifact.pom_sha256.as_deref() else {
            continue;
        };
        let package = artifact.as_package();
        pins.insert(
            (package.group_id, package.artifact_id, package.version),
            digest.to_string(),
        );
    }
    pins
}

/// The support-POM block a lockfile carries, decoded.
fn support_pom_pins(lock: &Lockfile) -> Result<BTreeMap<String, SupportPomLine>> {
    match lock.metadata.get(LOCK_SUPPORT_POMS_KEY) {
        Some(encoded) => Ok(decode_support_pom_lines(encoded)?),
        None => Ok(BTreeMap::new()),
    }
}

/// The first coordinate a support-POM pin and a companion-POM pin name
/// different bytes for.
///
/// The support-POM block and the artifact rows record the same file — Maven
/// keeps one `.pom` per GAV — from two independent observations, so the two
/// maps agreeing is what makes the lockfile describe a `~/.m2` that can exist.
/// `Lockfile::validate` refuses a lockfile where they do not; checking here
/// lets `rv sync` drop the platform responsible instead of failing the whole
/// run at write time. Only a pinned support line participates: a legacy
/// two-field line records no digest and so cannot disagree.
fn conflicting_support_companion_pin(
    support_poms: &BTreeMap<String, SupportPomLine>,
    companions: &HashMap<(String, String, String), String>,
) -> Option<String> {
    for (coord, line) in support_poms {
        let Some(support) = line.sha256.as_deref() else {
            continue;
        };
        let Some(gav) = split_support_gav(coord) else {
            continue;
        };
        if companions
            .get(&gav)
            .is_some_and(|companion| companion != support)
        {
            return Some(coord.clone());
        }
    }
    None
}

/// Refuse to write a lockfile whose support-POM block and artifact rows pin
/// one coordinate's `.pom` two ways.
///
/// `Lockfile::write_atomic` validates this too, for every consumer at once;
/// running it here names the coordinate and the recovery in `rv sync`'s own
/// terms, before the temp file is created.
fn check_support_companion_agreement(lock: &Lockfile) -> Result<()> {
    let Some(coord) =
        conflicting_support_companion_pin(&support_pom_pins(lock)?, &companion_pom_pins(lock))
    else {
        return Ok(());
    };
    Err(CliError::Message(format!(
        "resolution pinned two different POMs for {coord}: it was resolved both as a \
         parent/imported BOM and as a dependency, and Maven has one local-repository path per \
         coordinate. Re-run `rv sync` after clearing rv.lock, or report this if it persists"
    )))
}

/// Split a `g:a:v` support-POM coordinate. `None` for anything else, which the
/// codec already rejects on the way in and out of the lockfile.
fn split_support_gav(coord: &str) -> Option<(String, String, String)> {
    let mut parts = coord.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(group), Some(artifact), Some(version), None) => {
            Some((group.to_string(), artifact.to_string(), version.to_string()))
        }
        _ => None,
    }
}

/// The first coordinate `candidate` pins to a different POM than the freshly
/// resolved platforms do.
fn conflicting_companion_pom_pin(
    fresh: &HashMap<(String, String, String), String>,
    candidate: &LockPlatform,
) -> Option<String> {
    for artifact in &candidate.artifacts {
        let Some(digest) = artifact.pom_sha256.as_deref() else {
            continue;
        };
        let package = artifact.as_package();
        let gav = (
            package.group_id.clone(),
            package.artifact_id.clone(),
            package.version.clone(),
        );
        if fresh.get(&gav).is_some_and(|fresh| fresh != digest) {
            return Some(format!("{}:{}:{}", gav.0, gav.1, gav.2));
        }
    }
    None
}

/// Merge two blocks of tab-delimited `key\tid` lines, the fresh side winning
/// per key, re-encoded deterministically (sorted by key).
fn merge_id_lines(previous: &str, fresh: Option<&str>) -> String {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for line in previous.lines().chain(fresh.unwrap_or_default().lines()) {
        if let Some((key, id)) = line.split_once('\t') {
            map.insert(key.to_string(), id.to_string());
        }
    }
    map.iter()
        .map(|(key, id)| format!("{key}\t{id}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Lockfile `[metadata]` key under which `rv sync` records `url\tid` lines for
/// the id'd repositories that backed resolution, so `rv export-m2` can label
/// `_remote.repositories` markers for POM-declared repos. See
/// `export_m2::lock_repo_ids`.
pub(crate) const LOCK_REPO_IDS_KEY: &str = "repo_ids";

async fn ensure_artifacts(
    lock: &Lockfile,
    config: &Config,
    store: &Store,
    client: &RepoClient,
    platforms: &[Platform],
    trusted_repositories: &[Repository],
) -> Result<()> {
    let total: usize = lock
        .platforms
        .iter()
        .map(|platform| platform.artifacts.len())
        .sum();
    // No local ProgressBar here: the configured `ProgressReporter` is
    // already wired through `RepoClient::with_progress` and runs per
    // chunk, which is what users actually see during a sync. A post-hoc
    // `pb.set_position` call would run only after every download had
    // already completed, producing no animation.

    tracing::debug!(total_artifacts = total, "downloading artifacts");
    let results = rv_repo::sync::ensure_artifacts(
        client,
        store,
        lock,
        config,
        platforms,
        trusted_repositories,
    )
    .await?;

    // Track the dominant error class so the caller can return a typed
    // error instead of flattening every failure to `CliError::Message`
    // (which would always exit GENERAL_ERROR even for transient network
    // hiccups). When a checksum mismatch is involved we keep the
    // lockfile-mismatch path; otherwise the first transient/non-transient
    // RepoError carries through with its classification preserved.
    let mut failures = Vec::new();
    let mut checksum_failure_lines = Vec::new();
    let mut first_repo_error: Option<rv_repo::RepoError> = None;
    for result in &results {
        if result.result.is_ok() {
            tracing::debug!(artifact = %result.package, "artifact downloaded");
        }
        if let Err(err) = &result.result {
            if let rv_repo::RepoError::ChecksumMismatch {
                path,
                expected,
                actual,
            } = err
            {
                // Render the coordinate and the two hashes verbatim. A CAS path
                // like `sha256/ab/cd/...` gives the user no signal about which
                // lockfile pin is wrong, so it stays out of the message — but
                // the coordinate the mismatch is reported under does name which
                // pin failed, and it is not always the package's own artifact:
                // a package's companion POM carries a `...:pom` coordinate and
                // its own pin.
                let coordinate = if path.contains(':') {
                    path.as_str()
                } else {
                    result.package.as_str()
                };
                checksum_failure_lines.push(format!(
                    "{coordinate}: expected {} {}, got {}",
                    digest_algorithm_name(expected),
                    expected,
                    actual
                ));
            } else {
                if first_repo_error.is_none() {
                    first_repo_error = Some(clone_repo_error(err));
                }
                failures.push(format!("{}: {}", result.package, err));
            }
        }
    }

    if !checksum_failure_lines.is_empty() {
        return Err(CliError::LockfileMismatch {
            details: format_checksum_failure_details(&checksum_failure_lines, &failures),
        });
    }

    if !failures.is_empty() {
        if is_json_mode() {
            // Surface a structured failure envelope on the JSON channel so
            // consumers see typed `exit_code`/`error` fields without us
            // having to lift the classification through the top-level
            // handler twice.
            let exit_code = match first_repo_error.as_ref() {
                Some(err) if err.is_transient() => crate::error::ExitCodes::NETWORK_ERROR,
                Some(_) => crate::error::ExitCodes::RESOLUTION_ERROR,
                None => crate::error::ExitCodes::GENERAL_ERROR,
            };
            json_result(
                false,
                serde_json::json!({
                    "failed": failures.len(),
                    "exit_code": exit_code,
                    "error": format!("failed to download {} artifact(s)", failures.len()),
                }),
            );
            return Err(CliError::AlreadyReported { exit_code });
        }

        let message = format!(
            "failed to download {} artifact(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
        if let Some(err) = first_repo_error {
            // Wrap the typed RepoError so `CliError::exit_code()` routes
            // transient errors to NETWORK_ERROR and the rest to
            // RESOLUTION_ERROR. We attach the aggregated detail via a
            // tracing line so the user still sees every failure.
            tracing::error!("{message}");
            return Err(CliError::Repo(err));
        }
        return Err(CliError::Message(message));
    }

    Ok(())
}

/// Name the hash algorithm behind a lockfile pin from its digest length.
/// The lockfile loader enforces 64 hex characters for sha256 pins and 40
/// for sha1 pins, so the length is unambiguous here.
fn digest_algorithm_name(digest: &str) -> &'static str {
    match digest.len() {
        64 => "sha256",
        40 => "sha1",
        _ => "checksum",
    }
}

/// How many non-checksum failures are listed verbatim alongside a checksum
/// mismatch before the rest collapse into a "... and N more" footer.
const OTHER_FAILURES_DISPLAY_CAP: usize = 3;

/// Render the checksum-mismatch failure message for a download batch. The
/// checksum class drives the exit code, but other failures from the same
/// batch are appended so they are not silently discarded.
fn format_checksum_failure_details(checksum_lines: &[String], other_failures: &[String]) -> String {
    let mut details = format!(
        "checksum mismatch for {} artifact(s) (downloaded artifact doesn't match rv.lock). Run 'rv sync' to regenerate lockfile:\n{}",
        checksum_lines.len(),
        checksum_lines.join("\n")
    );
    if !other_failures.is_empty() {
        let shown = other_failures.len().min(OTHER_FAILURES_DISPLAY_CAP);
        details.push_str(&format!(
            "\nand {} other download failure(s):\n{}",
            other_failures.len(),
            other_failures[..shown].join("\n")
        ));
        if other_failures.len() > shown {
            details.push_str(&format!("\n... and {} more", other_failures.len() - shown));
        }
    }
    details
}

/// Approximate a clone of `RepoError` that preserves the
/// `is_transient()` classification used by `CliError::exit_code()`.
///
/// `RepoError` is not `Clone` because the `Http(reqwest::Error)` arm
/// owns transport state we can't duplicate. A byte-for-byte clone is not
/// needed; what is needed is an error of the same classification so
/// `CliError::Repo(...)` routes to the right `ExitCodes::NETWORK_ERROR`
/// vs `RESOLUTION_ERROR` bucket.
fn clone_repo_error(err: &rv_repo::RepoError) -> rv_repo::RepoError {
    use rv_repo::RepoError;
    let display = err.to_string();
    if err.is_transient() {
        // Any transient variant collapses to `UnexpectedResponse` with a
        // 5xx prefix so `is_transient()` returns true on the rebuild.
        // The aggregated message above already shows the user the real
        // details; this synthetic variant only drives the exit code.
        return RepoError::UnexpectedResponse(format!("503 {display}"));
    }
    match err {
        RepoError::NotFound(s) => RepoError::NotFound(s.clone()),
        RepoError::AuthError(s) => RepoError::AuthError(s.clone()),
        RepoError::MissingChecksum(s) => RepoError::MissingChecksum(s.clone()),
        RepoError::UnsupportedChecksum(s) => RepoError::UnsupportedChecksum(s.clone()),
        RepoError::InvalidMetadata(s) => RepoError::InvalidMetadata(s.clone()),
        RepoError::InvalidCoord(s) => RepoError::InvalidCoord(s.clone()),
        RepoError::OfflineNotCached(s) => RepoError::OfflineNotCached(s.clone()),
        RepoError::UntrustedRepoUrl(s) => RepoError::UntrustedRepoUrl(s.clone()),
        RepoError::RedirectRejected { kind, details } => RepoError::RedirectRejected {
            kind: *kind,
            details: details.clone(),
        },
        RepoError::SnapshotsDisabled { version, reason } => RepoError::SnapshotsDisabled {
            version: version.clone(),
            reason: reason.clone(),
        },
        RepoError::UnexpectedResponse(s) => RepoError::UnexpectedResponse(s.clone()),
        RepoError::ChecksumMismatch {
            path,
            expected,
            actual,
        } => RepoError::ChecksumMismatch {
            path: path.clone(),
            expected: expected.clone(),
            actual: actual.clone(),
        },
        // Non-Clone arms are listed explicitly (rather than `_`) so a new
        // RepoError variant fails compilation here instead of silently
        // collapsing to InvalidMetadata. Each preserves the display string;
        // the wrapped transport state is not reproducible.
        RepoError::Http(_)
        | RepoError::Url(_)
        | RepoError::Io(_)
        | RepoError::Xml(_)
        | RepoError::Store(_)
        | RepoError::DbError(_) => RepoError::InvalidMetadata(display),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LOCK_REPO_IDS_KEY, LOCK_SUPPORT_POMS_KEY, StrategyArg, SupportPomProvenance, SyncArgs,
        carry_forward_lock_data, check_frozen_config_hash, check_legacy_frozen_strategy,
        check_support_companion_agreement, companion_pom_pins, compute_config_hash,
        conflicting_companion_pom_pin, conflicting_support_companion_pin,
        conflicting_support_pom_digest, digest_algorithm_name, elapsed_saturating, filter_lock,
        format_checksum_failure_details, frozen_checks_local_inputs_only, hash_model_inputs,
        lock_artifact, lock_coordinate, lock_pins_incomplete, lock_references_unconfigured_origin,
        lock_resolution_matches, merge_companion_pom, merge_support_pom,
        platform_companion_pom_pins, require_lock_for_platforms, support_pom_pins,
    };
    use crate::error::CliError;
    use clap::Parser;
    use rv_config::{
        BlobId, LockGav, LockPackage, LockPlatform, LockResolutionStrategy, Lockfile, Platform,
    };
    use rv_resolver::ResolutionStrategy;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    fn empty_platform(os: &str, arch: &str) -> LockPlatform {
        LockPlatform::single_module(
            Platform::new(os, arch).expect("platform"),
            "",
            "pom.xml",
            LockGav::new("com.example", "root", "1"),
            "pom",
            Vec::new(),
            Vec::new(),
        )
    }

    fn push_package(platform: &mut LockPlatform, package: LockPackage) {
        let mut converted = LockPlatform::single_module(
            platform.platform.clone(),
            platform.model_hash.clone(),
            "pom.xml",
            LockGav::new("com.example", "root", "1"),
            "pom",
            vec![package],
            Vec::new(),
        );
        platform.modules[0]
            .packages
            .append(&mut converted.modules[0].packages);
        platform.artifacts.append(&mut converted.artifacts);
    }

    /// A fresh resolve must not strip top-level `extra` data or foreign
    /// metadata keys from the previous lockfile, and a partial-platform sync
    /// must keep the preserved platforms' repo-id provenance lines (merged
    /// with the fresh side winning per key).
    #[test]
    fn carry_forward_preserves_extra_and_merges_provenance() {
        let mut previous = Lockfile::new();
        previous
            .extra
            .insert("future_field".to_string(), toml::Value::from("kept"));
        previous
            .metadata
            .insert("foreign_key".to_string(), "kept".to_string());
        previous.metadata.insert(
            LOCK_REPO_IDS_KEY.to_string(),
            "https://old.example/\told-id\nhttps://shared.example/\tprev-id".to_string(),
        );
        previous.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            "g:a:1.0\tcorp".to_string(),
        );

        let mut lock = Lockfile::new();
        lock.metadata.insert(
            LOCK_REPO_IDS_KEY.to_string(),
            "https://shared.example/\tfresh-id".to_string(),
        );

        carry_forward_lock_data(&mut lock, &previous, true).expect("well-formed metadata merges");

        assert_eq!(
            lock.extra.get("future_field").and_then(|v| v.as_str()),
            Some("kept")
        );
        assert_eq!(
            lock.metadata.get("foreign_key").map(String::as_str),
            Some("kept")
        );
        let repo_ids = lock.metadata.get(LOCK_REPO_IDS_KEY).unwrap();
        assert!(repo_ids.contains("https://old.example/\told-id"));
        assert!(
            repo_ids.contains("https://shared.example/\tfresh-id"),
            "fresh side wins per key: {repo_ids}"
        );
        assert!(!repo_ids.contains("prev-id"));
        assert_eq!(
            lock.metadata.get(LOCK_SUPPORT_POMS_KEY).map(String::as_str),
            Some("g:a:1.0\tcorp")
        );
    }

    /// Without preserved platforms the fresh provenance is complete; the
    /// previous lockfile's rv-owned keys must NOT bleed in (stale repos
    /// would linger forever), while foreign keys still carry forward.
    #[test]
    fn carry_forward_full_resolve_keeps_fresh_provenance_only() {
        let mut previous = Lockfile::new();
        previous.metadata.insert(
            LOCK_REPO_IDS_KEY.to_string(),
            "https://stale.example/\tstale".to_string(),
        );
        previous
            .metadata
            .insert("foreign_key".to_string(), "kept".to_string());

        let mut lock = Lockfile::new();
        lock.metadata.insert(
            LOCK_REPO_IDS_KEY.to_string(),
            "https://fresh.example/\tfresh".to_string(),
        );

        carry_forward_lock_data(&mut lock, &previous, false).expect("well-formed metadata merges");

        assert_eq!(
            lock.metadata.get(LOCK_REPO_IDS_KEY).map(String::as_str),
            Some("https://fresh.example/\tfresh")
        );
        assert_eq!(
            lock.metadata.get("foreign_key").map(String::as_str),
            Some("kept")
        );
    }

    #[test]
    fn filter_lock_returns_none_when_platform_missing() {
        let mut lock = Lockfile::new();
        lock.platforms.push(empty_platform("linux", "x86_64"));
        let target = vec![Platform::new("windows", "x86_64").expect("platform")];
        let result = filter_lock(&lock, &target).expect("filter_lock should not error");
        assert!(
            result.is_none(),
            "missing platform should fall through to resolve"
        );
    }

    #[test]
    fn filter_lock_returns_some_when_all_platforms_present() {
        let mut lock = Lockfile::new();
        lock.platforms.push(empty_platform("linux", "x86_64"));
        lock.platforms.push(empty_platform("darwin", "aarch64"));
        let target = vec![Platform::new("linux", "x86_64").expect("platform")];
        let result = filter_lock(&lock, &target).expect("ok");
        let projected = result.expect("expected Some(lockfile)");
        assert_eq!(projected.platforms.len(), 1);
    }

    #[test]
    fn pom_only_origin_forces_repository_rediscovery() {
        use rv_config::{Config, RepoConfig, ResolvedPaths, UpdatePolicy};

        let temp = tempfile::tempdir().expect("temp dir");
        let paths = ResolvedPaths::discover().expect("paths");
        let central = RepoConfig {
            id: Some("central".to_string()),
            url: "https://repo1.maven.org/maven2/".to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: Some(UpdatePolicy::Daily),
        };
        let config =
            Config::for_testing_with_repos(temp.path().to_path_buf(), paths, vec![central]);
        let mut lock = Lockfile::new();
        let mut platform = empty_platform("linux", "x86_64");
        push_package(&mut platform, package("com.example", "demo", "1.0"));
        lock.platforms.push(platform);

        assert!(lock_references_unconfigured_origin(&lock, &config));
        lock.platforms[0].artifacts[0].repo_url = "https://repo1.maven.org/maven2".to_string();
        assert!(!lock_references_unconfigured_origin(&lock, &config));
    }

    /// The schema 1-3 exemption from fresh resolution is unconditional. A
    /// stale SNAPSHOT or an unconfigured recorded origin would otherwise force
    /// a comparison against the adapter's sentinel module GAV, which reports
    /// drift for every legacy lock no matter how unchanged the graph is.
    /// Offline keeps the unconfigured-origin condition: an offline resolve can
    /// still answer it from the local model and cached POMs.
    #[test]
    fn legacy_frozen_checks_stay_local_regardless_of_force_conditions() {
        for snapshot_refresh in [false, true] {
            for rediscover in [false, true] {
                for offline in [false, true] {
                    assert!(
                        frozen_checks_local_inputs_only(
                            offline,
                            true,
                            snapshot_refresh,
                            rediscover
                        ),
                        "legacy lock must stay local-inputs-only \
                         (offline={offline}, snapshot_refresh={snapshot_refresh}, \
                         rediscover={rediscover})"
                    );
                }
            }
        }

        // A schema-4 lock keeps the existing contract.
        assert!(frozen_checks_local_inputs_only(true, false, false, false));
        assert!(!frozen_checks_local_inputs_only(true, false, false, true));
        assert!(!frozen_checks_local_inputs_only(false, false, false, false));
    }

    /// An offline `--frozen` run must not be dragged into a re-resolve by an
    /// expired SNAPSHOT update policy. The cached `maven-metadata.xml` that
    /// resolve would need carries the same TTL that declared the pins stale, so
    /// the cache entry is expired whenever this condition fires and the run can
    /// only abort with `OfflineNotCached`. That holds even when an unconfigured
    /// origin would otherwise force the resolve.
    #[test]
    fn offline_frozen_stays_local_when_the_snapshot_policy_expired() {
        assert!(frozen_checks_local_inputs_only(true, false, true, false));
        assert!(frozen_checks_local_inputs_only(true, false, true, true));
        // Online, an expired policy still resolves afresh: that is the whole
        // point of the schema-4 contract.
        assert!(!frozen_checks_local_inputs_only(false, false, true, false));
    }

    /// Reactor aggregation must not let a module that saw no repository id
    /// keep a later module's real one out. `or_insert`-style merging did
    /// exactly that: the id-less module's placeholder won by arriving first,
    /// and the exported POM lost its `_remote.repositories` marker.
    #[test]
    fn aggregated_support_pom_upgrades_an_empty_repo_id() {
        let digest = "a".repeat(64);
        let idless = SupportPomProvenance {
            repo_id: String::new(),
            sha256: digest.clone(),
        };
        let known = SupportPomProvenance {
            repo_id: "corp".to_string(),
            sha256: digest.clone(),
        };

        let mut aggregate = BTreeMap::new();
        merge_support_pom(&mut aggregate, "g:a:1.0", &idless, "a/pom.xml").expect("first module");
        merge_support_pom(&mut aggregate, "g:a:1.0", &known, "b/pom.xml").expect("second module");
        assert_eq!(aggregate["g:a:1.0"].provenance.repo_id, "corp");

        // ...and the reverse order does not lose the id either.
        let mut aggregate = BTreeMap::new();
        merge_support_pom(&mut aggregate, "g:a:1.0", &known, "b/pom.xml").expect("first module");
        merge_support_pom(&mut aggregate, "g:a:1.0", &idless, "a/pom.xml").expect("second module");
        assert_eq!(aggregate["g:a:1.0"].provenance.repo_id, "corp");
        assert_eq!(aggregate["g:a:1.0"].provenance.sha256, digest);
    }

    /// Two reactor modules that fetched different bytes for one support-POM
    /// coordinate cannot both be pinned by a single lockfile entry, so the sync
    /// fails and names the coordinate and both modules rather than silently
    /// exporting one module's parent POM into the other's build.
    #[test]
    fn aggregated_support_pom_byte_conflict_is_an_error() {
        let mut aggregate = BTreeMap::new();
        merge_support_pom(
            &mut aggregate,
            "g:a:1.0",
            &SupportPomProvenance {
                repo_id: "corp".to_string(),
                sha256: "a".repeat(64),
            },
            "a/pom.xml",
        )
        .expect("first module");

        let err = merge_support_pom(
            &mut aggregate,
            "g:a:1.0",
            &SupportPomProvenance {
                repo_id: "corp".to_string(),
                sha256: "b".repeat(64),
            },
            "b/pom.xml",
        )
        .expect_err("two modules with different bytes must not be collapsed silently");

        let message = err.to_string();
        assert!(
            message.contains("g:a:1.0")
                && message.contains("a/pom.xml")
                && message.contains("b/pom.xml"),
            "conflict must name the coordinate and both modules, got: {message}"
        );
    }

    #[test]
    fn timestamped_snapshot_uses_logical_lock_coordinate() {
        use rv_config::Checksum;

        let timestamped = "1.0-20260720.123253-28";
        let mut snapshot = package("com.example", "demo", timestamped);
        snapshot.snapshot_timestamp = Some("20260720.123253".to_string());
        snapshot.checksum = Some(Checksum::new("sha256", "a".repeat(64)));

        let coordinate = lock_coordinate(&snapshot);
        assert_eq!(coordinate.version, "1.0-SNAPSHOT");
        let pom_blob = BlobId::from_bytes(b"<project/>");
        let artifact = lock_artifact(&snapshot, coordinate, &pom_blob);
        assert_eq!(
            artifact
                .snapshot
                .as_ref()
                .and_then(|value| value.build_number),
            Some(28)
        );
        assert_eq!(artifact.as_package().version, timestamped);
        assert_eq!(artifact.pom_sha256.as_deref(), Some(pom_blob.as_str()));
    }

    #[test]
    fn require_lock_for_platforms_errors_on_missing() {
        let mut lock = Lockfile::new();
        lock.platforms.push(empty_platform("linux", "x86_64"));
        let target = vec![Platform::new("windows", "x86_64").expect("platform")];
        let err = require_lock_for_platforms(&lock, &target).expect_err("expected error");
        assert!(
            matches!(err, crate::error::CliError::PlatformMissing { .. }),
            "got {err:?}"
        );
    }

    #[derive(Debug, Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: SyncArgs,
    }

    #[test]
    fn update_and_offline_can_be_combined() {
        // `--update --offline` is a valid combination: force re-resolution
        // using only cached metadata.
        let parsed = Wrapper::try_parse_from(["rv", "--update", "--offline"]).expect("parse");
        assert!(parsed.args.update);
        assert!(parsed.args.offline);
    }

    #[test]
    fn frozen_and_update_still_conflict() {
        Wrapper::try_parse_from(["rv", "--frozen", "--update"])
            .expect_err("--frozen and --update must remain mutually exclusive");
    }

    /// The documented `--platforms a,b` syntax must split on commas and
    /// yield one parsed platform per entry, not a single garbage platform
    /// named "a,b".
    #[test]
    fn platforms_comma_list_parses_to_multiple_platforms() {
        let parsed = Wrapper::try_parse_from(["rv", "--platforms", "linux-x86_64,darwin-aarch64"])
            .expect("comma-separated platform list must parse");
        let names: Vec<String> = parsed
            .args
            .platforms
            .iter()
            .map(|p| p.to_string())
            .collect();
        assert_eq!(names, ["linux-x86_64", "darwin-aarch64"]);
    }

    /// Repeating the flag still appends, with and without commas.
    #[test]
    fn platforms_repeated_flag_appends() {
        let parsed = Wrapper::try_parse_from([
            "rv",
            "--platforms",
            "linux-x86_64",
            "--platforms",
            "darwin-aarch64,windows-x86_64",
        ])
        .expect("repeated --platforms must parse");
        assert_eq!(parsed.args.platforms.len(), 3);
    }

    /// A token without an os-arch separator must be rejected at parse time.
    #[test]
    fn platforms_rejects_token_without_arch() {
        Wrapper::try_parse_from(["rv", "--platforms", "linux"])
            .expect_err("a bare os without an arch must not parse");
    }

    #[test]
    fn strategy_arg_converts_to_resolution_strategy() {
        assert_eq!(
            ResolutionStrategy::from(StrategyArg::Nearest),
            ResolutionStrategy::NearestWins
        );
        assert_eq!(
            ResolutionStrategy::from(StrategyArg::Highest),
            ResolutionStrategy::HighestWins
        );
    }

    /// A schema 1-3 lock is validated from local inputs alone, and
    /// `--strategy` changes none of them. Requesting a non-default strategy
    /// against one is the unrecorded-strategy ambiguity the schema-4 branch
    /// refuses, so it has to be refused here too rather than reported as "up
    /// to date". The default keeps passing: that is what the lock was built
    /// with.
    #[test]
    fn legacy_frozen_refuses_a_non_default_strategy_and_accepts_the_default() {
        check_legacy_frozen_strategy(LockResolutionStrategy::from(StrategyArg::default()))
            .expect("the default strategy stays verifiable against a legacy lock");

        let error =
            check_legacy_frozen_strategy(LockResolutionStrategy::from(StrategyArg::Highest))
                .expect_err("an unrecorded strategy must not pass --frozen");
        match error {
            CliError::LockfileMismatch { details } => {
                assert!(
                    details.contains("--strategy highest"),
                    "the message must name the requested strategy: {details}"
                );
                assert!(
                    details.contains("without --frozen"),
                    "the message must say how to migrate: {details}"
                );
            }
            other => panic!("expected LockfileMismatch, got {other:?}"),
        }
    }

    /// Regression: `Instant::elapsed` is documented to panic if
    /// the monotonic clock ever steps backwards. `elapsed_saturating`
    /// returns `Duration::ZERO` in that case. We cannot easily force the
    /// clock backwards from a test, so we just exercise the happy path
    /// and assert the helper returns a non-negative duration.
    #[test]
    fn elapsed_saturating_returns_non_negative_duration() {
        let start = Instant::now();
        let elapsed = elapsed_saturating(start);
        assert!(elapsed >= Duration::ZERO);
        // The helper must never panic for any `Instant`.
        let future = Instant::now();
        assert_eq!(
            elapsed_saturating(future + Duration::from_secs(60)),
            Duration::ZERO
        );
    }

    fn package(group: &str, artifact: &str, version: &str) -> LockPackage {
        LockPackage {
            group_id: group.to_string(),
            artifact_id: artifact.to_string(),
            version: version.to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/".to_string(),
            checksum: None,
            system_path: None,
            direct_scope: None,
            extra: std::collections::BTreeMap::new(),
        }
    }

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    /// Build a one-platform lock whose single artifact row pins `pom_sha256`.
    fn lock_pinning(os: &str, arch: &str, pom_sha256: &str) -> Lockfile {
        let mut lock = Lockfile::new();
        let mut platform = empty_platform(os, arch);
        push_package(&mut platform, package("com.example", "lib", "1.0"));
        platform.artifacts[0].pom_sha256 = Some(pom_sha256.to_string());
        lock.platforms.push(platform);
        lock
    }

    /// The fast path reuses a lockfile without resolving, so it is the one
    /// place that has to notice a lock still in the pre-pin shape. Left
    /// unnoticed, such a lock never migrates: nothing else about it ever
    /// changes, so every subsequent sync takes the same shortcut and its POMs
    /// stay on the store's last-writer-wins coordinate index forever.
    #[test]
    fn a_lock_missing_a_companion_pom_pin_is_incomplete() {
        let mut lock = lock_pinning("linux", "x86_64", &digest('a'));
        assert!(
            !lock_pins_incomplete(&lock),
            "a fully pinned lock takes the fast path"
        );

        lock.platforms[0].artifacts[0].pom_sha256 = None;
        assert!(
            lock_pins_incomplete(&lock),
            "an artifact row without pom_sha256 must fall through to resolution"
        );
    }

    /// The two-field support-POM line is the pre-digest form: it names a
    /// repository id and leaves the bytes to the coordinate index. It migrates
    /// on the same trigger.
    #[test]
    fn a_two_field_support_pom_line_is_incomplete() {
        let mut lock = lock_pinning("linux", "x86_64", &digest('a'));
        lock.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!(
                "com.example:parent:1.0\tcorp\t{}\ncom.example:bom:2.0\tcorp",
                digest('c')
            ),
        );
        assert!(
            lock_pins_incomplete(&lock),
            "one legacy line is enough to force the rewrite"
        );

        lock.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!(
                "com.example:parent:1.0\tcorp\t{}\ncom.example:bom:2.0\tcorp\t{}",
                digest('c'),
                digest('d')
            ),
        );
        assert!(
            !lock_pins_incomplete(&lock),
            "three-field lines are the current form"
        );
    }

    /// The empty-versus-absent case: a resolution that reached no parent or
    /// imported BOM writes no metadata block at all, under both the old and
    /// the current format. An absent key is therefore "nothing to pin", not
    /// "pins were never captured", and must not force a rewrite on every sync.
    #[test]
    fn a_lock_without_support_poms_is_complete() {
        let lock = lock_pinning("linux", "x86_64", &digest('a'));
        assert!(!lock.metadata.contains_key(LOCK_SUPPORT_POMS_KEY));
        assert!(!lock_pins_incomplete(&lock));
    }

    /// A companion POM republished with different bytes and identical edges is
    /// still a change a plain `rv sync` would write to rv.lock, so `--frozen`
    /// has to report it. Skipping `pom_sha256` here is what let a changed
    /// parent or BOM pass frozen while contradicting the documented contract.
    #[test]
    fn frozen_reports_a_companion_pom_byte_change_with_unchanged_edges() {
        let on_disk = lock_pinning("linux", "x86_64", &digest('a'));
        let fresh = lock_pinning("linux", "x86_64", &digest('b'));
        assert!(
            !lock_resolution_matches(&on_disk, &fresh),
            "a changed companion-POM pin is drift even when the graph is identical"
        );

        let diff = crate::commands::sync::diff::format_frozen_diff(&on_disk, &fresh);
        assert!(
            diff.contains("com.example:lib:1.0") && diff.contains("POM changed"),
            "the frozen diff must name the coordinate whose POM changed, got: {diff}"
        );
    }

    /// Negative control: an unchanged pin is not drift.
    #[test]
    fn frozen_accepts_an_unchanged_companion_pom_pin() {
        let on_disk = lock_pinning("linux", "x86_64", &digest('a'));
        let fresh = lock_pinning("linux", "x86_64", &digest('a'));
        assert!(lock_resolution_matches(&on_disk, &fresh));
    }

    /// Support POMs never become lockfile packages, so a parent or imported
    /// BOM republished with different bytes shows up only in the metadata
    /// block. Frozen must compare it there or miss the drift entirely.
    #[test]
    fn frozen_reports_a_support_pom_byte_change() {
        let mut on_disk = lock_pinning("linux", "x86_64", &digest('a'));
        on_disk.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:parent:1.0\tcorp\t{}", digest('c')),
        );
        let mut fresh = lock_pinning("linux", "x86_64", &digest('a'));
        fresh.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:parent:1.0\tcorp\t{}", digest('d')),
        );

        assert!(!lock_resolution_matches(&on_disk, &fresh));
        let diff = crate::commands::sync::diff::format_frozen_diff(&on_disk, &fresh);
        assert!(
            diff.contains("support POM changed for com.example:parent:1.0"),
            "the frozen diff must name the support POM, got: {diff}"
        );
    }

    /// A support POM only the on-disk union records belongs to a platform this
    /// run did not re-resolve, so it says nothing about drift. A coordinate the
    /// fresh resolution reached and the lockfile does not record does.
    #[test]
    fn frozen_ignores_disk_only_support_entries_but_not_missing_ones() {
        let mut on_disk = lock_pinning("linux", "x86_64", &digest('a'));
        on_disk.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!(
                "com.example:other-platform-parent:1.0\tcorp\t{}\ncom.example:parent:1.0\tcorp\t{}",
                digest('e'),
                digest('c')
            ),
        );
        let mut fresh = lock_pinning("linux", "x86_64", &digest('a'));
        fresh.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:parent:1.0\tcorp\t{}", digest('c')),
        );
        assert!(lock_resolution_matches(&on_disk, &fresh));

        fresh.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:new-parent:1.0\tcorp\t{}", digest('f')),
        );
        assert!(
            !lock_resolution_matches(&on_disk, &fresh),
            "a support POM this resolution reached but rv.lock does not record is drift"
        );
    }

    /// Two freshly resolved modules (or platforms) that parsed different bytes
    /// for one GAV's companion POM must fail the sync, naming both origins.
    /// The lockfile pins one digest per coordinate, so silently keeping either
    /// leaves the other module compiling against a POM it never resolved.
    #[test]
    fn fresh_companion_pom_conflict_names_both_origins() {
        let linux = Platform::new("linux", "x86_64").expect("platform");
        let darwin = Platform::new("darwin", "aarch64").expect("platform");
        let package = package("com.example", "lib", "1.0");
        let first = BlobId::from_bytes(b"<project>first</project>");
        let second = BlobId::from_bytes(b"<project>second</project>");

        let mut aggregate = BTreeMap::new();
        merge_companion_pom(&mut aggregate, &package, &first, &linux, "app/pom.xml")
            .expect("first observation");
        // Same bytes from another module is the normal case.
        merge_companion_pom(&mut aggregate, &package, &first, &linux, "lib/pom.xml")
            .expect("agreeing observation");

        let message =
            merge_companion_pom(&mut aggregate, &package, &second, &darwin, "app/pom.xml")
                .expect_err("differing bytes must fail the sync")
                .to_string();
        assert!(
            message.contains("com.example:lib:1.0")
                && message.contains("linux-x86_64/app/pom.xml")
                && message.contains("darwin-aarch64/app/pom.xml"),
            "conflict must name the coordinate and both origins, got: {message}"
        );
    }

    /// A preserved platform that pins a different POM than a freshly resolved
    /// one cannot be carried forward: Maven reads one `.pom` per coordinate, so
    /// export would write one of them and build the other platform against a
    /// POM it never resolved. The conflict has to be found before the lockfile
    /// is written.
    #[test]
    fn cross_platform_pom_pin_conflict_is_detected_before_writing() {
        let fresh = lock_pinning("linux", "x86_64", &digest('a'));
        let preserved = lock_pinning("darwin", "aarch64", &digest('b'));
        let pins = companion_pom_pins(&fresh);
        assert_eq!(
            conflicting_companion_pom_pin(&pins, &preserved.platforms[0]).as_deref(),
            Some("com.example:lib:1.0")
        );

        // Negative control: agreeing pins across platforms are the normal case.
        let agreeing = lock_pinning("darwin", "aarch64", &digest('a'));
        assert!(conflicting_companion_pom_pin(&pins, &agreeing.platforms[0]).is_none());
    }

    /// Support-POM provenance is one global metadata block, so a preserved
    /// platform cannot keep its own copy of a coordinate this run resolved to
    /// different bytes.
    #[test]
    fn cross_platform_support_pom_conflict_is_detected_before_writing() {
        let mut previous = Lockfile::new();
        previous.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:parent:1.0\tcorp\t{}", digest('c')),
        );
        let mut fresh = Lockfile::new();
        fresh.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:parent:1.0\tcorp\t{}", digest('d')),
        );
        assert_eq!(
            conflicting_support_pom_digest(&previous, &fresh)
                .expect("well-formed metadata")
                .as_deref(),
            Some("com.example:parent:1.0")
        );

        fresh.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!(
                "com.example:parent:1.0\tcorp\t{}\ncom.example:new:2.0\tcorp\t{}",
                digest('c'),
                digest('e')
            ),
        );
        assert!(
            conflicting_support_pom_digest(&previous, &fresh)
                .expect("well-formed metadata")
                .is_none(),
            "a coordinate only one side records is not a conflict"
        );
    }

    /// A GAV can be reached both as a parent/imported BOM and as a dependency,
    /// and the two recordings live in different halves of the lockfile: the
    /// support-POM metadata block and an artifact row's `pom_sha256`. Maven
    /// still keeps one `.pom` for it, so a preserved platform whose row
    /// disagrees with this run's support pin cannot be carried forward.
    #[test]
    fn preserved_companion_pin_conflicting_with_a_fresh_support_pin_is_detected() {
        let mut fresh = lock_pinning("linux", "x86_64", &digest('a'));
        fresh.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:lib:1.0\tcorp\t{}", digest('a')),
        );
        let fresh_support = support_pom_pins(&fresh).expect("well-formed metadata");

        let preserved = lock_pinning("darwin", "aarch64", &digest('b'));
        assert_eq!(
            conflicting_support_companion_pin(
                &fresh_support,
                &platform_companion_pom_pins(&preserved.platforms[0]),
            )
            .as_deref(),
            Some("com.example:lib:1.0")
        );

        // Negative control: the same bytes in both recordings is the healthy
        // shape and preserves the platform.
        let agreeing = lock_pinning("darwin", "aarch64", &digest('a'));
        assert!(
            conflicting_support_companion_pin(
                &fresh_support,
                &platform_companion_pom_pins(&agreeing.platforms[0]),
            )
            .is_none()
        );
    }

    /// The mirror direction: preserving any platform merges the previous
    /// lockfile's whole support block back in, so a previous-only support pin
    /// that contradicts a freshly resolved companion pin has to gate
    /// preservation too — nothing later in the write path would notice it.
    #[test]
    fn carried_support_pin_conflicting_with_a_fresh_companion_pin_is_detected() {
        let mut previous = Lockfile::new();
        previous.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:lib:1.0\tcorp\t{}", digest('b')),
        );
        let fresh = lock_pinning("linux", "x86_64", &digest('a'));
        assert_eq!(
            conflicting_support_companion_pin(
                &support_pom_pins(&previous).expect("well-formed metadata"),
                &companion_pom_pins(&fresh),
            )
            .as_deref(),
            Some("com.example:lib:1.0")
        );

        // A legacy two-field line pins no bytes, so it cannot disagree.
        previous.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            "com.example:lib:1.0\tcorp".to_string(),
        );
        assert!(
            conflicting_support_companion_pin(
                &support_pom_pins(&previous).expect("well-formed metadata"),
                &companion_pom_pins(&fresh),
            )
            .is_none()
        );
    }

    /// The last gate before the write. A coordinate resolved both ways inside
    /// one run has no preserved platform to drop, so the sync fails instead of
    /// recording a lockfile whose two halves contradict each other.
    #[test]
    fn support_companion_conflict_within_one_resolution_fails_the_sync() {
        let mut lock = lock_pinning("linux", "x86_64", &digest('a'));
        lock.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:lib:1.0\tcorp\t{}", digest('b')),
        );
        let message = check_support_companion_agreement(&lock)
            .expect_err("one GAV cannot pin two POMs")
            .to_string();
        assert!(
            message.contains("com.example:lib:1.0"),
            "the error must name the coordinate, got: {message}"
        );

        lock.metadata.insert(
            LOCK_SUPPORT_POMS_KEY.to_string(),
            format!("com.example:lib:1.0\tcorp\t{}", digest('a')),
        );
        check_support_companion_agreement(&lock).expect("agreeing pins are the healthy shape");
    }

    /// `rv sync --platforms <one>` must preserve every other platform's
    /// entries from the previous lockfile. The fix is implemented as a
    /// merge step between the in-memory `lock` (which holds only freshly
    /// resolved platforms) and `previous_lock`. This unit test exercises
    /// that merge directly to guard against a future refactor silently
    /// dropping the un-resolved entries again.
    #[test]
    fn partial_sync_preserves_other_platforms() {
        use std::collections::HashSet;

        let mut previous = Lockfile::new();
        let mut linux = empty_platform("linux", "x86_64");
        push_package(&mut linux, package("com.example", "lib", "1.0"));
        previous.platforms.push(linux);
        let mut darwin = empty_platform("darwin", "aarch64");
        push_package(&mut darwin, package("com.example", "lib", "1.0"));
        previous.platforms.push(darwin);

        // Simulate `rv sync --platforms linux-x86_64`: the in-memory
        // lockfile holds only the requested platform.
        let mut fresh = Lockfile::new();
        let mut linux_new = empty_platform("linux", "x86_64");
        push_package(&mut linux_new, package("com.example", "lib", "2.0"));
        fresh.platforms.push(linux_new);

        // The merge step (mirror of the production code in `run_inner`).
        let resolved: HashSet<Platform> =
            fresh.platforms.iter().map(|p| p.platform.clone()).collect();
        for prev_platform in &previous.platforms {
            if !resolved.contains(&prev_platform.platform) {
                fresh.platforms.push(prev_platform.clone());
            }
        }

        assert_eq!(
            fresh.platforms.len(),
            2,
            "merged lockfile must carry both platforms"
        );
        let linux_entry = fresh
            .platforms
            .iter()
            .find(|p| p.platform.to_string() == "linux-x86_64")
            .expect("linux entry present");
        assert_eq!(
            linux_entry.modules[0].packages[0].coordinate.version, "2.0",
            "linux platform must carry the freshly resolved version"
        );
        let darwin_entry = fresh
            .platforms
            .iter()
            .find(|p| p.platform.to_string() == "darwin-aarch64")
            .expect("darwin entry preserved");
        assert_eq!(
            darwin_entry.modules[0].packages[0].coordinate.version, "1.0",
            "un-resolved platform must keep its previous pin"
        );
    }

    /// The on-disk lock is sorted with remapped edge indices, while a fresh
    /// resolution is still in traversal order. Frozen comparison must
    /// canonicalize both without treating top-level metadata as graph drift.
    /// The timestamped snapshot matches the shape seen in the Apache Maven
    /// corpus.
    #[test]
    fn lock_resolution_matches_canonicalizes_package_order_and_edges() {
        use rv_config::{Checksum, LockEdge};

        let mut selected = Lockfile::new();
        let mut platform = empty_platform("linux", "x86_64");
        let mut pkg = package("com.example", "demo", "1.0-SNAPSHOT");
        pkg.snapshot_timestamp = Some("20240101.010101-7".to_string());
        pkg.checksum = Some(Checksum::new("sha256", "a".repeat(64)));
        push_package(&mut platform, pkg);
        push_package(&mut platform, package("com.example", "zeta", "1.0"));
        platform.modules[0].edges.push(LockEdge {
            from: 0,
            to: 1,
            scope: Some("compile".to_string()),
            optional: false,
            extra: std::collections::BTreeMap::new(),
        });
        selected.platforms.push(platform);
        selected.config_hash = Some("abc123".to_string());
        selected
            .metadata
            .insert("written_at".to_string(), "yesterday".to_string());

        let mut resolved = Lockfile::new();
        let mut platform = empty_platform("linux", "x86_64");
        push_package(&mut platform, package("com.example", "zeta", "1.0"));
        let mut refreshed = package("com.example", "demo", "1.0-SNAPSHOT");
        refreshed.snapshot_timestamp = Some("20240101.010101-7".to_string());
        refreshed.checksum = Some(Checksum::new("sha256", "a".repeat(64)));
        push_package(&mut platform, refreshed);
        platform.modules[0].edges.push(LockEdge {
            from: 1,
            to: 0,
            scope: Some("compile".to_string()),
            optional: false,
            extra: std::collections::BTreeMap::new(),
        });
        resolved.platforms.push(platform);

        assert!(
            lock_resolution_matches(&selected, &resolved),
            "traversal order and remapped edge indices must not register as drift"
        );
    }

    /// Frozen locks pin the unique timestamp/build identity of an external
    /// snapshot. A newly published build under the same logical
    /// `-SNAPSHOT` coordinate is lockfile drift.
    #[test]
    fn lock_resolution_snapshot_identity_change_is_drift() {
        use rv_config::Checksum;

        let mut old = Lockfile::new();
        let mut old_platform = empty_platform("linux", "x86_64");
        let mut old_snapshot = package("com.example", "demo", "1.0-SNAPSHOT");
        old_snapshot.snapshot_timestamp = Some("20240101.010101-7".to_string());
        old_snapshot.checksum = Some(Checksum::new("sha256", "a".repeat(64)));
        push_package(&mut old_platform, old_snapshot);
        old.platforms.push(old_platform);

        let mut new = Lockfile::new();
        let mut new_platform = empty_platform("linux", "x86_64");
        let mut new_snapshot = package("com.example", "demo", "1.0-SNAPSHOT");
        new_snapshot.snapshot_timestamp = Some("20240202.020202-9".to_string());
        new_snapshot.checksum = Some(Checksum::new("sha256", "b".repeat(64)));
        push_package(&mut new_platform, new_snapshot);
        new.platforms.push(new_platform);

        assert!(
            !lock_resolution_matches(&old, &new),
            "a newer timestamp/build identity must surface as drift"
        );
    }

    /// #34: a freshly published upstream SNAPSHOT advances the artifact bytes
    /// (and thus the sha256 pin) when its update-policy TTL elapses. The
    /// `--frozen` snapshot-refresh path must NOT treat that as drift, because
    /// the coordinate/edges are unchanged. Release pins keep the strict
    /// checksum comparison.
    #[test]
    fn lock_resolution_snapshot_checksum_change_is_not_drift() {
        use rv_config::Checksum;

        let mut old = Lockfile::new();
        let mut p_old = empty_platform("linux", "x86_64");
        let mut snap_old = package("com.example", "demo", "1.0-SNAPSHOT");
        snap_old.checksum = Some(Checksum::new("sha256", "a".repeat(64)));
        push_package(&mut p_old, snap_old);
        old.platforms.push(p_old);

        let mut new = Lockfile::new();
        let mut p_new = empty_platform("linux", "x86_64");
        let mut snap_new = package("com.example", "demo", "1.0-SNAPSHOT");
        snap_new.checksum = Some(Checksum::new("sha256", "c".repeat(64)));
        push_package(&mut p_new, snap_new);
        new.platforms.push(p_new);

        assert!(
            lock_resolution_matches(&old, &new),
            "a SNAPSHOT checksum change after a TTL refresh must not be flagged as drift"
        );
    }

    /// #34 guard: the snapshot relaxation must NOT leak into release pins. A
    /// release artifact whose checksum changed is genuine drift (a mismatch
    /// between the lockfile and what the repo now serves) and `--frozen` must
    /// reject it.
    #[test]
    fn lock_resolution_release_checksum_change_is_drift() {
        use rv_config::Checksum;

        let mut old = Lockfile::new();
        let mut p_old = empty_platform("linux", "x86_64");
        let mut rel_old = package("com.example", "demo", "1.0");
        rel_old.checksum = Some(Checksum::new("sha256", "a".repeat(64)));
        push_package(&mut p_old, rel_old);
        old.platforms.push(p_old);

        let mut new = Lockfile::new();
        let mut p_new = empty_platform("linux", "x86_64");
        let mut rel_new = package("com.example", "demo", "1.0");
        rel_new.checksum = Some(Checksum::new("sha256", "d".repeat(64)));
        push_package(&mut p_new, rel_new);
        new.platforms.push(p_new);

        assert!(
            !lock_resolution_matches(&old, &new),
            "a release checksum change must surface as drift"
        );
    }

    /// Regression: `--frozen` with no pom.xml and a legacy lockfile
    /// that has no `config_hash` must NOT silently pass; it must return a
    /// `LockfileMismatch` error (which exits with `LOCKFILE_MISMATCH = 7`).
    #[test]
    fn frozen_none_none_returns_mismatch_error() {
        let result = check_frozen_config_hash(None, None);
        assert!(
            matches!(result, Err(crate::error::CliError::LockfileMismatch { .. })),
            "--frozen (None, None) must return LockfileMismatch, got: {result:?}"
        );

        // Also verify the exit code is LOCKFILE_MISMATCH (7) so CI sees
        // a non-zero exit code rather than a silent pass.
        let err = result.unwrap_err();
        assert_eq!(
            err.exit_code(),
            crate::error::ExitCodes::LOCKFILE_MISMATCH,
            "exit code must be LOCKFILE_MISMATCH (7)"
        );
    }

    /// Regression: deleting the `config_hash` line from rv.lock while
    /// pom.xml is present must not defeat the `--frozen` CI gate. The
    /// `(Some(_), None)` combination has nothing to verify against and must
    /// fail with a `LockfileMismatch` that tells the user to re-run
    /// `rv sync` without --frozen.
    #[test]
    fn frozen_missing_config_hash_returns_mismatch_error() {
        let result = check_frozen_config_hash(Some("abc123"), None);
        let err = result.expect_err("--frozen (Some, None) must fail");
        match &err {
            crate::error::CliError::LockfileMismatch { details } => {
                assert!(
                    details.contains("config_hash") && details.contains("without --frozen"),
                    "error must explain the missing hash and the fix: {details}"
                );
            }
            other => panic!("expected LockfileMismatch, got {other:?}"),
        }
        assert_eq!(
            err.exit_code(),
            crate::error::ExitCodes::LOCKFILE_MISMATCH,
            "exit code must be LOCKFILE_MISMATCH (7)"
        );
    }

    /// The remaining `--frozen` hash combinations: equal hashes proceed,
    /// unequal hashes and a missing manifest both fail.
    #[test]
    fn frozen_config_hash_other_combinations() {
        assert!(check_frozen_config_hash(Some("abc"), Some("abc")).is_ok());
        assert!(matches!(
            check_frozen_config_hash(Some("abc"), Some("def")),
            Err(crate::error::CliError::LockfileMismatch { .. })
        ));
        assert!(matches!(
            check_frozen_config_hash(None, Some("abc")),
            Err(crate::error::CliError::LockfileMismatch { .. })
        ));
    }

    /// `--frozen` must not flag drift when the only difference between the
    /// lockfile selection and the fresh resolve is platform order: the
    /// selection follows CLI argument order while the resolve sorts by name.
    #[test]
    fn lock_resolution_matches_ignores_platform_order() {
        let mut selected = Lockfile::new();
        let mut linux = empty_platform("linux", "x86_64");
        push_package(&mut linux, package("com.example", "lib", "1.0"));
        let mut darwin = empty_platform("darwin", "aarch64");
        push_package(&mut darwin, package("com.example", "lib", "1.0"));
        // CLI order: linux first.
        selected.platforms.push(linux.clone());
        selected.platforms.push(darwin.clone());

        // Resolve order: sorted by platform name, darwin first.
        let mut resolved = Lockfile::new();
        resolved.platforms.push(darwin);
        resolved.platforms.push(linux);

        assert!(
            lock_resolution_matches(&selected, &resolved),
            "platform ordering alone must not register as drift"
        );
    }

    /// A release pin recorded with sha1 (the fallback when the repository
    /// publishes no sha256 sidecar) cannot be compared digest-for-digest
    /// against a freshly resolved sha256 pin; the pair is inconclusive, not
    /// drift. Same-algorithm digests still compare strictly (covered by
    /// `lock_resolution_release_checksum_change_is_drift`).
    #[test]
    fn lock_resolution_mixed_algorithm_release_pin_is_inconclusive() {
        use rv_config::Checksum;

        let mut old = Lockfile::new();
        let mut p_old = empty_platform("linux", "x86_64");
        let mut rel_old = package("com.example", "demo", "1.0");
        rel_old.checksum = Some(Checksum::new("sha1", "a".repeat(40)));
        push_package(&mut p_old, rel_old);
        old.platforms.push(p_old);

        let mut new = Lockfile::new();
        let mut p_new = empty_platform("linux", "x86_64");
        let mut rel_new = package("com.example", "demo", "1.0");
        rel_new.checksum = Some(Checksum::new("sha256", "b".repeat(64)));
        push_package(&mut p_new, rel_new);
        new.platforms.push(p_new);

        assert!(
            lock_resolution_matches(&old, &new),
            "a sha1 pin against a sha256 resolve must not be flagged as drift"
        );
    }

    /// A release pin that disappears (or appears) between the lockfile and
    /// the resolve is still drift; only mixed algorithms are inconclusive.
    #[test]
    fn lock_resolution_pin_appearing_is_drift() {
        use rv_config::Checksum;

        let mut old = Lockfile::new();
        let mut p_old = empty_platform("linux", "x86_64");
        push_package(&mut p_old, package("com.example", "demo", "1.0"));
        old.platforms.push(p_old);

        let mut new = Lockfile::new();
        let mut p_new = empty_platform("linux", "x86_64");
        let mut rel_new = package("com.example", "demo", "1.0");
        rel_new.checksum = Some(Checksum::new("sha256", "b".repeat(64)));
        push_package(&mut p_new, rel_new);
        new.platforms.push(p_new);

        assert!(!lock_resolution_matches(&old, &new));
    }

    /// `--frozen` mismatch error must include the changed entries so
    /// users can see which packages drifted without running `rv sync`.
    #[test]
    fn frozen_drift_error_includes_diff_entries() {
        use crate::commands::sync::diff::format_frozen_diff;

        let mut old = Lockfile::new();
        let mut platform_old = empty_platform("linux", "x86_64");
        push_package(&mut platform_old, package("com.example", "lib", "1.0"));
        push_package(&mut platform_old, package("com.example", "other", "2.0"));
        old.platforms.push(platform_old);

        let mut new = Lockfile::new();
        let mut platform_new = empty_platform("linux", "x86_64");
        // lib bumped; other removed; new-dep added
        push_package(&mut platform_new, package("com.example", "lib", "1.1"));
        push_package(&mut platform_new, package("com.example", "new-dep", "3.0"));
        new.platforms.push(platform_new);

        let diff = format_frozen_diff(&old, &new);
        assert!(
            !diff.is_empty(),
            "diff must not be empty when packages changed"
        );
        // Updated entry
        assert!(
            diff.contains("com.example:lib"),
            "updated package must appear in diff: {diff}"
        );
        // Removed entry
        assert!(
            diff.contains("com.example:other"),
            "removed package must appear in diff: {diff}"
        );
        // Added entry
        assert!(
            diff.contains("com.example:new-dep"),
            "added package must appear in diff: {diff}"
        );
    }

    /// A checksum-only drift (same coordinate and version, different
    /// same-algorithm digest) must produce a named diff entry rather than
    /// an empty diff that forces the fallback "would change" message.
    #[test]
    fn frozen_diff_names_checksum_only_drift() {
        use crate::commands::sync::diff::format_frozen_diff;
        use rv_config::Checksum;

        let mut old = Lockfile::new();
        let mut platform_old = empty_platform("linux", "x86_64");
        let mut pkg_old = package("com.example", "lib", "1.0");
        pkg_old.checksum = Some(Checksum::new("sha256", "a".repeat(64)));
        push_package(&mut platform_old, pkg_old);
        old.platforms.push(platform_old);

        let mut new = Lockfile::new();
        let mut platform_new = empty_platform("linux", "x86_64");
        let mut pkg_new = package("com.example", "lib", "1.0");
        pkg_new.checksum = Some(Checksum::new("sha256", "b".repeat(64)));
        push_package(&mut platform_new, pkg_new);
        new.platforms.push(platform_new);

        let diff = format_frozen_diff(&old, &new);
        assert!(
            diff.contains("checksum changed for com.example:lib:1.0"),
            "checksum-only drift must be named in the diff: {diff}"
        );
    }

    /// diff output must be capped at `FROZEN_DIFF_DISPLAY_CAP` entries
    /// with a "... and N more" footer when there are many changes.
    #[test]
    fn frozen_diff_capped_with_footer() {
        use crate::commands::sync::diff::{FROZEN_DIFF_DISPLAY_CAP, format_frozen_diff};

        let mut old = Lockfile::new();
        let mut platform_old = empty_platform("linux", "x86_64");
        // Add FROZEN_DIFF_DISPLAY_CAP + 3 packages in old (all removed in new).
        for i in 0..(FROZEN_DIFF_DISPLAY_CAP + 3) {
            push_package(
                &mut platform_old,
                package("com.example", &format!("dep{i}"), "1.0"),
            );
        }
        old.platforms.push(platform_old);

        // new is empty: every package was removed.
        let new = Lockfile::new();

        let diff = format_frozen_diff(&old, &new);
        assert!(
            diff.contains("... and 3 more"),
            "overflow footer must appear: {diff}"
        );
    }

    /// when lockfiles are identical, diff must be empty (no false
    /// positives in the --frozen mismatch error path).
    #[test]
    fn frozen_diff_empty_when_no_changes() {
        use crate::commands::sync::diff::format_frozen_diff;

        let mut lock = Lockfile::new();
        let mut platform = empty_platform("linux", "x86_64");
        push_package(&mut platform, package("com.example", "lib", "1.0"));
        lock.platforms.push(platform);

        let diff = format_frozen_diff(&lock, &lock.clone());
        assert!(
            diff.is_empty(),
            "diff must be empty when lockfiles are identical: {diff}"
        );
    }

    /// The checksum-mismatch message must label the pin with its real
    /// algorithm (derived from the digest length the lockfile loader
    /// enforces), not hardcode sha256.
    #[test]
    fn digest_algorithm_name_from_pin_length() {
        assert_eq!(digest_algorithm_name(&"a".repeat(64)), "sha256");
        assert_eq!(digest_algorithm_name(&"a".repeat(40)), "sha1");
        assert_eq!(digest_algorithm_name("oddball"), "checksum");
    }

    /// When a download batch has both checksum mismatches and other
    /// failures, the message must report both classes: checksum lines
    /// first, then the first few other failures with an overflow footer.
    #[test]
    fn checksum_failure_details_include_other_failures() {
        let checksum_lines = vec!["com.example:bad:1.0: expected sha1 aa, got bb".to_string()];
        let other: Vec<String> = (0..5)
            .map(|i| format!("com.example:dep{i}:1.0: not found"))
            .collect();

        let details = format_checksum_failure_details(&checksum_lines, &other);
        assert!(
            details.contains("checksum mismatch for 1 artifact(s)"),
            "details: {details}"
        );
        assert!(
            details.contains("and 5 other download failure(s)"),
            "other failures must be counted: {details}"
        );
        assert!(
            details.contains("com.example:dep0:1.0: not found"),
            "first other failures must be listed: {details}"
        );
        assert!(
            details.contains("... and 2 more"),
            "overflow beyond the display cap must be summarized: {details}"
        );

        // Without other failures the message stays as before.
        let alone = format_checksum_failure_details(&checksum_lines, &[]);
        assert!(
            !alone.contains("other download failure"),
            "details: {alone}"
        );
    }

    /// `config_hash` must cover more than the root pom.xml. Editing
    /// `.mvn/maven.config`, `rv.toml`, the user-level config.toml, or the
    /// active-profile set (all of which can change resolution) must change
    /// the hash so `--frozen` and the resolve fast-path do not silently reuse
    /// a stale lockfile.
    #[test]
    fn config_hash_covers_extra_inputs() {
        use super::compute_config_hash;
        use rv_config::{Config, ResolvedPaths};
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let raeva_home = root.join("raeva-home");
        let pom_path = root.join("pom.xml");
        fs::write(
            &pom_path,
            "<project><groupId>com.example</groupId>\
             <artifactId>demo</artifactId><version>1.0</version></project>",
        )
        .expect("write pom");

        let make_config = || {
            let paths = ResolvedPaths::from_raeva_home(&raeva_home);
            Config::for_testing_with_repos(root.to_path_buf(), paths, Vec::new())
        };

        let baseline = compute_config_hash(&make_config(), &pom_path).expect("hash baseline");

        // Re-hashing the same untouched inputs is stable.
        assert_eq!(
            baseline,
            compute_config_hash(&make_config(), &pom_path).expect("hash stable"),
            "config_hash must be deterministic for unchanged inputs"
        );

        // Adding `.mvn/maven.config` must change the hash.
        let mvn_dir = root.join(".mvn");
        fs::create_dir_all(&mvn_dir).expect("mkdir .mvn");
        fs::write(mvn_dir.join("maven.config"), "-Pprod\n").expect("write maven.config");
        let with_maven_config =
            compute_config_hash(&make_config(), &pom_path).expect("hash with maven.config");
        assert_ne!(
            baseline, with_maven_config,
            "adding .mvn/maven.config must change config_hash"
        );

        // Editing `.mvn/maven.config` must change the hash again.
        fs::write(mvn_dir.join("maven.config"), "-Pstaging\n").expect("rewrite maven.config");
        let edited_maven_config =
            compute_config_hash(&make_config(), &pom_path).expect("hash edited maven.config");
        assert_ne!(
            with_maven_config, edited_maven_config,
            "editing .mvn/maven.config must change config_hash"
        );

        // Adding `rv.toml` must change the hash.
        fs::write(root.join("rv.toml"), "[network]\nretries = 5\n").expect("write rv.toml");
        let with_rv_toml =
            compute_config_hash(&make_config(), &pom_path).expect("hash with rv.toml");
        assert_ne!(
            edited_maven_config, with_rv_toml,
            "adding rv.toml must change config_hash"
        );

        // Adding the user-level config.toml must change the hash too; it can
        // declare repositories/mirrors that steer resolution. The test config
        // points `user_config_path` at <root>/config.toml.
        fs::write(root.join("config.toml"), "[network]\nretries = 9\n")
            .expect("write user config.toml");
        let with_user_config =
            compute_config_hash(&make_config(), &pom_path).expect("hash with user config");
        assert_ne!(
            with_rv_toml, with_user_config,
            "adding the user config.toml must change config_hash"
        );
    }

    #[test]
    fn provisional_model_hash_covers_pom_bytes_and_active_profile_ids() {
        let profiles = vec!["release".to_string(), "ci".to_string()];
        let baseline = hash_model_inputs(b"<project>one</project>", &profiles);
        assert_eq!(
            baseline,
            hash_model_inputs(
                b"<project>one</project>",
                &["ci".to_string(), "release".to_string(), "ci".to_string()]
            ),
            "profile ordering and duplicates must not churn model_hash"
        );
        assert_ne!(
            baseline,
            hash_model_inputs(b"<project>two</project>", &profiles),
            "root POM bytes must affect model_hash"
        );
        assert_ne!(
            baseline,
            hash_model_inputs(
                b"<project>one</project>",
                &["ci".to_string(), "staging".to_string()]
            ),
            "active profile ids must affect model_hash"
        );
    }

    /// editing a local parent POM reached via `<relativePath>` must
    /// change the config hash. The parent can carry dependencyManagement /
    /// properties that steer the child's resolution, so a stale lockfile must
    /// not survive a parent edit.
    #[test]
    fn config_hash_covers_local_parent_chain() {
        use super::compute_config_hash;
        use rv_config::{Config, ResolvedPaths};
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let raeva_home = root.join("raeva-home");

        // Parent POM at <root>/parent/pom.xml; child references it via
        // relativePath ../parent/pom.xml.
        let parent_dir = root.join("parent");
        fs::create_dir_all(&parent_dir).expect("mkdir parent");
        let parent_pom = parent_dir.join("pom.xml");
        fs::write(
            &parent_pom,
            "<project><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.0</version>\
             <packaging>pom</packaging>\
             <properties><foo>one</foo></properties></project>",
        )
        .expect("write parent pom");

        let child_dir = root.join("child");
        fs::create_dir_all(&child_dir).expect("mkdir child");
        let child_pom = child_dir.join("pom.xml");
        fs::write(
            &child_pom,
            "<project>\
             <parent><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.0</version>\
             <relativePath>../parent/pom.xml</relativePath></parent>\
             <artifactId>child</artifactId></project>",
        )
        .expect("write child pom");

        let make_config = || {
            let paths = ResolvedPaths::from_raeva_home(&raeva_home);
            Config::for_testing_with_repos(child_dir.clone(), paths, Vec::new())
        };

        let before = compute_config_hash(&make_config(), &child_pom).expect("hash before");

        // The walk must actually have found the parent.
        let child_xml = rv_config::read_project_input_string(&child_pom).expect("read child pom");
        let chain = super::accepted_local_parents(
            &child_pom,
            &child_xml,
            &super::local_parent_boundary(&child_dir, 1),
            &std::collections::HashMap::new(),
        );
        assert_eq!(chain.len(), 1, "expected to walk exactly one local parent");

        // Editing the parent POM changes the hash.
        fs::write(
            &parent_pom,
            "<project><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.0</version>\
             <packaging>pom</packaging>\
             <properties><foo>two</foo></properties></project>",
        )
        .expect("rewrite parent pom");
        let after = compute_config_hash(&make_config(), &child_pom).expect("hash after");
        assert_ne!(
            before, after,
            "editing a local parent POM must change config_hash"
        );
    }

    /// Hash the reactor model rooted at `project_root` for the current
    /// platform, exactly as `rv sync` does.
    fn discover_model(project_root: &std::path::Path) -> super::ReactorModel {
        use rv_config::{Config, ResolvedPaths};

        let paths = ResolvedPaths::from_raeva_home(project_root.join("raeva-home"));
        let config = Config::for_testing_with_repos(project_root.to_path_buf(), paths, Vec::new());
        let platform = Platform::current().expect("platform");
        super::discover_reactor_model(&config, &platform).expect("discover model")
    }

    /// Build a project tree under a fresh tempdir and hash the reactor model
    /// rooted at `project_root`. Returns the module/parent paths the model
    /// hash covers.
    fn model_pom_paths(project_root: &std::path::Path) -> Vec<String> {
        discover_model(project_root)
            .pom_hashes
            .keys()
            .cloned()
            .collect()
    }

    /// A local parent named only through a `.mvn/maven.config` property.
    /// Resolution overlays those `-D` entries on the module POM and loads the
    /// parent, so its bytes shape the resolved graph and both hashes have to
    /// cover them: otherwise editing that parent leaves `model_hash`
    /// unchanged, the fast path reuses the stale lock, and `--frozen` reports
    /// no drift.
    #[test]
    fn model_hash_covers_a_parent_named_by_maven_config() {
        use rv_config::{LockGav, LockPlatform, Lockfile};
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let parent_dir = dir.path().join("parent");
        fs::create_dir_all(&parent_dir).expect("mkdir parent");
        let parent_pom = parent_dir.join("pom.xml");
        fs::write(
            &parent_pom,
            "<project><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.2.3</version>\
             <packaging>pom</packaging>\
             <properties><foo>one</foo></properties></project>",
        )
        .expect("write parent pom");

        let project_root = dir.path().join("app");
        fs::create_dir_all(project_root.join(".mvn")).expect("mkdir .mvn");
        fs::write(
            project_root.join(".mvn").join("maven.config"),
            "-DparentVersion=1.2.3\n",
        )
        .expect("write maven.config");
        // The declaration names the parent only once `parentVersion` expands.
        fs::write(
            project_root.join("pom.xml"),
            "<project>\
             <parent><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>${parentVersion}</version>\
             <relativePath>../parent/pom.xml</relativePath></parent>\
             <artifactId>app</artifactId><version>1.0</version></project>",
        )
        .expect("write project pom");

        let model = discover_model(&project_root);
        assert_eq!(
            model.pom_hashes.keys().cloned().collect::<Vec<_>>(),
            ["../parent/pom.xml", "pom.xml"],
            "the parent resolution loads must be a hashed model input"
        );

        // A lock written from this model, as `rv sync` records it.
        let mut platform = LockPlatform::single_module(
            Platform::current().expect("platform"),
            model.model_hash.clone(),
            "pom.xml",
            LockGav::new("com.example", "app", "1.0"),
            "jar",
            Vec::new(),
            Vec::new(),
        );
        super::record_model_inputs(&mut platform, &model);
        let mut lock = Lockfile::new();
        lock.platforms.push(platform);
        assert!(
            super::frozen_models_match(&lock, std::slice::from_ref(&model)),
            "an untouched reactor must stay on the fast path"
        );

        fs::write(
            &parent_pom,
            "<project><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.2.3</version>\
             <packaging>pom</packaging>\
             <properties><foo>two</foo></properties></project>",
        )
        .expect("rewrite parent pom");

        let edited = discover_model(&project_root);
        assert_ne!(
            model.model_hash, edited.model_hash,
            "editing that parent must change model_hash"
        );
        let error = super::validate_frozen_models(&lock, std::slice::from_ref(&edited))
            .expect_err("--frozen must report the edited parent as drift");
        match error {
            CliError::LockfileMismatch { details } => assert!(
                details.contains("local parent POM changed: ../parent/pom.xml"),
                "{details}"
            ),
            other => panic!("expected LockfileMismatch, got {other:?}"),
        }
    }

    /// The schema 1-3 `config_hash` recipe walks the same chain, so it needs
    /// the same `.mvn/maven.config` entries to reach that parent.
    #[test]
    fn config_hash_covers_a_parent_named_by_maven_config() {
        use rv_config::{Config, ResolvedPaths};
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let raeva_home = root.join("raeva-home");
        let parent_dir = root.join("parent");
        fs::create_dir_all(&parent_dir).expect("mkdir parent");
        let parent_pom = parent_dir.join("pom.xml");
        fs::write(
            &parent_pom,
            "<project><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.2.3</version>\
             <packaging>pom</packaging>\
             <properties><foo>one</foo></properties></project>",
        )
        .expect("write parent pom");

        let child_dir = root.join("child");
        fs::create_dir_all(child_dir.join(".mvn")).expect("mkdir .mvn");
        fs::write(
            child_dir.join(".mvn").join("maven.config"),
            "-DparentVersion=1.2.3\n",
        )
        .expect("write maven.config");
        let child_pom = child_dir.join("pom.xml");
        fs::write(
            &child_pom,
            "<project>\
             <parent><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>${parentVersion}</version>\
             <relativePath>../parent/pom.xml</relativePath></parent>\
             <artifactId>child</artifactId><version>1.0</version></project>",
        )
        .expect("write child pom");

        let make_config = || {
            let paths = ResolvedPaths::from_raeva_home(&raeva_home);
            Config::for_testing_with_repos(child_dir.clone(), paths, Vec::new())
        };
        let before = compute_config_hash(&make_config(), &child_pom).expect("hash before");

        fs::write(
            &parent_pom,
            "<project><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1.2.3</version>\
             <packaging>pom</packaging>\
             <properties><foo>two</foo></properties></project>",
        )
        .expect("rewrite parent pom");
        assert_ne!(
            before,
            compute_config_hash(&make_config(), &child_pom).expect("hash after"),
            "editing the parent named by maven.config must change config_hash"
        );
    }

    /// Security: a `<relativePath>` pointing outside the reactor must not put
    /// an arbitrary local path and digest into the commit-bound lockfile.
    #[test]
    fn model_hash_skips_parent_escaping_the_reactor() {
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).expect("mkdir outside");
        fs::write(
            outside.join("pom.xml"),
            "<project><groupId>com.example</groupId>\
             <artifactId>secret</artifactId><version>1.0</version>\
             <packaging>pom</packaging></project>",
        )
        .expect("write outside pom");

        let project_root = dir.path().join("nested").join("project");
        fs::create_dir_all(&project_root).expect("mkdir project");
        fs::write(
            project_root.join("pom.xml"),
            "<project>\
             <parent><groupId>com.example</groupId>\
             <artifactId>secret</artifactId><version>1.0</version>\
             <relativePath>../../outside/pom.xml</relativePath></parent>\
             <artifactId>demo</artifactId><version>1.0</version></project>",
        )
        .expect("write project pom");

        assert_eq!(model_pom_paths(&project_root), ["pom.xml"]);
    }

    /// A local file that is not the declared parent is not a model input
    /// either, so hashing must skip it exactly as resolution does.
    #[test]
    fn model_hash_skips_parent_with_mismatched_coordinates() {
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("pom.xml"),
            "<project><groupId>com.example</groupId>\
             <artifactId>unrelated</artifactId><version>1.0</version>\
             <packaging>pom</packaging></project>",
        )
        .expect("write outer pom");

        let project_root = dir.path().join("project");
        fs::create_dir_all(&project_root).expect("mkdir project");
        fs::write(
            project_root.join("pom.xml"),
            "<project>\
             <parent><groupId>com.example</groupId>\
             <artifactId>declared</artifactId><version>1.0</version></parent>\
             <artifactId>demo</artifactId><version>1.0</version></project>",
        )
        .expect("write project pom");

        assert_eq!(model_pom_paths(&project_root), ["pom.xml"]);
    }

    /// The flip side of the contract: the immediate external parent of a lone
    /// selected module is one resolution accepts, so the model hash covers it.
    #[test]
    fn model_hash_covers_accepted_external_parent_of_lone_module() {
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("pom.xml"),
            "<project><groupId>com.example</groupId>\
             <artifactId>outer</artifactId><version>1.0</version>\
             <packaging>pom</packaging>\
             <properties><revision>2.5.0</revision></properties></project>",
        )
        .expect("write outer pom");

        let project_root = dir.path().join("module");
        fs::create_dir_all(&project_root).expect("mkdir module");
        fs::write(
            project_root.join("pom.xml"),
            "<project>\
             <parent><groupId>com.example</groupId>\
             <artifactId>outer</artifactId><version>1.0</version></parent>\
             <artifactId>demo</artifactId><version>${revision}</version></project>",
        )
        .expect("write module pom");

        assert_eq!(model_pom_paths(&project_root), ["../pom.xml", "pom.xml"]);
    }

    #[test]
    fn config_hash_rejects_oversized_pom() {
        use rv_config::{Config, ResolvedPaths};

        let dir = tempfile::tempdir().expect("tempdir");
        let pom_path = dir.path().join("pom.xml");
        std::fs::write(&pom_path, vec![b'x'; rv_config::MAX_PROJECT_INPUT_SIZE + 1])
            .expect("write oversized pom");
        let config = Config::for_testing_with_repos(
            dir.path().to_path_buf(),
            ResolvedPaths::from_raeva_home(dir.path().join("raeva-home")),
            Vec::new(),
        );

        let error = compute_config_hash(&config, &pom_path).expect_err("oversized POM must fail");
        assert!(matches!(
            error,
            CliError::Config(rv_config::ConfigError::ProjectInputTooLarge { .. })
        ));
    }
}
