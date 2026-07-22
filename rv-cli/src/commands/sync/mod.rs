//! `rv sync` orchestrator: arg parsing plus the high-level run loop.
//!
//! Submodules house focused concerns:
//! - [`diff`]: lockfile diff rendering
//! - [`system_scope`]: system-scope policy enforcement and warnings
//! - [`disk`]: free-space sanity check on the store volume

mod diff;
mod disk;
mod system_scope;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{ArgAction, Args, ValueEnum};
use sha2::{Digest, Sha256};
use strum::{AsRefStr, Display, EnumString};

use rv_config::{
    Config, LockPackage, LockPlatform, Lockfile, LockfileGuard, Platform, UpdatePolicy,
};
use rv_maven_model::Pom;
use rv_repo::{RepoClient, is_snapshot_version, normalize_repo_url};
use rv_resolver::{ResolutionStrategy, ResolveContext, ResolveState, Resolver, RootSpec};
use rv_store::Store;

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

    let store = Arc::new(Store::open(&config.paths.store_dir)?);
    check_disk_space(&config.paths.store_dir);
    let progress = Arc::new(ProgressReporter::new());
    let client = RepoClient::new(config)
        .await?
        .with_progress(progress)
        .with_offline(args.offline)
        .with_allow_missing_checksums(args.allow_missing_checksums);

    let pom_path = config.project_root.join("pom.xml");
    let manifest_hash = if pom_path.is_file() {
        Some(compute_config_hash(config, &pom_path)?)
    } else {
        None
    };

    if args.frozen {
        let lock = read_lockfile(config)?;
        let selected = require_lock_for_platforms(&lock, &platforms)?;
        warn_system_scope_from_lock(&selected);
        let snapshot_refresh = lock_requires_snapshot_refresh(&selected, config);
        check_frozen_config_hash(manifest_hash.as_deref(), lock.config_hash.as_deref())?;
        if !snapshot_refresh {
            if !args.offline {
                ensure_artifacts(&selected, config, store.as_ref(), &client, &platforms).await?;
            }
            let dep_count = count_dependencies(&selected);
            print_summary(dep_count, elapsed_saturating(start));
            if !is_json_mode() && !quiet_enabled() {
                eprintln!("{}", success("lockfile is up to date"));
            }
            print_completed(elapsed_saturating(start));
            return Ok(dep_count);
        }
        // SNAPSHOT TTL elapsed: re-resolve against pom.xml. --frozen still
        // requires the manifest to exist for the re-resolve to verify.
        if manifest_hash.is_none() {
            return Err(CliError::ProjectFileMissing { path: pom_path });
        }
        reject_multi_module_pom(&pom_path)?;
        enforce_system_scope_policy(&pom_path)?;
        let resolved = resolve_lock(
            config,
            store.clone(),
            client.clone(),
            &platforms,
            &pom_path,
            strategy,
            args.frozen,
        )
        .await?;
        if !lock_resolution_matches(&selected, &resolved) {
            let diff = format_frozen_diff(&selected, &resolved);
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
            ensure_artifacts(&selected, config, store.as_ref(), &client, &platforms).await?;
        }
        let dep_count = count_dependencies(&selected);
        print_summary(dep_count, elapsed_saturating(start));
        if !is_json_mode() && !quiet_enabled() {
            eprintln!("{}", success("lockfile is up to date"));
        }
        print_completed(elapsed_saturating(start));
        return Ok(dep_count);
    }

    if !args.update
        && config.lock_path.is_file()
        && let Some(current_hash) = manifest_hash.as_deref()
    {
        let lock = read_lockfile(config)?;
        if lock.config_hash.as_deref() == Some(current_hash)
            // `filter_lock` returns `Ok(None)` when any requested platform
            // is missing from the lockfile; treat that as a cache miss so
            // we fall through to `resolve_lock` instead of erroring.
            && let Some(selected) = filter_lock(&lock, &platforms)?
            && !lock_requires_snapshot_refresh(&selected, config)
        {
            // `--offline` opts out of any network call; treat the fast-path
            // as resolution-only and skip the artifact download.
            if !args.offline {
                action("Downloading", "artifacts from lockfile...");
                ensure_artifacts(&selected, config, store.as_ref(), &client, &platforms).await?;
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

    // Falling through to a fresh resolve requires the pom.xml to exist;
    // --frozen had its own missing-manifest path above.
    let manifest_hash = manifest_hash.ok_or_else(|| CliError::ProjectFileMissing {
        path: pom_path.clone(),
    })?;
    reject_multi_module_pom(&pom_path)?;
    enforce_system_scope_policy(&pom_path)?;
    action("Resolving", "dependencies...");
    let mut lock = resolve_lock(
        config,
        store.clone(),
        client.clone(),
        &platforms,
        &pom_path,
        strategy,
        args.frozen,
    )
    .await?;
    lock.config_hash = Some(manifest_hash);

    action("Downloading", "artifacts...");
    ensure_artifacts(&lock, config, store.as_ref(), &client, &platforms).await?;
    result("Downloaded", "artifacts");

    // Preserve platform entries from the previous lockfile that we did not
    // re-resolve this run. `rv sync --platforms linux-x86_64` would otherwise
    // overwrite the on-disk lockfile with only the requested platform and
    // silently drop every other platform's pins (data loss for cross-platform
    // CI matrices that sync each platform from its own runner).
    if let Some(previous) = previous_lock.as_ref() {
        let resolved: HashSet<Platform> =
            lock.platforms.iter().map(|p| p.platform.clone()).collect();
        let mut preserved_platforms = false;
        for prev_platform in &previous.platforms {
            if !resolved.contains(&prev_platform.platform) {
                lock.platforms.push(prev_platform.clone());
                preserved_platforms = true;
            }
        }
        lock.platforms
            .sort_by(|a, b| a.platform.to_string().cmp(&b.platform.to_string()));
        carry_forward_lock_data(&mut lock, previous, preserved_platforms);
    }

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

/// Maximum number of local parent POMs walked when computing the config hash.
/// A relativePath chain is rare and shallow in single-module projects; the cap
/// guards against a cyclic or pathological `<relativePath>` chain spinning the
/// hash forever.
const MAX_PARENT_CHAIN: usize = 32;

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

    // 2. The local parent-POM chain, followed via <relativePath> (default
    //    `../pom.xml`). An empty relativePath disables the local lookup, which
    //    also terminates the walk.
    for (idx, parent_path) in local_parent_chain(pom_path, pom_xml)?
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

/// Resolve the chain of local parent POMs reachable from `pom_path` via
/// `<parent><relativePath>`. Stops at the first parent that is not present on
/// disk, has an empty relativePath (Maven's "skip local lookup" sentinel), or
/// fails to parse. Those parents resolve from the repository and are pinned by
/// the lockfile, not by a local file. Bounded by [`MAX_PARENT_CHAIN`].
fn local_parent_chain(pom_path: &Path, root_pom_xml: &str) -> Result<Vec<std::path::PathBuf>> {
    let mut chain = Vec::new();
    let mut current = pom_path.to_path_buf();
    let mut first = true;
    let mut seen: HashSet<std::path::PathBuf> = HashSet::new();
    seen.insert(current.canonicalize().unwrap_or_else(|_| current.clone()));

    for _ in 0..MAX_PARENT_CHAIN {
        let owned_xml;
        let xml = if first {
            first = false;
            root_pom_xml
        } else {
            owned_xml = rv_config::read_project_input_string(&current)?;
            &owned_xml
        };
        let Ok(pom) = Pom::parse(xml) else {
            break;
        };
        let Some(parent) = pom.parent.as_ref() else {
            break;
        };
        // Maven defaults relativePath to `../pom.xml`; an explicit empty value
        // disables the local lookup entirely.
        let rel = match parent.relative_path.as_deref() {
            Some("") => break,
            Some(rel) => rel,
            None => "../pom.xml",
        };
        let base = current.parent().unwrap_or_else(|| Path::new("."));
        let mut candidate = base.join(rel);
        // A relativePath pointing at a directory means `<dir>/pom.xml`.
        if candidate.is_dir() {
            candidate = candidate.join("pom.xml");
        }
        if !candidate.is_file() {
            break;
        }
        let canonical = candidate
            .canonicalize()
            .unwrap_or_else(|_| candidate.clone());
        if !seen.insert(canonical) {
            // Cycle (e.g. relativePath pointing back at a visited POM); stop.
            break;
        }
        chain.push(candidate.clone());
        current = candidate;
    }

    Ok(chain)
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
        for pkg in &platform.packages {
            seen.insert((
                pkg.group_id.clone(),
                pkg.artifact_id.clone(),
                pkg.version.clone(),
                pkg.packaging.clone(),
                pkg.classifier.clone(),
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
    // hash checks, diff renderers, etc.) keep their existing inputs.
    filtered.config_hash = lock.config_hash.clone();
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
/// `snapshot_timestamp` for SNAPSHOT refreshes). Compare only the
/// resolved dependency set + edges so `--frozen` rejects real graph
/// drift without false-positiving on those mutable fields.
///
/// #34: this helper is reached only after a TTL-triggered SNAPSHOT refresh, so
/// it must not treat a freshly-published upstream snapshot as drift. For a
/// `-SNAPSHOT` package the content (checksum) advancing is the *expected*
/// outcome of a refresh; the graph shape (coordinate, packaging, repo, edges)
/// is what `--frozen` guards. The checksum comparison is therefore skipped for
/// snapshot packages while staying strict for release pins, where any
/// checksum change is genuine drift the lockfile must reject.
fn lock_resolution_matches(a: &Lockfile, b: &Lockfile) -> bool {
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
        if lhs.platform != rhs.platform || lhs.edges != rhs.edges {
            return false;
        }
        if lhs.packages.len() != rhs.packages.len() {
            return false;
        }
        for (l, r) in lhs.packages.iter().zip(rhs.packages.iter()) {
            if l.group_id != r.group_id
                || l.artifact_id != r.artifact_id
                || l.version != r.version
                || l.packaging != r.packaging
                || l.classifier != r.classifier
                || l.repo_url != r.repo_url
                || l.system_path != r.system_path
                || l.direct_scope != r.direct_scope
            {
                return false;
            }
            if checksum_drifted(l, r) {
                return false;
            }
        }
    }
    true
}

/// True when two pins for the same coordinate disagree on checksum in a way
/// `--frozen` treats as drift.
///
/// A SNAPSHOT's bytes legitimately advance when its update-policy TTL
/// elapses, so snapshots never drift on checksum alone. For release pins the
/// digests are compared only when both sides use the same algorithm: a
/// lockfile carrying a sha1 fallback pin (written when the repository
/// publishes no sha256 sidecar) cannot be compared digest-for-digest against
/// a freshly resolved sha256 pin, so a mixed-algorithm pair is inconclusive
/// rather than a mismatch. The coordinate and version checks still apply.
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
        .flat_map(|platform| platform.packages.iter())
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

async fn resolve_lock(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    platforms: &[Platform],
    pom_path: &Path,
    strategy: ResolutionStrategy,
    strict_parents: bool,
) -> Result<Lockfile> {
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
            let ctx = ResolveContext::from_config_with_state(
                config.clone(),
                store.clone(),
                platform.clone(),
                Some(client.clone()),
                Arc::clone(&shared_state),
            );
            let resolver = Resolver::with_strategy(ctx, strategy).with_strict(strict_parents);
            let root_spec = RootSpec(pom_path.to_path_buf());
            async move { resolver.resolve(root_spec).await }
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
    // Support POM "g:a:v" -> serving repo id (a parent/BOM can come from a
    // different repo than its child).
    let mut support_repo_ids: BTreeMap<String, String> = BTreeMap::new();
    for result in resolved {
        for (url, id) in result.repositories {
            repo_ids.insert(url, id);
        }
        for (coord, id) in result.support_repo_ids {
            support_repo_ids.insert(coord, id);
        }
        lock.platforms.push(LockPlatform {
            platform: result.platform,
            packages: result.packages,
            edges: result.edges,
            extra: BTreeMap::new(),
        });
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
    if !support_repo_ids.is_empty() {
        let encoded = support_repo_ids
            .iter()
            .map(|(coord, id)| format!("{coord}\t{id}"))
            .collect::<Vec<_>>()
            .join("\n");
        lock.metadata
            .insert(LOCK_SUPPORT_REPO_IDS_KEY.to_string(), encoded);
    }

    Ok(lock)
}

/// Carry forward lockfile data a fresh resolve does not regenerate.
///
/// Unknown top-level fields (`extra`) and metadata keys rv does not own
/// round-trip read-to-write, but a resolve builds a new Lockfile from
/// scratch; without this step every successful sync would strip data a
/// future rv version or an external tool recorded. When platforms were
/// preserved from the previous lockfile, the rv-owned repo-id provenance
/// entries are merged line-wise as well: the preserved platforms' packages
/// stay in the lockfile, so dropping their `url\tid` / `g:a:v\tid` lines
/// would make `rv export-m2` mislabel their `_remote.repositories` markers
/// as `central`.
fn carry_forward_lock_data(lock: &mut Lockfile, previous: &Lockfile, preserved_platforms: bool) {
    if lock.extra.is_empty() && !previous.extra.is_empty() {
        lock.extra = previous.extra.clone();
    }
    for (key, value) in &previous.metadata {
        if key != LOCK_REPO_IDS_KEY && key != LOCK_SUPPORT_REPO_IDS_KEY {
            lock.metadata
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
    if !preserved_platforms {
        return;
    }
    for key in [LOCK_REPO_IDS_KEY, LOCK_SUPPORT_REPO_IDS_KEY] {
        let Some(prev_encoded) = previous.metadata.get(key) else {
            continue;
        };
        let merged = merge_id_lines(prev_encoded, lock.metadata.get(key).map(String::as_str));
        if !merged.is_empty() {
            lock.metadata.insert(key.to_string(), merged);
        }
    }
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

/// Lockfile `[metadata]` key under which `rv sync` records `g:a:v\tid` lines
/// giving the serving repository id for each support POM (parent / imported
/// BOM), so `rv export-m2` labels their markers with the right id even when a
/// parent/BOM resolves from a different repository than its child.
pub(crate) const LOCK_SUPPORT_REPO_IDS_KEY: &str = "support_repo_ids";

async fn ensure_artifacts(
    lock: &Lockfile,
    config: &Config,
    store: &Store,
    client: &RepoClient,
    platforms: &[Platform],
) -> Result<()> {
    let total: usize = lock.platforms.iter().map(|p| p.packages.len()).sum();
    // No local ProgressBar here: the configured `ProgressReporter` is
    // already wired through `RepoClient::with_progress` and runs per
    // chunk, which is what users actually see during a sync. A post-hoc
    // `pb.set_position` call would run only after every download had
    // already completed, producing no animation.

    tracing::debug!(total_artifacts = total, "downloading artifacts");
    let results = rv_repo::sync::ensure_artifacts(client, store, lock, config, platforms).await?;

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
                expected, actual, ..
            } = err
            {
                // Render the coordinate (already in `result.package`) and the
                // two hashes verbatim. A CAS path like `sha256/ab/cd/...`
                // gives the user no signal about which lockfile pin is wrong,
                // so it stays out of the message.
                checksum_failure_lines.push(format!(
                    "{}: expected {} {}, got {}",
                    result.package,
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

/// Reject reactor POMs with declared modules before resolution starts.
fn reject_multi_module_pom(path: &Path) -> Result<()> {
    let xml = rv_config::read_project_input_string(path)?;
    let pom = Pom::parse(&xml).map_err(|err| {
        CliError::Message(format!("invalid pom.xml at {}: {err}", path.display()))
    })?;
    if pom.modules.iter().any(|m| !m.trim().is_empty()) {
        return Err(CliError::MultiModuleNotSupported {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LOCK_REPO_IDS_KEY, LOCK_SUPPORT_REPO_IDS_KEY, StrategyArg, SyncArgs,
        carry_forward_lock_data, check_frozen_config_hash, compute_config_hash,
        digest_algorithm_name, elapsed_saturating, filter_lock, format_checksum_failure_details,
        lock_resolution_matches, require_lock_for_platforms,
    };
    use crate::error::CliError;
    use clap::Parser;
    use rv_config::{LockPackage, LockPlatform, Lockfile, Platform};
    use rv_resolver::ResolutionStrategy;
    use std::time::{Duration, Instant};

    fn empty_platform(os: &str, arch: &str) -> LockPlatform {
        LockPlatform {
            platform: Platform::new(os, arch).expect("platform"),
            packages: Vec::new(),
            edges: Vec::new(),
            extra: std::collections::BTreeMap::new(),
        }
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
            LOCK_SUPPORT_REPO_IDS_KEY.to_string(),
            "g:a:1.0\tcorp".to_string(),
        );

        let mut lock = Lockfile::new();
        lock.metadata.insert(
            LOCK_REPO_IDS_KEY.to_string(),
            "https://shared.example/\tfresh-id".to_string(),
        );

        carry_forward_lock_data(&mut lock, &previous, true);

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
            lock.metadata
                .get(LOCK_SUPPORT_REPO_IDS_KEY)
                .map(String::as_str),
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

        carry_forward_lock_data(&mut lock, &previous, false);

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
        linux.packages.push(package("com.example", "lib", "1.0"));
        previous.platforms.push(linux);
        let mut darwin = empty_platform("darwin", "aarch64");
        darwin.packages.push(package("com.example", "lib", "1.0"));
        previous.platforms.push(darwin);

        // Simulate `rv sync --platforms linux-x86_64`: the in-memory
        // lockfile holds only the requested platform.
        let mut fresh = Lockfile::new();
        let mut linux_new = empty_platform("linux", "x86_64");
        linux_new
            .packages
            .push(package("com.example", "lib", "2.0"));
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
            linux_entry.packages[0].version, "2.0",
            "linux platform must carry the freshly resolved version"
        );
        let darwin_entry = fresh
            .platforms
            .iter()
            .find(|p| p.platform.to_string() == "darwin-aarch64")
            .expect("darwin entry preserved");
        assert_eq!(
            darwin_entry.packages[0].version, "1.0",
            "un-resolved platform must keep its previous pin"
        );
    }

    /// `--frozen` must not flag a graph as drifted just because the
    /// on-disk lockfile carries a `config_hash`, fresh metadata, or an
    /// updated snapshot timestamp that the in-memory re-resolution
    /// hasn't stamped in. The semantic helper compares only the
    /// dependency content + edges.
    ///
    /// #26: uses a realistic timestamped snapshot (`1.0-SNAPSHOT` resolved to
    /// `1.0-20240101.010101-7`) rather than a bare base `-SNAPSHOT`, so the
    /// test exercises the same shape `rv sync` actually writes.
    #[test]
    fn lock_resolution_matches_ignores_mutable_metadata() {
        use rv_config::Checksum;

        let mut selected = Lockfile::new();
        let mut platform = empty_platform("linux", "x86_64");
        let mut pkg = package("com.example", "demo", "1.0-SNAPSHOT");
        // A realistic refreshed-snapshot pin: timestamped resolution + the
        // sha256 of the bytes that were current when the lockfile was written.
        pkg.snapshot_timestamp = Some("20240101.010101-7".to_string());
        pkg.checksum = Some(Checksum::new("sha256", "a".repeat(64)));
        platform.packages.push(pkg);
        selected.platforms.push(platform);
        selected.config_hash = Some("abc123".to_string());
        selected
            .metadata
            .insert("written_at".to_string(), "yesterday".to_string());

        // The re-resolution carries a newer snapshot timestamp AND new bytes
        // (a freshly published upstream snapshot), but the same base version.
        let mut resolved = Lockfile::new();
        let mut platform = empty_platform("linux", "x86_64");
        let mut refreshed = package("com.example", "demo", "1.0-SNAPSHOT");
        refreshed.snapshot_timestamp = Some("20240202.020202-9".to_string());
        refreshed.checksum = Some(Checksum::new("sha256", "b".repeat(64)));
        platform.packages.push(refreshed);
        resolved.platforms.push(platform);

        assert!(
            lock_resolution_matches(&selected, &resolved),
            "a refreshed snapshot (new timestamp + new checksum, same base version) \
             must not register as graph drift"
        );

        let mut drifted = resolved.clone();
        drifted.platforms[0].packages[0].version = "2.0-SNAPSHOT".to_string();
        assert!(
            !lock_resolution_matches(&selected, &drifted),
            "a real version change must surface as drift"
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
        p_old.packages.push(snap_old);
        old.platforms.push(p_old);

        let mut new = Lockfile::new();
        let mut p_new = empty_platform("linux", "x86_64");
        let mut snap_new = package("com.example", "demo", "1.0-SNAPSHOT");
        snap_new.checksum = Some(Checksum::new("sha256", "c".repeat(64)));
        p_new.packages.push(snap_new);
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
        p_old.packages.push(rel_old);
        old.platforms.push(p_old);

        let mut new = Lockfile::new();
        let mut p_new = empty_platform("linux", "x86_64");
        let mut rel_new = package("com.example", "demo", "1.0");
        rel_new.checksum = Some(Checksum::new("sha256", "d".repeat(64)));
        p_new.packages.push(rel_new);
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
        linux.packages.push(package("com.example", "lib", "1.0"));
        let mut darwin = empty_platform("darwin", "aarch64");
        darwin.packages.push(package("com.example", "lib", "1.0"));
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
        p_old.packages.push(rel_old);
        old.platforms.push(p_old);

        let mut new = Lockfile::new();
        let mut p_new = empty_platform("linux", "x86_64");
        let mut rel_new = package("com.example", "demo", "1.0");
        rel_new.checksum = Some(Checksum::new("sha256", "b".repeat(64)));
        p_new.packages.push(rel_new);
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
        p_old.packages.push(package("com.example", "demo", "1.0"));
        old.platforms.push(p_old);

        let mut new = Lockfile::new();
        let mut p_new = empty_platform("linux", "x86_64");
        let mut rel_new = package("com.example", "demo", "1.0");
        rel_new.checksum = Some(Checksum::new("sha256", "b".repeat(64)));
        p_new.packages.push(rel_new);
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
        platform_old
            .packages
            .push(package("com.example", "lib", "1.0"));
        platform_old
            .packages
            .push(package("com.example", "other", "2.0"));
        old.platforms.push(platform_old);

        let mut new = Lockfile::new();
        let mut platform_new = empty_platform("linux", "x86_64");
        // lib bumped; other removed; new-dep added
        platform_new
            .packages
            .push(package("com.example", "lib", "1.1"));
        platform_new
            .packages
            .push(package("com.example", "new-dep", "3.0"));
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
        platform_old.packages.push(pkg_old);
        old.platforms.push(platform_old);

        let mut new = Lockfile::new();
        let mut platform_new = empty_platform("linux", "x86_64");
        let mut pkg_new = package("com.example", "lib", "1.0");
        pkg_new.checksum = Some(Checksum::new("sha256", "b".repeat(64)));
        platform_new.packages.push(pkg_new);
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
            platform_old
                .packages
                .push(package("com.example", &format!("dep{i}"), "1.0"));
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
        platform.packages.push(package("com.example", "lib", "1.0"));
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
        let chain = super::local_parent_chain(&child_pom, &child_xml).expect("local parent chain");
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
