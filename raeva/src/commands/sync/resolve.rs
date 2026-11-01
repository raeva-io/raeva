use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use rv_config::Config;
use rv_lock::{Lockfile, Platform};
use rv_maven_model::HostInput;
use rv_repo::{RepoClient, Repository};
use rv_resolver::Resolver;
use rv_resolver::lock::{AssembleError, AssembledLock, PlatformModel};
use rv_store::Store;

use crate::commands::lock_inputs::{ReactorModel, declared_repository_urls, model_change_note};
use crate::error::{CliError, Result};
use crate::output::Output;

/// Refuse a project in which two repository URLs, from configuration or from
/// `urls`, name different directories that raeva.lock would record as the same
/// `./dir/` origin: a later run could not tell which directory resolution
/// read.
pub(super) fn check_origin_aliases(
    config: &Config,
    urls: impl IntoIterator<Item = String>,
) -> Result<()> {
    // Mirrors are endpoints, never recorded origins, so they cannot alias.
    let configured = config.repositories().iter().map(|repo| repo.url.clone());
    let urls: Vec<String> = configured.chain(urls).collect();
    match rv_lock::LockOrigins::for_root(&config.project_root)
        .alias(urls.iter().map(String::as_str))
    {
        None => Ok(()),
        Some(alias) => Err(CliError::RepositoryOriginAlias {
            origin: alias.origin,
            first: rv_lock::redact_origin(&alias.first),
            second: rv_lock::redact_origin(&alias.second),
        }),
    }
}

pub(super) async fn resolve_reactor_lock(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    platforms: &[Platform],
    models: &[ReactorModel],
) -> Result<ResolvedReactorLock> {
    // Platforms resolve concurrently. They share only the parsed-POM cache,
    // keyed by the POM's bytes; every module on every platform gets its own
    // metadata, project and missing-parent caches.
    let resolver = Resolver::new(Arc::new(config.clone()), store, client)
        .with_stall_timeout(workspace_stall_timeout());
    let futures: Vec<_> = platforms
        .iter()
        .map(|platform| {
            let model = super::model_for(models, platform).clone();
            let resolver = &resolver;
            async move {
                let resolution = resolver
                    .resolve_workspace(&model.workspace, platform)
                    .await?;
                Ok::<_, rv_resolver::ResolveError>((model, resolution))
            }
        })
        .collect();

    // Every platform runs to the end, so the warnings do not depend on which
    // one fails first, and the error reported is the first in platform
    // order.
    let resolved = futures::future::join_all(futures).await;
    // Freeing the parsed POMs takes a while and nothing waits for it.
    drop(std::thread::Builder::new().spawn(move || drop(resolver)));
    let resolved = resolved
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (models_resolved, resolutions): (Vec<ReactorModel>, Vec<_>) = resolved.into_iter().unzip();
    let platform_repositories = resolutions
        .iter()
        .map(|resolution| {
            (
                resolution.platform.clone(),
                resolution
                    .modules
                    .iter()
                    .flat_map(|module| module.resolution.trusted_repositories.iter().cloned())
                    .collect(),
            )
        })
        .collect();
    let resolutions = models_resolved
        .iter()
        .map(|model| PlatformModel {
            active_profiles: &model.active_profiles,
            pom_hashes: &model.pom_hashes,
            whole_reactor_pom_hashes: &model.whole_reactor_pom_hashes,
        })
        .zip(resolutions)
        .collect();
    let AssembledLock {
        mut lock,
        trusted_repositories,
        platform_reads,
        ..
    } = rv_resolver::lock::assemble(config, resolutions).map_err(|err| match err {
        AssembleError::Resolve(err) => CliError::Resolve(*err),
        AssembleError::Lock(err) => CliError::Lock(err),
        AssembleError::SystemFile { path, reason } => {
            CliError::InvalidProjectInput { path, reason }
        }
    })?;
    check_origin_aliases(
        config,
        declared_repository_urls(config, models)
            .chain(trusted_repositories.iter().map(|repo| repo.url.clone()))
            .chain(lock.repo_ids.keys().cloned()),
    )?;
    // The spelling raeva.lock records, so the frozen comparison, the diff and
    // the carry-forward of an earlier lock all compare like with like.
    lock.relativize_origins(&rv_lock::LockOrigins::for_root(&config.project_root))?;

    Ok(ResolvedReactorLock {
        lock,
        trusted_repositories,
        platform_repositories,
        reads: PlatformReads(platform_reads),
    })
}

pub(crate) struct ResolvedReactorLock {
    pub(super) lock: Lockfile,
    pub(super) trusted_repositories: Vec<Repository>,
    platform_repositories: Vec<(Platform, Vec<Repository>)>,
    pub(super) reads: PlatformReads,
}

/// When a run resolved several platforms, what each one's builds read.
pub(crate) struct PlatformReads(pub(super) Vec<(Platform, Vec<BTreeSet<HostInput>>)>);

impl ResolvedReactorLock {
    pub(super) fn repositories_for(&self, platform: &Platform) -> &[Repository] {
        self.platform_repositories
            .iter()
            .find(|(resolved, _)| resolved == platform)
            .map_or(&[], |(_, repositories)| repositories)
    }
}

/// How many of the files `lock` pins for `platforms` the store lacks, and
/// how many it pins, counting a stored file only where one of `trusted`,
/// the configuration or the row's origin served it. When the store holds a
/// file's bytes from another repository and `resolve` holds models, first
/// adds to `trusted` the repositories a resolution of them trusts, a remote
/// parent's included: a restore that fell back to one keeps the configured
/// origin. A resolution that fails adds none.
pub(crate) async fn count_stored(
    config: &Config,
    store: Arc<Store>,
    client: &RepoClient,
    lock: &Lockfile,
    platforms: &[Platform],
    trusted: &mut Vec<Repository>,
    resolve: Option<&[ReactorModel]>,
) -> Result<(usize, usize)> {
    let configs: Vec<_> = (platforms.iter())
        .map(|platform| config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]))
        .collect();
    let count = async |trusted: &[Repository]| {
        let contexts: Vec<_> = (configs.iter().zip(platforms))
            .map(|(config, platform)| rv_repo::RestoreContext {
                config,
                client,
                platforms: std::slice::from_ref(platform),
                trusted_repositories: trusted,
            })
            .collect();
        rv_repo::count_missing(&store, lock, &contexts).await
    };
    let (missing, unserved, files) = count(trusted).await?;
    let Some(models) = resolve.filter(|_| unserved > 0) else {
        return Ok((missing, files));
    };
    let platforms: Vec<_> = models.iter().map(|model| model.platform.clone()).collect();
    let resolved =
        resolve_reactor_lock(config, store.clone(), client.clone(), &platforms, models).await;
    let Ok(resolved) = resolved else {
        return Ok((missing, files));
    };
    trusted.extend(resolved.trusted_repositories);
    let (missing, _, files) = count(trusted).await?;
    Ok((missing, files))
}

/// Resolve current models and validate the result without rewriting the lock.
/// Both frozen sync and freshness checks use this gate. Platforms left out
/// follow plain sync's preservation rules, so one it would drop is drift.
/// Returns the fresh resolution, which names the reactor's current versions,
/// and the repositories it trusted, a remote parent's included.
pub(crate) async fn validate_frozen_resolution(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    lock: &Lockfile,
    models: &[ReactorModel],
    output: &Output,
) -> Result<(Lockfile, Vec<Repository>)> {
    let platforms: Vec<_> = models.iter().map(|model| model.platform.clone()).collect();
    let mut resolved = resolve_reactor_lock(config, store, client, &platforms, models).await?;
    super::merge::merge_previous(
        config,
        &mut resolved.lock,
        Some(lock),
        models,
        &resolved.reads,
        &resolved.trusted_repositories,
    )?;
    check_resolution(config, lock, &resolved, models, output)?;
    Ok((resolved.lock, resolved.trusted_repositories))
}

/// Compare pins after the caller applied its mode's platform merge rules.
pub(super) fn check_resolution(
    config: &Config,
    lock: &Lockfile,
    resolved: &ResolvedReactorLock,
    models: &[ReactorModel],
    output: &Output,
) -> Result<()> {
    super::download::check_repinned(lock, &resolved.lock)?;
    let origins = rv_lock::LockOrigins::for_root(&config.project_root);
    let selectors: HashMap<_, _> = lock
        .platforms
        .iter()
        .map(|entry| {
            let platform = &entry.platform;
            let config = config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
            (
                platform,
                rv_repo::LockRepositorySelector::new(
                    &config,
                    &origins,
                    resolved.repositories_for(platform),
                ),
            )
        })
        .collect();
    let declared = |platform: &Platform, url: &str| {
        selectors
            .get(platform)
            .expect("recorded platform")
            .select(url, None)
            .declared()
            .is_some()
    };
    if let Some(drift) = lock.resolution_drift(&resolved.lock, declared) {
        let diff = super::diff::format_frozen_diff(lock, &resolved.lock);
        let details = if diff.is_empty() {
            format!("raeva.lock is out of date: resolving again gives other results: {drift}")
        } else {
            format!("raeva.lock is out of date: resolving again changes these entries:\n{diff}")
        };
        return Err(match crate::commands::lock_inputs::jdk_hint(config, lock) {
            Some(hint) => CliError::lockfile_mismatch_with(details, hint),
            None => CliError::lockfile_mismatch(details),
        });
    }
    if let Some(note) = model_change_note(lock, &resolved.lock, models) {
        output.note(&note);
    }
    Ok(())
}

/// Overrides the resolver's stall timeout, in whole seconds. `0` disables
/// the watchdog. An unparseable value keeps the default.
pub(crate) const WORKSPACE_STALL_TIMEOUT_ENV: &str = "RAEVA_WORKSPACE_STALL_TIMEOUT_SECS";

const DEFAULT_WORKSPACE_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

fn workspace_stall_timeout() -> Option<std::time::Duration> {
    let Ok(raw) = std::env::var(WORKSPACE_STALL_TIMEOUT_ENV) else {
        return Some(DEFAULT_WORKSPACE_STALL_TIMEOUT);
    };
    match raw.trim().parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(std::time::Duration::from_secs(secs)),
        Err(_) => {
            tracing::warn!(
                sec_code = "SETTING_IGNORED",
                env = WORKSPACE_STALL_TIMEOUT_ENV,
                value = %raw,
                "ignoring unparseable stall timeout; using the default"
            );
            Some(DEFAULT_WORKSPACE_STALL_TIMEOUT)
        }
    }
}
