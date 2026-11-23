use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::StreamExt;

use rv_config::Config;
use rv_lock::{Lockfile, Platform};
use rv_maven_model::HostInput;
use rv_repo::{RepoClient, Repository};
use rv_resolver::lock::{AssembleError, AssembledLock, PlatformModel};
use rv_resolver::{Resolver, RootRepositories};
use rv_store::Store;

use super::download::check_repinned;
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

/// A lock whose inputs are unchanged, whose versions chosen for ranges,
/// `LATEST` and `RELEASE` a resolution keeps
/// ([`Resolver::with_locked_versions`]), and whether that left out a listed
/// version.
pub(super) struct Replay<'a> {
    lock: &'a Lockfile,
    applied: AtomicBool,
}

impl Replay<'_> {
    fn applied(&self) -> bool {
        self.applied.load(Ordering::Relaxed)
    }
}

pub(super) async fn resolve_reactor_lock(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    platforms: &[Platform],
    models: &[ReactorModel],
    replay: Option<&Replay<'_>>,
    observer: Option<RootRepositories>,
) -> Result<ResolvedReactorLock> {
    // Platforms resolve concurrently. They share only the parsed-POM cache,
    // keyed by the POM's bytes; every module on every platform gets its own
    // metadata, project and missing-parent caches.
    let mut resolver = Resolver::new(Arc::new(config.clone()), store, client)
        .with_stall_timeout(workspace_stall_timeout())
        .observing_root_repositories(observer);
    if let Some(replay) = replay {
        resolver = resolver.with_locked_versions(replay.lock);
    }
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
    if let Some(replay) = replay {
        (replay.applied).store(resolver.replayed_locked_versions(), Ordering::Relaxed);
    }
    // Freeing the parsed POMs takes a while and nothing waits for it.
    drop(std::thread::Builder::new().spawn(move || drop(resolver)));
    let resolved = resolved
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (models_resolved, resolutions): (Vec<ReactorModel>, Vec<_>) = resolved.into_iter().unzip();
    let platform_repositories = resolutions
        .iter()
        .map(|resolution| {
            let modules = resolution.modules.iter().map(|module| &module.resolution);
            PlatformRepositories {
                platform: resolution.platform.clone(),
                trusted: (modules.clone())
                    .flat_map(|module| module.trusted_repositories.iter().cloned())
                    .collect(),
                imports: modules
                    .flat_map(|module| module.import_repositories.iter().cloned())
                    .collect(),
            }
        })
        .collect();
    let pom_reads = (resolutions.iter())
        .map(|resolution| {
            let modules = (resolution.modules.iter())
                .map(|module| (module.pom_path.clone(), module.resolution.pom_reads.clone()));
            (resolution.platform.clone(), modules.collect())
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
    let origins = rv_lock::LockOrigins::for_root(&config.project_root);
    lock.relativize_origins(&origins)?;
    let platforms = lock.platforms.iter();
    let file_origins = (platforms.clone().flat_map(|platform| &platform.artifacts))
        .flat_map(|artifact| artifact.origins());
    let pom_origins = (platforms
        .clone()
        .flat_map(|platform| platform.support_poms.values()))
    .map(|pin| pin.repo_url.as_str());
    let range_origins = platforms.flat_map(rv_lock::LockPlatform::range_origins);
    if (file_origins.chain(pom_origins).chain(range_origins)).any(str::is_empty)
        && let Some(refusal) = empty_origin_refusal(
            &rv_repo::LockRepositorySelector::new(config, &origins, &trusted_repositories)
                .select("", None),
        )
    {
        return Err(CliError::Lock(rv_lock::LockError::UnrecordableOrigin(
            refusal.to_string(),
        )));
    }

    Ok(ResolvedReactorLock {
        lock,
        trusted_repositories,
        platform_repositories,
        reads: PlatformReads(platform_reads),
        pom_reads,
    })
}

pub(crate) struct ResolvedReactorLock {
    pub(super) lock: Lockfile,
    pub(super) trusted_repositories: Vec<Repository>,
    platform_repositories: Vec<PlatformRepositories>,
    pub(super) reads: PlatformReads,
    /// What each platform's modules read of POMs, by module, for the Maven
    /// 3.9 checks of the plugins.
    pub(super) pom_reads: ModulePomReads,
}

/// Each platform's modules' POM reads, by module path.
pub(crate) type ModulePomReads = Vec<(Platform, Vec<(String, rv_lock::PomReads)>)>;

/// The repositories one platform's resolution admitted.
struct PlatformRepositories {
    platform: Platform,
    /// Those it searched for artifacts and support POMs.
    trusted: Vec<Repository>,
    /// Each support POM an imported BOM's build read, with a repository
    /// only imported BOMs declare that the read searched.
    imports: Vec<(String, Repository)>,
}

/// When a run resolved several platforms, what each one's builds read.
pub(crate) struct PlatformReads(pub(super) Vec<(Platform, Vec<BTreeSet<HostInput>>)>);

impl ResolvedReactorLock {
    pub(super) fn repositories_for(&self, platform: &Platform) -> &[Repository] {
        self.platform(platform)
            .map_or(&[], |repositories| &repositories.trusted)
    }

    /// What `platform`'s imported BOMs searched; see
    /// [`PlatformRepositories::imports`].
    fn import_repositories_for(&self, platform: &Platform) -> &[(String, Repository)] {
        self.platform(platform)
            .map_or(&[], |repositories| &repositories.imports)
    }

    fn platform(&self, platform: &Platform) -> Option<&PlatformRepositories> {
        (self.platform_repositories.iter()).find(|repositories| repositories.platform == *platform)
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
    let configs = platform_configs(config, platforms);
    let clients = platform_clients(&configs, client);
    let count = async |trusted: &[Repository]| {
        let contexts = restore_contexts(&configs, platforms, &clients, trusted);
        rv_repo::count_missing(&store, lock, &contexts).await
    };
    let (missing, unserved, files) = count(trusted).await?;
    let Some(models) = resolve.filter(|_| unserved > 0) else {
        return Ok((missing, files));
    };
    let platforms: Vec<_> = models.iter().map(|model| model.platform.clone()).collect();
    let resolved = resolve_reactor_lock(
        config,
        store.clone(),
        client.clone(),
        &platforms,
        models,
        None,
        None,
    )
    .await;
    let Ok(resolved) = resolved else {
        return Ok((missing, files));
    };
    trusted.extend(resolved.trusted_repositories);
    let (missing, _, files) = count(trusted).await?;
    Ok((missing, files))
}

/// Each of `platforms`' own configuration.
pub(crate) fn platform_configs(config: &Config, platforms: &[Platform]) -> Vec<Config> {
    (platforms.iter())
        .map(|platform| config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]))
        .collect()
}

/// A client for each of `configs`, with that platform's filters and
/// credentials.
pub(crate) fn platform_clients(configs: &[Config], client: &RepoClient) -> Vec<RepoClient> {
    (configs.iter())
        .map(|config| client.for_platform(config))
        .collect()
}

/// A restore context for each of `platforms`, whose own configuration and
/// client `configs` and `clients` hold in order, trusting `trusted`.
pub(crate) fn restore_contexts<'a>(
    configs: &'a [Config],
    platforms: &'a [Platform],
    clients: &'a [RepoClient],
    trusted: &'a [Repository],
) -> Vec<rv_repo::RestoreContext<'a>> {
    (configs.iter().zip(clients).zip(platforms))
        .map(|((config, client), platform)| rv_repo::RestoreContext {
            config,
            client,
            platforms: std::slice::from_ref(platform),
            trusted_repositories: trusted,
        })
        .collect()
}

/// The repositories a resolution of `models` trusts, as the frozen check
/// fetches pinned files from them: remote parents' and those dependency
/// POMs declare that the policy admits. Offline the resolution reads every
/// model before any file, so they are here even when it then stops at a
/// file the store holds from no route it admits. The resolution replays
/// `lock`'s version choices, and reports a module's repositories only for
/// a graph of the lock's rows, as a passing frozen check solves: a seed's
/// unpinned rows cannot steer it to a POM that declares others. Beside
/// them, the repositories imported BOMs declare, for the support POMs
/// their builds read through them.
pub(crate) async fn resolution_trust(
    config: &Config,
    store: Arc<Store>,
    client: &RepoClient,
    lock: &Lockfile,
    models: &[ReactorModel],
) -> ResolutionTrust {
    let lock = &*lock.without_plugins();
    let replay = Replay {
        lock,
        applied: AtomicBool::new(false),
    };
    let platforms: Vec<_> = models.iter().map(|model| model.platform.clone()).collect();
    let learned = Arc::new(std::sync::Mutex::new(ResolutionTrust::default()));
    let observer: RootRepositories = Arc::new({
        let learned = Arc::clone(&learned);
        move |_: &Platform, repos: &[Repository], imports: &[(String, Repository)]| {
            let mut learned = learned
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            learned.repositories.extend(repos.iter().cloned());
            learned.imports.extend(imports.iter().cloned());
        }
    });
    // What it learned stands whether or not it finishes.
    let failed = resolve_reactor_lock(
        config,
        store,
        client.clone(),
        &platforms,
        models,
        Some(&replay),
        Some(observer),
    )
    .await
    .err();
    let learned = std::mem::take(
        &mut *learned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    ResolutionTrust { failed, ..learned }
}

/// What [`resolution_trust`] learned.
#[derive(Default)]
pub(crate) struct ResolutionTrust {
    /// The repositories the resolution trusts for every file.
    pub(crate) repositories: Vec<Repository>,
    /// Each support POM an imported BOM's build read, by `g:a:v`, with a
    /// repository only imported BOMs declare that the read searched: the
    /// frozen check takes that POM, and nothing else, from it.
    pub(crate) imports: Vec<(String, Repository)>,
    /// Why the resolution failed, if it did.
    pub(crate) failed: Option<CliError>,
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
    models_match: bool,
    output: &Output,
) -> Result<(Lockfile, Vec<Repository>)> {
    let resolved = recompute(config, store, client, lock, models, models_match, output).await?;
    Ok((resolved.lock, resolved.trusted_repositories))
}

/// [`validate_frozen_resolution`], returning the whole resolution.
///
/// `models_match` says the inputs are unchanged, so the lock's version
/// choices stand as a plain sync would keep them: the resolution replays
/// them, offering a range, `LATEST` or `RELEASE` no version above the one
/// the lock chose. A replay that left out a listed version and fails is
/// resolved again without it, since a version the lock rejected may have
/// been read too, as the highest of a range that lost to a nearer
/// declaration is; the lock passes when either matches. When only the
/// second resolves and the replay found no locked version listed, the lock
/// is out of date: its versions are no longer listed where the resolution
/// reads, as when a mirror lists less than the one the lock was written
/// behind. Otherwise the replay's error stands.
pub(super) async fn recompute(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    lock: &Lockfile,
    models: &[ReactorModel],
    models_match: bool,
    output: &Output,
) -> Result<ResolvedReactorLock> {
    // The plugin tables are checked on their own.
    let lock = &*lock.without_plugins();
    let (_prefetch, observer) =
        super::download::prefetch_pinned(config, &client, &store, lock, models);
    let platforms: Vec<_> = models.iter().map(|model| model.platform.clone()).collect();
    if client.is_offline() {
        seed_support_poms(config, &store, &client, lock, models).await;
    }
    let resolve = async |replay| {
        let mut resolved = resolve_reactor_lock(
            config,
            store.clone(),
            client.clone(),
            &platforms,
            models,
            replay,
            observer.clone(),
        )
        .await?;
        super::merge::merge_previous(
            config,
            &mut resolved.lock,
            Some(lock),
            None,
            models,
            &resolved.reads,
            &resolved.trusted_repositories,
        )?;
        check_repinned(lock, &resolved.lock, &store).await?;
        match drift(config, lock, &resolved) {
            Some(err) => Err(err),
            None => Ok(resolved),
        }
    };
    let replay = models_match.then(|| Replay {
        lock,
        applied: AtomicBool::new(false),
    });
    let resolved = match resolve(replay.as_ref()).await {
        Ok(resolved) => resolved,
        Err(err) if replay.as_ref().is_some_and(Replay::applied) => match resolve(None).await {
            Ok(resolved) => resolved,
            Err(drift @ CliError::LockfileMismatch { .. }) if no_locked_version(&err) => {
                return Err(drift);
            }
            Err(_) => return Err(err),
        },
        Err(err) => return Err(err),
    };
    if let Some(note) = model_change_note(lock, &resolved.lock, models) {
        output.note(&note);
    }
    Ok(resolved)
}

/// Whether a resolution failed because no listed version is one the lock
/// holds: a replay offers a range only versions the lock records.
pub(super) fn no_locked_version(err: &CliError) -> bool {
    let CliError::Resolve(err) = err else {
        return false;
    };
    let err = match err.cause() {
        rv_resolver::ResolveError::Plugin { error, .. } => error.cause(),
        err => err,
    };
    matches!(err, rv_resolver::ResolveError::VersionNotFound { .. })
}

/// Cache the support POMs `lock` pins for the platforms of `models` that
/// the store holds from the repository it records, which the
/// configuration or the models' POMs declare, as a restore does, for an
/// offline resolution to read when the metadata cache lost them. One it
/// cannot cache is left for the resolution to report.
async fn seed_support_poms(
    config: &Config,
    store: &Store,
    client: &RepoClient,
    lock: &Lockfile,
    models: &[ReactorModel],
) {
    let client = client.clone().with_lock_pins(lock).keeping_cached_poms();
    for model in models {
        let platform = &model.platform;
        let Some(entry) = (lock.platforms.iter()).find(|entry| entry.platform == *platform) else {
            continue;
        };
        let declared = (client.policy())
            .admit(
                model.declared_repositories(),
                rv_repo::Declaration::LocalPom,
            )
            .admitted;
        let config = config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
        let client = client.for_platform(&config);
        let context = rv_repo::RestoreContext {
            config: &config,
            client: &client,
            platforms: std::slice::from_ref(platform),
            trusted_repositories: &declared,
        };
        let contexts = std::slice::from_ref(&context);
        let seeded = (entry.support_poms.iter())
            .map(|(coord, pin)| rv_repo::ensure_support_pom(store, contexts, coord, pin));
        futures::stream::iter(seeded)
            .buffer_unordered(config.network.fetch_concurrency())
            .for_each(|_| async {})
            .await;
    }
}

/// The mismatch of `lock` with a resolution merged under its mode's
/// platform rules, if they differ.
fn drift(config: &Config, lock: &Lockfile, resolved: &ResolvedReactorLock) -> Option<CliError> {
    let origins = rv_lock::LockOrigins::for_root(&config.project_root);
    let selectors: HashMap<_, _> = lock
        .platforms
        .iter()
        .map(|entry| {
            let platform = &entry.platform;
            let config = config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
            let trusted = resolved.repositories_for(platform);
            let selector = rv_repo::LockRepositorySelector::new(&config, &origins, trusted);
            (platform, (selector, config))
        })
        .collect();
    let platform = |platform: &Platform| selectors.get(platform).expect("recorded platform");
    let declared =
        |at: &Platform, url: &str| (platform(at).0.select(url, None).declared()).is_some();
    let declared_for_support_poms = |at: &Platform, coord: &str, url: &str| {
        let searched: Vec<_> = (resolved.import_repositories_for(at).iter())
            .filter(|(read, _)| read == coord)
            .map(|(_, repository)| repository.clone())
            .collect();
        !searched.is_empty()
            && (rv_repo::LockRepositorySelector::new(&platform(at).1, &origins, &searched))
                .select(url, None)
                .declared()
                .is_some()
    };
    let drift = lock.resolution_drift(&resolved.lock, declared, declared_for_support_poms)?;
    let diff = super::diff::format_frozen_diff(lock, &resolved.lock);
    let details = if diff.is_empty() {
        format!("raeva.lock is out of date: resolving again gives other results: {drift}")
    } else {
        format!(
            "raeva.lock is out of date: resolving again gives other results: {drift}; these \
             entries change:\n{diff}"
        )
    };
    Some(match crate::commands::lock_inputs::jdk_hint(config, lock) {
        Some(hint) => CliError::lockfile_mismatch_with(details, hint),
        None => CliError::lockfile_mismatch(details),
    })
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

/// Why the lock may not record the empty origin, which stands for the one
/// repository a mirror serves whose URL raeva.lock cannot record, given
/// what that origin selects: with several no run could tell them apart, and
/// with none no run could fetch from it.
fn empty_origin_refusal<T>(selection: &rv_lock::OriginSelection<T>) -> Option<&'static str> {
    match selection {
        rv_lock::OriginSelection::Declared(_) => None,
        rv_lock::OriginSelection::Ambiguous => Some(
            "several repositories whose URLs do not parse or have a scheme raeva cannot \
             fetch are served by mirrors, and raeva.lock records none of their URLs, so it \
             cannot tell which one served a file or listed a version; correct their URLs",
        ),
        rv_lock::OriginSelection::Undeclared => Some(
            "a file or version list came from a repository whose URL raeva.lock cannot \
             record, and no repository with such a URL that a mirror serves is declared, so \
             no run could fetch it again; correct the repository's URL or the mirror that \
             serves it",
        ),
    }
}

#[cfg(test)]
mod empty_origin_tests {
    use rv_lock::OriginSelection;

    /// The refusal names several repositories only when there are several.
    #[test]
    fn the_refusal_counts_the_repositories() {
        assert_eq!(
            super::empty_origin_refusal(&OriginSelection::Declared(())),
            None
        );
        let several = super::empty_origin_refusal::<()>(&OriginSelection::Ambiguous).unwrap();
        assert!(several.starts_with("several repositories"), "{several}");
        let none = super::empty_origin_refusal::<()>(&OriginSelection::Undeclared).unwrap();
        assert!(!none.contains("several"), "{none}");
        assert!(none.contains("no repository with such a URL"), "{none}");
    }
}
