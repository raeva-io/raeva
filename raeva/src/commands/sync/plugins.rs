//! The plugin tables of raeva.lock, resolved and checked when the
//! `[plugins]` table of raeva.toml asks for them.

use std::collections::BTreeSet;
use std::sync::Arc;

use futures::StreamExt;

use rv_config::Config;
use rv_lock::{LockPlatform, Lockfile, Platform, PluginFiles};
use rv_maven_types::Sha256;
use rv_repo::RepoClient;
use rv_resolver::{PluginRequest, Resolver, SetReads};
use rv_store::Store;

use super::resolve::ModulePomReads;
use super::trace::{keyed_jvm_options, traces_hold};
use crate::commands::lock_inputs::ReactorModel;
use crate::error::{CliError, Result};
use crate::output::Output;

/// Whether raeva.lock holds the plugin tables: `plugins.lock` says so.
pub(super) fn wanted(config: &Config) -> bool {
    config.plugins.is_some()
}

/// Refuse, without plugin tables, a build where a repository id names one
/// repository for the dependencies and another for the plugins: Maven 3.9
/// and 3.10 give a module the POM an extension or an earlier module's
/// plugin read under that id, with its dependencies, and only the plugin
/// tables see what those read.
pub(super) fn refuse_split_repository_id(config: &Config, models: &[ReactorModel]) -> Result<()> {
    if wanted(config) {
        return Ok(());
    }
    let Some((id, repository, plugin_repository)) =
        (models.iter()).find_map(|model| model.workspace.split_repository_id(config))
    else {
        return Ok(());
    };
    Err(CliError::InvalidProjectInput {
        path: config.project_root.join("pom.xml"),
        reason: format!(
            "the repository id '{}' names {} for dependencies and {} for plugins: Maven gives a \
             module the POM an extension or plugin read under that id, which raeva sees only \
             with '[plugins] lock = true' in raeva.toml; set that, or give the two \
             repositories ids of their own",
            rv_maven_types::bounded(&id),
            rv_config::redact_url(&repository),
            rv_config::redact_url(&plugin_repository),
        ),
    })
}

/// The goals `[plugins]` names, when it locks the plugins.
fn goals(config: &Config) -> &[String] {
    config
        .plugins
        .as_ref()
        .map_or(&[], |plugins| &plugins.goals)
}

/// `[plugins]` locking the plugins and tracing a build with `arg`.
#[cfg(test)]
pub(super) fn traced(arg: &str) -> rv_config::PluginsConfig {
    let mut trace = rv_config::PluginTrace::default();
    trace.args = vec![arg.to_string()];
    let mut plugins = rv_config::PluginsConfig::default();
    plugins.trace = Some(trace);
    plugins
}

/// Tables raeva.toml does not ask for.
fn unwanted() -> CliError {
    CliError::lockfile_mismatch_with(
        "raeva.lock holds plugin tables, which raeva.toml does not ask for with [plugins] \
         lock = true"
            .to_string(),
        "Run 'raeva sync' and commit raeva.lock",
    )
}

/// `lock` without its plugin tables, which the dependency resolution
/// neither reads nor writes, and the lock as it was when it had any.
pub(super) fn strip(lock: &mut Lockfile) -> Option<Lockfile> {
    match lock.without_plugins() {
        std::borrow::Cow::Borrowed(_) => None,
        std::borrow::Cow::Owned(stripped) => Some(std::mem::replace(lock, stripped)),
    }
}

/// Whether every platform of `lock` that `platforms` names holds plugin
/// tables that stay, with a trace that stays.
pub(super) fn fresh(
    config: &Config,
    policy: &rv_repo::RepositoryPolicy,
    lock: &Lockfile,
    models: &[ReactorModel],
    platforms: &[Platform],
) -> Result<bool> {
    for entry in (lock.platforms.iter()).filter(|entry| platforms.contains(&entry.platform)) {
        let Some(files) = entry.plugin_files() else {
            return Ok(false);
        };
        if !trace_stays(config, &entry.platform, &files.tables, false)?
            || !stays(config, policy, lock, entry, &files, models)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The platforms of `platforms` whose plugin tables in `lock` fail the
/// frozen check, which a sync runs before it keeps the tables of a
/// raeva.lock this home neither wrote nor checked. One that fails, or
/// cannot resolve, is resolved again; the others keep their tables.
pub(super) async fn checked(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    lock: &Lockfile,
    models: &[ReactorModel],
    platforms: &[Platform],
) -> Vec<Platform> {
    let client = client.with_lock_pins(lock);
    let mut failed = Vec::new();
    for entry in (lock.platforms.iter())
        .filter(|entry| platforms.contains(&entry.platform) && entry.plugin_files().is_some())
    {
        let platform = std::slice::from_ref(&entry.platform);
        let (store, client) = (Arc::clone(&store), client.clone());
        if check_resolved(config, store, client, lock, models, platform)
            .await
            .is_err()
        {
            failed.push(entry.platform.clone());
        }
    }
    failed
}

/// Whether a sync may keep `files`, the plugin tables of `entry` in
/// `lock`, without resolving them, as a frozen check would: resolved from
/// the current inputs, naming only repositories the configuration and
/// `models` declare, with rows that record the checksums a resolution
/// writes.
fn stays(
    config: &Config,
    policy: &rv_repo::RepositoryPolicy,
    lock: &Lockfile,
    entry: &LockPlatform,
    files: &PluginFiles,
    models: &[ReactorModel],
) -> Result<bool> {
    let inputs = inputs_digest(
        config,
        goals(config),
        lock,
        entry,
        &files.tables.host_inputs,
    )?;
    let repos = PluginRepositories::new(config, policy, models, &entry.platform, None);
    Ok(files.tables.inputs == inputs
        && repos.undeclared(entry, files).is_none()
        && (files.artifacts.iter()).all(rv_lock::LockArtifact::checksums_as_resolved))
}

/// Whether a sync may keep `platform` of `lock` without resolving it: it
/// holds the plugin tables raeva.toml asks for, resolved from the inputs
/// `lock` records and with the trace raeva.toml names, which `--frozen`
/// checks.
pub(super) fn kept(config: &Config, lock: &Lockfile, platform: &Platform) -> Result<bool> {
    let Some(entry) = (lock.platforms.iter()).find(|entry| entry.platform == *platform) else {
        return Ok(false);
    };
    match entry.plugins.as_ref() {
        _ if !wanted(config) => Ok(true),
        Some(tables) if lock.maven == config.lock.maven.mode => {
            let inputs = inputs_digest(config, goals(config), lock, entry, &tables.host_inputs)?;
            Ok(tables.inputs == inputs && traces_hold(config, tables))
        }
        _ => Ok(false),
    }
}

/// Whether the trace `tables` hold, if any, stays: a current one, or a
/// stale one of this machine's OS and architecture, whose rows pin what the
/// trace that replaces it fetches, unless `update`.
fn trace_stays(
    config: &Config,
    platform: &Platform,
    tables: &rv_lock::PluginTables,
    update: bool,
) -> Result<bool> {
    Ok(traces_hold(config, tables)
        || (config.plugin_trace().is_some()
            && !update
            && platform.os_arch() == Platform::current()?.os_arch()))
}

/// Give each platform of `lock` that `models` resolved plugin tables from
/// the current inputs: `held`'s when they still hold, `client` does not
/// update and their platform is not in `failed`, the platforms whose
/// tables failed the frozen check (checked here when that is not known),
/// else resolved again, and put the files they pin in the store. Another
/// platform keeps `held`'s. `carried` holds the pins of a lock that does
/// not read, whose traces stay as a stale trace of `held` does.
#[allow(clippy::too_many_arguments)]
pub(super) async fn attach(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    lock: &mut Lockfile,
    models: &[ReactorModel],
    held: Option<&Lockfile>,
    carried: Option<&Lockfile>,
    failed: Option<Vec<Platform>>,
    output: &Output,
    pom_reads: Option<&ModulePomReads>,
) -> Result<()> {
    let goals = goals(config);
    let module_reads = |platform: &Platform| {
        (pom_reads.into_iter().flatten())
            .find(|(read, _)| read == platform)
            .map(|(_, modules)| modules.as_slice())
    };
    let update = client.updates();
    // `held`'s tables of a platform stay only once a check of them passed.
    let failed = match (failed, held.filter(|_| !update)) {
        (Some(failed), _) => Some(failed),
        (None, Some(held)) => {
            let platforms: Vec<Platform> =
                models.iter().map(|model| model.platform.clone()).collect();
            let (store, client) = (Arc::clone(&store), client.clone());
            Some(checked(config, store, client, held, models, &platforms).await)
        }
        (None, None) => None,
    };
    let verified =
        |platform: &Platform| (failed.as_ref()).is_some_and(|failed| !failed.contains(platform));
    let resolver = Resolver::new(Arc::new(config.clone()), Arc::clone(&store), client.clone());
    let mut stepped = false;
    let platforms: Vec<Platform> = (lock.platforms.iter())
        .map(|entry| entry.platform.clone())
        .collect();
    let mut resolved: Vec<(Platform, PluginFiles)> = Vec::new();
    for at in 0..lock.platforms.len() {
        let entry = &lock.platforms[at];
        let kept = (held.into_iter())
            .flat_map(|held| &held.platforms)
            .find(|other| other.platform == entry.platform)
            .and_then(LockPlatform::plugin_files);
        let model = models.iter().find(|model| model.platform == entry.platform);
        let mut files = match (kept, model) {
            // A platform kept from `held`, whose tables held there. Every
            // name `held` records has its value still, so the configuration
            // hash differs only by names the platforms resolved here read.
            (Some(mut kept), None) => {
                kept.tables.inputs =
                    inputs_digest(config, goals, lock, entry, &kept.tables.host_inputs)?;
                kept
            }
            (Some(kept), Some(_))
                if !update
                    && verified(&entry.platform)
                    && stays(config, client.policy(), lock, entry, &kept, models)? =>
            {
                kept
            }
            (kept, Some(model)) => {
                if !stepped {
                    output.step("Resolving plugins...");
                    stepped = true;
                }
                let modules = module_reads(&entry.platform);
                let mut files =
                    resolve(config, &resolver, goals, entry, model, lock, modules).await?;
                let fresh = files.clone();
                // A trace stays only from tables a check passed.
                if let Some(kept) = kept.filter(|_| !update && verified(&entry.platform)) {
                    carry_trace(&mut files, kept);
                }
                if let Some(carried) = carried.filter(|_| !update) {
                    carry_traces(&mut files, carried, &entry.platform, &platforms);
                }
                // A trace carried from raeva.lock that names a repository
                // neither the POMs nor this resolution do is dropped, for
                // the next trace to replace.
                let repos = PluginRepositories::new(
                    config,
                    client.policy(),
                    models,
                    &entry.platform,
                    Some(&fresh),
                );
                if repos.undeclared(entry, &files).is_some() {
                    files.retain_sets(|set| set.role != rv_lock::PluginRole::Trace);
                }
                resolved.push((entry.platform.clone(), fresh));
                files
            }
            (None, None) => continue,
        };
        if !trace_stays(config, &entry.platform, &files.tables, update)? {
            files.retain_sets(|set| set.role != rv_lock::PluginRole::Trace);
        }
        lock.platforms[at].set_plugins(files, &lock.repo_ids)?;
    }
    // Kept tables are not resolved again, but the modules' reads still meet
    // the Maven 3.9 refusal of a read without a POM.
    if config.lock.maven.mode == rv_maven_types::MavenMode::Maven39 {
        for (_, modules) in pom_reads.into_iter().flatten() {
            refuse_maven39_reads(modules, &[])?;
        }
    }
    let platforms: Vec<Platform> = models.iter().map(|model| model.platform.clone()).collect();
    fetch(config, store, client, lock, models, &platforms, &resolved).await
}

/// Add the trace `kept` holds to `files`, which a resolution gave.
fn carry_trace(files: &mut PluginFiles, mut kept: PluginFiles) {
    kept.retain_sets(|set| set.role == rv_lock::PluginRole::Trace);
    let mut origins: Vec<String> = Vec::new();
    for artifact in kept.artifacts {
        if !(files.artifacts.iter()).any(|held| held.coordinate == artifact.coordinate) {
            origins.push(artifact.repo_url.clone());
            origins.extend(artifact.other_repo_urls.iter().cloned());
            origins.extend(artifact.pom_repo_urls.iter().cloned());
            files.artifacts.push(artifact);
        }
    }
    for (coordinate, pom) in kept.poms {
        if let std::collections::btree_map::Entry::Vacant(entry) = files.poms.entry(coordinate) {
            origins.push(pom.repo_url.clone());
            entry.insert(pom);
        }
    }
    for (coordinate, read) in kept.tables.shared_origins {
        origins.extend(read.iter().cloned());
        (files.tables.shared_origins.entry(coordinate).or_default()).extend(read);
    }
    for (coordinate, read) in kept.tables.shared_without_pom {
        (files
            .tables
            .shared_without_pom
            .entry(coordinate)
            .or_default())
        .extend(read);
    }
    for origin in origins {
        if let Some(ids) = kept.tables.repo_ids.get(&origin) {
            (files.tables.repo_ids.entry(origin).or_default()).extend(ids.iter().cloned());
        }
    }
    files.tables.sets.extend(kept.tables.sets);
}

/// Add to `files`, resolved for `platform`, the traces that the versions
/// of a lock that does not read, `carried`, hold for it, and for a platform
/// of its OS and architecture the new lock, of `platforms`, leaves out: one
/// trace of `platform` as it is, else one stale trace of all their rows,
/// which the next trace replaces.
fn carry_traces(
    files: &mut PluginFiles,
    carried: &Lockfile,
    platform: &Platform,
    platforms: &[Platform],
) {
    let mut traces: Vec<(bool, PluginFiles)> = Vec::new();
    for version in (carried.platforms.iter()).filter(|version| {
        version.platform == *platform
            || (version.platform.os_arch() == platform.os_arch()
                && !platforms.contains(&version.platform))
    }) {
        if let Some(mut kept) = version.plugin_files() {
            kept.retain_sets(|set| set.role == rv_lock::PluginRole::Trace);
            if !kept.tables.sets.is_empty() {
                traces.push((version.platform == *platform, kept));
            }
        }
    }
    let Some((_, first)) = traces.first() else {
        return;
    };
    let one = |(exact, kept): &(bool, PluginFiles)| *exact && kept.tables.sets == first.tables.sets;
    if first.tables.sets.len() == 1 && traces.iter().all(one) {
        carry_trace(files, first.clone());
        return;
    }
    let mut merged = PluginFiles::new(files.tables.inputs.clone());
    let mut keys = String::from("merged\n");
    let mut set = rv_lock::PluginSet::new("", rv_lock::PluginRole::Trace);
    for (_, kept) in traces {
        for each in kept.tables.sets {
            keys.push_str(&format!("{}\n", each.key));
            set.artifacts.extend(each.artifacts);
            set.poms.extend(each.poms);
        }
        for artifact in kept.artifacts {
            if !(merged.artifacts.iter()).any(|held| held.coordinate == artifact.coordinate) {
                merged.artifacts.push(artifact);
            }
        }
        merged.poms.extend(kept.poms);
        for (coordinate, read) in kept.tables.shared_origins {
            (merged.tables.shared_origins.entry(coordinate).or_default()).extend(read);
        }
        for (coordinate, read) in kept.tables.shared_without_pom {
            (merged
                .tables
                .shared_without_pom
                .entry(coordinate)
                .or_default())
            .extend(read);
        }
        for (origin, ids) in kept.tables.repo_ids {
            merged
                .tables
                .repo_ids
                .entry(origin)
                .or_default()
                .extend(ids);
        }
    }
    // No build's key: the trace is stale wherever it stays.
    set.key = format!("sha256:{}", Sha256::from_bytes(keys.as_bytes()));
    merged.tables.sets.push(set);
    carry_trace(files, merged);
}

/// Refuse what `modules` and `sets` read in the Maven 3.9 mode that the
/// build's order decides: a version a set reads another way than a module
/// or another set, then a file one of them reads without a POM.
fn refuse_maven39_reads(modules: &[(String, rv_lock::PomReads)], sets: &[SetReads]) -> Result<()> {
    let names: Vec<String> = (modules.iter())
        .map(|(path, _)| format!("module {path}"))
        .collect();
    let readers: Vec<rv_lock::PomReader<'_>> = (modules.iter().zip(&names))
        .map(|((_, reads), name)| rv_lock::PomReader {
            name,
            role: None,
            reads,
        })
        .chain(sets.iter().map(|set| rv_lock::PomReader {
            name: &set.name,
            role: Some(set.role),
            reads: &set.poms,
        }))
        .collect();
    if let Some(reads) = rv_lock::read_difference(&readers) {
        return Err(rv_resolver::ResolveError::SharedDescriptorDiffers {
            coord: reads.coord,
            first: reads.first,
            second: reads.second,
        }
        .into());
    }
    match rv_lock::pomless_read(&readers) {
        Some((coord, reader)) => Err(rv_resolver::ResolveError::ReadsNoPom {
            coord: coord.to_string(),
            reader: reader.to_string(),
        }
        .into()),
        None => Ok(()),
    }
}

/// The plugin files of `entry`'s build in `lock`, with what the resolution
/// read from the host and the inputs digest that covers it. `modules` holds
/// what its modules read of POMs, by path, where this run resolved them.
async fn resolve(
    config: &Config,
    resolver: &Resolver,
    goals: &[String],
    entry: &LockPlatform,
    model: &ReactorModel,
    lock: &Lockfile,
    modules: Option<&[(String, rv_lock::PomReads)]>,
) -> Result<PluginFiles> {
    let mut request = PluginRequest::new(goals.to_vec());
    request.test_classpaths = (entry.modules.iter())
        .map(|module| (module.path.clone(), module.clone()))
        .collect();
    let (mut files, reads, sets) = resolver
        .resolve_plugins(
            &model.workspace,
            &entry.platform,
            &request,
            Sha256::from_bytes(b""),
        )
        .await?;
    files.relativize_read_origins(&rv_lock::LockOrigins::for_root(&config.project_root))?;
    let maven39 = config.lock.maven.mode == rv_maven_types::MavenMode::Maven39;
    let split_id = model.workspace.split_repository_id(config).is_some();
    if let Some(reads) = files
        .descriptor_differences(entry, maven39, split_id)
        .into_iter()
        .next()
    {
        let (coord, first, second) = (reads.coord, reads.first, reads.second);
        return Err(match maven39 {
            true => rv_resolver::ResolveError::SharedDescriptorDiffers {
                coord,
                first,
                second,
            },
            false => rv_resolver::ResolveError::OnePomPerVersion {
                coord,
                first,
                second,
            },
        }
        .into());
    }
    if maven39 {
        // Where this run did not resolve the modules, raeva.lock's record of
        // them stands in.
        let recorded;
        let modules = match modules {
            Some(modules) => modules,
            None => {
                recorded = entry.module_pom_reads();
                &recorded
            }
        };
        refuse_maven39_reads(modules, &sets)?;
        let later = (sets.iter()).find_map(|set| Some((set.reactor_later.first()?, &set.name)));
        if let Some((coord, set)) = later {
            return Err(rv_resolver::ResolveError::ReactorModuleUnordered {
                coord: coord.clone(),
                set: set.clone(),
            }
            .into());
        }
    }
    (files.pin_poms_rows_lack(entry, &lock.repo_ids))
        .map_err(|coord| rv_resolver::ResolveError::UnrecordablePluginPom { coord })?;
    let (host_inputs, _) = crate::commands::lock_inputs::recorded_inputs(config, reads, false)?;
    files.tables.inputs = inputs_digest(config, goals, lock, entry, &host_inputs)?;
    files.tables.host_inputs = host_inputs;
    Ok(files)
}

/// Refuse plugin tables raeva.toml does not give, without resolving: tables
/// it does not ask for, none where it asks for them, tables resolved from
/// other inputs, and a trace of another build. `lock` is raeva.lock with its
/// tables, if it has any.
pub(crate) fn check_held(
    config: &Config,
    lock: Option<&Lockfile>,
    platforms: &[Platform],
) -> Result<()> {
    let lock = lock.filter(|lock| lock.platforms.iter().any(|entry| entry.plugins.is_some()));
    if !wanted(config) {
        return lock.map_or(Ok(()), |_| Err(unwanted()));
    }
    let Some(lock) = lock else {
        return Err(stale(
            "raeva.toml sets [plugins] lock = true, but raeva.lock has no plugin tables"
                .to_string(),
        ));
    };
    for entry in (lock.platforms.iter()).filter(|entry| platforms.contains(&entry.platform)) {
        let on = format!("platform '{}'", entry.platform);
        let Some(tables) = entry.plugins.as_ref() else {
            return Err(stale(format!("raeva.lock has no plugin tables for {on}")));
        };
        let inputs = inputs_digest(config, goals(config), lock, entry, &tables.host_inputs)?;
        if tables.inputs != inputs {
            let read = (tables.host_inputs.iter())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            let host = match read.is_empty() {
                true => String::new(),
                false => format!(
                    ", or other values of what they read from this host ({})",
                    read.join(", ")
                ),
            };
            return Err(stale(format!(
                "the plugin tables of {on} were resolved from other inputs, such as other \
                 [plugins] goals in raeva.toml{host}"
            )));
        }
        if !traces_hold(config, tables) {
            return Err(match config.plugin_trace() {
                Some(_) => {
                    let here: Vec<String> = (keyed_jvm_options(config).into_iter())
                        .map(|(name, (_, channel))| format!("-D{name} in {channel}"))
                        .collect();
                    let mut here = match here.is_empty() {
                        true => "none here".to_string(),
                        false => format!("here {}", here.join(", ")),
                    };
                    if let Some(reason) = config.trace_key_unread() {
                        here.push_str(&format!(
                            "; every host-owned -D option is in the key, as raeva cannot read \
                             the project's files: {}",
                            rv_maven_types::bounded(reason)
                        ));
                    }
                    CliError::lockfile_mismatch_with(
                        format!(
                            "raeva.lock holds a trace for {on} of another build than [plugins] \
                             trace and mvn in raeva.toml name with this run's -P and -D \
                             options, active_profiles and inactive_profiles, and the -D options \
                             of MAVEN_OPTS and the JVM option variables ({here})"
                        ),
                        "Give the build the same options where 'raeva sync' traces it and \
                         where --frozen checks it, or move the -D options to .mvn/jvm.config; \
                         if the build changed, run 'raeva sync' and commit raeva.lock",
                    )
                }
                None => stale(format!(
                    "raeva.lock holds a trace for {on}, which raeva.toml does not ask for with \
                     [plugins] trace"
                )),
            });
        }
    }
    Ok(())
}

fn stale(what: String) -> CliError {
    CliError::lockfile_mismatch_with(what, "Run 'raeva sync' and commit raeva.lock")
}

/// `--frozen`: refuse plugin tables [`check_held`] refuses or that a
/// resolution of the same inputs does not give, and a lock without the
/// trace raeva.toml names for this machine, and put the files they pin in
/// the store, each checked against its pin.
pub(crate) async fn check_frozen(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    lock: Option<&Lockfile>,
    models: &[ReactorModel],
    platforms: &[Platform],
) -> Result<()> {
    check_held(config, lock, platforms)?;
    let Some(lock) = lock.filter(|_| wanted(config)) else {
        return Ok(());
    };
    // The plugin rows' pins vouch for the POMs they cache, as the
    // dependencies' do.
    let client = client.with_lock_pins(lock);
    // Offline, a home a plain sync filled lacks what this check reads.
    let offline = client.is_offline();
    let readied = |err| match err {
        CliError::LockfileMismatch { .. } => err,
        _ if offline => CliError::OfflinePlugins(Box::new(err)),
        _ => err,
    };
    let resolved = check_resolved(
        config,
        Arc::clone(&store),
        client.clone(),
        lock,
        models,
        platforms,
    )
    .await
    .map_err(readied)?;
    check_traced(config, lock, platforms)?;
    fetch(config, store, client, lock, models, platforms, &resolved)
        .await
        .map_err(readied)
}

/// Refuse a lock whose `platforms` of this machine's OS and architecture
/// hold no trace of the build `[plugins] trace` names.
pub(crate) fn check_traced(config: &Config, lock: &Lockfile, platforms: &[Platform]) -> Result<()> {
    let host = Platform::current()?.os_arch();
    let here = (lock.platforms.iter())
        .filter(|entry| platforms.contains(&entry.platform) && entry.platform.os_arch() == host);
    if config.plugin_trace().is_some()
        && here.clone().next().is_some()
        && !super::trace::traced_here(config, here)?
    {
        return Err(stale(format!(
            "raeva.lock has no trace for {host} of the build [plugins] trace and mvn in \
             raeva.toml name"
        )));
    }
    Ok(())
}

/// Refuse plugin tables of `lock`'s `platforms`, which [`check_held`]
/// passed, that a resolution of the same inputs does not give. Returns
/// each platform's resolution.
pub(crate) async fn check_resolved(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    lock: &Lockfile,
    models: &[ReactorModel],
    platforms: &[Platform],
) -> Result<Vec<(Platform, PluginFiles)>> {
    if client.is_offline() {
        seed_poms(config, &store, &client, lock, models, platforms).await;
    }
    let goals = goals(config);
    let policy = client.policy().clone();
    let policy = &policy;
    let config_arc = Arc::new(config.clone());
    let uncapped = Resolver::new(Arc::clone(&config_arc), Arc::clone(&store), client.clone());
    // While the inputs match, the tables' version choices stand, as the
    // dependencies' do, and a resolution without them is what a lock they do
    // not replay must match. After a POM edit only that resolution counts.
    let capped = Resolver::new(config_arc, store, client).with_locked_plugin_versions(lock);
    let mut each = Vec::new();
    for entry in (lock.platforms.iter()).filter(|entry| platforms.contains(&entry.platform)) {
        let held = entry
            .plugin_files()
            .expect("check_held refuses a platform without tables");
        let model = super::model_for(models, &entry.platform);
        let check = async |resolver: &Resolver, held_choices: bool| -> Result<PluginFiles> {
            let resolved = resolve(config, resolver, goals, entry, model, lock, None).await?;
            let repos =
                PluginRepositories::new(config, policy, models, &entry.platform, Some(&resolved));
            match plugin_drift(
                entry,
                &held,
                &resolved,
                &lock.repo_ids,
                &repos,
                held_choices,
            ) {
                Some(what) => Err(stale(format!("{what} on platform '{}'", entry.platform))),
                None => Ok(resolved),
            }
        };
        let inputs =
            current_inputs_digest(config, goals, lock, entry, model, &held.tables.host_inputs)?;
        let resolved = if held.tables.inputs != inputs {
            check(&uncapped, false).await?
        } else {
            match check(&capped, true).await {
                Ok(resolved) => resolved,
                // As for the dependencies: when only the unreplayed
                // resolution resolves, the lock is out of date.
                Err(err) if capped.replayed_locked_versions() => {
                    match check(&uncapped, false).await {
                        Ok(resolved) => resolved,
                        Err(drift @ CliError::LockfileMismatch { .. })
                            if super::resolve::no_locked_version(&err) =>
                        {
                            return Err(drift);
                        }
                        Err(_) => return Err(err),
                    }
                }
                Err(err) => return Err(err),
            }
        };
        each.push((entry.platform.clone(), resolved));
    }
    Ok(each)
}

/// Cache the POMs the plugin tables of `lock`'s `platforms` pin that the
/// store holds from a repository they record, as a restore does, for an
/// offline resolution to read when the metadata cache lost them. Only
/// bytes the store says that repository served are cached, so an edited
/// origin caches nothing, and one left out is for the resolution to report.
/// The empty origin is the declaration whose URL the lock cannot record.
async fn seed_poms(
    config: &Config,
    store: &Store,
    client: &RepoClient,
    lock: &Lockfile,
    models: &[ReactorModel],
    platforms: &[Platform],
) {
    let client = client.clone().with_lock_pins(lock).keeping_cached_poms();
    for entry in (lock.platforms.iter()).filter(|entry| platforms.contains(&entry.platform)) {
        let Some(held) = entry.plugin_files() else {
            continue;
        };
        let repos = PluginRepositories::new(config, client.policy(), models, &entry.platform, None);
        for file in held.pinned_files() {
            let Some(sha256) = (file.pin.as_sha256()).filter(|_| file.key.extension() == "pom")
            else {
                continue;
            };
            for repo in (file.origins.iter())
                .filter(|url| url.is_empty())
                .flat_map(|url| repos.known_at(url))
            {
                let _ = rv_repo::cache_pinned_pom(store, &client, repo, &file.key, sha256).await;
            }
            // Each id of the URL may route through its own mirror.
            for url in file.origins.iter().filter(|url| !url.is_empty()) {
                let ids = held.tables.repo_ids.get(*url).into_iter().flatten();
                let ids: Vec<_> = ids.cloned().map(Some).collect();
                for id in if ids.is_empty() { vec![None] } else { ids } {
                    let repo = rv_repo::Repository::new(id, *url, true, true);
                    let _ =
                        rv_repo::cache_pinned_pom(store, &client, &repo, &file.key, sha256).await;
                }
            }
        }
    }
}

/// Put the files the plugin tables of `lock`'s `platforms` pin in the
/// store, each checked against its pin, from the repositories
/// [`PluginRepositories`] gives with the tables of `resolved`, which this
/// run resolved. A file the modules use too is the dependencies' restore's.
pub(super) async fn fetch(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    lock: &Lockfile,
    models: &[ReactorModel],
    platforms: &[Platform],
    resolved: &[(Platform, PluginFiles)],
) -> Result<()> {
    let mut wanted = Vec::new();
    for entry in (lock.platforms.iter()).filter(|entry| platforms.contains(&entry.platform)) {
        let Some(held) = entry.plugin_files() else {
            continue;
        };
        let resolved = (resolved.iter())
            .find(|(platform, _)| *platform == entry.platform)
            .map(|(_, files)| files);
        let repos =
            PluginRepositories::new(config, client.policy(), models, &entry.platform, resolved);
        let used = UsedFiles::of(entry);
        for file in held.pinned_files().filter(|file| !used.holds(file)) {
            let candidates = repos.candidates(
                client.policy(),
                &held.tables.repo_ids,
                &held.tables.sets,
                &file,
            )?;
            wanted.push((file.key, file.pin, candidates));
        }
    }
    // The pins also let an offline resolution read the POMs, as a restore
    // of the dependencies caches theirs.
    let client = client.with_lock_pins(lock);
    let mut fetched = futures::stream::iter(wanted.into_iter().enumerate())
        .map(|(index, (coordinate, pin, candidates))| {
            let (store, client) = (&store, &client);
            async move {
                let fetched = async {
                    let repo = fetch_pinned(store, client, &coordinate, &pin, &candidates).await?;
                    if let Some(sha256) = pin.as_sha256()
                        && coordinate.extension() == "pom"
                    {
                        rv_repo::cache_pinned_pom(store, client, repo, &coordinate, sha256).await?;
                    }
                    Ok::<_, CliError>(())
                };
                (index, fetched.await)
            }
        })
        .buffer_unordered(config.network.fetch_concurrency())
        .collect::<Vec<_>>()
        .await;
    // The first failure in the tables' order, not the first to finish, so
    // the same lock gives the same error and exit code on every run.
    fetched.sort_unstable_by_key(|(index, _)| *index);
    fetched.into_iter().try_for_each(|(_, fetched)| fetched)
}

/// Put `coordinate`, pinned to `pin`, in the store from the first of
/// `candidates` that serves it, the recorded repository first, and return
/// that repository. A file stored intact from one of them is kept, which
/// the export takes from there. As a restore of the dependencies does, the
/// search goes on only past a repository that lacks the file, and only
/// for a SHA-256 pin: other bytes, bytes without their checksum file and a
/// failing server end it.
async fn fetch_pinned<'r>(
    store: &Store,
    client: &RepoClient,
    coordinate: &rv_maven_types::ArtifactCoord,
    pin: &rv_maven_types::Digest,
    candidates: &'r [rv_repo::Repository],
) -> Result<&'r rv_repo::Repository> {
    if let Some(sha256) = pin.as_sha256() {
        let served = store.served_by(coordinate, sha256).await?;
        // The store names a repository whose URL the lock cannot record
        // by its stand-in.
        let stored = (candidates.iter()).find(|repo| {
            let stored = rv_config::stored_repository(&repo.url);
            (served.iter()).any(|(url, _)| same_repository(url, stored))
        });
        if let Some(repo) = stored
            && (store.verify_blobs(std::slice::from_ref(sha256), 1).await?).contains(sha256)
        {
            return Ok(repo);
        }
    }
    let request = rv_repo::ArtifactRequest::from(coordinate);
    let mut first = None;
    for repo in candidates {
        let options = rv_repo::FetchArtifact {
            pin: Some(pin),
            index: Some(coordinate),
        };
        match client.fetch_artifact(repo, &request, store, options).await {
            Ok(_) => return Ok(repo),
            Err(
                err @ (rv_repo::RepoError::ChecksumMismatch { .. }
                | rv_repo::RepoError::MissingChecksum(_)),
            ) => return Err(err.into()),
            Err(err) if err.is_transient() || matches!(err.status_code(), Some(500..=599)) => {
                return Err(err.into());
            }
            Err(err) => {
                first.get_or_insert(err);
            }
        }
    }
    Err(first.map_or_else(
        || CliError::Internal(format!("no repository to fetch {coordinate} from")),
        CliError::from,
    ))
}

/// How `held`'s sets, other than a trace, and the files they pin and the
/// repositories that serve them differ from `resolved`'s, if they do. A row
/// the modules of `entry` read too keeps the origins their check covers;
/// `row_ids` are the ids of the rows' origins. A mirror that serves several
/// repositories answers for the first one searched, so a release file
/// whose SHA-256 pin agrees may be recorded under other repositories with
/// and without it, as a dependency row may, while `repos` declares each
/// origin `held` records for it. `capped` says the resolution held the
/// version choices of `held`, as a frozen check of unchanged inputs does.
fn plugin_drift(
    entry: &LockPlatform,
    held: &PluginFiles,
    resolved: &PluginFiles,
    row_ids: &rv_lock::RepoIds,
    repos: &PluginRepositories<'_>,
    capped: bool,
) -> Option<String> {
    let sets: Vec<_> = (held.tables.sets.iter())
        .filter(|set| set.role != rv_lock::PluginRole::Trace)
        .collect();
    let mut fresh = resolved.tables.clone();
    fresh
        .sets
        .sort_by(|a, b| (&a.key, &a.role).cmp(&(&b.key, &b.role)));
    if sets.len() != fresh.sets.len() || sets.iter().zip(&fresh.sets).any(|(a, b)| *a != b) {
        let names = |sets: &mut dyn Iterator<Item = &rv_lock::PluginSet>| {
            sets.flat_map(|set| set.coordinates.iter().cloned())
                .collect::<std::collections::BTreeSet<_>>()
        };
        let before = names(&mut sets.iter().copied());
        let after = names(&mut fresh.sets.iter());
        let changed: Vec<_> = before.symmetric_difference(&after).cloned().collect();
        return Some(match changed.is_empty() {
            true => "the plugin sets differ from a resolution of the same inputs".to_string(),
            false => format!(
                "the plugin sets differ from a resolution of the same inputs ({})",
                changed.join(", ")
            ),
        });
    }
    // A frozen check holds a plugin without a version at the version the
    // lock took and skips the newer ones, whose `requiredJavaVersion` the
    // sync may have read the JDK for. Held at the lock's choices, it also
    // skips what their POMs read, such as a parent's profile activated by
    // a property; `check_held` covers the values of all the tables list.
    let held_back = (held.tables.metadata_versions.iter())
        .any(|read| read.kind == rv_lock::MetadataVersionKind::Release);
    let skipped = |input: &rv_lock::AmbientInput| {
        held_back && (capped || *input == rv_lock::AmbientInput::JavaVersion)
    };
    if !fresh.host_inputs.is_subset(&held.tables.host_inputs)
        || !(held.tables.host_inputs.difference(&fresh.host_inputs)).all(skipped)
    {
        return Some(
            "the host inputs the plugin tables list differ from a resolution of the same inputs"
                .to_string(),
        );
    }
    // A prefix the lock records from another repository than the
    // resolution's still serves from a declared one each set of its plugin
    // searches, as the modules that build with it do.
    let prefixes = |all: &[rv_lock::PluginPrefix]| -> BTreeSet<(String, String, String)> {
        (all.iter())
            .map(|row| (row.group.clone(), row.prefix.clone(), row.artifact.clone()))
            .collect()
    };
    let searched = |row: &rv_lock::PluginPrefix| {
        let plugin = format!("{}:{}:", row.group, row.artifact);
        let named = |set: &&&rv_lock::PluginSet| {
            (set.coordinates.iter()).any(|coordinate| coordinate.starts_with(&plugin))
        };
        repos.declares(&row.repo_url)
            && (sets.iter().filter(named))
                .all(|set| (set.repo_urls.iter()).any(|read| same_repository(read, &row.repo_url)))
    };
    if held.tables.prefixes != fresh.prefixes
        && (prefixes(&held.tables.prefixes) != prefixes(&fresh.prefixes)
            || !held.tables.prefixes.iter().all(searched))
    {
        return Some("the plugin prefixes differ from a resolution of the same inputs".to_string());
    }
    // The ids are what the export labels each file with; a trace adds
    // those of the declared repositories its files came from, under the
    // ids they are declared with. A file from a repository nothing
    // declares is refused below, or when it is fetched.
    let traced = (held.tables.sets.iter()).any(|set| set.role == rv_lock::PluginRole::Trace);
    let ids_kept = (fresh.repo_ids.iter()).all(|(origin, ids)| {
        (held.tables.repo_ids.get(origin)).is_some_and(|held| held.is_superset(ids))
    });
    // An origin nothing declares is refused below, with what names it.
    let refused = repos.undeclared(entry, held).is_some();
    let ids_traced = refused
        || (held.tables.repo_ids.iter()).all(|(origin, ids)| {
            let read = fresh.repo_ids.get(origin);
            let rows = (row_ids.iter()).filter(|(url, _)| same_repository(url, origin));
            let rows: BTreeSet<&String> = rows.flat_map(|(_, ids)| ids).collect();
            (ids.iter()).all(|id| {
                read.is_some_and(|read| read.contains(id))
                    || rows.contains(id)
                    || repos.names(origin, id)
            })
        });
    if !ids_kept || !ids_traced || (!traced && held.tables.repo_ids != fresh.repo_ids) {
        return Some(
            "the plugin repository ids differ from a resolution of the same inputs".to_string(),
        );
    }
    if held.tables.metadata_versions != fresh.metadata_versions {
        return Some(
            "the versions the plugin tables took from repository metadata differ from a \
             resolution of the same inputs"
                .to_string(),
        );
    }
    if held.tables.range_versions != fresh.range_versions {
        return Some(
            "the versions the plugin tables' ranges took differ from a resolution of the same \
             inputs"
                .to_string(),
        );
    }
    let used = entry.module_rows();
    let read: std::collections::BTreeSet<&String> = (entry.modules.iter())
        .flat_map(|module| &module.support_poms)
        .collect();
    let origins = |urls: &mut dyn Iterator<Item = &str>| {
        urls.map(rv_repo::normalize_repo_url)
            .collect::<std::collections::BTreeSet<_>>()
    };
    // Where the origins differ, the lock's still serve: each is declared,
    // and each set that reads the file searches one, under whose id
    // `mvn -o` takes it.
    let serve = |reads: &dyn Fn(&rv_lock::PluginSet) -> bool, recorded: &[&str]| {
        recorded.iter().all(|url| repos.declares(url))
            && (sets.iter().filter(|set| reads(set))).all(|set| {
                (set.repo_urls.iter())
                    .any(|url| recorded.iter().any(|origin| same_repository(origin, url)))
            })
    };
    // The sets that read the file and search one of `recorded`, which read
    // its POM where `recorded` served it.
    let readers = |row: &rv_lock::LockArtifact, recorded: &[&str]| -> Vec<usize> {
        (sets.iter().enumerate())
            .filter(|(_, set)| set.artifacts.contains(&row.coordinate))
            .filter(|(_, set)| {
                (set.repo_urls.iter())
                    .any(|url| recorded.iter().any(|origin| same_repository(origin, url)))
            })
            .map(|(at, _)| at)
            .collect()
    };
    let relocated =
        |row: &rv_lock::LockArtifact, fresh: &rv_lock::LockArtifact, shared: &BTreeSet<String>| {
            let reads = |set: &rv_lock::PluginSet| set.artifacts.contains(&row.coordinate);
            let poms: Vec<&str> = row.pom_origins().collect();
            let files: Vec<&str> = match used.contains(&row.coordinate) {
                true => (row.file_origins())
                    .chain(shared.iter().map(String::as_str))
                    .collect(),
                false => row.file_origins().collect(),
            };
            !row.is_snapshot()
                && row.pin().is_some_and(|pin| pin.as_sha256().is_some())
                && serve(&reads, &files)
                && (used.contains(&row.coordinate)
                    || row.pom_sha256.is_none()
                    || (poms
                        .iter()
                        .all(|url| repos.declares(url) && !readers(row, &[url]).is_empty())
                        && readers(row, &poms)
                            == readers(row, &fresh.pom_origins().collect::<Vec<_>>())))
        };
    for artifact in &resolved.artifacts {
        let same = (held.artifacts.iter()).find(|row| row.coordinate == artifact.coordinate);
        let shared = (held.tables.shared_origins.get(&artifact.coordinate)).into_iter();
        let shared = origins(&mut shared.flatten().map(String::as_str));
        // A trace gives a row whose POM the resolution did not read the one
        // the build read.
        let pom_read = artifact.pom_sha256.is_some() || !traced;
        if same.is_none_or(|row| {
            // The dependencies' check holds a row they use to its checksums.
            (match used.contains(&row.coordinate) {
                true => row.pin() != artifact.pin(),
                false => row.checksums != artifact.checksums,
            }) || (artifact.pom_sha256.is_some() && row.pom_sha256 != artifact.pom_sha256)
                || (!used.contains(&row.coordinate)
                    && (origins(&mut row.file_origins()) != origins(&mut artifact.file_origins())
                        || (pom_read
                            && origins(&mut row.pom_origins())
                                != origins(&mut artifact.pom_origins())))
                    && !relocated(row, artifact, &shared))
                || (used.contains(&row.coordinate) && {
                    let fresh = origins(&mut rv_lock::unrecorded_origins(
                        row,
                        artifact,
                        row_ids,
                        &resolved.tables.repo_ids,
                    ));
                    // A trace adds the origins its files came from.
                    (!fresh.is_subset(&shared) || (!traced && fresh != shared))
                        && !relocated(row, artifact, &shared)
                })
                || (used.contains(&row.coordinate) && row.pom_sha256.is_some() && {
                    // The origins that served the file without the row's
                    // POM decide which builds `mvn -o` gives the POM.
                    let held = (held.tables.shared_without_pom.get(&artifact.coordinate))
                        .into_iter()
                        .flatten();
                    let held = origins(&mut held.map(String::as_str));
                    let fresh = match artifact.pom_sha256 {
                        Some(_) => BTreeSet::new(),
                        None => origins(&mut rv_lock::unrecorded_origins(
                            row,
                            artifact,
                            row_ids,
                            &resolved.tables.repo_ids,
                        )),
                    };
                    !fresh.is_subset(&held) || (!traced && fresh != held)
                })
        }) {
            return Some(format!(
                "the plugin file {} differs from a resolution of the same inputs",
                artifact.coordinate
            ));
        }
    }
    // A POM of a file a row pins would serve the row's readers too, so it
    // stays where the resolution read it.
    let companion = |coordinate: &str| {
        (entry.artifacts.iter().chain(&held.artifacts)).any(|row| {
            let gav = &row.coordinate;
            format!("{}:{}:{}", gav.group_id(), gav.artifact_id(), gav.version()) == coordinate
        })
    };
    let relocated_pom = |coordinate: &str, row: &rv_lock::SupportPom| {
        let reads = |set: &rv_lock::PluginSet| set.poms.iter().any(|pom| pom == coordinate);
        row.snapshot.is_none()
            && !companion(coordinate)
            && rv_lock::split_support_pom_coord(coordinate)
                .is_some_and(|(_, _, version)| !rv_maven_types::is_snapshot_version(version))
            && serve(&reads, &[row.repo_url.as_str()])
    };
    for (coordinate, pom) in &resolved.poms {
        if held.poms.get(coordinate).is_none_or(|row| {
            row.sha256 != pom.sha256
                || (!read.contains(coordinate)
                    && !same_repository(&row.repo_url, &pom.repo_url)
                    && !relocated_pom(coordinate, row))
        }) {
            return Some(format!(
                "the plugin POM {coordinate} differs from a resolution of the same inputs"
            ));
        }
    }
    // A trace adds the origins its files came from, each one declared.
    repos.undeclared(entry, held).map(undeclared)
}

/// What a refusal of the undeclared repository `url` says.
fn undeclared(url: &str) -> String {
    format!(
        "raeva.lock names the plugin repository {}, which neither the configuration nor the \
         project's POMs declare, nor a resolution of the plugins reads",
        rv_config::redact_url(url)
    )
}

pub(super) fn same_repository(a: &str, b: &str) -> bool {
    rv_repo::normalize_repo_url(a) == rv_repo::normalize_repo_url(b)
}

/// The repositories the configuration and the project's POMs declare, the
/// POMs' as `policy` admits them. The plugin repositories plugin resolution
/// reads come first, so their policies win at a URL and id they share; a
/// POM's `<pluginRepositories>` and the super POM's come with its own.
pub(super) fn known_repositories<'a>(
    config: &Config,
    policy: &rv_repo::RepositoryPolicy,
    models: impl IntoIterator<Item = &'a ReactorModel>,
) -> Vec<rv_repo::Repository> {
    let declared = (models.into_iter()).flat_map(|model| {
        (model.declared_plugin_repositories()).chain(model.declared_repositories())
    });
    (config.profile_plugin_repositories().iter())
        .chain(config.plugin_repositories())
        .chain(config.all_repositories())
        .map(rv_repo::Repository::from)
        .chain(
            policy
                .admit(declared, rv_repo::Declaration::LocalPom)
                .admitted,
        )
        .collect()
}

/// The repositories the plugin tables of one platform may take a file
/// from. raeva.lock comes from a checkout, so a URL only it records gains
/// nothing by being recorded: no request goes there and no credential
/// follows it. A repository the configuration or the platform's POMs
/// declare serves as declared, under an id the tables record only among
/// those at its exact URL. One only a resolution of the tables in this run
/// read, such as a remote parent's, serves as that resolution read it.
pub(super) struct PluginRepositories<'a> {
    origins: rv_lock::LockOrigins,
    known: Vec<rv_repo::Repository>,
    resolved: Option<&'a PluginFiles>,
}

impl<'a> PluginRepositories<'a> {
    /// The repositories of `platform`: those `config` and its `models`
    /// declare, and those `resolved`, its tables as this run resolved
    /// them, read.
    pub(super) fn new(
        config: &Config,
        policy: &rv_repo::RepositoryPolicy,
        models: &[ReactorModel],
        platform: &Platform,
        resolved: Option<&'a PluginFiles>,
    ) -> Self {
        // A platform the run has no model of, such as the one a trace
        // picks that a partial sync leaves out, takes the run's models'.
        let own = models.iter().any(|model| model.platform == *platform);
        let models = (models.iter()).filter(|model| !own || model.platform == *platform);
        Self {
            origins: rv_lock::LockOrigins::for_root(&config.project_root),
            known: known_repositories(config, policy, models),
            resolved,
        }
    }

    /// Those the configuration and the POMs declare.
    pub(super) fn known(&self) -> &[rv_repo::Repository] {
        &self.known
    }

    fn known_at<'s>(&'s self, url: &'s str) -> impl Iterator<Item = &'s rv_repo::Repository> {
        (self.known.iter()).filter(move |repo| self.origins.matches(url, &repo.url))
    }

    fn resolved_at(&self, url: &str) -> bool {
        self.resolved
            .is_some_and(|files| recorded_urls(files).any(|read| same_repository(read, url)))
    }

    /// Whether one of these is at `url`.
    pub(super) fn declares(&self, url: &str) -> bool {
        self.known_at(url).next().is_some() || self.resolved_at(url)
    }

    /// The first origin a row or POM of `files`, the plugin tables of
    /// `entry`, records that none of these declares: what [`fetch`] would
    /// ask, or what the export would label a file the modules use with.
    /// The origins of a row or POM `entry`'s modules use too are the
    /// dependencies' to check, those the sets add to it the tables'. The
    /// sets' lists of the repositories they resolve from, such as a remote
    /// parent's snapshot repository that serves no row, name none.
    pub(super) fn undeclared<'f>(
        &self,
        entry: &LockPlatform,
        files: &'f PluginFiles,
    ) -> Option<&'f str> {
        let used = UsedFiles::of(entry);
        (files.pinned_files())
            .filter(|file| !used.holds(file))
            .flat_map(|file| file.origins)
            .chain((files.tables.shared_origins.values().flatten()).map(String::as_str))
            .find(|url| !self.declares(url))
    }

    /// Whether `id` is one a repository declared at `url` goes by.
    fn names(&self, url: &str, id: &str) -> bool {
        self.known_at(url)
            .any(|repo| repo.id.as_deref() == Some(id))
    }

    /// The repositories to ask for `file`, which the plugin tables record
    /// with `repo_ids` and `sets`: those its row records, in order, and for
    /// a SHA-256 pin then those this run's resolution read it from and
    /// those of these the sets that read it search, once by URL.
    fn candidates(
        &self,
        policy: &rv_repo::RepositoryPolicy,
        repo_ids: &rv_lock::RepoIds,
        sets: &[rv_lock::PluginSet],
        file: &rv_lock::PinnedFile<'_>,
    ) -> Result<Vec<rv_repo::Repository>> {
        let mut candidates: Vec<rv_repo::Repository> = Vec::new();
        let mut add = |repo: rv_repo::Repository| {
            if !(candidates.iter()).any(|known| same_repository(&known.url, &repo.url)) {
                candidates.push(repo);
            }
        };
        let (recorded, others) = file.origins.split_first().expect("a file has an origin");
        add(self.repository(policy, repo_ids, recorded)?);
        if file.pin.as_sha256().is_none() {
            return Ok(candidates);
        }
        for url in others {
            add(self.repository(policy, repo_ids, url)?);
        }
        if let Some(files) = self.resolved {
            let read = (files.pinned_files())
                .find(|read| read.key == file.key && read.pin == file.pin)
                .map(|read| read.origins)
                .unwrap_or_default();
            for url in read {
                add(self.repository(policy, &files.tables.repo_ids, url)?);
            }
        }
        // Then the other repositories the sets that read the file search,
        // as Maven would ask them.
        let reads = |set: &&rv_lock::PluginSet| match file.row {
            rv_lock::PinnedRow::File(row) | rv_lock::PinnedRow::Pom(row) => {
                set.artifacts.contains(&row.coordinate)
            }
            rv_lock::PinnedRow::Support(coordinate, _) => {
                set.poms.iter().any(|pom| pom == coordinate)
            }
        };
        let searched = (sets.iter().filter(reads)).flat_map(|set| &set.repo_urls);
        for url in searched.filter(|url| self.declares(url)) {
            if let Ok(repo) = self.repository(policy, repo_ids, url)
                && repo.allows_version(file.key.version())
            {
                add(repo);
            }
        }
        Ok(candidates)
    }

    /// `url`, which the plugin tables record with `repo_ids`, as raeva may
    /// fetch from it.
    pub(super) fn repository(
        &self,
        policy: &rv_repo::RepositoryPolicy,
        repo_ids: &rv_lock::RepoIds,
        url: &str,
    ) -> Result<rv_repo::Repository> {
        // A URL may serve under several ids, each with its own credential.
        let ids = repo_ids.get(url);
        let recorded = self.known_at(url).find(|repo| {
            (repo.id.as_ref()).is_some_and(|id| ids.is_some_and(|ids| ids.contains(id)))
        });
        if let Some(repo) = recorded.or_else(|| self.known_at(url).next()) {
            return Ok(repo.clone());
        }
        let refused = || stale(undeclared(url));
        let Some(files) = self.resolved.filter(|_| self.resolved_at(url)) else {
            return Err(refused());
        };
        let read = (files.tables.repo_ids.iter()).find(|(origin, _)| same_repository(origin, url));
        let id = read.and_then(|(_, ids)| ids.iter().next().cloned());
        // A directory of the project is read as the checkout holds it, as the
        // resolution read a <pluginRepository> there; the pins check its files.
        if rv_lock::is_project_relative_origin(url) {
            return match self.origins.project_url(url) {
                Some(directory) => Ok(rv_repo::Repository::new(id, directory, true, false)),
                None => Err(refused()),
            };
        }
        // Admitted to the client, so what its provenance allows, such as a
        // proxy, holds for the fetch.
        let resolved = rv_repo::Repository::new(id, url, true, false);
        let admission = policy.admit([resolved], rv_repo::Declaration::RemoteParent);
        admission.admitted.into_iter().next().ok_or_else(refused)
    }
}

/// The plugin tables of `entry` of `lock` as a resolution gives them now,
/// when `models` holds its platform's.
pub(super) async fn resolved(
    config: &Config,
    store: Arc<Store>,
    client: RepoClient,
    lock: &Lockfile,
    entry: &LockPlatform,
    models: &[ReactorModel],
) -> Result<Option<PluginFiles>> {
    let Some(model) = models.iter().find(|model| model.platform == entry.platform) else {
        return Ok(None);
    };
    let resolver = Resolver::new(Arc::new(config.clone()), store, client);
    let files = resolve(config, &resolver, goals(config), entry, model, lock, None).await?;
    Ok(Some(files))
}

/// Each repository URL the plugin tables of `files` record.
fn recorded_urls(files: &PluginFiles) -> impl Iterator<Item = &str> {
    let tables = &files.tables;
    (files.pinned_files().flat_map(|file| file.origins))
        .chain((tables.sets.iter()).flat_map(|set| set.repo_urls.iter().map(String::as_str)))
        .chain(tables.repo_ids.keys().map(String::as_str))
        .chain((tables.shared_origins.values()).flat_map(|read| read.iter().map(String::as_str)))
}

/// The rows and support POMs a platform's modules use, which the
/// dependencies' restore puts in the store and their checks cover.
struct UsedFiles<'a> {
    rows: BTreeSet<&'a rv_maven_types::ArtifactCoord>,
    poms: BTreeSet<&'a str>,
}

impl<'a> UsedFiles<'a> {
    fn of(entry: &'a LockPlatform) -> Self {
        Self {
            rows: entry.module_rows(),
            poms: (entry.modules.iter().flat_map(|module| &module.support_poms))
                .map(String::as_str)
                .collect(),
        }
    }

    fn holds(&self, file: &rv_lock::PinnedFile<'_>) -> bool {
        match file.row {
            rv_lock::PinnedRow::File(row) | rv_lock::PinnedRow::Pom(row) => {
                self.rows.contains(&row.coordinate)
            }
            rv_lock::PinnedRow::Support(coordinate, _) => self.poms.contains(coordinate),
        }
    }
}

/// What decides `entry`'s plugin tables besides the POMs and configuration
/// `lock` records: the goals, `.mvn/extensions.xml`, the dependencies of
/// each module, whose test frameworks pick test providers, the Maven
/// version the tables follow, and this host's values of `host_inputs`,
/// what the plugin resolution read from the host and of the `-D` values,
/// `.mvn/extensions.xml` included.
pub(crate) fn inputs_digest(
    config: &Config,
    goals: &[String],
    lock: &Lockfile,
    entry: &LockPlatform,
    host_inputs: &std::collections::BTreeSet<rv_lock::AmbientInput>,
) -> Result<Sha256> {
    digest(config, goals, lock, entry, &entry.model_hash, host_inputs)
}

/// [`inputs_digest`] with the hash `model`, the current POMs, gives in
/// place of the one `lock` records.
fn current_inputs_digest(
    config: &Config,
    goals: &[String],
    lock: &Lockfile,
    entry: &LockPlatform,
    model: &ReactorModel,
    host_inputs: &std::collections::BTreeSet<rv_lock::AmbientInput>,
) -> Result<Sha256> {
    let model_hash = model.current(lock).model_hash;
    digest(config, goals, lock, entry, &model_hash, host_inputs)
}

fn digest(
    config: &Config,
    goals: &[String],
    lock: &Lockfile,
    entry: &LockPlatform,
    model_hash: &str,
    host_inputs: &std::collections::BTreeSet<rv_lock::AmbientInput>,
) -> Result<Sha256> {
    let mut text = format!("maven {}\n", lock.maven.version());
    text.push_str(&format!(
        "config {}\nline {}\nmodel {model_hash}\n",
        lock.config_hash.as_deref().unwrap_or("-"),
        lock.maven.as_str(),
    ));
    let extensions = config.mvn_dir().join("extensions.xml");
    let extensions = rv_config::read_optional_project_input(&extensions)?;
    let extensions = extensions.map(|bytes| rv_lock::inputs::text_sha256(&bytes).to_string());
    text.push_str(&format!(
        "extensions {}\n",
        extensions.as_deref().unwrap_or("-")
    ));
    // The settings.xml plugin repositories of the profiles active on the
    // entry's platform; the lock's configuration hash covers their
    // definitions.
    let platform = &entry.platform;
    let scoped = config.for_platforms([(platform.os(), platform.arch(), platform.jdk())]);
    let profile = (scoped.profile_plugin_repositories().iter()).map(|repo| ("profile", repo));
    let request = (scoped.named_plugin_repositories().iter()).map(|repo| ("request", repo));
    for (list, repo) in profile.chain(request) {
        // With the project's and the user's home directories as markers,
        // as the configuration hash spells them, so the lock holds on
        // another checkout path.
        let mut repo = repo.clone();
        repo.url = config.portable_location(&repo.url);
        repo.declared_url = (repo.declared_url.as_deref()).map(|url| config.portable_location(url));
        let repo = serde_json::to_string(&repo).unwrap_or_default();
        text.push_str(&format!("plugin-repository {list} {repo}\n"));
    }
    for goal in goals {
        text.push_str(&format!("goal {goal}\n"));
    }
    for group in config.plugin_groups() {
        text.push_str(&format!("plugin group {group}\n"));
    }
    // The values the plugin resolution read from the host, which the lock
    // names and never holds.
    // An active settings.xml profile property of a user property's name
    // ranks below `-D` values and above `.mvn/jvm.config`, as for
    // `config_hash`.
    let (mut names, mut overrides) = (BTreeSet::new(), BTreeSet::new());
    for (name, system) in host_inputs
        .iter()
        .filter_map(rv_lock::AmbientInput::user_property_name)
    {
        match system {
            true => names.insert(name.to_string()),
            false => overrides.insert(name.to_string()),
        };
    }
    let mut properties = scoped.user_override_inputs(&overrides);
    properties.extend(scoped.user_property_inputs(&names));
    let companions = (properties.into_iter())
        .filter(|(_, inputs)| !inputs.defined())
        .map(|(name, _)| rv_lock::AmbientInput::SettingsProperty(name))
        .filter(|settings| !host_inputs.contains(settings));
    for input in host_inputs.iter().cloned().chain(companions) {
        let value = crate::commands::lock_inputs::current_value(&scoped, &input);
        let value = value.map_or("-".to_string(), |value| {
            Sha256::from_bytes(value.as_bytes()).to_string()
        });
        text.push_str(&format!("host {input} {value}\n"));
    }
    // raeva.lock reads the modules and their packages back in another order
    // than a resolution lists them.
    let mut modules: Vec<_> = entry.modules.iter().collect();
    modules.sort_by(|a, b| a.path.cmp(&b.path));
    for module in modules {
        text.push_str(&format!("module {}\n", module.path));
        let mut packages: Vec<String> = (module.packages.iter())
            .map(|package| package.coordinate.to_string())
            .collect();
        packages.sort();
        for package in packages {
            text.push_str(&format!("package {package}\n"));
        }
    }
    Ok(Sha256::from_bytes(text.as_bytes()))
}

#[cfg(test)]
mod tests {
    use rv_repo::Provenance;

    /// A stale trace stays only on this machine's OS and architecture, for
    /// the trace that replaces it, and not under `--update`.
    #[test]
    fn a_stale_trace_stays_only_for_the_trace_that_replaces_it() {
        use rv_lock::{Platform, PluginFiles, PluginSet};
        let dir = tempfile::TempDir::new().unwrap();
        let mut config = rv_config::Config::for_testing(
            dir.path().to_path_buf(),
            rv_config::ResolvedPaths::from_raeva_home(dir.path().join("home")),
        );
        let mut tables = PluginFiles::new(rv_maven_types::Sha256::from_bytes(b"inputs")).tables;
        tables
            .sets
            .push(PluginSet::new("sha256:old", rv_lock::PluginRole::Trace));
        let host = Platform::current().unwrap();
        let other = match host.os() {
            "windows" => Platform::new("linux", host.arch()),
            _ => Platform::new("windows", host.arch()),
        }
        .unwrap();
        let stays = |config: &rv_config::Config, platform: &Platform, update: bool| {
            super::trace_stays(config, platform, &tables, update).unwrap()
        };
        let none = PluginFiles::new(rv_maven_types::Sha256::from_bytes(b"inputs")).tables;
        assert!(
            super::trace_stays(&config, &host, &none, true).unwrap(),
            "no trace"
        );
        assert!(
            !stays(&config, &host, false),
            "raeva.toml asks for no trace"
        );
        config.plugins = Some(super::traced("verify"));
        assert!(stays(&config, &host, false));
        assert!(!stays(&config, &host, true), "--update traces again");
        assert!(!stays(&config, &other, false), "no trace here replaces it");
    }

    /// The traces of a conflicted lock's versions: one that both hold stays
    /// as it is, and two under one key, or of another JDK, become one stale
    /// trace with the rows of both, which a lock can hold.
    #[test]
    fn the_traces_of_a_conflicted_lock_stay_as_one() {
        use rv_lock::{LockArtifact, LockPlatform, Lockfile, Platform, PluginFiles, PluginSet};
        use rv_maven_types::{ArtifactCoord, Digest, Sha256};
        let inputs = Sha256::from_bytes(b"inputs");
        let host = Platform::current().unwrap();
        let version = |platform: &Platform, artifact: &str| {
            let coordinate = ArtifactCoord::new("g", artifact, "1", "jar", None);
            let mut row = LockArtifact::new(coordinate.clone(), "https://r.example/");
            row.checksums = vec![Digest::Sha256(Sha256::from_bytes(artifact.as_bytes()))];
            let mut files = PluginFiles::new(inputs.clone());
            let mut set = PluginSet::new("sha256:key", rv_lock::PluginRole::Trace);
            set.artifacts.push(coordinate);
            files.tables.sets.push(set);
            files.artifacts.push(row);
            let mut entry = LockPlatform::new(platform.clone(), "");
            entry.set_plugins(files, &rv_lock::RepoIds::new()).unwrap();
            entry
        };
        let carried = |entries: Vec<LockPlatform>| {
            let mut lock = Lockfile::new();
            lock.platforms = entries;
            let mut files = PluginFiles::new(inputs.clone());
            super::carry_traces(&mut files, &lock, &host, std::slice::from_ref(&host));
            let mut entry = LockPlatform::new(host.clone(), "");
            entry.set_plugins(files, &rv_lock::RepoIds::new()).unwrap();
            entry.plugin_files().unwrap()
        };
        let same = carried(vec![version(&host, "a"), version(&host, "a")]);
        assert_eq!(same.tables.sets.len(), 1);
        assert_eq!(same.tables.sets[0].key, "sha256:key");
        let both = carried(vec![version(&host, "a"), version(&host, "b")]);
        assert_eq!(both.tables.sets.len(), 1);
        assert_ne!(both.tables.sets[0].key, "sha256:key");
        assert_eq!(both.tables.sets[0].artifacts.len(), 2);
        assert_eq!(both.artifacts.len(), 2);
        // A JDK the new lock leaves out, beside an entry of the host without
        // a trace.
        let jdk = host.clone().with_jdk("17");
        let mut untraced = version(&host, "a");
        untraced.remove_plugins();
        let other = carried(vec![untraced, version(&jdk, "a")]);
        assert_ne!(other.tables.sets[0].key, "sha256:key");
    }

    /// A repository the configuration declares keeps what it may do, and
    /// of two declared at one URL, the one under the recorded id serves.
    /// One only the tables name serves nothing, another path of a
    /// configured origin included; one this run's resolution read serves as
    /// a fetched POM's, under the id the resolution read, never a file path.
    #[tokio::test]
    async fn a_repository_only_the_tables_name_serves_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut config = rv_config::Config::for_testing_with_repos(
            dir.path().to_path_buf(),
            rv_config::ResolvedPaths::from_raeva_home(dir.path().join("home")),
            vec![
                rv_config::RepoConfig::new(Some("corp"), "https://corp.example/maven/"),
                rv_config::RepoConfig::new(Some("corp-plugins"), "https://corp.example/maven/"),
            ],
        );
        config.security.allow_transitive_repositories = true;
        let client = rv_repo::RepoClient::new(&config).await.unwrap();
        let policy = client.policy();
        let platform: rv_lock::Platform = "linux-x86_64".parse().unwrap();
        let mut repo_ids = rv_lock::RepoIds::new();
        for url in ["https://other.example/", "https://corp.example/other/"] {
            repo_ids.insert(url.to_string(), ["corp".to_string()].into());
        }
        let lock_only = super::PluginRepositories::new(&config, policy, &[], &platform, None);
        let repo = |repos: &super::PluginRepositories<'_>, url: &str| {
            repos.repository(policy, &repo_ids, url)
        };
        assert_eq!(
            repo(&lock_only, "https://corp.example/maven/")
                .unwrap()
                .provenance(),
            Provenance::Configured
        );
        let mut plugin_ids = repo_ids.clone();
        plugin_ids.insert(
            "https://corp.example/maven/".to_string(),
            ["corp-plugins".to_string()].into(),
        );
        let recorded = lock_only.repository(policy, &plugin_ids, "https://corp.example/maven/");
        assert_eq!(recorded.unwrap().id.as_deref(), Some("corp-plugins"));
        for url in [
            "https://other.example/",
            "https://corp.example/other/",
            "./repo/",
        ] {
            assert!(repo(&lock_only, url).is_err(), "{url}");
        }
        assert!(!client.trusts_origin("https://other.example/"));

        let mut files = rv_lock::PluginFiles::new(rv_maven_types::Sha256::from_bytes(b"inputs"));
        let mut set = rv_lock::PluginSet::new("sha256:key", rv_lock::PluginRole::Plugin);
        set.repo_urls = ["https://other.example/", "./repo/", "file:///etc/"]
            .map(String::from)
            .into();
        files.tables.sets.push(set);
        (files.tables.repo_ids).insert(
            "https://other.example/".to_string(),
            ["vendor".to_string()].into(),
        );
        let read = super::PluginRepositories::new(&config, policy, &[], &platform, Some(&files));
        let other = repo(&read, "https://other.example/").unwrap();
        assert_eq!(other.provenance(), Provenance::FetchedPom);
        assert_eq!(other.id.as_deref(), Some("vendor"));
        // The allowlist trusts it on the client that fetches from it, as
        // it did in the resolution that read it.
        assert!(client.trusts_origin("https://other.example/"));
        assert!(repo(&read, "file:///etc/").is_err());
        assert!(repo(&read, "https://corp.example/other/").is_err());
        // A directory of the project, read as the resolution read it.
        let local = repo(&read, "./repo/").unwrap();
        let origins = rv_lock::LockOrigins::for_root(dir.path());
        assert_eq!(Some(local.url), origins.project_url("./repo/"));
    }

    /// The repositories `https://r.example/` and `https://first.example/`,
    /// the latter with the id `first`, as the configuration declares them.
    fn declared() -> super::PluginRepositories<'static> {
        let repo = |id: Option<&str>, url: &str| {
            rv_repo::Repository::new(id.map(str::to_string), url, true, false)
        };
        super::PluginRepositories {
            origins: rv_lock::LockOrigins::for_root(std::path::Path::new("/project")),
            known: vec![
                repo(None, "https://r.example/"),
                repo(Some("first"), "https://first.example/"),
            ],
            resolved: None,
        }
    }

    /// A POM the trace gave a row a resolution leaves without one is no
    /// drift; a POM pin the lock drops is. A row recorded under another
    /// declared repository its set searches, as a mirror of both records
    /// it, is no drift either; one under a repository nothing declares, or
    /// one its set does not search, is.
    #[test]
    fn a_pom_pin_counts_where_the_resolution_has_one() {
        use rv_maven_types::{ArtifactCoord, Sha256};
        let files = |pom: Option<&[u8]>| {
            let mut files = rv_lock::PluginFiles::new(Sha256::from_bytes(b"inputs"));
            let coordinate = ArtifactCoord::new("g", "a", "1", "jar", None);
            let mut row = rv_lock::LockArtifact::new(coordinate, "https://r.example/");
            row.checksums = vec![rv_maven_types::Digest::Sha256(Sha256::from_bytes(b"jar"))];
            row.pom_sha256 = pom.map(Sha256::from_bytes);
            files.artifacts.push(row);
            files
        };
        let entry = rv_lock::LockPlatform::new("linux-x86_64".parse().unwrap(), "");
        let drift = |held, resolved| {
            super::plugin_drift(
                &entry,
                &held,
                &resolved,
                &rv_lock::RepoIds::new(),
                &declared(),
                true,
            )
        };
        assert_eq!(drift(files(Some(b"pom")), files(None)), None);
        assert!(drift(files(None), files(Some(b"pom"))).is_some());
        assert!(drift(files(Some(b"old")), files(Some(b"pom"))).is_some());
        let mut moved = files(None);
        moved.artifacts[0].repo_url = "https://elsewhere.example/".to_string();
        assert!(drift(moved, files(None)).is_some());
        let searching = |files: rv_lock::PluginFiles, repos: &[&str]| {
            let mut files = files;
            let mut set = rv_lock::PluginSet::new("sha256:key", rv_lock::PluginRole::Plugin);
            set.artifacts.push(files.artifacts[0].coordinate.clone());
            set.repo_urls = repos.iter().map(ToString::to_string).collect();
            files.tables.sets.push(set);
            files
        };
        let both = ["https://first.example/", "https://r.example/"];
        let mut first = files(Some(b"pom"));
        first.artifacts[0].repo_url = both[0].to_string();
        let resolved = searching(files(Some(b"pom")), &both);
        assert_eq!(
            drift(searching(first.clone(), &both), resolved.clone()),
            None
        );
        let resolved = searching(files(Some(b"pom")), &both[1..]);
        assert!(drift(searching(first, &both[1..]), resolved).is_some());
        // A POM recorded under a repository another set searches would
        // serve that set too, where the resolution's does not.
        let pom_from = |pom: &str| {
            let mut files = searching(files(Some(b"pom")), &both);
            let mut set = rv_lock::PluginSet::new("sha256:other", rv_lock::PluginRole::Plugin);
            set.artifacts.push(files.artifacts[0].coordinate.clone());
            set.repo_urls = vec![both[1].to_string()];
            files.tables.sets.push(set);
            let row = &mut files.artifacts[0];
            row.repo_url = both[0].to_string();
            row.other_repo_urls = vec![both[1].to_string()];
            row.pom_repo_urls = vec![pom.to_string()];
            files
        };
        assert_eq!(drift(pom_from(both[0]), pom_from(both[0])), None);
        assert!(drift(pom_from(both[1]), pom_from(both[0])).is_some());
        // Nor under one no set that reads it searches, where the
        // resolution's came from a repository a POM along the path added.
        let unsearched = |pom: &str| {
            let mut files = searching(files(Some(b"pom")), &both[..1]);
            files.artifacts[0].repo_url = both[0].to_string();
            files.artifacts[0].pom_repo_urls = vec![pom.to_string()];
            files
        };
        let added = "https://added.example/";
        assert!(drift(unsearched(both[1]), unsearched(added)).is_some());
        // A support POM moves to another declared repository its sets
        // search, unless a row pins a file of its coordinate, whose readers
        // it would serve too.
        let parent = |key: &str, at: &str| {
            let mut files = searching(files(None), &both);
            files.tables.sets[0].poms.push(key.to_string());
            (files.poms).insert(
                key.to_string(),
                rv_lock::SupportPom::new(at, Sha256::from_bytes(b"parent")),
            );
            files
        };
        assert_eq!(
            drift(parent("g:p:1", both[0]), parent("g:p:1", both[1])),
            None
        );
        assert!(drift(parent("g:a:1", both[0]), parent("g:a:1", both[1])).is_some());
    }

    /// A trace carries the origin it read a row the modules use from, and a
    /// frozen check takes it as the trace's addition where a repository is
    /// declared there under the id the tables record.
    #[test]
    fn a_trace_keeps_the_origin_it_read_a_shared_row_from() {
        use rv_maven_types::{ArtifactCoord, Digest, Gav, Sha256};
        let coordinate = ArtifactCoord::new("g", "a", "1", "jar", None);
        let traced = "https://first.example/".to_string();
        let mut row = rv_lock::LockArtifact::new(coordinate.clone(), "https://r.example/");
        row.checksums = vec![Digest::Sha256(Sha256::from_bytes(b"jar"))];
        let mut kept = rv_lock::PluginFiles::new(Sha256::from_bytes(b"inputs"));
        let mut set = rv_lock::PluginSet::new("sha256:key", rv_lock::PluginRole::Trace);
        set.artifacts.push(coordinate.clone());
        kept.tables.sets.push(set);
        (kept.tables.shared_origins).insert(coordinate.clone(), [traced.clone()].into());
        (kept.tables.repo_ids).insert(traced.clone(), ["first".into()].into());
        let mut files = rv_lock::PluginFiles::new(Sha256::from_bytes(b"inputs"));
        super::carry_trace(&mut files, kept.clone());
        assert_eq!(files.tables.shared_origins, kept.tables.shared_origins);
        assert!(files.tables.repo_ids.contains_key(&traced));
        let mut entry = rv_lock::LockPlatform::new("linux-x86_64".parse().unwrap(), "");
        let mut module = rv_lock::LockModule::new("pom.xml", Gav::new("g", "app", "1"), "jar");
        (module.packages).push(rv_lock::LockModulePackage::new(coordinate.clone(), None));
        entry.modules.push(module);
        kept.artifacts.push(row.clone());
        let mut resolved = rv_lock::PluginFiles::new(Sha256::from_bytes(b"inputs"));
        resolved.artifacts.push(row);
        let drift = |kept: &rv_lock::PluginFiles| {
            super::plugin_drift(
                &entry,
                kept,
                &resolved,
                &rv_lock::RepoIds::new(),
                &declared(),
                true,
            )
        };
        assert_eq!(drift(&kept), None);
        // An edit that names a repository nothing declares, or an id the
        // declared one does not go by, is drift.
        let mut elsewhere = kept.clone();
        let other = "https://t.example/".to_string();
        (elsewhere.tables.shared_origins).insert(coordinate.clone(), [other.clone()].into());
        (elsewhere.tables.repo_ids).insert(other, ["first".into()].into());
        assert!(drift(&elsewhere).is_some());
        let mut renamed = kept.clone();
        (renamed.tables.repo_ids).insert(traced, ["evil".into()].into());
        assert!(drift(&renamed).is_some());
        // Nor an id for a repository only the dependencies read from, as
        // a dependency's POM adds one, but the one they record.
        let added = "https://added.example/".to_string();
        let rows: rv_lock::RepoIds = [(added.clone(), ["added".into()].into())].into();
        let relabelled = |id: &str| {
            let mut kept = kept.clone();
            (kept.tables.repo_ids).insert(added.clone(), [id.to_string()].into());
            super::plugin_drift(&entry, &kept, &resolved, &rows, &declared(), true)
        };
        assert_eq!(relabelled("added"), None);
        assert!(relabelled("evil").is_some());
    }

    /// A frozen check that holds a plugin at the version the lock took
    /// may not read what the sync read for a newer version it skipped: the
    /// JDK, or a host input of that version's POMs. Without the lock's
    /// choices only the JDK may be left unread, and the check may never
    /// read an input the tables do not list.
    #[test]
    fn a_held_plugin_version_may_leave_the_host_unread() {
        use rv_lock::AmbientInput::{JavaHome, JavaVersion, UserProperty};
        let files = |held: bool, inputs: &[rv_lock::AmbientInput]| {
            let mut files = rv_lock::PluginFiles::new(rv_maven_types::Sha256::from_bytes(b"in"));
            if held {
                files
                    .tables
                    .metadata_versions
                    .push(rv_lock::MetadataVersion {
                        group: "g".to_string(),
                        artifact: "p".to_string(),
                        kind: rv_lock::MetadataVersionKind::Release,
                        version: "1".to_string(),
                    });
            }
            files.tables.host_inputs = inputs.iter().cloned().collect();
            files
        };
        let entry = rv_lock::LockPlatform::new("linux-x86_64".parse().unwrap(), "");
        let drift = |held, resolved, capped| {
            super::plugin_drift(
                &entry,
                &held,
                &resolved,
                &rv_lock::RepoIds::new(),
                &declared(),
                capped,
            )
        };
        let staging = || UserProperty("apache.staging".to_string());
        for capped in [true, false] {
            assert_eq!(
                drift(files(true, &[JavaVersion]), files(true, &[]), capped),
                None
            );
            assert!(drift(files(false, &[JavaVersion]), files(false, &[]), capped).is_some());
            assert!(drift(files(true, &[]), files(true, &[JavaVersion]), capped).is_some());
            assert!(drift(files(true, &[]), files(true, &[staging()]), capped).is_some());
            assert!(drift(files(false, &[JavaHome]), files(false, &[]), capped).is_some());
            assert_eq!(
                drift(files(true, &[JavaHome]), files(true, &[JavaHome]), capped),
                None
            );
        }
        assert_eq!(
            drift(files(true, &[JavaHome, staging()]), files(true, &[]), true),
            None
        );
        assert!(drift(files(true, &[staging()]), files(true, &[]), false).is_some());
        assert!(drift(files(true, &[JavaHome]), files(true, &[]), false).is_some());
    }

    /// An id the tables record for a plugin repository other than the
    /// resolution's is drift: the export would label the files with it.
    #[test]
    fn a_plugin_repository_id_counts() {
        use rv_maven_types::Sha256;
        let files = |id: &str| {
            let mut files = rv_lock::PluginFiles::new(Sha256::from_bytes(b"inputs"));
            (files.tables.repo_ids).insert("https://r.example/".to_string(), [id.into()].into());
            files
        };
        let entry = rv_lock::LockPlatform::new("linux-x86_64".parse().unwrap(), "");
        let drift = |held, resolved| {
            super::plugin_drift(
                &entry,
                &held,
                &resolved,
                &rv_lock::RepoIds::new(),
                &declared(),
                true,
            )
        };
        assert_eq!(drift(files("vendor"), files("vendor")), None);
        assert!(drift(files("central"), files("vendor")).is_some());
        let mut added = files("vendor");
        (added.tables.repo_ids).insert("https://other.example/".to_string(), ["x".into()].into());
        assert!(drift(added, files("vendor")).is_some());
    }
}
