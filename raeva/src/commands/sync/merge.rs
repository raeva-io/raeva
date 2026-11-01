use std::collections::BTreeSet;

use foldhash::{HashMap, HashSet};

use rv_config::Config;
use rv_lock::drift::ResolutionDrift;
use rv_lock::merge::{Candidate, DropReason};
use rv_lock::{AmbientInput, Lockfile, ModelInputs, Platform};
use rv_maven_model::HostInput;
use rv_repo::Repository;

use super::resolve::{PlatformReads, check_origin_aliases};
use crate::commands::lock_inputs::{
    ReactorModel, command_line_names, consulted_ambient, declared_repository_urls,
    discover_reactor_model, recorded_ambient, resolution_config_hash,
};
use crate::error::{CliError, Result};
use crate::output::command_line;

pub(super) fn merge_previous(
    config: &Config,
    lock: &mut Lockfile,
    previous: Option<&Lockfile>,
    models: &[ReactorModel],
    reads: &PlatformReads,
    trusted_repositories: &[Repository],
) -> Result<()> {
    let resolved: Vec<_> = lock
        .platforms
        .iter()
        .map(|entry| entry.platform.clone())
        .collect();
    // Before preservation, whose discovery of the other platforms reads
    // names no graph of this run did.
    let (consulted, sources) = consulted_ambient(config, !reads.0.is_empty())?;
    bind_host_inputs(lock, models, reads, &consulted, &sources)?;
    let mut ambient = BTreeSet::new();
    if let Some(previous) = previous {
        let previous_ambient = recorded_ambient(previous);
        preserve_platforms(
            config,
            lock,
            previous,
            models,
            trusted_repositories,
            &resolution_config_hash(config, &previous_ambient)?,
        )?;
        // A kept platform's graphs read what the previous lock lists, and a
        // property name stays while a kept graph lists it.
        let kept_reads: HashSet<&AmbientInput> = (lock.platforms.iter())
            .filter(|entry| !resolved.contains(&entry.platform))
            .filter_map(|entry| entry.model_inputs.as_ref())
            .flat_map(ModelInputs::read_names)
            .collect();
        ambient = (previous_ambient.into_iter())
            .filter(|name| name.is_property_name() && kept_reads.contains(name))
            .collect();
    }
    bind_module_reads(lock, &resolved, &consulted);
    ambient.extend(consulted);
    // What the platforms consulted besides property names, which the kept
    // platforms carried forward with their own lists.
    ambient.retain(AmbientInput::is_property_name);
    ambient.extend(lock.resolution.ambient_inputs.iter().cloned());
    lock.config_hash = Some(resolution_config_hash(config, &ambient)?);
    lock.resolution.command_line = command_line_names(config, &ambient);
    lock.resolution.ambient_inputs = ambient;
    check_support_companion_agreement(lock)
}

/// Bind each platform of `lock`, all resolved by this run, to the names of
/// `consulted` other than property names that it consulted: those its
/// discovery in `models` and its builds read, by `sources`. One no platform
/// read that way, such as a settings.xml condition, counts for every one.
fn bind_host_inputs(
    lock: &mut Lockfile,
    models: &[ReactorModel],
    reads: &PlatformReads,
    consulted: &BTreeSet<AmbientInput>,
    sources: &HashMap<HostInput, AmbientInput>,
) -> Result<()> {
    let mut own: HashMap<&Platform, BTreeSet<AmbientInput>> = HashMap::default();
    for (platform, builds) in &reads.0 {
        let discovery = (models.iter())
            .filter(|model| model.platform == *platform)
            .flat_map(|model| model.reads.iter());
        let names = (builds.iter().flatten().chain(discovery))
            .filter_map(|input| sources.get(input))
            .cloned()
            .collect();
        own.insert(platform, names);
    }
    let claimed: HashSet<&AmbientInput> = own.values().flatten().collect();
    let shared: Vec<AmbientInput> = (consulted.iter())
        .filter(|input| !input.is_property_name() && !claimed.contains(input))
        .cloned()
        .collect();
    let mut target_reads = lock.target_reads();
    for (entry, read) in lock.platforms.iter().zip(&mut target_reads) {
        read.host_inputs = own.remove(&entry.platform).unwrap_or_default();
        read.host_inputs.extend(shared.iter().cloned());
    }
    Ok(lock.set_target_reads(&target_reads)?)
}

/// Fewer readers than this keep a name in their own lists: a name that
/// moves to the platform's list changes every graph digest of the platform,
/// and in a small reactor one module's edit can move it.
const COMMON_READERS: usize = 8;

/// Bind the graphs of the `resolved` platforms to the names of `consulted`
/// they read. A property name the run read that no graph it resolved
/// claims counts for every graph resolved, and so does a name most modules
/// of a large reactor read. A module lists only what its platform does not.
fn bind_module_reads(
    lock: &mut Lockfile,
    resolved: &[Platform],
    consulted: &BTreeSet<AmbientInput>,
) {
    // Large reactors list many names per module, so the lookups hash.
    let read: HashSet<&AmbientInput> = consulted.iter().collect();
    // The read names some platform lists. No module lists another name, so
    // the rest join the platforms' own list after the modules are bound.
    let mut claimed: HashSet<&AmbientInput> = HashSet::default();
    let fresh = (lock.platforms.iter_mut()).filter(|entry| resolved.contains(&entry.platform));
    for entry in fresh {
        let modules = entry.modules.len();
        let Some(inputs) = entry.model_inputs.as_mut() else {
            continue;
        };
        inputs.ambient_inputs.retain(|input| {
            read.get(input)
                .map(|&input| claimed.insert(input))
                .is_some()
        });
        let mut readers: HashMap<&AmbientInput, usize> = HashMap::default();
        for name in (inputs.module_ambient_inputs.values()).flatten() {
            *readers.entry(name).or_default() += 1;
        }
        let (mut common, mut own) = (Vec::new(), HashSet::default());
        for (name, count) in readers {
            let Some(&name) = read.get(name) else {
                continue;
            };
            if inputs.ambient_inputs.contains(name) {
                continue;
            }
            claimed.insert(name);
            if count >= COMMON_READERS && count * 2 > modules {
                common.push(name.clone());
            } else {
                own.insert(name);
            }
        }
        inputs.ambient_inputs.extend(common);
        for names in inputs.module_ambient_inputs.values_mut() {
            names.retain(|input| own.contains(input));
        }
    }
    let unclaimed: Vec<AmbientInput> = (consulted.iter())
        .filter(|input| input.is_property_name() && !claimed.contains(input))
        .cloned()
        .collect();
    let fresh = (lock.platforms.iter_mut()).filter(|entry| resolved.contains(&entry.platform));
    for inputs in fresh.filter_map(|entry| entry.model_inputs.as_mut()) {
        inputs.ambient_inputs.extend(unclaimed.iter().cloned());
    }
}

/// Preserve platform entries from the previous lockfile that this run did not
/// re-resolve. `raeva sync --platforms linux-x86_64` would otherwise overwrite
/// the on-disk lockfile with only the requested platform and silently drop
/// every other platform's pins (data loss for cross-platform CI matrices that
/// sync each platform from its own runner).
///
/// `config_hash` is this run's, which `lock` was just resolved under.
pub(super) fn preserve_platforms(
    config: &Config,
    lock: &mut Lockfile,
    previous: &Lockfile,
    models: &[ReactorModel],
    trusted_repositories: &[Repository],
    config_hash: &str,
) -> Result<()> {
    let mut kept = Vec::new();
    let mut preserved_models = Vec::new();
    for Candidate {
        platform, dropped, ..
    } in rv_lock::merge::preservation(lock, previous, config_hash)
    {
        let current_jdk = match platform.jdk() {
            None => config.lock.jdks.is_empty(),
            Some(jdk) => config.lock.jdks.iter().any(|configured| configured == jdk),
        };
        if !current_jdk
            && lock
                .platforms
                .iter()
                .any(|entry| entry.platform.os_arch() == platform.os_arch())
        {
            continue;
        }
        let system_drift = previous
            .platforms
            .iter()
            .find(|entry| entry.platform == platform)
            .and_then(|entry| entry.system_file_drift(&config.project_root));
        let reason = match (dropped, system_drift) {
            (Some(reason), _) => reason,
            (None, Some(ResolutionDrift::SystemFile { path })) => {
                DropReason::SystemFileChanged { path }
            }
            (None, _) => match discover_reactor_model(config, &platform) {
                Ok(model)
                    if previous
                        .platforms
                        .iter()
                        .any(|entry| entry.platform == platform)
                        && model.matches(previous) =>
                {
                    kept.push(platform);
                    preserved_models.push(model);
                    continue;
                }
                Ok(_) => DropReason::ModelChanged,
                Err(err) => DropReason::ModelUnavailable {
                    error: err.to_string(),
                },
            },
        };
        // A JSON consumer loses the platform's pins too, so this is a
        // warning with a code, not only a log line.
        let sync = command_line("sync");
        let os_arch = platform.os_arch();
        tracing::warn!(
            sec_code = "PLATFORM_DROPPED",
            platform = %platform,
            "Dropping stale platform {platform}: {reason}; run `{sync} --platforms {os_arch}` to re-sync it"
        );
    }
    rv_lock::merge::carry_forward(lock, previous, &kept)?;
    // Each platform's declarations were alias-free on their own, but the
    // lock now records origins for the preserved platforms too, so two
    // spellings split across platforms would still share one token.
    check_origin_aliases(
        config,
        declared_repository_urls(config, models)
            .chain(declared_repository_urls(config, &preserved_models))
            .chain(trusted_repositories.iter().map(|repo| repo.url.clone())),
    )
}

/// Refuse to write a lockfile whose support-POM block and artifact rows pin
/// one coordinate's `.pom` two ways.
///
/// `Lockfile::write_atomic` validates this too, for every consumer at once;
/// running it here names the coordinate and the recovery in `raeva sync`'s own
/// terms, before the temp file is created.
pub(super) fn check_support_companion_agreement(lock: &Lockfile) -> Result<()> {
    let Some(coord) = lock.support_companion_conflict() else {
        return Ok(());
    };
    Err(CliError::Message(format!(
        "resolution pinned two different POMs for {coord}: it was resolved both as a \
         parent/imported BOM and as a dependency, and Maven has one local-repository path per \
         coordinate. Re-run `{sync}` after clearing raeva.lock, or report this if it persists",
        sync = command_line("sync")
    )))
}
