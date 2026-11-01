//! Gathering what a lockfile is checked against: the inputs `config_hash`
//! and `model_hash` cover, from configuration and the reactor model
//! discovered from local files. The recipes and the comparison with a
//! recorded lockfile are in [`rv_lock::inputs`].

#[cfg(test)]
mod golden_hashes;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rv_config::{Config, UpdatePolicy};
use rv_lock::inputs::{
    ConfigDrift, CurrentModel, CurrentModule, LocalParentInput, ModuleInput, ReactorInputs,
    RepositoryInputs, ResolutionInputs, SettingsProfileInput, config_hash, model_hash,
};
use rv_lock::{AmbientInput, HostCondition, Lockfile, Platform};
use rv_maven_model::{HostInput, HostReads, HostSnapshot};
use rv_repo::Repository;
use rv_resolver::{Workspace, WorkspaceError};

use crate::error::{CliError, Result};

/// Gather what `config_hash` covers from `config`, reading
/// effective `-P` selections from both option sources and the current values
/// of the consulted host and user-property inputs named in `ambient`. The update and checksum policies are recorded with the
/// defaults resolution applies, as their `Display` and `Debug` text.
///
/// Which settings.xml profiles a condition activates depends on the
/// platform, so the active profiles and repositories here are those of the
/// explicitly active profiles, and the conditional profiles are covered by
/// their definitions.
pub(crate) fn resolution_inputs(
    config: &Config,
    ambient: &BTreeSet<AmbientInput>,
) -> Result<ResolutionInputs> {
    let explicit = config.for_platforms([]);
    let names = ambient
        .iter()
        .filter_map(|input| match input {
            AmbientInput::UserProperty(name) => Some(name.clone()),
            _ => None,
        })
        .collect();
    let user_properties = config.user_property_values(&names);
    Ok(ResolutionInputs {
        profile_selections: config.maven_profile_selections(),
        active_profiles: explicit.active_profiles().to_vec(),
        inactive_profiles: config.inactive_profiles.clone(),
        repositories: explicit
            .repositories()
            .iter()
            .map(|repo| RepositoryInputs {
                id: repo.id.clone(),
                url: repo.url.clone(),
                releases: repo.releases,
                snapshots: repo.snapshots,
                snapshots_update_policy: repo
                    .snapshots_update_policy
                    .unwrap_or_default()
                    .to_string(),
                releases_update_policy: repo
                    .releases_update_policy
                    .unwrap_or(UpdatePolicy::Daily)
                    .to_string(),
                releases_checksum_policy: format!(
                    "{:?}",
                    repo.releases_checksum_policy.unwrap_or_default()
                ),
                snapshots_checksum_policy: format!(
                    "{:?}",
                    repo.snapshots_checksum_policy.unwrap_or_default()
                ),
            })
            .collect(),
        allow_transitive_repositories: config.security.allow_transitive_repositories,
        allow_env_substitution: config.security.allow_env_substitution.clone(),
        transitive_repository_allowlist: config.security.transitive_repository_allowlist.clone(),
        jdks: config.lock.jdks.clone(),
        settings_profiles: config
            .conditional_settings_profiles()
            .into_iter()
            .map(|(id, content)| SettingsProfileInput { id, content })
            .collect(),
        // An active settings.xml profile sets a listed property that no `-D`
        // sets, whether or not the lock lists it as a settings property.
        ambient: (ambient.iter())
            .flat_map(|name| {
                let value = match name {
                    AmbientInput::UserProperty(name) => {
                        user_properties.get(name).cloned().flatten()
                    }
                    _ => current_value(config, name),
                };
                let settings = settings_companion(name)
                    .filter(|settings| value.is_none() && !ambient.contains(settings))
                    .map(|settings| {
                        let value = current_value(config, &settings);
                        (settings, value)
                    });
                std::iter::once((name.clone(), value)).chain(settings)
            })
            .collect(),
    })
}

/// The lockfile's top-level configuration hash for `config`, with the
/// current values of the host inputs named in `ambient`; see
/// [`rv_lock::inputs::config_hash`].
pub(crate) fn resolution_config_hash(
    config: &Config,
    ambient: &BTreeSet<AmbientInput>,
) -> Result<String> {
    Ok(config_hash(&resolution_inputs(config, ambient)?))
}

/// [`resolution_config_hash`] with each condition in `ambient` at the
/// outcome recorded there: what the configuration alone decides. A check
/// whose models changed uses it, since its resolution compares again the
/// conditions both sides consulted.
pub(crate) fn recorded_outcome_config_hash(
    config: &Config,
    ambient: &BTreeSet<AmbientInput>,
) -> Result<String> {
    let mut inputs = resolution_inputs(config, ambient)?;
    for (input, value) in inputs.ambient.iter_mut() {
        if let AmbientInput::Condition { holds, .. } = input {
            *value = Some(holds.to_string());
        }
    }
    Ok(config_hash(&inputs))
}

pub(crate) fn recorded_ambient(lock: &Lockfile) -> BTreeSet<AmbientInput> {
    lock.resolution.ambient_inputs.clone()
}

/// Past this many `<jdk>` and `<property>` conditions, a lock lists the host
/// values they test instead, so a hostile dependency tree cannot grow
/// raeva.lock without bound.
const MAX_HOST_CONDITIONS: usize = 1024;

/// The most `<file>` conditions a lock records. Each module tests its own
/// paths, so a large reactor with a shared parent reaches far more than
/// [`MAX_HOST_CONDITIONS`].
const MAX_FILE_CONDITIONS: usize = 65_536;

/// The host inputs the model builds of this run read so far, each
/// condition with its outcome on this host, and the settings.xml conditions
/// that decided a profile with repositories. A `<file>` condition in the
/// project has no host value to record instead, so one raeva.lock cannot
/// hold, or one past [`MAX_FILE_CONDITIONS`], fails the sync.
///
/// With `sources`, also each host input that became a name other than a
/// property or variable name, with that name.
pub(crate) fn consulted_ambient(
    config: &Config,
    sources: bool,
) -> Result<(
    BTreeSet<AmbientInput>,
    foldhash::HashMap<HostInput, AmbientInput>,
)> {
    let host = config.host();
    let mut consulted = host.consulted();
    consulted.extend(host.consulted_file_lookups());
    consulted.extend(
        host.consulted_user_properties()
            .into_iter()
            .map(HostInput::UserProperty),
    );
    let conditions = consulted
        .iter()
        .filter(|input| matches!(input, HostInput::Jdk(_) | HostInput::Property { .. }))
        .count();
    let roots = [
        Some(config.project_root.clone()),
        dunce::canonicalize(&config.project_root).ok(),
    ];
    let refuse = |reason: String| CliError::InvalidProjectInput {
        path: config.project_root.join("pom.xml"),
        reason,
    };
    let portable_base = |base_dir: &Option<PathBuf>| -> Result<Option<String>> {
        base_dir
            .as_ref()
            .map(|base| {
                let base = dunce::canonicalize(base).unwrap_or_else(|_| base.clone());
                let relative = roots
                    .iter()
                    .flatten()
                    .find_map(|root| base.strip_prefix(root).ok())
                    .ok_or_else(|| {
                        refuse("a private file activation is based outside the project root".into())
                    })?;
                let names = relative
                    .components()
                    .map(|component| match component {
                        Component::Normal(name) => name.to_str(),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| {
                        refuse(
                            "a private file activation has an unsupported local POM directory"
                                .into(),
                        )
                    })?;
                Ok::<_, CliError>(names.join("/"))
            })
            .transpose()
    };
    let mut ambient = BTreeSet::new();
    let mut by_input = foldhash::HashMap::default();
    for input in consulted {
        let recorded = match &input {
            HostInput::FileLookup {
                expression,
                properties,
                base_dir,
                default_packaging,
                source,
            } => {
                let base_dir = portable_base(base_dir)?;
                Some(AmbientInput::file_lookup(
                    expression,
                    properties,
                    base_dir,
                    default_packaging.clone(),
                    *source,
                ))
            }
            HostInput::InterpolationLookup {
                expression,
                properties,
                source,
                default_packaging,
                model,
                model_interpolation,
                ..
            } => {
                let mut model = model.clone();
                if let Some(model) = &mut model {
                    model.base_dir = portable_base(&model.base_dir)?.map(PathBuf::from);
                }
                Some(AmbientInput::interpolation_lookup(
                    expression,
                    properties,
                    default_packaging.clone(),
                    *source,
                    model,
                    *model_interpolation,
                ))
            }
            HostInput::File(path) => match project_file(&roots, path) {
                Some(None) => {
                    return Err(refuse(
                        "a <file> condition in its models names a project file raeva.lock \
                         cannot record: a path over 256 characters, one ending in `/.`, or \
                         one that is not valid UTF-8"
                            .to_string(),
                    ));
                }
                file => file.flatten(),
            },
            HostInput::UserProperty(name) => {
                Some(AmbientInput::user_property(name).map_err(|_| {
                    refuse(
                        "a consulted user-property name cannot be recorded in raeva.lock"
                            .to_string(),
                    )
                })?)
            }
            HostInput::SettingsProperty(name) => match AmbientInput::settings_property(name) {
                Ok(recorded) => Some(recorded),
                Err(_) => {
                    return Err(refuse(
                        "its models read a settings.xml profile property whose name raeva.lock \
                         cannot record: a name must be 1 to 128 ASCII letters, digits, `.`, `-` \
                         or `_`"
                            .to_string(),
                    ));
                }
            },
            input => ambient_input(host, input, conditions <= MAX_HOST_CONDITIONS),
        };
        let Some(recorded) = recorded else {
            continue;
        };
        if sources && !recorded.is_property_name() {
            by_input.insert(input, recorded.clone());
        }
        ambient.insert(recorded);
    }
    let files = ambient
        .iter()
        .filter(|input| {
            matches!(
                input,
                AmbientInput::Condition {
                    condition: HostCondition::File(_),
                    ..
                }
            )
        })
        .count();
    if files > MAX_FILE_CONDITIONS {
        return Err(refuse(format!(
            "its models test more than {MAX_FILE_CONDITIONS} <file> conditions in the \
             project, which raeva.lock does not record"
        )));
    }
    let settings = config.consulted_settings_conditions();
    ambient.extend(settings.iter().filter_map(|key| {
        let (_, holds) = config.settings_condition(key)?;
        AmbientInput::settings(key, holds).ok()
    }));
    Ok((ambient, by_input))
}

/// The `<file>` condition on `text` as raeva.lock records it: `None` for a
/// path outside every one of `roots`, the project directory, or naming that
/// directory, which exists, and `Some(None)` for one inside that raeva.lock
/// cannot hold.
fn project_file(roots: &[Option<PathBuf>], text: &str) -> Option<Option<AmbientInput>> {
    let path = Path::new(text);
    // `..` decides by name whether the path is in the project, as a module's
    // `${project.basedir}/..` climbs to the reactor root. The recorded path
    // keeps it, for the filesystem to resolve as it resolved it here.
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            component => normalized.push(component),
        }
    }
    let root = roots
        .iter()
        .flatten()
        .find(|root| normalized.starts_with(root))?;
    let names: Option<Vec<&str>> = path.strip_prefix(root).ok().and_then(|relative| {
        relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => name.to_str(),
                Component::ParentDir => Some(".."),
                _ => None,
            })
            .collect()
    });
    if names.as_ref().is_some_and(Vec::is_empty) {
        return None;
    }
    // A final `.` tests for a directory, and the recorded path has no `.`.
    if text.ends_with("/.") || text.ends_with("\\.") {
        return Some(None);
    }
    Some(names.and_then(|names| AmbientInput::file(&names.join("/"), path.exists()).ok()))
}

/// `input`, other than a file, as raeva.lock records it. A condition
/// raeva.lock cannot hold, or any condition when `conditions` is false, is
/// recorded as the host value it tests.
fn ambient_input(host: &HostSnapshot, input: &HostInput, conditions: bool) -> Option<AmbientInput> {
    let condition = match input {
        HostInput::JavaVersion => return Some(AmbientInput::JavaVersion),
        HostInput::JavaHome => return Some(AmbientInput::JavaHome),
        HostInput::OsRelease => return Some(AmbientInput::OsRelease),
        // The allowlist admits only names raeva.lock can record.
        HostInput::Env(name) => return AmbientInput::env(name).ok(),
        HostInput::SettingsProperty(name) => return AmbientInput::settings_property(name).ok(),
        HostInput::UserProperty(name) => return AmbientInput::user_property(name).ok(),
        HostInput::UserPropertyLookup {
            expression,
            properties,
            default_packaging,
            source,
            ..
        } => {
            return Some(AmbientInput::user_property_lookup(
                expression,
                properties,
                default_packaging.clone(),
                *source,
            ));
        }
        HostInput::File(_)
        | HostInput::FileLookup { .. }
        | HostInput::InterpolationLookup { .. } => return None,
        HostInput::Jdk(spec) => conditions
            .then(|| AmbientInput::jdk(spec, host.holds(input)?).ok())
            .flatten(),
        HostInput::Property { name, value } => conditions
            .then(|| AmbientInput::property(name, value.as_deref(), host.holds(input)?).ok())
            .flatten(),
    };
    condition.or_else(|| match input {
        HostInput::Property { name, .. } => {
            let name = name.strip_prefix('!').unwrap_or(name);
            match name {
                "java.home" => Some(AmbientInput::JavaHome),
                "java.version" => Some(AmbientInput::JavaVersion),
                _ => AmbientInput::env(name.strip_prefix("env.")?).ok(),
            }
        }
        _ => Some(AmbientInput::JavaVersion),
    })
}

/// The settings property of the name a user property reads.
fn settings_companion(name: &AmbientInput) -> Option<AmbientInput> {
    match name {
        AmbientInput::UserProperty(name) => Some(AmbientInput::SettingsProperty(name.clone())),
        _ => None,
    }
}

/// What `config_hash` covers for `name` in `config`: a value, or for a
/// condition its current outcome.
fn current_value(config: &Config, name: &AmbientInput) -> Option<String> {
    let host = config.host();
    match name {
        AmbientInput::JavaVersion => host.value(&HostInput::JavaVersion),
        AmbientInput::JavaHome => host.value(&HostInput::JavaHome),
        AmbientInput::OsRelease => host.value(&HostInput::OsRelease),
        AmbientInput::Env(name) => host.value(&HostInput::Env(name.clone())),
        AmbientInput::SettingsProperty(name) => config.settings_property_value(name),
        AmbientInput::UserPropertyLookup(template) => config.user_property_lookup_value(template),
        AmbientInput::UserProperty(name) => config
            .user_property_values(&BTreeSet::from([name.clone()]))
            .remove(name)
            .flatten(),
        AmbientInput::Condition { condition, .. } => {
            condition_holds(config, condition).map(|holds| holds.to_string())
        }
    }
}

fn condition_holds(config: &Config, condition: &HostCondition) -> Option<bool> {
    let input = match condition {
        HostCondition::Jdk(spec) => HostInput::Jdk(spec.clone()),
        HostCondition::Property { name, value } => HostInput::Property {
            name: name.clone(),
            value: value.clone(),
        },
        HostCondition::File(path) => return Some(config.project_root.join(path).exists()),
        HostCondition::Settings(key) => {
            return config.settings_condition(key).map(|(_, holds)| holds);
        }
    };
    config.host().holds(&input)
}

/// The `-D` overrides of the user properties `ambient` lists and the command
/// line's `-P` options by name,
/// as raeva.lock records them in `[resolution] command_line`. A name raeva.lock cannot hold is left
/// out; `config_hash` still covers it.
pub(crate) fn command_line_names(
    config: &Config,
    ambient: &BTreeSet<AmbientInput>,
) -> BTreeSet<String> {
    let names = (ambient.iter())
        .filter_map(|input| match input {
            AmbientInput::UserProperty(name) => Some(name.clone()),
            _ => None,
        })
        .collect();
    option_names(config, &names)
}

fn option_names(config: &Config, names: &BTreeSet<String>) -> BTreeSet<String> {
    let command_line = config.command_line();
    let properties = config.user_property_values(names);
    let defines = properties
        .iter()
        .filter(|(_, value)| value.is_some())
        .map(|(name, _)| format!("-D{name}"));
    let profiles = (command_line.profiles.iter())
        .flat_map(|list| list.split(','))
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| format!("-P{id}"));
    defines
        .chain(profiles)
        .filter(|option| rv_lock::is_command_line_name(option))
        .collect()
}

/// The options added and removed since raeva.lock was written, by name.
fn command_line_change(config: &Config, lock: &Lockfile) -> Option<String> {
    let mut names = config.host().consulted_user_properties();
    names.extend(
        lock.resolution
            .ambient_inputs
            .iter()
            .filter_map(|input| match input {
                AmbientInput::UserProperty(name) => Some(name.clone()),
                _ => None,
            }),
    );
    let now = option_names(config, &names);
    let then = &lock.resolution.command_line;
    // Both sides hold only terminal-safe names.
    let list = |names: Vec<&String>| crate::commands::util::join_and(names.into_iter().cloned());
    let added: Vec<&String> = now.difference(then).collect();
    let removed: Vec<&String> = then.difference(&now).collect();
    let mut clauses = Vec::new();
    if !added.is_empty() {
        let (is, was) = if added.len() == 1 {
            ("is", "was")
        } else {
            ("are", "were")
        };
        clauses.push(format!(
            "{} {is} set here and {was} not when raeva.lock was written",
            list(added)
        ));
    }
    if !removed.is_empty() {
        let is = if removed.len() == 1 { "is" } else { "are" };
        clauses.push(format!(
            "raeva.lock was written with {}, which {is} not set here",
            list(removed)
        ));
    }
    (!clauses.is_empty()).then(|| {
        format!(
            "{}; pass the same options, or run 'raeva sync' with these to relock",
            clauses.join(", and ")
        )
    })
}

/// How many changed conditions a message names.
const SHOWN_CONDITIONS: usize = 5;

/// Why `config_hash` differs, naming recorded conditions and option names,
/// or the active profiles `models` changed. Value-bearing inputs have no
/// separate diagnostic hashes.
pub(crate) fn config_changed(config: &Config, lock: &Lockfile, models: &[ReactorModel]) -> String {
    let flipped: Vec<String> = recorded_ambient(lock)
        .iter()
        .filter_map(|input| {
            let AmbientInput::Condition { condition, holds } = input else {
                return None;
            };
            let now = condition_holds(config, condition)?;
            (now != *holds).then(|| {
                let text = match condition {
                    HostCondition::Settings(key) => match config.settings_condition(key) {
                        Some((text, _)) => format!("settings.xml {text}"),
                        None => condition.to_string(),
                    },
                    _ => condition.to_string(),
                };
                format!("{} was {holds}, now {now}", rv_maven_types::bounded(&text))
            })
        })
        .collect();
    let options = command_line_change(config, lock);
    let mut changed = Vec::new();
    if !flipped.is_empty() {
        let mut conditions = format!(
            "host conditions: {}",
            flipped[..flipped.len().min(SHOWN_CONDITIONS)].join(", ")
        );
        if flipped.len() > SHOWN_CONDITIONS {
            conditions.push_str(&format!(" and {} more", flipped.len() - SHOWN_CONDITIONS));
        }
        changed.push(conditions);
    }
    if let Some(options) = options {
        changed.push(COMMAND_LINE.to_string());
        return format!(
            "{CONFIG_CHANGED} in {}: {options}",
            crate::commands::util::join_and(changed)
        );
    }
    let current: Vec<CurrentModel> = models.iter().map(|model| model.current(lock)).collect();
    let profiles = match lock.model_drift(&current) {
        Some(drift @ rv_lock::inputs::ModelDrift::Profiles { .. }) => Some(drift.to_string()),
        _ => None,
    };
    match (changed.is_empty(), profiles) {
        (true, Some(profiles)) => format!("{CONFIG_CHANGED}: {profiles}"),
        (true, None) => format!(
            "{CONFIG_CHANGED} since raeva.lock was written; raeva.lock covers the repositories, \
             profiles, [lock] jdks, [security], .mvn/maven.config, {COMMAND_LINE} and \
             {HOST_VALUES}"
        ),
        (false, profiles) => format!(
            "{CONFIG_CHANGED} in {}{}",
            crate::commands::util::join_and(changed),
            profiles.map_or_else(String::new, |profiles| format!("; {profiles}"))
        ),
    }
}

const COMMAND_LINE: &str = "the -D and -P options";

const HOST_VALUES: &str = "the host values under ambient_inputs";

#[derive(Debug, Clone)]
pub(crate) struct ReactorModel {
    pub(crate) platform: Platform,
    pub(crate) workspace: Workspace,
    pub(crate) model_hash: String,
    pub(crate) active_profiles: Vec<String>,
    pub(crate) pom_hashes: BTreeMap<String, rv_maven_types::Sha256>,
    /// Per module path, the reactor modules its POM record covers, `None`
    /// for all of them. See [`rv_resolver::ModuleContext::covers`].
    pub(crate) covers: BTreeMap<String, Option<BTreeSet<String>>>,
    /// See [`rv_lock::inputs::ModelHash::whole_reactor_hash`].
    pub(crate) whole_reactor_hash: String,
    pub(crate) whole_reactor_pom_hashes: BTreeMap<String, rv_maven_types::Sha256>,
    /// The host inputs discovery read.
    pub(crate) reads: Arc<BTreeSet<HostInput>>,
}

impl ReactorModel {
    /// Repositories the project's own POMs declare (root, reactor modules and
    /// accepted local parents, active profiles included), interpolated. These
    /// are the only POM declarations a check that runs without resolution may
    /// trust; a dependency's POM never contributes one.
    pub(crate) fn declared_repositories(&self) -> impl Iterator<Item = Repository> + '_ {
        self.workspace
            .modules()
            .iter()
            .flat_map(|module| &module.descriptor.repositories)
            .filter(|repo| repo.root_declared)
            .map(Repository::from)
    }

    /// Whether `lock`'s graph of this platform can be trusted; see
    /// [`frozen_models_match`]. A platform `lock` does not record matches.
    pub(crate) fn matches(&self, lock: &Lockfile) -> bool {
        let Some(entry) = (lock.platforms.iter()).find(|entry| entry.platform == self.platform)
        else {
            return true;
        };
        if !entry.graphs_match(
            lock.config_hash.as_deref(),
            &lock.resolution.ambient_inputs,
            &lock.repo_ids,
        ) || !lock.models_match(&[self.current(lock)])
        {
            return false;
        }
        let whole = self.whole_reactor_in(lock);
        let gavs = self.gavs(lock);
        let reactor: HashSet<(&str, &str, &str)> = (gavs.iter())
            .map(|(_, (group, artifact, version))| {
                (group.as_str(), artifact.as_str(), version.as_str())
            })
            .collect();
        let is_reactor = |group: &str, artifact: &str, version: &str| {
            let base = rv_maven_types::snapshot_base_version(version);
            reactor.contains(&(group, artifact, base.as_deref().unwrap_or(version)))
        };
        let support = entry.support_poms.keys().any(|coord| {
            rv_lock::split_support_pom_coord(coord)
                .is_some_and(|(group, artifact, version)| is_reactor(group, artifact, version))
        });
        !support
            && entry.modules.iter().all(|module| {
                let covers = (self.covers.get(&module.path))
                    .and_then(Option::as_ref)
                    .filter(|_| !whole);
                module
                    .packages
                    .iter()
                    .all(|package| match &package.workspace_module {
                        Some(path) => covers
                            .is_none_or(|covers| *path == module.path || covers.contains(path)),
                        None => {
                            let gav = &package.coordinate.gav;
                            package.system_sha256.is_some()
                                || !is_reactor(&gav.group, &gav.artifact, gav.version())
                        }
                    })
            })
    }

    /// Whether `lock` records this platform with whole-reactor records:
    /// they differ from the current ones for fewer POMs than the others.
    fn whole_reactor_in(&self, lock: &Lockfile) -> bool {
        let Some(inputs) = (lock.platforms.iter())
            .find(|entry| entry.platform == self.platform)
            .and_then(|entry| entry.model_inputs.as_ref())
        else {
            return false;
        };
        let differing = |current: &BTreeMap<String, rv_maven_types::Sha256>| {
            (inputs.pom_hashes.iter())
                .filter(|(path, digest)| current.get(*path) != Some(*digest))
                .count()
        };
        differing(&self.whole_reactor_pom_hashes) < differing(&self.pom_hashes)
    }

    /// Each module's path and effective GAV. Discovery cannot know a GAV a
    /// remote parent decides; its record covers that parent's coordinates,
    /// so the GAV `lock` records for the path stands.
    fn gavs(&self, lock: &Lockfile) -> Vec<(&str, (String, String, String))> {
        let locked = (lock.platforms.iter())
            .find(|entry| entry.platform == self.platform)
            .map_or(&[][..], |entry| entry.modules.as_slice());
        (self.workspace.modules().iter())
            .map(|module| {
                let recorded = (module.descriptor.gav_is_provisional())
                    .then(|| locked.iter().find(|locked| locked.path == module.pom_path))
                    .flatten();
                let gav = match recorded {
                    Some(locked) => (
                        locked.gav.group.to_string(),
                        locked.gav.artifact.to_string(),
                        locked.gav.version().to_owned(),
                    ),
                    None => {
                        let gav = module.gav();
                        (
                            gav.group_id.clone(),
                            gav.artifact_id.clone(),
                            gav.version.clone(),
                        )
                    }
                };
                (module.pom_path.as_str(), gav)
            })
            .collect()
    }

    /// This model as `lock` records it.
    pub(crate) fn current(&self, lock: &Lockfile) -> CurrentModel {
        let whole = self.whole_reactor_in(lock);
        CurrentModel {
            platform: self.platform.clone(),
            model_hash: if whole {
                &self.whole_reactor_hash
            } else {
                &self.model_hash
            }
            .clone(),
            active_profiles: self.active_profiles.clone(),
            modules: (self.gavs(lock).into_iter())
                .map(|(path, (group, artifact, version))| CurrentModule {
                    path: path.to_owned(),
                    group,
                    artifact,
                    version,
                })
                .collect(),
            pom_hashes: if whole {
                &self.whole_reactor_pom_hashes
            } else {
                &self.pom_hashes
            }
            .clone(),
        }
    }
}

/// Refuse a project whose POMs declare a repository URL with userinfo, a
/// query or a fragment, as configuration with one is refused: raeva.lock would
/// record it. The message names the module, never the URL, which may be
/// inherited from a local parent.
fn refuse_secret_repository_urls(
    root: &Path,
    modules: &[&rv_resolver::WorkspaceModule],
) -> Result<()> {
    for module in modules {
        let declared = module
            .descriptor
            .repositories
            .iter()
            .filter(|repo| repo.root_declared);
        for repo in declared {
            if let Some(part) = rv_config::secret_url_part(&repo.url) {
                return Err(CliError::InvalidProjectInput {
                    path: root.join(&module.pom_path),
                    reason: format!(
                        "a <repository> URL it declares or inherits has {part}, which raeva.lock \
                         would record; remove it, and put credentials in an [[auth]] entry in \
                         config.toml or a <server> in settings.xml with the repository's id"
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Discover and hash one platform's reactor model without repository access.
///
/// The inputs are those [`rv_lock::inputs::model_hash`] describes: every
/// active module's root-relative path, effective GAV and POM bytes, the
/// active profile ids, and every local parent POM the resolver accepts (see
/// [`Workspace::local_parent_poms`]), labeled root-relatively.
/// Warn, as Maven 3.9 does, for each requested profile id that no module's
/// POM lineage activates on any platform and no settings.xml profile has.
/// A parent discovery did not read may have the profile, so a reactor with
/// one gets no warning.
fn warn_unknown_profiles(config: &Config, models: &[ReactorModel]) {
    let Some(first) = models.first() else {
        return;
    };
    let modules = || models.iter().flat_map(|model| model.workspace.modules());
    if modules().any(|module| module.descriptor.has_unread_parent) {
        return;
    }
    let (selected, deselected) = first.workspace.profile_options();
    let known: HashSet<&str> = modules()
        .flat_map(|module| module.descriptor.selected_profiles().iter().flatten())
        .map(String::as_str)
        .chain(config.settings_profile_ids())
        .collect();
    for id in config.active_profiles().iter().chain(selected) {
        let off = deselected.contains(id) || config.inactive_profiles.contains(id);
        if !off && !known.contains(id.as_str()) {
            tracing::warn!(
                sec_code = "PROFILE_NOT_FOUND",
                "requested profile '{}' is not defined in any project POM, its parents or \
                 settings.xml, so it activates nothing",
                rv_maven_types::bounded(id)
            );
        }
    }
}

pub(crate) fn discover_reactor_model(config: &Config, platform: &Platform) -> Result<ReactorModel> {
    let reads = HostReads::default();
    let config = &(config.recording_into(&reads)).for_platforms([(
        platform.os(),
        platform.arch(),
        platform.jdk(),
    )]);
    let workspace = Workspace::discover_project(config, Some(platform))
        .map_err(|err| discovery_error(&config.project_root, err))?;

    let mut modules: Vec<_> = workspace.modules().iter().collect();
    modules.sort_by(|left, right| left.pom_path.cmp(&right.pom_path));
    refuse_secret_repository_urls(workspace.root(), &modules)?;

    // The settings.xml profiles a condition activates add only repositories,
    // which config_hash covers, so only the explicit ids count.
    let mut active_profiles: BTreeSet<String> = config.active_profiles().iter().cloned().collect();
    let mut module_inputs = Vec::with_capacity(modules.len());
    let mut resolution_contexts = workspace.resolution_contexts();
    let mut covers = BTreeMap::new();
    for module in modules {
        let bytes = rv_config::read_project_input(&workspace.root().join(&module.pom_path))?;
        active_profiles.extend(module.descriptor.active_profiles.iter().cloned());
        let gav = module.gav();
        module_inputs.push(ModuleInput {
            path: module.pom_path.clone(),
            group: gav.group_id.clone(),
            artifact: gav.artifact_id.clone(),
            version: gav.version.clone(),
            pom: bytes,
            active_profiles: module.descriptor.active_profiles.clone(),
            resolution_context: {
                let context = resolution_contexts
                    .remove(&module.pom_path)
                    .expect("module context");
                covers.insert(module.pom_path.clone(), context.covers);
                context.values
            },
        });
    }

    let mut local_parents: BTreeMap<&Path, LocalParentInput> = BTreeMap::new();
    for parent in workspace.local_parent_poms() {
        let label_path =
            pathdiff::diff_paths(parent, workspace.root()).unwrap_or_else(|| parent.clone());
        local_parents.insert(
            parent,
            LocalParentInput {
                label: label_path.to_string_lossy().replace('\\', "/"),
                pom: rv_config::read_project_input(parent)?,
            },
        );
    }

    let inputs = ReactorInputs {
        modules: module_inputs,
        active_profiles: active_profiles.into_iter().collect(),
        local_parents: local_parents.into_values().collect(),
    };
    let hashed = model_hash(&inputs);

    Ok(ReactorModel {
        platform: platform.clone(),
        workspace,
        model_hash: hashed.hash,
        active_profiles: inputs.active_profiles,
        pom_hashes: hashed.pom_hashes,
        covers,
        whole_reactor_hash: hashed.whole_reactor_hash,
        whole_reactor_pom_hashes: hashed.whole_reactor_pom_hashes,
        reads: Arc::new(reads.take()),
    })
}

/// A reactor that cannot be discovered is invalid project input, such as a
/// module that does not exist, except when a file could not be read.
fn discovery_error(project_root: &Path, err: WorkspaceError) -> CliError {
    match err {
        WorkspaceError::Io { path, source } if source.kind() == std::io::ErrorKind::NotFound => {
            CliError::InvalidProjectInput {
                path: path.into(),
                reason: source.to_string(),
            }
        }
        WorkspaceError::Io { path, source } => CliError::io_at(path)(source),
        WorkspaceError::InvalidPom { path, source } => CliError::InvalidProjectInput {
            path: path.into(),
            reason: source.to_string(),
        },
        WorkspaceError::InvalidMavenConfig { path, source } => CliError::InvalidProjectInput {
            path: path.into(),
            reason: source.to_string(),
        },
        WorkspaceError::ProjectInputTooLarge { path, limit } => CliError::InvalidProjectInput {
            path: path.into(),
            reason: format!("exceeds the {limit}-byte project input limit"),
        },
        other => CliError::InvalidProjectInput {
            path: project_root.join("pom.xml"),
            reason: format!("failed to discover Maven reactor: {other}"),
        },
    }
}

/// The URLs the project's own POMs declare in `models`.
pub(crate) fn declared_repository_urls<'a>(
    config: &Config,
    models: &'a [ReactorModel],
) -> impl Iterator<Item = String> + 'a {
    rv_repo::RepositoryPolicy::screen(
        config,
        models.iter().flat_map(ReactorModel::declared_repositories),
        rv_repo::Declaration::LocalPom,
    )
    .admitted
    .into_iter()
    .map(|repo| repo.url)
}

/// The current project for one platform, discovered from local files only.
#[derive(Debug, Clone)]
pub(crate) struct LocalProject {
    pub(crate) module_poms: Vec<rv_export::ProjectPom>,
    /// The active modules' effective coordinates, as sync recorded them or,
    /// for a module raeva.lock does not list, as discovery interpolates them.
    pub(crate) modules: Vec<rv_maven_types::Gav>,
    pub(crate) declared_repositories: Vec<Repository>,
}

/// The current project `model` describes, discovered from local files only,
/// for commands that must not take module paths or repositories from
/// raeva.lock. Only the coordinates of a module come from its `recorded`
/// entry: local discovery reads no remote parent, which may decide them.
pub(crate) fn local_project(
    config: &Config,
    model: &ReactorModel,
    recorded: &[rv_lock::LockModule],
) -> LocalProject {
    LocalProject {
        module_poms: model
            .workspace
            .modules()
            .iter()
            .map(|module| rv_export::ProjectPom {
                local_parent: !module.local_parents().is_empty(),
                path: model.workspace.root().join(&module.pom_path),
            })
            .collect(),
        modules: model
            .workspace
            .modules()
            .iter()
            .map(
                |module| match recorded.iter().find(|m| m.path == module.pom_path) {
                    Some(recorded) => recorded.gav.clone(),
                    None => {
                        let gav = module.gav();
                        rv_maven_types::Gav::new(&gav.group_id, &gav.artifact_id, &gav.version)
                    }
                },
            )
            .collect(),
        declared_repositories: rv_repo::RepositoryPolicy::screen(
            config,
            model.declared_repositories(),
            rv_repo::Declaration::LocalPom,
        )
        .admitted,
    }
}

pub(crate) fn discover_reactor_models(
    config: &Config,
    platforms: &[Platform],
) -> Result<Vec<ReactorModel>> {
    let models = platforms
        .iter()
        .map(|platform| discover_reactor_model(config, platform))
        .collect::<Result<Vec<_>>>()?;
    warn_unknown_profiles(config, &models);
    Ok(models)
}

/// What changed in `lock`'s records when `resolved`, resolving again, keeps
/// its graphs.
pub(crate) fn model_change_note(
    lock: &Lockfile,
    resolved: &Lockfile,
    models: &[ReactorModel],
) -> Option<String> {
    let current: Vec<CurrentModel> = models.iter().map(|model| model.current(lock)).collect();
    let drift = lock.model_drift(&current)?;
    let mut paths = BTreeSet::new();
    for model in &current {
        if let Some(inputs) = lock
            .platforms
            .iter()
            .find(|entry| entry.platform == model.platform)
            .and_then(|entry| entry.model_inputs.as_ref())
        {
            for path in inputs.pom_hashes.keys().chain(model.pom_hashes.keys()) {
                if inputs.pom_hashes.get(path) != model.pom_hashes.get(path) {
                    paths.insert(path.clone());
                }
            }
        }
    }
    // Whole-reactor records all change with any edit and name no POM.
    let whole = models.iter().any(|model| model.whole_reactor_in(resolved));
    let changed = if paths.is_empty() {
        drift.to_string()
    } else if whole {
        "a reactor POM changed since raeva.lock was written".to_owned()
    } else {
        format!(
            "{} changed since raeva.lock was written",
            paths.into_iter().collect::<Vec<_>>().join(", ")
        )
    };
    Some(format!(
        "{changed}, without changing the dependencies; a plain 'raeva sync' records its new hash."
    ))
}

/// Whether the recorded POM records match `models` and cover every reactor
/// module each locked graph reaches. A graph can reach one only through an
/// external dependency, which the module's own record does not cover, unless
/// the records cover the whole reactor. A locked external artifact or support
/// POM that now has a reactor module's coordinates would resolve to that
/// module.
pub(crate) fn frozen_models_match(lock: &Lockfile, models: &[ReactorModel]) -> bool {
    models.iter().all(|model| model.matches(lock))
}

/// `config_hash` and recorded system files still match. `unrecorded` is the
/// mismatch when raeva.lock stores no hash.
pub(crate) fn check_recorded_freshness(
    config: &Config,
    lock: &Lockfile,
    models: &[ReactorModel],
    models_match: bool,
    unrecorded: &str,
) -> Result<()> {
    let ambient = recorded_ambient(lock);
    let config_hash = if models_match {
        resolution_config_hash(config, &ambient)?
    } else {
        recorded_outcome_config_hash(config, &ambient)?
    };
    match lock.config_drift(&config_hash) {
        None => {}
        Some(ConfigDrift::Changed) => {
            return Err(config_mismatch(config, lock, models));
        }
        Some(ConfigDrift::Unrecorded) => {
            return Err(CliError::lockfile_mismatch(unrecorded));
        }
    }
    if let Some(drift) = lock.system_file_drift(&config.project_root) {
        return Err(CliError::lockfile_mismatch(drift));
    }
    Ok(())
}

/// Check configuration and, on model drift, resolve every recorded platform
/// again using the same comparison as `sync --frozen`. Also returns the
/// reactor model it checked the lock against for each locked platform, in
/// lock order, and the repositories a resolution trusted, a remote parent's
/// included; none when the check did not resolve.
pub(crate) async fn read_fresh_lockfile(
    config: &Config,
    offline: bool,
    output: &crate::output::Output,
) -> Result<(Lockfile, Vec<ReactorModel>, Vec<Repository>)> {
    let mut lock = crate::commands::read_lockfile(config)?;
    let pom_path = config.project_root.join("pom.xml");
    if !pom_path.is_file() {
        return Err(CliError::ProjectFileMissing { path: pom_path });
    }

    let platforms: Vec<Platform> = (lock.platforms.iter())
        .map(|platform| platform.platform.clone())
        .collect();
    let config = config.for_platforms(
        platforms
            .iter()
            .map(|platform| (platform.os(), platform.arch(), platform.jdk())),
    );
    let models = discover_reactor_models(&config, &platforms)?;
    let models_match = frozen_models_match(&lock, &models);
    check_recorded_freshness(
        &config,
        &lock,
        &models,
        models_match,
        "raeva.lock has no config_hash and cannot be checked for staleness",
    )?;
    // Match `sync --frozen`: resolve again for model drift or an undeclared
    // origin, keeping the locked SNAPSHOT builds.
    let mut trusted = Vec::new();
    if crate::commands::sync::lock_needs_fresh_resolution(&lock, &config, &models) {
        let store = std::sync::Arc::new(rv_store::Store::open(&config.paths.store_dir)?);
        let client = rv_repo::RepoClient::new(&config)
            .await?
            .with_progress(output.progress())
            .with_offline(offline)
            .with_pinned_snapshots(true)
            .with_lock_pins(&lock);
        let fresh;
        (fresh, trusted) = crate::commands::sync::validate_frozen_resolution(
            &config, store, client, &lock, &models, output,
        )
        .await?;
        // Reports name the modules as the POMs do now.
        lock.adopt_module_versions(&fresh);
    }
    output.note(&format!(
        "raeva.lock is up to date for {}",
        crate::commands::sync::platform_list(&platforms)
    ));
    Ok((lock, models, trusted))
}

/// Why raeva.lock is stale when its `config_hash` differs.
pub(crate) const CONFIG_CHANGED: &str = "raeva.lock is out of date: the configuration changed";

/// The mismatch [`config_changed`] describes, with [`jdk_hint`], or a
/// hint naming `[lock] jdks` when raeva.lock records `java.version` and the
/// host values may be what changed.
pub(crate) fn config_mismatch(
    config: &Config,
    lock: &Lockfile,
    models: &[ReactorModel],
) -> CliError {
    let details = config_changed(config, lock, models);
    let hint = jdk_hint(config, lock).or_else(|| {
        (recorded_ambient(lock).contains(&AmbientInput::JavaVersion)
            && details.contains(HOST_VALUES))
        .then(|| {
            jdk_advice(&format!(
                "raeva.lock records java.version, and this JDK is {}",
                config.host().java_version()
            ))
        })
    });
    match hint {
        Some(hint) => CliError::lockfile_mismatch_with(details, hint),
        None => CliError::lockfile_mismatch(details),
    }
}

/// A hint for a stale raeva.lock when a condition it records on the JDK,
/// a `<jdk>` or `java.version` activation, flipped on this host: it names
/// the condition and `[lock] jdks`, which locks several JDKs at once.
pub(crate) fn jdk_hint(config: &Config, lock: &Lockfile) -> Option<String> {
    let flipped = recorded_ambient(lock).into_iter().find_map(|input| {
        let AmbientInput::Condition { condition, holds } = input else {
            return None;
        };
        let on_jdk = match &condition {
            HostCondition::Jdk(_) => true,
            HostCondition::Property { name, .. } => {
                name.strip_prefix('!').unwrap_or(name) == "java.version"
            }
            _ => false,
        };
        (on_jdk && condition_holds(config, &condition)? != holds).then(|| condition.to_string())
    })?;
    Some(jdk_advice(&format!(
        "The JDK condition {} flipped on this JDK ({})",
        rv_maven_types::bounded(&flipped),
        config.host().java_version()
    )))
}

fn jdk_advice(cause: &str) -> String {
    format!(
        "{cause}. Run on the JDK raeva.lock was written with, or list every JDK the build uses \
         in [lock] jdks in raeva.toml and run 'raeva sync'"
    )
}
