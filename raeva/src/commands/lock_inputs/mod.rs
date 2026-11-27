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
use rv_lock::{AmbientInput, HostCondition, Lockfile, PackageSource, Platform};
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
    let ambient = &with_filter_properties(config, ambient);
    let explicit = config.for_platforms([]);
    let (names, overrides) = user_property_names(ambient);
    let user_properties = config.user_property_inputs(&names);
    let user_overrides = config.user_override_inputs(&overrides);
    let inputs = ResolutionInputs {
        profile_selections: config.maven_profile_selections(),
        active_profiles: explicit.active_profiles().to_vec(),
        inactive_profiles: config.inactive_profiles.clone(),
        repositories: explicit
            .repositories()
            .iter()
            .map(|repo| repository_inputs(config, repo))
            .collect(),
        plugin_repositories: (explicit.profile_plugin_repositories().iter())
            .chain(explicit.named_plugin_repositories())
            .map(|repo| repository_inputs(config, repo))
            .collect(),
        allow_transitive_repositories: config.security.allow_transitive_repositories,
        ignore_transitive_repositories: config.ignores_transitive_repositories(),
        allow_env_substitution: config.security.allow_env_substitution.clone(),
        transitive_repository_allowlist: config.security.transitive_repository_allowlist.clone(),
        jdks: config.lock.jdks.clone(),
        maven: config.lock.maven.mode,
        settings_profiles: config
            .conditional_settings_profiles()
            .into_iter()
            .map(|(id, content)| SettingsProfileInput { id, content })
            .collect(),
        settings_model_repositories: config.settings_model_repository_inputs(),
        // An active settings.xml profile sets a listed property that no `-D`
        // sets, whether or not the lock lists it as a settings property. It
        // ranks above `.mvn/jvm.config`, so a value from there alone still
        // leaves it to check.
        ambient: (ambient.iter())
            .flat_map(|name| {
                let (value, overridden) = match name.user_property_name() {
                    Some((property, system)) => {
                        let inputs = match system {
                            true => &user_properties,
                            false => &user_overrides,
                        };
                        match inputs.get(property) {
                            Some(inputs) => (inputs.hash_value(), inputs.defined()),
                            None => (None, false),
                        }
                    }
                    None => (current_value(config, name), false),
                };
                let settings = settings_companion(name)
                    .filter(|settings| !overridden && !ambient.contains(settings))
                    .map(|settings| {
                        let value = current_value(config, &settings);
                        (settings, value)
                    });
                std::iter::once((name.clone(), value)).chain(settings)
            })
            .collect(),
        repository_filters: filter_rule_input(config),
    };
    Ok(inputs)
}

/// What the configuration hash covers of the repository filters: the
/// host's rule input, or, where a platform's `${os.*}` or `java.version`
/// gives another, each distinct one, sorted, so that every host of the
/// lock's platforms hashes alike.
fn filter_rule_input(config: &Config) -> Option<String> {
    let listed = |name: &str| AmbientInput::user_property(name).is_ok();
    let host = config.repository_filters().rule_input(listed);
    let mut inputs: BTreeSet<String> = (config.platform_repository_filters().iter())
        .filter_map(|filters| filters.rule_input(listed))
        .filter(|input| Some(input) != host.as_ref())
        .collect();
    if inputs.is_empty() {
        return host;
    }
    inputs.extend(host);
    let lines: Vec<String> = (inputs.into_iter())
        .map(|input| format!("platform\n{input}"))
        .collect();
    Some(lines.join("\n"))
}

fn repository_inputs(config: &Config, repo: &rv_config::RepoConfig) -> RepositoryInputs {
    RepositoryInputs {
        id: repo.id.clone(),
        // As written: Maven 3.10's repository filters read that spelling.
        // The project's and the user's home directories in it are markers.
        url: config.portable_location(repo.declared_url.as_deref().unwrap_or(&repo.url)),
        releases: repo.releases,
        snapshots: repo.snapshots,
        snapshots_update_policy: repo.snapshots_update_policy.unwrap_or_default().to_string(),
        releases_update_policy: (repo.releases_update_policy)
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
    }
}

/// `ambient` with the remote repository filter properties in effect, which
/// decide which repository serves a file whether or not a model reads
/// them, so a lock written without them sees them once they are set.
fn with_filter_properties(
    config: &Config,
    ambient: &BTreeSet<AmbientInput>,
) -> BTreeSet<AmbientInput> {
    let mut ambient = ambient.clone();
    ambient.extend(filter_properties(config));
    ambient
}

/// The user properties in effect that resolution reads without a recorded
/// read, as raeva.lock lists them: the remote repository filter properties
/// it can list (`config_hash` covers the others by value), and a
/// `path.separator` a `-D` or `.mvn/jvm.config` sets, which an `<os>`
/// family `dos` or `unix` tests in place of the target platform's.
fn filter_properties(config: &Config) -> impl Iterator<Item = AmbientInput> + '_ {
    const SEPARATOR: &str = "path.separator";
    let separator = (config.user_property_inputs(&BTreeSet::from([SEPARATOR.to_string()])))
        .values()
        .any(rv_config::PropertyInputs::is_set)
        .then_some(SEPARATOR);
    (config.repository_filters().property_names())
        .chain(separator)
        .filter_map(|name| AmbientInput::user_property(name).ok())
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

/// [`resolution_inputs`] with each condition in `ambient` at the outcome
/// recorded there: what the configuration alone decides. A check whose
/// models changed uses it, since its resolution compares again the
/// conditions both sides consulted.
fn recorded_outcome_inputs(
    config: &Config,
    ambient: &BTreeSet<AmbientInput>,
) -> Result<ResolutionInputs> {
    let mut inputs = resolution_inputs(config, ambient)?;
    for (input, value) in inputs.ambient.iter_mut() {
        if let AmbientInput::Condition { holds, .. } = input {
            *value = Some(holds.to_string());
        }
    }
    Ok(inputs)
}

/// The most JDK-home `<file>` lookups [`jdk_home_lookups_answer`] tries
/// each outcome of, as it hashes every combination.
const MAX_JDK_HOME_LOOKUPS: usize = 10;

/// Whether `lock`'s `config_hash` holds for `inputs` with some outcome of
/// each `<file>` path on the JDK's home that `lock` records, on a host
/// with no JDK home to test them. raeva.lock keeps no outcome of its own
/// for these, only the hash.
fn jdk_home_lookups_answer(config: &Config, lock: &Lockfile, mut inputs: ResolutionInputs) -> bool {
    if config.host().java_home().is_some() {
        return false;
    }
    let lookups: Vec<(AmbientInput, [String; 2])> = (inputs.ambient.keys())
        .filter_map(|input| match input {
            AmbientInput::UserPropertyLookup(template) => {
                Some((input.clone(), config.jdk_home_lookup_values(template)?))
            }
            _ => None,
        })
        .collect();
    if lookups.is_empty() || lookups.len() > MAX_JDK_HOME_LOOKUPS {
        return false;
    }
    (0..1u32 << lookups.len()).any(|outcomes| {
        for (bit, (input, values)) in lookups.iter().enumerate() {
            let value = values[((outcomes >> bit) & 1) as usize].clone();
            inputs.ambient.insert(input.clone(), Some(value));
        }
        lock.config_drift(&config_hash(&inputs)).is_none()
    })
}

pub(crate) fn recorded_ambient(lock: &Lockfile) -> BTreeSet<AmbientInput> {
    lock.resolution.ambient_inputs.clone()
}

/// Whether `lock` records a read of a variable that is now set where Maven
/// reads it but hidden here. The lock records no value for it, so only a
/// resolution tells whether the value changes a profile's activation. A
/// `<file>` path that takes `${env.JAVA_HOME}` reads the JDK's home
/// instead, and the lookup it records keeps what the path tested; the bare
/// read it also records is taken as that one wherever such a lookup is.
pub(crate) fn reads_hidden_env(config: &Config, lock: &Lockfile) -> bool {
    let environment = config.host().host_environment();
    let mut lookups = Vec::new();
    let mut names = Vec::new();
    for input in &lock.resolution.ambient_inputs {
        match input {
            AmbientInput::UserPropertyLookup(template) => {
                lookups.extend(config.user_property_lookup_env_reads(template));
            }
            input => names.extend(
                (input.user_property_name())
                    .and_then(|(name, _)| name.strip_prefix("env."))
                    .map(str::to_string),
            ),
        }
    }
    let answered = |name: &str| (lookups.iter()).any(|(read, answered)| *answered && read == name);
    let hidden = |name: &str| environment.hides_env(name);
    (lookups.iter()).any(|(name, answered)| !answered && hidden(name))
        || (names.iter()).any(|name| hidden(name) && !answered(name))
}

/// Whether the lock hash of `lock`'s inputs reads a host directory as a
/// marker: there a copy keeps the hash while a value a POM compares names
/// another directory, which only a resolution sees.
pub(crate) fn hides_host_directories(config: &Config, lock: &Lockfile) -> Result<bool> {
    let ambient = recorded_ambient(lock);
    Ok(resolution_config_hash(&config.with_host_paths(), &ambient)?
        != resolution_config_hash(config, &ambient)?)
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
    consulted.extend(
        host.consulted_user_overrides()
            .into_iter()
            .map(HostInput::UserOverride),
    );
    let (mut ambient, by_input) = recorded_inputs(config, consulted, sources)?;
    ambient.extend(filter_properties(config));
    let settings = config.consulted_settings_conditions();
    ambient.extend(settings.iter().filter_map(|key| {
        let (_, holds) = config.settings_condition(key)?;
        AmbientInput::settings(key, holds).ok()
    }));
    Ok((ambient, by_input))
}

/// Whether the property `name`, `!` and all, is the JDK version.
fn is_java_version_name(name: &str) -> bool {
    matches!(
        name.trim_start_matches('!'),
        "java.version" | "java.specification.version"
    )
}

/// Whether the recorded `input` takes the JDK version: itself, a `<jdk>`
/// or JDK version condition of a POM or settings.xml, or a user property
/// whose `-D` value expands it.
fn reads_jdk(config: &Config, input: &AmbientInput) -> bool {
    match input {
        AmbientInput::JavaVersion => true,
        AmbientInput::Condition { condition, .. } => match condition {
            HostCondition::Jdk(_) => true,
            HostCondition::Property { name, .. } => is_java_version_name(name),
            HostCondition::Settings(key) => {
                config.settings_condition(key).is_some_and(|(text, _)| {
                    text.starts_with("jdk:")
                        || (text.strip_prefix("property:")).is_some_and(|rest| {
                            is_java_version_name(rest.split('=').next().unwrap_or(rest))
                        })
                })
            }
            HostCondition::File(_) => false,
        },
        AmbientInput::UserProperty(name) => config.user_property_reads_jdk(name),
        _ => false,
    }
}

/// Whether `ambient` takes the JDK version where neither the JDK nor
/// `JAVA_VERSION` names it, so its values are those of the stand-in 17.
pub(crate) fn reads_unnamed_jdk(config: &Config, ambient: &BTreeSet<AmbientInput>) -> bool {
    unnamed_jdk(config) && ambient.iter().any(|input| reads_jdk(config, input))
}

fn unnamed_jdk(config: &Config) -> bool {
    config.host().named_java_version().is_none() && config.lock.jdks.is_empty()
}

/// [`refuse_unnamed_jdk`] for a lock whose recorded inputs are `ambient`.
pub(crate) fn refuse_unnamed_jdk_reads(
    config: &Config,
    ambient: &BTreeSet<AmbientInput>,
) -> Result<()> {
    refuse_unnamed_jdk(config, reads_unnamed_jdk(config, ambient))
}

/// Refuse a resolution that `reads_version` of the JDK, a `<jdk>`
/// condition, `java.version` or `java.specification.version`, where
/// neither the JDK nor `JAVA_VERSION` names it: raeva would lock what the
/// stand-in 17 selects where Maven reads the JDK it runs on.
fn refuse_unnamed_jdk(config: &Config, reads_version: bool) -> Result<()> {
    if !reads_version || !unnamed_jdk(config) {
        return Ok(());
    }
    Err(CliError::InvalidProjectInput {
        path: config.project_root.join("pom.xml"),
        reason: "the resolution depends on the JDK version (a <jdk> condition, java.version or \
                 java.specification.version), and neither the release file of the JDK from \
                 JAVA_HOME or PATH nor JAVA_VERSION names it; set JAVA_HOME to the JDK the \
                 build uses, or list the JDKs in [lock] jdks in raeva.toml"
            .to_string(),
    })
}

/// `consulted`, host inputs a model build read, as raeva.lock records
/// them; see [`consulted_ambient`].
pub(crate) fn recorded_inputs(
    config: &Config,
    consulted: BTreeSet<HostInput>,
    sources: bool,
) -> Result<(
    BTreeSet<AmbientInput>,
    foldhash::HashMap<HostInput, AmbientInput>,
)> {
    let host = config.host();
    let reads_version = consulted.iter().any(|input| match input {
        HostInput::JavaVersion | HostInput::Jdk(_) => true,
        HostInput::Property { name, .. } => is_java_version_name(name),
        HostInput::UserProperty(name) => config.user_property_reads_jdk(name),
        _ => false,
    });
    refuse_unnamed_jdk(config, reads_version)?;
    let conditions = consulted
        .iter()
        .filter(|input| matches!(input, HostInput::Jdk(_) | HostInput::Property { .. }))
        .count();
    // A short root and a module past `MAX_PATH` canonicalize to a plain and
    // a `\\?\` path, so both are compared in their plain form.
    let roots = [
        Some(config.project_root.clone()),
        dunce::canonicalize(&config.project_root)
            .ok()
            .map(|root| rv_fs::plain_path(&root)),
    ];
    let refuse = |reason: String| CliError::InvalidProjectInput {
        path: config.project_root.join("pom.xml"),
        reason,
    };
    let portable_base = |base_dir: &Option<PathBuf>| -> Result<Option<String>> {
        base_dir
            .as_ref()
            .map(|base| {
                let base =
                    rv_fs::plain_path(&dunce::canonicalize(base).unwrap_or_else(|_| base.clone()));
                // A module beside the root, as raeva.lock names its path.
                let beside = || {
                    let root = roots[1].as_deref()?;
                    let common = root
                        .ancestors()
                        .find(|ancestor| base.starts_with(ancestor))?;
                    let up = root.components().count() - common.components().count();
                    let below = base.strip_prefix(common).ok()?;
                    let up = std::iter::repeat_n(Component::ParentDir, up);
                    Some(up.chain(below.components()).collect::<PathBuf>())
                };
                let relative = roots
                    .iter()
                    .flatten()
                    .find_map(|root| base.strip_prefix(root).ok().map(Path::to_path_buf))
                    .or_else(beside)
                    .ok_or_else(|| {
                        refuse("a private file activation is based outside the project root".into())
                    })?;
                let names = relative
                    .components()
                    .map(|component| match component {
                        Component::Normal(name) => name.to_str(),
                        Component::ParentDir => Some(".."),
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
                         cannot record: a path over 256 characters, one ending in `/.`, one \
                         that is not valid UTF-8, or one that leaves the project and comes \
                         back to another directory"
                            .to_string(),
                    ));
                }
                file => file.flatten(),
            },
            HostInput::UserProperty(name) | HostInput::UserOverride(name) => {
                let recorded = match input {
                    HostInput::UserProperty(_) => AmbientInput::user_property(name),
                    _ => AmbientInput::user_override(name),
                };
                Some(recorded.map_err(|_| {
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
    // A symlink in the project can lead the path out of it.
    if let Ok(target) = rv_fs::canonicalize_existing_prefix(path)
        && !roots.iter().flatten().any(|root| {
            target.starts_with(root)
                || rv_fs::canonicalize_existing_prefix(root)
                    .is_ok_and(|root| target.starts_with(root))
        })
    {
        return None;
    }
    // A path that does not start with the root is refused: the steps from
    // the root to where it does start would have to be guessed.
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
    // A path that leaves the root by name and comes back, such as
    // `${project.basedir}/../project/marker.txt`, is recorded without the
    // way out and back, when the filesystem resolves that, from where the
    // path stands, back to where it stands. The rest stays as written, for the filesystem to
    // resolve as it did here.
    let names = names.and_then(|names| {
        let canonical = rv_fs::canonicalize_existing_prefix;
        let mut kept = Vec::new();
        let mut detour = Vec::new();
        let mut depth = 0usize;
        for name in names {
            if !detour.is_empty() {
                detour.push(name);
                let level: isize = detour
                    .iter()
                    .map(|name| if *name == ".." { -1 } else { 1 })
                    .sum();
                let base = root.join(kept.join("/"));
                let resolved = base.join(detour.join("/"));
                // Windows resolves `..` by name, so every step must exist for
                // the path to mean the same on other systems.
                let steps_exist =
                    (1..=detour.len()).all(|steps| base.join(detour[..steps].join("/")).is_dir());
                if level == 0 && steps_exist && canonical(&resolved).ok() == canonical(&base).ok() {
                    detour.clear();
                }
            } else if name == ".." && depth == 0 {
                detour.push(name);
            } else {
                depth = if name == ".." { depth - 1 } else { depth + 1 };
                kept.push(name);
            }
        }
        detour.is_empty().then_some(kept)
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
        HostInput::JavaVendor => return Some(AmbientInput::JavaVendor),
        HostInput::OsRelease => return Some(AmbientInput::OsRelease),
        // The allowlist admits only names raeva.lock can record.
        HostInput::Env(name) => return AmbientInput::env(name).ok(),
        HostInput::SettingsProperty(name) => return AmbientInput::settings_property(name).ok(),
        HostInput::UserProperty(name) => return AmbientInput::user_property(name).ok(),
        HostInput::UserOverride(name) => return AmbientInput::user_override(name).ok(),
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
                "java.vendor" => Some(AmbientInput::JavaVendor),
                "java.version" | "java.specification.version" => Some(AmbientInput::JavaVersion),
                _ => AmbientInput::env(name.strip_prefix("env.")?).ok(),
            }
        }
        _ => Some(AmbientInput::JavaVersion),
    })
}

/// The settings property of the name a user property reads.
fn settings_companion(name: &AmbientInput) -> Option<AmbientInput> {
    match name {
        AmbientInput::UserProperty(name) | AmbientInput::UserOverride(name) => {
            Some(AmbientInput::SettingsProperty(name.clone()))
        }
        _ => None,
    }
}

/// What `config_hash` covers for `name` in `config`: a value, or for a
/// condition its current outcome.
pub(crate) fn current_value(config: &Config, name: &AmbientInput) -> Option<String> {
    let host = config.host();
    match name {
        AmbientInput::JavaVersion => host.value(&HostInput::JavaVersion),
        AmbientInput::JavaHome => host.value(&HostInput::JavaHome),
        AmbientInput::JavaVendor => host.value(&HostInput::JavaVendor),
        AmbientInput::OsRelease => host.value(&HostInput::OsRelease),
        AmbientInput::Env(name) => host.value(&HostInput::Env(name.clone())),
        AmbientInput::SettingsProperty(name) => config.settings_property_value(name),
        AmbientInput::UserPropertyLookup(template) => config.user_property_lookup_value(template),
        AmbientInput::UserProperty(name) => config
            .user_property_inputs(&BTreeSet::from([name.clone()]))
            .remove(name)
            .and_then(|inputs| inputs.hash_value()),
        AmbientInput::UserOverride(name) => config
            .user_override_inputs(&BTreeSet::from([name.clone()]))
            .remove(name)
            .and_then(|inputs| inputs.hash_value()),
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
        HostCondition::File(path) => {
            // Recorded only where the path stays in the project, which an
            // edited raeva.lock need not keep to: such a path is not tested.
            let file = config.project_root.join(path);
            let inside = rv_fs::canonicalize_existing_prefix(&file).is_ok_and(|target| {
                rv_fs::canonicalize_existing_prefix(&config.project_root)
                    .is_ok_and(|root| target.starts_with(root))
            });
            return inside.then(|| file.exists());
        }
        HostCondition::Settings(key) => {
            return config.settings_condition(key).map(|(_, holds)| holds);
        }
    };
    config.host().holds(&input)
}

/// The `-D` overrides of the user properties `ambient` lists and the `-P`
/// options of the command line and `.mvn/maven.config` by name,
/// as raeva.lock records them in `[resolution] command_line`. A name raeva.lock cannot hold is left
/// out; `config_hash` still covers it.
pub(crate) fn command_line_names(
    config: &Config,
    ambient: &BTreeSet<AmbientInput>,
) -> BTreeSet<String> {
    let (names, overrides) = user_property_names(ambient);
    option_names(config, &names, &overrides)
}

/// The names of the user properties `ambient` lists: those a system
/// property answers where no user property does, and those the model
/// defines ([`AmbientInput::UserOverride`]).
fn user_property_names(ambient: &BTreeSet<AmbientInput>) -> (BTreeSet<String>, BTreeSet<String>) {
    let (mut names, mut overrides) = (BTreeSet::new(), BTreeSet::new());
    for (name, system) in ambient.iter().filter_map(AmbientInput::user_property_name) {
        match system {
            true => names.insert(name.to_string()),
            false => overrides.insert(name.to_string()),
        };
    }
    (names, overrides)
}

fn option_names(
    config: &Config,
    names: &BTreeSet<String>,
    overrides: &BTreeSet<String>,
) -> BTreeSet<String> {
    let command_line = config.maven_command_line();
    let mut properties = config.user_override_inputs(overrides);
    properties.extend(config.user_property_inputs(names));
    let defines = properties
        .iter()
        .filter(|(_, inputs)| inputs.is_set())
        .map(|(name, _)| format!("-D{name}"));
    // As Maven reads them, so equivalent spellings record the same names.
    let profiles = (command_line.profiles.iter())
        .flat_map(|list| rv_config::maven_config::profile_actions(list))
        .map(|(inactive, id)| {
            format!(
                "-P{}",
                rv_config::maven_config::profile_action(inactive, id)
            )
        });
    defines
        .chain(profiles)
        .filter(|option| rv_lock::is_command_line_name(option))
        .collect()
}

/// The options added and removed since raeva.lock was written, by name.
fn command_line_change(config: &Config, lock: &Lockfile) -> Option<String> {
    let (mut names, mut overrides) = user_property_names(&lock.resolution.ambient_inputs);
    names.extend(config.host().consulted_user_properties());
    names.extend((config.repository_filters().property_names()).map(str::to_string));
    overrides.extend(config.host().consulted_user_overrides());
    let now = option_names(config, &names, &overrides);
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
            "{}; set them as raeva.lock was written (on the command line or in \
             .mvn/maven.config, and -D options also in .mvn/jvm.config), or run 'raeva sync' to \
             relock",
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
    let selection = &config.lock.maven;
    if lock.maven != selection.mode {
        return format!(
            "{CONFIG_CHANGED}: raeva.lock was resolved as Maven {}, and {} selects Maven {}",
            lock.maven, selection.source, selection.mode
        );
    }
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
        changed.push(format!(
            "{COMMAND_LINE}, .mvn/jvm.config or a JVM option variable"
        ));
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
        (true, Some(profiles)) => format!(
            "{CONFIG_CHANGED}: {profiles}; check .mvn/jvm.config and the Maven profile options"
        ),
        (true, None) => format!(
            "{CONFIG_CHANGED} since raeva.lock was written; raeva.lock covers the repositories, \
             profiles, [lock] jdks, [security], .mvn/maven.config, .mvn/jvm.config, the remote \
             repository filter files, {COMMAND_LINE} and {HOST_VALUES}"
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

    /// The same of their `<pluginRepositories>`, the super POM's `central`
    /// included, from which raeva.lock's plugin rows come. A dependency is
    /// never searched for in these.
    pub(crate) fn declared_plugin_repositories(&self) -> impl Iterator<Item = Repository> + '_ {
        (self.workspace.modules().iter())
            .flat_map(|module| &module.descriptor.plugin_repositories)
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
            lock.maven,
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
                    .all(|package| match package.source() {
                        PackageSource::Module(path) => {
                            covers.is_none_or(|covers| path == module.path || covers.contains(path))
                        }
                        PackageSource::System(_) => true,
                        // A module takes its own coordinates from a repository.
                        PackageSource::Repository => {
                            let gav = &package.coordinate.gav;
                            module.owns(gav)
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

/// Refuse a project whose POMs declare a repository or plugin repository
/// URL with userinfo, a query or a fragment, as configuration with one is
/// refused, or whose path or id holds the value of one of `secrets`
/// ([`Config::secret_named_inputs`]): raeva.lock would record it, or whose
/// id takes a `${...}` raeva does not follow
/// ([`rv_repo::expression_id_refusal`]), a plugin repository's only when
/// `[plugins]` locks the plugins. The message names the module and the
/// input, never the URL, which may be inherited from a local parent, or the
/// value.
fn refuse_secret_repositories(
    config: &Config,
    modules: &[&rv_resolver::WorkspaceModule],
    secrets: &[(String, String)],
    names: &[(String, String)],
) -> Result<()> {
    for module in modules {
        let descriptor = &module.descriptor;
        let declared = (descriptor
            .repositories
            .iter()
            .map(|repo| ("repository", repo)))
        .chain((descriptor.plugin_repositories.iter()).map(|repo| ("plugin repository", repo)));
        // A fetched parent's URL or secret id leaves the repository ignored;
        // an id Maven reads apart from raeva fails the build wherever the
        // lineage declares it.
        for (kind, repo) in declared {
            let own = repo.root_declared;
            let refusal = (own.then(|| {
                rv_repo::secret_url_refusal(&repo.url, &repo.url_reads, secrets, names).or_else(
                    || {
                        let declared = repo.declared_url.as_deref()?;
                        rv_maven_model::file_transport::host_refusal(declared)
                    },
                )
            }))
            .flatten();
            let entry = repo.id.as_deref().map_or_else(
                || format!("a {kind} without an id"),
                |id| {
                    let id = rv_repo::shown_id(id, &repo.id_reads, secrets, names);
                    format!("{kind} '{}'", rv_maven_types::bounded(&id))
                },
            );
            let reason = if let Some(refusal) = refusal {
                format!("the URL of {entry} it declares or inherits {refusal}")
            } else if let Some(refusal) = (own.then(|| {
                rv_repo::secret_id_refusal(repo.id.as_deref(), &repo.id_reads, secrets, names)
            }))
            .flatten()
            .or_else(|| {
                // A plugin repository serves only the plugins, which only
                // `[plugins]` locks.
                let read = kind == "repository" || config.plugins.is_some();
                let declared = rv_repo::Repository::from(repo.clone());
                (read.then(|| rv_repo::expression_id_refusal(config, &declared)))
                    .flatten()
                    .map(String::from)
            }) {
                format!("the id of a {kind} it declares or inherits {refusal}")
            } else {
                continue;
            };
            return Err(CliError::InvalidProjectInput {
                path: module.pom_file().to_path_buf(),
                reason,
            });
        }
    }
    Ok(())
}

/// Refuse a settings.xml repository of `ids` that the projects of the
/// reactor fill in differently, or one leaves unfilled: Maven fills it in
/// once, from the first project its build order reaches, and every project
/// reads that one.
fn refuse_settings_repositories_filled_apart(
    modules: &[&rv_resolver::WorkspaceModule],
    ids: &[String],
) -> Result<()> {
    for id in ids {
        let filled = |module: &rv_resolver::WorkspaceModule| {
            (module.descriptor.repositories.iter())
                .rfind(|repo| repo.root_declared && repo.id.as_deref() == Some(id))
                .map(|repo| {
                    (
                        repo.url.clone(),
                        repo.declared_url.clone(),
                        repo.layout.clone(),
                        [repo.releases_enabled, repo.snapshots_enabled],
                        [
                            repo.releases_update_policy.clone(),
                            repo.snapshots_update_policy.clone(),
                            repo.releases_checksum_policy.clone(),
                            repo.snapshots_checksum_policy.clone(),
                        ],
                    )
                })
        };
        let shown = rv_maven_types::bounded(id);
        let filled: Vec<_> = modules.iter().map(|module| filled(module)).collect();
        let unfilled = (modules.iter().zip(&filled)).find(|(_, repo)| {
            // Maven 3.10 reads a URL without a scheme as a `file:` one.
            repo.as_ref().is_none_or(|(url, declared, ..)| {
                [Some(url), declared.as_ref()]
                    .into_iter()
                    .flatten()
                    .any(|url| url.contains("${"))
            })
        });
        let reason = if let Some((module, _)) = unfilled {
            Some((
                module,
                format!(
                    "the settings.xml repository '{shown}' takes a ${{...}} that this project \
                     leaves unfilled, while Maven fills it in once for the whole build; set the \
                     property in the settings.xml profile, or write the URL out"
                ),
            ))
        } else {
            (modules.iter().zip(&filled))
                .find(|(_, repo)| *repo != &filled[0])
                .map(|(module, _)| {
                    (
                        module,
                        format!(
                            "the settings.xml repository '{shown}' takes a ${{...}} that this \
                             project fills in otherwise than {} does, while Maven fills it in \
                             once for the whole build and every project reads that one; set the \
                             property in the settings.xml profile, or write the URL out",
                            modules[0].pom_path
                        ),
                    )
                })
        };
        if let Some((module, reason)) = reason {
            return Err(CliError::InvalidProjectInput {
                path: module.pom_file().to_path_buf(),
                reason,
            });
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
    let secrets = config.secret_named_inputs();
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
    refuse_secret_repositories(config, &modules, &secrets, &config.secret_input_names())?;
    let environment = config.model_environment(platform.os(), platform.arch(), platform.jdk());
    let ids = config.settings_model_repository_ids(&environment);
    refuse_settings_repositories_filled_apart(&modules, &ids)?;

    // The settings.xml profiles a condition activates add only repositories,
    // which config_hash covers, so only the explicit ids count.
    let mut active_profiles: BTreeSet<String> = config.active_profiles().iter().cloned().collect();
    let mut module_inputs = Vec::with_capacity(modules.len());
    let mut resolution_contexts = workspace.resolution_contexts();
    let mut covers = BTreeMap::new();
    for module in modules {
        let bytes = rv_config::read_project_input(module.pom_file())?;
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
        WorkspaceError::MissingModule {
            ref declaring_pom,
            ref profile,
            ..
        } => CliError::InvalidProjectInput {
            path: project_root.join(declaring_pom),
            reason: match profile {
                Some(_) => format!("{err}; select the profiles the build uses with -P"),
                None => err.to_string(),
            },
        },
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

/// The URLs the project's own POMs declare in `models`, their plugin
/// repositories' included.
pub(crate) fn declared_repository_urls<'a>(
    config: &Config,
    models: &'a [ReactorModel],
) -> impl Iterator<Item = String> + 'a {
    let plugins = models
        .iter()
        .flat_map(ReactorModel::declared_plugin_repositories);
    rv_repo::RepositoryPolicy::screen(
        config,
        models
            .iter()
            .flat_map(ReactorModel::declared_repositories)
            .chain(plugins),
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
                local_parents: module.local_parents().to_vec(),
                path: module.pom_file().to_path_buf(),
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
/// module, except the module's own artifacts, which its graph takes from a
/// repository. The plugin tables are no graph: a plugin's support POM at a
/// reactor module's coordinates was read from a repository.
pub(crate) fn frozen_models_match(lock: &Lockfile, models: &[ReactorModel]) -> bool {
    let lock = lock.without_plugins();
    models.iter().all(|model| model.matches(&lock))
}

/// `config_hash` and recorded system files still match. `unrecorded` is the
/// mismatch when raeva.lock stores no hash. A command that `builds` on this
/// machine's JDK compares the `<file>` paths on the JDK's home too; a report
/// of the lock on a host with no JDK home takes them as raeva.lock has them.
pub(crate) fn check_recorded_freshness(
    config: &Config,
    lock: &Lockfile,
    models: &[ReactorModel],
    models_match: bool,
    builds: bool,
    unrecorded: &str,
) -> Result<()> {
    // `config_hash` covers the configured line, not the lock's record of it.
    if lock.maven != config.lock.maven.mode {
        return Err(config_mismatch(config, lock, models));
    }
    let ambient = recorded_ambient(lock);
    let inputs = match models_match {
        true => resolution_inputs(config, &ambient),
        false => recorded_outcome_inputs(config, &ambient),
    }?;
    match lock.config_drift(&config_hash(&inputs)) {
        None => {}
        Some(ConfigDrift::Changed) if !builds && jdk_home_lookups_answer(config, lock, inputs) => {}
        Some(ConfigDrift::Changed) => return Err(config_mismatch(config, lock, models)),
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
/// included; none when the check did not resolve. A command that `builds`
/// on this machine's JDK refuses a lock that reads a JDK version neither
/// the JDK nor `JAVA_VERSION` names; a report of the lock needs no JDK.
pub(crate) async fn read_fresh_lockfile(
    config: &Config,
    builds: bool,
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
    config.settings_activation()?;
    let models = discover_reactor_models(&config, &platforms)?;
    let models_match = frozen_models_match(&lock, &models);
    if builds {
        refuse_unnamed_jdk_reads(&config, &recorded_ambient(&lock))?;
    }
    check_recorded_freshness(
        &config,
        &lock,
        &models,
        models_match,
        builds,
        "raeva.lock has no config_hash and cannot be checked for staleness",
    )?;
    crate::commands::sync::check_plugin_tables(&config, Some(&lock), &platforms)?;
    crate::commands::sync::check_plugin_trace(&config, &lock, &platforms)?;
    // Match `sync --frozen`: resolve again for model drift or an undeclared
    // origin, keeping the locked SNAPSHOT builds.
    // A lock hash that reads a host directory as a marker holds in a copy
    // too, so the lock stands without one only where this home wrote or
    // checked it.
    let mut trusted = Vec::new();
    let drift = crate::commands::sync::lock_needs_fresh_resolution(&lock, &config, &models);
    let client = match drift || hides_host_directories(&config, &lock)? {
        true => Some(
            (crate::commands::sync::Mode::check(offline).client(&config))
                .await?
                .with_progress(output.progress())
                .with_lock_pins(&lock),
        ),
        false => None,
    };
    let client = client.filter(|client| {
        drift || !crate::commands::sync::checked_here(&config, client, &platforms)
    });
    if let Some(client) = client {
        let store = std::sync::Arc::new(rv_store::Store::open(&config.paths.store_dir)?);
        let fresh;
        (fresh, trusted) = crate::commands::sync::validate_frozen_resolution(
            &config,
            std::sync::Arc::clone(&store),
            client.clone(),
            &lock,
            &models,
            models_match,
            output,
        )
        .await?;
        // A POM edit can move a plugin and leave every dependency.
        if config.plugins.is_some() {
            crate::commands::sync::check_resolved_plugins(
                &config, store, client, &lock, &models, &platforms,
            )
            .await?;
        }
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
            HostCondition::Property { name, .. } => matches!(
                name.strip_prefix('!').unwrap_or(name),
                "java.version" | "java.specification.version"
            ),
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
