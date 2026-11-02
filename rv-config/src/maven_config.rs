//! `.mvn/maven.config` read the way Maven 3.9.11's `MavenCli` reads it.
//!
//! Every non-empty line that does not start with `#` is one command-line
//! argument, kept as written. `CLIManager.parse` then joins arguments split
//! inside double quotes (`CleanArgument.cleanArgs`) and hands them to
//! commons-cli's `GnuParser` with Maven's option table. Only `-D`, `-P` and
//! `-s` matter to `raeva`; every other Maven option is accepted and ignored,
//! and anything Maven would reject is an error.
//!
//! The same options given to `raeva` itself, [`CommandLine`], join the file's
//! as `MavenCli.cliMerge` joins the command line with it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};

use rv_maven_model::{ActivationContext, ModelEnvironment, PropertyMap};
pub use rv_maven_model::{ModelLookup, PropertySource};
use rv_maven_types::bounded;
use thiserror::Error;

/// An authored expression and the public context needed to replay its input reads.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyLookup {
    /// The expression before interpolation.
    pub expression: String,
    /// Properties declared in the POM, without external input values.
    pub properties: BTreeMap<String, String>,
    /// A file condition instead of a property activation lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileLookup>,
    /// The public packaging default supplied by the model during interpolation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_packaging: Option<String>,
    /// User or system placement of command-line properties in the model request.
    pub source: PropertySource,
    /// The operation replayed after interpolation.
    pub mode: LookupMode,
    /// Public model fields when replay uses ordinary model interpolation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<Box<ModelLookup>>,
}

/// The read performed by a public expression recipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LookupMode {
    /// Interpolate a property activation name, then look up that property.
    Property,
    /// Interpolate a file path, then test its existence.
    File,
    /// Interpolate activation text without another lookup of its result.
    Interpolation,
    /// Interpolate ordinary model text with model fields and model precedence.
    Model,
}

/// Public context for a private file activation path.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileLookup {
    /// The local POM directory relative to the project root, absent for repository POMs.
    pub base_dir: Option<String>,
}

impl PropertyLookup {
    /// Encode the public expression for an ambient input record.
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("property lookup serializes")
    }

    /// Parse a public expression from an ambient input record.
    pub fn parse(text: &str) -> Option<Self> {
        serde_json::from_str(text).ok()
    }
}

/// The `-D`, `-P` and `-s` options given to `raeva`, which Maven reads as the
/// same options given to `mvn`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommandLine {
    /// Each `-D` value, `name=value` or `name`, in order.
    pub defines: Vec<String>,
    /// Each `-P` value, a comma-separated list of ids, in order.
    pub profiles: Vec<String>,
    /// Each `-s` value, in order, as written.
    pub settings: Vec<String>,
}

impl CommandLine {
    /// The options as `mvn` reads them, each value with the quotes around it
    /// stripped as commons-cli strips them.
    ///
    /// # Errors
    ///
    /// [`MavenConfigError::QuotedValue`] for a value Maven reads one way
    /// written `-Dvalue` and another written `-D value`: `CleanArgument`
    /// leaves an argument that starts with the option as it is, but joins
    /// and unquotes one that starts with `"`.
    pub fn new(
        defines: Vec<String>,
        profiles: Vec<String>,
        settings: Vec<String>,
    ) -> Result<Self, MavenConfigError> {
        let clean = |values: Vec<String>| {
            (values.into_iter())
                .map(|value| {
                    let attached = strip_quotes(&value);
                    let separate = clean_args(&[value.as_str()]).ok();
                    match separate.as_deref() {
                        Some([separate]) if strip_quotes(separate) == attached => {
                            Ok(attached.to_string())
                        }
                        _ => Err(MavenConfigError::QuotedValue(value)),
                    }
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            defines: clean(defines)?,
            profiles: clean(profiles)?,
            settings: clean(settings)?,
        })
    }
}

/// The user property that sets `mvn`'s local repository.
pub const LOCAL_REPOSITORY_PROPERTY: &str = "maven.repo.local";

/// The name of a `-D` value, as `MavenCli` splits it.
fn define_name(define: &str) -> &str {
    match define.find('=') {
        Some(equals) if equals > 0 => define[..equals].trim(),
        _ => define.trim(),
    }
}

/// The `-D` and `-P` options of one `.mvn/maven.config` merged with a
/// [`CommandLine`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MavenConfigOptions {
    /// User properties, with values interpolated as `MavenCli` does.
    pub properties: HashMap<String, String>,
    /// The user properties written with a `${...}`, whose value can hold
    /// one of the host's.
    pub expanded_properties: BTreeSet<String>,
    /// The profile ids `-P` selects.
    pub active_profiles: Vec<String>,
    /// The profile ids `-P` deselects with `!` or `-`.
    pub inactive_profiles: Vec<String>,
}

fn entry_list(entries: &[String]) -> String {
    const SHOWN: usize = 16;
    let mut list = entries
        .iter()
        .take(SHOWN)
        .map(|entry| bounded(entry).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if entries.len() > SHOWN {
        list.push_str(&format!(", ... ({} entries)", entries.len()));
    }
    list
}

/// An entry Maven refuses with "Unable to parse maven.config file options".
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MavenConfigError {
    /// Arguments that are not options or option values, such as a line
    /// that does not start with `-` (leading whitespace counts) or anything
    /// after `--`. Holds each one as written.
    #[error("Unrecognized maven.config file entries: [{}]", entry_list(.0))]
    UnrecognizedEntries(Vec<String>),
    /// A `-` argument that names no Maven 3.9.11 option. Holds the token.
    #[error("Unrecognized option: {}", bounded(.0))]
    UnrecognizedOption(String),
    /// An option that takes a value, such as `-D` or `-P`, is last or is
    /// followed by another option. Holds the option's name without dashes.
    #[error("Missing argument for option: {0}")]
    MissingArgument(String),
    /// `-llr` (`--legacy-local-repository`), which Maven 3.9.1 and later
    /// refuse.
    #[error("Option '-llr' is not supported starting with Maven 3.9.1")]
    UnsupportedOption,
    /// `-f` (`--file`), with which Maven builds another POM than the
    /// project's `pom.xml` that raeva locks.
    #[error(
        "-f (--file) makes mvn build another POM, and raeva locks the project's pom.xml; \
         remove it"
    )]
    ProjectFile,
    /// An argument that is a lone `"`, which Maven's quote joining cannot
    /// close.
    #[error("unterminated quote in argument")]
    BrokenQuote,
    /// A `raeva` option value that starts with `"` and that Maven reads
    /// differently attached to its option and apart from it. Holds the
    /// value.
    #[error(
        "mvn reads the quotes of {} differently attached to the option and apart from it; drop them",
        bounded(.0)
    )]
    QuotedValue(String),
    /// A `-D` value with no property name, such as `-D=`, which Maven
    /// refuses with "key can't be empty". Holds the value.
    #[error("-D{} has no property name: write -Dname or -Dname=value", bounded(.0))]
    EmptyPropertyName(String),
    /// A `${...}` in a `-D` or `-P` value could not be interpolated. Holds
    /// the interpolation error's message.
    #[error("invalid property value: {0}")]
    Interpolation(String),
}

/// `(short, long, takes a value, value optional)` for every option in
/// Maven 3.9.11's `CLIManager`.
const OPTIONS: &[(Option<&str>, Option<&str>, bool, bool)] = &[
    (Some("h"), Some("help"), false, false),
    (Some("f"), Some("file"), true, false),
    (Some("D"), Some("define"), true, false),
    (Some("o"), Some("offline"), false, false),
    (Some("v"), Some("version"), false, false),
    (Some("q"), Some("quiet"), false, false),
    (Some("X"), Some("debug"), false, false),
    (Some("e"), Some("errors"), false, false),
    (Some("N"), Some("non-recursive"), false, false),
    (Some("U"), Some("update-snapshots"), false, false),
    (Some("P"), Some("activate-profiles"), true, false),
    (Some("B"), Some("batch-mode"), false, false),
    (Some("nsu"), Some("no-snapshot-updates"), false, false),
    (Some("C"), Some("strict-checksums"), false, false),
    (Some("c"), Some("lax-checksums"), false, false),
    (Some("s"), Some("settings"), true, false),
    (Some("gs"), Some("global-settings"), true, false),
    (Some("t"), Some("toolchains"), true, false),
    (Some("gt"), Some("global-toolchains"), true, false),
    (Some("ff"), Some("fail-fast"), false, false),
    (Some("fae"), Some("fail-at-end"), false, false),
    (Some("fn"), Some("fail-never"), false, false),
    (Some("rf"), Some("resume-from"), true, false),
    (Some("pl"), Some("projects"), true, false),
    (Some("am"), Some("also-make"), false, false),
    (Some("amd"), Some("also-make-dependents"), false, false),
    (Some("l"), Some("log-file"), true, false),
    (Some("V"), Some("show-version"), false, false),
    (Some("emp"), Some("encrypt-master-password"), true, true),
    (Some("ep"), Some("encrypt-password"), true, true),
    (Some("T"), Some("threads"), true, false),
    (Some("b"), Some("builder"), true, false),
    (Some("ntp"), Some("no-transfer-progress"), false, false),
    (
        Some("itr"),
        Some("ignore-transitive-repositories"),
        false,
        false,
    ),
    (Some("npr"), Some("no-plugin-registry"), false, false),
    (Some("cpu"), Some("check-plugin-updates"), false, false),
    (Some("up"), Some("update-plugins"), false, false),
    (Some("npu"), Some("no-plugin-updates"), false, false),
    (Some("llr"), Some("legacy-local-repository"), false, false),
    (None, Some("raw-streams"), false, false),
    (None, Some("color"), true, true),
];

#[derive(Clone, Copy)]
struct CliOption {
    name: &'static str,
    takes_value: bool,
    value_optional: bool,
}

/// commons-cli `Options.getOption`: one leading `--` or `-` is dropped, then
/// the short names are tried before the long ones.
fn option(token: &str) -> Option<CliOption> {
    let name = token
        .strip_prefix("--")
        .or_else(|| token.strip_prefix('-'))
        .unwrap_or(token);
    let found = OPTIONS
        .iter()
        .find(|(short, _, _, _)| *short == Some(name))
        .or_else(|| OPTIONS.iter().find(|(_, long, _, _)| *long == Some(name)))?;
    let (short, long, takes_value, value_optional) = *found;
    Some(CliOption {
        name: short.or(long).unwrap_or_default(),
        takes_value,
        value_optional,
    })
}

/// Java's line terminators: `\n`, `\r\n` or a lone `\r`.
fn java_lines(content: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(content);
    std::iter::from_fn(move || {
        let text = rest?;
        match text.find(['\n', '\r']) {
            Some(end) => {
                let skip = if text[end..].starts_with("\r\n") {
                    2
                } else {
                    1
                };
                rest = Some(&text[end + skip..]).filter(|tail| !tail.is_empty());
                Some(&text[..end])
            }
            None => {
                rest = None;
                Some(text)
            }
        }
    })
}

/// `CleanArgument.cleanArgs`: an argument starting with `"` opens a buffer
/// that following arguments join, separated by a space, until an argument
/// that both starts and ends with `"`, or another opening `"`, closes it.
fn clean_args(args: &[&str]) -> Result<Vec<String>, MavenConfigError> {
    let mut cleaned = Vec::new();
    let mut current: Option<String> = None;
    for arg in args {
        let mut added_to_buffer = false;
        if let Some(rest) = arg.strip_prefix('"') {
            if let Some(open) = current.take() {
                cleaned.push(open);
            }
            current = Some(rest.to_string());
            added_to_buffer = true;
        }
        if added_to_buffer && arg.ends_with('"') {
            let mut buffer = current.take().unwrap_or_default();
            // Maven shortens the buffer by one, which throws for a lone `"`.
            if buffer.pop().is_none() {
                return Err(MavenConfigError::BrokenQuote);
            }
            cleaned.push(buffer);
            continue;
        }
        if !added_to_buffer {
            match current.as_mut() {
                Some(buffer) => {
                    buffer.push(' ');
                    buffer.push_str(arg);
                }
                None => cleaned.push((*arg).to_string()),
            }
        }
    }
    if let Some(open) = current {
        cleaned.push(open);
    }
    Ok(cleaned)
}

/// `GnuParser.flatten`: `--opt=value` and `-Xvalue` become an option token
/// followed by a value token.
fn flatten(args: Vec<String>) -> Vec<String> {
    let mut tokens = Vec::with_capacity(args.len());
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            tokens.push(arg);
            tokens.extend(args.by_ref());
            break;
        }
        if arg == "-" || !arg.starts_with('-') || option(&arg).is_some() {
            tokens.push(arg);
            continue;
        }
        let name = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .unwrap_or(&arg);
        if let Some(equals) = name.find('=')
            && option(&name[..equals]).is_some()
        {
            let split = arg.find('=').unwrap_or(arg.len());
            tokens.push(arg[..split].to_string());
            tokens.push(arg[split + 1..].to_string());
        } else if arg.is_char_boundary(2) && option(&arg[..2]).is_some() {
            tokens.push(arg[..2].to_string());
            tokens.push(arg[2..].to_string());
        } else {
            tokens.push(arg);
        }
    }
    tokens
}

/// commons-cli's `Util.stripLeadingAndTrailingQuotes`.
fn strip_quotes(value: &str) -> &str {
    match value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
    {
        Some(inner) if !inner.contains('"') => inner,
        _ => value,
    }
}

#[cfg(test)]
pub(crate) fn parse(content: &str) -> Result<MavenConfigOptions, MavenConfigError> {
    parse_for(
        Some(content),
        &CommandLine::default(),
        &ModelEnvironment::default(),
        Path::new("/project"),
    )
}

/// The directory names `MavenCli` expands in option values ahead of the
/// system properties and the `-D` values: all three are the directory
/// `mvn` runs in, the project root.
fn insert_root(map: &mut PropertyMap, project_root: &Path) {
    let root = project_root.to_string_lossy();
    for name in [
        "session.rootDirectory",
        "session.topDirectory",
        "maven.multiModuleProjectDirectory",
    ] {
        map.insert(name, root.as_ref());
    }
}

/// Parse `.mvn/maven.config`, `None` when there is none, merged with
/// `command_line` for a build in `environment`, the platform being locked.
/// The command line's `-D` values come after the file's, so they win, and
/// its `-P` values come first. `${...}` in `-D`, `-P` and `-s` values
/// resolves against the platform's system properties as `MavenCli` resolves
/// it against its own, and `${session.rootDirectory}`,
/// `${session.topDirectory}` and `${maven.multiModuleProjectDirectory}`
/// against `project_root`.
pub fn parse_for(
    content: Option<&str>,
    command_line: &CommandLine,
    environment: &ModelEnvironment,
    project_root: &Path,
) -> Result<MavenConfigOptions, MavenConfigError> {
    let written = match content {
        Some(content) => written_values(content)?,
        None => Written::default(),
    };
    let defines = written.defines.iter().chain(&command_line.defines);
    let profiles = command_line.profiles.iter().chain(&written.profiles);
    let mut options = MavenConfigOptions::default();
    let system_properties =
        ActivationContext::new(environment.clone()).platform_system_properties();
    let mut raw = PropertyMap::new();
    for (name, value) in &system_properties {
        raw.insert(name, value);
    }
    let mut names = Vec::new();
    for define in defines {
        let name = define_name(define);
        if name.is_empty() {
            return Err(MavenConfigError::EmptyPropertyName(define.clone()));
        }
        let value = match define.find('=') {
            Some(equals) if equals > 0 => &define[equals + 1..],
            _ => "true",
        };
        if !names.iter().any(|known| known == name) {
            names.push(name.to_string());
        }
        raw.insert(name, value);
    }
    // `MavenCli.populateProperties` expands each value against the `-D`
    // values as written and the system properties.
    let mut lookup = raw.clone();
    insert_root(&mut lookup, project_root);
    let mut session = PropertyMap::new();
    for (name, value) in &system_properties {
        session.insert(name, value);
    }
    // Values matter only when a model reads their names. The configuration
    // hash covers those effective values without recording eager host reads.
    let property_environment = environment.detached();
    for name in names {
        let value = raw.get(&name).cloned().unwrap_or_default();
        if value.contains("${") {
            options.expanded_properties.insert(name.clone());
        }
        let value = lookup
            .interpolate_str_exact(&value, &property_environment)
            .map_err(|error| MavenConfigError::Interpolation(error.to_string()))?;
        session.insert(name.as_str(), value.as_str());
        options.properties.insert(name, value);
    }
    insert_root(&mut session, project_root);

    // `MavenCli.properties` then expands every other option value against
    // the system properties, which by then hold the `-D` values too.
    for value in profiles {
        let value = session
            .interpolate_str_exact(value, environment)
            .map_err(|error| MavenConfigError::Interpolation(error.to_string()))?;
        for action in value.split(',').filter(|action| !action.is_empty()) {
            let action = action.trim();
            let (inactive, profile) = match action.chars().next() {
                Some('-' | '!') => (true, &action[1..]),
                Some('+') => (false, &action[1..]),
                _ => (false, action),
            };
            let destination = if inactive {
                &mut options.inactive_profiles
            } else {
                &mut options.active_profiles
            };
            if !destination.iter().any(|known| known == profile) {
                destination.push(profile.to_string());
            }
        }
    }
    Ok(options)
}

/// The first `-s` file of `command_line`, `None` when it names none, as
/// commons-cli's `getOptionValue` answers it, expanded against the
/// command line's `-D` values and the system properties, with
/// `${session.rootDirectory}`, `${session.topDirectory}` and
/// `maven.multiModuleProjectDirectory` as `project_root`. A relative path is
/// taken from the working directory. Unlike Maven, raeva takes neither a
/// `-s` nor the `-D` values that expand one from `.mvn/maven.config`: the
/// project would pick the mirrors, proxies, environment and local
/// repository that only the user's own files may set.
///
/// # Errors
///
/// As [`parse_for`], which it runs whether or not there is a `-s`.
pub fn settings_file(
    content: Option<&str>,
    command_line: &CommandLine,
    environment: &ModelEnvironment,
    project_root: &Path,
) -> Result<Option<PathBuf>, MavenConfigError> {
    parse_for(content, command_line, &environment.detached(), project_root)?;
    let Some(value) = command_line.settings.first() else {
        return Ok(None);
    };
    let options = parse_for(None, command_line, &environment.detached(), project_root)?;
    let mut session = PropertyMap::new();
    let system_properties =
        ActivationContext::new(environment.clone()).platform_system_properties();
    for (name, value) in &system_properties {
        session.insert(name, value);
    }
    for (name, value) in &options.properties {
        session.insert(name, value);
    }
    insert_root(&mut session, project_root);
    let value = session
        .interpolate_str_exact(value, environment)
        .map_err(|error| MavenConfigError::Interpolation(error.to_string()))?;
    let path = std::path::absolute(&value).unwrap_or_else(|_| value.into());
    Ok(Some(
        (path.components())
            .filter(|component| *component != Component::CurDir)
            .collect(),
    ))
}

/// The options `.mvn/maven.config` names that raeva does not read from it:
/// the settings options `-s` and `-gs`, and the reactor selection `-pl`,
/// `-am` and `-amd`, since raeva locks the whole reactor.
///
/// # Errors
///
/// When Maven refuses the file's syntax, before any value is expanded.
pub fn ignored_options(content: &str) -> Result<Vec<&'static str>, MavenConfigError> {
    let written = written_values(content)?;
    Ok([("-s", written.settings), ("-gs", written.global_settings)]
        .into_iter()
        .filter_map(|(option, named)| named.then_some(option))
        .chain(written.selection)
        .collect())
}

/// Whether a `-P` value of `.mvn/maven.config` or `command_line` holds a
/// `${...}`, so the profiles it selects can differ by platform.
pub(crate) fn selects_profiles_by_expression(
    content: Option<&str>,
    command_line: &CommandLine,
) -> bool {
    let written = content.map_or_else(|| Ok(Written::default()), written_values);
    written.is_ok_and(|written| {
        (written.profiles.iter())
            .chain(&command_line.profiles)
            .any(|p| p.contains("${"))
    })
}

/// The option values of a `.mvn/maven.config` that `raeva` reads, as
/// written.
#[derive(Default)]
struct Written {
    defines: Vec<String>,
    profiles: Vec<String>,
    settings: bool,
    global_settings: bool,
    /// The reactor selection options, `-pl`, `-am` and `-amd`, each once.
    selection: Vec<&'static str>,
}

fn written_values(content: &str) -> Result<Written, MavenConfigError> {
    let lines: Vec<&str> = java_lines(content)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let tokens = flatten(clean_args(&lines)?);

    let mut written = Written::default();
    let mut entries = Vec::new();
    let mut tokens = tokens.into_iter().peekable();
    while let Some(token) = tokens.next() {
        if token == "--" {
            entries.extend(tokens.by_ref().filter(|token| token != "--"));
            break;
        }
        if token == "-" || !token.starts_with('-') {
            entries.push(token);
            continue;
        }
        let Some(option) = option(&token) else {
            return Err(MavenConfigError::UnrecognizedOption(token));
        };
        if option.name == "llr" {
            return Err(MavenConfigError::UnsupportedOption);
        }
        if option.name == "f" {
            return Err(MavenConfigError::ProjectFile);
        }
        if let Some(selection) = ["-pl", "-am", "-amd"]
            .into_iter()
            .find(|selection| selection[1..] == *option.name)
            && !written.selection.contains(&selection)
        {
            written.selection.push(selection);
        }
        if !option.takes_value {
            continue;
        }
        let value = match tokens.peek() {
            Some(next) if !(next.starts_with('-') && self::option(next).is_some()) => {
                tokens.next().map(|next| strip_quotes(&next).to_string())
            }
            _ => None,
        };
        match (option.name, value) {
            ("D", Some(value)) => written.defines.push(value),
            ("P", Some(value)) => written.profiles.push(value),
            ("s", Some(_)) => written.settings = true,
            ("gs", Some(_)) => written.global_settings = true,
            (_, Some(_)) => {}
            (name, None) if !option.value_optional => {
                return Err(MavenConfigError::MissingArgument(name.to_string()));
            }
            (_, None) => {}
        }
    }
    if !entries.is_empty() {
        return Err(MavenConfigError::UnrecognizedEntries(entries));
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup record encodes as it did before a model field joined it
    /// unset, so the names a lock lists keep their spelling.
    #[test]
    fn a_lookup_record_without_new_model_fields_encodes_unchanged() {
        let record = r#"{"expression":"${${selector}}","properties":{},"default_packaging":"jar","source":"user","mode":"model","model":{"group_id":"g","artifact_id":"app","version":"1","packaging":"jar","parent":null,"build":{"directory":null,"finalName":null,"defaultGoal":null,"outputDirectory":null,"testOutputDirectory":null,"sourceDirectory":null,"testSourceDirectory":null,"scriptSourceDirectory":null},"base_dir":""}}"#;
        assert_eq!(PropertyLookup::parse(record).unwrap().encode(), record);
    }

    #[test]
    fn eager_user_property_expansion_does_not_record_host_inputs() {
        let host = rv_maven_model::HostSnapshot::for_testing(&[]);
        let environment = host.host_environment();
        let options = parse_for(
            Some("-Dbuild.jdk=${java.version}\n"),
            &CommandLine::default(),
            &environment,
            Path::new("/project"),
        )
        .unwrap();
        assert_eq!(options.properties["build.jdk"], host.java_version());
        assert!(host.consulted().is_empty());
        settings_file(
            Some("-P${java.version}\n"),
            &CommandLine::default(),
            &environment,
            Path::new("."),
        )
        .unwrap();
        assert!(
            host.consulted().is_empty(),
            "validation must not add host reads"
        );
        parse_for(
            Some("-P${java.version}\n"),
            &CommandLine::default(),
            &environment,
            Path::new("/project"),
        )
        .unwrap();
        assert!(
            host.consulted()
                .contains(&rv_maven_model::HostInput::JavaVersion)
        );
    }

    fn properties(content: &str) -> HashMap<String, String> {
        parse(content).expect("parses").properties
    }

    fn property(content: &str, name: &str) -> Option<String> {
        properties(content).get(name).cloned()
    }

    /// Each case was run through Maven 3.9.11 and the value read back from
    /// `help:effective-pom`.
    #[test]
    fn properties_follow_maven() {
        assert_eq!(property("-Da=1 -Db=2\n", "a").as_deref(), Some("1 -Db=2"));
        assert_eq!(property("-Da=1 -Db=2\n", "b"), None);
        assert_eq!(property("-D\nd=4\n", "d").as_deref(), Some("4"));
        assert_eq!(property("# -De=5\n", "e"), None);
        assert_eq!(
            property("-Df=\" quoted \"\n", "f").as_deref(),
            Some("\" quoted \"")
        );
        assert_eq!(property("-D\n\"g=5\"\n", "g").as_deref(), Some("5"));
        assert_eq!(property("-Dh\n", "h").as_deref(), Some("true"));
        assert_eq!(property("--define=i=6\n", "i").as_deref(), Some("6"));
        assert_eq!(property("--define\nj=7\n", "j").as_deref(), Some("7"));
        assert_eq!(property("-D k=8\n", "k").as_deref(), Some("8"));
        assert_eq!(property("-Dq=1   \n", "q").as_deref(), Some("1   "));
        assert_eq!(property("-Dn=a=b\n", "n").as_deref(), Some("a=b"));
        assert_eq!(property("-Do=1\n-Do=2\n", "o").as_deref(), Some("2"));
        assert_eq!(property("-Dr=\"x\"y\"\n", "r").as_deref(), Some("\"x\"y\""));
        assert_eq!(
            property("-D\n\"s=1\" \"t=2\"\n", "s").as_deref(),
            Some("1\" \"t=2")
        );
        assert_eq!(property("-D\n\"u=1\n", "u").as_deref(), Some("1"));
        assert_eq!(property("-D\nv=1\"\n", "v").as_deref(), Some("1\""));
        assert_eq!(property("-D\"u=1\"\n", "u").as_deref(), Some("1"));
        assert_eq!(
            property("-D\n\"u=1\n-D\nv=1\"\n", "u").as_deref(),
            Some("1 -D v=1\"")
        );
        assert_eq!(property("-Dx=${u}\n-Du=5\n", "x").as_deref(), Some("5"));
        assert_eq!(property("-Dz=1\r\n", "z").as_deref(), Some("1"));
        assert_eq!(property("-T\n4\n-Dy=1\n", "y").as_deref(), Some("1"));
    }

    #[test]
    fn maven_rejects_these_entries() {
        assert_eq!(
            parse("  -Dl=9\n"),
            Err(MavenConfigError::UnrecognizedEntries(vec![
                "  -Dl=9".to_string()
            ]))
        );
        assert_eq!(
            parse("garbage\n"),
            Err(MavenConfigError::UnrecognizedEntries(vec![
                "garbage".to_string()
            ]))
        );
        assert_eq!(
            parse("-P\n-Dx=1\n"),
            Err(MavenConfigError::MissingArgument("P".to_string()))
        );
        assert_eq!(
            parse("-D\n\"u=1\n--define\n\"w=1\"\n"),
            Err(MavenConfigError::UnrecognizedEntries(vec![
                "w=1".to_string()
            ]))
        );
        // Maven: "key can't be empty"; `-D=x` is `-D x`.
        for (content, value) in [("-D=\n", ""), ("-D\n =x\n", " =x")] {
            assert_eq!(
                parse(content),
                Err(MavenConfigError::EmptyPropertyName(value.to_string()))
            );
        }
        assert_eq!(property("-D=x\n", "x").as_deref(), Some("true"));
        assert_eq!(parse("-llr\n"), Err(MavenConfigError::UnsupportedOption));
        for content in ["-D\n\"\"\n", "--define= =x\n"] {
            assert!(
                matches!(parse(content), Err(MavenConfigError::EmptyPropertyName(_))),
                "{content:?}"
            );
        }
        assert!(matches!(
            parse("--no-such-option\n"),
            Err(MavenConfigError::UnrecognizedOption(_))
        ));
    }

    #[test]
    fn rejected_entries_are_bounded_in_the_message() {
        let mut content = format!("a\u{1b}[2J{}\n", "x".repeat(500));
        for n in 0..40 {
            content.push_str(&format!("entry{n}\n"));
        }
        let message = parse(&content).expect_err("refused").to_string();
        assert!(!message.contains('\u{1b}'), "{message}");
        assert!(message.contains("a\\u{1b}[2J"), "{message}");
        assert!(message.contains("x... (505 bytes)"), "{message}");
        assert!(message.contains("entry14, ... (41 entries)]"), "{message}");
        assert!(!message.contains("entry15"), "{message}");

        let option = format!("--{}\u{202e}\n", "o".repeat(300));
        let message = parse(&option).expect_err("refused").to_string();
        assert!(message.len() < 200, "{message}");
        assert!(!message.contains('\u{202e}'), "{message}");
    }

    #[test]
    fn profiles_follow_maven() {
        let options =
            parse("-Pp1,+p2\n-P p3\n--activate-profiles=p4\n-P\n!p5\n-P-p6,,p7\n").expect("parses");
        assert_eq!(options.active_profiles, ["p1", "p2", "p3", "p4", "p7"]);
        assert_eq!(options.inactive_profiles, ["p5", "p6"]);
    }

    #[test]
    fn other_maven_options_are_ignored() {
        let options =
            parse("-B\n--no-transfer-progress\n-T 1C\n-s\nsettings.xml\n-Dk=v\n").expect("parses");
        assert_eq!(options.properties.get("k").map(String::as_str), Some("v"));
    }

    /// `MavenCli` expands `-D` values against the JVM's system properties
    /// and then every other option value, `-P` included, against the system
    /// properties holding the `-D` values too.
    #[test]
    fn values_expand_against_the_platform_and_defines() {
        let system = ModelEnvironment::builder()
            .platform("linux", "aarch64")
            .build();
        let options = parse_for(
            Some("-DnativeArch=${os.arch}\n-Dchosen=extra\n-P${chosen},arch-${os.arch}\n"),
            &CommandLine::default(),
            &system,
            Path::new("/project"),
        )
        .expect("parses");
        assert_eq!(
            options.properties.get("nativeArch").map(String::as_str),
            Some("aarch64")
        );
        assert_eq!(options.active_profiles, ["extra", "arch-aarch64"]);
        let options = parse_for(
            Some("-P${undefined}\n"),
            &CommandLine::default(),
            &system,
            Path::new("/project"),
        )
        .expect("parses");
        assert_eq!(options.active_profiles, ["${undefined}"]);
    }

    /// Maven 3.9.12 merges the command line with `.mvn/maven.config`: the
    /// command line's `-P` values first and its `-D` values last, so they
    /// win, and the first `-s` is the one read.
    #[test]
    fn the_command_line_merges_as_maven_merges_it() {
        let command_line = CommandLine::new(
            vec!["v=cli".into(), "\"q=quoted\"".into(), "flag".into()],
            vec!["!pb".into()],
            Vec::new(),
        )
        .expect("valid");
        let options = parse_for(
            Some("-Dv=file\n-Dw=${v}\n-Ppb,pc\n-s\nfirst.xml\n-s\nsecond.xml\n"),
            &command_line,
            &ModelEnvironment::default(),
            Path::new("/project"),
        )
        .expect("parses");
        let property = |name: &str| options.properties.get(name).map(String::as_str);
        assert_eq!(property("v"), Some("cli"));
        assert_eq!(property("w"), Some("cli"));
        assert_eq!(property("q"), Some("quoted"));
        assert_eq!(property("flag"), Some("true"));
        assert_eq!(options.active_profiles, ["pb", "pc"]);
        assert_eq!(options.inactive_profiles, ["pb"]);
        // `-D"a=${a}` defines `"a`, `-D "a=${a}"` defines `a`.
        for value in ["\"a=${a}", "\"a=\"hello\"\"", "\""] {
            assert_eq!(
                CommandLine::new(vec![value.into()], Vec::new(), Vec::new()),
                Err(MavenConfigError::QuotedValue(value.into()))
            );
        }
    }

    /// `-Dmaven.repo.local` stays a user property.
    #[test]
    fn the_local_repository_stays_a_user_property() {
        let command_line = CommandLine::new(
            vec![
                "maven.repo.local=/m2".into(),
                " maven.repo.local =/other".into(),
                "maven.repo.local.tail=/tail".into(),
            ],
            Vec::new(),
            Vec::new(),
        )
        .expect("valid");
        let options = parse_for(
            None,
            &command_line,
            &ModelEnvironment::default(),
            Path::new("/project"),
        )
        .expect("parses");
        assert_eq!(
            options
                .properties
                .get(LOCAL_REPOSITORY_PROPERTY)
                .map(String::as_str),
            Some("/other")
        );
    }

    /// The command line's first `-s` wins, and its value expands with the
    /// command line's `-D` values and the project directory. Neither a `-s`
    /// nor a `-D` value of the file counts.
    #[test]
    fn the_settings_file_is_the_first_expanded() {
        let root = Path::new("/project");
        let file = |content: &str, command_line: &CommandLine| {
            settings_file(
                Some(content),
                command_line,
                &ModelEnvironment::default(),
                root,
            )
        };
        let content = "-Ddir=ci\n--settings=${maven.multiModuleProjectDirectory}/.mvn/${dir}.xml\n\
                       -s\nsecond.xml\n-gs\ng.xml\n";
        assert_eq!(file(content, &CommandLine::default()), Ok(None));
        let given = CommandLine::new(
            vec!["dir=cd".into()],
            Vec::new(),
            vec!["/ci/${dir}.xml".into(), "/other.xml".into()],
        )
        .unwrap();
        // On Windows `/ci` is on the current directory's drive.
        let absolute = |path: &str| Ok(Some(std::path::absolute(path).expect("absolute")));
        assert_eq!(file(content, &given), absolute("/ci/cd.xml"));
        let undefined = CommandLine::new(Vec::new(), Vec::new(), vec!["/ci/${dir}.xml".into()]);
        assert_eq!(
            file(content, &undefined.unwrap()),
            absolute("/ci/${dir}.xml")
        );
        let relative = CommandLine::new(Vec::new(), Vec::new(), vec!["here.xml".into()]).unwrap();
        assert_eq!(
            file("", &relative),
            Ok(Some(std::env::current_dir().expect("cwd").join("here.xml")))
        );
        assert_eq!(file("-Dx=1\n", &CommandLine::default()), Ok(None));
        assert_eq!(ignored_options(content), Ok(vec!["-s", "-gs"]));
        assert_eq!(ignored_options("-s\nx.xml\n"), Ok(vec!["-s"]));
        assert_eq!(ignored_options("-Dx=1\n"), Ok(vec![]));
        assert_eq!(
            ignored_options("--projects=app\n-amd\n--also-make\n-pl\nlib\n-s\nx.xml\n"),
            Ok(vec!["-s", "-pl", "-amd", "-am"])
        );
        assert_eq!(
            parse("-s\n").err(),
            Some(MavenConfigError::MissingArgument("s".into()))
        );
    }

    /// Maven 3.9.12 expands these three names to the project directory in
    /// `-s` and `-D` values, ahead of a `-D` of the same name (trino reads
    /// its settings from `${session.rootDirectory}/.mvn/settings.xml`).
    #[test]
    fn the_project_directory_names_expand_in_values() {
        let root = Path::new("/project");
        for name in [
            "session.rootDirectory",
            "session.topDirectory",
            "maven.multiModuleProjectDirectory",
        ] {
            let content = format!(
                "-s\n${{{name}}}/.mvn/s.xml\n-Dx=${{{name}}}/x\n-D{name}=/no\n-Pp${{{name}}}\n"
            );
            assert_eq!(
                settings_file(
                    Some(&content),
                    &CommandLine::default(),
                    &ModelEnvironment::default(),
                    root,
                ),
                Ok(None),
                "{name}"
            );
            let command_line = CommandLine {
                settings: vec![format!("${{{name}}}/.mvn/s.xml")],
                ..CommandLine::default()
            };
            assert_eq!(
                settings_file(None, &command_line, &ModelEnvironment::default(), root),
                Ok(Some(std::path::absolute("/project/.mvn/s.xml").unwrap())),
                "{name}"
            );
            let options = parse_for(
                Some(&content),
                &CommandLine::default(),
                &ModelEnvironment::default(),
                root,
            )
            .expect("parses");
            assert_eq!(options.properties["x"], "/project/x", "{name}");
            assert_eq!(options.properties[name], "/no", "{name}");
            assert_eq!(options.active_profiles, ["p/project"], "{name}");
            assert!(options.expanded_properties.contains("x"));
        }
    }

    /// Maven 3.9.12 builds `sub/pom.xml` for `-f sub/pom.xml` in
    /// `.mvn/maven.config`; raeva would lock another project, so it refuses.
    #[test]
    fn a_project_file_is_refused() {
        for content in ["-f\nsub/pom.xml\n", "--file=sub\n", "-fsub\n"] {
            assert_eq!(
                parse(content),
                Err(MavenConfigError::ProjectFile),
                "{content:?}"
            );
        }
        assert!(parse("-fae\n-ff\n-fn\n").is_ok());
    }
}
