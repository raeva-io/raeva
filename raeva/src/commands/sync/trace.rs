//! The plugin trace: what a build's mojos resolve while they run, which no
//! model names. Maven runs the build raeva.toml's `[plugins] trace` names
//! once, online, on a local repository that holds what the plugin tables
//! lock; each file it adds is fetched again by raeva, checked against
//! Maven's bytes, and pinned in a `trace` set keyed by the build's launcher
//! and arguments and the static sets it ran with.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use rv_config::Config;
use rv_lock::{
    LockArtifact, LockPlatform, Lockfile, PluginFiles, PluginRole, PluginSet, PluginTables,
    SupportPom,
};
use rv_maven_types::{ArtifactCoord, BlobId, Digest, Sha1, Sha256};
use rv_repo::{ArtifactRequest, FetchArtifact, RepoClient, RepoError, Repository};
use rv_store::{Origin, Store};

use crate::commands::lock_inputs::ReactorModel;
use crate::error::{CliError, Result};
use crate::session::Session;

/// The `sha256:` the trace set is keyed by: the launcher, arguments and
/// forwarded options of the build `config` traces, and the static sets it
/// ran with; `None` when it traces none. Another value means the trace is
/// stale.
pub(crate) fn trace_key(config: &Config, tables: &PluginTables) -> Option<String> {
    let trace = config.plugin_trace()?;
    let mvn = trace.mvn.as_deref().unwrap_or("mvn");
    let mut text = "trace\n".to_string();
    push_line(&mut text, "mvn", &[mvn]);
    for arg in &trace.args {
        push_line(&mut text, "arg", &[arg]);
    }
    // Maven reads the `-D` options, of `.mvn/maven.config` too, into
    // properties, the last value of a name winning, and its JVM those of
    // `.mvn/jvm.config` into system properties, which Maven sets the
    // former over. The build's local repository is raeva's.
    let line = config.maven_command_line();
    let defines: BTreeMap<&str, &str> = (line.defines.iter())
        .map(|define| rv_config::maven_config::define_property(define))
        .collect();
    for (&name, value) in &defines {
        if !LOCAL_REPOSITORY_PROPERTIES.contains(&name) {
            push_line(&mut text, "option -D", &[name, value]);
        }
    }
    for (name, value) in config.jvm_config_properties() {
        let name = name.as_str();
        if !LOCAL_REPOSITORY_PROPERTIES.contains(&name) && !defines.contains_key(name) {
            push_line(&mut text, "jvm -D", &[name, value]);
        }
    }
    // Plugins read the JVM option variables' too, such as `-Dartifact` in
    // `MAVEN_OPTS` for `dependency:get`.
    for (name, (value, _)) in keyed_jvm_options(config) {
        push_line(&mut text, "environment -D", &[&name, &value]);
    }
    // Maven 3.9 selects profiles by set membership, so the key holds the
    // ids each `-P` action names, however they are spelled and ordered.
    let mut profiles = BTreeSet::new();
    let written = (line.profiles.iter()).map(|ids| ("-P", ids.clone()));
    for (_, value) in
        (forwarded(config).into_iter().chain(written)).filter(|(option, _)| *option == "-P")
    {
        for (inactive, id) in rv_config::maven_config::profile_actions(&value) {
            profiles.insert((inactive, id.to_string()));
        }
    }
    for (inactive, id) in profiles {
        let action = rv_config::maven_config::profile_action(inactive, &id);
        push_line(&mut text, "option -P", &[&action]);
    }
    for set in tables
        .sets
        .iter()
        .filter(|set| set.role != PluginRole::Trace)
    {
        push_line(&mut text, "set", &[&set.key]);
    }
    Some(format!("sha256:{}", Sha256::from_bytes(text.as_bytes())))
}

/// Adds a line of [`trace_key`]'s text: `tag`, then each of `fields` after
/// its length in bytes, so that no field, such as a value that holds a
/// newline, reads as the end of its line or the start of another.
fn push_line(text: &mut String, tag: &str, fields: &[&str]) {
    text.push_str(tag);
    for field in fields {
        text.push_str(&format!(" {}:{field}", field.len()));
    }
    text.push('\n');
}

/// [`Config::jvm_option_properties`], with the project's POM files as
/// reactor discovery finds them on this machine. Discovery does not read
/// the options among the trace's arguments.
pub(crate) fn jvm_option_properties(config: &Config) -> BTreeMap<String, (String, &'static str)> {
    config.jvm_option_properties(|| {
        let options = (config.plugin_trace().into_iter())
            .flat_map(|trace| &trace.args)
            .any(|arg| arg.starts_with('-'));
        let config = config.recording_only_into(&rv_maven_model::HostReads::default());
        // The sync's own discovery reports what this one would log.
        let found = tracing::dispatcher::with_default(&tracing::Dispatch::none(), || {
            rv_resolver::Workspace::discover_project(&config, None)
                .and_then(|workspace| workspace.project_poms(options))
        });
        found.map_err(|error| error.to_string())
    })
}

/// The system properties of the JVM option variables that key the trace,
/// each with its value and channel: those the local repository raeva sets
/// and a `-D` on the command line or in `.mvn/maven.config` do not override.
pub(crate) fn keyed_jvm_options(config: &Config) -> BTreeMap<String, (String, &'static str)> {
    let line = config.maven_command_line();
    let defines: BTreeSet<&str> = (line.defines.iter())
        .map(|define| rv_config::maven_config::define_property(define).0)
        .collect();
    let mut options = jvm_option_properties(config);
    options.retain(|name, _| {
        !LOCAL_REPOSITORY_PROPERTIES.contains(&name.as_str()) && !defines.contains(name.as_str())
    });
    options
}

/// The `-D` and `-P` options the resolution read that the traced `mvn`
/// does not read itself: raeva's, then `active_profiles` and
/// `inactive_profiles`. It reads `.mvn/maven.config` and settings.xml.
/// [`option_args`] writes each so Maven reads it as raeva did.
fn forwarded(config: &Config) -> Vec<(&'static str, String)> {
    let line = config.command_line();
    let defines = (line.defines.iter()).map(|define| ("-D", define.clone()));
    let profiles = (line.profiles.iter()).chain(config.added_active_profiles());
    let inactive = (config.inactive_profiles.iter()).map(|id| ("-P", format!("!{id}")));
    (defines.chain(profiles.map(|ids| ("-P", ids.clone()))))
        .chain(inactive)
        .collect()
}

/// `option` and `value` as Maven reads them as `option value`: attached,
/// as a value that starts like an option of its own, such as `-ci` for
/// `-c`, would be read as one, unless it starts with `=`, where Maven
/// would split an attached `-P=a` at the `=`, or is empty, where a bare
/// `-P` would take the next argument.
fn option_args(option: &str, value: &str) -> Vec<String> {
    match value.is_empty() || value.starts_with('=') {
        true => vec![option.to_string(), value.to_string()],
        false => vec![format!("{option}{value}")],
    }
}

/// The properties [`with_local_repository`] sets over the build's own.
const LOCAL_REPOSITORY_PROPERTIES: [&str; 3] = [
    "maven.repo.local",
    "maven.repo.local.tail",
    "maven.repo.local.head",
];

/// `args` with the local repository `m2` after every option: Maven takes
/// the last `-D` of a name, however spelled, over .mvn/maven.config,
/// settings.xml profiles and MAVEN_OPTS too, and reads each argument after
/// `--` as a goal. An empty tail or head chains no other local repository,
/// which would serve files the build then never downloads into `m2`.
fn with_local_repository(args: &[String], m2: &Path) -> Vec<String> {
    let end = (args.iter())
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let mut all = args[..end].to_vec();
    let [local, tail, head] = LOCAL_REPOSITORY_PROPERTIES;
    all.push(format!("-D{local}={}", m2.display()));
    all.extend([format!("-D{tail}="), format!("-D{head}=")]);
    all.extend_from_slice(&args[end..]);
    all
}

/// The option the traced build's JVM gets through `JDK_JAVA_OPTIONS`,
/// which the java launcher of JDK 9 and later reads, every JVM the build
/// forks included, and JDK 8 does not: it turns off HotSpot's Base64
/// intrinsics, through whose x86-64 decoder CVE-2026-114938 (Java4Shell)
/// corrupts memory. A HotSpot JVM before 11 has no such option and refuses
/// to start with it; the trace then runs once more without it
/// ([`Seen::rejected_hardening`]).
const HARDENING: &str = "-XX:-UseBASE64Intrinsics";

/// How long the output of a traced build is still read once `mvn` has
/// exited, for what a process it left behind, such as one a mavenrc file
/// started, holds its output open with.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(2);

/// Whether and how [`HARDENING`] goes into `JDK_JAVA_OPTIONS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hardening {
    /// Not at all.
    Off,
    /// After the exported value, if any.
    Added,
    /// In place of a value the shell holds without exporting it, which the
    /// JVM does not get.
    Exported,
}

impl Hardening {
    /// The word the traced build's shell reads ([`rv_maven_model::mavenrc::TracedLaunch::Sourced`]).
    fn word(self) -> &'static [u8] {
        match self {
            Self::Off => b"run\n",
            Self::Added => b"harden\n",
            Self::Exported => b"harden-unexported\n",
        }
    }
}

/// Whether the traced build gets [`HARDENING`], as `mvn` holds the
/// variables `shell` once the mavenrc files `files` ran, with
/// `.mvn/jvm.config` `jvm_config`, on the JDK `release`. It does only on a
/// HotSpot JDK whose release file names 11 or later, and where no option
/// makes it refuse an option it does not know. OpenJ9 has no HotSpot
/// intrinsics.
///
/// # Errors
///
/// When an option the JVM reads after `JDK_JAVA_OPTIONS`, of
/// `.mvn/jvm.config`, `MAVEN_OPTS`, `MAVEN_DEBUG_OPTS` or `_JAVA_OPTIONS`,
/// turns the intrinsic back on, or names a file that sets it, which raeva
/// does not read.
fn hardening(
    release: Option<&rv_maven_model::JdkRelease>,
    shell: &rv_maven_model::mavenrc::Shell,
    jvm_config: Option<&str>,
    files: &[PathBuf],
    dir: &Path,
) -> Result<Hardening> {
    let text =
        |value: Option<Vec<u8>>| String::from_utf8_lossy(&value.unwrap_or_default()).into_owned();
    let tool = text(shell.exported("JAVA_TOOL_OPTIONS"));
    let launcher = text(shell.exported("JDK_JAVA_OPTIONS"));
    // The command line `mvn` gives, then what HotSpot reads after it.
    let after = [
        (
            ".mvn/jvm.config",
            jvm_config.unwrap_or_default().to_string(),
        ),
        ("MAVEN_OPTS", text(shell.shell_value("MAVEN_OPTS"))),
        (
            "MAVEN_DEBUG_OPTS",
            text(shell.shell_value("MAVEN_DEBUG_OPTS")),
        ),
        ("_JAVA_OPTIONS", text(shell.exported("_JAVA_OPTIONS"))),
    ];
    let Some(release) = release else {
        return Ok(Hardening::Off);
    };
    let feature = release
        .version_numbers()
        .and_then(|numbers| numbers.first().copied());
    let strict = (after.iter().map(|(_, opts)| opts.as_str()))
        .chain([tool.as_str(), launcher.as_str()])
        .any(|opts| opts.contains("IgnoreUnrecognizedXXColonOptions"));
    if feature.is_none_or(|feature| feature < 11) || release.openj9 || strict {
        return Ok(Hardening::Off);
    }
    if let Some((channel, why)) = intrinsic_back_on(&after, dir) {
        let by = match files.is_empty() {
            true => String::new(),
            false => {
                let files: Vec<String> = (files.iter())
                    .map(|file| file.display().to_string())
                    .collect();
                format!(", as {} leave it,", files.join(" and "))
            }
        };
        return Err(CliError::Config(
            rv_config::ConfigError::UnreadHostProperty(format!(
                "{channel}{by} {why}, after the {HARDENING} raeva gives the build [plugins] \
                 trace runs in JDK_JAVA_OPTIONS, so the build would run with HotSpot's Base64 \
                 intrinsics (CVE-2026-114938); take it out of {channel}"
            )),
        ));
    }
    let unexported = shell.shell_value("JDK_JAVA_OPTIONS").is_some()
        && shell.exported("JDK_JAVA_OPTIONS").is_none();
    Ok(match unexported {
        true => Hardening::Exported,
        false => Hardening::Added,
    })
}

/// The channel of `channels`, in the order the JVM reads them, whose
/// option last names the Base64 intrinsic, and how, where that does not
/// leave it off: an option that turns it on, or an argument file (`@file`
/// on the command line, `-XX:VMOptionsFile=` anywhere) that names it, which
/// raeva does not read in place. A relative file is read from `dir`.
fn intrinsic_back_on(
    channels: &[(&'static str, String)],
    dir: &Path,
) -> Option<(&'static str, String)> {
    let mut last = None;
    for (channel, text) in channels {
        let split = || {
            (text.split([' ', '\t', '\n', '\r']))
                .filter(|word| !word.is_empty())
                .map(str::to_string)
                .collect()
        };
        // HotSpot reads quotes in its variables; `mvn` passes the others on
        // unquoted, split at white space.
        let words: Vec<String> = match *channel {
            "_JAVA_OPTIONS" => rv_config::jvm_words(text.as_bytes()).map_or_else(split, |words| {
                (words.iter())
                    .map(|word| String::from_utf8_lossy(word).into_owned())
                    .collect()
            }),
            _ => split(),
        };
        for word in &words {
            let file = match word.strip_prefix('@') {
                Some(file) if *channel != "_JAVA_OPTIONS" => Some((file, false)),
                _ => (word.split_once("VMOptionsFile=")).map(|(_, file)| (file, true)),
            };
            if let Some((file, vm)) = file {
                if names_intrinsic(&dir.join(file), vm, dir, 0) {
                    last = Some((*channel, format!("names {word}, which sets the intrinsic")));
                }
            } else if word.contains("UseBASE64Intrinsics") {
                let option = word.replace(['"', '\''], "");
                last = (option != HARDENING).then(|| (*channel, format!("gives {option}")));
            }
        }
    }
    last
}

/// Whether the option file `file`, an argument file or a VM options file
/// when `vm`, or one it names with `-XX:VMOptionsFile=`, names the Base64
/// intrinsic. Its words are read as the JVM reads that kind of file, so a
/// quoted name may hold a space.
fn names_intrinsic(file: &Path, vm: bool, dir: &Path, depth: usize) -> bool {
    let Ok(text) = std::fs::read(file) else {
        return false;
    };
    if String::from_utf8_lossy(&text).contains("UseBASE64Intrinsics") {
        return true;
    }
    let words = match vm {
        true => rv_config::jvm_words(&text).unwrap_or_default(),
        false => rv_config::argument_file_words(&text),
    };
    depth < 8
        && (words.iter())
            .map(|word| String::from_utf8_lossy(word).into_owned())
            .filter_map(|word| {
                (word.split_once("VMOptionsFile=")).map(|(_, file)| file.to_string())
            })
            .any(|nested| names_intrinsic(&dir.join(nested), true, dir, depth + 1))
}

/// `files` as a message names them.
fn listed(files: &[PathBuf]) -> String {
    (files.iter())
        .map(|file| file.display().to_string())
        .collect::<Vec<_>>()
        .join(" and ")
}

/// Refuse a traced build whose launcher runs a `bin/mvn` of its own, which
/// skips the mavenrc `files` the shell sourced from `before`, as `shell`
/// leaves them, where that `bin/mvn` would not have what they leave: a
/// variable it reads that they set without exporting it, or one the
/// Wrapper's `mvnw` reads that they change, which it would not see.
fn refuse_lost_by_exec(
    shell: &rv_maven_model::mavenrc::Shell,
    before: &[(OsString, OsString)],
    files: &[PathBuf],
) -> Result<()> {
    use rv_maven_model::mavenrc::{EXEC_SHELL_VARIABLES, EXEC_WRAPPER_VARIABLES};

    let was = |name: &str| {
        (before.iter().rev())
            .find(|(set, _)| set == name)
            .map(|(_, value)| value.as_encoded_bytes().to_vec())
    };
    let why = if let Some(name) =
        (EXEC_SHELL_VARIABLES.iter()).find(|name| shell.shell_value(name) != shell.exported(name))
    {
        format!("set {name} without exporting it")
    } else if let Some(name) =
        (EXEC_WRAPPER_VARIABLES.iter()).find(|name| shell.exported(name) != was(name))
    {
        format!("change {name}, which the Maven Wrapper reads before they run")
    } else {
        return Ok(());
    };
    Err(CliError::Config(
        rv_config::ConfigError::UnreadHostProperty(format!(
            "{}, which mvn sources, {why}; the launcher of the build [plugins] trace runs \
             starts a mvn of its own, which skips them after raeva sourced them, so it would \
             not have that: export it in them instead, or run both raeva and mvn with \
             MAVEN_SKIP_RC=1",
            listed(files)
        )),
    ))
}

/// Why the traced build cannot run: its launcher would source the mavenrc
/// files again.
fn unsourced(error: rv_maven_model::mavenrc::UnsourcedLauncher) -> CliError {
    CliError::Config(rv_config::ConfigError::UnreadHostProperty(format!(
        "{}, which mvn sources, may run again when {} starts the build [plugins] trace runs, \
         after raeva read them, and give it values raeva does not see: it reads them its own \
         way, which may not skip them; run both raeva and mvn with MAVEN_SKIP_RC=1 to trace \
         the build",
        listed(&error.files),
        error.launcher.display()
    )))
}

/// The longest line of the traced build's output raeva matches: of a
/// longer one, only this much.
const LINE: usize = 8 * 1024;

/// How much of the traced build's output a JVM that refuses [`HARDENING`]
/// writes before it says so, at most: it says so before anything else runs.
const HEAD: usize = 64 * 1024;

/// What raeva holds that the traced build's output may select and never
/// supply: the plugins of the platform's tables, by `g:a:v`, the files that
/// hold their goals, and the artifactIds of the reactor's modules.
struct Known<'a> {
    plugins: Vec<&'a str>,
    artifacts: &'a [LockArtifact],
    store: &'a Store,
    modules: Vec<&'a str>,
}

impl Known<'_> {
    /// The goal of `plugin`'s descriptor, in the store, spelled `goal`.
    fn goal(&self, plugin: &str, goal: &[u8]) -> Option<String> {
        let jar = (self.artifacts.iter()).find(|artifact| {
            let coordinate = &artifact.coordinate;
            coordinate.extension() == "jar"
                && coordinate.classifier().is_none()
                && coordinate.gav.to_string() == plugin
        })?;
        let Some(Digest::Sha256(sha256)) = jar.pin() else {
            return None;
        };
        let blob: BlobId = sha256.to_string().parse().ok()?;
        (rv_resolver::plugin_goals(&self.store.get_path(&blob)).into_iter())
            .find(|known| known.as_bytes() == goal)
    }
}

/// A failure the traced build's output shows, each found by a fixed
/// pattern and told in raeva's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Failure {
    Jvm,
    Plugin,
    Pom,
    Refused,
}

/// What Maven's line about a file a repository did not give starts with.
const TRANSFER: &[u8] = b"Could not transfer ";

impl Failure {
    const ALL: [Self; 4] = [Self::Jvm, Self::Plugin, Self::Pom, Self::Refused];

    fn shown_by(self, line: &[u8]) -> bool {
        let starts = |prefix: &str| line.starts_with(prefix.as_bytes());
        let holds = |text: &str| (line.windows(text.len())).any(|part| part == text.as_bytes());
        match self {
            // A JVM the build forks prints the same lines, so it is "a JVM".
            Self::Jvm => {
                starts("Error: Could not create the Java Virtual Machine")
                    || starts("Error occurred during initialization of VM")
            }
            Self::Plugin => {
                starts("[ERROR] Plugin ")
                    && holds(" or one of its dependencies could not be resolved")
            }
            Self::Pom => {
                (starts("[ERROR] ") || starts("[FATAL] "))
                    && (holds("The build could not read ")
                        || holds("Non-resolvable parent POM")
                        || holds("Non-readable POM"))
            }
            // Maven's "Could not transfer ..." line ends "status code: 401" on
            // 3.9's default transport, "HTTP Status: 401" on 3.10's and
            // "status: 401 Unauthorized" on wagon's.
            Self::Refused => {
                let Some(at) = (line.windows(TRANSFER.len())).position(|part| part == TRANSFER)
                else {
                    return false;
                };
                let rest = &line[at + TRANSFER.len()..];
                ["status code: ", "HTTP Status: ", "status: "]
                    .iter()
                    .any(|spelling| {
                        ["401", "403"].iter().any(|code| {
                            let text = [spelling.as_bytes(), code.as_bytes()].concat();
                            (rest.windows(text.len()).enumerate()).any(|(at, part)| {
                                part == text.as_slice()
                                    && !(rest.get(at + text.len())).is_some_and(u8::is_ascii_digit)
                            })
                        })
                    })
            }
        }
    }

    fn words(self) -> &'static str {
        match self {
            Self::Jvm => "a JVM could not start",
            Self::Plugin => "a plugin could not be resolved",
            Self::Pom => "a POM could not be read or built",
            Self::Refused => "a repository refused access (401 or 403)",
        }
    }
}

/// Where Maven's first `[ERROR] Failed to execute goal` line says the
/// build failed, in raeva's own names: a plugin of [`Known::plugins`], the
/// goal its descriptor spells as the line does, and a module.
#[derive(Debug, Default, PartialEq, Eq)]
struct Failed {
    plugin: Option<usize>,
    goal: Option<String>,
    module: Option<usize>,
}

/// What raeva takes from one run of the traced build's output as it reads
/// it a line at a time, and drops each line: whether lines match a few
/// fixed patterns, and which of raeva's own names Maven's failure line
/// selects.
#[derive(Debug, Default)]
struct Seen {
    /// How many bytes of output were read, of both streams.
    read: usize,
    /// Whether the JVM said it does not know [`HARDENING`] within [`HEAD`].
    unknown_hardening: bool,
    /// Whether the JVM said it could not start within [`HEAD`].
    no_jvm: bool,
    failed: Option<Failed>,
    failures: BTreeSet<Failure>,
}

impl Seen {
    /// Take what raeva matches from `line`, at most [`LINE`] bytes of one,
    /// which starts `at` bytes into the output.
    fn line(&mut self, line: &[u8], at: usize, known: &Known<'_>) {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let holds = |text: &[u8]| (line.windows(text.len())).any(|part| part == text);
        if at < HEAD {
            self.unknown_hardening |= holds(b"Unrecognized VM option 'UseBASE64Intrinsics'");
            self.no_jvm |= holds(b"Could not create the Java Virtual Machine");
        }
        for failure in Failure::ALL {
            if failure.shown_by(line) {
                self.failures.insert(failure);
            }
        }
        if self.failed.is_none() {
            self.failed = failed(line, known);
        }
    }

    /// Whether the build failed because its JVM refused to start with
    /// [`HARDENING`], as a HotSpot JVM before 11 does.
    fn rejected_hardening(&self) -> bool {
        self.unknown_hardening && self.no_jvm
    }
}

/// [`Failed`] of `line`, when it is Maven's
/// `[ERROR] Failed to execute goal <g>:<a>:<v>:<goal> (<execution>) on
/// project <artifactId>: ...` or `[ERROR] Failed to execute goal on project
/// <artifactId>: ...`. Only names raeva holds are taken, and the execution
/// never.
fn failed(line: &[u8], known: &Known<'_>) -> Option<Failed> {
    let rest = line.strip_prefix(b"[ERROR] Failed to execute goal ")?;
    let mut failed = Failed::default();
    let word = rest.split(|&b| b == b' ').next().unwrap_or_default();
    let parts: Vec<&[u8]> = word.split(|&b| b == b':').collect();
    if let [group, artifact, version, goal] = parts[..] {
        let plugin = [group, artifact, version].join(&b':');
        failed.plugin = (known.plugins.iter()).position(|known| known.as_bytes() == plugin);
        let plain = !goal.is_empty()
            && goal.len() <= 64
            && (goal.iter()).all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
        if let Some(plugin) = failed.plugin.filter(|_| plain) {
            failed.goal = known.goal(known.plugins[plugin], goal);
        }
    }
    const PROJECT: &[u8] = b" on project ";
    let at = (line.windows(PROJECT.len())).position(|part| part == PROJECT);
    if let Some(at) = at {
        let name = line[at + PROJECT.len()..].split(|&b| b == b':').next();
        failed.module = (known.modules.iter())
            .position(|module| name.is_some_and(|name| module.as_bytes() == name));
    }
    Some(failed)
}

/// Read each line `from` gives into `seen` and drop it, until its end or,
/// once `ended` turns true, [`DRAIN`] later: a process the build left may
/// hold it open. The bytes are matched as they are, in no encoding.
async fn scan(
    from: Option<impl tokio::io::AsyncRead + Unpin>,
    seen: &std::sync::Mutex<Seen>,
    known: &Known<'_>,
    mut ended: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let Some(mut from) = from else {
        return Ok(());
    };
    let stop = async move {
        let _ = ended.wait_for(|ended| *ended).await;
        tokio::time::sleep(DRAIN).await;
    };
    tokio::pin!(stop);
    let mut chunk = vec![0; LINE];
    let mut line = Vec::with_capacity(LINE);
    let mut at = 0;
    loop {
        let read = tokio::select! {
            biased;
            read = from.read(&mut chunk) => read?,
            () = &mut stop => 0,
        };
        let mut seen = seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if read == 0 {
            if !line.is_empty() {
                seen.line(&line, at, known);
            }
            return Ok(());
        }
        for part in chunk[..read].split_inclusive(|&b| b == b'\n') {
            if line.is_empty() {
                at = seen.read;
            }
            seen.read = seen.read.saturating_add(part.len());
            let room = LINE - line.len();
            line.extend_from_slice(&part[..part.len().min(room)]);
            if part.ends_with(b"\n") {
                seen.line(&line, at, known);
                line.clear();
            }
        }
    }
}

/// Refuse what the traced build cannot be given as the resolution read
/// it: a profile id of raeva.toml or config.toml that `-P` would split,
/// trim, negate or expand, or a reactor selection, with which it would run
/// only some of the modules raeva locks.
pub(super) fn check_forwarded(config: &Config) -> Result<()> {
    if let Some((origin, option)) = config.reactor_selection() {
        return Err(CliError::Config(rv_config::ConfigError::Invalid {
            origin: origin.clone(),
            message: format!(
                "it holds {option}, which picks the modules a build runs, so the build \
                 [plugins] trace runs would not build the whole reactor raeva locks and would \
                 miss what the other modules' plugins fetch; take it out where raeva traces \
                 the build"
            ),
        }));
    }
    let ids = (config.added_active_profiles().iter()).chain(&config.inactive_profiles);
    if let Some(id) = ids.into_iter().find(|id| {
        // Maven trims each id as Java's trim does.
        id.is_empty()
            || id.trim() != id.as_str()
            || id.starts_with(['!', '-', '+', '?', '"'])
            || id.contains(|c: char| c.is_control() || c == ',' || c == '$')
    }) {
        return Err(CliError::Usage(format!(
            "profile id {id:?} in active_profiles or inactive_profiles cannot be given to the \
             build [plugins] trace runs, which reads it as `-P` does; rename the profile or \
             drop the id"
        )));
    }
    Ok(())
}

/// Whether `tables` hold at most one trace, of the build `config` names.
pub(crate) fn traces_hold(config: &Config, tables: &PluginTables) -> bool {
    let mut traced = (tables.sets.iter()).filter(|set| set.role == PluginRole::Trace);
    match (traced.next(), traced.next()) {
        (None, _) => true,
        (Some(set), None) => trace_key(config, tables).is_some_and(|key| set.key == key),
        (Some(_), Some(_)) => false,
    }
}

/// Whether `entries` for this machine's OS and architecture hold one trace,
/// of the build `config` names: a conflicted lock regenerated may keep a
/// stale trace beside it on another JDK.
pub(crate) fn traced_here<'a>(
    config: &Config,
    entries: impl IntoIterator<Item = &'a LockPlatform>,
) -> Result<bool> {
    let host = rv_lock::Platform::current()?.os_arch();
    Ok(traced_on(config, entries, &host))
}

/// [`traced_here`] for the OS and architecture `os_arch`.
pub(crate) fn traced_on<'a>(
    config: &Config,
    entries: impl IntoIterator<Item = &'a LockPlatform>,
    os_arch: &str,
) -> bool {
    let mut traced = (entries.into_iter())
        .filter(|entry| entry.platform.os_arch() == os_arch)
        .filter_map(|entry| entry.plugins.as_ref())
        .flat_map(|tables| {
            (tables.sets.iter())
                .filter(|set| set.role == PluginRole::Trace)
                .map(move |set| (tables, set))
        });
    match (traced.next(), traced.next()) {
        (Some((tables, set)), None) => trace_key(config, tables).as_deref() == Some(&set.key),
        _ => false,
    }
}

/// Run the build raeva.toml names and add what it read to the plugin
/// tables, on the platform of this machine's OS, architecture and JDK, or
/// its first of this OS and architecture. Only a plain online sync calls
/// this: the build runs the project's code. A file raeva.lock pins, such as
/// one of the trace this replaces, keeps its bytes unless `update`. On
/// failure or cancellation, raeva.lock gets back the bytes it held before
/// an `--update` sync, unless another write changed it meanwhile. Returns
/// the lock it wrote, if it wrote one.
pub(super) async fn trace(
    session: &Session,
    config: &Config,
    start: Start,
    update: bool,
    allow_missing_checksums: bool,
) -> Result<Option<rv_lock::Lockfile>> {
    let Start {
        models,
        written,
        previous,
    } = start;
    let mut put_back = PutBack {
        config,
        output: session.output(),
        project_root: session.project_root(),
        written,
        previous,
    };
    let mode = super::Mode::trace(allow_missing_checksums);
    let traced = trace_build(session, config, &models, mode, update, &put_back.written).await;
    let restored = match &traced {
        Ok(Ended::Recorded(_)) => false,
        _ if put_back.previous.is_none() => false,
        _ => {
            let guard = super::lockfile_guard(config, session.project_root(), session.output());
            match guard.await {
                Ok(_guard) => put_back.put_back()?,
                Err(_) => false,
            }
        }
    };
    put_back.previous = None;
    let (held, again) = match restored {
        true => ("is as it was before this sync", "raeva sync --update"),
        false => ("holds no trace of it", "raeva sync"),
    };
    if traced.is_err() && restored {
        session
            .output()
            .note("raeva.lock is as it was before this sync");
    }
    match traced? {
        Ended::Recorded(written) => Ok(written),
        Ended::Failed { failure, rerun } => Err(CliError::Message(format!(
            "the traced build failed{failure}, so raeva.lock {held}. raeva does not show or keep \
             the build's output: to see it, {rerun}. Make the build pass in this checkout, where \
             raeva.toml and raeva.lock may be new files to it, then run '{again}' again"
        ))),
    }
}

/// raeva.lock as an `--update` sync found it, to put back over the bytes
/// the sync wrote when the trace does not record: also when the sync is
/// cancelled during the build, as a drop.
struct PutBack<'a> {
    config: &'a Config,
    output: &'a crate::output::Output,
    project_root: &'a Path,
    written: Option<Vec<u8>>,
    previous: Option<Vec<u8>>,
}

impl PutBack<'_> {
    /// Put back the previous bytes once, under the lockfile guard the
    /// caller holds, unless another write changed raeva.lock. Bytes the
    /// sync left as they were stay unwritten, as a link raeva does not
    /// write through.
    fn put_back(&mut self) -> Result<bool> {
        let path = &self.config.lock_path;
        match self.previous.take() {
            Some(previous) if super::lock_bytes(path) == self.written => {
                if self.written.as_ref() != Some(&previous) {
                    crate::commands::util::write_atomic(path, &previous)?;
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

impl Drop for PutBack<'_> {
    fn drop(&mut self) {
        if self.previous.is_none() {
            return;
        }
        // As a failed trace waits, before the process exits.
        let output = self.output;
        let guard = rv_lock::LockfileGuard::acquire(
            &self.config.paths.cache_dir,
            self.project_root,
            std::time::Duration::from_secs(60),
            || output.step("Waiting for another raeva sync of this project to finish..."),
        );
        match guard.is_ok_and(|_guard| self.put_back().unwrap_or(false)) {
            true => output.note("raeva.lock is as it was before this sync"),
            false => output.note(
                "raeva.lock may not be as this sync found it; run 'raeva sync --update' again",
            ),
        }
    }
}

/// What the trace starts from, read under the sync's lockfile guard. The
/// build runs without it, so another sync may write raeva.lock meanwhile:
/// the trace is then not recorded, and the lock not put back.
pub(super) struct Start {
    /// The models the sync resolved.
    pub(super) models: Vec<ReactorModel>,
    /// raeva.lock as the sync left it.
    pub(super) written: Option<Vec<u8>>,
    /// Under `--update`, raeva.lock as the sync found it.
    pub(super) previous: Option<Vec<u8>>,
}

/// How the traced build ended: recorded, with the lock it wrote, if any,
/// or failed, as where and how, with how to run it again.
enum Ended {
    Recorded(Option<rv_lock::Lockfile>),
    Failed { failure: String, rerun: String },
}

async fn trace_build(
    session: &Session,
    config: &Config,
    models: &[ReactorModel],
    mode: super::Mode,
    update: bool,
    written: &Option<Vec<u8>>,
) -> Result<Ended> {
    let Some(traced) = config.plugin_trace() else {
        return Ok(Ended::Recorded(None));
    };
    let path = &config.lock_path;
    let mut lock = crate::commands::util::read_lockfile_at(path)?;
    if traced_here(config, &lock.platforms)? {
        return Ok(Ended::Recorded(None));
    }
    let host = rv_lock::Platform::current()?.os_arch();
    let here: Vec<usize> = (0..lock.platforms.len())
        .filter(|&at| {
            let entry = &lock.platforms[at];
            entry.platform.os_arch() == host && entry.plugins.is_some()
        })
        .collect();
    let host_jdk = config.host().named_java_version();
    let Some(at) = (here.iter().copied())
        .find(|&at| {
            (lock.platforms[at].platform.jdk()).is_none_or(|jdk| {
                host_jdk.is_some_and(|host| rv_config::jdk_matches_target(jdk, host))
            })
        })
        .or(here.first().copied())
    else {
        return Ok(Ended::Recorded(None));
    };
    let mut files = lock.platforms[at]
        .plugin_files()
        .expect("the platform holds plugin tables");
    let key = trace_key(config, &files.tables).expect("raeva.toml names a trace");
    files.retain_sets(|set| set.role != PluginRole::Trace);

    let work = tempfile::Builder::new()
        .prefix("plugin-trace-")
        .tempdir_in(&config.paths.cache_dir)
        .map_err(CliError::io_at(&config.paths.cache_dir))?;
    let m2 = work.path().join("m2");
    let export = crate::commands::export_m2::ExportM2Args {
        dry_run: false,
        overwrite: false,
        link: rv_export::LinkStrategy::Copy,
        m2_path: Some(m2.clone()),
        with_sources: false,
        with_javadocs: false,
        plan_json: false,
    };
    // The build runs on the static tables of the platform it traces: a
    // file the trace this replaces pinned, or only another platform pins,
    // is one the build must read for this trace to see it.
    let mut exported = lock.clone();
    let read = exported.target_reads().swap_remove(at);
    exported.platforms = vec![exported.platforms.swap_remove(at)];
    exported.set_target_reads(&[read])?;
    drop_trace(&mut exported.platforms[0], &lock.repo_ids)?;
    let mut export_config = config.clone();
    export_config.lock_path = work.path().join("raeva.lock");
    // The lock holds the tables without the trace this sync makes.
    if let Some(plugins) = export_config.plugins.as_mut() {
        plugins.trace = None;
    }
    let exported_lock = export_config.lock_path.clone();
    exported.write_atomic(&exported_lock)?;
    let output = session.output();
    if output.shows_progress() {
        output.step("Tracing the plugins of the build...");
    }
    // Its notes, such as that raeva.lock is up to date, are not this sync's.
    let quiet = session.with_output(output.quieted());
    crate::commands::export_m2::run_with(&export, &quiet, export_config, true).await?;
    let before = files_under(&m2)?;

    let mvn = traced.launcher(&config.project_root)?;
    let options = forwarded(config);
    let launch = rv_maven_model::mavenrc::traced_launch(&mvn, HARDENING).map_err(unsourced)?;
    let store = Store::open(&config.paths.store_dir)?;
    let known = Known {
        plugins: (files.tables.sets.iter())
            .filter(|set| matches!(set.role, PluginRole::Plugin | PluginRole::BuildExtension))
            .filter_map(|set| set.coordinates.first().map(String::as_str))
            .collect(),
        artifacts: &files.artifacts,
        store: &store,
        modules: (models.iter())
            .flat_map(|model| model.workspace.modules())
            .map(|module| module.gav().artifact_id.as_str())
            .collect(),
    };
    let mut harden = true;
    let mut noted = false;
    let (status, started, hardened, seen) = loop {
        let run = TraceRun {
            config,
            output,
            mvn: &mvn,
            known: &known,
            options: &options,
            args: with_local_repository(&traced.args, &m2),
            arg_count: traced.args.len(),
            harden,
            noted,
        };
        let started = std::time::SystemTime::now();
        let (status, hardened, seen) = run.run(&launch).await?;
        noted = true;
        if !status.success() && hardened && seen.rejected_hardening() {
            harden = false;
            output.note(&format!(
                "The JVM of the traced build does not know {HARDENING}; tracing it again \
                 without that option"
            ));
            // Lets a Ctrl-C that came with the exit stop the sync first.
            tokio::task::yield_now().await;
            continue;
        }
        break (status, started, hardened, seen);
    };
    if !status.success() {
        let mut failure = String::new();
        if let Some(failed) = &seen.failed {
            if let Some(plugin) = failed.plugin {
                failure = format!(" in {}", known.plugins[plugin]);
                if let Some(goal) = &failed.goal {
                    failure = format!("{failure}:{goal}");
                }
            }
            if let Some(module) = failed.module {
                failure = format!("{failure} on project {}", known.modules[module]);
            }
        }
        failure = format!("{failure} ({status})");
        let failures: Vec<&str> = (seen.failures.iter())
            .map(|failure| failure.words())
            .collect();
        if !failures.is_empty() {
            failure = format!("{failure}: {}", failures.join("; "));
        }
        let sourced = matches!(
            launch,
            rv_maven_model::mavenrc::TracedLaunch::Sourced { .. }
        );
        let rerun = rerun(config, &mvn, &options, sourced, hardened);
        return Ok(Ended::Failed { failure, rerun });
    }

    let added: Vec<PathBuf> = (files_under(&m2)?.into_iter())
        .filter(|file| !before.contains(file))
        .collect();
    let mut client = mode.client(config).await?;
    if !update {
        client = client.with_lock_pins(&lock);
    }
    let found = lock.clone();
    let entry = &lock.platforms[at];
    let candidates = candidate_repositories(config, &client, &store, models, &lock, entry, &files);
    let Some((repos, declared)) = candidates.await? else {
        session.output().note(&format!(
            "raeva.lock has no trace of platform '{}': its plugins resolve from a repository \
             the project's own POMs do not declare, which only a sync of that platform can \
             check; run 'raeva sync' with it among the platforms",
            entry.platform
        ));
        return Ok(Ended::Recorded(None));
    };
    let (mut read, unmarked) = traced_files(&m2, &before, &added)?;
    let known = |id: &str| declared.iter().any(|repo| names(config, repo, id));
    read.extend(nested_repository_files(
        &config.project_root,
        &m2,
        started,
        &known,
    )?);
    let mut traced = Vec::new();
    let required = read.into_iter().map(|read| (read, true));
    for ((coordinate, file, id), required) in
        required.chain(unmarked.into_iter().map(|read| (read, false)))
    {
        let sha256 = Sha256::from_file(&file).map_err(CliError::io_at(&file))?;
        let repos = named_first(config, &repos, id.as_deref());
        match fetch_matching(&client, &store, &repos, &coordinate, &sha256).await {
            Ok(repo) => traced.push((coordinate, sha256, repo)),
            Err(error) if repinned(&error) => return Err(error),
            // A file no repository serves is the build's own.
            Err(_) if !required => {}
            Err(error) => return Err(error),
        }
    }
    let origins = rv_lock::LockOrigins::for_root(&config.project_root);
    // A file read through a repository whose URL the lock cannot record
    // takes the empty origin, as a resolution's does.
    let mut unrecorded = Vec::new();
    for (_, _, repo) in &mut traced {
        if !origins.records_declaration(&repo.url) {
            let read = (std::mem::take(&mut repo.url), repo.id.take());
            if !unrecorded.contains(&read) {
                unrecorded.push(read);
            }
        }
    }
    // The tables may hold the empty origin already, for a file read
    // through another such repository, so all the trace may read count.
    if !unrecorded.is_empty() {
        let selection =
            rv_repo::LockRepositorySelector::new(config, &origins, &repos).select("", None);
        let refusal = match selection {
            rv_lock::OriginSelection::Declared(_) if unrecorded.len() == 1 => None,
            rv_lock::OriginSelection::Undeclared if unrecorded.len() == 1 => {
                Some(rv_lock::unrecordable_plugin_origin())
            }
            _ => Some(rv_lock::several_unrecordable_plugin_origins()),
        };
        if let Some(refusal) = refusal {
            return Err(CliError::Lock(refusal));
        }
    }
    // The arguments may hold a secret, so the set records only their key.
    let mut row = PluginSet::new(&key, PluginRole::Trace);
    // The POMs the lock pins without the traces this one replaces, which
    // the lock it writes no longer holds.
    let mut kept = lock.clone();
    for &other in &here {
        drop_trace(&mut kept.platforms[other], &lock.repo_ids)?;
    }
    let names: Vec<String> = (kept.platforms.iter())
        .map(|entry| entry.platform.to_string())
        .collect();
    record(&mut files, &mut row, traced, &pom_pins(&kept), at, &names)?;
    files.relativize_origins(&origins)?;
    files.tables.sets.push(row);
    lock.platforms[at].set_plugins(files, &lock.repo_ids)?;
    // One trace serves every JDK of this OS and architecture.
    for &other in here.iter().filter(|&&other| other != at) {
        drop_trace(&mut lock.platforms[other], &lock.repo_ids)?;
    }
    lock.mark_missing_checksums(&client.admissions(), Some(&found));
    let _guard = super::lockfile_guard(config, session.project_root(), session.output()).await?;
    if super::lock_bytes(path) != *written {
        return Err(CliError::Message(
            "raeva.lock changed while the traced build ran, so the trace is not recorded; run \
             'raeva sync' again"
                .to_string(),
        ));
    }
    lock.write_atomic(path)?;
    Ok(Ended::Recorded(Some(lock)))
}

/// The process group of a traced build's shell, which has one of its own,
/// killed when the run is dropped before the build ended, as when the sync
/// is stopped: the terminal's signals do not reach it.
struct BuildGroup(Option<u32>);

impl Drop for BuildGroup {
    fn drop(&mut self) {
        if let Some(group) = self.0 {
            rv_maven_model::mavenrc::kill_group(group);
        }
    }
}

/// The mavenrc files a traced build's shell sources, whether its launcher
/// runs another `mvn` with `exec`, the environment it starts from, and its
/// process group.
struct Sourcing<'a> {
    files: &'a [PathBuf],
    exec: bool,
    before: &'a [(OsString, OsString)],
    group: Option<u32>,
}

/// One run of the traced build.
struct TraceRun<'a> {
    config: &'a Config,
    output: &'a crate::output::Output,
    mvn: &'a Path,
    known: &'a Known<'a>,
    options: &'a [(&'static str, String)],
    /// The build's own arguments, with raeva's local repository.
    args: Vec<String>,
    /// How many arguments raeva.toml gives.
    arg_count: usize,
    /// Whether the build may get [`HARDENING`].
    harden: bool,
    /// Whether raeva said it traces the build.
    noted: bool,
}

impl TraceRun<'_> {
    /// Run the build as `launch` starts it; how it exited, whether it got
    /// [`HARDENING`], and what raeva took from its output.
    async fn run(
        self,
        launch: &rv_maven_model::mavenrc::TracedLaunch,
    ) -> Result<(std::process::ExitStatus, bool, Seen)> {
        use rv_maven_model::mavenrc::{Shell, TracedLaunch};

        let config = self.config;
        // The traced mvn runs in the project directory, where a path the
        // configuration took from another names another file.
        if let Some(what) = rv_config::working_dir_read() {
            let here = std::env::current_dir().and_then(std::fs::canonicalize);
            if here.ok() != std::fs::canonicalize(&config.project_root).ok() {
                return Err(CliError::Config(
                    rv_config::ConfigError::UnreadHostProperty(format!(
                        "{what} gives a path relative to the directory raeva runs in, \
                         but the build [plugins] trace runs starts in the project directory, \
                         where that path names another file; run raeva in the project directory"
                    )),
                ));
            }
        }
        let before: Vec<(OsString, OsString)> = (std::env::vars_os())
            .filter(|(name, _)| !rv_maven_model::mavenrc::internal_variable(name))
            .collect();
        // Waited on as a future, so Ctrl-C and SIGTERM stop the sync, and the
        // build with it.
        let mut command = match launch {
            TracedLaunch::Direct | TracedLaunch::Resourced { .. } => {
                tokio::process::Command::new(self.mvn)
            }
            TracedLaunch::Sourced {
                script,
                launcher,
                exec,
                files,
            } => {
                if *exec {
                    self.refuse_read_skip(files, launcher)?;
                }
                let program = std::env::current_exe().map_err(|error| {
                    CliError::Message(format!("raeva cannot name itself: {error}"))
                })?;
                let mut command = tokio::process::Command::new("/bin/sh");
                command.arg("-c").arg(script).arg(launcher);
                // A group of its own, which a timeout of the files stops
                // whole, as [`BuildGroup`] does when the sync stops.
                #[cfg(unix)]
                command.process_group(0);
                command
                    .env_clear()
                    .envs(before.iter().map(|(name, value)| (name, value)))
                    .env(rv_maven_model::mavenrc::TRACE_DUMP_PROGRAM, program);
                command
            }
        };
        command.kill_on_drop(true);
        command.arg("-B");
        for (option, value) in self.options {
            command.args(option_args(option, value));
        }
        if let Some(settings) = config.settings_path.as_ref().filter(|path| path.is_file()) {
            command.arg("-s").arg(settings);
        }
        command.args(&self.args);
        let mut hardened = Hardening::Off;
        let direct = match launch {
            // With no mavenrc file, the variables are this process's.
            TracedLaunch::Direct => Some(self.hardening(&Shell::process(), &[])?),
            TracedLaunch::Resourced { files } => Some(self.resourced(files)?),
            TracedLaunch::Sourced { .. } => None,
        };
        if let Some(direct) = direct {
            hardened = direct;
            if hardened != Hardening::Off {
                let mut opts = std::env::var_os("JDK_JAVA_OPTIONS").unwrap_or_default();
                if !opts.is_empty() {
                    opts.push(" ");
                }
                opts.push(HARDENING);
                command.env("JDK_JAVA_OPTIONS", opts);
            }
            self.note(hardened);
        }
        let sourced = matches!(launch, TracedLaunch::Sourced { .. });
        let could_not_run =
            |error| CliError::Message(format!("could not run {}: {error}", self.mvn.display()));
        let mut child = command
            .current_dir(&config.project_root)
            .stdin(match sourced {
                true => std::process::Stdio::piped(),
                false => std::process::Stdio::null(),
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| match error.kind() {
                // A command name `plugins.mvn` gives that is on no PATH.
                std::io::ErrorKind::NotFound => CliError::Config(rv_config::ConfigError::Invalid {
                    origin: rv_config::ConfigOrigin::ProjectConfig(
                        config.project_root.join("raeva.toml"),
                    ),
                    // As raeva.toml spells it; on Windows `self.mvn` has `.cmd` added.
                    message: format!(
                        "plugins.mvn: {} is not found; name a launcher on PATH or in the \
                             project, such as './mvnw'",
                        (config.plugin_trace().and_then(|trace| trace.mvn.as_deref()))
                            .unwrap_or("mvn")
                    ),
                }),
                _ => could_not_run(error),
            })?;
        let mut group = BuildGroup(child.id().filter(|_| sourced));
        let seen = std::sync::Mutex::new(Seen::default());
        let (ended, ending) = tokio::sync::watch::channel(false);
        let (stdin, stdout, stderr) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take());
        // The shell writes the dump to its stdout, the build's output to
        // its stderr.
        let (dump, stdout) = match sourced {
            true => (stdout, None),
            false => (None, stdout),
        };
        let started = async {
            let ran = async {
                if let TracedLaunch::Sourced { files, exec, .. } = launch {
                    let sourcing = Sourcing {
                        files,
                        exec: *exec,
                        before: &before,
                        group: group.0,
                    };
                    hardened = (self.sourced(sourcing, dump, stdin)).await?;
                }
                child.wait().await.map_err(could_not_run)
            };
            let ran = ran.await;
            let _ = ended.send(true);
            if ran.is_err() {
                let _ = child.start_kill();
            }
            ran
        };
        let (status, out, err) = tokio::join!(
            started,
            scan(stdout, &seen, self.known, ending.clone()),
            scan(stderr, &seen, self.known, ending)
        );
        group.0 = None;
        let status = status?;
        out.and(err).map_err(could_not_run)?;
        let seen = seen
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok((status, hardened != Hardening::Off, seen))
    }

    /// Read the dump of the shell `sourcing` describes, register the
    /// secrets it holds, and tell the shell whether to add [`HARDENING`]. A
    /// shell whose files run out of time is stopped with its process group.
    async fn sourced(
        &self,
        sourcing: Sourcing<'_>,
        dump: Option<tokio::process::ChildStdout>,
        stdin: Option<tokio::process::ChildStdin>,
    ) -> Result<Hardening> {
        use rv_maven_model::mavenrc::{MavenrcError, NOTE_AFTER, Shell, TIMEOUT};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Sourcing {
            files,
            exec,
            before,
            group,
        } = sourcing;

        let refuse = |why: &str| {
            CliError::Config(rv_config::ConfigError::UnreadHostProperty(
                MavenrcError {
                    files: files.to_vec(),
                    why: format!("{why} when the build [plugins] trace runs sourced it"),
                }
                .to_string(),
            ))
        };
        let read = async {
            let mut dump = dump?;
            let mut data = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match dump.read(&mut chunk).await {
                    Ok(0) | Err(_) => return None,
                    Ok(read) => data.extend_from_slice(&chunk[..read]),
                }
                if let Some(vars) = rv_maven_model::mavenrc::parse_dump(&data) {
                    return Some(vars);
                }
            }
        };
        tokio::pin!(read);
        let vars = match tokio::time::timeout(NOTE_AFTER, &mut read).await {
            Ok(vars) => vars,
            Err(_) => {
                self.output.note(&rv_maven_model::mavenrc::still_running());
                (tokio::time::timeout(TIMEOUT - NOTE_AFTER, &mut read).await).map_err(|_| {
                    if let Some(group) = group {
                        rv_maven_model::mavenrc::kill_group(group);
                    }
                    refuse(&format!(
                        "did not finish within {} seconds",
                        TIMEOUT.as_secs()
                    ))
                })?
            }
        };
        let vars = vars
            .ok_or_else(|| refuse("stops mvn's shell before mvn starts Maven, as an exit does,"))?;
        let shell = Shell::traced(files.to_vec(), before.to_vec(), vars);
        if let Some(why) = shell.moved_from(&self.config.project_root) {
            return Err(refuse(&why));
        }
        // The build must run with the values raeva resolved with and keyed
        // the trace by, so a value the files take anew each time refuses
        // it, except in a variable named like a secret, such as a token
        // they fetch: a POM cannot read that unless [security]
        // allow_env_substitution names it, and then it is not exempt. A
        // settings.xml credential may take it, which decides no file. raeva
        // hides its value in its own messages.
        let first = Shell::capture(&self.config.project_root).map_err(|err| {
            CliError::Config(rv_config::ConfigError::UnreadHostProperty(err.to_string()))
        })?;
        let substituted = &self.config.security.allow_env_substitution;
        let hidden = |name: &str| {
            rv_config::secret_named(name) && !substituted.iter().any(|allowed| allowed == name)
        };
        for (name, value) in shell.exported_env() {
            if hidden(&name.to_string_lossy()) {
                rv_config::register_named_secret(&value.to_string_lossy());
            }
        }
        let varies = (shell.varies_from(&first, hidden)).or_else(changed_file);
        if let Some(varies) = varies {
            return Err(CliError::Config(
                rv_config::ConfigError::UnreadHostProperty(format!(
                    "{}, which mvn sources, gives {varies} another value each time it runs, so the \
                 build [plugins] trace runs would not run with the value raeva resolved with and \
                 keyed the trace by; set it in the environment instead, or run both raeva and \
                 mvn with MAVEN_SKIP_RC=1 to trace the build",
                    listed(files)
                )),
            ));
        }
        if shell
            .shell_value("MAVEN_SKIP_RC")
            .is_some_and(|skip| skip.is_empty())
        {
            return Err(CliError::Config(
                rv_config::ConfigError::UnreadHostProperty(
                    "MAVEN_SKIP_RC is set but empty, which raeva cannot keep so in the build \
                 [plugins] trace runs; unset it, or set it to 1"
                        .to_string(),
                ),
            ));
        }
        if exec {
            refuse_lost_by_exec(&shell, before, files)?;
        }
        let hardened = self.hardening(&shell, files)?;
        self.note(hardened);
        // A shell that has gone ends the build itself.
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(hardened.word()).await;
        }
        Ok(hardened)
    }

    /// Refuse a traced build whose `launcher`, which runs a `bin/mvn` of
    /// its own, gets `MAVEN_SKIP_RC` exported, so that it skips `files`,
    /// where the POMs may read it.
    fn refuse_read_skip(&self, files: &[PathBuf], launcher: &Path) -> Result<()> {
        let name = "MAVEN_SKIP_RC";
        let allowed = &self.config.security.allow_env_substitution;
        if !allowed.iter().any(|allowed| allowed == name) {
            return Ok(());
        }
        Err(CliError::Config(
            rv_config::ConfigError::UnreadHostProperty(format!(
                "{} starts a mvn of its own, which skips {}, which raeva sourced, only with \
                 {name} exported, which the build [plugins] trace runs would then have as \
                 env.{name} for [security] allow_env_substitution; run both raeva and mvn with \
                 {name}=1 to trace the build",
                launcher.display(),
                listed(files)
            )),
        ))
    }

    /// [`hardening`] for the build `mvn.cmd` starts once it sourced
    /// `files` again, as raeva read them, which get `JDK_JAVA_OPTIONS`
    /// with [`HARDENING`] already in it: refused when they change it, which
    /// may drop the option.
    fn resourced(&self, files: &[PathBuf]) -> Result<Hardening> {
        use rv_maven_model::mavenrc::Shell;

        let name = "JDK_JAVA_OPTIONS";
        let unread = |err: rv_maven_model::mavenrc::MavenrcError| {
            rv_config::ConfigError::UnreadHostProperty(err.to_string())
        };
        let shell = Shell::capture(&self.config.project_root).map_err(unread)?;
        let refuse = |why: String, how: &str| {
            CliError::Config(rv_config::ConfigError::UnreadHostProperty(format!(
                "{}, which mvn sources, {why}; {how}run both raeva and mvn with MAVEN_SKIP_RC=1 \
                 to trace the build",
                listed(files)
            )))
        };
        // mvn.cmd sources them again, so a value they take anew each time
        // is not the one raeva resolved with and keyed the trace by.
        let varies = shell.varies_in(&self.config.project_root).map_err(unread)?;
        if let Some(varies) = varies.or_else(changed_file) {
            return Err(refuse(
                format!(
                    "gives {varies} another value each time it runs, so the build [plugins] trace \
                     runs, where mvn.cmd sources them again, would not run with the value raeva \
                     resolved with and keyed the trace by"
                ),
                "",
            ));
        }
        let hardened = self.hardening(&shell, files)?;
        let mentions = |file: &PathBuf| {
            std::fs::read(file).is_ok_and(|text| {
                (text.windows(name.len())).any(|part| part.eq_ignore_ascii_case(name.as_bytes()))
            })
        };
        if hardened != Hardening::Off
            && (shell.exported(name) != Shell::process().exported(name)
                || files.iter().any(mentions))
        {
            return Err(refuse(
                format!(
                    "reads {name}, where raeva gives the build [plugins] trace runs {HARDENING} \
                     before mvn.cmd sources them again"
                ),
                &format!("set {name} in the environment instead, or "),
            ));
        }
        Ok(hardened)
    }

    /// [`hardening`] for the build `mvn` starts with `shell`, as the
    /// mavenrc files `files` leave it.
    fn hardening(
        &self,
        shell: &rv_maven_model::mavenrc::Shell,
        files: &[PathBuf],
    ) -> Result<Hardening> {
        if !self.harden {
            return Ok(Hardening::Off);
        }
        let config = self.config;
        let release = config.host().jdk_release();
        hardening(
            release,
            shell,
            config.jvm_config(),
            files,
            &config.project_root,
        )
    }

    /// Say that raeva traces the build, once.
    fn note(&self, hardened: Hardening) {
        if self.noted {
            return;
        }
        // The arguments may hold a secret, so only their count.
        let plural = crate::commands::util::plural;
        self.output.note(&format!(
            "Tracing the plugins of the build: running {} with {} from raeva.toml{}{}",
            self.mvn.display(),
            plural(self.arg_count, "argument", "arguments"),
            match self.options.len() {
                0 => String::new(),
                count => format!(
                    " and {}",
                    plural(count, "-P or -D option", "-P or -D options")
                ),
            },
            match hardened {
                Hardening::Off => String::new(),
                _ => format!(", {HARDENING} added to JDK_JAVA_OPTIONS"),
            },
        ));
    }
}

/// How to run the traced build `mvn` to see its output, and what raeva
/// gave it, by name: the `-P` ids and `-D` names of `options`, without a
/// value or an argument, which may hold a secret.
fn rerun(
    config: &Config,
    mvn: &Path,
    options: &[(&'static str, String)],
    sourced: bool,
    hardened: bool,
) -> String {
    let mut added = vec!["-B".to_string()];
    for (option, value) in options {
        added.push(match *option {
            "-D" => format!("-D{}", value.split('=').next().unwrap_or_default()),
            _ => format!("{option}{value}"),
        });
    }
    if (config.settings_path.as_ref()).is_some_and(|path| path.is_file()) {
        added.push("-s with the settings file raeva read".to_string());
    }
    added.push(
        "-Dmaven.repo.local with a new local repository of the files raeva.lock pins (and empty \
         -Dmaven.repo.local.tail and -Dmaven.repo.local.head)"
            .to_string(),
    );
    if sourced {
        added.push("MAVEN_SKIP_RC, as raeva ran the mavenrc files first".to_string());
    }
    if hardened {
        added.push(format!("{HARDENING} in JDK_JAVA_OPTIONS"));
    }
    format!(
        "run {} with the arguments of [plugins] trace in the project directory; raeva ran it \
         with {}",
        mvn.display(),
        added.join(", ")
    )
}

/// A POM a row or support POM of the lock pins: the platform index, the
/// pin, and whether the dependencies hold it, which leaves it to them.
struct PomPin {
    platform: usize,
    pin: Option<Sha256>,
    fixed: bool,
}

/// Each POM `lock` pins or holds a row without, by the POM's coordinate.
type PomPins = BTreeMap<ArtifactCoord, Vec<PomPin>>;

fn pom_pins(lock: &rv_lock::Lockfile) -> PomPins {
    let mut pins = PomPins::new();
    for (platform, entry) in lock.platforms.iter().enumerate() {
        let used = entry.module_rows();
        for artifact in &entry.artifacts {
            pins.entry(artifact.coordinate.pom())
                .or_default()
                .push(PomPin {
                    platform,
                    pin: artifact.pom_sha256.clone(),
                    fixed: used.contains(&artifact.coordinate),
                });
        }
        for (coordinate, pom) in &entry.support_poms {
            if let Some((group, artifact, version)) = rv_lock::split_support_pom_coord(coordinate) {
                let coordinate = ArtifactCoord::new(group, artifact, version, "pom", None);
                pins.entry(coordinate).or_default().push(PomPin {
                    platform,
                    pin: Some(pom.sha256.clone()),
                    fixed: true,
                });
            }
        }
    }
    pins
}

/// Add what the traced build read on platform `at` to `files` and to its
/// set `row`: each file not pinned yet, and the id of the repository that
/// served each file it records. Every row of one version pins one POM, as
/// one Maven local repository holds one, and `pins` holds the lock's agreed
/// one, else the POM Maven read. A POM Maven read in other bytes than the
/// lock pins is refused; `names` names the platforms for that error.
fn record(
    files: &mut PluginFiles,
    row: &mut PluginSet,
    traced: Vec<(ArtifactCoord, Sha256, Repository)>,
    pins: &PomPins,
    at: usize,
    names: &[String],
) -> Result<()> {
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    let mut companions: BTreeMap<ArtifactCoord, (Sha256, String)> = BTreeMap::new();
    let mut added = Vec::new();
    for (coordinate, sha256, repo) in traced {
        if let Some(id) = repo.id.filter(|id| !id.is_empty()) {
            ids.insert(repo.url.clone(), id);
        }
        if coordinate.extension() == "pom" {
            companions.insert(coordinate, (sha256, repo.url));
        } else {
            added.push((coordinate, sha256, repo.url));
        }
    }
    let mut origins = BTreeSet::new();
    let mut poms = BTreeSet::new();
    for (coordinate, sha256, repo_url) in added {
        poms.insert(coordinate.pom());
        if !(files.artifacts.iter()).any(|artifact| artifact.coordinate == coordinate) {
            let mut artifact = LockArtifact::new(coordinate.clone(), repo_url.clone());
            artifact.checksums = vec![Digest::Sha256(sha256)];
            files.artifacts.push(artifact);
            origins.insert(repo_url);
        }
        if !row.artifacts.contains(&coordinate) {
            row.artifacts.push(coordinate);
        }
    }
    poms.extend(companions.keys().cloned());
    for pom in poms {
        let held = pins.get(&pom).map(Vec::as_slice).unwrap_or_default();
        let ours = held
            .iter()
            .any(|pin| pin.platform == at && pin.pin.is_some());
        let companion = companions.get(&pom);
        // Rows take the pin, or the POM Maven read, unless a row the
        // dependencies or another platform hold keeps none: every row of one
        // version pins one POM. Beside such a row it is a support POM, as
        // the plugin tables pin one.
        let take = (held.iter()).all(|pin| pin.pin.is_some() || (pin.platform == at && !pin.fixed));
        let pinned = held
            .iter()
            .find_map(|pin| Some((pin.platform, pin.pin.as_ref()?)));
        let (pin, repo_url) = match pinned {
            Some((by, pin)) => match companion {
                // As the plugin tables refuse a POM they and the
                // dependencies pin in different bytes.
                Some((sha256, repo_url)) if sha256 != pin => {
                    let name = |platform: usize| names.get(platform).map_or("", String::as_str);
                    return Err(CliError::Lock(rv_lock::LockError::Invalid(format!(
                        "the build traced on platform {} read POM {}:{}:{} from {repo_url} \
                         as {sha256}, which raeva.lock pins as {pin} for platform {}; one \
                         Maven local repository holds one POM per version, so both platforms \
                         must read it from repositories that serve the same bytes",
                        name(at),
                        pom.group_id(),
                        pom.artifact_id(),
                        pom.version(),
                        name(by)
                    ))));
                }
                // Only another platform pins it: `at` records it too, as
                // read where the build read it, to keep it when that one is
                // dropped.
                Some((_, repo_url)) if !ours => (pin.clone(), Some(repo_url)),
                _ => (pin.clone(), None),
            },
            None => {
                let Some((sha256, repo_url)) = companion else {
                    continue;
                };
                (sha256.clone(), Some(repo_url))
            }
        };
        let mut taken = false;
        for artifact in
            (files.artifacts.iter_mut()).filter(|artifact| take && artifact.coordinate.pom() == pom)
        {
            taken = true;
            if artifact.pom_sha256.is_some() {
                continue;
            }
            if let Some(repo_url) = repo_url
                && *repo_url != artifact.repo_url
            {
                artifact.pom_repo_urls.push(repo_url.clone());
                origins.insert(repo_url.clone());
            }
            artifact.pom_sha256 = Some(pin.clone());
        }
        if let Some(repo_url) = repo_url.filter(|_| !taken && (!ours || !take)) {
            let key = format!("{}:{}:{}", pom.group_id(), pom.artifact_id(), pom.version());
            (files.poms.entry(key.clone())).or_insert_with(|| SupportPom::new(repo_url, pin));
            row.poms.push(key);
            origins.insert(repo_url.clone());
        }
    }
    for origin in origins {
        if let Some(id) = ids.remove(&origin) {
            (files.tables.repo_ids.entry(origin).or_default()).insert(id);
        }
    }
    Ok(())
}

/// Every regular file below `root`, relative to it.
fn files_under(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut files = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(CliError::io_at(&dir)(error)),
        };
        for entry in entries {
            let entry = entry.map_err(CliError::io_at(&dir))?;
            let kind = entry.file_type().map_err(CliError::io_at(entry.path()))?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file()
                && let Ok(relative) = entry.path().strip_prefix(root)
            {
                files.insert(relative.to_path_buf());
            }
        }
    }
    Ok(files)
}

/// Whether a local repository file `name` may be a traced artifact: not
/// metadata, a marker, a checksum, or a signature, which Maven fetches
/// without a checksum.
fn traceable(name: &str) -> bool {
    !((name.starts_with("maven-metadata") && name.ends_with(".xml"))
        || name == "_remote.repositories"
        || name == "resolver-status.properties"
        || name.ends_with(".lastUpdated")
        || [".sha1", ".md5", ".sha256", ".sha512", ".asc"]
            .iter()
            .any(|suffix| name.ends_with(suffix)))
}

/// Each file with the id of the repository Maven's marker names it by.
type Traced = Vec<(ArtifactCoord, PathBuf, Option<String>)>;

/// The artifacts among `added` that a remote repository served, by
/// coordinate: a file `_remote.repositories` names with a repository id.
/// Then those it does not name at all, which a resolver other than
/// Maven's wrote, such as karaf-maven-plugin's. What the build installed,
/// checksums and metadata are left out, and so is a newer build of a
/// SNAPSHOT the lock holds, which the export, among `before`, keeps.
fn traced_files(
    m2: &Path,
    before: &BTreeSet<PathBuf>,
    added: &[PathBuf],
) -> Result<(Traced, Traced)> {
    let mut read = Vec::new();
    let mut unmarked = Vec::new();
    for relative in added {
        let Some(name) = relative.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !traceable(name)
            || relative
                .components()
                .any(|part| part.as_os_str() == ".tracking")
        {
            continue;
        }
        let file = m2.join(relative);
        let markers = file.with_file_name("_remote.repositories");
        let markers = std::fs::read_to_string(&markers).unwrap_or_default();
        let markers = rv_export::parse_remote_repositories(&markers);
        let id = (markers.iter())
            .find(|(named, _)| named == name)
            .map(|(_, id)| id.as_str());
        match (id, layout_coordinate(relative)) {
            (Some(""), _) | (None, None) => {}
            (Some(id), Some(coordinate)) => read.push((coordinate, file, Some(id.to_string()))),
            // A file outside a version directory is no artifact Maven
            // resolves.
            (Some(_), None) if relative.components().count() < 4 => {}
            (Some(_), None) if !holds_version(before, relative) => {
                return Err(unpinnable(relative));
            }
            (Some(_), None) => {}
            (None, Some(coordinate)) => unmarked.push((coordinate, file, None)),
        }
    }
    read.sort();
    unmarked.sort();
    Ok((read, unmarked))
}

/// What builds the traced one runs, such as maven-invoker-plugin's, took
/// from a remote repository into a local repository of their own below
/// `root`: each file a `_remote.repositories` written since `since` names
/// by the key of a repository the build has, as `known` says, and that
/// `m2` lacks. Such a build reads `m2` as a remote repository offline, so
/// the export must hold these files. A file a marker names by another
/// key is left out, such as maven-resolver's demos give Central at a URL
/// the build does not reach it at.
fn nested_repository_files(
    root: &Path,
    m2: &Path,
    since: std::time::SystemTime,
    known: &dyn Fn(&str) -> bool,
) -> Result<Traced> {
    let mut versions = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        // A test may leave a directory it cannot read, or remove one.
        let skipped = |error: &std::io::Error| {
            use std::io::ErrorKind::{NotFound, PermissionDenied};
            matches!(error.kind(), NotFound | PermissionDenied)
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if skipped(&error) => continue,
            Err(error) => return Err(CliError::io_at(&dir)(error)),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if skipped(&error) => continue,
                Err(error) => return Err(CliError::io_at(&dir)(error)),
            };
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() && entry.file_name() != ".git" {
                pending.push(entry.path());
            } else if kind.is_file()
                && entry.file_name() == "_remote.repositories"
                && (entry.metadata().and_then(|meta| meta.modified()))
                    .is_ok_and(|modified| modified >= since)
            {
                versions.push(dir.clone());
            }
        }
    }
    // A version's POM names its group and so where its repository starts;
    // a version without one, such as a jar a mojo resolved alone, is read
    // from the start its neighbours' POMs give.
    let starts: Vec<PathBuf> = versions.iter().filter_map(|dir| pom_start(dir)).collect();
    let mut read = Vec::new();
    for dir in &versions {
        let start = pom_start(dir).or_else(|| {
            (starts.iter())
                .filter(|start| {
                    dir.ancestors()
                        .nth(3)
                        .is_some_and(|group| group.starts_with(start))
                })
                .max_by_key(|start| start.components().count())
                .cloned()
        });
        if let Some(start) = start {
            read.extend(nested_version_files(dir, &start, m2, known)?);
        }
    }
    read.sort();
    read.dedup_by(|a, b| a.0 == b.0);
    Ok(read)
}

/// The directory the local repository holding the version directory `dir`
/// starts at, by the group its POM names.
fn pom_start(dir: &Path) -> Option<PathBuf> {
    let name = |path: Option<&Path>| path?.file_name()?.to_str().map(str::to_string);
    let (version, artifact) = (name(Some(dir))?, name(dir.parent())?);
    let pom = dir.join(format!("{artifact}-{version}.pom"));
    let bytes = rv_config::read_optional_project_input(&pom).ok()??;
    let pom = rv_maven_model::Pom::parse(&rv_maven_model::decode_pom(&bytes).ok()?).ok()?;
    let group = (pom.group_id.filter(|group| !group.contains("${")))
        .or_else(|| pom.parent.map(|parent| parent.group_id))
        .filter(|group| !group.contains("${"))?;
    let segments: Vec<&str> = group.split('.').collect();
    let start = dir.ancestors().nth(segments.len() + 2)?;
    let expected: PathBuf = (segments.iter().copied())
        .chain([artifact.as_str(), version.as_str()])
        .collect();
    (dir.strip_prefix(start).ok()? == expected).then(|| start.to_path_buf())
}

/// The files the `_remote.repositories` of the version directory `dir`,
/// in the local repository starting at `start`, names with a `known`
/// repository id, by coordinate, that `m2` lacks.
fn nested_version_files(
    dir: &Path,
    start: &Path,
    m2: &Path,
    known: &dyn Fn(&str) -> bool,
) -> Result<Traced> {
    let Ok(layout) = dir.strip_prefix(start) else {
        return Ok(Vec::new());
    };
    let Ok(markers) = std::fs::read_to_string(dir.join("_remote.repositories")) else {
        return Ok(Vec::new());
    };
    // A start taken from the neighbours may be wrong, so only a SNAPSHOT
    // version is known to be one the plugin tables cannot pin.
    let snapshot = (dir.file_name().and_then(|name| name.to_str()))
        .is_some_and(rv_maven_types::resolves_through_snapshot_metadata);
    let mut read = Vec::new();
    for (file, id) in rv_export::parse_remote_repositories(&markers) {
        let relative = layout.join(&file);
        let path = dir.join(&file);
        if id.is_empty()
            || !known(&id)
            || !traceable(&file)
            || m2.join(&relative).exists()
            || !path.is_file()
        {
            continue;
        }
        match layout_coordinate(&relative) {
            Some(coordinate) => read.push((coordinate, path, Some(id))),
            None if snapshot && !m2.join(layout).is_dir() => return Err(unpinnable(&relative)),
            None => {}
        }
    }
    Ok(read)
}

/// Whether `files` holds one in the version directory of `relative`.
fn holds_version(files: &BTreeSet<PathBuf>, relative: &Path) -> bool {
    let Some(dir) = relative.parent() else {
        return false;
    };
    (files.range(dir.to_path_buf()..))
        .take_while(|file| file.starts_with(dir))
        .any(|file| file.parent() == Some(dir))
}

/// A file Maven downloaded at no release file's path: a SNAPSHOT build,
/// which plugin locking does not pin, as the plugin tables refuse one.
fn unpinnable(relative: &Path) -> CliError {
    let coord = (relative.components())
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    CliError::Resolve(rv_resolver::ResolveError::PluginSnapshot { coord })
}

/// The coordinate of the release file at `relative`, a local repository
/// path.
fn layout_coordinate(relative: &Path) -> Option<ArtifactCoord> {
    let parts: Vec<&str> = (relative.components())
        .map(|part| part.as_os_str().to_str())
        .collect::<Option<_>>()?;
    rv_maven_types::layout::parse_artifact_path(&parts.join("/"))
}

/// The repositories a traced file may come from: the plugin sets', the
/// project's, then the configured ones. A set's repository only raeva.lock
/// names, and no resolution of the plugins of `entry` reads, is none.
/// `None` when a set names one the POMs do not declare and this run has no
/// model of `entry`'s platform to resolve with: a trace could then record
/// another repository for a file. Then all of them, before one is kept per
/// URL: another id at a URL is the build's too.
async fn candidate_repositories(
    config: &Config,
    client: &RepoClient,
    store: &Store,
    models: &[ReactorModel],
    lock: &Lockfile,
    entry: &LockPlatform,
    files: &PluginFiles,
) -> Result<Option<(Vec<Repository>, Vec<Repository>)>> {
    let policy = client.policy();
    let platform = &entry.platform;
    let known = super::plugins::PluginRepositories::new(config, policy, models, platform, None);
    let tables = &files.tables;
    let urls = || (tables.sets.iter()).flat_map(|set| set.repo_urls.iter());
    let resolved = match urls().any(|url| !known.declares(url)) {
        true => {
            let store = std::sync::Arc::new(store.clone());
            let resolved =
                super::plugins::resolved(config, store, client.clone(), lock, entry, models);
            match resolved.await? {
                Some(files) => Some(files),
                None => return Ok(None),
            }
        }
        false => None,
    };
    let repos = super::plugins::PluginRepositories::new(
        config,
        policy,
        models,
        platform,
        resolved.as_ref(),
    );
    let plugin = urls().filter_map(|url| repos.repository(policy, &tables.repo_ids, url).ok());
    let all: Vec<Repository> = plugin.chain(repos.known().iter().cloned()).collect();
    let mut candidates: Vec<Repository> = Vec::new();
    let mut seen = BTreeSet::new();
    for repo in all.iter().cloned() {
        if seen.insert(repo.url.clone()) {
            candidates.push(repo);
        }
    }
    Ok(Some((candidates, all)))
}

/// `repos` with those first that Maven names `id`: a repository of that
/// id, or one a mirror of that id serves, then one Maven 3.10 keys `id`.
/// Another of `repos` may serve the same bytes, but `mvn -o` takes the
/// file from the export only under an id the build asks for it.
fn named_first(config: &Config, repos: &[Repository], id: Option<&str>) -> Vec<Repository> {
    let mut repos = repos.to_vec();
    repos.sort_by_key(|repo| match id {
        Some(id) if named_by_id(config, repo, id) => 0,
        Some(id) if keyed(config, repo, id) => 1,
        _ => 2,
    });
    repos
}

/// Whether Maven names `repo` `id` in `_remote.repositories`, by id or by
/// key.
fn names(config: &Config, repo: &Repository, id: &str) -> bool {
    named_by_id(config, repo, id) || keyed(config, repo, id)
}

/// Whether `id` is the id Maven 3.9 writes for `repo`: its own, or that of
/// its mirror.
fn named_by_id(config: &Config, repo: &Repository, id: &str) -> bool {
    [
        repo.id.clone(),
        rv_repo::mirrored_repository(config, repo).id,
    ]
    .contains(&Some(id.to_string()))
}

/// Whether `id` is the key Maven 3.10's resolver writes for `repo`
/// (`nid_hurl`): the id it is reached at, `-`, and the SHA-1 of that URL as
/// declared. Maven reaches it through its mirror, or directly where only
/// raeva's config mirrors it. A URL raeva keeps only normalized, as the
/// plugin tables record it, may have been declared without its `/`.
/// Central is at the super POM's `https://repo.maven.apache.org/maven2`,
/// not at the URL with a `/` maven-resolver's demos reach it at.
fn keyed(config: &Config, repo: &Repository, id: &str) -> bool {
    let reached = rv_repo::mirrored_repository(config, repo);
    [repo, &reached].into_iter().any(|repo| {
        let Some(hash) = (repo.id.as_deref())
            .and_then(|named| id.strip_prefix(&path_segment(named)))
            .and_then(|rest| rest.strip_prefix('-'))
        else {
            return false;
        };
        let central = repo.id.as_deref() == Some("central")
            && [
                "https://repo1.maven.org/maven2/",
                "https://repo.maven.apache.org/maven2/",
            ]
            .contains(&repo.url.as_str());
        let declared = repo.declared_url();
        let urls = match central {
            true => vec!["https://repo.maven.apache.org/maven2"],
            false => [declared]
                .into_iter()
                .chain(declared.strip_suffix('/'))
                .collect(),
        };
        (urls.into_iter()).any(|url| Sha1::from_bytes(url.as_bytes()).as_str() == hash)
    })
}

/// `id` as resolver 2's `PathUtils.stringToPathSegment` writes it.
fn path_segment(id: &str) -> String {
    match id {
        "." => "-DOT-".to_string(),
        ".." => "-DOTDOT-".to_string(),
        _ => (id.chars())
            .map(|c| match c {
                '\\' => "-BACKSLASH-".to_string(),
                '/' => "-SLASH-".to_string(),
                ':' => "-COLON-".to_string(),
                '"' => "-QUOTE-".to_string(),
                '<' => "-LT-".to_string(),
                '>' => "-GT-".to_string(),
                '|' => "-PIPE-".to_string(),
                '?' => "-QMARK-".to_string(),
                '*' => "-ASTERISK-".to_string(),
                c => c.to_string(),
            })
            .collect(),
    }
}

/// Fetch `coordinate` from the first of `repos` that serves the bytes
/// Maven read, store them with their origin, and name that repository.
async fn fetch_matching(
    client: &RepoClient,
    store: &Store,
    repos: &[Repository],
    coordinate: &ArtifactCoord,
    sha256: &Sha256,
) -> Result<Repository> {
    let request = ArtifactRequest::from(coordinate);
    let mut failure = None;
    for repo in repos {
        let fetched = match client
            .fetch_artifact(repo, &request, store, FetchArtifact::default())
            .await
        {
            Ok(fetched) => fetched,
            Err(
                RepoError::NotFound(_)
                | RepoError::ReleasesDisabled { .. }
                | RepoError::SnapshotsDisabled { .. },
            ) => continue,
            Err(error) => {
                let error = CliError::Repo(error);
                if repinned(&error) {
                    return Err(error);
                }
                failure.get_or_insert(error);
                continue;
            }
        };
        if fetched.blob != *sha256 {
            continue;
        }
        let blob: BlobId = fetched.blob;
        store
            .add_artifacts(vec![(coordinate.clone(), blob.clone())])
            .await?;
        let origin = Origin {
            repo_url: repo.url.clone(),
            endpoint_url: fetched.served_by,
            checksum_verified: fetched.checksum_verified,
            served: true,
        };
        store
            .record_origins(vec![(coordinate.clone(), blob, origin)])
            .await?;
        return Ok(repo.clone());
    }
    // A repository that failed may hold them.
    if let Some(error) = failure {
        return Err(error);
    }
    Err(CliError::Message(format!(
        "no repository serves the bytes the traced build read for {coordinate}"
    )))
}

fn drop_trace(entry: &mut LockPlatform, row_ids: &rv_lock::RepoIds) -> Result<()> {
    if let Some(mut files) = entry.plugin_files() {
        files.retain_sets(|set| set.role != PluginRole::Trace);
        entry.set_plugins(files, row_ids)?;
    }
    Ok(())
}

/// Whether `error` is other bytes than raeva.lock pins.
fn repinned(error: &CliError) -> bool {
    matches!(
        error,
        CliError::Repo(rv_repo::RepoError::ChecksumMismatch {
            check: rv_repo::IntegritySource::LockPin,
            ..
        })
    )
}

/// A file the configuration read, an option file, `.mvn` file or settings
/// file, that no longer holds what it read, as when the mavenrc files
/// write it anew each time they run.
fn changed_file() -> Option<String> {
    rv_config::changed_option_file().map(|name| match name.contains(['.', ' ']) {
        true => name.to_string(),
        false => format!("the option file {name} names"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The option goes after the user's `_JAVA_OPTIONS` only for a HotSpot
    /// JDK whose release file names 11 or later, where OpenJ9 is not told
    /// to refuse options it does not know.
    #[test]
    fn base64_intrinsics_go_off_only_for_a_jdk_known_to_have_the_option() {
        use rv_maven_model::mavenrc::Shell;
        let release = |version: &str| rv_maven_model::JdkRelease {
            version: Some(version.to_string()),
            ..rv_maven_model::JdkRelease::default()
        };
        let dir = Path::new("/nonexistent");
        let env = |vars: &[(&str, &str)]| Shell::for_testing(&[], vars, vars, &[]);
        let on = |version: &str, vars: &[(&str, &str)]| {
            hardening(Some(&release(version)), &env(vars), None, &[], dir).unwrap()
        };
        assert_eq!(
            on("21.0.9", &[("JDK_JAVA_OPTIONS", "-Xmx1g")]),
            Hardening::Added
        );
        assert_eq!(on("11", &[]), Hardening::Added);
        assert_eq!(
            on("27-ea", &[("_JAVA_OPTIONS", "-Xmx512m")]),
            Hardening::Added
        );
        for old in ["1.8.0_442", "9", "10.0.2", "1", "", "x"] {
            assert_eq!(on(old, &[]), Hardening::Off, "{old}");
        }
        let none = hardening(None, &env(&[]), None, &[], dir).unwrap();
        assert_eq!(none, Hardening::Off);
        let openj9 = rv_maven_model::JdkRelease {
            openj9: true,
            ..release("21")
        };
        let openj9 = hardening(Some(&openj9), &env(&[]), None, &[], dir).unwrap();
        assert_eq!(openj9, Hardening::Off);
        let strict = "-XX:-IgnoreUnrecognizedXXColonOptions";
        let config = hardening(Some(&release("21")), &env(&[]), Some(strict), &[], dir).unwrap();
        assert_eq!(config, Hardening::Off);
        assert_eq!(on("21", &[("JAVA_TOOL_OPTIONS", strict)]), Hardening::Off);
        // A value the shell holds unexported is replaced, as the JVM does
        // not get it.
        let unexported = Shell::for_testing(&[], &[], &[], &[("JDK_JAVA_OPTIONS", "-Da=1")]);
        let unexported = hardening(Some(&release("21")), &unexported, None, &[], dir).unwrap();
        assert_eq!(unexported, Hardening::Exported);
    }

    /// An option the JVM reads after `JDK_JAVA_OPTIONS` that turns the
    /// intrinsic back on refuses the trace: one of the command line or
    /// `_JAVA_OPTIONS`, or an argument file that names it. One before, in
    /// `JAVA_TOOL_OPTIONS`, or one a later option turns off again does not.
    #[test]
    fn an_option_that_turns_the_intrinsic_back_on_refuses() {
        use rv_maven_model::mavenrc::Shell;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("on.args"), "-XX:+UseBASE64Intrinsics\n").unwrap();
        std::fs::write(dir.path().join("other.args"), "-Xmx1g\n").unwrap();
        let release = rv_maven_model::JdkRelease {
            version: Some("21".to_string()),
            ..rv_maven_model::JdkRelease::default()
        };
        let check = |config: Option<&str>, shell: &[(&str, &str)], vars: &[(&str, &str)]| {
            let shell = Shell::for_testing(&["/rc"], vars, vars, shell);
            hardening(
                Some(&release),
                &shell,
                config,
                &[PathBuf::from("/rc")],
                dir.path(),
            )
        };
        let on = "-XX:+UseBASE64Intrinsics";
        for (config, shell, vars) in [
            (Some(on), vec![], vec![]),
            (None, vec![("MAVEN_OPTS", on)], vec![]),
            (None, vec![("MAVEN_DEBUG_OPTS", on)], vec![]),
            (
                None,
                vec![],
                vec![("_JAVA_OPTIONS", "-Xmx1g -XX:+UseBASE64Intrinsics")],
            ),
            (
                None,
                vec![],
                vec![("_JAVA_OPTIONS", "\"-XX:+UseBASE64Intrinsics\"")],
            ),
            (None, vec![("MAVEN_OPTS", "@on.args")], vec![]),
            (
                None,
                vec![],
                vec![("_JAVA_OPTIONS", "-XX:VMOptionsFile=on.args")],
            ),
            (
                Some("-XX:-UseBASE64Intrinsics"),
                vec![("MAVEN_OPTS", on)],
                vec![],
            ),
        ] {
            let refused = check(config, &shell, &vars).unwrap_err().to_string();
            assert!(refused.contains("UseBASE64Intrinsics"), "{refused}");
            assert!(refused.contains("/rc"), "{refused}");
        }
        for (config, shell, vars) in [
            (None, vec![], vec![("JAVA_TOOL_OPTIONS", on)]),
            (
                None,
                vec![(
                    "MAVEN_OPTS",
                    "-XX:+UseBASE64Intrinsics -XX:-UseBASE64Intrinsics",
                )],
                vec![],
            ),
            (
                Some(on),
                vec![],
                vec![("_JAVA_OPTIONS", "-XX:-UseBASE64Intrinsics")],
            ),
            (None, vec![], vec![("_JAVA_OPTIONS", "-Xmx512m")]),
            (
                None,
                vec![("MAVEN_OPTS", "@other.args @missing.args")],
                vec![],
            ),
            (None, vec![], vec![("_JAVA_OPTIONS", "@on.args")]),
        ] {
            let traced = check(config, &shell, &vars);
            assert_eq!(
                traced.unwrap(),
                Hardening::Added,
                "{config:?} {shell:?} {vars:?}"
            );
        }
    }

    /// An argument file that names a VM options file which turns the
    /// intrinsic back on refuses the trace, as the JVM reads that file too.
    #[test]
    fn a_vm_options_file_an_argument_file_names_refuses() {
        use rv_maven_model::mavenrc::Shell;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("opts"), "-XX:VMOptionsFile=vmopts\n").unwrap();
        std::fs::write(dir.path().join("vmopts"), "-XX:+UseBASE64Intrinsics\n").unwrap();
        let release = rv_maven_model::JdkRelease {
            version: Some("21".to_string()),
            ..rv_maven_model::JdkRelease::default()
        };
        let shell = Shell::for_testing(&["/rc"], &[], &[], &[("MAVEN_OPTS", "@opts")]);
        let refused = hardening(
            Some(&release),
            &shell,
            None,
            &[PathBuf::from("/rc")],
            dir.path(),
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains("MAVEN_OPTS"), "{refused}");
        assert!(refused.contains("names @opts"), "{refused}");
    }

    /// A VM options file whose quoted name holds a space refuses the trace
    /// too, named in an argument file or in `_JAVA_OPTIONS`, whose quotes
    /// the JVM reads.
    #[test]
    fn a_quoted_vm_options_file_with_a_space_refuses() {
        use rv_maven_model::mavenrc::Shell;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("opts"), "-XX:VMOptionsFile=\"vm opts\"\n").unwrap();
        std::fs::write(dir.path().join("vm opts"), "-XX:+UseBASE64Intrinsics\n").unwrap();
        let release = rv_maven_model::JdkRelease {
            version: Some("21".to_string()),
            ..rv_maven_model::JdkRelease::default()
        };
        for (shell, vars) in [
            (vec![("MAVEN_OPTS", "@opts")], vec![]),
            (
                vec![],
                vec![("_JAVA_OPTIONS", "-XX:VMOptionsFile='vm opts'")],
            ),
        ] {
            let shell = Shell::for_testing(&[], &vars, &vars, &shell);
            let refused = hardening(Some(&release), &shell, None, &[], dir.path())
                .unwrap_err()
                .to_string();
            assert!(refused.contains("sets the intrinsic"), "{refused}");
        }
    }

    /// A forwarded value that starts like a Maven option stays attached,
    /// and one that is empty or starts with `=` is its own argument.
    #[test]
    fn a_forwarded_value_is_written_as_maven_reads_it() {
        assert_eq!(option_args("-P", "-ci"), ["-P-ci"]);
        assert_eq!(option_args("-D", "a=b"), ["-Da=b"]);
        assert_eq!(option_args("-P", "=dev"), ["-P", "=dev"]);
        assert_eq!(option_args("-P", ""), ["-P", ""]);
    }

    /// The local repository comes after every option, before `--`.
    #[test]
    fn the_local_repository_comes_last_before_the_goals_after_dashes() {
        let args = |args: &[&str]| args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        let forced = [
            "-Dmaven.repo.local=/m2",
            "-Dmaven.repo.local.tail=",
            "-Dmaven.repo.local.head=",
        ];
        let m2 = Path::new("/m2");
        assert_eq!(
            with_local_repository(&args(&["-Da=1", "verify"]), m2),
            args(&[&["-Da=1", "verify"][..], &forced].concat())
        );
        assert_eq!(
            with_local_repository(&args(&["-Da=1", "--", "validate", "--"]), m2),
            args(&[&["-Da=1"][..], &forced, &["--", "validate", "--"]].concat())
        );
    }

    /// A failed trace puts back the lock the sync found only over the bytes
    /// the sync wrote under its guard: a lock another sync wrote after the
    /// guard was released stays.
    #[tokio::test]
    async fn a_failed_trace_puts_back_only_the_lock_it_wrote() {
        let project = tempfile::TempDir::new().unwrap();
        let paths = rv_config::ResolvedPaths::for_testing().unwrap();
        let mut config = Config::for_testing(project.path().to_path_buf(), paths);
        let mut plugins = rv_config::PluginsConfig::default();
        plugins.trace = Some(rv_config::PluginTrace::default());
        config.plugins = Some(plugins);
        let session = Session::new(project.path()).unwrap();
        // Bytes no lock parse reads, so the trace fails before its build.
        for (on_disk, kept) in [("written", "found"), ("another sync's", "another sync's")] {
            std::fs::write(&config.lock_path, on_disk).unwrap();
            let start = Start {
                models: Vec::new(),
                written: Some(b"written".to_vec()),
                previous: Some(b"found".to_vec()),
            };
            assert!(trace(&session, &config, start, true, false).await.is_err());
            assert_eq!(std::fs::read_to_string(&config.lock_path).unwrap(), kept);
        }
    }

    /// A sync cancelled during its trace puts back the lock it found once
    /// another sync releases the guard, also after more than a second.
    #[test]
    fn a_cancelled_trace_puts_back_the_lock_after_the_guard_is_free() {
        let project = tempfile::TempDir::new().unwrap();
        let paths = rv_config::ResolvedPaths::for_testing().unwrap();
        let config = Config::for_testing(project.path().to_path_buf(), paths);
        let session = Session::new(project.path()).unwrap();
        std::fs::write(&config.lock_path, "written").unwrap();
        let (cache, root) = (config.paths.cache_dir.clone(), project.path().to_path_buf());
        let duration = std::time::Duration::from_secs(1);
        let guard = rv_lock::LockfileGuard::acquire(&cache, &root, duration, || {}).unwrap();
        let other = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            drop(guard);
        });
        drop(PutBack {
            config: &config,
            output: session.output(),
            project_root: project.path(),
            written: Some(b"written".to_vec()),
            previous: Some(b"found".to_vec()),
        });
        other.join().unwrap();
        assert_eq!(std::fs::read_to_string(&config.lock_path).unwrap(), "found");
    }

    /// What [`scan`] takes from `parts`, read one after another, so a line
    /// may span reads.
    async fn scanned(parts: &[&[u8]], known: &Known<'_>) -> Seen {
        use tokio::io::AsyncReadExt;
        let mut from: Box<dyn tokio::io::AsyncRead + Unpin + Send> = Box::new(&b""[..]);
        for part in parts {
            from = Box::new(from.chain(*part));
        }
        let seen = std::sync::Mutex::new(Seen::default());
        let (_ended, ending) = tokio::sync::watch::channel(false);
        scan(Some(from), &seen, known, ending).await.unwrap();
        seen.into_inner().unwrap()
    }

    /// Maven's failure line selects a plugin and a module raeva holds, by
    /// its own names, and supplies none: not a coordinate or project raeva
    /// does not hold, a goal no descriptor in the store spells, or the
    /// execution. A line without the `[ERROR] ` anchor selects nothing, and
    /// a line longer than [`LINE`] is matched by its start.
    #[tokio::test]
    async fn the_output_selects_only_names_raeva_holds() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let known = Known {
            plugins: vec!["t:p:1", "t:q:2"],
            artifacts: &[],
            store: &store,
            modules: vec!["app", "lib"],
        };
        let failed = |plugin, module| {
            Some(Failed {
                plugin,
                goal: None,
                module,
            })
        };
        let long = "x".repeat(3 * LINE);
        let cases: [(&[&[u8]], Option<Failed>); 7] = [
            (
                &[b"[INFO] x\n[ERROR] Failed to execute goal t:q:2:run (zqEXECzq) on project ",
                  b"lib: zqTOKENzq\n"],
                failed(Some(1), Some(1)),
            ),
            (
                &[b"[ERROR] Failed to execute goal t:zqTOKENzq:1:run (x) on project zqTOKENzq: e\n"],
                failed(None, None),
            ),
            (
                &[b"[ERROR] Failed to execute goal on project app: Could not resolve\n"],
                failed(None, Some(0)),
            ),
            (
                &[b"Failed to execute goal t:p:1:run on project app\n",
                  b" [ERROR] Failed to execute goal t:p:1:run on project app\n"],
                None,
            ),
            (
                &[long.as_bytes(), b"\n[ERROR] Failed to execute goal t:p:1:run on project app\r\n"],
                failed(Some(0), Some(0)),
            ),
            (
                &[b"[ERROR] Failed to execute goal t:p:1:run on project app: ", long.as_bytes()],
                failed(Some(0), Some(0)),
            ),
            (
                &[b"[ERROR] Failed to execute goal t:p:1:r\xffn on project \xfe\xff: e\n"],
                failed(Some(0), None),
            ),
        ];
        for (parts, expected) in cases {
            assert_eq!(scanned(parts, &known).await.failed, expected, "{parts:?}");
        }
    }

    /// Each failure class is found by its fixed pattern, and the JVM's
    /// refusal of [`HARDENING`] only in the first [`HEAD`] bytes.
    #[tokio::test]
    async fn the_output_shows_a_failure_class_and_a_refused_option() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let known = Known {
            plugins: Vec::new(),
            artifacts: &[],
            store: &store,
            modules: Vec::new(),
        };
        // Lines as Maven 3.9.12 (default and wagon transport) and 3.10.0
        // print them, and lines a build's own tools print.
        let cases: [(&[u8], &[Failure]); 14] = [
            (
                b"Error: Could not create the Java Virtual Machine.\n",
                &[Failure::Jvm],
            ),
            (
                b"Error occurred during initialization of VM\n",
                &[Failure::Jvm],
            ),
            (b"Unrecognized option: --zq\n", &[]),
            (
                b"[ERROR] Plugin t:p:1 or one of its dependencies could not be resolved: x\n",
                &[Failure::Plugin],
            ),
            (
                b"[ERROR]   Non-resolvable parent POM for t:a:1\n",
                &[Failure::Pom],
            ),
            (
                b"[ERROR] \tCaused by: The following artifacts could not be resolved: t:p:pom:1 \
                  (absent): Could not transfer artifact t:p:pom:1 from/to r (http://h/): status \
                  code: 401, reason phrase: Unauthorized (401)\n",
                &[Failure::Refused],
            ),
            (
                b"[ERROR] \tThe following artifacts could not be resolved: t:p:pom:1 (absent): \
                  Could not transfer artifact t:p:pom:1 from/to r (http://h/): HTTP Status: 403\n",
                &[Failure::Refused],
            ),
            (
                b"[WARNING] Could not transfer metadata t/maven-metadata.xml from/to r \
                  (http://h/): HTTP Status: 401\n",
                &[Failure::Refused],
            ),
            (
                b"[ERROR] \tThe following artifacts could not be resolved: t:p:pom:1 (absent): \
                  Could not transfer artifact t:p:pom:1 from/to r (http://h/): authorization \
                  failed for http://h/t/p/1/p-1.pom, status: 403 Forbidden\n",
                &[Failure::Refused],
            ),
            (
                b"[FATAL] Non-resolvable parent POM for t:a:1: The following artifacts could not \
                  be resolved: t:b:pom:1 (absent): Could not transfer artifact t:b:pom:1 from/to \
                  r (http://h/): authentication failed for http://h/t/b/1/b-1.pom, status: 401 \
                  Unauthorized and 'parent.relativePath' points at wrong local POM\n",
                &[Failure::Pom, Failure::Refused],
            ),
            (b"GET /x returned status code: 403\n", &[]),
            (b"[ERROR] x: HTTP Status: 401\n", &[]),
            (
                b"[ERROR] Could not transfer artifact t:p:pom:1: HTTP Status: 4010, status code: \
                  4031, status: 4019\n",
                &[],
            ),
            (b"[INFO] Non-resolvable parent POM, Plugin x\n", &[]),
        ];
        for (text, expected) in cases {
            let seen = scanned(&[text], &known).await;
            assert!(
                seen.failures.iter().eq(expected),
                "{text:?}: {:?}",
                seen.failures
            );
        }
        let refusal: &[u8] = b"NOTE: Picked up JDK_JAVA_OPTIONS\n\
            Unrecognized VM option 'UseBASE64Intrinsics'\n\
            Error: Could not create the Java Virtual Machine.\n";
        assert!(scanned(&[refusal], &known).await.rejected_hardening());
        let late = [&b"y\n"[..]].repeat(HEAD / 2 + 1).concat();
        assert!(
            !scanned(&[&late, refusal], &known)
                .await
                .rejected_hardening()
        );
    }

    /// The tables hold at most one trace, keyed by the build raeva.toml
    /// names.
    #[test]
    fn only_one_trace_of_the_named_build_holds() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut config = Config::for_testing(
            dir.path().to_path_buf(),
            rv_config::ResolvedPaths::from_raeva_home(dir.path().join("home")),
        );
        let mut tables = PluginFiles::new(Sha256::from_bytes(b"inputs")).tables;
        assert!(traces_hold(&config, &tables));
        tables
            .sets
            .push(PluginSet::new("sha256:old", PluginRole::Trace));
        assert!(
            !traces_hold(&config, &tables),
            "a trace raeva.toml names none of"
        );
        config.plugins = Some(crate::commands::sync::plugins::traced("verify"));
        assert!(!traces_hold(&config, &tables), "a stale trace");
        let key = trace_key(&config, &tables).unwrap();
        // Without options, the key locks hold, so a change to its text is seen.
        assert_eq!(
            key,
            "sha256:95ad07daffa80599221bb7a22e0c72d6e82fb40de2a752d1672496e2223441a3"
        );
        tables.sets[0] = PluginSet::new(&key, PluginRole::Trace);
        assert!(traces_hold(&config, &tables));
        tables.sets.push(PluginSet::new(&key, PluginRole::Trace));
        assert!(!traces_hold(&config, &tables), "two traces");
    }

    /// A field of the key's text cannot spell another line of it, as an
    /// argument or launcher holding a newline did.
    #[test]
    fn a_field_cannot_spell_another_line_of_the_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = |mvn: Option<&str>, args: &[&str]| {
            let mut config = Config::for_testing(
                dir.path().to_path_buf(),
                rv_config::ResolvedPaths::from_raeva_home(dir.path().join("home")),
            );
            let mut trace = rv_config::PluginTrace::default();
            trace.args = args.iter().map(ToString::to_string).collect();
            trace.mvn = mvn.map(str::to_string);
            let mut plugins = rv_config::PluginsConfig::default();
            plugins.trace = Some(trace);
            config.plugins = Some(plugins);
            let tables = PluginFiles::new(Sha256::from_bytes(b"inputs")).tables;
            trace_key(&config, &tables).unwrap()
        };
        assert_ne!(
            key(None, &["verify\narg -Dartifact=g:a:2"]),
            key(None, &["verify", "-Dartifact=g:a:2"])
        );
        assert_ne!(
            key(Some("mvn\narg verify"), &["-q"]),
            key(None, &["verify", "-q"])
        );
    }

    /// A traced file takes the POM the lock pins for its version, else the
    /// one Maven read where only plugin rows of the platform hold the
    /// version; a POM Maven read beside a row without one of the
    /// dependencies or of another platform, and one no row takes, is a
    /// support POM; and each serving repository's id is recorded.
    #[test]
    fn records_traced_files_with_their_poms() {
        let coordinate = |text: &str| layout_coordinate(Path::new(text)).unwrap();
        let sha = |text: &str| Sha256::from_bytes(text.as_bytes());
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        // A plugin row the export wrote without a POM, which Maven reads.
        (files.artifacts).push(LockArtifact::new(
            coordinate("g/old/1/old-1.jar"),
            "https://r.example/",
        ));
        let mut held = LockArtifact::new(coordinate("g/held/1/held-1.jar"), "https://r.example/");
        held.pom_sha256 = Some(sha("held"));
        files.artifacts.push(held);
        let repo = Repository::new(
            Some("central".to_string()),
            "https://r.example/",
            true,
            false,
        );
        let traced = [
            "g/a/1/a-1.jar",
            "g/a/1/a-1-linux.jar",
            "g/a/1/a-1.pom",
            "g/old/1/old-1.pom",
            "g/held/1/held-1-tests.jar",
            "g/p/1/p-1.pom",
            "g/dep/1/dep-1-tests.jar",
            "g/dep/1/dep-1.pom",
            "g/far/1/far-1-x.jar",
            "g/far/1/far-1.pom",
            "g/sup/1/sup-1.jar",
        ]
        .map(|path| (coordinate(path), sha(path), repo.clone()));
        let pin = |platform, pin: Option<&str>, fixed| PomPin {
            platform,
            pin: pin.map(sha),
            fixed,
        };
        let pins = PomPins::from([
            (coordinate("g/old/1/old-1.pom"), vec![pin(0, None, false)]),
            (
                coordinate("g/held/1/held-1.pom"),
                vec![pin(0, Some("held"), false)],
            ),
            // A dependency row without a POM, and a row of another platform.
            (coordinate("g/dep/1/dep-1.pom"), vec![pin(0, None, true)]),
            (coordinate("g/far/1/far-1.pom"), vec![pin(1, None, false)]),
            (
                coordinate("g/sup/1/sup-1.pom"),
                vec![pin(0, Some("support"), true)],
            ),
        ]);
        let mut row = PluginSet::new("sha256:ab", PluginRole::Trace);
        record(&mut files, &mut row, traced.into(), &pins, 0, &[]).unwrap();
        let poms: Vec<_> = (files.artifacts.iter())
            .map(|artifact| (artifact.coordinate.to_string(), artifact.pom_sha256.clone()))
            .collect();
        assert_eq!(
            poms,
            [
                ("g:old:1:jar".to_string(), Some(sha("g/old/1/old-1.pom"))),
                ("g:held:1:jar".to_string(), Some(sha("held"))),
                ("g:a:1:jar".to_string(), Some(sha("g/a/1/a-1.pom"))),
                ("g:a:1:jar:linux".to_string(), Some(sha("g/a/1/a-1.pom"))),
                ("g:held:1:jar:tests".to_string(), Some(sha("held"))),
                ("g:dep:1:jar:tests".to_string(), None),
                ("g:far:1:jar:x".to_string(), None),
                ("g:sup:1:jar".to_string(), Some(sha("support"))),
            ]
        );
        let named: Vec<String> = row.artifacts.iter().map(ToString::to_string).collect();
        assert_eq!(
            named,
            [
                "g:a:1:jar",
                "g:a:1:jar:linux",
                "g:held:1:jar:tests",
                "g:dep:1:jar:tests",
                "g:far:1:jar:x",
                "g:sup:1:jar"
            ]
        );
        assert_eq!(row.poms, ["g:dep:1", "g:far:1", "g:p:1"]);
        assert!(files.tables.repo_ids["https://r.example/"].contains("central"));
    }

    /// A POM another platform pins is a support POM of the traced one
    /// beside a dependency row of it without a POM, and a POM Maven read in
    /// other bytes than the lock pins is refused.
    #[test]
    fn a_traced_pom_is_recorded_beside_a_row_without_one_or_refused() {
        let coordinate = |text: &str| layout_coordinate(Path::new(text)).unwrap();
        let sha = |text: &str| Sha256::from_bytes(text.as_bytes());
        let repo = Repository::new(Some("r".to_string()), "https://r.example/", true, false);
        let pin = |platform, pin: Option<&str>| PomPin {
            platform,
            pin: pin.map(sha),
            fixed: true,
        };
        let names = ["host".to_string(), "other".to_string()];
        let pins = PomPins::from([(
            coordinate("g/lib/1/lib-1.pom"),
            vec![pin(0, None), pin(1, Some("lib"))],
        )]);
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        let mut row = PluginSet::new("sha256:ab", PluginRole::Trace);
        let traced = vec![
            (
                coordinate("g/lib/1/lib-1-tests.jar"),
                sha("jar"),
                repo.clone(),
            ),
            (coordinate("g/lib/1/lib-1.pom"), sha("lib"), repo.clone()),
        ];
        record(&mut files, &mut row, traced, &pins, 0, &names).unwrap();
        assert_eq!(row.poms, ["g:lib:1"]);
        assert_eq!(files.poms["g:lib:1"].sha256, sha("lib"));
        // The row keeps no POM, as the dependency row of its version.
        assert_eq!(files.artifacts[0].pom_sha256, None);

        let pins = PomPins::from([(coordinate("g/lib/1/lib-1.pom"), vec![pin(1, Some("lib"))])]);
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        let mut row = PluginSet::new("sha256:ab", PluginRole::Trace);
        let traced = vec![
            (coordinate("g/lib/1/lib-1.jar"), sha("jar"), repo.clone()),
            (coordinate("g/lib/1/lib-1.pom"), sha("other bytes"), repo),
        ];
        let refused = record(&mut files, &mut row, traced, &pins, 0, &names).unwrap_err();
        let refused = refused.to_string();
        assert!(
            refused.contains("g:lib:1") && refused.contains("other") && refused.contains("host"),
            "{refused}"
        );
    }

    /// A trace records the id of a repository only for a file it records.
    #[test]
    fn a_trace_records_the_ids_of_the_origins_it_records() {
        let coordinate = |text: &str| layout_coordinate(Path::new(text)).unwrap();
        let sha = |text: &str| Sha256::from_bytes(text.as_bytes());
        let mut files = PluginFiles::new(Sha256::from_bytes(b"inputs"));
        files.artifacts.push(LockArtifact::new(
            coordinate("g/old/1/old-1.jar"),
            "https://r.example/",
        ));
        let mut resolved = PluginSet::new("sha256:cd", PluginRole::Plugin);
        resolved.artifacts.push(coordinate("g/old/1/old-1.jar"));
        files.tables.sets.push(resolved);
        let repo = |id: &str, url: &str| Repository::new(Some(id.to_string()), url, true, false);
        let traced = vec![
            (
                coordinate("g/old/1/old-1.pom"),
                sha("old"),
                repo("traced", "https://t.example/"),
            ),
            (
                coordinate("g/dep/1/dep-1.pom"),
                sha("dep"),
                repo("skipped", "https://s.example/"),
            ),
        ];
        let pins = PomPins::from([
            (
                coordinate("g/old/1/old-1.pom"),
                vec![PomPin {
                    platform: 0,
                    pin: None,
                    fixed: false,
                }],
            ),
            (
                coordinate("g/dep/1/dep-1.pom"),
                vec![PomPin {
                    platform: 0,
                    pin: Some(sha("dep")),
                    fixed: true,
                }],
            ),
        ]);
        let mut row = PluginSet::new("sha256:ab", PluginRole::Trace);
        record(&mut files, &mut row, traced, &pins, 0, &[]).unwrap();
        assert!(files.tables.repo_ids["https://t.example/"].contains("traced"));
        assert!(!files.tables.repo_ids.contains_key("https://s.example/"));
    }

    /// The lock's support POMs and the rows its modules use count as fixed.
    #[test]
    fn reads_the_pom_pins_of_the_lock() {
        let mut lock = rv_lock::Lockfile::new();
        let mut entry = rv_lock::LockPlatform::new(rv_lock::Platform::current().unwrap(), "model");
        entry.support_poms.insert(
            "g:s:1".to_string(),
            SupportPom::new("https://r.example/", Sha256::from_bytes(b"s")),
        );
        lock.platforms.push(entry);
        let pins = pom_pins(&lock);
        let support = &pins[&ArtifactCoord::new("g", "s", "1", "pom", None)][0];
        assert_eq!(support.pin, Some(Sha256::from_bytes(b"s")));
        assert!(support.fixed);
    }

    /// A row of a reactor module's coordinates that only the plugins read
    /// leaves its POM to them.
    #[test]
    fn a_reactor_modules_coordinates_fix_no_pom() {
        let mut lock = rv_lock::Lockfile::new();
        let mut entry = rv_lock::LockPlatform::new(rv_lock::Platform::current().unwrap(), "model");
        let lib = ArtifactCoord::new("g", "lib", "2", "jar", None);
        entry.artifacts.push(rv_lock::LockArtifact::new(
            lib.clone(),
            "https://r.example/",
        ));
        let mut app = rv_lock::LockModule::new(
            "app/pom.xml",
            rv_maven_types::Gav::new("g", "app", "1"),
            "jar",
        );
        let mut package = rv_lock::LockModulePackage::new(lib.clone(), None);
        package.workspace_module = Some("lib/pom.xml".to_string());
        app.packages.push(package);
        entry.modules.push(app);
        lock.platforms.push(entry);
        assert!(!pom_pins(&lock)[&lib.pom()][0].fixed);
    }

    /// A file no marker names is traced as one another resolver fetched;
    /// one installed by the build is not. A marker names the repository by
    /// its id unescaped.
    #[test]
    fn sorts_added_files_by_their_markers() {
        let m2 = tempfile::TempDir::new().unwrap();
        let dir = m2.path().join("g/a/1");
        std::fs::create_dir_all(&dir).unwrap();
        for file in ["a-1.jar", "a-1.zip", "a-1-built.jar", "a-1.jar.sha1"] {
            std::fs::write(dir.join(file), file).unwrap();
        }
        // As `java.util.Properties` escapes a key.
        std::fs::write(
            dir.join("_remote.repositories"),
            "#NOTE\na-1.jar>corp\\:maven\\ 1=\na-1-built.jar>=\n",
        )
        .unwrap();
        let added: Vec<PathBuf> = ["a-1.jar", "a-1.zip", "a-1-built.jar", "a-1.jar.sha1"]
            .map(|file| PathBuf::from("g/a/1").join(file))
            .into();
        let (read, unmarked) = traced_files(m2.path(), &BTreeSet::new(), &added).unwrap();
        let names = |files: &Traced| -> Vec<String> {
            files
                .iter()
                .map(|(coordinate, ..)| coordinate.to_string())
                .collect()
        };
        assert_eq!(names(&read), ["g:a:1:jar"]);
        assert_eq!(read[0].2.as_deref(), Some("corp:maven 1"));
        assert_eq!(names(&unmarked), ["g:a:1:zip"]);
    }

    /// A SNAPSHOT build Maven downloaded, into the export or a forked
    /// build's repository, is refused as the plugin tables refuse one; one
    /// the build installed is passed by.
    #[test]
    fn refuses_a_downloaded_snapshot() {
        let (root, m2) = (
            tempfile::TempDir::new().unwrap(),
            tempfile::TempDir::new().unwrap(),
        );
        let refused = |error: CliError, path: &str| {
            assert!(
                matches!(
                    &error,
                    CliError::Resolve(rv_resolver::ResolveError::PluginSnapshot { coord })
                        if coord == path
                ),
                "{error}"
            );
        };
        let dir = m2.path().join("g/a/1-SNAPSHOT");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a-1-SNAPSHOT.jar"), "jar").unwrap();
        let added = [PathBuf::from("g/a/1-SNAPSHOT/a-1-SNAPSHOT.jar")];
        let none = BTreeSet::new();
        std::fs::write(dir.join("_remote.repositories"), "a-1-SNAPSHOT.jar>=\n").unwrap();
        assert!(traced_files(m2.path(), &none, &added).unwrap().0.is_empty());
        std::fs::write(
            dir.join("_remote.repositories"),
            "a-1-SNAPSHOT.jar>snapshots=\n",
        )
        .unwrap();
        refused(
            traced_files(m2.path(), &none, &added).unwrap_err(),
            "g/a/1-SNAPSHOT/a-1-SNAPSHOT.jar",
        );
        // A newer build of a SNAPSHOT the lock holds, which Maven checks
        // for online, is left to the export.
        let locked = BTreeSet::from([PathBuf::from("g/a/1-SNAPSHOT/a-1-20260101.000000-1.jar")]);
        let (read, unmarked) = traced_files(m2.path(), &locked, &added).unwrap();
        assert!(read.is_empty() && unmarked.is_empty());
        assert!(!holds_version(&locked, Path::new("g/a/1/a-1.jar")));
        assert!(!holds_version(&locked, Path::new("g/a/1-SNAPSHOT-x/a.jar")));
        assert!(!holds_version(&locked, Path::new("g/a/a.jar")));
        // A marked file outside a version directory is no artifact Maven
        // resolves, and no SNAPSHOT build.
        std::fs::write(m2.path().join("g/a/x.jar"), "x").unwrap();
        std::fs::write(m2.path().join("x.jar"), "x").unwrap();
        for (dir, name) in [("g/a", "x.jar"), ("", "x.jar")] {
            let markers = m2.path().join(dir).join("_remote.repositories");
            std::fs::write(markers, format!("{name}>central=\n")).unwrap();
            let added = [Path::new(dir).join(name)];
            let (read, unmarked) = traced_files(m2.path(), &none, &added).unwrap();
            assert!(read.is_empty() && unmarked.is_empty(), "{dir}");
        }

        let nested = root.path().join("it/repo/g/a/1-SNAPSHOT");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("a-1-SNAPSHOT.pom"),
            "<project><groupId>g</groupId><artifactId>a</artifactId>\
             <version>1-SNAPSHOT</version></project>",
        )
        .unwrap();
        std::fs::write(
            nested.join("_remote.repositories"),
            "a-1-SNAPSHOT.pom>snapshots=\n",
        )
        .unwrap();
        let since = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        assert!(
            nested_repository_files(root.path(), m2.path(), since, &|_| true)
                .unwrap()
                .is_empty()
        );
        std::fs::remove_dir_all(m2.path().join("g")).unwrap();
        refused(
            nested_repository_files(root.path(), m2.path(), since, &|_| true).unwrap_err(),
            "g/a/1-SNAPSHOT/a-1-SNAPSHOT.pom",
        );
    }

    /// A forked build's own local repository yields what it downloaded and
    /// the export lacks, its group read from the POM.
    #[test]
    fn reads_what_a_forked_build_downloaded() {
        let root = tempfile::TempDir::new().unwrap();
        let m2 = tempfile::TempDir::new().unwrap();
        let version = root.path().join("it/local-repo/org/apache/p/clean/3.2.0");
        std::fs::create_dir_all(&version).unwrap();
        std::fs::write(
            version.join("clean-3.2.0.pom"),
            "<project><parent><groupId>org.apache.p</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>clean</artifactId></project>",
        )
        .unwrap();
        for file in [
            "clean-3.2.0.jar",
            "clean-3.2.0-tests.jar",
            "clean-3.2.0-built.jar",
        ] {
            std::fs::write(version.join(file), file).unwrap();
        }
        std::fs::write(
            version.join("_remote.repositories"),
            "clean-3.2.0.pom>central=\nclean-3.2.0.jar>central=\n\
             clean-3.2.0-tests.jar>central=\nclean-3.2.0-built.jar>=\n",
        )
        .unwrap();
        let held = m2
            .path()
            .join("org/apache/p/clean/3.2.0/clean-3.2.0-tests.jar");
        std::fs::create_dir_all(held.parent().unwrap()).unwrap();
        std::fs::write(&held, "tests").unwrap();
        let since = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        let read =
            super::nested_repository_files(root.path(), m2.path(), since, &|_| true).unwrap();
        let named: Vec<String> = (read.iter())
            .map(|(coordinate, ..)| coordinate.to_string())
            .collect();
        assert_eq!(
            named,
            [
                "org.apache.p:clean:3.2.0:jar",
                "org.apache.p:clean:3.2.0:pom"
            ]
        );
        // A jar resolved alone sits beside a version whose POM gives the
        // repository's start, and a directory a test left unreadable is
        // passed by.
        let alone = root.path().join("it/local-repo/junit/junit/4.12");
        std::fs::create_dir_all(&alone).unwrap();
        std::fs::write(alone.join("junit-4.12.jar"), "junit").unwrap();
        std::fs::write(
            alone.join("_remote.repositories"),
            "junit-4.12.jar>central=\n",
        )
        .unwrap();
        let unreadable = root.path().join("target/locked");
        std::fs::create_dir_all(&unreadable).unwrap();
        #[cfg(unix)]
        let mode = |mode| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        #[cfg(not(unix))]
        let mode = |_: u32| {};
        mode(0);
        let read = super::nested_repository_files(root.path(), m2.path(), since, &|_| true);
        mode(0o755);
        let named: Vec<String> = (read.unwrap().iter())
            .map(|(coordinate, ..)| coordinate.to_string())
            .collect();
        assert_eq!(
            named,
            [
                "junit:junit:4.12:jar",
                "org.apache.p:clean:3.2.0:jar",
                "org.apache.p:clean:3.2.0:pom"
            ]
        );
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        assert!(
            super::nested_repository_files(root.path(), m2.path(), later, &|_| true)
                .unwrap()
                .is_empty()
        );
    }

    /// A marker names a repository by Maven 3.9's id or by Maven 3.10's
    /// `<id>-<sha1 of the URL>` for each way Maven may reach it: through the
    /// mirror its settings give, or directly where only raeva's config
    /// mirrors it, at the URL as declared or, where raeva keeps it only
    /// normalized, without the `/`. Central is at the super POM's URL, not
    /// at the one maven-resolver's demos spell with a `/`; and a repository
    /// whose literal id is the marker comes before one whose key it is.
    #[test]
    fn a_marker_names_a_repository_by_maven_3_10_s_key() {
        let project = tempfile::TempDir::new().unwrap();
        let paths = rv_config::ResolvedPaths::for_testing().unwrap();
        let plain = Config::for_testing(project.path().to_path_buf(), paths);
        let mut mirror = rv_config::MirrorConfig::new(Some("corp"), "https://cache.example/m2");
        mirror.mirror_of = vec!["central".to_string()];
        let mirrored = plain.clone().with_mirrors(vec![mirror]);
        let key =
            |id: &str, url: &str| format!("{id}-{}", Sha1::from_bytes(url.as_bytes()).as_str());
        let repo = |id: &str, url: &str| Repository::new(Some(id.to_string()), url, true, false);
        let central = repo("central", "https://repo.maven.apache.org/maven2");
        let super_pom = key("central", "https://repo.maven.apache.org/maven2");
        let demos = key("central", "https://repo.maven.apache.org/maven2/");
        assert!(names(
            &mirrored,
            &central,
            &key("corp", "https://cache.example/m2")
        ));
        assert!(names(&mirrored, &central, &super_pom));
        assert!(names(&mirrored, &central, "central"));
        for config in [&plain, &mirrored] {
            for url in [
                "https://repo1.maven.org/maven2/",
                "https://repo.maven.apache.org/maven2/",
            ] {
                assert!(names(config, &repo("central", url), &super_pom), "{url}");
                assert!(!names(config, &repo("central", url), &demos), "{url}");
            }
        }
        let recorded = repo("corp-plugins", "https://repo.example/m2/");
        assert!(names(
            &plain,
            &recorded,
            &key("corp-plugins", "https://repo.example/m2")
        ));
        assert!(names(
            &plain,
            &recorded,
            &key("corp-plugins", "https://repo.example/m2/")
        ));
        let odd = repo("a:b", "https://x.example/r");
        assert!(names(
            &plain,
            &odd,
            &key("a-COLON-b", "https://x.example/r")
        ));
        assert!(!names(&plain, &odd, &key("a:b", "https://x.example/r")));

        let hashed = repo("corp", "https://u.example/r");
        let literal = key("corp", "https://u.example/r");
        let first = named_first(
            &plain,
            &[hashed, repo(&literal, "https://v.example/r")],
            Some(&literal),
        );
        assert_eq!(first[0].id.as_deref(), Some(literal.as_str()));
    }

    /// A path of the local repository reads as parse_artifact_path reads
    /// its text, which layout.rs tests.
    #[test]
    fn reads_coordinates_from_the_local_repository_layout() {
        let coordinate = |path: &str| layout_coordinate(Path::new(path)).map(|c| c.to_string());
        assert_eq!(
            coordinate("g/h/a/1/a-1.jar").as_deref(),
            Some("g.h:a:1:jar")
        );
        assert_eq!(coordinate("g/a/1-SNAPSHOT/a-1-SNAPSHOT.jar"), None);
    }
}
