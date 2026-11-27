use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rv_maven_types::{MavenMode, bounded};

use crate::environment::LauncherSet;
use crate::{HostInput, ModelEnvironment, PomError};

mod java_regex;
mod jvm_names;

use java_regex::{MAX_REGEX_LENGTH, full_regex_match};

/// Where Maven places command-line properties while building a model.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum PropertySource {
    /// Project models receive command-line properties as user properties.
    #[default]
    User,
    /// Imported models receive user properties without external settings profiles.
    Import,
    /// Dependency models receive them as system properties, without settings profiles.
    System,
}

/// The property that turns off Maven 3.10's restricted interpolation of the
/// models it reads from a repository.
const FULL_EXTERNAL_INTERPOLATION: &str = "maven.model.dependencyInterpolation.full";

/// Whether Maven 3.10 reads `name` from the user and system properties when
/// it interpolates a model it reads from a repository.
pub(crate) fn is_safe_external_property(name: &str) -> bool {
    name.starts_with("java.")
        || name.starts_with("os.")
        || name.starts_with("maven.")
        || matches!(
            name,
            "file.separator"
                | "path.separator"
                | "line.separator"
                | "revision"
                | "changelist"
                | "sha1"
        )
}

/// What profile activation and model interpolation read from outside the
/// POM: user and system properties, the host and target platform, the
/// project directory and the `-P` selections.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ActivationContext {
    /// The source of command-line properties in this model request.
    pub property_source: PropertySource,
    /// Maven user properties: the `-D` entries of `.mvn/maven.config`. Maven
    /// copies them over its system properties, so they win wherever Maven
    /// reads both.
    pub properties: HashMap<String, String>,
    /// The public POM packaging used when the request supplies no user override.
    pub(crate) default_packaging: Option<String>,
    /// Whether `properties.packaging` is that public default rather than an external value.
    pub(crate) packaging_injected: bool,
    /// The platform, JDK and environment variables the build sees. The
    /// JVM system properties Maven sees come from it: `os.name` and
    /// `os.arch` of the target platform, `java.version`, and `java.home`
    /// when known. `os.version` is left out because raeva cannot know it.
    pub environment: ModelEnvironment,
    /// System properties set over the JVM's. Maven builds a dependency's
    /// model with the project's user properties here rather than as user
    /// properties, so the dependency's own properties win over them.
    pub system_properties: HashMap<String, String>,
    /// The project directory: `${basedir}` and `${project.basedir}`, and
    /// the base a relative `<file>` condition is joined to. Without it a
    /// relative `<file>` condition does not activate.
    pub base_dir: Option<PathBuf>,
    /// Profile ids selected with `-P`, which activate whatever their
    /// conditions say.
    pub active_profiles: Vec<String>,
    /// Profile ids deselected with `-P!`, which never activate.
    pub inactive_profiles: Vec<String>,
    /// The names among [`Self::properties`] and [`Self::system_properties`]
    /// whose `.mvn/maven.config` value was expanded from a `${...}`, so it
    /// can hold a host value. Condition text built from one is the host's.
    pub expanded_properties: BTreeSet<String>,
    /// Properties from active `settings.xml` profiles, which Maven 3.9's
    /// `DefaultModelBuilder` treats as external profiles of the build
    /// request: placed under [`Self::properties`] (`-D` user properties) in
    /// the profile activation user properties and injected into the
    /// project's model after its POM profiles.
    pub settings_properties: crate::PropertyMap,
    /// The repositories of each active `settings.xml` profile whose URL
    /// still holds a `${...}` once the file is interpolated, root-declared
    /// and in activation order. Maven injects them into the project's own
    /// model after its POM profiles, so the model's properties fill them
    /// in and its parent lookup reads them as written.
    pub settings_repositories: Vec<Vec<crate::Repository>>,
    /// Every property name defined by any profile in `settings.xml`, active
    /// or not, so project-lineage builds record [`HostInput::SettingsProperty`]
    /// when a resolution-relevant expression or profile condition reads one.
    pub settings_property_names: BTreeSet<String>,
    /// Whether `settings.xml`, `config.toml` or `raeva.toml` names a
    /// repository `central`, which Maven 3.10 keeps over the super POM's.
    pub configured_central: bool,
    /// The `env.*` entries of the `<properties>` of a model Maven 3.10
    /// reads from a repository, which a `<property>` condition sees when
    /// the variable is unset.
    pub(crate) repository_env: HashMap<String, String>,
    /// The names of [`Self::system_properties`] a `-D` set, which are the
    /// build's own even where a `.mvn/jvm.config` value is the same.
    pub(crate) system_defines: BTreeSet<String>,
}

/// The system properties [`ActivationContext::system_property`] answers
/// from the platform, the JDK and the Maven line.
const SYSTEM_PROPERTY_NAMES: [&str; 11] = [
    "file.separator",
    "java.home",
    "java.specification.version",
    "java.version",
    "line.separator",
    "maven.build.version",
    "maven.version",
    "org.jline.terminal.exec.redirectPipeCreationMode",
    "os.arch",
    "os.name",
    "path.separator",
];

/// The constant value Maven 3.10.0's `bin/mvn` and `mvn.cmd` pass as
/// `-Dorg.jline.terminal.exec.redirectPipeCreationMode`.
const JLINE_REDIRECT_MODE: &str = "native,reflection";

/// What Maven's JVM holds for a system property that the JVM, `mvn` or
/// `MavenCli` sets on every run: the value raeva knows on the platform,
/// JDK and Maven line of an environment, or [`Self::Unread`] for one raeva
/// does not read from the host, such as `java.vendor` or `user.name`.
/// Profile activation, settings.xml interpolation and `-D`/`-P` expansion
/// all read this one model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostProperty {
    /// The value Maven sees, from inputs raeva.lock records.
    Answered(String),
    /// A value raeva cannot know.
    Unread,
}

/// [`HostProperty`] for `name` in `environment`, `None` when neither the
/// JVM nor this Maven line's launcher sets it, so Maven leaves `${name}` as
/// written. Nothing is recorded as read: a reader records the value it
/// takes, or what it tested.
///
/// A `.mvn/jvm.config` value comes first. `java.home` is the host JDK's,
/// and unread under a `[lock] jdks` entry unless the lock lists the host's
/// JDK alone: raeva does not know another JDK's home.
pub fn host_property(environment: &ModelEnvironment, name: &str) -> Option<HostProperty> {
    let mode = environment.maven_mode();
    // What `mvn` sets in its JVM's environment itself.
    if let Some(variable) = name.strip_prefix("env.") {
        return match environment.launcher_set(variable)? {
            LauncherSet::Value(value) => Some(HostProperty::Answered(value.to_string())),
            LauncherSet::Unknown => Some(HostProperty::Unread),
            LauncherSet::Unset => None,
        };
    }
    if environment.unread_system_property(name) {
        return Some(HostProperty::Unread);
    }
    // A `.mvn/jvm.config` value of a JVM-owned name, which some JDKs keep
    // their own value of (Temurin's `java.vendor.version`, 17's
    // `java.specification.maintenance.version`), is not one every JDK the
    // lock covers lets stand.
    if environment.system_properties().contains_key(name) && jvm_owned(name) {
        return Some(HostProperty::Unread);
    }
    match jvm_names::class(name, mode)? {
        jvm_names::Class::Fixed(value) => return Some(HostProperty::Answered(value.to_string())),
        jvm_names::Class::PerHost | jvm_names::Class::Uneven => return Some(HostProperty::Unread),
        jvm_names::Class::Locked | jvm_names::Class::Unseen => {}
    }
    let windows = environment.platform().map(|(os, _)| os == "windows");
    let known = |value: Option<&str>| {
        value.map_or(HostProperty::Unread, |value| {
            HostProperty::Answered(value.to_string())
        })
    };
    Some(match name {
        // Windows 10, 11 and Server JVMs each report their own.
        "os.name" if windows == Some(true) && environment.windows_os_name().is_none() => {
            HostProperty::Unread
        }
        "os.name" => known(environment.os_name()),
        "os.arch" => known(environment.os_arch()),
        "file.separator" => known(windows.map(|windows| if windows { "\\" } else { "/" })),
        "path.separator" => known(windows.map(|windows| if windows { ";" } else { ":" })),
        "line.separator" => known(windows.map(|windows| if windows { "\r\n" } else { "\n" })),
        // A `[lock] jdks` entry is a feature version, whose patch releases
        // each report their own.
        "java.version" if environment.target_jdk().is_some() => HostProperty::Unread,
        "java.version" => known(Some(environment.host_java_version())),
        "java.specification.version" => known(Some(java_specification_version(
            environment.host_java_version(),
        ))),
        "java.home" => known(environment.host_java_home()),
        "maven.version" => known(Some(mode.version())),
        "maven.build.version" => known(Some(mode.build_version())),
        "org.jline.terminal.exec.redirectPipeCreationMode" => known(Some(JLINE_REDIRECT_MODE)),
        "maven.multiModuleProjectDirectory" => known(environment.launcher_root()),
        _ => HostProperty::Unread,
    })
}

/// How a refusal over the unread host property `name` tells the user to
/// fix it. `user.home` differs from host to host even where `MAVEN_OPTS`
/// or another JVM option sets it, so only a `-D` both raeva and Maven take
/// gives every host one. Under `[lock] jdks` naming another JDK than the
/// host's, no allowlist gives its home.
pub fn unread_property_fix(name: &str, environment: &ModelEnvironment) -> String {
    let other_jdk = environment.target_jdk().is_some() && environment.host_java_home().is_none();
    match name {
        "user.home" => "give every host one Maven user home with -Duser.home=<dir> on the \
                        command line of both raeva and mvn; one in MAVEN_OPTS or another JVM \
                        option is each host's own"
            .to_string(),
        "java.home" | "env.JAVA_HOME" if other_jdk => {
            "raeva knows the home only of the JDK mvn runs on \
                                          this host, so list that JDK alone in [lock] jdks, \
                                          or none"
                .to_string()
        }
        _ => match name.strip_prefix("env.") {
            Some(var) if environment.launcher_set(var).is_some() => {
                format!("mvn sets {var} itself, to a value raeva cannot know; do not read it")
            }
            Some(var) => crate::environment::allow_env_fix(var),
            None => format!("set it with -D{name}=<value>"),
        },
    }
}

/// The answered system properties whose value differs by locked platform or
/// JDK; the others raeva answers are the same on every one.
pub const PLATFORM_PROPERTIES: [&str; 8] = [
    "file.separator",
    "java.home",
    "java.specification.version",
    "java.version",
    "line.separator",
    "os.arch",
    "os.name",
    "path.separator",
];

/// The values of every [`HostProperty::Answered`] name in `environment`.
pub fn answered_host_properties(environment: &ModelEnvironment) -> Vec<(&'static str, String)> {
    jvm_names::names()
        .filter_map(|name| match host_property(environment, name)? {
            HostProperty::Answered(value) => Some((name, value)),
            HostProperty::Unread => None,
        })
        .collect()
}

/// The first `${...}` of `text` that names a [`HostProperty::Unread`]
/// property in `environment`, or a variable set outside the `${env.*}`
/// allowlist: text Maven expands where raeva cannot.
pub fn unread_host_reference(text: &str, environment: &ModelEnvironment) -> Option<String> {
    (crate::properties::expression_names(text).into_iter())
        .find(|read| {
            host_property(environment, read) == Some(HostProperty::Unread)
                || (read.strip_prefix("env.")).is_some_and(|var| environment.hides_env(var))
        })
        .map(str::to_string)
}

/// Whether `name` is a system property a JVM or `mvn` sets where a model
/// sees it, on some JDK, OS or Maven line Maven was measured on
/// (`activation/jvm_names.tsv`). Of these, raeva answers only what the
/// lock's inputs fix on every host it covers ([`host_property`]); any
/// other name is unset unless the POM, the user or `.mvn/` sets it.
pub fn jvm_owned(name: &str) -> bool {
    jvm_names::measured_name(name)
}

/// The text every `java.version` a JDK of the `[lock] jdks` entry `entry`
/// reports starts with, followed by nothing or by `.`, `_` or `-`: `1.8.0`
/// for `1.8`, whose updates all report `1.8.0_N`, else the entry.
fn covered_root(entry: &str) -> &str {
    match entry.trim() {
        "1.8" => "1.8.0",
        entry => entry,
    }
}

/// Whether `version` is one a JDK of the `[lock] jdks` entry `entry` can
/// report.
fn covered_version(entry: &str, version: &str) -> bool {
    (version.strip_prefix(covered_root(entry)))
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '_', '-']))
}

/// The `java.version` profile activation tests on a JDK `environment`
/// fixes by a `[lock] jdks` entry: one that entry covers, as a test every
/// JDK it covers answers alike gives its answer on all of them.
fn tested_java_version<'a>(version: &'a str, environment: &ModelEnvironment) -> &'a str {
    match environment.target_jdk() {
        Some(_) => covered_root(version),
        None => version,
    }
}

/// Whether every JDK the `[lock] jdks` entry `entry` covers reports the
/// `java.version` `value`: `None` when some do and others do not.
fn equal_on_every_patch(entry: &str, value: &str) -> Option<bool> {
    (!covered_version(entry, value)).then_some(false)
}

/// The answer `JdkVersionProfileActivator` gives the `<jdk>` `spec` on
/// every JDK the `[lock] jdks` entry `entry` covers, `None` when they
/// differ or Maven fails on one.
///
/// A prefix test holds on all of them when it is a prefix of the entry's
/// [`covered_root`], on some when it continues the root past a separator,
/// and on none otherwise. A range compares the first three numbers of
/// `java.version`, split at `.`, `_` and `-`, with each bound's: the entry
/// fixes the numbers it names and the others take any value, so the
/// answer changes only where a free number crosses a number some bound
/// names. Testing each such number, the ones beside it, 0 and
/// `i32::MAX` covers every case.
fn jdk_on_every_patch(entry: &str, spec: &str) -> Option<bool> {
    let root = covered_root(entry);
    let prefix = |prefix: &str| {
        if root.starts_with(prefix) {
            Some(true)
        } else if (prefix.strip_prefix(root)).is_some_and(|rest| rest.starts_with(['.', '_', '-']))
        {
            None
        } else {
            Some(false)
        }
    };
    if let Some(negated) = spec.strip_prefix('!') {
        return prefix(negated).map(|holds| !holds);
    }
    if !(spec.starts_with('[') || spec.starts_with('(')) {
        return prefix(spec);
    }
    let fixed: Vec<i32> = (root.split('.'))
        .map(|part| {
            part.parse()
                .ok()
                .filter(|_| part.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect::<Option<_>>()?;
    let mut values: BTreeSet<i32> = BTreeSet::from([0, i32::MAX]);
    for part in spec.split(|c: char| !(c.is_ascii_digit() || c == '-' || c == '+')) {
        if let Ok(number) = part.parse::<i32>() {
            values.extend([number.saturating_sub(1), number, number.saturating_add(1)]);
        }
    }
    values.retain(|value| *value >= 0);
    let mut versions = vec![fixed.clone()];
    for _ in fixed.len()..3 {
        versions = (versions.into_iter())
            .flat_map(|version| {
                values.iter().map(move |value| {
                    let mut version = version.clone();
                    version.push(*value);
                    version
                })
            })
            .collect();
    }
    let mut answers = versions.iter().map(|version| {
        let text: Vec<String> = version.iter().map(i32::to_string).collect();
        jdk_in_range(spec, &text.join("."))
    });
    let first = answers.next()??;
    answers.all(|answer| answer == Some(first)).then_some(first)
}

/// `text` with each `${...}` that names a [`HostProperty::Answered`]
/// property of `environment` replaced by its value, as Maven's settings
/// builder and `MavenCli` expand it. Other references stay as written.
pub fn expand_host_properties(text: &str, environment: &ModelEnvironment) -> String {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        let key = rv_maven_types::expression_key(&after[..end]);
        if matches!(key, "java.version" | "java.specification.version") {
            environment.record_java_lookup();
        }
        let value = match host_property(environment, key) {
            Some(HostProperty::Answered(value)) => Some(value),
            _ => None,
        };
        output.push_str(&rest[..start]);
        match value {
            Some(value) => output.push_str(&value),
            None => output.push_str(&rest[start..start + 3 + end]),
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}

/// Whether a `.mvn/jvm.config` `-D` of `name` changes nothing in Maven:
/// JDK 17, 21 and 27 keep their own value of these, the `mvn` launcher of
/// `mode` passes its own after the file, and `MavenCli.populateProperties`
/// sets `maven.version` and `maven.build.version` over any.
pub fn fixed_over_jvm_config(name: &str, mode: MavenMode) -> bool {
    let launcher = match mode {
        MavenMode::Maven39 => &["library.jansi.path"][..],
        MavenMode::Maven310 => &[
            "library.jline.path",
            "org.jline.terminal.exec.redirectPipeCreationMode",
        ][..],
    };
    launcher.contains(&name)
        || matches!(
            name,
            "java.version"
                | "java.version.date"
                | "java.vendor"
                | "java.vendor.url"
                | "java.vendor.url.bug"
                | "java.class.version"
                | "java.class.path"
                | "java.vm.version"
                | "java.vm.name"
                | "java.vm.vendor"
                | "java.vm.info"
                | "java.vm.compressedOopsMode"
                | "java.vm.specification.version"
                | "java.vm.specification.name"
                | "java.vm.specification.vendor"
                | "java.specification.version"
                | "java.specification.maintenance.version"
                | "java.specification.name"
                | "java.specification.vendor"
                | "java.runtime.version"
                | "java.runtime.name"
                | "jdk.debug"
                | "native.encoding"
                | "sun.jnu.encoding"
                | "sun.java.launcher"
                | "sun.java.command"
                | "sun.boot.library.path"
                | "sun.management.compiler"
                | "classworlds.conf"
                | "maven.home"
                | "maven.multiModuleProjectDirectory"
                | "maven.version"
                | "maven.build.version"
        )
}

/// The names [`fixed_over_jvm_config`] drops that some JDKs take a
/// `.mvn/jvm.config` `-D` of, with the first feature release that keeps
/// its own: JDK 8 takes each `-D`, JDK 11 those kept from 17, and 11, 17,
/// 21, 26 and 27 keep the rest. The others some JDKs take, such as
/// `java.version.date`, are unset on those JDKs, so any read of them
/// refuses already.
const KEPT_FROM: [(&str, u32); 8] = [
    ("java.class.version", 17),
    ("java.specification.name", 17),
    ("java.specification.vendor", 17),
    ("java.specification.version", 17),
    ("java.vendor", 11),
    ("java.vendor.url", 11),
    ("java.vendor.url.bug", 11),
    ("sun.jnu.encoding", 11),
];

/// Why the value `value` of `name` that the JVM option channel `channel`
/// gives gives a lock raeva cannot make, `None` when it can: every JDK of
/// `jdks`, the `[lock] jdks`
/// entries, keeps its own value, or `name` is one raeva never answers and
/// `value` is not empty, so only a presence test reads it, which holds on
/// every JDK. Without `jdks` the JDK that runs `mvn` is not one the lock
/// records.
pub fn jvm_config_by_jdk(
    name: &str,
    value: &str,
    jdks: &[String],
    channel: &str,
) -> Option<String> {
    let &(_, kept_from) = KEPT_FROM.iter().find(|(known, _)| *known == name)?;
    // Measured on 8, 11, 17 and later only.
    let keeps = |entry: &String| {
        let entry = entry.trim();
        let feature = entry.strip_prefix("1.").unwrap_or(entry);
        let digits = feature.find(|c: char| !c.is_ascii_digit());
        let feature: Option<u32> = feature[..digits.unwrap_or(feature.len())].parse().ok();
        feature.is_some_and(|feature| feature >= kept_from && (feature == 11 || feature >= 17))
    };
    let answered = name.starts_with("java.specification.");
    if (!jdks.is_empty() && jdks.iter().all(keeps)) || (!answered && !value.is_empty()) {
        return None;
    }
    let takers = match kept_from {
        17 => "JDK 8 and 11 take",
        _ => "JDK 8 takes",
    };
    Some(format!(
        "{channel} sets -D{name}, which {takers} from it and JDK {kept_from} and newer \
         ignore, so the value Maven sees depends on the JDK that runs mvn; list JDKs \
         {kept_from} or newer alone in [lock] jdks, or remove -D{name} from {channel}"
    ))
}

impl ActivationContext {
    /// Install external properties at the same precedence as the model request.
    pub fn set_external_properties(
        &mut self,
        properties: HashMap<String, String>,
        source: PropertySource,
    ) {
        self.property_source = source;
        match source {
            PropertySource::User | PropertySource::Import => self.properties = properties,
            PropertySource::System => {
                self.system_properties = self.environment.system_properties().clone();
                self.define_system_properties(properties);
            }
        }
    }

    /// Set `properties`, `-D` values, as system properties.
    pub fn define_system_properties(&mut self, properties: HashMap<String, String>) {
        self.system_defines.extend(properties.keys().cloned());
        self.system_properties.extend(properties);
    }

    /// A context with no user properties, profile selections or base
    /// directory.
    pub fn new(environment: ModelEnvironment) -> Self {
        Self {
            system_properties: environment.system_properties().clone(),
            environment,
            ..Self::default()
        }
    }

    /// Maven 3.10's `${project.rootDirectory}` for the project in
    /// [`Self::base_dir`], in the 3.10 mode only.
    pub(crate) fn root_directory(&self) -> Option<PathBuf> {
        let base = self.base_dir.as_deref()?;
        let fallback = (self.environment.launcher_root().map(Path::new))
            .or(self.environment.reactor_root())
            .unwrap_or(base);
        (self.environment.maven_mode() == MavenMode::Maven310)
            .then(|| root_directory(base, fallback))
    }

    /// Whether `name` is a directory of the project that a `<file>` path
    /// reads ahead of the properties: `${basedir}`, `${project.basedir}`
    /// and, in the 3.10 mode, `${project.rootDirectory}`.
    pub(crate) fn is_file_directory(&self, name: &str) -> bool {
        match name {
            "basedir" | "project.basedir" => self.base_dir.is_some(),
            "project.rootDirectory" => {
                self.base_dir.is_some() && self.environment.maven_mode() == MavenMode::Maven310
            }
            _ => false,
        }
    }

    /// The values of `${basedir}`, `${project.basedir}` and, in the 3.10
    /// mode, `${project.rootDirectory}`.
    pub fn file_directories(&self) -> Vec<(&'static str, String)> {
        let mut directories = Vec::new();
        if let Some(base) = &self.base_dir {
            let base = base.to_string_lossy().into_owned();
            directories.push(("basedir", base.clone()));
            directories.push(("project.basedir", base));
        }
        if let Some(root) = self.root_directory() {
            directories.push(("project.rootDirectory", root.to_string_lossy().into_owned()));
        }
        directories
    }

    /// Sets `maven.multiModuleProjectDirectory` in the properties of a
    /// `<file>` path to the launcher's directory, and `java.home` and
    /// `env.JAVA_HOME` to the host JDK's, each unless a `-D`, settings.xml
    /// or POM value set it.
    /// They go in as the project directories do, so the lock keeps what the
    /// path tested and not the directory.
    pub fn insert_launcher_root(&self, map: &mut crate::PropertyMap) {
        for (name, directory) in [
            (
                "maven.multiModuleProjectDirectory",
                self.environment.launcher_root(),
            ),
            ("java.home", self.environment.host_java_home()),
            ("env.JAVA_HOME", self.environment.host_java_home_env()),
        ] {
            if let (None, Some(directory)) = (map.get(name), directory) {
                map.insert(name, directory);
            }
        }
    }

    /// Sets `os.name`, `os.arch`, and `path.separator` from a Rust OS/arch name.
    #[cfg(test)]
    pub(crate) fn set_platform(&mut self, rust_os: &str, rust_arch: &str) {
        self.environment = self.environment.for_platform(rust_os, rust_arch);
    }

    /// The JVM's `path.separator` on the target platform. Maven's `dos` and
    /// `unix` OS families test it instead of `os.name`.
    pub fn path_separator(&self) -> Option<char> {
        self.environment.path_separator()
    }

    /// This context with the `packaging` user property Maven 3.9 adds for a
    /// model it builds: the input POM's `<packaging>` as written, `jar` when
    /// absent, unless a `packaging` user property is already set. The whole
    /// parent chain's profile activation sees it.
    pub fn with_input_packaging(&self, pom: &crate::Pom) -> Self {
        let mut ctx = self.clone();
        if !ctx.packaging_injected {
            ctx.default_packaging =
                Some(pom.packaging.clone().unwrap_or_else(|| "jar".to_string()));
        }
        if self.settings_properties.get("packaging").is_none()
            && let std::collections::hash_map::Entry::Vacant(entry) =
                ctx.properties.entry("packaging".to_string())
        {
            let packaging = ctx
                .default_packaging
                .clone()
                .unwrap_or_else(|| "jar".to_string());
            entry.insert(packaging.clone());
            ctx.packaging_injected = true;
        }
        ctx
    }

    /// Properties for ordinary model interpolation, with external user properties first.
    pub fn model_properties(&self, public: &crate::PropertyMap) -> crate::PropertyMap {
        let mut properties = public.clone();
        for (name, value) in self.model_user_properties() {
            properties.insert_external(name, value);
        }
        properties.set_input_context(self);
        properties
    }

    /// Whether Maven 3.10 interpolates this model as one it reads from a
    /// repository: a dependency's, a parent of one, or an imported BOM,
    /// unless `maven.model.dependencyInterpolation.full` is `true`.
    pub(crate) fn restricts_interpolation(&self) -> bool {
        let full = |properties: &HashMap<String, String>| {
            (properties.get(FULL_EXTERNAL_INTERPOLATION))
                .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        };
        self.repository_model() && !full(&self.properties) && !full(&self.system_properties)
    }

    /// Whether Maven 3.10 reads this model from a repository, so activates
    /// its profiles apart and never its `<file>` profiles.
    pub(crate) fn repository_model(&self) -> bool {
        self.environment.maven_mode() == MavenMode::Maven310
            && self.property_source != PropertySource::User
    }

    /// The active settings.xml profile properties, then the user
    /// properties, that model interpolation reads ahead of the model's own:
    /// in a [`Self::restricts_interpolation`] model only those Maven 3.10
    /// reads there.
    pub(crate) fn model_user_properties(&self) -> impl Iterator<Item = (&String, &String)> {
        let restricted = self.restricts_interpolation();
        (self.settings_properties.iter())
            .chain(&self.properties)
            .filter(move |(name, _)| !restricted || is_safe_external_property(name))
    }

    /// Properties for activation interpolation, with the POM's own properties first.
    pub fn activation_properties(&self, public: &crate::PropertyMap) -> crate::PropertyMap {
        let mut properties = crate::PropertyMap::new();
        for name in ["file.separator", "path.separator", "line.separator"] {
            if let Some(value) = self.system_property(name) {
                properties.insert_external(name, value);
            }
        }
        for (name, value) in self.activation_system_properties() {
            properties.insert_external(name, value);
        }
        for (name, value) in self.settings_properties.iter() {
            properties.insert_external(name, value);
        }
        for (name, value) in &self.properties {
            properties.insert_external(name, value);
        }
        properties.extend(public);
        properties.set_input_context(self);
        properties
    }

    /// A property as Maven's profile activators read it: the user property,
    /// then an active `settings.xml` profile property, else the system
    /// property. Maven sets each `-D` value as a system property too, so a
    /// reader of system properties sees it this way.
    pub fn property(&self, name: &str) -> Option<&str> {
        self.properties
            .get(name)
            .or_else(|| self.settings_properties.get(name))
            .map(String::as_str)
            .or_else(|| self.system_property(name))
    }

    /// Whether an interpolated `<exists>` path exists, aligned to the local POM directory.
    /// Without a local directory, only absolute paths can activate.
    pub fn file_condition_exists(&self, path: &str) -> bool {
        let path = self.base_dir.as_ref().map_or_else(
            || path.to_string(),
            |base| crate::project::profiles::align_to_base_directory(path, base, &self.environment),
        );
        file_active(
            &ActivationFile {
                exists: Some(path),
                missing: None,
            },
            true,
            self,
            &self.environment.detached(),
        )
    }

    /// The value of `name` a `<property>` condition compares, when Maven
    /// expanded it from a `${...}` before: a `-D` value, one passed to a
    /// dependency's model, or a settings.xml profile property. A
    /// `.mvn/jvm.config` value reaches the JVM as written.
    fn expanded_value(&self, name: &str) -> Option<&str> {
        let expanded = self.expanded_properties.contains(name);
        let value = match self.properties.get(name) {
            Some(value) => Some(value).filter(|_| expanded),
            None => (self.settings_properties.get(name))
                .or_else(|| (self.system_properties.get(name)).filter(|_| expanded)),
        };
        value.map(String::as_str)
    }

    /// A `-D` value, else the system property: what Maven's OS activator
    /// and os-maven-plugin read, without settings.xml profile properties.
    fn user_or_system_property(&self, name: &str) -> Option<&str> {
        (self.properties.get(name).map(String::as_str)).or_else(|| self.system_property(name))
    }

    pub(crate) fn system_property(&self, name: &str) -> Option<&str> {
        if let Some(value) = self.system_properties.get(name) {
            return Some(value);
        }
        match name {
            "os.name" => self.environment.os_name(),
            "os.arch" => self.environment.os_arch(),
            "java.version" => Some(tested_java_version(
                self.environment.java_version(),
                &self.environment,
            )),
            "java.specification.version" => {
                Some(java_specification_version(self.environment.java_version()))
            }
            "java.home" => self.environment.java_home(),
            "maven.version" => Some(self.environment.maven_mode().version()),
            "maven.build.version" => Some(self.environment.maven_mode().build_version()),
            "org.jline.terminal.exec.redirectPipeCreationMode" => (self.environment.maven_mode()
                == MavenMode::Maven310)
                .then_some(JLINE_REDIRECT_MODE),
            "file.separator" | "path.separator" | "line.separator" => {
                let windows = self.environment.platform()?.0 == "windows";
                Some(match (name, windows) {
                    ("file.separator", false) => "/",
                    ("file.separator", true) => "\\",
                    ("path.separator", false) => ":",
                    ("path.separator", true) => ";",
                    (_, false) => "\n",
                    (_, true) => "\r\n",
                })
            }
            _ => match jvm_names::class(name, self.environment.maven_mode()) {
                Some(jvm_names::Class::Fixed(value)) => Some(value),
                _ => None,
            },
        }
    }

    /// The target platform's `os.*` system properties, Maven's
    /// `maven.version` and `maven.build.version`, the jline pipe mode
    /// 3.10's `mvn` sets, and those every JVM sets alike. Host paths such as
    /// `java.home` stay out.
    pub fn platform_system_properties(&self) -> HashMap<String, String> {
        let mode = self.environment.maven_mode();
        // Windows 10, 11 and Server JVMs each report their own `os.name`, so
        // text that reads it keeps `${os.name}`, and refuses where it can
        // change the lock.
        let windows = self
            .environment
            .platform()
            .is_some_and(|(os, _)| os == "windows");
        [
            (
                "os.name",
                (self.environment.os_name())
                    .filter(|_| !windows || self.environment.windows_os_name().is_some()),
            ),
            ("os.arch", self.environment.os_arch()),
            ("maven.version", Some(mode.version())),
            ("maven.build.version", Some(mode.build_version())),
            (
                "org.jline.terminal.exec.redirectPipeCreationMode",
                (mode == MavenMode::Maven310).then_some(JLINE_REDIRECT_MODE),
            ),
        ]
        .into_iter()
        .chain(jvm_names::fixed_values().map(|(name, value)| (name, Some(value))))
        .filter(|(key, _)| !self.environment.unread_system_property(key))
        .filter_map(|(key, value)| Some((key.to_string(), value?.to_string())))
        .collect()
    }

    /// The system properties profile activation interpolates with, apart
    /// from `java.version`, which the environment answers when asked: the
    /// target platform's `os.*` and [`Self::system_properties`].
    pub fn activation_system_properties(&self) -> HashMap<String, String> {
        let mut properties = self.platform_system_properties();
        properties.extend(
            self.system_properties
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        properties
    }

    /// The system properties model interpolation sees below model
    /// properties, apart from `java.version`, which the environment answers
    /// when a model asks for it. A `-D` override is a user property and
    /// reaches interpolation through the model's own property map instead.
    ///
    /// `os.detected.*` is what os-maven-plugin sets from the JVM's `os.name`
    /// and `os.arch`, below a value [`Self::system_properties`] holds, as a
    /// dependency's model sees the project's `-D` values.
    pub(crate) fn interpolation_system_properties(&self) -> HashMap<String, String> {
        let mut properties = self.activation_system_properties();
        for key in crate::properties::OS_DETECTED_PROPERTIES {
            if self.system_properties.contains_key(key) {
                continue;
            }
            if let Some(value) = crate::properties::os_detected(
                key,
                self.user_or_system_property("os.name"),
                self.user_or_system_property("os.arch"),
            ) {
                properties.insert(key.to_string(), value);
            }
        }
        properties
    }

    /// This context as Maven 3.10 activates the profiles of a model it reads
    /// from a repository with: no user or settings.xml profile property,
    /// and `own`, the POM's `<properties>`, below the system properties. A
    /// property the JVM, the Maven launcher or the environment always sets
    /// keeps its value, an `env.*` one while the variable is set; others,
    /// such as `jdk.version`, are the POM's. `mvn`
    /// copies each `-D` into the system properties, so it still counts, but
    /// the `packaging` the model builder adds does not.
    fn external_activation(&self, own: &crate::PropertyMap) -> Self {
        // A JVM that sets an unevenly set name keeps its value over the POM's,
        // so the POM's decides nothing.
        let set_by_host = |name: &str| {
            name.starts_with("env.")
                || always_set(name, self)
                || jvm_names::class(name, self.environment.maven_mode())
                    == Some(jvm_names::Class::Uneven)
        };
        let mut system_properties: HashMap<String, String> = (own.iter())
            .filter(|(name, _)| !set_by_host(name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let repository_env = (own.iter())
            .filter(|(name, _)| name.starts_with("env."))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        system_properties.extend(self.system_properties.clone());
        system_properties.extend(
            (self.properties.iter())
                .filter(|(name, _)| !self.packaging_injected || *name != "packaging")
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        let mut system_defines = self.system_defines.clone();
        system_defines.extend(self.properties.keys().cloned());
        Self {
            properties: HashMap::new(),
            settings_properties: crate::PropertyMap::new(),
            settings_repositories: Vec::new(),
            system_properties,
            system_defines,
            repository_env,
            ..self.clone()
        }
    }

    /// The environment a model of this context is interpolated in: without
    /// classifier likes when [`Self::system_properties`] sets
    /// `os.detected.classifier`, which a dependency's model then reads as
    /// it is, and [`ModelEnvironment::restricted`] when this context
    /// [`Self::restricts_interpolation`].
    pub(crate) fn model_environment(&self) -> ModelEnvironment {
        let environment = if self
            .system_properties
            .contains_key("os.detected.classifier")
        {
            self.environment.with_classifier_likes(None)
        } else {
            self.environment.clone()
        };
        match self.restricts_interpolation() {
            true => environment.restricted(),
            false => environment,
        }
    }
}

/// A `<property>` activation condition.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivationProperty {
    /// The property name. A leading `!` activates when the property is
    /// absent or empty. An `env.` prefix reads an environment variable, and
    /// one outside the `${env.*}` allowlist reads as absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The value to compare with exactly; a leading `!` negates the
    /// comparison. Without a value, any non-empty value activates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// An `<os>` activation condition, compared case-insensitively with the
/// target platform's `os.*` properties. A value may start with `!` to
/// negate it, except a `regex:` version.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivationOs {
    /// The `os.name` to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A Maven OS family such as `windows`, `unix` or `mac`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// The `os.arch` to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// The `os.version` to match, or a `regex:` pattern. raeva does not know
    /// the host's `os.version`, so only a `-D` or system property value
    /// can match it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A `<file>` activation condition, tested against the filesystem when a
/// profile is evaluated.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivationFile {
    /// A path that must exist. When non-empty, [`Self::missing`] is ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exists: Option<String>,
    /// A path that must not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
}

/// A profile's `<activation>` block. Activation by its conditions needs
/// every explicit condition it holds to match.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Activation {
    /// `<activeByDefault>`: active when no other profile of the same POM is
    /// selected or activated by a condition.
    #[serde(
        default,
        deserialize_with = "maven_boolean",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub active_by_default: bool,
    /// The `<property>` condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<ActivationProperty>,
    /// The `<os>` condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<ActivationOs>,
    /// The `<jdk>` condition: a `java.version` prefix, `!` and a prefix
    /// that must not match, or a range such as `[17,)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jdk: Option<String>,
    /// The `<file>` condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<ActivationFile>,
    /// Whether host or user-property values contributed to the condition text.
    /// The text stays out of recorded conditions when it can contain those values.
    #[serde(skip)]
    pub(crate) jdk_from_input: bool,
    #[serde(skip)]
    pub(crate) property_from_input: bool,
    /// Expected-value provenance must not hide a separate lookup of the tested name.
    #[serde(skip)]
    pub(crate) property_name_from_input: bool,
    /// Whether interpolation put a host value into the `<file>` path. Such
    /// a path is not recorded, since it holds that value.
    #[serde(skip)]
    pub(crate) path_from_host: bool,
    #[serde(skip)]
    pub(crate) interpolation_reads: ConditionReads,
}

/// The host values interpolation read, per condition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConditionReads {
    pub(crate) os: BTreeSet<HostInput>,
    pub(crate) file: BTreeSet<HostInput>,
    pub(crate) jdk: BTreeSet<HostInput>,
    pub(crate) property: BTreeSet<HostInput>,
    /// Whether interpolating the os, file, jdk and property condition read
    /// `java.version`, though the reads above may keep only a lookup.
    pub(crate) java: [bool; 4],
}

impl Activation {
    /// A property the JVM or the launcher sets whose value raeva does not
    /// know, such as `os.version`, or `java.vendor` where the JDK's
    /// `release` file does not tell it, when this interpolated
    /// activation tests its value, reads it through `${...}`, or tests the
    /// presence of one only some JDKs set: no `-D` sets it and the other
    /// conditions do not already keep the profile off.
    pub fn unread_host_property(&self, ctx: &ActivationContext) -> Option<String> {
        // A `-D`, a settings.xml property or, for a dependency's model, a
        // user property passed as a system property: its value is the
        // build's own. A `.mvn/jvm.config` value of a JVM-owned name is not.
        let jvm_config = ctx.environment.system_properties();
        let jvm_config_only = |name: &str| {
            jvm_config.contains_key(name)
                && !ctx.system_defines.contains(name)
                && ctx.system_properties.get(name) == jvm_config.get(name)
                && !ctx.properties.contains_key(name)
                && ctx.settings_properties.get(name).is_none()
        };
        let user_set = |name: &str| {
            ctx.properties.contains_key(name)
                || ctx.settings_properties.get(name).is_some()
                || (ctx.system_properties.contains_key(name) && !jvm_config_only(name))
        };
        // `java.home` and the `java.version` family are host inputs of
        // their own, which a read here would record. Without a JDK,
        // `${java.home}` stays as written, and the lock records what a path
        // holding it tested.
        let windows = ctx
            .environment
            .platform()
            .is_some_and(|(os, _)| os == "windows");
        let target_jdk = ctx
            .environment
            .target_jdk()
            .filter(|_| !user_set("java.version"));
        let host_java_home = ctx.environment.host_java_home().is_some();
        let answered_on_every_edition = self
            .answer_on_every_windows_edition(ctx, &ctx.environment.detached())
            .is_some();
        let unread_value = |name: &str| {
            // A JVM option may set it in a way raeva does not read.
            ctx.environment.unread_system_property(name)
                || match name {
                    // Unknown for a `[lock] jdks` JDK other than the host's.
                    "java.home" | "env.JAVA_HOME" => {
                        ctx.environment.target_jdk().is_some() && !host_java_home
                    }
                    // The target platform and JDK answer these, but Windows
                    // JVMs each report their own `os.name`, and the patch
                    // releases of a `[lock] jdks` entry their own `java.version`.
                    "os.name" => windows && !answered_on_every_edition,
                    "java.version" => target_jdk.is_some(),
                    "os.arch"
                    | "file.separator"
                    | "path.separator"
                    | "line.separator"
                    | "java.specification.version" => false,
                    _ => host_property(&ctx.environment, name) == Some(HostProperty::Unread),
                }
        };
        let unread_path = |name: &str| {
            let hidden =
                || (name.strip_prefix("env.")).is_some_and(|var| ctx.environment.hides_env(var));
            (unread_value(name) || hidden()) && !user_set(name)
        };
        // The launcher's directory, which the lock records what a path
        // holding it tested, but not what a `<property>` condition on it
        // compared.
        let launcher = |name: &str| {
            matches!(
                name,
                "maven.multiModuleProjectDirectory" | LAUNCHER_ROOT_VARIABLE
            ) && always_set(name, ctx)
                && !user_set(name)
        };
        let unread = |name: &str| unread_path(name) || launcher(name);
        // A `<property>` test of the host JDK's vendor, which the lock
        // records with its outcome, though `${java.vendor}` stays unread.
        let vendor_known = |name: &str| {
            name == "java.vendor"
                && ctx.environment.host_java_vendor().is_some()
                && !ctx.environment.unread_system_property(name)
                && !jvm_config.contains_key(name)
        };
        let in_text = |text: &Option<String>, unread: &dyn Fn(&str) -> bool| {
            (crate::properties::expression_names(text.as_deref()?).into_iter())
                .find(|read| unread(read))
                .map(str::to_string)
        };
        // Maven 3.9.12 and 3.10.0 interpolate every kind of condition with
        // all system properties, so text still holding one of these after
        // interpolation would be compared as written where Maven compares
        // the host's value. Condition interpolation leaves `java.home` out,
        // as model interpolation does, except in a `<file>` path.
        let unread_text = |name: &str| unread(name) || name == "java.home";
        let target_jdk = ctx
            .environment
            .target_jdk()
            .filter(|_| !user_set("java.version"));
        let mut others = self.clone();
        let mut found = None;
        if let Some(property) = &self.property {
            let (_, name) = negation(property.name.as_deref().unwrap_or_default());
            let valued = (property.value.as_deref()).is_some_and(|value| !value.is_empty());
            let decided = (property.value.as_deref())
                .is_some_and(|value| !could_be_host_value(name, negation(value).1));
            // A test every patch release of a `[lock] jdks` entry answers
            // alike, such as `!1.8`.
            let same_on_every_patch = name == "java.version"
                && target_jdk.is_some_and(|entry| {
                    (property.value.as_deref())
                        .filter(|value| !value.is_empty())
                        .is_none_or(|value| {
                            equal_on_every_patch(entry, negation(value).1).is_some()
                        })
                });
            let unread_name = match hidden_value_decides_nothing(property, ctx) {
                true => unread_value(name) && !user_set(name),
                false => unread(name) && !vendor_known(name),
            };
            // A presence test holds only where every JVM sets the name.
            let tested = (unread_name
                && !decided
                && !same_on_every_patch
                && (valued || !set_on_every_run(name, ctx.environment.maven_mode())))
            .then(|| name.to_string());
            // The compared value can hold one too: a `-D` value `MavenCli`
            // expands, or a settings.xml property its builder expands, that
            // still reads `${java.vendor}`. Any value passes a presence test.
            let compared = (valued && !name.contains("${"))
                .then(|| ctx.expanded_value(name))
                .flatten()
                .and_then(|value| unread_host_reference(value, &ctx.environment));
            // A name no one sets keeps the profile off, or with a negated
            // value on, whatever the value reads.
            let unset = !name.contains("${")
                && !name.starts_with("env.")
                && !ctx.properties.contains_key(name)
                && ctx.settings_properties.get(name).is_none()
                && !ctx.system_properties.contains_key(name)
                && !always_set(name, ctx)
                && !jvm_owned(name)
                && !SYSTEM_PROPERTY_NAMES.contains(&name);
            found = tested
                .or(compared)
                .or_else(|| in_text(&property.name, &unread_text))
                .or_else(|| {
                    (!unset)
                        .then(|| in_text(&property.value, &unread_text))
                        .flatten()
                });
            if found.is_some() {
                others.property = None;
            }
        }
        if let (Some(os), Some(stripped)) = (&self.os, &mut others.os) {
            for (field, text) in [
                (&mut stripped.family, &os.family),
                (&mut stripped.name, &os.name),
                (&mut stripped.arch, &os.arch),
                (&mut stripped.version, &os.version),
            ] {
                if let Some(name) = in_text(text, &unread_text) {
                    found.get_or_insert(name);
                    *field = None;
                }
            }
            // Windows 10, 11 and Server JVMs each report their own `os.name`;
            // `<family>` and `<arch>` hold on all of them.
            if (os.name.as_deref()).is_some_and(|name| is_windows_name(negation(name).1))
                && unread("os.name")
            {
                found.get_or_insert_with(|| "os.name".to_string());
                stripped.name = None;
            }
            // The OS activator reads no settings.xml profile property.
            if os.version.is_some() && ctx.user_or_system_property("os.version").is_none() {
                found.get_or_insert_with(|| "os.version".to_string());
                stripped.version = None;
            }
            if [
                &stripped.family,
                &stripped.name,
                &stripped.arch,
                &stripped.version,
            ]
            .iter()
            .all(|field| field.is_none())
            {
                others.os = None;
            }
        }
        if let Some(name) = in_text(&self.jdk, &unread_text) {
            found.get_or_insert(name);
            others.jdk = None;
        }
        // A `<jdk>` every patch release of a `[lock] jdks` entry answers
        // alike, such as `21` or `[17,22)`, holds; `21.0.13` does not.
        if let (Some(jdk), Some(feature)) = (&self.jdk, target_jdk)
            && !jdk.contains("${")
            && jdk.is_ascii()
            && jdk_on_every_patch(feature, jdk).is_none()
        {
            found.get_or_insert_with(|| "java.version".to_string());
            others.jdk = None;
        }
        // Maven tests `<missing>` only when `<exists>` is empty.
        let tested_file = self.file.as_ref().and_then(|condition| {
            match condition.exists.as_deref().filter(|path| !path.is_empty()) {
                Some(_) => in_text(&condition.exists, &unread_path),
                None => in_text(&condition.missing, &unread_path),
            }
        });
        if let Some(name) = tested_file {
            found.get_or_insert(name);
            others.file = None;
        }
        let name = found?;
        let conditions = [
            others.property.is_some(),
            others.os.is_some(),
            others.jdk.is_some(),
        ];
        let decided = (conditions.contains(&true) || others.file.is_some())
            && !others
                .explicit_conditions_active(ctx, &ctx.environment.detached())
                .unwrap_or(true);
        (!decided).then_some(name)
    }

    /// Returns whether this single `<activation>` block matches the runtime
    /// context, **without** Maven's POM-level suppression rule.
    ///
    /// Per the Maven Profile spec, an `<activeByDefault>true</activeByDefault>`
    /// profile is suppressed when ANY other profile in the same POM activates
    /// by an explicit condition (property/os/jdk/file) or by command-line
    /// selection. That decision can only be made at POM scope because it
    /// depends on the other profiles. This method does NOT apply the
    /// suppression; it answers the local question "does this block, in
    /// isolation, request activation?".
    ///
    /// Use `select_profiles` for the cross-profile, suppression-aware
    /// answer when computing the active profile set for an effective POM.
    pub fn is_active(&self, ctx: &ActivationContext) -> bool {
        // `<activeByDefault>true</activeByDefault>` activates the profile in
        // isolation. POM-level suppression lives in `select_profiles`.
        if self.active_by_default {
            return true;
        }

        self.explicit_conditions_active(ctx, &ctx.environment)
            .unwrap_or(false)
    }

    /// Whether the explicit conditions match, as [`Self::is_active`] decides
    /// them without `<activeByDefault>`, and the host values and files they
    /// tested that decide it, or the error Maven fails the profile `id`
    /// with. Nothing is recorded in `ctx`'s environment.
    pub fn evaluate(
        &self,
        id: &str,
        ctx: &ActivationContext,
    ) -> Result<(bool, BTreeSet<HostInput>), PomError> {
        let recorder = ctx.environment.detached();
        let active = self
            .explicit_conditions_active(ctx, &recorder)
            .map_err(|error| error.into_pom_error(id))?;
        Ok((active, recorder.take_reads()))
    }

    /// Maven's `DefaultProfileSelector.isActive`: whether every explicit
    /// condition (jdk / os / property / file) matches, without the
    /// `activeByDefault` short-circuit. A block with no explicit condition
    /// is not active. Each condition is evaluated, as Maven evaluates every
    /// activator, so a condition Maven reports as a model error fails even
    /// when another one does not match.
    ///
    /// The host values and files the conditions test are recorded in
    /// `recorder`, up to the first condition that does not match: the ones
    /// after it cannot change the outcome while it stays false. `<os>`
    /// depends only on the target platform, so it is tested first, then the
    /// project's files, then the host.
    fn explicit_conditions_active(
        &self,
        ctx: &ActivationContext,
        recorder: &ModelEnvironment,
    ) -> Result<bool, ActivationError> {
        if self.property.is_none() && self.os.is_none() && self.jdk.is_none() && self.file.is_none()
        {
            return Ok(false);
        }
        if let Some(answer) = self.answer_on_every_windows_edition(ctx, recorder) {
            return Ok(answer);
        }
        let mut active = true;
        let mut test =
            |(interpolation, java): (&BTreeSet<HostInput>, bool),
             condition: &dyn Fn(&ModelEnvironment) -> Result<bool, ActivationError>| {
                // The condition's own reads reach `recorder` only while the
                // conditions before it hold, so its `java.version` read
                // counts only then too.
                let reads = recorder.detached_apart();
                let holds = condition(&reads)?;
                if active {
                    for input in reads.take_reads().into_iter().chain(interpolation.clone()) {
                        recorder.record(input);
                    }
                    if java {
                        recorder.record_java_lookup();
                    }
                }
                active &= holds;
                Ok::<_, ActivationError>(())
            };
        let interpolation = &self.interpolation_reads;
        let [os_java, file_java, jdk_java, property_java] = interpolation.java;
        if let Some(os) = &self.os {
            test((&interpolation.os, os_java), &|reads| {
                os_active(os, ctx, reads)
            })?;
        }
        if let Some(file) = &self.file {
            test((&interpolation.file, file_java), &|reads| {
                Ok(file_active(file, self.path_from_host, ctx, reads))
            })?;
        }
        if let Some(jdk) = &self.jdk {
            if (jdk.starts_with('[') || jdk.starts_with('(')) && !jdk.is_ascii() {
                return Err(ActivationError::NonAsciiJdkRange(jdk.clone()));
            }
            test((&interpolation.jdk, jdk_java), &|reads| {
                Ok(jdk_active(jdk, self.jdk_from_input, ctx, reads))
            })?;
        }
        if let Some(property) = &self.property {
            test((&interpolation.property, property_java), &|reads| {
                property_active(
                    property,
                    self.property_from_input,
                    self.property_name_from_input,
                    ctx,
                    reads,
                )
            })?;
        }
        Ok(active)
    }

    /// The answer this activation gives on every Windows edition, where
    /// the platform is Windows, the activation reads `os.name`, which each
    /// edition's JVM reports its own of ([`WINDOWS_OS_NAMES`]), no `-D` or
    /// settings.xml property sets it, and the editions agree. `None` where
    /// they differ, or the rule does not apply. Each edition's reads go to
    /// `recorder`.
    fn answer_on_every_windows_edition(
        &self,
        ctx: &ActivationContext,
        recorder: &ModelEnvironment,
    ) -> Option<bool> {
        let windows = (ctx.environment.platform()).is_some_and(|(os, _)| os == "windows");
        let set = ctx.properties.contains_key("os.name")
            || ctx.system_properties.contains_key("os.name")
            || ctx.settings_properties.get("os.name").is_some();
        if !windows || set || ctx.environment.windows_os_name().is_some() {
            return None;
        }
        let property_name = (self.property.as_ref())
            .and_then(|property| property.name.as_deref())
            .is_some_and(|name| negation(name).1 == "os.name");
        let os_name = (self.os.as_ref()).is_some_and(|os| os.name.is_some());
        let mut texts = self.texts();
        let in_text =
            texts.any(|text| crate::properties::expression_names(text).contains(&"os.name"));
        if !(property_name || os_name || in_text) {
            return None;
        }
        let mut answer = None;
        for name in WINDOWS_OS_NAMES {
            let mut edition = ctx.clone();
            edition.environment = ctx.environment.with_windows_os_name(name);
            let activation = self.with_windows_os_name(name, &edition);
            let active = activation
                .explicit_conditions_active(&edition, recorder)
                .ok()?;
            if *answer.get_or_insert(active) != active {
                return None;
            }
        }
        answer
    }

    /// The text of each condition.
    fn texts(&self) -> impl Iterator<Item = &str> {
        let property = (self.property.iter()).flat_map(|p| [&p.name, &p.value]);
        let os = (self.os.iter()).flat_map(|os| [&os.name, &os.family, &os.arch, &os.version]);
        let file = (self.file.iter()).flat_map(|f| [&f.exists, &f.missing]);
        (std::iter::once(&self.jdk)
            .chain(property)
            .chain(os)
            .chain(file))
        .flatten()
        .map(String::as_str)
    }

    /// This activation with `${os.name}` in its text as the Windows edition
    /// `name`'s JVM expands it, and a relative `<file>` path that then
    /// holds no reference aligned to the project directory, as Maven aligns
    /// one.
    fn with_windows_os_name(&self, name: &str, ctx: &ActivationContext) -> Self {
        let mut activation = self.clone();
        let property = (activation.property.iter_mut()).flat_map(|p| [&mut p.name, &mut p.value]);
        let os = (activation.os.iter_mut())
            .flat_map(|os| [&mut os.name, &mut os.family, &mut os.arch, &mut os.version]);
        for text in property.chain(os).chain([&mut activation.jdk]).flatten() {
            *text = with_os_name(text, name);
        }
        let file = (activation.file.iter_mut()).flat_map(|f| [&mut f.exists, &mut f.missing]);
        for path in file.flatten() {
            if !crate::properties::expression_names(path).contains(&"os.name") {
                continue;
            }
            *path = with_os_name(path, name);
            if let Some(base) = &ctx.base_dir
                && !path.contains("${")
                && !Path::new(path.as_str()).is_absolute()
            {
                *path =
                    crate::project::profiles::align_to_base_directory(path, base, &ctx.environment);
            }
        }
        activation
    }

    /// This settings.xml activation with the system properties raeva
    /// answers on `ctx`'s platform and JDK expanded in its `<property>`,
    /// `<os>` and `<jdk>` text, which Maven expands with the rest of
    /// settings.xml. The `<file>` path expands apart, on the host.
    #[must_use]
    pub fn with_host_properties(mut self, ctx: &ActivationContext) -> Self {
        let property = (self.property.iter_mut()).flat_map(|p| [&mut p.name, &mut p.value]);
        let os = (self.os.iter_mut())
            .flat_map(|os| [&mut os.name, &mut os.family, &mut os.arch, &mut os.version]);
        for text in property.chain(os).chain([&mut self.jdk]).flatten() {
            *text = expand_host_properties(text, &ctx.environment);
        }
        self
    }

    /// This activation of a profile from outside the POM, such as a
    /// settings.xml profile, with its `<file>` path expanded and aligned to
    /// `ctx`'s base directory as Maven does before testing it. The other
    /// conditions are tested as written.
    #[must_use]
    pub fn with_external_file(mut self, ctx: &ActivationContext) -> Self {
        if let Some(file) = &mut self.file {
            crate::project::profiles::interpolate_external_file(file, ctx);
        }
        self
    }
}

#[derive(Debug)]
pub(crate) struct ProfileSelection {
    pub(crate) active: Vec<usize>,
    /// For each profile, the host values its activation read: the
    /// conditions it tested and the values interpolating them read.
    pub(crate) reads: Vec<BTreeSet<HostInput>>,
    /// For each profile, whether its activation read `java.version`, also
    /// through a lookup that keeps only the expression.
    pub(crate) reads_java: Vec<bool>,
    /// For each profile, the property its activation tests that raeva does
    /// not read from the host, if any.
    pub(crate) unread: Vec<Option<String>>,
    /// For each profile, whether `-P` or its conditions activated it, or
    /// `None` when it was left out of the selection.
    selected: Vec<Option<bool>>,
}

impl ProfileSelection {
    /// Whether host values decide whether profile `index` is active: its
    /// own conditions read one, or it is an `activeByDefault` profile and a
    /// condition of the POM read one, which decides whether the default
    /// applies.
    pub(crate) fn host_decides(&self, profiles: &[crate::Profile], index: usize) -> bool {
        // User-property values are hashed separately; their names do not make a profile host-specific.
        let reads_host = |reads: &BTreeSet<HostInput>| reads.iter().any(HostInput::is_host_read);
        reads_host(&self.reads[index])
            || (is_active_by_default(&profiles[index]) && self.reads.iter().any(reads_host))
    }

    /// A profile whose activation tests a value raeva does not read, and
    /// that value, when that decides which of the profiles `relevant` marks
    /// Maven activates. Once another profile is activated, the defaults are
    /// off whatever such a condition gives, so only a relevant profile with
    /// one decides. Otherwise any of them can turn the defaults off; the
    /// one exception is an `activeByDefault` profile that is the only
    /// relevant default and the only one with such a condition, which is
    /// active whether that condition holds or not.
    pub(crate) fn undecided(
        &self,
        profiles: &[crate::Profile],
        relevant: &[bool],
    ) -> Option<(usize, &str)> {
        let unknown: Vec<usize> = (0..profiles.len())
            .filter(|&index| self.unread[index].is_some())
            .collect();
        let activated = (0..profiles.len())
            .any(|index| self.unread[index].is_none() && self.selected[index] == Some(true));
        let deciding = if activated {
            unknown.iter().copied().find(|&index| relevant[index])
        } else {
            let defaults: Vec<usize> = (0..profiles.len())
                .filter(|&index| {
                    relevant[index]
                        && self.selected[index].is_some()
                        && is_active_by_default(&profiles[index])
                })
                .collect();
            let decided = (defaults.is_empty() && !unknown.iter().any(|&index| relevant[index]))
                || (unknown.len() == 1 && defaults == unknown);
            unknown.first().copied().filter(|_| !decided)
        };
        deciding.and_then(|index| Some((index, self.unread[index].as_deref()?)))
    }
}

/// A boolean element as Maven's reader takes it, with `Boolean.valueOf` on
/// the trimmed text: `true` in any case, and anything else is false.
fn maven_boolean<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    let text = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
    Ok(text.is_some_and(|text| text.trim_matches(|c| c <= ' ').eq_ignore_ascii_case("true")))
}

pub(crate) fn is_active_by_default(profile: &crate::Profile) -> bool {
    profile
        .activation
        .as_ref()
        .is_some_and(|activation| activation.active_by_default)
}

/// Maven's `DefaultProfileSelector.getActiveProfiles` for the profiles of
/// one POM: the profiles selected with `-P` or whose conditions match, in
/// declaration order, or, when none is, the `activeByDefault` ones. `-P!`
/// deselects a profile either way.
///
/// Maven selects the profiles of each POM in a parent chain on its own, so a
/// profile activating in a child does not suppress a default profile of its
/// parent; callers pass one POM's profiles at a time.
///
/// Nothing is recorded in `ctx`'s environment: the caller decides which
/// profiles' host reads count.
///
/// Maven 3.10 selects the profiles of a model it reads from a repository
/// apart: it leaves out every profile with a `<file>` condition, and the
/// conditions see no user property, with `own`, the POM's `<properties>`
/// as written, below the system properties.
pub(crate) fn select_profiles(
    profiles: &[crate::Profile],
    own: &crate::PropertyMap,
    ctx: &ActivationContext,
) -> Result<ProfileSelection, PomError> {
    use std::collections::HashSet;

    let external = ctx.repository_model().then(|| ctx.external_activation(own));
    let ctx = external.as_ref().unwrap_or(ctx);

    let explicit_active: HashSet<&str> = ctx.active_profiles.iter().map(String::as_str).collect();
    let explicit_inactive: HashSet<&str> =
        ctx.inactive_profiles.iter().map(String::as_str).collect();

    let mut activated = Vec::new();
    let mut defaults = Vec::new();
    let mut selection = Vec::with_capacity(profiles.len());
    let mut reads = Vec::with_capacity(profiles.len());
    let mut reads_java = Vec::with_capacity(profiles.len());
    let mut unread = Vec::with_capacity(profiles.len());
    for (index, profile) in profiles.iter().enumerate() {
        let id = profile.id.as_str();
        let mut read = BTreeSet::new();
        let java_read = Arc::new(AtomicBool::new(false));
        let file =
            (profile.activation.as_ref()).is_some_and(|activation| activation.file.is_some());
        if explicit_inactive.contains(id) || (external.is_some() && file) {
            reads.push(read);
            reads_java.push(false);
            unread.push(None);
            selection.push(None);
            continue;
        }
        let selected = explicit_active.contains(id)
            || match &profile.activation {
                Some(activation) => {
                    let recorder = ctx.environment.selection(&java_read);
                    let active = activation
                        .explicit_conditions_active(ctx, &recorder)
                        .map_err(|error| error.into_pom_error(id))?;
                    read = recorder.take_reads();
                    active
                }
                None => false,
            };
        reads.push(read);
        reads_java.push(java_read.load(Ordering::Relaxed));
        unread.push(
            (profile.activation.as_ref())
                .filter(|_| !explicit_active.contains(id))
                .and_then(|activation| activation.unread_host_property(ctx)),
        );
        selection.push(Some(selected));
        if selected {
            activated.push(index);
        } else if is_active_by_default(profile) {
            defaults.push(index);
        }
    }
    Ok(ProfileSelection {
        active: if activated.is_empty() {
            defaults
        } else {
            activated
        },
        reads,
        reads_java,
        unread,
        selected: selection,
    })
}

/// [`select_profiles`], with every host read recorded.
#[cfg(test)]
pub(crate) fn evaluate_profiles<'a>(
    profiles: &'a [crate::Profile],
    ctx: &ActivationContext,
) -> Result<Vec<&'a crate::Profile>, PomError> {
    let selection = select_profiles(profiles, &crate::PropertyMap::new(), ctx)?;
    for input in selection.reads.into_iter().flatten() {
        ctx.environment.record(input);
    }
    Ok(selection
        .active
        .into_iter()
        .map(|index| &profiles[index])
        .collect())
}

/// A condition Maven reports as a model error, which fails the build.
#[derive(Debug)]
enum ActivationError {
    PropertyNameRequired,
    Regex(String),
    RegexTooLong {
        length: usize,
    },
    UnsupportedRegex {
        construct: String,
        why: &'static str,
    },
    /// A `<jdk>` range with a character that is not ASCII, held here.
    NonAsciiJdkRange(String),
}

impl ActivationError {
    fn into_pom_error(self, id: &str) -> PomError {
        PomError::InvalidModel(match self {
            ActivationError::PropertyNameRequired => format!(
                "The property name is required to activate the profile {}",
                bounded(id)
            ),
            ActivationError::Regex(error) => format!(
                "Failed to determine activation for profile {}: {}",
                bounded(id),
                bounded(&error)
            ),
            ActivationError::RegexTooLong { length } => format!(
                "Failed to determine activation for profile {}: regex: the pattern has {length} \
                 characters, more than the {MAX_REGEX_LENGTH} raeva compiles",
                bounded(id)
            ),
            ActivationError::UnsupportedRegex { construct, why } => format!(
                "Failed to determine activation for profile {}: regex: {} is not supported, {why}",
                bounded(id),
                bounded(&construct)
            ),
            // `Integer.parseInt` reads the bounds, and takes the decimal
            // digits of the JDK's Unicode version.
            ActivationError::NonAsciiJdkRange(range) => {
                return PomError::Unlockable(format!(
                    "the <jdk> range {} of profile {} holds a character that is not ASCII; \
                     Maven parses its bounds with Java's Integer.parseInt, which takes other \
                     decimal digits, such as U+FF12 for 2, and more of them on newer JDKs, so \
                     raeva cannot tell where the profile is active; write the bounds in ASCII",
                    bounded(&range),
                    bounded(id)
                ));
            }
        })
    }
}

/// Maven's `PropertyProfileActivator`, on values the POM reader already
/// trimmed: one leading `!` on the name negates presence, a non-empty
/// `<value>` with its own leading `!` is compared exactly, and a present
/// value is any non-empty one.
fn property_active(
    property: &ActivationProperty,
    text_from_input: bool,
    name_from_input: bool,
    ctx: &ActivationContext,
    recorder: &ModelEnvironment,
) -> Result<bool, ActivationError> {
    let name = property.name.as_deref().unwrap_or_default();
    let (_, name) = negation(name);
    if name.is_empty() {
        return Err(ActivationError::PropertyNameRequired);
    }

    if !name_from_input {
        recorder.record_user_property(name);
    }
    if !name_from_input
        && ctx.settings_property_names.contains(name)
        && !ctx.properties.contains_key(name)
    {
        recorder.record(HostInput::SettingsProperty(name.to_string()));
    }

    // A user property, then an active settings.xml profile property, then a
    // system property, of any name comes first, `env.*` included: Maven
    // keeps the environment in its system properties as `env.*` entries,
    // below the `-D` and settings profile values.
    let value = property.value.as_deref().filter(|value| !value.is_empty());
    let specification;
    let (actual, host_input) = if let Some(value) = ctx.properties.get(name) {
        (Some(value.as_str()), None)
    } else if let Some(value) = ctx.settings_properties.get(name) {
        (Some(value.as_str()), None)
    } else if let Some(value) = ctx.system_properties.get(name) {
        (Some(value.as_str()), None)
    } else if let Some(key) = name.strip_prefix("env.") {
        // Supply-chain hardening: a variable outside the `${env.*}`
        // allowlist, the same gate interpolation applies, reads as absent,
        // so a transitive POM cannot key a profile off a host secret.
        let allowed = ctx.environment.allows_env(key);
        if !allowed {
            ctx.environment.warn_hidden_env(key);
        }
        // Unset, the variable gives way to the model's own value, so the
        // outcome follows the variable's value rather than the condition.
        match ctx.repository_env.get(name) {
            Some(own) => {
                if allowed && !name_from_input {
                    recorder.record(HostInput::Env(key.to_string()));
                }
                let value = ctx.environment.host_env_var(key).or(Some(own.as_str()));
                (value, None)
            }
            None => {
                let input = allowed.then(|| HostInput::Env(key.to_string()));
                (ctx.environment.host_env_var(key), input)
            }
        }
    } else {
        match name {
            "java.version" => (
                Some(tested_java_version(
                    ctx.environment.host_java_version(),
                    &ctx.environment,
                )),
                Some(HostInput::JavaVersion),
            ),
            // Every JVM sets it, so a presence test holds without a JDK too.
            "java.home" => (
                (ctx.environment.host_java_home()).or(value.is_none().then_some("set")),
                Some(HostInput::JavaHome),
            ),
            "java.specification.version" => {
                specification = java_specification_version(ctx.environment.host_java_version());
                (Some(specification), Some(HostInput::JavaVersion))
            }
            // Unknown, a value test of it refuses in `unread_host_property`,
            // and a presence test holds on every JVM.
            "java.vendor" if value.is_some() && ctx.environment.host_java_vendor().is_some() => (
                ctx.environment.host_java_vendor(),
                Some(HostInput::JavaVendor),
            ),
            // The JVM or the launcher sets these on every host, so a presence
            // check holds. A value test of one raeva does not know refuses
            // the lock in `unread_host_property`.
            _ => match ctx.property(name) {
                None if value.is_none() && always_set(name, ctx) => (Some("set"), None),
                actual => (actual, None),
            },
        }
    };
    let raw_name = property.name.as_deref().unwrap_or_default();
    if let Some(input) = host_input.filter(|_| !name_from_input) {
        recorder.record(if text_from_input {
            input
        } else {
            HostInput::Property {
                name: raw_name.to_string(),
                value: value.map(str::to_string),
            }
        });
    }
    Ok(property_matches(raw_name, value, actual))
}

/// Whether the valued `<property>` test `property` of a hidden variable,
/// `env.NAME`, gives the outcome with the variable's value that it gives
/// with the variable unset, as [`property_active`] reads it: then the value
/// decides nothing, and activation goes on as where it is unset. A presence
/// test of a set variable can differ, and the value of one `mvn` sets
/// itself is unknown.
fn hidden_value_decides_nothing(property: &ActivationProperty, ctx: &ActivationContext) -> bool {
    let raw_name = property.name.as_deref().unwrap_or_default();
    let (_, name) = negation(raw_name);
    let value = property.value.as_deref().filter(|value| !value.is_empty());
    let Some(actual) = (value.and(name.strip_prefix("env.")))
        .and_then(|variable| ctx.environment.hidden_env_value(variable))
    else {
        return false;
    };
    let unset = ctx.repository_env.get(name).map(String::as_str);
    property_matches(raw_name, value, Some(actual)) == property_matches(raw_name, value, unset)
}

/// Whether `value` can be what Maven's launcher passes for `name`: 3.10.0's
/// `library.jline.path` is always the Maven home's `lib/jline-native`, so a
/// value test against other text is decided whatever the home is.
fn could_be_host_value(name: &str, value: &str) -> bool {
    match name {
        "library.jline.path" => {
            value.ends_with("/lib/jline-native") || value.ends_with("\\lib\\jline-native")
        }
        // Every Windows JVM's `os.name` starts with `Windows`.
        "os.name" => is_windows_name(value),
        _ => true,
    }
}

fn is_windows_name(value: &str) -> bool {
    (value.get(..7)).is_some_and(|start| start.eq_ignore_ascii_case("windows"))
}

/// Whether the JVM or the Maven launcher of `ctx`'s line sets the system
/// property `name` on every run.
/// `text` with each `${os.name}`, in any spelling Maven reads it by, as
/// `value`.
fn with_os_name(text: &str, value: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        out.push_str(&rest[..start]);
        if rv_maven_types::expression_key(&after[..end]) == "os.name" {
            out.push_str(value);
        } else {
            out.push_str(&rest[start..start + 3 + end]);
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn always_set(name: &str, ctx: &ActivationContext) -> bool {
    set_on_every_run(name, ctx.environment.maven_mode())
}

/// Whether every JVM and the Maven launcher of `mode` set the system
/// property `name` on every run.
fn set_on_every_run(name: &str, mode: MavenMode) -> bool {
    name == LAUNCHER_ROOT_VARIABLE
        || matches!(
            jvm_names::class(name, mode),
            Some(jvm_names::Class::Locked | jvm_names::Class::Fixed(_) | jvm_names::Class::PerHost)
        )
}

/// The variable `mvn` exports as `maven.multiModuleProjectDirectory`.
const LAUNCHER_ROOT_VARIABLE: &str = "env.MAVEN_PROJECTBASEDIR";

/// The JVM's `java.specification.version` for its `java.version`: `1.8`
/// for `1.8.0_442`, the feature release from Java 9 on.
pub(crate) fn java_specification_version(java_version: &str) -> &str {
    let digits = |text: &str| {
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len())
    };
    match java_version.strip_prefix("1.") {
        Some(rest) => &java_version[..2 + digits(rest)],
        None => &java_version[..digits(java_version)],
    }
}

pub(crate) fn property_matches(name: &str, value: Option<&str>, actual: Option<&str>) -> bool {
    let (reverse_name, _) = negation(name);
    match value {
        Some(expected) => {
            let (reverse_value, expected) = negation(expected);
            (actual == Some(expected)) != reverse_value
        }
        None => actual.is_some_and(|value| !value.is_empty()) != reverse_name,
    }
}

/// Match Maven 3.9's `OperatingSystemProfileActivator`. It lowercases the
/// expected and actual values before comparing, strips one leading `!` after
/// that, and reads the actual values from the system properties, so a `-D`
/// override of `os.name`, `os.arch` or `os.version` applies here too. An empty
/// `<os/>` never activates. The values are the POM reader's trimmed text,
/// interpolated and not trimmed again. `<version>` is only tested, and a bad
/// `regex:` only reported, when the other conditions matched.
fn os_active(
    os: &ActivationOs,
    ctx: &ActivationContext,
    recorder: &ModelEnvironment,
) -> Result<bool, ActivationError> {
    let mut active =
        os.family.is_some() || os.name.is_some() || os.arch.is_some() || os.version.is_some();
    let actual = |key: &str| {
        recorder.record_user_property(key);
        ctx.user_or_system_property(key).map(str::to_lowercase)
    };
    let name = actual("os.name");
    if active && let Some(family) = &os.family {
        // `dos` and `unix` test the JVM's `path.separator`, which `-D` sets.
        // The lock lists a set one whether or not a condition reads it.
        let separator = ctx.user_or_system_property("path.separator");
        active = family_matches(family, name.as_deref(), separator);
    }
    if active && let Some(expected) = &os.name {
        active = exact_matches(expected, name.as_deref());
    }
    if active && let Some(expected) = &os.arch {
        active = exact_matches(expected, actual("os.arch").as_deref());
    }
    if active && let Some(expected) = &os.version {
        active = version_matches(expected, actual("os.version").as_deref())?;
    }
    Ok(active)
}

/// Strips the one `!` Maven honours. `!!x` therefore tests `!x`.
pub(crate) fn negation(test: &str) -> (bool, &str) {
    match test.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, test),
    }
}

/// `<name>` and `<arch>`: equality after lowercasing. An unknown actual value
/// matches neither `x` nor `!x`.
fn exact_matches(expected: &str, actual: Option<&str>) -> bool {
    let test = expected.to_lowercase();
    let (reverse, test) = negation(&test);
    actual.is_some_and(|actual| (actual == test) != reverse)
}

/// `<version>`: `regex:` takes a Java regular expression that must match the
/// whole lowercased version, without negation. Otherwise `!` and
/// case-insensitive equality apply.
fn version_matches(expected: &str, actual: Option<&str>) -> Result<bool, ActivationError> {
    match expected.strip_prefix("regex:") {
        Some(pattern) => full_regex_match(pattern, actual),
        None => Ok(exact_matches(expected, actual)),
    }
}

fn family_matches(expected: &str, os_name: Option<&str>, path_separator: Option<&str>) -> bool {
    let test = expected.to_lowercase();
    let (reverse, test) = negation(&test);
    os_name.is_some_and(|os_name| is_family(test, os_name, path_separator) != reverse)
}

/// Maven 3.9's `org.apache.maven.utils.Os.isFamily` for a lowercased family
/// and `os.name`. `dos` and `unix` test `path.separator`, which a `-D`
/// override of `os.name` does not change. A family Maven does not name
/// matches when `os.name` contains it, so `linux` matches Linux only.
fn is_family(family: &str, os_name: &str, path_separator: Option<&str>) -> bool {
    let windows = os_name.contains("windows");
    let win9x = windows && ["95", "98", "me", "ce"].iter().any(|t| os_name.contains(t));
    let mac = os_name.contains("mac") || os_name.contains("darwin");
    match family {
        "windows" => windows,
        "win9x" => win9x,
        "winnt" => windows && !win9x,
        "os/2" | "netware" | "os/400" | "openvms" => os_name.contains(family),
        "dos" => path_separator == Some(";") && !os_name.contains("netware") && !windows,
        "mac" => mac,
        "tandem" => os_name.contains("nonstop_kernel"),
        "unix" => {
            path_separator == Some(":")
                && !os_name.contains("openvms")
                && (!mac || os_name.ends_with('x'))
        }
        "z/os" => os_name.contains("z/os") || os_name.contains("os/390"),
        _ => os_name.contains(family),
    }
}

/// Match Maven's `JdkVersionProfileActivator`.
/// A leading `!` negates a prefix match, including for `![17,)`. Otherwise,
/// `[` or `(` starts a range; any other value matches a `java.version` prefix.
/// Malformed ranges never activate.
fn jdk_active(
    jdk: &str,
    text_from_host: bool,
    ctx: &ActivationContext,
    recorder: &ModelEnvironment,
) -> bool {
    // `JdkVersionProfileActivator` reads the system properties, which hold
    // the `-D` values.
    recorder.record_user_property("java.version");
    let found = ctx
        .properties
        .get("java.version")
        .or_else(|| ctx.system_properties.get("java.version"));
    match found {
        // Maven refuses an empty `java.version` before it reads `<jdk>`.
        Some(found) => !found.is_empty() && jdk_matches(jdk, found),
        // Every host `java.version` starts with the empty prefix.
        None if jdk.is_empty() => true,
        None => {
            recorder.record(if text_from_host {
                HostInput::JavaVersion
            } else {
                HostInput::Jdk(jdk.to_string())
            });
            jdk_matches(
                jdk,
                tested_java_version(ctx.environment.host_java_version(), &ctx.environment),
            )
        }
    }
}

/// Maven compares `java.version` as it is set, spaces included.
pub(crate) fn jdk_matches(req: &str, found: &str) -> bool {
    if let Some(negated) = req.strip_prefix('!') {
        return !found.starts_with(negated);
    }
    if req.starts_with('[') || req.starts_with('(') {
        return jdk_in_range(req, found).unwrap_or(false);
    }
    found.starts_with(req)
}

struct JdkBound {
    value: String,
    closed: bool,
}

/// Maven classifies comma-separated pieces by their brackets and ignores
/// pieces with no bracket. A single bound gets an open upper bound of 99999999.
fn jdk_in_range(range: &str, actual: &str) -> Option<bool> {
    let mut bounds: Vec<JdkBound> = Vec::new();
    for token in java_split(range, &[',']) {
        let (value, closed) = if token.starts_with('[') {
            (token.replace('[', ""), true)
        } else if token.starts_with('(') {
            (token.replace('(', ""), false)
        } else if token.ends_with(']') {
            (token.replace(']', ""), true)
        } else if token.ends_with(')') {
            (token.replace(')', ""), false)
        } else if token.is_empty() {
            (String::new(), false)
        } else {
            continue;
        };
        bounds.push(JdkBound {
            value: value.trim().to_string(),
            closed,
        });
    }
    if bounds.len() < 2 {
        bounds.push(JdkBound {
            value: "99999999".to_string(),
            closed: false,
        });
    }
    use std::cmp::Ordering::*;
    match jdk_relation(actual, bounds.first()?, true)? {
        Equal => Some(true),
        Less => Some(false),
        Greater => Some(jdk_relation(actual, bounds.get(1)?, false)? != Greater),
    }
}

/// Java's split drops trailing empty components, except for an empty input.
fn java_split<'a>(value: &'a str, separators: &[char]) -> Vec<&'a str> {
    let mut tokens: Vec<_> = value.split(separators).collect();
    if !value.is_empty() {
        while tokens.last().is_some_and(|token| token.is_empty()) {
            tokens.pop();
        }
    }
    tokens
}

/// Compare JDK version components as Maven's `JdkVersionProfileActivator` does.
/// Clean only `java.version`, split it on `._-`, and split bounds on dots.
/// Compare up to three signed Java integers, stopping at the first difference.
fn jdk_relation(actual: &str, bound: &JdkBound, is_left: bool) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering::*;
    if bound.value.is_empty() {
        return Some(if is_left { Greater } else { Less });
    }
    let cleaned: String = actual
        .chars()
        .filter(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
        .collect();
    let actual_parts = java_split(&cleaned, &['.', '-', '_']);
    let bound_parts = java_split(&bound.value, &['.']);
    for i in 0..3 {
        let actual = actual_parts.get(i).unwrap_or(&"0").parse::<i32>().ok()?;
        let bound = bound_parts.get(i).unwrap_or(&"0").parse::<i32>().ok()?;
        match actual.cmp(&bound) {
            Equal => {}
            order => return Some(order),
        }
    }
    Some(if bound.closed {
        Equal
    } else if is_left {
        Less
    } else {
        Greater
    })
}

/// Maven 3.10's `DefaultRootLocator.findMandatoryRoot` for a project in
/// `base`: the nearest directory from `base` up to the file system root
/// that holds a `.mvn` directory, else `fallback`, the launcher's
/// `maven.multiModuleProjectDirectory`, normalized.
fn root_directory(base: &Path, fallback: &Path) -> PathBuf {
    let normalized = |path: &Path| {
        let mut normal = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    normal.pop();
                }
                other => normal.push(other),
            }
        }
        normal
    };
    let (base, fallback) = (normalized(base), normalized(fallback));
    (base.ancestors())
        .find(|dir| dir.join(".mvn").is_dir())
        .unwrap_or(&fallback)
        .to_path_buf()
}

/// Maven's `FileProfileActivator`: a non-empty `<exists>` is tested and
/// `<missing>` is then ignored, the value is used as interpolated, spaces
/// included, and a path that is still relative without a base directory
/// does not activate. The path tested is recorded in `recorder` unless it
/// holds a host value.
fn file_active(
    file: &ActivationFile,
    path_from_host: bool,
    ctx: &ActivationContext,
    recorder: &ModelEnvironment,
) -> bool {
    let non_empty = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
    let (path, missing) = match (non_empty(&file.exists), non_empty(&file.missing)) {
        (Some(path), _) => (path, false),
        (None, Some(path)) => (path, true),
        (None, None) => return false,
    };
    let path = PathBuf::from(without_trailing_separator(&path));
    let path = match &ctx.base_dir {
        Some(base) if !path.is_absolute() => {
            crate::properties::java_absolute_path(&path, base, &ctx.environment)
                .unwrap_or_else(|| base.join(path))
        }
        _ => path,
    };
    if !path.is_absolute() {
        return false;
    }
    if !path_from_host {
        recorder.record(HostInput::File(path.to_string_lossy().into_owned()));
    }
    path.exists() != missing
}

/// `path` without the trailing separators `java.io.File` drops, which would
/// make it test for a directory. A root such as `/` or `C:\` keeps its own.
pub(crate) fn without_trailing_separator(mut path: &str) -> &str {
    while path.ends_with(['/', std::path::MAIN_SEPARATOR])
        && std::path::Path::new(path).parent().is_some()
    {
        path = &path[..path.len() - 1];
    }
    path
}

/// The JVM's `os.name` for a Rust OS name (`std::env::consts::OS`, or a
/// `--platforms` target's, where `darwin` also names macOS), which is passed
/// through when raeva does not know it. The JVM names Windows by release; raeva
/// assumes Windows 11, the release current JVMs report on current Windows.
/// `.mvn/maven.config` can set `-Dos.name` for another release.
pub(crate) fn jvm_os_name(rust_os: &str) -> &str {
    match rust_os {
        "linux" => "Linux",
        "macos" | "darwin" => "Mac OS X",
        "windows" => "Windows 11",
        "freebsd" => "FreeBSD",
        "openbsd" => "OpenBSD",
        "netbsd" => "NetBSD",
        "dragonfly" => "DragonFly",
        "solaris" | "illumos" => "SunOS",
        "aix" => "AIX",
        _ => rust_os,
    }
}

/// Every `os.name` a Windows JVM of JDK 17, 21, 25 or 27 reports: the
/// values `src/java.base/windows/native/libjava/java_props_md.c` sets, as
/// of openjdk/jdk17u d2b244d8, jdk21u c673c524, jdk25u 082ecfa4 and jdk
/// c368bac4. 25 and 27 dropped the releases before Windows 8, which 17 and
/// 21 still name.
const WINDOWS_OS_NAMES: [&str; 24] = [
    "Windows 95",
    "Windows 98",
    "Windows Me",
    "Windows 9X (unknown)",
    "Windows NT",
    "Windows 2000",
    "Windows XP",
    "Windows 2003",
    "Windows Vista",
    "Windows Server 2008",
    "Windows 7",
    "Windows Server 2008 R2",
    "Windows 8",
    "Windows Server 2012",
    "Windows 8.1",
    "Windows Server 2012 R2",
    "Windows 10",
    "Windows Server 2016",
    "Windows Server 2019",
    "Windows Server 2022",
    "Windows 11",
    "Windows Server 2025",
    "Windows NT (unknown)",
    "Windows (unknown)",
];

/// The JVM's `os.arch` for a Rust target. OpenJDK reports x86_64 as `amd64`
/// everywhere except macOS, and POMs activate native profiles on that value.
/// `amd64` and `arm64` are accepted as `--platforms` spellings.
pub(crate) fn jvm_os_arch<'a>(rust_os: &str, rust_arch: &'a str) -> &'a str {
    match (rust_os, rust_arch) {
        ("macos" | "darwin", "x86_64" | "amd64") => "x86_64",
        (_, "x86_64" | "amd64") => "amd64",
        (_, "aarch64" | "arm64") => "aarch64",
        ("linux", "x86") => "i386",
        _ => rust_arch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_separators_go_and_roots_stay() {
        assert_eq!(without_trailing_separator("/a/b//"), "/a/b");
        assert_eq!(without_trailing_separator("marker/"), "marker");
        assert_eq!(without_trailing_separator("/"), "/");
        if cfg!(windows) {
            assert_eq!(without_trailing_separator("C:\\"), "C:\\");
            assert_eq!(without_trailing_separator("C:\\a\\"), "C:\\a");
        }
    }

    /// The root is the nearest directory up from the project that holds a
    /// `.mvn` directory, above the reactor root too, else the fallback; the
    /// project path is normalized first.
    #[test]
    fn root_directory_is_the_nearest_with_a_mvn_directory() {
        let dir = tempfile::tempdir().unwrap();
        let reactor = dir.path().join("reactor");
        for path in [
            ".mvn",
            "reactor/sub/.mvn",
            "reactor/sub/mod",
            "reactor/other",
        ] {
            std::fs::create_dir_all(dir.path().join(path)).unwrap();
        }
        let sub = reactor.join("sub");
        let (above, fallback) = (dir.path().to_path_buf(), Path::new("/fallback"));
        for (base, root) in [
            (sub.join("mod"), &sub),
            (sub.clone(), &sub),
            (reactor.join("other"), &above),
            (reactor.clone(), &above),
            (sub.join("mod/../../other"), &above),
            (sub.join("mod/./../mod"), &sub),
            (reactor.join("../reactor/sub/mod"), &sub),
            (dir.path().to_path_buf(), &above),
        ] {
            assert_eq!(&root_directory(&base, fallback), root, "{}", base.display());
        }
        let environment = (crate::HostSnapshot::for_testing(&[]).with_reactor_root(&reactor))
            .environment("linux", "x86_64");
        let mut ctx = ActivationContext::new(environment.with_maven_mode(MavenMode::Maven39));
        ctx.base_dir = Some(sub.join("mod"));
        assert_eq!(ctx.root_directory(), None);
        assert!(!ctx.is_file_directory("project.rootDirectory"));
        ctx.environment = environment.clone().with_maven_mode(MavenMode::Maven310);
        assert_eq!(ctx.root_directory(), Some(sub.clone()));
        ctx.base_dir = Some(reactor.join("other"));
        assert_eq!(ctx.root_directory(), Some(above.clone()));
        ctx.base_dir = Some(sub.join("mod"));
        assert!(ctx.is_file_directory("project.rootDirectory"));
        ctx.base_dir = None;
        assert_eq!(ctx.root_directory(), None);
        assert!(!ctx.is_file_directory("project.rootDirectory"));
        // The launcher's `maven.multiModuleProjectDirectory` looks above
        // the reactor too, and does not follow the module.
        ctx.base_dir = Some(sub.join("mod"));
        let mut file = ActivationFile {
            exists: Some("${maven.multiModuleProjectDirectory}/x".to_string()),
            missing: None,
        };
        crate::project::profiles::interpolate_external_file(&mut file, &ctx);
        assert_eq!(file.exists.map(PathBuf::from), Some(dir.path().join("x")));
        let path = "<file><exists>${maven.multiModuleProjectDirectory}/x</exists></file>";
        assert_eq!(activation(path).unread_host_property(&ctx).as_deref(), None);
        // A `<property>` condition on it is not one raeva.lock can record.
        ctx.properties.insert("x".to_string(), "/x".to_string());
        for text in [
            "<property><name>maven.multiModuleProjectDirectory</name><value>/x</value></property>",
            "<property><name>x</name><value>${maven.multiModuleProjectDirectory}</value></property>",
        ] {
            let unread = activation(text).unread_host_property(&ctx);
            let unread = unread.as_deref();
            assert_eq!(unread, Some("maven.multiModuleProjectDirectory"), "{text}");
        }
        let presence = "<property><name>maven.multiModuleProjectDirectory</name></property>";
        assert!(activation(presence).is_active(&ctx));
        std::fs::remove_dir(dir.path().join(".mvn")).unwrap();
        assert_eq!(root_directory(&reactor, fallback), fallback);
        let environment = crate::HostSnapshot::for_testing(&[]).with_reactor_root(&reactor);
        let launcher = reactor.to_string_lossy();
        assert_eq!(
            environment.host_environment().launcher_root(),
            Some(&*launcher)
        );
    }

    fn activation(conditions: &str) -> Activation {
        quick_xml::de::from_str(&format!("<activation>{conditions}</activation>")).unwrap()
    }

    fn property(name: &str, value: &str) -> Activation {
        let value = if value.is_empty() {
            String::new()
        } else {
            format!("<value>{value}</value>")
        };
        activation(&format!("<property><name>{name}</name>{value}</property>"))
    }

    fn with_properties(properties: &[(&str, &str)]) -> ActivationContext {
        let mut ctx = ActivationContext::default();
        for (name, value) in properties {
            ctx.properties.insert(name.to_string(), value.to_string());
        }
        ctx
    }

    /// A `!` before a name negates presence but is ignored next to a value;
    /// one before a value negates the comparison. A user property named
    /// `env.X` counts without the environment.
    #[test]
    fn property_conditions_follow_maven() {
        for (name, value, properties, active) in [
            ("feature", "on", &[("feature", "on")][..], true),
            ("feature", "on", &[("feature", "off")], false),
            ("!skipTests", "", &[], true),
            ("!skipTests", "", &[("skipTests", "true")], false),
            ("!feature", "on", &[("feature", "on")], true),
            ("!feature", "on", &[("feature", "off")], false),
            ("feature", "!on", &[("feature", "off")], true),
            ("feature", "!on", &[("feature", "on")], false),
            ("user.home", "", &[], true),
            ("!user.dir", "", &[], false),
            ("user.name", "root", &[], false),
            (
                "env.RAEVA_TEST_UNSET_ENV",
                "yes",
                &[("env.RAEVA_TEST_UNSET_ENV", "yes")],
                true,
            ),
        ] {
            let ctx = with_properties(properties);
            assert_eq!(
                property(name, value).is_active(&ctx),
                active,
                "{name}={value} with {properties:?}"
            );
        }
        let ctx = ActivationContext::new(
            ModelEnvironment::builder()
                .env("RAEVA_TEST_ENV", Some("on"))
                .build(),
        );
        assert!(property("env.RAEVA_TEST_ENV", "on").is_active(&ctx));
    }

    /// What Maven 3.9.12 and 3.10.0 activated on JDK 27: the launcher's
    /// `maven.version` and `maven.build.version` are those of the line, a
    /// name the JVM or the launcher always sets is present, and
    /// `java.specification.version` follows `java.version`.
    #[test]
    fn properties_the_jvm_and_launcher_set_are_present() {
        let host = crate::HostSnapshot::for_testing(&[]).with_java_version("1.8.0_442");
        let environment = host.environment("linux", "x86_64");
        for (mode, name, value, active) in [
            (MavenMode::Maven39, "maven.version", "3.9.12", true),
            (MavenMode::Maven310, "maven.version", "3.9.12", false),
            (MavenMode::Maven310, "maven.version", "3.10.0", true),
            (MavenMode::Maven310, "!maven.version", "", false),
            (
                MavenMode::Maven310,
                "maven.build.version",
                "Apache Maven 3.10.0 (c43a36b8d67be7e0805a411bc0898af1a51f5472)",
                true,
            ),
            (MavenMode::Maven39, "maven.home", "", true),
            (MavenMode::Maven39, "!os.version", "", false),
            (MavenMode::Maven39, "!file.encoding", "", false),
            (MavenMode::Maven39, "!path.separator", "", false),
            (MavenMode::Maven39, "user.language", "", true),
            (MavenMode::Maven39, "library.jansi.path", "", true),
            (MavenMode::Maven310, "library.jansi.path", "", false),
            (MavenMode::Maven39, "maven.build.timestamp", "", false),
            (
                MavenMode::Maven39,
                "java.specification.version",
                "1.8",
                true,
            ),
            (MavenMode::Maven39, "java.specification.version", "8", false),
        ] {
            let ctx = ActivationContext::new(environment.with_maven_mode(mode));
            assert_eq!(
                property(name, value).is_active(&ctx),
                active,
                "{mode} {name}={value}"
            );
        }
        for (java, specification) in [("21.0.1", "21"), ("27-ea", "27"), ("1.8.0_442", "1.8")] {
            assert_eq!(java_specification_version(java), specification);
        }
        let ctx = ActivationContext::new(environment.clone());
        let reads = property("java.specification.version", "1.8")
            .evaluate("spec", &ctx)
            .unwrap()
            .1;
        let input = HostInput::Property {
            name: "java.specification.version".to_string(),
            value: Some("1.8".to_string()),
        };
        assert!(reads.contains(&input), "{reads:?}");
        assert_eq!(host.holds(&input), Some(true));
        // Maven 3.10's launcher sets no library.jansi.path, so a dependency
        // model's own value activates.
        let ctx = ActivationContext::new(environment.with_maven_mode(MavenMode::Maven310));
        let mut own = crate::PropertyMap::new();
        own.insert("library.jansi.path", "x");
        let external = ctx.external_activation(&own);
        assert!(property("library.jansi.path", "x").is_active(&external));
        // Its own `env.X` stands in for an unset variable X, by Maven 3.10.0
        // runs, and the variable decides once set.
        let mut own = crate::PropertyMap::new();
        own.insert("env.RAEVA_TEST_FLAG", "on");
        for (set, active) in [(None, true), (Some("off"), false), (Some("on"), true)] {
            let environment = ModelEnvironment::builder()
                .env("RAEVA_TEST_FLAG", set)
                .build()
                .with_maven_mode(MavenMode::Maven310);
            let external = ActivationContext::new(environment).external_activation(&own);
            let (outcome, reads) = property("env.RAEVA_TEST_FLAG", "on")
                .evaluate("flag", &external)
                .unwrap();
            assert_eq!(outcome, active, "{set:?}");
            let env = HostInput::Env("RAEVA_TEST_FLAG".to_string());
            let user = HostInput::UserProperty("env.RAEVA_TEST_FLAG".to_string());
            assert_eq!(reads, [env, user].into());
        }
        // A `[lock] jdks` JDK decides it, as it decides `java.version`.
        let ctx = ActivationContext::new(ModelEnvironment::builder().target_jdk("21.0.1").build());
        assert!(property("java.specification.version", "21").is_active(&ctx));
        let override_read = HostInput::UserProperty("java.specification.version".to_string());
        assert_eq!(ctx.environment.take_reads(), [override_read].into());
        // The replay of a `${...}` condition name reads it this way.
        assert_eq!(ctx.property("java.specification.version"), Some("21"));
    }

    /// A JVM-owned name is answered only where the platform, the
    /// `[lock] jdks` entry or a `-D` fixes it on every host the section
    /// covers; any other read of one refuses the lock.
    #[test]
    fn jvm_owned_names_refuse_unless_the_lock_fixes_them() {
        let host = crate::HostSnapshot::for_testing(&[]);
        let refused =
            |ctx: &ActivationContext, text: &str| activation(text).unread_host_property(ctx);
        // Windows JVMs set names Linux ones do not, and each Windows
        // release reports its own `os.name`.
        let windows = ActivationContext::new(host.environment("windows", "x86_64"));
        for (text, name) in [
            (
                "<property><name>sun.cpu.isalist</name></property>",
                "sun.cpu.isalist",
            ),
            (
                "<property><name>!user.script</name></property>",
                "user.script",
            ),
            (
                "<property><name>sun.os.patch.level</name><value>x</value></property>",
                "sun.os.patch.level",
            ),
            ("<os><name>Windows 11</name></os>", "os.name"),
            ("<os><name>!windows 10</name></os>", "os.name"),
            (
                "<property><name>os.name</name><value>Windows 11</value></property>",
                "os.name",
            ),
            (
                "<file><exists>${user.variant}x</exists></file>",
                "user.variant",
            ),
        ] {
            assert_eq!(refused(&windows, text).as_deref(), Some(name), "{text}");
        }
        // A test every Windows edition's `os.name` answers alike holds.
        for text in [
            "<os><name>!Linux</name></os>",
            "<property><name>!os.name</name></property>",
            "<file><missing>m-${os.name}</missing></file>",
        ] {
            assert_eq!(refused(&windows, text), None, "{text}");
        }
        for text in [
            "<os><family>windows</family></os>",
            "<os><arch>amd64</arch></os>",
            "<os><name>Linux</name></os>",
            "<property><name>os.name</name><value>Linux</value></property>",
            "<property><name>os.detected.name</name></property>",
            "<property><name>user.timezone</name></property>",
        ] {
            assert_eq!(refused(&windows, text), None, "{text}");
        }
        let linux = ActivationContext::new(host.environment("linux", "x86_64"));
        assert_eq!(refused(&linux, "<os><name>Linux</name></os>"), None);
        // A `-D` decides one.
        let mut set = windows.clone();
        set.properties
            .insert("sun.cpu.isalist".into(), "amd64".into());
        set.properties.insert("os.name".into(), "Windows 11".into());
        assert_eq!(
            refused(&set, "<property><name>sun.cpu.isalist</name></property>"),
            None
        );
        assert_eq!(refused(&set, "<os><name>Windows 11</name></os>"), None);

        // Some JDKs keep their own value of a JVM-owned name over
        // `.mvn/jvm.config`'s, so that value answers nothing; another name's
        // stands.
        let jvm_config: HashMap<String, String> = [
            ("java.vendor.version", "V"),
            ("java.specification.maintenance.version", "9"),
            ("own", "yes"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .into();
        let configured = host.clone().with_system_properties(jvm_config.clone());
        let environment = configured.environment("linux", "x86_64");
        assert_eq!(
            host_property(&environment, "java.vendor.version"),
            Some(HostProperty::Unread)
        );
        assert_eq!(host_property(&environment, "own"), None);
        let mut ctx = ActivationContext::new(environment);
        ctx.system_properties = jvm_config;
        for name in [
            "java.vendor.version",
            "java.specification.maintenance.version",
        ] {
            let text = format!("<property><name>{name}</name><value>V</value></property>");
            assert_eq!(refused(&ctx, &text).as_deref(), Some(name));
        }
        assert_eq!(
            refused(
                &ctx,
                "<property><name>own</name><value>yes</value></property>"
            ),
            None
        );

        // A `[lock] jdks` entry fixes the feature release, not the patch.
        let jdk = ActivationContext::new(host.environment_for("linux", "x86_64", Some("21")));
        for text in [
            "<jdk>21</jdk>",
            "<jdk>[17,22)</jdk>",
            "<jdk>!1.8</jdk>",
            "<jdk>17</jdk>",
            "<property><name>java.version</name><value>!1.8</value></property>",
            "<property><name>java.specification.version</name><value>21</value></property>",
            "<property><name>java.version</name></property>",
        ] {
            assert_eq!(refused(&jdk, text), None, "{text}");
        }
        for text in [
            "<jdk>21.0.13</jdk>",
            "<jdk>[21.0.5,22)</jdk>",
            "<jdk>[21.0.7,21.0.8)</jdk>",
            "<jdk>(21.0.7,22)</jdk>",
            "<property><name>java.version</name><value>21</value></property>",
            "<property><name>java.version</name><value>21.0.13.0.3</value></property>",
        ] {
            assert_eq!(
                refused(&jdk, text).as_deref(),
                Some("java.version"),
                "{text}"
            );
        }
        let mut x = jdk.clone();
        x.properties.insert("x".into(), "21.0.13".into());
        let read = "<property><name>x</name><value>${java.version}</value></property>";
        assert_eq!(refused(&x, read).as_deref(), Some("java.version"));
        let mut defined = jdk.clone();
        defined
            .properties
            .insert("java.version".into(), "21.0.13".into());
        assert_eq!(refused(&defined, "<jdk>21.0.13</jdk>"), None);
    }

    /// One model of what Maven's JVM holds, per platform, JDK and line:
    /// answered names expand, unread ones are named, and a name neither
    /// the JVM nor that line's `mvn` sets is none of them.
    #[test]
    fn host_properties_follow_the_platform_jdk_and_line() {
        let host = crate::HostSnapshot::default();
        for mode in [MavenMode::Maven39, MavenMode::Maven310] {
            let windows = host.environment("windows", "x86_64").with_maven_mode(mode);
            let answered = |name| match host_property(&windows, name) {
                Some(HostProperty::Answered(value)) => Some(value),
                _ => None,
            };
            // Windows 10, 11 and Server JVMs each report their own.
            assert_eq!(
                host_property(&windows, "os.name"),
                Some(HostProperty::Unread)
            );
            assert_eq!(answered("path.separator").as_deref(), Some(";"));
            assert_eq!(answered("maven.version").as_deref(), Some(mode.version()));
            let jline = (mode == MavenMode::Maven310).then(|| "native,reflection".to_string());
            assert_eq!(
                answered("org.jline.terminal.exec.redirectPipeCreationMode"),
                jline
            );
            assert_eq!(
                host_property(&windows, "java.vendor"),
                Some(HostProperty::Unread)
            );
            assert_eq!(
                host_property(&windows, "java.home"),
                Some(HostProperty::Unread)
            );
            assert_eq!(host_property(&windows, "no.such"), None);
            let (jansi, jline) = (
                host_property(&windows, "library.jansi.path"),
                host_property(&windows, "library.jline.path"),
            );
            match mode {
                MavenMode::Maven39 => {
                    assert_eq!((jansi, jline), (Some(HostProperty::Unread), None))
                }
                MavenMode::Maven310 => {
                    assert_eq!((jansi, jline), (None, Some(HostProperty::Unread)))
                }
            }
            assert_eq!(
                expand_host_properties("${os.name}|${.os.arch}|${java.vendor}|${x", &windows),
                "${os.name}|amd64|${java.vendor}|${x"
            );
            assert_eq!(
                unread_host_reference("a-${user.name}-${os.name}", &windows).as_deref(),
                Some("user.name")
            );
            assert!(fixed_over_jvm_config("maven.version", mode));
            assert!(!fixed_over_jvm_config("os.name", mode));
            assert_eq!(
                fixed_over_jvm_config("library.jansi.path", mode),
                mode == MavenMode::Maven39
            );
        }
        let jdk = host.environment_for("linux", "x86_64", Some("17"));
        assert_eq!(host_property(&jdk, "java.home"), Some(HostProperty::Unread));
        assert_eq!(
            host_property(&jdk, "java.specification.version"),
            Some(HostProperty::Answered("17".to_string()))
        );
    }

    /// Maven 3.9.12 and 3.10.0 compare a `<value>` with the JVM's system
    /// property. The separators are those of the locked platform, in a
    /// condition and in its interpolation; a value raeva cannot know, or the
    /// presence of a property only some JDKs set, refuses the lock in both
    /// forms unless `-D` sets it, instead of reading as absent.
    #[test]
    fn jvm_property_values_follow_the_platform_or_refuse() {
        let separators = |os| match os {
            "windows" => ["\\", ";", "\r\n"],
            _ => ["/", ":", "\n"],
        };
        let valued = [
            "file.separator",
            "java.home",
            "java.specification.version",
            "java.version",
            "line.separator",
            "maven.build.version",
            "maven.version",
            "org.jline.terminal.exec.redirectPipeCreationMode",
            "os.arch",
            "os.name",
            "path.separator",
        ];
        for os in ["linux", "macos", "windows"] {
            for mode in [MavenMode::Maven39, MavenMode::Maven310] {
                let environment = (crate::HostSnapshot::for_testing(&[]))
                    .environment(os, "x86_64")
                    .with_maven_mode(mode);
                let ctx = ActivationContext::new(environment);
                for (name, actual) in ["file.separator", "path.separator", "line.separator"]
                    .into_iter()
                    .zip(separators(os))
                {
                    assert_eq!(ctx.property(name), Some(actual), "{os} {name}");
                    let other = if actual == "/" { "\\" } else { "/" };
                    for (value, active) in [
                        (actual.to_string(), true),
                        (format!("!{actual}"), false),
                        (other.to_string(), false),
                        (format!("!{other}"), true),
                    ] {
                        let activation = Activation {
                            property: Some(ActivationProperty {
                                name: Some(name.to_string()),
                                value: Some(value.clone()),
                            }),
                            ..Activation::default()
                        };
                        assert_eq!(activation.is_active(&ctx), active, "{os} {name}={value:?}");
                        assert_eq!(
                            activation.unread_host_property(&ctx).as_deref(),
                            None,
                            "{name}"
                        );
                    }
                }
                // Without a JDK, `java.home` is a host input as the
                // `java.version` family is, unknown to a value test.
                for (name, _, _) in jvm_names::JVM_NAMES {
                    let class = jvm_names::class(name, mode);
                    let uneven = class == Some(jvm_names::Class::Uneven);
                    let fixed = matches!(class, Some(jvm_names::Class::Fixed(_)));
                    for value in ["x", "!x"] {
                        let unread = property(name, value).unread_host_property(&ctx);
                        let unread = unread.as_deref();
                        // 3.10's `library.jline.path` ends in `lib/jline-native`.
                        let expected =
                            ((always_set(name, &ctx) && !valued.contains(&name) && !fixed)
                                || uneven)
                                && could_be_host_value(name, "x");
                        let expected = expected.then_some(name);
                        assert_eq!(unread, expected, "{os} {mode} {name}={value}");
                    }
                    let presence = uneven.then_some(name);
                    assert_eq!(
                        property(name, "").unread_host_property(&ctx).as_deref(),
                        presence,
                        "{name}"
                    );
                }
                let interpolation = ctx.activation_properties(&crate::PropertyMap::new());
                assert_eq!(
                    interpolation.get("file.separator").map(String::as_str),
                    Some(separators(os)[0]),
                    "{os}"
                );
                // Maven keeps the space after the `!`, so this name is unset.
                let spaced = property("! java.vendor", "!Acme");
                assert_eq!(spaced.unread_host_property(&ctx).as_deref(), None);
                assert!(spaced.is_active(&ctx));
                // No JDK raeva supports sets `user.timezone` before activation.
                assert!(property("!user.timezone", "").is_active(&ctx));
                // Without the directory raeva runs in, there is no launcher's.
                let path = "<file><exists>${maven.multiModuleProjectDirectory}/x</exists></file>";
                let unread = activation(path).unread_host_property(&ctx);
                let unread = unread.as_deref();
                assert_eq!(unread, Some("maven.multiModuleProjectDirectory"));
                for file in [
                    "<file><exists>m-${java.vendor}</exists></file>",
                    "<file><missing>m-${java.vendor}</missing></file>",
                ] {
                    let file = activation(file);
                    assert_eq!(
                        file.unread_host_property(&ctx).as_deref(),
                        Some("java.vendor")
                    );
                }
                let dotted = activation("<file><exists>m-${.java.vendor}</exists></file>");
                assert_eq!(
                    dotted.unread_host_property(&ctx).as_deref(),
                    Some("java.vendor")
                );
                for text in [
                    "<file><exists>m-${unknown.prop}</exists></file>",
                    "<file><exists>m-${unknown.${java.vendor}}</exists></file>",
                    "<os><name>${unknown.prop}</name></os>",
                ] {
                    assert_eq!(
                        activation(text).unread_host_property(&ctx).as_deref(),
                        None,
                        "{text}"
                    );
                }
                // Maven expands every system property in each kind of
                // condition, so `<os>` and `<jdk>` text cannot compare one
                // raeva does not know as written.
                for (text, name) in [
                    ("<os><name>${java.vendor}</name></os>", "java.vendor"),
                    ("<os><family>!${.java.vendor}</family></os>", "java.vendor"),
                    ("<os><arch>${os.version}</arch></os>", "os.version"),
                    ("<jdk>!${java.vendor}</jdk>", "java.vendor"),
                    ("<jdk>${java.home}</jdk>", "java.home"),
                    ("<os><name>${java.home}</name></os>", "java.home"),
                ] {
                    assert_eq!(
                        activation(text).unread_host_property(&ctx).as_deref(),
                        Some(name),
                        "{text}"
                    );
                }
                // A `-D` value is known.
                let mut defined = ctx.clone();
                defined
                    .properties
                    .insert("java.vendor".into(), "Acme".into());
                let vendor = activation("<os><name>${java.vendor}</name></os>");
                assert_eq!(vendor.unread_host_property(&defined).as_deref(), None);
                // Without a JDK the path keeps `${java.home}` as written,
                // and the lock records what it tested.
                let home = "<file><exists>${java.home}/release</exists></file>";
                assert_eq!(activation(home).unread_host_property(&ctx).as_deref(), None);
                let mut jdk = ctx.clone();
                jdk.environment = (ModelEnvironment::builder())
                    .platform(os, "x86_64")
                    .java_home("/jdk")
                    .build();
                jdk.properties.insert("p".to_string(), "x".to_string());
                for (text, expected) in [
                    (home, None),
                    (
                        "<property><name>java.home</name><value>/jdk</value></property>",
                        None,
                    ),
                    ("<property><name>java.home</name></property>", None),
                    // Activation interpolation leaves `java.home` out of a
                    // `<property>` condition, and Maven's ends at the first `}`.
                    (
                        "<property><name>p</name><value>${java.home}</value></property>",
                        Some("java.home"),
                    ),
                    (
                        "<property><name>${java.home}</name></property>",
                        Some("java.home"),
                    ),
                    (
                        "<property><name>p</name><value>${.java.home}</value></property>",
                        Some("java.home"),
                    ),
                    (
                        "<property><name>p</name><value>${foo.${java.home}}</value></property>",
                        None,
                    ),
                    // No one sets `q`, which decides the condition: by
                    // Maven 3.9.12 and 3.10.0 runs, inactive, or active with
                    // a negated value.
                    (
                        "<property><name>q</name><value>${java.home}</value></property>",
                        None,
                    ),
                    (
                        "<property><name>!q</name><value>!${.java.home}</value></property>",
                        None,
                    ),
                ] {
                    let unread = activation(text).unread_host_property(&jdk);
                    let unread = unread.as_deref();
                    assert_eq!(unread, expected, "{text}");
                }
                let settings = property("file.separator", "!${file.separator}");
                assert!(settings.is_active(&ctx));
                assert!(!settings.with_host_properties(&ctx).is_active(&ctx));
                let version = activation("<os><version>5.0</version></os>");
                assert_eq!(
                    version.unread_host_property(&ctx).as_deref(),
                    Some("os.version")
                );
                // The OS activator does not read a settings.xml profile property.
                let mut settings = ctx.clone();
                settings.settings_properties.insert("os.version", "5.0");
                assert_eq!(
                    version.unread_host_property(&settings).as_deref(),
                    Some("os.version")
                );
                let other = if os == "windows" { "unix" } else { "windows" };
                let moot = format!("<os><family>{other}</family><version>5.0</version></os>");
                assert_eq!(
                    activation(&moot).unread_host_property(&ctx).as_deref(),
                    None
                );
                let mut set = ctx.clone();
                set.properties
                    .insert("java.vendor".to_string(), "Acme".to_string());
                assert_eq!(
                    property("java.vendor", "Acme")
                        .unread_host_property(&set)
                        .as_deref(),
                    None
                );
                assert!(property("java.vendor", "Acme").is_active(&set));
            }
        }
    }

    // Security: an `env.X` profile condition must NOT activate when the
    // variable is not on the substitution allowlist. Otherwise a transitive
    // POM author could key a profile off host secrets (AWS_SECRET_ACCESS_KEY,
    // GITHUB_TOKEN, ...).
    #[test]
    fn env_property_activation_requires_allowlist() {
        let ctx = ActivationContext::new(
            ModelEnvironment::builder()
                .env("RAEVA_SOME_OTHER_VAR", Some("on"))
                .build(),
        );
        let condition = "<name>env.RAEVA_TEST_ENV_DENIED</name>";
        for value in ["<value>on</value>", ""] {
            let activation = activation(&format!("<property>{condition}{value}</property>"));
            assert!(!activation.is_active(&ctx), "{value}");
        }
    }

    /// A hidden variable whose value gives a valued test the outcome it
    /// gives unset decides nothing: Maven 3.9.12 leaves a `true` profile
    /// off for `CI=false` and `CI=1`, as where `CI` is unset. A value that
    /// changes the outcome refuses, and so does any value of a presence
    /// test. Under Maven 3.10, a dependency's own `env.CI` stands in for the
    /// unset variable.
    #[test]
    fn a_hidden_value_that_gives_the_unset_outcome_decides_nothing() {
        let outcomes = |own: Option<&str>, set: Option<&str>| {
            let mut environment = ModelEnvironment::builder();
            if let Some(set) = set {
                environment = environment.hidden_env("RAEVA_TEST_CI", set);
            }
            let environment = environment.build().with_maven_mode(MavenMode::Maven310);
            let ctx = ActivationContext::new(environment);
            match own {
                Some(own) => {
                    let mut own_properties = crate::PropertyMap::new();
                    own_properties.insert("env.RAEVA_TEST_CI", own);
                    ctx.external_activation(&own_properties)
                }
                None => ctx,
            }
        };
        for (name, value, own, set, refused) in [
            ("env.RAEVA_TEST_CI", "true", None, "false", false),
            ("env.RAEVA_TEST_CI", "true", None, "1", false),
            ("env.RAEVA_TEST_CI", "true", None, "", false),
            ("env.RAEVA_TEST_CI", "true", None, "true", true),
            ("env.RAEVA_TEST_CI", "!true", None, "false", false),
            ("env.RAEVA_TEST_CI", "!true", None, "true", true),
            ("!env.RAEVA_TEST_CI", "true", None, "false", false),
            ("env.RAEVA_TEST_CI", "", None, "false", true),
            ("!env.RAEVA_TEST_CI", "", None, "false", true),
            ("env.RAEVA_TEST_CI", "on", Some("on"), "on", false),
            ("env.RAEVA_TEST_CI", "on", Some("on"), "off", true),
            ("env.RAEVA_TEST_CI", "on", Some("off"), "true", false),
        ] {
            let case = format!("{name}={value:?} own {own:?} set {set:?}");
            let activation = property(name, value);
            let ctx = outcomes(own, Some(set));
            let unread = activation.unread_host_property(&ctx);
            let expected = refused.then_some("env.RAEVA_TEST_CI");
            assert_eq!(unread.as_deref(), expected, "{case}");
            if !refused {
                let unset = outcomes(own, None);
                assert_eq!(
                    activation.is_active(&ctx),
                    activation.is_active(&unset),
                    "{case}"
                );
            }
        }
    }

    /// `<exists>` is tested before `<missing>`, relative to the base
    /// directory and without trimming; without a base directory a relative
    /// path does not activate.
    #[test]
    fn file_conditions_follow_maven() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("marker"), b"").unwrap();
        let ctx = ActivationContext {
            base_dir: Some(base.path().to_path_buf()),
            ..ActivationContext::default()
        };
        let file = |file: &str| activation(&format!("<file>{file}</file>"));
        for (conditions, active) in [
            ("<exists>marker</exists><missing>marker</missing>", true),
            ("<exists>marker</exists><missing>absent</missing>", true),
            ("<exists> marker </exists>", false),
            ("<missing>absent</missing>", true),
            ("<exists></exists><missing></missing>", false),
        ] {
            assert_eq!(file(conditions).is_active(&ctx), active, "{conditions}");
        }
        let missing = file("<missing>absent</missing>");
        assert!(!missing.is_active(&ActivationContext::default()));
    }

    /// An `<os>` condition needs every field it names, and an empty one
    /// never activates. Maven lowercases both sides of a name or arch and
    /// compares the whole value; one `!` is stripped, after lowercasing and
    /// without trimming, and an unknown value confirms neither form. A family
    /// Maven does not name matches when `os.name` contains it.
    #[test]
    fn os_conditions_follow_maven() {
        let os = |fields: &str| activation(&format!("<os>{fields}</os>"));
        for (fields, rust_os, active) in [
            (
                "<name>linux</name><family>unix</family><arch>amd64</arch>",
                "linux",
                true,
            ),
            ("<family>Linux</family><arch>amd64</arch>", "linux", true),
            ("<family>Linux</family><arch>amd64</arch>", "macos", false),
            ("", "linux", false),
        ] {
            let mut ctx = ActivationContext::default();
            ctx.set_platform(rust_os, "x86_64");
            assert_eq!(os(fields).is_active(&ctx), active, "{fields} on {rust_os}");
        }
        for (expected, actual, matches) in [
            ("Linux", Some("linux"), true),
            ("Mac OS X", Some("mac os x"), true),
            ("macosx", Some("mac os x"), false),
            ("mac", Some("mac os x"), false),
            ("windows", Some("windows 10"), false),
            ("!windows", Some("linux"), true),
            ("!linux", Some("linux"), false),
            ("!AMD64", Some("amd64"), false),
            ("! linux", Some("linux"), true),
            ("!", Some("linux"), true),
            ("", Some("linux"), false),
            ("linux", None, false),
            ("!linux", None, false),
        ] {
            assert_eq!(
                exact_matches(expected, actual),
                matches,
                "{expected:?} on {actual:?}"
            );
        }
        for (family, name, separator, matches) in [
            ("!windows", Some("linux"), ":", true),
            ("!unix", Some("linux"), ":", false),
            // `!!windows` tests the family `!windows`, which no name contains.
            ("!!windows", Some("linux"), ":", true),
            // An empty family is contained in every name; `!` alone negates it.
            ("", Some("linux"), ":", true),
            ("!", Some("linux"), ":", false),
            ("unix", None, ":", false),
            ("!unix", None, ":", false),
            ("nux", Some("linux"), ":", true),
            ("linux", Some("mac os x"), ":", false),
            ("darwin", Some("mac os x"), ":", false),
            ("win", Some("windows 10"), ";", true),
            ("bsd", Some("freebsd"), ":", true),
        ] {
            assert_eq!(
                family_matches(family, name, Some(separator)),
                matches,
                "{family:?} on {name:?}"
            );
        }
    }

    /// `os.name` in the JVM's casing for every OS raeva knows, and the Maven
    /// families each one is in. macOS and Windows values were recorded from
    /// a JVM on those systems; Maven counts every OS whose path separator is
    /// `:` as unix, DragonFly included.
    #[test]
    fn platforms_report_jvm_os_names_and_maven_families() {
        const FAMILIES: [&str; 12] = [
            "dos", "mac", "netware", "winnt", "openvms", "os/2", "os/400", "tandem", "unix",
            "win9x", "windows", "z/os",
        ];
        for (rust_os, name, families) in [
            ("linux", "Linux", &["unix"][..]),
            ("macos", "Mac OS X", &["mac", "unix"]),
            ("darwin", "Mac OS X", &["mac", "unix"]),
            ("windows", "Windows 11", &["winnt", "windows"]),
            ("freebsd", "FreeBSD", &["unix"]),
            ("openbsd", "OpenBSD", &["unix"]),
            ("netbsd", "NetBSD", &["unix"]),
            ("dragonfly", "DragonFly", &["unix"]),
            ("solaris", "SunOS", &["unix"]),
            ("illumos", "SunOS", &["unix"]),
            ("aix", "AIX", &["unix"]),
            ("haiku", "haiku", &["unix"]),
        ] {
            let mut ctx = ActivationContext::default();
            ctx.set_platform(rust_os, "aarch64");
            assert_eq!(ctx.property("os.name"), Some(name), "{rust_os}");
            assert_eq!(ctx.property("os.family"), None, "{rust_os}");
            let lower = name.to_lowercase();
            let matched: Vec<&str> = FAMILIES
                .into_iter()
                .filter(|family| {
                    family_matches(family, Some(&lower), ctx.property("path.separator"))
                })
                .collect();
            assert_eq!(matched, families, "{rust_os}");
        }
    }

    /// Recorded with Maven 3.9.11: `-Dos.name=Windows11` on a Linux host
    /// still matches `unix`, because that family tests the path separator.
    #[test]
    fn os_name_override_keeps_the_platform_path_separator() {
        let mut ctx = ActivationContext::default();
        ctx.set_platform("linux", "x86_64");
        ctx.properties
            .insert("os.name".to_string(), "Windows11".to_string());
        let os = |family: &str| ActivationOs {
            name: None,
            family: Some(family.to_string()),
            arch: None,
            version: None,
        };
        assert!(os_active(&os("unix"), &ctx, &ctx.environment).unwrap());
        assert!(os_active(&os("windows"), &ctx, &ctx.environment).unwrap());
        assert!(os_active(&os("winnt"), &ctx, &ctx.environment).unwrap());
        assert!(!os_active(&os("mac"), &ctx, &ctx.environment).unwrap());
    }

    /// Recorded with Maven 3.9.12 and 3.10.0: `-Dpath.separator=;` on a
    /// Linux host matches `dos` and not `unix`, in the project's POM and in
    /// a dependency's, where the `-D` is a system property.
    #[test]
    fn a_path_separator_override_moves_dos_and_unix() {
        let os = |family: &str| ActivationOs {
            name: None,
            family: Some(family.to_string()),
            arch: None,
            version: None,
        };
        for dependency in [false, true] {
            let mut ctx = ActivationContext::default();
            ctx.set_platform("linux", "x86_64");
            let properties = if dependency {
                &mut ctx.system_properties
            } else {
                &mut ctx.properties
            };
            properties.insert("path.separator".to_string(), ";".to_string());
            let recorder = ctx.environment.detached();
            assert!(os_active(&os("dos"), &ctx, &recorder).unwrap());
            assert!(!os_active(&os("unix"), &ctx, &recorder).unwrap());
            assert!(os_active(&os("!unix"), &ctx, &recorder).unwrap());
        }
        let mut ctx = ActivationContext::default();
        ctx.set_platform("linux", "x86_64");
        let recorder = ctx.environment.detached();
        assert!(os_active(&os("unix"), &ctx, &recorder).unwrap());
        assert!(!os_active(&os("dos"), &ctx, &recorder).unwrap());
    }

    /// A settings.xml profile property is a user property of activation,
    /// not a system property, so it does not change the OS that Maven's
    /// OS activator or os-maven-plugin see.
    #[test]
    fn a_settings_os_name_does_not_change_the_os() {
        let mut ctx = ActivationContext::default();
        ctx.set_platform("linux", "x86_64");
        ctx.settings_properties.insert("os.name", "Windows 11");
        ctx.settings_properties.insert("os.arch", "aarch64");
        let os = |family: &str| ActivationOs {
            name: None,
            family: Some(family.to_string()),
            arch: None,
            version: None,
        };
        assert!(!os_active(&os("windows"), &ctx, &ctx.environment).unwrap());
        assert!(os_active(&os("unix"), &ctx, &ctx.environment).unwrap());
        let detected = ctx.interpolation_system_properties();
        assert_eq!(
            detected.get("os.detected.name").map(String::as_str),
            Some("linux")
        );
        assert_eq!(
            detected.get("os.detected.arch").map(String::as_str),
            Some("x86_64")
        );
    }

    #[test]
    fn jvm_os_arch_matches_openjdk_names() {
        for (rust_os, rust_arch, jvm) in [
            ("linux", "x86_64", "amd64"),
            ("windows", "x86_64", "amd64"),
            ("macos", "x86_64", "x86_64"),
            ("darwin", "x86_64", "x86_64"),
            ("linux", "aarch64", "aarch64"),
            ("darwin", "arm64", "aarch64"),
            ("linux", "amd64", "amd64"),
            ("linux", "x86", "i386"),
            ("windows", "x86", "x86"),
            ("linux", "riscv64", "riscv64"),
        ] {
            assert_eq!(
                jvm_os_arch(rust_os, rust_arch),
                jvm,
                "{rust_os} {rust_arch}"
            );
        }
    }

    /// A `<jdk>` or `java.version` test is decided for a `[lock] jdks`
    /// entry only where every JDK it covers answers it alike, whatever
    /// numbers a bound spells.
    #[test]
    fn a_jdk_test_holds_for_an_entry_only_when_every_patch_answers_alike() {
        for (entry, spec, expected) in [
            ("21", "21", Some(true)),
            ("21", "2", Some(true)),
            ("21", "21.0", None),
            ("21", "21-", None),
            ("21", "210", Some(false)),
            ("21", "17", Some(false)),
            ("21", "!21", Some(false)),
            ("21", "!21.0.1", None),
            ("1.8", "1.8.0", Some(true)),
            ("1.8", "1.8.0_4", None),
            ("1.8", "!1.8", Some(false)),
            ("1.8", "1.8.1", Some(false)),
            ("21", "[17,22)", Some(true)),
            ("21", "[21,)", Some(true)),
            ("21", "[22,)", Some(false)),
            ("21", "(,21]", None),
            ("21", "(,21)", Some(false)),
            ("21", "[21.0.11,21.0.12]", None),
            ("21", "[021.0.11,021.0.12]", None),
            ("21", "[+21.0.11,+21.0.12]", None),
            ("21", "[21.0.011,21.0.012]", None),
            ("21", "[21,21.0.0]", None),
            ("21", "[21,21.2147483647.2147483647]", Some(true)),
            ("21", "[21.x,22)", None),
            ("17", "[21.x,22)", Some(false)),
            ("1.8", "[1.8,1.9)", Some(true)),
            ("1.8", "[1.8.0,1.8.0]", Some(true)),
            ("1.8", "(1.8.0,1.9)", Some(false)),
            ("21.0.2", "[21.0.2,21.0.3)", Some(true)),
            ("21-ea", "[21,22)", None),
        ] {
            assert_eq!(jdk_on_every_patch(entry, spec), expected, "{entry} {spec}");
        }
        for (entry, value, expected) in [
            ("21", "21", None),
            ("21", "21.0.1", None),
            ("21", "21.", None),
            ("21", "2", Some(false)),
            ("21", "210", Some(false)),
            ("1.8", "1.8", Some(false)),
            ("1.8", "1.8.0_442", None),
        ] {
            assert_eq!(
                equal_on_every_patch(entry, value),
                expected,
                "{entry} {value}"
            );
        }
    }

    /// Expected values match Maven's `help:active-profiles` output.
    #[test]
    fn jdk_activation_matches_maven_semantics() {
        let cases: &[(&str, &str, bool)] = &[
            ("[17,", "21.0.12.1", true),
            ("[17,", "11", false),
            ("[17", "21", true),
            ("[17,)", "21", true),
            ("[17,]", "21", true),
            ("17", "21", false),
            ("17", "17.0.2", true),
            ("21", "21.0.12.1", true),
            ("1.8", "1.8.0_292", true),
            ("1.8", "21", false),
            ("!1.8", "21", true),
            ("!1.8", "1.8.0_292", false),
            ("!17", "17.0.2", false),
            ("!17", "21.0.1", true),
            ("![17,)", "21", true),
            ("![17,)", "11", true),
            ("(,1.8]", "21", false),
            ("(,1.8]", "1.8.0_292", true),
            ("[1.8,1.9)", "1.8.0_292", true),
            ("[1.8,1.9)", "21", false),
            ("[,17]", "21", false),
            ("[,17]", "11", true),
            ("[17,21)", "21", false),
            ("[17,21)", "17.0.2", true),
            ("[17,21]", "21", true),
            ("[17,22)", "21.0.12.1", true),
            ("(21,)", "21", false),
            ("(21,)", "21.0.12", true),
            ("[21.0.1,)", "21", false),
            ("[21.0.1,)", "21.0.12", true),
            ("(,)", "21", true),
            ("[17]", "17.0.2", false),
            ("[abc,)", "21", false),
            ("17,", "21", false),
            ("[17,)", "26-ea", true),
            ("[26,27)", "26-ea", true),
            ("(26,)", "26-ea", false),
            // The value is compared as interpolated, spaces included.
            (" 17", "17.0.2", false),
            ("17 ", "17", false),
            ("[17,)", "21.0.2+13", true),
            ("[21.0.2,21.0.3)", "21.0.2+13", false),
            ("[21.0.213,21.0.214)", "21.0.2+13", true),
            ("[1.8,1.9)", "1.8.0_402", true),
            ("(1.8,)", "1.8.0_402", false),
            ("[21,22)", "21...", true),
            ("[21,22)", "21-ea._-", true),
            ("[21,22)", "21..1", false),
            ("[21,22)", "21.0.2..999999999999", true),
            ("[21.,22.)", "21", true),
            ("[21-0,22)", "21", false),
            ("[21_0,22)", "21", false),
            ("[21,22)", "21.2147483648", false),
            ("[17,)", "21.2147483648", true),
            ("[21,22)", "21.0.0.2147483648", true),
            ("[21,21)", "21", true),
            ("", "21", true),
            ("!", "21", false),
        ];
        for (jdk, version, expected) in cases {
            let activation = activation(&format!("<jdk>{jdk}</jdk>"));
            let ctx = ActivationContext {
                environment: crate::ModelEnvironment::builder()
                    .jdk_version(version)
                    .build(),
                ..ActivationContext::default()
            };
            assert_eq!(
                activation.is_active(&ctx),
                *expected,
                "<jdk>{jdk}</jdk> on java.version {version}"
            );
        }
        // `-Djava.version=" 17"`, as Maven 3.9.12 and 3.10.0 activated it.
        for (jdk, expected) in [
            ("17", false),
            ("!17", true),
            ("[17,)", true),
            ("[18,)", false),
        ] {
            let mut ctx = ActivationContext::default();
            ctx.properties.insert("java.version".into(), " 17".into());
            let active = activation(&format!("<jdk>{jdk}</jdk>")).is_active(&ctx);
            assert_eq!(active, expected, "<jdk>{jdk}</jdk>");
        }
        // Maven refuses an empty `java.version` and activates no `<jdk>`.
        for jdk in ["", "!17", "17"] {
            let mut ctx = ActivationContext::default();
            ctx.properties.insert("java.version".into(), String::new());
            assert!(
                !activation(&format!("<jdk>{jdk}</jdk>")).is_active(&ctx),
                "<jdk>{jdk}</jdk> on -Djava.version="
            );
        }
    }

    /// Maven's `DefaultProfileSelector` adds every `activeByDefault`
    /// profile that did not activate when nothing else in the POM did, so a
    /// default profile with a failing condition, an empty `<os/>` among
    /// them, is still a default, and one whose condition matches suppresses
    /// the others. Recorded with Maven 3.9.11.
    #[test]
    fn active_by_default_profiles_follow_maven() {
        let profile = |id: &str, condition: &str| -> crate::Profile {
            quick_xml::de::from_str(&format!(
                "<profile><id>{id}</id><activation><activeByDefault>true</activeByDefault>\
                 {condition}</activation></profile>"
            ))
            .unwrap()
        };
        let profiles = [
            profile(
                "conditional",
                "<property><name>requiresThis</name><value>yes</value></property>",
            ),
            profile("empty-os", "<os/>"),
            profile("plain", ""),
        ];
        for (properties, expected) in [
            (&[][..], &["conditional", "empty-os", "plain"][..]),
            (&[("requiresThis", "yes")], &["conditional"]),
        ] {
            let active = evaluate_profiles(&profiles, &with_properties(properties)).unwrap();
            let ids: Vec<&str> = active.iter().map(|p| p.id.as_str()).collect();
            assert_eq!(ids, expected);
        }
    }

    /// `DefaultModelBuilder.getProfileActivationContext` in Maven 3.9.11:
    /// `userProperties.computeIfAbsent("packaging", rawModel::getPackaging)`.
    #[test]
    fn input_packaging_is_a_user_property_unless_one_is_set() {
        let pom = |packaging: Option<&str>| crate::Pom {
            packaging: packaging.map(str::to_string),
            ..crate::Pom::default()
        };
        let ctx = ActivationContext::default();
        assert_eq!(
            ctx.with_input_packaging(&pom(None)).property("packaging"),
            Some("jar")
        );
        assert_eq!(
            ctx.with_input_packaging(&pom(Some("bundle")))
                .property("packaging"),
            Some("bundle")
        );
        let mut user = ActivationContext::default();
        user.properties
            .insert("packaging".to_string(), "war".to_string());
        assert_eq!(
            user.with_input_packaging(&pom(Some("bundle")))
                .property("packaging"),
            Some("war")
        );
    }

    #[test]
    fn host_snapshot_ignores_os_version_env_var() {
        temp_env::with_var("OS_VERSION", Some("99.99-MALICIOUS"), || {
            let ctx = ActivationContext::new(
                crate::HostSnapshot::capture(&[]).environment("linux", "x86_64"),
            );
            assert_eq!(
                ctx.property("os.version"),
                None,
                "OS_VERSION env var must not leak into activation context"
            );
        });
    }

    /// Recorded with Maven 3.9.11 on Linux, where `os.version` is
    /// `7.2.9-arch1-1`.
    #[test]
    fn os_version_follows_maven() {
        let version = Some("7.2.9-arch1-1");
        assert!(version_matches("7.2.9-ARCH1-1", version).unwrap());
        assert!(version_matches("regex:7\\.2\\..*", version).unwrap());
        assert!(!version_matches("regex:7\\.2\\.9-ARCH.*", version).unwrap());
        assert!(version_matches("!1.0", version).unwrap());
        // `!` before `regex:` makes a literal comparison.
        assert!(version_matches("!regex:1.*", version).unwrap());
        assert!(!version_matches("", version).unwrap());
        assert!(version_matches("!", version).unwrap());
        assert!(version_matches("regex:[", version).is_err());
        assert!(version_matches("regex:[", None).is_err());
        // Java accepts lookaround.
        assert!(version_matches("regex:(?=7).*", version).unwrap());
        // Java's `\Q...\E` quotes a literal, to `\E` or the end.
        assert!(version_matches("regex:\\Q7.2.9\\E.*", version).unwrap());
        assert!(!version_matches("regex:\\Q7x2\\E.*", version).unwrap());
        assert!(version_matches("regex:7\\Q.2.9-arch1-1", version).unwrap());
        assert!(!version_matches("regex:\\\\Q7.*", version).unwrap());
        // Quoted characters stay literal in a class and under `(?x)`.
        assert!(!version_matches("regex:[\\Qa-z\\E]", Some("b")).unwrap());
        assert!(version_matches("regex:[\\Qa-z\\E]", Some("-")).unwrap());
        assert!(!version_matches("regex:(?x)\\Qa b\\E", Some("ab")).unwrap());
        assert!(version_matches("regex:(?x)\\Qa b\\E", Some("a b")).unwrap());
        assert!(version_matches("regex:(1)\\1\\Q2\\E", Some("112")).unwrap());
        assert!(!version_matches("7.2.9-arch1-1", None).unwrap());
        assert!(!version_matches("!1.0", None).unwrap());
    }

    /// Each pattern and text with the result Java 27's `Pattern.matches`
    /// gave, `None` for a pattern Java refuses. raeva must give the same result
    /// or refuse the pattern; it may never give the other answer.
    #[test]
    fn regex_matches_like_java_or_names_what_it_cannot() {
        let cases: [(&str, &str, Option<bool>); 153] = [
            ("7\\.2\\..*", "7.2.9-arch1-1", Some(true)),
            ("\\d+\\.\\d+", "10.0", Some(true)),
            ("\\d+", "\u{661}\u{662}", Some(false)),
            ("\\w+", "caf\u{E9}", Some(false)),
            ("\\s", "\u{A0}", Some(false)),
            (".*", "a\u{D}b", Some(false)),
            (".*", "a\u{2028}b", Some(false)),
            ("a.b", "a\u{A}b", Some(false)),
            ("(?s)a.b", "a\u{A}b", Some(true)),
            ("(?i)ABC", "abc", Some(true)),
            ("(?i)k", "\u{212A}", Some(false)),
            ("\\bab\\b", "ab", Some(true)),
            ("\\p{Punct}", "$", Some(true)),
            ("\\p{Alpha}", "\u{E9}", Some(false)),
            ("\\p{L}", "\u{E9}", Some(true)),
            ("\\h", "\u{9}", Some(true)),
            ("\\v", "\u{B}", Some(true)),
            ("\\R", "\u{D}\u{A}", Some(true)),
            ("(a)\\12", "aa2", Some(true)),
            ("(a)\\1", "aa", Some(true)),
            ("\\0101", "A", Some(true)),
            ("\\x41", "A", Some(true)),
            ("\\x{41}", "A", Some(true)),
            ("\\u0041", "A", Some(true)),
            ("[a-z&&[^aeiou]]", "b", Some(true)),
            ("[a-d[m-p]]", "n", Some(true)),
            ("[]a]", "]", Some(true)),
            ("[\\d]", "5", Some(true)),
            ("[\\D]", "a", Some(true)),
            ("a{,2}", "a", None),
            ("a{2}", "aa", Some(true)),
            ("x{y}", "x{y}", None),
            ("a*+a", "aaa", Some(false)),
            ("a++", "aa", Some(true)),
            ("(?>a*)a", "aa", Some(false)),
            ("(?=7).*", "7.1", Some(true)),
            ("(?<=a)b", "ab", Some(false)),
            ("(?<=a)b", "b", Some(false)),
            ("\\Z", "", Some(true)),
            ("a\\Z", "a\u{A}", Some(false)),
            ("\\e", "\u{1B}", Some(true)),
            ("\\cA", "\u{1}", Some(true)),
            ("(?x) a b ", "ab", Some(true)),
            ("(?x)[ a]", "a", Some(true)),
            ("(?U)\\w", "\u{E9}", Some(true)),
            ("(?u)(?i)\u{E9}", "\u{C9}", Some(true)),
            ("(?m)a$", "a", Some(true)),
            ("(?d)a.", "a\u{D}", Some(true)),
            ("[\\w-]+", "a-b", Some(true)),
            ("\\S+", "abc", Some(true)),
            ("\\W", "-", Some(true)),
            ("\\Ba", "ba", Some(false)),
            ("(?<n>a)\\k<n>", "aa", Some(true)),
            ("\\Qa.b\\E", "a.b", Some(true)),
            ("10\\.0(\\.\\d+)?", "10.0.1", Some(true)),
            ("6\\.\\d+\\..*-generic", "6.8.0-45-generic", Some(true)),
            ("\\\\", "\\", Some(true)),
            ("\\-", "-", Some(true)),
            ("[\\]]", "]", Some(true)),
            ("a|b", "b", Some(true)),
            ("(?i:A)b", "ab", Some(true)),
            ("\\a", "\u{7}", Some(true)),
            ("\\t", "\u{9}", Some(true)),
            ("[^.]", "a", Some(true)),
            ("a$\\n", "a\n", Some(true)),
            ("a$\\r\\n", "a\r\n", Some(true)),
            ("a\\r$\\n", "a\r\n", Some(false)),
            ("a$\\r", "a\r", Some(true)),
            ("a$\\u2028", "a\u{2028}", Some(true)),
            (".*$", "a\n", Some(false)),
            ("^6\\..*$", "6.8", Some(true)),
            ("a$$", "a", Some(true)),
            ("[$]", "$", Some(true)),
            ("x$|y", "y", Some(true)),
            ("(?P<n>a)", "a", None),
            ("(?<a_b>a)", "a", None),
            ("(a)\\k<1>", "aa", None),
            ("(?i)\\u212A", "k", Some(false)),
            ("(?i)\u{17F}", "s", Some(false)),
            ("(?i)[\\x{212A}]", "k", Some(false)),
            ("(?i)(a)\\1", "aA", Some(true)),
            ("(?ix)a", "A", Some(true)),
            ("(?x)a\\ b", "a b", Some(true)),
            ("(?x)a\u{A0}b", "a\u{A0}b", Some(true)),
            ("(?x)a#b", "a", Some(true)),
            ("(a(?i)b)c", "aBC", Some(false)),
            ("((?i)a)b", "AB", Some(false)),
            ("(?i)(a(?-i)b)c", "AbC", Some(true)),
            ("{1}a", "a", Some(true)),
            ("a{2}{3}", "aa", Some(true)),
            ("a*{2}", "aaa", Some(true)),
            ("a{1", "a", None),
            ("a{1x}", "a", None),
            ("[\\w-z]", "`", Some(false)),
            ("[\\s-x]", "5", Some(false)),
            ("[a-\\w]", "a", None),
            ("[\\w-.]", ".", Some(true)),
            ("[a~~b]", "~", Some(true)),
            ("[+--]", ",", Some(true)),
            ("[--9]", "5", Some(true)),
            ("[a--b]", "a", None),
            ("[\\b]", "b", None),
            ("a*?+", "a", None),
            ("a}", "a}", Some(true)),
            ("a]", "a]", Some(true)),
            ("[a-]", "-", Some(true)),
            ("[-a]", "-", Some(true)),
            ("[a-c-]", "-", Some(true)),
            ("[\\w-]", "-", Some(true)),
            ("(a)(?<=\\1)", "a", None),
            ("(?i:a)B", "Ab", Some(false)),
            ("(?-i:a)", "a", Some(true)),
            ("(?x:a b)", "ab", Some(true)),
            ("[^-a]", "b", Some(true)),
            ("[a^]", "^", Some(true)),
            ("(?:)*a", "a", Some(true)),
            ("a|", "", Some(true)),
            ("()", "", Some(true)),
            ("(?<name>a)(?<v>b)\\k<v>", "abb", Some(true)),
            ("(?<name>a)(?<v>b)\\k<v>", "aba", Some(false)),
            ("(?<v>\\d+)\\.\\k<v>", "1.1", Some(true)),
            ("((a)\\2)", "aa", Some(true)),
            ("(a\\1)", "aa", Some(false)),
            ("\\1(a)", "a", Some(false)),
            ("x{0}", "", Some(true)),
            ("a{1,1000}", "a", Some(true)),
            ("(?i-i)a", "a", Some(true)),
            ("(?i:k)", "K", Some(true)),
            ("a(?<=b*c*)", "a", Some(false)),
            ("x(?<!a*b*)", "x", Some(true)),
            ("ba(?<=(?:b|c)*a)", "ba", None),
            ("(?:a?|b)*+", "ab", Some(false)),
            ("(?:x?|y)*+z", "xyz", Some(false)),
            ("(a?){2}\\1b", "aab", Some(false)),
            ("(?:^|a){2}b", "ab", Some(false)),
            ("(?:b*+.?){2}ba1", "1ba1", Some(false)),
            ("6(\\.\\d+){2}", "6.1.2", Some(true)),
            (".*(?<=(a|b){1,2})d", "ad", None),
            (".*(?<=(?:ab|c){2})d", "cabd", None),
            (".*(?<=(?:a?){1})d", "ad", None),
            (".*(?<=(?:a{1,2}){2})d", "aad", None),
            (".*(?<=(?:ab)?)d", "abd", Some(true)),
            (".*(?<=(ab){2})d", "ababd", Some(true)),
            (".*(?<=(?:ab){2})d", "xabd", Some(false)),
            (".*(?<=(ab){1,3})d", "abd", Some(true)),
            (".*(?<=(?:[ab]){2,5})d", "bad", Some(true)),
            (".*(?<=(?:(?:ab){2}){2})d", "ababababd", Some(true)),
            (".*(?<=(?:a{2}?){2})d", "aaad", Some(false)),
            (".*(?<=(?:(?=a|b)a){2})d", "aad", Some(true)),
            (".*(?<=(?:a|b)?)d", "ad", Some(true)),
            (".*(?<=(?:a(?:b|c)?){2})d", "aad", None),
            (".*(?<=(?:(?:a|b)c){2})d", "acbcd", None),
            (".*(?<=(?:a??){2})d", "aad", None),
        ];
        let mut refused = Vec::new();
        for (pattern, text, java) in cases {
            match (
                version_matches(&format!("regex:{pattern}"), Some(text)),
                java,
            ) {
                (Ok(raeva), Some(java)) => assert_eq!(raeva, java, "{pattern:?} on {text:?}"),
                (Ok(raeva), None) => {
                    panic!("{pattern:?} on {text:?}: Java refuses it, raeva gave {raeva}")
                }
                (
                    Err(
                        error @ (ActivationError::Regex(_)
                        | ActivationError::UnsupportedRegex { .. }),
                    ),
                    _,
                ) => refused.push((pattern, format!("{error:?}"))),
                (Err(error), _) => panic!("{pattern:?}: {error:?}"),
            }
        }
        // What a version pattern commonly uses stays supported.
        for (pattern, error) in &refused {
            assert!(
                ![
                    "7\\.2\\..*",
                    "\\d+\\.\\d+",
                    "10\\.0(\\.\\d+)?",
                    "6\\.\\d+\\..*-generic",
                    "(?i)ABC",
                    "[\\w-]+",
                    "(?=7).*",
                    "(a)\\1",
                    "6(\\.\\d+){2}",
                    "(?<n>a)\\k<n>",
                    "(?<v>\\d+)\\.\\k<v>",
                ]
                .contains(pattern),
                "{pattern:?}: {error}"
            );
        }
    }

    #[test]
    fn a_regex_over_the_length_limit_is_refused() {
        // Characters count, not bytes: half of these take two bytes.
        let at_limit = "é".repeat(MAX_REGEX_LENGTH / 2) + &"a".repeat(MAX_REGEX_LENGTH / 2);
        assert!(version_matches(&format!("regex:{at_limit}"), Some(&at_limit)).unwrap());
        let over = format!("{at_limit}a");
        let error = version_matches(&format!("regex:{over}"), Some("x")).expect_err("refused");
        assert!(
            matches!(error, ActivationError::RegexTooLong { length: 4097 }),
            "{error:?}"
        );
        let message = error.into_pom_error("p").to_string();
        assert_eq!(
            message,
            "invalid model: Failed to determine activation for profile p: regex: the pattern \
             has 4097 characters, more than the 4096 raeva compiles"
        );
    }

    #[test]
    fn a_regex_whose_translation_is_too_long_is_refused() {
        let error = version_matches(
            &format!("regex:{}", "$".repeat(MAX_REGEX_LENGTH)),
            Some("x"),
        )
        .expect_err("refused");
        assert!(
            matches!(&error, ActivationError::UnsupportedRegex { construct, .. }
                if construct.contains("16384 bytes")),
            "{error:?}"
        );
        assert!(version_matches("regex:1\\.0$", Some("1.0")).unwrap());
    }

    /// A refusal does not repeat a group name, which interpolation may have
    /// taken from the host.
    #[test]
    fn a_refused_regex_does_not_repeat_a_group_name() {
        let name = "s3cr3t".repeat(40);
        for pattern in [
            format!("(?<{name}>x)(?<{name}>y)"),
            format!("\\k<{name}>(?<{name}>x)"),
        ] {
            let error = version_matches(&format!("regex:{pattern}"), Some("xy"))
                .expect_err("refused")
                .into_pom_error("p")
                .to_string();
            assert!(!error.contains("s3cr3t"), "{error}");
        }
    }

    /// Constructs Java answers otherwise than `fancy-regex` would, each
    /// checked against Java 27, are refused.
    #[test]
    fn what_java_answers_otherwise_is_refused() {
        let nested = format!("{}a{}", "(?:".repeat(7), "){1000}".repeat(7));
        for (pattern, text) in [
            // Java keeps the capture of the shortest lookbehind match.
            ("7\\.(?<=(7\\.)|\\.)x\\1", "7.x7."),
            ("aa(?<=(?:(aa)|a))x\\1", "aaxaa"),
            ("ab(?<=(?<n>ab)|b)x\\k<n>", "abxab"),
            // Java steps back into a surrogate pair.
            ("a.(?<=a.)", "a\u{1f600}"),
            ("x.(?<!x.)", "x\u{1f600}"),
            (nested.as_str(), "a"),
        ] {
            assert!(
                matches!(
                    version_matches(&format!("regex:{pattern}"), Some(text)),
                    Err(ActivationError::UnsupportedRegex { .. })
                ),
                "{pattern:?}"
            );
        }
        assert!(version_matches("regex:(\\d{1,3}\\.){3}\\d+", Some("1.2.3.4")).unwrap());
    }

    /// Lookarounds split a pattern into regexes with a size limit each,
    /// so the copies of the whole pattern are bounded too.
    #[test]
    fn the_counts_of_a_whole_pattern_are_bounded() {
        let piece = "(?:(?:a{1000}){20}(?=a))";
        assert!(!version_matches(&format!("regex:{}", piece.repeat(4)), Some("a")).unwrap());
        assert!(matches!(
            version_matches(&format!("regex:{}", piece.repeat(5)), Some("a")),
            Err(ActivationError::UnsupportedRegex { .. })
        ));
    }
}
