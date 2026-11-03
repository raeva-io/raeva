//! What a model build reads from outside the POMs: the target platform, the
//! JDK and the environment variables the user allowed POMs to read.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

/// What a model build read from the host: the JDK's `java.version`, its
/// `java.home`, an allowlisted environment variable, the Linux release, a
/// profile activation condition that tested one of the first three, or
/// whether a file a `<file>` condition names exists. A condition stands for
/// its outcome, so a host whose values differ but give the same outcomes
/// builds the same model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostInput {
    /// The JDK's `java.version`.
    JavaVersion,
    /// The JDK's `java.home`, from `JAVA_HOME`.
    JavaHome,
    /// The environment variable of this name.
    Env(String),
    /// The `ID`, `VERSION_ID` and `ID_LIKE` of the Linux release, which
    /// os-maven-plugin reads from `/etc/os-release`.
    OsRelease,
    /// A `<jdk>` condition, as interpolated, that tested the host JDK
    /// version.
    Jdk(String),
    /// A `<property>` condition that tested `java.version`, `java.home` or
    /// an `env.NAME` variable of the host: the name as written, with its
    /// `!`, and the `<value>` when it is not empty.
    Property {
        /// The `<name>` after activation interpolation, `!` included.
        name: String,
        /// The `<value>`, or `None` when it is absent or empty.
        value: Option<String>,
    },
    /// The absolute path a `<file>` condition tested; it holds when the
    /// path exists.
    File(String),
    /// A private file path, retained as an authored expression for freshness checks.
    FileLookup {
        /// The path before interpolation.
        expression: String,
        /// Referenced properties declared in the POM, before interpolation.
        properties: BTreeMap<String, String>,
        /// The local POM directory, absent for repository POMs.
        base_dir: Option<PathBuf>,
        /// The public packaging default, when interpolation consulted it.
        default_packaging: Option<String>,
        /// The source of external properties in this model request.
        source: crate::PropertySource,
    },
    /// A property defined by a `settings.xml` profile that a project-lineage
    /// build read in a way that can change resolution.
    SettingsProperty(String),
    /// A user-property lookup, including an absent `-D` override.
    UserProperty(String),
    /// An activation lookup whose name contains external values. Only the
    /// authored expression and the POM properties it reads are retained.
    UserPropertyLookup {
        /// The property name before interpolation.
        expression: String,
        /// Referenced properties declared in the POM, before interpolation.
        properties: BTreeMap<String, String>,
        /// Whether interpolation read a host value rather than only `-D` values.
        from_host: bool,
        /// The public packaging default, when interpolation consulted it.
        default_packaging: Option<String>,
        /// The source of external properties in this model request.
        source: crate::PropertySource,
    },
    /// Public interpolation text that consulted a privately derived property name.
    InterpolationLookup {
        /// The authored expression before interpolation.
        expression: String,
        /// Public POM properties read by the expression.
        properties: BTreeMap<String, String>,
        /// The source of external properties in this model request.
        source: crate::PropertySource,
        /// The public packaging default used by activation.
        default_packaging: Option<String>,
        /// Public model fields for model interpolation, absent for exact interpolation.
        model: Option<Box<crate::ModelLookup>>,
        /// Whether the expression follows ordinary model interpolation rules.
        model_interpolation: bool,
        /// Whether a private lookup read a host value.
        from_host: bool,
    },
}

impl HostInput {
    pub(crate) fn is_host_read(&self) -> bool {
        !matches!(
            self,
            Self::UserProperty(_)
                | Self::UserPropertyLookup {
                    from_host: false,
                    ..
                }
                | Self::InterpolationLookup {
                    from_host: false,
                    ..
                }
        )
    }

    pub(crate) fn is_java_version(&self) -> bool {
        match self {
            Self::JavaVersion | Self::Jdk(_) => true,
            Self::Property { name, .. } => crate::activation::negation(name).1 == "java.version",
            _ => false,
        }
    }
}

/// The full process environment captured once by [`HostSnapshot::capture`] for
/// `settings.xml` profile activation, which is user-owned and not gated on the
/// POM `${env.*}` allowlist. Always compares equal so [`ModelEnvironment`]
/// equality still reflects only the allowlisted POM inputs.
#[derive(Clone, Default)]
struct HostEnv(Arc<BTreeMap<String, String>>);

// The environment can hold secrets, so Debug shows only its size.
impl std::fmt::Debug for HostEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostEnv({} variables)", self.0.len())
    }
}

impl PartialEq for HostEnv {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for HostEnv {}

/// The host values the builds of one [`HostSnapshot`] read, shared by every
/// environment made from it, and the flag of a probed environment, which
/// any read sets. Two recorders always compare equal, so they do not change
/// an environment's identity.
#[derive(Debug, Clone, Default)]
struct Consulted {
    inputs: Arc<Mutex<Record>>,
    probe: Option<Arc<AtomicBool>>,
    also: Option<HostReads>,
    /// In a [`ModelEnvironment::selection`] record, or one detached from
    /// it, the flag a `java.version` read sets instead of warning: the read
    /// counts only if its profile can change resolution.
    selection: Option<Arc<AtomicBool>>,
}

impl Consulted {
    fn record(&self, input: HostInput) {
        if let Some(probe) = &self.probe
            && input.is_host_read()
        {
            probe.store(true, Ordering::Relaxed);
        }
        if let Some(also) = &self.also {
            lock_reads(&also.0).reads.insert(input.clone());
        }
        lock_reads(&self.inputs).reads.insert(input);
    }

    /// [`Self::record`] for each of `reads`, but for the Java version when
    /// `skip_java_version`. A record takes one set once.
    fn record_all(&self, reads: &Arc<BTreeSet<HostInput>>, skip_java_version: bool) {
        if reads.is_empty() {
            return;
        }
        let kept = |input: &&HostInput| !(skip_java_version && input.is_java_version());
        if let Some(probe) = &self.probe
            && reads.iter().filter(kept).any(HostInput::is_host_read)
        {
            probe.store(true, Ordering::Relaxed);
        }
        let key = (Arc::as_ptr(reads) as usize, skip_java_version);
        for record in (self.also.iter().map(|also| &also.0)).chain([&self.inputs]) {
            let mut record = lock_reads(record);
            if record.taken.contains_key(&key) {
                continue;
            }
            for input in reads.iter().filter(kept) {
                if !record.reads.contains(input) {
                    record.reads.insert(input.clone());
                }
            }
            record.taken.insert(key, Arc::clone(reads));
        }
    }

    fn snapshot(&self) -> BTreeSet<HostInput> {
        lock_reads(&self.inputs).reads.iter().cloned().collect()
    }
}

/// Host values read, and the shared sets of reads already taken whole,
/// by address and Java-version filter. A taken set is kept, so its address
/// names it until the record forgets it. The reads hash: builds record
/// many more than a record ends up holding.
#[derive(Debug, Default)]
struct Record {
    reads: foldhash::HashSet<HostInput>,
    taken: foldhash::HashMap<(usize, bool), Arc<BTreeSet<HostInput>>>,
}

fn lock_reads(record: &Mutex<Record>) -> std::sync::MutexGuard<'_, Record> {
    record.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// The host values one part of a run read, kept besides the snapshot's
/// record of the whole run; see [`HostSnapshot::recording_into`].
#[derive(Debug, Clone, Default)]
pub struct HostReads(Arc<Mutex<Record>>);

impl HostReads {
    /// Take what was read so far out of the record.
    pub fn take(&self) -> BTreeSet<HostInput> {
        let mut record = lock_reads(&self.0);
        record.taken.clear();
        std::mem::take(&mut record.reads).into_iter().collect()
    }
}

impl PartialEq for Consulted {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for Consulted {}

/// The host inputs `raeva` reads once per run, before any POM is read.
///
/// [`HostSnapshot::capture`] is the only place that reads the process
/// environment for model building: `JAVA_HOME` and its `release` file,
/// `JAVA_VERSION`, the variables named in the `${env.*}` allowlist, and on
/// Linux the os-release file.
/// Everything a model build needs from the host comes from a snapshot
/// through [`HostSnapshot::environment`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostSnapshot(EnvironmentInner);

impl HostSnapshot {
    /// Read the host's JDK and the values of the allowlisted variables.
    /// A variable that is unset or not Unicode is left out.
    ///
    /// This reads the process environment on purpose, and is the one place
    /// model building does: `JAVA_HOME`, the `JAVA_VERSION=` line of
    /// `$JAVA_HOME/release`, the `JAVA_VERSION` variable when that file
    /// gives no version, and each variable named in `allowlist`. No other
    /// variable is read, so a POM cannot reach one outside the allowlist.
    /// Without a JDK version, builds see `java.version` 17. On Linux it
    /// also reads the os-release file os-maven-plugin reads.
    pub fn capture(allowlist: &[String]) -> Self {
        let java_home = std::env::var("JAVA_HOME").ok();
        let not_blank = |version: &String| !version.trim().is_empty();
        let java_version = java_home
            .as_deref()
            .and_then(|home| parse_java_release(Path::new(home)))
            .filter(not_blank)
            .or_else(|| std::env::var("JAVA_VERSION").ok().filter(not_blank));
        let host_env: BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        let allowed: BTreeSet<String> = allowlist.iter().cloned().collect();
        let env = allowed
            .iter()
            .filter_map(|name| Some((name.clone(), host_env.get(name)?.clone())))
            .collect();
        Self(EnvironmentInner {
            platform: None,
            java_version,
            target_jdk: false,
            java_home,
            system_properties: HashMap::new(),
            env,
            host_env: HostEnv(Arc::new(host_env)),
            allowed,
            allow_all_env: false,
            linux_release: LinuxRelease::host(),
            classifier_likes: None,
            consulted: Consulted::default(),
            defaulted_java: Warned::default(),
        })
    }

    /// This snapshot with the JVM properties supplied by the project's launcher options.
    #[must_use]
    pub fn with_system_properties(mut self, properties: HashMap<String, String>) -> Self {
        self.0.system_properties = properties;
        self
    }

    /// A snapshot for tests: the allowlisted variables as
    /// [`HostSnapshot::capture`] reads them, which a test sets itself, and no
    /// JDK or Linux release, so the defaults apply wherever the test runs.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing(allowlist: &[String]) -> Self {
        Self(EnvironmentInner {
            java_home: None,
            java_version: None,
            linux_release: None,
            ..Self::capture(allowlist).0
        })
    }

    /// This snapshot with the Linux release in `os_release`, the contents of
    /// an os-release file.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn with_os_release(mut self, os_release: &str) -> Self {
        self.0.linux_release = LinuxRelease::parse(os_release);
        self
    }

    /// This snapshot with `version` as the JDK version.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn with_java_version(mut self, version: &str) -> Self {
        self.0.java_version = Some(version.to_string());
        self
    }

    /// This snapshot, whose environments also record what they read in
    /// `reads`. Environments made from this snapshot before keep their
    /// record.
    #[must_use]
    pub fn recording_into(&self, reads: &HostReads) -> Self {
        let mut snapshot = self.clone();
        snapshot.0.consulted = Consulted {
            also: Some(reads.clone()),
            probe: None,
            ..self.0.consulted.clone()
        };
        snapshot
    }

    /// This snapshot, whose environments record what they read in `reads`
    /// alone, apart from the record of the run.
    #[must_use]
    pub fn recording_only_into(&self, reads: &HostReads) -> Self {
        let mut snapshot = self.clone();
        snapshot.0.consulted = Consulted {
            inputs: Arc::clone(&reads.0),
            ..Consulted::default()
        };
        snapshot
    }

    /// The host values the model builds of this snapshot's environments
    /// read so far. A value a POM's own property or a `-D` value shadowed is
    /// not among them, nor is a variable outside the allowlist.
    pub fn consulted(&self) -> BTreeSet<HostInput> {
        self.0
            .consulted
            .snapshot()
            .into_iter()
            .filter(|input| {
                !matches!(
                    input,
                    HostInput::UserProperty(_) | HostInput::FileLookup { .. }
                )
            })
            .collect()
    }

    /// User-property names looked up by models, including absent overrides.
    pub fn consulted_user_properties(&self) -> BTreeSet<String> {
        self.0
            .consulted
            .snapshot()
            .into_iter()
            .filter_map(|input| match input {
                HostInput::UserProperty(name) => Some(name),
                _ => None,
            })
            .collect()
    }

    /// Private file conditions retained as public expressions, without expanded paths.
    pub fn consulted_file_lookups(&self) -> BTreeSet<HostInput> {
        self.0
            .consulted
            .snapshot()
            .into_iter()
            .filter(|input| matches!(input, HostInput::FileLookup { .. }))
            .collect()
    }

    /// The current value of `input`: what a model build reads for it, or
    /// `None` when it is unset, for a variable not allowlisted, or a
    /// condition (see [`HostSnapshot::holds`]).
    pub fn value(&self, input: &HostInput) -> Option<String> {
        match input {
            HostInput::Jdk(_)
            | HostInput::Property { .. }
            | HostInput::File(_)
            | HostInput::FileLookup { .. }
            | HostInput::SettingsProperty(_)
            | HostInput::UserProperty(_)
            | HostInput::UserPropertyLookup { .. }
            | HostInput::InterpolationLookup { .. } => None,
            HostInput::JavaVersion => Some(
                self.0
                    .java_version
                    .clone()
                    .unwrap_or_else(|| DEFAULT_JAVA_VERSION.to_string()),
            ),
            HostInput::JavaHome => self.0.java_home.clone(),
            HostInput::Env(name) if self.0.allowed.contains(name) => self.0.env.get(name).cloned(),
            HostInput::Env(_) => None,
            HostInput::OsRelease => self.0.linux_release.as_ref().map(|release| {
                format!(
                    "{}\n{}\n{}",
                    release.id,
                    release.version.as_deref().unwrap_or_default(),
                    release.like.join(" ")
                )
            }),
        }
    }

    /// Whether the condition `input` holds on this host, as profile
    /// activation decides it, or `None` when `input` is not a condition.
    pub fn holds(&self, input: &HostInput) -> Option<bool> {
        match input {
            HostInput::Jdk(spec) => Some(crate::activation::jdk_matches(
                spec,
                &self.value(&HostInput::JavaVersion).unwrap_or_default(),
            )),
            HostInput::Property { name, value } => {
                let actual = match crate::activation::negation(name).1 {
                    "java.version" => self.value(&HostInput::JavaVersion),
                    "java.home" => self.value(&HostInput::JavaHome),
                    other => other
                        .strip_prefix("env.")
                        .and_then(|variable| self.value(&HostInput::Env(variable.to_string()))),
                };
                Some(crate::activation::property_matches(
                    name,
                    value.as_deref(),
                    actual.as_deref(),
                ))
            }
            HostInput::File(path) => Some(Path::new(path).exists()),
            HostInput::JavaVersion
            | HostInput::JavaHome
            | HostInput::Env(_)
            | HostInput::OsRelease
            | HostInput::FileLookup { .. }
            | HostInput::SettingsProperty(_)
            | HostInput::UserProperty(_)
            | HostInput::UserPropertyLookup { .. }
            | HostInput::InterpolationLookup { .. } => None,
        }
    }

    /// [`Self::holds`] for a `settings.xml` profile condition, where
    /// `<property>` activation sees every environment variable as `env.NAME`
    /// regardless of the POM `${env.*}` allowlist.
    pub fn holds_in_settings(&self, input: &HostInput) -> Option<bool> {
        if let HostInput::Property { name, value } = input
            && let Some(variable) = crate::activation::negation(name).1.strip_prefix("env.")
        {
            let actual = self
                .0
                .host_env
                .0
                .get(variable)
                .or_else(|| self.0.env.get(variable))
                .map(String::as_str);
            return Some(crate::activation::property_matches(
                name,
                value.as_deref(),
                actual,
            ));
        }
        self.holds(input)
    }

    /// The values of the allowlisted variables that are set.
    pub fn env_values(&self) -> &BTreeMap<String, String> {
        &self.0.env
    }

    /// The variables POMs may read.
    pub fn env_allowlist(&self) -> &BTreeSet<String> {
        &self.0.allowed
    }

    /// The host's `java.version`: from `$JAVA_HOME/release`, else
    /// `JAVA_VERSION`, else `17`.
    pub fn java_version(&self) -> &str {
        self.0
            .java_version
            .as_deref()
            .unwrap_or(DEFAULT_JAVA_VERSION)
    }

    /// The environment of a build for the host platform.
    pub fn host_environment(&self) -> ModelEnvironment {
        self.environment(std::env::consts::OS, std::env::consts::ARCH)
    }

    /// The environment of a build for the platform `os`/`arch`, named as
    /// Rust names them (`linux`, `x86_64`) or as `--platforms` spells them.
    pub fn environment(&self, os: &str, arch: &str) -> ModelEnvironment {
        self.environment_for(os, arch, None)
    }

    /// [`ModelEnvironment::record_reads`] through the environment
    /// [`Self::environment_for`] gives for `jdk`, without making it.
    pub fn record_reads(&self, reads: &Arc<BTreeSet<HostInput>>, jdk: Option<&str>) {
        let target_jdk = self.0.target_jdk || jdk.is_some();
        if !target_jdk && reads.iter().any(HostInput::is_java_version) {
            warn_defaulted_java(&self.0, None);
        }
        (self.0.consulted).record_all(reads, target_jdk);
    }

    /// [`Self::environment`], with `jdk` as `java.version` when given. A
    /// target JDK fixes `java.version` for that resolution, so reads of it
    /// are not recorded as host reads.
    pub fn environment_for(&self, os: &str, arch: &str, jdk: Option<&str>) -> ModelEnvironment {
        let mut inner = self.0.clone();
        inner.platform = Some((os.to_string(), arch.to_string()));
        if let Some(jdk) = jdk {
            inner.java_version = Some(jdk.to_string());
            inner.target_jdk = true;
        }
        ModelEnvironment::new(inner)
    }
}

/// Everything outside the POMs that can change an effective model, fixed
/// for one build: the target platform, the JDK version, `JAVA_HOME`, and the
/// allowlisted environment variables with their values.
///
/// Cloning is cheap; clones share one value. [`ModelEnvironment::default`]
/// names no platform, no JDK and no variable, so a model built with it sees
/// none of them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ModelEnvironment {
    inner: Arc<EnvironmentInner>,
    /// Where reads through this environment are recorded. A detached
    /// environment shares `inner` and records on its own.
    consulted: Consulted,
}

#[derive(Clone, Default, PartialEq, Eq)]
struct EnvironmentInner {
    platform: Option<(String, String)>,
    java_version: Option<String>,
    target_jdk: bool,
    java_home: Option<String>,
    system_properties: HashMap<String, String>,
    env: BTreeMap<String, String>,
    host_env: HostEnv,
    allowed: BTreeSet<String>,
    allow_all_env: bool,
    linux_release: Option<LinuxRelease>,
    /// os-maven-plugin's `os.detection.classifierWithLikes` for the build.
    classifier_likes: Option<ClassifierLikes>,
    consulted: Consulted,
    defaulted_java: Warned,
}

/// os-maven-plugin's `os.detection.classifierWithLikes` for a build, with a
/// flag that turns true once a build reads `${os.detected.classifier}` where
/// the likes can give it a suffix. Clones share the flag, and two values
/// compare equal by their likes alone. A read whose other host reads a
/// build later drops, as for a dependency resolution does not follow,
/// still sets it: the likes are then recorded as an input they are not.
#[derive(Debug, Clone, Default)]
pub struct ClassifierLikes {
    likes: Option<String>,
    read: Arc<AtomicBool>,
}

impl ClassifierLikes {
    /// The likes `likes`, or none, not read yet.
    pub fn new(likes: Option<&str>) -> Self {
        Self {
            likes: likes.map(str::to_string),
            read: Arc::default(),
        }
    }

    /// The likes, as the build sets them.
    pub fn value(&self) -> Option<&str> {
        self.likes.as_deref()
    }

    /// Whether a build read them.
    pub fn read(&self) -> bool {
        self.read.load(Ordering::Relaxed)
    }
}

impl PartialEq for ClassifierLikes {
    fn eq(&self, other: &Self) -> bool {
        self.likes == other.likes
    }
}

impl Eq for ClassifierLikes {}

/// Set once a build read the stand-in `java.version`, shared by every
/// environment of a snapshot. Two flags always compare equal.
#[derive(Debug, Clone, Default)]
struct Warned(Arc<AtomicBool>);

impl PartialEq for Warned {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for Warned {}

/// The variables outside the allowlist that a POM read, each reported once
/// per run.
static HIDDEN_ENV_WARNED: LazyLock<Mutex<BTreeSet<String>>> = LazyLock::new(Mutex::default);

/// Warn once per snapshot that a read of `java.version` that counts, by
/// `pom` when known, saw the stand-in because no JDK is named.
fn warn_defaulted_java(inner: &EnvironmentInner, pom: Option<&str>) {
    if inner.java_version.is_some() || inner.defaulted_java.0.load(Ordering::Relaxed) {
        return;
    }
    let warned = Arc::clone(&inner.defaulted_java.0);
    let pom = pom.map(str::to_string);
    let reader = pom.as_ref().map_or_else(
        || "the build".to_string(),
        |pom| format!("the POM of {pom}"),
    );
    crate::held::when_shown(move || {
        if !warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                sec_code = "JAVA_VERSION_DEFAULTED",
                pom = pom.as_deref(),
                "{reader} reads java.version, and neither JAVA_HOME nor JAVA_VERSION names a \
                 JDK, so raeva used {DEFAULT_JAVA_VERSION}; set JAVA_HOME to the JDK the build \
                 uses, or list the JDKs in [lock] jdks in raeva.toml"
            );
        }
    });
}

/// Test hook: the contents of an os-release file a build with the `testing`
/// feature takes as the host's, so a lock does not depend on the machine
/// that runs the tests.
#[cfg(any(test, feature = "testing"))]
pub const OS_RELEASE_TEST_ENV: &str = "RAEVA_TEST_OS_RELEASE";

/// What os-maven-plugin's `Detector` reads on Linux from the first of
/// `/etc/os-release` and `/usr/lib/os-release` that has an `ID=` line, else
/// from `/etc/redhat-release`: the `ID`, the `VERSION_ID`, and the `ID` and
/// `ID_LIKE` entries it is "like".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxRelease {
    pub(crate) id: String,
    pub(crate) version: Option<String>,
    pub(crate) like: Vec<String>,
}

impl LinuxRelease {
    /// The release in `contents`, read as the plugin reads the file: lines
    /// that start with `ID=`, `VERSION_ID=` or `ID_LIKE=`, with every `"`
    /// removed and the value trimmed, the last `ID=` winning.
    fn parse(contents: &str) -> Option<Self> {
        let value = |line: &str, prefix: &str| {
            line.strip_prefix(prefix)
                .map(|value| value.trim().replace('"', ""))
        };
        let (mut id, mut version, mut like) = (None, None, Vec::<String>::new());
        let mut add_like = |name: &str| {
            if !name.is_empty() && !like.iter().any(|known| known == name) {
                like.push(name.to_string());
            }
        };
        for line in contents.lines() {
            if let Some(value) = value(line, "ID=") {
                add_like(&value);
                id = Some(value);
            } else if let Some(value) = value(line, "VERSION_ID=") {
                version = Some(value);
            } else if let Some(value) = value(line, "ID_LIKE=") {
                value.split_whitespace().for_each(&mut add_like);
            }
        }
        Some(Self {
            id: id?,
            version,
            like,
        })
    }

    /// The release in the first line of `/etc/redhat-release`, as the
    /// plugin reads it there: CentOS, Fedora or Red Hat Enterprise Linux,
    /// the line's first number as the version, and like `rhel`, `fedora` and
    /// itself.
    fn parse_redhat(contents: &str) -> Option<Self> {
        let line = contents.lines().next()?.to_lowercase();
        let id = [
            ("centos", "centos"),
            ("fedora", "fedora"),
            ("red hat enterprise linux", "rhel"),
        ]
        .into_iter()
        .find_map(|(name, id)| line.contains(name).then_some(id))?;
        let version = line
            .split(|c: char| !c.is_ascii_digit())
            .find(|digits| !digits.is_empty())
            .map(str::to_string);
        let mut like = vec!["rhel".to_string(), "fedora".to_string()];
        if !like.iter().any(|known| known == id) {
            like.push(id.to_string());
        }
        Some(Self {
            id: id.to_string(),
            version,
            like,
        })
    }

    /// The release of this host: on Linux the one the files name, elsewhere
    /// none. A build with the `testing` feature takes the contents of an
    /// os-release file from [`OS_RELEASE_TEST_ENV`] instead when it is set,
    /// on any host, and none when it is empty.
    fn host() -> Option<Self> {
        #[cfg(any(test, feature = "testing"))]
        if let Some(contents) = std::env::var_os(OS_RELEASE_TEST_ENV) {
            return Self::parse(&contents.to_string_lossy());
        }
        cfg!(target_os = "linux").then(Self::read).flatten()
    }

    fn read() -> Option<Self> {
        let read = |path| std::fs::read_to_string(path).ok();
        ["/etc/os-release", "/usr/lib/os-release"]
            .into_iter()
            .find_map(|path| Self::parse(&read(path)?))
            .or_else(|| Self::parse_redhat(&read("/etc/redhat-release")?))
    }
}

struct EnvNames<'a>(&'a BTreeMap<String, String>);

impl std::fmt::Debug for EnvNames<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_map()
            .entries(self.0.keys().map(|name| (name, "<redacted>")))
            .finish()
    }
}

impl std::fmt::Debug for ModelEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl std::fmt::Debug for EnvironmentInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ModelEnvironment")
            .field("platform", &self.platform)
            .field("java_version", &self.java_version)
            .field("java_home", &self.java_home)
            .field("env", &EnvNames(&self.env))
            .field("allowed", &self.allowed)
            .field("linux_release", &self.linux_release)
            .field("classifier_likes", &self.classifier_likes)
            .finish_non_exhaustive()
    }
}

/// Builds a [`ModelEnvironment`] with every input named explicitly.
#[derive(Debug, Default)]
pub struct ModelEnvironmentBuilder {
    inner: EnvironmentInner,
}

impl ModelEnvironmentBuilder {
    /// The target platform, by its Rust or `--platforms` OS and
    /// architecture names.
    pub fn platform(mut self, os: &str, arch: &str) -> Self {
        self.inner.platform = Some((os.to_string(), arch.to_string()));
        self
    }

    /// The JDK's `java.version`, which profile activation and
    /// `${java.version}` see.
    pub fn jdk_version(mut self, version: &str) -> Self {
        self.inner.java_version = Some(version.to_string());
        self
    }

    /// The target JDK's `java.version`, fixed by configuration rather than
    /// read from the host.
    pub fn target_jdk(mut self, version: &str) -> Self {
        self.inner.java_version = Some(version.to_string());
        self.inner.target_jdk = true;
        self
    }

    /// The `java.home` system property of profile activation.
    pub fn java_home(mut self, path: &str) -> Self {
        self.inner.java_home = Some(path.to_string());
        self
    }

    /// Allow POMs to read the variable `name`, set to `value`, or unset
    /// when `value` is `None`.
    pub fn env(mut self, name: &str, value: Option<&str>) -> Self {
        self.inner.allowed.insert(name.to_string());
        match value {
            Some(value) => self.inner.env.insert(name.to_string(), value.to_string()),
            None => self.inner.env.remove(name),
        };
        self
    }

    /// The environment with the inputs set so far.
    pub fn build(self) -> ModelEnvironment {
        ModelEnvironment::new(self.inner)
    }
}

/// `java.version` when neither `JAVA_HOME` nor `JAVA_VERSION` names a JDK.
/// `raeva` runs no JVM, so this is a stand-in rather than a detected version.
const DEFAULT_JAVA_VERSION: &str = "17";

impl ModelEnvironment {
    fn new(inner: EnvironmentInner) -> Self {
        Self {
            consulted: inner.consulted.clone(),
            inner: Arc::new(inner),
        }
    }

    /// A builder that starts from no platform, no JDK and no variable.
    pub fn builder() -> ModelEnvironmentBuilder {
        ModelEnvironmentBuilder::default()
    }

    /// The JVM properties supplied by the project's launcher options.
    pub fn system_properties(&self) -> &HashMap<String, String> {
        &self.inner.system_properties
    }

    /// This environment for another target platform.
    pub fn for_platform(&self, os: &str, arch: &str) -> Self {
        Self {
            inner: Arc::new(EnvironmentInner {
                platform: Some((os.to_string(), arch.to_string())),
                ..EnvironmentInner::clone(&self.inner)
            }),
            consulted: self.consulted.clone(),
        }
    }

    /// This environment with `likes` as os-maven-plugin's
    /// `os.detection.classifierWithLikes`, which the plugin reads once for
    /// the whole build: from the first project of the reactor, else from
    /// the user properties. `${os.detected.classifier}` on Linux then takes
    /// the first entry the build machine's release is like as a suffix, and
    /// marks the likes read.
    #[must_use]
    pub fn with_classifier_likes(&self, likes: Option<&ClassifierLikes>) -> Self {
        Self {
            inner: Arc::new(EnvironmentInner {
                classifier_likes: likes.cloned(),
                ..EnvironmentInner::clone(&self.inner)
            }),
            consulted: self.consulted.clone(),
        }
    }

    /// The entries of [`Self::with_classifier_likes`], trimmed, without
    /// empty ones.
    pub(crate) fn classifier_likes(&self) -> impl Iterator<Item = &str> {
        self.inner
            .classifier_likes
            .iter()
            .filter_map(ClassifierLikes::value)
            .flat_map(|likes| likes.split(','))
            .map(str::trim)
            .filter(|like| !like.is_empty())
    }

    /// Mark the likes of [`Self::with_classifier_likes`] read.
    pub(crate) fn note_classifier_likes_read(&self) {
        if let Some(likes) = &self.inner.classifier_likes {
            likes.read.store(true, Ordering::Relaxed);
        }
    }

    /// Whether a build for this environment's platform can take a
    /// classifier suffix from [`Self::with_classifier_likes`]: the platform
    /// is Linux and the build machine's release is known. Nothing is
    /// recorded as read.
    pub fn reads_classifier_likes(&self) -> bool {
        self.platform().is_some_and(|(os, _)| os == "linux") && self.inner.linux_release.is_some()
    }

    /// os-maven-plugin's `os.detected.classifier` for this platform, and
    /// the entry of [`Self::with_classifier_likes`] it appends on this
    /// machine, when it appends one. For diagnostics: nothing is recorded
    /// as read.
    pub fn classifier_like(&self) -> Option<(String, &str)> {
        let release =
            (self.inner.linux_release.as_ref()).filter(|_| self.reads_classifier_likes())?;
        let like = self
            .classifier_likes()
            .find(|like| release.like.iter().any(|known| known == like))?;
        let classifier = crate::properties::os_detected(
            "os.detected.classifier",
            self.os_name(),
            self.os_arch(),
        )?;
        Some((classifier, like))
    }

    /// The Rust OS and architecture names of the target platform.
    pub fn platform(&self) -> Option<(&str, &str)> {
        self.inner
            .platform
            .as_ref()
            .map(|(os, arch)| (os.as_str(), arch.as_str()))
    }

    /// The target JDK version fixed for this environment, or `None` when it
    /// uses the host's JDK.
    pub fn target_jdk(&self) -> Option<&str> {
        self.inner
            .target_jdk
            .then_some(self.inner.java_version.as_deref())
            .flatten()
    }

    pub(crate) fn os_name(&self) -> Option<&str> {
        self.platform()
            .map(|(os, _)| crate::activation::jvm_os_name(os))
    }

    pub(crate) fn os_arch(&self) -> Option<&str> {
        self.platform()
            .map(|(os, arch)| crate::activation::jvm_os_arch(os, arch))
    }

    pub(crate) fn path_separator(&self) -> Option<char> {
        self.platform()
            .map(|(os, _)| if os == "windows" { ';' } else { ':' })
    }

    /// The `java.version` system property Maven's JVM would report: the one
    /// value `<jdk>` activation, `java.version` conditions, `.mvn/maven.config`
    /// and `${java.version}` in a model see, as in Maven. It is 17 when no
    /// JDK is known.
    pub(crate) fn java_version(&self) -> &str {
        self.record(HostInput::JavaVersion);
        self.host_java_version()
    }

    /// [`Self::java_version`] for a reader that records what it tested
    /// itself.
    pub(crate) fn host_java_version(&self) -> &str {
        self.inner
            .java_version
            .as_deref()
            .unwrap_or(DEFAULT_JAVA_VERSION)
    }

    /// Warn, naming `pom`, that a profile of it that can change resolution
    /// read `java.version` while selecting profiles.
    pub(crate) fn warn_java_read_by(&self, pom: &str) {
        if self.consulted.selection.is_none() && !self.inner.target_jdk {
            warn_defaulted_java(&self.inner, Some(pom));
        }
    }

    pub(crate) fn java_home(&self) -> Option<&str> {
        self.record(HostInput::JavaHome);
        self.host_java_home()
    }

    /// [`Self::java_home`] for a reader that records what it tested itself.
    pub(crate) fn host_java_home(&self) -> Option<&str> {
        self.inner.java_home.as_deref()
    }

    /// The build machine's Linux release, which os-maven-plugin reads when
    /// it detects Linux.
    pub(crate) fn linux_release(&self) -> Option<&LinuxRelease> {
        self.record(HostInput::OsRelease);
        self.inner.linux_release.as_ref()
    }

    /// Record a user-property lookup without retaining its value.
    pub fn record_user_property(&self, name: &str) {
        self.record(HostInput::UserProperty(name.to_string()));
    }

    /// Record a read of the settings.xml profile property `name`.
    pub fn record_settings_property(&self, name: &str) {
        self.record(HostInput::SettingsProperty(name.to_string()));
    }

    pub(crate) fn record(&self, input: HostInput) {
        if input.is_java_version() {
            if self.inner.target_jdk {
                return;
            }
            match &self.consulted.selection {
                Some(read) => read.store(true, Ordering::Relaxed),
                None => warn_defaulted_java(&self.inner, None),
            }
        }
        self.consulted.record(input);
    }

    /// This environment, with a flag that turns true once a read through it
    /// records a host input.
    pub(crate) fn probed(&self) -> (ModelEnvironment, Arc<AtomicBool>) {
        let probe = Arc::new(AtomicBool::new(false));
        let consulted = Consulted {
            probe: Some(Arc::clone(&probe)),
            ..self.consulted.clone()
        };
        (self.with_consulted(consulted), probe)
    }

    /// This environment with a record of host reads of its own: a read
    /// through it counts for the snapshot only once its build passes it on
    /// by explicitly merging the reads.
    pub fn detached(&self) -> ModelEnvironment {
        self.with_consulted(Consulted {
            selection: self.consulted.selection.clone(),
            ..Consulted::default()
        })
    }

    /// [`Self::detached`], but in a selection record with a flag of its
    /// own, so a `java.version` read through it counts for the profile only
    /// once its reads are passed on.
    pub(crate) fn detached_apart(&self) -> ModelEnvironment {
        match &self.consulted.selection {
            Some(_) => self.selection(&Arc::default()),
            None => self.detached(),
        }
    }

    /// A read of `java.version` that the reads passed on keep only as a
    /// lookup: in a selection record it sets the flag, elsewhere it warns.
    pub(crate) fn record_java_lookup(&self) {
        if self.inner.target_jdk {
            return;
        }
        match &self.consulted.selection {
            Some(read) => read.store(true, Ordering::Relaxed),
            None => warn_defaulted_java(&self.inner, None),
        }
    }

    /// [`Self::detached`], for selecting a POM's profiles: a `java.version`
    /// read through it sets `java_read` instead of warning of the stand-in
    /// JDK, since only a profile that can change resolution passes its reads
    /// on.
    pub(crate) fn selection(&self, java_read: &Arc<AtomicBool>) -> ModelEnvironment {
        self.with_consulted(Consulted {
            selection: Some(Arc::clone(java_read)),
            ..Consulted::default()
        })
    }

    fn with_consulted(&self, consulted: Consulted) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            consulted,
        }
    }

    /// Record `reads` as read through this environment, as a build that
    /// reuses what another build read does. Builds share one set of reads,
    /// so each record takes it once.
    pub fn record_reads(&self, reads: &Arc<BTreeSet<HostInput>>) {
        if !self.inner.target_jdk
            && self.consulted.selection.is_none()
            && reads.iter().any(HostInput::is_java_version)
        {
            warn_defaulted_java(&self.inner, None);
        }
        self.consulted.record_all(reads, self.inner.target_jdk);
    }

    /// Take what was read through this environment's own record, which a
    /// [`Self::detached`] environment keeps.
    pub fn take_reads(&self) -> BTreeSet<HostInput> {
        let mut record = lock_reads(&self.consulted.inputs);
        record.taken.clear();
        std::mem::take(&mut record.reads).into_iter().collect()
    }

    /// This environment with the target JDK of `target`, when it has one.
    #[must_use]
    pub fn with_java_version_of(&self, target: &ModelEnvironment) -> Self {
        let Some(jdk) = target.target_jdk() else {
            return self.clone();
        };
        Self {
            inner: Arc::new(EnvironmentInner {
                java_version: Some(jdk.to_string()),
                target_jdk: true,
                ..EnvironmentInner::clone(&self.inner)
            }),
            consulted: self.consulted.clone(),
        }
    }

    /// This environment with every host environment variable visible to
    /// profile activation, as `settings.xml` profile activation sees them.
    #[must_use]
    pub fn with_all_env(&self) -> Self {
        Self {
            inner: Arc::new(EnvironmentInner {
                allow_all_env: true,
                ..EnvironmentInner::clone(&self.inner)
            }),
            consulted: self.consulted.clone(),
        }
    }

    pub(crate) fn allows_env(&self, name: &str) -> bool {
        self.inner.allow_all_env || self.inner.allowed.contains(name)
    }

    /// Report, once per run, that a POM read the variable `name`, which is
    /// set but not on the allowlist and so reads as unset, where Maven reads
    /// its value. A name from a nested `${...}` that is not a plain variable
    /// name is not reported, and no value is.
    pub(crate) fn warn_hidden_env(&self, name: &str) {
        let plain = name.len() <= 64
            && !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        // JAVA_HOME (usually read for the pre-9 tools.jar profile) and PWD
        // are host paths; allowing them would make the lock differ on every
        // machine.
        if !plain
            || matches!(name, "JAVA_HOME" | "PWD")
            || !self.inner.host_env.0.contains_key(name)
        {
            return;
        }
        let name = name.to_string();
        crate::held::when_shown(move || {
            let first = (HIDDEN_ENV_WARNED.lock())
                .unwrap_or_else(|poison| poison.into_inner())
                .insert(name.clone());
            if first {
                tracing::warn!(
                    sec_code = "ENV_VAR_HIDDEN",
                    variable = name,
                    "a POM reads the environment variable {name}, which is set here, but raeva \
                     treats it as unset where Maven reads its value; if the value may be \
                     public, add \"{name}\" to [security] allow_env_substitution in config.toml"
                );
            }
        });
    }

    pub(crate) fn env_var(&self, name: &str) -> Option<&str> {
        if !self.inner.allowed.contains(name) {
            return None;
        }
        self.record(HostInput::Env(name.to_string()));
        self.inner.env.get(name).map(String::as_str)
    }

    /// [`Self::env_var`] for a reader that records what it tested itself.
    pub(crate) fn host_env_var(&self, name: &str) -> Option<&str> {
        if !self.allows_env(name) {
            return None;
        }
        if self.inner.allow_all_env {
            return self
                .inner
                .host_env
                .0
                .get(name)
                .or_else(|| self.inner.env.get(name))
                .map(String::as_str);
        }
        self.inner.env.get(name).map(String::as_str)
    }
}

fn parse_java_release(java_home: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(java_home.join("release")).ok()?;
    contents.lines().find_map(|line| {
        let value = line.trim().strip_prefix("JAVA_VERSION=")?;
        Some(strip_quotes(value.trim()))
    })
}

fn strip_quotes(value: &str) -> String {
    let trimmed = value.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = trimmed
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner.to_string();
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_file_wins_over_a_blank_or_other_variable() {
        let home = tempfile::tempdir().unwrap();
        let release = home.path().join("release");
        for (contents, java_home, variable, expected) in [
            (
                "IMPLEMENTOR=\"x\"\nJAVA_VERSION=\"27\"\n",
                true,
                "jdk-21.0.4+7",
                "27",
            ),
            ("", false, " ", "17"),
            // A blank release value falls back to the variable.
            ("JAVA_VERSION=\"\"\n", true, "21.0.4", "21.0.4"),
        ] {
            std::fs::write(&release, contents).unwrap();
            let java_home = java_home.then(|| home.path().as_os_str());
            let vars = [
                ("JAVA_HOME", java_home),
                ("JAVA_VERSION", Some(std::ffi::OsStr::new(variable))),
            ];
            temp_env::with_vars(vars, || {
                let env = HostSnapshot::capture(&[]).host_environment();
                assert_eq!(env.java_version(), expected, "{contents:?} {variable:?}");
            });
        }
    }

    #[test]
    fn debug_output_leaves_out_variable_values() {
        let host = HostSnapshot(EnvironmentInner {
            allowed: BTreeSet::from(["RAEVA_TOKEN".to_string()]),
            env: BTreeMap::from([("RAEVA_TOKEN".to_string(), "s3cr3t-value".to_string())]),
            ..EnvironmentInner::default()
        });
        for debug in [
            format!("{host:?}"),
            format!("{:?}", host.host_environment()),
        ] {
            assert!(debug.contains("RAEVA_TOKEN"), "{debug}");
            assert!(!debug.contains("s3cr3t-value"), "{debug}");
        }
    }

    #[test]
    fn records_what_builds_read() {
        let host = HostSnapshot(EnvironmentInner {
            java_home: Some("/jdk".to_string()),
            allowed: BTreeSet::from(["RAEVA_SET".to_string(), "RAEVA_UNSET".to_string()]),
            env: BTreeMap::from([("RAEVA_SET".to_string(), "on".to_string())]),
            ..EnvironmentInner::default()
        });
        let linux = host.environment("linux", "x86_64");
        let windows = linux.for_platform("windows", "x86_64");
        assert!(host.consulted().is_empty());
        assert_eq!(linux.env_var("RAEVA_SET"), Some("on"));
        assert_eq!(windows.env_var("RAEVA_UNSET"), None);
        assert_eq!(windows.env_var("HOME"), None);
        assert_eq!(windows.java_version(), "17");
        assert_eq!(
            host.consulted(),
            BTreeSet::from([
                HostInput::JavaVersion,
                HostInput::Env("RAEVA_SET".to_string()),
                HostInput::Env("RAEVA_UNSET".to_string()),
            ])
        );
        assert_eq!(host.value(&HostInput::JavaVersion).as_deref(), Some("17"));
        assert_eq!(host.value(&HostInput::JavaHome).as_deref(), Some("/jdk"));
        assert_eq!(host.value(&HostInput::Env("RAEVA_UNSET".into())), None);
        assert_eq!(host.value(&HostInput::Env("HOME".into())), None);
        assert_eq!(
            linux,
            ModelEnvironment::builder()
                .platform("linux", "x86_64")
                .java_home("/jdk")
                .env("RAEVA_SET", Some("on"))
                .env("RAEVA_UNSET", None)
                .build()
        );
    }

    /// A condition on a host value is recorded as the condition, and two
    /// hosts that give it the same outcome cannot be told apart.
    #[test]
    fn conditions_stand_for_their_outcomes() {
        let pom = crate::Pom::parse(
            "<project><profiles>\
             <profile><id>modern</id><activation><jdk>[17,)</jdk></activation></profile>\
             <profile><id>flavored</id><activation><property><name>env.RAEVA_FLAVOR</name>\
             <value>plain</value></property></activation></profile>\
             <profile><id>jdk-known</id><activation><property><name>java.version</name>\
             </property></activation></profile>\
             <profile><id>secret-set</id><activation><property><name>!env.RAEVA_SECRET</name>\
             </property></activation></profile>\
             </profiles></project>",
        )
        .unwrap();
        let host = |version: &str, flavor: &str| {
            HostSnapshot(EnvironmentInner {
                java_version: Some(version.to_string()),
                allowed: BTreeSet::from(["RAEVA_FLAVOR".to_string(), "RAEVA_SECRET".to_string()]),
                env: BTreeMap::from([
                    ("RAEVA_FLAVOR".to_string(), flavor.to_string()),
                    ("RAEVA_SECRET".to_string(), "s3cr3t".to_string()),
                ]),
                ..EnvironmentInner::default()
            })
        };
        let active = |host: &HostSnapshot, properties: &[(&str, &str)]| {
            let ctx = crate::ActivationContext {
                environment: host.environment("linux", "x86_64"),
                properties: properties
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
                ..crate::ActivationContext::default()
            };
            crate::activation::evaluate_profiles(&pom.profiles, &ctx)
                .unwrap()
                .iter()
                .map(|profile| profile.id.clone())
                .collect::<Vec<_>>()
        };

        let first = host("17.0.1", "plain");
        assert_eq!(active(&first, &[]), ["modern", "flavored", "jdk-known"]);
        let conditions = BTreeSet::from([
            HostInput::Jdk("[17,)".to_string()),
            HostInput::Property {
                name: "env.RAEVA_FLAVOR".to_string(),
                value: Some("plain".to_string()),
            },
            HostInput::Property {
                name: "java.version".to_string(),
                value: None,
            },
            HostInput::Property {
                name: "!env.RAEVA_SECRET".to_string(),
                value: None,
            },
        ]);
        assert_eq!(first.consulted(), conditions);

        let outcomes = |host: &HostSnapshot| {
            conditions
                .iter()
                .map(|condition| host.holds(condition).unwrap())
                .collect::<Vec<_>>()
        };
        let other_patch = host("17.0.9", "plain");
        assert_eq!(outcomes(&first), outcomes(&other_patch));
        assert_eq!(active(&other_patch, &[]), active(&first, &[]));
        let older = host("11", "other");
        assert_eq!(outcomes(&older), [false, false, false, true]);
        assert_eq!(active(&older, &[]), ["jdk-known"]);
        assert_eq!(first.holds(&HostInput::JavaVersion), None);

        // A `-D` value answers the JDK conditions instead of the host.
        let shadowed = host("17", "plain");
        active(&shadowed, &[("java.version", "1.8")]);
        assert!(
            !shadowed
                .consulted()
                .iter()
                .any(|input| matches!(input, HostInput::Jdk(_))),
            "{:?}",
            shadowed.consulted()
        );
    }

    /// A condition whose text interpolation took from the host is recorded
    /// as the host values it read and tested, never by that text.
    #[test]
    fn a_condition_written_from_a_host_value_records_the_value() {
        let mut pom = crate::Pom::parse(
            "<project><properties><own>[11,)</own></properties><profiles>\
             <profile><id>by-env</id><activation><jdk>${env.RAEVA_TOKEN}</jdk></activation></profile>\
             <profile><id>by-jdk</id><activation><jdk>${java.version}</jdk></activation></profile>\
             <profile><id>by-value</id><activation><property><name>env.RAEVA_FLAVOR</name>\
             <value>${env.RAEVA_TOKEN}</value></property></activation></profile>\
             <profile><id>by-name</id><activation><property><name>${env.RAEVA_TOKEN}</name>\
             </property></activation></profile>\
             <profile><id>own</id><activation><jdk>${own}</jdk></activation></profile>\
             </profiles></project>",
        )
        .unwrap();
        let host = HostSnapshot(EnvironmentInner {
            java_version: Some("17.0.1".to_string()),
            allowed: BTreeSet::from(["RAEVA_FLAVOR".to_string(), "RAEVA_TOKEN".to_string()]),
            env: BTreeMap::from([
                ("RAEVA_FLAVOR".to_string(), "plain".to_string()),
                ("RAEVA_TOKEN".to_string(), "env.s3cr3t".to_string()),
            ]),
            ..EnvironmentInner::default()
        });
        let ctx = crate::ActivationContext::new(host.environment("linux", "x86_64"));
        crate::project::profiles::interpolate_lineage_activations(&mut pom, &ctx).unwrap();
        let active: Vec<_> = crate::activation::evaluate_profiles(&pom.profiles, &ctx)
            .unwrap()
            .iter()
            .map(|profile| profile.id.clone())
            .collect();
        assert_eq!(active, ["by-jdk", "own"]);
        assert_eq!(
            host.consulted(),
            BTreeSet::from([
                HostInput::JavaVersion,
                HostInput::Env("RAEVA_FLAVOR".to_string()),
                HostInput::Env("RAEVA_TOKEN".to_string()),
                HostInput::Jdk("[11,)".to_string()),
                HostInput::UserPropertyLookup {
                    expression: "${env.RAEVA_TOKEN}".to_string(),
                    properties: BTreeMap::new(),
                    from_host: true,
                    default_packaging: None,
                    source: crate::PropertySource::User,
                },
            ])
        );
    }

    /// A remote POM's `<exists>` that expands to nothing leaves `<missing>`
    /// to be tested, so what the expansion read still decides the profile.
    #[test]
    fn an_empty_exists_path_keeps_its_reads() {
        let mut pom = crate::Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <profiles><profile><id>p</id><activation><file>\
             <exists>${override.file}</exists><missing>/raeva/absent</missing>\
             </file></activation></profile></profiles></project>",
        )
        .unwrap();
        let host = HostSnapshot::for_testing(&[]);
        let mut ctx = crate::ActivationContext::new(host.environment("linux", "x86_64"));
        ctx.properties
            .insert("override.file".to_string(), String::new());
        crate::project::profiles::interpolate_lineage_activations(&mut pom, &ctx).unwrap();
        crate::activation::evaluate_profiles(&pom.profiles, &ctx).unwrap();
        assert_eq!(
            host.consulted_user_properties(),
            BTreeSet::from(["override.file".to_string()])
        );
    }

    /// A POM activation reads the settings.xml properties its interpolation
    /// looks up, through a `project.properties.` prefix or a nested name,
    /// and no other, without copying the settings for each one: many large
    /// unused properties stay cheap.
    #[test]
    fn activation_records_the_settings_properties_interpolation_reads() {
        let mut pom = crate::Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <properties><selector>p2</selector><p3>own</p3></properties><profiles>\
             <profile><id>direct</id><activation><property><name>flag</name>\
             <value>${p0}</value></property></activation></profile>\
             <profile><id>prefixed</id><activation><jdk>${project.properties.p1}</jdk>\
             </activation></profile>\
             <profile><id>nested</id><activation><os><name>${${selector}}</name></os>\
             </activation></profile>\
             <profile><id>shadowed</id><activation><jdk>${p3}</jdk></activation></profile>\
             </profiles></project>",
        )
        .unwrap();
        let host = HostSnapshot::for_testing(&[]);
        let mut ctx = crate::ActivationContext::new(host.environment("linux", "x86_64"));
        let value = "v".repeat(1024);
        for index in 0..4000 {
            let name = format!("p{index}");
            ctx.settings_properties
                .insert(name.as_str(), value.as_str());
            ctx.settings_property_names.insert(name);
        }
        crate::project::profiles::interpolate_lineage_activations(&mut pom, &ctx).unwrap();
        crate::activation::evaluate_profiles(&pom.profiles, &ctx).unwrap();
        let settings: BTreeSet<_> = host
            .consulted()
            .into_iter()
            .filter_map(|input| match input {
                HostInput::SettingsProperty(name) => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(
            settings,
            BTreeSet::from(["p0", "p1", "p2"].map(str::to_string))
        );
    }

    /// A dependency's POM, such as javassist's with its optional
    /// `com.sun:tools:${java.version}`, reads the host for resolution only
    /// through the dependencies resolution follows from it, and through an
    /// environment variable in any version, whose empty value would make
    /// the POM invalid. A project's own dependencies all count, and the
    /// profiles a model keeps for reference never do.
    #[test]
    fn a_model_counts_the_host_values_its_resolution_reads() {
        let pom = crate::Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <dependencies>\
             <dependency><groupId>g</groupId><artifactId>followed</artifactId>\
             <version>${env.RAEVA_FOLLOWED}</version></dependency>\
             <dependency><groupId>com.sun</groupId><artifactId>tools</artifactId>\
             <version>${java.version}</version><scope>system</scope><optional>true</optional>\
             <systemPath>${java.home}/lib/tools.jar</systemPath></dependency>\
             <dependency><groupId>g</groupId><artifactId>tested</artifactId>\
             <version>1</version><scope>test</scope><exclusions><exclusion>\
             <groupId>g</groupId><artifactId>${env.RAEVA_EXCLUDED}</artifactId>\
             </exclusion></exclusions></dependency>\
             <dependency><groupId>g</groupId><artifactId>scoped</artifactId>\
             <version>1</version><scope>${env.RAEVA_SCOPE}</scope></dependency>\
             <dependency><groupId>g</groupId><artifactId>optional</artifactId>\
             <version>${env.RAEVA_OPTIONAL}</version><optional>true</optional></dependency>\
             </dependencies><profiles><profile><id>off</id><dependencies><dependency>\
             <groupId>g</groupId><artifactId>p</artifactId><version>${env.RAEVA_PROFILE}</version>\
             </dependency></dependencies></profile></profiles></project>",
        )
        .unwrap();
        let names = [
            "RAEVA_FOLLOWED",
            "RAEVA_OPTIONAL",
            "RAEVA_EXCLUDED",
            "RAEVA_SCOPE",
            "RAEVA_PROFILE",
        ];
        let env = |name: &str| HostInput::Env(name.to_string());
        for (policy, expected) in [
            (
                crate::ModelPolicy::DEPENDENCY,
                BTreeSet::from([
                    env("RAEVA_FOLLOWED"),
                    env("RAEVA_OPTIONAL"),
                    env("RAEVA_SCOPE"),
                ]),
            ),
            (
                crate::ModelPolicy::PROJECT,
                BTreeSet::from([
                    HostInput::JavaVersion,
                    env("RAEVA_FOLLOWED"),
                    env("RAEVA_OPTIONAL"),
                    env("RAEVA_EXCLUDED"),
                    env("RAEVA_SCOPE"),
                ]),
            ),
        ] {
            let host = HostSnapshot(EnvironmentInner {
                java_version: Some("21.0.4".to_string()),
                allowed: names.iter().map(|name| name.to_string()).collect(),
                env: names
                    .iter()
                    .map(|name| (name.to_string(), "compile".to_string()))
                    .collect(),
                ..EnvironmentInner::default()
            });
            let ctx = crate::ActivationContext::new(host.environment("linux", "x86_64"));
            let project = crate::ready(crate::Project::build(
                pom.clone(),
                &crate::MemorySource::new(),
                policy,
                &ctx,
            ))
            .unwrap();
            assert_eq!(project.dependencies[1].version.as_deref(), Some("21.0.4"));
            assert_eq!(host.consulted(), expected, "root={}", policy.root);
        }
    }

    #[test]
    fn user_property_reads_cover_nested_names_and_dependency_models() {
        for policy in [crate::ModelPolicy::PROJECT, crate::ModelPolicy::DEPENDENCY] {
            let pom = crate::Pom::parse("<project><groupId>g</groupId><artifactId>root</artifactId><version>1</version>\
                <properties><selector>lib.version</selector><lib.version>1</lib.version></properties>\
                <dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>\
                <version>${project.properties.${selector}}</version></dependency>\
                <dependency><groupId>g</groupId><artifactId>tests</artifactId><version>${excluded.version}</version><scope>test</scope></dependency></dependencies>\
                <profiles><profile><id>extra</id><activation><property><name>enable.extra</name></property></activation>\
                <dependencies><dependency><groupId>g</groupId><artifactId>extra</artifactId><version>1</version></dependency></dependencies>\
                </profile></profiles></project>").unwrap();
            let host = HostSnapshot::for_testing(&[]);
            let mut ctx = crate::ActivationContext::new(host.environment("linux", "x86_64"));
            ctx.properties
                .insert("unused".to_string(), "value".to_string());
            ctx.properties
                .insert("excluded.version".to_string(), "1".to_string());
            crate::ready(crate::Project::build(
                pom,
                &crate::MemorySource::new(),
                policy,
                &ctx,
            ))
            .unwrap();
            let names = host.consulted_user_properties();
            for name in ["selector", "lib.version", "enable.extra"] {
                assert!(names.contains(name), "{policy:?}: {names:?}");
            }
            assert!(!names.contains("unused"), "{policy:?}: {names:?}");
            assert_eq!(names.contains("excluded.version"), policy.root, "{names:?}");
        }
    }

    /// `/etc/redhat-release` as os-maven-plugin 1.7.1 reads it.
    #[test]
    fn redhat_release_names_three_releases() {
        for (line, expected) in [
            (
                "CentOS Linux release 7.9.2009 (Core)\n",
                Some(("centos", Some("7"), "rhel fedora centos")),
            ),
            (
                "Red Hat Enterprise Linux Server release 6.10 (Santiago)",
                Some(("rhel", Some("6"), "rhel fedora")),
            ),
            (
                "Fedora release 20 (Heisenbug)",
                Some(("fedora", Some("20"), "rhel fedora")),
            ),
            ("FEDORA", Some(("fedora", None, "rhel fedora"))),
            ("Rocky Linux release 8.9 (Green Obsidian)", None),
            ("", None),
        ] {
            let release = LinuxRelease::parse_redhat(line);
            let actual = release.as_ref().map(|release| {
                (
                    release.id.as_str(),
                    release.version.as_deref(),
                    release.like.join(" "),
                )
            });
            assert_eq!(
                actual,
                expected.map(|(id, version, like)| (id, version, like.to_string())),
                "{line}"
            );
        }
    }

    /// A variable that is not Unicode is left out of the captured
    /// environment instead of failing the capture.
    #[cfg(unix)]
    #[test]
    fn capture_skips_a_variable_that_is_not_unicode() {
        use std::os::unix::ffi::OsStrExt;
        let value = std::ffi::OsStr::from_bytes(b"a\xffb");
        temp_env::with_var("RAEVA_TEST_NOT_UNICODE", Some(value), || {
            let host = HostSnapshot::capture(&[]);
            let env = host.host_environment().with_all_env();
            assert_eq!(env.host_env_var("RAEVA_TEST_NOT_UNICODE"), None);
        });
    }

    /// A target JDK fixes `java.version` for that build: `<jdk>`,
    /// `<property>` on `java.version` and `${java.version}` read the target
    /// JDK and record no JDK host input, while `java.home` stays the host's
    /// and `-Djava.version` still overrides the target.
    #[test]
    fn target_jdk_evaluates_jdk_without_recording_jdk_host_reads() {
        let pom = crate::Pom::parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <profiles>\
             <profile><id>jdk21</id><activation><jdk>[21,)</jdk></activation>\
             <dependencies><dependency><groupId>g</groupId><artifactId>d</artifactId>\
             <version>${java.version}</version><scope>system</scope>\
             <systemPath>${java.home}/lib/d.jar</systemPath></dependency></dependencies>\
             </profile>\
             <profile><id>prop21</id><activation><property><name>java.version</name>\
             <value>21</value></property></activation></profile>\
             <profile><id>has-jdk</id><activation><property><name>!java.version</name>\
             </property></activation></profile>\
             </profiles></project>",
        )
        .unwrap();
        let host = HostSnapshot(EnvironmentInner {
            java_version: Some("17.0.2".to_string()),
            java_home: Some("/host/jdk".to_string()),
            ..EnvironmentInner::default()
        });
        assert_eq!(host.java_version(), "17.0.2");

        let env17 = host.environment_for("linux", "x86_64", Some("17"));
        assert_eq!(env17.target_jdk(), Some("17"));
        let ctx17 = crate::ActivationContext::new(env17);
        let project17 = crate::ready(crate::Project::build(
            pom.clone(),
            &crate::MemorySource::new(),
            crate::ModelPolicy::PROJECT,
            &ctx17,
        ))
        .unwrap();
        assert!(project17.dependencies.is_empty());
        assert!(host.consulted().is_empty(), "{:?}", host.consulted());

        let env21 = host.environment_for("linux", "x86_64", Some("21"));
        let ctx21 = crate::ActivationContext::new(env21);
        let project21 = crate::ready(crate::Project::build(
            pom.clone(),
            &crate::MemorySource::new(),
            crate::ModelPolicy::PROJECT,
            &ctx21,
        ))
        .unwrap();
        assert_eq!(project21.dependencies.len(), 1);
        assert_eq!(project21.dependencies[0].version.as_deref(), Some("21"));
        assert!(host.consulted().is_empty(), "{:?}", host.consulted());

        let shadowed = HostSnapshot(EnvironmentInner {
            java_version: Some("17.0.2".to_string()),
            ..EnvironmentInner::default()
        });
        let mut ctx_override =
            crate::ActivationContext::new(shadowed.environment_for("linux", "x86_64", Some("21")));
        ctx_override
            .properties
            .insert("java.version".to_string(), "11".to_string());
        let overridden = crate::ready(crate::Project::build(
            pom,
            &crate::MemorySource::new(),
            crate::ModelPolicy::PROJECT,
            &ctx_override,
        ))
        .unwrap();
        assert!(overridden.dependencies.is_empty());
        assert!(shadowed.consulted().is_empty());
    }

    /// The likes entry this machine's release appends, for a Linux target
    /// only, and none on a machine without a Linux release.
    #[test]
    fn the_classifier_like_needs_a_linux_target_and_release() {
        let ubuntu = HostSnapshot::for_testing(&[]).with_os_release("ID=ubuntu\nID_LIKE=debian\n");
        let like = |host: &HostSnapshot, os: &str| {
            host.environment(os, "x86_64")
                .with_classifier_likes(Some(&ClassifierLikes::new(Some("fedora, debian,ubuntu"))))
                .classifier_like()
                .map(|(classifier, like)| format!("{classifier} {like}"))
        };
        assert_eq!(
            like(&ubuntu, "linux").as_deref(),
            Some("linux-x86_64 debian")
        );
        assert_eq!(like(&ubuntu, "macos"), None);
        assert_eq!(like(&HostSnapshot::for_testing(&[]), "linux"), None);
        assert!(ubuntu.consulted().is_empty());
    }
}
