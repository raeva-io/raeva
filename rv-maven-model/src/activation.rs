use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rv_maven_types::bounded;

use crate::{HostInput, ModelEnvironment, PomError};

mod java_regex;

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
    /// Every property name defined by any profile in `settings.xml`, active
    /// or not, so project-lineage builds record [`HostInput::SettingsProperty`]
    /// when a resolution-relevant expression or profile condition reads one.
    pub settings_property_names: BTreeSet<String>,
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
            PropertySource::System => self.system_properties = properties,
        }
    }

    /// A context with no user properties, profile selections or base
    /// directory.
    pub fn new(environment: ModelEnvironment) -> Self {
        Self {
            environment,
            ..Self::default()
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
        for (name, value) in self.settings_properties.iter() {
            properties.insert_external(name, value);
        }
        for (name, value) in &self.properties {
            properties.insert_external(name, value);
        }
        properties.set_input_context(self);
        properties
    }

    /// Properties for activation interpolation, with the POM's own properties first.
    pub fn activation_properties(&self, public: &crate::PropertyMap) -> crate::PropertyMap {
        let mut properties = crate::PropertyMap::new();
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
            |base| crate::project::profiles::align_to_base_directory(path, base),
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
            "java.version" => Some(self.environment.java_version()),
            "java.home" => self.environment.java_home(),
            _ => None,
        }
    }

    /// The target platform's `os.*` system properties. Host paths such as
    /// `java.home` stay out.
    pub fn platform_system_properties(&self) -> HashMap<String, String> {
        [
            ("os.name", self.environment.os_name()),
            ("os.arch", self.environment.os_arch()),
        ]
        .into_iter()
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

    /// The environment a model of this context is interpolated in: without
    /// classifier likes when [`Self::system_properties`] sets
    /// `os.detected.classifier`, which a dependency's model then reads as
    /// it is.
    pub(crate) fn model_environment(&self) -> ModelEnvironment {
        if self
            .system_properties
            .contains_key("os.detected.classifier")
        {
            self.environment.with_classifier_likes(None)
        } else {
            self.environment.clone()
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
    /// tested that decide it. Nothing is recorded in `ctx`'s environment.
    pub fn evaluate(&self, ctx: &ActivationContext) -> (bool, BTreeSet<HostInput>) {
        let recorder = ctx.environment.detached();
        let active = self
            .explicit_conditions_active(ctx, &recorder)
            .unwrap_or(false);
        (active, recorder.take_reads())
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
pub(crate) fn select_profiles(
    profiles: &[crate::Profile],
    ctx: &ActivationContext,
) -> Result<ProfileSelection, PomError> {
    use std::collections::HashSet;

    let explicit_active: HashSet<&str> = ctx.active_profiles.iter().map(String::as_str).collect();
    let explicit_inactive: HashSet<&str> =
        ctx.inactive_profiles.iter().map(String::as_str).collect();

    let mut activated = Vec::new();
    let mut defaults = Vec::new();
    let mut reads = Vec::with_capacity(profiles.len());
    let mut reads_java = Vec::with_capacity(profiles.len());
    for (index, profile) in profiles.iter().enumerate() {
        let id = profile.id.as_str();
        let mut read = BTreeSet::new();
        let java_read = Arc::new(AtomicBool::new(false));
        if explicit_inactive.contains(id) {
            reads.push(read);
            reads_java.push(false);
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
    })
}

/// [`select_profiles`], with every host read recorded.
#[cfg(test)]
pub(crate) fn evaluate_profiles<'a>(
    profiles: &'a [crate::Profile],
    ctx: &ActivationContext,
) -> Result<Vec<&'a crate::Profile>, PomError> {
    let selection = select_profiles(profiles, ctx)?;
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
        let input = allowed.then(|| HostInput::Env(key.to_string()));
        (ctx.environment.host_env_var(key), input)
    } else {
        match name {
            "java.version" => (
                Some(ctx.environment.host_java_version()),
                Some(HostInput::JavaVersion),
            ),
            "java.home" => (ctx.environment.host_java_home(), Some(HostInput::JavaHome)),
            _ => (ctx.property(name), None),
        }
    };
    let value = property.value.as_deref().filter(|value| !value.is_empty());
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
        active = family_matches(family, name.as_deref(), ctx.path_separator());
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

fn family_matches(expected: &str, os_name: Option<&str>, path_separator: Option<char>) -> bool {
    let test = expected.to_lowercase();
    let (reverse, test) = negation(&test);
    os_name.is_some_and(|os_name| is_family(test, os_name, path_separator) != reverse)
}

/// Maven 3.9's `org.apache.maven.utils.Os.isFamily` for a lowercased family
/// and `os.name`. `dos` and `unix` test the platform's path separator, which
/// a `-D` override of `os.name` does not change. A family Maven does not name
/// matches when `os.name` contains it, so `linux` matches Linux only.
fn is_family(family: &str, os_name: &str, path_separator: Option<char>) -> bool {
    let windows = os_name.contains("windows");
    let win9x = windows && ["95", "98", "me", "ce"].iter().any(|t| os_name.contains(t));
    let mac = os_name.contains("mac") || os_name.contains("darwin");
    match family {
        "windows" => windows,
        "win9x" => win9x,
        "winnt" => windows && !win9x,
        "os/2" | "netware" | "os/400" | "openvms" => os_name.contains(family),
        "dos" => path_separator == Some(';') && !os_name.contains("netware") && !windows,
        "mac" => mac,
        "tandem" => os_name.contains("nonstop_kernel"),
        "unix" => {
            path_separator == Some(':')
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
            jdk_matches(jdk, ctx.environment.host_java_version())
        }
    }
}

pub(crate) fn jdk_matches(req: &str, found: &str) -> bool {
    // Maven compares the value as interpolated, spaces included.
    let found = found.trim();

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
        Some(base) if !path.is_absolute() => base.join(path),
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

    fn activation(conditions: &str) -> Activation {
        quick_xml::de::from_str(&format!("<activation>{conditions}</activation>")).unwrap()
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
        let property = |name: &str, value: &str| {
            let value = if value.is_empty() {
                String::new()
            } else {
                format!("<value>{value}</value>")
            };
            activation(&format!("<property><name>{name}</name>{value}</property>"))
        };
        for (name, value, properties, active) in [
            ("feature", "on", &[("feature", "on")][..], true),
            ("feature", "on", &[("feature", "off")], false),
            ("!skipTests", "", &[], true),
            ("!skipTests", "", &[("skipTests", "true")], false),
            ("!feature", "on", &[("feature", "on")], true),
            ("!feature", "on", &[("feature", "off")], false),
            ("feature", "!on", &[("feature", "off")], true),
            ("feature", "!on", &[("feature", "on")], false),
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
            ("!windows", Some("linux"), ':', true),
            ("!unix", Some("linux"), ':', false),
            // `!!windows` tests the family `!windows`, which no name contains.
            ("!!windows", Some("linux"), ':', true),
            // An empty family is contained in every name; `!` alone negates it.
            ("", Some("linux"), ':', true),
            ("!", Some("linux"), ':', false),
            ("unix", None, ':', false),
            ("!unix", None, ':', false),
            ("nux", Some("linux"), ':', true),
            ("linux", Some("mac os x"), ':', false),
            ("darwin", Some("mac os x"), ':', false),
            ("win", Some("windows 10"), ';', true),
            ("bsd", Some("freebsd"), ':', true),
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
                .filter(|family| family_matches(family, Some(&lower), ctx.path_separator()))
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
