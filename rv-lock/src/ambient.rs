//! Host values a resolution can consult, by name.

use std::fmt;
use std::str::FromStr;

use rv_maven_types::is_terminal_safe;

/// A value from outside the project that a resolution read, or a
/// condition on one it tested: the JDK version (`java.version`), the JDK
/// home (`java.home`), an environment variable (`env.NAME`), a
/// user-property lookup (`user-property:NAME`), a settings.xml profile
/// property (`settings-property:NAME`), the Linux
/// release os-maven-plugin reads (`os-release`), or a profile activation
/// condition with its outcome (`jdk:SPEC is true`, `property:NAME=VALUE is
/// false`, `file:PATH is true`, `settings:KEY is false`).
///
/// raeva.lock lists the inputs a resolution consulted in
/// `[resolution] ambient_inputs`, and `config_hash` covers the current
/// value of each plain input and the current outcome of each condition
/// ([`crate::inputs::ResolutionInputs::ambient`]), so `--frozen` can check
/// them again without resolving. A condition records the POM's text and
/// the outcome, never the host value it tested, so a host whose JDK or
/// variables differ but give every condition the same outcome still
/// matches. A name that no resolution consulted is not recorded.
///
/// Inputs order by their text, which is how raeva.lock lists them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AmbientInput {
    /// `env.NAME`: the environment variable `NAME`.
    Env(String),
    /// `java.home`: the JDK home directory.
    JavaHome,
    /// `java.version`: the JDK version.
    JavaVersion,
    /// `os-release`: the ID, VERSION_ID and ID_LIKE of the Linux release.
    OsRelease,
    /// `settings-property:NAME`: the settings.xml profile property `NAME`.
    SettingsProperty(String),
    /// `user-property:NAME`: a consulted user-property override.
    UserProperty(String),
    /// `user-property-lookup:JSON`: public text for private interpolation or activation reads.
    UserPropertyLookup(String),
    /// A profile activation condition on the host and whether it held.
    Condition {
        /// The condition, as activation read it.
        condition: HostCondition,
        /// Whether the condition held on the host; written as ` is true` or
        /// ` is false` after the condition.
        holds: bool,
    },
}

/// A profile activation condition that tested a host value, as activation
/// read it: interpolated, with file paths relative to the project.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostCondition {
    /// `jdk:SPEC`: a `<jdk>` condition, as interpolated.
    Jdk(String),
    /// `property:NAME` or `property:NAME=VALUE`: a `<property>` condition
    /// on `java.version`, `java.home` or `env.NAME`, the name with its
    /// `!`, and the expected value when it is not empty.
    Property {
        /// The property name, with a leading `!` when the POM negates it.
        name: String,
        /// The expected value, `None` when the condition has none. Never
        /// empty.
        value: Option<String>,
    },
    /// `file:PATH`: a `<file>` condition on a path inside the project,
    /// relative to the directory that holds raeva.lock, with `/`
    /// separators. It holds when the path exists.
    File(String),
    /// `settings:KEY`: a host condition of a settings.xml profile, named by
    /// a key derived from its text, which stays out of raeva.lock: 16
    /// lowercase hex digits.
    Settings(String),
}

/// A name that is not `java.version`, `java.home`, `env.NAME` with a valid
/// variable name, or a valid condition. Holds the rejected text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InvalidAmbientInput(pub String);

impl fmt::Display for InvalidAmbientInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ambient input {} is not java.version, java.home, os-release, env.NAME with \
             NAME made of ASCII letters, digits and '_', not starting with a digit, \
             user-property:NAME with a printable option name, \
             settings-property:NAME with NAME made of ASCII letters, digits, '.', '-' and '_', \
             or a jdk:, property:, file: or settings: condition followed by \" is true\" or \
             \" is false\"",
            rv_maven_types::quoted(&self.0)
        )
    }
}

impl std::error::Error for InvalidAmbientInput {}

/// Longest variable name accepted, well above any real one.
const MAX_ENV_NAME_LEN: usize = 255;

/// Longest settings.xml property name accepted.
const MAX_SETTINGS_PROPERTY_NAME_LEN: usize = 128;

/// Longest condition text (a `<jdk>` spec or an expected `<value>`)
/// accepted, in characters.
pub const MAX_CONDITION_TEXT_LEN: usize = 256;

/// Whether `name` is a portable environment variable name: ASCII letters,
/// digits and `_`, not starting with a digit. The name ends up in raeva.lock and
/// in messages, so nothing else is accepted.
pub(crate) fn is_env_var_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= MAX_ENV_NAME_LEN
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Whether `name` is a settings.xml property name raeva.lock can record:
/// 1 to [`MAX_SETTINGS_PROPERTY_NAME_LEN`] ASCII letters, digits, `.`, `-`
/// and `_`.
fn is_settings_property_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SETTINGS_PROPERTY_NAME_LEN
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Condition text raeva.lock can hold: not empty, at most
/// [`MAX_CONDITION_TEXT_LEN`] characters, and none that a terminal would
/// hide or reorder ([`is_terminal_safe`]).
fn is_condition_text(text: &str) -> bool {
    !text.is_empty() && text.chars().count() <= MAX_CONDITION_TEXT_LEN && is_terminal_safe(text)
}

/// Whether `path` is a relative path inside the project, in the form
/// raeva.lock records it: `/`-separated names, none empty or `.`, where a
/// `..` never climbs above the project.
fn is_project_path(path: &str) -> bool {
    let mut depth = 0usize;
    is_condition_text(path)
        && !path.contains(['\\', ':'])
        && path.split('/').all(|name| match name {
            "" | "." => false,
            ".." => depth.checked_sub(1).map(|up| depth = up).is_some(),
            _ => {
                depth += 1;
                true
            }
        })
}

impl AmbientInput {
    /// Whether this is a property or variable name, which
    /// [`crate::inputs::config_hash`] leaves out while it is unset. Every
    /// other entry always counts, so dropping one changes the hash.
    pub fn is_property_name(&self) -> bool {
        matches!(
            self,
            Self::UserProperty(_) | Self::SettingsProperty(_) | Self::Env(_)
        )
    }

    /// The environment variable `name`, if it is a portable name: at most
    /// 255 ASCII letters, digits and `_`, not starting with a digit.
    pub fn env(name: &str) -> Result<Self, InvalidAmbientInput> {
        if is_env_var_name(name) {
            Ok(Self::Env(name.to_string()))
        } else {
            Err(InvalidAmbientInput(format!("env.{name}")))
        }
    }

    /// The settings.xml profile property `name`, if raeva.lock can hold the
    /// name: 1 to 128 ASCII letters, digits, `.`, `-` and `_`.
    pub fn settings_property(name: &str) -> Result<Self, InvalidAmbientInput> {
        if is_settings_property_name(name) {
            Ok(Self::SettingsProperty(name.to_string()))
        } else {
            Err(InvalidAmbientInput(format!("settings-property:{name}")))
        }
    }

    /// A consulted user-property name, without its value.
    pub fn user_property(name: &str) -> Result<Self, InvalidAmbientInput> {
        if crate::codec::is_option_name(name) {
            Ok(Self::UserProperty(name.to_string()))
        } else {
            Err(InvalidAmbientInput(format!("user-property:{name}")))
        }
    }

    /// A public activation expression, without its expanded name or external values.
    pub fn user_property_lookup(
        expression: &str,
        properties: &std::collections::BTreeMap<String, String>,
        default_packaging: Option<String>,
        source: rv_config::maven_config::PropertySource,
    ) -> Self {
        Self::UserPropertyLookup(
            rv_config::maven_config::PropertyLookup {
                expression: expression.to_string(),
                properties: properties.clone(),
                file: None,
                default_packaging,
                source,
                mode: rv_config::maven_config::LookupMode::Property,
                model: None,
            }
            .encode(),
        )
    }

    /// A private file path retained as a public expression and portable POM context.
    pub fn file_lookup(
        expression: &str,
        properties: &std::collections::BTreeMap<String, String>,
        base_dir: Option<String>,
        default_packaging: Option<String>,
        source: rv_config::maven_config::PropertySource,
    ) -> Self {
        Self::UserPropertyLookup(
            rv_config::maven_config::PropertyLookup {
                expression: expression.to_string(),
                properties: properties.clone(),
                file: Some(rv_config::maven_config::FileLookup { base_dir }),
                default_packaging,
                source,
                mode: rv_config::maven_config::LookupMode::File,
                model: None,
            }
            .encode(),
        )
    }

    /// Interpolation reads whose private names must remain inside the aggregate hash.
    pub fn interpolation_lookup(
        expression: &str,
        properties: &std::collections::BTreeMap<String, String>,
        default_packaging: Option<String>,
        source: rv_config::maven_config::PropertySource,
        model: Option<Box<rv_config::maven_config::ModelLookup>>,
        model_interpolation: bool,
    ) -> Self {
        let mode = if model_interpolation {
            rv_config::maven_config::LookupMode::Model
        } else {
            rv_config::maven_config::LookupMode::Interpolation
        };
        Self::UserPropertyLookup(
            rv_config::maven_config::PropertyLookup {
                expression: expression.to_string(),
                properties: properties.clone(),
                file: None,
                default_packaging,
                source,
                mode,
                model,
            }
            .encode(),
        )
    }

    /// The `<jdk>` condition `spec` with its outcome, if raeva.lock can hold
    /// the spec.
    pub fn jdk(spec: &str, holds: bool) -> Result<Self, InvalidAmbientInput> {
        if is_condition_text(spec) {
            Ok(Self::Condition {
                condition: HostCondition::Jdk(spec.to_string()),
                holds,
            })
        } else {
            Err(InvalidAmbientInput(format!("jdk:{spec}")))
        }
    }

    /// The `<property>` condition on `name` (with its `!`) expecting
    /// `value`, with its outcome, if raeva.lock can hold it.
    pub fn property(
        name: &str,
        value: Option<&str>,
        holds: bool,
    ) -> Result<Self, InvalidAmbientInput> {
        let property = name.strip_prefix('!').unwrap_or(name);
        let host = matches!(property, "java.version" | "java.home")
            || property.strip_prefix("env.").is_some_and(is_env_var_name);
        if host && value.is_none_or(is_condition_text) {
            Ok(Self::Condition {
                condition: HostCondition::Property {
                    name: name.to_string(),
                    value: value.map(str::to_string),
                },
                holds,
            })
        } else {
            Err(InvalidAmbientInput(format!(
                "property:{name}{}",
                value.map(|value| format!("={value}")).unwrap_or_default()
            )))
        }
    }

    /// Whether the project path `path` exists, if raeva.lock can hold the
    /// path.
    pub fn file(path: &str, exists: bool) -> Result<Self, InvalidAmbientInput> {
        if is_project_path(path) {
            Ok(Self::Condition {
                condition: HostCondition::File(path.to_string()),
                holds: exists,
            })
        } else {
            Err(InvalidAmbientInput(format!("file:{path}")))
        }
    }

    /// The settings.xml condition named `key` with its outcome, if `key` is
    /// a settings condition key.
    pub fn settings(key: &str, holds: bool) -> Result<Self, InvalidAmbientInput> {
        // A settings condition key is 16 lowercase hex digits.
        let key_ok = key.len() == 16
            && key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if key_ok {
            Ok(Self::Condition {
                condition: HostCondition::Settings(key.to_string()),
                holds,
            })
        } else {
            Err(InvalidAmbientInput(format!("settings:{key}")))
        }
    }
}

impl HostCondition {
    fn pieces(&self) -> [&str; 4] {
        match self {
            Self::Jdk(spec) => ["jdk:", spec, "", ""],
            Self::File(path) => ["file:", path, "", ""],
            Self::Settings(key) => ["settings:", key, "", ""],
            Self::Property { name, value: None } => ["property:", name, "", ""],
            Self::Property {
                name,
                value: Some(value),
            } => ["property:", name, "=", value],
        }
    }
}

impl fmt::Display for HostCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.pieces()
            .iter()
            .try_for_each(|piece| f.write_str(piece))
    }
}

impl AmbientInput {
    fn pieces(&self) -> [&str; 6] {
        match self {
            Self::Env(name) => ["env.", name, "", "", "", ""],
            Self::JavaHome => ["java.home", "", "", "", "", ""],
            Self::JavaVersion => ["java.version", "", "", "", "", ""],
            Self::OsRelease => ["os-release", "", "", "", "", ""],
            Self::SettingsProperty(name) => ["settings-property:", name, "", "", "", ""],
            Self::UserProperty(name) => ["user-property:", name, "", "", "", ""],
            Self::UserPropertyLookup(template) => {
                ["user-property-lookup:", template, "", "", "", ""]
            }
            Self::Condition { condition, holds } => {
                let [a, b, c, d] = condition.pieces();
                let holds = if *holds { " is true" } else { " is false" };
                [a, b, c, d, holds, ""]
            }
        }
    }
}

impl fmt::Display for AmbientInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.pieces()
            .iter()
            .try_for_each(|piece| f.write_str(piece))
    }
}

impl Ord for AmbientInput {
    /// The order of the texts, compared a run of bytes at a time: lock
    /// writing and merging compare many names.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let (ours, theirs) = (self.pieces(), other.pieces());
        let (mut ours, mut theirs) = (
            ours.iter().map(|piece| piece.as_bytes()),
            theirs.iter().map(|piece| piece.as_bytes()),
        );
        let (mut a, mut b): (&[u8], &[u8]) = (&[], &[]);
        loop {
            while a.is_empty()
                && let Some(next) = ours.next()
            {
                a = next;
            }
            while b.is_empty()
                && let Some(next) = theirs.next()
            {
                b = next;
            }
            if a.is_empty() || b.is_empty() {
                return a.len().cmp(&b.len());
            }
            let n = a.len().min(b.len());
            match a[..n].cmp(&b[..n]) {
                std::cmp::Ordering::Equal => (a, b) = (&a[n..], &b[n..]),
                order => return order,
            }
        }
    }
}

impl PartialOrd for AmbientInput {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for AmbientInput {
    type Err = InvalidAmbientInput;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidAmbientInput(value.to_string());
        match value {
            "java.home" => return Ok(Self::JavaHome),
            "java.version" => return Ok(Self::JavaVersion),
            "os-release" => return Ok(Self::OsRelease),
            _ => {}
        }
        if let Some(name) = value.strip_prefix("user-property:") {
            return Self::user_property(name).map_err(|_| invalid());
        }
        if let Some(template) = value.strip_prefix("user-property-lookup:") {
            return rv_config::maven_config::PropertyLookup::parse(template)
                .filter(|_| is_terminal_safe(template))
                .map(|lookup| Self::UserPropertyLookup(lookup.encode()))
                .ok_or_else(invalid);
        }
        if let Some(name) = value.strip_prefix("env.") {
            return Self::env(name).map_err(|_| invalid());
        }
        if let Some(name) = value.strip_prefix("settings-property:") {
            return Self::settings_property(name).map_err(|_| invalid());
        }
        let (condition, holds) = value.rsplit_once(" is ").ok_or_else(invalid)?;
        let holds = match holds {
            "true" => true,
            "false" => false,
            _ => return Err(invalid()),
        };
        let parsed = if let Some(spec) = condition.strip_prefix("jdk:") {
            Self::jdk(spec, holds)
        } else if let Some(path) = condition.strip_prefix("file:") {
            Self::file(path, holds)
        } else if let Some(key) = condition.strip_prefix("settings:") {
            Self::settings(key, holds)
        } else if let Some(property) = condition.strip_prefix("property:") {
            match property.split_once('=') {
                Some((name, expected)) => Self::property(name, Some(expected), holds),
                None => Self::property(property, None, holds),
            }
        } else {
            return Err(invalid());
        };
        parsed.map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indirect_property_lookup_templates_round_trip_without_external_values() {
        let input = AmbientInput::user_property_lookup(
            "${alias}",
            &[("alias".into(), "${selector}".into())].into(),
            None,
            rv_config::maven_config::PropertySource::User,
        );
        assert_eq!(input.to_string().parse::<AmbientInput>().unwrap(), input);
        for base_dir in [None, Some("module".into())] {
            let file = AmbientInput::file_lookup(
                "${activation.path}",
                &Default::default(),
                base_dir,
                None,
                rv_config::maven_config::PropertySource::User,
            );
            assert_eq!(file.to_string().parse::<AmbientInput>().unwrap(), file);
        }
        assert!(
            "user-property-lookup:invalid"
                .parse::<AmbientInput>()
                .is_err()
        );
    }

    #[test]
    fn inputs_round_trip_and_sort_as_text() {
        let names = [
            "env.A_1",
            "env.CI",
            "file:.git/HEAD is false",
            "file:a/../shared.txt is false",
            "file:mod b/is true is true",
            "java.home",
            "java.version",
            "jdk:1.8 is false",
            "jdk:[1.8, 11) is true",
            "jdk:x is true is false",
            "os-release",
            "property:!env.CI is true",
            "property:env.CI=yes=no is false",
            "property:java.home is true",
            "settings-property:a_b-1.2",
            "settings:0123456789abcdef is true",
        ];
        let parsed: Vec<AmbientInput> = names.iter().map(|name| name.parse().unwrap()).collect();
        let mut sorted = parsed.clone();
        sorted.sort();
        assert_eq!(parsed, sorted);
        for a in &parsed {
            for b in &parsed {
                assert_eq!(a.cmp(b), a.to_string().cmp(&b.to_string()), "{a} {b}");
            }
        }
        assert_eq!(
            parsed.iter().map(ToString::to_string).collect::<Vec<_>>(),
            names
        );
        assert_eq!(
            parsed[4],
            AmbientInput::file("mod b/is true", true).unwrap()
        );
        assert_eq!(
            parsed[9],
            AmbientInput::Condition {
                condition: HostCondition::Jdk("x is true".to_string()),
                holds: false,
            }
        );
        assert_eq!(
            parsed[12],
            AmbientInput::property("env.CI", Some("yes=no"), false).unwrap()
        );
        let widest = format!("jdk:{} is true", "\u{e9}".repeat(MAX_CONDITION_TEXT_LEN));
        assert!(widest.parse::<AmbientInput>().is_ok());
    }

    #[test]
    fn unknown_kinds_bad_names_and_bad_conditions_are_refused() {
        let long = format!("jdk:{} is true", "1".repeat(MAX_CONDITION_TEXT_LEN + 1));
        for bad in [
            "",
            "java.vendor",
            "JAVA_HOME",
            "env.",
            "env.1A",
            "env.A-B",
            "env.A\u{202e}",
            " java.home",
            "jdk:[17,)",
            "jdk:[17,) is yes",
            "jdk: is true",
            "jdk:1\u{7} is true",
            "property:env.CI=\u{200b}yes is true",
            "property:os.name is true",
            "property:!!env.CI is true",
            "property:env.CI= is true",
            "os:linux is true",
            "file:/etc/passwd is true",
            "file:../x is true",
            "file:a/../../x is true",
            "file:a//b is true",
            "file:./a is true",
            "file:a\\b is true",
            "file:C:x is true",
            "file: is true",
            "settings:0123456789ABCDEF is true",
            "settings:0123456789abcde is true",
            "settings-property:",
            "settings-property:a/b",
            "settings-property:a b",
            long.as_str(),
        ] {
            let err = bad.parse::<AmbientInput>().expect_err(bad).to_string();
            assert!(!err.chars().any(char::is_control), "{err}");
        }
        assert!(AmbientInput::env(&"A".repeat(256)).is_err());
        assert!(AmbientInput::settings_property(&"a".repeat(129)).is_err());
        assert!(AmbientInput::jdk("1\n", true).is_err());
        assert!(AmbientInput::property("java.version", Some(""), true).is_err());
    }
}
