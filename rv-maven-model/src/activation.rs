use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rv_version::{Version, VersionReq};

#[derive(Debug, Clone, Default)]
pub struct ActivationContext {
    pub properties: HashMap<String, String>,
    pub os_name: Option<String>,
    pub os_family: Option<String>,
    pub os_arch: Option<String>,
    pub os_version: Option<String>,
    pub jdk_version: Option<String>,
    pub base_dir: Option<PathBuf>,
    pub local_repository: Option<PathBuf>,
    pub active_profiles: Vec<String>,
    pub inactive_profiles: Vec<String>,
}

impl ActivationContext {
    /// Build an activation context from the host environment.
    ///
    /// Populates only well-known OS / JVM-equivalent properties (`os.name`,
    /// `os.family`, `os.arch`, `os.version`, `java.home`, `java.version`).
    /// Other host environment variables are NOT mixed into `properties`:
    /// doing so would let `<activation><property><name>X</name>` (without
    /// the `env.` prefix) match any host env var, including secrets such as
    /// `AWS_SECRET_ACCESS_KEY` or `GITHUB_TOKEN`. Profile activations that
    /// genuinely need an environment variable still work through the
    /// `env.NAME` lookup path (see `property_active`), which reads
    /// `std::env::var` directly.
    pub fn from_system() -> Self {
        let mut properties: HashMap<String, String> = HashMap::new();
        let os_name = Some(rust_os_to_maven_name(std::env::consts::OS).to_string());
        let os_arch = Some(std::env::consts::ARCH.to_string());
        let os_family = detect_family(std::env::consts::OS).map(str::to_string);
        // SECURITY: Maven's `os.version` is JVM-supplied (`System.getProperty`).
        // Honouring a host env var here would let a third-party POM activate
        // a profile based on an attacker-controlled value (e.g. CI exporting
        // `OS_VERSION=…` for an unrelated purpose). Leave it unset until
        // platform detection is genuinely available.
        let os_version: Option<String> = None;
        let base_dir = std::env::current_dir().ok();

        let java_home = std::env::var("JAVA_HOME").ok();
        let jdk_version = java_home
            .as_deref()
            .and_then(|home| parse_java_release(Path::new(home)));
        let jdk_version = jdk_version.or_else(|| std::env::var("JAVA_VERSION").ok());

        if let Some(value) = os_name.as_ref() {
            properties.insert("os.name".to_string(), value.clone());
        }
        if let Some(value) = os_family.as_ref() {
            properties.insert("os.family".to_string(), value.clone());
        }
        if let Some(value) = os_arch.as_ref() {
            properties.insert("os.arch".to_string(), value.clone());
        }
        if let Some(value) = os_version.as_ref() {
            properties.insert("os.version".to_string(), value.clone());
        }
        if let Some(value) = java_home.as_ref() {
            properties.insert("java.home".to_string(), value.clone());
        }
        if let Some(value) = jdk_version.as_ref() {
            properties.insert("java.version".to_string(), value.clone());
        }

        ActivationContext {
            properties,
            os_name,
            os_family,
            os_arch,
            os_version,
            jdk_version,
            base_dir,
            local_repository: None,
            active_profiles: Vec::new(),
            inactive_profiles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivationProperty {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivationOs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivationFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exists: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activation {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub active_by_default: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<ActivationProperty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<ActivationOs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jdk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<ActivationFile>,
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
    /// Use [`evaluate_profiles`] for the cross-profile, suppression-aware
    /// answer when computing the active profile set for an effective POM.
    pub fn is_active(&self, ctx: &ActivationContext) -> bool {
        // `<activeByDefault>true</activeByDefault>` activates the profile in
        // isolation. POM-level suppression lives in `evaluate_profiles`.
        if self.active_by_default {
            return true;
        }

        if !self.has_explicit_condition() {
            return false;
        }

        self.explicit_conditions_active(ctx)
    }

    /// Returns whether this activation block's EXPLICIT conditions
    /// (property / os / jdk / file) all match, WITHOUT the
    /// `activeByDefault` short-circuit.
    ///
    /// [`evaluate_profiles`]'s first pass must use this rather than
    /// [`Activation::is_active`]: a profile carrying both
    /// `<activeByDefault>true</activeByDefault>` AND an explicit condition
    /// that does NOT match must not be treated as condition-activated. The
    /// `is_active` short-circuit would otherwise report `true` purely on the
    /// default flag, wrongly promoting the profile and suppressing the other
    /// genuine `activeByDefault` profiles in the same POM.
    ///
    /// If no explicit condition is present this returns `false` (there is
    /// nothing to satisfy).
    fn explicit_conditions_active(&self, ctx: &ActivationContext) -> bool {
        if !self.has_explicit_condition() {
            return false;
        }

        if let Some(property) = &self.property
            && !property_active(property, ctx)
        {
            return false;
        }

        if let Some(os) = &self.os
            && !os_active(os, ctx)
        {
            return false;
        }

        if let Some(jdk) = &self.jdk
            && !jdk_active(jdk, ctx)
        {
            return false;
        }

        if let Some(file) = &self.file
            && !file_active(file, ctx)
        {
            return false;
        }

        true
    }

    /// Returns whether this activation block contains at least one explicit
    /// condition (property / os / jdk / file). Used by [`evaluate_profiles`]
    /// to detect a condition-activated profile that suppresses the
    /// active-by-default fallback.
    fn has_explicit_condition(&self) -> bool {
        self.property.is_some() || self.os.is_some() || self.jdk.is_some() || self.file.is_some()
    }
}

/// Evaluate a POM's profiles against the activation context, applying Maven's
/// suppression rule for `<activeByDefault>`.
///
/// The Maven spec: an `activeByDefault` profile contributes ONLY when no
/// other profile in the same POM is activated by an explicit condition
/// (property/os/jdk/file) or by command-line selection. Maven runs profile
/// selection per raw model in the inheritance lineage, so the suppression is
/// scoped to one POM's profiles: a child profile activating must not suppress
/// the parent's default profile, nor the reverse. The profiles here arrive as
/// the inheritance-merged pool, so the grouping key is `Profile::origin_level`
/// (which POM in the lineage declared the profile). Callers should use this
/// function instead of invoking [`Activation::is_active`] per profile.
///
/// Inputs:
/// - `profiles`: every profile declared across the POM's lineage. The order
///   is preserved in the returned set.
/// - `ctx`: activation context (system info plus explicit `active_profiles` /
///   `inactive_profiles` selections from `-P` / `-!P`).
///
/// Returns the subset of `profiles` that are active in this context, in
/// declaration order.
pub(crate) fn evaluate_profiles<'a>(
    profiles: &'a [crate::Profile],
    ctx: &ActivationContext,
) -> Vec<&'a crate::Profile> {
    use std::collections::HashSet;

    let explicit_active: HashSet<&str> = ctx.active_profiles.iter().map(String::as_str).collect();
    let explicit_inactive: HashSet<&str> =
        ctx.inactive_profiles.iter().map(String::as_str).collect();

    // First pass: profiles activated by explicit `-P` selection or by a
    // condition other than `activeByDefault`. The `activeByDefault` fallback
    // is delayed until we know, PER ORIGIN POM, whether anything else in
    // that same POM activated.
    let mut active: Vec<&crate::Profile> = Vec::new();
    let mut activated_levels: HashSet<u32> = HashSet::new();
    for profile in profiles {
        let id = profile.id.as_str();
        if explicit_inactive.contains(id) {
            continue;
        }
        let activated = explicit_active.contains(id)
            || profile
                .activation
                .as_ref()
                .is_some_and(|act| act.explicit_conditions_active(ctx));
        if activated {
            active.push(profile);
            activated_levels.insert(profile.origin_level);
        }
    }

    // Apply the suppression rule: promote `activeByDefault` profiles of a
    // POM only when nothing else from that same POM activated. Matches
    // Maven's `DefaultProfileSelector` run per model.
    //
    // A profile carrying BOTH `<activeByDefault>true</activeByDefault>` AND an
    // explicit condition is only eligible for the default fallback when that
    // explicit condition actually matches: a default profile gated on, say, a
    // `<property>` that is absent must not slip in via the default path. (It
    // already failed the first pass; promoting it here would re-introduce the
    // bug from the opposite direction.)
    let defaults: Vec<&crate::Profile> = profiles
        .iter()
        .filter(|profile| {
            let id = profile.id.as_str();
            if explicit_inactive.contains(id) || activated_levels.contains(&profile.origin_level) {
                return false;
            }
            profile.activation.as_ref().is_some_and(|act| {
                act.active_by_default
                    && (!act.has_explicit_condition() || act.explicit_conditions_active(ctx))
            })
        })
        .collect();

    if defaults.is_empty() {
        return active;
    }

    // Re-walk in declaration order so the merged result keeps the original
    // ordering regardless of which pass admitted each profile.
    let chosen: HashSet<*const crate::Profile> = active
        .iter()
        .chain(defaults.iter())
        .map(|p| *p as *const crate::Profile)
        .collect();
    profiles
        .iter()
        .filter(|p| chosen.contains(&(*p as *const crate::Profile)))
        .collect()
}

/// Returns true if `name` is permitted to drive profile activation via an
/// `env.NAME` `<property>` condition. Mirrors the gate `properties.rs`
/// applies to `${env.NAME}` interpolation: the operator must have installed
/// an allowlist (via `set_env_substitution_allowlist`) containing `name`.
/// When no allowlist is set, this fails closed.
fn env_var_allowlisted(name: &str) -> bool {
    crate::env_substitution_allowlist()
        .map(|list| list.iter().any(|allowed| allowed == name))
        .unwrap_or(false)
}

fn property_active(property: &ActivationProperty, ctx: &ActivationContext) -> bool {
    let Some(name) = property
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };

    let (negated, actual_name) = match name.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, name),
    };
    let actual_name = actual_name.trim();
    if actual_name.is_empty() {
        return false;
    }

    let resolved = if let Some(stripped) = actual_name.strip_prefix("env.") {
        let key = stripped.trim();
        if key.is_empty() || !env_var_allowlisted(key) {
            // Supply-chain hardening: refuse to key a profile off a host
            // environment variable unless the operator explicitly added it
            // to the `${env.*}` substitution allowlist (the same gate that
            // properties.rs applies to `${env.NAME}` interpolation). Without
            // this, any transitive POM author could toggle profiles based on
            // host secrets such as AWS_SECRET_ACCESS_KEY or GITHUB_TOKEN.
            // Treat a non-allowlisted variable as absent.
            None
        } else {
            std::env::var(key).ok()
        }
    } else {
        ctx.properties.get(actual_name).cloned()
    };
    // Treat a present-but-blank value as absent (matches Maven, which keys on
    // `System.getProperty` returning a meaningful value).
    let resolved = resolved.filter(|value| !value.trim().is_empty());

    // Maven's `PropertyProfileActivator` semantics: when a non-empty `<value>`
    // is supplied the `!` prefix on the NAME is ignored; only the value
    // comparison (which has its own `!` prefix for "not equal to") decides
    // activation. The name's `!` prefix only matters in the value-less form,
    // where it flips presence ("activate when the property is NOT set").
    match property
        .value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(expected) => {
            let (value_negated, expected) = match expected.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, expected),
            };
            let equals = resolved.as_deref() == Some(expected);
            value_negated != equals
        }
        None => {
            let present = resolved.is_some();
            negated != present
        }
    }
}

fn os_active(os: &ActivationOs, ctx: &ActivationContext) -> bool {
    let matches_name = matches_os_field(os.name.as_deref(), ctx.os_name.as_deref());
    let matches_arch = matches_os_field(os.arch.as_deref(), ctx.os_arch.as_deref());
    let matches_version = matches_os_field(os.version.as_deref(), ctx.os_version.as_deref());
    let matches_family = matches_os_family(os.family.as_deref(), ctx);

    matches_name && matches_arch && matches_version && matches_family
}

fn matches_os_field(expected: Option<&str>, actual: Option<&str>) -> bool {
    let Some(expected) = expected.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    // Maven honours a leading `!` to negate the os name/arch/version match,
    // e.g. <name>!windows</name> means "active when os.name is NOT windows".
    let (negated, expected) = match expected.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, expected),
    };
    if expected.is_empty() {
        // `<name>!</name>` has no field to compare against.
        return false;
    }
    let Some(actual) = actual.map(str::trim).filter(|value| !value.is_empty()) else {
        // Field unknown in the context (e.g. `os.version`, which raeva leaves
        // unset). Neither a positive nor a negated condition can be confirmed,
        // so fail closed rather than spuriously activating on `!something`.
        return false;
    };
    // Maven uses case-insensitive equality after stripping spaces.
    // e.g. "Linux" matches "linux", "Mac OS X" matches "mac os x".
    let normalize = |s: &str| s.to_ascii_lowercase().replace(' ', "");
    let matched = normalize(actual) == normalize(expected);
    matched ^ negated
}

fn matches_os_family(expected: Option<&str>, ctx: &ActivationContext) -> bool {
    let Some(expected) = expected.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    // Maven honours a leading `!` to negate the family match, e.g.
    // <family>!windows</family> means "active when the OS family is NOT
    // windows".
    let (negated, expected) = match expected.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, expected),
    };
    if expected.is_empty() {
        return false;
    }

    let expected = normalize_family(expected);
    let ctx_family = ctx
        .os_family
        .as_deref()
        .and_then(normalize_family)
        .or_else(|| ctx.os_name.as_deref().and_then(detect_family));

    // The host family is unknown: fail closed for both the positive and the
    // negated form rather than spuriously activating on `!something`.
    if ctx_family.is_none() {
        return false;
    }

    let matched = match (expected, ctx_family) {
        (Some("unix"), Some("unix" | "mac")) => true,
        (Some("mac"), Some("mac")) => true,
        (Some("windows"), Some("windows")) => true,
        (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
        _ => false,
    };
    matched ^ negated
}

fn jdk_active(jdk: &str, ctx: &ActivationContext) -> bool {
    let req = jdk.trim();
    if req.is_empty() {
        return false;
    }

    // Support `!`-negation prefix: `!17` means "activate when JDK is NOT 17".
    if let Some(negated) = req.strip_prefix('!') {
        let Some(found) = ctx
            .jdk_version
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            // No JDK version known; cannot confirm the condition, treat as inactive.
            return false;
        };
        return !jdk_matches(negated, found);
    }

    let Some(found) = ctx
        .jdk_version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        return false;
    };

    jdk_matches(req, found)
}

/// Check whether `req` (a JDK version requirement string without the `!` prefix)
/// matches `actual` (the concrete JDK version string).
fn jdk_matches(req: &str, actual: &str) -> bool {
    if req.starts_with('[') || req.starts_with('(') {
        let Ok(requirement) = VersionReq::parse(req) else {
            return false;
        };
        let Ok(version) = Version::parse(actual) else {
            return false;
        };
        requirement.matches(&version)
    } else {
        actual.starts_with(req)
    }
}

fn file_active(file: &ActivationFile, ctx: &ActivationContext) -> bool {
    if let Some(path) = file
        .exists
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && !resolve_path(path, ctx.base_dir.as_deref()).exists()
    {
        return false;
    }

    if let Some(path) = file
        .missing
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && resolve_path(path, ctx.base_dir.as_deref()).exists()
    {
        return false;
    }

    true
}

fn resolve_path(path: &str, base_dir: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(path);
    match base_dir {
        Some(base) if !path.is_absolute() => base.join(path),
        _ => path,
    }
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    // The os-family detection tokens are ASCII, so an ASCII-lowercase fold of
    // both sides plus the standard substring search gives a case-insensitive
    // match without a hand-rolled byte scan.
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Maps Rust OS names to Maven/JVM-equivalent os.name values.
/// Maven profiles use JVM `os.name` system property values, which differ
/// from Rust's `std::env::consts::OS`.
fn rust_os_to_maven_name(rust_os: &str) -> &str {
    match rust_os {
        "macos" => "mac os x",
        "linux" => "linux",
        "windows" => "windows",
        "freebsd" => "freebsd",
        "openbsd" => "openbsd",
        "netbsd" => "netbsd",
        "solaris" | "illumos" => "sunos",
        "aix" => "aix",
        _ => rust_os,
    }
}

fn detect_family(os_name: &str) -> Option<&'static str> {
    if contains_ignore_ascii_case(os_name, "windows") {
        Some("windows")
    } else if contains_ignore_ascii_case(os_name, "mac")
        || contains_ignore_ascii_case(os_name, "darwin")
    {
        Some("mac")
    } else if contains_ignore_ascii_case(os_name, "unix")
        || contains_ignore_ascii_case(os_name, "linux")
        || contains_ignore_ascii_case(os_name, "aix")
        || contains_ignore_ascii_case(os_name, "bsd")
        || contains_ignore_ascii_case(os_name, "sunos")
    {
        Some("unix")
    } else {
        None
    }
}

fn normalize_family(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower == "windows" || lower == "win" || lower.starts_with("windows") {
        Some("windows")
    } else if lower == "mac"
        || lower == "macos"
        || lower == "osx"
        || lower == "darwin"
        || lower == "mac os x"
    {
        Some("mac")
    } else if lower == "unix"
        || lower == "linux"
        || lower == "aix"
        || lower == "freebsd"
        || lower == "openbsd"
        || lower == "netbsd"
        || lower == "sunos"
    {
        Some("unix")
    } else {
        None
    }
}

fn parse_java_release(java_home: &Path) -> Option<String> {
    let release_path = java_home.join("release");
    let contents = std::fs::read_to_string(release_path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix("JAVA_VERSION=") else {
            continue;
        };
        let value = value.trim();
        return Some(strip_quotes(value));
    }
    None
}

fn strip_quotes(value: &str) -> String {
    let trimmed = value.trim();
    // Check for double quotes
    if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return inner.to_string();
    }
    // Check for single quotes
    if let Some(inner) = trimmed
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
    {
        return inner.to_string();
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises the tests in THIS module that mutate the process-wide
    /// `${env.*}` allowlist so they do not race each other. (The allowlist is
    /// global crate state shared with `properties.rs`; cross-file races are an
    /// existing property of that design, but at least our own tests stay
    /// deterministic relative to one another.)
    static ENV_ALLOWLIST_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn parses_activation() {
        let xml = r"
        <activation>
          <activeByDefault>true</activeByDefault>
          <property>
            <name>foo</name>
            <value>bar</value>
          </property>
          <os>
            <name>Linux</name>
            <family>unix</family>
            <arch>x86_64</arch>
            <version>5.0</version>
          </os>
          <jdk>17</jdk>
          <file>
            <exists>pom.xml</exists>
            <missing>missing.txt</missing>
          </file>
        </activation>
        ";
        let activation: Activation = quick_xml::de::from_str(xml).unwrap();
        assert!(activation.active_by_default);
        assert_eq!(activation.property.unwrap().name.as_deref(), Some("foo"));
        assert_eq!(activation.os.unwrap().arch.as_deref(), Some("x86_64"));
        assert_eq!(activation.jdk.as_deref(), Some("17"));
        assert_eq!(activation.file.unwrap().exists.as_deref(), Some("pom.xml"));
    }

    #[test]
    fn property_activation_matches_value() {
        let activation = Activation {
            active_by_default: false,
            property: Some(ActivationProperty {
                name: Some("feature".to_string()),
                value: Some("on".to_string()),
            }),
            os: None,
            jdk: None,
            file: None,
        };
        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("feature".to_string(), "on".to_string());
        assert!(activation.is_active(&ctx));
    }

    #[test]
    fn property_activation_matches_env_namespace() {
        let _guard = ENV_ALLOWLIST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = format!("RAEVA_TEST_ENV_{}", unique_suffix());
        temp_env::with_var(&key, Some("on"), || {
            // The env var must be on the substitution allowlist for it to
            // drive profile activation (same gate as `${env.X}` interpolation).
            crate::set_env_substitution_allowlist(vec![key.clone()]);
            let activation = Activation {
                active_by_default: false,
                property: Some(ActivationProperty {
                    name: Some(format!("env.{key}")),
                    value: Some("on".to_string()),
                }),
                os: None,
                jdk: None,
                file: None,
            };
            let ctx = ActivationContext::default();
            assert!(activation.is_active(&ctx));
            crate::properties::reset_env_substitution_allowlist_for_tests();
        });
    }

    // Security: an `env.X` profile condition must NOT activate when the
    // host env var is not on the substitution allowlist, even if the variable
    // is set in the environment. Otherwise a transitive POM author could key a
    // profile off host secrets (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, ...).
    #[test]
    fn env_property_activation_requires_allowlist() {
        let _guard = ENV_ALLOWLIST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = format!("RAEVA_TEST_ENV_DENIED_{}", unique_suffix());
        temp_env::with_var(&key, Some("on"), || {
            // Allowlist a DIFFERENT key so the policy is installed but does
            // not cover the variable under test (fail-closed otherwise).
            crate::set_env_substitution_allowlist(vec!["RAEVA_SOME_OTHER_VAR".to_string()]);
            let activation = Activation {
                active_by_default: false,
                property: Some(ActivationProperty {
                    name: Some(format!("env.{key}")),
                    value: Some("on".to_string()),
                }),
                os: None,
                jdk: None,
                file: None,
            };
            let ctx = ActivationContext::default();
            assert!(
                !activation.is_active(&ctx),
                "non-allowlisted env var must not drive profile activation"
            );

            // Even a value-less env condition (`env.X` present?) must not
            // activate for a non-allowlisted variable.
            let presence = Activation {
                active_by_default: false,
                property: Some(ActivationProperty {
                    name: Some(format!("env.{key}")),
                    value: None,
                }),
                os: None,
                jdk: None,
                file: None,
            };
            assert!(
                !presence.is_active(&ctx),
                "non-allowlisted env var must not satisfy a value-less env condition"
            );
            crate::properties::reset_env_substitution_allowlist_for_tests();
        });
    }

    #[test]
    fn property_activation_supports_negation() {
        let activation = Activation {
            active_by_default: false,
            property: Some(ActivationProperty {
                name: Some("!skipTests".to_string()),
                value: None,
            }),
            os: None,
            jdk: None,
            file: None,
        };
        let ctx = ActivationContext::default();
        assert!(activation.is_active(&ctx));

        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("skipTests".to_string(), "true".to_string());
        assert!(!activation.is_active(&ctx));
    }

    #[test]
    fn os_activation_matches_fields() {
        let activation = Activation {
            active_by_default: false,
            property: None,
            os: Some(ActivationOs {
                name: Some("linux".to_string()),
                family: Some("unix".to_string()),
                arch: Some("x86_64".to_string()),
                version: None,
            }),
            jdk: None,
            file: None,
        };
        let ctx = ActivationContext {
            properties: HashMap::new(),
            os_name: Some("Linux".to_string()),
            os_family: Some("unix".to_string()),
            os_arch: Some("X86_64".to_string()),
            os_version: None,
            jdk_version: None,
            base_dir: None,
            local_repository: None,
            active_profiles: Vec::new(),
            inactive_profiles: Vec::new(),
        };
        assert!(activation.is_active(&ctx));
    }

    #[test]
    fn jdk_activation_matches_range() {
        let activation = Activation {
            active_by_default: false,
            property: None,
            os: None,
            jdk: Some("[17,)".to_string()),
            file: None,
        };
        let ctx = ActivationContext {
            properties: HashMap::new(),
            os_name: None,
            os_family: None,
            os_arch: None,
            os_version: None,
            jdk_version: Some("17.0.1".to_string()),
            base_dir: None,
            local_repository: None,
            active_profiles: Vec::new(),
            inactive_profiles: Vec::new(),
        };
        assert!(activation.is_active(&ctx));
    }

    #[test]
    fn file_activation_checks_base_dir() {
        let base_tmp = tempfile::tempdir().unwrap();
        let base_dir = base_tmp.path();
        let exists_path = base_dir.join("exists.txt");
        std::fs::write(&exists_path, b"ok").unwrap();

        let activation = Activation {
            active_by_default: false,
            property: None,
            os: None,
            jdk: None,
            file: Some(ActivationFile {
                exists: Some("exists.txt".to_string()),
                missing: Some("missing.txt".to_string()),
            }),
        };
        let ctx = ActivationContext {
            properties: HashMap::new(),
            os_name: None,
            os_family: None,
            os_arch: None,
            os_version: None,
            jdk_version: None,
            base_dir: Some(base_dir.to_path_buf()),
            local_repository: None,
            active_profiles: Vec::new(),
            inactive_profiles: Vec::new(),
        };
        assert!(activation.is_active(&ctx));
    }

    // JDK negation prefix `!`
    #[test]
    fn jdk_negation_inactive_when_version_matches() {
        // `!17` with JDK 17 → NOT active.
        let activation = Activation {
            active_by_default: false,
            property: None,
            os: None,
            jdk: Some("!17".to_string()),
            file: None,
        };
        let ctx = ActivationContext {
            jdk_version: Some("17.0.8".to_string()),
            ..ActivationContext::default()
        };
        assert!(
            !activation.is_active(&ctx),
            "!17 should NOT be active with JDK 17"
        );
    }

    #[test]
    fn jdk_negation_active_when_version_differs() {
        // `!17` with JDK 21 → active.
        let activation = Activation {
            active_by_default: false,
            property: None,
            os: None,
            jdk: Some("!17".to_string()),
            file: None,
        };
        let ctx = ActivationContext {
            jdk_version: Some("21.0.1".to_string()),
            ..ActivationContext::default()
        };
        assert!(
            activation.is_active(&ctx),
            "!17 should be active with JDK 21"
        );
    }

    #[test]
    fn jdk_positive_prefix_still_works() {
        // `17` with JDK 17 → active (positive prefix match, no regression).
        let activation = Activation {
            active_by_default: false,
            property: None,
            os: None,
            jdk: Some("17".to_string()),
            file: None,
        };
        let ctx = ActivationContext {
            jdk_version: Some("17.0.8".to_string()),
            ..ActivationContext::default()
        };
        assert!(
            activation.is_active(&ctx),
            "17 should be active with JDK 17"
        );
    }

    // OS field uses normalized equality, not bidirectional substring match.
    #[test]
    fn os_field_matches_case_insensitive_equality() {
        // "Linux" (actual) vs "linux" (expected); must match.
        assert!(super::matches_os_field(Some("linux"), Some("Linux")));
        // "mac os x" (actual) vs "Mac OS X" (expected); must match.
        assert!(super::matches_os_field(Some("Mac OS X"), Some("mac os x")));
    }

    #[test]
    fn os_field_does_not_match_substring() {
        // The Maven spec requires equality, not a bidirectional substring
        // match, so "mac" must NOT match "Mac OS X".
        assert!(
            !super::matches_os_field(Some("mac"), Some("Mac OS X")),
            "'mac' should NOT match 'Mac OS X' under equality semantics"
        );
        assert!(
            !super::matches_os_field(Some("windows"), Some("Windows 10")),
            "'windows' should NOT match 'Windows 10' under equality semantics"
        );
    }

    // `<activeByDefault>true</activeByDefault>` on its own must activate the
    // profile, even when none of `property`, `os`, `jdk`, `file` are present.
    #[test]
    fn active_by_default_alone_activates_profile() {
        let activation = Activation {
            active_by_default: true,
            property: None,
            os: None,
            jdk: None,
            file: None,
        };
        let ctx = ActivationContext::default();
        assert!(
            activation.is_active(&ctx),
            "<activeByDefault>true</activeByDefault> alone must activate the profile"
        );
    }

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    }

    // Regression for the OS_VERSION env-var profile-activation hole:
    // `ActivationContext::from_system` must not populate `os.version` from
    // a host env var. Doing so would let a third-party POM key a profile off
    // a value an attacker can set in CI, so the context ignores it.
    #[test]
    fn from_system_ignores_os_version_env_var() {
        temp_env::with_var("OS_VERSION", Some("99.99-MALICIOUS"), || {
            let ctx = ActivationContext::from_system();
            assert!(
                ctx.os_version.is_none(),
                "OS_VERSION env var must not leak into activation context"
            );
            assert!(
                !ctx.properties.contains_key("os.version"),
                "os.version property must not be populated from OS_VERSION env var"
            );
        });
    }

    fn profile_from_xml(xml: &str) -> crate::Profile {
        quick_xml::de::from_str(xml).expect("profile parses")
    }

    // A profile with BOTH `<activeByDefault>true</activeByDefault>`
    // AND a non-matching explicit `<property>` condition must NOT be
    // condition-activated in `evaluate_profiles`' first pass. If it were, it
    // would wrongly suppress the OTHER genuine activeByDefault profile in the
    // same POM. Maven evaluates the explicit conditions independently of the
    // default flag.
    #[test]
    fn active_by_default_with_failing_condition_does_not_suppress_other_default() {
        let with_failing_condition = profile_from_xml(
            r"
            <profile>
              <id>default-but-conditional</id>
              <activation>
                <activeByDefault>true</activeByDefault>
                <property>
                  <name>requiresThis</name>
                  <value>yes</value>
                </property>
              </activation>
            </profile>",
        );
        let plain_default = profile_from_xml(
            r"
            <profile>
              <id>plain-default</id>
              <activation>
                <activeByDefault>true</activeByDefault>
              </activation>
            </profile>",
        );
        // The property is NOT present, so the explicit condition fails.
        let ctx = ActivationContext::default();
        let profiles = [with_failing_condition, plain_default];
        let active = super::evaluate_profiles(&profiles, &ctx);
        let ids: Vec<&str> = active.iter().map(|p| p.id.as_str()).collect();

        assert!(
            !ids.contains(&"default-but-conditional"),
            "a default profile with a failing explicit condition must not be condition-activated"
        );
        assert!(
            ids.contains(&"plain-default"),
            "the genuine activeByDefault profile must not be suppressed by the other's stale condition"
        );
    }

    // Counterpart: when the explicit condition DOES match, the profile is
    // condition-activated and (per Maven) suppresses the other activeByDefault
    // profile in the same POM.
    #[test]
    fn active_by_default_with_matching_condition_suppresses_other_default() {
        let with_matching_condition = profile_from_xml(
            r"
            <profile>
              <id>default-but-conditional</id>
              <activation>
                <activeByDefault>true</activeByDefault>
                <property>
                  <name>requiresThis</name>
                  <value>yes</value>
                </property>
              </activation>
            </profile>",
        );
        let plain_default = profile_from_xml(
            r"
            <profile>
              <id>plain-default</id>
              <activation>
                <activeByDefault>true</activeByDefault>
              </activation>
            </profile>",
        );
        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("requiresThis".to_string(), "yes".to_string());
        let profiles = [with_matching_condition, plain_default];
        let active = super::evaluate_profiles(&profiles, &ctx);
        let ids: Vec<&str> = active.iter().map(|p| p.id.as_str()).collect();

        assert_eq!(
            ids,
            vec!["default-but-conditional"],
            "matching explicit condition activates and suppresses the plain default"
        );
    }

    // OS name/arch/family activation honours the Maven `!` negation
    // prefix.
    #[test]
    fn os_field_honours_negation_prefix() {
        // `!windows` is active when the OS is NOT windows.
        assert!(
            super::matches_os_field(Some("!windows"), Some("linux")),
            "'!windows' should match a non-windows OS"
        );
        assert!(
            !super::matches_os_field(Some("!linux"), Some("linux")),
            "'!linux' should NOT match linux"
        );
        // Arch negation likewise.
        assert!(super::matches_os_field(Some("!aarch64"), Some("x86_64")));
        assert!(!super::matches_os_field(Some("!x86_64"), Some("x86_64")));
    }

    #[test]
    fn os_family_honours_negation_prefix() {
        let linux_ctx = ActivationContext {
            os_name: Some("Linux".to_string()),
            os_family: Some("unix".to_string()),
            ..ActivationContext::default()
        };
        assert!(
            super::matches_os_family(Some("!windows"), &linux_ctx),
            "'!windows' family should match a unix host"
        );
        assert!(
            !super::matches_os_family(Some("!unix"), &linux_ctx),
            "'!unix' family should NOT match a unix host"
        );
    }

    // `!name` combined with a `<value>` follows Maven, where the
    // name's `!` is ignored and only the value comparison applies.
    #[test]
    fn property_negated_name_with_value_follows_maven() {
        // <name>!feature</name><value>on</value>: per Maven the name's `!`
        // is ignored; activate iff the resolved value equals "on".
        let activation = Activation {
            active_by_default: false,
            property: Some(ActivationProperty {
                name: Some("!feature".to_string()),
                value: Some("on".to_string()),
            }),
            os: None,
            jdk: None,
            file: None,
        };

        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("feature".to_string(), "on".to_string());
        assert!(
            activation.is_active(&ctx),
            "name '!' is ignored when a value is present; value matches → active"
        );

        let mut ctx_off = ActivationContext::default();
        ctx_off
            .properties
            .insert("feature".to_string(), "off".to_string());
        assert!(
            !activation.is_active(&ctx_off),
            "name '!' is ignored when a value is present; value differs → inactive"
        );
    }

    #[test]
    fn property_negated_value_semantics() {
        // <name>feature</name><value>!on</value>: active iff value is NOT "on".
        let activation = Activation {
            active_by_default: false,
            property: Some(ActivationProperty {
                name: Some("feature".to_string()),
                value: Some("!on".to_string()),
            }),
            os: None,
            jdk: None,
            file: None,
        };
        let mut ctx = ActivationContext::default();
        ctx.properties
            .insert("feature".to_string(), "off".to_string());
        assert!(activation.is_active(&ctx), "value '!on' matches 'off'");

        let mut ctx_on = ActivationContext::default();
        ctx_on
            .properties
            .insert("feature".to_string(), "on".to_string());
        assert!(
            !activation.is_active(&ctx_on),
            "value '!on' must not match 'on'"
        );
    }
}
