use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use indexmap::IndexMap;

use crate::PomError;

/// Process-wide allowlist of environment-variable names whose values may be
/// substituted into `${env.NAME}` POM property references.
///
/// Set once at startup by [`set_env_substitution_allowlist`] (typically from
/// `Config::security.allow_env_substitution`). When unset OR empty, `${env.*}`
/// substitution is **disabled**: any package author embedding `${env.SECRET}`
/// in a POM is otherwise able to read host environment variables via the
/// resolved value (lockfiles, error messages, cache keys).
///
/// Storage is `OnceLock<RwLock<Option<Vec<String>>>>`. The `OnceLock`
/// initializes the `RwLock` exactly once (so the synchronisation
/// primitive itself is shared and stable); the inner `Option<Vec<String>>`
/// then captures "uninitialised" vs "set to N entries (possibly empty)" so
/// a process that never calls `set_env_substitution_allowlist` still fails
/// closed.
///
/// `set_env_substitution_allowlist` overwrites the cell (last write wins). In
/// production the sole caller is `Config::load`, which runs once per CLI
/// invocation, so the policy is effectively installed once. Tests swap the
/// allowlist between scenarios and clear it back to "uninitialised" via the
/// `#[cfg(test)]` helper [`reset_env_substitution_allowlist_for_tests`].
static ENV_SUBSTITUTION_ALLOWLIST: OnceLock<RwLock<Option<Vec<String>>>> = OnceLock::new();

fn allowlist_cell() -> &'static RwLock<Option<Vec<String>>> {
    ENV_SUBSTITUTION_ALLOWLIST.get_or_init(|| RwLock::new(None))
}

/// Install the process-wide `${env.*}` substitution allowlist, replacing any
/// previously installed policy.
///
/// The sole production caller is `Config::load`, which runs once per CLI
/// invocation, so "overwrite" and "first-wins" are equivalent in practice.
/// Overwriting is what lets DOWNSTREAM-crate tests swap the allowlist
/// deterministically: `cfg!(test)` is evaluated in *this* crate's build, so
/// it is `false` when rv-maven-model is merely a dependency of another
/// crate's test binary. Without overwrite semantics, every set after the
/// first in such a process is silently dropped, making allowlist-dependent
/// tests order-fragile. The allowlist only ever originates from the user's
/// trusted `rv.toml` `[security]`; POMs cannot reach this setter, so honoring
/// the most recently loaded policy carries no supply-chain risk.
pub fn set_env_substitution_allowlist(allowlist: Vec<String>) {
    let cell = allowlist_cell();
    let Ok(mut guard) = cell.write() else {
        // A poisoned lock here would only happen if a previous writer
        // panicked. Skip the install rather than propagating the panic;
        // env-substitution then stays in its current state.
        return;
    };
    *guard = Some(allowlist);
}

/// Test-only helper that clears the allowlist back to "uninitialised" so
/// the next [`set_env_substitution_allowlist`] call (or absence thereof)
/// can install a fresh policy. Useful around scenarios that rely on the
/// fail-closed default behaviour of `${env.X}` substitution.
#[cfg(test)]
pub fn reset_env_substitution_allowlist_for_tests() {
    if let Ok(mut guard) = allowlist_cell().write() {
        *guard = None;
    }
}

/// Returns true if `name` is permitted for `${env.NAME}` POM substitution.
fn env_var_allowlisted(name: &str) -> bool {
    let Some(cell) = ENV_SUBSTITUTION_ALLOWLIST.get() else {
        return false;
    };
    let Ok(guard) = cell.read() else {
        return false;
    };
    guard
        .as_ref()
        .map(|list| list.iter().any(|allowed| allowed == name))
        .unwrap_or(false)
}

/// Returns a snapshot of the currently-installed allowlist, or `None` if
/// none has been set. Consumers needing to scan resolved output for
/// allowlisted env-var values use this to fetch the policy without
/// reaching into the static directly.
pub fn env_substitution_allowlist() -> Option<Vec<String>> {
    let cell = ENV_SUBSTITUTION_ALLOWLIST.get()?;
    cell.read().ok()?.clone()
}

/// Best-effort default for `${java.version}` when no `JAVA_VERSION` env var is
/// set. Raeva does not run a JVM, so the value is a sentinel rather than a
/// detected runtime version: 17 (current LTS) is the safest middle ground for
/// POMs that branch on JDK major versions. Override via `JAVA_VERSION`.
const DEFAULT_JAVA_VERSION: &str = "17";

/// Returns a process-global snapshot of safe-to-publish Java-equivalent
/// system properties, populated on first use.
///
/// Maven resolves `${java.version}`, `${os.name}`, etc. via
/// `System.getProperties()`. Raeva is not a JVM, so these values are
/// best-effort: OS/arch are derived from `std::env::consts`, and
/// `java.version` falls back to the `JAVA_VERSION` env var or a documented
/// sentinel ([`DEFAULT_JAVA_VERSION`]).
///
/// Supply-chain hardening (finding #57): the host-path / host-identity
/// sysprops `user.home`, `user.dir`, and `java.home` are deliberately
/// excluded from this map. They are attacker-readable when a transitive
/// POM embeds e.g. `${user.home}` in a value that then lands in `rv.lock`,
/// an error message, or a cache key, leaking the host user's filesystem
/// layout. They are also non-reproducible across machines, so they have no
/// place in a deterministic effective model regardless of trust. Only the
/// deterministic, non-sensitive sysprops below are interpolated.
///
/// The map is computed once and reused; subsequent env-var changes are not
/// reflected. This keeps interpolation deterministic across a single
/// resolution run.
pub fn sysprops_for_interpolation() -> &'static HashMap<String, String> {
    static SYSPROPS: OnceLock<HashMap<String, String>> = OnceLock::new();
    SYSPROPS.get_or_init(build_sysprops)
}

fn build_sysprops() -> HashMap<String, String> {
    let mut props = HashMap::with_capacity(4);

    let java_version = std::env::var("JAVA_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_JAVA_VERSION.to_string());
    props.insert("java.version".to_string(), java_version);

    props.insert("os.name".to_string(), maven_os_name().to_string());
    props.insert("os.arch".to_string(), std::env::consts::ARCH.to_string());

    // NOTE: `user.home`, `user.dir`, and `java.home` are intentionally NOT
    // inserted here; see the doc comment above. A `${user.home}` reference in
    // a (possibly transitive) POM is left unresolved rather than substituted
    // with the host path.
    props
}

/// Map Rust's `std::env::consts::OS` to the Maven-style `os.name`. Windows
/// returns the unversioned "windows" token: `<os><family>` activations work,
/// but exact-version Windows checks need `os.name` set in `.mvn/maven.config`.
fn maven_os_name() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "Mac OS X",
        "windows" => "windows",
        "freebsd" => "FreeBSD",
        "openbsd" => "OpenBSD",
        "netbsd" => "NetBSD",
        "dragonfly" => "DragonFly",
        "solaris" => "SunOS",
        other => other,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct PropertyMap {
    props: IndexMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParentInfo {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectInfo {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub packaging: String,
    pub parent: Option<ParentInfo>,
    pub basedir: Option<PathBuf>,
    pub local_repository: Option<PathBuf>,
}

impl PropertyMap {
    pub fn new() -> Self {
        Self {
            props: IndexMap::new(),
        }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.props.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.props.get(key)
    }

    pub fn is_empty(&self) -> bool {
        self.props.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.props.iter()
    }

    pub fn merge_ref(&self, other: &PropertyMap) -> PropertyMap {
        let mut merged = self.clone();
        merged.extend(other);
        merged
    }

    pub fn extend(&mut self, other: &PropertyMap) {
        // IndexMap's extend can use an iterator of references efficiently
        for (k, v) in &other.props {
            self.props.insert(k.clone(), v.clone());
        }
    }

    pub(crate) fn interpolate_str(
        &self,
        input: &str,
        project: &ProjectInfo,
    ) -> Result<String, PomError> {
        self.interpolate_str_with(input, Some(project))
    }

    /// Interpolate `${...}` references in `input` using only the entries in this
    /// map. No `${project.*}` substitutions are attempted; use
    /// [`Self::interpolate_str_with_project`] when project context is needed.
    pub fn interpolate_str_no_project(&self, input: &str) -> Result<String, PomError> {
        self.interpolate_str_with(input, None)
    }

    pub(crate) fn interpolate_opt(
        &self,
        input: Option<&str>,
        project: &ProjectInfo,
    ) -> Result<Option<String>, PomError> {
        input.map(|s| self.interpolate_str(s, project)).transpose()
    }

    fn interpolate_str_with(
        &self,
        input: &str,
        project: Option<&ProjectInfo>,
    ) -> Result<String, PomError> {
        let mut active = HashSet::new();
        let mut cycle_path = Vec::new();
        self.interpolate_str_inner(input, project, &mut active, &mut cycle_path, 0)
    }

    /// Cap on the size of an interpolated string. Stops a self-referential
    /// or exponentially-expanding property chain from ballooning memory.
    const MAX_INTERPOLATION_LENGTH: usize = 1024 * 1024;
    /// Cap on nested ${...} expansion depth. Maven's own limit is similar;
    /// real POMs almost never exceed two or three levels of indirection.
    const MAX_INTERPOLATION_DEPTH: usize = 100;

    fn interpolate_str_inner(
        &self,
        input: &str,
        project: Option<&ProjectInfo>,
        active: &mut HashSet<String>,
        cycle_path: &mut Vec<String>,
        depth: usize,
    ) -> Result<String, PomError> {
        // WHY: count every recursive call, not just `resolve_value_inner`
        // entries that succeed in `cycle_path.push`. Pure
        // `${${${...}}}` key-nesting recurses through
        // `interpolate_str_inner` without going through `resolve_value_inner`
        // (the inner keys may not be defined), so `cycle_path.len()` stays
        // at zero and the depth guard never fires. The explicit counter
        // catches the key-nesting DoS path.
        if depth >= Self::MAX_INTERPOLATION_DEPTH {
            return Err(PomError::InvalidModel(format!(
                "property interpolation depth limit exceeded (max: {})",
                Self::MAX_INTERPOLATION_DEPTH
            )));
        }
        // Pre-allocate capacity to avoid O(n²) reallocations during string building.
        // Most interpolations expand slightly (property names become values), so
        // use 2x input length as a reasonable heuristic to minimize reallocations.
        let mut output = String::with_capacity(input.len() * 2);
        let mut rest = input;

        while let Some(start) = rest.find("${") {
            output.push_str(&rest[..start]);

            if output.len() > Self::MAX_INTERPOLATION_LENGTH {
                return Err(PomError::InvalidModel(
                    "property interpolation too large".to_string(),
                ));
            }

            let after = &rest[start + 2..];
            if let Some(end) = find_matching_brace(after) {
                let key_raw = &after[..end];
                // Recursively interpolate any nested ${} in the key itself
                let key =
                    self.interpolate_str_inner(key_raw, project, active, cycle_path, depth + 1)?;
                if let Some(value) =
                    self.resolve_value_inner(&key, project, active, cycle_path, depth + 1)?
                {
                    output.push_str(&value);
                } else {
                    // Key not found: preserve the original literal with resolved inner parts
                    output.push_str("${");
                    output.push_str(&key);
                    output.push('}');
                }
                // Guard immediately after the push so a single oversize substitution
                // can't double the buffer before the next-iter guard fires.
                if output.len() > Self::MAX_INTERPOLATION_LENGTH {
                    return Err(PomError::InvalidModel(
                        "property interpolation too large".to_string(),
                    ));
                }
                rest = &after[end + 1..];
            } else {
                output.push_str(rest);
                if output.len() > Self::MAX_INTERPOLATION_LENGTH {
                    return Err(PomError::InvalidModel(
                        "property interpolation too large".to_string(),
                    ));
                }
                return Ok(output);
            }
        }

        output.push_str(rest);

        if output.len() > Self::MAX_INTERPOLATION_LENGTH {
            return Err(PomError::InvalidModel(
                "property interpolation too large".to_string(),
            ));
        }

        Ok(output)
    }

    fn resolve_value_inner(
        &self,
        key: &str,
        project: Option<&ProjectInfo>,
        active: &mut HashSet<String>,
        cycle_path: &mut Vec<String>,
        depth: usize,
    ) -> Result<Option<String>, PomError> {
        if let Some(value) = resolve_builtin(key, project) {
            return Ok(Some(value));
        }

        let raw_value = match self.props.get(key) {
            Some(value) => value.clone(),
            None => return Ok(None),
        };

        // Check for cycle before inserting to avoid allocation when not in active set
        if active.contains(key) {
            // Only allocate the cycle path when we detect a cycle
            cycle_path.push(key.to_string());
            return Err(PomError::PropertyCycle(cycle_path.clone()));
        }

        // Use a borrowed key to avoid allocation during insertion
        let key_owned = key.to_string();
        active.insert(key_owned.clone());
        cycle_path.push(key_owned.clone());

        let resolved =
            self.interpolate_str_inner(&raw_value, project, active, cycle_path, depth)?;

        cycle_path.pop();
        active.remove(&key_owned);

        Ok(Some(resolved))
    }
}

/// Find the position of the closing `}` that matches the opening `{` implied at position -1.
/// Handles nested `${}` expressions by counting brace depth. Returns the index
/// of the matching `}` in the input string, or None if not found.
fn find_matching_brace(s: &str) -> Option<usize> {
    let mut depth = 1;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn resolve_builtin(key: &str, project: Option<&ProjectInfo>) -> Option<String> {
    if let Some(rest) = key.strip_prefix("pom.") {
        let alias = format!("project.{rest}");
        if let Some(value) = resolve_builtin(&alias, project) {
            return Some(value);
        }
    }

    match key {
        "os.detected.name" => return os_detected_name().map(|value| value.to_string()),
        "os.detected.arch" => return os_detected_arch().map(|value| value.to_string()),
        "os.detected.classifier" => return os_detected_classifier(),
        _ => {}
    }

    if let Some(project) = project {
        match key {
            "project.groupId" | "groupId" => return Some(project.group_id.clone()),
            "project.artifactId" | "artifactId" => return Some(project.artifact_id.clone()),
            "project.version" | "version" => return Some(project.version.clone()),
            "project.packaging" | "packaging" => return Some(project.packaging.clone()),
            "project.parent.groupId" => {
                return project
                    .parent
                    .as_ref()
                    .map(|parent| parent.group_id.clone());
            }
            "project.parent.artifactId" => {
                return project
                    .parent
                    .as_ref()
                    .map(|parent| parent.artifact_id.clone());
            }
            "project.parent.version" => {
                return project.parent.as_ref().map(|parent| parent.version.clone());
            }
            "project.basedir" | "basedir" => {
                return project.basedir.as_ref().map(|path| path_to_string(path));
            }
            "project.build.directory" => {
                return project
                    .basedir
                    .as_ref()
                    .map(|path| path_to_string(&path.join("target")));
            }
            "project.build.outputDirectory" => {
                return project
                    .basedir
                    .as_ref()
                    .map(|path| path_to_string(&path.join("target").join("classes")));
            }
            "project.build.sourceDirectory" => {
                return project
                    .basedir
                    .as_ref()
                    .map(|path| path_to_string(&path.join("src").join("main").join("java")));
            }
            "project.build.testSourceDirectory" => {
                return project
                    .basedir
                    .as_ref()
                    .map(|path| path_to_string(&path.join("src").join("test").join("java")));
            }
            "settings.localRepository" => {
                return project
                    .local_repository
                    .as_ref()
                    .map(|path| path_to_string(path));
            }
            _ => {}
        }
    }

    // Deterministic Java-equivalent system properties (`java.version`,
    // `os.name`, `os.arch`) are consulted before env.* so a POM that uses the
    // standard Maven sysprop key resolves to the host value instead of
    // falling through to the literal `${...}`. Host-path / host-identity
    // sysprops (`user.home`, `user.dir`, `java.home`) are excluded from this
    // map (finding #57) and therefore fall through unresolved.
    if let Some(value) = sysprops_for_interpolation().get(key) {
        return Some(value.clone());
    }

    if let Some(rest) = key.strip_prefix("env.") {
        if rest.is_empty() {
            return None;
        }
        // Supply-chain hardening: refuse to resolve ${env.NAME} unless the
        // operator has explicitly added NAME to the allowlist. Without this
        // gate, any transitive POM author can exfiltrate host env vars (like
        // AWS_SECRET_ACCESS_KEY or GITHUB_TOKEN) by interpolating them into
        // a value that lands in the lockfile, error messages, or cache keys.
        if !env_var_allowlisted(rest) {
            tracing::debug!(
                env_var = %rest,
                "refusing ${{env.X}} POM substitution: not on allowlist (see [security] allow_env_substitution)"
            );
            return None;
        }
        return std::env::var(rest).ok();
    }

    None
}

fn path_to_string(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

fn os_detected_name() -> Option<&'static str> {
    match std::env::consts::OS {
        "linux" => Some("linux"),
        "macos" => Some("osx"),
        "windows" => Some("windows"),
        _ => None,
    }
}

fn os_detected_arch() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" | "amd64" => Some("x86_64"),
        "x86" | "i686" | "i386" => Some("x86_32"),
        "aarch64" | "arm64" => Some("aarch_64"),
        _ => None,
    }
}

fn os_detected_classifier() -> Option<String> {
    match (os_detected_name(), os_detected_arch()) {
        (Some(name), Some(arch)) => Some(format!("{name}-{arch}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolates_custom_properties() {
        let mut props = PropertyMap::new();
        props.insert("name", "raeva");
        props.insert("path", "/opt/${name}");

        let project = ProjectInfo {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let value = props.interpolate_str("${path}/bin", &project).unwrap();
        assert_eq!(value, "/opt/raeva/bin");
    }

    #[test]
    fn interpolates_project_properties() {
        let props = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.2.3".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let value = props
            .interpolate_str("${project.groupId}:${project.artifactId}", &project)
            .unwrap();
        assert_eq!(value, "com.example:demo");
    }

    #[test]
    fn interpolates_env_properties() {
        // The allowlist is set once per process. The first test that needs an
        // allowlisted env var installs the full set the test suite cares about;
        // other tests can rely on it because `OnceLock::set` after that is a
        // no-op. Variables NOT on this list must NOT resolve via ${env.X}.
        set_env_substitution_allowlist(vec![
            "RAEVA_TEST_ENV".to_string(),
            "RAEVA_TEST_ALLOWED".to_string(),
        ]);
        temp_env::with_var("RAEVA_TEST_ENV", Some("ok"), || {
            let props = PropertyMap::new();
            let project = ProjectInfo {
                group_id: "g".to_string(),
                artifact_id: "a".to_string(),
                version: "v".to_string(),
                packaging: "jar".to_string(),
                parent: None,
                basedir: None,
                local_repository: None,
            };

            let value = props
                .interpolate_str("${env.RAEVA_TEST_ENV}", &project)
                .unwrap();
            assert_eq!(value, "ok");
        });
    }

    /// Regression test for the supply-chain hardening of `${env.X}` POM
    /// substitution: a non-allowlisted env var must NOT be resolved, even when
    /// the variable is set in the process environment. The unresolved reference
    /// is preserved verbatim (so downstream parsing typically rejects it,
    /// matching the desired fail-closed behaviour).
    #[test]
    fn env_substitution_without_allowlist_is_blocked() {
        // Don't install the allowlist here: the global state may already be
        // pinned by a previously-run test. What we DO know is that
        // `RAEVA_TEST_DISALLOWED_SECRET` is not on the allowlist installed by
        // `interpolates_env_properties` above, so it must not be resolved.
        temp_env::with_var(
            "RAEVA_TEST_DISALLOWED_SECRET",
            Some("super-secret-token"),
            || {
                let props = PropertyMap::new();
                let project = ProjectInfo {
                    group_id: "g".to_string(),
                    artifact_id: "a".to_string(),
                    version: "v".to_string(),
                    packaging: "jar".to_string(),
                    parent: None,
                    basedir: None,
                    local_repository: None,
                };

                let value = props
                    .interpolate_str("${env.RAEVA_TEST_DISALLOWED_SECRET}", &project)
                    .unwrap();
                // Unresolved reference is preserved as a literal; the secret
                // value must not leak into the output.
                assert_eq!(value, "${env.RAEVA_TEST_DISALLOWED_SECRET}");
                assert!(!value.contains("super-secret-token"));
            },
        );
    }

    /// The reset helper must drop the previously-installed allowlist so a
    /// follow-up `set_env_substitution_allowlist([])` call deliberately
    /// installs the empty (fail-closed) policy. Without the reset the
    /// previous test's allowlist would silently win in `cfg(test)` builds.
    #[test]
    fn reset_helper_restores_fail_closed_default() {
        set_env_substitution_allowlist(vec!["RAEVA_TEST_KEEP".to_string()]);
        assert_eq!(
            env_substitution_allowlist(),
            Some(vec!["RAEVA_TEST_KEEP".to_string()])
        );
        reset_env_substitution_allowlist_for_tests();
        assert_eq!(env_substitution_allowlist(), None);
        // After reset, env_var_allowlisted must read as "not allowlisted" so
        // a `${env.X}` reference for a previously-allowed variable does not
        // resolve.
        assert!(!super::env_var_allowlisted("RAEVA_TEST_KEEP"));
    }

    /// Tests can re-install a different allowlist between scenarios.
    /// Production semantics remain first-writer-wins; `cfg(test)` lets us
    /// overwrite. Run two installs back to back and check the second wins.
    #[test]
    fn allowlist_overwrite_in_tests_takes_effect() {
        set_env_substitution_allowlist(vec!["RAEVA_TEST_A".to_string()]);
        set_env_substitution_allowlist(vec!["RAEVA_TEST_B".to_string()]);
        let snap = env_substitution_allowlist().expect("allowlist installed");
        assert_eq!(snap, vec!["RAEVA_TEST_B".to_string()]);
    }

    /// Regression test for the allowlist positive path: a variable explicitly
    /// added to the allowlist does substitute.
    #[test]
    fn env_substitution_with_allowlist_resolves() {
        // Install (idempotently) the allowlist used across these tests.
        set_env_substitution_allowlist(vec![
            "RAEVA_TEST_ENV".to_string(),
            "RAEVA_TEST_ALLOWED".to_string(),
        ]);
        temp_env::with_var("RAEVA_TEST_ALLOWED", Some("hello"), || {
            let props = PropertyMap::new();
            let project = ProjectInfo {
                group_id: "g".to_string(),
                artifact_id: "a".to_string(),
                version: "v".to_string(),
                packaging: "jar".to_string(),
                parent: None,
                basedir: None,
                local_repository: None,
            };
            let value = props
                .interpolate_str("${env.RAEVA_TEST_ALLOWED}", &project)
                .unwrap();
            assert_eq!(value, "hello");
        });
    }

    #[test]
    fn unresolved_property_kept() {
        let props = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let value = props.interpolate_str("${missing}/bin", &project).unwrap();
        assert_eq!(value, "${missing}/bin");
    }

    #[test]
    fn detects_cycles() {
        let mut props = PropertyMap::new();
        props.insert("a", "${b}");
        props.insert("b", "${a}");
        let project = ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let err = props.interpolate_str("${a}", &project).unwrap_err();
        match err {
            PomError::PropertyCycle(path) => assert_eq!(path, vec!["a", "b", "a"]),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn interpolate_without_project() {
        let mut props = PropertyMap::new();
        props.insert("version", "1.0.0");

        let value = props.interpolate_str_no_project("${version}").unwrap();
        assert_eq!(value, "1.0.0");
    }

    #[test]
    fn resolves_bare_groupid_version_shorthands() {
        // Maven allows ${groupId}, ${artifactId}, ${version} as shorthands for
        // ${project.groupId} etc. Netty codec-dns and other real-world POMs use this.
        let props = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "io.netty".to_string(),
            artifact_id: "netty-codec-dns".to_string(),
            version: "4.1.0.Final".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let group = props.interpolate_str("${groupId}", &project).unwrap();
        assert_eq!(group, "io.netty");

        let version = props.interpolate_str("${version}", &project).unwrap();
        assert_eq!(version, "4.1.0.Final");

        let artifact = props.interpolate_str("${artifactId}", &project).unwrap();
        assert_eq!(artifact, "netty-codec-dns");

        // Full dependency coordinate as used in real Netty POMs:
        // <groupId>${groupId}</groupId>...<version>${version}</version>
        let coord = props
            .interpolate_str("${groupId}:apacheds-i18n:${version}", &project)
            .unwrap();
        assert_eq!(coord, "io.netty:apacheds-i18n:4.1.0.Final");
    }

    #[test]
    fn bare_coordinate_shorthand_resolves_to_project_field() {
        // ${groupId} is a project-coordinate alias (equivalent to ${project.groupId}),
        // not a property-table lookup. Even when a property named "groupId" exists,
        // the built-in alias is checked first and wins. This matches Maven's
        // behaviour: project coordinates take priority over user-defined properties
        // of the same name.
        let mut props = PropertyMap::new();
        props.insert("groupId", "com.override");

        let project = ProjectInfo {
            group_id: "io.netty".to_string(),
            artifact_id: "netty-codec-dns".to_string(),
            version: "4.1.0.Final".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let group = props.interpolate_str("${groupId}", &project).unwrap();
        assert_eq!(group, "io.netty");
    }

    #[test]
    fn interpolates_parent_properties() {
        let props = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "com.example".to_string(),
            artifact_id: "child".to_string(),
            version: "1.0.0".to_string(),
            packaging: "jar".to_string(),
            parent: Some(ParentInfo {
                group_id: "com.base".to_string(),
                artifact_id: "parent".to_string(),
                version: "2.0.0".to_string(),
            }),
            basedir: None,
            local_repository: None,
        };

        let value = props
            .interpolate_str(
                "${project.parent.groupId}:${project.parent.artifactId}:${project.parent.version}",
                &project,
            )
            .unwrap();
        assert_eq!(value, "com.base:parent:2.0.0");
    }

    #[test]
    fn interpolates_basedir_and_build_properties() {
        let props = PropertyMap::new();
        let basedir = PathBuf::from("workspace");
        let project = ProjectInfo {
            group_id: "com.example".to_string(),
            artifact_id: "app".to_string(),
            version: "1.0.0".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: Some(basedir.clone()),
            local_repository: None,
        };

        let base_value = props
            .interpolate_str("${project.basedir}", &project)
            .unwrap();
        assert_eq!(base_value, basedir.to_string_lossy().into_owned());

        let build_dir = props
            .interpolate_str("${project.build.directory}", &project)
            .unwrap();
        assert_eq!(
            build_dir,
            basedir.join("target").to_string_lossy().into_owned()
        );

        let output_dir = props
            .interpolate_str("${project.build.outputDirectory}", &project)
            .unwrap();
        assert_eq!(
            output_dir,
            basedir
                .join("target")
                .join("classes")
                .to_string_lossy()
                .into_owned()
        );

        let source_dir = props
            .interpolate_str("${project.build.sourceDirectory}", &project)
            .unwrap();
        assert_eq!(
            source_dir,
            basedir
                .join("src")
                .join("main")
                .join("java")
                .to_string_lossy()
                .into_owned()
        );

        let test_source_dir = props
            .interpolate_str("${project.build.testSourceDirectory}", &project)
            .unwrap();
        assert_eq!(
            test_source_dir,
            basedir
                .join("src")
                .join("test")
                .join("java")
                .to_string_lossy()
                .into_owned()
        );
    }

    #[test]
    fn pom_aliases_project_properties() {
        let props = PropertyMap::new();
        let basedir = PathBuf::from("workspace");
        let project = ProjectInfo {
            group_id: "com.example".to_string(),
            artifact_id: "app".to_string(),
            version: "1.2.3".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: Some(basedir.clone()),
            local_repository: None,
        };

        let value = props
            .interpolate_str("${pom.groupId}:${pom.artifactId}:${pom.version}", &project)
            .unwrap();
        assert_eq!(value, "com.example:app:1.2.3");

        let source_dir = props
            .interpolate_str("${pom.build.sourceDirectory}", &project)
            .unwrap();
        assert_eq!(
            source_dir,
            basedir
                .join("src")
                .join("main")
                .join("java")
                .to_string_lossy()
                .into_owned()
        );
    }

    #[test]
    fn interpolates_settings_local_repository() {
        let props = PropertyMap::new();
        let local_repo = PathBuf::from("repo");
        let project = ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: Some(local_repo.clone()),
        };

        let value = props
            .interpolate_str("${settings.localRepository}", &project)
            .unwrap();
        assert_eq!(value, local_repo.to_string_lossy().into_owned());
    }

    #[test]
    fn resolves_os_detected_properties() {
        assert_eq!(
            resolve_builtin("os.detected.name", None),
            os_detected_name().map(|value| value.to_string())
        );
        assert_eq!(
            resolve_builtin("os.detected.arch", None),
            os_detected_arch().map(|value| value.to_string())
        );
        assert_eq!(
            resolve_builtin("os.detected.classifier", None),
            os_detected_classifier()
        );
    }

    #[test]
    fn interpolates_nested_properties() {
        let mut props = PropertyMap::new();
        props.insert("env", "prod");
        props.insert("config.prod.url", "https://prod.example.com");
        props.insert("config.dev.url", "https://dev.example.com");

        let project = ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        // Test nested property: ${config.${env}.url} should resolve to ${config.prod.url}
        let value = props
            .interpolate_str("${config.${env}.url}", &project)
            .unwrap();
        assert_eq!(value, "https://prod.example.com");
    }

    #[test]
    fn interpolates_deeply_nested_properties() {
        let mut props = PropertyMap::new();
        props.insert("level", "one");
        props.insert("one", "two");
        props.insert("value.two", "success");

        let project = ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        // Test: ${value.${${level}}} -> ${value.${one}} -> ${value.two} -> success
        let value = props
            .interpolate_str("${value.${${level}}}", &project)
            .unwrap();
        assert_eq!(value, "success");
    }

    #[test]
    fn find_matching_brace_simple() {
        assert_eq!(find_matching_brace("foo}"), Some(3));
        assert_eq!(find_matching_brace("}"), Some(0));
        assert_eq!(find_matching_brace("no closing brace"), None);
    }

    #[test]
    fn find_matching_brace_nested() {
        // "config.${env}.url}" - the } at position 17 is the matching one
        assert_eq!(find_matching_brace("config.${env}.url}"), Some(17));
        // "${a}${b}}" - first } at 3 doesn't match because of nested ${
        assert_eq!(find_matching_brace("${a}${b}}"), Some(8));
    }

    #[test]
    fn interpolates_java_sysprops() {
        let props = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        // os.name maps to the Maven-style display name on the host platform;
        // confirm it interpolates rather than passing through as a literal.
        let os_name = props.interpolate_str("${os.name}", &project).unwrap();
        assert_ne!(os_name, "${os.name}");
        let expected_os = match std::env::consts::OS {
            "linux" => "Linux",
            "macos" => "Mac OS X",
            "windows" => "windows",
            "freebsd" => "FreeBSD",
            "openbsd" => "OpenBSD",
            "netbsd" => "NetBSD",
            "dragonfly" => "DragonFly",
            "solaris" => "SunOS",
            other => other,
        };
        assert_eq!(os_name, expected_os);

        // os.arch comes straight from std::env::consts::ARCH.
        let os_arch = props.interpolate_str("${os.arch}", &project).unwrap();
        assert_eq!(os_arch, std::env::consts::ARCH);

        // java.version defaults to the documented sentinel when the env var
        // is absent.
        let java_version = props.interpolate_str("${java.version}", &project).unwrap();
        assert!(!java_version.is_empty());
        assert_ne!(java_version, "${java.version}");
    }

    #[test]
    fn sysprops_include_expected_keys() {
        let sysprops = sysprops_for_interpolation();
        assert!(sysprops.contains_key("java.version"));
        assert!(sysprops.contains_key("os.name"));
        assert!(sysprops.contains_key("os.arch"));
    }

    /// `maven_os_name` must map Linux and macOS to the JVM-style names. On
    /// Windows we deliberately produce a version-agnostic "windows" token
    /// because we do not probe the host registry; profile activation that
    /// keys on `os.family` still works.
    #[test]
    fn maven_os_name_maps_known_platforms() {
        // The test runs on the host OS; only the actual host's mapping is
        // observable, but each branch is encoded in the match arms so a
        // regression in any of them is loud during code review.
        let host = maven_os_name();
        match std::env::consts::OS {
            "linux" => assert_eq!(host, "Linux"),
            "macos" => assert_eq!(host, "Mac OS X"),
            "windows" => assert_eq!(host, "windows"),
            _ => {
                // Less-common platforms get the raw token, exercised by
                // `interpolates_java_sysprops`.
            }
        }
    }

    /// Finding #57: the host-path / host-identity sysprops `user.home`,
    /// `user.dir`, and `java.home` must NOT appear in the interpolation map, so
    /// a (possibly transitive) POM that references them cannot read the host's
    /// filesystem layout via a value that lands in the lockfile, an error
    /// message, or a cache key.
    #[test]
    fn sensitive_sysprops_are_not_interpolated() {
        let sysprops = sysprops_for_interpolation();
        for key in ["user.home", "user.dir", "java.home"] {
            assert!(
                !sysprops.contains_key(key),
                "{key} must be excluded from the interpolation sysprops map"
            );
        }

        // A POM value referencing a sensitive sysprop is left as the literal
        // `${...}` instead of leaking the host value. Even with JAVA_HOME set
        // in the environment, `${java.home}` must not resolve.
        let props = PropertyMap::new();
        let project = ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };
        temp_env::with_var("JAVA_HOME", Some("/opt/secret-jdk"), || {
            let home = props.interpolate_str("${user.home}", &project).unwrap();
            assert_eq!(home, "${user.home}");
            let dir = props.interpolate_str("${user.dir}", &project).unwrap();
            assert_eq!(dir, "${user.dir}");
            let java_home = props.interpolate_str("${java.home}", &project).unwrap();
            assert_eq!(java_home, "${java.home}");
            assert!(!java_home.contains("secret-jdk"));
        });
    }

    #[test]
    fn rejects_excessive_interpolation_depth() {
        let mut props = PropertyMap::new();
        // Create a chain: a -> b -> c -> d -> ... -> z (depth 101)
        for i in 0..101 {
            let key = format!("prop{}", i);
            let value = format!("${{prop{}}}", i + 1);
            props.insert(key, value);
        }
        props.insert("prop101", "final");

        let project = ProjectInfo {
            group_id: "g".to_string(),
            artifact_id: "a".to_string(),
            version: "v".to_string(),
            packaging: "jar".to_string(),
            parent: None,
            basedir: None,
            local_repository: None,
        };

        let err = props.interpolate_str("${prop0}", &project).unwrap_err();
        match err {
            PomError::InvalidModel(msg) => {
                assert!(msg.contains("depth limit exceeded"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
