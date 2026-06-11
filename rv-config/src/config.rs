use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use rv_maven_model::ActivationContext;

use crate::error::{ConfigError, io_error_with_context, toml_de_error_with_context};
use crate::maven_settings::{MavenProfile, MavenSettings};
use crate::paths::ResolvedPaths;
use crate::settings::{AuthConfig, MirrorConfig, ProxyConfig, RepoConfig};

/// Security-related configuration toggles.
///
/// Designed to be additive and forward-compatible: every field has a safe-by-default
/// value, and missing fields deserialize to that default. New entries should also be
/// purely additive so older `rv.toml` files keep parsing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Allowlist of environment-variable names whose values may be substituted into
    /// `${env.NAME}` POM property references during effective-model computation.
    ///
    /// **Default is empty**, which disables `${env.*}` substitution entirely. Any
    /// transitive package can author a POM that references `${env.SECRET}`; without
    /// this gate the resolved value lands in lockfiles, error messages, and cache
    /// keys, giving package authors a read-channel for host environment variables
    /// like `AWS_SECRET_ACCESS_KEY` or `GITHUB_TOKEN`.
    ///
    /// Users who rely on `${env.X}` substitution in their own POMs must opt those
    /// variables in explicitly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_env_substitution: Vec<String>,

    /// When `true`, `<repositories>` declared by a fetched (transitive) POM are
    /// merged into the active resolution's repository set so that subsequent
    /// fetches in the same resolution can query them.
    ///
    /// **Default is `false`**, which is a deliberate break from Maven's
    /// "everyone-can-add-repos" default. A hostile transitive package would
    /// otherwise be able to introduce an attacker-controlled repository URL,
    /// which subsequent resolutions would then trust silently. Users who need
    /// a particular transitive repository must opt in via
    /// [`Self::transitive_repository_allowlist`] (URL-prefix match) or by
    /// flipping this flag globally.
    #[serde(default)]
    pub allow_transitive_repositories: bool,

    /// URL-prefix allowlist for transitive `<repositories>` declarations. Even when
    /// [`Self::allow_transitive_repositories`] is `false`, a transitive repository
    /// whose URL starts with one of these prefixes is accepted.
    ///
    /// Default is empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transitive_repository_allowlist: Vec<String>,
}

impl SecurityConfig {
    /// Returns true if the environment variable `name` is allowlisted for
    /// `${env.NAME}` POM substitution.
    pub fn allows_env_var(&self, name: &str) -> bool {
        self.allow_env_substitution.iter().any(|n| n == name)
    }

    /// Returns true if the given repository URL is allowed to be inherited from a
    /// transitive POM declaration. When the global allow-flag is set, all URLs
    /// pass. Otherwise the URL must share the same scheme, host, and port as
    /// one of the allowlist entries, and the candidate path must start with
    /// the allowlist entry's path (preventing `corp.example` from matching
    /// `corp.example.evil.com`).
    pub fn allows_transitive_repo_url(&self, url: &str) -> bool {
        if self.allow_transitive_repositories {
            return true;
        }
        let Some(candidate) = parse_url_origin(url) else {
            return false;
        };
        self.transitive_repository_allowlist
            .iter()
            .filter_map(|entry| parse_url_origin(entry))
            .any(|allowed| url_origin_matches(&allowed, &candidate))
    }

    /// Validate that every entry in the `transitive_repository_allowlist` can
    /// be parsed as a URL. Returns the first unparseable entry so `Config::load`
    /// can surface a clear error before any resolution begins.
    pub fn validate_allowlist(&self) -> Result<(), String> {
        for entry in &self.transitive_repository_allowlist {
            if parse_url_origin(entry).is_none() {
                return Err(format!(
                    "transitive_repository_allowlist entry is not a valid URL: {entry:?}"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ProjectConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_repository: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<RepoConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirrors: Option<Vec<MirrorConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<Vec<AuthConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxies: Option<Vec<ProxyConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfigToml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_profiles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactive_profiles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityConfig>,
    // Opaque sinks: accepted so legacy rv.toml files that still carry the
    // pre-v1 manifest sections (or the dropped `mode` setting) keep parsing.
    // v1 ignores their contents; `pom.xml` is the only manifest input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vars: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_management: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<toml::Value>,
}

impl ProjectConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        load_optional_toml(path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct UserConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_repository: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<RepoConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirrors: Option<Vec<MirrorConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<Vec<AuthConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxies: Option<Vec<ProxyConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfigToml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_profiles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactive_profiles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityConfig>,
    /// Opaque sink: pre-v1 `mode` setting kept for back-compat parsing only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<toml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default = "default_retries")]
    pub retries: usize,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
}

/// `[network]` table as written in rv.toml / config.toml. Fields are optional
/// so layering can tell "unset" apart from "explicitly set": a field the
/// project file leaves out inherits the user file's value instead of
/// resetting it to the default. `Config::load` resolves the merged table
/// into [`NetworkConfig`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NetworkConfigToml {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout: default_timeout(),
            retries: default_retries(),
            concurrency: default_concurrency(),
        }
    }
}

fn default_timeout() -> u64 {
    30
}

fn default_retries() -> usize {
    2
}

/// Environment variable overriding `network.timeout` (request timeout in seconds).
const RV_TIMEOUT_ENV: &str = "RV_TIMEOUT";
/// Environment variable overriding `network.retries` (network retry attempts).
const RV_RETRIES_ENV: &str = "RV_RETRIES";

fn default_concurrency() -> usize {
    8
}

impl UserConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        load_optional_toml(path)
    }
}

#[derive(Debug, Clone, Default)]
struct MavenSettingsData {
    local_repository: Option<PathBuf>,
    repositories: Vec<RepoConfig>,
    mirrors: Vec<MirrorConfig>,
    auth: Vec<AuthConfig>,
    proxies: Vec<ProxyConfig>,
    active_profiles: Vec<String>,
}

#[derive(Debug, Clone)]
struct ConfigInputs {
    project_repositories: Option<Vec<RepoConfig>>,
    project_mirrors: Option<Vec<MirrorConfig>>,
    project_auth: Option<Vec<AuthConfig>>,
    project_proxies: Option<Vec<ProxyConfig>>,
    project_local_repository: Option<PathBuf>,
    project_active_profiles: Option<Vec<String>>,
    user_repositories: Option<Vec<RepoConfig>>,
    user_mirrors: Option<Vec<MirrorConfig>>,
    user_auth: Option<Vec<AuthConfig>>,
    user_proxies: Option<Vec<ProxyConfig>>,
    user_local_repository: Option<PathBuf>,
    user_active_profiles: Option<Vec<String>>,
}

pub struct Config {
    pub network: NetworkConfig,
    pub inactive_profiles: Vec<String>,
    /// Security toggles for supply-chain hardening (`${env.*}` substitution,
    /// transitive `<repositories>` policy, …). Default is safe-by-default: env
    /// substitution disabled, transitive repos disabled.
    pub security: SecurityConfig,
    pub paths: ResolvedPaths,
    pub project_root: PathBuf,
    pub project_config_path: PathBuf,
    pub user_config_path: PathBuf,
    pub lock_path: PathBuf,
    inputs: ConfigInputs,
    maven_data: OnceLock<MavenSettingsData>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("network", &self.network)
            .field("inactive_profiles", &self.inactive_profiles)
            .field("security", &self.security)
            .field("paths", &self.paths)
            .field("project_root", &self.project_root)
            .field("project_config_path", &self.project_config_path)
            .field("user_config_path", &self.user_config_path)
            .field("lock_path", &self.lock_path)
            .field("maven_data", &self.maven_data.get())
            .finish()
    }
}

impl Clone for Config {
    fn clone(&self) -> Self {
        let maven_data = OnceLock::new();
        if let Some(data) = self.maven_data.get() {
            let _ = maven_data.set(data.clone());
        }
        Self {
            network: self.network.clone(),
            inactive_profiles: self.inactive_profiles.clone(),
            security: self.security.clone(),
            paths: self.paths.clone(),
            project_root: self.project_root.clone(),
            project_config_path: self.project_config_path.clone(),
            user_config_path: self.user_config_path.clone(),
            lock_path: self.lock_path.clone(),
            inputs: self.inputs.clone(),
            maven_data,
        }
    }
}

/// Computes the final set of active profile ids from `settings.xml` given the
/// explicit `<activeProfiles>` list. Mirrors Maven's `DefaultProfileSelector`:
///
/// 1. A profile is active if its id appears in `explicit_active_profiles`.
/// 2. A profile is active if its `<activation>` block has a `<jdk>`, `<os>`,
///    `<file>`, or `<property>` rule that matches the current system.
/// 3. A profile is active if its activation only sets `<activeByDefault>true</...>`
///    AND no other profile from this source has been activated by (1) or (2).
fn resolve_active_profiles(
    profiles: Option<&[MavenProfile]>,
    explicit_active_profiles: &[String],
) -> Vec<String> {
    let mut active: Vec<String> = explicit_active_profiles.to_vec();
    let Some(profiles) = profiles else {
        return active;
    };

    let ctx = ActivationContext::from_system();
    let mut any_rule_activated = false;
    let mut default_eligible: Vec<String> = Vec::new();

    for profile in profiles {
        let Some(id) = profile.profile.id.as_deref() else {
            continue;
        };
        let Some(activation) = profile.activation.as_ref() else {
            continue;
        };

        // `Activation::is_active` collapses rule and default sources; track
        // rule-only matches so `activeByDefault` can be suppressed when any
        // rule or explicit activation fires.
        let has_rule = activation.property.is_some()
            || activation.os.is_some()
            || activation.jdk.is_some()
            || activation.file.is_some();
        let rule_matched = has_rule && activation.is_active(&ctx);
        if rule_matched {
            if !active.iter().any(|a| a == id) {
                active.push(id.to_string());
            }
            any_rule_activated = true;
            continue;
        }

        if activation.active_by_default {
            default_eligible.push(id.to_string());
        }
    }

    // `<activeByDefault>` only kicks in when nothing else was activated for the
    // same profile source. Explicit `<activeProfiles>` and rule-based matches
    // both suppress the default-active fallback.
    let any_explicit = !explicit_active_profiles.is_empty();
    if !any_rule_activated && !any_explicit {
        for id in default_eligible {
            if !active.iter().any(|a| a == &id) {
                active.push(id);
            }
        }
    }

    active
}

impl Config {
    pub fn load(project_root: &Path) -> Result<Self, ConfigError> {
        if !project_root.exists() {
            return Err(ConfigError::ProjectRootMissing(project_root.to_path_buf()));
        }

        let paths = ResolvedPaths::discover()?;
        let project_config_path = project_root.join("rv.toml");
        let lock_path = project_root.join("rv.lock");
        let user_config_path = paths.config_file_path();

        let project_config = ProjectConfig::load(&project_config_path)?;
        let user_config = UserConfig::load(&user_config_path)?;

        // Opaque sinks parsed for back-compat: warn so users learn that
        // these sections are now ignored. The fields stay parseable
        // (deleting them under `deny_unknown_fields` would break existing
        // rv.toml files); pom.xml is the only manifest input in v1.
        warn_ignored_sink_field(&project_config_path, "mode", project_config.mode.is_some());
        warn_ignored_sink_field(
            &project_config_path,
            "project",
            project_config.project.is_some(),
        );
        warn_ignored_sink_field(
            &project_config_path,
            "dependencies",
            project_config.dependencies.is_some(),
        );
        warn_ignored_sink_field(&project_config_path, "vars", project_config.vars.is_some());
        warn_ignored_sink_field(
            &project_config_path,
            "policy",
            project_config.policy.is_some(),
        );
        warn_ignored_sink_field(
            &project_config_path,
            "dependency_management",
            project_config.dependency_management.is_some(),
        );
        warn_ignored_sink_field(
            &project_config_path,
            "build",
            project_config.build.is_some(),
        );
        warn_ignored_sink_field(&user_config_path, "mode", user_config.mode.is_some());

        // `[network]` merges per-field across layers: a field the project
        // file leaves unset inherits the user file's value (and only then
        // the built-in default), so a project that sets only `timeout` does
        // not silently reset user-level retries or concurrency.
        let project_network = project_config.network.unwrap_or_default();
        let user_network = user_config.network.unwrap_or_default();
        let mut network = NetworkConfig {
            timeout: project_network
                .timeout
                .or(user_network.timeout)
                .unwrap_or_else(default_timeout),
            retries: project_network
                .retries
                .or(user_network.retries)
                .unwrap_or_else(default_retries),
            concurrency: project_network
                .concurrency
                .or(user_network.concurrency)
                .unwrap_or_else(default_concurrency),
        };
        match std::env::var(RV_TIMEOUT_ENV) {
            Ok(val) => match val.parse() {
                Ok(timeout) => network.timeout = timeout,
                Err(e) => tracing::warn!(
                    env = RV_TIMEOUT_ENV,
                    value = %val,
                    error = %e,
                    "ignoring invalid RV_TIMEOUT value; expected a number"
                ),
            },
            Err(std::env::VarError::NotPresent) => {}
            Err(e) => tracing::warn!(env = RV_TIMEOUT_ENV, error = %e, "failed to read RV_TIMEOUT"),
        }
        match std::env::var(RV_RETRIES_ENV) {
            Ok(val) => match val.parse() {
                Ok(retries) => network.retries = retries,
                Err(e) => tracing::warn!(
                    env = RV_RETRIES_ENV,
                    value = %val,
                    error = %e,
                    "ignoring invalid RV_RETRIES value; expected a number"
                ),
            },
            Err(std::env::VarError::NotPresent) => {}
            Err(e) => tracing::warn!(env = RV_RETRIES_ENV, error = %e, "failed to read RV_RETRIES"),
        }

        let inactive_profiles = merge_option(
            project_config.inactive_profiles,
            user_config.inactive_profiles,
            Vec::new(),
        );

        // `[security]` takes the project file when present, otherwise the user
        // file, otherwise the safe-by-default empty config.
        let security = project_config
            .security
            .or(user_config.security)
            .unwrap_or_default();

        // Validate all allowlist entries are parseable URLs up-front so users
        // get a clear error at load time rather than a silent no-match later.
        security
            .validate_allowlist()
            .map_err(|msg| ConfigError::InvalidSettings(format!("[security] {msg}")))?;

        let inputs = ConfigInputs {
            project_repositories: project_config.repositories,
            project_mirrors: project_config.mirrors,
            project_auth: project_config.auth,
            project_proxies: project_config.proxies,
            project_local_repository: project_config.local_repository,
            project_active_profiles: project_config.active_profiles,
            user_repositories: user_config.repositories,
            user_mirrors: user_config.mirrors,
            user_auth: user_config.auth,
            user_proxies: user_config.proxies,
            user_local_repository: user_config.local_repository,
            user_active_profiles: user_config.active_profiles,
        };

        // Install the process-wide `${env.X}` POM substitution allowlist as
        // soon as we know it. The setter overwrites (last write wins); in
        // production this is the sole caller and runs once per CLI invocation,
        // so the policy is pinned for the lifetime of the process. Tests can
        // swap policies between scenarios; see
        // [`rv_maven_model::set_env_substitution_allowlist`].
        rv_maven_model::set_env_substitution_allowlist(security.allow_env_substitution.clone());

        let config = Self {
            network,
            inactive_profiles,
            security,
            paths,
            project_root: project_root.to_path_buf(),
            project_config_path,
            user_config_path,
            lock_path,
            inputs,
            maven_data: OnceLock::new(),
        };

        // A present-but-malformed settings.xml (bad XML, oversize, DOCTYPE,
        // non-UTF-8) must abort like Maven does, NOT silently fall back to
        // defaults. Falling back would drop the user's mirrors, server
        // credentials, and proxies and could send unauthenticated fetches to
        // an unexpected public host. An absent settings.xml is fine
        // (`load_default` returns `Ok(default)` for a missing file).
        MavenSettings::load_default().map_err(|err| {
            ConfigError::InvalidSettings(format!(
                "failed to load Maven settings.xml: {err}; fix or remove it"
            ))
        })?;

        // Eagerly populate the settings.xml-derived state on the sync
        // load path so the first async call into `repositories()`,
        // `mirrors()`, etc. doesn't block a tokio worker parsing XML.
        // Callers running off-runtime (CLI startup, tests) pay the same
        // cost they already would on first access.
        config.ensure_maven_settings_loaded();

        tracing::debug!(path = %project_root.display(), "config loaded");

        Ok(config)
    }

    fn maven_data(&self) -> &MavenSettingsData {
        self.maven_data.get_or_init(|| {
            let settings = MavenSettings::load_default().unwrap_or_else(|err| {
                tracing::warn!(error = %err, "failed to parse Maven settings.xml, using defaults");
                MavenSettings::default()
            });

            // Resolve the explicit active-profile list (project > user > settings.xml).
            // This seeds the active set; <activation> rules and <activeByDefault>
            // can extend it below.
            let explicit_active_profiles = self
                .inputs
                .project_active_profiles
                .as_ref()
                .or(self.inputs.user_active_profiles.as_ref())
                .cloned()
                .or_else(|| settings.active_profiles.clone())
                .unwrap_or_default();

            // Derive the full set of active profile ids by combining explicit
            // <activeProfiles>, rule-based <activation> matches, and the
            // <activeByDefault> fallback. Maven activates `<activeByDefault>true</...>`
            // profiles only when no other profile from the same source has been
            // activated by any other mechanism, matching `DefaultProfileSelector`.
            let active_profiles =
                resolve_active_profiles(settings.profiles.as_deref(), &explicit_active_profiles);

            // Collect repositories from the final set of active profiles.
            let settings_repositories = {
                if let Some(ref profiles) = settings.profiles {
                    let mut repos = Vec::new();
                    for profile in profiles {
                        let Some(id) = profile.profile.id.as_deref() else {
                            continue;
                        };
                        if active_profiles.iter().any(|ap| ap == id) {
                            repos.extend(profile.profile.repositories.clone());
                        }
                    }
                    if repos.is_empty() { None } else { Some(repos) }
                } else {
                    None
                }
            };

            let local_repository = self
                .inputs
                .project_local_repository
                .as_ref()
                .or(self.inputs.user_local_repository.as_ref())
                .cloned()
                .or(settings.local_repository);

            // Order repositories by precedence (project > user > settings),
            // matching mirrors and proxies below: resolution searches the
            // list in order, so the higher-precedence layer must come first
            // for a project rv.toml repo to out-prioritize a settings.xml
            // repo. On id collision the higher-precedence entry wins; the
            // lower layer only fills in fields left unset.
            let mut repositories = self.inputs.project_repositories.clone().unwrap_or_default();
            if let Some(ref user_repos) = self.inputs.user_repositories {
                merge_repositories(&mut repositories, user_repos);
            }
            merge_repositories(
                &mut repositories,
                &settings_repositories.unwrap_or_default(),
            );
            if repositories.is_empty() {
                repositories = default_repositories();
            }

            // Order mirrors by precedence (project > user > settings). Mirror
            // selection takes the first matching entry within a match class
            // (see MirrorSelector::matching_mirror), so the higher-precedence
            // layer must come first for a project rv.toml mirror to override a
            // settings.xml mirror of the same repository.
            let mut mirrors = Vec::new();
            if let Some(ref project_mirrors) = self.inputs.project_mirrors {
                mirrors.extend(project_mirrors.iter().cloned());
            }
            if let Some(ref user_mirrors) = self.inputs.user_mirrors {
                mirrors.extend(user_mirrors.iter().cloned());
            }
            mirrors.extend(settings.mirrors.unwrap_or_default());

            let mut auth = settings.servers.unwrap_or_default();
            if let Some(ref user_auth) = self.inputs.user_auth {
                merge_auth(&mut auth, user_auth);
            }
            if let Some(ref project_auth) = self.inputs.project_auth {
                merge_auth(&mut auth, project_auth);
            }

            // Order proxies by precedence (project > user > settings), for the
            // same first-match reason as mirrors above.
            let mut proxies = Vec::new();
            if let Some(ref project_proxies) = self.inputs.project_proxies {
                proxies.extend(project_proxies.iter().cloned());
            }
            if let Some(ref user_proxies) = self.inputs.user_proxies {
                proxies.extend(user_proxies.iter().cloned());
            }
            proxies.extend(settings.proxies.unwrap_or_default());

            tracing::debug!(
                mirror_count = mirrors.len(),
                server_count = auth.len(),
                repo_count = repositories.len(),
                proxy_count = proxies.len(),
                "settings.xml loaded"
            );

            MavenSettingsData {
                local_repository,
                repositories,
                mirrors,
                auth,
                proxies,
                active_profiles,
            }
        })
    }

    pub fn repositories(&self) -> &[RepoConfig] {
        &self.maven_data().repositories
    }

    pub fn mirrors(&self) -> &[MirrorConfig] {
        &self.maven_data().mirrors
    }

    pub fn auth(&self) -> &[AuthConfig] {
        &self.maven_data().auth
    }

    pub fn proxies(&self) -> &[ProxyConfig] {
        &self.maven_data().proxies
    }

    pub fn local_repository(&self) -> Option<&Path> {
        self.maven_data().local_repository.as_deref()
    }

    pub fn active_profiles(&self) -> &[String] {
        &self.maven_data().active_profiles
    }

    pub fn ensure_maven_settings_loaded(&self) {
        let _ = self.maven_data();
    }

    #[cfg(test)]
    pub fn for_testing(project_root: PathBuf, paths: ResolvedPaths) -> Self {
        Self::for_testing_with_repos(project_root, paths, Vec::new())
    }

    #[doc(hidden)]
    pub fn for_testing_with_repos(
        project_root: PathBuf,
        paths: ResolvedPaths,
        repositories: Vec<RepoConfig>,
    ) -> Self {
        Self::for_testing_with(project_root, paths, repositories, SecurityConfig::default())
    }

    /// The full-control `for_testing` variant. A test scenario can install an
    /// explicit [`SecurityConfig`] and propagate its `allow_env_substitution`
    /// into the process-wide allowlist used by `${env.X}` POM substitution. The
    /// plain `for_testing_with_repos` path delegates here with the
    /// safe-by-default empty `SecurityConfig`, which keeps env substitution
    /// disabled in tests while still threading the allowlist through so that the
    /// `OnceLock` policy matches `Config::load`'s production behaviour.
    #[doc(hidden)]
    pub fn for_testing_with(
        project_root: PathBuf,
        paths: ResolvedPaths,
        repositories: Vec<RepoConfig>,
        security: SecurityConfig,
    ) -> Self {
        let maven_data = OnceLock::new();
        let repositories = if repositories.is_empty() {
            default_repositories()
        } else {
            repositories
        };
        let _ = maven_data.set(MavenSettingsData {
            local_repository: None,
            repositories,
            mirrors: Vec::new(),
            auth: Vec::new(),
            proxies: Vec::new(),
            active_profiles: Vec::new(),
        });

        // Mirror the production `Config::load` path: the test-config
        // `security.allow_env_substitution` policy must be visible to
        // every `interpolate_str` call from this point forward, or the
        // OnceLock retains whichever allowlist the first test installed
        // and downstream scenarios silently observe the wrong policy.
        rv_maven_model::set_env_substitution_allowlist(security.allow_env_substitution.clone());

        Self {
            network: NetworkConfig::default(),
            inactive_profiles: Vec::new(),
            security,
            paths,
            project_config_path: project_root.join("rv.toml"),
            user_config_path: project_root.join("config.toml"),
            lock_path: project_root.join("rv.lock"),
            project_root,
            inputs: ConfigInputs {
                project_repositories: None,
                project_mirrors: None,
                project_auth: None,
                project_proxies: None,
                project_local_repository: None,
                project_active_profiles: None,
                user_repositories: None,
                user_mirrors: None,
                user_auth: None,
                user_proxies: None,
                user_local_repository: None,
                user_active_profiles: None,
            },
            maven_data,
        }
    }
}

fn merge_option<T>(project: Option<T>, user: Option<T>, default: T) -> T {
    project.or(user).unwrap_or(default)
}

/// Merge a lower-precedence `underlay` into `repositories`. An underlay entry
/// whose id already exists keeps the existing (higher-precedence) url and only
/// fills in the policy fields the existing entry left unset, which is the same
/// per-field override result as overlaying high on low; unseen ids and id-less
/// entries are appended, keeping higher-precedence layers first in search order.
fn merge_repositories(repositories: &mut Vec<RepoConfig>, underlay: &[RepoConfig]) {
    for repo in underlay {
        if let Some(id) = repo.id.as_deref()
            && let Some(existing) = repositories
                .iter_mut()
                .find(|existing| existing.id.as_deref() == Some(id))
        {
            if existing.releases.is_none() {
                existing.releases = repo.releases;
            }
            if existing.snapshots.is_none() {
                existing.snapshots = repo.snapshots;
            }
            if existing.snapshots_update_policy.is_none() {
                existing.snapshots_update_policy = repo.snapshots_update_policy;
            }
            continue;
        }
        repositories.push(repo.clone());
    }
}

fn merge_auth(auth: &mut Vec<AuthConfig>, overlay: &[AuthConfig]) {
    for entry in overlay {
        if let Some(id) = entry.id.as_deref()
            && let Some(existing) = auth.iter_mut().find(|item| item.id.as_deref() == Some(id))
        {
            if let Some(ref username) = entry.username {
                existing.username = Some(username.clone());
            }
            if let Some(ref password) = entry.password {
                existing.password = Some(password.clone());
            }
            if let Some(ref token) = entry.token {
                existing.token = Some(token.clone());
            }
            continue;
        }
        auth.push(entry.clone());
    }
}

fn default_repositories() -> Vec<RepoConfig> {
    vec![RepoConfig::maven_central(), RepoConfig::google()]
}

/// Parsed representation of a URL's origin: scheme, host, optional port, and path.
/// Used by `allows_transitive_repo_url` to compare origins without a full URL crate.
#[derive(Debug, PartialEq)]
struct UrlOrigin<'a> {
    scheme: &'a str,
    host: &'a str,
    /// Explicit port if present; `None` means rely on the scheme default.
    port: Option<u16>,
    /// Path component, always starts with `/`.
    path: &'a str,
}

/// Parse scheme, host, port, and path out of `url`. Returns `None` if the
/// string doesn't look like a valid `scheme://host[:port][/path]` URL.
fn parse_url_origin(url: &str) -> Option<UrlOrigin<'_>> {
    // Split at "://".
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return None;
    }
    // Authority ends at the first `/`, `?`, or `#`.
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    // Strip userinfo (everything before the last `@` in the authority).
    let authority = match authority.rfind('@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };
    // Split host:port, handling IPv6 literals `[::1]:8080`.
    let (host, port) = if authority.starts_with('[') {
        // IPv6: `[addr]:port` or `[addr]`.
        let close = authority.find(']')?;
        let host = &authority[..=close]; // include brackets
        let port_str = &authority[close + 1..];
        let port = if let Some(p) = port_str.strip_prefix(':') {
            Some(p.parse::<u16>().ok()?)
        } else {
            None
        };
        (host, port)
    } else {
        match authority.rfind(':') {
            Some(idx) => {
                let port_str = &authority[idx + 1..];
                // Make sure the "port" part is all digits (not part of the host).
                if port_str.chars().all(|c| c.is_ascii_digit()) && !port_str.is_empty() {
                    (&authority[..idx], Some(port_str.parse::<u16>().ok()?))
                } else {
                    (authority, None)
                }
            }
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(UrlOrigin {
        scheme,
        host,
        port,
        path: if path.is_empty() { "/" } else { path },
    })
}

/// Returns true iff `candidate` shares the same scheme/host/port as `allowed`,
/// and `candidate`'s path starts with `allowed`'s path.
fn url_origin_matches(allowed: &UrlOrigin<'_>, candidate: &UrlOrigin<'_>) -> bool {
    if !allowed.scheme.eq_ignore_ascii_case(candidate.scheme) {
        return false;
    }
    if !allowed.host.eq_ignore_ascii_case(candidate.host) {
        return false;
    }
    if allowed.port != candidate.port {
        return false;
    }
    // Path prefix match that aligns on a segment boundary, so
    // `/corp` does not prefix-match `/corp-evil`.
    let allowed_path = allowed.path;
    let candidate_path = candidate.path;
    if candidate_path == allowed_path {
        return true;
    }
    let sep_terminated = allowed_path.ends_with('/');
    candidate_path.starts_with(allowed_path)
        && (sep_terminated || candidate_path[allowed_path.len()..].starts_with('/'))
}

/// Build the warning text for an ignored rv.toml sink `field`.
///
/// Dependency-declaration fields (`dependencies`, `dependency_management`) get
/// a more pointed message so users do not assume rv.toml can drive resolution;
/// every other sink gets the generic "ignored section" note. rv.toml is
/// settings-only: pom.xml is the only manifest input in v1.
fn ignored_sink_message(field: &str) -> String {
    if matches!(field, "dependencies" | "dependency_management") {
        format!(
            "rv.toml is settings-only; the `{field}` section declares dependencies, which are ignored (pom.xml is the only manifest input). Remove the section to silence this warning."
        )
    } else {
        format!(
            "rv.toml `{field}` is ignored in v1; pom.xml is the only manifest input. Remove the section to silence this warning."
        )
    }
}

/// Surface a one-shot warning for an opaque sink field so the user notices
/// that a `[project]`, `[dependencies]`, `[vars]`, etc. block in their rv.toml
/// is being silently ignored (v1 reads pom.xml exclusively for manifest data).
/// `rv.toml` is settings-only; dependency declarations there have no effect.
fn warn_ignored_sink_field(source: &Path, field: &str, present: bool) {
    if !present {
        return;
    }
    tracing::warn!(
        path = %source.display(),
        field = field,
        "{}",
        ignored_sink_message(field)
    );
}

fn load_optional_toml<T: for<'de> Deserialize<'de> + Default>(
    path: &Path,
) -> Result<T, ConfigError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(err) => {
            return Err(Err(err)
                .with_context(|| format!("failed to read config {}", path.display()))
                .map_err(|err| ConfigError::Io(io_error_with_context(err)))?);
        }
    };
    toml::from_str(&contents)
        .with_context(|| format!("failed to parse TOML config {}", path.display()))
        .map_err(|err| ConfigError::TomlDeserialize(toml_de_error_with_context(err)))
}

#[cfg(test)]
mod tests {
    use super::{Config, ProjectConfig, UserConfig, ignored_sink_message};
    use crate::settings::{MirrorConfig, ProxyConfig, RepoConfig};
    use std::fs;
    use std::path::Path;

    fn write_toml(path: &Path, config: &impl serde::Serialize) {
        let contents = toml::to_string(config).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn with_raeva_home<F: FnOnce(&Path)>(f: F) {
        let home_tmp = tempfile::tempdir().unwrap();
        let home_dir = home_tmp.path();
        temp_env::with_vars(
            [
                ("RAEVA_HOME", Some(home_dir.to_string_lossy().as_ref())),
                ("HOME", Some(home_dir.to_string_lossy().as_ref())),
            ],
            || f(home_dir),
        );
    }

    #[test]
    fn project_config_overrides_user_config() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let project_config_path = project_root.join("rv.toml");
            let user_config_path = home_dir.join("config.toml");

            let project_config = ProjectConfig {
                repositories: Some(vec![RepoConfig {
                    id: Some("project".to_string()),
                    url: "https://project.example/maven2/".to_string(),
                    releases: Some(true),
                    snapshots: Some(false),
                    snapshots_update_policy: None,
                }]),
                ..Default::default()
            };
            write_toml(&project_config_path, &project_config);

            let user_config = UserConfig {
                repositories: Some(vec![RepoConfig {
                    id: Some("user".to_string()),
                    url: "https://user.example/maven2/".to_string(),
                    releases: Some(true),
                    snapshots: Some(false),
                    snapshots_update_policy: None,
                }]),
                ..Default::default()
            };
            write_toml(&user_config_path, &user_config);

            let config = Config::load(project_root).unwrap();
            assert_eq!(config.repositories().len(), 2);
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("project"))
            );
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("user"))
            );
        });
    }

    #[test]
    fn defaults_apply_when_configs_missing() {
        with_raeva_home(|_home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();

            let config = Config::load(project_root).unwrap();
            assert_eq!(config.repositories().len(), 2);
            assert_eq!(config.repositories()[0].id.as_deref(), Some("central"));
            assert_eq!(config.repositories()[1].id.as_deref(), Some("google"));
            assert!(config.local_repository().is_none());
        });
    }

    #[test]
    fn settings_merge_order_applies() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let project_config_path = project_root.join("rv.toml");
            let user_config_path = home_dir.join("config.toml");

            let m2_dir = home_dir.join(".m2");
            fs::create_dir_all(&m2_dir).unwrap();
            let settings_path = m2_dir.join("settings.xml");
            let settings_xml = r"
            <settings>
              <profiles>
                <profile>
                  <id>dev</id>
                  <repositories>
                    <repository>
                      <id>settings</id>
                      <url>https://settings.example/maven2/</url>
                    </repository>
                  </repositories>
                </profile>
              </profiles>
              <activeProfiles>
                <activeProfile>dev</activeProfile>
              </activeProfiles>
            </settings>
            ";
            fs::write(&settings_path, settings_xml).unwrap();

            let project_config = ProjectConfig {
                repositories: Some(vec![RepoConfig {
                    id: Some("project".to_string()),
                    url: "https://project.example/maven2/".to_string(),
                    releases: Some(true),
                    snapshots: Some(false),
                    snapshots_update_policy: None,
                }]),
                ..Default::default()
            };
            write_toml(&project_config_path, &project_config);

            let user_config = UserConfig {
                repositories: Some(vec![RepoConfig {
                    id: Some("user".to_string()),
                    url: "https://user.example/maven2/".to_string(),
                    releases: Some(true),
                    snapshots: Some(false),
                    snapshots_update_policy: None,
                }]),
                ..Default::default()
            };
            write_toml(&user_config_path, &user_config);

            let config = Config::load(project_root).unwrap();
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("settings"))
            );
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("user"))
            );
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("project"))
            );

            fs::remove_file(&project_config_path).unwrap();
            let config = Config::load(project_root).unwrap();
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("settings"))
            );
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("user"))
            );
            assert!(
                !config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("project"))
            );

            fs::remove_file(&user_config_path).unwrap();
            let config = Config::load(project_root).unwrap();
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("settings"))
            );
            assert!(
                !config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("user"))
            );
        });
    }

    /// Mirror precedence must be project > user > settings. Mirror selection
    /// takes the first matching entry within a match class, so the merged list
    /// must be ordered higher-precedence-first; otherwise a project rv.toml
    /// mirror cannot override a settings.xml mirror of the same repository.
    #[test]
    fn mirror_precedence_orders_project_over_user_over_settings() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let project_config_path = project_root.join("rv.toml");
            let user_config_path = home_dir.join("config.toml");

            let m2_dir = home_dir.join(".m2");
            fs::create_dir_all(&m2_dir).unwrap();
            let settings_xml = r"
            <settings>
              <mirrors>
                <mirror>
                  <id>settings-m</id>
                  <mirrorOf>central</mirrorOf>
                  <url>https://settings.example/maven2/</url>
                </mirror>
              </mirrors>
            </settings>
            ";
            fs::write(m2_dir.join("settings.xml"), settings_xml).unwrap();

            let project_config = ProjectConfig {
                mirrors: Some(vec![MirrorConfig {
                    id: Some("project-m".to_string()),
                    url: "https://project.example/maven2/".to_string(),
                    mirror_of: vec!["central".to_string()],
                }]),
                ..Default::default()
            };
            write_toml(&project_config_path, &project_config);

            let user_config = UserConfig {
                mirrors: Some(vec![MirrorConfig {
                    id: Some("user-m".to_string()),
                    url: "https://user.example/maven2/".to_string(),
                    mirror_of: vec!["central".to_string()],
                }]),
                ..Default::default()
            };
            write_toml(&user_config_path, &user_config);

            let config = Config::load(project_root).unwrap();
            let ids: Vec<&str> = config
                .mirrors()
                .iter()
                .filter_map(|m| m.id.as_deref())
                .collect();
            assert_eq!(
                ids,
                vec!["project-m", "user-m", "settings-m"],
                "project rv.toml mirror must take precedence over user and settings.xml"
            );
        });
    }

    /// Proxy precedence must be project > user > settings, for the same
    /// first-match reason as mirrors: `RepoClient` applies proxies in list
    /// order, so the higher-precedence layer must come first.
    #[test]
    fn proxy_precedence_orders_project_over_user_over_settings() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let user_config_path = home_dir.join("config.toml");

            let m2_dir = home_dir.join(".m2");
            fs::create_dir_all(&m2_dir).unwrap();
            let settings_xml = r"
            <settings>
              <proxies>
                <proxy>
                  <id>settings-p</id>
                  <active>true</active>
                  <protocol>http</protocol>
                  <host>settings.proxy.example</host>
                  <port>8080</port>
                </proxy>
              </proxies>
            </settings>
            ";
            fs::write(m2_dir.join("settings.xml"), settings_xml).unwrap();

            let proxy = |id: &str, host: &str| ProxyConfig {
                id: Some(id.to_string()),
                protocol: Some("http".to_string()),
                host: host.to_string(),
                port: 8080,
                auth_type: None,
                username: None,
                password: None,
                token_env: None,
                token: None,
                non_proxy_hosts: Vec::new(),
            };

            let project_config = ProjectConfig {
                proxies: Some(vec![proxy("project-p", "project.proxy.example")]),
                ..Default::default()
            };
            write_toml(&project_root.join("rv.toml"), &project_config);

            let user_config = UserConfig {
                proxies: Some(vec![proxy("user-p", "user.proxy.example")]),
                ..Default::default()
            };
            write_toml(&user_config_path, &user_config);

            let config = Config::load(project_root).unwrap();
            let ids: Vec<&str> = config
                .proxies()
                .iter()
                .filter_map(|p| p.id.as_deref())
                .collect();
            assert_eq!(
                ids,
                vec!["project-p", "user-p", "settings-p"],
                "project rv.toml proxy must take precedence over user and settings.xml"
            );
        });
    }

    /// Repository precedence must be project > user > settings, matching
    /// mirrors and proxies: resolution searches the merged list in order, so
    /// the project layer must lead. On id collision the higher-precedence
    /// entry wins and only inherits the policy fields it left unset.
    #[test]
    fn repository_precedence_orders_project_over_user_over_settings() {
        use crate::settings::UpdatePolicy;
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let user_config_path = home_dir.join("config.toml");

            let m2_dir = home_dir.join(".m2");
            fs::create_dir_all(&m2_dir).unwrap();
            let settings_xml = r"
            <settings>
              <profiles>
                <profile>
                  <id>dev</id>
                  <repositories>
                    <repository>
                      <id>settings-r</id>
                      <url>https://settings.example/maven2/</url>
                    </repository>
                    <repository>
                      <id>shared</id>
                      <url>https://settings.example/shared/</url>
                      <snapshots>
                        <enabled>true</enabled>
                        <updatePolicy>interval:15</updatePolicy>
                      </snapshots>
                    </repository>
                  </repositories>
                </profile>
              </profiles>
              <activeProfiles>
                <activeProfile>dev</activeProfile>
              </activeProfiles>
            </settings>
            ";
            fs::write(m2_dir.join("settings.xml"), settings_xml).unwrap();

            let repo = |id: &str, url: &str| RepoConfig {
                id: Some(id.to_string()),
                url: url.to_string(),
                releases: None,
                snapshots: None,
                snapshots_update_policy: None,
            };

            let project_config = ProjectConfig {
                repositories: Some(vec![
                    repo("project-r", "https://project.example/maven2/"),
                    repo("shared", "https://project.example/shared/"),
                ]),
                ..Default::default()
            };
            write_toml(&project_root.join("rv.toml"), &project_config);

            let user_config = UserConfig {
                repositories: Some(vec![repo("user-r", "https://user.example/maven2/")]),
                ..Default::default()
            };
            write_toml(&user_config_path, &user_config);

            let config = Config::load(project_root).unwrap();
            let ids: Vec<&str> = config
                .repositories()
                .iter()
                .filter_map(|r| r.id.as_deref())
                .collect();
            assert_eq!(
                ids,
                vec!["project-r", "shared", "user-r", "settings-r"],
                "project rv.toml repos must lead the merged list"
            );

            // The id-collision entry keeps the project url and inherits only
            // the policy fields the project layer left unset.
            let shared = config
                .repositories()
                .iter()
                .find(|r| r.id.as_deref() == Some("shared"))
                .unwrap();
            assert_eq!(shared.url, "https://project.example/shared/");
            assert_eq!(shared.snapshots, Some(true));
            assert_eq!(
                shared.snapshots_update_policy,
                Some(UpdatePolicy::Interval(15))
            );
        });
    }

    /// `[network]` must merge per-field across layers: a project rv.toml that
    /// sets only `timeout` must not reset user-level retries or concurrency
    /// back to the built-in defaults.
    #[test]
    fn network_section_merges_per_field_across_layers() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            fs::write(project_root.join("rv.toml"), "[network]\ntimeout = 60\n").unwrap();
            fs::write(
                home_dir.join("config.toml"),
                "[network]\nretries = 7\nconcurrency = 3\n",
            )
            .unwrap();

            let config = Config::load(project_root).unwrap();
            assert_eq!(config.network.timeout, 60, "project timeout must apply");
            assert_eq!(
                config.network.retries, 7,
                "user retries must survive a project [network] table"
            );
            assert_eq!(
                config.network.concurrency, 3,
                "user concurrency must survive a project [network] table"
            );
        });
    }

    /// A present-but-malformed settings.xml must make `Config::load` fail
    /// rather than silently falling back to defaults (which would drop the
    /// user's mirrors/credentials/proxies). An absent settings.xml is fine.
    #[test]
    fn malformed_settings_xml_is_a_hard_error() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();

            // Absent settings.xml: load succeeds.
            Config::load(project_root).expect("absent settings.xml must not error");

            // Now write a broken settings.xml.
            let m2_dir = home_dir.join(".m2");
            fs::create_dir_all(&m2_dir).unwrap();
            fs::write(
                m2_dir.join("settings.xml"),
                "<settings><mirrors><mirror></settings>not closed",
            )
            .unwrap();

            let err = Config::load(project_root)
                .expect_err("a malformed settings.xml must surface as a config error");
            let msg = format!("{err}");
            assert!(
                msg.contains("settings.xml"),
                "error should name settings.xml, got: {msg}"
            );
        });
    }

    /// rv.toml carrying pre-v1 manifest sections must still parse: v1
    /// keeps `[project]`, `[dependencies]`, `[dependency_management]`,
    /// `[vars]`, and `mode` as opaque sinks so existing configs do not
    /// break on upgrade. The CLI ignores their contents; pom.xml is the
    /// only manifest input.
    #[test]
    fn project_config_accepts_legacy_manifest_sections_as_opaque_sinks() {
        let toml = r#"
mode = "compat"

[project]
group = "com.example"
artifact = "demo"
version = "1.0.0"

[vars]
spring = "6.1.0"

[dependency_management]
imports = ["org.springframework.boot:spring-boot-dependencies:3.3.4"]

[dependencies]
compile = ["org.example:lib:1.0"]

[security]
allow_env_substitution = ["FOO"]

[[repositories]]
id = "internal"
url = "https://internal.example/maven2/"
"#;
        let cfg: ProjectConfig = toml::from_str(toml).expect("rv.toml must parse");
        assert!(cfg.mode.is_some());
        assert!(cfg.project.is_some());
        assert!(cfg.dependencies.is_some());
        assert!(cfg.dependency_management.is_some());
        assert!(cfg.vars.is_some());
        assert!(cfg.security.is_some());
        assert!(cfg.repositories.is_some());
    }

    /// Dependency-declaration sinks must produce a pointed "settings-only,
    /// declarations ignored" message; other sinks keep the generic note. Both
    /// always interpolate the concrete field name (regression guard against a
    /// literal `{field}` leaking into the text).
    #[test]
    fn ignored_sink_message_flags_dependency_declarations() {
        for field in ["dependencies", "dependency_management"] {
            let msg = ignored_sink_message(field);
            assert!(
                msg.contains("settings-only") && msg.contains("declares dependencies"),
                "dependency sink `{field}` should warn that declarations are ignored: {msg}"
            );
            assert!(msg.contains(field), "message must name the field: {msg}");
            assert!(!msg.contains("{field}"), "message must interpolate: {msg}");
        }

        for field in ["mode", "project", "vars", "policy", "build"] {
            let msg = ignored_sink_message(field);
            assert!(
                msg.contains("is ignored in v1") && !msg.contains("declares dependencies"),
                "non-dependency sink `{field}` should use the generic note: {msg}"
            );
            assert!(msg.contains(field), "message must name the field: {msg}");
            assert!(!msg.contains("{field}"), "message must interpolate: {msg}");
        }
    }

    // ---------- <activation> evaluation in settings.xml ----------

    /// Drops a `settings.xml` containing `xml_body` into `$HOME/.m2/`, writes
    /// a minimal `rv.toml` at `project_root`, and calls `Config::load`.
    fn load_with_settings(home_dir: &Path, project_root: &Path, xml_body: &str) -> Config {
        let m2_dir = home_dir.join(".m2");
        fs::create_dir_all(&m2_dir).unwrap();
        fs::write(m2_dir.join("settings.xml"), xml_body).unwrap();
        // Empty rv.toml so Config::load doesn't blow up on a missing file.
        let project_config_path = project_root.join("rv.toml");
        if !project_config_path.exists() {
            fs::write(&project_config_path, "").unwrap();
        }
        Config::load(project_root).unwrap()
    }

    #[test]
    fn active_by_default_publishes_repositories_when_no_explicit_profile_is_active() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let xml = r"
            <settings>
              <profiles>
                <profile>
                  <id>corp-default</id>
                  <activation>
                    <activeByDefault>true</activeByDefault>
                  </activation>
                  <repositories>
                    <repository>
                      <id>corp-mirror</id>
                      <url>https://corp.example/maven2/</url>
                    </repository>
                  </repositories>
                </profile>
              </profiles>
            </settings>
            ";
            let config = load_with_settings(home_dir, project_root, xml);
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("corp-mirror")),
                "expected <activeByDefault> profile to publish its repositories, got: {:?}",
                config.repositories()
            );
        });
    }

    #[test]
    fn jdk_activation_filters_profiles_by_version() {
        // Force JAVA_VERSION so ActivationContext::from_system picks a known JDK.
        with_raeva_home(|home_dir| {
            temp_env::with_var("JAVA_VERSION", Some("11.0.0"), || {
                let project_tmp = tempfile::tempdir().unwrap();
                let project_root = project_tmp.path();
                let xml = r"
                <settings>
                  <profiles>
                    <profile>
                      <id>jdk-1-8</id>
                      <activation>
                        <jdk>1.8</jdk>
                      </activation>
                      <repositories>
                        <repository>
                          <id>jdk8-repo</id>
                          <url>https://jdk8.example/maven2/</url>
                        </repository>
                      </repositories>
                    </profile>
                  </profiles>
                </settings>
                ";
                let config = load_with_settings(home_dir, project_root, xml);
                assert!(
                    !config
                        .repositories()
                        .iter()
                        .any(|repo| repo.id.as_deref() == Some("jdk8-repo")),
                    "profile gated on JDK 1.8 must NOT activate when JAVA_VERSION=11"
                );
            });
        });
    }

    #[test]
    fn property_activation_matches_environment() {
        with_raeva_home(|home_dir| {
            // Use an env.* property name so ActivationContext consults the env
            // directly; the temp_env override only affects this thread.
            let key = format!("RAEVA_H8_PROP_{}", std::process::id());
            temp_env::with_var(&key, Some("bar"), || {
                let project_tmp = tempfile::tempdir().unwrap();
                let project_root = project_tmp.path();
                // Opt this env var into the allowlist exactly as a real user
                // would via rv.toml's [security] allow_env_substitution.
                // Config::load eagerly resolves settings-profile activation
                // (ensure_maven_settings_loaded), so the policy must be installed
                // (here, parsed from rv.toml at load) *before* that resolution.
                fs::write(
                    project_root.join("rv.toml"),
                    format!("[security]\nallow_env_substitution = [\"{key}\"]\n"),
                )
                .unwrap();
                let xml = format!(
                    r#"
                <settings>
                  <profiles>
                    <profile>
                      <id>by-prop</id>
                      <activation>
                        <property>
                          <name>env.{key}</name>
                          <value>bar</value>
                        </property>
                      </activation>
                      <repositories>
                        <repository>
                          <id>prop-repo</id>
                          <url>https://prop.example/maven2/</url>
                        </repository>
                      </repositories>
                    </profile>
                  </profiles>
                </settings>
                "#
                );
                let config = load_with_settings(home_dir, project_root, &xml);
                assert!(
                    config
                        .repositories()
                        .iter()
                        .any(|repo| repo.id.as_deref() == Some("prop-repo")),
                    "expected <property> activation to match env.{key}=bar"
                );
            });
        });
    }

    #[test]
    fn file_exists_activation_toggles_on_filesystem() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let flag_path = home_dir.join("raeva-h8-flag");
            // `Activation::file::exists` is resolved against `ctx.base_dir`,
            // which `ActivationContext::from_system` sets to the current
            // working directory. Use an absolute path so the test holds
            // regardless of where cargo invokes it.
            let xml = format!(
                r#"
                <settings>
                  <profiles>
                    <profile>
                      <id>by-file</id>
                      <activation>
                        <file>
                          <exists>{}</exists>
                        </file>
                      </activation>
                      <repositories>
                        <repository>
                          <id>file-repo</id>
                          <url>https://file.example/maven2/</url>
                        </repository>
                      </repositories>
                    </profile>
                  </profiles>
                </settings>
                "#,
                flag_path.display()
            );
            // First: file is absent, so the profile must NOT activate.
            let config = load_with_settings(home_dir, project_root, &xml);
            assert!(
                !config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("file-repo")),
                "profile gated on existing file must be inactive when the file is missing"
            );

            // Second: create the file, and the profile must activate (Config
            // caches maven_data on first call, so build a fresh Config).
            fs::write(&flag_path, b"").unwrap();
            let config = load_with_settings(home_dir, project_root, &xml);
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("file-repo")),
                "profile gated on existing file must activate once the file exists"
            );

            fs::remove_file(&flag_path).unwrap();
        });
    }

    #[test]
    fn active_by_default_suppressed_by_explicit_active_profile() {
        // Maven semantics: when any explicit <activeProfiles> entry is present,
        // `<activeByDefault>` no longer applies (DefaultProfileSelector). The
        // default-eligible profile must NOT contribute its repos in that case.
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let xml = r"
            <settings>
              <profiles>
                <profile>
                  <id>by-default</id>
                  <activation>
                    <activeByDefault>true</activeByDefault>
                  </activation>
                  <repositories>
                    <repository>
                      <id>default-repo</id>
                      <url>https://default.example/maven2/</url>
                    </repository>
                  </repositories>
                </profile>
                <profile>
                  <id>chosen</id>
                  <repositories>
                    <repository>
                      <id>chosen-repo</id>
                      <url>https://chosen.example/maven2/</url>
                    </repository>
                  </repositories>
                </profile>
              </profiles>
              <activeProfiles>
                <activeProfile>chosen</activeProfile>
              </activeProfiles>
            </settings>
            ";
            let config = load_with_settings(home_dir, project_root, xml);
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("chosen-repo")),
                "explicit <activeProfiles> entry must activate its profile"
            );
            assert!(
                !config
                    .repositories()
                    .iter()
                    .any(|repo| repo.id.as_deref() == Some("default-repo")),
                "<activeByDefault> must NOT apply when another profile is explicitly active"
            );
        });
    }

    // ---- allow_project_local_certs is fully removed ----

    /// A config file that contains `security.allow_project_local_certs` must now
    /// fail to parse with a clear `deny_unknown_fields` error, giving the user an
    /// actionable message rather than silently ignoring a dead knob.
    #[test]
    fn project_config_rejects_allow_project_local_certs() {
        let toml = r#"
[security]
allow_project_local_certs = true
"#;
        let result: Result<ProjectConfig, _> = toml::from_str(toml);
        assert!(
            result.is_err(),
            "allow_project_local_certs must be rejected by deny_unknown_fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("allow_project_local_certs") || err.contains("unknown field"),
            "error should mention the unknown field: {err}"
        );
    }

    // ---- origin-aware allowlist matching ----

    /// `https://corp.example` must NOT match `https://corp.example.evil.com/`.
    /// Prefix-only matching on the raw string would incorrectly allow this.
    #[test]
    fn allowlist_does_not_match_subdomain_extension() {
        use super::SecurityConfig;
        let security = SecurityConfig {
            transitive_repository_allowlist: vec!["https://corp.example".to_string()],
            ..Default::default()
        };
        // Same string prefix but different host: must be rejected.
        assert!(
            !security.allows_transitive_repo_url("https://corp.example.evil.com/maven2/"),
            "https://corp.example.evil.com must NOT match allowlist entry https://corp.example"
        );
        // Exact host match: must pass.
        assert!(
            security.allows_transitive_repo_url("https://corp.example/maven2/"),
            "https://corp.example/maven2/ must match allowlist entry https://corp.example"
        );
        // Subpath of the allowlist entry host: must pass.
        assert!(
            security.allows_transitive_repo_url("https://corp.example/deep/path/"),
            "subpath of allowlisted host must pass"
        );
    }

    /// An allowlist entry with an explicit path must only match URLs whose path
    /// starts with the entry's path on a segment boundary, not a raw prefix match.
    #[test]
    fn allowlist_path_must_align_on_segment_boundary() {
        use super::SecurityConfig;
        let security = SecurityConfig {
            transitive_repository_allowlist: vec!["https://corp.example/maven2".to_string()],
            ..Default::default()
        };
        // Extends the path with a new segment: must pass.
        assert!(security.allows_transitive_repo_url("https://corp.example/maven2/sub/"),);
        // Same path verbatim: must pass.
        assert!(security.allows_transitive_repo_url("https://corp.example/maven2"),);
        // Path that shares the prefix but not a segment boundary: must NOT pass.
        assert!(
            !security.allows_transitive_repo_url("https://corp.example/maven2-evil/"),
            "/maven2-evil must not match /maven2 allowlist entry"
        );
    }

    /// An allowlist entry with an explicit port must only match URLs on the same port.
    #[test]
    fn allowlist_port_must_match_exactly() {
        use super::SecurityConfig;
        let security = SecurityConfig {
            transitive_repository_allowlist: vec!["https://corp.example:8443/maven2/".to_string()],
            ..Default::default()
        };
        assert!(
            security.allows_transitive_repo_url("https://corp.example:8443/maven2/"),
            "exact port must match"
        );
        assert!(
            !security.allows_transitive_repo_url("https://corp.example/maven2/"),
            "no port (default 443) must NOT match an entry with explicit port 8443"
        );
        assert!(
            !security.allows_transitive_repo_url("https://corp.example:9999/maven2/"),
            "different port must NOT match"
        );
    }

    /// An unparseable allowlist entry must surface a `ConfigError::InvalidSettings`
    /// error at load time, not a silent no-match.
    #[test]
    fn unparseable_allowlist_entry_rejected_at_config_load() {
        with_raeva_home(|_home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let project_config_path = project_root.join("rv.toml");
            fs::write(
                &project_config_path,
                r#"[security]
transitive_repository_allowlist = ["not-a-url"]
"#,
            )
            .unwrap();
            let err = Config::load(project_root).expect_err("bad allowlist must error");
            let msg = err.to_string();
            assert!(
                msg.contains("not-a-url") || msg.contains("transitive_repository_allowlist"),
                "error must identify the bad entry: {msg}"
            );
        });
    }

    // ---- merge test for project+user config ----

    /// A project config and a user config with disjoint fields must merge
    /// correctly with project taking precedence on shared fields (network).
    #[test]
    fn project_and_user_configs_merge_correctly() {
        with_raeva_home(|home_dir| {
            let project_tmp = tempfile::tempdir().unwrap();
            let project_root = project_tmp.path();
            let project_config_path = project_root.join("rv.toml");
            let user_config_path = home_dir.join("config.toml");

            // Project sets a custom timeout; user sets a different one.
            // Project should win.
            let project_toml = r#"
[network]
timeout = 60
retries = 5

[[repositories]]
id = "project-repo"
url = "https://project.example/maven2/"
"#;
            let user_toml = r#"
[network]
timeout = 10
retries = 1

[[repositories]]
id = "user-repo"
url = "https://user.example/maven2/"
"#;
            fs::write(&project_config_path, project_toml).unwrap();
            fs::write(&user_config_path, user_toml).unwrap();

            let config = Config::load(project_root).unwrap();
            // Project network config takes precedence.
            assert_eq!(config.network.timeout, 60);
            assert_eq!(config.network.retries, 5);
            // Both repos appear.
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|r| r.id.as_deref() == Some("project-repo")),
                "project repo must be present"
            );
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|r| r.id.as_deref() == Some("user-repo")),
                "user repo must be present"
            );
        });
    }
}
