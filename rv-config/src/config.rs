use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use sha2::Digest;

use rv_maven_model::{
    Activation, ActivationContext, HostInput, HostSnapshot, ModelEnvironment, PropertyMap,
};

use crate::error::{ConfigError, ConfigOrigin};
use crate::maven_config::{CommandLine, MavenConfigOptions};
use crate::maven_settings::{MavenProfile, MavenSettings};
use crate::paths::ResolvedPaths;
use crate::settings::{AuthConfig, MirrorConfig, ProxyConfig, RepoConfig};

/// Security-related configuration toggles.
///
/// In a loaded [`Config`] this is the merged policy: the user `config.toml`
/// sets it, and a project `raeva.toml` can only narrow it.
///
/// Designed to be additive and forward-compatible: every field has a safe-by-default
/// value, and missing fields deserialize to that default. New entries should also be
/// purely additive so older `raeva.toml` files keep parsing.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
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
    /// variables in explicitly, in the user `config.toml`.
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
    pub allow_transitive_repositories: bool,

    /// URL-prefix allowlist for transitive `<repositories>` declarations. Even when
    /// [`Self::allow_transitive_repositories`] is `false`, a transitive repository
    /// whose URL starts with one of these prefixes is accepted.
    ///
    /// Default is empty.
    pub transitive_repository_allowlist: Vec<String>,
}

impl SecurityConfig {
    /// Whether a repository URL a dependency POM declares may be searched.
    /// Only parsed HTTP(S) URLs are eligible, even with the global allow-flag.
    /// Otherwise the URL must share the same scheme, host, and port as one of
    /// the allowlist entries, and the candidate path must start with the
    /// allowlist entry's path (preventing `corp.example` from matching
    /// `corp.example.evil.com`).
    pub fn allows_transitive_repo_url(&self, url: &str) -> bool {
        let Some(candidate) = parse_url_origin(url) else {
            return false;
        };
        if self.allow_transitive_repositories {
            return true;
        }
        self.transitive_repository_allowlist
            .iter()
            .filter_map(|entry| parse_url_origin(entry))
            .any(|allowed| url_origin_matches(&allowed, &candidate))
    }

    /// Validate that every entry in the `transitive_repository_allowlist` can
    /// be parsed as a URL. Names the first unparseable entry by its position,
    /// and shows it redacted, so `Config::load` can surface a clear error
    /// before any resolution begins.
    pub(crate) fn validate_allowlist(&self) -> Result<(), String> {
        for (index, name) in self.allow_env_substitution.iter().enumerate() {
            if !is_env_var_name(name) {
                return Err(format!(
                    "allow_env_substitution entry {} must be an environment variable name made of \
                     ASCII letters, digits and '_', not starting with a digit",
                    index + 1
                ));
            }
        }
        for (index, entry) in self.transitive_repository_allowlist.iter().enumerate() {
            if parse_url_origin(entry).is_none() {
                return Err(format!(
                    "transitive_repository_allowlist entry {} must be an HTTP(S) URL: {}",
                    index + 1,
                    crate::redact_url(entry)
                ));
            }
        }
        Ok(())
    }
}

/// The rule raeva.lock applies to the variable names it records: ASCII letters,
/// digits and `_`, not starting with a digit, at most 255 bytes.
fn is_env_var_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 255
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// `[security]` table as written in raeva.toml / config.toml. Fields are
/// optional so the merge can tell a key the project file leaves out, which
/// inherits the user file's value, from one it sets, which may only narrow
/// it. `Config::load` resolves both tables into [`SecurityConfig`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct SecurityConfigToml {
    pub allow_env_substitution: Option<Vec<String>>,
    pub allow_transitive_repositories: Option<bool>,
    pub transitive_repository_allowlist: Option<Vec<String>>,
}

/// Merge `[security]` so that a project `raeva.toml`, which arrives with a
/// cloned repository, can only narrow what the user `config.toml` allows.
/// Every key widens what raeva trusts when it grows:
///
/// - `allow_env_substitution` keeps the project's names that the user list
///   also holds;
/// - `allow_transitive_repositories` is true only when both files allow it;
/// - `transitive_repository_allowlist` keeps the project's entries that the
///   user policy already accepts, through its flag or a user entry the
///   project entry falls under.
///
/// A key the project leaves out takes the user value. Returns the merged
/// policy and the project keys that asked for more than the user allows.
fn merge_security(
    project: Option<SecurityConfigToml>,
    user: Option<SecurityConfigToml>,
    (project_origin, user_origin): &(ConfigOrigin, ConfigOrigin),
) -> Result<(SecurityConfig, Vec<&'static str>), ConfigError> {
    let user = user.unwrap_or_default();
    let user = SecurityConfig {
        allow_env_substitution: user.allow_env_substitution.unwrap_or_default(),
        allow_transitive_repositories: user.allow_transitive_repositories.unwrap_or(false),
        transitive_repository_allowlist: user.transitive_repository_allowlist.unwrap_or_default(),
    };
    user.validate_allowlist()
        .map_err(|message| invalid_security(user_origin, message))?;
    let Some(project) = project else {
        return Ok((user, Vec::new()));
    };

    let mut merged = user.clone();
    let mut widened = Vec::new();
    if let Some(names) = project.allow_env_substitution {
        let (kept, dropped): (Vec<_>, Vec<_>) = names
            .into_iter()
            .partition(|name| user.allow_env_substitution.contains(name));
        if !dropped.is_empty() {
            widened.push("allow_env_substitution");
        }
        merged.allow_env_substitution = kept;
    }
    if let Some(allow) = project.allow_transitive_repositories {
        if allow && !user.allow_transitive_repositories {
            widened.push("allow_transitive_repositories");
        }
        merged.allow_transitive_repositories = allow && user.allow_transitive_repositories;
    }
    if let Some(entries) = project.transitive_repository_allowlist {
        SecurityConfig {
            transitive_repository_allowlist: entries.clone(),
            ..SecurityConfig::default()
        }
        .validate_allowlist()
        .map_err(|message| invalid_security(project_origin, message))?;
        let (kept, dropped): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|entry| user.allows_transitive_repo_url(entry));
        if !dropped.is_empty() {
            widened.push("transitive_repository_allowlist");
        }
        merged.transitive_repository_allowlist = kept;
    }
    Ok((merged, widened))
}

/// The `protocol` values a proxy accepts. `protocol` picks the URL schemes
/// a proxy carries, and raeva fetches only `http` and `https` URLs, so a proxy
/// with any other value, such as `socks5`, would carry nothing and its
/// traffic would go direct.
pub(crate) const PROXY_PROTOCOLS: [&str; 3] = ["http", "https", "all"];

/// Whether `protocol` (absent means `http`) is one [`PROXY_PROTOCOLS`] lists,
/// ignoring ASCII case.
pub(crate) fn is_supported_proxy_protocol(protocol: Option<&str>) -> bool {
    protocol.is_none_or(|protocol| {
        PROXY_PROTOCOLS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(protocol))
    })
}

fn check_proxy_protocols(
    proxies: &[ProxyConfig],
    origin: &ConfigOrigin,
) -> Result<(), ConfigError> {
    for proxy in proxies {
        if !is_supported_proxy_protocol(proxy.protocol.as_deref()) {
            return Err(ConfigError::Invalid {
                origin: origin.clone(),
                message: format!(
                    "the proxy for {:?} has protocol {:?}; use http, https or all",
                    proxy.host.rsplit('@').next().unwrap_or_default(),
                    proxy.protocol.as_deref().unwrap_or_default()
                ),
            });
        }
    }
    Ok(())
}

/// Proxies and mirrors describe the machine's network, and a project
/// `raeva.toml` arrives with a cloned repository: a proxy it named would see
/// every plain-HTTP request, with its `Authorization` header, and a mirror
/// would take the requests for every repository it covers, with the
/// credential of the id it names. Maven reads neither from a project.
fn refuse_project_endpoints(
    project: &ConfigFile,
    origins: &(ConfigOrigin, ConfigOrigin),
) -> Result<(), ConfigError> {
    let key = if project.proxies.is_some() {
        "[[proxies]]"
    } else if project.mirrors.is_some() {
        "[[mirrors]]"
    } else {
        return Ok(());
    };
    Err(ConfigError::Invalid {
        origin: origins.0.clone(),
        message: format!(
            "{key} is not allowed in a project raeva.toml, since it belongs to this machine's \
             network, not to the project; move it to {}",
            origins.1
        ),
    })
}

/// Refuse a repository or mirror URL that carries userinfo, a query or a
/// fragment. raeva.lock records repository URLs as written, so a password in
/// one would end up in a tracked file; credentials go in an `[[auth]]` entry
/// or a settings.xml `<server>` with the repository's id, as Maven keeps
/// them in `<server>`. The message names the entry, never the URL.
fn refuse_secret_urls<'a>(
    urls: impl IntoIterator<Item = (&'static str, Option<&'a str>, &'a str)>,
    origin: &ConfigOrigin,
) -> Result<(), ConfigError> {
    for (kind, id, url) in urls {
        let Some(part) = crate::redact::secret_url_part(url) else {
            continue;
        };
        let entry = match id {
            Some(id) => format!("{kind} '{id}'"),
            None => format!("a {kind} without an id"),
        };
        let fix = match part {
            "userinfo" => {
                "remove it and put the credentials in an [[auth]] entry in config.toml or a \
                 <server> in settings.xml with the repository's id"
            }
            _ => "remove it; a repository URL is a base that raeva appends artifact paths to",
        };
        return Err(ConfigError::Invalid {
            origin: origin.clone(),
            message: format!("the URL of {entry} has {part}, which raeva.lock would record; {fix}"),
        });
    }
    Ok(())
}

/// Refuse a repository or mirror URL that is not an `http`, `https` or
/// `file` URL, naming its entry and file, before a fetch fails on it as
/// "relative URL without a base" or "builder error". The URL is not
/// quoted: text that does not parse may hold a credential redaction misses.
fn refuse_unusable_urls<'a>(
    urls: impl IntoIterator<Item = (&'static str, Option<&'a str>, &'a str)>,
    origin: &ConfigOrigin,
) -> Result<(), ConfigError> {
    for (kind, id, url) in urls {
        let problem = match url::Url::parse(url.trim()) {
            Ok(url) if matches!(url.scheme(), "http" | "https" | "file") => continue,
            Ok(url) => format!(
                "has scheme '{}'; raeva reads http, https and file URLs",
                rv_maven_types::bounded(url.scheme())
            ),
            Err(error) => format!("is not a URL ({error})"),
        };
        let entry = match id {
            Some(id) => format!("{kind} '{}'", rv_maven_types::bounded(id)),
            None => format!("a {kind} without an id"),
        };
        return Err(ConfigError::Invalid {
            origin: origin.clone(),
            message: format!("the URL of {entry} {problem}"),
        });
    }
    Ok(())
}

fn repository_urls<'a>(
    repositories: Option<&'a Vec<RepoConfig>>,
    mirrors: Option<&'a Vec<MirrorConfig>>,
) -> impl Iterator<Item = (&'static str, Option<&'a str>, &'a str)> {
    let repositories = repositories
        .into_iter()
        .flatten()
        .map(|repo| ("repository", repo.id.as_deref(), repo.url.as_str()));
    let mirrors = mirrors
        .into_iter()
        .flatten()
        .map(|mirror| ("mirror", mirror.id.as_deref(), mirror.url.as_str()));
    repositories.chain(mirrors)
}

fn invalid_security(origin: &ConfigOrigin, message: String) -> ConfigError {
    ConfigError::Invalid {
        origin: origin.clone(),
        message: format!("security.{message}"),
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ConfigFile {
    pub local_repository: Option<PathBuf>,
    pub repositories: Option<Vec<RepoConfig>>,
    pub mirrors: Option<Vec<MirrorConfig>>,
    pub auth: Option<Vec<AuthConfig>>,
    pub proxies: Option<Vec<ProxyConfig>>,
    pub network: Option<NetworkConfigToml>,
    pub lock: Option<LockConfigToml>,
    pub active_profiles: Option<Vec<String>>,
    pub inactive_profiles: Option<Vec<String>>,
    pub security: Option<SecurityConfigToml>,
}

/// The `[lock]` settings in effect.
///
/// [`Config::load`] takes `jdks` from the project `raeva.toml`, else the user
/// `config.toml`, else an empty list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockConfig {
    /// The `java.version` values `raeva sync` resolves each platform for.
    /// An empty list means the host's JDK alone.
    pub jdks: Vec<String>,
}

/// `[lock]` table as written in raeva.toml / config.toml.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LockConfigToml {
    pub jdks: Option<Vec<String>>,
}

/// Whether `jdk` is a valid `[lock] jdks` entry or `[[platforms]] jdk` value:
/// 1 to 32 ASCII letters, digits, `.`, `_`, `-` or `+`.
pub fn is_valid_jdk(jdk: &str) -> bool {
    !jdk.is_empty()
        && jdk.len() <= 32
        && jdk
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

/// Whether a host's `java.version` matches a `[lock] jdks` entry: equal to
/// `target`, or starting with `target` followed by `.`, `_` or `-`.
pub fn jdk_matches_target(target: &str, host_java_version: &str) -> bool {
    let host = host_java_version.trim();
    host == target
        || host
            .strip_prefix(target)
            .is_some_and(|rest| rest.starts_with(['.', '_', '-']))
}

fn merge_lock(
    project: Option<LockConfigToml>,
    user: Option<LockConfigToml>,
    origins: &(ConfigOrigin, ConfigOrigin),
) -> Result<LockConfig, ConfigError> {
    let (p, u) = (project.unwrap_or_default(), user.unwrap_or_default());
    let (jdks, origin) = layered(p.jdks, u.jdks, Vec::new(), origins);
    if let Some(origin) = origin {
        for (index, jdk) in jdks.iter().enumerate() {
            if !is_valid_jdk(jdk) {
                return Err(ConfigError::Invalid {
                    origin,
                    message: format!(
                        "lock.jdks entry {} must be 1 to 32 ASCII letters, digits, '.', '_', \
                         '-' or '+'",
                        index + 1
                    ),
                });
            }
            if jdks[..index].contains(jdk) {
                return Err(ConfigError::Invalid {
                    origin,
                    message: format!("lock.jdks lists {jdk:?} more than once"),
                });
            }
        }
    }
    Ok(LockConfig { jdks })
}

impl ConfigFile {
    fn load(path: &Path, origin: ConfigOrigin) -> Result<Self, ConfigError> {
        let Some(contents) = crate::read_optional_project_input_string(path)? else {
            return Ok(Self::default());
        };
        toml::from_str(&contents).map_err(|err| {
            // serde ends most messages with its list of expected keys or
            // types, which can run past `bounded`'s cut. Any other text may
            // quote the file, so it is escaped and cut.
            let (found, expected) = match err.message().rsplit_once(", expected ") {
                Some((found, expected))
                    if expected.len() <= 400 && rv_maven_types::is_terminal_safe(expected) =>
                {
                    (found, Some(expected))
                }
                _ => (err.message(), None),
            };
            // A value in the wrong place may be a secret, such as a numeric
            // `password`, so only its type is named.
            let found = match found.split_once(['`', '"']) {
                Some((kind, _))
                    if ["invalid type: ", "invalid value: ", "unknown variant "]
                        .iter()
                        .any(|start| found.starts_with(start)) =>
                {
                    kind.trim_end()
                }
                _ => found,
            };
            let found = rv_maven_types::bounded(found);
            let message = match expected {
                Some(expected) => format!("{found}, expected {expected}"),
                None => found.to_string(),
            };
            let message = match err.span() {
                Some(span) => {
                    let before = contents.as_bytes().get(..span.start).unwrap_or_default();
                    let line = 1 + before.iter().filter(|&&b| b == b'\n').count();
                    format!("line {line}: {message}")
                }
                None => message,
            };
            ConfigError::Invalid { origin, message }
        })
    }
}

/// The `[network]` settings in effect.
///
/// [`Config::load`] takes each key from the project `raeva.toml`, else the user
/// `config.toml`, else the default, then applies the `RAEVA_TIMEOUT`,
/// `RAEVA_RETRIES`, `RAEVA_LOW_SPEED_LIMIT` and `RAEVA_LOW_SPEED_TIME`
/// overrides. An override that is not a number fails the load, as does a
/// timeout, retry count or `low_speed_time` out of range, from a file or
/// the environment. [`MAX_ARTIFACT_SIZE_ENV`] alone sets
/// [`Self::max_artifact_size`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NetworkConfig {
    /// Request timeout in seconds, from 1 to 86400. Default 30.
    pub timeout: u64,
    /// Network retry attempts, at most 100. Default 3.
    pub retries: usize,
    /// How many downloads run at once. Default 8, with no environment
    /// override. Stages use [`Self::fetch_concurrency`].
    pub concurrency: usize,
    /// Minimum artifact body throughput in bytes/s; zero disables the check.
    pub low_speed_limit: u64,
    /// Rolling throughput window in seconds (must be positive).
    pub low_speed_time: u64,
    /// Largest artifact body a download accepts, in bytes. Set only by
    /// [`MAX_ARTIFACT_SIZE_ENV`]; raeva.toml has no key for it.
    pub max_artifact_size: u64,
}

/// Environment variable setting [`NetworkConfig::max_artifact_size`].
pub const MAX_ARTIFACT_SIZE_ENV: &str = "RAEVA_MAX_ARTIFACT_SIZE";
/// [`NetworkConfig::max_artifact_size`] when the environment does not set
/// it: 16 GiB.
const DEFAULT_MAX_ARTIFACT_SIZE: u64 = 16 * 1024 * 1024 * 1024;

/// The artifact size cap from [`MAX_ARTIFACT_SIZE_ENV`]. A value that is not
/// a positive number is ignored with a warning.
fn max_artifact_size_from_env() -> u64 {
    match std::env::var(MAX_ARTIFACT_SIZE_ENV) {
        Ok(val) => match val.trim().parse::<u64>() {
            Ok(limit) if limit > 0 => limit,
            _ => {
                tracing::warn!(
                    sec_code = "SETTING_IGNORED",
                    env = MAX_ARTIFACT_SIZE_ENV,
                    value = %val,
                    "ignoring invalid RAEVA_MAX_ARTIFACT_SIZE value; expected a positive byte count"
                );
                DEFAULT_MAX_ARTIFACT_SIZE
            }
        },
        Err(_) => DEFAULT_MAX_ARTIFACT_SIZE,
    }
}

/// `[network]` table as written in raeva.toml / config.toml. Fields are optional
/// so layering can tell "unset" apart from "explicitly set": a field the
/// project file leaves out inherits the user file's value instead of
/// resetting it to the default. `Config::load` resolves the merged table
/// into [`NetworkConfig`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NetworkConfigToml {
    pub timeout: Option<u64>,
    pub retries: Option<usize>,
    pub concurrency: Option<usize>,
    pub low_speed_limit: Option<u64>,
    pub low_speed_time: Option<u64>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout: 30,
            retries: 3,
            concurrency: 8,
            low_speed_limit: 1024,
            low_speed_time: 30,
            max_artifact_size: DEFAULT_MAX_ARTIFACT_SIZE,
        }
    }
}

/// Largest accepted `network.timeout`, in seconds (one day).
const MAX_NETWORK_TIMEOUT_SECS: u64 = 86_400;
/// Largest accepted `network.retries`.
const MAX_NETWORK_RETRIES: usize = 100;
/// Largest `network.concurrency` a stage runs with.
const MAX_NETWORK_CONCURRENCY: usize = 128;

impl NetworkConfig {
    /// Files in flight for one stage: [`Self::concurrency`] clamped to `1..=128`.
    /// Zero counts as one.
    pub fn fetch_concurrency(&self) -> usize {
        self.concurrency.clamp(1, MAX_NETWORK_CONCURRENCY)
    }

    /// Reject values no network could need. A checked-in raeva.toml is
    /// semi-trusted input, and an unbounded retry count or timeout would
    /// keep `raeva sync` running for years against an unreachable host.
    /// Each origin is where the value came from; `None` is the built-in
    /// default, which is always valid.
    fn validate(
        &self,
        timeout: Option<ConfigOrigin>,
        retries: Option<ConfigOrigin>,
        low_speed_time: Option<ConfigOrigin>,
    ) -> Result<(), ConfigError> {
        if let Some(origin) = timeout
            && !(1..=MAX_NETWORK_TIMEOUT_SECS).contains(&self.timeout)
        {
            return Err(invalid_network(
                origin,
                "timeout",
                format!(
                    "must be between 1 and {MAX_NETWORK_TIMEOUT_SECS} seconds, got {}",
                    self.timeout
                ),
            ));
        }
        if let Some(origin) = retries
            && self.retries > MAX_NETWORK_RETRIES
        {
            return Err(invalid_network(
                origin,
                "retries",
                format!(
                    "must be at most {MAX_NETWORK_RETRIES}, got {}",
                    self.retries
                ),
            ));
        }
        if let Some(origin) = low_speed_time
            && self.low_speed_time == 0
        {
            let disable = match origin {
                ConfigOrigin::Env(_) => format!("{LOW_SPEED_LIMIT_ENV}=0"),
                _ => "low_speed_limit = 0".to_string(),
            };
            return Err(invalid_network(
                origin,
                "low_speed_time",
                format!("must be a positive number of seconds; use {disable} to disable the check"),
            ));
        }
        Ok(())
    }
}

fn invalid_network(origin: ConfigOrigin, key: &str, rule: String) -> ConfigError {
    let message = match origin {
        ConfigOrigin::Env(_) => rule,
        _ => format!("network.{key} {rule}"),
    };
    ConfigError::Invalid { origin, message }
}

fn layered<T>(
    project: Option<T>,
    user: Option<T>,
    default: T,
    (project_origin, user_origin): &(ConfigOrigin, ConfigOrigin),
) -> (T, Option<ConfigOrigin>) {
    match (project, user) {
        (Some(value), _) => (value, Some(project_origin.clone())),
        (None, Some(value)) => (value, Some(user_origin.clone())),
        (None, None) => (default, None),
    }
}

/// Environment variable overriding `network.timeout` (request timeout in seconds).
const TIMEOUT_ENV: &str = "RAEVA_TIMEOUT";
/// Environment variable overriding `network.retries` (network retry attempts).
const RETRIES_ENV: &str = "RAEVA_RETRIES";
const LOW_SPEED_LIMIT_ENV: &str = "RAEVA_LOW_SPEED_LIMIT";
const LOW_SPEED_TIME_ENV: &str = "RAEVA_LOW_SPEED_TIME";

/// Profile ids to deactivate: user first, then project ids not already listed.
/// Missing and empty lists both add nothing, so a project cannot clear the
/// user's denylist.
fn merge_inactive_profiles(project: Option<Vec<String>>, user: Option<Vec<String>>) -> Vec<String> {
    let mut merged = user.unwrap_or_default();
    for id in project.unwrap_or_default() {
        if !merged.contains(&id) {
            merged.push(id);
        }
    }
    merged
}

fn merge_network(
    project: Option<NetworkConfigToml>,
    user: Option<NetworkConfigToml>,
    origins: &(ConfigOrigin, ConfigOrigin),
) -> Result<NetworkConfig, ConfigError> {
    let (p, u) = (project.unwrap_or_default(), user.unwrap_or_default());
    let d = NetworkConfig::default();
    let max_artifact_size = max_artifact_size_from_env();
    let mut timeout = layered(p.timeout, u.timeout, d.timeout, origins);
    let mut retries = layered(p.retries, u.retries, d.retries, origins);
    let mut time = layered(
        p.low_speed_time,
        u.low_speed_time,
        d.low_speed_time,
        origins,
    );
    let mut limit = (p.low_speed_limit.or(u.low_speed_limit)).unwrap_or(d.low_speed_limit);
    if let Some(value) = network_env(LOW_SPEED_LIMIT_ENV)? {
        limit = value;
    }
    if let Some(value) = network_env(LOW_SPEED_TIME_ENV)? {
        time = (value, Some(ConfigOrigin::Env(LOW_SPEED_TIME_ENV)));
    }
    if let Some(value) = network_env(TIMEOUT_ENV)? {
        timeout = (value, Some(ConfigOrigin::Env(TIMEOUT_ENV)));
    }
    // Parsed as u64 so an oversized count is rejected below, not refused as
    // unparsable where usize is 32 bits.
    if let Some(value) = network_env::<u64>(RETRIES_ENV)? {
        let value = usize::try_from(value).unwrap_or(usize::MAX);
        retries = (value, Some(ConfigOrigin::Env(RETRIES_ENV)));
    }
    let network = NetworkConfig {
        timeout: timeout.0,
        retries: retries.0,
        concurrency: (p.concurrency.or(u.concurrency)).unwrap_or(d.concurrency),
        low_speed_limit: limit,
        low_speed_time: time.0,
        max_artifact_size,
    };
    network.validate(timeout.1, retries.1, time.1)?;
    Ok(network)
}

/// A network override from the environment. A value that is not an
/// unsigned number fails, as one out of range does, rather than running
/// with another timeout or retry count than the one the job set.
fn network_env<T: std::str::FromStr>(name: &'static str) -> Result<Option<T>, ConfigError> {
    let invalid = |message| ConfigError::Invalid {
        origin: ConfigOrigin::Env(name),
        message,
    };
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(invalid(
                "expected an unsigned number, got non-UTF-8 text".into(),
            ));
        }
    };
    // Empty, as `RAEVA_TIMEOUT=${CI_TIMEOUT:-}` leaves it, is unset.
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value.parse().map(Some).map_err(|_| {
        invalid(format!(
            "expected an unsigned number, got \"{}\"",
            rv_maven_types::bounded(value)
        ))
    })
}

#[derive(Debug, Clone, Default)]
struct MavenSettingsData {
    user_local_repository: Option<PathBuf>,
    maven_local_repository: Option<PathBuf>,
    repositories: Vec<RepoConfig>,
    defaults: usize,
    mirrors: Vec<MirrorConfig>,
    auth: Vec<AuthConfig>,
    auth_layers: AuthConfigLayers,
    proxies: Vec<ProxyConfig>,
    proxy_error: Option<String>,
    active_profiles: Vec<String>,
    active_settings_profiles: Vec<String>,
    user_urls: Vec<String>,
}

impl MavenSettingsData {
    /// Merges the settings.xml layer under the project and user layers, with
    /// the settings.xml profiles active on any of `platforms`. With no
    /// platform, only the explicitly active profiles apply. The keys of the
    /// host conditions that decided a profile with repositories go to
    /// `read`. A `<file>` path expands with the `host`'s values, since it
    /// names a file on this machine, and a target JDK's `java.version`.
    fn merge(
        inputs: &ConfigInputs,
        settings: MavenSettings,
        host: &ModelEnvironment,
        platforms: &[ModelEnvironment],
        explicit_environments: &[ModelEnvironment],
        read: Option<&SettingsReads>,
    ) -> Self {
        let (project, user) = (&inputs.project, &inputs.user);
        // The explicit list seeds the active set; <activation> rules and
        // <activeByDefault> can extend it below.
        let explicit_active_profiles = project
            .active_profiles
            .as_ref()
            .or(user.active_profiles.as_ref())
            .or(settings.active_profiles.as_ref())
            .cloned()
            .unwrap_or_default();

        // The settings.xml profiles active on any platform: those named
        // explicitly, those whose <activation> matches, and those active by
        // default. Only the explicit ids select POM profiles; Maven's request
        // carries those alone, and activates the others as external profiles.
        let environments = if !platforms.is_empty() {
            platforms
        } else if !explicit_environments.is_empty() {
            explicit_environments
        } else {
            std::slice::from_ref(host)
        };
        let mut active_settings_profiles = Vec::new();
        if platforms.is_empty() {
            for environment in environments {
                for id in
                    explicit_settings_profiles(inputs, &explicit_active_profiles, environment).0
                {
                    if !active_settings_profiles.contains(&id) {
                        active_settings_profiles.push(id);
                    }
                }
            }
        }
        for environment in platforms {
            for id in resolve_active_profiles(
                settings.profiles.as_deref(),
                inputs,
                &explicit_active_profiles,
                environment,
                &settings_file_context(inputs, &host.with_java_version_of(environment)),
                read,
            ) {
                if !active_settings_profiles.contains(&id) {
                    active_settings_profiles.push(id);
                }
            }
        }
        let settings_repositories: Vec<RepoConfig> = settings
            .profiles
            .iter()
            .flatten()
            .filter(|profile| {
                let id = profile.id.as_ref();
                id.is_some_and(|id| active_settings_profiles.contains(id))
            })
            .flat_map(|profile| profile.repositories.clone())
            .collect();

        // A deactivated id selects no POM profile, as in Maven, where it
        // wins over <activeProfiles>. A `-P` value can deactivate it on some
        // platforms only, where the POM's activation still leaves it off.
        let deactivated: Vec<Vec<String>> = (environments.iter())
            .map(|environment| inputs.maven_options(environment).inactive_profiles)
            .collect();
        let deactivated = |id: &String| {
            inputs.inactive_profiles.contains(id)
                || deactivated.iter().all(|inactive| inactive.contains(id))
        };
        let maven_local_repository = settings.local_repository;
        let user_local_repository = user
            .local_repository
            .clone()
            .or(maven_local_repository.clone());

        // Resolution searches the list in order, so the project layer comes
        // first, then the user's, then settings.xml. On a shared id the
        // earlier entry wins and the later one fills only its unset fields.
        let mut repositories = project.repositories.clone().unwrap_or_default();
        merge_repositories(&mut repositories, user.repositories.iter().flatten());
        merge_repositories(&mut repositories, &settings_repositories);
        let mut user_urls: Vec<String> = user
            .repositories
            .iter()
            .flatten()
            .chain(&settings_repositories)
            .map(|repo| repo.url.clone())
            .chain(
                (user.mirrors.iter().flatten())
                    .chain(settings.mirrors.iter().flatten())
                    .map(|mirror| mirror.url.clone()),
            )
            .collect();
        // As Maven keeps the super POM's central after the POM and settings
        // profile repositories, the defaults follow the configured ones,
        // each unless a configured repository takes its id. A mirror of
        // central replaces it at resolution.
        let configured = repositories.len();
        for default in default_repositories() {
            if !repositories.iter().any(|repo| repo.id == default.id) {
                user_urls.push(default.url.clone());
                repositories.push(default);
            }
        }
        let defaults = repositories.len() - configured;

        // Mirror selection takes the first matching entry within a match
        // class, so the same precedence orders the mirrors. A project
        // raeva.toml has none.
        let mirrors: Vec<MirrorConfig> = (user.mirrors.iter().flatten())
            .cloned()
            .chain(settings.mirrors.unwrap_or_default())
            .collect();

        let auth_layers = AuthConfigLayers {
            project: project.auth.clone().unwrap_or_default(),
            user: user.auth.clone().unwrap_or_default(),
            settings: settings.servers.unwrap_or_default(),
        };
        let auth: Vec<AuthConfig> = auth_layers
            .project
            .iter()
            .chain(&auth_layers.user)
            .chain(&auth_layers.settings)
            .cloned()
            .collect();

        // The user's proxies come before the settings.xml ones: the first
        // proxy that fits a URL carries it. A project raeva.toml has none.
        // The environment's apply only when neither file names one.
        let mut proxies = user.proxies.clone().unwrap_or_default();
        proxies.extend(settings.proxies.unwrap_or_default());
        let mut proxy_error = settings.proxy_error;
        if proxy_error.is_none() && proxies.is_empty() {
            match &inputs.environment_proxies {
                Ok(environment) => proxies.clone_from(environment),
                Err((variable, message)) => {
                    proxy_error = Some(format!("{variable}: {message}"));
                }
            }
        }

        tracing::debug!(
            mirror_count = mirrors.len(),
            server_count = auth.len(),
            repo_count = repositories.len(),
            proxy_count = proxies.len(),
            "settings.xml loaded"
        );

        MavenSettingsData {
            user_local_repository,
            maven_local_repository,
            repositories,
            defaults,
            mirrors,
            auth,
            auth_layers,
            proxies,
            proxy_error,
            active_profiles: explicit_active_profiles
                .into_iter()
                .filter(|id| !deactivated(id))
                .collect(),
            active_settings_profiles,
            user_urls,
        }
    }
}

/// The `[[auth]]` entries of each source kept apart, in the order
/// [`Config::auth`] joins them.
#[derive(Debug, Clone, Default)]
pub struct AuthConfigLayers {
    project: Vec<AuthConfig>,
    user: Vec<AuthConfig>,
    settings: Vec<AuthConfig>,
}

impl AuthConfigLayers {
    /// The entries from the project `raeva.toml`.
    pub fn project(&self) -> &[AuthConfig] {
        &self.project
    }

    /// The entries from the user `config.toml`.
    pub fn user(&self) -> &[AuthConfig] {
        &self.user
    }

    /// The settings.xml `<server>` entries that carry credentials.
    pub fn settings(&self) -> &[AuthConfig] {
        &self.settings
    }
}

#[derive(Debug, Clone)]
struct ConfigInputs {
    project: ConfigFile,
    user: ConfigFile,
    inactive_profiles: Vec<String>,
    /// `.mvn/maven.config` as read, whose `-D` and `-P` options, with
    /// `command_line`'s, select settings.xml profiles as they select the
    /// POM's.
    maven_config: Option<String>,
    command_line: CommandLine,
    project_root: PathBuf,
    /// The proxies `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` give, or the
    /// variable and why raeva cannot use it.
    environment_proxies: Result<Vec<ProxyConfig>, (&'static str, String)>,
}

impl Default for ConfigInputs {
    fn default() -> Self {
        Self {
            project: ConfigFile::default(),
            user: ConfigFile::default(),
            inactive_profiles: Vec::new(),
            maven_config: None,
            command_line: CommandLine::default(),
            project_root: PathBuf::new(),
            environment_proxies: Ok(Vec::new()),
        }
    }
}

impl ConfigInputs {
    /// `.mvn/maven.config` merged with the command line for `environment`.
    /// An invalid maven.config fails the load, unless the command contacts
    /// no repository, when it is left out.
    fn maven_options(&self, environment: &ModelEnvironment) -> MavenConfigOptions {
        crate::maven_config::parse_for(
            self.maven_config.as_deref(),
            &self.command_line,
            environment,
            &self.project_root,
        )
        .unwrap_or_default()
    }
}

type SettingsReads = Arc<Mutex<BTreeSet<String>>>;

/// The conditions of a settings.xml profile's `<activation>` that can read
/// the host or the project: their text as written, before `${env.*}`
/// expansion, from which a key that names them in raeva.lock is derived,
/// and the read profile activation records when it tests one in `ctx`. A
/// `<file>` path can name the target JDK's `java.version`, so its text
/// names the JDK of a `ctx` that has one.
fn settings_conditions(
    profile: &MavenProfile,
    ctx: &ActivationContext,
) -> Vec<(String, HostInput)> {
    let Some(activation) = profile.activation.as_ref() else {
        return Vec::new();
    };
    let written = profile.written_activation.as_ref().unwrap_or(activation);
    let non_empty = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
    let mut conditions = Vec::new();
    let tested = activation.clone().with_external_file(ctx);
    let written_file = written.file.as_ref();
    if let (Some(file), Some(tested)) = (written_file, &tested.file)
        && let Some((path, tested)) = (non_empty(&file.exists).zip(non_empty(&tested.exists)))
            .or_else(|| non_empty(&file.missing).zip(non_empty(&tested.missing)))
    {
        let text = match ctx.environment.target_jdk() {
            Some(jdk) => format!("file:{path} (JDK {jdk})"),
            None => format!("file:{path}"),
        };
        conditions.push((text, HostInput::File(tested)));
    }
    if let Some(jdk) = non_empty(&activation.jdk) {
        let text = non_empty(&written.jdk).unwrap_or_else(|| jdk.clone());
        conditions.push((format!("jdk:{}", text), HostInput::Jdk(jdk)));
    }
    if let Some(property) = &activation.property
        && let Some(name) = non_empty(&property.name)
    {
        let value = non_empty(&property.value);
        let written = written.property.as_ref();
        let written_name = written
            .and_then(|written| non_empty(&written.name))
            .unwrap_or_else(|| name.clone());
        let written_value = written
            .and_then(|written| non_empty(&written.value))
            .or_else(|| value.clone());
        let text = match &written_value {
            Some(value) => format!("property:{}={}", written_name, value),
            None => format!("property:{}", written_name),
        };
        conditions.push((text, HostInput::Property { name, value }));
    }
    conditions
}

/// What a settings.xml `<file>` path expands with: the project root, the
/// `-D` values of `.mvn/maven.config` and the command line, and the `host`'s
/// system properties.
fn settings_file_context(inputs: &ConfigInputs, host: &ModelEnvironment) -> ActivationContext {
    let mut ctx = ActivationContext::new(host.with_all_env());
    ctx.base_dir = Some(inputs.project_root.clone());
    ctx.properties = inputs.maven_options(host).properties;
    ctx
}

/// The key raeva.lock names a settings.xml condition by: the first 16 hex
/// digits of the SHA-256 of its text, so the settings text stays out of it.
fn settings_key(text: &str) -> String {
    hex::encode(sha2::Sha256::digest(text.as_bytes()))[..16].to_string()
}

/// The configuration for one project: the project `raeva.toml`, the user
/// `config.toml` and Maven's `settings.xml` merged, with the environment
/// overrides applied.
///
/// [`Config::load`] builds it. The merged lists are read through methods;
/// the files they came from stay private.
#[derive(Clone)]
pub struct Config {
    /// The `[network]` settings in effect.
    pub network: NetworkConfig,
    /// The `[lock]` settings in effect.
    pub lock: LockConfig,
    /// Profile ids to deactivate: the user list, then any project ids not
    /// already present. An empty or missing list in either file adds nothing.
    pub inactive_profiles: Vec<String>,
    /// Security toggles for supply-chain hardening (`${env.*}` substitution,
    /// transitive `<repositories>` policy, …). Default is safe-by-default: env
    /// substitution disabled, transitive repos disabled.
    pub security: SecurityConfig,
    /// raeva's own directories.
    pub paths: ResolvedPaths,
    /// The project directory the configuration was loaded for.
    pub project_root: PathBuf,
    /// `raeva.toml` in the project root, whether or not it exists.
    pub project_config_path: PathBuf,
    /// The user `config.toml`, whether or not it exists.
    pub user_config_path: PathBuf,
    /// `raeva.lock` in the project root.
    pub lock_path: PathBuf,
    /// The Maven settings file this configuration reads: the `-s` file, or
    /// `settings.xml` in the Maven user home, whether or not it exists.
    pub settings_path: Option<PathBuf>,
    inputs: ConfigInputs,
    maven_data: MavenSettingsData,
    settings: Option<MavenSettings>,
    host: HostSnapshot,
    settings_reads: SettingsReads,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("network", &self.network)
            .field("lock", &self.lock)
            .field("inactive_profiles", &self.inactive_profiles)
            .field("security", &self.security)
            .field("paths", &self.paths)
            .field("project_root", &self.project_root)
            .field("project_config_path", &self.project_config_path)
            .field("user_config_path", &self.user_config_path)
            .field("lock_path", &self.lock_path)
            .field("maven_data", &self.maven_data)
            .finish()
    }
}

/// The settings.xml profile ids that `explicit_active_profiles` and `-P` in
/// `.mvn/maven.config` name in `environment`, less those `inactive_profiles`
/// and `-P !id` turn off, with the parsed maven.config.
fn explicit_settings_profiles(
    inputs: &ConfigInputs,
    explicit_active_profiles: &[String],
    environment: &ModelEnvironment,
) -> (Vec<String>, MavenConfigOptions) {
    let options = inputs.maven_options(environment);
    let mut active: Vec<String> = Vec::new();
    for id in explicit_active_profiles
        .iter()
        .chain(&options.active_profiles)
    {
        let off = (inputs.inactive_profiles.iter())
            .chain(&options.inactive_profiles)
            .any(|inactive| inactive == id);
        if !off && !active.contains(id) {
            active.push(id.clone());
        }
    }
    (active, options)
}

/// Computes the final set of active profile ids from `settings.xml` for
/// one platform. Mirrors Maven's `DefaultProfileSelector` for profiles that
/// do not come from a POM, with the `-D` and `-P` options of
/// `.mvn/maven.config` and a relative `<file>` taken from the project root:
///
/// 1. A profile named in `inactive_profiles` or deselected with `-P` is not
///    active.
/// 2. A profile is active if its id appears in `explicit_active_profiles`
///    or is selected with `-P`.
/// 3. A profile is active if its `<activation>` block has a `<jdk>`, `<os>`,
///    `<file>`, or `<property>` rule that matches.
/// 4. A profile is active if its activation sets `<activeByDefault>true</...>`.
///    Unlike a POM's, it stays active when another profile is active.
fn resolve_active_profiles(
    profiles: Option<&[MavenProfile]>,
    inputs: &ConfigInputs,
    explicit_active_profiles: &[String],
    environment: &ModelEnvironment,
    file_ctx: &ActivationContext,
    read: Option<&SettingsReads>,
) -> Vec<String> {
    let (mut active, options) =
        explicit_settings_profiles(inputs, explicit_active_profiles, environment);
    let inactive = |id: &str| {
        (inputs.inactive_profiles.iter())
            .chain(&options.inactive_profiles)
            .any(|inactive| inactive == id)
    };
    let Some(profiles) = profiles else {
        return active;
    };

    let mut ctx = ActivationContext::new(environment.with_all_env());
    ctx.base_dir = Some(inputs.project_root.clone());
    ctx.properties = options.properties;
    for profile in profiles {
        let Some(id) = profile.id.as_deref() else {
            continue;
        };
        let Some(activation) = profile.activation.as_ref() else {
            continue;
        };
        if inactive(id) || active.iter().any(|a| a == id) {
            continue;
        }
        if activation.active_by_default {
            active.push(id.to_string());
            continue;
        }
        let (matched, reads) = activation
            .clone()
            .with_external_file(file_ctx)
            .evaluate(&ctx);
        for input in &reads {
            if let rv_maven_model::HostInput::UserProperty(name) = input {
                environment.record_user_property(name);
            }
        }
        // A profile's properties are recorded by name when a model reads them.
        if let Some(read) = read
            && !profile.repositories.is_empty()
        {
            let mut read = read.lock().unwrap_or_else(|poison| poison.into_inner());
            for (text, input) in settings_conditions(profile, file_ctx) {
                if reads.contains(&input) {
                    read.insert(settings_key(&text));
                }
            }
        }
        if matched {
            active.push(id.to_string());
        }
    }

    active
}

fn encode_target_values(values: Vec<Option<String>>) -> Option<String> {
    values
        .iter()
        .any(Option::is_some)
        .then(|| serde_json::to_string(&values).expect("property values serialize"))
}

impl Config {
    /// Loads the configuration for the project at `project_root`.
    ///
    /// Reads `raeva.toml` there, the user `config.toml` in the directory
    /// [`ResolvedPaths::discover`] finds, and `~/.m2/settings.xml` (with
    /// `settings-security.xml` for encrypted passwords). Missing files are
    /// empty. Repositories and credentials are listed project first, then
    /// user, then settings.xml; a single value or a profile list comes from
    /// the first source that sets it. The project file can only narrow
    /// `[security]` and cannot declare `[[proxies]]` or `[[mirrors]]`. Also captures
    /// the [`HostSnapshot`]: the JDK and the environment variables
    /// `[security]` allows.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ProjectRootMissing`] when `project_root` does not
    /// exist, and [`ConfigError::Invalid`] naming the origin of a value out
    /// of range or of a malformed settings.xml, which is not replaced by
    /// defaults, or of a `.mvn/maven.config` Maven would refuse. Other
    /// variants come from reading and parsing the files.
    pub fn load(project_root: &Path) -> Result<Self, ConfigError> {
        Self::load_with(project_root, &CommandLine::default(), true)
    }

    /// [`Self::load`] with the `-D`, `-P` and `-s` options of
    /// `command_line`, merged with `.mvn/maven.config` as Maven merges them.
    /// The command line's `-s` file is read in place of
    /// `~/.m2/settings.xml`; one in `.mvn/maven.config` is ignored.
    ///
    /// # Errors
    ///
    /// As [`Self::load`], and [`ConfigError::SettingsFileMissing`] when the
    /// `-s` file is not a file.
    pub fn load_with_command_line(
        project_root: &Path,
        command_line: &CommandLine,
    ) -> Result<Self, ConfigError> {
        Self::load_with(project_root, command_line, true)
    }

    /// [`Self::load_with_command_line`] for a command that reads only
    /// raeva.lock and the store and contacts no repository. A
    /// `.mvn/maven.config` that cannot be read or parsed is left out instead
    /// of failing the load, so a lock can still be inspected; its settings.xml
    /// profiles then ignore that file.
    ///
    /// # Errors
    ///
    /// As [`Self::load_with_command_line`], apart from `.mvn/maven.config`.
    pub fn load_for_lock(
        project_root: &Path,
        command_line: &CommandLine,
    ) -> Result<Self, ConfigError> {
        Self::load_with(project_root, command_line, false)
    }

    fn load_with(
        project_root: &Path,
        command_line: &CommandLine,
        strict_maven_config: bool,
    ) -> Result<Self, ConfigError> {
        if !project_root.exists() {
            return Err(ConfigError::ProjectRootMissing(project_root.to_path_buf()));
        }

        let paths = ResolvedPaths::discover()?;
        let project_config_path = project_root.join("raeva.toml");
        let lock_path = project_root.join("raeva.lock");
        let user_config_path = paths.config_file_path();
        let (old, new): (Vec<_>, Vec<_>) = [("rv.toml", "raeva.toml"), ("rv.lock", "raeva.lock")]
            .into_iter()
            .filter(|(old, new)| {
                !project_root.join(new).exists() && project_root.join(old).exists()
            })
            .unzip();
        if !old.is_empty() {
            tracing::warn!(
                sec_code = "SETTING_IGNORED",
                "ignoring {} in {}, which raeva 0.4 wrote; raeva reads {}",
                old.join(" and "),
                project_root.display(),
                new.join(" and "),
            );
        }

        let origins = (
            ConfigOrigin::ProjectConfig(project_config_path.clone()),
            ConfigOrigin::UserConfig(user_config_path.clone()),
        );
        let mut project = ConfigFile::load(&project_config_path, origins.0.clone())?;
        let mut user = ConfigFile::load(&user_config_path, origins.1.clone())?;
        let network = merge_network(project.network.take(), user.network.take(), &origins)?;
        let lock = merge_lock(project.lock.take(), user.lock.take(), &origins)?;
        let inactive_profiles = merge_inactive_profiles(
            project.inactive_profiles.take(),
            user.inactive_profiles.take(),
        );

        let (security, widened) =
            merge_security(project.security.take(), user.security.take(), &origins)?;
        refuse_project_endpoints(&project, &origins)?;
        if let Some(proxies) = &user.proxies {
            check_proxy_protocols(proxies, &origins.1)?;
        }
        for key in widened {
            tracing::warn!(
                sec_code = "PROJECT_SECURITY_WIDENING_IGNORED",
                key = key,
                "ignoring the part of security.{key} in {} that {} does not allow; \
                 only the user config can widen [security]",
                origins.0,
                origins.1,
            );
        }
        let host = HostSnapshot::capture(&security.allow_env_substitution);
        // settings.xml profiles follow its -P and -D, so a file Maven would
        // refuse fails here, before any repository is used.
        let maven_config_path = project_root.join(".mvn").join("maven.config");
        let environment = host.host_environment();
        let file_error = |message: String| ConfigError::Invalid {
            origin: ConfigOrigin::MavenConfig(maven_config_path.clone()),
            message,
        };
        let read_maven_config = || {
            let content = crate::read_optional_project_input_string(&maven_config_path)?;
            if let Some(text) = &content {
                let ignored = crate::maven_config::ignored_options(text)
                    .map_err(|error| file_error(error.to_string()))?;
                for option in ignored {
                    let reason = match option {
                        "-gs" => "raeva reads no global settings file",
                        "-pl" | "-am" | "-amd" => {
                            "raeva locks the whole reactor, whatever projects a build selects, \
                             so a module this build skips can still fail the sync"
                        }
                        _ => {
                            "a project cannot choose the settings file, which can hold mirrors, \
                             proxies and credentials; declare its repositories in raeva.toml, or \
                             review the file and pass it as raeva -s <file> sync"
                        }
                    };
                    tracing::warn!(
                        sec_code = "SETTING_IGNORED",
                        "ignoring {option} in {}; {reason}",
                        maven_config_path.display()
                    );
                }
            }
            Ok(content)
        };
        let mut maven_config = match read_maven_config() {
            Ok(content) => content,
            Err(error) if strict_maven_config => return Err(error),
            Err(_) => None,
        };
        // Maven expands the values once the command line is merged in, so a
        // command-line -D can mend a value of the file.
        let merged = |content: Option<&str>, command_line: &CommandLine| {
            let path = crate::maven_config::settings_file(
                content,
                command_line,
                &environment,
                project_root,
            )
            .map_err(|error| ConfigError::Invalid {
                origin: ConfigOrigin::CommandLine,
                message: error.to_string(),
            })?;
            match path {
                Some(path) if !path.is_file() => Err(ConfigError::SettingsFileMissing(path)),
                path => Ok(path),
            }
        };
        let settings = match merged(maven_config.as_deref(), command_line) {
            Ok(settings) => settings,
            Err(error) => {
                // The command line is to blame when it fails on its own.
                let file_fails = maven_config.is_some() && merged(None, command_line).is_ok();
                if !file_fails {
                    return Err(error);
                }
                if strict_maven_config {
                    return Err(match error {
                        ConfigError::Invalid { message, .. } => file_error(message),
                        error => error,
                    });
                }
                maven_config = None;
                merged(None, command_line)?
            }
        };
        let settings_path = settings.or_else(crate::maven_settings::default_settings_path);
        let inputs = ConfigInputs {
            project,
            user,
            inactive_profiles: inactive_profiles.clone(),
            maven_config,
            command_line: command_line.clone(),
            project_root: project_root.to_path_buf(),
            environment_proxies: crate::environment_proxies(|name| std::env::var(name).ok()),
        };

        // A present-but-malformed settings.xml (bad XML, oversize, DOCTYPE,
        // unsupported encoding) must abort like Maven does, NOT silently fall back to
        // defaults. Falling back would drop the user's mirrors, server
        // credentials, and proxies and could send unauthenticated fetches to
        // an unexpected public host. An absent settings.xml is fine
        // (`load_optional` returns `Ok(default)` for a missing file).
        let mut settings = match &settings_path {
            Some(path) => MavenSettings::load_optional(path).map_err(|err| {
                let message = match err {
                    ConfigError::Invalid { .. } => return err,
                    ConfigError::RefusedSettings(message) => message,
                    ConfigError::InvalidSettings(message) => format!("{message}; fix or remove it"),
                    other => format!("{other}; fix or remove it"),
                };
                ConfigError::Invalid {
                    origin: ConfigOrigin::MavenSettings(path.clone()),
                    message,
                }
            })?,
            None => MavenSettings::default(),
        };
        if let (Some(path), Some(error)) = (&settings_path, &mut settings.proxy_error) {
            *error = format!(
                "invalid {}: {error}",
                ConfigOrigin::MavenSettings(path.clone())
            );
        }
        for (file, origin) in [(&inputs.project, &origins.0), (&inputs.user, &origins.1)] {
            let urls = || repository_urls(file.repositories.as_ref(), file.mirrors.as_ref());
            refuse_secret_urls(urls(), origin)?;
            refuse_unusable_urls(urls(), origin)?;
        }
        if let Some(path) = settings_path.clone() {
            // Every profile, since another platform may activate one this
            // host does not.
            let profiles = settings.profiles.iter().flatten();
            refuse_secret_urls(
                profiles
                    .flat_map(|profile| &profile.repositories)
                    .map(|repo| ("repository", repo.id.as_deref(), repo.url.as_str()))
                    .chain(repository_urls(None, settings.mirrors.as_ref())),
                &ConfigOrigin::MavenSettings(path),
            )?;
        }
        let initial_environment = host.host_environment().detached();
        let maven_data = MavenSettingsData::merge(
            &inputs,
            settings.clone(),
            &initial_environment,
            std::slice::from_ref(&initial_environment),
            &[],
            None,
        );

        let config = Self {
            network,
            lock,
            inactive_profiles,
            security,
            paths,
            project_root: project_root.to_path_buf(),
            project_config_path,
            user_config_path,
            lock_path,
            settings_path,
            inputs,
            maven_data,
            settings: Some(settings),
            host,
            settings_reads: SettingsReads::default(),
        };

        tracing::debug!(path = %project_root.display(), "config loaded");

        Ok(config)
    }

    /// The configured repositories, in search order: the project's, the
    /// user's, then those of the active settings.xml profiles. On a shared
    /// id the earlier entry wins and a later one fills only its unset
    /// fields. Then [`Config::default_repositories`].
    pub fn repositories(&self) -> &[RepoConfig] {
        &self.maven_data.repositories
    }

    /// The tail of [`Config::repositories`] that raeva adds: Maven Central,
    /// unless `raeva.toml` or `config.toml` names a repository; a settings.xml
    /// repository with id `central` replaces it. Like Maven's super POM
    /// `central`, it is searched after the repositories the project's POMs declare.
    pub fn default_repositories(&self) -> &[RepoConfig] {
        let repositories = &self.maven_data.repositories;
        &repositories[repositories.len() - self.maven_data.defaults..]
    }

    /// The mirrors, the user's before the settings.xml ones. Of two
    /// mirrors that match a repository equally well, the earlier is used.
    pub fn mirrors(&self) -> &[MirrorConfig] {
        &self.maven_data.mirrors
    }

    /// Every `[[auth]]` entry and every settings.xml `<server>` that carries
    /// credentials, project first, then user, then settings.xml.
    /// [`Config::auth_layers`] keeps them apart.
    pub fn auth(&self) -> &[AuthConfig] {
        &self.maven_data.auth
    }

    /// The entries of [`Config::auth`], by source.
    pub fn auth_layers(&self) -> &AuthConfigLayers {
        &self.maven_data.auth_layers
    }

    /// The proxies, the user's before the settings.xml ones; the first that
    /// fits a URL carries it. When neither file names one, those of
    /// `HTTPS_PROXY` and `HTTP_PROXY`.
    pub fn proxies(&self) -> &[ProxyConfig] {
        &self.maven_data.proxies
    }

    /// Why the proxies cannot be used: a settings.xml proxy raeva would use
    /// whose port is not a number, or, when no file names a proxy, proxy
    /// variables set to something raeva does not support. The variable is
    /// named and its value is not shown.
    pub fn proxy_error(&self) -> Option<&str> {
        self.maven_data.proxy_error.as_deref()
    }

    /// The URLs of the repositories and mirrors that the user `config.toml`
    /// and `settings.xml` name, and of the built-in default repositories
    /// that are searched. A project's files cannot add to it.
    pub fn user_endpoint_urls(&self) -> &[String] {
        &self.maven_data.user_urls
    }

    /// The local repository from the user's config.toml or settings.xml,
    /// leaving out the project's raeva.toml. A cloned project must not choose
    /// where `export-m2` writes.
    pub fn user_local_repository(&self) -> Option<&Path> {
        self.maven_data.user_local_repository.as_deref()
    }

    /// `<localRepository>` from settings.xml as written: where `mvn` itself
    /// writes, unless `-Dmaven.repo.local` says otherwise.
    pub fn maven_local_repository(&self) -> Option<&Path> {
        self.maven_data.maven_local_repository.as_deref()
    }

    /// Whether the project's raeva.toml sets `local_repository`.
    pub fn project_sets_local_repository(&self) -> bool {
        self.inputs.project.local_repository.is_some()
    }

    /// The profile ids that select POM profiles: those `raeva.toml`,
    /// `config.toml` or settings.xml `<activeProfiles>` name.
    pub fn active_profiles(&self) -> &[String] {
        &self.maven_data.active_profiles
    }

    /// The ids of the settings.xml profiles, active or not; Maven names a
    /// profile without one `default`.
    pub fn settings_profile_ids(&self) -> impl Iterator<Item = &str> {
        (self.settings.iter())
            .flat_map(|settings| settings.profiles.iter().flatten())
            .map(|profile| profile.id.as_deref().unwrap_or("default"))
    }

    /// The explicitly active profile ids and the settings.xml profiles
    /// whose `<activation>` matches or that are active by default.
    /// Their repositories are in [`Config::repositories`]; their ids do not
    /// select POM profiles.
    pub fn active_settings_profiles(&self) -> &[String] {
        &self.maven_data.active_settings_profiles
    }

    /// This configuration with the settings.xml profiles that are active
    /// on any of `platforms`, each an OS, architecture and optional target
    /// JDK, instead of on the host. With no platform, only the profiles that
    /// `<activeProfiles>`, `raeva.toml` or `config.toml` name are active.
    /// [`Config::load`] evaluates the profiles for the host.
    pub fn for_platforms<'a>(
        &self,
        platforms: impl IntoIterator<Item = (&'a str, &'a str, Option<&'a str>)>,
    ) -> Self {
        let mut config = self.clone();
        let environments: Vec<ModelEnvironment> = platforms
            .into_iter()
            .map(|(os, arch, jdk)| self.host.environment_for(os, arch, jdk))
            .collect();
        if let Some(settings) = &self.settings {
            let explicit_environments = if environments.is_empty() {
                self.target_environments()
            } else {
                Vec::new()
            };
            config.maven_data = MavenSettingsData::merge(
                &self.inputs,
                settings.clone(),
                &self.host.host_environment(),
                &environments,
                &explicit_environments,
                Some(&self.settings_reads),
            );
        }
        config
    }

    /// The merged `<properties>` of the settings.xml profiles active on the
    /// platform `os`/`arch`, in settings.xml file order.
    pub fn settings_profile_properties(&self, os: &str, arch: &str) -> PropertyMap {
        self.settings_profile_properties_for(&self.host.environment(os, arch))
    }

    /// The merged `<properties>` of the settings.xml profiles active in
    /// `environment`, in file order, so a later profile overrides an
    /// earlier one on a shared key, as Maven merges external profiles.
    pub fn settings_profile_properties_for(&self, environment: &ModelEnvironment) -> PropertyMap {
        self.settings_profile_properties_on(environment, &self.host.host_environment())
    }

    /// [`Self::settings_profile_properties_for`], with `host` as the
    /// environment of the `.mvn/maven.config` options and `<file>`
    /// conditions.
    fn settings_profile_properties_on(
        &self,
        environment: &ModelEnvironment,
        host: &ModelEnvironment,
    ) -> PropertyMap {
        let Some(settings) = &self.settings else {
            return PropertyMap::new();
        };
        let Some(profiles) = settings.profiles.as_deref() else {
            return PropertyMap::new();
        };
        let explicit_active_profiles = self
            .inputs
            .project
            .active_profiles
            .as_ref()
            .or(self.inputs.user.active_profiles.as_ref())
            .or(settings.active_profiles.as_ref())
            .cloned()
            .unwrap_or_default();
        let active = resolve_active_profiles(
            Some(profiles),
            &self.inputs,
            &explicit_active_profiles,
            environment,
            &settings_file_context(&self.inputs, &host.with_java_version_of(environment)),
            None,
        );
        let mut merged = PropertyMap::new();
        for profile in profiles {
            if profile
                .id
                .as_deref()
                .is_some_and(|id| active.iter().any(|active_id| active_id == id))
            {
                for (key, value) in profile.properties.iter() {
                    merged.insert(key.clone(), value.clone());
                }
            }
        }
        merged
    }

    /// Every property name defined by any profile in settings.xml, active
    /// or not.
    pub fn defined_settings_properties(&self) -> BTreeSet<String> {
        self.settings
            .as_ref()
            .and_then(|settings| settings.profiles.as_deref())
            .into_iter()
            .flatten()
            .flat_map(|profile| profile.properties.iter().map(|(key, _)| key.clone()))
            .collect()
    }

    /// Encoded settings-property values across supported targets, including absence.
    /// The target order is fixed, independent of the platforms selected by a command.
    pub fn settings_property_value(&self, name: &str) -> Option<String> {
        encode_target_values(
            self.target_environments()
                .iter()
                .map(|environment| {
                    self.settings_profile_properties_for(environment)
                        .get(name)
                        .cloned()
                })
                .collect(),
        )
    }

    fn target_environments(&self) -> Vec<ModelEnvironment> {
        let jdks: Vec<Option<&str>> = if self.lock.jdks.is_empty() {
            vec![None]
        } else {
            self.lock
                .jdks
                .iter()
                .map(|jdk| Some(jdk.as_str()))
                .collect()
        };
        [
            ("linux", "x86_64"),
            ("linux", "aarch64"),
            ("macos", "x86_64"),
            ("macos", "aarch64"),
            ("windows", "x86_64"),
            ("windows", "aarch64"),
        ]
        .into_iter()
        .flat_map(|(os, arch)| {
            jdks.iter()
                .map(move |jdk| self.host.environment_for(os, arch, *jdk))
        })
        .collect()
    }

    fn target_maven_options(&self) -> Vec<MavenConfigOptions> {
        self.target_environments()
            .iter()
            .map(|environment| self.inputs.maven_options(environment))
            .collect()
    }

    /// The inputs a POM can take into a repository URL that are private to
    /// this host and named like a secret ([`crate::secret_named`]), on any
    /// target platform: `-D` options on the command line or in
    /// `.mvn/maven.config`, the properties of active settings.xml profiles,
    /// and the allowlisted environment variables. Each comes as how a
    /// message names it, then its value, expanded as far as these inputs
    /// go, which no message may show.
    pub fn secret_named_inputs(&self) -> Vec<(String, String)> {
        // Read apart from the model builds, whose host reads raeva.lock
        // records.
        let host = self.host.host_environment().detached();
        let env = self.host.env_values();
        let mut inputs: Vec<_> = (env.iter())
            .filter(|(name, _)| crate::secret_named(name))
            .map(|(name, value)| (format!("${{env.{name}}}"), value.clone()))
            .collect();
        // A model reads these names from these inputs alone: a POM can set
        // any other, even `os.arch`, and a model field such as
        // `project.artifactId` wins over a property of its name.
        let model_owned = |name: &str| {
            name.starts_with("project.") || name.starts_with("pom.") || name == "basedir"
        };
        // A model reads `${NAME}` as `${env.NAME}` below its properties.
        let mut with_env = PropertyMap::new();
        for (name, value) in env {
            with_env.insert(format!("env.{name}"), value.as_str());
            if !model_owned(name) {
                with_env.insert(name.as_str(), value.as_str());
            }
        }
        for environment in self.target_environments() {
            let environment = environment.detached();
            let defines = self.inputs.maven_options(&environment).properties;
            let settings = self.settings_profile_properties_on(&environment, &host);
            // As the project's model and a dependency's, which reads `-D`
            // values without the settings.xml properties, read them.
            let mut project = with_env.clone();
            let mut dependency = with_env.clone();
            for (name, value) in settings.iter().chain(&defines) {
                if !model_owned(name) {
                    project.insert(name.as_str(), value.as_str());
                }
            }
            for (name, value) in &defines {
                if !model_owned(name) {
                    dependency.insert(name.as_str(), value.as_str());
                }
            }
            let defines = (defines.iter()).map(|(name, value)| (format!("-D{name}"), name, value));
            let settings = (settings.iter())
                .map(|(name, value)| (format!("settings.xml property {name}"), name, value));
            for (input, _, value) in defines
                .chain(settings)
                .filter(|(_, name, _)| crate::secret_named(name))
            {
                for properties in [&project, &dependency] {
                    if let Ok(expanded) = properties.clone().interpolate_str_no_project(value) {
                        inputs.push((input.clone(), expanded));
                    }
                }
                inputs.push((input, value.clone()));
            }
        }
        inputs.sort();
        inputs.dedup();
        inputs
    }

    /// Effective user-property values across supported targets, including absent overrides.
    pub fn user_property_values(
        &self,
        names: &BTreeSet<String>,
    ) -> BTreeMap<String, Option<String>> {
        if names.is_empty() {
            return BTreeMap::new();
        }
        let options = self.target_maven_options();
        names
            .iter()
            .map(|name| {
                let values: Vec<_> = options
                    .iter()
                    .map(|options| options.properties.get(name).cloned())
                    .collect();
                let value = encode_target_values(values);
                (name.clone(), value)
            })
            .collect()
    }

    /// Replay authored input reads for the aggregate configuration hash.
    /// Only the expression and its POM context are public; returned values stay private.
    pub fn user_property_lookup_value(&self, template: &str) -> Option<String> {
        use crate::maven_config::{LookupMode, PropertyLookup, PropertySource};
        let lookup = PropertyLookup::parse(template)?;
        let values: Vec<_> = self
            .target_environments()
            .into_iter()
            .map(|environment| {
                let environment = environment.detached();
                let mut ctx = ActivationContext::new(environment.clone());
                ctx.set_external_properties(
                    self.inputs.maven_options(&environment).properties,
                    lookup.source,
                );
                if lookup.source == PropertySource::User {
                    ctx.settings_properties = self.settings_profile_properties_for(&environment);
                }
                if let Some(packaging) = &lookup.default_packaging {
                    let mut pom = rv_maven_model::Pom::default();
                    pom.packaging = Some(packaging.clone());
                    ctx = ctx.with_input_packaging(&pom);
                }
                ctx.base_dir = lookup
                    .file
                    .as_ref()
                    .and_then(|file| file.base_dir.as_ref())
                    .map(|base| self.project_root.join(base))
                    .or_else(|| {
                        lookup
                            .model
                            .as_ref()
                            .and_then(|model| model.base_dir.as_ref())
                            .map(|base| self.project_root.join(base))
                    });
                let mut public = PropertyMap::new();
                for (name, value) in &lookup.properties {
                    public.insert(name, value);
                }
                let mut properties = if lookup.mode == LookupMode::Model {
                    ctx.model_properties(&public)
                } else {
                    ctx.activation_properties(&public)
                };
                if lookup.mode == LookupMode::File
                    && let Some(base) = &ctx.base_dir
                {
                    let base = base.to_string_lossy();
                    properties.insert("basedir", base.as_ref());
                    properties.insert("project.basedir", base.as_ref());
                }
                let (expanded, reads) = if lookup.mode == LookupMode::Model {
                    match &lookup.model {
                        Some(model) => model.interpolate(&lookup.expression, &properties, &ctx),
                        None => properties.replay_model_names(&lookup.expression, &ctx),
                    }
                } else {
                    properties.replay_exact_names(&lookup.expression, &environment)
                };
                let expanded = expanded.ok()?;
                let system = ctx.activation_system_properties();
                let read_values: BTreeMap<_, _> = reads
                    .into_iter()
                    .filter_map(|name| {
                        if properties.get(&name).is_some() && !properties.is_external(&name) {
                            return None;
                        }
                        let value = properties
                            .get(&name)
                            .cloned()
                            .or_else(|| system.get(&name).cloned())
                            .or_else(|| match name.as_str() {
                                "java.version" => ctx.property("java.version").map(str::to_string),
                                name => name
                                    .strip_prefix("env.")
                                    .or_else(|| (lookup.mode == LookupMode::Model).then_some(name))
                                    .and_then(|key| self.host.env_values().get(key))
                                    .cloned(),
                            });
                        Some((name, value))
                    })
                    .collect();
                let actual = match lookup.mode {
                    LookupMode::File => Some(ctx.file_condition_exists(&expanded).to_string()),
                    LookupMode::Property => {
                        let name = expanded.strip_prefix('!').unwrap_or(&expanded);
                        ctx.property(name).map(str::to_string).or_else(|| {
                            name.strip_prefix("env.")
                                .and_then(|key| self.host.env_values().get(key))
                                .cloned()
                        })
                    }
                    LookupMode::Interpolation | LookupMode::Model => Some(expanded),
                };
                Some((read_values, actual))
            })
            .collect();
        Some(serde_json::to_string(&values).expect("property lookup values serialize"))
    }

    /// Effective `-P` selections across supported targets, from both option sources.
    pub fn maven_profile_selections(&self) -> Vec<String> {
        let options = self.target_maven_options();
        if options.iter().all(|options| {
            options.active_profiles.is_empty() && options.inactive_profiles.is_empty()
        }) {
            return Vec::new();
        }
        options
            .into_iter()
            .map(|options| {
                serde_json::to_string(&(options.active_profiles, options.inactive_profiles))
                    .expect("profile selections serialize")
            })
            .collect()
    }

    /// The settings.xml profiles with an `<activation>`, in file order, as
    /// an id and a canonical text of the activation and the repositories:
    /// what decides, per platform, whether and how they apply. Every
    /// profile is listed when a `.mvn/maven.config` `-P` value holds a
    /// `${...}`, since it can name another profile on each platform.
    pub fn conditional_settings_profiles(&self) -> Vec<(String, String)> {
        let Some(profiles) = self
            .settings
            .as_ref()
            .and_then(|settings| settings.profiles.as_deref())
        else {
            return Vec::new();
        };
        let every = crate::maven_config::selects_profiles_by_expression(
            self.inputs.maven_config.as_deref(),
            &self.inputs.command_line,
        );
        let unconditional = Activation::default();
        profiles
            .iter()
            .filter_map(|profile| {
                let id = profile.id.clone()?;
                let activation =
                    (profile.activation.as_ref()).or_else(|| every.then_some(&unconditional))?;
                let content = serde_json::json!({
                    "activation": activation,
                    "repositories": profile.repositories,
                });
                Some((id, content.to_string()))
            })
            .collect()
    }

    /// The keys of the settings.xml conditions that decided a profile with
    /// repositories on a platform this configuration, or one made from the
    /// same [`Config::load`], was given with [`Config::for_platforms`].
    /// [`Config::settings_condition`] names the condition of a key.
    pub fn consulted_settings_conditions(&self) -> Vec<String> {
        let read = self.settings_reads.lock();
        read.unwrap_or_else(|poison| poison.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// The text of the settings.xml condition with the key `key`, and
    /// whether it holds now, on the host or, for a condition that names
    /// one, the `[lock] jdks` entry. `None` when no settings.xml profile has
    /// it.
    pub fn settings_condition(&self, key: &str) -> Option<(String, bool)> {
        let profiles = self.settings.as_ref()?.profiles.as_deref()?;
        let host = self.host.host_environment();
        let targets = (self.lock.jdks.iter()).map(|jdk| {
            host.with_java_version_of(&self.host.environment_for("linux", "x86_64", Some(jdk)))
        });
        std::iter::once(host.clone())
            .chain(targets)
            .find_map(|environment| {
                let ctx = settings_file_context(&self.inputs, &environment);
                profiles
                    .iter()
                    .flat_map(|profile| settings_conditions(profile, &ctx))
                    .find(|(text, _)| settings_key(text) == key)
            })
            .and_then(|(text, input)| Some((text, self.host.holds_in_settings(&input)?)))
    }

    /// This configuration, whose model builds also record what they read
    /// from the host in `reads`.
    #[must_use]
    pub fn recording_into(&self, reads: &rv_maven_model::HostReads) -> Self {
        let mut config = self.clone();
        config.host = self.host.recording_into(reads);
        config
    }

    /// This configuration, whose model builds record what they read from
    /// the host in `reads` alone, apart from the record of the run.
    #[must_use]
    pub fn recording_only_into(&self, reads: &rv_maven_model::HostReads) -> Self {
        let mut config = self.clone();
        config.host = self.host.recording_only_into(reads);
        config
    }

    /// This configuration with `host` as its host snapshot, for tests.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn with_host(mut self, host: HostSnapshot) -> Self {
        self.host = host;
        self
    }

    /// The JDK and allowlisted environment variables read when the config
    /// was loaded.
    pub fn host(&self) -> &HostSnapshot {
        &self.host
    }

    /// The `-D`, `-P` and `-s` options the configuration was loaded with.
    pub fn command_line(&self) -> &CommandLine {
        &self.inputs.command_line
    }

    /// The environment of a model build for the platform `os`/`arch` and
    /// optional target `jdk`.
    pub fn model_environment(&self, os: &str, arch: &str, jdk: Option<&str>) -> ModelEnvironment {
        self.host.environment_for(os, arch, jdk)
    }

    /// This test configuration with `mirrors` as its mirrors, in
    /// precedence order.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_mirrors(mut self, mirrors: Vec<MirrorConfig>) -> Self {
        self.maven_data.mirrors = mirrors;
        self
    }

    /// A test configuration with the default repositories; see
    /// [`Config::for_testing_with`].
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing(project_root: PathBuf, paths: ResolvedPaths) -> Self {
        Self::for_testing_with_repos(project_root, paths, Vec::new())
    }

    /// A test configuration with `repositories`, or the defaults when it is
    /// empty, and the default [`SecurityConfig`]; see
    /// [`Config::for_testing_with`].
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing_with_repos(
        project_root: PathBuf,
        paths: ResolvedPaths,
        repositories: Vec<RepoConfig>,
    ) -> Self {
        Self::for_testing_with(project_root, paths, repositories, SecurityConfig::default())
    }

    /// The full-control `for_testing` variant, with an explicit
    /// [`SecurityConfig`]. The host snapshot has the allowlisted variables
    /// but no JDK ([`HostSnapshot::for_testing`]), so a test does not depend
    /// on the machine's; [`Config::with_host`] sets another.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing_with(
        project_root: PathBuf,
        paths: ResolvedPaths,
        repositories: Vec<RepoConfig>,
        security: SecurityConfig,
    ) -> Self {
        let (repositories, defaults) = if repositories.is_empty() {
            (default_repositories(), 1)
        } else {
            (repositories, 0)
        };
        let maven_data = MavenSettingsData {
            user_local_repository: None,
            maven_local_repository: None,
            user_urls: repositories.iter().map(|repo| repo.url.clone()).collect(),
            repositories,
            defaults,
            mirrors: Vec::new(),
            auth: Vec::new(),
            auth_layers: AuthConfigLayers::default(),
            proxies: Vec::new(),
            proxy_error: None,
            active_profiles: Vec::new(),
            active_settings_profiles: Vec::new(),
        };

        let host = HostSnapshot::for_testing(&security.allow_env_substitution);

        Self {
            network: NetworkConfig::default(),
            lock: LockConfig::default(),
            inactive_profiles: Vec::new(),
            security,
            paths,
            project_config_path: project_root.join("raeva.toml"),
            user_config_path: project_root.join("config.toml"),
            lock_path: project_root.join("raeva.lock"),
            settings_path: None,
            project_root,
            inputs: ConfigInputs::default(),
            maven_data,
            settings: None,
            host,
            settings_reads: SettingsReads::default(),
        }
    }
}

/// Merge a lower-precedence `underlay` into `repositories`: an entry whose
/// id is already there only fills the fields that one left unset, and the
/// others are appended.
fn merge_repositories<'a>(
    repositories: &mut Vec<RepoConfig>,
    underlay: impl IntoIterator<Item = &'a RepoConfig>,
) {
    for repo in underlay {
        let Some(existing) = repositories
            .iter_mut()
            .find(|existing| repo.id.is_some() && existing.id == repo.id)
        else {
            repositories.push(repo.clone());
            continue;
        };
        existing.releases = existing.releases.or(repo.releases);
        existing.snapshots = existing.snapshots.or(repo.snapshots);
        existing.snapshots_update_policy = existing
            .snapshots_update_policy
            .or(repo.snapshots_update_policy);
        existing.releases_update_policy = existing
            .releases_update_policy
            .or(repo.releases_update_policy);
        existing.releases_checksum_policy = existing
            .releases_checksum_policy
            .or(repo.releases_checksum_policy);
        existing.snapshots_checksum_policy = existing
            .snapshots_checksum_policy
            .or(repo.snapshots_checksum_policy);
    }
}

fn default_repositories() -> Vec<RepoConfig> {
    vec![RepoConfig::maven_central()]
}

/// Parse HTTP(S) URLs with the fetch layer's parser.
/// It normalizes scheme whitespace, which must not disguise filesystem access.
fn parse_url_origin(raw: &str) -> Option<url::Url> {
    let url = url::Url::parse(raw).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some()).then_some(url)
}

/// Match the parsed origin and a path prefix aligned to a segment boundary.
fn url_origin_matches(allowed: &url::Url, candidate: &url::Url) -> bool {
    if allowed.origin() != candidate.origin() {
        return false;
    }
    let allowed_path = allowed.path();
    let candidate_path = candidate.path();
    candidate_path == allowed_path
        || (candidate_path.starts_with(allowed_path)
            && (allowed_path.ends_with('/')
                || candidate_path[allowed_path.len()..].starts_with('/')))
}

#[cfg(test)]
mod tests {
    use super::{CommandLine, Config, ConfigFile, NetworkConfig, SecurityConfig};
    use crate::error::{ConfigError, ConfigOrigin};
    use std::fs;
    use std::path::Path;

    /// Runs `f` with `RAEVA_HOME` and the Maven user home at a fresh
    /// directory, passing it and a fresh project directory.
    fn with_homes<T>(f: impl FnOnce(&Path, &Path) -> T) -> T {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home_dir = home.path().to_string_lossy().into_owned();
        temp_env::with_vars(
            [
                ("RAEVA_HOME", Some(home_dir.as_str())),
                ("HOME", Some(home_dir.as_str())),
                (crate::MAVEN_USER_HOME_TEST_ENV, Some(home_dir.as_str())),
            ],
            || f(home.path(), project.path()),
        )
    }

    fn write_settings(home: &Path, xml: &str) {
        fs::create_dir_all(home.join(".m2")).unwrap();
        fs::write(home.join(".m2/settings.xml"), xml).unwrap();
    }

    fn ids<'a, T>(items: &'a [T], id: impl Fn(&'a T) -> &'a Option<String>) -> Vec<&'a str> {
        items
            .iter()
            .filter_map(|item| id(item).as_deref())
            .collect()
    }

    /// A settings.xml proxy with a broken port fails only a command that
    /// builds a client, as Maven fails only when it connects.
    #[test]
    fn a_settings_proxy_port_error_waits_for_a_client() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><proxies><proxy><id>p</id><host>user@proxy.example</host>\
                 <port>${env.RAEVA_TEST_DEFINITELY_NOT_SET}</port></proxy></proxies></settings>",
            );
            let config = Config::load(project).unwrap();
            assert!(config.proxies().is_empty());
            let error = config.proxy_error().unwrap();
            assert!(
                error.contains("settings.xml") && error.contains("'proxy.example'"),
                "{error}"
            );
            assert!(!error.contains("user@"), "{error}");
        });
    }

    #[test]
    fn layers_merge_project_over_user_over_settings() {
        with_homes(|home, project| {
            let config = Config::load(project).unwrap();
            assert_eq!(ids(config.repositories(), |r| &r.id), ["central"]);
            assert!(config.user_local_repository().is_none());
            assert_eq!(config.network.timeout, 30);

            write_settings(
                home,
                r"<settings>
                  <localRepository>/settings/m2</localRepository>
                  <mirrors><mirror><id>settings-m</id><mirrorOf>central</mirrorOf>
                    <url>https://settings.example/m/</url></mirror></mirrors>
                  <servers><server><id>s</id><username>u</username></server></servers>
                  <proxies><proxy><id>settings-p</id><host>settings.proxy</host></proxy></proxies>
                  <profiles><profile><id>dev</id><repositories>
                    <repository><id>settings-r</id><url>https://settings.example/r/</url></repository>
                    <repository><id>shared</id><url>https://settings.example/shared/</url>
                      <snapshots><updatePolicy>interval:15</updatePolicy></snapshots></repository>
                  </repositories></profile></profiles>
                  <activeProfiles><activeProfile>dev</activeProfile></activeProfiles>
                </settings>",
            );
            fs::write(
                home.join("config.toml"),
                "inactive_profiles = ['user-off']\n\
                 [network]\ntimeout = 10\nretries = 7\nconcurrency = 3\n\
                 [[repositories]]\nid = 'user-r'\nurl = 'https://user.example/r/'\n\
                 [[mirrors]]\nid = 'user-m'\nurl = 'https://user.example/m/'\nmirror_of = ['central']\n\
                 [[auth]]\nid = 'u'\nusername = 'x'\n\
                 [[proxies]]\nid = 'user-p'\nhost = 'user.proxy'\nport = 8080\n",
            )
            .unwrap();
            fs::write(
                project.join("raeva.toml"),
                "local_repository = 'project-m2'\n[network]\ntimeout = 60\n\
                 [[repositories]]\nid = 'project-r'\nurl = 'https://project.example/r/'\n\
                 [[repositories]]\nid = 'shared'\nurl = 'https://project.example/shared/'\n\
                 [[auth]]\nid = 'p'\ntoken = 't'\n",
            )
            .unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(
                ids(config.repositories(), |r| &r.id),
                ["project-r", "shared", "user-r", "settings-r", "central"]
            );
            let shared = &config.repositories()[1];
            assert_eq!(shared.url, "https://project.example/shared/");
            assert_eq!(shared.snapshots, Some(true));
            assert_eq!(
                shared.snapshots_update_policy,
                Some(crate::UpdatePolicy::Interval(15))
            );
            assert_eq!(ids(config.mirrors(), |m| &m.id), ["user-m", "settings-m"]);
            assert_eq!(ids(config.proxies(), |p| &p.id), ["user-p", "settings-p"]);
            assert_eq!(ids(config.auth(), |a| &a.id), ["p", "u", "s"]);
            let layers = config.auth_layers();
            assert_eq!(
                (
                    layers.project().len(),
                    layers.user().len(),
                    layers.settings().len()
                ),
                (1, 1, 1)
            );
            assert_eq!(
                config.user_endpoint_urls(),
                [
                    "https://user.example/r/",
                    "https://settings.example/r/",
                    "https://settings.example/shared/",
                    "https://user.example/m/",
                    "https://settings.example/m/",
                    crate::RepoConfig::maven_central().url.as_str(),
                ]
            );
            assert_eq!(
                config.user_local_repository(),
                Some(Path::new("/settings/m2"))
            );
            assert_eq!(
                config.maven_local_repository(),
                Some(Path::new("/settings/m2"))
            );
            assert!(config.project_sets_local_repository());
            assert_eq!(config.inactive_profiles, ["user-off"]);
            let network = &config.network;
            assert_eq!(
                (network.timeout, network.retries, network.concurrency),
                (60, 7, 3)
            );
        });
    }

    /// A project's empty `inactive_profiles` must not clear the user's denylist,
    /// and a project id is appended without dropping the user's.
    #[test]
    fn inactive_profiles_union_user_then_project() {
        with_homes(|home, project| {
            fs::write(
                home.join("config.toml"),
                "inactive_profiles = ['user-off']\n",
            )
            .unwrap();
            fs::write(project.join("raeva.toml"), "inactive_profiles = []\n").unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(config.inactive_profiles, ["user-off"]);

            fs::write(
                project.join("raeva.toml"),
                "inactive_profiles = ['project-off']\n",
            )
            .unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(config.inactive_profiles, ["user-off", "project-off"]);
        });
    }

    /// As Maven keeps central after the active settings.xml profiles'
    /// repositories, the default follows them, and one with id `central`
    /// replaces it.
    #[test]
    fn settings_repositories_come_before_the_defaults() {
        with_homes(|home, project| {
            write_settings(
                home,
                r"<settings><profiles><profile><id>p</id>
                  <activation><activeByDefault>true</activeByDefault></activation>
                  <repositories>
                    <repository><id>corp</id><url>https://corp.example/m2/</url></repository>
                    <repository><id>central</id><url>https://central.example/m2/</url></repository>
                  </repositories></profile></profiles></settings>",
            );
            let config = Config::load(project).unwrap();
            let repositories = config.repositories();
            assert_eq!(ids(repositories, |r| &r.id), ["corp", "central"]);
            assert_eq!(repositories[1].url, "https://central.example/m2/");
            assert!(config.default_repositories().is_empty());
            assert_eq!(
                config.user_endpoint_urls(),
                ["https://corp.example/m2/", "https://central.example/m2/"]
            );

            fs::write(
                project.join("raeva.toml"),
                "[[repositories]]\nid = 'own'\nurl = 'https://own.example/m2/'\n",
            )
            .unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(
                ids(config.repositories(), |r| &r.id),
                ["own", "corp", "central"]
            );
            assert!(config.default_repositories().is_empty());
        });
    }

    /// `[[repositories]]` in raeva.toml and config.toml adds to Maven
    /// Central, as a POM's repositories do in Maven. An entry with id
    /// `central` replaces it.
    #[test]
    fn configured_repositories_keep_central() {
        with_homes(|home, project| {
            fs::write(
                project.join("raeva.toml"),
                "[[repositories]]\nid = 'own'\nurl = 'https://own.example/m2/'\n",
            )
            .unwrap();
            fs::write(
                home.join("config.toml"),
                "[[repositories]]\nid = 'corp'\nurl = 'https://corp.example/m2/'\n",
            )
            .unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(
                ids(config.repositories(), |r| &r.id),
                ["own", "corp", "central"]
            );
            assert_eq!(ids(config.default_repositories(), |r| &r.id), ["central"]);
            assert_eq!(
                config.repositories()[2].url,
                crate::RepoConfig::maven_central().url
            );

            fs::write(
                home.join("config.toml"),
                "[[repositories]]\nid = 'central'\nurl = 'https://central.example/m2/'\n",
            )
            .unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(ids(config.repositories(), |r| &r.id), ["own", "central"]);
            assert_eq!(config.repositories()[1].url, "https://central.example/m2/");
            assert!(config.default_repositories().is_empty());
        });
    }

    #[test]
    fn network_values_are_layered_bounded_and_overridable() {
        with_homes(|home, project| {
            let raeva_toml = project.join("raeva.toml");
            let config_toml = home.join("config.toml");
            let load = |toml: &str, vars: [(&str, Option<&str>); 5]| {
                fs::write(&raeva_toml, toml).unwrap();
                temp_env::with_vars(vars, || Config::load(project).map(|config| config.network))
            };
            let env = |timeout, retries, limit, time, max| {
                [
                    ("RAEVA_TIMEOUT", timeout),
                    ("RAEVA_RETRIES", retries),
                    ("RAEVA_LOW_SPEED_LIMIT", limit),
                    ("RAEVA_LOW_SPEED_TIME", time),
                    (super::MAX_ARTIFACT_SIZE_ENV, max),
                ]
            };
            fs::write(
                &config_toml,
                "[network]\nlow_speed_limit = 2000\nlow_speed_time = 45\n",
            )
            .unwrap();
            let gib16 = 16 * 1024 * 1024 * 1024;
            for (toml, vars, expected) in [
                (
                    "[network]\nlow_speed_limit = 1000\n",
                    env(None, None, None, None, None),
                    (30, 3, 1000, 45, gib16),
                ),
                (
                    "[network]\ntimeout = 86400\nretries = 100\n",
                    env(None, None, Some("0"), Some("2"), Some(" 4096 ")),
                    (86_400, 100, 0, 2, 4096),
                ),
                (
                    "[network]\ntimeout = 0\n",
                    env(Some("30"), None, None, None, Some("0")),
                    (30, 3, 2000, 45, gib16),
                ),
                (
                    "[network]\ntimeout = 0\n",
                    env(Some(" 30 "), Some(""), None, None, None),
                    (30, 3, 2000, 45, gib16),
                ),
            ] {
                let network = load(toml, vars).unwrap();
                let actual = (
                    network.timeout,
                    network.retries,
                    network.low_speed_limit,
                    network.low_speed_time,
                    network.max_artifact_size,
                );
                assert_eq!(actual, expected, "{toml:?}");
            }

            let file = format!("invalid project config {}: network.", raeva_toml.display());
            let var = "invalid environment variable";
            let none = env(None, None, None, None, None);
            for (toml, vars, expected) in [
                (
                    "[network]\ntimeout = 86401\n",
                    none,
                    format!("{file}timeout must be between 1 and 86400 seconds, got 86401"),
                ),
                (
                    "[network]\nlow_speed_time = 0\n",
                    none,
                    format!(
                        "{file}low_speed_time must be a positive number of seconds; use \
                         low_speed_limit = 0 to disable the check"
                    ),
                ),
                (
                    "",
                    env(Some("18446744073709551615"), None, None, None, None),
                    format!(
                        "{var} RAEVA_TIMEOUT: must be between 1 and 86400 seconds, got \
                         18446744073709551615"
                    ),
                ),
                (
                    "",
                    env(None, Some("-1"), None, None, None),
                    format!("{var} RAEVA_RETRIES: expected an unsigned number, got \"-1\""),
                ),
                (
                    "",
                    env(Some("30s"), None, None, None, None),
                    format!("{var} RAEVA_TIMEOUT: expected an unsigned number, got \"30s\""),
                ),
                (
                    "[network]\nmax_artifact_size = 4096\n",
                    none,
                    format!(
                        "invalid project config {}: line 2: unknown field `max_artifact_size`",
                        raeva_toml.display()
                    ),
                ),
                (
                    "\nbogus_key = 1\n",
                    none,
                    format!(
                        "invalid project config {}: line 2: unknown field `bogus_key`, expected \
                         one of `local_repository`, `repositories`, `mirrors`, `auth`, `proxies`, \
                         `network`, `lock`, `active_profiles`, `inactive_profiles`, `security`",
                        raeva_toml.display()
                    ),
                ),
                (
                    "# comment\n[network\ntimeout = 3\n",
                    none,
                    format!(
                        "invalid project config {}: line 2: unclosed table, expected `]`",
                        raeva_toml.display()
                    ),
                ),
                (
                    "[network]\n\"\\u001b[2J\" = 1\n",
                    none,
                    format!(
                        "invalid project config {}: line 2: unknown field `\\u{{1b}}[2J`",
                        raeva_toml.display()
                    ),
                ),
                (
                    "[network]\nconcurrency = \"x, expected \\u001b[2J\"\n",
                    none,
                    format!(
                        "invalid project config {}: line 2: invalid type: string, expected usize",
                        raeva_toml.display()
                    ),
                ),
                (
                    "[lock]\njdks = [\"17\"]\n\n[network]\nconcurrency = \"4\"\n",
                    none,
                    format!(
                        "invalid project config {}: line 5: invalid type: string, expected usize",
                        raeva_toml.display()
                    ),
                ),
                (
                    "[[proxies]]\nid = \"p\"\nhost = \"h\"\nauth_type = \"271828\"\n",
                    none,
                    format!(
                        "invalid project config {}: line 4: unknown variant, expected",
                        raeva_toml.display()
                    ),
                ),
                (
                    "[[auth]]\nid = \"corp\"\npassword = 271828\n",
                    none,
                    format!(
                        "invalid project config {}: line 3: invalid type: integer, expected a \
                         string",
                        raeva_toml.display()
                    ),
                ),
            ] {
                let error = load(toml, vars).unwrap_err().to_string();
                assert!(error.contains(&expected), "{error}");
                assert!(
                    !error.contains("271828") && !error.contains("\"4\""),
                    "{error}"
                );
            }

            fs::write(&config_toml, "[network]\nretries = 500\n").unwrap();
            assert_eq!(
                load("", none).unwrap_err().to_string(),
                format!(
                    "invalid user config {}: network.retries must be at most 100, got 500",
                    config_toml.display()
                )
            );
        });
    }

    /// Proxies and mirrors describe the machine's network: a project
    /// `raeva.toml` may not name one, so it cannot take the requests, and the
    /// credential, of the user's mirror id. A proxy that would carry nothing
    /// is refused.
    #[test]
    fn proxies_and_mirrors_come_from_the_user() {
        with_homes(|home, project| {
            let proxy = "[[proxies]]\nhost = \"user:pw@proxy.example\"\nport = 3128\n";
            let mirror = "[[mirrors]]\nid = \"corp-mirror\"\nurl = \"https://proxy.example/\"\n\
                          mirror_of = [\"*\"]\n";
            for (raeva_toml, key) in [
                (proxy, "[[proxies]]"),
                ("proxies = []\n", "[[proxies]]"),
                (mirror, "[[mirrors]]"),
                ("mirrors = []\n", "[[mirrors]]"),
            ] {
                fs::write(project.join("raeva.toml"), raeva_toml).unwrap();
                let error = Config::load(project).unwrap_err();
                let message = error.to_string();
                assert!(
                    matches!(
                        &error,
                        ConfigError::Invalid {
                            origin: ConfigOrigin::ProjectConfig(_),
                            ..
                        }
                    ),
                    "{message}"
                );
                assert!(message.contains(key) && message.contains("config.toml"));
                assert!(!message.contains("proxy.example"), "{message}");
            }
            fs::write(project.join("raeva.toml"), "").unwrap();
            for protocol in ["HTTP", "https", "All"] {
                let toml = format!("{proxy}protocol = \"{protocol}\"\n");
                fs::write(home.join("config.toml"), toml).unwrap();
                let config = Config::load(project).unwrap();
                assert_eq!(config.proxies()[0].port, 3128);
            }
            fs::write(
                home.join("config.toml"),
                format!("{proxy}protocol = \"socks5\"\n"),
            )
            .unwrap();
            let error = Config::load(project).unwrap_err();
            let message = error.to_string();
            assert!(
                matches!(
                    &error,
                    ConfigError::Invalid {
                        origin: ConfigOrigin::UserConfig(_),
                        ..
                    }
                ),
                "{message}"
            );
            assert!(
                message.contains("socks5") && !message.contains("user:pw"),
                "{message}"
            );
        });
    }

    /// raeva 0.4's `rv.toml` and `rv.lock` are not read; each warns until
    /// the file raeva reads in its place exists.
    #[test]
    fn files_raeva_0_4_wrote_warn() {
        with_homes(|_, project| {
            let ignored = || {
                let (config, warnings) =
                    crate::test_warnings::capture_warnings(|| Config::load(project));
                config.unwrap();
                warnings
                    .into_iter()
                    .filter(|w| w.sec_code.as_deref() == Some("SETTING_IGNORED"))
                    .map(|w| w.message)
                    .collect::<Vec<_>>()
            };
            fs::write(project.join("rv.toml"), "").unwrap();
            fs::write(project.join("rv.lock"), "").unwrap();
            assert_eq!(
                ignored(),
                [format!(
                    "ignoring rv.toml and rv.lock in {}, which raeva 0.4 wrote; raeva reads \
                     raeva.toml and raeva.lock",
                    project.display()
                )]
            );
            fs::write(project.join("raeva.toml"), "").unwrap();
            assert_eq!(ignored().len(), 1);
            fs::write(project.join("raeva.lock"), "").unwrap();
            assert_eq!(ignored(), Vec::<String>::new());
        });
    }

    /// A repository or mirror URL that is not http, https or file fails at
    /// load, naming its entry and file.
    #[test]
    fn repository_urls_that_are_not_urls_are_refused() {
        with_homes(|home, project| {
            for (file, toml, expected) in [
                (
                    "raeva.toml",
                    "[[repositories]]\nid = 'r'\nurl = 'not a url'\n",
                    "the URL of repository 'r' is not a URL (relative URL without a base)",
                ),
                (
                    "config.toml",
                    "[[mirrors]]\nid = 'm'\nurl = 'ftp://x/'\n",
                    "the URL of mirror 'm' has scheme 'ftp'; raeva reads http, https and file URLs",
                ),
                (
                    "config.toml",
                    "[[mirrors]]\nid = 'b'\nurl = 'https://[bad'\n",
                    "the URL of mirror 'b' is not a URL (invalid IPv6 address)",
                ),
            ] {
                let path = if file == "raeva.toml" { project } else { home }.join(file);
                fs::write(&path, toml).unwrap();
                let message = Config::load(project).unwrap_err().to_string();
                assert!(
                    message.contains(file) && message.contains(expected),
                    "{message}"
                );
                fs::remove_file(&path).unwrap();
            }
            fs::write(
                project.join("raeva.toml"),
                "[[repositories]]\nid = 'r'\nurl = ' https://repo.example/ '\n",
            )
            .unwrap();
            Config::load(project).unwrap();
        });
    }

    /// raeva.lock records repository URLs as written, so none may carry a
    /// secret, in any file.
    #[test]
    fn repository_urls_with_secrets_are_refused() {
        with_homes(|home, project| {
            let cases = [
                (
                    "raeva.toml",
                    "[[repositories]]\nid = 'r'\nurl = 'https://u:p@repo.example/'\n",
                ),
                (
                    "config.toml",
                    "[[mirrors]]\nurl = 'https://repo.example/?token=x'\n",
                ),
            ];
            for (file, toml) in cases {
                let path = if file == "raeva.toml" { project } else { home }.join(file);
                fs::write(&path, toml).unwrap();
                let message = Config::load(project).unwrap_err().to_string();
                assert!(
                    message.contains("which raeva.lock would record"),
                    "{message}"
                );
                assert!(!message.contains("u:p") && !message.contains("token=x"));
                fs::remove_file(&path).unwrap();
            }
            write_settings(
                home,
                "<settings><profiles><profile><id>off</id><repositories><repository>\
                 <id>r</id><url>https://repo.example/#frag</url></repository>\
                 </repositories></profile></profiles></settings>",
            );
            let message = Config::load(project).unwrap_err().to_string();
            assert!(
                message.contains("repository 'r' has a fragment"),
                "{message}"
            );
        });
    }

    #[test]
    fn settings_xml_errors_and_warnings_reach_the_user_once() {
        with_homes(|home, project| {
            write_settings(home, "<settings><mirrors><mirror></settings>not closed");
            let message = Config::load(project).unwrap_err().to_string();
            let prefix = format!(
                "invalid Maven settings {}: ",
                home.join(".m2").join("settings.xml").display()
            );
            assert!(message.starts_with(&prefix), "{message}");
            assert!(message.ends_with("; fix or remove it"), "{message}");

            // A refusal that says what to do instead does not get it too.
            write_settings(
                home,
                "<settings><profiles><profile><id>p</id><repositories><repository>\
                 <id>corp</id><url>https://dl.example/${env.REPO_TOKEN}/maven/</url>\
                 </repository></repositories></profile></profiles></settings>",
            );
            let message = Config::load(project).unwrap_err().to_string();
            assert!(message.starts_with(&prefix), "{message}");
            assert!(
                message.ends_with("if it is not a secret, rename REPO_TOKEN")
                    && message.contains("looks like a secret's")
                    && !message.contains("fix or remove it"),
                "{message}"
            );

            write_settings(
                home,
                "<settings><servers><server><id>corp</id><username>user</username>\
                 <password>{EbvSxq8u/P5Y6MJqsF8=}</password></server></servers>\
                 <mirrors><mirror><id>m</id><url>https://mirror.example/</url>\
                 <mirrorOf>*</mirrorOf></mirror></mirrors></settings>",
            );
            let (config, warnings) =
                crate::test_warnings::capture_warnings(|| Config::load(project));
            let config = config.unwrap();
            let dropped = warnings
                .iter()
                .filter(|w| w.sec_code.as_deref() == Some("CREDENTIAL_DROPPED"))
                .count();
            assert_eq!(dropped, 1, "{warnings:?}");
            assert_eq!(ids(config.mirrors(), |m| &m.id), ["m"]);
        });
    }

    /// Maven's `DefaultProfileSelector` for profiles that do not come from
    /// a POM: explicitly active ones, those whose activation matches, and
    /// those active by default, even beside an explicit one.
    #[test]
    fn settings_profiles_activate_as_in_maven() {
        with_homes(|home, project| {
            let flag = home.join("raeva-flag");
            let key = format!("RAEVA_TEST_PROP_{}", std::process::id());
            fs::write(
                home.join("config.toml"),
                format!("[security]\nallow_env_substitution = [\"{key}\"]\n"),
            )
            .unwrap();
            let profile = |id: &str, activation: &str| {
                format!(
                    "<profile><id>{id}</id>{activation}<repositories><repository>\
                     <id>{id}-repo</id><url>https://{id}.example/</url></repository>\
                     </repositories></profile>"
                )
            };
            let profiles = [
                profile("chosen", ""),
                profile("idle", ""),
                profile(
                    "default",
                    "<activation><activeByDefault>true</activeByDefault></activation>",
                ),
                profile("jdk8", "<activation><jdk>1.8</jdk></activation>"),
                profile(
                    "prop",
                    &format!(
                        "<activation><property><name>env.{key}</name><value>bar</value>\
                         </property></activation>"
                    ),
                ),
                profile(
                    "file",
                    &format!(
                        "<activation><file><exists>{}</exists></file></activation>",
                        flag.display()
                    ),
                ),
            ];
            write_settings(
                home,
                &format!(
                    "<settings><profiles>{}</profiles><activeProfiles>\
                     <activeProfile>chosen</activeProfile></activeProfiles></settings>",
                    profiles.concat()
                ),
            );
            let load = || {
                temp_env::with_vars(
                    [
                        ("JAVA_VERSION", Some("11.0.0")),
                        (key.as_str(), Some("bar")),
                    ],
                    || Config::load(project).unwrap(),
                )
            };
            let config = load();
            assert_eq!(
                ids(config.repositories(), |r| &r.id),
                ["chosen-repo", "default-repo", "prop-repo", "central"]
            );
            assert_eq!(config.active_profiles(), ["chosen"]);
            assert_eq!(
                config.active_settings_profiles(),
                ["chosen", "default", "prop"]
            );
            fs::write(&flag, b"").unwrap();
            let config = load();
            assert!(
                config
                    .active_settings_profiles()
                    .iter()
                    .any(|id| id == "file")
            );
            let conditional = config.conditional_settings_profiles();
            let conditional: Vec<&str> = conditional.iter().map(|(id, _)| id.as_str()).collect();
            assert_eq!(conditional, ["default", "jdk8", "prop", "file"]);
            let explicit = config.for_platforms([]);
            assert_eq!(explicit.active_settings_profiles(), ["chosen"]);
        });
    }

    /// Maven selects settings.xml profiles with the `-D` and `-P` options of
    /// `.mvn/maven.config` and the inactive profiles too, and tests a
    /// relative `<file>` in the project. A condition that decided a profile
    /// with repositories is recorded by a key, never by its text, and only
    /// for the platforms a configuration is made for.
    #[test]
    fn settings_profiles_see_maven_config_and_the_project() {
        with_homes(|home, project| {
            let profile = |id: &str, activation: &str, repository: bool| {
                let repositories = if repository {
                    format!(
                        "<repositories><repository><id>{id}-repo</id>\
                         <url>https://{id}.example/</url></repository></repositories>"
                    )
                } else {
                    String::new()
                };
                format!("<profile><id>{id}</id>{activation}{repositories}</profile>")
            };
            let profiles = [
                profile("chosen", "", true),
                profile("dropped", "", true),
                profile("listed", "", true),
                profile("jdk8", "<activation><jdk>1.8</jdk></activation>", true),
                profile(
                    "modern",
                    "<activation><jdk>[17,)</jdk><file><exists>marker/</exists></file>\
                     </activation>",
                    true,
                ),
                profile("quiet", "<activation><jdk>[17,)</jdk></activation>", false),
                profile(
                    "spelled",
                    "<activation><file><exists>${project.basedir}/${mark}</exists></file>\
                     </activation>",
                    true,
                ),
            ];
            write_settings(
                home,
                &format!(
                    "<settings><profiles>{}</profiles><activeProfiles>\
                     <activeProfile>dropped</activeProfile><activeProfile>listed</activeProfile>\
                     </activeProfiles></settings>",
                    profiles.concat()
                ),
            );
            fs::write(
                home.join("config.toml"),
                "inactive_profiles = ['dropped']\n",
            )
            .unwrap();
            fs::create_dir_all(project.join(".mvn")).unwrap();
            fs::write(project.join("marker"), b"").unwrap();
            let load = |maven_config: &str| {
                fs::write(project.join(".mvn/maven.config"), maven_config).unwrap();
                temp_env::with_var("JAVA_VERSION", Some("21.0.1"), || {
                    Config::load(project).unwrap()
                })
            };
            let repositories = |config: &Config| {
                ids(config.repositories(), |r| &r.id)
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            };
            let config = load("-Pchosen\n");
            assert_eq!(
                repositories(&config),
                ["chosen-repo", "listed-repo", "modern-repo", "central"]
            );
            assert_eq!(config.conditional_settings_profiles().len(), 4);
            let by_expression = load("-P${os.name}\n");
            assert_eq!(by_expression.conditional_settings_profiles().len(), 7);
            assert_eq!(
                repositories(&config.for_platforms([])),
                ["chosen-repo", "listed-repo", "central"]
            );
            assert!(config.consulted_settings_conditions().is_empty());
            let linux = config.for_platforms([("linux", "x86_64", None)]);
            let keys = linux.consulted_settings_conditions();
            assert_eq!(keys.len(), 4, "{keys:?}");
            let mut conditions: Vec<_> = keys
                .iter()
                .map(|key| linux.settings_condition(key).unwrap())
                .collect();
            conditions.sort();
            assert_eq!(
                conditions,
                [
                    ("file:${project.basedir}/${mark}".to_string(), false),
                    ("file:marker/".to_string(), true),
                    ("jdk:1.8".to_string(), false),
                    ("jdk:[17,)".to_string(), true),
                ]
            );
            assert!(
                keys.iter()
                    .all(|key| key.len() == 16 && !key.contains("jdk"))
            );

            let config = load("-Dmark=marker\n");
            assert_eq!(
                repositories(&config),
                ["listed-repo", "modern-repo", "spelled-repo", "central"]
            );
            let key = config
                .for_platforms([("linux", "x86_64", None)])
                .consulted_settings_conditions()
                .into_iter()
                .find(|key| {
                    config
                        .settings_condition(key)
                        .unwrap()
                        .0
                        .contains("${mark}")
                })
                .unwrap();
            assert_eq!(
                config.settings_condition(&key),
                Some(("file:${project.basedir}/${mark}".to_string(), true))
            );

            let config = load("-P!chosen,!listed\n-Djava.version=1.8\n");
            assert_eq!(repositories(&config), ["jdk8-repo", "central"]);
            assert_eq!(repositories(&config.for_platforms([])), ["central"]);
            fs::remove_file(project.join("marker")).unwrap();
            let config = load("");
            assert_eq!(repositories(&config), ["listed-repo", "central"]);
        });
    }

    /// A `.mvn/maven.config` Maven would refuse fails the load, rather than
    /// losing a `-P !id` that turns off a settings.xml repository, except
    /// for a command that reads only the lock.
    #[test]
    fn a_maven_config_maven_refuses_fails_the_load() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><profiles><profile><id>public</id><repositories><repository>\
                 <id>central</id><url>https://repo.example/maven2/</url></repository>\
                 </repositories></profile></profiles><activeProfiles>\
                 <activeProfile>public</activeProfile></activeProfiles></settings>",
            );
            fs::create_dir_all(project.join(".mvn")).unwrap();
            for content in [&b"-P!public\ngarbage\n"[..], b"-P!public\n\xff\n"] {
                fs::write(project.join(".mvn/maven.config"), content).unwrap();
                let Err(error) = Config::load(project) else {
                    panic!("refused");
                };
                assert!(error.to_string().contains("maven.config"), "{error}");
                Config::load_for_lock(project, &CommandLine::default())
                    .expect("a lock can still be read");
            }
            fs::write(project.join(".mvn/maven.config"), "-P!public\n").unwrap();
            let config = Config::load(project).unwrap();
            assert!(
                config
                    .repositories()
                    .iter()
                    .all(|r| !r.url.contains("repo.example"))
            );
        });
    }

    /// `-P !id` keeps an `<activeProfiles>` id from selecting POM profiles
    /// on the platform it expands to deactivate the id on.
    #[test]
    fn a_deactivated_id_leaves_the_explicit_profiles_per_platform() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><activeProfiles><activeProfile>amd64</activeProfile>\
                 <activeProfile>kept</activeProfile></activeProfiles></settings>",
            );
            let command_line =
                CommandLine::new(Vec::new(), vec!["!${os.arch}".into()], Vec::new()).unwrap();
            let config = Config::load_with_command_line(project, &command_line).unwrap();
            let active = |platforms: &[(&str, &str)]| {
                let platforms = platforms.iter().map(|(os, arch)| (*os, *arch, None));
                config.for_platforms(platforms).active_profiles().to_vec()
            };
            assert_eq!(active(&[("linux", "x86_64")]), ["kept"]);
            assert_eq!(active(&[("linux", "aarch64")]), ["amd64", "kept"]);
            let both = [("linux", "x86_64"), ("linux", "aarch64")];
            assert_eq!(active(&both), ["amd64", "kept"]);
        });
    }

    /// A project `raeva.toml` arrives with a cloned repository, so it may only
    /// narrow the user's `[security]`; each key it asks to widen warns by
    /// name, never with what it asked for.
    #[test]
    fn a_project_can_only_narrow_the_user_security_policy() {
        with_homes(|home, project| {
            let merged = |project_keys: &str, user_keys: &str| {
                fs::write(
                    project.join("raeva.toml"),
                    format!("[security]\n{project_keys}\n"),
                )
                .unwrap();
                fs::write(
                    home.join("config.toml"),
                    format!("[security]\n{user_keys}\n"),
                )
                .unwrap();
                let (config, warnings) =
                    crate::test_warnings::capture_warnings(|| Config::load(project));
                let widened: Vec<String> = warnings
                    .iter()
                    .filter(|w| w.sec_code.as_deref() == Some("PROJECT_SECURITY_WIDENING_IGNORED"))
                    .map(|w| {
                        for secret in ["GITHUB_TOKEN", "AWS_SECRET", "hunter2", "evil.example"] {
                            assert!(!w.message.contains(secret), "{}", w.message);
                        }
                        w.key.clone().unwrap()
                    })
                    .collect();
                (config.unwrap().security, widened)
            };

            let user = "allow_env_substitution = ['A', 'B']";
            for (project_list, expected, warns) in [
                ("", &["A", "B"][..], false),
                ("['B']", &["B"], false),
                ("[]", &[], false),
                // Names match exactly, as `${env.NAME}` lookups do.
                ("['a']", &[], true),
            ] {
                let keys = match project_list {
                    "" => String::new(),
                    list => format!("allow_env_substitution = {list}"),
                };
                let (policy, widened) = merged(&keys, user);
                assert_eq!(policy.allow_env_substitution, expected, "{project_list}");
                assert_eq!(widened.len(), usize::from(warns), "{project_list}");
            }

            for (project_flag, user_flag, expected, warns) in [
                ("", "true", true, false),
                ("true", "", false, true),
                ("true", "false", false, true),
                ("true", "true", true, false),
                ("false", "true", false, false),
            ] {
                let keys = |flag: &str| match flag {
                    "" => String::new(),
                    flag => format!("allow_transitive_repositories = {flag}"),
                };
                let (policy, widened) = merged(&keys(project_flag), &keys(user_flag));
                assert_eq!(policy.allow_transitive_repositories, expected);
                assert_eq!(widened.len(), usize::from(warns));
            }

            let user = "transitive_repository_allowlist = ['https://corp.example/maven2/']";
            let (policy, widened) = merged(
                "transitive_repository_allowlist = ['https://corp.example/maven2/team/', \
                 'https://evil.example/', 'https://corp.example/maven2-evil/', \
                 'http://corp.example/maven2/', 'https://corp.example:8443/maven2/', \
                 'https://corp.example/']",
                user,
            );
            assert_eq!(
                policy.transitive_repository_allowlist,
                ["https://corp.example/maven2/team/"]
            );
            assert_eq!(widened, ["transitive_repository_allowlist"]);
            // The user flag accepts every HTTP(S) entry, and the project can
            // trade the flag for a list, which narrows.
            let (policy, widened) = merged(
                "allow_transitive_repositories = false\n\
                 transitive_repository_allowlist = ['https://vendor.example/']",
                "allow_transitive_repositories = true",
            );
            assert!(!policy.allow_transitive_repositories);
            assert_eq!(
                policy.transitive_repository_allowlist,
                ["https://vendor.example/"]
            );
            assert!(widened.is_empty());

            let (policy, widened) = merged(
                "allow_env_substitution = ['AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN']\n\
                 allow_transitive_repositories = true\n\
                 transitive_repository_allowlist = ['https://user:hunter2@evil.example/']",
                "",
            );
            assert!(policy.allow_env_substitution.is_empty());
            assert!(policy.transitive_repository_allowlist.is_empty());
            assert_eq!(
                widened,
                [
                    "allow_env_substitution",
                    "allow_transitive_repositories",
                    "transitive_repository_allowlist"
                ]
            );

            // POMs see only the merged policy's variables.
            fs::write(
                project.join("raeva.toml"),
                "[security]\nallow_env_substitution = ['GITHUB_TOKEN', 'BUILD_NUMBER']\n",
            )
            .unwrap();
            fs::write(
                home.join("config.toml"),
                "[security]\nallow_env_substitution = ['BUILD_NUMBER']\n",
            )
            .unwrap();
            let vars = [
                ("GITHUB_TOKEN", Some("ghp_secret")),
                ("BUILD_NUMBER", Some("42")),
            ];
            let config = temp_env::with_vars(vars, || Config::load(project)).unwrap();
            let host = config.host();
            assert_eq!(
                host.env_allowlist().iter().collect::<Vec<_>>(),
                ["BUILD_NUMBER"]
            );
            assert_eq!(host.env_values().values().collect::<Vec<_>>(), ["42"]);

            for (file, keys, error) in [
                ("raeva.toml", "not-a-url", "invalid project config "),
                ("config.toml", "file:///etc/", "invalid user config "),
            ] {
                let path = if file == "raeva.toml" { project } else { home }.join(file);
                fs::write(
                    &path,
                    format!("[security]\ntransitive_repository_allowlist = ['https://ok.example/', '{keys}']\n"),
                )
                .unwrap();
                let message = Config::load(project).unwrap_err().to_string();
                assert!(message.starts_with(error), "{message}");
                assert!(
                    message.contains("entry 2 must be an HTTP(S) URL"),
                    "{message}"
                );
                fs::write(&path, "").unwrap();
            }
            fs::write(
                home.join("config.toml"),
                "[security]\nallow_env_substitution = ['OK', 'MY-VAR']\n",
            )
            .unwrap();
            let message = Config::load(project).unwrap_err().to_string();
            assert!(message.contains(
                "security.allow_env_substitution entry 2 must be an environment variable name"
            ));
            assert!(!message.contains("MY-VAR"), "{message}");
        });
    }

    #[test]
    fn unknown_and_removed_keys_are_rejected() {
        for toml in [
            "mode = \"compat\"",
            "[dependencies]\ncompile = []",
            "[security]\nallow_project_local_certs = true",
            "[security]\nallow_everything = true",
            "[lock]\nplatforms = [\"linux-x86_64\"]",
        ] {
            let error = toml::from_str::<ConfigFile>(toml).expect_err(toml);
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
    }

    #[test]
    fn lock_jdks_are_layered_and_validated() {
        with_homes(|home, project| {
            let raeva_toml = project.join("raeva.toml");
            let config_toml = home.join("config.toml");

            let config = Config::load(project).unwrap();
            assert!(config.lock.jdks.is_empty());

            fs::write(&config_toml, "[lock]\njdks = ['11', '17']\n").unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(config.lock.jdks, ["11", "17"]);

            // Project raeva.toml wins over user config.toml when it sets jdks.
            fs::write(&raeva_toml, "[lock]\njdks = ['17', '21.0.4_7-ea+1']\n").unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(config.lock.jdks, ["17", "21.0.4_7-ea+1"]);
            assert!(format!("{config:?}").contains("21.0.4_7-ea+1"));

            // Empty [lock] table in project leaves user's jdks in effect.
            fs::write(&raeva_toml, "[lock]\n").unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(config.lock.jdks, ["11", "17"]);

            // Empty list is the same as no list.
            fs::write(&config_toml, "").unwrap();
            fs::write(&raeva_toml, "[lock]\njdks = []\n").unwrap();
            let config = Config::load(project).unwrap();
            assert!(config.lock.jdks.is_empty());

            for (bad, expected) in [
                ("['']", "lock.jdks entry 1 must be 1 to 32"),
                (
                    "['123456789012345678901234567890123']",
                    "lock.jdks entry 1 must be 1 to 32",
                ),
                ("['17', '21/ea']", "lock.jdks entry 2 must be 1 to 32"),
                ("['[17,)']", "lock.jdks entry 1 must be 1 to 32"),
                (
                    "['17', '21', '17']",
                    "lock.jdks lists \"17\" more than once",
                ),
            ] {
                fs::write(&raeva_toml, format!("[lock]\njdks = {bad}\n")).unwrap();
                let err = Config::load(project).unwrap_err().to_string();
                assert!(err.contains(expected), "{bad}: {err}");
            }
        });

        for (target, host, matches) in [
            ("21", "21", true),
            ("21", "21.0.12.1", true),
            ("21", "21-ea", true),
            ("1.8", "1.8.0_442", true),
            ("21", "210", false),
            ("21", "21+35", false),
            ("21", "17.0.2", false),
        ] {
            assert_eq!(
                super::jdk_matches_target(target, host),
                matches,
                "{target} vs {host}"
            );
        }
    }

    #[test]
    fn transitive_repository_allowlist_matches_origin_and_path_segments() {
        let security = |allow_all, entries: &[&str]| SecurityConfig {
            allow_transitive_repositories: allow_all,
            transitive_repository_allowlist: entries.iter().map(|e| e.to_string()).collect(),
            ..SecurityConfig::default()
        };
        let list = security(
            false,
            &[
                "https://corp.example/maven2",
                "https://corp.example:8443/m2/",
                "file:///",
            ],
        );
        for (url, allowed) in [
            ("https://corp.example/maven2", true),
            ("https://corp.example/maven2/sub/", true),
            ("ht\ttps://corp.example/maven2/", true),
            ("https://corp.example:8443/m2/x/", true),
            ("https://corp.example.evil.com/maven2/", false),
            ("https://corp.example/maven2-evil/", false),
            ("https://corp.example/m2/", false),
            ("https://corp.example:9999/maven2/", false),
            ("http://corp.example/maven2/", false),
            ("file:///etc/", false),
            ("fi\tle:///etc/", false),
            ("not-a-url", false),
        ] {
            assert_eq!(list.allows_transitive_repo_url(url), allowed, "{url:?}");
        }
        let all = security(true, &[]);
        assert!(all.allows_transitive_repo_url("https://any.example/"));
        assert!(!all.allows_transitive_repo_url("f\riLe:///etc/"));
        assert!(!all.allows_transitive_repo_url("ftp://corp.example/"));

        for (entry, shown) in [
            ("https://alice:s3cret@bad host/", "<unparsable URL>"),
            (
                "ftp://u:s3cret@corp.example/?t=x",
                "ftp://corp.example/?***",
            ),
            ("alice:/s3cret@corp.example/m2", "<unparsable URL>"),
        ] {
            let error = security(false, &["https://corp.example/", entry])
                .validate_allowlist()
                .unwrap_err();
            assert_eq!(
                error,
                format!("transitive_repository_allowlist entry 2 must be an HTTP(S) URL: {shown}")
            );
        }
    }

    #[test]
    fn fetch_concurrency_clamps() {
        let mut network = NetworkConfig::default();
        for (raw, clamped) in [(0, 1), (500, 128), (8, 8)] {
            network.concurrency = raw;
            assert_eq!(network.fetch_concurrency(), clamped);
        }
    }

    /// A settings.xml `<file>` path names a file on this machine, and reads
    /// the target JDK's `java.version`.
    #[test]
    fn settings_file_activation_reads_the_target_jdk() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><profiles><profile><id>marked</id>\
                 <activation><file><exists>${basedir}/marker-${java.version}</exists></file>\
                 </activation><properties><marked>yes</marked></properties>\
                 </profile></profiles></settings>",
            );
            fs::write(project.join("marker-21"), "").unwrap();
            let config = Config::load(project).unwrap();
            let marked = |jdk| {
                let env = config.host().environment_for("linux", "x86_64", Some(jdk));
                config
                    .settings_profile_properties_for(&env)
                    .get("marked")
                    .cloned()
            };
            assert_eq!(marked("21"), Some("yes".to_string()));
            assert_eq!(marked("17"), None);
        });
    }

    /// A settings.xml `<file>` condition that names `java.version` is
    /// recorded and checked once per `[lock] jdks` entry, not on the host's
    /// JDK.
    #[test]
    fn settings_file_conditions_hold_per_target_jdk() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><profiles><profile><id>marked</id>\
                 <activation><file><exists>${basedir}/marker-${java.version}</exists></file>\
                 </activation><repositories><repository><id>marked-repo</id>\
                 <url>https://marked.example/</url></repository></repositories>\
                 </profile></profiles></settings>",
            );
            fs::write(project.join("raeva.toml"), "[lock]\njdks = ['17', '21']\n").unwrap();
            let config = temp_env::with_var("JAVA_VERSION", Some("17"), || {
                Config::load(project).unwrap()
            });
            let scoped = config.for_platforms([
                ("linux", "x86_64", Some("17")),
                ("linux", "x86_64", Some("21")),
            ]);
            let conditions = || {
                let mut conditions: Vec<_> = (scoped.consulted_settings_conditions().iter())
                    .map(|key| config.settings_condition(key).unwrap())
                    .collect();
                conditions.sort();
                conditions
            };
            let condition = |jdk: &str, holds: bool| {
                (
                    format!("file:${{basedir}}/marker-${{java.version}} (JDK {jdk})"),
                    holds,
                )
            };
            assert_eq!(
                conditions(),
                [condition("17", false), condition("21", false)]
            );
            fs::write(project.join("marker-21"), "").unwrap();
            assert_eq!(
                conditions(),
                [condition("17", false), condition("21", true)]
            );
        });
    }

    /// The private inputs a POM can take into a repository URL, named like
    /// a secret, from each source and on any platform, with their values
    /// expanded; the others are left out.
    #[test]
    fn secret_named_inputs_come_from_defines_settings_and_allowlisted_env() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><activeProfiles><activeProfile>p</activeProfile></activeProfiles>\
                 <profiles><profile><id>p</id><properties><cs.token>s1</cs.token>\
                 <nexus.url>https://nexus.example</nexus.url>\
                 <alias.token>${repo.value}</alias.token><repo.value>s8</repo.value>\
                 <arch.token>${os.arch}/s9</arch.token>\
                 <project.artifactId>ignored</project.artifactId>\
                 <field.token>${chain.alias}</field.token>\
                 <chain.alias>${project.artifactId}/s10</chain.alias>\
                 </properties></profile>\
                 <profile><id>off</id><properties><off.token>s2</off.token></properties>\
                 </profile><profile><id>windows</id><activation><os><family>windows</family>\
                 </os></activation><properties><win.token>s7</win.token></properties>\
                 </profile></profiles></settings>",
            );
            fs::write(
                home.join("config.toml"),
                "[security]\nallow_env_substitution = [\"CS_API_KEY\", \"CS_ORG\"]\n",
            )
            .unwrap();
            fs::create_dir_all(project.join(".mvn")).unwrap();
            fs::write(
                project.join(".mvn/maven.config"),
                "-Drepo.password=s3\n-Drepo.path=open\n",
            )
            .unwrap();
            let command_line = CommandLine {
                defines: vec![
                    "gpg.passphrase=s4".to_string(),
                    "revision=1".to_string(),
                    "staged.key=${repo.value}/s12".to_string(),
                    "ci.token=${CS_ORG}/${env.CS_ORG}/${alias.token}".to_string(),
                ],
                ..CommandLine::default()
            };
            let config = temp_env::with_vars(
                [
                    ("CS_API_KEY", Some("s5")),
                    ("CS_ORG", Some("acme")),
                    ("OTHER_TOKEN", Some("s6")),
                ],
                || Config::load_with_command_line(project, &command_line).unwrap(),
            );
            let inputs = config.secret_named_inputs();
            let expected = [
                ("${env.CS_API_KEY}", "s5"),
                // As a model reads it, `${NAME}` as `${env.NAME}`.
                ("-Dci.token", "${CS_ORG}/acme/${alias.token}"),
                ("-Dci.token", "acme/acme/${alias.token}"),
                ("-Dci.token", "acme/acme/s8"),
                ("-Dgpg.passphrase", "s4"),
                ("-Drepo.password", "s3"),
                // As a dependency's model and the project's read it.
                ("-Dstaged.key", "${repo.value}/s12"),
                ("-Dstaged.key", "s8/s12"),
                ("settings.xml property alias.token", "${repo.value}"),
                ("settings.xml property alias.token", "s8"),
                // A POM can set `os.arch`.
                ("settings.xml property arch.token", "${os.arch}/s9"),
                ("settings.xml property cs.token", "s1"),
                // A model field wins over a property of its name.
                ("settings.xml property field.token", "${chain.alias}"),
                (
                    "settings.xml property field.token",
                    "${project.artifactId}/s10",
                ),
                ("settings.xml property win.token", "s7"),
            ];
            assert_eq!(
                inputs,
                expected.map(|(label, value)| (label.to_string(), value.to_string()))
            );
        });
    }

    #[test]
    fn settings_profile_properties_merge_in_file_order_per_platform_and_see_all_env() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><profiles>\
                 <profile><id>first</id>\
                   <activation><activeByDefault>true</activeByDefault></activation>\
                   <properties><shared>1</shared><common>all</common></properties>\
                 </profile>\
                 <profile><id>second</id>\
                   <properties><shared>2</shared></properties>\
                 </profile>\
                 <profile><id>linux-only</id>\
                   <activation><os><family>unix</family></os></activation>\
                   <properties><native>so</native></properties>\
                 </profile>\
                 <profile><id>ci-env</id>\
                   <activation><property><name>env.RAEVA_UNALLOWLISTED_CI</name></property></activation>\
                   <properties><ci.flag>yes</ci.flag></properties>\
                   <repositories><repository><id>ci-repo</id>\
                     <url>https://ci.example/</url></repository></repositories>\
                 </profile>\
                 <profile><id>not-ci</id>\
                   <activation><property><name>!env.RAEVA_UNALLOWLISTED_CI</name></property></activation>\
                   <properties><local.only>1</local.only></properties>\
                 </profile>\
                 </profiles><activeProfiles>\
                   <activeProfile>second</activeProfile>\
                 </activeProfiles></settings>",
            );
            let load = |ci: Option<&str>| {
                temp_env::with_var("RAEVA_UNALLOWLISTED_CI", ci, || {
                    Config::load(project).unwrap()
                })
            };
            let config = load(Some("1"));
            assert!(config.security.allow_env_substitution.is_empty());
            assert_eq!(
                config.defined_settings_properties(),
                std::collections::BTreeSet::from([
                    "ci.flag".to_string(),
                    "common".to_string(),
                    "local.only".to_string(),
                    "native".to_string(),
                    "shared".to_string(),
                ])
            );
            // `second` appears after `first` in settings.xml, so `shared` is `2`.
            let linux_props = config.settings_profile_properties("linux", "x86_64");
            assert_eq!(linux_props.get("shared"), Some(&"2".to_string()));
            assert_eq!(linux_props.get("native"), Some(&"so".to_string()));
            assert_eq!(linux_props.get("ci.flag"), Some(&"yes".to_string()));
            assert_eq!(linux_props.get("local.only"), None);
            let win_props = config.settings_profile_properties("windows", "x86_64");
            assert_eq!(win_props.get("native"), None);

            let multi =
                config.for_platforms([("linux", "x86_64", None), ("windows", "x86_64", None)]);
            assert_eq!(
                multi.settings_property_value("common"),
                Some(serde_json::to_string(&vec![Some("all"); 6]).unwrap())
            );
            assert_eq!(multi.settings_property_value("local.only"), None);
            let native = serde_json::to_string(&[
                Some("so"),
                Some("so"),
                Some("so"),
                Some("so"),
                None,
                None,
            ])
            .unwrap();
            assert_eq!(
                multi.settings_property_value("native"),
                Some(native.to_string())
            );
            let reversed =
                config.for_platforms([("windows", "x86_64", None), ("linux", "x86_64", None)]);
            assert_eq!(
                reversed.settings_property_value("native"),
                Some(native.to_string())
            );
            assert_eq!(
                config.settings_property_value("native"),
                Some(native.to_string())
            );
            let keys = multi.consulted_settings_conditions();
            assert_eq!(keys.len(), 1, "{keys:?}");
            assert_eq!(
                multi.settings_condition(&keys[0]),
                Some(("property:env.RAEVA_UNALLOWLISTED_CI".to_string(), true))
            );
            let without_ci = load(None);
            assert_eq!(
                without_ci.settings_condition(&keys[0]),
                Some(("property:env.RAEVA_UNALLOWLISTED_CI".to_string(), false))
            );
            assert_eq!(
                without_ci
                    .settings_profile_properties("linux", "x86_64")
                    .get("local.only"),
                Some(&"1".to_string())
            );
        });
    }
    #[test]
    fn private_property_lookups_hash_only_consulted_external_values() {
        with_homes(|home, project| {
            let template = crate::maven_config::PropertyLookup {
                expression: "${alias}".into(),
                properties: [("alias".into(), "${selector}".into())].into(),
                file: None,
                default_packaging: None,
                source: rv_maven_model::PropertySource::User,
                mode: crate::maven_config::LookupMode::Property,
                model: None,
            }
            .encode();
            let value = |defines: &[&str]| {
                let command_line = CommandLine::new(
                    defines.iter().map(|value| value.to_string()).collect(),
                    Vec::new(),
                    Vec::new(),
                )
                .unwrap();
                Config::load_with_command_line(project, &command_line)
                    .unwrap()
                    .user_property_lookup_value(&template)
                    .unwrap()
            };
            let yes = value(&["selector=private-key", "private-key=yes"]);
            assert_eq!(
                yes,
                value(&["selector=private-key", "private-key=yes", "unread=no"])
            );
            assert_ne!(yes, value(&["selector=private-key", "private-key=no"]));
            let absent = value(&["selector=private-key"]);
            assert_ne!(yes, absent);
            write_settings(
                home,
                "<settings><profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault></activation><properties><private-key>yes</private-key></properties></profile></profiles></settings>",
            );
            assert_ne!(absent, value(&["selector=private-key"]));
            assert_eq!(yes, value(&["selector=private-key"]));
            assert!(!template.contains("private-key"));
        });
    }

    #[test]
    fn private_file_lookup_replays_portable_local_context() {
        with_homes(|home, project| {
            fs::create_dir(project.join("module")).unwrap();
            let template = crate::maven_config::PropertyLookup {
                expression: "${project.basedir}/${alias}".into(),
                properties: [("alias".into(), "${selector}-${packaging}".into())].into(),
                file: Some(crate::maven_config::FileLookup {
                    base_dir: Some("module".into()),
                }),
                default_packaging: Some("jar".into()),
                source: rv_maven_model::PropertySource::User,
                mode: crate::maven_config::LookupMode::File,
                model: None,
            }
            .encode();
            let command_line =
                CommandLine::new(vec!["selector=private".into()], Vec::new(), Vec::new()).unwrap();
            let value = |project: &Path| {
                Config::load_with_command_line(project, &command_line)
                    .unwrap()
                    .user_property_lookup_value(&template)
                    .unwrap()
            };
            let absent = value(project);
            fs::write(project.join("module/private-jar"), "x").unwrap();
            let present = value(project);
            assert_ne!(absent, present);
            let moved = home.join("moved");
            fs::rename(project, &moved).unwrap();
            assert_eq!(present, value(&moved));
            assert!(!template.contains("private"));
        });
    }

    #[test]
    fn target_property_encodings_do_not_alias_literal_vector_or_joined_text() {
        with_homes(|home, project| {
            fs::write(project.join("raeva.toml"), "[lock]\njdks = ['17', '21']\n").unwrap();
            fs::create_dir_all(project.join(".mvn")).unwrap();
            let path = project.join(".mvn/maven.config");
            fs::write(&path, "-Dflag=${java.version}\n").unwrap();
            let names = std::collections::BTreeSet::from(["flag".to_string()]);
            let config = Config::load(project).unwrap();
            let varying = config.user_property_values(&names)["flag"].clone().unwrap();
            let values: Vec<Option<String>> = (0..6)
                .flat_map(|_| [Some("17".to_string()), Some("21".to_string())])
                .collect();
            let literal = serde_json::to_string(&values).unwrap();
            fs::write(&path, format!("-Dflag={literal}\n")).unwrap();
            let uniform =
                Config::load(project).unwrap().user_property_values(&names)["flag"].clone();
            assert_ne!(Some(varying), uniform);

            write_settings(
                home,
                "<settings><profiles><profile><id>17</id><activation><jdk>17</jdk></activation><properties><flag>17</flag></properties></profile><profile><id>21</id><activation><jdk>21</jdk></activation><properties><flag>21</flag></properties></profile></profiles></settings>",
            );
            let varying = Config::load(project)
                .unwrap()
                .settings_property_value("flag");
            let targets = [
                "linux-x86_64",
                "linux-aarch64",
                "macos-x86_64",
                "macos-aarch64",
                "windows-x86_64",
                "windows-aarch64",
            ];
            let literal = targets
                .into_iter()
                .flat_map(|target| {
                    ["17", "21"]
                        .into_iter()
                        .map(move |jdk| format!("{target} (JDK {jdk})={jdk}"))
                })
                .collect::<Vec<_>>()
                .join("\n");
            write_settings(
                home,
                &format!(
                    "<settings><profiles><profile><id>all</id><activation><activeByDefault>true</activeByDefault></activation><properties><flag>{literal}</flag></properties></profile></profiles></settings>"
                ),
            );
            let uniform = Config::load(project)
                .unwrap()
                .settings_property_value("flag");
            assert_ne!(varying, uniform);
            assert_eq!(
                serde_json::from_str::<Vec<Option<String>>>(uniform.as_deref().unwrap()).unwrap(),
                vec![Some(literal); 12]
            );
        });
    }
}
