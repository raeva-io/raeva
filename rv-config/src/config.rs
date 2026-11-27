use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use sha2::Digest;

use rv_maven_model::{
    Activation, ActivationContext, HostInput, HostSnapshot, ModelEnvironment, PropertyMap,
};

use crate::credential_scope::CredentialScope;
use crate::error::{ConfigError, ConfigOrigin};
use crate::maven_config::{CommandLine, MavenConfigOptions};
use crate::maven_mode::MavenSelection;
use crate::maven_settings::{MavenProfile, MavenSettings};
use crate::paths::ResolvedPaths;
use crate::repository_filters::RepositoryFilters;
use crate::settings::{AuthConfig, MirrorConfig, ProxyConfig, RepoConfig};
use rv_maven_types::MavenMode;

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
/// them in `<server>`. A mirror's URL is not recorded, but joining an
/// artifact path drops its query and fragment. The message names the entry,
/// never the URL.
fn refuse_secret_urls<'a>(
    urls: impl IntoIterator<Item = (&'static str, Option<&'a str>, &'a str)>,
    origin: &ConfigOrigin,
) -> Result<(), ConfigError> {
    for (kind, id, url) in urls {
        let entry = match id {
            Some(id) => format!("{kind} '{id}'"),
            None => format!("a {kind} without an id"),
        };
        if let Some(refusal) = crate::redact::url_refusal(url) {
            return Err(ConfigError::Invalid {
                origin: origin.clone(),
                message: format!("the URL of {entry} {refusal}"),
            });
        }
        let Some(part) = crate::redact::secret_url_part(url) else {
            continue;
        };
        // raeva.lock records a repository's URL, never a mirror's.
        let message = match (kind, part) {
            ("mirror", "userinfo") => format!(
                "the URL of {entry} has userinfo; raeva takes a mirror's credentials only from \
                 an [[auth]] entry in config.toml or a <server> in settings.xml with the \
                 mirror's id, so remove it and put them there"
            ),
            ("mirror", _) => format!(
                "the URL of {entry} has {part}, which raeva drops as it appends artifact paths \
                 to the URL; remove it"
            ),
            (_, "userinfo") => format!(
                "the URL of {entry} has userinfo, which raeva.lock would record; remove it and \
                 put the credentials in an [[auth]] entry in config.toml or a <server> in \
                 settings.xml with the repository's id"
            ),
            _ => format!(
                "the URL of {entry} has {part}, which raeva.lock would record; remove it; a \
                 repository URL is a base that raeva appends artifact paths to"
            ),
        };
        return Err(ConfigError::Invalid {
            origin: origin.clone(),
            message,
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

/// The mirrors that serve a repository, and the URLs of those that mirror
/// nothing, which only name a redirect target.
fn split_mirrors(
    mirrors: impl IntoIterator<Item = MirrorConfig>,
) -> (Vec<MirrorConfig>, Vec<String>) {
    let (mirrors, targets): (Vec<_>, Vec<_>) =
        (mirrors.into_iter()).partition(|mirror| !mirror.mirrors_nothing());
    (
        mirrors,
        targets.into_iter().map(|mirror| mirror.url).collect(),
    )
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
    pub plugins: Option<crate::plugins::PluginsConfigToml>,
    pub active_profiles: Option<Vec<String>>,
    pub inactive_profiles: Option<Vec<String>>,
    pub security: Option<SecurityConfigToml>,
}

/// The `[lock]` settings in effect.
///
/// [`Config::load`] takes `jdks` from the project `raeva.toml`, else the user
/// `config.toml`, else an empty list, and `maven` from the project
/// `raeva.toml`, else the Maven wrapper, else 3.9.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockConfig {
    /// The `java.version` values `raeva sync` resolves each platform for.
    /// An empty list means the host's JDK alone.
    pub jdks: Vec<String>,
    /// The Maven line the project selects, which resolution follows.
    pub maven: MavenSelection,
}

/// `[lock]` table as written in raeva.toml / config.toml.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LockConfigToml {
    pub jdks: Option<Vec<String>>,
    pub maven: Option<String>,
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
    project_root: &Path,
    mvn_dir: &Path,
    strict: bool,
) -> Result<LockConfig, ConfigError> {
    let (p, u) = (project.unwrap_or_default(), user.unwrap_or_default());
    // The Maven line is the project's, as its wrapper is, so two machines
    // lock the project alike.
    if u.maven.is_some() {
        return Err(ConfigError::Invalid {
            origin: origins.1.clone(),
            message: "lock.maven belongs in the project's raeva.toml".to_string(),
        });
    }
    let project_path = match &origins.0 {
        ConfigOrigin::ProjectConfig(path) => path.clone(),
        _ => project_root.join("raeva.toml"),
    };
    let maven = crate::maven_mode::select(mvn_dir, p.maven.as_deref(), &project_path, strict)?;
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
            // It covers `1.8.0_N` as `1.8` does, but names no
            // `java.specification.version`.
            if jdk == "1" {
                return Err(ConfigError::Invalid {
                    origin,
                    message: format!(
                        "lock.jdks entry {} is \"1\", which names no Java release; write \"1.8\" \
                         for JDK 8",
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
    Ok(LockConfig { jdks, maven })
}

/// The `.mvn` directory `mvn` reads for `project_root`, which may be above
/// the project, as the Maven wrapper reads it too: in `shell`'s
/// `MAVEN_BASEDIR`, else in the nearest directory with a `.mvn` up from
/// where `shell`'s `PWD` names the project. The configuration and the
/// secret pre-pass both take it from here.
pub(crate) fn launcher_mvn_dir(
    project_root: &Path,
    shell: &crate::user_home::Shell,
) -> Result<PathBuf, ConfigError> {
    let env = |name: &str| String::from_utf8(shell.shell_value(name)?).ok();
    for name in ["MAVEN_BASEDIR", "PWD"] {
        if shell.shell_value(name).is_some() && env(name).is_none() {
            return Err(ConfigError::UnreadHostProperty(format!(
                "{name} is not UTF-8 text, which raeva does not read as the directory mvn \
                 takes .mvn from; set it to a UTF-8 path, or unset it"
            )));
        }
    }
    // `mvn` passes a relative one on as written, and reads files under it
    // from the directory it runs in.
    if env("MAVEN_BASEDIR").is_some_and(|dir| !dir.is_empty() && !Path::new(&dir).is_absolute()) {
        return Err(ConfigError::Invalid {
            origin: ConfigOrigin::Env("MAVEN_BASEDIR"),
            message: "a relative path, which Maven reads from the directory mvn runs in and \
                      passes on as written; set it to an absolute path"
                .to_string(),
        });
    }
    Ok(Path::new(&rv_maven_model::launcher_root(
        project_root,
        env("MAVEN_BASEDIR").as_deref(),
        env("PWD").as_deref(),
        std::env::current_dir().ok().as_deref(),
    ))
    .join(".mvn"))
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

/// A `MAVEN_CONFIG` with an option that changes what Maven resolves, as
/// the mavenrc files leave it, where one of the Maven Wrapper `scripts`
/// passes it to Maven before its own arguments. `mvn` and the
/// only-script wrapper pass none of it, so raeva cannot tell which the
/// build reads. Names no value. Returns its reactor selection where a
/// script passes it, which raeva ignores, as in `MAVEN_ARGS`.
fn refuse_wrapper_maven_config(
    shell: &crate::user_home::Shell,
    scripts: impl IntoIterator<Item = PathBuf>,
) -> Result<Vec<&'static str>, ConfigError> {
    let refuse = |why: String| ConfigError::Invalid {
        origin: ConfigOrigin::Env("MAVEN_CONFIG"),
        message: why,
    };
    let value = shell.shell_value("MAVEN_CONFIG").unwrap_or_default();
    let read = (std::str::from_utf8(&value).ok())
        .and_then(|args| crate::maven_config::maven_args(args).ok());
    if value.iter().all(u8::is_ascii_whitespace)
        || read.as_ref() == Some(&crate::maven_config::MavenArgs::default())
    {
        return Ok(Vec::new());
    }
    let wrapper = scripts.into_iter().find(|script| {
        (crate::prime::read_option_file(script)).is_some_and(|text| {
            text.lines()
                .any(|line| line.contains("WRAPPER_LAUNCHER") && line.contains("MAVEN_CONFIG"))
        })
    });
    match (wrapper, read) {
        (None, _) => Ok(Vec::new()),
        (Some(_), Some(read)) if read.line == CommandLine::default() => Ok(read.selection),
        (Some(script), _) => Err(refuse(format!(
            "it holds options that {} passes to Maven and mvn does not, so raeva cannot tell \
             which the build reads; unset it, or pass them to both raeva and mvn",
            script.display()
        ))),
    }
}

const MAVEN_REPO_CENTRAL: &str = "maven.repo.central";
const MAVEN_REPO_CENTRAL_ENV: &str = "MAVEN_REPO_CENTRAL";

fn central_from_env(value: Option<std::ffi::OsString>) -> Result<Option<String>, ConfigError> {
    value
        .map(|value| {
            value.into_string().map_err(|_| ConfigError::Invalid {
                origin: ConfigOrigin::Env(MAVEN_REPO_CENTRAL_ENV),
                message: "the URL is not UTF-8 text".into(),
            })
        })
        .transpose()
}

/// Refuse a Central URL raeva cannot use or record, as for a configured
/// repository. The message names where the URL was set, never the URL.
/// Plain HTTP to a host that is not loopback is Maven's default HTTP
/// blocker's to refuse, request by request, unless a mirror serves it.
fn refuse_unusable_central(url: &str, origin: &ConfigOrigin) -> Result<(), ConfigError> {
    let entry = [("repository", Some("central"), url)];
    refuse_secret_urls(entry, origin)?;
    refuse_unusable_urls(entry, origin)?;
    if url.trim() == url {
        return Ok(());
    }
    Err(ConfigError::Invalid {
        origin: origin.clone(),
        message: format!("the {MAVEN_REPO_CENTRAL} URL has leading or trailing whitespace"),
    })
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
    /// How many of the defaults, at the end, come from the profiles
    /// `<activeProfiles>` names: settings.xml repositories still.
    requested: usize,
    profile_plugin_repositories: Vec<RepoConfig>,
    plugin_repositories: Vec<RepoConfig>,
    /// How many of `plugin_repositories` settings.xml names, before the
    /// defaults.
    named_plugin_repositories: usize,
    request_repositories: Vec<RepoConfig>,
    settings_endpoints: Vec<RepoConfig>,
    mirrors: Vec<MirrorConfig>,
    redirect_origins: Vec<String>,
    auth: Vec<AuthConfig>,
    auth_layers: AuthConfigLayers,
    server_ids: std::collections::BTreeSet<String>,
    basic_only_server_ids: std::collections::BTreeSet<String>,
    proxies: Vec<ProxyConfig>,
    proxy_error: Option<String>,
    active_profiles: Vec<String>,
    active_settings_profiles: Vec<String>,
    user_urls: Vec<String>,
    /// The first `<activation>` error of a settings.xml profile, which
    /// fails the build in Maven.
    activation_error: Option<String>,
    /// Why the first refused plugin repository of an active settings.xml
    /// profile cannot be used, which fails a sync only where `[plugins]`
    /// locks the plugins it serves.
    plugin_repository_error: Option<String>,
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
        mut settings: MavenSettings,
        host: &ModelEnvironment,
        platforms: &[ModelEnvironment],
        explicit_environments: &[ModelEnvironment],
        read: Option<&SettingsReads>,
    ) -> Self {
        let (project, user) = (&inputs.project, &inputs.user);
        // The explicit list seeds the active set; <activation> rules and
        // <activeByDefault> can extend it below.
        let explicit_active_profiles = explicit_active_profiles(inputs, &settings);

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
        let mut activation_error = None;
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
            let active = resolve_active_profiles(
                settings.profiles.as_deref(),
                inputs,
                &explicit_active_profiles,
                environment,
                &settings_file_context(inputs, &host.with_java_version_of(environment)),
                read,
            );
            let active = active.unwrap_or_else(|error| {
                activation_error.get_or_insert(error.to_string());
                Vec::new()
            });
            for id in active {
                if !active_settings_profiles.contains(&id) {
                    active_settings_profiles.push(id);
                }
            }
        }
        let profiles = || settings.profiles.iter().flatten();
        let active: Vec<&MavenProfile> = profiles()
            .filter(|profile| active_settings_profiles.contains(&profile.id))
            .collect();
        if let Some(refusal) = (active.iter())
            .find_map(|profile| Some((profile, profile.refused_repositories.first()?)))
            .map(|(profile, refusal)| {
                format!(
                    "in the active profile '{}', {refusal}",
                    rv_maven_types::bounded(&profile.id)
                )
            })
        {
            activation_error.get_or_insert(refusal);
        }
        let plugin_repository_error = (active.iter())
            .find_map(|profile| Some((profile, profile.refused_plugin_repositories.first()?)))
            .map(|(profile, refusal)| {
                format!(
                    "in the active profile '{}', {refusal}",
                    rv_maven_types::bounded(&profile.id)
                )
            });
        let named = (profiles()).filter(|profile| {
            (settings.active_profiles.iter().flatten()).any(|id| profile.id == *id)
        });
        if let Some(refusal) = model_repository_refusal(&active, named) {
            activation_error.get_or_insert(refusal);
        }
        // The project's model gives those it fills in.
        let settings_repositories: Vec<RepoConfig> =
            (injected(&active, |profile| &profile.repositories).into_iter())
                .filter(|repo| !active.iter().any(|profile| profile.fills_in(repo)))
                .collect();
        // Every repository of an active profile, those a shared id hides
        // included: on a configuration for several platforms, each may be
        // the one a platform reads.
        let settings_endpoints: Vec<RepoConfig> = (active.iter())
            .flat_map(|profile| {
                profile
                    .repositories
                    .iter()
                    .chain(&profile.plugin_repositories)
            })
            .cloned()
            .collect();
        let profile_plugin_repositories = injected(&active, |profile| &profile.plugin_repositories);
        let central = inputs.central.as_ref().map(|(url, _)| url.as_str());
        // Maven's request carries the repositories and plugin repositories
        // of the profiles <activeProfiles> names, in file order, the first
        // of an id kept, then Central unless one has its id; a project
        // searches them after its model's. A profile deactivated by id
        // keeps its entries here. `-P` and `active_profiles` add none.
        let named_profiles = || {
            profiles().filter(|profile| {
                let named = settings.active_profiles.iter().flatten();
                named.into_iter().any(|id| profile.id == *id)
            })
        };
        let named: Vec<RepoConfig> = named_profiles()
            .flat_map(|profile| profile.plugin_repositories.iter().cloned())
            .collect();
        let request_repositories: Vec<RepoConfig> = named_profiles()
            .flat_map(|profile| profile.repositories.iter().cloned())
            .collect();
        let requested: Vec<RepoConfig> = named_profiles()
            .flat_map(|profile| {
                let on = active_settings_profiles.contains(&profile.id);
                (profile.repositories.iter())
                    .filter(move |repo| !(on && profile.fills_in(repo)))
                    .cloned()
            })
            .collect();
        let mut plugin_repositories: Vec<RepoConfig> = Vec::new();
        let push = |list: &mut Vec<RepoConfig>, repo: RepoConfig| {
            if repo.id.is_none() || !list.iter().any(|known| known.id == repo.id) {
                list.push(repo);
            }
        };
        for repo in named.iter().cloned() {
            push(&mut plugin_repositories, repo);
        }
        let named_plugin_repositories = plugin_repositories.len();
        for repo in default_repositories(central) {
            push(&mut plugin_repositories, repo);
        }

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
        let user_local_repository = (user.local_repository.clone()).or(maven_local_repository
            .clone()
            .filter(|_| !inputs.project_settings));

        // Resolution searches the list in order, so the project layer comes
        // first, then the user's, then settings.xml. On a shared id the
        // earlier entry wins and the later one fills only its unset fields.
        let mut repositories = project.repositories.clone().unwrap_or_default();
        merge_repositories(&mut repositories, user.repositories.iter().flatten());
        merge_repositories(&mut repositories, &settings_repositories);
        // Mirror selection takes the first matching entry within a match
        // class, so the same precedence orders the mirrors. A project
        // raeva.toml has none. Maven's request keeps the first mirror of an
        // id; a config.toml mirror without one has none to share.
        let mut mirror_ids = BTreeSet::new();
        let mirrors: Vec<MirrorConfig> = (user.mirrors.iter().flatten().cloned())
            .chain(settings.mirrors.unwrap_or_default())
            .filter(|mirror| (mirror.id.as_ref()).is_none_or(|id| mirror_ids.insert(id.clone())))
            .collect();
        // A settings file the project chose names no endpoint of the user's.
        let user_settings = !inputs.project_settings;
        let mut user_urls: Vec<String> = (user.repositories.iter().flatten())
            .chain((settings_endpoints.iter().chain(&named)).filter(|_| user_settings))
            .map(|repo| repo.url.clone())
            .chain(
                (mirrors.iter())
                    .filter(|mirror| {
                        !mirror.mirrors_nothing()
                            && (user_settings
                                || (user.mirrors.iter().flatten()).any(|own| own == *mirror))
                    })
                    .map(|mirror| mirror.url.clone()),
            )
            .collect();
        // As Maven keeps the super POM's central after the POM and settings
        // profile repositories, the defaults follow the configured ones,
        // each unless a configured repository takes its id. A mirror of
        // central replaces it at resolution.
        let configured = repositories.len();
        // A Central URL from `.mvn/` is the project's choice, so it gets no
        // credential the user keeps for their own endpoints.
        let project_central = (inputs.central.as_ref()).is_some_and(|(_, origin)| {
            !matches!(origin, ConfigOrigin::CommandLine | ConfigOrigin::Env(_))
        });
        for default in default_repositories(central) {
            if !repositories.iter().any(|repo| repo.id == default.id) {
                if !(project_central && default.id.as_deref() == Some("central")) {
                    user_urls.push(default.url.clone());
                }
                repositories.push(default);
            }
        }
        let before_requested = repositories.len();
        for repo in requested {
            if !repositories.iter().any(|known| known.id == repo.id) {
                user_urls.push(repo.url.clone());
                repositories.push(repo);
            }
        }
        let defaults = repositories.len() - configured;
        let requested = repositories.len() - before_requested;

        let (mirrors, redirect_origins) = split_mirrors(mirrors);

        let server_ids = std::mem::take(&mut settings.server_ids);
        let basic_only_server_ids = std::mem::take(&mut settings.basic_only_server_ids);
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
        let mut proxy_error = None;
        if proxies.is_empty() {
            match &inputs.environment_proxies {
                Ok(environment) => proxies.clone_from(environment),
                Err((variable, message)) => proxy_error = Some(format!("{variable}: {message}")),
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
            requested,
            profile_plugin_repositories,
            plugin_repositories,
            named_plugin_repositories,
            request_repositories,
            settings_endpoints,
            mirrors,
            redirect_origins,
            auth,
            auth_layers,
            server_ids,
            basic_only_server_ids,
            proxies,
            proxy_error,
            active_profiles: explicit_active_profiles
                .into_iter()
                .filter(|id| !deactivated(id))
                .collect(),
            active_settings_profiles,
            user_urls,
            activation_error,
            plugin_repository_error,
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
    /// `.mvn/jvm.config` as read, whose `-D` options set system properties.
    jvm_config: Option<String>,
    /// The system properties `mvn`'s JVM takes from `.mvn/jvm.config` and
    /// the option files it names.
    jvm_config_properties: BTreeMap<String, String>,
    /// The JVM option channel that sets each system property, such as
    /// `MAVEN_OPTS`.
    jvm_channels: HashMap<String, &'static str>,
    /// The names of [`Config::jvm_option_properties`] the project's files
    /// hold, found once, and why it took them all when it could
    /// not read the project's files.
    pom_reads: Arc<std::sync::OnceLock<(BTreeSet<String>, Option<String>)>>,
    command_line: CommandLine,
    /// A reactor selection option of `MAVEN_ARGS`, a `MAVEN_CONFIG` a
    /// wrapper script passes or `.mvn/maven.config`, with where it was given.
    reactor_selection: Option<(ConfigOrigin, &'static str)>,
    project_root: PathBuf,
    /// The proxies `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` give, or the
    /// variable and why raeva cannot use it.
    environment_proxies: Result<Vec<ProxyConfig>, (&'static str, String)>,
    /// In the Maven 3.10 mode, the `maven.repo.central` URL that replaces
    /// Maven Central's, with where it was set.
    central: Option<(String, ConfigOrigin)>,
    /// Maven's user home ([`crate::paths::maven_user_home`]).
    user_home: Option<PathBuf>,
    /// Whether the settings file is one `.mvn/maven.config` names with `-s`:
    /// the project's choice, so its endpoints get no credential the user
    /// keeps for their own and it does not choose where `export-m2` writes.
    project_settings: bool,
}

impl Default for ConfigInputs {
    fn default() -> Self {
        Self {
            project: ConfigFile::default(),
            user: ConfigFile::default(),
            inactive_profiles: Vec::new(),
            maven_config: None,
            jvm_config: None,
            jvm_config_properties: BTreeMap::new(),
            jvm_channels: HashMap::new(),
            pom_reads: Arc::default(),
            command_line: CommandLine::default(),
            reactor_selection: None,
            project_root: PathBuf::new(),
            environment_proxies: Ok(Vec::new()),
            central: None,
            user_home: crate::paths::jvm_user_home(crate::paths::LauncherJdk::default())
                .ok()
                .flatten(),
            project_settings: false,
        }
    }
}

impl ConfigInputs {
    /// The ids `active_profiles` adds as `-P` does, from `raeva.toml` or
    /// else `config.toml`.
    fn added_active_profiles(&self) -> &[String] {
        (self.project.active_profiles.as_deref())
            .or(self.user.active_profiles.as_deref())
            .unwrap_or_default()
    }

    /// Maven 3.10's request-level Central URL: the `maven.repo.central`
    /// user property, else the system property, which `MAVEN_REPO_CENTRAL`
    /// sets over a `.mvn/jvm.config` value, with where it was set.
    fn central(
        &self,
        environment: &ModelEnvironment,
        system: Option<ConfigOrigin>,
        maven_config_path: &Path,
    ) -> Option<(String, ConfigOrigin)> {
        if let Some(found) = self.user_property(environment, MAVEN_REPO_CENTRAL, maven_config_path)
        {
            return Some(found);
        }
        let url = environment.system_properties().get(MAVEN_REPO_CENTRAL)?;
        Some((url.clone(), system?))
    }

    /// The `-D` user property `name` of the command line, else of
    /// `.mvn/maven.config`, with where it was set.
    fn user_property(
        &self,
        environment: &ModelEnvironment,
        name: &str,
        maven_config_path: &Path,
    ) -> Option<(String, ConfigOrigin)> {
        let value = (self.maven_options(environment).properties).remove(name)?;
        let command_line = crate::maven_config::parse_for(
            None,
            &self.command_line,
            environment,
            &self.project_root,
        )
        .is_ok_and(|options| options.properties.contains_key(name));
        let origin = if command_line {
            ConfigOrigin::CommandLine
        } else {
            ConfigOrigin::MavenConfig(maven_config_path.to_path_buf())
        };
        Some((value, origin))
    }

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

/// The text of the `<os>`, `<property>`, `<jdk>` and `<file>` conditions
/// of a settings.xml profile's `<activation>`, as written, when one holds a
/// `${...}`, with the
/// platform and target JDK of `environment`. Settings interpolation expands
/// an `${env.*}`, a `-D` value or `user.home` there before activation reads
/// the text, and neither the platform nor the host values the lock records
/// decide it, so the lock records whether the profile activates on each
/// platform, keyed by this text; [`settings_activation_holds`] decides it.
/// Text with no `${...}` reads only the platform, and the
/// [`settings_conditions`] keys cover the other kinds.
fn settings_expansion(profile: &MavenProfile, environment: &ModelEnvironment) -> Option<String> {
    let written = profile.written_activation.as_ref()?;
    let (os, arch) = environment.platform()?;
    let shown = |kind: &str, texts: &[(&str, &Option<String>)]| {
        let read =
            (texts.iter()).any(|(_, text)| text.as_deref().is_some_and(|text| text.contains("${")));
        read.then(|| {
            let texts = (texts.iter())
                .filter_map(|(name, text)| Some(format!("{name}={}", text.as_deref()?)));
            format!("{kind}:{}", texts.collect::<Vec<_>>().join(","))
        })
    };
    let os_text = written.os.as_ref().and_then(|written| {
        shown(
            "os",
            &[
                ("name", &written.name),
                ("family", &written.family),
                ("arch", &written.arch),
                ("version", &written.version),
            ],
        )
    });
    let property_text = (written.property.as_ref()).and_then(|written| {
        shown(
            "property",
            &[("name", &written.name), ("value", &written.value)],
        )
    });
    let jdk_text = shown("jdk", &[("jdk", &written.jdk)]);
    let file_text = (written.file.as_ref()).and_then(|written| {
        shown(
            "file",
            &[("exists", &written.exists), ("missing", &written.missing)],
        )
    });
    let conditions: Vec<String> = (os_text.into_iter())
        .chain(property_text)
        .chain(jdk_text)
        .chain(file_text)
        .collect();
    if conditions.is_empty() {
        return None;
    }
    let jdk = (environment.target_jdk()).map_or_else(String::new, |jdk| format!(" (JDK {jdk})"));
    Some(format!("{} on {os}-{arch}{jdk}", conditions.join("; ")))
}

/// Whether the `<activation>` of the settings.xml profile `profile` holds
/// on the platform of `environment`, as [`resolve_active_profiles`] tests
/// it on a `host`.
fn settings_activation_holds(
    profile: &MavenProfile,
    inputs: &ConfigInputs,
    host: &ModelEnvironment,
    environment: &ModelEnvironment,
) -> Option<bool> {
    let activation = profile.activation.as_ref()?;
    let ctx = settings_activation_context(inputs, environment, inputs.maven_options(environment));
    let file_ctx = settings_file_context(inputs, &host.with_java_version_of(environment));
    let tested = (activation.clone())
        .with_external_file(&file_ctx)
        .with_host_properties(&ctx);
    let (matched, _) = tested.evaluate(&profile.id, &ctx).ok()?;
    Some(matched)
}

/// Refuse a `-D` value that takes `maven.version` or `maven.build.version`
/// while a JVM option, `system` with each name's channel in `channels`,
/// sets it and no `-D` does: `MavenCli` expands the `-D` values with the
/// JVM's value and only then sets its own, which raeva, holding one value
/// of each, does not follow.
fn refuse_jvm_version_reads(
    system: &HashMap<String, String>,
    channels: &HashMap<String, &'static str>,
    command_line: &CommandLine,
) -> Result<(), ConfigError> {
    let defines: Vec<(&str, &str)> = (command_line.defines.iter())
        .map(|define| crate::maven_config::define_property(define))
        .collect();
    let jvm: Vec<(&str, &str)> = (system.iter())
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    for name in ["maven.version", "maven.build.version"] {
        let set = jvm.iter().any(|(set, _)| *set == name);
        if !set || defines.iter().any(|(defined, _)| *defined == name) {
            continue;
        }
        // Through other `.mvn/jvm.config` values too, which a `-D` value
        // expands.
        let mut readers = vec![name];
        while let Some(reader) = (jvm.iter())
            .filter(|(property, _)| !readers.contains(property))
            .find(|(_, value)| {
                readers
                    .iter()
                    .any(|read| value.contains(&format!("${{{read}}}")))
            })
            .map(|(property, _)| *property)
        {
            readers.push(reader);
        }
        let reads = |value: &str| {
            (readers.iter())
                .find(|read| value.contains(&format!("${{{read}}}")))
                .copied()
        };
        if let Some((define, read)) =
            (defines.iter()).find_map(|(define, value)| Some((*define, reads(value)?)))
        {
            let through = match read == name {
                true => String::new(),
                false => format!(" through ${{{read}}}"),
            };
            let channel = channels
                .get(name)
                .copied()
                .unwrap_or(crate::jvm_options::JVM_CONFIG);
            return Err(ConfigError::UnreadHostProperty(format!(
                "the -D{define} value takes ${{{name}}}{through}, which {channel} sets: \
                 Maven expands -D values with that value and then sets its own {name}, which \
                 raeva does not follow; write the value out, or set -D{name}"
            )));
        }
    }
    Ok(())
}

/// What settings.xml profile activation reads on the platform of
/// `environment`: every environment variable, the project root, and the
/// `-D` values of `.mvn/maven.config` and the command line.
fn settings_activation_context(
    inputs: &ConfigInputs,
    environment: &ModelEnvironment,
    options: crate::maven_config::MavenConfigOptions,
) -> ActivationContext {
    let mut ctx = ActivationContext::new(environment.with_all_env());
    ctx.base_dir = Some(inputs.project_root.clone());
    ctx.properties = options.properties;
    ctx.expanded_properties = options.expanded_properties;
    ctx
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
    /// The `[plugins]` settings of the project's raeva.toml, when they lock
    /// the plugins.
    pub plugins: Option<crate::PluginsConfig>,
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
    repository_filters: Arc<RepositoryFilters>,
    credential_scope: Option<Arc<CredentialScope>>,
    /// Where the Maven 3.10 `maven.repo.central` system property was set.
    central_system: Option<ConfigOrigin>,
    /// The first error a platform of [`Config::for_platforms`] fails with
    /// where its `.mvn/maven.config` options differ from the host's.
    platform_error: Option<(ConfigOrigin, String)>,
    /// The host's values, where [`Config::for_platforms`] replaced them.
    host_session: Option<PlatformSession>,
    /// [`Config::portable`] keeps the host's directories as they are.
    host_paths: bool,
}

/// What [`Config::for_platforms`] reads again for a platform whose
/// `.mvn/maven.config` options differ from the host's.
#[derive(Clone)]
struct PlatformSession {
    central: Option<(String, ConfigOrigin)>,
    credential_scope: Option<Arc<CredentialScope>>,
    repository_filters: Arc<RepositoryFilters>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("network", &self.network)
            .field("lock", &self.lock)
            .field("plugins", &self.plugins)
            .field("inactive_profiles", &self.inactive_profiles)
            .field("security", &self.security)
            .field("paths", &self.paths)
            .field("project_root", &self.project_root)
            .field("project_config_path", &self.project_config_path)
            .field("user_config_path", &self.user_config_path)
            .field("lock_path", &self.lock_path)
            .field("maven_data", &self.maven_data)
            .field("repository_filters", &self.repository_filters)
            .finish()
    }
}

/// The profile ids `<activeProfiles>` names, then those `active_profiles`
/// adds as `-P` does, from `raeva.toml` or else `config.toml`.
/// Why raeva does not answer the settings.xml repositories each project
/// fills in, which Maven fills once for the whole build and orders among
/// the others by profile: one that shares its id with another active
/// profile's repository, any beside a literal one, or a `<layout>` that
/// holds a `${...}` in a profile `<activeProfiles>` names, active or not.
/// [`Config::settings_model_repository_ids`] gives those the projects must
/// fill in alike.
fn model_repository_refusal<'a>(
    active: &[&MavenProfile],
    named: impl Iterator<Item = &'a MavenProfile>,
) -> Option<String> {
    for profile in named {
        if let Some(refusal) = profile.expression_layouts.first() {
            let id = rv_maven_types::bounded(&profile.id);
            return Some(format!(
                "in the profile '{id}' that <activeProfiles> names, {refusal}"
            ));
        }
    }
    let declared = || active.iter().flat_map(|profile| &profile.repositories);
    for profile in active {
        for model in &profile.model_repositories {
            let id = rv_maven_types::bounded(model.id.as_deref().unwrap_or_default());
            let entry = format!(
                "in the active profile '{}', the <url> of repository '{id}' still holds a \
                 ${{...}} once settings.xml is interpolated, which Maven fills in once for the \
                 whole build",
                rv_maven_types::bounded(&profile.id)
            );
            if declared().filter(|repo| repo.id == model.id).count() > 1 {
                return Some(format!(
                    "{entry}, and another repository of an active profile has its id; raeva \
                     does not follow which of them Maven reads"
                ));
            }
            let literal = active.iter().find_map(|other| {
                let repo = (other.repositories.iter()).find(|repo| !other.fills_in(repo))?;
                Some((other, repo))
            });
            if let Some((other, repo)) = literal {
                return Some(format!(
                    "{entry}, and the active profile '{}' declares the literal repository '{}'; \
                     raeva does not follow Maven's order between them",
                    rv_maven_types::bounded(&other.id),
                    rv_maven_types::bounded(repo.id.as_deref().unwrap_or_default())
                ));
            }
        }
    }
    None
}

fn explicit_active_profiles(inputs: &ConfigInputs, settings: &MavenSettings) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for id in (settings.active_profiles.iter().flatten()).chain(inputs.added_active_profiles()) {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    ids
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
fn settings_activation(
    path: Option<&PathBuf>,
    data: &MavenSettingsData,
    plugins: bool,
) -> Result<(), ConfigError> {
    let plugin_error = data.plugin_repository_error.as_ref().filter(|_| plugins);
    match (path, data.activation_error.as_ref().or(plugin_error)) {
        (Some(path), Some(message)) => Err(ConfigError::Invalid {
            origin: ConfigOrigin::MavenSettings(path.clone()),
            message: message.clone(),
        }),
        _ => Ok(()),
    }
}

fn resolve_active_profiles(
    profiles: Option<&[MavenProfile]>,
    inputs: &ConfigInputs,
    explicit_active_profiles: &[String],
    environment: &ModelEnvironment,
    file_ctx: &ActivationContext,
    read: Option<&SettingsReads>,
) -> Result<Vec<String>, rv_maven_model::PomError> {
    let (mut active, options) =
        explicit_settings_profiles(inputs, explicit_active_profiles, environment);
    let inactive = |id: &str| {
        (inputs.inactive_profiles.iter())
            .chain(&options.inactive_profiles)
            .any(|inactive| inactive == id)
    };
    let Some(profiles) = profiles else {
        return Ok(active);
    };

    let ctx = settings_activation_context(inputs, environment, options.clone());
    let explicit = active.clone();
    for profile in profiles {
        let id = profile.id.as_str();
        let Some(activation) = profile.activation.as_ref() else {
            continue;
        };
        if inactive(id) || explicit.iter().any(|a| a == id) {
            continue;
        }
        let expanded = (activation.clone())
            .with_external_file(file_ctx)
            .with_host_properties(&ctx);
        // Maven tests the conditions of an `activeByDefault` profile too, and
        // fails on an error there.
        let (matched, reads) = expanded.evaluate(id, &ctx)?;
        let inert = profile.properties.is_empty()
            && profile.repositories.is_empty()
            && profile.plugin_repositories.is_empty();
        if !activation.active_by_default
            && !inert
            && let Some(name) = expanded.unread_host_property(&ctx)
        {
            return Err(rv_maven_model::PomError::Unlockable(format!(
                "the activation of settings.xml profile {} depends on {name}, which raeva does \
                 not read from the host or which differs across the hosts the lock covers; {}",
                rv_maven_types::bounded(id),
                rv_maven_model::unread_property_fix(&name, &ctx.environment),
            )));
        }
        if activation.active_by_default {
            if !active.iter().any(|a| a == id) {
                active.push(id.to_string());
            }
            continue;
        }
        for input in &reads {
            match input {
                rv_maven_model::HostInput::UserProperty(name) => {
                    environment.record_user_property(name);
                }
                rv_maven_model::HostInput::UserOverride(name) => {
                    environment.record_user_override(name);
                }
                _ => {}
            }
        }
        // A profile's properties are recorded by name when a model reads them.
        if let Some(read) = read
            && !(profile.repositories.is_empty() && profile.plugin_repositories.is_empty())
        {
            let mut read = read.lock().unwrap_or_else(|poison| poison.into_inner());
            for (text, input) in settings_conditions(profile, file_ctx) {
                if reads.contains(&input) {
                    read.insert(settings_key(&text));
                }
            }
            if let Some(text) = settings_expansion(profile, environment) {
                read.insert(settings_key(&text));
            }
        }
        if matched && !active.iter().any(|a| a == id) {
            active.push(id.to_string());
        }
    }

    Ok(active)
}

/// A property value the lock hash covers. A POM property ranks below a `-D`
/// and above `.mvn/jvm.config`, so the same text from each can resolve
/// differently and hashes differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyInput {
    /// Set by anything but `.mvn/jvm.config`: a `-D` on the command line or
    /// in `.mvn/maven.config`, settings.xml, the environment or the platform.
    Value(String),
    /// Set only by `.mvn/jvm.config`.
    JvmConfig(String),
}

impl serde::Serialize for PropertyInput {
    // A value encodes as a plain string, as before jvm.config was read, so
    // the hashes of locks without one are unchanged.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Self::Value(value) => serializer.serialize_str(value),
            Self::JvmConfig(value) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(".mvn/jvm.config", value)?;
                map.end()
            }
        }
    }
}

/// One user property's [`PropertyInput`] on each target a lock covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyInputs(Vec<Option<PropertyInput>>);

impl PropertyInputs {
    /// Whether some target sets it.
    pub fn is_set(&self) -> bool {
        self.0.iter().any(Option::is_some)
    }

    /// Whether a `-D` on the command line or in `.mvn/maven.config` sets it
    /// on some target.
    pub fn defined(&self) -> bool {
        (self.0.iter()).any(|input| matches!(input, Some(PropertyInput::Value(_))))
    }

    /// What the lock hash covers, `None` when no target sets it.
    pub fn hash_value(&self) -> Option<String> {
        self.is_set()
            .then(|| serde_json::to_string(&self.0).expect("property inputs serialize"))
    }
}

fn encode_target_values(values: Vec<Option<String>>) -> Option<String> {
    values
        .iter()
        .any(Option::is_some)
        .then(|| serde_json::to_string(&values).expect("property values serialize"))
}

/// Inputs, each with how a message names it.
type Labelled = Vec<(String, String)>;

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
    /// `~/.m2/settings.xml`, or else one `.mvn/maven.config` names.
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
    /// profiles then ignore that file. A Maven wrapper that selects no line
    /// raeva knows leaves the line at 3.9.
    ///
    /// # Errors
    ///
    /// As [`Self::load_with_command_line`], apart from `.mvn/maven.config`
    /// and the Maven wrapper.
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
        // The variables as `mvn` holds them once it has sourced the mavenrc
        // files, which everything below reads.
        let shell = crate::user_home::Shell::capture(project_root)
            .map_err(|error| ConfigError::UnreadHostProperty(error.to_string()))?;
        // Before anything can fail with a message, as raeva's own first
        // pass does for its command line.
        crate::prime::prime_project(project_root, &command_line.defines, &shell);

        let paths = ResolvedPaths::discover()?;
        let project_config_path = project_root.join("raeva.toml");
        let lock_path = project_root.join("raeva.lock");
        let user_config_path = paths.config_file_path();
        let origins = (
            ConfigOrigin::ProjectConfig(project_config_path.clone()),
            ConfigOrigin::UserConfig(user_config_path.clone()),
        );
        let mut project = ConfigFile::load(&project_config_path, origins.0.clone())?;
        let mut user = ConfigFile::load(&user_config_path, origins.1.clone())?;
        let network = merge_network(project.network.take(), user.network.take(), &origins)?;
        let mvn_dir = launcher_mvn_dir(project_root, &shell)?;
        let lock = merge_lock(
            project.lock.take(),
            user.lock.take(),
            &origins,
            project_root,
            &mvn_dir,
            strict_maven_config,
        )?;
        let plugins =
            crate::plugins::merge_plugins(project.plugins.take(), user.plugins.take(), &origins)?;
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
        // As the module directories are, which the root directory search
        // compares with it.
        let reactor_root = std::fs::canonicalize(project_root).map_or_else(
            |_| project_root.to_path_buf(),
            |root| rv_fs::plain_path(&root),
        );
        let host = HostSnapshot::capture_after(&shell, &security.allow_env_substitution)
            .with_reactor_root(&reactor_root)
            .with_project_directory(project_root)
            .with_maven_mode(lock.maven.mode)
            .with_locked_jdks(&lock.jdks);
        let maven_310 = lock.maven.mode == MavenMode::Maven310;
        let jvm_config_path = mvn_dir.join("jvm.config");
        let launcher = host.host_environment();
        let jvm_config = crate::read_optional_project_input_string(&jvm_config_path)?;
        crate::jvm_options::record_option_file(
            ".mvn/jvm.config",
            &jvm_config_path,
            jvm_config.as_deref().map(str::as_bytes),
        );
        let jvm_config = jvm_config
            .map(|text| {
                let root = launcher.launcher_root();
                crate::maven_config::launcher_jvm_config(&text, root, lock.maven.mode).map_err(
                    |why| {
                        ConfigError::UnreadHostProperty(format!(
                            "{} {why}, so raeva cannot tell what mvn's JVM takes from it",
                            jvm_config_path.display()
                        ))
                    },
                )
            })
            .transpose()?;
        // The JDK `mvn` runs.
        let jdk = match host.jdk_release() {
            Some(release) => {
                crate::paths::LauncherJdk::of(release.version.as_deref(), release.openj9)
            }
            _ => crate::paths::LauncherJdk::default(),
        };
        let working_dir = std::env::current_dir().unwrap_or_else(|_| project_root.to_path_buf());
        let user_home_host = crate::user_home::Host {
            shell,
            jdk,
            working_dir: &working_dir,
        };
        let mut jvm_options = crate::jvm_options::read(jvm_config.as_deref(), &user_home_host)?;
        jvm_options.refuse_jdk_dependent(&lock.jdks)?;
        jvm_options.register_unread();
        // `user.home` has a reader of its own; the models read the value
        // the JVM takes last only where `.mvn/jvm.config` gives it, as one
        // from the host's channels differs by host.
        let jvm_config_home = (jvm_options.define(USER_HOME))
            .filter(|define| define.channel == crate::jvm_options::JVM_CONFIG)
            .filter(|_| jvm_options.unread(USER_HOME).is_none())
            .and_then(|define| String::from_utf8(define.value.clone()).ok());
        let jvm_values: HashMap<String, String> = (jvm_options.properties())
            .filter(|(name, _, _)| *name != USER_HOME)
            .map(|(name, value, _)| (name.to_string(), value.to_string()))
            .collect();
        let jvm_channels: HashMap<String, &'static str> = (jvm_options.properties())
            .map(|(name, _, channel)| (name.to_string(), channel))
            .collect();
        let jvm_config_properties = (jvm_options.jvm_config().iter())
            .filter(|(name, _)| !rv_maven_model::fixed_over_jvm_config(name, lock.maven.mode))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let mut system_properties: HashMap<String, String> = (jvm_values.iter())
            .filter(|(name, _)| !rv_maven_model::fixed_over_jvm_config(name, lock.maven.mode))
            .map(|(name, value)| (name.clone(), value.clone()))
            .chain(jvm_config_home.map(|home| (USER_HOME.to_string(), home)))
            .collect();
        let jvm_defines: Vec<String> = system_properties.keys().cloned().collect();
        let central_env = if maven_310 {
            central_from_env(
                (user_home_host.shell.exported(MAVEN_REPO_CENTRAL_ENV))
                    .map(rv_maven_model::mavenrc::os_string),
            )?
        } else {
            None
        };
        if let Some(url) = &central_env {
            refuse_unusable_central(url, &ConfigOrigin::Env(MAVEN_REPO_CENTRAL_ENV))?;
        }
        let central_system = match central_env {
            Some(url) => {
                system_properties.insert(MAVEN_REPO_CENTRAL.to_string(), url);
                Some(ConfigOrigin::Env(MAVEN_REPO_CENTRAL_ENV))
            }
            None => (maven_310 && system_properties.contains_key(MAVEN_REPO_CENTRAL)).then(|| {
                match jvm_channels.get(MAVEN_REPO_CENTRAL) {
                    Some(&channel) if channel != crate::jvm_options::JVM_CONFIG => {
                        ConfigOrigin::Env(channel)
                    }
                    _ => ConfigOrigin::MavenConfig(jvm_config_path.clone()),
                }
            }),
        };
        let unread_properties: Vec<String> = (jvm_options.unread_names())
            .filter(|name| *name != USER_HOME)
            .map(str::to_string)
            .collect();
        let host = host
            .with_system_properties(system_properties)
            .with_unread_system_properties(unread_properties);
        // settings.xml profiles follow its -P and -D, so a file Maven would
        // refuse fails here, before any repository is used.
        let maven_config_path = mvn_dir.join("maven.config");
        let environment = host.host_environment();
        // `mvn` puts `MAVEN_ARGS`, as the mavenrc files leave it, before the
        // arguments of its command line.
        let maven_args = user_home_host.shell.shell_value("MAVEN_ARGS");
        // `mvn` splits it at `IFS`.
        if maven_args.as_ref().is_some_and(|args| !args.is_empty()) {
            crate::user_home::refuse_changed_ifs(&user_home_host.shell)?;
        }
        let maven_args = (maven_args.as_deref())
            .map(|args| {
                (std::str::from_utf8(args).map_err(|_| "is not UTF-8 text".to_string()))
                    .and_then(crate::maven_config::maven_args)
            })
            .transpose()
            .map_err(|refusal| ConfigError::Invalid {
                origin: ConfigOrigin::Env("MAVEN_ARGS"),
                message: format!(
                    "it {refusal}, which raeva cannot read as mvn does; pass the option to both \
                     raeva and mvn, or put it in .mvn/maven.config"
                ),
            })?
            .unwrap_or_default();
        for option in &maven_args.selection {
            tracing::warn!(
                sec_code = "SETTING_IGNORED",
                "ignoring {option} in MAVEN_ARGS; raeva locks the whole reactor, whatever \
                 projects a build selects, so a module this build skips can still fail the sync"
            );
        }
        let mut reactor_selection =
            (maven_args.selection.first()).map(|option| (ConfigOrigin::Env("MAVEN_ARGS"), *option));
        let maven_args = maven_args.line;
        let traced = (plugins.as_ref().and_then(|plugins| plugins.trace.as_ref()))
            .and_then(|trace| trace.launcher(project_root).ok())
            .filter(|launcher| launcher.is_absolute());
        let scripts = ([
            Some(project_root),
            environment.launcher_root().map(Path::new),
        ]
        .into_iter())
        .flatten()
        .flat_map(|dir| [dir.join("mvnw"), dir.join("mvnw.cmd")])
        .chain(traced);
        for option in refuse_wrapper_maven_config(&user_home_host.shell, scripts)? {
            tracing::warn!(
                sec_code = "SETTING_IGNORED",
                "ignoring {option} in MAVEN_CONFIG; raeva locks the whole reactor, whatever \
                 projects a build selects, so a module this build skips can still fail the sync"
            );
            reactor_selection.get_or_insert((ConfigOrigin::Env("MAVEN_CONFIG"), option));
        }
        let command_line = &CommandLine {
            defines: (maven_args.defines.into_iter())
                .chain(command_line.defines.iter().cloned())
                .collect(),
            profiles: (maven_args.profiles.into_iter())
                .chain(command_line.profiles.iter().cloned())
                .collect(),
            // Maven reads the first `-s`.
            settings: (maven_args.settings.into_iter())
                .chain(command_line.settings.iter().cloned())
                .collect(),
        };
        let file_error = |message: String| ConfigError::Invalid {
            origin: ConfigOrigin::MavenConfig(maven_config_path.clone()),
            message,
        };
        let read_maven_config = || {
            let content = crate::read_optional_project_input_string(&maven_config_path)?;
            crate::jvm_options::record_option_file(
                ".mvn/maven.config",
                &maven_config_path,
                content.as_deref().map(str::as_bytes),
            );
            if let Some(text) = &content {
                let ignored = crate::maven_config::ignored_options(text)
                    .map_err(|error| file_error(error.to_string()))?;
                for option in ignored {
                    tracing::warn!(
                        sec_code = "SETTING_IGNORED",
                        "ignoring {option} in {}; raeva locks the whole reactor, whatever \
                         projects a build selects, so a module this build skips can still fail \
                         the sync",
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
        if reactor_selection.is_none()
            && let Some(Ok(selection)) =
                (maven_config.as_deref()).map(crate::maven_config::ignored_options)
            && let Some(option) = selection.first()
        {
            reactor_selection = Some((
                ConfigOrigin::MavenConfig(maven_config_path.clone()),
                *option,
            ));
        }
        refuse_jvm_version_reads(
            &jvm_values,
            &jvm_channels,
            &crate::maven_config::with_maven_config(maven_config.as_deref(), command_line),
        )?;
        // Maven expands the values once the command line is merged in, so a
        // command-line -D can mend a value of the file.
        let merged = |content: Option<&str>, command_line: &CommandLine| {
            let user_home = crate::user_home::user_home_define(
                &jvm_options,
                &crate::maven_config::with_maven_config(content, command_line),
                command_line,
            )?;
            let path = crate::maven_config::settings_file(
                content,
                command_line,
                &environment,
                project_root,
                crate::paths::maven_user_home(user_home.as_deref(), jdk)?.as_deref(),
            )
            .map_err(|error| match error {
                crate::maven_config::MavenConfigError::UnreadHostProperty(..) => {
                    ConfigError::UnreadHostProperty(error.to_string())
                }
                error => ConfigError::Invalid {
                    origin: ConfigOrigin::CommandLine,
                    message: error.to_string(),
                },
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
        let define = crate::user_home::user_home_define(
            &jvm_options,
            &crate::maven_config::with_maven_config(maven_config.as_deref(), command_line),
            command_line,
        )?;
        // The variables the JVM takes its own `user.home` from.
        let platform_home = (cfg!(target_os = "macos").then_some(crate::paths::CF_FIXED_USER_HOME))
            .into_iter()
            .chain(crate::paths::jvm_reads_home(jdk).then_some("HOME"));
        for name in platform_home.filter(|_| define.is_none()) {
            if let Some(file) = user_home_host.shell.changing(name) {
                return Err(crate::user_home::mavenrc_changes(&file, name));
            }
        }
        let user_home = crate::paths::maven_user_home(define.as_deref(), jdk)?;
        // A `-s` neither the command line nor `MAVEN_ARGS` gave is
        // `.mvn/maven.config`'s.
        let project_settings = settings.is_some() && command_line.settings.is_empty();
        let settings_path = settings
            .or_else(|| (user_home.as_ref()).map(|home| home.join(".m2").join("settings.xml")));
        // Maven reads the settings.xml of a `user.home` with an expression
        // as written, and then expands the expression again where the
        // settings take `${user.home}`.
        if let Some(define) = define.as_deref().filter(|define| define.contains("${"))
            && let Some(path) = settings_path.as_deref().filter(|path| {
                (crate::limited_read::read_capped(path, crate::MAX_PROJECT_INPUT_SIZE).ok())
                    .is_some_and(|text| text.windows(9).any(|w| w == b"user.home"))
            })
        {
            return Err(ConfigError::UnreadHostProperty(format!(
                "-Duser.home={} takes an expression, which Maven expands again where {} takes \
                 ${{user.home}}, and raeva does not; write the directory out",
                rv_maven_types::bounded(define),
                path.display()
            )));
        }
        crate::paths::refuse_unread_encoding(
            (user_home.iter().chain(&settings_path)).map(PathBuf::as_path),
            &user_home_host.shell,
        )?;
        let mut inputs = ConfigInputs {
            project,
            user,
            inactive_profiles: inactive_profiles.clone(),
            maven_config,
            jvm_config,
            jvm_config_properties,
            jvm_channels,
            pom_reads: Arc::default(),
            command_line: command_line.clone(),
            reactor_selection,
            project_root: project_root.to_path_buf(),
            environment_proxies: crate::environment_proxies(|name| std::env::var(name).ok()),
            central: None,
            user_home,
            project_settings,
        };
        if maven_310 {
            inputs.central =
                inputs.central(&environment, central_system.clone(), &maven_config_path);
            if let Some((url, origin)) = &inputs.central {
                refuse_unusable_central(url, origin)?;
            }
        }

        // A present-but-malformed settings.xml (bad XML, oversize, DOCTYPE,
        // unsupported encoding) must abort like Maven does, NOT silently fall back to
        // defaults. Falling back would drop the user's mirrors, server
        // credentials, and proxies and could send unauthenticated fetches to
        // an unexpected public host. An absent settings.xml is fine
        // (`load_optional` returns `Ok(default)` for a missing file).
        // Maven's settings builder takes the user properties `MavenCli`
        // reads from `.mvn/maven.config` and the command line.
        let defines = crate::maven_config::parse_for(
            inputs.maven_config.as_deref(),
            &inputs.command_line,
            &environment.detached(),
            &inputs.project_root,
        );
        let defines = defines.unwrap_or_default();
        // settings.xml takes a value of the host's platform, which another
        // locked platform does not share, as written.
        let mut properties = defines.properties;
        properties.extend(defines.platform_values);
        let mut settings_inputs =
            crate::maven_settings::SettingsInputs::new(lock.maven.mode, properties);
        settings_inputs.user_home = (inputs.user_home.as_deref())
            .and_then(Path::to_str)
            .map(str::to_string);
        settings_inputs.secret_properties = defines.secret_inputs;
        settings_inputs.host = environment.detached();
        settings_inputs.launcher_root = environment.launcher_root().map(str::to_string);
        settings_inputs.settings_security = crate::maven_config::parse_for(
            None,
            &inputs.command_line,
            &environment.detached(),
            &inputs.project_root,
        )
        .ok()
        .and_then(|defines| defines.properties.get("settings.security").cloned());
        settings_inputs.project_defines = (jvm_defines.into_iter())
            .filter(|name| rv_maven_model::jvm_owned(name))
            .collect();
        settings_inputs.mirror_ids = (inputs.user.mirrors.iter().flatten())
            .filter_map(|mirror| mirror.id.clone())
            .collect();
        if let Some(path) = &settings_path {
            // The settings file this load reads, wherever `-s` named it, with
            // the JVM's system properties a credential may take a part of.
            let properties: Vec<String> = (jvm_options.properties())
                .map(|(name, value, _)| format!("{name}={value}"))
                .chain(command_line.defines.iter().cloned())
                .collect();
            crate::prime::prime_settings(
                Vec::new(),
                &properties,
                std::slice::from_ref(path),
                &user_home_host.shell,
            );
        }
        let mut settings = match &settings_path {
            Some(path) => MavenSettings::load_optional(path, &settings_inputs).map_err(|err| {
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
                    .flat_map(|profile| {
                        let plugin = (profile.plugin_repositories.iter())
                            .map(|repo| ("plugin repository", repo));
                        (profile.repositories.iter().map(|repo| ("repository", repo))).chain(plugin)
                    })
                    .map(|(kind, repo)| (kind, repo.id.as_deref(), repo.url.as_str()))
                    .chain(repository_urls(None, settings.mirrors.as_ref())),
                &ConfigOrigin::MavenSettings(path),
            )?;
        }
        crate::file_transport::read_directories(&mut settings, lock.maven.mode, &reactor_root);
        let initial_environment = host.host_environment().detached();
        let maven_data = MavenSettingsData::merge(
            &inputs,
            settings.clone(),
            &initial_environment,
            std::slice::from_ref(&initial_environment),
            &[],
            None,
        );
        settings_activation(settings_path.as_ref(), &maven_data, plugins.is_some())?;
        // Neither a refusal nor where a credential goes is in the lock, so
        // what they read is no lock input.
        let session_environment = environment.detached();
        let session = SessionProperties {
            inputs: &inputs,
            environment: &session_environment,
            profiles: requested_profile_properties(
                &inputs,
                &settings,
                &inputs.maven_options(&session_environment),
                lock.maven.mode,
            ),
            jvm_config_path: &jvm_config_path,
            maven_config_path: &maven_config_path,
            settings_path: settings_path.as_ref(),
        };
        refuse_unread_session_properties(&session, lock.maven.mode, |name| {
            jvm_options.unread(name)
        })?;
        let credential_scope = match lock.maven.mode {
            MavenMode::Maven310 => {
                Some(Arc::new(credential_scope(&session, &settings, &origins.1)?))
            }
            MavenMode::Maven39 => None,
        };

        // The filter values are lock inputs by themselves, so what reading
        // them reads is none.
        let repository_filters = Arc::new(load_repository_filters(
            &inputs,
            &settings,
            &environment.detached(),
            lock.maven.mode,
        )?);

        let mut config = Self {
            network,
            lock,
            plugins,
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
            repository_filters,
            credential_scope,
            central_system,
            platform_error: None,
            host_session: None,
            host_paths: false,
        };
        let names = config.secret_coordinate_names();
        config.host = (config.host.clone()).with_secret_names(names);
        config.register_secrets();

        if config.settings_path.is_some() {
            config.warn_of_unread_settings_urls();
        }
        tracing::debug!(path = %project_root.display(), "config loaded");

        Ok(config)
    }

    /// Warn of a settings.xml repository or mirror URL that does not parse
    /// or has a scheme raeva does not read. Maven skips such a repository,
    /// which still hides another with its id, so raeva keeps it and its
    /// requests fail. The URLs Maven reads as a directory, such
    /// as `file:repo` and in the 3.10 mode `symlink+file:`, `C:/repo` or
    /// one without a scheme, were rewritten to `file:` URLs as settings.xml
    /// was read. `raeva.toml` and `config.toml` URLs, and a Central URL,
    /// were checked as they were read, so any left are settings.xml's.
    fn warn_of_unread_settings_urls(&self) {
        let repositories =
            (self.all_repositories()).map(|repo| ("repository", repo.id.as_deref(), &repo.url));
        let mirrors = (self.settings.iter())
            .flat_map(|settings| settings.mirrors.iter().flatten())
            .map(|mirror| ("mirror", mirror.id.as_deref(), &mirror.url));
        let mut seen = HashSet::new();
        for (kind, id, url) in repositories.chain(mirrors) {
            if !seen.insert((kind, id, url)) {
                continue;
            }
            let entry = match id {
                Some(id) => format!("{kind} '{}'", rv_maven_types::bounded(id)),
                None => format!("a {kind} without an id"),
            };
            match url::Url::parse(url) {
                Ok(url) if matches!(url.scheme(), "http" | "https" | "file") => {}
                // Neither the URL nor its scheme is shown: either may come
                // from a secret's variable.
                _ => tracing::warn!(
                    sec_code = "SETTING_IGNORED",
                    "the settings.xml {entry} has no http, https or file URL that raeva can \
                     read; as in Maven, a mirror of it serves its requests, and without one \
                     they fail and the search goes on"
                ),
            }
        }
    }

    /// The configured repositories, in search order: the project's, the
    /// user's, then those of the active settings.xml profiles. On a shared
    /// id the earlier entry wins and a later one fills only its unset
    /// fields. Then [`Config::default_repositories`].
    pub fn repositories(&self) -> &[RepoConfig] {
        &self.maven_data.repositories
    }

    /// The tail of [`Config::repositories`] searched after the repositories
    /// the project's POMs declare: Maven Central, unless `raeva.toml` or
    /// `config.toml` names a repository, as Maven's super POM `central`; a
    /// settings.xml repository with id `central` replaces it. Then those
    /// of the profiles `<activeProfiles>` names that no earlier entry has
    /// the id of, as Maven's request carries them: the repositories of
    /// such a profile `-P !id` or `inactive_profiles` turns off.
    pub fn default_repositories(&self) -> &[RepoConfig] {
        let repositories = &self.maven_data.repositories;
        &repositories[repositories.len() - self.maven_data.defaults..]
    }

    /// The tail of [`Config::default_repositories`] from the profiles
    /// `<activeProfiles>` names but `-P !id` or `inactive_profiles` turns
    /// off. A project repository under one's id replaces it before Central.
    pub fn requested_repositories(&self) -> &[RepoConfig] {
        let repositories = &self.maven_data.repositories;
        &repositories[repositories.len() - self.maven_data.requested..]
    }

    /// The repositories of the profiles `<activeProfiles>` names, active or
    /// turned off, which Maven's request carries before Central: a
    /// project's model resolver searches them after the POM's.
    pub fn request_repositories(&self) -> &[RepoConfig] {
        &self.maven_data.request_repositories
    }

    /// The `<pluginRepositories>` of the active settings.xml profiles, as
    /// Maven puts them before each project's own: the last active
    /// profile's first, its entry winning a shared id.
    pub fn profile_plugin_repositories(&self) -> &[RepoConfig] {
        &self.maven_data.profile_plugin_repositories
    }

    /// The plugin repositories of Maven's request: those of the settings.xml
    /// profiles that `<activeProfiles>` names, in file order, then Central
    /// unless one has its id. Core extensions resolve from these, and a
    /// project's plugins from these after its model's.
    pub fn plugin_repositories(&self) -> &[RepoConfig] {
        &self.maven_data.plugin_repositories
    }

    /// [`Self::plugin_repositories`] without the defaults: those
    /// settings.xml names.
    pub fn named_plugin_repositories(&self) -> &[RepoConfig] {
        &self.maven_data.plugin_repositories[..self.maven_data.named_plugin_repositories]
    }

    /// [`Self::repositories`], then every repository and plugin repository
    /// of the active settings.xml profiles and of Maven's request, those a
    /// shared id hides included: what this machine's files name.
    pub fn all_repositories(&self) -> impl Iterator<Item = &RepoConfig> {
        (self.repositories().iter())
            .chain(&self.maven_data.settings_endpoints)
            .chain(self.plugin_repositories())
    }

    /// Every repository of the active settings.xml profiles, those a
    /// shared id hides included.
    pub fn settings_repositories(&self) -> &[RepoConfig] {
        &self.maven_data.settings_endpoints
    }

    /// The repositories `raeva.toml` and `config.toml` name, which Maven
    /// does not read, so its default HTTP blocker, which blocks a
    /// settings.xml one, does not apply to them.
    pub fn own_repositories(&self) -> impl Iterator<Item = &RepoConfig> {
        (self.inputs.project.repositories.iter().flatten())
            .chain(self.inputs.user.repositories.iter().flatten())
    }

    /// Whether `settings.xml`, `config.toml` or `raeva.toml` names a
    /// repository `central`.
    pub fn configures_central(&self) -> bool {
        let repositories = &self.maven_data.repositories;
        (repositories[..repositories.len() - self.maven_data.defaults].iter())
            .any(|repo| repo.id.as_deref() == Some("central"))
    }

    /// The URL that replaces Maven Central's in the Maven 3.10 mode, from
    /// `maven.repo.central` or `MAVEN_REPO_CENTRAL`, with where it was set,
    /// while [`Config::default_repositories`] keeps Central.
    pub fn replaced_central(&self) -> Option<(&str, &ConfigOrigin)> {
        let (url, origin) = self.inputs.central.as_ref()?;
        (self.default_repositories().iter())
            .any(|repo| repo.id.as_deref() == Some("central"))
            .then_some((url.as_str(), origin))
    }

    /// The mirrors, the user's before the settings.xml ones. Of two
    /// mirrors that match a repository equally well, the earlier is used.
    pub fn mirrors(&self) -> &[MirrorConfig] {
        &self.maven_data.mirrors
    }

    /// The URLs of the mirrors of no repository: origins a proxied redirect
    /// may reach, which get no request and no credential otherwise.
    pub fn redirect_origins(&self) -> &[String] {
        &self.maven_data.redirect_origins
    }

    /// Every `[[auth]]` entry and every settings.xml `<server>` that carries
    /// credentials, project first, then user, then settings.xml.
    /// [`Config::auth_layers`] keeps them apart.
    pub fn auth(&self) -> &[AuthConfig] {
        &self.maven_data.auth
    }

    /// The ids a settings.xml `<server>` or an `[[auth]]` entry names.
    pub fn credential_ids(&self) -> impl Iterator<Item = &str> {
        let layers = &self.maven_data.auth_layers;
        (layers.project.iter().chain(&layers.user))
            .filter_map(|auth| auth.id.as_deref())
            .chain(self.maven_data.server_ids.iter().map(String::as_str))
    }

    /// Whether `id` takes nothing from a `<server>` or `[[auth]]` but a
    /// settings.xml username and password, which Maven sends only once a
    /// request is challenged.
    pub fn sends_only_challenged_credentials(&self, id: &str) -> bool {
        let layers = &self.maven_data.auth_layers;
        !(layers.project.iter().chain(&layers.user)).any(|auth| auth.id.as_deref() == Some(id))
            && (!self.maven_data.server_ids.contains(id)
                || self.maven_data.basic_only_server_ids.contains(id))
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

    /// Why the proxies cannot be used: when no file names a proxy, proxy
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

    /// Maven's user home, the JVM's `user.home`: the last `-Duser.home`
    /// Maven takes, else the passwd entry's home on Unix and the profile
    /// folder on Windows, never `HOME`.
    pub fn maven_user_home(&self) -> Option<&Path> {
        self.inputs.user_home.as_deref()
    }

    /// `<localRepository>` from settings.xml as written: where `mvn` itself
    /// writes, unless `-Dmaven.repo.local` says otherwise.
    pub fn maven_local_repository(&self) -> Option<&Path> {
        self.maven_data.maven_local_repository.as_deref()
    }

    /// Maven's remote repository filters for this build.
    pub fn repository_filters(&self) -> &Arc<RepositoryFilters> {
        &self.repository_filters
    }

    /// Where Maven 3.10 sends a settings.xml server's username and
    /// password; `None` in the Maven 3.9 mode, which sends them by id.
    pub fn credential_scope(&self) -> Option<&CredentialScope> {
        self.credential_scope.as_deref()
    }

    /// Whether the project's raeva.toml sets `local_repository`.
    pub fn project_sets_local_repository(&self) -> bool {
        self.inputs.project.local_repository.is_some()
    }

    /// Whether the settings file is one `.mvn/maven.config` names with `-s`
    /// and sets `<localRepository>`, which export-m2 does not follow.
    pub fn project_settings_local_repository(&self) -> bool {
        self.inputs.project_settings && self.maven_data.maven_local_repository.is_some()
    }

    /// Whether settings.xml sets `<offline>true</offline>` or
    /// `.mvn/maven.config` holds `-o`, either of which makes a run offline
    /// as `--offline` does.
    pub fn offline(&self) -> bool {
        (self.settings.as_ref()).is_some_and(|settings| settings.offline)
            || crate::maven_config::sets_offline(self.inputs.maven_config.as_deref())
    }

    /// Whether `.mvn/maven.config` holds `-itr`, with which Maven reads no
    /// repository a dependency's or a plugin's POM declares, for its
    /// dependencies or for its own parents and imports, whatever
    /// `[security]` admits.
    pub fn ignores_transitive_repositories(&self) -> bool {
        crate::maven_config::ignores_transitive_repositories(self.inputs.maven_config.as_deref())
    }

    /// The settings.xml `<pluginGroups>`.
    pub fn plugin_groups(&self) -> &[String] {
        self.settings
            .as_ref()
            .map_or(&[], |settings| &settings.plugin_groups)
    }

    /// The profile ids that select POM profiles: those `raeva.toml`,
    /// `config.toml` or settings.xml `<activeProfiles>` name.
    pub fn active_profiles(&self) -> &[String] {
        &self.maven_data.active_profiles
    }

    /// The profile ids `active_profiles` in `raeva.toml`, or else
    /// `config.toml`, adds as `-P` does.
    pub fn added_active_profiles(&self) -> &[String] {
        self.inputs.added_active_profiles()
    }

    /// The ids of the settings.xml profiles, active or not; Maven names a
    /// profile without one `default`.
    pub fn settings_profile_ids(&self) -> impl Iterator<Item = &str> {
        (self.settings.iter())
            .flat_map(|settings| settings.profiles.iter().flatten())
            .map(|profile| profile.id.as_str())
    }

    /// The ids of the repositories and plugin repositories the settings.xml
    /// profiles declare, active or not: a Maven run with other `-P` options
    /// may read them.
    pub fn settings_profile_repository_ids(&self) -> impl Iterator<Item = &str> {
        (self.settings.iter())
            .flat_map(|settings| settings.profiles.iter().flatten())
            .flat_map(|profile| {
                profile
                    .repositories
                    .iter()
                    .chain(&profile.plugin_repositories)
            })
            .filter_map(|repo| repo.id.as_deref())
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
    ///
    /// Of one platform it also takes the repository filters, and in the
    /// Maven 3.10 mode the Central URL and the credential scope, Maven reads
    /// there, where its `${os.*}` or `java.version` changes the
    /// `.mvn/maven.config` options; [`Self::settings_activation`] returns
    /// the error one of `platforms` fails with there. Of several, or none,
    /// they stay the host's.
    pub fn for_platforms<'a>(
        &self,
        platforms: impl IntoIterator<Item = (&'a str, &'a str, Option<&'a str>)>,
    ) -> Self {
        let mut config = self.clone();
        if let Some(host) = config.host_session.take() {
            config.set_session(host);
        }
        config.platform_error = None;
        let platforms: Vec<_> = platforms.into_iter().collect();
        let environments: Vec<ModelEnvironment> = (platforms.iter())
            .map(|(os, arch, jdk)| self.host.environment_for(os, arch, *jdk))
            .collect();
        let host_options = self
            .inputs
            .maven_options(&self.host.host_environment().detached());
        for ((os, arch, _), environment) in platforms.iter().zip(&environments) {
            if self.inputs.maven_options(&environment.detached()) == host_options {
                continue;
            }
            match self.platform_session(environment) {
                Ok(session) if environments.len() == 1 => {
                    config.host_session = Some(config.session());
                    config.set_session(session);
                }
                Ok(_) => {}
                Err(error) => {
                    let (origin, message) = match error {
                        ConfigError::Invalid { origin, message } => (origin, message),
                        error => (
                            ConfigOrigin::MavenConfig(self.maven_config_path()),
                            error.to_string(),
                        ),
                    };
                    let message = format!("on platform {os}-{arch}: {message}");
                    config.platform_error.get_or_insert((origin, message));
                }
            }
        }
        if let Some(settings) = &self.settings {
            let explicit_environments = if environments.is_empty() {
                self.target_environments()
            } else {
                Vec::new()
            };
            config.maven_data = MavenSettingsData::merge(
                &config.inputs,
                settings.clone(),
                &self.host.host_environment(),
                &environments,
                &explicit_environments,
                Some(&self.settings_reads),
            );
        }
        config
    }

    /// The repository filters a build reads on each platform raeva knows
    /// where its `.mvn/maven.config` options differ from the host's, which
    /// a lock covers as it covers every settings.xml profile. A platform
    /// they fail on fails its sync instead.
    pub fn platform_repository_filters(&self) -> Vec<Arc<RepositoryFilters>> {
        let host = self
            .inputs
            .maven_options(&self.host.host_environment().detached());
        (self.target_environments().iter())
            .filter(|environment| self.inputs.maven_options(&environment.detached()) != host)
            .filter_map(|environment| self.platform_session(environment).ok())
            .map(|session| session.repository_filters)
            .collect()
    }

    fn session(&self) -> PlatformSession {
        PlatformSession {
            central: self.inputs.central.clone(),
            credential_scope: self.credential_scope.clone(),
            repository_filters: Arc::clone(&self.repository_filters),
        }
    }

    fn set_session(&mut self, session: PlatformSession) {
        self.inputs.central = session.central;
        self.credential_scope = session.credential_scope;
        self.repository_filters = session.repository_filters;
    }

    /// The `.mvn` directory `mvn` reads, in the launcher's directory.
    pub fn mvn_dir(&self) -> PathBuf {
        let environment = self.host.host_environment();
        (environment.launcher_root().map(Path::new))
            .unwrap_or(&self.project_root)
            .join(".mvn")
    }

    fn maven_config_path(&self) -> PathBuf {
        self.mvn_dir().join("maven.config")
    }

    /// The Maven 3.10 Central URL, the credential scope and the repository
    /// filters of a build in `environment`, as [`Config::load`] takes them
    /// for the host.
    fn platform_session(
        &self,
        environment: &ModelEnvironment,
    ) -> Result<PlatformSession, ConfigError> {
        let Some(settings) = &self.settings else {
            return Ok((self.host_session.clone()).unwrap_or_else(|| self.session()));
        };
        let mode = self.lock.maven.mode;
        let maven_config_path = self.maven_config_path();
        let jvm_config_path = self.mvn_dir().join("jvm.config");
        let mut inputs = self.inputs.clone();
        if mode == MavenMode::Maven310 {
            inputs.central =
                inputs.central(environment, self.central_system.clone(), &maven_config_path);
            if let Some((url, origin)) = &inputs.central {
                refuse_unusable_central(url, origin)?;
            }
        }
        let environment = environment.detached();
        let session = SessionProperties {
            inputs: &inputs,
            environment: &environment,
            profiles: requested_profile_properties(
                &inputs,
                settings,
                &inputs.maven_options(&environment),
                mode,
            ),
            jvm_config_path: &jvm_config_path,
            maven_config_path: &maven_config_path,
            settings_path: self.settings_path.as_ref(),
        };
        let user_origin = ConfigOrigin::UserConfig(self.user_config_path.clone());
        let credential_scope = match mode {
            MavenMode::Maven310 => Some(Arc::new(credential_scope(
                &session,
                settings,
                &user_origin,
            )?)),
            MavenMode::Maven39 => None,
        };
        let filters = load_repository_filters(&inputs, settings, &environment, mode)?;
        Ok(PlatformSession {
            central: inputs.central,
            credential_scope,
            repository_filters: Arc::new(filters),
        })
    }

    /// The error a settings.xml profile activation fails with on a platform
    /// of [`Self::for_platforms`], which fails Maven's build there as on the
    /// host. The settings.xml URLs of the profiles active there are warned
    /// of as [`Config::load`] warns of the host's, once each.
    pub fn settings_activation(&self) -> Result<(), ConfigError> {
        if let Some((origin, message)) = &self.platform_error {
            return Err(ConfigError::Invalid {
                origin: origin.clone(),
                message: message.clone(),
            });
        }
        settings_activation(
            self.settings_path.as_ref(),
            &self.maven_data,
            self.plugins.is_some(),
        )?;
        if self.settings_path.is_some() {
            self.warn_of_unread_settings_urls();
        }
        Ok(())
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
            .0
    }

    /// [`Self::settings_profile_properties_for`], with `host` as the
    /// environment of the `.mvn/maven.config` options and `<file>`
    /// conditions, and the `${...}` each property took a value from when
    /// settings.xml was read.
    fn settings_profile_properties_on(
        &self,
        environment: &ModelEnvironment,
        host: &ModelEnvironment,
    ) -> (PropertyMap, HashMap<String, Vec<String>>) {
        let mut inputs = HashMap::new();
        let Some(settings) = &self.settings else {
            return (PropertyMap::new(), inputs);
        };
        let Some(profiles) = settings.profiles.as_deref() else {
            return (PropertyMap::new(), inputs);
        };
        let explicit_active_profiles = explicit_active_profiles(&self.inputs, settings);
        let active = resolve_active_profiles(
            Some(profiles),
            &self.inputs,
            &explicit_active_profiles,
            environment,
            &settings_file_context(&self.inputs, &host.with_java_version_of(environment)),
            None,
        )
        // `Config::load` refuses an activation error on the host.
        .unwrap_or_default();
        let mut merged = PropertyMap::new();
        for profile in profiles {
            if active.contains(&profile.id) {
                for (key, value) in profile.properties.iter() {
                    // As Maven's settings builder expands it on this platform.
                    let value = rv_maven_model::expand_host_properties(value, environment);
                    merged.insert(key.clone(), value);
                    match profile.property_inputs.get(key) {
                        Some(taken) => inputs.insert(key.clone(), taken.clone()),
                        None => inputs.remove(key),
                    };
                }
            }
        }
        (merged, inputs)
    }

    /// The ids of [`Config::settings_model_repositories_for`]: Maven fills
    /// each in once for the whole build, so raeva answers one only where
    /// every project fills it in alike.
    pub fn settings_model_repository_ids(&self, environment: &ModelEnvironment) -> Vec<String> {
        (self
            .settings_model_repositories_for(environment)
            .into_iter())
        .flatten()
        .filter_map(|repo| repo.id)
        .collect()
    }

    /// The repositories of each settings.xml profile active in
    /// `environment` whose URL a project's model fills in
    /// ([`rv_maven_model::ActivationContext::settings_repositories`]), in
    /// file order, each unless a later profile's entry takes its id.
    pub fn settings_model_repositories_for(
        &self,
        environment: &ModelEnvironment,
    ) -> Vec<Vec<rv_maven_model::Repository>> {
        let Some(settings) = &self.settings else {
            return Vec::new();
        };
        let Some(profiles) = settings.profiles.as_deref() else {
            return Vec::new();
        };
        let host = self.host.host_environment();
        let explicit_active_profiles = explicit_active_profiles(&self.inputs, settings);
        let active = resolve_active_profiles(
            Some(profiles),
            &self.inputs,
            &explicit_active_profiles,
            environment,
            &settings_file_context(&self.inputs, &host.with_java_version_of(environment)),
            None,
        )
        .unwrap_or_default();
        let active: Vec<&MavenProfile> = (profiles.iter())
            .filter(|profile| active.contains(&profile.id))
            .collect();
        let injected = injected(&active, |profile| &profile.repositories);
        (active.iter())
            .map(|profile| {
                (profile.model_repositories.iter())
                    .filter(|model| {
                        (injected.iter()).any(|repo| {
                            let url = repo.declared_url.as_deref().unwrap_or(&repo.url);
                            repo.id == model.id && url == model.url
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .filter(|repositories| !repositories.is_empty())
            .collect()
    }

    /// The repositories of every settings.xml profile, in file order, that
    /// a project's model fills in, each as written, for the lock's
    /// configuration hash.
    pub fn settings_model_repository_inputs(&self) -> Vec<String> {
        let profiles = (self.settings.as_ref())
            .and_then(|settings| settings.profiles.as_deref())
            .unwrap_or_default();
        let field = |value: Option<&str>| value.map_or("\u{0}".to_string(), str::to_string);
        (profiles.iter())
            .flat_map(|profile| {
                (profile.model_repositories.iter()).map(move |repo| (profile, repo))
            })
            .map(|(profile, repo)| {
                [
                    profile.id.clone(),
                    field(repo.id.as_deref()),
                    self.portable_location(&repo.url),
                    field(repo.layout.as_deref()),
                    repo.releases_enabled.to_string(),
                    repo.snapshots_enabled.to_string(),
                    field(repo.releases_update_policy.as_deref()),
                    field(repo.snapshots_update_policy.as_deref()),
                    field(repo.releases_checksum_policy.as_deref()),
                    field(repo.snapshots_checksum_policy.as_deref()),
                ]
                .join("\n")
            })
            .collect()
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
                        .map(|value| self.portable(value))
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

    /// Whether a read of the user property `name` takes the JDK version: it
    /// is `java.version` or `java.specification.version`, which the JDK
    /// answers where no `-D` sets it, or its `-D` value expands one.
    pub fn user_property_reads_jdk(&self, name: &str) -> bool {
        const NAMES: [&str; 2] = ["java.version", "java.specification.version"];
        let environment = self.host.host_environment().detached();
        NAMES.contains(&name)
            || (self
                .inputs
                .maven_options(&environment)
                .platform_values
                .get(name))
            .is_some_and(|value| NAMES.iter().any(|read| value.contains(read)))
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
    /// `.mvn/maven.config` or `.mvn/jvm.config`, active settings.xml profiles,
    /// and the allowlisted environment variables, and those that take a
    /// value from one through any chain of others, such as a settings.xml
    /// property that takes `${env.API_KEY}`. Each comes as how a message
    /// names it, then its value, expanded as far as these inputs go, which
    /// no message may show.
    pub fn secret_named_inputs(&self) -> Vec<(String, String)> {
        self.secret_inputs().0
    }

    /// The property names of [`Self::secret_named_inputs`], each with how a
    /// message names its input: those named like a secret, and those that
    /// take a value from one. A model that looks one up for a repository
    /// URL takes the secret into it, whatever its value.
    pub fn secret_input_names(&self) -> Vec<(String, String)> {
        self.secret_inputs().1
    }

    /// The names a model may read a host input named like a secret under,
    /// each with how a message names the input: [`Self::secret_input_names`]
    /// and the allowlisted environment variables named like a secret, as
    /// `${env.NAME}` and as `${NAME}`. One whose value is too short or too
    /// ordinary to be a secret, such as a version, is left out, as messages
    /// show it.
    fn secret_coordinate_names(&self) -> BTreeMap<String, String> {
        let secret = |value: &str| !crate::redact::ordinary_value(value);
        let mut names: BTreeMap<String, String> = BTreeMap::new();
        for (name, value) in self.host.env_values() {
            if crate::secret_named(name) && secret(value) {
                let input = format!("${{env.{name}}}");
                names.insert(format!("env.{name}"), input.clone());
                names.insert(name.clone(), input);
            }
        }
        let inputs = self.secret_named_inputs();
        let held =
            |input: &str| (inputs.iter()).any(|(name, value)| name == input && secret(value));
        names.extend((self.secret_input_names().into_iter()).filter(|(_, input)| held(input)));
        names
    }

    /// Hide from every output the values of [`Self::secret_named_inputs`]
    /// and every password and token: a message or log that quotes a URL or
    /// text a server sent may hold one.
    fn register_secrets(&self) {
        for (_, value) in self.secret_named_inputs() {
            crate::redact::register_named_secret(&value);
        }
        let auth = (self.auth().iter()).flat_map(|auth| [&auth.password, &auth.token]);
        let proxies = (self.proxies().iter()).flat_map(|proxy| [&proxy.password, &proxy.token]);
        for secret in auth.chain(proxies).flatten() {
            crate::redact::register_secret(secrecy::ExposeSecret::expose_secret(secret));
        }
        let token_envs = self
            .proxies()
            .iter()
            .filter_map(|proxy| proxy.token_env.as_ref());
        for value in token_envs.filter_map(|name| std::env::var(name).ok()) {
            crate::redact::register_secret(&value);
        }
    }

    /// [`Self::secret_named_inputs`] and [`Self::secret_input_names`], read
    /// in one pass.
    pub fn secret_inputs(&self) -> (Labelled, Labelled) {
        // Read apart from the model builds, whose host reads raeva.lock
        // records.
        let host = self.host.host_environment().detached();
        let env = self.host.env_values();
        let mut inputs: Vec<_> = (env.iter())
            .filter(|(name, _)| crate::secret_named(name))
            .map(|(name, value)| (format!("${{env.{name}}}"), value.clone()))
            .collect();
        let mut names: Vec<(String, String)> = Vec::new();
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
            let options = self.inputs.maven_options(&environment);
            let defines = options.properties;
            let (settings, settings_inputs) =
                self.settings_profile_properties_on(&environment, &host);
            // As the project's model and a dependency's, which reads `-D`
            // values without the settings.xml properties, read them.
            let mut project = with_env.clone();
            let mut dependency = with_env.clone();
            for (name, value) in environment.system_properties() {
                if !model_owned(name) {
                    project.insert(name.as_str(), value.as_str());
                    dependency.insert(name.as_str(), value.as_str());
                }
            }
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
            // Whether a model reads the value of an input under its name: a
            // `-D` value hides a settings.xml property and a .mvn/jvm.config
            // one of its name.
            let defined = |name: &str| defines.contains_key(name);
            let system = environment.system_properties().iter().map(|(name, value)| {
                let channel = (self.inputs.jvm_channels.get(name).copied())
                    .unwrap_or(crate::jvm_options::JVM_CONFIG);
                let input = format!("{channel} -D{name}");
                (input, name, value, !defined(name))
            });
            let settings = (settings.iter()).map(|(name, value)| {
                let input = format!("settings.xml property {name}");
                (input, name, value, !defined(name))
            });
            let all: Vec<_> = (defines.iter())
                .map(|(name, value)| (format!("-D{name}"), name, value, true))
                .chain(settings)
                .chain(system)
                .collect();
            // The secret-named input each other one takes a value from, as
            // `${NAME}`: when its `-D` value or settings.xml property was
            // read, or as a model expands it, through any other.
            let mut sources: HashMap<String, String> = HashMap::new();
            let source_of = |read: &str, sources: &HashMap<String, String>| {
                if !crate::secret_named(read) {
                    sources.get(read).cloned()
                } else if env.contains_key(read) && project.get(read) == env.get(read) {
                    Some(format!("${{env.{read}}}"))
                } else {
                    Some(format!("${{{read}}}"))
                }
            };
            for (name, read) in &options.secret_inputs {
                sources.insert(name.clone(), format!("${{{}}}", read[0]));
            }
            for (name, taken) in (settings_inputs.iter()).filter(|(name, _)| !defined(name)) {
                if let Some(source) = taken.iter().find_map(|read| source_of(read, &sources)) {
                    sources.insert(name.clone(), source);
                }
            }
            let mut changed = true;
            while changed {
                changed = false;
                for (_, name, value, _) in all.iter().filter(|input| input.3) {
                    if crate::secret_named(name) || sources.contains_key(name.as_str()) {
                        continue;
                    }
                    let source = [&project, &dependency].into_iter().find_map(|properties| {
                        let (_, read) =
                            (properties.clone()).interpolate_str_exact_names(value, &environment);
                        (read.iter())
                            .filter(|read| *read != *name && properties.get(read).is_some())
                            .find_map(|read| source_of(read, &sources))
                    });
                    if let Some(source) = source {
                        sources.insert(name.to_string(), source);
                        changed = true;
                    }
                }
            }
            for (input, name, value, read) in all {
                let input = match sources.get(name.as_str()) {
                    _ if crate::secret_named(name) => input,
                    Some(source) if read => format!("{source} (through {input})"),
                    _ => continue,
                };
                names.push((name.to_string(), input.clone()));
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
        names.sort();
        names.dedup();
        (inputs, names)
    }

    /// The values of the user properties `names` on each target: a `-D` on
    /// the command line or in `.mvn/maven.config`, else a JVM option's.
    pub fn user_property_inputs(
        &self,
        names: &BTreeSet<String>,
    ) -> BTreeMap<String, PropertyInputs> {
        self.property_inputs(names, true)
    }

    /// [`Self::user_property_inputs`] for names a model defines, whose own
    /// value ranks above a JVM option's: a `-D` alone.
    pub fn user_override_inputs(
        &self,
        names: &BTreeSet<String>,
    ) -> BTreeMap<String, PropertyInputs> {
        self.property_inputs(names, false)
    }

    fn property_inputs(
        &self,
        names: &BTreeSet<String>,
        system: bool,
    ) -> BTreeMap<String, PropertyInputs> {
        if names.is_empty() {
            return BTreeMap::new();
        }
        let options = self.target_maven_options();
        let environment = self.host.host_environment();
        names
            .iter()
            .map(|name| {
                let inputs = (options.iter())
                    .map(|options| match options.properties.get(name) {
                        Some(value) => Some(PropertyInput::Value(self.portable(value))),
                        None => (environment.system_properties().get(name))
                            .filter(|_| system)
                            .map(|value| PropertyInput::JvmConfig(self.portable(value))),
                    })
                    .collect();
                (name.clone(), PropertyInputs(inputs))
            })
            .collect()
    }

    /// `value` as the lock hash covers it: the project directory in it,
    /// spelled as given, as resolved, as the shell names it or as
    /// `${project.baseUri}` writes it, replaced by a marker, so the hash is
    /// the same in every checkout. A `file://` URL of the directory, its
    /// path percent-encoded or not, is one marker. The launcher's directory,
    /// spelled as `mvn` passes it, is the marker, or the marker so many
    /// levels up when a `.mvn` above the project puts it there, and the
    /// Maven user home, `${user.home}`, is another marker. Only a whole
    /// directory matches: one that follows no path or URL text and is
    /// followed by a separator or the end.
    ///
    /// The marker hides what a value names on this host, which a POM can
    /// still compare: [`Self::with_host_paths`] keeps it, for a sync to tell
    /// whether a lock it reuses was written with the same values.
    pub fn portable(&self, value: &str) -> String {
        match self.host_paths {
            true => value.to_string(),
            false => self.portable_location(value),
        }
    }

    /// [`Self::portable`], under [`Self::with_host_paths`] too: for a
    /// repository URL, which no model reads, and whose files the lock pins
    /// where it records them.
    pub fn portable_location(&self, value: &str) -> String {
        const ROOT: &str = "\0project\0";
        const ROOT_URI: &str = "\0project-uri\0";
        const HOME: &str = "\0home\0";
        const HOME_URI: &str = "\0home-uri\0";
        let environment = self.host.host_environment();
        let reactor_root = environment.reactor_root();
        let shell_named = environment.project_directory();
        let mut spellings = Vec::new();
        let mut spell = |root: &Path, (native, uri): (&str, &str), up: usize| {
            let up = "/..".repeat(up);
            let text = root.to_string_lossy();
            spellings.push((text.to_string(), format!("{native}{up}")));
            spellings.push((format!("file://{text}"), format!("{uri}{up}")));
            let encoded = rv_maven_model::directory_uri(root);
            spellings.push((
                encoded.trim_end_matches('/').to_string(),
                format!("{uri}{up}"),
            ));
        };
        let roots: Vec<&Path> = [Some(self.project_root.as_path()), reactor_root, shell_named]
            .into_iter()
            .flatten()
            .filter(|root| root.is_absolute())
            .collect();
        for root in &roots {
            spell(root, (ROOT, ROOT_URI), 0);
        }
        // The launcher's directory is spelled as `mvn` passes it, which may
        // name the project in another case where the file system folds it.
        // Values are matched in their own case, as a profile compares them.
        let fold = folds_case(&self.project_root);
        if let Some(launcher) = environment.launcher_root().map(Path::new)
            && let Some(levels) = (roots.iter()).find_map(|root| levels_below(root, launcher, fold))
        {
            spell(launcher, (ROOT, ROOT_URI), levels);
        }
        // A home at the file system's root would match every path.
        if let Some(home) =
            (self.inputs.user_home.as_deref()).filter(|home| home.parent().is_some())
        {
            spell(home, (HOME, HOME_URI), 0);
        }
        // Longest first; the project's spellings, pushed first, win a tie.
        spellings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        with_markers(value, &spellings)
    }

    /// This configuration with [`Self::portable`] keeping the host's
    /// directories, so a hash of it names them.
    #[must_use]
    pub fn with_host_paths(&self) -> Self {
        Self {
            host_paths: true,
            ..self.clone()
        }
    }

    /// `lookup` replayed in `environment`, one of the target environments.
    fn replay_lookup(
        &self,
        lookup: &crate::maven_config::PropertyLookup,
        environment: ModelEnvironment,
    ) -> LookupReplay {
        use crate::maven_config::{LookupMode, PropertySource};
        // Canonical, as the module directories of a resolution are.
        let root = (environment.reactor_root().map(Path::to_path_buf))
            .unwrap_or_else(|| self.project_root.clone());
        let mut ctx = ActivationContext::new(environment.clone());
        let defines = self.inputs.maven_options(&environment).properties;
        ctx.set_external_properties(defines.clone(), lookup.source);
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
            .map(|base| root.join(base))
            .or_else(|| {
                lookup
                    .model
                    .as_ref()
                    .and_then(|model| model.base_dir.as_ref())
                    .map(|base| root.join(base))
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
        if lookup.mode == LookupMode::File {
            for (name, directory) in ctx.file_directories() {
                properties.insert(name, directory);
            }
            ctx.insert_launcher_root(&mut properties);
        }
        let (expanded, reads) = if lookup.mode == LookupMode::Model {
            match &lookup.model {
                Some(model) => model.interpolate(&lookup.expression, &properties, &ctx),
                None => properties.replay_model_names(&lookup.expression, &ctx),
            }
        } else {
            properties.replay_exact_names(&lookup.expression, &environment)
        };
        LookupReplay {
            environment,
            ctx,
            defines,
            properties,
            expanded,
            reads,
        }
    }

    /// The `env.NAME` names replaying the lookup `template` reads, each with
    /// whether the replay answers it itself, as a `<file>` path answers
    /// `env.JAVA_HOME` with the JDK's, rather than reading the variable.
    pub fn user_property_lookup_env_reads(&self, template: &str) -> Vec<(String, bool)> {
        use crate::maven_config::{LookupMode, PropertyLookup};
        let Some(lookup) = PropertyLookup::parse(template) else {
            return Vec::new();
        };
        let mut reads = Vec::new();
        for environment in self.target_environments() {
            let replay = self.replay_lookup(&lookup, environment.detached());
            let tested = (lookup.mode == LookupMode::Property)
                .then(|| replay.expanded.as_deref().ok())
                .flatten()
                .map(|name| name.strip_prefix('!').unwrap_or(name).to_string());
            for name in replay.reads.iter().chain(&tested) {
                if let Some(variable) = name.strip_prefix("env.") {
                    let answered = replay.properties.get(name).is_some();
                    reads.push((variable.to_string(), answered));
                }
            }
        }
        reads
    }

    /// Replay authored input reads for the aggregate configuration hash.
    /// Only the expression and its POM context are public; returned values stay private.
    pub fn user_property_lookup_value(&self, template: &str) -> Option<String> {
        self.lookup_value(template, None)
    }

    /// The values [`Self::user_property_lookup_value`] gives the `<file>`
    /// lookup `template` where its path tested missing and where it tested
    /// present, when the path is on the JDK's home and no `-D` or
    /// settings.xml sets that; `None` for any other lookup.
    pub fn jdk_home_lookup_values(&self, template: &str) -> Option<[String; 2]> {
        use crate::maven_config::{LookupMode, PropertyLookup};
        let lookup = PropertyLookup::parse(template)?;
        if lookup.mode != LookupMode::File {
            return None;
        }
        let reads_home = self.target_environments().into_iter().all(|environment| {
            let replay = self.replay_lookup(&lookup, environment.detached());
            (replay.reads.iter())
                .any(|name| is_jdk_home(name) && !replay.properties.is_external(name))
        });
        if !reads_home {
            return None;
        }
        Some([
            self.lookup_value(template, Some(false))?,
            self.lookup_value(template, Some(true))?,
        ])
    }

    /// [`Self::user_property_lookup_value`], with a `<file>` path taken as
    /// having `tested` so where that is given.
    fn lookup_value(&self, template: &str, tested: Option<bool>) -> Option<String> {
        use crate::maven_config::{LookupMode, PropertyLookup};
        let lookup = PropertyLookup::parse(template)?;
        let values: Vec<_> = self
            .target_environments()
            .into_iter()
            .map(|environment| {
                let LookupReplay {
                    environment,
                    ctx,
                    defines,
                    properties,
                    expanded,
                    reads,
                } = self.replay_lookup(&lookup, environment.detached());
                let expanded = expanded.ok()?;
                // Resolution records a `<file>` path that reads nothing but
                // the POM properties the lookup holds as a file condition,
                // so such a lookup is text an edited raeva.lock holds and
                // its path is not tested.
                if lookup.mode == LookupMode::File
                    && !(reads.iter()).any(|name| {
                        !lookup.properties.contains_key(name) || properties.is_external(name)
                    })
                {
                    return None;
                }
                let system = ctx.activation_system_properties();
                let read_values: BTreeMap<_, _> = reads
                    .into_iter()
                    .filter_map(|name| {
                        if properties.get(&name).is_some() && !properties.is_external(&name) {
                            return None;
                        }
                        // The JDK's home, or `${...}` as written without
                        // one: a lookup keeps only what its path tested, so
                        // JAVA_HOME set or unset for one JDK hashes alike.
                        if lookup.mode == LookupMode::File
                            && is_jdk_home(&name)
                            && !properties.is_external(&name)
                        {
                            return None;
                        }
                        // A dependency model reads a `-D` as a system property.
                        let jvm_config = environment.system_properties().contains_key(&name)
                            && !defines.contains_key(&name);
                        let value = properties
                            .get(&name)
                            .map(|value| PropertyInput::Value(self.portable(value)))
                            .or_else(|| {
                                let value = self.portable(system.get(&name)?);
                                Some(match jvm_config {
                                    true => PropertyInput::JvmConfig(value),
                                    false => PropertyInput::Value(value),
                                })
                            })
                            .or_else(|| {
                                match name.as_str() {
                                    "java.version" => {
                                        ctx.property("java.version").map(str::to_string)
                                    }
                                    name => name
                                        .strip_prefix("env.")
                                        .or_else(|| {
                                            (lookup.mode == LookupMode::Model).then_some(name)
                                        })
                                        .and_then(|key| self.host.env_value(key))
                                        .map(str::to_string),
                                }
                                .map(|value| PropertyInput::Value(self.portable(&value)))
                            });
                        Some((name, value))
                    })
                    .collect();
                let actual = match lookup.mode {
                    LookupMode::File => Some(
                        tested
                            .unwrap_or_else(|| ctx.file_condition_exists(&expanded))
                            .to_string(),
                    ),
                    LookupMode::Property => {
                        let name = expanded.strip_prefix('!').unwrap_or(&expanded);
                        ctx.property(name)
                            .map(str::to_string)
                            .or_else(|| {
                                name.strip_prefix("env.")
                                    .and_then(|key| self.host.env_value(key))
                                    .map(str::to_string)
                            })
                            .map(|value| self.portable(&value))
                    }
                    LookupMode::Interpolation | LookupMode::Model => Some(self.portable(&expanded)),
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
                let portable = |ids: Vec<String>| -> Vec<String> {
                    ids.iter().map(|id| self.portable(id)).collect()
                };
                let selections = (
                    portable(options.active_profiles),
                    portable(options.inactive_profiles),
                );
                serde_json::to_string(&selections).expect("profile selections serialize")
            })
            .collect()
    }

    /// The settings.xml profiles with an `<activation>`, in file order, as
    /// an id and a canonical text of the activation, as written before
    /// `${...}` expansion, and the repositories and plugin repositories:
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
                let id = profile.id.clone();
                let activation = (profile.written_activation.as_ref())
                    .or_else(|| every.then_some(&unconditional))?;
                let mut content = serde_json::json!({
                    "activation": activation,
                    "repositories": profile.repositories,
                });
                if !profile.plugin_repositories.is_empty() {
                    content["plugin_repositories"] = serde_json::json!(profile.plugin_repositories);
                }
                Some((id, content.to_string()))
            })
            .collect()
    }

    /// The keys of the settings.xml conditions that decided a profile with
    /// repositories or plugin repositories on a platform this configuration, or one made from the
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
        let held = std::iter::once(host.clone())
            .chain(targets)
            .find_map(|environment| {
                let ctx = settings_file_context(&self.inputs, &environment);
                profiles
                    .iter()
                    .flat_map(|profile| settings_conditions(profile, &ctx))
                    .find(|(text, _)| settings_key(text) == key)
            });
        if let Some((text, input)) = held {
            return Some((text, self.host.holds_in_settings(&input)?));
        }
        self.target_environments().iter().find_map(|environment| {
            profiles.iter().find_map(|profile| {
                let text = settings_expansion(profile, environment)?;
                (settings_key(&text) == key).then(|| {
                    let holds =
                        settings_activation_holds(profile, &self.inputs, &host, environment);
                    Some((text, holds?))
                })?
            })
        })
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
        self.host = (host.with_maven_mode(self.lock.maven.mode)).with_locked_jdks(&self.lock.jdks);
        self
    }

    /// The JDK and allowlisted environment variables read when the config
    /// was loaded.
    pub fn host(&self) -> &HostSnapshot {
        &self.host
    }

    /// The `-D`, `-P` and `-s` options the configuration was loaded with,
    /// after the `-D` and `-P` of `MAVEN_ARGS`.
    pub fn command_line(&self) -> &CommandLine {
        &self.inputs.command_line
    }

    /// A reactor selection option, such as `-pl`, that `MAVEN_ARGS`, a
    /// `MAVEN_CONFIG` a wrapper script passes or `.mvn/maven.config` gives
    /// `mvn`, with where; the resolution ignores it.
    pub fn reactor_selection(&self) -> Option<(&ConfigOrigin, &'static str)> {
        (self.inputs.reactor_selection.as_ref()).map(|(origin, option)| (origin, *option))
    }

    /// The `-D` and `-P` options `mvn` reads from `.mvn/maven.config` and
    /// the command line: see [`crate::maven_config::with_maven_config`].
    pub fn maven_command_line(&self) -> CommandLine {
        crate::maven_config::with_maven_config(
            self.inputs.maven_config.as_deref(),
            &self.inputs.command_line,
        )
    }

    /// The project's `.mvn/jvm.config` as read, if it has one.
    pub fn jvm_config(&self) -> Option<&str> {
        self.inputs.jvm_config.as_deref()
    }

    /// The system properties `mvn`'s JVM takes from the JVM option
    /// variables and the argument files they name, as it takes the last of a
    /// name, and the channel of each. Left out: `user.home`, the resolver's
    /// lock factory, a name like a secret's, which may change each run, one
    /// an option sets in a way raeva does not read, and the JDK's own names
    /// and those in the namespaces that tune the JVM, the transport or the
    /// console that the project does not read: such as `os.name`,
    /// `https.protocols`, `maven.wagon.http.pool` or
    /// `org.slf4j.simpleLogger.showDateTime`. Other names in `os.`, `user.`,
    /// `file.`, `java.`, `javax.` and `http.`, such as os-maven-plugin's
    /// `os.detected.classifier` or a POM's `java.source.version`, are left
    /// in, as is a POM's `jdk.javadoc.doclet.version`.
    ///
    /// The project reads a name that a POM of `project_poms` defines as a
    /// property, or that a value of such a POM or `.mvn/extensions.xml`,
    /// `.mvn/maven.config`, `.mvn/jvm.config`, a `-D` value or the trace's
    /// arguments holds other than as the name a `-D` option sets, as Maven
    /// may read it through an expression raeva does not evaluate. When
    /// `project_poms` fails or such a file cannot be read, every name stays
    /// in.
    pub fn jvm_option_properties(
        &self,
        project_poms: impl FnOnce() -> Result<Vec<PathBuf>, String>,
    ) -> BTreeMap<String, (String, &'static str)> {
        const HOST_OWNED: [&str; 65] = [
            "java.awt.",
            "java.class.",
            "java.content.",
            "java.io.",
            "java.lang.",
            "java.locale.",
            "java.naming.",
            "java.net.",
            "java.nio.",
            "java.protocol.",
            "java.rmi.",
            "java.runtime.",
            "java.security.",
            "java.specification.",
            "java.system.",
            "java.text.",
            "java.time.",
            "java.util.",
            "java.vendor",
            "java.vm.",
            "javax.accessibility.",
            "javax.imageio.",
            "javax.management.",
            "javax.naming.",
            "javax.net.",
            "javax.print.",
            "javax.rmi.",
            "javax.security.",
            "javax.smartcardio.",
            "javax.sound.",
            "javax.xml.accessExternal",
            "javax.xml.catalog.",
            "javax.xml.datatype.",
            "javax.xml.parsers.",
            "javax.xml.stream.",
            "javax.xml.transform.",
            "javax.xml.validation.",
            "javax.xml.xpath.",
            "jdk.",
            "sun.",
            "com.sun.",
            "http.agent",
            "http.auth.",
            "http.keepAlive",
            "http.maxConnections",
            "http.maxRedirects",
            "http.nonProxyHosts",
            "http.proxy",
            "https.",
            "ftp.",
            "socks",
            "org.slf4j.",
            "maven.wagon.",
            "aether.connector.",
            "aether.transport.",
            "maven.resolver.transport",
            "maven.artifact.threads",
            "style.",
            "jansi.",
            "file.encoding",
            "user.language",
            "user.country",
            "user.script",
            "user.variant",
            "user.extensions",
        ];
        const JDK_NAMES: [&str; 22] = [
            "java.compiler",
            "java.endorsed.dirs",
            "java.ext.dirs",
            "java.home",
            "java.library.path",
            "java.version",
            "java.version.date",
            "javax.xml.useCatalog",
            "os.name",
            "os.arch",
            "os.version",
            "file.separator",
            "path.separator",
            "line.separator",
            "native.encoding",
            "stdin.encoding",
            "stdout.encoding",
            "stderr.encoding",
            "user.name",
            "user.dir",
            "user.region",
            "user.timezone",
        ];
        const LEFT_OUT: [&str; 2] = [
            "user.home",
            // Picks how the resolver locks the local repository, not what it reads.
            "aether.syncContext.named.factory",
        ];
        let environment = self.host.host_environment();
        let host_owned = |name: &str| {
            HOST_OWNED.iter().any(|prefix| name.starts_with(prefix)) || JDK_NAMES.contains(&name)
        };
        let read = self.inputs.pom_reads.get_or_init(|| {
            let names: Vec<&str> = (environment.system_properties().keys())
                .map(String::as_str)
                .filter(|name| host_owned(name))
                .collect();
            if names.is_empty() {
                return (BTreeSet::new(), None);
            }
            let read = project_poms().and_then(|poms| {
                crate::pom_mentions::mentioned(
                    &self.project_root,
                    &poms,
                    &self.texts_maven_reads(&environment),
                    &names,
                )
            });
            match read {
                Ok(read) => (read, None),
                Err(reason) => {
                    tracing::debug!(
                        reason = %rv_maven_types::bounded(&reason),
                        "the trace key holds every host-owned -D option, as raeva cannot read \
                         the project's files"
                    );
                    let all = names.iter().map(ToString::to_string).collect();
                    (all, Some(self.within_project(&reason)))
                }
            }
        });
        let read = &read.0;
        (environment.system_properties().iter())
            .filter(|(name, _)| {
                (!host_owned(name) || read.contains(name.as_str()))
                    && !LEFT_OUT.contains(&name.as_str())
                    && !crate::secret_named(name)
                    && !environment.unread_system_property(name)
            })
            .filter_map(|(name, value)| {
                let channel = *self.inputs.jvm_channels.get(name)?;
                (channel != crate::jvm_options::JVM_CONFIG)
                    .then(|| (name.clone(), (value.clone(), channel)))
            })
            .collect()
    }

    /// Why [`Self::jvm_option_properties`] took every host-owned name into
    /// the trace key, when it could not read the project's files, with the
    /// paths in the project relative to it.
    pub fn trace_key_unread(&self) -> Option<&str> {
        self.inputs.pom_reads.get()?.1.as_deref()
    }

    /// `text` with the project directory's prefix taken off the paths in it.
    fn within_project(&self, text: &str) -> String {
        let mut text = text.to_string();
        let canonical = std::fs::canonicalize(&self.project_root).ok();
        for root in std::iter::once(&self.project_root).chain(canonical.as_ref()) {
            let prefix = format!("{}{}", root.display(), std::path::MAIN_SEPARATOR);
            text = text.replace(&prefix, "");
        }
        text
    }

    /// The text Maven reads besides the POMs, where a value may read a
    /// system property: `.mvn/maven.config`, `.mvn/jvm.config`,
    /// the `-D` values of the JVM in `environment`, of raeva's command line
    /// and of `MAVEN_ARGS`, and the trace's arguments.
    fn texts_maven_reads<'a>(&'a self, environment: &'a ModelEnvironment) -> Vec<&'a str> {
        let jvm = (self.inputs.jvm_config_properties.values())
            .chain(environment.system_properties().values());
        (self.inputs.maven_config.iter())
            .chain(self.inputs.jvm_config.iter())
            .chain(jvm)
            .chain(&self.inputs.command_line.defines)
            .chain((self.plugin_trace().into_iter()).flat_map(|trace| &trace.args))
            .map(String::as_str)
            .collect()
    }

    /// The system properties `mvn`'s JVM takes from `.mvn/jvm.config` and
    /// the argument and VM options files it names, as that channel sets
    /// them, without the names the JVM, the `mvn` launcher or `MavenCli`
    /// set over them ([`rv_maven_model::fixed_over_jvm_config`]).
    pub fn jvm_config_properties(&self) -> &BTreeMap<String, String> {
        &self.inputs.jvm_config_properties
    }

    /// The environment of a model build for the platform `os`/`arch` and
    /// optional target `jdk`, in the selected Maven mode.
    pub fn model_environment(&self, os: &str, arch: &str, jdk: Option<&str>) -> ModelEnvironment {
        (self.host.environment_for(os, arch, jdk)).with_maven_mode(self.lock.maven.mode)
    }

    /// This test configuration with `mirrors` as its mirrors, in
    /// precedence order.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_mirrors(mut self, mirrors: Vec<MirrorConfig>) -> Self {
        (self.maven_data.mirrors, self.maven_data.redirect_origins) = split_mirrors(mirrors);
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
        // The repositories a test names are its raeva.toml's.
        let project = ConfigFile {
            repositories: Some(repositories.clone()).filter(|repos| !repos.is_empty()),
            ..ConfigFile::default()
        };
        let (repositories, defaults) = if repositories.is_empty() {
            (default_repositories(None), 1)
        } else {
            (repositories, 0)
        };
        let maven_data = MavenSettingsData {
            user_local_repository: None,
            maven_local_repository: None,
            user_urls: repositories.iter().map(|repo| repo.url.clone()).collect(),
            repositories,
            defaults,
            requested: 0,
            profile_plugin_repositories: Vec::new(),
            plugin_repositories: default_repositories(None),
            named_plugin_repositories: 0,
            request_repositories: Vec::new(),
            settings_endpoints: Vec::new(),
            mirrors: Vec::new(),
            redirect_origins: Vec::new(),
            auth: Vec::new(),
            auth_layers: AuthConfigLayers::default(),
            server_ids: Default::default(),
            basic_only_server_ids: Default::default(),
            proxies: Vec::new(),
            proxy_error: None,
            active_profiles: Vec::new(),
            active_settings_profiles: Vec::new(),
            activation_error: None,
            plugin_repository_error: None,
        };

        let host = HostSnapshot::for_testing(&security.allow_env_substitution)
            .with_reactor_root(&project_root);

        Self {
            network: NetworkConfig::default(),
            lock: LockConfig::default(),
            plugins: None,
            inactive_profiles: Vec::new(),
            security,
            paths,
            project_config_path: project_root.join("raeva.toml"),
            user_config_path: project_root.join("config.toml"),
            lock_path: project_root.join("raeva.lock"),
            settings_path: None,
            project_root,
            inputs: ConfigInputs {
                project,
                ..ConfigInputs::default()
            },
            maven_data,
            settings: None,
            host,
            settings_reads: SettingsReads::default(),
            repository_filters: Arc::default(),
            credential_scope: None,
            central_system: None,
            platform_error: None,
            host_session: None,
            host_paths: false,
        }
    }

    /// This configuration with `filters` as its remote repository filters.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_repository_filters(mut self, filters: RepositoryFilters) -> Self {
        self.repository_filters = Arc::new(filters);
        self
    }
}

const USER_HOME: &str = "user.home";

/// Maven's remote repository filters for the build: the
/// `aether.remoteRepositoryFilter.*` properties, which resolver reads from
/// the properties of the settings.xml profiles `<activeProfiles>` and `-P`
/// name, then the system properties (`.mvn/jvm.config`), then the user
/// properties (`-D` on the command line and in `.mvn/maven.config`), the
/// later winning, with the rule files they name. A relative basedir is taken
/// from the local repository Maven uses: `maven.repo.local`, else the
/// settings.xml `<localRepository>`, else `~/.m2/repository`, a relative one
/// from the working directory, as Maven takes it.
fn load_repository_filters(
    inputs: &ConfigInputs,
    settings: &MavenSettings,
    environment: &ModelEnvironment,
    mode: MavenMode,
) -> Result<RepositoryFilters, ConfigError> {
    let options = inputs.maven_options(environment);
    let home = inputs.user_home.clone();
    let mut properties = BTreeMap::new();
    let mut local_repository = None;
    let profile_properties = requested_profile_properties(inputs, settings, &options, mode);
    let sources = (profile_properties.iter().cloned())
        .chain(environment.system_properties().clone())
        .chain(options.properties.clone());
    for (name, value) in sources {
        if name.starts_with(crate::repository_filters::FILTER_PROPERTY_PREFIX) {
            properties.insert(name, value);
        } else if name == crate::maven_config::LOCAL_REPOSITORY_PROPERTY {
            local_repository = Some(PathBuf::from(value));
        }
    }
    let local_repository = local_repository
        .or_else(|| settings.local_repository.clone())
        .or_else(|| home.map(|home| home.join(".m2").join("repository")))
        .map(|path| std::path::absolute(&path).unwrap_or(path))
        .unwrap_or_default();
    let filters = RepositoryFilters::load(mode, properties, &local_repository)?;
    Ok(filters.with_profile_properties(profile_properties))
}

/// The properties of the settings.xml profiles Maven's session takes them
/// from, in file order: each profile `<activeProfiles>` or `-P` names, even
/// one `-P !id` turns off, and in Maven 3.10 also each `<activeByDefault>`
/// profile no `-P !id` turns off.
fn requested_profile_properties(
    inputs: &ConfigInputs,
    settings: &MavenSettings,
    options: &MavenConfigOptions,
    mode: MavenMode,
) -> Vec<(String, String)> {
    let explicit = explicit_active_profiles(inputs, settings);
    let named = |id: &String| {
        explicit
            .iter()
            .chain(&options.active_profiles)
            .any(|a| a == id)
    };
    let inactive = |id: &String| {
        (inputs.inactive_profiles.iter())
            .chain(&options.inactive_profiles)
            .any(|inactive| inactive == id)
    };
    let by_default = |profile: &MavenProfile| {
        mode == MavenMode::Maven310
            && (profile.activation.as_ref()).is_some_and(|activation| activation.active_by_default)
    };
    (settings.profiles.iter().flatten())
        .filter(|profile| named(&profile.id) || (by_default(profile) && !inactive(&profile.id)))
        .flat_map(|profile| profile.properties.iter())
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Where Maven's session reads its configuration properties.
struct SessionProperties<'a> {
    inputs: &'a ConfigInputs,
    environment: &'a ModelEnvironment,
    /// [`requested_profile_properties`].
    profiles: Vec<(String, String)>,
    jvm_config_path: &'a Path,
    maven_config_path: &'a Path,
    settings_path: Option<&'a PathBuf>,
}

impl SessionProperties<'_> {
    /// The value Maven's session takes for `name`, with the file it comes
    /// from: a user property (`-D` or `.mvn/maven.config`), else a system
    /// property (`.mvn/jvm.config`), else the last requested settings.xml
    /// profile's.
    fn get(&self, name: &str) -> Option<(String, ConfigOrigin)> {
        (self.inputs)
            .user_property(self.environment, name, self.maven_config_path)
            .or_else(|| {
                let value = self.environment.system_properties().get(name)?;
                let origin = ConfigOrigin::MavenConfig(self.jvm_config_path.into());
                Some((value.clone(), origin))
            })
            .or_else(|| {
                let (_, value) = self.profiles.iter().rfind(|(key, _)| key == name)?;
                let origin = ConfigOrigin::MavenSettings(self.settings_path?.clone());
                let value = rv_maven_model::expand_host_properties(value, self.environment);
                Some((value, origin))
            })
    }
}

/// Maven Central's URL in Maven 3.10, which binds the id `central`.
const MAVEN_310_CENTRAL: &str = "https://repo.maven.apache.org/maven2";

/// Maven 3.10's [`CredentialScope`]: `maven.repository.credentialScope`,
/// and each settings.xml server's username and password bound to the
/// origins of the mirrors and of the repositories of Maven's request with
/// its id, and of its `<repositoryOrigins>`. The user's `config.toml`
/// repositories and mirrors bind their ids as settings.xml's do; the
/// project's `raeva.toml`, like its POMs, binds none. A URL whose origin
/// raeva cannot tell as Maven does is refused when it would bind a
/// username and password.
fn credential_scope(
    session: &SessionProperties<'_>,
    settings: &MavenSettings,
    user_origin: &ConfigOrigin,
) -> Result<CredentialScope, ConfigError> {
    const SCOPE: &str = "maven.repository.credentialScope";
    let mut scope = match session.get(SCOPE) {
        None => CredentialScope::new(None).unwrap_or_default(),
        Some((value, origin)) => {
            CredentialScope::new(Some(&value)).ok_or_else(|| ConfigError::Invalid {
                origin,
                message: format!(
                    "{SCOPE} is none of origin, strict and id, which Maven 3.10 refuses"
                ),
            })?
        }
    };
    let to_descriptors = session.get("aether.remoteRepositoryManager.authToDescriptorRepositories");
    scope = scope.with_descriptors(
        to_descriptors.is_some_and(|(value, _)| value.eq_ignore_ascii_case("true")),
    );
    let bound: HashSet<&str> = (settings.servers.iter().flatten())
        .filter(|server| server.token.is_none())
        .filter_map(|server| server.id.as_deref())
        .collect();
    let settings_origin =
        || ConfigOrigin::MavenSettings(session.settings_path.cloned().unwrap_or_default());
    let user_origin = || user_origin.clone();
    let named: Vec<&MavenProfile> = (settings.profiles.iter().flatten())
        .filter(|profile| (settings.active_profiles.iter().flatten()).any(|id| *id == profile.id))
        .collect();
    // Maven's request keeps the first repository and plugin repository of
    // an id.
    let first_of_ids = |list: fn(&MavenProfile) -> &[RepoConfig]| {
        let mut ids = HashSet::new();
        (named.iter().flat_map(move |profile| list(profile)))
            .filter_map(|repo| Some((repo.id.as_deref()?, repo.url.as_str())))
            .filter(move |(id, _)| ids.insert(*id))
    };
    let requested = first_of_ids(|profile| &profile.repositories)
        .chain(first_of_ids(|profile| &profile.plugin_repositories))
        .map(|(id, url)| ("repository", id, url, settings_origin()));
    let raeva_central = RepoConfig::maven_central();
    let central = match &session.inputs.central {
        Some((url, _)) => vec![url.as_str()],
        None => vec![MAVEN_310_CENTRAL, raeva_central.url.as_str()],
    };
    // Maven adds Central to the request's repositories and to its plugin
    // repositories, each unless one has its id.
    let has_central = |list: fn(&MavenProfile) -> &[RepoConfig]| {
        (named.iter()).any(|profile| {
            list(profile)
                .iter()
                .any(|repo| repo.id.as_deref() == Some("central"))
        })
    };
    let injected = (!has_central(|profile| &profile.repositories)
        || !has_central(|profile| &profile.plugin_repositories))
    .then_some(central)
    .into_iter()
    .flatten()
    .map(|url| ("repository", "central", url, settings_origin()));
    let mirrors = (settings.mirrors.iter().flatten()).filter_map(|mirror| {
        Some((
            "mirror",
            mirror.id.as_deref()?,
            mirror.url.as_str(),
            settings_origin(),
        ))
    });
    let user = &session.inputs.user;
    let user_entries = (user.repositories.iter().flatten())
        .filter_map(|repo| {
            Some((
                "repository",
                repo.id.as_deref()?,
                repo.url.as_str(),
                user_origin(),
            ))
        })
        .chain((user.mirrors.iter().flatten()).filter_map(|mirror| {
            Some((
                "mirror",
                mirror.id.as_deref()?,
                mirror.url.as_str(),
                user_origin(),
            ))
        }));
    let origins = (settings.repository_origins.iter()).flat_map(|(id, origins)| {
        origins.iter().map(move |url| {
            (
                "<repositoryOrigin>",
                id.as_str(),
                url.as_str(),
                settings_origin(),
            )
        })
    });
    for (kind, id, url, origin) in mirrors
        .chain(requested)
        .chain(injected)
        .chain(user_entries)
        .chain(origins)
    {
        if bound.contains(id) && scope.declare(id, url).is_err() {
            return Err(ConfigError::Invalid {
                origin,
                message: format!(
                    "raeva cannot tell which origin Maven 3.10 reads in the URL of the {kind} \
                     {}, to which it binds the credentials of the server with that id; write the \
                     host in ASCII, as a name or an address",
                    rv_maven_types::bounded(id),
                ),
            });
        }
    }
    Ok(scope)
}

/// Session properties Maven reads that change what it resolves and raeva
/// does not read: the Maven line that reads one only one line reads, and
/// whether a value keeps Maven's default in a mode. raeva reads
/// [`COLLECTOR`] from `-D`, `.mvn/maven.config` and `.mvn/jvm.config`, but
/// not from a settings.xml profile.
#[rustfmt::skip]
const UNREAD_SESSION_PROPERTIES: &[(&str, Option<MavenMode>, KeepsDefault)] = &[
    ("maven.relocations.entries", Some(MavenMode::Maven310), |_, _| false),
    ("maven.session.versionFilter", Some(MavenMode::Maven310), |_, _| false),
    ("maven.resolver.dependencyManagerTransitivity", Some(MavenMode::Maven310),
        |value, _| !value.eq_ignore_ascii_case("true")),
    ("aether.conflictResolver.versionSelector.selectionStrategy", Some(MavenMode::Maven310),
        |value, _| value == "nearest"),
    ("aether.system.repositoryKeyFunction", Some(MavenMode::Maven310),
        |value, _| value.eq_ignore_ascii_case("nid_hurl")),
    ("aether.system.dependencyVisitor", Some(MavenMode::Maven310),
        |value, _| value == "levelOrder"),
    ("maven.versionRangeResolutionNature", None,
        |value, _| value.eq_ignore_ascii_case("release_or_snapshot")),
    (COLLECTOR, None,
        |value, mode| value == if mode == MavenMode::Maven39 { "df" } else { "bf" }),
];

const COLLECTOR: &str = "aether.dependencyCollector.impl";

type KeepsDefault = fn(&str, MavenMode) -> bool;

/// Refuse a property of [`UNREAD_SESSION_PROPERTIES`] that does not keep
/// Maven's default, naming the file of the value Maven takes: its session
/// takes the [`requested_profile_properties`], then the system properties
/// (`.mvn/jvm.config`), then the user properties (`-D` and
/// `.mvn/maven.config`), the later winning. raeva reads
/// `aether.dependencyCollector.impl` from the last two only, so one a
/// settings.xml profile alone sets must pick the mode's default collector.
/// `unread` says how a JVM option may set a name in a way raeva does not
/// read, such as a pattern the shell may expand, which may not keep it.
fn refuse_unread_session_properties(
    session: &SessionProperties<'_>,
    mode: MavenMode,
    unread: impl Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    for &(name, read_by, keeps_default) in UNREAD_SESSION_PROPERTIES {
        if read_by.is_some_and(|read_by| read_by != mode) {
            continue;
        }
        let Some((value, origin)) = session.get(name) else {
            if let Some(why) = unread(name) {
                return Err(ConfigError::UnreadHostProperty(format!(
                    "{why}, which Maven reads to resolve and raeva does not; set {name} without \
                     a pattern, or with -D"
                )));
            }
            continue;
        };
        let in_settings = matches!(origin, ConfigOrigin::MavenSettings(_));
        if keeps_default(&value, mode) || (name == COLLECTOR && !in_settings) {
            continue;
        }
        // The value is not shown: it may come from a secret's variable.
        let message = if name == COLLECTOR {
            format!(
                "{name} sets another collector than the default in a settings.xml profile, \
                 where raeva does not read it; set it with -D or in .mvn/maven.config"
            )
        } else {
            let line = if mode == MavenMode::Maven39 {
                "3.9"
            } else {
                "3.10"
            };
            format!(
                "{name}, as set here, changes what Maven {line} resolves, and raeva does not \
                 read it; remove it"
            )
        };
        return Err(ConfigError::Invalid { origin, message });
    }
    Ok(())
}

/// The repositories `list` gives each of the `active` settings.xml
/// profiles, as Maven injects the profiles into a project's model in turn:
/// each before what is there, its entry winning a shared id.
fn injected(
    active: &[&MavenProfile],
    list: impl Fn(&MavenProfile) -> &[RepoConfig],
) -> Vec<RepoConfig> {
    let mut merged: Vec<RepoConfig> = Vec::new();
    for profile in active.iter().rev() {
        let start = merged.len();
        for repo in list(profile) {
            match (merged.iter()).position(|known| repo.id.is_some() && known.id == repo.id) {
                // A second entry of an id in one profile takes the first's place.
                Some(at) if at >= start => merged[at] = repo.clone(),
                Some(_) => {}
                None => merged.push(repo.clone()),
            }
        }
    }
    merged
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

fn default_repositories(central: Option<&str>) -> Vec<RepoConfig> {
    let maven_central = RepoConfig::maven_central();
    vec![match central {
        Some(url) => RepoConfig {
            url: url.to_string(),
            ..maven_central
        },
        None => maven_central,
    }]
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

/// `value` with each `spellings` entry that names a whole directory there
/// replaced by its marker; see `Config::portable`. On Windows `/` and `\\`
/// are one separator.
fn with_markers(value: &str, spellings: &[(String, String)]) -> String {
    let same = |a: char, b: char| {
        a == b || (cfg!(windows) && matches!(a, '/' | '\\') && matches!(b, '/' | '\\'))
    };
    let strip = |text: &'_ str, prefix: &str| {
        let mut rest = text.chars();
        for wanted in prefix.chars() {
            if !same(rest.next()?, wanted) {
                return None;
            }
        }
        Some(rest.as_str().len())
    };
    let in_path = |c: char| c.is_alphanumeric() || "/\\.%".contains(c);
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    let mut before = None;
    'scan: while let Some(next) = rest.chars().next() {
        if !before.is_some_and(in_path) {
            for (spelling, marker) in spellings {
                if let Some(left) = strip(rest, spelling) {
                    let after = &rest[rest.len() - left..];
                    if after.is_empty() || after.starts_with(['/', '\\']) {
                        out.push_str(marker);
                        rest = after;
                        before = Some('/');
                        continue 'scan;
                    }
                }
            }
        }
        out.push(next);
        before = Some(next);
        rest = &rest[next.len_utf8()..];
    }
    out
}

/// How many directories `dir` is below `ancestor`, `None` when it is not
/// in it; `fold` compares the names in any letter case.
fn levels_below(dir: &Path, ancestor: &Path, fold: bool) -> Option<usize> {
    let name = |component: std::path::Component<'_>| {
        let text = component.as_os_str().to_string_lossy().into_owned();
        match fold {
            true => text.to_lowercase(),
            false => text,
        }
    };
    let mut below = dir.components();
    for component in ancestor.components() {
        if name(below.next()?) != name(component) {
            return None;
        }
    }
    Some(below.count())
}

/// Whether the file system that holds `dir` takes names that differ only
/// in letter case for one name, as Windows and macOS do by default: the
/// same directory answers `dir` with its last letter's case changed.
fn folds_case(dir: &Path) -> bool {
    if cfg!(windows) {
        return true;
    }
    let text = dir.to_string_lossy();
    let Some((at, letter)) =
        (text.char_indices().rev()).find(|(_, c)| c.is_lowercase() != c.is_uppercase())
    else {
        return false;
    };
    let flipped: String = match letter.is_lowercase() {
        true => letter.to_uppercase().collect(),
        false => letter.to_lowercase().collect(),
    };
    let other = format!(
        "{}{flipped}{}",
        &text[..at],
        &text[at + letter.len_utf8()..]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::metadata(dir), std::fs::metadata(&other)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = other;
        false
    }
}

/// A [`crate::maven_config::PropertyLookup`] replayed in one target
/// environment.
/// Whether the property `name` is the JDK's home, or `${...}` as written
/// without one.
fn is_jdk_home(name: &str) -> bool {
    matches!(name, "java.home" | "env.JAVA_HOME")
}

struct LookupReplay {
    environment: ModelEnvironment,
    ctx: ActivationContext,
    defines: HashMap<String, String>,
    properties: PropertyMap,
    expanded: Result<String, rv_maven_model::PomError>,
    reads: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        CommandLine, Config, ConfigFile, NetworkConfig, SecurityConfig, folds_case, levels_below,
        with_markers,
    };
    use crate::error::{ConfigError, ConfigOrigin};
    use std::fs;
    use std::path::Path;

    /// Runs `f` with `RAEVA_HOME` and the Maven user home at a fresh
    /// directory and no JDK, passing it and a fresh project directory.
    fn with_homes<T>(f: impl FnOnce(&Path, &Path) -> T) -> T {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home_dir = home.path().to_string_lossy().into_owned();
        let no_jdk = home.path().join("no-jdk").to_string_lossy().into_owned();
        temp_env::with_vars(
            [
                ("RAEVA_HOME", Some(home_dir.as_str())),
                ("HOME", Some(home_dir.as_str())),
                (crate::MAVEN_USER_HOME_TEST_ENV, Some(home_dir.as_str())),
                ("JAVA_HOME", None),
                (rv_maven_model::JAVA_PATH_TEST_ENV, Some(no_jdk.as_str())),
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

    /// Maven 3.10 binds a settings.xml server's username and password to
    /// the origins of the mirrors and of its request's repositories with
    /// the server's id, those of the profiles `<activeProfiles>` names and
    /// Central, and to the server's `<repositoryOrigins>`. The user's
    /// config.toml binds as settings.xml does; the 3.9 mode binds nothing.
    #[test]
    fn maven_310_binds_a_server_to_the_origins_maven_declares_for_its_id() {
        with_homes(|home, project| {
            let server = |id: &str, extra: &str| {
                format!(
                    "<server><id>{id}</id><username>u</username><password>p</password>{extra}</server>"
                )
            };
            let profile = |id: &str, repo: &str, url: &str| {
                format!(
                    "<profile><id>{id}</id><activation><activeByDefault>true</activeByDefault>\
                     </activation><repositories><repository><id>{repo}</id><url>{url}</url>\
                     </repository></repositories></profile>"
                )
            };
            write_settings(
                home,
                &format!(
                    "<settings><mirrors><mirror><id>mirrored</id><mirrorOf>x</mirrorOf>\
                     <url>https://mirror.example/m2</url></mirror></mirrors><servers>{}{}{}{}{}{}\
                     </servers><profiles>{}{}{}</profiles><activeProfiles>\
                     <activeProfile>named</activeProfile><activeProfile>later</activeProfile>\
                     </activeProfiles></settings>",
                    server("mirrored", ""),
                    server("requested", ""),
                    server("bydefault", ""),
                    server("central", ""),
                    server(
                        "listed",
                        "<repositoryOrigins><repositoryOrigin>https://Listed.example:443/path\
                         </repositoryOrigin></repositoryOrigins>"
                    ),
                    server("user", ""),
                    profile("named", "requested", "https://requested.example/m2"),
                    profile("later", "requested", "https://second.example/m2"),
                    profile("default", "bydefault", "https://default.example/m2"),
                ),
            );
            fs::write(
                home.join("config.toml"),
                "[[repositories]]\nid = 'user'\nurl = 'https://user.example/m2'\n",
            )
            .unwrap();
            fs::write(project.join("raeva.toml"), "[lock]\nmaven = '3.9'\n").unwrap();
            assert!(Config::load(project).unwrap().credential_scope().is_none());
            fs::write(project.join("raeva.toml"), "[lock]\nmaven = '3.10'\n").unwrap();
            let config = Config::load(project).unwrap();
            let scope = config.credential_scope().unwrap();
            for (id, url, sends) in [
                ("mirrored", "https://mirror.example/other", true),
                ("mirrored", "https://repo.example/", false),
                ("requested", "https://requested.example/", true),
                ("requested", "https://second.example/m2", false),
                ("bydefault", "https://default.example/m2", true),
                ("central", "https://repo.maven.apache.org/maven2/", true),
                ("central", "https://repo1.maven.org/maven2/", true),
                ("central", "https://nexus.example/central/", false),
                ("listed", "https://listed.example/m2", true),
                ("listed", "http://listed.example/m2", false),
                ("user", "https://user.example/m2", true),
                ("user", "https://project.example/m2", false),
            ] {
                assert_eq!(scope.sends(id, url), sends, "{id} {url}");
            }
            assert!(!scope.to_descriptors());

            fs::create_dir_all(project.join(".mvn")).unwrap();
            for (options, refused) in [
                ("-Dmaven.repository.credentialScope=strict", false),
                ("-Dmaven.repository.credentialScope=Strict", true),
            ] {
                fs::write(project.join(".mvn/maven.config"), format!("{options}\n")).unwrap();
                let config = Config::load(project);
                assert_eq!(config.is_err(), refused, "{options}");
                if let Ok(config) = config {
                    let scope = config.credential_scope().unwrap();
                    assert!(!scope.sends("bydefault", "https://default.example/m2"));
                    assert!(scope.sends("requested", "https://requested.example/"));
                }
            }
        });
    }

    /// Maven adds Central to its request's repositories and to its plugin
    /// repositories apart, so a settings.xml repository `central` leaves
    /// Central's origin bound for the plugin repositories.
    #[test]
    fn central_stays_bound_for_the_plugin_repositories_a_profile_leaves_it_in() {
        with_homes(|home, project| {
            fs::write(project.join("raeva.toml"), "[lock]\nmaven = '3.10'\n").unwrap();
            fs::create_dir_all(project.join(".mvn")).unwrap();
            fs::write(
                project.join(".mvn/maven.config"),
                "-Dmaven.repo.central=https://plugins.example/m2\n",
            )
            .unwrap();
            let repo = |kind: &str| {
                format!("<{kind}><id>central</id><url>https://deps.example/m2</url></{kind}>")
            };
            for (plugin_repositories, plugins_bound) in [
                (String::new(), true),
                (
                    format!(
                        "<pluginRepositories>{}</pluginRepositories>",
                        repo("pluginRepository")
                    ),
                    false,
                ),
            ] {
                write_settings(
                    home,
                    &format!(
                        "<settings><servers><server><id>central</id><username>u</username>\
                         <password>p</password></server></servers><profiles><profile><id>p</id>\
                         <repositories>{}</repositories>{plugin_repositories}</profile>\
                         </profiles><activeProfiles><activeProfile>p</activeProfile>\
                         </activeProfiles></settings>",
                        repo("repository")
                    ),
                );
                let config = Config::load(project).unwrap();
                let scope = config.credential_scope().unwrap();
                assert!(scope.sends("central", "https://deps.example/"));
                assert_eq!(
                    scope.sends("central", "https://plugins.example/m2"),
                    plugins_bound,
                    "{plugin_repositories}"
                );
            }
        });
    }

    /// A `<repositoryOrigin>` Maven 3.10 refuses fails the build there, so
    /// raeva refuses it in that mode, as it does a mirror or repository URL
    /// whose origin it cannot tell as Maven does when it binds a server's
    /// username and password. The 3.9 mode reads neither.
    #[test]
    fn origins_maven_310_refuses_or_raeva_cannot_tell_are_refused() {
        with_homes(|home, project| {
            for (settings, refused) in [
                (
                    "<servers><server><id>s</id><repositoryOrigins><repositoryOrigin>\
                  https://h:1:2/</repositoryOrigin></repositoryOrigins></server></servers>",
                    true,
                ),
                (
                    "<servers><server><id>s</id><repositoryOrigins><repositoryOrigin>\
                  https://user:pw@h/</repositoryOrigin></repositoryOrigins></server></servers>",
                    true,
                ),
                (
                    "<servers><server><id>s</id><repositoryOrigins><repositoryOrigin>\
                  https://h/</repositoryOrigin></repositoryOrigins></server></servers>",
                    false,
                ),
                (
                    "<mirrors><mirror><id>s</id><mirrorOf>x</mirrorOf><url>https://h\u{e9}.example/</url>\
                  </mirror></mirrors><servers><server><id>s</id><username>u</username>\
                  <password>p</password></server></servers>",
                    true,
                ),
                (
                    "<mirrors><mirror><id>s</id><mirrorOf>x</mirrorOf><url>https://h\u{e9}.example/</url>\
                  </mirror></mirrors>",
                    false,
                ),
            ] {
                write_settings(home, &format!("<settings>{settings}</settings>"));
                for (mode, mode_refused) in [("3.9", false), ("3.10", refused)] {
                    fs::write(
                        project.join("raeva.toml"),
                        format!("[lock]\nmaven = '{mode}'\n"),
                    )
                    .unwrap();
                    let load = Config::load(project);
                    assert_eq!(load.is_err(), mode_refused, "{mode} {settings}");
                    if let Err(err) = load {
                        assert!(!err.to_string().contains("pw@"), "{err}");
                    }
                }
            }
        });
    }

    /// A settings.xml proxy with a broken port is read as port 0, as Maven
    /// reads it, so it fails only a fetch it carries and leaves the other
    /// proxies working.
    #[test]
    fn a_settings_proxy_port_error_fails_only_that_proxy() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><proxies><proxy><id>bad</id><protocol>http</protocol>\
                 <host>proxy.example</host><port>not-a-number</port></proxy><proxy>\
                 <id>good</id><protocol>https</protocol><host>proxy.example</host>\
                 <port>8443</port></proxy></proxies></settings>",
            );
            let config = Config::load(project).unwrap();
            assert_eq!(config.proxy_error(), None);
            let ports: Vec<u16> = config.proxies().iter().map(|proxy| proxy.port).collect();
            assert_eq!(ports, [0, 8443]);
        });
    }

    /// A mirror of no repository only names an origin a proxied redirect
    /// may reach: no repository goes to it, and the credentials that the
    /// user's own endpoints unlock stay off it.
    #[test]
    fn a_mirror_of_no_repository_only_names_a_redirect_origin() {
        with_homes(|home, project| {
            let (storage, blank) = ("https://storage.example/", "https://blank.example/");
            fs::write(
                home.join("config.toml"),
                format!("[[mirrors]]\nid = 'storage'\nurl = '{storage}'\n"),
            )
            .unwrap();
            write_settings(
                home,
                &format!(
                    "<settings><mirrors><mirror><id>blank</id><mirrorOf></mirrorOf>\
                     <url>{blank}</url></mirror></mirrors></settings>"
                ),
            );
            let config = Config::load(project).unwrap();
            assert!(config.mirrors().is_empty());
            let endpoints = config.user_endpoint_urls();
            assert!(!endpoints.iter().any(|url| url == storage || url == blank));
            assert_eq!(config.redirect_origins(), [storage, blank]);
        });
    }

    /// Maven's request keeps the first mirror of an id. raeva puts the
    /// user `config.toml` mirrors before the `settings.xml` ones, so a
    /// `settings.xml` mirror whose id a `config.toml` mirror has is not
    /// used, nor is a later `config.toml` mirror of an earlier one's id. A
    /// `config.toml` mirror without an id shares none, while a
    /// `settings.xml` one is `default`.
    #[test]
    fn a_settings_mirror_with_a_user_mirrors_id_is_not_used() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><mirrors>\
                 <mirror><id>m</id><url>https://settings.example/m/</url><mirrorOf>other</mirrorOf></mirror>\
                 <mirror><url>https://settings.example/d/</url><mirrorOf>third</mirrorOf></mirror>\
                 <mirror><id>s</id><url>https://settings.example/s/</url><mirrorOf>fourth</mirrorOf></mirror>\
                 <mirror><id>default</id><url>https://settings.example/d2/</url><mirrorOf>x</mirrorOf></mirror>\
                 </mirrors></settings>",
            );
            fs::write(
                home.join("config.toml"),
                "[[mirrors]]\nid = 'm'\nurl = 'https://user.example/m/'\nmirror_of = ['central']\n\
                 [[mirrors]]\nurl = 'https://user.example/d/'\nmirror_of = ['fifth']\n\
                 [[mirrors]]\nid = 'm'\nurl = 'https://user.example/m2/'\nmirror_of = ['sixth']\n\
                 [[mirrors]]\nurl = 'https://storage-a.example/'\n\
                 [[mirrors]]\nurl = 'https://storage-b.example/'\n",
            )
            .unwrap();
            let config = Config::load(project).unwrap();
            let urls: Vec<_> = config.mirrors().iter().map(|m| m.url.as_str()).collect();
            assert_eq!(
                urls,
                [
                    "https://user.example/m/",
                    "https://user.example/d/",
                    "https://settings.example/d/",
                    "https://settings.example/s/"
                ]
            );
            assert_eq!(
                config.redirect_origins(),
                ["https://storage-a.example/", "https://storage-b.example/"]
            );
            assert!(!(config.user_endpoint_urls().iter()).any(|url| {
                url.starts_with("https://settings.example/m")
                    || url.starts_with("https://settings.example/d2")
                    || url.starts_with("https://user.example/m2")
            }));
        });
    }

    /// A settings file `.mvn/maven.config` names is the project's choice: its
    /// repositories and mirrors get no `[[auth]]` entry without an id, and
    /// its `<localRepository>` is not where export-m2 writes.
    #[test]
    fn a_settings_file_the_project_names_is_not_the_users() {
        with_homes(|home, project| {
            fs::create_dir_all(project.join(".mvn")).unwrap();
            fs::write(
                project.join(".mvn/maven.config"),
                "-s\n${session.rootDirectory}/team.xml\n",
            )
            .unwrap();
            fs::write(
                project.join("team.xml"),
                "<settings><localRepository>/tmp/team-m2</localRepository>\
                 <mirrors><mirror><id>tm</id><url>https://team.example/m/</url>\
                 <mirrorOf>other</mirrorOf></mirror></mirrors>\
                 <profiles><profile><id>p</id><repositories><repository><id>ext</id>\
                 <url>https://team.example/ext/</url></repository></repositories></profile>\
                 </profiles><activeProfiles><activeProfile>p</activeProfile></activeProfiles>\
                 </settings>",
            )
            .unwrap();
            fs::write(
                home.join("config.toml"),
                "[[mirrors]]\nid = 'own'\nurl = 'https://user.example/m/'\nmirror_of = ['third']\n",
            )
            .unwrap();
            let config = Config::load(project).unwrap();
            let urls = config.user_endpoint_urls();
            assert!(
                urls.iter().any(|url| url == "https://user.example/m/"),
                "{urls:?}"
            );
            assert!(
                !urls.iter().any(|url| url.contains("team.example")),
                "{urls:?}"
            );
            assert!(
                config
                    .repositories()
                    .iter()
                    .any(|repo| repo.url.contains("team.example/ext"))
            );
            assert!(config.user_local_repository().is_none());
            assert!(config.project_settings_local_repository());
        });
    }

    /// A settings.xml mirror that a config.toml mirror's id puts out of use
    /// names no stored URL, so a mirror in use at the same secret URL
    /// stores its rows under its own id.
    #[test]
    fn a_settings_mirror_out_of_use_names_no_stored_url() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><mirrors>\
                 <mirror><id>n7m</id><url>https://n7.example/${env.N7_TOKEN_A}/</url><mirrorOf>other</mirrorOf></mirror>\
                 <mirror><id>n7s</id><url>https://n7.example/${env.N7_TOKEN_B}/</url><mirrorOf>fourth</mirrorOf></mirror>\
                 </mirrors></settings>",
            );
            fs::write(
                home.join("config.toml"),
                "[[mirrors]]\nid = 'n7m'\nurl = 'https://user.example/m/'\nmirror_of = ['central']\n",
            )
            .unwrap();
            let tokens = [
                ("N7_TOKEN_A", Some("tok-n7")),
                ("N7_TOKEN_B", Some("tok-n7")),
            ];
            temp_env::with_vars(tokens, || Config::load(project).unwrap());
            assert_eq!(
                crate::redact::stored_urls("https://n7.example/tok-n7/"),
                "mirror:n7s/"
            );
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
            assert!(config.redirect_origins().is_empty());
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

    /// Maven 3.9.12 and 3.10.0 fail the build on a settings.xml profile
    /// whose condition is in error, `activeByDefault` or not.
    #[test]
    fn a_settings_activation_error_fails_the_load() {
        let broken = "<property><name></name><value>x</value></property>";
        let profile = |id: &str, activation: &str| {
            format!("<profile>{id}<activation>{activation}</activation></profile>")
        };
        let ok = profile("<id>p</id>", "<property><name>!nope</name></property>");
        with_homes(|home, project| {
            for (profiles, error) in [
                (
                    profile("<id>p</id>", broken),
                    "The property name is required to activate the profile p",
                ),
                (
                    profile(
                        "<id>p</id>",
                        "<activeByDefault>true</activeByDefault><os><version>regex:[</version></os>",
                    ),
                    "Failed to determine activation for profile p",
                ),
                // Maven names a profile without an id `default`, and tests
                // each condition unless `-P` selected the id.
                (
                    profile("", broken),
                    "The property name is required to activate the profile default",
                ),
                (
                    format!("{ok}{}", profile("<id>p</id>", broken)),
                    "The property name is required to activate the profile p",
                ),
            ] {
                write_settings(
                    home,
                    &format!("<settings><profiles>{profiles}</profiles></settings>"),
                );
                let message = Config::load(project).unwrap_err().to_string();
                assert!(message.contains(error), "{message}");
            }
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

    /// Maven interpolates settings.xml with `-D` and the system properties,
    /// so `${user.home}` and a `-D` value fill a mirror and a repository URL.
    #[test]
    fn settings_urls_take_user_home_and_user_properties() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><mirrors><mirror><id>local</id><url>file://${user.home}/m2/</url>\
                 <mirrorOf>central</mirrorOf></mirror></mirrors><profiles><profile><id>corp</id>\
                 <repositories><repository><id>corp</id><url>${repo.url}</url></repository>\
                 </repositories></profile></profiles>\
                 <activeProfiles><activeProfile>corp</activeProfile></activeProfiles></settings>",
            );
            let command_line = CommandLine {
                defines: vec!["repo.url=https://repo.example/maven/".to_string()],
                ..CommandLine::default()
            };
            let config = Config::load_with_command_line(project, &command_line).unwrap();
            // Maven pastes the value as it is, on Windows `file://C:\home\m2/`,
            // which its file transporter and raeva both read as that directory.
            let mirror = &config.mirrors()[0].url;
            assert_eq!(*mirror, format!("file://{}/m2/", home.display()));
            let read = url::Url::parse(mirror).unwrap().to_file_path().unwrap();
            assert_eq!(read, home.join("m2"));
            assert_eq!(config.repositories()[0].url, "https://repo.example/maven/");

            // Maven expands it with a `-D` of the project's `.mvn/` files,
            // the command line's first.
            write_settings(
                home,
                "<settings><localRepository>${m2}</localRepository></settings>",
            );
            fs::create_dir_all(project.join(".mvn")).unwrap();
            for (file, other) in [
                ("maven.config", "jvm.config"),
                ("jvm.config", "maven.config"),
            ] {
                let _ = fs::remove_file(project.join(".mvn").join(other));
                fs::write(project.join(".mvn").join(file), "-Dm2=/elsewhere\n").unwrap();
                let config = Config::load(project).unwrap();
                assert_eq!(
                    config.user_local_repository(),
                    Some(Path::new("/elsewhere"))
                );
                let defined = CommandLine {
                    defines: vec!["m2=/cli".to_string()],
                    ..CommandLine::default()
                };
                let config = Config::load_with_command_line(project, &defined).unwrap();
                assert_eq!(config.user_local_repository(), Some(Path::new("/cli")));
            }
        });
    }

    /// Maven's sec-dispatcher reads the master password from the file
    /// `-Dsettings.security` names, a leading `~` the home directory.
    #[test]
    fn settings_security_names_the_master_password_file() {
        with_homes(|home, project| {
            let password = crate::encryption::encrypt_for_tests(b"s3cret", "master", [7; 8]);
            write_settings(
                home,
                &format!(
                    "<settings><servers><server><id>corp</id><username>u</username>\
                     <password>{password}</password></server></servers></settings>"
                ),
            );
            fs::create_dir_all(home.join("sec")).unwrap();
            fs::write(
                home.join("sec/settings-security.xml"),
                "<settingsSecurity><master>master</master></settingsSecurity>",
            )
            .unwrap();
            let password = |defines: Vec<String>| {
                let command_line = CommandLine {
                    defines,
                    ..CommandLine::default()
                };
                let config = Config::load_with_command_line(project, &command_line).unwrap();
                let server = &config.auth_layers().settings()[0];
                (server.password.as_ref())
                    .map(|p| secrecy::ExposeSecret::expose_secret(p).to_string())
            };
            assert_eq!(password(Vec::new()), None);
            let relocated = "settings.security=~/sec/settings-security.xml";
            fs::create_dir_all(project.join(".mvn")).unwrap();
            fs::write(
                project.join(".mvn/maven.config"),
                format!("-D{relocated}\n"),
            )
            .unwrap();
            assert_eq!(password(Vec::new()), None);
            assert_eq!(
                password(vec![relocated.to_string()]).as_deref(),
                Some("s3cret")
            );
        });
    }

    /// Maven's settings model names a profile without an `<id>` `default`,
    /// so `<activeProfiles>` and `<activeByDefault>` both activate one.
    #[test]
    fn a_settings_profile_without_an_id_is_named_default() {
        with_homes(|home, project| {
            for (activation, by_default) in [
                (
                    "<activeProfiles><activeProfile>default</activeProfile></activeProfiles>",
                    "",
                ),
                (
                    "",
                    "<activation><activeByDefault>true</activeByDefault></activation>",
                ),
            ] {
                write_settings(
                    home,
                    &format!(
                        "<settings>{activation}<profiles><profile>{by_default}<repositories>\
                         <repository><id>corp</id><url>https://corp.example/m2/</url>\
                         </repository></repositories></profile></profiles></settings>"
                    ),
                );
                let config = Config::load(project).unwrap();
                assert_eq!(ids(config.repositories(), |r| &r.id), ["corp", "central"]);
                assert_eq!(config.active_settings_profiles(), ["default"]);
            }
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

    /// In the Maven 3.10 mode, `maven.repo.central` replaces Central's URL
    /// as Maven 3.10 sets it: a command-line `-D`, then a `.mvn/maven.config`
    /// one, then `MAVEN_REPO_CENTRAL`, then a `.mvn/jvm.config` `-D`. The
    /// 3.9 mode and a configured `central` keep it.
    #[test]
    fn maven_310_replaces_central_with_maven_repo_central() {
        with_homes(|home, project| {
            fs::create_dir_all(project.join(".mvn")).unwrap();
            let jvm = project.join(".mvn").join("jvm.config");
            let maven_config = project.join(".mvn").join("maven.config");
            let load = |mode: &str,
                        cli: Option<&str>,
                        file: Option<&str>,
                        env: Option<&str>,
                        jvm_value: Option<&str>| {
                fs::write(
                    project.join("raeva.toml"),
                    format!("[lock]\nmaven = '{mode}'\n"),
                )
                .unwrap();
                let define = |url| format!("-Dmaven.repo.central={url}\n");
                fs::write(&maven_config, file.map(define).unwrap_or_default()).unwrap();
                fs::write(&jvm, jvm_value.map(define).unwrap_or_default()).unwrap();
                let command_line = CommandLine {
                    defines: cli
                        .map(|url| format!("maven.repo.central={url}"))
                        .into_iter()
                        .collect(),
                    ..CommandLine::default()
                };
                temp_env::with_var(super::MAVEN_REPO_CENTRAL_ENV, env, || {
                    Config::load_with_command_line(project, &command_line)
                })
            };
            let central = |config: &Config| {
                let replaced = config.replaced_central().map(|(url, origin)| {
                    assert_eq!(config.default_repositories()[0].url, url);
                    (url.to_string(), origin.to_string())
                });
                assert_eq!(ids(config.default_repositories(), |r| &r.id), ["central"]);
                replaced
            };
            let (a, b, c, d) = (
                "https://a.example/m2",
                "https://b.example/m2",
                "https://c.example/m2",
                "https://d.example/m2",
            );
            let jvm_origin = jvm.display().to_string();
            let file_origin = maven_config.display().to_string();
            for (cli, file, env, jvm_value, expected) in [
                (
                    Some(a),
                    Some(b),
                    Some(c),
                    Some(d),
                    Some((a, "-D or -P option")),
                ),
                (
                    None,
                    Some(b),
                    Some(c),
                    Some(d),
                    Some((b, file_origin.as_str())),
                ),
                (
                    None,
                    None,
                    Some(c),
                    Some(d),
                    Some((c, "environment variable MAVEN_REPO_CENTRAL")),
                ),
                (None, None, None, Some(d), Some((d, jvm_origin.as_str()))),
                (None, None, None, None, None),
            ] {
                let config = load("3.10", cli, file, env, jvm_value).unwrap();
                let expected = expected.map(|(url, origin)| (url.to_string(), origin.to_string()));
                assert_eq!(central(&config), expected, "{cli:?} {file:?} {env:?}");
                // Only a Central the user chose gets the user's credentials.
                let user_chose = cli.is_some() || (file.is_none() && env.is_some());
                let url = &config.default_repositories()[0].url;
                assert_eq!(
                    config.user_endpoint_urls().contains(url),
                    expected.is_none() || user_chose,
                    "{cli:?} {file:?} {env:?}"
                );
                if expected.is_none() {
                    assert_eq!(
                        config.default_repositories()[0].url,
                        crate::RepoConfig::maven_central().url
                    );
                }
                let config = load("3.9", cli, file, env, jvm_value).unwrap();
                assert_eq!(central(&config), None);
                assert_eq!(
                    config.default_repositories()[0].url,
                    crate::RepoConfig::maven_central().url
                );
            }
            // A MAVEN_REPO_CENTRAL value reaches POM interpolation as the
            // system property, over the jvm.config one. Every environment the
            // configuration replays lock inputs in is in the mode.
            let config = load("3.10", None, None, Some(c), Some(d)).unwrap();
            assert!(
                (config.target_environments().iter())
                    .all(|environment| environment.maven_mode()
                        == rv_maven_types::MavenMode::Maven310)
            );
            assert_eq!(
                config.host.host_environment().system_properties()["maven.repo.central"],
                c
            );
            // A configured `central` keeps its URL.
            write_settings(
                home,
                "<settings><profiles><profile><id>p</id><activation>\
                 <activeByDefault>true</activeByDefault></activation><repositories>\
                 <repository><id>central</id><url>https://central.example/m2/</url>\
                 </repository></repositories></profile></profiles></settings>",
            );
            let config = load("3.10", None, None, Some(c), None).unwrap();
            assert_eq!(config.replaced_central(), None);
            assert_eq!(config.repositories()[0].url, "https://central.example/m2/");
        });
    }

    /// The reactor root is the canonical project directory, as the module
    /// directories the root directory search walks from are.
    #[cfg(unix)]
    #[test]
    fn the_reactor_root_is_canonical() {
        with_homes(|home, project| {
            let link = home.join("link");
            std::os::unix::fs::symlink(project, &link).unwrap();
            let config = Config::load(&link.join(".")).unwrap();
            assert_eq!(
                config.host.host_environment().reactor_root(),
                Some(fs::canonicalize(project).unwrap().as_path())
            );
        });
    }

    /// A Central URL is untrusted input: one raeva could not use and one
    /// with a credential, query or fragment are refused, naming where it
    /// was set and never the URL.
    #[test]
    fn maven_310_refuses_an_unusable_central() {
        with_homes(|_, project| {
            fs::write(project.join("raeva.toml"), "[lock]\nmaven = '3.10'\n").unwrap();
            let load = |url: &str| {
                temp_env::with_var(super::MAVEN_REPO_CENTRAL_ENV, Some(url), || {
                    Config::load(project)
                })
            };
            for (url, problem) in [
                ("https://user:s3cret@repo.example/m2", "has userinfo"),
                ("https://s3cret@repo.example/m2", "has userinfo"),
                ("https://repo.example/m2?token=s3cret", "has a query"),
                ("https://repo.example/m2#s3cret", "has a fragment"),
                ("ftp://repo.example/s3cret", "has scheme 'ftp'"),
                ("s3cret", "is not a URL"),
                ("", "is not a URL"),
                (" https://repo.example/s3cret", "whitespace"),
            ] {
                let error = load(url).unwrap_err().to_string();
                assert!(error.contains(problem), "{url}: {error}");
                assert!(error.contains("MAVEN_REPO_CENTRAL"), "{url}: {error}");
                assert!(!error.contains("s3cret"), "{url}: {error}");
            }
            // Plain HTTP to another host is the HTTP blocker's to refuse.
            for url in [
                "http://localhost:8081/m2",
                "http://127.0.0.1/m2",
                "http://repo.example/m2",
                "file:///srv/m2",
            ] {
                let config = load(url).unwrap();
                assert_eq!(config.default_repositories()[0].url, url);
            }
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                let error = super::central_from_env(Some(std::ffi::OsString::from_vec(
                    b"https://\xff".into(),
                )))
                .unwrap_err();
                assert!(error.to_string().contains("not UTF-8"), "{error}");
            }
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
                         `network`, `lock`, `plugins`, `active_profiles`, `inactive_profiles`, \
                         `security`",
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

    /// A session property Maven reads that changes what it resolves and
    /// raeva does not read fails the load (exit 3) in the modes whose Maven
    /// reads it, from `.mvn/maven.config`, `.mvn/jvm.config` or a requested
    /// settings.xml profile, unless it keeps Maven's default.
    #[test]
    fn session_properties_raeva_does_not_read_are_refused() {
        with_homes(|home, project| {
            let mvn = project.join(".mvn");
            fs::create_dir_all(&mvn).unwrap();
            #[rustfmt::skip]
            let cases: &[(&str, &str, bool, bool)] = &[
                // (name, value, refused in 3.9, refused in 3.10)
                ("maven.relocations.entries", "g:a:*>g:b:*", false, true),
                ("maven.session.versionFilter", "l(1)", false, true),
                ("maven.resolver.dependencyManagerTransitivity", "TRUE", false, true),
                ("maven.resolver.dependencyManagerTransitivity", "false", false, false),
                ("aether.conflictResolver.versionSelector.selectionStrategy", "highest", false, true),
                ("aether.conflictResolver.versionSelector.selectionStrategy", "nearest", false, false),
                ("aether.system.repositoryKeyFunction", "simple", false, true),
                ("aether.system.repositoryKeyFunction", "NID_HURL", false, false),
                ("aether.system.dependencyVisitor", "preOrder", false, true),
                ("aether.system.dependencyVisitor", "levelOrder", false, false),
                ("maven.versionRangeResolutionNature", "release", true, true),
                ("maven.versionRangeResolutionNature", "release_or_snapshot", false, false),
            ];
            for (name, value, in_39, in_310) in cases {
                for source in ["maven.config", "jvm.config", "settings.xml"] {
                    let _ = fs::remove_file(mvn.join("maven.config"));
                    let _ = fs::remove_file(mvn.join("jvm.config"));
                    write_settings(home, "<settings/>");
                    match source {
                        "settings.xml" => write_settings(
                            home,
                            &format!(
                                "<settings><profiles><profile><id>p</id><properties>\
                                 <{name}>{}</{name}></properties></profile></profiles>\
                                 <activeProfiles><activeProfile>p</activeProfile>\
                                 </activeProfiles></settings>",
                                value.replace('>', "&gt;")
                            ),
                        ),
                        file => fs::write(mvn.join(file), format!("-D{name}={value}\n")).unwrap(),
                    }
                    for (mode, refused) in [("3.9", in_39), ("3.10", in_310)] {
                        fs::write(
                            project.join("raeva.toml"),
                            format!("[lock]\nmaven = '{mode}'\n"),
                        )
                        .unwrap();
                        let load = Config::load(project);
                        let case = format!("{name}={value} from {source} in {mode}");
                        match load {
                            Ok(_) => assert!(!refused, "{case} loaded"),
                            Err(error) => {
                                let message = error.to_string();
                                assert!(*refused, "{case}: {message}");
                                assert!(
                                    message.contains(name) && message.contains(source),
                                    "{case}: {message}"
                                );
                                // A value may come from a secret's variable.
                                assert!(!message.contains(value), "{case}: {message}");
                            }
                        }
                    }
                }
            }
        });
    }

    /// raeva reads `aether.dependencyCollector.impl` from `-D`,
    /// `.mvn/maven.config` and `.mvn/jvm.config`, so a settings.xml
    /// profile's that picks another collector than the mode's default and
    /// that none of those override fails the load.
    #[test]
    fn a_settings_profile_collector_is_refused_unless_it_is_the_default() {
        with_homes(|home, project| {
            let profile = |value: &str| {
                format!(
                    "<settings><profiles><profile><id>p</id><properties>\
                     <aether.dependencyCollector.impl>{value}</aether.dependencyCollector.impl>\
                     </properties></profile></profiles><activeProfiles>\
                     <activeProfile>p</activeProfile></activeProfiles></settings>"
                )
            };
            for (mode, value, refused) in [
                ("3.9", "df", false),
                ("3.9", "bf", true),
                ("3.10", "bf", false),
                ("3.10", "df", true),
            ] {
                fs::write(
                    project.join("raeva.toml"),
                    format!("[lock]\nmaven = '{mode}'\n"),
                )
                .unwrap();
                write_settings(home, &profile(value));
                let load = Config::load(project);
                assert_eq!(load.is_err(), refused, "{mode} {value}");
                fs::create_dir_all(project.join(".mvn")).unwrap();
                let other = if value == "df" { "bf" } else { "df" };
                fs::write(
                    project.join(".mvn/maven.config"),
                    format!("-Daether.dependencyCollector.impl={other}\n"),
                )
                .unwrap();
                Config::load(project).unwrap();
                fs::remove_file(project.join(".mvn/maven.config")).unwrap();
            }
        });
    }

    /// A settings.xml repository or mirror URL that does not parse, or
    /// that raeva does not read, is skipped with a warning that shows
    /// neither the URL nor its scheme, as Maven skips it. One without a
    /// scheme Maven 3.10 reads as a directory, and so does that mode.
    #[test]
    fn settings_urls_raeva_cannot_read_are_skipped() {
        with_homes(|home, project| {
            let profile = |url: &str| {
                format!(
                    "<settings><profiles><profile><id>p</id><repositories><repository>\
                     <id>r</id><url>{url}</url></repository></repositories></profile>\
                     </profiles><activeProfiles><activeProfile>p</activeProfile>\
                     </activeProfiles></settings>"
                )
            };
            let mirror = |url: &str| {
                format!(
                    "<settings><mirrors><mirror><id>m</id><url>{url}</url>\
                     <mirrorOf>other</mirrorOf></mirror></mirrors></settings>"
                )
            };
            for (xml, entry) in [
                (profile("http://[::1"), "repository 'r'"),
                (profile("https://[secret"), "repository 'r'"),
                (profile("http://127.0.0.1:99999/"), "repository 'r'"),
                (profile("secret://repo.example/maven2/"), "repository 'r'"),
                (profile("/srv/secret"), "repository 'r'"),
                (mirror("https://[secret"), "mirror 'm'"),
                (mirror("secret://repo.example/maven2/"), "mirror 'm'"),
            ] {
                write_settings(home, &xml);
                let (config, warnings) =
                    crate::test_warnings::capture_warnings(|| Config::load(project));
                config.unwrap();
                let [warning] = &warnings[..] else {
                    panic!("{warnings:?}");
                };
                assert_eq!(warning.sec_code.as_deref(), Some("SETTING_IGNORED"));
                assert!(warning.message.contains(entry), "{}", warning.message);
                assert!(!warning.message.contains("secret"), "{}", warning.message);
            }
            // Maven 3.10 reads a path without a scheme as a directory, and
            // so does that mode, in every profile.
            fs::write(project.join("raeva.toml"), "[lock]\nmaven = '3.10'\n").unwrap();
            write_settings(home, &profile("/srv/secret"));
            let (config, warnings) =
                crate::test_warnings::capture_warnings(|| Config::load(project));
            let config = config.unwrap();
            assert!(warnings.is_empty(), "{warnings:?}");
            let urls: Vec<_> = config
                .all_repositories()
                .map(|repo| repo.url.clone())
                .collect();
            // On Windows the path is on the project's drive, as `new File`
            // reads it from the project directory.
            let srv = match project.components().next() {
                Some(std::path::Component::Prefix(drive)) => {
                    std::path::PathBuf::from(drive.as_os_str())
                        .join(std::path::MAIN_SEPARATOR_STR)
                        .join("srv/secret")
                }
                _ => std::path::PathBuf::from("/srv/secret"),
            };
            let srv = rv_maven_model::directory_uri(&srv);
            assert!(urls.contains(&srv), "{urls:?}");
        });
    }

    /// raeva.lock records repository URLs as written, so none may carry a
    /// secret, in any file. A mirror's is not recorded, but its query would
    /// be dropped.
    #[test]
    fn repository_urls_with_secrets_are_refused() {
        with_homes(|home, project| {
            let cases = [
                (
                    "raeva.toml",
                    "[[repositories]]\nid = 'r'\nurl = 'https://u:p@repo.example/'\n",
                    "which raeva.lock would record",
                ),
                (
                    "config.toml",
                    "[[mirrors]]\nurl = 'https://repo.example/?token=x'\n",
                    "which raeva drops as it appends artifact paths to the URL",
                ),
            ];
            for (file, toml, reason) in cases {
                let path = if file == "raeva.toml" { project } else { home }.join(file);
                fs::write(&path, toml).unwrap();
                let message = Config::load(project).unwrap_err().to_string();
                assert!(message.contains(reason), "{message}");
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

    /// A secret-named variable in the URL path of a settings.xml repository
    /// is refused for what raeva.lock would record, or, for a URL with no
    /// http, https or file scheme, which it records none of, as raeva takes
    /// no secret from a URL of any scheme.
    #[test]
    fn a_secret_named_variable_in_a_settings_url_is_refused_for_the_true_reason() {
        with_homes(|home, project| {
            for (url, reason) in [
                (
                    "https://dl.example/${env.REPO_TOKEN}/maven/",
                    "raeva.lock would record expanded",
                ),
                (
                    "ftp://dl.example/${env.REPO_TOKEN}/maven/",
                    "raeva refuses in a URL of any scheme",
                ),
                (
                    "./${env.REPO_TOKEN}",
                    "raeva refuses in a URL of any scheme",
                ),
                (
                    "https://dl.example/m/?t=${env.REPO_TOKEN}",
                    "raeva.lock would record expanded",
                ),
                (
                    "ftp://dl.example/m/?t=${env.REPO_TOKEN}",
                    "raeva refuses in a URL of any scheme",
                ),
            ] {
                write_settings(
                    home,
                    &format!(
                        "<settings><profiles><profile><id>p</id><repositories><repository>\
                         <id>corp</id><url>{url}</url></repository></repositories></profile>\
                         </profiles></settings>"
                    ),
                );
                let message = Config::load(project).unwrap_err().to_string();
                assert!(message.contains(reason), "{url}: {message}");
            }
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
            // Maven puts each active profile's repositories before the
            // earlier ones'.
            assert_eq!(
                ids(config.repositories(), |r| &r.id),
                ["prop-repo", "default-repo", "chosen-repo", "central"]
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

    /// A settings.xml activation is named by its text as written, so two
    /// hosts whose `${env.*}` differ but activate the same profile agree.
    #[test]
    fn conditional_settings_profiles_hold_the_activation_as_written() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><profiles><profile><id>on</id><activation><file>\
                 <exists>\n ${env.RAEVA_TEST_ACTIVATION_DIR}/on </exists></file></activation>\
                 </profile></profiles></settings>",
            );
            let conditional = |dir: &Path| {
                fs::write(dir.join("on"), b"").unwrap();
                let dir = dir.to_str().unwrap();
                temp_env::with_var("RAEVA_TEST_ACTIVATION_DIR", Some(dir), || {
                    let config = Config::load(project).unwrap();
                    assert_eq!(config.active_settings_profiles(), ["on"]);
                    config.conditional_settings_profiles()
                })
            };
            let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let written = conditional(first.path());
            assert_eq!(written, conditional(second.path()));
            assert!(
                written[0]
                    .1
                    .contains("\"${env.RAEVA_TEST_ACTIVATION_DIR}/on\"")
            );
        });
    }

    /// A `<file>` or `<jdk>` condition with a `${...}`, which settings
    /// interpolation expands before activation reads it, keys the lock with
    /// its text as written and whether it holds on each platform.
    #[test]
    fn an_expanded_file_or_jdk_condition_keys_the_lock_by_platform() {
        with_homes(|home, project| {
            let profile = |id: &str, activation: &str| {
                format!(
                    "<profile><id>{id}</id><activation>{activation}</activation><repositories>\
                     <repository><id>{id}-repo</id><url>https://{id}.example/</url>\
                     </repository></repositories></profile>"
                )
            };
            write_settings(
                home,
                &format!(
                    "<settings><profiles>{}{}</profiles></settings>",
                    profile("file", "<file><exists>${user.home}/marker</exists></file>"),
                    profile("jdk", "<jdk>${env.REQ_JDK}</jdk>"),
                ),
            );
            fs::write(home.join("marker"), b"").unwrap();
            let config = temp_env::with_vars(
                [("JAVA_VERSION", Some("21.0.1")), ("REQ_JDK", Some("[17,)"))],
                || Config::load(project).unwrap(),
            );
            assert_eq!(config.conditional_settings_profiles().len(), 2);
            let linux = config.for_platforms([("linux", "x86_64", None)]);
            let conditions: Vec<(String, bool)> = (linux.consulted_settings_conditions().iter())
                .map(|key| linux.settings_condition(key).unwrap())
                .collect();
            for text in [
                "file:exists=${user.home}/marker on linux-x86_64",
                "jdk:jdk=${env.REQ_JDK} on linux-x86_64",
            ] {
                assert!(
                    conditions.iter().any(|(found, _)| found == text),
                    "{text}: {conditions:?}"
                );
            }
        });
    }

    /// The request repositories are those of every profile
    /// `<activeProfiles>` names, one turned off by id too, and not those of
    /// a profile only its `<activation>` turns on.
    #[test]
    fn request_repositories_are_those_of_the_named_profiles() {
        with_homes(|home, project| {
            let profile = |id: &str, activation: &str| {
                format!(
                    "<profile><id>{id}</id>{activation}<repositories><repository>\
                     <id>{id}-dep</id><url>https://{id}.example/</url></repository>\
                     </repositories></profile>"
                )
            };
            write_settings(
                home,
                &format!(
                    "<settings><profiles>{}{}{}</profiles><activeProfiles>\
                     <activeProfile>a</activeProfile><activeProfile>d</activeProfile>\
                     </activeProfiles></settings>",
                    profile("a", ""),
                    profile(
                        "b",
                        "<activation><property><name>!no.b</name></property></activation>"
                    ),
                    profile("d", ""),
                ),
            );
            fs::write(home.join("config.toml"), "inactive_profiles = ['d']\n").unwrap();
            let config = Config::load(project).unwrap();
            assert_eq!(config.active_settings_profiles(), ["a", "b"]);
            assert_eq!(
                ids(config.request_repositories(), |r| &r.id),
                ["a-dep", "d-dep"]
            );
        });
    }

    /// Maven injects each active settings.xml profile into a project's
    /// model before the earlier ones, so the last one's repositories come
    /// first and its entry wins a shared id. Its request carries the plugin
    /// repositories of the profiles `<activeProfiles>` names, in file order,
    /// then Central, even for one turned off by id.
    #[test]
    fn settings_profiles_order_repositories_as_maven_injects_them() {
        with_homes(|home, project| {
            let profile = |id: &str, activation: &str| {
                let repo = |kind: &str, name: &str| {
                    format!(
                        "<{kind}><id>{name}</id><url>https://{id}.example/{name}/</url></{kind}>"
                    )
                };
                format!(
                    "<profile><id>{id}</id>{activation}<repositories>{}{}</repositories>\
                     <pluginRepositories>{}{}</pluginRepositories></profile>",
                    repo("repository", &format!("{id}-dep")),
                    repo("repository", "shared"),
                    repo("pluginRepository", &format!("{id}-plug")),
                    repo("pluginRepository", "pshared"),
                )
            };
            write_settings(
                home,
                &format!(
                    "<settings><profiles>{}{}<profile><id>c</id><pluginRepositories>\
                     <pluginRepository><id>c-plug</id><url>https://c.example/</url>\
                     </pluginRepository></pluginRepositories></profile></profiles>\
                     <activeProfiles><activeProfile>a</activeProfile>\
                     <activeProfile>c</activeProfile></activeProfiles></settings>",
                    profile("a", ""),
                    profile(
                        "b",
                        "<activation><property><name>!no.b</name></property></activation>"
                    ),
                ),
            );
            let url = |repos: &[crate::RepoConfig], id: &str| {
                let repo = repos.iter().find(|repo| repo.id.as_deref() == Some(id));
                repo.unwrap().url.clone()
            };
            let config = Config::load(project).unwrap();
            assert_eq!(
                ids(config.repositories(), |r| &r.id),
                ["b-dep", "shared", "a-dep", "central"]
            );
            assert_eq!(
                url(config.repositories(), "shared"),
                "https://b.example/shared/"
            );
            let all: Vec<&str> = (config.all_repositories())
                .map(|repo| repo.url.as_str())
                .collect();
            for hidden in ["https://a.example/shared/", "https://a.example/pshared/"] {
                assert!(all.contains(&hidden), "{all:?}");
            }
            let plugins = config.profile_plugin_repositories();
            assert_eq!(
                ids(plugins, |r| &r.id),
                ["c-plug", "b-plug", "pshared", "a-plug"]
            );
            assert_eq!(url(plugins, "pshared"), "https://b.example/pshared/");
            let request = config.plugin_repositories();
            assert_eq!(
                ids(request, |r| &r.id),
                ["a-plug", "pshared", "c-plug", "central"]
            );
            assert_eq!(url(request, "pshared"), "https://a.example/pshared/");

            fs::write(home.join("config.toml"), "inactive_profiles = ['a']\n").unwrap();
            let config = Config::load(project).unwrap();
            let plugins = config.profile_plugin_repositories();
            assert_eq!(ids(plugins, |r| &r.id), ["c-plug", "b-plug", "pshared"]);
            let request = config.plugin_repositories();
            assert_eq!(
                ids(request, |r| &r.id),
                ["a-plug", "pshared", "c-plug", "central"]
            );
        });
    }

    /// `active_profiles` adds to `<activeProfiles>`, as `-P` does, and
    /// Maven's request carries the repositories of the profiles
    /// `<activeProfiles>` names after the model's, so one that `-P !id` or
    /// `inactive_profiles` turns off is searched after Central. The lists
    /// are those Maven 3.9.12 and 3.10.0 print for `-Px` and `-P!a`.
    #[test]
    fn active_profiles_add_to_the_settings_and_a_named_one_turned_off_follows_central() {
        with_homes(|home, project| {
            let profile = |id: &str| {
                format!(
                    "<profile><id>{id}</id><repositories><repository><id>{id}-dep</id>\
                     <url>https://{id}.example/dep/</url></repository><repository>\
                     <id>shared</id><url>https://{id}.example/shared/</url></repository>\
                     </repositories><pluginRepositories><pluginRepository><id>{id}-plug</id>\
                     <url>https://{id}.example/plug/</url></pluginRepository>\
                     </pluginRepositories></profile>"
                )
            };
            write_settings(
                home,
                &format!(
                    "<settings><profiles>{}{}</profiles><activeProfiles>\
                     <activeProfile>a</activeProfile></activeProfiles></settings>",
                    profile("a"),
                    profile("x")
                ),
            );
            fs::create_dir_all(project.join(".mvn")).unwrap();
            for (toml, maven_config, dependencies, shared, profile_plugins, active) in [
                ("", "", "a-dep shared central", "a", "a-plug", "a"),
                (
                    "active_profiles = ['x']\n",
                    "",
                    "x-dep shared a-dep central",
                    "x",
                    "x-plug a-plug",
                    "a x",
                ),
                ("", "-P!a", "central a-dep shared", "a", "", ""),
                (
                    "active_profiles = ['x']\n",
                    "-P!a",
                    "x-dep shared central a-dep",
                    "x",
                    "x-plug",
                    "x",
                ),
                (
                    "active_profiles = ['x']\ninactive_profiles = ['a']\n",
                    "",
                    "x-dep shared central a-dep",
                    "x",
                    "x-plug",
                    "x",
                ),
            ] {
                fs::write(project.join("raeva.toml"), toml).unwrap();
                fs::write(project.join(".mvn/maven.config"), maven_config).unwrap();
                let config = Config::load(project).unwrap();
                let case = format!("{toml:?} {maven_config:?}");
                let shown = |repos: &[crate::RepoConfig]| ids(repos, |r| &r.id).join(" ");
                assert_eq!(shown(config.repositories()), dependencies, "{case}");
                let url = (config.repositories().iter())
                    .find(|repo| repo.id.as_deref() == Some("shared"))
                    .map(|repo| repo.url.clone());
                assert_eq!(
                    url,
                    Some(format!("https://{shared}.example/shared/")),
                    "{case}"
                );
                assert_eq!(
                    shown(config.profile_plugin_repositories()),
                    profile_plugins,
                    "{case}"
                );
                assert_eq!(
                    shown(config.plugin_repositories()),
                    "a-plug central",
                    "{case}"
                );
                let mut profiles = config.active_profiles().to_vec();
                profiles.sort();
                assert_eq!(profiles.join(" "), active, "{case}");
            }
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
                [
                    "modern-repo",
                    "listed-repo",
                    "chosen-repo",
                    "central",
                    "dropped-repo"
                ]
            );
            assert_eq!(config.conditional_settings_profiles().len(), 4);
            // Windows editions differ on os.name, so raeva refuses it there.
            if cfg!(windows) {
                fs::write(project.join(".mvn/maven.config"), "-P${os.name}\n").unwrap();
                let refused =
                    temp_env::with_var("JAVA_VERSION", Some("21.0.1"), || Config::load(project));
                assert!(refused.is_err_and(|error| error.to_string().contains("${os.name}")));
            } else {
                let by_expression = load("-P${os.name}\n");
                assert_eq!(by_expression.conditional_settings_profiles().len(), 7);
            }
            assert_eq!(
                repositories(&config.for_platforms([])),
                ["listed-repo", "chosen-repo", "central", "dropped-repo"]
            );
            assert!(config.consulted_settings_conditions().is_empty());
            let linux = config.for_platforms([("linux", "x86_64", None)]);
            let keys = linux.consulted_settings_conditions();
            assert_eq!(keys.len(), 5, "{keys:?}");
            let mut conditions: Vec<_> = keys
                .iter()
                .map(|key| linux.settings_condition(key).unwrap())
                .collect();
            conditions.sort();
            assert_eq!(
                conditions,
                [
                    ("file:${project.basedir}/${mark}".to_string(), false),
                    (
                        "file:exists=${project.basedir}/${mark} on linux-x86_64".to_string(),
                        false
                    ),
                    ("file:marker/".to_string(), true),
                    ("jdk:1.8".to_string(), false),
                    ("jdk:[17,)".to_string(), true),
                ]
            );
            assert!(
                keys.iter()
                    .all(|key| key.len() == 16 && !key.contains("jdk"))
            );

            // Maven expands settings.xml with a `.mvn/maven.config` `-D`.
            let marked = load("-Dmark=marker\n");
            assert!(repositories(&marked).contains(&"spelled-repo".to_string()));

            let config = load("-P!chosen,!listed\n-Djava.version=1.8\n");
            assert_eq!(
                repositories(&config),
                ["jdk8-repo", "central", "dropped-repo", "listed-repo"]
            );
            assert_eq!(
                repositories(&config.for_platforms([])),
                ["central", "dropped-repo", "listed-repo"]
            );
            fs::remove_file(project.join("marker")).unwrap();
            let config = load("");
            assert_eq!(
                repositories(&config),
                ["listed-repo", "central", "dropped-repo"]
            );
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

    /// An empty id would pick another credential than an omitted one while
    /// caches keyed by id treat them alike, so neither file takes one.
    #[test]
    fn an_empty_id_is_refused() {
        for toml in [
            "[[repositories]]\nid = ''\nurl = 'https://repo.example/'",
            "[[repositories]]\nid = ' '\nurl = 'https://repo.example/'",
            "[[mirrors]]\nid = ''\nurl = 'https://mirror.example/'\nmirror_of = '*'",
            "[[auth]]\nid = ''\ntoken = 't'",
        ] {
            let error = toml::from_str::<ConfigFile>(toml).expect_err(toml);
            assert!(error.to_string().contains("an empty id"), "{error}");
        }
        let omitted = "[[repositories]]\nurl = 'https://repo.example/'\n[[auth]]\ntoken = 't'";
        toml::from_str::<ConfigFile>(omitted).expect(omitted);
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
                    "['17', '1']",
                    "lock.jdks entry 2 is \"1\", which names no Java",
                ),
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

    /// A bare `-Duser.home` is empty, which puts `~/.m2` at the root, as
    /// `new File("", ".m2")` does.
    #[cfg(unix)]
    #[test]
    fn an_empty_user_home_is_the_root() {
        assert_eq!(
            crate::paths::maven_user_home(Some(""), crate::paths::LauncherJdk::default()).unwrap(),
            Some(std::path::PathBuf::from("/"))
        );
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
    /// the target JDK's `java.specification.version`.
    #[test]
    fn settings_file_activation_reads_the_target_jdk() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><profiles><profile><id>marked</id>\
                 <activation><file><exists>${basedir}/marker-${java.specification.version}\
                 </exists></file>\
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

    /// A settings.xml `<file>` condition that names
    /// `java.specification.version` is recorded and checked once per
    /// `[lock] jdks` entry, not on the host's JDK. One that names
    /// `java.version` refuses, since each patch release reports its own.
    #[test]
    fn settings_file_conditions_hold_per_target_jdk() {
        with_homes(|home, project| {
            let settings = |name: &str| {
                format!(
                    "<settings><profiles><profile><id>marked</id>\
                     <activation><file><exists>${{basedir}}/marker-${{{name}}}</exists></file>\
                     </activation><repositories><repository><id>marked-repo</id>\
                     <url>https://marked.example/</url></repository></repositories>\
                     </profile></profiles></settings>"
                )
            };
            fs::write(project.join("raeva.toml"), "[lock]\njdks = ['17', '21']\n").unwrap();
            write_settings(home, &settings("java.version"));
            let config = temp_env::with_var("JAVA_VERSION", Some("17"), || {
                Config::load(project).unwrap()
            });
            let scoped = config.for_platforms([("linux", "x86_64", Some("21"))]);
            let refused = scoped.settings_activation().unwrap_err().to_string();
            assert!(refused.contains("depends on java.version"), "{refused}");
            write_settings(home, &settings("java.specification.version"));
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
                    format!("file:${{basedir}}/marker-${{java.specification.version}} (JDK {jdk})"),
                    holds,
                )
            };
            // The text as written, and the outcome on each platform.
            let expansion = |jdk: &str, holds: bool| {
                (
                    format!(
                        "file:exists=${{basedir}}/marker-${{java.specification.version}} \
                         on linux-x86_64 (JDK {jdk})"
                    ),
                    holds,
                )
            };
            assert_eq!(
                conditions(),
                [
                    condition("17", false),
                    condition("21", false),
                    expansion("17", false),
                    expansion("21", false)
                ]
            );
            fs::write(project.join("marker-21"), "").unwrap();
            assert_eq!(
                conditions(),
                [
                    condition("17", false),
                    condition("21", true),
                    expansion("17", false),
                    expansion("21", true)
                ]
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
            fs::write(
                project.join(".mvn/jvm.config"),
                "-Djvm.password=${repo.value}\n",
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
                (".mvn/jvm.config -Djvm.password", "${repo.value}"),
                (".mvn/jvm.config -Djvm.password", "s8"),
                ("settings.xml property alias.token", "${repo.value}"),
                ("settings.xml property alias.token", "s8"),
                // Settings interpolation takes each platform's `os.arch`.
                ("settings.xml property arch.token", "aarch64/s9"),
                ("settings.xml property arch.token", "amd64/s9"),
                ("settings.xml property arch.token", "x86_64/s9"),
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

    /// A settings.xml repository may not take a `-D` value that took a
    /// secret-named one into its URL path or id either.
    #[test]
    fn a_settings_repository_refuses_an_alias_of_a_secret() {
        for repository in [
            "<id>r</id><url>https://repo.example/${slug}/</url>",
            "<id>${slug}</id><url>https://repo.example/m2/</url>",
        ] {
            with_homes(|home, project| {
                write_settings(
                    home,
                    &format!(
                        "<settings><activeProfiles><activeProfile>p</activeProfile>\
                         </activeProfiles><profiles><profile><id>p</id><repositories>\
                         <repository>{repository}</repository></repositories></profile>\
                         </profiles></settings>"
                    ),
                );
                let command_line = CommandLine {
                    defines: vec![
                        "api.token=canary".to_string(),
                        "slug=${api.token}".to_string(),
                    ],
                    ..CommandLine::default()
                };
                let error = Config::load_with_command_line(project, &command_line)
                    .expect_err("refused")
                    .to_string();
                assert!(
                    error.contains("takes ${api.token} (through -Dslug)"),
                    "{error}"
                );
                assert!(!error.contains("canary"), "{error}");
            });
        }
    }

    #[test]
    fn secret_named_inputs_follow_aliases_of_a_secret() {
        with_homes(|home, project| {
            write_settings(
                home,
                "<settings><activeProfiles><activeProfile>p</activeProfile></activeProfiles>\
                 <profiles><profile><id>p</id><properties>\
                 <cs.slug>${env.RV_ALIAS_API_KEY}</cs.slug><mid>${cs.slug}</mid>\
                 <open>${env.RV_ALIAS_PLAIN}</open><via.define>${staged}</via.define>\
                 <over>${env.RV_ALIAS_API_KEY}</over>\
                 </properties></profile></profiles></settings>",
            );
            fs::write(
                home.join("config.toml"),
                "[security]\nallow_env_substitution = [\"CS_API_KEY\"]\n",
            )
            .unwrap();
            fs::create_dir_all(project.join(".mvn")).unwrap();
            fs::write(project.join(".mvn/maven.config"), "-Dhop=${mid}\n").unwrap();
            let command_line = CommandLine {
                defines: vec![
                    "staged=${env.CS_API_KEY}-x".to_string(),
                    "plain=${open}".to_string(),
                    // Hides the settings.xml property of its name.
                    "over=public".to_string(),
                ],
                ..CommandLine::default()
            };
            let config = temp_env::with_vars(
                [
                    ("CS_API_KEY", Some("s5")),
                    ("RV_ALIAS_API_KEY", Some("s1")),
                    ("RV_ALIAS_PLAIN", Some("public")),
                ],
                || Config::load_with_command_line(project, &command_line).unwrap(),
            );
            let expected = [
                ("${env.CS_API_KEY}", "s5"),
                ("${env.CS_API_KEY} (through -Dstaged)", "s5-x"),
                (
                    "${env.CS_API_KEY} (through settings.xml property via.define)",
                    "s5-x",
                ),
                ("${env.RV_ALIAS_API_KEY} (through -Dhop)", "${mid}"),
                ("${env.RV_ALIAS_API_KEY} (through -Dhop)", "s1"),
                (
                    "${env.RV_ALIAS_API_KEY} (through settings.xml property cs.slug)",
                    "s1",
                ),
                (
                    "${env.RV_ALIAS_API_KEY} (through settings.xml property mid)",
                    "${cs.slug}",
                ),
                (
                    "${env.RV_ALIAS_API_KEY} (through settings.xml property mid)",
                    "s1",
                ),
            ];
            assert_eq!(
                config.secret_named_inputs(),
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
    /// The hash reads the project directory as a marker, whole directories
    /// only, in a path and in a `file:` URI, encoded or not, and the user
    /// home as another; [`Config::with_host_paths`] keeps both.
    #[test]
    fn hashed_values_hold_the_project_directory_as_a_marker() {
        with_homes(|home, project| {
            let config = Config::load(project).unwrap();
            let root = project.display().to_string();
            let uri = rv_maven_model::directory_uri(project);
            assert_eq!(
                config.portable(&format!("{root}/lib:{root}")),
                "\0project\0/lib:\0project\0"
            );
            assert_eq!(
                config.portable(&format!("{root}x/lib")),
                format!("{root}x/lib")
            );
            assert_eq!(config.portable(&format!("{uri}r")), "\0project-uri\0/r");
            assert_eq!(config.portable("/elsewhere/lib"), "/elsewhere/lib");
            let url = format!("https://repo.example{root}/m2");
            assert_eq!(config.portable(&url), url);
            assert_eq!(config.portable(&format!("-cp={root}")), "-cp=\0project\0");
            assert_eq!(
                config.portable(&format!("file://{root}/r")),
                "\0project-uri\0/r"
            );
            let home = home.display().to_string();
            assert_eq!(
                config.portable(&format!("file://{home}/corp/")),
                "\0home-uri\0/corp/"
            );
            assert_eq!(config.portable(&format!("{home}/corp")), "\0home\0/corp");
            let raw = config.with_host_paths();
            assert_eq!(raw.portable(&format!("{root}/lib")), format!("{root}/lib"));
        });
    }

    /// A value names the project in the project's own case, as a profile
    /// compares it, and on Windows with either separator. Whether the file
    /// system folds case decides only whether the launcher's directory in
    /// another case is the project.
    #[test]
    fn markers_match_the_directory_as_spelled() {
        let spellings = [("/Work/App".to_string(), "\0project\0".to_string())];
        assert_eq!(with_markers("/work/APP/lib", &spellings), "/work/APP/lib");
        assert_eq!(with_markers("/Work/App/lib", &spellings), "\0project\0/lib");
        assert_eq!(with_markers("/Work/Apps", &spellings), "/Work/Apps");
        let windows = [("C:\\Work\\App".to_string(), "\0project\0".to_string())];
        let marked = with_markers("C:/Work/App/lib", &windows);
        assert_eq!(marked == "\0project\0/lib", cfg!(windows), "{marked}");
        let dir = tempfile::tempdir().unwrap();
        let named = dir.path().join("Case");
        std::fs::create_dir(&named).unwrap();
        assert_eq!(folds_case(&named), dir.path().join("case").exists());
        let upper = Path::new("/WORK/APP");
        assert_eq!(levels_below(Path::new("/work/app/m"), upper, true), Some(1));
        assert_eq!(levels_below(Path::new("/work/app/m"), upper, false), None);
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

    /// A `<file>` lookup whose path no input of the run supplies, a literal
    /// only an edited raeva.lock holds, is not tested: resolution records a
    /// literal path as a file condition, never as a lookup.
    #[test]
    fn a_lookup_of_a_literal_path_tests_no_file() {
        with_homes(|home, project| {
            let outside = home.join("outside-marker");
            let lookup = |expression: &str| {
                crate::maven_config::PropertyLookup {
                    expression: expression.into(),
                    properties: [("alias".into(), outside.to_string_lossy().into_owned())].into(),
                    file: Some(crate::maven_config::FileLookup {
                        base_dir: Some(String::new()),
                    }),
                    default_packaging: None,
                    source: rv_maven_model::PropertySource::User,
                    mode: crate::maven_config::LookupMode::File,
                    model: None,
                }
                .encode()
            };
            let config = Config::load(project).unwrap();
            for template in [lookup(&outside.to_string_lossy()), lookup("${alias}")] {
                let absent = config.user_property_lookup_value(&template);
                fs::write(&outside, "x").unwrap();
                let present = config.user_property_lookup_value(&template);
                fs::remove_file(&outside).unwrap();
                assert_eq!(absent, present, "{template}");
            }
        });
    }

    /// A replay reads `${project.rootDirectory}` from the canonical module
    /// directory, as resolution does, also when raeva runs through a link.
    #[cfg(unix)]
    #[test]
    fn a_root_directory_lookup_replays_through_a_link() {
        with_homes(|home, project| {
            fs::write(project.join("raeva.toml"), "[lock]\nmaven = '3.10'\n").unwrap();
            fs::create_dir_all(project.join("a/.mvn")).unwrap();
            fs::create_dir_all(project.join("a/m")).unwrap();
            let link = home.join("link");
            std::os::unix::fs::symlink(project, &link).unwrap();
            let template = crate::maven_config::PropertyLookup {
                expression: "${project.rootDirectory}/marker".into(),
                properties: Default::default(),
                file: Some(crate::maven_config::FileLookup {
                    base_dir: Some("a/m".into()),
                }),
                default_packaging: None,
                source: rv_maven_model::PropertySource::User,
                mode: crate::maven_config::LookupMode::File,
                model: None,
            }
            .encode();
            let value = |root: &Path| {
                Config::load(root)
                    .unwrap()
                    .user_property_lookup_value(&template)
                    .unwrap()
            };
            let absent = value(project);
            fs::write(project.join("a/marker"), "x").unwrap();
            let present = value(project);
            assert_ne!(absent, present);
            assert_eq!(present, value(&link));
        });
    }

    /// A value encodes as the JSON array of plain strings it hashed as
    /// before `.mvn/jvm.config` was read; a jvm.config value encodes apart.
    #[test]
    fn property_inputs_keep_the_old_encoding_without_jvm_config() {
        use super::{PropertyInput, PropertyInputs};
        let value = |text: &str| Some(PropertyInput::Value(text.to_string()));
        let inputs = PropertyInputs(vec![value("2.0"), None]);
        assert_eq!(inputs.hash_value().as_deref(), Some(r#"["2.0",null]"#));
        assert!(inputs.defined());
        let jvm = PropertyInputs(vec![Some(PropertyInput::JvmConfig("2.0".to_string()))]);
        assert_eq!(
            jvm.hash_value().as_deref(),
            Some(r#"[{".mvn/jvm.config":"2.0"}]"#)
        );
        assert!(jvm.is_set() && !jvm.defined());
        assert_eq!(PropertyInputs(vec![None, None]).hash_value(), None);
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
            let varying = config.user_property_inputs(&names)["flag"]
                .hash_value()
                .unwrap();
            let values: Vec<Option<String>> = (0..6)
                .flat_map(|_| [Some("17".to_string()), Some("21".to_string())])
                .collect();
            let literal = serde_json::to_string(&values).unwrap();
            fs::write(&path, format!("-Dflag={literal}\n")).unwrap();
            let uniform =
                Config::load(project).unwrap().user_property_inputs(&names)["flag"].hash_value();
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

    /// The filter properties come from a settings.xml profile `-P` names,
    /// `.mvn/jvm.config`, `.mvn/maven.config` and `-D`, the later winning,
    /// and `${session.rootDirectory}` in a basedir is the project root.
    /// A filter basedir that names `${os.arch}` gives a platform of
    /// `for_platforms` the rules of that platform's directory, as Maven run
    /// there reads them, and so does a Maven 3.10 Central URL; of several
    /// platforms, the host's stay, and the error one fails with is told.
    #[test]
    fn a_platform_reads_the_maven_config_values_its_architecture_names() {
        with_homes(|_, project| {
            for (arch, group) in [("amd64", "other"), ("aarch64", "t")] {
                let dir = project.join(".mvn/rrf").join(arch);
                fs::create_dir_all(&dir).unwrap();
                fs::write(dir.join("groupId-r1.txt"), format!("{group}\n")).unwrap();
            }
            fs::write(
                project.join(".mvn/maven.config"),
                "-Daether.remoteRepositoryFilter.groupId=true\n\
                 -Daether.remoteRepositoryFilter.groupId.basedir=\
                 ${session.rootDirectory}/.mvn/rrf/${os.arch}\n\
                 -Dmaven.repo.central=https://${os.arch}.example/maven2\n",
            )
            .unwrap();
            fs::write(project.join("raeva.toml"), "[lock]\nmaven = \"3.10\"\n").unwrap();
            let config = Config::load(project).unwrap();
            let allowed = |config: &Config, group: &str| {
                let path = format!("{group}/a/1/a-1.jar");
                (config.repository_filters())
                    .rejects(Some("r1"), "https://r1.example/", group, &path)
                    .is_none()
            };
            for (arch, group, other) in [("aarch64", "t", "other"), ("x86_64", "other", "t")] {
                let platform = config.for_platforms([("linux", arch, None)]);
                platform.settings_activation().unwrap();
                assert!(
                    allowed(&platform, group) && !allowed(&platform, other),
                    "{arch}"
                );
                let arch = if arch == "x86_64" { "amd64" } else { arch };
                let (url, _) = platform.replaced_central().unwrap();
                assert_eq!(url, format!("https://{arch}.example/maven2"));
            }
            // Scoped again, a configuration takes the values of the platform
            // it is scoped to, or the host's, never those of the one before.
            let host = std::env::consts::ARCH;
            let other = if host == "aarch64" {
                "x86_64"
            } else {
                "aarch64"
            };
            let scoped = config.for_platforms([("linux", other, None)]);
            for again in [
                scoped.for_platforms([("linux", host, None)]),
                scoped.for_platforms([("linux", other, None), ("linux", host, None)]),
                scoped.for_platforms([]),
            ] {
                assert_eq!(
                    again.repository_filters().rule_input(|_| false),
                    config.repository_filters().rule_input(|_| false)
                );
                assert_eq!(again.replaced_central(), config.replaced_central());
            }
            let both =
                config.for_platforms([("linux", "aarch64", None), ("linux", "x86_64", None)]);
            assert_eq!(
                both.repository_filters().rule_input(|_| false),
                config.repository_filters().rule_input(|_| false)
            );
            assert!(!config.platform_repository_filters().is_empty());

            // The directory of the platform other than the host's.
            let (broken, dir, kept) = match std::env::consts::ARCH {
                "aarch64" => ("x86_64", "amd64", "aarch64"),
                _ => ("aarch64", "aarch64", "x86_64"),
            };
            let dir = project.join(".mvn/rrf").join(dir);
            fs::remove_dir_all(&dir).unwrap();
            fs::write(&dir, "not a directory").unwrap();
            let config = Config::load(project).unwrap();
            for platforms in [
                &[("linux", broken, None)][..],
                &[("linux", kept, None), ("linux", broken, None)],
            ] {
                let error = (config.for_platforms(platforms.iter().copied()))
                    .settings_activation()
                    .unwrap_err()
                    .to_string();
                assert!(
                    error.contains(&format!("linux-{broken}")) && error.contains("not a directory"),
                    "{error}"
                );
            }
            (config.for_platforms([("linux", kept, None)]))
                .settings_activation()
                .unwrap();
        });
    }

    #[test]
    fn repository_filters_read_maven_properties_and_their_rule_files() {
        with_homes(|home, project| {
            let rrf = project.join(".mvn/rrf");
            fs::create_dir_all(&rrf).unwrap();
            fs::write(rrf.join("groupId-r1.txt"), "org.ex.b\n").unwrap();
            fs::write(rrf.join("prefixes-r1.txt"), "/org/ex\n").unwrap();
            fs::create_dir_all(home.join(".m2/repository/.remoteRepositoryFilters")).unwrap();
            fs::write(
                home.join(".m2/repository/.remoteRepositoryFilters/prefixes-r1.txt"),
                "/com\n",
            )
            .unwrap();
            let allowed = |config: &Config, group: &str| {
                let path = format!("{}/a/1/a-1.jar", group.replace('.', "/"));
                (config.repository_filters())
                    .rejects(Some("r1"), "https://r1.example/", group, &path)
                    .is_none()
            };
            let none = Config::load(project).unwrap();
            assert!(!none.repository_filters().is_active());
            assert_eq!(none.repository_filters().property_names().count(), 0);
            assert_eq!(none.repository_filters().rule_input(|_| false), None);

            fs::write(
                project.join(".mvn/maven.config"),
                "-Daether.remoteRepositoryFilter.groupId=true\n\
                 -Daether.remoteRepositoryFilter.groupId.basedir=${session.rootDirectory}/.mvn/rrf/\n",
            )
            .unwrap();
            let config = Config::load(project).unwrap();
            assert!(allowed(&config, "org.ex.b"));
            assert!(!allowed(&config, "org.ex.a"));
            let input = config.repository_filters().rule_input(|_| false).unwrap();
            assert!(!input.contains(&project.display().to_string()), "{input}");

            // jvm.config enables the prefixes filter, read from the local
            // repository, and -D turns the groupId filter off.
            fs::write(
                project.join(".mvn/jvm.config"),
                "-Daether.remoteRepositoryFilter.prefixes=true\n",
            )
            .unwrap();
            let off = CommandLine {
                defines: vec!["aether.remoteRepositoryFilter.groupId=false".to_string()],
                ..CommandLine::default()
            };
            let config = Config::load_with_command_line(project, &off).unwrap();
            assert!(allowed(&config, "com.x"));
            assert!(!allowed(&config, "org.ex.b"));

            // A settings.xml profile -P names ranks below jvm.config, and
            // sets the basedir neither of the others sets.
            fs::create_dir_all(home.join("elsewhere")).unwrap();
            fs::write(home.join("elsewhere/prefixes-r1.txt"), "/net\n").unwrap();
            write_settings(
                home,
                "<settings><profiles><profile><id>rrf</id><properties>\
                 <aether.remoteRepositoryFilter.prefixes>false</aether.remoteRepositoryFilter.prefixes>\
                 <aether.remoteRepositoryFilter.prefixes.basedir>${user.home}/elsewhere</aether.remoteRepositoryFilter.prefixes.basedir>\
                 </properties></profile></profiles></settings>",
            );
            let profile = CommandLine {
                profiles: vec!["rrf".to_string()],
                ..off
            };
            let config = Config::load_with_command_line(project, &profile).unwrap();
            assert!(allowed(&config, "net.x"));
            assert!(!allowed(&config, "com.x"));
        });
    }

    /// Maven takes a relative local repository from the directory it runs
    /// in, not the project's, and reads the rule files below it there.
    #[cfg(unix)]
    #[test]
    fn a_relative_local_repository_holds_rule_files_below_the_working_directory() {
        with_homes(|home, project| {
            let rules = home.join("m2/.remoteRepositoryFilters");
            fs::create_dir_all(&rules).unwrap();
            fs::write(rules.join("prefixes-r1.txt"), "/com\n").unwrap();
            let cwd = std::env::current_dir().unwrap();
            let up: std::path::PathBuf = cwd.components().skip(1).map(|_| "..").collect();
            let relative = up.join(home.strip_prefix("/").unwrap()).join("m2");
            // Deeper than the working directory, so the path from it leads
            // elsewhere from the project.
            let project = cwd
                .components()
                .fold(project.to_path_buf(), |dir, _| dir.join("d"));
            fs::create_dir_all(&project).unwrap();
            let command_line = CommandLine {
                defines: vec![
                    "aether.remoteRepositoryFilter.prefixes=true".to_string(),
                    format!("maven.repo.local={}", relative.display()),
                ],
                ..CommandLine::default()
            };
            let config = Config::load_with_command_line(&project, &command_line).unwrap();
            let filters = config.repository_filters();
            assert!(
                filters
                    .rejects(
                        Some("r1"),
                        "https://r1.example/",
                        "org.x",
                        "org/x/a/1/a-1.jar"
                    )
                    .is_some()
            );
            assert!(
                filters
                    .rejects(
                        Some("r1"),
                        "https://r1.example/",
                        "com.x",
                        "com/x/a/1/a-1.jar"
                    )
                    .is_none()
            );
        });
    }

    /// The filter properties come from each settings.xml profile
    /// `<activeProfiles>` names, though `-P !id` turns it off, and in the
    /// 3.10 mode from an `<activeByDefault>` profile `-P !id` leaves on, as
    /// Maven's `getPropertiesFromRequestedProfiles` takes them.
    #[test]
    fn repository_filters_take_the_settings_profiles_maven_requests() {
        with_homes(|home, project| {
            fs::create_dir_all(home.join("rules")).unwrap();
            fs::write(home.join("rules/groupId-r1.txt"), "org.ex.b\n").unwrap();
            let allowed = |config: &Config, group: &str| {
                let path = format!("{}/a/1/a-1.jar", group.replace('.', "/"));
                (config.repository_filters())
                    .rejects(Some("r1"), "https://r1.example/", group, &path)
                    .is_none()
            };
            let profile = |activation: &str| {
                format!(
                    "<profile><id>rrf</id>{activation}<properties>\
                     <aether.remoteRepositoryFilter.groupId>true</aether.remoteRepositoryFilter.groupId>\
                     <aether.remoteRepositoryFilter.groupId.basedir>${{user.home}}/rules</aether.remoteRepositoryFilter.groupId.basedir>\
                     </properties></profile>"
                )
            };
            let off = CommandLine {
                profiles: vec!["!rrf".to_string()],
                ..CommandLine::default()
            };
            let load = |command_line: &CommandLine| {
                Config::load_with_command_line(project, command_line).unwrap()
            };
            write_settings(
                home,
                &format!(
                    "<settings><profiles>{}</profiles>\
                     <activeProfiles><activeProfile>rrf</activeProfile></activeProfiles></settings>",
                    profile("")
                ),
            );
            assert!(!allowed(&load(&CommandLine::default()), "org.ex.a"));
            let config = load(&off);
            assert!(!allowed(&config, "org.ex.a"));
            // What the profile sets is a lock input, though no settings
            // profile a model sees has it.
            let input = config.repository_filters().rule_input(|_| true).unwrap();
            assert!(
                input.contains("settings-property aether.remoteRepositoryFilter.groupId=true"),
                "{input}"
            );
            assert!(!input.contains("basedir"), "{input}");

            write_settings(
                home,
                &format!(
                    "<settings><profiles>{}</profiles></settings>",
                    profile("<activation><activeByDefault>true</activeByDefault></activation>")
                ),
            );
            assert!(allowed(&load(&CommandLine::default()), "org.ex.a"));
            fs::write(project.join("raeva.toml"), "[lock]\nmaven = '3.10'\n").unwrap();
            assert!(!allowed(&load(&CommandLine::default()), "org.ex.a"));
            assert!(allowed(&load(&off), "org.ex.a"));
        });
    }
}
