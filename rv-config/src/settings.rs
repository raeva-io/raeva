use std::fmt;
use std::str::FromStr;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// How raeva authenticates to a proxy, sent as `Proxy-Authorization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyAuthType {
    /// [`ProxyConfig::username`] and [`ProxyConfig::password`]; nothing is
    /// sent without a username.
    #[default]
    Basic,
    /// A bearer token from [`ProxyConfig::token`], else from the variable
    /// [`ProxyConfig::token_env`] names.
    Bearer,
}

/// How long a cached snapshot or metadata answer stays fresh, as Maven's
/// `<updatePolicy>` names it. The default is `interval:60`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePolicy {
    /// Check again on every use.
    Always,
    /// Check again after 24 hours, not at the next calendar day.
    Daily,
    /// Check again after this many minutes; [`UpdatePolicy::parse`]
    /// refuses zero.
    Interval(u32),
    /// Do not check again.
    Never,
}

impl UpdatePolicy {
    /// Parses `always`, `daily`, `never` or `interval:N` with `N` minutes
    /// above zero, ignoring ASCII case and surrounding whitespace. `None`
    /// for anything else, including an empty string.
    pub fn parse(value: &str) -> Option<Self> {
        let lower = value.trim().to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("interval:") {
            let minutes = rest.trim().parse::<u32>().ok()?;
            if minutes == 0 {
                return None;
            }
            return Some(UpdatePolicy::Interval(minutes));
        }
        match lower.as_str() {
            "always" => Some(UpdatePolicy::Always),
            "daily" => Some(UpdatePolicy::Daily),
            "never" => Some(UpdatePolicy::Never),
            _ => None,
        }
    }

    /// The freshness window in seconds: 0 for [`Self::Always`] and
    /// `i64::MAX` for [`Self::Never`].
    pub fn ttl_secs(self) -> i64 {
        match self {
            UpdatePolicy::Always => 0,
            UpdatePolicy::Daily => 24 * 60 * 60,
            UpdatePolicy::Interval(minutes) => i64::from(minutes) * 60,
            UpdatePolicy::Never => i64::MAX,
        }
    }
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        UpdatePolicy::Interval(60)
    }
}

impl fmt::Display for UpdatePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdatePolicy::Always => f.write_str("always"),
            UpdatePolicy::Daily => f.write_str("daily"),
            UpdatePolicy::Interval(minutes) => write!(f, "interval:{minutes}"),
            UpdatePolicy::Never => f.write_str("never"),
        }
    }
}

impl FromStr for UpdatePolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UpdatePolicy::parse(s).ok_or_else(|| format!("invalid update policy: {s}"))
    }
}

impl Serialize for UpdatePolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for UpdatePolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        UpdatePolicy::parse(&s).ok_or_else(|| serde::de::Error::custom("invalid update policy"))
    }
}

/// Maven repository checksum policy. raeva applies `warn`, `fail` and `ignore`
/// to remote metadata only, and [`Self::Unsupported`] to every download.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChecksumPolicy {
    /// Accept metadata whose checksum does not match, with a warning.
    #[default]
    Warn,
    /// Reject metadata whose checksum does not match.
    Fail,
    /// Maven's `ignore`. raeva accepts the metadata and still warns, as for
    /// [`Self::Warn`].
    Ignore,
    /// A value a POM or settings.xml gives that Maven does not support,
    /// such as `FAIL` or an empty one. Maven refuses every download from
    /// the repository for the versions the policy covers, and so does raeva.
    /// `raeva.toml` and `config.toml` cannot set it.
    #[serde(skip_deserializing)]
    Unsupported,
}

impl ChecksumPolicy {
    /// Parses `warn`, `fail` or `ignore` after trimming whitespace. The match
    /// is case-sensitive, as in Maven; `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "warn" => Some(Self::Warn),
            "fail" => Some(Self::Fail),
            "ignore" => Some(Self::Ignore),
            _ => None,
        }
    }

    /// The policy a `<checksumPolicy>` element Maven reads gives:
    /// [`Self::parse`], or [`Self::Unsupported`] for any other value.
    pub fn from_maven(value: &str) -> Self {
        Self::parse(value).unwrap_or(Self::Unsupported)
    }
}

/// A repository to resolve from: a `[[repositories]]` entry in `raeva.toml` or
/// `config.toml`, or a repository of an active settings.xml profile.
///
/// Unset fields take their defaults where the repository is used, not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RepoConfig {
    /// The id that `[[auth]]` entries, settings.xml `<server>`s and mirrors'
    /// `mirror_of` patterns match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The repository's base URL.
    pub url: String,
    /// Whether release versions resolve here; unset means yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases: Option<bool>,
    /// Whether snapshot versions resolve here; unset means no. A settings.xml
    /// repository without `<snapshots><enabled>` reads as yes, as in Maven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<bool>,
    /// How long cached snapshot metadata stays fresh.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "snapshots-update-policy"
    )]
    pub snapshots_update_policy: Option<UpdatePolicy>,
    /// How long cached release metadata stays fresh.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "releases-update-policy"
    )]
    pub releases_update_policy: Option<UpdatePolicy>,
    /// Metadata checksum policy for release versions. Artifact and POM
    /// mismatches always fail.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "releases-checksum-policy"
    )]
    pub releases_checksum_policy: Option<ChecksumPolicy>,
    /// Metadata checksum policy for snapshot versions. Artifact and POM
    /// mismatches always fail.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "snapshots-checksum-policy"
    )]
    pub snapshots_checksum_policy: Option<ChecksumPolicy>,
}

/// A mirror that serves requests for the repositories `mirror_of` matches:
/// a `[[mirrors]]` entry in `config.toml`, or a settings.xml `<mirror>`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct MirrorConfig {
    /// The id that `[[auth]]` entries and settings.xml `<server>`s match.
    #[serde(default)]
    pub id: Option<String>,
    /// The mirror's base URL.
    pub url: String,
    /// Maven `<mirrorOf>` patterns, which join with `,` into the text of a
    /// settings.xml `<mirrorOf>`, kept there as one entry.
    #[serde(default)]
    pub mirror_of: Vec<String>,
    /// settings.xml `<mirrorOfLayouts>`, Maven's `default,legacy` when
    /// unset.
    #[serde(skip)]
    pub mirror_of_layouts: Option<String>,
    /// Maven's `<blocked>`: the repositories this mirror matches get no
    /// requests, through it or around it.
    #[serde(default)]
    pub blocked: bool,
}

/// Credentials for a repository or mirror id: an `[[auth]]` entry in
/// `raeva.toml` or `config.toml`, or a settings.xml `<server>`. Secrets are
/// never serialized.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AuthConfig {
    /// The repository or mirror id these credentials apply to.
    #[serde(default)]
    pub id: Option<String>,
    /// The basic-auth username.
    #[serde(default)]
    pub username: Option<String>,
    /// The basic-auth password, decrypted when settings.xml held it
    /// Maven-encrypted.
    #[serde(default)]
    pub password: Option<SecretString>,
    /// A bearer token, used instead of basic auth when set. From settings.xml
    /// it is the `Bearer` value of an `Authorization` header under
    /// `<configuration><httpHeaders>`.
    #[serde(default)]
    pub token: Option<SecretString>,
}

impl MirrorConfig {
    /// A mirror with this id and URL that mirrors nothing until
    /// `mirror_of` names repositories.
    pub fn new(id: Option<&str>, url: &str) -> Self {
        Self {
            id: id.map(str::to_string),
            url: url.to_string(),
            mirror_of: Vec::new(),
            mirror_of_layouts: None,
            blocked: false,
        }
    }
}

impl AuthConfig {
    /// Credentials for the repository or mirror `id`, with no username,
    /// password or token set yet.
    pub fn new(id: Option<&str>) -> Self {
        Self {
            id: id.map(str::to_string),
            username: None,
            password: None,
            token: None,
        }
    }
}

/// An HTTP proxy: a `[[proxies]]` entry in the user `config.toml`, or an
/// active settings.xml `<proxy>`. A project `raeva.toml` cannot declare one.
/// Secrets are never serialized.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// A name for the entry; nothing selects a proxy by it.
    #[serde(default)]
    pub id: Option<String>,
    /// The URL scheme the proxy carries: `http` (when unset), `https` or
    /// `all`, in any ASCII case. An `http` proxy also carries `https:` URLs
    /// that no `https` proxy takes, as in Maven.
    /// [`Config::load`](crate::Config::load) rejects another value in
    /// `config.toml` and drops a settings.xml proxy that has one.
    #[serde(default)]
    pub protocol: Option<String>,
    /// The proxy's host name or IP literal, without scheme, port or
    /// credentials.
    pub host: String,
    /// The proxy's port; settings.xml defaults it to 8080.
    pub port: u16,
    /// How raeva authenticates to the proxy; unset means
    /// [`ProxyAuthType::Basic`].
    #[serde(default)]
    pub auth_type: Option<ProxyAuthType>,
    /// The basic-auth username.
    #[serde(default)]
    pub username: Option<String>,
    /// The basic-auth password.
    #[serde(default)]
    pub password: Option<SecretString>,
    /// The environment variable holding the bearer token, read when the
    /// proxy client is built and only if [`Self::token`] is unset.
    #[serde(default)]
    pub token_env: Option<String>,
    /// The bearer token for [`ProxyAuthType::Bearer`].
    #[serde(default)]
    pub token: Option<SecretString>,
    /// Hosts reached directly, as Maven's `<nonProxyHosts>` patterns;
    /// settings.xml's `|`-separated list is split here.
    #[serde(default)]
    pub non_proxy_hosts: Vec<String>,
    /// Set for a proxy from `HTTPS_PROXY` or `HTTP_PROXY`, which carries
    /// only its own scheme and leaves alone what `NO_PROXY` names.
    #[serde(skip)]
    pub environment: Option<crate::EnvironmentProxy>,
}

impl ProxyConfig {
    /// A proxy at `host:port` with no protocol set, which reads as `http`,
    /// and without credentials or `non_proxy_hosts`.
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            id: None,
            protocol: None,
            host: host.to_string(),
            port,
            auth_type: None,
            username: None,
            password: None,
            token_env: None,
            token: None,
            non_proxy_hosts: Vec::new(),
            environment: None,
        }
    }
}

impl RepoConfig {
    /// An entry with this id and URL and every other setting unset, as a
    /// `[[repositories]]` table holding only `id` and `url` reads.
    pub fn new(id: Option<&str>, url: &str) -> Self {
        Self {
            id: id.map(str::to_string),
            url: url.to_string(),
            releases: None,
            snapshots: None,
            snapshots_update_policy: None,
            releases_update_policy: None,
            releases_checksum_policy: None,
            snapshots_checksum_policy: None,
        }
    }

    /// Maven Central (`central`, `https://repo1.maven.org/maven2/`), with
    /// releases on and snapshots off.
    pub fn maven_central() -> Self {
        Self {
            releases: Some(true),
            snapshots: Some(false),
            ..Self::new(Some("central"), "https://repo1.maven.org/maven2/")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ChecksumPolicy, RepoConfig, UpdatePolicy};

    #[test]
    fn update_policies_parse_and_print() {
        for (text, policy, ttl) in [
            (" Always ", Some(UpdatePolicy::Always), 0),
            ("daily", Some(UpdatePolicy::Daily), 24 * 60 * 60),
            ("interval: 15", Some(UpdatePolicy::Interval(15)), 15 * 60),
            ("NEVER", Some(UpdatePolicy::Never), i64::MAX),
            ("interval:0", None, 0),
            ("", None, 0),
            ("hourly", None, 0),
        ] {
            assert_eq!(UpdatePolicy::parse(text), policy, "{text:?}");
            if let Some(policy) = policy {
                assert_eq!(policy.ttl_secs(), ttl);
                assert_eq!(policy.to_string().parse::<UpdatePolicy>(), Ok(policy));
            }
        }
        assert!("hourly".parse::<UpdatePolicy>().is_err());
        assert_eq!(UpdatePolicy::default(), UpdatePolicy::Interval(60));
    }

    #[test]
    fn repository_tables_use_kebab_case_keys() {
        let repo: RepoConfig = toml::from_str(
            "url = 'https://example.com/'\nreleases-checksum-policy = 'fail'\n\
             snapshots-update-policy = 'interval:15'",
        )
        .unwrap();
        assert_eq!(repo.releases_checksum_policy, Some(ChecksumPolicy::Fail));
        assert_eq!(
            repo.snapshots_update_policy,
            Some(UpdatePolicy::Interval(15))
        );
        for bad in [
            "snapshots-checksum-policy = 'strict'",
            "snapshots-checksum-policy = 'unsupported'",
            "snapshots_update_policy = 'daily'",
            "releases-update-policy = 'hourly'",
        ] {
            let toml = format!("url = 'https://example.com/'\n{bad}");
            assert!(toml::from_str::<RepoConfig>(&toml).is_err(), "{bad}");
        }
        assert_eq!(
            serde_json::to_string(&repo).unwrap(),
            r#"{"url":"https://example.com/","snapshots-update-policy":"interval:15","releases-checksum-policy":"fail"}"#
        );
        assert_eq!(
            ChecksumPolicy::parse(" ignore "),
            Some(ChecksumPolicy::Ignore)
        );
        assert_eq!(
            ChecksumPolicy::from_maven("Warn"),
            ChecksumPolicy::Unsupported
        );
    }
}
