use std::fmt;
use std::str::FromStr;

use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display as StrumDisplay, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
enum UpdatePolicySimple {
    Always,
    Daily,
    Never,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    EnumString,
    StrumDisplay,
    AsRefStr,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum ProxyAuthType {
    #[default]
    Basic,
    Bearer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePolicy {
    Always,
    Daily,
    Interval(u32),
    Never,
}

impl UpdatePolicy {
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("interval:") {
            let minutes = rest.trim().parse::<u32>().ok()?;
            if minutes == 0 {
                return None;
            }
            return Some(UpdatePolicy::Interval(minutes));
        }
        match UpdatePolicySimple::from_str(&lower).ok()? {
            UpdatePolicySimple::Always => Some(UpdatePolicy::Always),
            UpdatePolicySimple::Daily => Some(UpdatePolicy::Daily),
            UpdatePolicySimple::Never => Some(UpdatePolicy::Never),
        }
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "snapshots-update-policy",
        alias = "snapshots_update_policy"
    )]
    pub snapshots_update_policy: Option<UpdatePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mirror_of: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing)]
    pub password: Option<Secret<String>>,
    #[serde(default, skip_serializing)]
    pub token: Option<Secret<String>>,
}

impl PartialEq for AuthConfig {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.username == other.username
            && eq_opt_secret(&self.password, &other.password)
            && eq_opt_secret(&self.token, &other.token)
    }
}

impl Eq for AuthConfig {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<ProxyAuthType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing)]
    pub password: Option<Secret<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    #[serde(default, skip_serializing)]
    pub token: Option<Secret<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub non_proxy_hosts: Vec<String>,
}

impl PartialEq for ProxyConfig {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.protocol == other.protocol
            && self.host == other.host
            && self.port == other.port
            && self.auth_type == other.auth_type
            && self.username == other.username
            && eq_opt_secret(&self.password, &other.password)
            && self.token_env == other.token_env
            && eq_opt_secret(&self.token, &other.token)
            && self.non_proxy_hosts == other.non_proxy_hosts
    }
}

impl Eq for ProxyConfig {}

/// Compares two optional secrets for equality.
///
/// `Secret<String>` does not derive `PartialEq`, so config equality (used by
/// tests and merge dedup) needs an explicit helper. A constant-time comparison
/// was used here previously, but it guarded a timing channel that does not
/// exist: these secrets come from the user's own settings, not from attacker
/// input fed through a comparison loop. Plain equality is sufficient and
/// clearer.
fn eq_opt_secret(a: &Option<Secret<String>>, b: &Option<Secret<String>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.expose_secret() == b.expose_secret(),
        (None, None) => true,
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<RepoConfig>,
}

impl RepoConfig {
    pub fn maven_central() -> Self {
        Self {
            id: Some("central".to_string()),
            url: "https://repo1.maven.org/maven2/".to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: None,
        }
    }

    pub fn google() -> Self {
        Self {
            id: Some("google".to_string()),
            url: "https://dl.google.com/dl/android/maven2/".to_string(),
            releases: Some(true),
            snapshots: Some(false),
            snapshots_update_policy: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthConfig, MirrorConfig, ProxyAuthType, ProxyConfig, RepoConfig, UpdatePolicy};
    use secrecy::Secret;

    #[test]
    fn update_policy_ttl_secs() {
        assert_eq!(UpdatePolicy::Always.ttl_secs(), 0);
        assert_eq!(UpdatePolicy::Daily.ttl_secs(), 24 * 60 * 60);
        assert_eq!(UpdatePolicy::Interval(15).ttl_secs(), 15 * 60);
        assert_eq!(UpdatePolicy::Never.ttl_secs(), i64::MAX);
    }

    #[test]
    fn repo_config_round_trip() {
        let repo = RepoConfig::maven_central();
        let encoded = toml::to_string(&repo).unwrap();
        let decoded: RepoConfig = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, repo);
    }

    #[test]
    fn update_policy_round_trip() {
        let repo = RepoConfig {
            id: Some("snapshots".to_string()),
            url: "https://snapshots.example/".to_string(),
            releases: Some(false),
            snapshots: Some(true),
            snapshots_update_policy: Some(UpdatePolicy::Interval(15)),
        };
        let encoded = toml::to_string(&repo).unwrap();
        let decoded: RepoConfig = toml::from_str(&encoded).unwrap();
        assert_eq!(
            decoded.snapshots_update_policy,
            repo.snapshots_update_policy
        );
    }

    #[test]
    fn mirror_config_round_trip() {
        let mirror = MirrorConfig {
            id: Some("corp".to_string()),
            url: "https://repo.corp.example/maven2/".to_string(),
            mirror_of: vec!["central".to_string()],
        };
        let encoded = toml::to_string(&mirror).unwrap();
        let decoded: MirrorConfig = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, mirror);
    }

    #[test]
    fn auth_config_round_trip() {
        let auth = AuthConfig {
            id: Some("central".to_string()),
            username: Some("user".to_string()),
            password: Some(Secret::new("pass".to_string())),
            token: None,
        };
        let encoded = toml::to_string(&auth).unwrap();
        let decoded: AuthConfig = toml::from_str(&encoded).unwrap();
        // Secrets are skipped serialization
        assert_eq!(decoded.id, auth.id);
        assert_eq!(decoded.username, auth.username);
        assert!(decoded.password.is_none());
    }

    #[test]
    fn proxy_config_round_trip() {
        let proxy = ProxyConfig {
            id: Some("corp".to_string()),
            protocol: Some("https".to_string()),
            host: "proxy.corp.example".to_string(),
            port: 8443,
            auth_type: Some(ProxyAuthType::Basic),
            username: Some("user".to_string()),
            password: Some(Secret::new("pass".to_string())),
            token_env: None,
            token: None,
            non_proxy_hosts: vec!["localhost".to_string()],
        };
        let encoded = toml::to_string(&proxy).unwrap();
        let decoded: ProxyConfig = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.id, proxy.id);
        assert_eq!(decoded.host, proxy.host);
        assert!(decoded.password.is_none());
    }

    #[test]
    fn auth_config_eq_compares_secret_payloads() {
        let base = AuthConfig {
            id: Some("central".to_string()),
            username: Some("user".to_string()),
            password: Some(Secret::new("pass".to_string())),
            token: None,
        };

        let same = AuthConfig {
            password: Some(Secret::new("pass".to_string())),
            ..base.clone()
        };
        assert_eq!(base, same);

        // Differing password payload makes the configs unequal.
        let other_pw = AuthConfig {
            password: Some(Secret::new("other".to_string())),
            ..base.clone()
        };
        assert_ne!(base, other_pw);

        // Differing length is still detected (the old constant-time helper
        // short-circuited here; plain equality must keep the same answer).
        let longer_pw = AuthConfig {
            password: Some(Secret::new("password-much-longer".to_string())),
            ..base.clone()
        };
        assert_ne!(base, longer_pw);

        // Some vs None on a secret field is unequal.
        let no_pw = AuthConfig {
            password: None,
            ..base.clone()
        };
        assert_ne!(base, no_pw);

        // Both None on the same field is equal.
        let token_none_a = AuthConfig {
            password: None,
            token: None,
            ..base.clone()
        };
        let token_none_b = token_none_a.clone();
        assert_eq!(token_none_a, token_none_b);
    }
}
