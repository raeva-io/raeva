use serde::{Deserialize, Deserializer};

use crate::pom::parse_bool;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Repository {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub url: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub releases_enabled: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub snapshots_enabled: bool,
    /// Raw update-policy token from `<releases><updatePolicy>…</updatePolicy></releases>`.
    /// Stored as a string so the model crate does not depend on rv-config's
    /// `UpdatePolicy` enum; consumers (rv-repo) parse it into a typed policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases_update_policy: Option<String>,
    /// Raw update-policy token from `<snapshots><updatePolicy>…</updatePolicy></snapshots>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshots_update_policy: Option<String>,
}

impl<'de> Deserialize<'de> for Repository {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RepositoryXml {
            id: Option<String>,
            url: Option<String>,
            releases: Option<PolicyXml>,
            snapshots: Option<PolicyXml>,
        }

        #[derive(Deserialize)]
        struct PolicyXml {
            enabled: Option<String>,
            #[serde(rename = "updatePolicy")]
            update_policy: Option<String>,
        }

        let xml = RepositoryXml::deserialize(deserializer)?;

        let parse_enabled = |policy: &Option<PolicyXml>, default: bool| -> bool {
            if let Some(p) = policy.as_ref() {
                if let Some(s) = p.enabled.as_deref() {
                    return parse_bool(s).unwrap_or(default);
                }
                return default;
            }
            default
        };

        let extract_update_policy = |policy: &Option<PolicyXml>| -> Option<String> {
            policy
                .as_ref()
                .and_then(|p| p.update_policy.clone())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        let releases_enabled = parse_enabled(&xml.releases, true);
        let snapshots_enabled = parse_enabled(&xml.snapshots, true);
        let releases_update_policy = extract_update_policy(&xml.releases);
        let snapshots_update_policy = extract_update_policy(&xml.snapshots);

        Ok(Repository {
            id: xml.id,
            url: xml
                .url
                .ok_or_else(|| serde::de::Error::missing_field("url"))?,
            releases_enabled,
            snapshots_enabled,
            releases_update_policy,
            snapshots_update_policy,
        })
    }
}

pub(crate) fn deserialize_repositories<'de, D>(deserializer: D) -> Result<Vec<Repository>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(rename = "repository", default)]
        items: Vec<Repository>,
    }
    Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|w| w.items).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_repository() {
        let xml = r"
        <repository>
          <id>central</id>
          <url>https://repo1.maven.org/maven2</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
        ";
        let repo: Repository = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(repo.id.as_deref(), Some("central"));
        assert_eq!(repo.url, "https://repo1.maven.org/maven2");
        assert!(repo.releases_enabled);
        assert!(!repo.snapshots_enabled);
    }

    #[test]
    fn omitted_snapshot_policy_defaults_to_enabled() {
        let xml = r"
        <repository>
          <id>apache.snapshots</id>
          <url>https://repository.apache.org/snapshots</url>
          <releases><enabled>false</enabled></releases>
        </repository>
        ";
        let repo: Repository = quick_xml::de::from_str(xml).unwrap();

        assert!(!repo.releases_enabled);
        assert!(repo.snapshots_enabled);
    }
}
