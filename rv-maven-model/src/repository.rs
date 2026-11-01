use serde::{Deserialize, Deserializer};

/// A `<repository>` a POM, a profile or the configuration declares.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Repository {
    /// Provenance from the resolver for project and local POMs.
    /// XML, cached models, and lockfile metadata cannot grant it.
    pub root_declared: bool,
    /// The `<id>`, which mirrors, credentials and later declarations match.
    pub id: Option<String>,
    /// Empty when absent. Dependency/BOM models drop repositories without a URL.
    pub url: String,
    /// `<releases><enabled>` as Maven reads it once interpolated: `true`
    /// when absent, otherwise whether the trimmed text is `true` in any
    /// case, so `yes` and an empty element are `false`. Before the model
    /// interpolates it, a value that holds a `${...}` reads as `true`.
    pub releases_enabled: bool,
    /// `<snapshots><enabled>`, read as [`Repository::releases_enabled`] is.
    pub snapshots_enabled: bool,
    /// The `<releases><enabled>` text as written, which interpolation reads
    /// again.
    pub(crate) releases_enabled_text: Option<String>,
    /// The `<snapshots><enabled>` text as written.
    pub(crate) snapshots_enabled_text: Option<String>,
    /// Raw update-policy token from `<releases><updatePolicy>…</updatePolicy></releases>`.
    /// Stored as a string so the model crate does not depend on rv-config's
    /// `UpdatePolicy` enum; consumers (rv-repo) parse it into a typed policy.
    pub releases_update_policy: Option<String>,
    /// Raw update-policy token from `<snapshots><updatePolicy>…</updatePolicy></snapshots>`.
    pub snapshots_update_policy: Option<String>,
    /// Raw `<releases><checksumPolicy>` token, as written.
    pub releases_checksum_policy: Option<String>,
    /// Raw `<snapshots><checksumPolicy>` token, as written.
    pub snapshots_checksum_policy: Option<String>,
}

impl Repository {
    /// A repository with this id and URL as written, with releases and
    /// snapshots enabled and no update or checksum policy, which is what a
    /// `<repository>` holding only an `<id>` and a `<url>` reads as. It is
    /// not declared by the root project.
    pub fn new(id: Option<&str>, url: &str) -> Self {
        Self {
            root_declared: false,
            id: id.map(str::to_string),
            url: url.to_string(),
            releases_enabled: true,
            snapshots_enabled: true,
            releases_enabled_text: None,
            snapshots_enabled_text: None,
            releases_update_policy: None,
            snapshots_update_policy: None,
            releases_checksum_policy: None,
            snapshots_checksum_policy: None,
        }
    }

    /// Whether the URL or a policy still holds a `${...}` that the model
    /// has not interpolated.
    pub fn has_expression(&self) -> bool {
        [
            Some(&self.url),
            self.releases_enabled_text.as_ref(),
            self.snapshots_enabled_text.as_ref(),
            self.releases_update_policy.as_ref(),
            self.snapshots_update_policy.as_ref(),
            self.releases_checksum_policy.as_ref(),
            self.snapshots_checksum_policy.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|text| text.contains("${"))
    }

    /// Whether snapshot enablement or freshness still depends on an
    /// uninterpolated property, for callers that only have a local model.
    pub fn snapshot_policy_has_expression(&self) -> bool {
        [
            self.snapshots_enabled_text.as_ref(),
            self.snapshots_update_policy.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|text| text.contains("${"))
    }

    /// Expand the update and checksum policies and the `<enabled>` texts
    /// with `interpolate`, and reread the texts as Maven reads them in the
    /// interpolated model. The id and URL are the caller's.
    pub(crate) fn interpolate_policies<E>(
        &mut self,
        mut interpolate: impl FnMut(&str) -> Result<String, E>,
    ) -> Result<(), E> {
        for policy in [
            &mut self.releases_update_policy,
            &mut self.snapshots_update_policy,
            &mut self.releases_checksum_policy,
            &mut self.snapshots_checksum_policy,
        ] {
            if let Some(raw) = policy.as_deref() {
                *policy = Some(interpolate(raw)?);
            }
        }
        for (text, enabled) in [
            (&mut self.releases_enabled_text, &mut self.releases_enabled),
            (
                &mut self.snapshots_enabled_text,
                &mut self.snapshots_enabled,
            ),
        ] {
            if let Some(raw) = text.as_deref() {
                let value = interpolate(raw)?;
                *enabled = maven_enabled(Some(&value));
                *text = Some(value);
            }
        }
        Ok(())
    }

    /// Read `<enabled>` and the policies as written, as Maven reads the
    /// repositories of a raw model while it looks up that model's parent.
    pub(crate) fn read_policies_as_written(&mut self) {
        let Ok(()) =
            self.interpolate_policies(|text| Ok::<_, std::convert::Infallible>(text.to_owned()));
    }
}

/// Maven's reading of an interpolated `<enabled>`: absent is `true`,
/// anything else is `true` only when its trimmed text is `true` in any case.
fn maven_enabled(text: Option<&str>) -> bool {
    text.is_none_or(|text| text.trim().eq_ignore_ascii_case("true"))
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
            #[serde(rename = "checksumPolicy")]
            checksum_policy: Option<String>,
        }

        let xml = RepositoryXml::deserialize(deserializer)?;

        let enabled_text =
            |policy: &Option<PolicyXml>| policy.as_ref().and_then(|p| p.enabled.clone());
        // Interpolation decides a value with an expression; until then it
        // keeps the repository usable.
        let parse_enabled = |text: &Option<String>| -> bool {
            text.as_deref()
                .is_none_or(|text| text.contains("${") || maven_enabled(Some(text)))
        };

        let extract_update_policy = |policy: &Option<PolicyXml>| -> Option<String> {
            policy
                .as_ref()
                .and_then(|p| p.update_policy.clone())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        let releases_enabled_text = enabled_text(&xml.releases);
        let snapshots_enabled_text = enabled_text(&xml.snapshots);
        let releases_enabled = parse_enabled(&releases_enabled_text);
        let snapshots_enabled = parse_enabled(&snapshots_enabled_text);
        let releases_update_policy = extract_update_policy(&xml.releases);
        let snapshots_update_policy = extract_update_policy(&xml.snapshots);

        Ok(Repository {
            root_declared: false,
            id: xml.id,
            url: xml.url.unwrap_or_default(),
            releases_enabled,
            snapshots_enabled,
            releases_enabled_text,
            snapshots_enabled_text,
            releases_update_policy,
            snapshots_update_policy,
            releases_checksum_policy: xml.releases.and_then(|p| p.checksum_policy),
            snapshots_checksum_policy: xml.snapshots.and_then(|p| p.checksum_policy),
        })
    }
}

element_list!(pub(crate) fn deserialize_repositories, "repository", Repository);

#[cfg(test)]
mod tests {
    use super::*;

    /// A POM's `<enabled>` reads as Maven reads it: absent is true,
    /// otherwise only a trimmed `true` in any case; an expression waits for
    /// interpolation.
    #[test]
    fn enabled_reads_as_maven_reads_it() {
        for (enabled, expected) in [
            ("<snapshots/>", true),
            ("<snapshots><enabled> TRUE </enabled></snapshots>", true),
            ("<snapshots><enabled>yes</enabled></snapshots>", false),
            ("<snapshots><enabled></enabled></snapshots>", false),
            ("<snapshots><enabled>${on}</enabled></snapshots>", true),
            ("<releases><enabled>false</enabled></releases>", true),
        ] {
            let xml = format!("<repository><url>https://example.com/</url>{enabled}</repository>");
            let repo: Repository = quick_xml::de::from_str(&xml).unwrap();
            assert_eq!(repo.snapshots_enabled, expected, "{enabled}");
            assert_eq!(
                repo.releases_enabled,
                !enabled.contains("false"),
                "{enabled}"
            );
        }

        let xml = "<repository><url>https://example.com/</url>\
                   <snapshots><enabled>${on}</enabled><checksumPolicy>${cs}</checksumPolicy>\
                   </snapshots></repository>";
        let mut repo: Repository = quick_xml::de::from_str(xml).unwrap();
        assert!(repo.has_expression());
        repo.interpolate_policies(|text| {
            Ok::<_, ()>(text.replace("${on}", "false").replace("${cs}", "fail"))
        })
        .unwrap();
        assert!(!repo.snapshots_enabled);
        assert_eq!(repo.snapshots_checksum_policy.as_deref(), Some("fail"));
        assert!(!repo.has_expression());
    }
}
