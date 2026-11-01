use packageurl::PackageUrl;

/// A Package URL that could not be built, with the reason.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
#[non_exhaustive]
pub struct PurlError(pub String);

/// Generate Package URL for Maven artifact.
///
/// Returns an error if any of the inputs are empty or invalid.
pub fn maven_purl(group: &str, artifact: &str, version: &str) -> Result<String, PurlError> {
    maven_purl_with_qualifiers(group, artifact, version, "jar", None)
}

/// Generate a Maven Package URL with artifact type and classifier qualifiers.
pub fn maven_purl_with_qualifiers(
    group: &str,
    artifact: &str,
    version: &str,
    packaging: &str,
    classifier: Option<&str>,
) -> Result<String, PurlError> {
    if artifact.trim().is_empty() {
        return Err(PurlError(
            "invalid artifact name '': name cannot be empty".to_string(),
        ));
    }
    if group.trim().is_empty() {
        return Err(PurlError(
            "invalid group '': group cannot be empty".to_string(),
        ));
    }
    if version.trim().is_empty() {
        return Err(PurlError(
            "invalid version '': version cannot be empty".to_string(),
        ));
    }

    let packaging =
        Some(packaging).filter(|packaging| !packaging.is_empty() && *packaging != "jar");
    let classifier = classifier.filter(|classifier| !classifier.is_empty());
    let plain = |value: &str| {
        (value.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    };
    if [group, artifact, version]
        .into_iter()
        .chain(packaging)
        .chain(classifier)
        .all(plain)
    {
        return Ok(plain_maven_purl(
            group, artifact, version, packaging, classifier,
        ));
    }
    encoded_maven_purl(group, artifact, version, packaging, classifier)
}

/// The purl of coordinates that need no percent-encoding, as most do:
/// what [`encoded_maven_purl`] gives for them, without the parse.
fn plain_maven_purl(
    group: &str,
    artifact: &str,
    version: &str,
    packaging: Option<&str>,
    classifier: Option<&str>,
) -> String {
    let mut purl = format!("pkg:maven/{group}/{artifact}@{version}");
    let mut separator = '?';
    for (key, value) in [("classifier", classifier), ("type", packaging)] {
        if let Some(value) = value {
            purl.push(separator);
            purl.push_str(key);
            purl.push('=');
            purl.push_str(value);
            separator = '&';
        }
    }
    purl
}

fn encoded_maven_purl(
    group: &str,
    artifact: &str,
    version: &str,
    packaging: Option<&str>,
    classifier: Option<&str>,
) -> Result<String, PurlError> {
    let mut purl = PackageUrl::new("maven", artifact)
        .map_err(|e| PurlError(format!("invalid artifact name '{}': {}", artifact, e)))?;
    purl.with_namespace(group)
        .and_then(|purl| purl.with_version(version))
        .map_err(|error| PurlError(error.to_string()))?;
    if let Some(packaging) = packaging {
        purl.add_qualifier("type", packaging)
            .map_err(|error| PurlError(error.to_string()))?;
    }
    if let Some(classifier) = classifier {
        purl.add_qualifier("classifier", classifier)
            .map_err(|error| PurlError(error.to_string()))?;
    }
    purl.validate()
        .map_err(|error| PurlError(error.to_string()))?;
    Ok(canonical_purl_string(&purl))
}

fn canonical_purl_string(purl: &PackageUrl<'_>) -> String {
    let rendered = purl.to_string();
    let base = rendered
        .split_once('?')
        .map_or(rendered.as_str(), |(base, _)| base);
    let base = if let Some((path, version)) = base.rsplit_once('@') {
        format!("{path}@{}", version.replace('/', "%2F"))
    } else {
        base.to_string()
    };
    if purl.qualifiers().is_empty() {
        return base;
    }

    let mut qualifiers = purl.qualifiers().iter().collect::<Vec<_>>();
    qualifiers.sort();
    let qualifiers = qualifiers
        .into_iter()
        .map(|(key, value)| format!("{key}={}", encode_qualifier_value(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{qualifiers}")
}

/// Re-renders a purl in the form [`maven_purl_with_qualifiers`] produces, or
/// `None` when it does not parse.
pub fn canonicalize_purl(purl: &str) -> Option<String> {
    let parsed: PackageUrl<'_> = purl.parse().ok()?;
    Some(canonical_purl_string(&parsed))
}

/// The `group:artifact` and version a Maven purl names, percent-decoded, or
/// `None` when it does not parse as one.
pub fn maven_purl_name_version(purl: &str) -> Option<(String, String)> {
    let parsed: PackageUrl<'_> = purl.parse().ok()?;
    if parsed.ty() != "maven" {
        return None;
    }
    let name = format!("{}:{}", parsed.namespace()?, parsed.name());
    Some((name, parsed.version()?.to_string()))
}

fn encode_qualifier_value(value: &str) -> String {
    let mut probe = PackageUrl::new("generic", "probe").expect("valid probe purl");
    probe
        .add_qualifier("value", value)
        .expect("valid probe qualifier");
    probe
        .to_string()
        .split_once("?value=")
        .expect("probe qualifier")
        .1
        .replace('&', "%26")
}

#[cfg(test)]
mod tests {
    use packageurl::PackageUrl;

    use super::{maven_purl, maven_purl_with_qualifiers};

    #[test]
    fn name_and_version_are_decoded() {
        let purl = maven_purl("org.example", "lib", "1.0+2").unwrap();
        assert_eq!(
            super::maven_purl_name_version(&purl),
            Some(("org.example:lib".to_string(), "1.0+2".to_string()))
        );
        assert_eq!(super::maven_purl_name_version("pkg:npm/lib@1"), None);
    }

    #[test]
    fn maven_purl_names_the_coordinates() {
        assert_eq!(
            maven_purl("org.apache", "commons-lang3", "3.12.0").unwrap(),
            "pkg:maven/org.apache/commons-lang3@3.12.0"
        );
        let error = maven_purl("org.example", "", "1.0.0").unwrap_err();
        assert!(error.to_string().contains("invalid artifact name"));
    }

    #[test]
    fn maven_purl_round_trips_reserved_characters_in_every_field() {
        for value in ["%", "@", "/", "&", "=", "?", "#", " ", "\u{e9}"] {
            for field in 0..5 {
                let mut fields =
                    ["org.example", "artifact", "1.0", "zip", "tests"].map(String::from);
                fields[field] = format!("x{value}y");
                let [group, artifact, version, packaging, classifier] = &fields;
                let purl = maven_purl_with_qualifiers(
                    group,
                    artifact,
                    version,
                    packaging,
                    Some(classifier),
                )
                .unwrap();
                let parsed: PackageUrl<'_> = purl.parse().unwrap();
                let qualifier = |name: &str| parsed.qualifiers().get(name).map(|v| v.to_string());
                assert_eq!(parsed.namespace(), Some(group.as_str()), "{purl}");
                assert_eq!(parsed.name(), artifact, "{purl}");
                assert_eq!(parsed.version(), Some(version.as_str()), "{purl}");
                assert_eq!(qualifier("type").as_ref(), Some(packaging), "{purl}");
                assert_eq!(qualifier("classifier").as_ref(), Some(classifier), "{purl}");
            }
        }
    }

    #[test]
    fn plain_coordinates_render_as_encoded_ones_do() {
        for (group, artifact, version) in [
            ("org.example", "lib", "1.0"),
            ("Org_Example.sub-x", "Lib_2-core.x", "1.0.0-SNAPSHOT"),
            ("a", "b", "20260101.123456-1"),
        ] {
            for packaging in [None, Some("pom"), Some("test-jar"), Some("Zip_2.x")] {
                for classifier in [None, Some("tests"), Some("linux-x86_64"), Some("A_b.c")] {
                    assert_eq!(
                        super::plain_maven_purl(group, artifact, version, packaging, classifier),
                        super::encoded_maven_purl(group, artifact, version, packaging, classifier)
                            .unwrap()
                    );
                }
            }
        }
        assert_eq!(
            maven_purl_with_qualifiers("g", "a", "1", "jar", Some("")).unwrap(),
            "pkg:maven/g/a@1"
        );
        assert_eq!(
            maven_purl_with_qualifiers("g", "a", "1", "", Some("tests")).unwrap(),
            "pkg:maven/g/a@1?classifier=tests"
        );
    }

    #[test]
    fn maven_purl_does_not_collapse_percent_encoded_lookalikes() {
        for field in 0..5 {
            let purl = |value: &str| {
                let mut fields = ["g", "a", "1", "zip", "tests"];
                fields[field] = value;
                let [group, artifact, version, packaging, classifier] = fields;
                maven_purl_with_qualifiers(group, artifact, version, packaging, Some(classifier))
                    .unwrap()
            };
            assert_ne!(purl("x@y"), purl("x%40y"), "field {field}");
        }
    }
}
