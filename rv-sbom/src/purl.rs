use packageurl::PackageUrl;

use crate::SbomError;

/// Generate Package URL for Maven artifact.
///
/// Returns an error if any of the inputs are empty or invalid.
pub fn maven_purl(group: &str, artifact: &str, version: &str) -> Result<String, SbomError> {
    maven_purl_with_qualifiers(group, artifact, version, "jar", None)
}

/// Generate a Maven Package URL with artifact type and classifier qualifiers.
pub fn maven_purl_with_qualifiers(
    group: &str,
    artifact: &str,
    version: &str,
    packaging: &str,
    classifier: Option<&str>,
) -> Result<String, SbomError> {
    // Validate inputs before passing to packageurl crate
    if artifact.trim().is_empty() {
        return Err(SbomError::InvalidComponent(
            "invalid artifact name '': name cannot be empty".to_string(),
        ));
    }
    if group.trim().is_empty() {
        return Err(SbomError::InvalidComponent(
            "invalid group '': group cannot be empty".to_string(),
        ));
    }
    if version.trim().is_empty() {
        return Err(SbomError::InvalidComponent(
            "invalid version '': version cannot be empty".to_string(),
        ));
    }

    let mut purl = PackageUrl::new("maven", artifact).map_err(|e| {
        SbomError::InvalidComponent(format!("invalid artifact name '{}': {}", artifact, e))
    })?;
    purl.with_namespace(group)
        .and_then(|purl| purl.with_version(version))
        .map_err(|error| SbomError::InvalidComponent(error.to_string()))?;
    if !packaging.is_empty() && packaging != "jar" {
        purl.add_qualifier("type", packaging)
            .map_err(|error| SbomError::InvalidComponent(error.to_string()))?;
    }
    if let Some(classifier) = classifier.filter(|classifier| !classifier.is_empty()) {
        purl.add_qualifier("classifier", classifier)
            .map_err(|error| SbomError::InvalidComponent(error.to_string()))?;
    }
    purl.validate()
        .map_err(|error| SbomError::InvalidComponent(error.to_string()))?;
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

pub(crate) fn canonicalize_purl(purl: &str) -> Option<String> {
    let parsed: PackageUrl = purl.parse().ok()?;
    Some(canonical_purl_string(&parsed))
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

/// Parse a Package URL
///
/// Returns (group, artifact, version) if the purl is a valid Maven purl.
pub fn parse_purl(purl: &str) -> Option<(String, String, String)> {
    let parsed: PackageUrl = purl.parse().ok()?;

    // Only accept Maven purls
    if parsed.ty() != "maven" {
        return None;
    }

    let namespace = parsed.namespace()?;
    let name = parsed.name();
    let version = parsed.version()?;

    if namespace.is_empty() || name.is_empty() || version.is_empty() {
        return None;
    }

    Some((namespace.to_string(), name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use packageurl::PackageUrl;

    use super::{maven_purl, maven_purl_with_qualifiers, parse_purl};

    #[test]
    fn maven_purl_roundtrip() {
        let purl = maven_purl("org.apache", "commons-lang3", "3.12.0")
            .expect("expected purl generation to succeed");
        assert_eq!(purl, "pkg:maven/org.apache/commons-lang3@3.12.0");

        let parsed = parse_purl(&purl).expect("expected purl to parse");
        assert_eq!(parsed.0, "org.apache");
        assert_eq!(parsed.1, "commons-lang3");
        assert_eq!(parsed.2, "3.12.0");
    }

    #[test]
    fn maven_purl_rejects_empty_artifact() {
        let result = maven_purl("org.example", "", "1.0.0");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid artifact name"));
    }

    #[test]
    fn parse_purl_strips_qualifiers() {
        let parsed =
            parse_purl("pkg:maven/org.example/app@1.0.0?type=jar").expect("expected purl to parse");
        assert_eq!(parsed.2, "1.0.0");
    }

    #[test]
    fn parse_purl_rejects_invalid() {
        assert!(parse_purl("pkg:maven/just-group@1.0.0").is_none());
        assert!(parse_purl("pkg:generic/thing@1.0.0").is_none());
    }

    #[test]
    fn maven_purl_escapes_special_characters() {
        let group = "org.example team";
        let artifact = "artifact@core";
        let version = "1.0.0";
        let purl = maven_purl(group, artifact, version).expect("purl generation");

        assert!(purl.contains("org.example%20team"));
        assert!(purl.contains("artifact%40core"));

        let parsed = parse_purl(&purl).expect("parse generated purl");
        assert_eq!(parsed.0, group);
        assert_eq!(parsed.1, artifact);
        assert_eq!(parsed.2, version);
    }

    #[test]
    fn maven_purl_round_trips_reserved_characters_in_every_field() {
        const VALUES: &[&str] = &["%", "@", "/", "&", "=", "?", "#", " ", "é"];

        for value in VALUES {
            let group = format!("org{value}example");
            assert_fields(&group, "artifact", "1.0", "zip", "tests");

            let artifact = format!("artifact{value}core");
            assert_fields("org.example", &artifact, "1.0", "zip", "tests");

            let version = format!("1{value}0");
            assert_fields("org.example", "artifact", &version, "zip", "tests");

            let packaging = format!("type{value}value");
            assert_fields("org.example", "artifact", "1.0", &packaging, "tests");

            let classifier = format!("class{value}value");
            assert_fields("org.example", "artifact", "1.0", "zip", &classifier);
        }
    }

    #[test]
    fn maven_purl_does_not_collapse_percent_encoded_lookalikes() {
        assert_distinct("g@x", "g%40x", "a", "1", "zip", "tests");
        assert_distinct("g", "g", "a@x", "a%40x", "zip", "tests");
        assert_distinct("g", "g", "a", "a", "v@x", "v%40x");

        let type_at =
            maven_purl_with_qualifiers("g", "a", "1", "t@x", Some("tests")).expect("type purl");
        let type_percent =
            maven_purl_with_qualifiers("g", "a", "1", "t%40x", Some("tests")).expect("type purl");
        assert_ne!(type_at, type_percent);

        let classifier_at =
            maven_purl_with_qualifiers("g", "a", "1", "zip", Some("c@x")).expect("classifier purl");
        let classifier_percent = maven_purl_with_qualifiers("g", "a", "1", "zip", Some("c%40x"))
            .expect("classifier purl");
        assert_ne!(classifier_at, classifier_percent);
    }

    fn assert_fields(
        group: &str,
        artifact: &str,
        version: &str,
        packaging: &str,
        classifier: &str,
    ) {
        let purl =
            maven_purl_with_qualifiers(group, artifact, version, packaging, Some(classifier))
                .expect("purl");
        let parsed: PackageUrl = purl.parse().expect("parse purl");
        assert_eq!(parsed.namespace(), Some(group));
        assert_eq!(parsed.name(), artifact);
        assert_eq!(parsed.version(), Some(version));
        assert_eq!(
            parsed.qualifiers().get("type").map(|value| value.as_ref()),
            Some(packaging)
        );
        assert_eq!(
            parsed
                .qualifiers()
                .get("classifier")
                .map(|value| value.as_ref()),
            Some(classifier)
        );
        let rebuilt = maven_purl_with_qualifiers(
            parsed.namespace().unwrap(),
            parsed.name(),
            parsed.version().unwrap(),
            parsed.qualifiers().get("type").unwrap(),
            parsed
                .qualifiers()
                .get("classifier")
                .map(|value| value.as_ref()),
        )
        .expect("rebuild purl");
        assert_eq!(rebuilt, purl);
    }

    fn assert_distinct(
        left_group: &str,
        right_group: &str,
        left_artifact: &str,
        right_artifact: &str,
        left_version: &str,
        right_version: &str,
    ) {
        let left = maven_purl(left_group, left_artifact, left_version).expect("left purl");
        let right = maven_purl(right_group, right_artifact, right_version).expect("right purl");
        assert_ne!(left, right);
    }

    #[test]
    fn parse_purl_rejects_non_maven_purls() {
        assert!(parse_purl("pkg:npm/react@18.2.0").is_none());
        assert!(parse_purl("pkg:golang/github.com/pkg/errors@v0.9.1").is_none());
    }

    #[test]
    fn parse_purl_rejects_malformed_purls() {
        assert!(parse_purl("not-a-purl").is_none());
        assert!(parse_purl("pkg:maven/@1.0.0").is_none());
        assert!(parse_purl("pkg:maven/org.example/app").is_none());
    }
}
