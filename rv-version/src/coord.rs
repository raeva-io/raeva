use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ArtifactId, GroupId, Version, VersionError};

/// A fully-qualified Maven coordinate (groupId:artifactId:version[:packaging[:classifier]]).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Coord {
    pub group_id: GroupId,
    pub artifact_id: ArtifactId,
    pub version: Version,
    pub packaging: Option<String>,
    pub classifier: Option<String>,
}

impl Coord {
    /// Parses a colon-separated coordinate string (e.g. `"com.example:lib:1.0"`).
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(VersionError::InvalidCoord(trimmed.to_string()));
        }

        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() < 3 || parts.len() > 5 {
            return Err(VersionError::InvalidCoord(trimmed.to_string()));
        }

        let group_id = parts[0].trim();
        let artifact_id = parts[1].trim();
        let version_str = parts[2].trim();

        // The three positional components are mandatory and must be non-empty.
        if group_id.is_empty() || artifact_id.is_empty() || version_str.is_empty() {
            return Err(VersionError::InvalidCoord(trimmed.to_string()));
        }

        let packaging = parts.get(3).map(|s| s.trim());
        let classifier = parts.get(4).map(|s| s.trim());

        // The only empty optional segment we tolerate is an empty PACKAGING slot
        // followed by a non-empty classifier, i.e. the `g:a:1::tests` shape that
        // `Display` emits for a classifier-without-packaging `Coord`. Accepting
        // it makes the serde round-trip total. Every other empty optional
        // segment (a trailing empty packaging or classifier such as `g:a:1:`,
        // `g:a:1::`, `g:a:1:jar:`) stays rejected so coordinates cannot alias.
        if let Some(classifier) = classifier {
            // A classifier slot is present (5 segments). The classifier itself
            // must be non-empty; an empty packaging slot before it is allowed
            // (that is the `g:a:1::tests` round-trip shape).
            if classifier.is_empty() {
                return Err(VersionError::InvalidCoord(trimmed.to_string()));
            }
        } else if let Some(packaging) = packaging
            && packaging.is_empty()
        {
            // 4 segments with an empty trailing packaging slot (`g:a:1:`).
            return Err(VersionError::InvalidCoord(trimmed.to_string()));
        }

        let version = Version::parse(version_str)
            .map_err(|_| VersionError::InvalidCoord(trimmed.to_string()))?;

        // An empty packaging slot (only reachable when a classifier follows)
        // means "no packaging": store it as `None` so the parsed value equals
        // the `Coord` that produced the rendered string.
        let packaging = packaging.filter(|s| !s.is_empty());

        Ok(Self {
            group_id: GroupId::from(group_id),
            artifact_id: ArtifactId::from(artifact_id),
            version,
            packaging: packaging.map(ToString::to_string),
            classifier: classifier.map(ToString::to_string),
        })
    }
}

impl fmt::Display for Coord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.group_id, self.artifact_id, self.version)?;
        if let Some(packaging) = &self.packaging {
            write!(f, ":{}", packaging)?;
            if let Some(classifier) = &self.classifier {
                write!(f, ":{}", classifier)?;
            }
        } else if let Some(classifier) = &self.classifier {
            write!(f, "::{}", classifier)?;
        }
        Ok(())
    }
}

impl FromStr for Coord {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Coord::parse(s)
    }
}

impl Serialize for Coord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Coord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Coord::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A partially-specified Maven coordinate for search and matching.
///
/// Supports artifact-only (`"my-lib"`), group:artifact (`"com.example:lib"`),
/// or full coordinates. Use `matches()` to test against a full `Coord`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PartialCoord {
    pub group_id: Option<GroupId>,
    pub artifact_id: ArtifactId,
    pub version: Option<Version>,
    pub packaging: Option<String>,
    pub classifier: Option<String>,
}

impl PartialCoord {
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(VersionError::InvalidCoord(trimmed.to_string()));
        }

        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() > 5 {
            return Err(VersionError::InvalidCoord(trimmed.to_string()));
        }

        // Single segment: artifact-only search
        if parts.len() == 1 {
            let artifact_id = parts[0].trim();
            if artifact_id.is_empty() {
                return Err(VersionError::InvalidCoord(trimmed.to_string()));
            }
            return Ok(Self {
                group_id: None,
                artifact_id: ArtifactId::from(artifact_id),
                version: None,
                packaging: None,
                classifier: None,
            });
        }

        // Two or more segments: group:artifact[:version[:packaging[:classifier]]]
        let group_id = parts[0].trim();
        let artifact_id = parts[1].trim();

        if group_id.is_empty() || artifact_id.is_empty() {
            return Err(VersionError::InvalidCoord(trimmed.to_string()));
        }

        // A trailing colon with no payload after it is meaningless: any number
        // of empty segments after the last non-empty positional component is
        // rejected. Inspecting only the literal `last` segment is not enough:
        // `g:a:::` would parse as a wildcard while `g:a:::::` would slip
        // through because middle segments happen to populate the optional
        // fields. Reject any input with trailing empties.
        let trailing_empty_count = parts
            .iter()
            .rev()
            .take_while(|s| s.trim().is_empty())
            .count();
        if trailing_empty_count > 0 {
            return Err(VersionError::InvalidCoord(trimmed.to_string()));
        }

        // Optional positional segments use an empty placeholder ("::") to mean
        // "wildcard" so the canonical Display form round-trips losslessly
        // through `parse` and produces an equivalent matching predicate.
        let version = parts
            .get(2)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|v| Version::parse(v).map_err(|_| VersionError::InvalidCoord(trimmed.to_string())))
            .transpose()?;

        let packaging = parts.get(3).map(|s| s.trim()).filter(|s| !s.is_empty());
        let classifier = parts.get(4).map(|s| s.trim()).filter(|s| !s.is_empty());

        Ok(Self {
            group_id: Some(GroupId::from(group_id)),
            artifact_id: ArtifactId::from(artifact_id),
            version,
            packaging: packaging.map(ToString::to_string),
            classifier: classifier.map(ToString::to_string),
        })
    }

    #[cfg(test)]
    pub(crate) fn has_version(&self) -> bool {
        self.version.is_some()
    }

    #[cfg(test)]
    pub(crate) fn has_group(&self) -> bool {
        self.group_id.is_some()
    }

    #[cfg(test)]
    pub(crate) fn is_artifact_only(&self) -> bool {
        self.group_id.is_none()
    }

    /// Converts to a full `Coord` if both group and version are present.
    #[cfg(test)]
    pub(crate) fn to_coord(&self) -> Option<Coord> {
        match (&self.group_id, &self.version) {
            (Some(group_id), Some(version)) => Some(Coord {
                group_id: group_id.clone(),
                artifact_id: self.artifact_id.clone(),
                version: version.clone(),
                packaging: self.packaging.clone(),
                classifier: self.classifier.clone(),
            }),
            _ => None,
        }
    }

    /// Returns true if this partial coordinate matches the given full coordinate.
    pub fn matches(&self, coord: &Coord) -> bool {
        if let Some(ref group_id) = self.group_id
            && *group_id != coord.group_id
        {
            return false;
        }
        if self.artifact_id != coord.artifact_id {
            return false;
        }
        if let Some(ref version) = self.version
            && *version != coord.version
        {
            return false;
        }
        if let Some(ref packaging) = self.packaging
            && coord.packaging.as_deref() != Some(packaging.as_str())
        {
            return false;
        }
        if let Some(ref classifier) = self.classifier
            && coord.classifier.as_deref() != Some(classifier.as_str())
        {
            return false;
        }
        true
    }
}

impl fmt::Display for PartialCoord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Canonical form: every component that participates in `matches()` must
        // also appear in the rendered string, so a Display->parse->matches
        // round-trip preserves semantics. When an "outer" optional field
        // (version, packaging) is missing but an "inner" field is set, an
        // empty placeholder segment is emitted between the colons.
        let Some(ref group_id) = self.group_id else {
            // Artifact-only partial coords cannot carry version/packaging/
            // classifier information through parse, so the matching predicate
            // ignores them too; we only emit the artifact id.
            return write!(f, "{}", self.artifact_id);
        };

        write!(f, "{}:{}", group_id, self.artifact_id)?;

        let has_tail =
            self.version.is_some() || self.packaging.is_some() || self.classifier.is_some();
        if !has_tail {
            return Ok(());
        }

        match &self.version {
            Some(version) => write!(f, ":{}", version)?,
            None => write!(f, ":")?,
        }

        let has_pkg_or_classifier = self.packaging.is_some() || self.classifier.is_some();
        if !has_pkg_or_classifier {
            return Ok(());
        }

        match &self.packaging {
            Some(packaging) => write!(f, ":{}", packaging)?,
            None => write!(f, ":")?,
        }

        if let Some(ref classifier) = self.classifier {
            write!(f, ":{}", classifier)?;
        }

        Ok(())
    }
}

impl FromStr for PartialCoord {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PartialCoord::parse(s)
    }
}

impl From<Coord> for PartialCoord {
    fn from(coord: Coord) -> Self {
        Self {
            group_id: Some(coord.group_id),
            artifact_id: coord.artifact_id,
            version: Some(coord.version),
            packaging: coord.packaging,
            classifier: coord.classifier,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Coord, PartialCoord};

    #[test]
    fn parse_basic_coord() {
        let c = Coord::parse("g:a:1.0").unwrap();
        assert_eq!(c.group_id.as_str(), "g");
        assert_eq!(c.artifact_id.as_str(), "a");
        assert_eq!(c.version.to_string(), "1.0");
        assert!(c.packaging.is_none());
        assert!(c.classifier.is_none());
        assert_eq!(c.to_string(), "g:a:1.0");
    }

    #[test]
    fn parse_with_packaging_and_classifier() {
        let c = Coord::parse("g:a:1.0:jar:tests").unwrap();
        assert_eq!(c.packaging.as_deref(), Some("jar"));
        assert_eq!(c.classifier.as_deref(), Some("tests"));
        assert_eq!(c.to_string(), "g:a:1.0:jar:tests");
    }

    #[test]
    fn invalid_coord_is_error() {
        Coord::parse("g:a").expect_err("requires version segment");
    }

    #[test]
    fn partial_coord_without_version() {
        let pc = PartialCoord::parse("g:a").unwrap();
        assert_eq!(pc.group_id.as_ref().unwrap().as_str(), "g");
        assert_eq!(pc.artifact_id.as_str(), "a");
        assert!(pc.version.is_none());
        assert!(!pc.has_version());
        assert!(pc.has_group());
        assert_eq!(pc.to_string(), "g:a");
    }

    #[test]
    fn partial_coord_with_version() {
        let pc = PartialCoord::parse("g:a:1.0").unwrap();
        assert_eq!(pc.group_id.as_ref().unwrap().as_str(), "g");
        assert_eq!(pc.artifact_id.as_str(), "a");
        assert!(pc.has_version());
        assert!(pc.has_group());
        assert_eq!(pc.version.as_ref().unwrap().to_string(), "1.0");
        assert_eq!(pc.to_string(), "g:a:1.0");
    }

    #[test]
    fn partial_coord_artifact_only() {
        let pc = PartialCoord::parse("my-artifact").unwrap();
        assert!(pc.group_id.is_none());
        assert_eq!(pc.artifact_id.as_str(), "my-artifact");
        assert!(pc.version.is_none());
        assert!(!pc.has_group());
        assert!(pc.is_artifact_only());
        assert_eq!(pc.to_string(), "my-artifact");
    }

    #[test]
    fn partial_coord_artifact_only_matches_any_group() {
        let pc = PartialCoord::parse("demo").unwrap();
        let c1 = Coord::parse("com.example:demo:1.0").unwrap();
        let c2 = Coord::parse("org.other:demo:2.0").unwrap();
        let c3 = Coord::parse("com.example:other:1.0").unwrap();

        assert!(pc.matches(&c1)); // matches - same artifact
        assert!(pc.matches(&c2)); // matches - same artifact, different group
        assert!(!pc.matches(&c3)); // doesn't match - different artifact
    }

    #[test]
    fn partial_coord_matches_any_version() {
        let pc = PartialCoord::parse("g:a").unwrap();
        let c1 = Coord::parse("g:a:1.0").unwrap();
        let c2 = Coord::parse("g:a:2.0").unwrap();
        let c3 = Coord::parse("g:b:1.0").unwrap();

        assert!(pc.matches(&c1));
        assert!(pc.matches(&c2));
        assert!(!pc.matches(&c3));
    }

    #[test]
    fn partial_coord_matches_specific_version() {
        let pc = PartialCoord::parse("g:a:1.0").unwrap();
        let c1 = Coord::parse("g:a:1.0").unwrap();
        let c2 = Coord::parse("g:a:2.0").unwrap();

        assert!(pc.matches(&c1));
        assert!(!pc.matches(&c2));
    }

    #[test]
    fn partial_coord_to_coord() {
        let pc_with = PartialCoord::parse("g:a:1.0").unwrap();
        let pc_without = PartialCoord::parse("g:a").unwrap();

        assert!(pc_with.to_coord().is_some());
        assert!(pc_without.to_coord().is_none());
    }

    // ===== Regression tests =====

    /// `Coord::parse` must reject a trailing empty segment such as
    /// `g:a:1:`, `g:a:1::`, or `g:a:1:jar:`. The previous parser silently
    /// dropped the trailing empty classifier, opening the door to
    /// coordinate aliasing.
    #[test]
    fn coord_parse_rejects_trailing_empty_segments() {
        for bad in &["g:a:1:", "g:a:1::", "g:a:1:jar:", "g:a:1: :"] {
            assert!(
                Coord::parse(bad).is_err(),
                "Coord::parse({bad:?}) should have failed"
            );
        }
    }

    #[test]
    fn coord_parse_still_accepts_fully_qualified() {
        for good in ["g:a:1", "g:a:1:jar", "g:a:1:jar:tests"] {
            Coord::parse(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
    }

    /// Regression for #54: a `Coord` carrying a classifier but NO packaging
    /// renders as `g:a:1.0::tests` (empty packaging placeholder). Parsing that
    /// back used to fail because the empty middle segment was rejected, so the
    /// serde round-trip was not total. The empty packaging slot before a
    /// non-empty classifier must parse back to `packaging: None`.
    #[test]
    fn coord_classifier_without_packaging_round_trips() {
        let c = Coord {
            group_id: crate::GroupId::from("com.example"),
            artifact_id: crate::ArtifactId::from("lib"),
            version: crate::Version::parse("1.0").unwrap(),
            packaging: None,
            classifier: Some("tests".to_string()),
        };
        let rendered = c.to_string();
        assert_eq!(rendered, "com.example:lib:1.0::tests");

        let parsed = Coord::parse(&rendered)
            .unwrap_or_else(|e| panic!("re-parse of {rendered:?} failed: {e}"));
        assert_eq!(c, parsed, "Coord round-trip diverged");
        assert!(parsed.packaging.is_none());
        assert_eq!(parsed.classifier.as_deref(), Some("tests"));
    }

    /// The serde representation (string newtype) must round-trip the same
    /// classifier-without-packaging shape.
    #[test]
    fn coord_classifier_without_packaging_serde_round_trips() {
        let c = Coord {
            group_id: crate::GroupId::from("com.example"),
            artifact_id: crate::ArtifactId::from("lib"),
            version: crate::Version::parse("1.0").unwrap(),
            packaging: None,
            classifier: Some("sources".to_string()),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"com.example:lib:1.0::sources\"");
        let back: Coord = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    /// `PartialCoord` Display and `matches()` must agree: parsing the
    /// rendered form back must produce a value with the same matching
    /// behaviour for any full Coord.
    #[test]
    fn partial_coord_display_round_trip_preserves_matching() {
        let target_with_classifier = Coord::parse("com.example:lib:1.0:jar:tests").unwrap();
        let target_no_classifier = Coord::parse("com.example:lib:1.0:jar").unwrap();
        let target_other_artifact = Coord::parse("com.example:other:1.0:jar:tests").unwrap();

        let cases = vec![
            "lib",
            "com.example:lib",
            "com.example:lib:1.0",
            "com.example:lib:1.0:jar",
            "com.example:lib:1.0:jar:tests",
        ];

        for input in cases {
            let original = PartialCoord::parse(input)
                .unwrap_or_else(|err| panic!("failed to parse {input:?}: {err}"));
            let rendered = original.to_string();
            let parsed = PartialCoord::parse(&rendered)
                .unwrap_or_else(|err| panic!("failed to re-parse {rendered:?}: {err}"));
            assert_eq!(
                original.matches(&target_with_classifier),
                parsed.matches(&target_with_classifier),
                "matching diverged for {input:?} -> {rendered:?}"
            );
            assert_eq!(
                original.matches(&target_no_classifier),
                parsed.matches(&target_no_classifier),
                "matching diverged for {input:?} -> {rendered:?}"
            );
            assert_eq!(
                original.matches(&target_other_artifact),
                parsed.matches(&target_other_artifact),
                "matching diverged for {input:?} -> {rendered:?}"
            );
        }
    }

    /// A `PartialCoord` programmatically constructed with sparse optional
    /// fields must round-trip through Display+parse without losing its
    /// matching semantics.
    #[test]
    fn partial_coord_with_packaging_but_no_version_round_trips() {
        let pc = PartialCoord {
            group_id: Some(crate::GroupId::from("com.example")),
            artifact_id: crate::ArtifactId::from("lib"),
            version: None,
            packaging: Some("jar".to_string()),
            classifier: None,
        };
        let rendered = pc.to_string();
        let parsed = PartialCoord::parse(&rendered)
            .unwrap_or_else(|err| panic!("failed to re-parse {rendered:?}: {err}"));
        assert_eq!(pc, parsed);

        // And the matching predicate agrees on real coords:
        let coord_jar = Coord::parse("com.example:lib:1.0:jar").unwrap();
        let coord_pom = Coord::parse("com.example:lib:1.0").unwrap();
        assert_eq!(pc.matches(&coord_jar), parsed.matches(&coord_jar));
        assert_eq!(pc.matches(&coord_pom), parsed.matches(&coord_pom));
    }

    /// Regression: any number of trailing empty segments must be
    /// rejected uniformly. The previous parser only inspected the literal
    /// last segment, so an input where middle positions happened to fill
    /// the optional fields (`g:a:1::`, but not `g:a:::::`) leaked through.
    #[test]
    fn partial_coord_trailing_empty_segments_are_rejected() {
        for bad in &["g:a:", "g:a::", "g:a:::", "g:a::::", "g:a:::::"] {
            PartialCoord::parse(bad).expect_err(bad);
        }
    }

    /// Middle empty segments are still allowed as wildcard placeholders, but
    /// only when followed by at least one non-empty positional component.
    #[test]
    fn partial_coord_middle_empty_segments_remain_valid() {
        for good in ["g:a::jar", "g:a:::tests", "g:a::jar:tests"] {
            PartialCoord::parse(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
    }
}
