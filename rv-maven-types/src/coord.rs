use std::fmt;
use std::sync::Arc;

use crate::component::{
    CoordinateField, InvalidCoordinateComponent, validate_coordinate_component,
};
use crate::{ArtifactId, GroupId, Version, VersionError};

/// A fully-qualified Maven coordinate (`groupId:artifactId:version[:packaging[:classifier]]`).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Coord {
    /// The `groupId`.
    pub group_id: GroupId,
    /// The `artifactId`.
    pub artifact_id: ArtifactId,
    /// The parsed version. Two strings that parse equal, such as `1.0` and
    /// `1.0.0`, give equal coordinates.
    pub version: Version,
    /// The packaging, the fourth segment of the string form.
    pub packaging: Option<String>,
    /// The classifier, the fifth segment. Without a packaging it is written
    /// after an empty fourth segment (`g:a:1::tests`).
    pub classifier: Option<String>,
}

impl Coord {
    /// Parses a colon-separated coordinate string (e.g. `"com.example:lib:1.0"`).
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        let invalid = || VersionError::InvalidCoord(trimmed.to_string());
        let parts: Vec<&str> = trimmed.split(':').map(str::trim).collect();
        let [group_id, artifact_id, version, rest @ ..] = parts.as_slice() else {
            return Err(invalid());
        };
        // `g:a:1::tests` is how `Display` writes a classifier without a
        // packaging. Every other empty segment is refused, so coordinates
        // cannot alias.
        let (packaging, classifier) = match rest {
            [] => (None, None),
            [packaging] if !packaging.is_empty() => (Some(*packaging), None),
            [packaging, classifier] if !classifier.is_empty() => (
                Some(*packaging).filter(|p| !p.is_empty()),
                Some(*classifier),
            ),
            _ => return Err(invalid()),
        };
        if group_id.is_empty() || artifact_id.is_empty() || version.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            group_id: GroupId::from(*group_id),
            artifact_id: ArtifactId::from(*artifact_id),
            version: Version::parse(version).map_err(|_| invalid())?,
            packaging: packaging.map(ToString::to_string),
            classifier: classifier.map(ToString::to_string),
        })
    }
}

impl fmt::Display for Coord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.group_id, self.artifact_id, self.version)?;
        match (&self.packaging, &self.classifier) {
            (Some(packaging), Some(classifier)) => write!(f, ":{packaging}:{classifier}"),
            (Some(packaging), None) => write!(f, ":{packaging}"),
            (None, Some(classifier)) => write!(f, "::{classifier}"),
            (None, None) => Ok(()),
        }
    }
}

impl std::str::FromStr for Coord {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Coord::parse(s)
    }
}

/// A partially-specified Maven coordinate for search and matching.
///
/// Supports artifact-only (`"my-lib"`), group:artifact (`"com.example:lib"`),
/// or full coordinates. Use `matches()` to test against a full `Coord`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PartialCoord {
    /// The `groupId` to match, or `None` for an artifact-only search.
    pub group_id: Option<GroupId>,
    /// The `artifactId` to match. It is always present.
    pub artifact_id: ArtifactId,
    /// The version to match, or `None` for any version.
    pub version: Option<Version>,
    /// The packaging to match, or `None` for any packaging.
    pub packaging: Option<String>,
    /// The classifier to match, or `None` for any classifier.
    pub classifier: Option<String>,
}

impl PartialCoord {
    /// Parses `artifact` or `group:artifact[:version[:packaging[:classifier]]]`.
    ///
    /// An empty middle segment is a wildcard (`g:a::jar` matches any
    /// version), so the [`Display`](fmt::Display) form parses back to an
    /// equal value. Trailing empty segments and more than five segments are
    /// refused. Only the version is checked, by [`Version::parse`]; no
    /// character rules are applied.
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let trimmed = s.trim();
        let invalid = || VersionError::InvalidCoord(trimmed.to_string());
        let parts: Vec<&str> = trimmed.split(':').map(str::trim).collect();
        if parts.len() > 5 || parts.last().is_some_and(|last| last.is_empty()) {
            return Err(invalid());
        }
        if let [artifact_id] = parts[..] {
            return Ok(Self {
                group_id: None,
                artifact_id: ArtifactId::from(artifact_id),
                version: None,
                packaging: None,
                classifier: None,
            });
        }
        if parts[0].is_empty() || parts[1].is_empty() {
            return Err(invalid());
        }
        // An empty middle segment is a wildcard.
        let field = |index: usize| parts.get(index).copied().filter(|part| !part.is_empty());
        let version = field(2)
            .map(|version| Version::parse(version).map_err(|_| invalid()))
            .transpose()?;
        Ok(Self {
            group_id: Some(GroupId::from(parts[0])),
            artifact_id: ArtifactId::from(parts[1]),
            version,
            packaging: field(3).map(ToString::to_string),
            classifier: field(4).map(ToString::to_string),
        })
    }

    /// Returns true if this partial coordinate matches the given full coordinate.
    pub fn matches(&self, coord: &Coord) -> bool {
        self.group_id
            .as_ref()
            .is_none_or(|id| *id == coord.group_id)
            && self.artifact_id == coord.artifact_id
            && self.version.as_ref().is_none_or(|v| *v == coord.version)
            && (self.packaging.as_ref()).is_none_or(|p| coord.packaging.as_ref() == Some(p))
            && (self.classifier.as_ref()).is_none_or(|c| coord.classifier.as_ref() == Some(c))
    }
}

impl fmt::Display for PartialCoord {
    /// Every component `matches` reads is written, with an empty segment
    /// for a missing version or packaging before a set one, so the text
    /// parses back to an equal value. An artifact-only value has no other
    /// component.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(group_id) = &self.group_id else {
            return write!(f, "{}", self.artifact_id);
        };
        write!(f, "{group_id}:{}", self.artifact_id)?;
        let tail = self.packaging.is_some() || self.classifier.is_some();
        if self.version.is_none() && !tail {
            return Ok(());
        }
        write!(f, ":")?;
        if let Some(version) = &self.version {
            write!(f, "{version}")?;
        }
        if !tail {
            return Ok(());
        }
        write!(f, ":{}", self.packaging.as_deref().unwrap_or_default())?;
        if let Some(classifier) = &self.classifier {
            write!(f, ":{classifier}")?;
        }
        Ok(())
    }
}

/// A group, artifact and the version exactly as written.
///
/// The version is a string, never a parsed [`Version`]: `1.0` and `1.0.0`
/// compare equal as versions but name different files in a repository, and
/// the string is what raeva.lock and the model hash record. Nothing trims or
/// normalizes it.
///
/// The order is the order of the three strings, group first. The derived
/// order of [`Gav`] differs from the order of the joined `g:a:v` text.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Gav {
    /// The `groupId`, unchecked until [`Gav::validate`].
    pub group: GroupId,
    /// The `artifactId`, unchecked until [`Gav::validate`].
    pub artifact: ArtifactId,
    version: Arc<str>,
}

impl Gav {
    /// No character rules here; call [`Gav::validate`] before a path, URL, or line-oriented file.
    pub fn new(group: &str, artifact: &str, version: &str) -> Self {
        Self {
            group: group.into(),
            artifact: artifact.into(),
            version: Arc::from(version),
        }
    }

    /// The version exactly as written.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Checks the three parts with [`validate_coordinate_component`].
    pub fn validate(&self) -> Result<(), InvalidCoordinateComponent> {
        validate_coordinate_component(CoordinateField::Group, self.group.as_str())?;
        validate_coordinate_component(CoordinateField::Artifact, self.artifact.as_str())?;
        validate_coordinate_component(CoordinateField::Version, &self.version)
    }
}

impl fmt::Display for Gav {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.group, self.artifact, self.version)
    }
}

/// One file of a Maven artifact: a [`Gav`], the file extension and an
/// optional classifier.
///
/// The extension is what raeva.lock calls `packaging`. An empty classifier is
/// the same as none: [`ArtifactCoord::new`] maps it to `None`, so the two
/// cannot give unequal keys or unequal hashes, and a key survives the
/// artifact index, which stores no classifier as `""`.
///
/// The derived order is group, artifact, version, extension, classifier,
/// each as a string, which is the order of the lock rows.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArtifactCoord {
    /// The group, artifact and version of the file.
    pub gav: Gav,
    extension: Arc<str>,
    classifier: Option<Arc<str>>,
}

impl ArtifactCoord {
    /// Same absence of checks as [`Gav::new`].
    pub fn new(
        group: &str,
        artifact: &str,
        version: &str,
        extension: &str,
        classifier: Option<&str>,
    ) -> Self {
        Self::of(Gav::new(group, artifact, version), extension, classifier)
    }

    /// An empty classifier becomes `None`.
    pub fn of(gav: Gav, extension: &str, classifier: Option<&str>) -> Self {
        Self {
            gav,
            extension: Arc::from(extension),
            classifier: classifier.filter(|c| !c.is_empty()).map(Arc::from),
        }
    }

    /// The `groupId` of [`Self::gav`].
    pub fn group_id(&self) -> &str {
        self.gav.group.as_str()
    }

    /// The `artifactId` of [`Self::gav`].
    pub fn artifact_id(&self) -> &str {
        self.gav.artifact.as_str()
    }

    /// The version of [`Self::gav`], exactly as written.
    pub fn version(&self) -> &str {
        self.gav.version()
    }

    /// The file extension, which raeva.lock records as `packaging`.
    pub fn extension(&self) -> &str {
        &self.extension
    }

    /// The classifier, never `Some("")`.
    pub fn classifier(&self) -> Option<&str> {
        self.classifier.as_deref()
    }

    /// The classifier as the artifact index stores it: the classifier, or
    /// `""` when there is none.
    pub fn classifier_key(&self) -> &str {
        self.classifier.as_deref().unwrap_or("")
    }

    /// The POM of the same GAV.
    pub fn pom(&self) -> Self {
        Self::of(self.gav.clone(), "pom", None)
    }

    /// Checks every part with [`validate_coordinate_component`].
    pub fn validate(&self) -> Result<(), InvalidCoordinateComponent> {
        self.gav.validate()?;
        validate_coordinate_component(CoordinateField::Extension, &self.extension)?;
        self.classifier().map_or(Ok(()), |classifier| {
            validate_coordinate_component(CoordinateField::Classifier, classifier)
        })
    }
}

/// `g:a:v:extension[:classifier]`.
impl fmt::Display for ArtifactCoord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.gav, self.extension)?;
        if let Some(classifier) = &self.classifier {
            write!(f, ":{classifier}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactCoord, Coord, Gav, PartialCoord};

    #[test]
    fn coord_parse_and_display() {
        for (input, shown) in [
            ("g:a:1.0", "g:a:1.0"),
            (" g : a : 1.0 ", "g:a:1.0"),
            ("g:a:1.0:jar:tests", "g:a:1.0:jar:tests"),
            ("g:a:1.0::tests", "g:a:1.0::tests"),
        ] {
            assert_eq!(Coord::parse(input).unwrap().to_string(), shown);
        }
        let parsed = Coord::parse("g:a:1.0::tests").unwrap();
        assert_eq!(parsed.packaging, None);
        assert_eq!(parsed.classifier.as_deref(), Some("tests"));
        for bad in [
            "",
            "g:a",
            "g::1",
            "g:a:1:",
            "g:a:1::",
            "g:a:1:jar:",
            "g:a:1: :",
            "a:b:c:d:e:f",
        ] {
            Coord::parse(bad).expect_err(bad);
        }
    }

    #[test]
    fn partial_coord_parse_and_match() {
        let coords: Vec<Coord> = ["g:a:1.0", "g:a:2.0:jar:tests", "h:a:1.0:jar", "g:b:1.0"]
            .iter()
            .map(|c| Coord::parse(c).unwrap())
            .collect();
        for (pattern, matching) in [
            ("a", [true, true, true, false]),
            ("g:a", [true, true, false, false]),
            ("g:a:1.0", [true, false, false, false]),
            ("g:a::jar", [false, true, false, false]),
            ("g:a:::tests", [false, true, false, false]),
            ("g:a::jar:tests", [false, true, false, false]),
        ] {
            let partial = PartialCoord::parse(pattern).unwrap();
            assert_eq!(PartialCoord::parse(&partial.to_string()).unwrap(), partial);
            let got: Vec<bool> = coords.iter().map(|c| partial.matches(c)).collect();
            assert_eq!(got, matching, "{pattern}");
        }
        for bad in [
            "",
            ":a",
            "g:",
            "g:a:",
            "g:a::",
            "g:a:::::",
            "g:a:1:j:c:x",
            "g:a:${v}",
        ] {
            PartialCoord::parse(bad).expect_err(bad);
        }
    }

    #[test]
    fn gav_and_artifact_coord() {
        let one = Gav::new("g", "a", "1.0");
        assert_ne!(one, Gav::new("g", "a", "1.0.0"));
        assert_eq!(
            (one.version(), one.to_string().as_str()),
            ("1.0", "g:a:1.0")
        );

        let empty = ArtifactCoord::new("g", "a", "1", "jar", Some(""));
        assert_eq!(empty, ArtifactCoord::new("g", "a", "1", "jar", None));
        assert_eq!((empty.classifier(), empty.classifier_key()), (None, ""));
        assert_eq!(empty.to_string(), "g:a:1:jar");
        let tests = ArtifactCoord::new("g", "a", "1", "jar", Some("tests"));
        assert_eq!(tests.to_string(), "g:a:1:jar:tests");
        assert_eq!(tests.pom(), ArtifactCoord::new("g", "a", "1", "pom", None));

        let mut sorted = [
            ArtifactCoord::new("g", "a", "2", "jar", None),
            ArtifactCoord::new("g", "a", "1", "pom", None),
            tests.clone(),
            empty.clone(),
            ArtifactCoord::new("f", "z", "9", "jar", None),
        ];
        sorted.sort();
        let rendered: Vec<String> = sorted.iter().map(ToString::to_string).collect();
        let lock_order = "f:z:9:jar g:a:1:jar g:a:1:jar:tests g:a:1:pom g:a:2:jar";
        assert_eq!(rendered.join(" "), lock_order);

        tests.validate().unwrap();
        for bad in [
            ArtifactCoord::new("org/example", "demo", "1.0", "jar", None),
            ArtifactCoord::new("org.example", "demo", "1.0\n", "jar", None),
            ArtifactCoord::new("org.example", "demo", "1.0", "", None),
            ArtifactCoord::new("org.example", "demo", "1.0", "jar", Some("a:b")),
        ] {
            bad.validate().unwrap_err();
        }
    }
}
