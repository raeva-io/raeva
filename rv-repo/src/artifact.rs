use serde::{Deserialize, Serialize};

use rv_maven_types::{
    ArtifactCoord, Coord, CoordinateField, is_snapshot_version, layout,
    validate_coordinate_component,
};

const DEFAULT_PACKAGING: &str = "jar";

/// One file to fetch from a repository, named by its Maven coordinate.
///
/// The fields are not checked on construction; [`ArtifactRequest::validate`]
/// checks them, and the [`crate::RepoClient`] fetch methods call it before
/// building a URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRequest {
    /// The group id, such as `org.slf4j`. Its dots become directories.
    pub group_id: String,
    /// The artifact id, such as `slf4j-api`.
    pub artifact_id: String,
    /// The version: a release, a `-SNAPSHOT` base version, or a timestamped
    /// snapshot version.
    pub version: String,
    /// The file extension, such as `jar` or `pom`. Defaults to `jar`.
    pub packaging: String,
    /// The classifier, such as `sources`, or `None` for the main artifact.
    pub classifier: Option<String>,
}

impl From<&ArtifactCoord> for ArtifactRequest {
    fn from(coord: &ArtifactCoord) -> Self {
        Self {
            group_id: coord.group_id().to_string(),
            artifact_id: coord.artifact_id().to_string(),
            version: coord.version().to_string(),
            packaging: coord.extension().to_string(),
            classifier: coord.classifier().map(str::to_string),
        }
    }
}

impl ArtifactRequest {
    /// A request for the `jar` of `group_id:artifact_id:version`, with no
    /// classifier.
    pub fn new(
        group_id: impl Into<String>,
        artifact_id: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            artifact_id: artifact_id.into(),
            version: version.into(),
            packaging: DEFAULT_PACKAGING.to_string(),
            classifier: None,
        }
    }

    /// A request for `coord`, taking its packaging as the extension (`jar`
    /// when it has none) and its classifier.
    pub fn from_coord(coord: &Coord) -> Self {
        Self {
            group_id: coord.group_id.to_string(),
            artifact_id: coord.artifact_id.to_string(),
            version: coord.version.to_string(),
            packaging: coord
                .packaging
                .clone()
                .unwrap_or_else(|| DEFAULT_PACKAGING.to_string()),
            classifier: coord.classifier.clone(),
        }
    }

    /// The same request with `packaging` as the file extension.
    pub fn with_packaging(mut self, packaging: impl Into<String>) -> Self {
        self.packaging = packaging.into();
        self
    }

    /// The same request with `classifier` set.
    pub fn with_classifier(mut self, classifier: impl Into<String>) -> Self {
        self.classifier = Some(classifier.into());
        self
    }

    /// The repository-relative path in the standard Maven layout, such as
    /// `com/example/demo/1.0.0/demo-1.0.0.jar`. The version names both the
    /// directory and the file. It does not validate the components; call
    /// [`ArtifactRequest::validate`] first for untrusted input.
    pub fn to_path(&self) -> String {
        self.to_path_with_versions(&self.version, &self.version)
    }

    pub(crate) fn to_path_with_versions(&self, dir_version: &str, file_version: &str) -> String {
        layout::artifact_path_from_parts(
            &self.group_id,
            &self.artifact_id,
            dir_version,
            file_version,
            &self.packaging,
            self.classifier.as_deref(),
        )
    }

    /// The request for this coordinate's POM: the same group, artifact and
    /// version, with the `pom` extension and no classifier.
    pub fn pom(&self) -> Self {
        let mut request = self.clone();
        request.packaging = "pom".to_string();
        request.classifier = None;
        request
    }

    /// `-SNAPSHOT` suffix or a timestamped build such as `1.0-20240101.010101-1`.
    pub fn is_snapshot(&self) -> bool {
        is_snapshot_version(&self.version)
    }

    /// Refuse path traversal and SSRF-enabling characters in every coordinate
    /// part, with [`validate_coordinate_component`].
    pub fn validate(&self) -> std::result::Result<(), String> {
        [
            (CoordinateField::Group, self.group_id.as_str()),
            (CoordinateField::Artifact, &self.artifact_id),
            (CoordinateField::Version, &self.version),
            (CoordinateField::Extension, &self.packaging),
        ]
        .into_iter()
        .chain(
            (self.classifier.as_deref())
                .map(|classifier| (CoordinateField::Classifier, classifier)),
        )
        .try_for_each(|(field, value)| validate_coordinate_component(field, value))
        .map_err(|err| err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::ArtifactRequest;

    /// A coordinate must not smuggle a path or URL control into a request
    /// for another path, and a refusal must not echo a control character.
    #[test]
    fn validate_refuses_what_the_lock_refuses() {
        let base = || ArtifactRequest::new("com.example", "demo", "1.0");
        for request in [
            ArtifactRequest::new("com.example/../evil", "demo", "1.0.0"),
            ArtifactRequest::new("com.example", "demo/../../etc", "1.0.0"),
            ArtifactRequest::new("com.example", "demo", "1.0?redirect=evil.com"),
            ArtifactRequest::new("com.example", "demo\u{1b}[31m", "1.0"),
            ArtifactRequest::new("com.example", "de mo", "1.0"),
            base().with_classifier("x:y"),
            base().with_classifier(""),
        ] {
            let err = request.validate().expect_err(&format!("{request:?}"));
            assert!(!err.chars().any(char::is_control), "{err:?}");
        }
        for (g, a, v) in [
            ("com.example", "demo", "1.0.0-SNAPSHOT"),
            ("org.springframework.boot", "spring-boot", "3.2.0"),
        ] {
            ArtifactRequest::new(g, a, v)
                .validate()
                .unwrap_or_else(|e| panic!("{g}:{a}:{v}: {e}"));
        }
    }
}
