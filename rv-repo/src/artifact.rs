use serde::{Deserialize, Serialize};

use rv_version::Coord;

use crate::repository::is_snapshot_version;

const DEFAULT_PACKAGING: &str = "jar";

/// Validates that a coordinate component does not contain path traversal
/// sequences or path separators that could lead to SSRF when used in URL paths.
///
/// Exposed at crate scope so the snapshot-resolution path can run the
/// server-controlled `<snapshotVersion><value>` through the same gate before
/// it is spliced into an artifact filename. [`ArtifactRequest::validate`] only
/// covers the requested coordinate, not the resolved snapshot version.
pub(crate) fn validate_coordinate_component(
    component: &str,
    field: &str,
) -> std::result::Result<(), String> {
    if component.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if component.contains("..") {
        return Err(format!("{field} must not contain '..'"));
    }
    // Reject path separators and URL-significant characters
    for ch in ['/', '\\', '?', '#', '@', ':'] {
        if component.contains(ch) {
            return Err(format!("{field} must not contain '{ch}'"));
        }
    }
    // Reject control characters
    if component.chars().any(|c| c.is_control()) {
        return Err(format!("{field} must not contain control characters"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRequest {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub packaging: String,
    pub classifier: Option<String>,
}

impl ArtifactRequest {
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

    pub fn with_packaging(mut self, packaging: impl Into<String>) -> Self {
        self.packaging = packaging.into();
        self
    }

    pub fn with_classifier(mut self, classifier: impl Into<String>) -> Self {
        self.classifier = Some(classifier.into());
        self
    }

    pub fn to_path(&self) -> String {
        self.to_path_with_versions(&self.version, &self.version)
    }

    pub fn to_path_with_versions(&self, dir_version: &str, file_version: &str) -> String {
        let group_path = self.group_id.replace('.', "/");
        let filename = if let Some(classifier) = self.classifier.as_deref() {
            format!(
                "{}-{}-{}.{}",
                self.artifact_id, file_version, classifier, self.packaging
            )
        } else {
            format!("{}-{}.{}", self.artifact_id, file_version, self.packaging)
        };
        format!(
            "{}/{}/{}/{}",
            group_path, self.artifact_id, dir_version, filename
        )
    }

    pub fn pom(&self) -> Self {
        let mut request = self.clone();
        request.packaging = "pom".to_string();
        request.classifier = None;
        request
    }

    /// Returns true if this artifact version is a snapshot (either `-SNAPSHOT` suffix
    /// or timestamped snapshot like `1.0-20240101.010101-1`).
    ///
    /// Uses the shared `is_snapshot_version` utility from `repository.rs` to avoid
    /// duplicating the snapshot detection regex.
    pub fn is_snapshot(&self) -> bool {
        is_snapshot_version(&self.version)
    }

    pub fn base_version(&self) -> Option<&str> {
        self.version.strip_suffix("-SNAPSHOT")
    }

    /// Validates that all coordinate components are safe for use in URL paths.
    /// Returns an error if any component contains path traversal or SSRF-enabling characters.
    pub fn validate(&self) -> std::result::Result<(), String> {
        validate_coordinate_component(&self.group_id, "group_id")?;
        validate_coordinate_component(&self.artifact_id, "artifact_id")?;
        validate_coordinate_component(&self.version, "version")?;
        validate_coordinate_component(&self.packaging, "packaging")?;
        if let Some(classifier) = &self.classifier {
            validate_coordinate_component(classifier, "classifier")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ArtifactRequest;

    #[test]
    fn default_packaging_is_jar() {
        let req = ArtifactRequest::new("com.example", "demo", "1.0.0");
        assert_eq!(req.packaging, "jar");
    }

    #[test]
    fn builds_artifact_path() {
        let req = ArtifactRequest::new("com.example", "demo", "1.0.0");
        assert_eq!(req.to_path(), "com/example/demo/1.0.0/demo-1.0.0.jar");
    }

    #[test]
    fn builds_classifier_path() {
        let req = ArtifactRequest::new("com.example", "demo", "1.0.0").with_classifier("tests");
        assert_eq!(req.to_path(), "com/example/demo/1.0.0/demo-1.0.0-tests.jar");
    }

    #[test]
    fn builds_snapshot_filename() {
        let req = ArtifactRequest::new("com.example", "demo", "1.0-SNAPSHOT");
        let path = req.to_path_with_versions("1.0-SNAPSHOT", "1.0-20240101.010101-1");
        assert!(path.ends_with("demo-1.0-20240101.010101-1.jar"));
    }

    #[test]
    fn pom_clears_classifier() {
        let req = ArtifactRequest::new("com.example", "demo", "1.0.0").with_classifier("tests");
        let pom = req.pom();
        assert_eq!(pom.packaging, "pom");
        assert!(pom.classifier.is_none());
    }

    #[test]
    fn detects_regular_snapshot() {
        let req = ArtifactRequest::new("com.example", "demo", "1.0-SNAPSHOT");
        assert!(req.is_snapshot());
    }

    #[test]
    fn detects_timestamped_snapshot() {
        let req = ArtifactRequest::new("com.example", "demo", "1.0-20240101.010101-1");
        assert!(req.is_snapshot());
    }

    #[test]
    fn detects_timestamped_snapshot_with_different_build_number() {
        let req = ArtifactRequest::new("com.example", "demo", "2.5.3-20230815.123456-42");
        assert!(req.is_snapshot());
    }

    #[test]
    fn release_version_is_not_snapshot() {
        let req = ArtifactRequest::new("com.example", "demo", "1.0.0");
        assert!(!req.is_snapshot());
    }

    #[test]
    fn version_with_similar_pattern_is_not_snapshot() {
        // Should not match if pattern is not at the end
        let req = ArtifactRequest::new("com.example", "demo", "1.0-20240101.010101-1.Final");
        assert!(!req.is_snapshot());
    }

    #[test]
    fn validate_rejects_traversal_and_url_chars() {
        // Each field must reject path-traversal / URL-control characters so the
        // coordinate cannot be smuggled into a request that targets another path.
        let bad = [
            ("com.example/../evil", "demo", "1.0.0"),
            ("com.example", "demo/../../etc", "1.0.0"),
            ("com.example", "demo", "1.0?redirect=evil.com"),
        ];
        for (g, a, v) in bad {
            ArtifactRequest::new(g, a, v)
                .validate()
                .expect_err(&format!("{g}:{a}:{v}"));
        }
    }

    #[test]
    fn validate_accepts_normal_coordinates() {
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
