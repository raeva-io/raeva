//! Shared utility functions for the resolver.

use rv_maven_model::{Parent, Pom};

/// Returns true if `pom` could be the parent referenced by `parent`. Artifact
/// id must match; group id and version are checked only when the POM declares
/// them (they can be inherited).
pub fn pom_matches_parent(pom: &Pom, parent: &Parent) -> bool {
    if pom.artifact_id.as_deref() != Some(parent.artifact_id.as_str()) {
        return false;
    }
    if let Some(group_id) = pom.group_id.as_deref()
        && group_id != parent.group_id
    {
        return false;
    }
    if let Some(version) = pom.version.as_deref()
        && version != parent.version
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pom(group_id: Option<&str>, artifact_id: Option<&str>, version: Option<&str>) -> Pom {
        let mut pom = Pom::default();
        pom.group_id = group_id.map(String::from);
        pom.artifact_id = artifact_id.map(String::from);
        pom.version = version.map(String::from);
        pom
    }

    fn make_parent(group_id: &str, artifact_id: &str, version: &str) -> Parent {
        Parent {
            group_id: group_id.to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
            relative_path: None,
        }
    }

    #[test]
    fn matches_when_all_fields_match() {
        let pom = make_pom(Some("com.example"), Some("parent"), Some("1.0"));
        let parent = make_parent("com.example", "parent", "1.0");
        assert!(pom_matches_parent(&pom, &parent));
    }

    #[test]
    fn matches_when_pom_has_no_group_or_version() {
        let pom = make_pom(None, Some("parent"), None);
        let parent = make_parent("com.example", "parent", "1.0");
        assert!(pom_matches_parent(&pom, &parent));
    }

    #[test]
    fn fails_when_artifact_id_differs() {
        let pom = make_pom(Some("com.example"), Some("other"), Some("1.0"));
        let parent = make_parent("com.example", "parent", "1.0");
        assert!(!pom_matches_parent(&pom, &parent));
    }

    #[test]
    fn fails_when_group_id_differs() {
        let pom = make_pom(Some("com.other"), Some("parent"), Some("1.0"));
        let parent = make_parent("com.example", "parent", "1.0");
        assert!(!pom_matches_parent(&pom, &parent));
    }

    #[test]
    fn fails_when_version_differs() {
        let pom = make_pom(Some("com.example"), Some("parent"), Some("2.0"));
        let parent = make_parent("com.example", "parent", "1.0");
        assert!(!pom_matches_parent(&pom, &parent));
    }
}
