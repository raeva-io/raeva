//! Canonical Maven coordinate key (group:artifact:version:packaging[:classifier]).

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ArtifactKey {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub packaging: String,
    pub classifier: Option<String>,
}

impl ArtifactKey {
    pub fn new(
        group_id: impl Into<String>,
        artifact_id: impl Into<String>,
        version: impl Into<String>,
        packaging: impl Into<String>,
        classifier: Option<String>,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            artifact_id: artifact_id.into(),
            version: version.into(),
            packaging: packaging.into(),
            // An empty classifier is equivalent to no classifier. Normalizing
            // here keeps the empty/None distinction from leaking into hashing
            // and equality, so a key round-trips losslessly through the index
            // (which stores the classifier as `classifier_key`, i.e. "" for
            // None). See #55.
            classifier: normalize_classifier(classifier),
        }
    }

    /// The classifier as stored in the artifact index: the classifier string,
    /// or `""` when there is none. This is the inverse of [`classifier_from_key`].
    pub fn classifier_key(&self) -> &str {
        self.classifier.as_deref().unwrap_or("")
    }
}

/// Reconstruct an `Option<String>` classifier from its stored `classifier_key`
/// form, where an empty string means "no classifier". Inverse of
/// [`ArtifactKey::classifier_key`]; keeps the index round-trip consistent (#55).
pub fn classifier_from_key(classifier: impl Into<String>) -> Option<String> {
    normalize_classifier(Some(classifier.into()))
}

fn normalize_classifier(classifier: Option<String>) -> Option<String> {
    classifier.filter(|c| !c.is_empty())
}

impl fmt::Display for ArtifactKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(classifier) = &self.classifier {
            write!(
                f,
                "{}:{}:{}:{}:{}",
                self.group_id, self.artifact_id, self.version, self.packaging, classifier
            )
        } else {
            write!(
                f,
                "{}:{}:{}:{}",
                self.group_id, self.artifact_id, self.version, self.packaging
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_classifier_normalizes_to_none() {
        // #55: a `Some("")` classifier is indistinguishable from `None` once it
        // round-trips through the index (which stores "" for None), so `new`
        // collapses the two up front to keep hashing/equality consistent.
        let with_empty = ArtifactKey::new("g", "a", "1", "jar", Some(String::new()));
        assert_eq!(with_empty.classifier, None);
        assert_eq!(with_empty.classifier_key(), "");

        let with_none = ArtifactKey::new("g", "a", "1", "jar", None);
        assert_eq!(with_empty, with_none);

        let with_value = ArtifactKey::new("g", "a", "1", "jar", Some("sources".to_string()));
        assert_eq!(with_value.classifier.as_deref(), Some("sources"));
        assert_eq!(with_value.classifier_key(), "sources");
    }

    #[test]
    fn classifier_key_round_trips_through_classifier_from_key() {
        // The stored form (classifier_key) must reconstruct an equal key (#55).
        for classifier in [None, Some("sources".to_string()), Some(String::new())] {
            let key = ArtifactKey::new("g", "a", "1", "jar", classifier);
            let reconstructed = ArtifactKey::new(
                key.group_id.clone(),
                key.artifact_id.clone(),
                key.version.clone(),
                key.packaging.clone(),
                classifier_from_key(key.classifier_key()),
            );
            assert_eq!(key, reconstructed);
        }
    }

    #[test]
    fn classifier_from_key_maps_empty_to_none() {
        assert_eq!(classifier_from_key(""), None);
        assert_eq!(classifier_from_key("sources"), Some("sources".to_string()));
    }
}
