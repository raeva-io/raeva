use serde::{Deserialize, Serialize};

use crate::SbomError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub purl: String,
    /// SPDX license expression supplied by the caller.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub license_expression: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hash {
    pub algorithm: HashAlgorithm,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Md5,
    Sha1,
}

pub fn validate_components(components: &[Component]) -> Result<(), SbomError> {
    let mut seen = std::collections::HashSet::with_capacity(components.len());
    for component in components {
        if component.name.trim().is_empty() {
            return Err(SbomError::InvalidComponent(format!(
                "component {} has empty name",
                component.purl
            )));
        }
        if component.version.trim().is_empty() {
            return Err(SbomError::InvalidComponent(format!(
                "component {} has empty version",
                component.name
            )));
        }
        let canonical_purl = crate::purl::canonicalize_purl(&component.purl).ok_or_else(|| {
            SbomError::InvalidComponent(format!("invalid purl: {}", component.purl))
        })?;
        if canonical_purl != component.purl {
            return Err(SbomError::InvalidComponent(format!(
                "non-canonical purl: {}",
                component.purl
            )));
        }
        if !seen.insert(component.purl.as_str()) {
            return Err(SbomError::InvalidComponent(format!(
                "duplicate purl: {}",
                component.purl
            )));
        }
        if component
            .license_expression
            .as_ref()
            .is_some_and(|expression| expression.trim().is_empty())
        {
            return Err(SbomError::InvalidComponent(format!(
                "component {} has empty license expression",
                component.name
            )));
        }
        for hash in &component.hashes {
            validate_hash(component, hash)?;
        }
    }

    for component in components {
        for dependency in &component.dependencies {
            if !seen.contains(dependency.as_str()) {
                return Err(SbomError::InvalidComponent(format!(
                    "component {} references unknown dependency {}",
                    component.purl, dependency
                )));
            }
        }
    }

    Ok(())
}

fn validate_hash(component: &Component, hash: &Hash) -> Result<(), SbomError> {
    let expected_length = match hash.algorithm {
        HashAlgorithm::Sha256 => 64,
        HashAlgorithm::Sha512 => 128,
        HashAlgorithm::Md5 => 32,
        HashAlgorithm::Sha1 => 40,
    };
    if hash.value.len() != expected_length
        || !hash.value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SbomError::InvalidComponent(format!(
            "component {} has invalid {:?} hash",
            component.purl, hash.algorithm
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Component, Hash, HashAlgorithm, validate_components};

    fn component_with_purl(name: &str, purl: &str) -> Component {
        Component {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            group: None,
            purl: purl.to_string(),
            license_expression: None,
            hashes: vec![],
            dependencies: vec![],
        }
    }

    #[test]
    fn validate_components_accepts_unique_purls() {
        let components = vec![
            component_with_purl("a", "pkg:maven/org.example/a@1.0.0"),
            component_with_purl("b", "pkg:maven/org.example/b@1.0.0"),
        ];
        assert!(validate_components(&components).is_ok());
    }

    #[test]
    fn validate_components_rejects_empty_purl() {
        let components = vec![component_with_purl("a", "   ")];
        let err = validate_components(&components).unwrap_err();
        assert!(err.to_string().contains("invalid purl"));
    }

    #[test]
    fn validate_components_rejects_duplicate_purls() {
        let components = vec![
            component_with_purl("a", "pkg:maven/org.example/dup@1.0.0"),
            component_with_purl("b", "pkg:maven/org.example/dup@1.0.0"),
        ];
        let err = validate_components(&components).unwrap_err();
        assert!(
            err.to_string().contains("duplicate purl"),
            "expected duplicate purl error, got: {err}"
        );
    }

    #[test]
    fn component_clone_and_fields() {
        let component = Component {
            name: "example".to_string(),
            version: "1.0.0".to_string(),
            group: Some("org.example".to_string()),
            purl: "pkg:maven/org.example/example@1.0.0".to_string(),
            license_expression: Some("Apache-2.0".to_string()),
            hashes: vec![Hash {
                algorithm: HashAlgorithm::Sha256,
                value: "d".repeat(64),
            }],
            dependencies: vec!["pkg:maven/org.example/dep@2.0.0".to_string()],
        };

        let cloned = component.clone();
        assert_eq!(component, cloned);
    }

    #[test]
    fn validate_components_rejects_empty_name_and_version() {
        let mut component = component_with_purl(" ", "pkg:maven/org.example/a@1.0.0");
        let error = validate_components(&[component.clone()]).expect_err("empty name must fail");
        assert!(error.to_string().contains("empty name"));

        component.name = "a".to_string();
        component.version = " ".to_string();
        let error = validate_components(&[component]).expect_err("empty version must fail");
        assert!(error.to_string().contains("empty version"));
    }

    #[test]
    fn validate_components_rejects_invalid_and_noncanonical_purls() {
        let invalid = component_with_purl("a", "not-a-purl");
        let error = validate_components(&[invalid]).expect_err("invalid purl must fail");
        assert!(error.to_string().contains("invalid purl"));

        let noncanonical = component_with_purl(
            "a",
            "pkg:maven/org.example/a@1.0.0?type=jar&classifier=tests",
        );
        let error = validate_components(&[noncanonical]).expect_err("non-canonical purl must fail");
        assert!(error.to_string().contains("non-canonical purl"));
    }

    #[test]
    fn validate_components_checks_hash_encoding_and_length() {
        let cases = [
            (HashAlgorithm::Sha256, 64),
            (HashAlgorithm::Sha512, 128),
            (HashAlgorithm::Md5, 32),
            (HashAlgorithm::Sha1, 40),
        ];
        for (algorithm, length) in cases {
            let mut component = component_with_purl("a", "pkg:maven/org.example/a@1.0.0");
            component.hashes = vec![Hash {
                algorithm: algorithm.clone(),
                value: "a".repeat(length - 1),
            }];
            assert!(validate_components(&[component.clone()]).is_err());

            component.hashes[0].value = format!("{}g", "a".repeat(length - 1));
            assert!(validate_components(&[component.clone()]).is_err());

            component.hashes[0].value = "A".repeat(length);
            assert!(validate_components(&[component]).is_ok());
        }
    }

    #[test]
    fn validate_components_rejects_unknown_dependency_target() {
        let mut component = component_with_purl("a", "pkg:maven/org.example/a@1.0.0");
        component.dependencies = vec!["pkg:maven/org.example/missing@1.0.0".to_string()];
        let error = validate_components(&[component]).expect_err("unknown dependency must fail");
        assert!(error.to_string().contains("unknown dependency"));
    }
}
