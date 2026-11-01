use serde::Serialize;

use crate::SbomError;

/// One package to list in an SBOM.
///
/// The generator checks every component before rendering anything, and
/// returns [`SbomError::InvalidComponent`] on the first failure:
///
/// - `name` and `version` are not blank.
/// - `purl` parses and equals the form [`rv_maven_types::canonicalize_purl`]
///   returns for it, and no two components in one document share a purl.
/// - each hash is hex of the length its algorithm produces.
/// - each `dependencies` entry is the purl of a component in the same
///   document.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Component {
    /// Package name (the Maven artifactId), written as CycloneDX `name`.
    pub name: String,
    /// Package version, written as CycloneDX `version`.
    pub version: String,
    /// Maven groupId, written as CycloneDX `group`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Package URL in canonical form. It is the CycloneDX `bom-ref` and the
    /// key `dependencies` entries refer to.
    pub purl: String,
    /// Digests of the package artifact, written as CycloneDX `hashes`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<Hash>,
    /// Licenses from the effective POM, written as CycloneDX `licenses`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<crate::License>,
    /// Purls of the components this one depends on directly, written as a
    /// CycloneDX `dependsOn` list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
}

/// One digest of a component's artifact.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Hash {
    /// Algorithm that produced `value`.
    pub algorithm: HashAlgorithm,
    /// Hex digest of the length `algorithm` produces. Either letter case is
    /// accepted, and the value is written as given.
    pub value: String,
}

/// Digest algorithm of a [`Hash`](struct@Hash).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256, 64 hex digits.
    Sha256,
    /// SHA-512, 128 hex digits.
    Sha512,
    /// MD5, 32 hex digits.
    Md5,
    /// SHA-1, 40 hex digits.
    Sha1,
}

pub(crate) fn validate_components<'a>(
    components: impl Iterator<Item = &'a Component> + Clone,
) -> Result<(), SbomError> {
    let invalid = |message: String| Err(SbomError::InvalidComponent(message));
    let mut seen = std::collections::HashSet::new();
    for component in components.clone() {
        let purl = &component.purl;
        if component.name.trim().is_empty() {
            return invalid(format!("component {purl} has empty name"));
        }
        if component.version.trim().is_empty() {
            return invalid(format!("component {} has empty version", component.name));
        }
        match rv_maven_types::canonicalize_purl(purl) {
            None => return invalid(format!("invalid purl: {purl}")),
            Some(canonical) if canonical != *purl => {
                return invalid(format!("non-canonical purl: {purl}"));
            }
            Some(_) => {}
        }
        if !seen.insert(purl.as_str()) {
            return invalid(format!("duplicate purl: {purl}"));
        }
        for hash in &component.hashes {
            let length = match hash.algorithm {
                HashAlgorithm::Sha256 => 64,
                HashAlgorithm::Sha512 => 128,
                HashAlgorithm::Md5 => 32,
                HashAlgorithm::Sha1 => 40,
            };
            if hash.value.len() != length || !hash.value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return invalid(format!(
                    "component {purl} has invalid {:?} hash",
                    hash.algorithm
                ));
            }
        }
    }
    for component in components {
        for dependency in &component.dependencies {
            if !seen.contains(dependency.as_str()) {
                return invalid(format!(
                    "component {} references unknown dependency {dependency}",
                    component.purl
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Component, Hash, HashAlgorithm, validate_components};

    fn component(purl: &str) -> Component {
        Component {
            name: "a".to_string(),
            version: "1.0.0".to_string(),
            group: None,
            purl: purl.to_string(),
            hashes: vec![],
            licenses: vec![],
            dependencies: vec![],
        }
    }

    fn error(components: &[Component]) -> String {
        validate_components(components.iter())
            .expect_err("invalid components")
            .to_string()
    }

    #[test]
    fn validation_rejects_each_defect() {
        let purl = "pkg:maven/org.example/a@1.0.0";
        let ok = component(purl);
        assert!(validate_components([ok.clone()].iter()).is_ok());

        let blank_name = Component {
            name: " ".into(),
            ..ok.clone()
        };
        let blank_version = Component {
            version: " ".into(),
            ..ok.clone()
        };
        let dangling = Component {
            dependencies: vec!["pkg:maven/org.example/missing@1.0.0".into()],
            ..ok.clone()
        };
        let cases = [
            (vec![blank_name], "empty name"),
            (vec![blank_version], "empty version"),
            (vec![component("not-a-purl")], "invalid purl"),
            (
                vec![component(&format!("{purl}?type=jar&classifier=tests"))],
                "non-canonical purl",
            ),
            (vec![ok.clone(), ok.clone()], "duplicate purl"),
            (vec![dangling], "unknown dependency"),
        ];
        for (components, expected) in cases {
            let message = error(&components);
            assert!(message.contains(expected), "{expected}: {message}");
        }
    }

    #[test]
    fn validation_checks_hash_encoding_and_length() {
        let cases = [
            (HashAlgorithm::Sha256, 64),
            (HashAlgorithm::Sha512, 128),
            (HashAlgorithm::Md5, 32),
            (HashAlgorithm::Sha1, 40),
        ];
        for (algorithm, length) in cases {
            let mut component = component("pkg:maven/org.example/a@1.0.0");
            for (value, valid) in [
                ("a".repeat(length - 1), false),
                (format!("{}g", "a".repeat(length - 1)), false),
                ("A".repeat(length), true),
            ] {
                component.hashes = vec![Hash {
                    algorithm: algorithm.clone(),
                    value,
                }];
                assert_eq!(validate_components([&component].into_iter()).is_ok(), valid);
            }
        }
    }
}
