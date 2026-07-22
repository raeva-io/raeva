use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{Component, HashAlgorithm, SbomError, validate_components};

/// SPDX SBOM generator
#[derive(Debug, Clone)]
pub struct SpdxGenerator {
    pub document_name: String,
    pub namespace_prefix: String,
    pub creators: Vec<String>,
    pub root_component: Option<Component>,
    pub document_namespace: Option<String>,
    pub created: Option<DateTime<Utc>>,
}

impl Default for SpdxGenerator {
    fn default() -> Self {
        Self {
            document_name: "raeva-sbom".to_string(),
            namespace_prefix: "urn:uuid:".to_string(),
            creators: vec!["Tool: rv-sbom".to_string()],
            root_component: None,
            document_namespace: None,
            created: None,
        }
    }
}

impl SpdxGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate(&self, components: &[Component]) -> Result<String, SbomError> {
        let mut package_components =
            Vec::with_capacity(components.len() + usize::from(self.root_component.is_some()));
        if let Some(root) = &self.root_component {
            package_components.push(root.clone());
        }
        package_components.extend_from_slice(components);
        validate_components(&package_components)?;

        let mut spdx_ids = HashMap::new();
        for (index, component) in package_components.iter().enumerate() {
            let spdx_id = format!("SPDXRef-Package-{}", index + 1);
            if spdx_ids.insert(component.purl.clone(), spdx_id).is_some() {
                return Err(SbomError::InvalidComponent(format!(
                    "duplicate purl: {}",
                    component.purl
                )));
            }
        }

        let packages = package_components
            .iter()
            .map(|component| {
                let spdx_id = spdx_ids.get(&component.purl).cloned().ok_or_else(|| {
                    SbomError::InvalidComponent(format!(
                        "missing SPDX ID for purl {}",
                        component.purl
                    ))
                })?;

                // Metadata-only packages have no file analysis or verification code.
                let license = component
                    .license_expression
                    .clone()
                    .unwrap_or_else(|| "NOASSERTION".to_string());
                Ok(SpdxPackage {
                    spdx_id,
                    name: component.name.clone(),
                    version_info: component.version.clone(),
                    download_location: "NOASSERTION".to_string(),
                    files_analyzed: false,
                    license_concluded: license.clone(),
                    license_declared: license,
                    copyright_text: "NOASSERTION".to_string(),
                    checksums: spdx_checksums(&component.hashes),
                    external_refs: vec![SpdxExternalRef {
                        reference_category: "PACKAGE-MANAGER",
                        reference_type: "purl",
                        reference_locator: component.purl.clone(),
                    }],
                })
            })
            .collect::<Result<Vec<_>, SbomError>>()?;

        let mut relationships = Vec::new();
        let described_components: &[Component] = self
            .root_component
            .as_ref()
            .map(std::slice::from_ref)
            .unwrap_or(&package_components);
        for component in described_components {
            if let Some(spdx_id) = spdx_ids.get(&component.purl) {
                relationships.push(SpdxRelationship {
                    spdx_element_id: "SPDXRef-DOCUMENT".to_string(),
                    relationship_type: "DESCRIBES".to_string(),
                    related_spdx_element: spdx_id.clone(),
                });
            }
        }

        for component in &package_components {
            let spdx_id = spdx_ids.get(&component.purl).cloned().ok_or_else(|| {
                SbomError::InvalidComponent(format!("missing SPDX ID for purl {}", component.purl))
            })?;
            for dependency in &component.dependencies {
                let dep_id = spdx_ids.get(dependency).cloned().ok_or_else(|| {
                    SbomError::InvalidComponent(format!(
                        "component {} references unknown dependency {}",
                        component.purl, dependency
                    ))
                })?;
                relationships.push(SpdxRelationship {
                    spdx_element_id: spdx_id.clone(),
                    relationship_type: "DEPENDS_ON".to_string(),
                    related_spdx_element: dep_id,
                });
            }
        }

        let document = SpdxDocument {
            spdx_version: "SPDX-2.3",
            data_license: "CC0-1.0",
            spdx_id: "SPDXRef-DOCUMENT",
            name: self.document_name.clone(),
            document_namespace: self
                .document_namespace
                .clone()
                .unwrap_or_else(|| format!("{}{}", self.namespace_prefix, Uuid::new_v4())),
            creation_info: SpdxCreationInfo {
                created: self.created.unwrap_or_else(Utc::now),
                creators: self.creators.clone(),
            },
            packages,
            relationships,
        };

        Ok(serde_json::to_string_pretty(&document)?)
    }
}

#[derive(Debug, Serialize)]
struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    spdx_version: &'static str,
    #[serde(rename = "dataLicense")]
    data_license: &'static str,
    #[serde(rename = "SPDXID")]
    spdx_id: &'static str,
    name: String,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    #[serde(rename = "creationInfo")]
    creation_info: SpdxCreationInfo,
    packages: Vec<SpdxPackage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    relationships: Vec<SpdxRelationship>,
}

#[derive(Debug, Serialize)]
struct SpdxCreationInfo {
    created: DateTime<Utc>,
    creators: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "versionInfo")]
    version_info: String,
    #[serde(rename = "downloadLocation")]
    download_location: String,
    #[serde(rename = "filesAnalyzed")]
    files_analyzed: bool,
    #[serde(rename = "licenseConcluded")]
    license_concluded: String,
    #[serde(rename = "licenseDeclared")]
    license_declared: String,
    #[serde(rename = "copyrightText")]
    copyright_text: String,
    #[serde(rename = "checksums", skip_serializing_if = "Vec::is_empty")]
    checksums: Vec<SpdxChecksum>,
    #[serde(rename = "externalRefs")]
    external_refs: Vec<SpdxExternalRef>,
}

#[derive(Debug, Serialize)]
struct SpdxExternalRef {
    #[serde(rename = "referenceCategory")]
    reference_category: &'static str,
    #[serde(rename = "referenceType")]
    reference_type: &'static str,
    #[serde(rename = "referenceLocator")]
    reference_locator: String,
}

#[derive(Debug, Serialize)]
struct SpdxChecksum {
    algorithm: &'static str,
    #[serde(rename = "checksumValue")]
    checksum_value: String,
}

#[derive(Debug, Serialize)]
struct SpdxRelationship {
    #[serde(rename = "spdxElementId")]
    spdx_element_id: String,
    #[serde(rename = "relationshipType")]
    relationship_type: String,
    #[serde(rename = "relatedSpdxElement")]
    related_spdx_element: String,
}

fn spdx_checksums(hashes: &[crate::Hash]) -> Vec<SpdxChecksum> {
    hashes
        .iter()
        .map(|hash| SpdxChecksum {
            algorithm: spdx_hash_algorithm(&hash.algorithm),
            checksum_value: hash.value.clone(),
        })
        .collect()
}

fn spdx_hash_algorithm(algorithm: &HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha256 => "SHA256",
        HashAlgorithm::Sha512 => "SHA512",
        HashAlgorithm::Md5 => "MD5",
        HashAlgorithm::Sha1 => "SHA1",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::SpdxGenerator;
    use crate::{Component, Hash, HashAlgorithm};

    fn sample_components() -> Vec<Component> {
        vec![
            Component {
                name: "app".to_string(),
                version: "1.0.0".to_string(),
                group: Some("org.example".to_string()),
                purl: "pkg:maven/org.example/app@1.0.0".to_string(),
                license_expression: Some("Apache-2.0".to_string()),
                hashes: vec![Hash {
                    algorithm: HashAlgorithm::Sha256,
                    value: "d".repeat(64),
                }],
                dependencies: vec!["pkg:maven/org.example/lib@2.0.0".to_string()],
            },
            Component {
                name: "lib".to_string(),
                version: "2.0.0".to_string(),
                group: Some("org.example".to_string()),
                purl: "pkg:maven/org.example/lib@2.0.0".to_string(),
                license_expression: None,
                hashes: vec![],
                dependencies: vec![],
            },
        ]
    }

    #[test]
    fn generates_spdx_json() {
        let generator = SpdxGenerator::default();
        let components = sample_components();
        let json = generator.generate(&components).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        assert_eq!(value["spdxVersion"], "SPDX-2.3");
        assert_eq!(value["dataLicense"], "CC0-1.0");
        assert_eq!(value["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(
            value["documentNamespace"]
                .as_str()
                .expect("documentNamespace")
                .starts_with("urn:uuid:")
        );
        assert_eq!(value["packages"].as_array().unwrap().len(), 2);

        let relationships = value["relationships"].as_array().unwrap();
        assert!(relationships.iter().any(|rel| {
            rel.get("relationshipType").and_then(|value| value.as_str()) == Some("DEPENDS_ON")
        }));

        // Verify externalRefs with PURL are present
        let packages = value["packages"].as_array().unwrap();
        for package in packages {
            let external_refs = package["externalRefs"].as_array().unwrap();
            assert!(!external_refs.is_empty());
            let purl_ref = external_refs
                .iter()
                .find(|r| r["referenceType"] == "purl")
                .expect("expected purl external ref");
            assert_eq!(purl_ref["referenceCategory"], "PACKAGE-MANAGER");
            assert!(
                purl_ref["referenceLocator"]
                    .as_str()
                    .unwrap()
                    .starts_with("pkg:maven/")
            );
        }
    }

    #[test]
    fn packages_set_files_analyzed_false_and_license_fields() {
        let generator = SpdxGenerator::default();
        let components = sample_components();
        let json = generator.generate(&components).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        for package in value["packages"].as_array().unwrap() {
            // Package-manager SBOMs never analyze files; SPDX 2.3 requires the verification
            // code be omitted in that case, which it is.
            assert_eq!(
                package["filesAnalyzed"].as_bool(),
                Some(false),
                "filesAnalyzed must be false for metadata-only packages"
            );
            assert!(
                package.get("packageVerificationCode").is_none(),
                "verification code must be omitted when filesAnalyzed is false"
            );
            // Both license fields and a copyright text must be present (NOASSERTION when unknown).
            assert!(package["licenseConcluded"].is_string());
            assert!(package["licenseDeclared"].is_string());
            assert_eq!(
                package["copyrightText"].as_str(),
                Some("NOASSERTION"),
                "copyrightText should default to NOASSERTION"
            );
        }

        // The app component carries Apache-2.0; both license fields must reflect it.
        let app = value["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "app")
            .expect("app package");
        assert_eq!(app["licenseConcluded"], "Apache-2.0");
        assert_eq!(app["licenseDeclared"], "Apache-2.0");
    }

    #[test]
    fn generate_rejects_duplicate_purls() {
        let generator = SpdxGenerator::default();
        let dup = Component {
            name: "dup".to_string(),
            version: "1.0.0".to_string(),
            group: None,
            purl: "pkg:maven/org.example/dup@1.0.0".to_string(),
            license_expression: None,
            hashes: vec![],
            dependencies: vec![],
        };
        let components = vec![dup.clone(), dup];
        let err = generator.generate(&components).unwrap_err();
        assert!(err.to_string().contains("duplicate purl"));
    }

    #[test]
    fn generate_rejects_unknown_dependency_target() {
        let mut component = sample_components().remove(1);
        component.dependencies = vec!["pkg:maven/org.example/missing@1.0.0".to_string()];
        let error = SpdxGenerator::default()
            .generate(&[component])
            .expect_err("unknown dependency must fail");
        assert!(error.to_string().contains("unknown dependency"));
    }

    #[test]
    fn generates_minimal_spdx_for_empty_components() {
        let generator = SpdxGenerator::default();
        let json = generator.generate(&[]).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        assert_eq!(value["spdxVersion"], "SPDX-2.3");
        assert_eq!(
            value["packages"].as_array().expect("packages array").len(),
            0
        );
        assert!(
            value.get("relationships").is_none(),
            "empty component set should omit relationships"
        );
    }

    #[test]
    fn generates_expected_spdx_relationships_for_components() {
        let generator = SpdxGenerator::default();
        let components = sample_components();
        let json = generator.generate(&components).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        let relationships = value["relationships"].as_array().expect("relationships");
        let describes_count = relationships
            .iter()
            .filter(|rel| rel["relationshipType"] == "DESCRIBES")
            .count();
        let depends_on_count = relationships
            .iter()
            .filter(|rel| rel["relationshipType"] == "DEPENDS_ON")
            .count();

        assert_eq!(describes_count, components.len());
        assert_eq!(depends_on_count, 1);
    }

    #[test]
    fn configured_root_component_is_the_described_package() {
        let generator = SpdxGenerator {
            root_component: Some(Component {
                name: "demo".to_string(),
                version: "1.0.0".to_string(),
                group: Some("com.example".to_string()),
                purl: "pkg:maven/com.example/demo@1.0.0".to_string(),
                license_expression: None,
                hashes: Vec::new(),
                dependencies: vec!["pkg:maven/org.example/app@1.0.0".to_string()],
            }),
            document_namespace: Some(
                "https://raeva.io/spdx/00000000-0000-8000-8000-000000000000".to_string(),
            ),
            ..SpdxGenerator::default()
        };

        let json = generator
            .generate(&sample_components())
            .expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        assert_eq!(
            value["documentNamespace"],
            "https://raeva.io/spdx/00000000-0000-8000-8000-000000000000"
        );
        assert_eq!(value["packages"].as_array().unwrap().len(), 3);
        assert_eq!(value["packages"][0]["name"], "demo");
        assert_eq!(value["packages"][0]["licenseDeclared"], "NOASSERTION");
        let relationships = value["relationships"].as_array().unwrap();
        assert_eq!(
            relationships
                .iter()
                .filter(|relationship| relationship["relationshipType"] == "DESCRIBES")
                .count(),
            1
        );
        assert!(relationships.iter().any(|relationship| {
            relationship["relationshipType"] == "DEPENDS_ON"
                && relationship["spdxElementId"] == "SPDXRef-Package-1"
        }));
    }

    #[test]
    fn document_namespace_is_unique_per_generation() {
        let generator = SpdxGenerator::default();
        let components = sample_components();
        let first = generator.generate(&components).expect("first generation");
        let second = generator.generate(&components).expect("second generation");

        let first_value: Value = serde_json::from_str(&first).expect("parse first");
        let second_value: Value = serde_json::from_str(&second).expect("parse second");
        assert_ne!(
            first_value["documentNamespace"],
            second_value["documentNamespace"]
        );
    }

    #[test]
    fn spdx_preserves_explicit_license_expression() {
        let generator = SpdxGenerator::default();
        let components = vec![Component {
            name: "licensed-lib".to_string(),
            version: "1.0.0".to_string(),
            group: None,
            purl: "pkg:maven/org.example/licensed-lib@1.0.0".to_string(),
            license_expression: Some("0BSD OR MIT".to_string()),
            hashes: vec![],
            dependencies: vec![],
        }];

        let json = generator.generate(&components).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["packages"][0]["licenseConcluded"], "0BSD OR MIT");
        assert_eq!(value["packages"][0]["licenseDeclared"], "0BSD OR MIT");
    }
}
