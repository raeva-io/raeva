use std::io::Write;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{Component, HashAlgorithm, SbomError, validate_components};

/// CycloneDX SBOM generator
#[derive(Debug, Clone)]
pub struct CycloneDxGenerator {
    pub tool_vendor: String,
    pub tool_name: String,
    pub tool_version: String,
    pub root_name: String,
    pub root_version: String,
    pub root_component: Option<Component>,
    pub timestamp: Option<DateTime<Utc>>,
    pub serial_number: Option<String>,
}

impl Default for CycloneDxGenerator {
    fn default() -> Self {
        Self {
            tool_vendor: "raeva".to_string(),
            tool_name: "rv-sbom".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            root_name: "raeva".to_string(),
            root_version: env!("CARGO_PKG_VERSION").to_string(),
            root_component: None,
            timestamp: Some(Utc::now()),
            serial_number: Some(format!("urn:uuid:{}", Uuid::new_v4())),
        }
    }
}

impl CycloneDxGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate(&self, components: &[Component]) -> Result<String, SbomError> {
        self.validate_components(components)?;

        let bom = self.build_bom(components);
        Ok(serde_json::to_string_pretty(&bom)?)
    }

    /// Write the SBOM to a writer instead of buffering the whole document in memory.
    pub fn generate_to_writer<W: Write>(
        &self,
        components: &[Component],
        writer: W,
    ) -> Result<(), SbomError> {
        self.validate_components(components)?;

        let bom = self.build_bom(components);
        serde_json::to_writer_pretty(writer, &bom)?;
        Ok(())
    }

    fn build_bom(&self, components: &[Component]) -> CycloneDxBom {
        let root = self
            .root_component
            .as_ref()
            .map(|component| CycloneDxMetadataComponent {
                component_type: "application",
                group: component.group.clone(),
                name: component.name.clone(),
                version: component.version.clone(),
                bom_ref: Some(component.purl.clone()),
                purl: Some(component.purl.clone()),
            })
            .unwrap_or_else(|| CycloneDxMetadataComponent {
                component_type: "application",
                group: None,
                name: self.root_name.clone(),
                version: self.root_version.clone(),
                bom_ref: None,
                purl: None,
            });
        let metadata = CycloneDxMetadata {
            timestamp: self.timestamp,
            tools: CycloneDxTools {
                components: vec![CycloneDxToolComponent {
                    component_type: "application",
                    group: Some(self.tool_vendor.clone()),
                    name: self.tool_name.clone(),
                    version: self.tool_version.clone(),
                }],
            },
            component: root,
        };

        let component_models = components
            .iter()
            .map(|component| CycloneDxComponent {
                // Dependency refs must match component bom-refs.
                bom_ref: component.purl.clone(),
                component_type: "library",
                group: component.group.clone(),
                name: component.name.clone(),
                version: component.version.clone(),
                purl: component.purl.clone(),
                licenses: cyclonedx_licenses(component.license_expression.as_deref()),
                hashes: cyclonedx_hashes(&component.hashes),
            })
            .collect();

        let mut dependencies =
            Vec::with_capacity(components.len() + usize::from(self.root_component.is_some()));
        if let Some(root) = &self.root_component {
            dependencies.push(CycloneDxDependency {
                reference: root.purl.clone(),
                depends_on: root.dependencies.clone(),
            });
        }
        dependencies.extend(components.iter().map(|component| CycloneDxDependency {
            reference: component.purl.clone(),
            depends_on: component.dependencies.clone(),
        }));

        CycloneDxBom {
            bom_format: "CycloneDX",
            spec_version: "1.5",
            serial_number: self.serial_number.clone(),
            version: 1,
            metadata,
            components: component_models,
            dependencies,
        }
    }

    fn validate_components(&self, components: &[Component]) -> Result<(), SbomError> {
        let Some(root) = &self.root_component else {
            return validate_components(components);
        };
        let mut all_components = Vec::with_capacity(components.len() + 1);
        all_components.push(root.clone());
        all_components.extend_from_slice(components);
        validate_components(&all_components)
    }
}

#[derive(Debug, Serialize)]
struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    #[serde(rename = "serialNumber")]
    #[serde(skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    version: u32,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
    dependencies: Vec<CycloneDxDependency>,
}

#[derive(Debug, Serialize)]
struct CycloneDxMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<DateTime<Utc>>,
    tools: CycloneDxTools,
    component: CycloneDxMetadataComponent,
}

#[derive(Debug, Serialize)]
struct CycloneDxTools {
    components: Vec<CycloneDxToolComponent>,
}

#[derive(Debug, Serialize)]
struct CycloneDxToolComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct CycloneDxMetadataComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    name: String,
    version: String,
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    bom_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
}

#[derive(Debug, Serialize)]
struct CycloneDxComponent {
    /// Stable identifier shared with the dependency graph.
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    name: String,
    version: String,
    purl: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    licenses: Vec<CycloneDxLicenseChoice>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<CycloneDxHash>,
}

#[derive(Debug, Serialize)]
struct CycloneDxLicenseChoice {
    expression: String,
}

#[derive(Debug, Serialize)]
struct CycloneDxHash {
    #[serde(rename = "alg")]
    algorithm: &'static str,
    #[serde(rename = "content")]
    value: String,
}

#[derive(Debug, Serialize)]
struct CycloneDxDependency {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
}

fn cyclonedx_licenses(expression: Option<&str>) -> Vec<CycloneDxLicenseChoice> {
    expression
        .map(|expression| {
            vec![CycloneDxLicenseChoice {
                expression: expression.to_string(),
            }]
        })
        .unwrap_or_default()
}

fn cyclonedx_hashes(hashes: &[crate::Hash]) -> Vec<CycloneDxHash> {
    let mut result = Vec::with_capacity(hashes.len());
    for hash in hashes {
        result.push(CycloneDxHash {
            algorithm: cyclonedx_hash_algorithm(&hash.algorithm),
            value: hash.value.clone(),
        });
    }
    result
}

fn cyclonedx_hash_algorithm(algorithm: &HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha256 => "SHA-256",
        HashAlgorithm::Sha512 => "SHA-512",
        HashAlgorithm::Md5 => "MD5",
        HashAlgorithm::Sha1 => "SHA-1",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::CycloneDxGenerator;
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
    fn generates_cyclonedx_json() {
        let generator = CycloneDxGenerator::default();
        let components = sample_components();
        let json = generator.generate(&components).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        assert_eq!(value["bomFormat"], "CycloneDX");
        assert_eq!(value["specVersion"], "1.5");
        assert_eq!(value["version"], 1);
        assert!(
            value["serialNumber"]
                .as_str()
                .expect("serialNumber")
                .starts_with("urn:uuid:")
        );
        assert_eq!(value["components"].as_array().unwrap().len(), 2);
        assert_eq!(value["metadata"]["component"]["name"], "raeva");

        let dependencies = value["dependencies"].as_array().unwrap();
        let app_dep = dependencies
            .iter()
            .find(|dep| {
                dep.get("ref").and_then(|value| value.as_str())
                    == Some("pkg:maven/org.example/app@1.0.0")
            })
            .expect("app dependency entry");
        let depends_on = app_dep["dependsOn"].as_array().unwrap();
        assert!(
            depends_on
                .iter()
                .any(|dep| { dep.as_str() == Some("pkg:maven/org.example/lib@2.0.0") })
        );

        // Verify group field is included in components
        let components_arr = value["components"].as_array().unwrap();
        let app_component = components_arr
            .iter()
            .find(|c| c["name"] == "app")
            .expect("app component");
        assert_eq!(app_component["group"], "org.example");
    }

    #[test]
    fn components_have_bom_ref_matching_dependency_ref() {
        let generator = CycloneDxGenerator::default();
        let components = sample_components();
        let json = generator.generate(&components).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        let components_arr = value["components"].as_array().unwrap();
        let dependencies_arr = value["dependencies"].as_array().unwrap();

        // Every bom-ref in components must match a ref in the dependency graph
        for component in components_arr {
            let bom_ref = component["bom-ref"].as_str().expect("bom-ref present");
            assert!(!bom_ref.is_empty(), "bom-ref should not be empty");

            let dep_entry = dependencies_arr
                .iter()
                .find(|d| d["ref"].as_str() == Some(bom_ref));
            assert!(
                dep_entry.is_some(),
                "component bom-ref '{}' should have a matching entry in dependencies",
                bom_ref
            );
        }
    }

    #[test]
    fn generates_minimal_cyclonedx_for_empty_components() {
        let generator = CycloneDxGenerator::default();
        let json = generator.generate(&[]).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        assert_eq!(value["bomFormat"], "CycloneDX");
        assert_eq!(
            value["components"]
                .as_array()
                .expect("components array")
                .len(),
            0
        );
        assert_eq!(
            value["dependencies"]
                .as_array()
                .expect("dependencies array")
                .len(),
            0
        );
        assert!(value.get("metadata").is_some());
    }

    #[test]
    fn generates_components_without_licenses() {
        let generator = CycloneDxGenerator::default();
        let components = vec![Component {
            name: "no-license-lib".to_string(),
            version: "1.2.3".to_string(),
            group: Some("org.example".to_string()),
            purl: "pkg:maven/org.example/no-license-lib@1.2.3".to_string(),
            license_expression: None,
            hashes: vec![],
            dependencies: vec![],
        }];

        let json = generator.generate(&components).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");
        let component = value["components"][0]
            .as_object()
            .expect("component object");
        assert!(
            !component.contains_key("licenses"),
            "empty licenses should be omitted"
        );
    }

    #[test]
    fn preserves_explicit_license_expression() {
        let generator = CycloneDxGenerator::default();
        let components = vec![Component {
            name: "multi-license-lib".to_string(),
            version: "2.0.0".to_string(),
            group: Some("org.example".to_string()),
            purl: "pkg:maven/org.example/multi-license-lib@2.0.0".to_string(),
            license_expression: Some("MIT OR Apache-2.0".to_string()),
            hashes: vec![],
            dependencies: vec![],
        }];

        let json = generator.generate(&components).expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");
        let licenses = value["components"][0]["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 1);
        let expression = licenses[0]["expression"]
            .as_str()
            .expect("expression field");
        assert_eq!(expression, "MIT OR Apache-2.0");
    }

    #[test]
    fn generate_rejects_duplicate_purls() {
        // Duplicate purls would produce colliding bom-refs, which is an invalid CycloneDX BOM.
        let generator = CycloneDxGenerator::default();
        let dup = Component {
            name: "dup".to_string(),
            version: "1.0.0".to_string(),
            group: None,
            purl: "pkg:maven/org.example/dup@1.0.0".to_string(),
            license_expression: None,
            hashes: vec![],
            dependencies: vec![],
        };
        let err = generator.generate(&[dup.clone(), dup]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate purl"),
            "expected duplicate purl rejection, got: {err}"
        );
    }

    #[test]
    fn bom_refs_are_unique() {
        let generator = CycloneDxGenerator::default();
        let json = generator
            .generate(&sample_components())
            .expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");
        let mut refs: Vec<&str> = value["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["bom-ref"].as_str().expect("bom-ref"))
            .collect();
        let count = refs.len();
        refs.sort_unstable();
        refs.dedup();
        assert_eq!(refs.len(), count, "bom-ref values must be unique");
    }

    #[test]
    fn configured_root_component_drives_metadata_and_dependency_graph() {
        let generator = CycloneDxGenerator {
            root_component: Some(Component {
                name: "demo".to_string(),
                version: "1.0.0".to_string(),
                group: Some("com.example".to_string()),
                purl: "pkg:maven/com.example/demo@1.0.0".to_string(),
                license_expression: None,
                hashes: Vec::new(),
                dependencies: vec!["pkg:maven/org.example/app@1.0.0".to_string()],
            }),
            timestamp: None,
            serial_number: Some("urn:uuid:00000000-0000-8000-8000-000000000000".to_string()),
            ..CycloneDxGenerator::default()
        };

        let json = generator
            .generate(&sample_components())
            .expect("sbom generation");
        let value: Value = serde_json::from_str(&json).expect("valid json");

        assert!(value["metadata"].get("timestamp").is_none());
        assert_eq!(value["metadata"]["component"]["group"], "com.example");
        assert_eq!(
            value["metadata"]["component"]["purl"],
            "pkg:maven/com.example/demo@1.0.0"
        );
        assert_eq!(
            value["serialNumber"],
            "urn:uuid:00000000-0000-8000-8000-000000000000"
        );
        assert!(
            value["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| {
                    entry["ref"] == "pkg:maven/com.example/demo@1.0.0"
                        && entry["dependsOn"][0] == "pkg:maven/org.example/app@1.0.0"
                })
        );
    }

    #[test]
    fn cyclonedx_generate_parse_roundtrip_validates_structure() {
        let generator = CycloneDxGenerator::default();
        let components = sample_components();
        let json = generator.generate(&components).expect("sbom generation");
        let parsed: Value = serde_json::from_str(&json).expect("parse generated json");

        assert_eq!(parsed["specVersion"], "1.5");
        assert_eq!(
            parsed["components"].as_array().expect("components").len(),
            2
        );
        assert!(
            parsed["serialNumber"]
                .as_str()
                .expect("serialNumber string")
                .starts_with("urn:uuid:")
        );
    }
}
