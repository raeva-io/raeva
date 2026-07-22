//! SBOM generation from caller-supplied package metadata.
//!
//! License evidence is accepted only as one explicit SPDX expression. The crate
//! passes that expression through and does not infer relationships between licenses.

mod component;
mod cyclonedx;
mod purl;
mod spdx;

pub use component::{Component, Hash, HashAlgorithm, validate_components};
pub use cyclonedx::CycloneDxGenerator;
pub use purl::{maven_purl, maven_purl_with_qualifiers, parse_purl};
pub use spdx::SpdxGenerator;

#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    #[error("failed to serialize SBOM: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid component data: {0}")]
    InvalidComponent(String),
}

#[cfg(test)]
mod tests {
    use super::SbomError;

    #[test]
    fn invalid_component_error_message() {
        let error = SbomError::InvalidComponent("missing purl".to_string());
        assert_eq!(error.to_string(), "invalid component data: missing purl");
    }

    // SBOM schema validation tests.

    fn fixture_components() -> Vec<crate::Component> {
        vec![
            crate::Component {
                name: "spring-core".to_string(),
                version: "6.1.0".to_string(),
                group: Some("org.springframework".to_string()),
                purl: "pkg:maven/org.springframework/spring-core@6.1.0".to_string(),
                license_expression: Some("Apache-2.0".to_string()),
                hashes: vec![crate::Hash {
                    algorithm: crate::HashAlgorithm::Sha256,
                    value: "a".repeat(64),
                }],
                dependencies: vec!["pkg:maven/org.springframework/spring-jcl@6.1.0".to_string()],
            },
            crate::Component {
                name: "spring-jcl".to_string(),
                version: "6.1.0".to_string(),
                group: Some("org.springframework".to_string()),
                purl: "pkg:maven/org.springframework/spring-jcl@6.1.0".to_string(),
                license_expression: Some("Apache-2.0".to_string()),
                hashes: vec![],
                dependencies: vec![],
            },
        ]
    }

    /// Validate CycloneDX 1.5 SBOM structure by checking required top-level fields.
    ///
    /// Per the CycloneDX 1.5 JSON schema the following fields are required:
    /// - `bomFormat`: must be `"CycloneDX"`
    /// - `specVersion`: must be `"1.5"`
    /// - `version`: integer (≥ 1)
    /// - `components`: array
    #[test]
    fn cyclonedx_sbom_structure_validation() {
        let generator = crate::CycloneDxGenerator::default();
        let components = fixture_components();
        let json = generator.generate(&components).expect("SBOM generation");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("SBOM output is valid JSON");

        // Required top-level fields per CycloneDX 1.5 spec.
        assert_eq!(
            value["bomFormat"].as_str(),
            Some("CycloneDX"),
            "bomFormat must be 'CycloneDX'"
        );
        assert_eq!(
            value["specVersion"].as_str(),
            Some("1.5"),
            "specVersion must be '1.5'"
        );
        assert!(
            value["version"].as_u64().is_some_and(|v| v >= 1),
            "version must be a positive integer"
        );
        assert!(
            value["components"].is_array(),
            "components must be an array"
        );
        assert!(
            value["metadata"].is_object(),
            "metadata must be present and an object"
        );
        assert!(
            value["serialNumber"]
                .as_str()
                .is_some_and(|s| s.starts_with("urn:uuid:")),
            "serialNumber must be a urn:uuid: URI"
        );

        // Validate component structure.
        let comps = value["components"].as_array().unwrap();
        assert_eq!(comps.len(), 2, "should have 2 components");
        for comp in comps {
            assert!(comp["name"].is_string(), "component must have name");
            assert!(comp["version"].is_string(), "component must have version");
            assert!(comp["purl"].is_string(), "component must have purl");
            assert!(
                comp["type"].as_str().is_some_and(|t| !t.is_empty()),
                "component must have non-empty type"
            );
            assert!(
                comp["bom-ref"].as_str().is_some_and(|r| !r.is_empty()),
                "component must have non-empty bom-ref"
            );
        }

        // Validate dependencies section.
        assert!(
            value["dependencies"].is_array(),
            "dependencies must be an array"
        );
        let deps = value["dependencies"].as_array().unwrap();
        assert_eq!(
            deps.len(),
            2,
            "should have dependency entry for each component"
        );
        for dep in deps {
            assert!(
                dep["ref"].is_string(),
                "each dependency entry must have a 'ref'"
            );
        }
    }

    /// Validate SPDX 2.3 SBOM structure by checking required top-level fields.
    ///
    /// Per the SPDX 2.3 spec the following fields are required at document level:
    /// - `spdxVersion`: must be `"SPDX-2.3"`
    /// - `SPDXID`: must be `"SPDXRef-DOCUMENT"`
    /// - `packages`: array (one entry per software package)
    #[test]
    fn spdx_sbom_structure_validation() {
        let generator = crate::SpdxGenerator::default();
        let components = fixture_components();
        let json = generator.generate(&components).expect("SPDX generation");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("SPDX output is valid JSON");

        // Required top-level fields per SPDX 2.3 spec.
        assert_eq!(
            value["spdxVersion"].as_str(),
            Some("SPDX-2.3"),
            "spdxVersion must be 'SPDX-2.3'"
        );
        assert_eq!(
            value["SPDXID"].as_str(),
            Some("SPDXRef-DOCUMENT"),
            "SPDXID must be 'SPDXRef-DOCUMENT'"
        );
        assert!(
            value["dataLicense"].as_str().is_some_and(|d| !d.is_empty()),
            "dataLicense must be present"
        );
        assert!(value["packages"].is_array(), "packages must be an array");
        assert!(
            value["documentNamespace"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "documentNamespace must be present"
        );

        // Validate package structure.
        let packages = value["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 2, "should have 2 packages");
        for pkg in packages {
            assert!(
                pkg["SPDXID"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("SPDXRef-")),
                "package SPDXID must start with 'SPDXRef-'"
            );
            assert!(pkg["name"].is_string(), "package must have name");
            assert!(
                pkg["versionInfo"].is_string(),
                "package must have versionInfo"
            );
            assert!(
                pkg["downloadLocation"].is_string(),
                "package must have downloadLocation"
            );
            assert!(
                pkg["licenseConcluded"].is_string(),
                "package must have licenseConcluded"
            );

            // externalRefs with PURL is required for SBOM tool output.
            let external_refs = pkg["externalRefs"]
                .as_array()
                .expect("externalRefs present");
            assert!(
                !external_refs.is_empty(),
                "package must have at least one externalRef"
            );
            let purl_ref = external_refs
                .iter()
                .find(|r| r["referenceType"] == "purl")
                .expect("package must have a purl externalRef");
            assert_eq!(
                purl_ref["referenceCategory"].as_str(),
                Some("PACKAGE-MANAGER"),
                "purl externalRef must have referenceCategory PACKAGE-MANAGER"
            );
            assert!(
                purl_ref["referenceLocator"]
                    .as_str()
                    .is_some_and(|l| l.starts_with("pkg:")),
                "referenceLocator must be a PURL"
            );
        }
    }
}
