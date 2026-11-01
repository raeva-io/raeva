use serde::Serialize;

use crate::component::validate_components;
use crate::{Component, HashAlgorithm, SbomError, VulnerabilityAnalysis};

/// Renders components as a CycloneDX 1.5 JSON document.
#[derive(Debug, Clone)]
pub struct CycloneDxGenerator {
    /// `name` of the tool entry in `metadata.tools.components`, whose
    /// `group` is `raeva`.
    pub tool_name: String,
    /// `version` of the tool entry.
    pub tool_version: String,
    /// The project the document describes, written as `metadata.component`
    /// of type `application` (its hashes are not written). It is
    /// validated with the other components, and its `dependencies` become
    /// the first `dependencies` entry.
    pub root_component: Component,
    /// `serialNumber`, written as given.
    pub serial_number: String,
    /// `vulnerabilities`, in the order given; left out when empty. Each
    /// `affects` purl must be a component of the document.
    pub vulnerabilities: Vec<VulnerabilityAnalysis>,
}

impl CycloneDxGenerator {
    /// Validates `components` together with `root_component` and renders
    /// them as pretty-printed CycloneDX JSON.
    ///
    /// Each component becomes a `library` entry whose `bom-ref` is its purl,
    /// in input order, and gets one `dependencies` entry.
    ///
    /// # Errors
    ///
    /// [`SbomError::InvalidComponent`] when a component fails a check listed
    /// on [`Component`], and [`SbomError::Serialize`] when JSON serialization
    /// fails.
    pub fn generate(&self, components: &[Component]) -> Result<String, SbomError> {
        self.generate_with_properties(components, &[])
    }

    /// Renders a document with the given name/value pairs in `metadata.properties`.
    /// Validation and errors are the same as [`Self::generate`].
    pub fn generate_with_properties(
        &self,
        components: &[Component],
        properties: &[(String, String)],
    ) -> Result<String, SbomError> {
        let root = &self.root_component;
        validate_components(std::iter::once(root).chain(components))?;
        for vulnerability in &self.vulnerabilities {
            for purl in &vulnerability.affects {
                if *purl != root.purl && !components.iter().any(|c| c.purl == *purl) {
                    return Err(SbomError::InvalidComponent(format!(
                        "vulnerability {} affects {purl}, which is not a component",
                        vulnerability.id
                    )));
                }
            }
        }

        let bom = Bom {
            bom_format: "CycloneDX",
            spec_version: "1.5",
            serial_number: &self.serial_number,
            version: 1,
            metadata: Metadata {
                properties: properties
                    .iter()
                    .map(|(name, value)| Property { name, value })
                    .collect(),
                tools: Tools {
                    components: [Tool {
                        component_type: "application",
                        group: "raeva",
                        name: &self.tool_name,
                        version: &self.tool_version,
                    }],
                },
                component: MetadataComponent {
                    component_type: "application",
                    group: root.group.as_deref(),
                    name: &root.name,
                    version: &root.version,
                    bom_ref: &root.purl,
                    purl: &root.purl,
                    licenses: root
                        .licenses
                        .iter()
                        .map(|license| LicenseChoice { license })
                        .collect(),
                },
            },
            components: components.iter().map(library).collect(),
            dependencies: std::iter::once(root)
                .chain(components)
                .map(|component| Dependency {
                    reference: &component.purl,
                    depends_on: &component.dependencies,
                })
                .collect(),
            vulnerabilities: self
                .vulnerabilities
                .iter()
                .map(|vulnerability| Vulnerability {
                    id: &vulnerability.id,
                    analysis: Analysis {
                        state: vulnerability.state,
                        justification: vulnerability.justification,
                        detail: vulnerability.detail.as_deref(),
                    },
                    affects: (vulnerability.affects.iter())
                        .map(|purl| Affects { reference: purl })
                        .collect(),
                })
                .collect(),
        };
        Ok(serde_json::to_string_pretty(&bom)?)
    }
}

fn library(component: &Component) -> Library<'_> {
    Library {
        bom_ref: &component.purl,
        component_type: "library",
        group: component.group.as_deref(),
        name: &component.name,
        version: &component.version,
        purl: &component.purl,
        licenses: component
            .licenses
            .iter()
            .map(|license| LicenseChoice { license })
            .collect(),
        hashes: component
            .hashes
            .iter()
            .map(|hash| Hash {
                algorithm: match hash.algorithm {
                    HashAlgorithm::Sha256 => "SHA-256",
                    HashAlgorithm::Sha512 => "SHA-512",
                    HashAlgorithm::Md5 => "MD5",
                    HashAlgorithm::Sha1 => "SHA-1",
                },
                value: &hash.value,
            })
            .collect(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Bom<'a> {
    bom_format: &'static str,
    spec_version: &'static str,
    serial_number: &'a str,
    version: u32,
    metadata: Metadata<'a>,
    components: Vec<Library<'a>>,
    dependencies: Vec<Dependency<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vulnerabilities: Vec<Vulnerability<'a>>,
}

#[derive(Serialize)]
struct Vulnerability<'a> {
    id: &'a str,
    analysis: Analysis<'a>,
    affects: Vec<Affects<'a>>,
}

#[derive(Serialize)]
struct Analysis<'a> {
    state: crate::AnalysisState,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<crate::AnalysisJustification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

#[derive(Serialize)]
struct Affects<'a> {
    #[serde(rename = "ref")]
    reference: &'a str,
}

#[derive(Serialize)]
struct Property<'a> {
    name: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct Metadata<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property<'a>>,
    tools: Tools<'a>,
    component: MetadataComponent<'a>,
}

#[derive(Serialize)]
struct Tools<'a> {
    components: [Tool<'a>; 1],
}

#[derive(Serialize)]
struct Tool<'a> {
    #[serde(rename = "type")]
    component_type: &'static str,
    group: &'static str,
    name: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct MetadataComponent<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    licenses: Vec<LicenseChoice<'a>>,
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<&'a str>,
    name: &'a str,
    version: &'a str,
    #[serde(rename = "bom-ref")]
    bom_ref: &'a str,
    purl: &'a str,
}

#[derive(Serialize)]
struct Library<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    licenses: Vec<LicenseChoice<'a>>,
    #[serde(rename = "bom-ref")]
    bom_ref: &'a str,
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<&'a str>,
    name: &'a str,
    version: &'a str,
    purl: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<Hash<'a>>,
}

#[derive(Serialize)]
struct Hash<'a> {
    #[serde(rename = "alg")]
    algorithm: &'static str,
    #[serde(rename = "content")]
    value: &'a str,
}

#[derive(Serialize)]
struct LicenseChoice<'a> {
    license: &'a crate::License,
}

#[derive(Serialize)]
struct Dependency<'a> {
    #[serde(rename = "ref")]
    reference: &'a str,
    #[serde(rename = "dependsOn", skip_serializing_if = "is_empty")]
    depends_on: &'a [String],
}

fn is_empty(list: &&[String]) -> bool {
    list.is_empty()
}
