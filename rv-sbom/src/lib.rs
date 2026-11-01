//! SBOM generation from caller-supplied package metadata.
//!
//! [`CycloneDxGenerator`] renders a CycloneDX 1.5 JSON document from a
//! [`Component`] list. It validates the list first (the checks are listed on
//! [`Component`]) and returns [`SbomError`] instead of writing a document with
//! duplicate or dangling references.
//!
//! The crate does not read `raeva.lock`, resolve dependencies or fetch artifacts:
//! the caller builds the components, including their hashes and dependency
//! edges (`raeva` builds them from its lockfile).

mod component;
mod cyclonedx;
mod license;

pub use component::{Component, Hash, HashAlgorithm};
pub use cyclonedx::CycloneDxGenerator;
pub use license::License;

/// A vulnerability assessment for some components, written as a CycloneDX
/// `vulnerabilities` entry with its `analysis`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnerabilityAnalysis {
    /// The advisory id, written as `id`.
    pub id: String,
    /// `analysis.state`.
    pub state: AnalysisState,
    /// `analysis.justification`, left out when `None`.
    pub justification: Option<AnalysisJustification>,
    /// `analysis.detail`, left out when `None`.
    pub detail: Option<String>,
    /// Purls of the components assessed, written as `affects` refs.
    pub affects: Vec<String>,
}

/// CycloneDX `analysis.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AnalysisState {
    /// The component is not affected.
    NotAffected,
    /// The vulnerability can be exploited in the component.
    Exploitable,
    /// The vulnerability is fixed in the component.
    Resolved,
    /// The assessment is not finished.
    InTriage,
}

/// CycloneDX `analysis.justification`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AnalysisJustification {
    /// The vulnerable code is not in the component.
    CodeNotPresent,
    /// The vulnerable code is not reachable.
    CodeNotReachable,
    /// Exploiting it needs an environment the product does not have.
    RequiresEnvironment,
    /// A mitigating control protects the component.
    ProtectedByMitigatingControl,
}

/// Why an SBOM document could not be generated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SbomError {
    /// The document could not be serialized to JSON.
    #[error("failed to serialize SBOM: {0}")]
    Serialize(#[from] serde_json::Error),
    /// A component failed one of the checks listed on [`Component`]. The
    /// message names the component (by purl or name) and the failed check.
    #[error("invalid component data: {0}")]
    InvalidComponent(String),
}
