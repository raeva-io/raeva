use indexmap::IndexSet;

use crate::{FailedFetch, OsvClient, Result, VulnResult};

/// Looks up a set of [`Dependency`] coordinates in OSV.
pub struct VulnScanner {
    client: OsvClient,
}

impl VulnScanner {
    /// A scanner over a configured client (endpoint, proxies, retries).
    pub fn from_client(client: OsvClient) -> Self {
        Self { client }
    }

    /// Query OSV once per distinct purl among `dependencies` and report
    /// every vulnerability found, whatever its severity.
    ///
    /// One distinct purl uses OSV `/query`; more use `/querybatch`, in
    /// chunks of 100, and then fetch each named record once from
    /// `/vulns/{id}`. A coordinate that cannot be written as a purl fails
    /// with [`VulnError::InvalidPurl`](crate::VulnError::InvalidPurl) before
    /// any request, and a failed query fails the scan. A record the
    /// batch names but that cannot be fetched does not: the report keeps the
    /// records that were fetched and lists it in
    /// [`ScanReport::failed_fetches`], and the scan is incomplete.
    pub async fn scan(&self, dependencies: &[Dependency]) -> Result<ScanReport> {
        let unique_purls: Vec<String> = dependencies
            .iter()
            .map(Dependency::purl)
            .collect::<Result<IndexSet<_>>>()?
            .into_iter()
            .collect();

        let (fetched, failed_fetches) = match unique_purls.as_slice() {
            [] => (Vec::new(), Vec::new()),
            [purl] => {
                let vulnerabilities = self.client.query(purl).await?;
                let result = VulnResult {
                    purl: purl.clone(),
                    vulnerabilities,
                };
                (vec![result], Vec::new())
            }
            purls => self.client.query_batch(purls).await?,
        };

        // Both queries answer each purl once, in the order asked.
        Ok(ScanReport {
            total_dependencies: unique_purls.len(),
            vulnerabilities: (fetched.into_iter())
                .filter(|result| !result.vulnerabilities.is_empty())
                .collect(),
            failed_fetches,
        })
    }
}

/// One Maven coordinate to look up.
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Maven `groupId`, the purl namespace.
    pub group_id: String,
    /// Maven `artifactId`, the purl name.
    pub artifact_id: String,
    /// Resolved version, the purl version.
    pub version: String,
    /// Artifact type. Anything other than `jar` or empty becomes the purl
    /// `type` qualifier.
    pub packaging: String,
    /// Maven classifier, written as the purl `classifier` qualifier when
    /// present and not empty.
    pub classifier: Option<String>,
}

impl Dependency {
    /// A `jar` dependency without a classifier.
    pub fn new(
        group_id: impl Into<String>,
        artifact_id: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            artifact_id: artifact_id.into(),
            version: version.into(),
            packaging: "jar".to_string(),
            classifier: None,
        }
    }

    /// The canonical Maven purl, the same string `rv-sbom` writes for this coordinate.
    pub fn purl(&self) -> Result<String> {
        rv_maven_types::maven_purl_with_qualifiers(
            &self.group_id,
            &self.artifact_id,
            &self.version,
            &self.packaging,
            self.classifier.as_deref(),
        )
        .map_err(|err| crate::VulnError::InvalidPurl(err.to_string()))
    }
}

/// The outcome of [`VulnScanner::scan`]. A report with
/// [`ScanReport::failed_fetches`] is incomplete: a purl may have more
/// findings than it lists.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// Number of distinct purls scanned. Dependencies with the same purl
    /// count once.
    pub total_dependencies: usize,
    /// One entry per vulnerable purl, in first-seen input order. Purls
    /// without findings are left out.
    pub vulnerabilities: Vec<VulnResult>,
    /// Records OSV named for the scanned purls that could not be fetched,
    /// so their findings are missing from this report.
    pub failed_fetches: Vec<FailedFetch>,
}

impl ScanReport {
    /// Whether every record OSV named was fetched.
    pub fn is_complete(&self) -> bool {
        self.failed_fetches.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use rv_test_support::http::{Response, StubServer};

    use crate::{Dependency, OsvClient, OsvSettings, VulnError, VulnScanner};

    #[test]
    fn a_dependency_without_a_purl_names_the_field() {
        for (dependency, reason) in [
            (
                Dependency::new("", "demo", "1.0.0"),
                "invalid group '': group cannot be empty",
            ),
            (
                Dependency::new("org.example", "", "1.0.0"),
                "invalid artifact name '': name cannot be empty",
            ),
            (
                Dependency::new("org.example", "demo", " "),
                "invalid version '': version cannot be empty",
            ),
        ] {
            let error = dependency.purl().expect_err("no purl");
            assert!(matches!(error, VulnError::InvalidPurl(_)), "{error:?}");
            assert_eq!(error.to_string(), format!("invalid purl: {reason}"));
        }
    }

    /// Dependency counts are over distinct purls, and a record OSV names but
    /// does not serve makes the scan incomplete.
    #[tokio::test]
    async fn scan_counts_distinct_purls_and_bands() {
        let server = StubServer::start(|request| {
            let json =
                |body: String| Response::new(200, body).header("Content-Type", "application/json");
            match request.path.as_str() {
                "/v1/querybatch" => {
                    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                    let results: Vec<_> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|query| {
                            let purl = query["package"]["purl"].as_str().unwrap();
                            if purl.starts_with("pkg:maven/org.example/one@") {
                                serde_json::json!({ "vulns": [
                                    {"id": "OSV-HIGH"}, {"id": "OSV-NONE"}, {"id": "OSV-MISSING"}
                                ]})
                            } else {
                                serde_json::json!({})
                            }
                        })
                        .collect();
                    json(serde_json::json!({ "results": results }).to_string())
                }
                "/v1/vulns/OSV-HIGH" => json(
                    r#"{"id":"OSV-HIGH","severity":[{"type":"CVSS_V3","score":"1.0"},{"type":"CVSS_V3","score":"8.0"}]}"#.to_string(),
                ),
                "/v1/vulns/OSV-NONE" => json(r#"{"id":"OSV-NONE"}"#.to_string()),
                _ => Response::new(400, r#"{"message":"missing record"}"#),
            }
        });
        let client = OsvClient::with_settings(
            format!("http://{}/v1", server.addr()),
            OsvSettings::default(),
        )
        .expect("OSV client");
        let dependencies = [
            Dependency::new("org.example", "one", "1.0.0"),
            Dependency::new("org.example", "two", "1.0.0"),
            Dependency::new("org.example", "one", "1.0.0"),
        ];
        let report = VulnScanner::from_client(client)
            .scan(&dependencies)
            .await
            .expect("scan");

        assert_eq!(report.total_dependencies, 2);
        assert_eq!(report.vulnerabilities.len(), 1);
        assert_eq!(
            report.vulnerabilities[0].purl,
            "pkg:maven/org.example/one@1.0.0"
        );
        let severity = report.vulnerabilities[0].vulnerabilities[0]
            .severity
            .as_ref();
        assert_eq!(severity.map(|s| s.score.as_str()), Some("8.0"));
        let bands: Vec<_> = (report.vulnerabilities[0].vulnerabilities.iter())
            .map(crate::Vulnerability::severity_band)
            .collect();
        assert_eq!(
            bands,
            [crate::SeverityBand::High, crate::SeverityBand::Unknown]
        );
        assert!(!report.is_complete());
        assert_eq!(report.failed_fetches[0].id, "OSV-MISSING");
        server.stop();
    }
}
