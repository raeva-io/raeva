use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use packageurl::PackageUrl;

use crate::{OsvClient, Result, SeverityBand, VulnCache, VulnResult, Vulnerability};

pub struct VulnScanner {
    client: OsvClient,
    cache: Option<VulnCache>,
}

impl VulnScanner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: OsvClient::new()?,
            cache: Some(VulnCache::default()),
        })
    }

    pub fn without_cache() -> Result<Self> {
        Ok(Self {
            client: OsvClient::new()?,
            cache: None,
        })
    }

    pub fn with_cache(cache: VulnCache) -> Result<Self> {
        Ok(Self {
            client: OsvClient::new()?,
            cache: Some(cache),
        })
    }

    pub fn from_client(client: OsvClient) -> Self {
        Self {
            client,
            cache: None,
        }
    }

    pub async fn scan(&self, dependencies: &[Dependency]) -> Result<ScanReport> {
        self.scan_with_threshold(dependencies, 0.0).await
    }

    pub async fn scan_with_threshold(
        &self,
        dependencies: &[Dependency],
        min_severity: f32,
    ) -> Result<ScanReport> {
        let total_dependencies = dependencies.len();

        // Deduplicate PURLs and separate cached from uncached in one pass
        let mut unique_purls: Vec<Arc<str>> = Vec::new();
        let mut results_map: HashMap<Arc<str>, Vec<Vulnerability>> = HashMap::new();
        let mut to_query: Vec<Arc<str>> = Vec::new();
        let mut seen: HashSet<Arc<str>> = HashSet::new();

        for dependency in dependencies {
            let purl: Arc<str> = dependency.purl()?.into();
            if !seen.insert(purl.clone()) {
                continue;
            }

            unique_purls.push(purl.clone());
            if let Some(vulnerabilities) = self.cache.as_ref().and_then(|c| c.get(&purl)) {
                results_map.insert(purl, vulnerabilities);
            } else {
                to_query.push(purl);
            }
        }

        if !to_query.is_empty() {
            let query_strings: Vec<String> = to_query.iter().map(|p| p.to_string()).collect();
            let query_count = query_strings.len();

            let fetched = if query_count == 1 {
                let purl = query_strings[0].clone();
                let vulnerabilities = self.client.query(&purl).await?;
                vec![VulnResult {
                    purl,
                    vulnerabilities,
                }]
            } else {
                let batch_result = self.client.query_batch(&query_strings).await?;
                if !batch_result.failed_fetches.is_empty() {
                    return Err(crate::VulnError::InvalidResponse(format!(
                        "failed to fetch {} vulnerability record(s)",
                        batch_result.failed_fetches.len()
                    )));
                }
                batch_result.results
            };

            // Build a HashMap for O(1) lookup of Arc<str> by purl string
            let purl_map: HashMap<&str, Arc<str>> = to_query
                .iter()
                .map(|arc| (arc.as_ref(), arc.clone()))
                .collect();

            // Only cache results when we have a complete response (one result per queried PURL).
            // A partial response means some results may be missing. Caching "no vulns" for
            // those PURLs would be a false negative.
            let is_complete_response = fetched.len() == query_count;

            // Reuse Arc<str> from to_query to avoid redundant allocations
            for result in fetched {
                let arc_purl = purl_map
                    .get(result.purl.as_str())
                    .cloned()
                    .unwrap_or_else(|| result.purl.as_str().into());

                if is_complete_response && let Some(c) = self.cache.as_ref() {
                    c.insert(arc_purl.to_string(), result.vulnerabilities.clone());
                }
                results_map.insert(arc_purl, result.vulnerabilities);
            }
        }

        let mut filtered_results = Vec::new();

        for purl in unique_purls {
            let vulnerabilities = results_map.remove(&purl).unwrap_or_default();
            let filtered = filter_vulnerabilities(vulnerabilities, min_severity);
            if filtered.is_empty() {
                continue;
            }
            filtered_results.push(VulnResult {
                purl: purl.to_string(),
                vulnerabilities: filtered,
            });
        }

        Ok(ScanReport::from_results(
            total_dependencies,
            filtered_results,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub packaging: String,
    pub classifier: Option<String>,
}

impl Dependency {
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

    pub fn purl(&self) -> Result<String> {
        if self.group_id.trim().is_empty() {
            return Err(crate::VulnError::InvalidPurl(
                "Maven group cannot be empty".to_string(),
            ));
        }
        if self.artifact_id.trim().is_empty() {
            return Err(crate::VulnError::InvalidPurl(
                "Maven artifact cannot be empty".to_string(),
            ));
        }
        if self.version.trim().is_empty() {
            return Err(crate::VulnError::InvalidPurl(
                "Maven version cannot be empty".to_string(),
            ));
        }

        let mut purl = PackageUrl::new("maven", self.artifact_id.as_str())
            .map_err(|err| crate::VulnError::InvalidPurl(err.to_string()))?;
        purl.with_namespace(self.group_id.as_str())
            .and_then(|purl| purl.with_version(self.version.as_str()))
            .map_err(|err| crate::VulnError::InvalidPurl(err.to_string()))?;

        if !self.packaging.is_empty() && self.packaging != "jar" {
            purl.add_qualifier("type", self.packaging.as_str())
                .map_err(|err| crate::VulnError::InvalidPurl(err.to_string()))?;
        }
        if let Some(classifier) = self.classifier.as_deref()
            && !classifier.is_empty()
        {
            purl.add_qualifier("classifier", classifier)
                .map_err(|err| crate::VulnError::InvalidPurl(err.to_string()))?;
        }

        purl.validate()
            .map_err(|err| crate::VulnError::InvalidPurl(err.to_string()))?;

        Ok(canonical_purl_string(&purl))
    }
}

fn canonical_purl_string(purl: &PackageUrl<'_>) -> String {
    let rendered = purl.to_string();
    let base = rendered
        .split_once('?')
        .map_or(rendered.as_str(), |(base, _)| base);
    let base = if let Some((path, version)) = base.rsplit_once('@') {
        format!("{path}@{}", version.replace('/', "%2F"))
    } else {
        base.to_string()
    };
    if purl.qualifiers().is_empty() {
        return base;
    }

    let mut qualifiers = purl.qualifiers().iter().collect::<Vec<_>>();
    qualifiers.sort();
    let qualifiers = qualifiers
        .into_iter()
        .map(|(key, value)| format!("{key}={}", encode_qualifier_value(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{qualifiers}")
}

fn encode_qualifier_value(value: &str) -> String {
    let mut probe = PackageUrl::new("generic", "probe").expect("valid probe purl");
    probe
        .add_qualifier("value", value)
        .expect("valid probe qualifier");
    probe
        .to_string()
        .split_once("?value=")
        .expect("probe qualifier")
        .1
        .replace('&', "%26")
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub total_dependencies: usize,
    pub vulnerable_dependencies: usize,
    pub vulnerabilities: Vec<VulnResult>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub unknown_count: usize,
}

impl ScanReport {
    fn from_results(total_dependencies: usize, results: Vec<VulnResult>) -> Self {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut unknown_count = 0;

        for result in &results {
            for vulnerability in &result.vulnerabilities {
                match vulnerability.severity_band() {
                    SeverityBand::Unknown => unknown_count += 1,
                    SeverityBand::Low => low_count += 1,
                    SeverityBand::Medium => medium_count += 1,
                    SeverityBand::High => high_count += 1,
                    SeverityBand::Critical => critical_count += 1,
                }
            }
        }

        Self {
            total_dependencies,
            vulnerable_dependencies: results.len(),
            vulnerabilities: results,
            critical_count,
            high_count,
            medium_count,
            low_count,
            unknown_count,
        }
    }
}

fn filter_vulnerabilities(
    vulnerabilities: Vec<Vulnerability>,
    min_severity: f32,
) -> Vec<Vulnerability> {
    vulnerabilities
        .into_iter()
        .filter(|vulnerability| {
            severity_score(vulnerability).is_none_or(|score| score >= min_severity)
        })
        .collect()
}

fn severity_score(vulnerability: &Vulnerability) -> Option<f32> {
    vulnerability
        .severity
        .as_ref()
        .and_then(|severity| severity.score_value())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use packageurl::PackageUrl;

    use super::ScanReport;
    use crate::{
        Dependency, OsvClient, Severity, VulnError, VulnResult, VulnScanner, Vulnerability,
    };

    #[test]
    fn dependency_to_purl() {
        let dependency = crate::Dependency::new("org.example", "demo", "1.0.0");
        assert_eq!(
            dependency.purl().expect("purl"),
            "pkg:maven/org.example/demo@1.0.0"
        );
    }

    #[test]
    fn dependency_purl_includes_non_default_artifact_identity() {
        let dependency = crate::Dependency {
            packaging: "test-jar".to_string(),
            classifier: Some("tests".to_string()),
            ..crate::Dependency::new("org.example", "demo", "1.0.0")
        };
        assert_eq!(
            dependency.purl().expect("purl"),
            "pkg:maven/org.example/demo@1.0.0?classifier=tests&type=test-jar"
        );
    }

    #[test]
    fn dependency_purl_round_trips_reserved_characters_in_every_field() {
        const VALUES: &[&str] = &["%", "@", "/", "&", "=", "?", "#", " ", "é"];

        for value in VALUES {
            let mut dependency = Dependency::new(format!("g{value}x"), "a", "1");
            assert_dependency_fields(&dependency);

            dependency = Dependency::new("g", format!("a{value}x"), "1");
            assert_dependency_fields(&dependency);

            dependency = Dependency::new("g", "a", format!("1{value}x"));
            assert_dependency_fields(&dependency);

            dependency.packaging = format!("type{value}value");
            dependency.classifier = Some("tests".to_string());
            assert_dependency_fields(&dependency);

            dependency.packaging = "zip".to_string();
            dependency.classifier = Some(format!("class{value}value"));
            assert_dependency_fields(&dependency);
        }
    }

    #[test]
    fn dependency_purl_does_not_collapse_percent_encoded_lookalikes() {
        assert_ne!(
            Dependency::new("g@x", "a", "1").purl().expect("purl"),
            Dependency::new("g%40x", "a", "1").purl().expect("purl")
        );
        assert_ne!(
            Dependency::new("g", "a@x", "1").purl().expect("purl"),
            Dependency::new("g", "a%40x", "1").purl().expect("purl")
        );
        assert_ne!(
            Dependency::new("g", "a", "v@x").purl().expect("purl"),
            Dependency::new("g", "a", "v%40x").purl().expect("purl")
        );

        let mut type_at = Dependency::new("g", "a", "1");
        type_at.packaging = "t@x".to_string();
        let mut type_percent = type_at.clone();
        type_percent.packaging = "t%40x".to_string();
        assert_ne!(
            type_at.purl().expect("purl"),
            type_percent.purl().expect("purl")
        );

        let mut classifier_at = Dependency::new("g", "a", "1");
        classifier_at.classifier = Some("c@x".to_string());
        let mut classifier_percent = classifier_at.clone();
        classifier_percent.classifier = Some("c%40x".to_string());
        assert_ne!(
            classifier_at.purl().expect("purl"),
            classifier_percent.purl().expect("purl")
        );
    }

    #[test]
    fn dependency_purl_rejects_empty_artifact() {
        let error = Dependency::new("g", " ", "1")
            .purl()
            .expect_err("empty artifact must fail");
        assert!(error.to_string().contains("artifact"));
    }

    fn assert_dependency_fields(dependency: &Dependency) {
        let purl = dependency.purl().expect("purl");
        let parsed: PackageUrl = purl.parse().expect("parse purl");
        assert_eq!(parsed.namespace(), Some(dependency.group_id.as_str()));
        assert_eq!(parsed.name(), dependency.artifact_id);
        assert_eq!(parsed.version(), Some(dependency.version.as_str()));
        if dependency.packaging != "jar" {
            assert_eq!(
                parsed.qualifiers().get("type").map(|value| value.as_ref()),
                Some(dependency.packaging.as_str())
            );
        }
        if let Some(classifier) = dependency.classifier.as_deref() {
            assert_eq!(
                parsed
                    .qualifiers()
                    .get("classifier")
                    .map(|value| value.as_ref()),
                Some(classifier)
            );
        }
        let rebuilt = Dependency {
            group_id: parsed.namespace().unwrap().to_string(),
            artifact_id: parsed.name().to_string(),
            version: parsed.version().unwrap().to_string(),
            packaging: parsed
                .qualifiers()
                .get("type")
                .map_or_else(|| "jar".to_string(), ToString::to_string),
            classifier: parsed
                .qualifiers()
                .get("classifier")
                .map(ToString::to_string),
        }
        .purl()
        .expect("rebuild purl");
        assert_eq!(rebuilt, purl);
    }

    #[test]
    fn scan_report_counts_severity() {
        let vulnerabilities = vec![
            vulnerability_with_score("9.8"),
            vulnerability_with_score("7.0"),
            vulnerability_with_score("5.0"),
            vulnerability_with_score("2.0"),
        ];
        let results = vec![VulnResult {
            purl: "pkg:maven/org.example/demo@1.0.0".to_string(),
            vulnerabilities,
        }];

        let report = ScanReport::from_results(3, results);
        assert_eq!(report.total_dependencies, 3);
        assert_eq!(report.vulnerable_dependencies, 1);
        assert_eq!(report.critical_count, 1);
        assert_eq!(report.high_count, 1);
        assert_eq!(report.medium_count, 1);
        assert_eq!(report.low_count, 1);
        assert_eq!(report.unknown_count, 0);
    }

    #[test]
    fn scan_report_counts_unknown_severity_separately() {
        let mut unknown = vulnerability_with_score("invalid");
        unknown.severity = None;
        let report = ScanReport::from_results(
            1,
            vec![VulnResult {
                purl: "pkg:maven/org.example/demo@1.0.0".to_string(),
                vulnerabilities: vec![unknown],
            }],
        );
        assert_eq!(report.unknown_count, 1);
        assert_eq!(report.low_count, 0);
    }

    #[test]
    fn severity_filter_keeps_unknown_findings_at_high_thresholds() {
        let mut unknown = vulnerability_with_score("invalid");
        unknown.severity = None;
        assert_eq!(super::filter_vulnerabilities(vec![unknown], 10.0).len(), 1);
    }

    #[tokio::test]
    async fn scan_rejects_incomplete_batch_results() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().expect("mock server address");
        let server = std::thread::spawn(move || {
            let responses = [
                (
                    "/v1/querybatch",
                    "200 OK",
                    r#"{"results":[{"vulns":[{"id":"OSV-MISSING"}]},{"vulns":[]}] }"#,
                ),
                (
                    "/v1/vulns/OSV-MISSING",
                    "400 Bad Request",
                    r#"{"message":"missing record"}"#,
                ),
            ];
            for (path, status, body) in responses {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut request = [0_u8; 8192];
                let size = stream.read(&mut request).expect("read request");
                let request = String::from_utf8_lossy(&request[..size]);
                assert!(request.contains(path), "request={request}");
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
        });

        let scanner = VulnScanner::from_client(
            OsvClient::with_base_url(format!("http://{address}/v1")).expect("OSV client"),
        );
        let dependencies = [
            Dependency::new("org.example", "one", "1.0.0"),
            Dependency::new("org.example", "two", "1.0.0"),
        ];
        let error = scanner
            .scan(&dependencies)
            .await
            .expect_err("scan must fail");
        assert!(matches!(
            error,
            VulnError::InvalidResponse(ref details)
                if details.contains("OSV-MISSING")
        ));
        server.join().expect("mock server");
    }

    fn vulnerability_with_score(score: &str) -> Vulnerability {
        Vulnerability {
            id: "OSV-TEST".to_string(),
            aliases: Vec::new(),
            summary: "test".to_string(),
            details: None,
            severity: Some(Severity {
                type_: "CVSS_V3".to_string(),
                score: score.to_string(),
            }),
            references: Vec::new(),
            affected: Vec::new(),
        }
    }
}
