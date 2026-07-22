//! Live smoke tests against the real OSV.dev API.
//!
//! These are `#[ignore]`d by default because they require outbound network access and
//! depend on third-party data. Run explicitly with:
//!
//! ```text
//! cargo test -p rv-vuln --test live_osv -- --ignored
//! ```
//!
//! They also check the OSV response shape and known Log4Shell data.

use rv_vuln::{Dependency, OsvClient, VulnScanner};

/// Known Log4Shell identifiers for log4j-core 2.14.1.
const LOG4J_PURL: &str = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
const LOG4SHELL_GHSA: &str = "GHSA-jfh8-c2jp-5v3q";
const LOG4SHELL_CVE: &str = "CVE-2021-44228";

#[tokio::test]
#[ignore = "requires network access to api.osv.dev"]
async fn live_query_finds_log4shell() {
    let client = OsvClient::new().expect("client builds");
    let vulns = client.query(LOG4J_PURL).await.expect("OSV query succeeds");

    assert!(
        !vulns.is_empty(),
        "OSV should report vulnerabilities for log4j-core 2.14.1"
    );

    let log4shell = vulns
        .iter()
        .find(|v| v.id == LOG4SHELL_GHSA || v.aliases.iter().any(|a| a == LOG4SHELL_CVE))
        .unwrap_or_else(|| {
            panic!(
                "expected Log4Shell ({LOG4SHELL_GHSA}/{LOG4SHELL_CVE}) among {:?}",
                vulns.iter().map(|v| &v.id).collect::<Vec<_>>()
            )
        });

    // OSV appends a temporal metric to this CVSS vector.
    let severity = log4shell
        .severity
        .as_ref()
        .expect("Log4Shell must carry a severity");
    assert_eq!(
        severity.severity_label(),
        "Critical",
        "Log4Shell must be classified Critical, got score {:?}",
        severity.score_value()
    );
}

#[tokio::test]
#[ignore = "requires network access to api.osv.dev"]
async fn live_scanner_counts_log4shell_as_critical() {
    let scanner = VulnScanner::without_cache().expect("scanner builds");
    let deps = vec![Dependency::new(
        "org.apache.logging.log4j",
        "log4j-core",
        "2.14.1",
    )];

    let report = scanner.scan(&deps).await.expect("scan succeeds");

    assert_eq!(report.total_dependencies, 1);
    assert_eq!(
        report.vulnerable_dependencies, 1,
        "log4j-core 2.14.1 must be flagged vulnerable"
    );
    assert!(
        report.critical_count >= 1,
        "scan must count at least one Critical vulnerability, got {report:?}"
    );
}
