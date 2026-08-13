use std::collections::BTreeMap;
use std::path::Path;

use chrono::{SecondsFormat, Utc};
use clap::{Args, ValueEnum};
use rv_vuln::{OsvClient, ScanReport, SeverityBand, VulnScanner, Vulnerability};

use crate::commands::module_selector::ModuleSelector;
use crate::error::{CliError, Result};
use crate::output::{Table, is_json_mode, json_result};

const OSV_BASE_URL_ENV: &str = "RAEVA_OSV_BASE_URL";

#[derive(Debug, Args)]
#[command(
    about = "Scan dependencies in rv.lock for known vulnerabilities",
    after_long_help = "\
Formats:
  table    Human-readable findings (default)
  json     Machine-readable scan envelope
  sarif    SARIF 2.1.0 for code scanning systems

Exit codes:
  0  Scan completed with no findings at or above the threshold
  1  Scan completed with findings at or above the threshold
  2  Scan did not complete

Unknown severity meets every --fail-on threshold.

Examples:
  rv vuln
  rv vuln --module app/pom.xml
  rv vuln --module com.acme:app
  rv vuln --format json
  rv vuln --format sarif
  rv vuln --fail-on high
"
)]
pub struct VulnArgs {
    #[command(flatten)]
    module: ModuleSelector,
    #[arg(
        long,
        value_enum,
        default_value = "table",
        help = "Output format: table, json, or sarif"
    )]
    format: VulnOutputFormat,
    #[arg(
        long,
        value_enum,
        default_value = "any",
        value_name = "SEVERITY",
        help = "Return exit 1 at this severity; unknown always matches"
    )]
    fail_on: SeverityThreshold,
}

impl VulnArgs {
    pub(crate) fn json_output(&self) -> bool {
        self.format != VulnOutputFormat::Table
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VulnOutputFormat {
    Table,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SeverityThreshold {
    Any,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityThreshold {
    fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn matches(self, vulnerability: &Vulnerability) -> bool {
        if self == Self::Any {
            return true;
        }
        match vulnerability.severity_band() {
            SeverityBand::Unknown => true,
            SeverityBand::Low => self == Self::Low,
            SeverityBand::Medium => matches!(self, Self::Low | Self::Medium),
            SeverityBand::High => matches!(self, Self::Low | Self::Medium | Self::High),
            SeverityBand::Critical => true,
        }
    }
}

pub async fn run(args: &VulnArgs, project_root: &Path) -> Result<()> {
    let query_timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let metadata = scan_metadata(&query_timestamp);

    match scan(project_root, &args.module).await {
        Ok(scan) => render_report(args, scan, metadata),
        Err(err) => {
            let details = err.user_message();
            if is_json_mode() {
                json_result(
                    false,
                    serde_json::json!({
                        "metadata": metadata,
                        "exit_code": 2,
                        "error": details,
                    }),
                );
                Err(CliError::AlreadyReported { exit_code: 2 })
            } else {
                Err(CliError::VulnerabilityScan { details })
            }
        }
    }
}

struct ScanData {
    report: ScanReport,
    platform: String,
    reachability: BTreeMap<String, Vec<String>>,
}

async fn scan(project_root: &Path, selector: &ModuleSelector) -> Result<ScanData> {
    let project_root = project_root.to_path_buf();
    let selector = selector.clone();
    let (adapted, platform, reachability) = tokio::task::spawn_blocking(move || {
        let config = rv_config::Config::load(&project_root)?;
        let lock = crate::commands::read_fresh_lockfile(&config)?;
        let platform = crate::commands::select_platform(&lock)?;
        let platform_name = platform.platform.to_string();
        let selection = selector.select(platform)?;
        let adapted =
            crate::commands::lock_adapter::adapt_vulnerability_modules(selection.modules())
                .map_err(|err| CliError::Message(format!("failed to map rv.lock: {err}")))?;
        Ok::<_, CliError>((adapted.dependencies, platform_name, adapted.reachability))
    })
    .await
    .map_err(|err| CliError::Message(format!("vulnerability scan task panicked: {err}")))??;

    let scanner = match std::env::var(OSV_BASE_URL_ENV) {
        Ok(base_url) => VulnScanner::from_client(OsvClient::with_base_url(base_url)?),
        Err(std::env::VarError::NotPresent) => VulnScanner::without_cache()?,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::Message(format!(
                "{OSV_BASE_URL_ENV} contains non-Unicode data"
            )));
        }
    };
    let report = scanner.scan(&adapted).await?;
    Ok(ScanData {
        report,
        platform,
        reachability,
    })
}

fn render_report(args: &VulnArgs, scan: ScanData, metadata: serde_json::Value) -> Result<()> {
    let report = &scan.report;
    let total_vulnerabilities: usize = report
        .vulnerabilities
        .iter()
        .map(|result| result.vulnerabilities.len())
        .sum();
    let matching_findings = report
        .vulnerabilities
        .iter()
        .flat_map(|result| &result.vulnerabilities)
        .filter(|vulnerability| args.fail_on.matches(vulnerability))
        .count();

    if args.format == VulnOutputFormat::Sarif {
        println!(
            "{}",
            serde_json::to_string_pretty(&sarif_report(report, &scan.reachability))?
        );
    } else if is_json_mode() {
        render_json_report(
            report,
            &scan.platform,
            &scan.reachability,
            metadata,
            args.fail_on,
            matching_findings,
            total_vulnerabilities,
        );
    } else {
        render_table(report, &scan.reachability, matching_findings, args.fail_on)
    }

    if matching_findings > 0 {
        Err(CliError::AlreadyReported { exit_code: 1 })
    } else {
        Ok(())
    }
}

fn render_json_report(
    report: &ScanReport,
    platform: &str,
    reachability: &BTreeMap<String, Vec<String>>,
    metadata: serde_json::Value,
    threshold: SeverityThreshold,
    matching_findings: usize,
    total_vulnerabilities: usize,
) {
    let results = report
        .vulnerabilities
        .iter()
        .map(|result| {
            serde_json::json!({
                "purl": result.purl,
                "affected_modules": reachability.get(&result.purl).cloned().unwrap_or_default(),
                "vulnerabilities": result.vulnerabilities,
            })
        })
        .collect::<Vec<_>>();
    json_result(
        true,
        serde_json::json!({
            "metadata": metadata,
            "platform": platform,
            "threshold": threshold.as_str(),
            "threshold_exceeded": matching_findings > 0,
            "summary": {
                "total_dependencies": report.total_dependencies,
                "vulnerable_dependencies": report.vulnerable_dependencies,
                "total_vulnerabilities": total_vulnerabilities,
                "findings_at_or_above_threshold": matching_findings,
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "unknown": report.unknown_count,
            },
            "results": results,
        }),
    );
}

fn sarif_report(
    report: &ScanReport,
    reachability: &BTreeMap<String, Vec<String>>,
) -> serde_json::Value {
    let mut vulnerabilities = BTreeMap::<&str, &Vulnerability>::new();
    for result in &report.vulnerabilities {
        for vulnerability in &result.vulnerabilities {
            vulnerabilities
                .entry(vulnerability.id.as_str())
                .or_insert(vulnerability);
        }
    }

    let rules = vulnerabilities
        .values()
        .map(|vulnerability| {
            let mut rule = serde_json::json!({
                "id": vulnerability.id,
                "shortDescription": {
                    "text": vulnerability.summary,
                },
                "helpUri": advisory_url(vulnerability),
            });
            if let Some(score) = vulnerability
                .severity
                .as_ref()
                .and_then(|severity| severity.score_value())
            {
                rule["properties"] = serde_json::json!({
                    "security-severity": format!("{score:.1}"),
                });
            }
            rule
        })
        .collect::<Vec<_>>();
    let rule_indices = vulnerabilities
        .keys()
        .enumerate()
        .map(|(index, id)| (*id, index))
        .collect::<BTreeMap<_, _>>();

    let mut findings = report
        .vulnerabilities
        .iter()
        .flat_map(|result| {
            result
                .vulnerabilities
                .iter()
                .map(move |vulnerability| (vulnerability, result.purl.as_str()))
        })
        .collect::<Vec<_>>();
    findings.sort_by(
        |(left_vulnerability, left_purl), (right_vulnerability, right_purl)| {
            left_vulnerability
                .id
                .cmp(&right_vulnerability.id)
                .then_with(|| left_purl.cmp(right_purl))
        },
    );
    findings.dedup_by(
        |(left_vulnerability, left_purl), (right_vulnerability, right_purl)| {
            left_vulnerability.id == right_vulnerability.id && left_purl == right_purl
        },
    );

    let results = findings
        .into_iter()
        .map(|(vulnerability, purl)| {
            let modules = reachability.get(purl).cloned().unwrap_or_default();
            let locations = modules
                .iter()
                .map(|module| {
                    serde_json::json!({
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": module,
                            },
                        },
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "ruleId": vulnerability.id,
                "ruleIndex": rule_indices[vulnerability.id.as_str()],
                "level": sarif_level(vulnerability),
                "message": {
                    "text": format!(
                        "{} affects {purl} (reachable from {})",
                        vulnerability.id,
                        modules.join(", ")
                    ),
                },
                "locations": locations,
                "properties": {
                    "dependencyPurl": purl,
                    "affectedModules": modules,
                },
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rv",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                },
            },
            "results": results,
        }],
    })
}

fn advisory_url(vulnerability: &Vulnerability) -> String {
    vulnerability
        .references
        .iter()
        .find(|reference| reference.type_.eq_ignore_ascii_case("ADVISORY"))
        .map(|reference| reference.url.clone())
        .unwrap_or_else(|| format!("https://osv.dev/vulnerability/{}", vulnerability.id))
}

fn sarif_level(vulnerability: &Vulnerability) -> &'static str {
    match vulnerability.severity_band() {
        SeverityBand::Critical | SeverityBand::High => "error",
        SeverityBand::Medium | SeverityBand::Unknown => "warning",
        SeverityBand::Low => "note",
    }
}

fn render_table(
    report: &ScanReport,
    reachability: &BTreeMap<String, Vec<String>>,
    matching_findings: usize,
    threshold: SeverityThreshold,
) {
    if report.vulnerabilities.is_empty() {
        println!(
            "No vulnerabilities found in {} dependencies.",
            report.total_dependencies
        );
        return;
    }

    let mut table = Table::new([
        "Dependency",
        "Vulnerability",
        "Severity",
        "Score",
        "Affected modules",
        "Summary",
    ]);
    for result in &report.vulnerabilities {
        for vulnerability in &result.vulnerabilities {
            let (severity, score) = vulnerability
                .severity
                .as_ref()
                .map(|severity| {
                    (
                        severity.severity_label().to_string(),
                        severity
                            .score_value()
                            .map(|score| format!("{score:.1}"))
                            .unwrap_or_else(|| "-".to_string()),
                    )
                })
                .unwrap_or_else(|| ("Unknown".to_string(), "-".to_string()));
            table.add_row([
                result.purl.clone(),
                vulnerability.id.clone(),
                severity,
                score,
                reachability
                    .get(&result.purl)
                    .map(|modules| modules.join(", "))
                    .unwrap_or_default(),
                vulnerability.summary.clone(),
            ]);
        }
    }
    println!("{}", table.render());
    println!(
        "{matching_findings} finding(s) at or above the {} threshold.",
        threshold.as_str()
    );
}

fn scan_metadata(query_timestamp: &str) -> serde_json::Value {
    serde_json::json!({
        "tool": {
            "name": "rv",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "scanner": {
            "provider": "osv.dev",
            "database_snapshot": null,
        },
        "query_timestamp": query_timestamp,
    })
}

#[cfg(test)]
mod tests {
    use rv_vuln::{Reference, Severity, Vulnerability};

    use super::{SeverityThreshold, advisory_url, sarif_level};

    fn vulnerability(score: Option<&str>) -> Vulnerability {
        Vulnerability {
            id: "OSV-TEST".to_string(),
            aliases: Vec::new(),
            summary: "test".to_string(),
            details: None,
            severity: score.map(|score| Severity {
                type_: "CVSS_V3".to_string(),
                score: score.to_string(),
            }),
            references: Vec::new(),
            affected: Vec::new(),
        }
    }

    #[test]
    fn severity_thresholds_treat_unknown_as_meeting_every_threshold() {
        let unknown = vulnerability(None);
        assert!(SeverityThreshold::Any.matches(&unknown));
        assert!(SeverityThreshold::Low.matches(&unknown));
        assert!(SeverityThreshold::Medium.matches(&unknown));
        assert!(SeverityThreshold::High.matches(&unknown));
        assert!(SeverityThreshold::Critical.matches(&unknown));

        let high = vulnerability(Some("7.5"));
        assert!(SeverityThreshold::Low.matches(&high));
        assert!(SeverityThreshold::Medium.matches(&high));
        assert!(SeverityThreshold::High.matches(&high));
        assert!(!SeverityThreshold::Critical.matches(&high));
    }

    #[test]
    fn cvss_v2_has_no_critical_band() {
        let mut v2 = vulnerability(Some("10.0"));
        v2.severity.as_mut().unwrap().type_ = "CVSS_V2".to_string();
        assert!(SeverityThreshold::High.matches(&v2));
        assert!(!SeverityThreshold::Critical.matches(&v2));
        assert_eq!(sarif_level(&v2), "error");
    }

    #[test]
    fn sarif_levels_follow_security_severity() {
        assert_eq!(sarif_level(&vulnerability(Some("9.8"))), "error");
        assert_eq!(sarif_level(&vulnerability(Some("7.0"))), "error");
        assert_eq!(sarif_level(&vulnerability(Some("5.0"))), "warning");
        assert_eq!(sarif_level(&vulnerability(Some("2.0"))), "note");
        assert_eq!(sarif_level(&vulnerability(None)), "warning");
    }

    #[test]
    fn advisory_url_prefers_advisory_reference() {
        let mut vulnerability = vulnerability(Some("5.0"));
        vulnerability.references = vec![Reference {
            type_: "ADVISORY".to_string(),
            url: "https://example.com/advisory".to_string(),
        }];
        assert_eq!(advisory_url(&vulnerability), "https://example.com/advisory");
    }
}
