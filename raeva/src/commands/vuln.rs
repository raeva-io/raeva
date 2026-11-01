use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;

use chrono::{SecondsFormat, Utc};
use clap::{Args, Subcommand, ValueEnum};
use rv_vuln::{OsvClient, ScanReport, SeverityBand, VulnScanner, Vulnerability};

use crate::commands::module_selector::ModuleSelector;
use crate::commands::report_selector::{ReportSelector, ReportTarget};
use crate::commands::util::{modules_phrase, plural};
use crate::commands::vex::{
    Assessment, Justification, NewStatement, VexSet, same_module, versionless_purl,
};
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Output, Report, Table};
use crate::session::Session;

const OSV_BASE_URL_ENV: &str = "RAEVA_OSV_BASE_URL";

#[derive(Debug, Args)]
#[command(
    args_conflicts_with_subcommands = true,
    after_long_help = format!(
        "\
Formats:
  table    Human-readable findings (default); raeva --json prints them as JSON
  sarif    SARIF 2.1.0 for code scanning systems

Exit codes:
  0  Scan completed with no findings at or above the threshold
  1  Scan completed with findings at or above the threshold
  2  Scan did not complete, for a cause with no more specific code
  3  Invalid configuration, a missing or invalid raeva.lock, --baseline, or --vex file,
     or an untrusted OSV certificate
  4  The OSV API could not be reached, or answered 429, 502, 503 or 504
  7  raeva.lock is out of date for the project or its configuration

A scan that could not fetch every record OSV named is incomplete: it
prints the findings it has and exits with the code of the fetch errors,
never 0 or 1.

Unknown severity (no CVSS score) meets every --fail-on threshold. A CVSS
score of 0.0 is None, which only any meets. --fail-on never reports the
findings and exits 0, but an incomplete scan or invalid configuration still
fails. Dependencies a module reaches only on its test classpath are not
scanned unless --include-test is given. A finding that a --vex file marks not_affected is shown as
suppressed and does not count toward --fail-on. The Fixed column is the
nearest version above the locked one that the advisory names as fixed.

With --baseline, only new findings count toward --fail-on. A finding is
existing when the same exact dependency purl and OSV id occur anywhere in
the baseline, in any of its targets and modules. Only the current inventory
is queried. Every current finding is shown as New or Existing. A record
fetch failure fails the scan. The baseline does not need to match the
current project POMs or targets.

By default, scan every recorded platform and JDK, deduplicated by exact
purl. --platform and --jdk restrict the scan to recorded targets;
--jdk matches the exact target version. Missing targets fail without a
host fallback. --include-test includes test-only dependencies in both
inventories. VEX applies to every selected module identity.

{}",
        crate::commands::util::help_examples(&[
            ("vuln", ""),
            ("vuln --module app/pom.xml", ""),
            ("vuln --module com.acme:app", ""),
            ("--json vuln", ""),
            ("vuln --format sarif", ""),
            ("vuln --fail-on critical", ""),
            ("vuln --fail-on never", ""),
            ("vuln --vex vex.json", ""),
            ("vuln --baseline base.lock", ""),
            ("vuln --platform linux-x86_64 --jdk 21", ""),
            ("vuln --include-test", ""),
            (
                "vuln triage GHSA-xxxx-xxxx-xxxx --justification vulnerable_code_not_in_execute_path --vex vex.json --author \"Acme Security\"",
                "",
            ),
        ])
    )
)]
pub(crate) struct VulnArgs {
    #[command(subcommand)]
    command: Option<VulnCommand>,
    #[command(flatten)]
    module: ModuleSelector,
    #[command(flatten)]
    targets: ReportSelector,
    #[arg(long, help = "Include dependencies reached only on the test classpath")]
    include_test: bool,
    #[arg(
        long,
        value_enum,
        default_value = "table",
        help = "Output format: table or sarif"
    )]
    format: VulnOutputFormat,
    #[arg(
        long,
        value_enum,
        default_value = "high",
        value_name = "SEVERITY",
        help = "Exit 1 for a finding at this severity or above; unknown always counts, and never only reports"
    )]
    fail_on: SeverityThreshold,
    #[arg(
        long,
        value_name = "FILE",
        help = "Suppress the findings an OpenVEX file marks not_affected (repeatable)"
    )]
    vex: Vec<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Count only findings new against this lockfile toward --fail-on"
    )]
    baseline: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum VulnCommand {
    /// Record in an OpenVEX file that a finding does not affect a module
    Triage(TriageArgs),
}

#[derive(Debug, Args)]
#[command(after_long_help = "\
The finding must be unique among the scanned modules and dependencies.
When the advisory affects several, --module and --component pick one.
An identical statement already in the file leaves it unchanged; a
different one for the same finding fails and changes nothing.

The statement names the module without its version, so it still applies
after a release; the dependency version is exact, so upgrading or
downgrading the dependency ends it. --product-version names this module
version only.")]
struct TriageArgs {
    #[arg(value_name = "ID", help = "The advisory id or one of its aliases")]
    id: String,
    #[arg(long, value_enum, help = "Why the finding does not affect the module")]
    justification: Justification,
    #[command(flatten)]
    module: ModuleSelector,
    #[command(flatten)]
    targets: ReportSelector,
    #[arg(long, help = "Include dependencies reached only on the test classpath")]
    include_test: bool,
    #[arg(
        long,
        value_name = "COMPONENT",
        help = "The dependency, as its purl or as the table shows it"
    )]
    component: Option<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "The OpenVEX file to add the statement to"
    )]
    vex: PathBuf,
    #[arg(long, value_name = "TEXT", help = "Explain the justification")]
    impact_statement: Option<String>,
    #[arg(
        long,
        value_name = "NAME",
        help = "The document author, needed when the file does not exist"
    )]
    author: Option<String>,
    #[arg(
        long,
        help = "Record the statement for this module version only, not for every version"
    )]
    product_version: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VulnOutputFormat {
    Table,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, strum::IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
enum SeverityThreshold {
    Any,
    Low,
    Medium,
    High,
    Critical,
    Never,
}

impl SeverityThreshold {
    fn as_str(self) -> &'static str {
        self.into()
    }

    fn matches(self, vulnerability: &Vulnerability) -> bool {
        let band = vulnerability.severity_band();
        let lowest = match self {
            Self::Never => return false,
            Self::Any => SeverityBand::None,
            Self::Low => SeverityBand::Low,
            Self::Medium => SeverityBand::Medium,
            Self::High => SeverityBand::High,
            Self::Critical => SeverityBand::Critical,
        };
        band == SeverityBand::Unknown || severity_display(band).0 >= severity_display(lowest).0
    }
}

pub(crate) async fn run(args: &VulnArgs, session: &Session) -> Result<Report> {
    if let Some(VulnCommand::Triage(triage_args)) = &args.command {
        return triage(triage_args, session).await;
    }
    session.require_network("vuln", "queries the OSV vulnerability database")?;
    let vex = VexSet::load(&args.vex)?;
    let query_timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let metadata = scan_metadata(&query_timestamp);

    match scan(
        session,
        &args.module,
        &args.targets,
        args.include_test,
        args.baseline.as_ref(),
    )
    .await
    {
        Ok(scan) => scan_report(args, scan, &vex, metadata, session.output()),
        Err(cause) => Ok(Report::data(ScanFailed { metadata })
            .failed(CliError::VulnerabilityScan(Box::new(cause)))),
    }
}

struct ScanFailed {
    metadata: serde_json::Value,
}

impl CommandOutput for ScanFailed {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({ "metadata": self.metadata }))
    }

    fn render_human(&self, _human: &mut Human<'_>) -> io::Result<()> {
        Ok(())
    }
}

struct Baseline {
    path: PathBuf,
    purls: BTreeSet<String>,
}

struct ScanData {
    baseline: Option<Baseline>,
    report: ScanReport,
    targets: Vec<ReportTarget>,
    reachability: BTreeMap<String, Vec<String>>,
    module_purls: BTreeSet<String>,
    products: BTreeMap<String, Vec<(String, String)>>,
    test_only: usize,
}

async fn scan(
    session: &Session,
    selector: &ModuleSelector,
    target_selector: &ReportSelector,
    include_test: bool,
    baseline_path: Option<&PathBuf>,
) -> Result<ScanData> {
    let selector = selector.clone();
    let target_selector = target_selector.clone();
    let baseline_path = baseline_path.cloned();
    let (adapted, baseline, targets, osv) = session
        .blocking("vulnerability scan", move |session| {
            let baseline_lock = baseline_path
                .as_ref()
                .map(|path| {
                    rv_lock::Lockfile::read(path).map_err(|err| CliError::InvalidProjectInput {
                        path: path.clone(),
                        reason: format!("cannot read --baseline lockfile: {err}"),
                    })
                })
                .transpose()?;
            let config = session.config()?;
            let lock = session.fresh_lockfile(&config)?.0;
            let selected = target_selector.select(&lock)?;
            let targets = selected.targets();
            let modules = selected
                .platforms
                .iter()
                .map(|platform| selector.select(platform))
                .collect::<Result<Vec<_>>>()?;
            let modules = modules
                .iter()
                .flat_map(|selection| selection.modules().iter().copied())
                .collect::<Vec<_>>();
            let adapted =
                crate::commands::lock_adapter::adapt_vulnerability_modules(&modules, include_test)
                    .map_err(|err| CliError::LockfileDefect {
                        details: err.to_string(),
                    })?;
            let baseline = baseline_path
                .as_ref()
                .zip(baseline_lock.as_ref())
                .map(|(path, lock)| {
                    // Every target of the baseline, whatever the selectors, so
                    // a change that adds a platform or JDK still compares.
                    let modules = (lock.platforms.iter())
                        .flat_map(|p| p.modules.iter())
                        .collect::<Vec<_>>();
                    let base = crate::commands::lock_adapter::adapt_vulnerability_modules(
                        &modules,
                        include_test,
                    )
                    .map_err(|err| CliError::InvalidProjectInput {
                        path: path.clone(),
                        reason: format!("cannot use --baseline lockfile: {err}"),
                    })?;
                    Ok::<_, CliError>(Baseline {
                        path: path.clone(),
                        purls: base.reachability.into_keys().collect(),
                    })
                })
                .transpose()?;
            let osv = rv_vuln::OsvSettings {
                proxies: rv_repo::configured_proxies(&config)?,
                timeout: std::time::Duration::from_secs(config.network.timeout),
                retries: config.network.retries,
                on_retry: Some({
                    let output = session.output().clone();
                    std::sync::Arc::new(move |line: String| output.note(&line))
                }),
            };
            Ok((adapted, baseline, targets, osv))
        })
        .await?;

    let base_url = match std::env::var(OSV_BASE_URL_ENV) {
        Ok(base_url) => base_url,
        Err(std::env::VarError::NotPresent) => OsvClient::DEFAULT_BASE_URL.to_string(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::Usage(format!(
                "{OSV_BASE_URL_ENV} contains non-Unicode data"
            )));
        }
    };
    // Checked here so a malformed value is a usage error, not a failed
    // request. The value is not printed: it may carry credentials.
    if !url::Url::parse(&base_url).is_ok_and(|url| matches!(url.scheme(), "http" | "https")) {
        return Err(CliError::Usage(format!(
            "{OSV_BASE_URL_ENV} is not an http or https URL"
        )));
    }
    let scanner = VulnScanner::from_client(OsvClient::with_settings(base_url, osv)?);
    // A baseline counts only by its purls, so only the current inventory
    // is queried.
    let report = scanner.scan(&adapted.dependencies).await?;
    Ok(ScanData {
        baseline,
        report,
        targets,
        reachability: adapted.reachability,
        module_purls: adapted.module_purls,
        products: adapted.products,
        test_only: adapted.test_only,
    })
}

/// One advisory on one dependency, and what the `--vex` files say about it
/// in each module that reaches the dependency.
struct Finding {
    result: usize,
    vulnerability: usize,
    new: Option<bool>,
    /// The modules no statement suppresses it in. Empty when it is
    /// suppressed.
    active: Vec<String>,
    /// The statement that matched, by module.
    vex: Vec<(String, Assessment)>,
}

impl Finding {
    fn suppressed(&self) -> bool {
        self.active.is_empty()
    }
}

fn names(vulnerability: &Vulnerability) -> Vec<&str> {
    std::iter::once(vulnerability.id.as_str())
        .chain(vulnerability.aliases.iter().map(String::as_str))
        .collect()
}

/// Every finding of the scan, with each module's statement applied before
/// the modules are combined.
fn assess(scan: &ScanData, vex: &VexSet) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for (result_index, result) in scan.report.vulnerabilities.iter().enumerate() {
        let modules = scan
            .products
            .get(&result.purl)
            .map_or(&[][..], Vec::as_slice);
        for (index, vulnerability) in result.vulnerabilities.iter().enumerate() {
            let ids = names(vulnerability);
            let mut finding = Finding {
                result: result_index,
                vulnerability: index,
                // Shared purls use the same OSV records, so each advisory on
                // one also occurs in the baseline, regardless of module path.
                new: scan
                    .baseline
                    .as_ref()
                    .map(|base| !base.purls.contains(&result.purl)),
                active: Vec::new(),
                vex: Vec::new(),
            };
            for (module, product) in modules {
                let assessment = if vex.is_empty() {
                    None
                } else {
                    vex.assess(product, &result.purl, &ids)?
                };
                if !assessment.is_some_and(Assessment::suppresses) {
                    finding.active.push(module.clone());
                }
                if let Some(assessment) = assessment {
                    finding.vex.push((module.clone(), assessment.clone()));
                }
            }
            finding.active.sort();
            finding.active.dedup();
            let mut distinct = Vec::new();
            for statement in finding.vex {
                if !distinct.contains(&statement) {
                    distinct.push(statement);
                }
            }
            finding.vex = distinct;
            findings.push(finding);
        }
    }
    Ok(findings)
}

fn scan_report(
    args: &VulnArgs,
    scan: ScanData,
    vex: &VexSet,
    metadata: serde_json::Value,
    output: &Output,
) -> Result<Report> {
    let failed_fetches = scan.report.failed_fetches.clone();
    let findings = assess(&scan, vex)?;
    // A record the scan could not fetch may be the one a statement is for.
    if failed_fetches.is_empty() {
        vex.warn_unused(output, |product| {
            (scan.module_purls.iter()).any(|module| same_module(product, module))
        });
    }
    let matching_findings = findings
        .iter()
        .filter(|finding| !finding.suppressed() && finding.new != Some(false))
        .filter(|finding| args.fail_on.matches(vulnerability(&scan.report, finding)))
        .count();

    let report = match args.format {
        VulnOutputFormat::Sarif => Report::document(serde_json::to_string_pretty(&sarif_report(
            &scan, &findings,
        ))?),
        VulnOutputFormat::Table => Report::data(VulnReport {
            scan,
            findings,
            metadata,
            threshold: args.fail_on,
            matching_findings,
        }),
    };
    if !failed_fetches.is_empty() {
        Ok(report.failed(CliError::VulnerabilityScan(Box::new(
            CliError::VulnRecordsUnfetched {
                failures: failed_fetches,
            },
        ))))
    } else if matching_findings > 0 {
        Ok(report.failed(CliError::VulnerabilitiesFound {
            findings: matching_findings,
            threshold: args.fail_on.as_str(),
        }))
    } else {
        Ok(report)
    }
}

fn vulnerability<'a>(report: &'a ScanReport, finding: &Finding) -> &'a Vulnerability {
    &report.vulnerabilities[finding.result].vulnerabilities[finding.vulnerability]
}

fn vex_json(id: &str, module: &str, assessment: &Assessment) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "module": module,
        "status": assessment.status,
        "justification": assessment.justification,
        "impact_statement": assessment.impact_statement,
    })
}

struct VulnReport {
    scan: ScanData,
    findings: Vec<Finding>,
    metadata: serde_json::Value,
    threshold: SeverityThreshold,
    matching_findings: usize,
}

impl CommandOutput for VulnReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let report = &self.scan.report;
        let mut bands = BTreeMap::<SeverityBand, usize>::new();
        for finding in self.findings.iter().filter(|finding| !finding.suppressed()) {
            *bands
                .entry(vulnerability(report, finding).severity_band())
                .or_default() += 1;
        }
        let band = |band| bands.get(&band).copied().unwrap_or_default();
        let results = report
            .vulnerabilities
            .iter()
            .enumerate()
            .map(|(index, result)| {
                let findings = || self.findings.iter().filter(move |f| f.result == index);
                let suppressed = findings()
                    .filter(|finding| finding.suppressed())
                    .map(|finding| &result.vulnerabilities[finding.vulnerability].id)
                    .collect::<Vec<_>>();
                let vex = findings()
                    .flat_map(|finding| {
                        let id = &result.vulnerabilities[finding.vulnerability].id;
                        (finding.vex.iter())
                            .map(move |(module, assessment)| vex_json(id, module, assessment))
                    })
                    .collect::<Vec<_>>();
                let severities = findings()
                    .map(|finding| {
                        let vulnerability = &result.vulnerabilities[finding.vulnerability];
                        let mut json = serde_json::json!({
                            "id": vulnerability.id,
                            "severity": severity_display(vulnerability.severity_band()).1,
                            "fixed": fixed_version(vulnerability, &result.purl),
                        });
                        if let Some(new) = finding.new {
                            json["new"] = new.into();
                        }
                        json
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "purl": result.purl,
                    "findings": severities,
                    "affected_modules": self
                        .scan
                        .reachability
                        .get(&result.purl)
                        .cloned()
                        .unwrap_or_default(),
                    "vulnerabilities": result.vulnerabilities,
                    "suppressed": suppressed,
                    "vex": vex,
                })
            })
            .collect::<Vec<_>>();
        let failed_records = report
            .failed_fetches
            .iter()
            .map(|failed| {
                serde_json::json!({
                    "id": failed.id,
                    "purls": failed.purls,
                })
            })
            .collect::<Vec<_>>();
        let mut json = serde_json::json!({
            "metadata": self.metadata,
            "targets": self.scan.targets,
            "complete": report.is_complete(),
            "failed_records": failed_records,
            "threshold": self.threshold.as_str(),
            "threshold_exceeded": self.matching_findings > 0,
            "summary": {
                "total_dependencies": report.total_dependencies,
                "test_only_dependencies": self.scan.test_only,
                "vulnerable_dependencies": report.vulnerabilities.len(),
                "total_vulnerabilities": self.findings.len(),
                "suppressed": self.findings.iter().filter(|f| f.suppressed()).count(),
                "findings_at_or_above_threshold": self.matching_findings,
                "critical": band(SeverityBand::Critical),
                "high": band(SeverityBand::High),
                "medium": band(SeverityBand::Medium),
                "low": band(SeverityBand::Low),
                "none": band(SeverityBand::None),
                "unknown": band(SeverityBand::Unknown),
            },
            "results": results,
        });
        if let Some(baseline) = &self.scan.baseline {
            json["baseline"] = baseline.path.display().to_string().into();
        }
        if let [target] = self.scan.targets.as_slice() {
            json["platform"] = target.platform.clone().into();
            if let Some(jdk) = &target.jdk {
                json["jdk"] = jdk.clone().into();
            }
        }
        Ok(json)
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        human.note(format!(
            "Scanned raeva.lock for {}",
            self.scan
                .targets
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
        if let Some(baseline) = &self.scan.baseline {
            human.note(format!(
                "Compared with baseline {}; only new findings count toward --fail-on.",
                baseline.path.display()
            ))?;
        }
        render_table(
            human,
            &self.scan,
            &self.findings,
            self.matching_findings,
            self.threshold,
        )
    }
}

fn sarif_report(scan: &ScanData, findings: &[Finding]) -> serde_json::Value {
    let report = &scan.report;
    let mut vulnerabilities = BTreeMap::<&str, &Vulnerability>::new();
    let mut ordered = Vec::with_capacity(findings.len());
    for finding in findings {
        let vulnerability = vulnerability(report, finding);
        vulnerabilities
            .entry(vulnerability.id.as_str())
            .or_insert(vulnerability);
        let purl = report.vulnerabilities[finding.result].purl.as_str();
        ordered.push(((vulnerability.id.as_str(), purl), finding, vulnerability));
    }
    ordered.sort_by_key(|(key, _, _)| *key);

    let rules = vulnerabilities
        .values()
        .map(|vulnerability| {
            let mut rule = serde_json::json!({
                "id": vulnerability.id,
                "shortDescription": {
                    "text": vulnerability.summary,
                },
                "helpUri": vulnerability
                    .references
                    .iter()
                    .find(|reference| reference.type_.eq_ignore_ascii_case("ADVISORY"))
                    .map(|reference| reference.url.clone())
                    .unwrap_or_else(|| {
                        format!("https://osv.dev/vulnerability/{}", vulnerability.id)
                    }),
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

    let results = ordered
        .into_iter()
        .map(|((_, purl), finding, vulnerability)| {
            let all = scan.reachability.get(purl).cloned().unwrap_or_default();
            // A suppressed finding keeps its locations; an active one lists
            // the modules it is active in.
            let modules = if finding.suppressed() {
                &all
            } else {
                &finding.active
            };
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
            let fixed = fixed_version(vulnerability, purl);
            let fixed_in = fixed
                .as_ref()
                .map_or_else(String::new, |fixed| format!("; fixed in {fixed}"));
            let severity = severity_display(vulnerability.severity_band()).1;
            let mut result = serde_json::json!({
                "ruleId": vulnerability.id,
                "ruleIndex": rule_indices[vulnerability.id.as_str()],
                "level": sarif_level(vulnerability),
                "message": {
                    "text": format!(
                        "{} ({severity}) affects {purl} (reachable from {}){fixed_in}",
                        vulnerability.id,
                        modules.join(", ")
                    ),
                },
                "locations": locations,
                "properties": {
                    "dependencyPurl": purl,
                    "affectedModules": all,
                    "severity": severity,
                },
            });
            if let Some(new) = finding.new {
                result["baselineState"] = if new { "new" } else { "unchanged" }.into();
            }
            if let Some(fixed) = fixed {
                result["properties"]["fixedVersion"] = fixed.into();
            }
            if !finding.vex.is_empty() {
                result["properties"]["vex"] = finding
                    .vex
                    .iter()
                    .map(|(module, assessment)| vex_json(&vulnerability.id, module, assessment))
                    .collect();
            }
            if finding.suppressed() {
                let justifications = finding
                    .vex
                    .iter()
                    .filter_map(|(_, assessment)| assessment.justification)
                    .map(Justification::as_str)
                    .collect::<BTreeSet<_>>();
                result["suppressions"] = serde_json::json!([{
                    "kind": "external",
                    "status": "accepted",
                    "justification": format!(
                        "OpenVEX not_affected: {}",
                        justifications.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                }]);
            }
            result
        })
        .collect::<Vec<_>>();

    let mut run = serde_json::json!({
        "tool": {
            "driver": {
                "name": "raeva",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            },
        },
        "results": results,
        "properties": { "targets": scan.targets },
    });
    if !report.is_complete() {
        let notifications = report
            .failed_fetches
            .iter()
            .map(|failed| {
                serde_json::json!({
                    "level": "error",
                    "message": {
                        "text": format!(
                            "OSV record {} for {} could not be fetched",
                            failed.id,
                            failed.purls.join(", ")
                        ),
                    },
                })
            })
            .collect::<Vec<_>>();
        run["invocations"] = serde_json::json!([{
            "executionSuccessful": false,
            "toolExecutionNotifications": notifications,
        }]);
    }

    serde_json::json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    })
}

fn sarif_level(vulnerability: &Vulnerability) -> &'static str {
    match vulnerability.severity_band() {
        SeverityBand::Critical | SeverityBand::High => "error",
        SeverityBand::Medium | SeverityBand::Unknown => "warning",
        SeverityBand::Low | SeverityBand::None => "note",
    }
}

/// The findings table on stdout, then the findings `--vex` suppresses. When
/// findings meet the threshold, the error the command ends with counts
/// them; when the scan is incomplete, the error names the records it lacks,
/// and nothing here reads as clean.
fn render_table(
    human: &mut Human<'_>,
    scan: &ScanData,
    findings: &[Finding],
    matching_findings: usize,
    threshold: SeverityThreshold,
) -> io::Result<()> {
    let report = &scan.report;
    if findings.is_empty() {
        if report.is_complete() {
            human.line(format!(
                "No vulnerabilities found in {}.",
                plural(report.total_dependencies, "dependency", "dependencies")
            ))?;
        }
        return render_test_only(human, scan.test_only);
    }

    let modules: BTreeSet<&String> = scan.reachability.values().flatten().collect();
    let show_modules = modules.len() > 1;
    let in_modules = |modules: &[String], text: String| {
        if show_modules {
            let modules = modules.iter().cloned().collect();
            format!("In {}: {text}", modules_phrase(&modules))
        } else {
            text
        }
    };

    let mut rows = Vec::new();
    for finding in findings.iter().filter(|finding| !finding.suppressed()) {
        let vulnerability = vulnerability(report, finding);
        let score = vulnerability
            .severity
            .as_ref()
            .and_then(|severity| severity.score_value());
        rows.push((vulnerability.severity_band(), score, finding, vulnerability));
    }
    // Most severe first; the order of the scan breaks ties.
    rows.sort_by(|left, right| {
        severity_display(right.0)
            .0
            .cmp(&severity_display(left.0).0)
            .then(
                right
                    .1
                    .partial_cmp(&left.1)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    if !rows.is_empty() {
        // The dependency, which can be wider than its column, goes last of
        // the short columns so an overflow does not push the others out of
        // line.
        let mut columns = vec![
            "Severity",
            "Score",
            "Advisory",
            "Fixed",
            "Dependency",
            "Summary",
        ];
        if scan.baseline.is_some() {
            columns.insert(4, "Baseline");
        }
        let mut table = Table::new(columns);
        let first = &report.vulnerabilities[rows[0].2.result].purl;
        let why = purl_parts(first).map(|parts| format!("{}:{}", parts.group, parts.artifact));
        for (band, score, finding, vulnerability) in rows {
            let purl = &report.vulnerabilities[finding.result].purl;
            let mut summary = vulnerability.summary.clone();
            let statuses = (finding.vex.iter())
                .filter(|(_, assessment)| !assessment.suppresses())
                .map(|(_, assessment)| assessment.status.as_str())
                .collect::<BTreeSet<_>>();
            if !statuses.is_empty() {
                let statuses = statuses.into_iter().collect::<Vec<_>>().join(", ");
                summary = format!("(VEX {statuses}) {summary}");
            }
            let mut row = vec![
                severity_display(band).1.to_string(),
                score.map_or_else(|| "-".to_string(), |score| format!("{score:.1}")),
                vulnerability.id.clone(),
                fixed_version(vulnerability, purl).unwrap_or_else(|| "-".to_string()),
                purl_coordinate(purl),
                in_modules(&finding.active, summary),
            ];
            if let Some(new) = finding.new {
                row.insert(4, baseline_label(new).to_string());
            }
            table.add_row(row);
        }
        human.painted_table(&table, paint_severity)?;
        if let Some(why) = why {
            human.note(format!(
                "Fixed is the nearest fixed version. 'raeva why {why}' shows what brings a \
                 dependency in."
            ))?;
        }
    }

    let mut columns = vec!["Advisory", "Dependency", "Justification"];
    if scan.baseline.is_some() {
        columns.insert(1, "Baseline");
    }
    let mut suppressed = Table::new(columns);
    let (mut count, mut partial) = (0, 0);
    for finding in findings {
        let mut justifications = BTreeMap::<&str, Vec<String>>::new();
        for (module, assessment) in &finding.vex {
            if let Some(justification) = assessment.justification {
                justifications
                    .entry(justification.as_str())
                    .or_default()
                    .push(module.clone());
            }
        }
        if justifications.is_empty() {
            continue;
        }
        if finding.suppressed() {
            count += 1;
        } else {
            partial += 1;
        }
        let vulnerability = vulnerability(report, finding);
        for (justification, modules) in justifications {
            let mut row = vec![
                vulnerability.id.clone(),
                purl_coordinate(&report.vulnerabilities[finding.result].purl),
                in_modules(&modules, justification.to_string()),
            ];
            if let Some(new) = finding.new {
                row.insert(1, baseline_label(new).to_string());
            }
            suppressed.add_row(row);
        }
    }
    if count + partial > 0 {
        let mut heading = Vec::new();
        if count > 0 {
            heading.push(plural(count, "finding", "findings"));
        }
        if partial > 0 {
            let partial = plural(partial, "finding", "findings");
            heading.push(format!("{partial} in some modules only"));
        }
        human.blank_line()?;
        human.line(format!("Suppressed by VEX: {}", heading.join("; ")))?;
        human.table(&suppressed)?;
    }
    if threshold == SeverityThreshold::Never {
        if report.is_complete() && findings.iter().any(|finding| !finding.suppressed()) {
            human.line("--fail-on never reports these findings and passes.")?;
        }
    } else if matching_findings == 0 && report.is_complete() {
        let threshold = threshold.as_str();
        let unsuppressed = if count > 0 { "unsuppressed " } else { "" };
        let new = if scan.baseline.is_some() { "new " } else { "" };
        human.line(format!(
            "No {new}{unsuppressed}finding is at {threshold} severity or above, so --fail-on \
             {threshold} passes."
        ))?;
    }
    render_test_only(human, scan.test_only)
}

fn baseline_label(new: bool) -> &'static str {
    if new { "New" } else { "Existing" }
}

fn render_test_only(human: &mut Human<'_>, test_only: usize) -> io::Result<()> {
    if test_only == 0 {
        return Ok(());
    }
    human.line(format!(
        "Not scanned: {} only on the test classpath.",
        plural(test_only, "dependency", "dependencies")
    ))
}

/// Rank, table label, and colour for each severity band. Rank sorts the
/// findings table (higher first); Unknown sits between High and Medium so
/// unscored findings stay visible.
fn severity_display(band: SeverityBand) -> (u8, &'static str) {
    match band {
        SeverityBand::Critical => (5, "Critical"),
        SeverityBand::High => (4, "High"),
        SeverityBand::Unknown => (3, "Unknown (no CVSS score)"),
        SeverityBand::Medium => (2, "Medium"),
        SeverityBand::Low => (1, "Low"),
        SeverityBand::None => (0, "None"),
    }
}

/// Colour the severity a table line starts with.
fn paint_severity(line: &str) -> String {
    use owo_colors::OwoColorize;
    let Some(rest) = line.strip_prefix(' ') else {
        return line.to_string();
    };
    for band in [
        SeverityBand::Critical,
        SeverityBand::High,
        SeverityBand::Medium,
        SeverityBand::Low,
        SeverityBand::None,
        SeverityBand::Unknown,
    ] {
        let label = severity_display(band).1;
        if let Some(tail) = rest.strip_prefix(label) {
            let painted = match band {
                SeverityBand::Critical => label.red().bold().to_string(),
                SeverityBand::High => label.red().to_string(),
                SeverityBand::Medium => label.yellow().to_string(),
                SeverityBand::Low => label.blue().to_string(),
                SeverityBand::None => label.dimmed().to_string(),
                SeverityBand::Unknown => label.dimmed().to_string(),
            };
            return format!(" {painted}{tail}");
        }
    }
    line.to_string()
}

/// The coordinates of a Maven purl as raeva writes it.
struct PurlParts<'a> {
    group: &'a str,
    artifact: &'a str,
    version: &'a str,
    kind: Option<&'a str>,
    classifier: Option<&'a str>,
}

fn purl_parts(purl: &str) -> Option<PurlParts<'_>> {
    let rest = purl.strip_prefix("pkg:maven/")?;
    let (name, qualifiers) = rest.split_once('?').unwrap_or((rest, ""));
    let (path, version) = name.split_once('@')?;
    let (group, artifact) = path.split_once('/')?;
    let mut parts = PurlParts {
        group,
        artifact,
        version,
        kind: None,
        classifier: None,
    };
    for pair in qualifiers.split('&') {
        match pair.split_once('=') {
            Some(("type", value)) => parts.kind = Some(value),
            Some(("classifier", value)) => parts.classifier = Some(value),
            _ => {}
        }
    }
    Some(parts)
}

/// `group:artifact:version` for a Maven purl, with the type and classifier
/// its qualifiers name, or the purl as it is.
fn purl_coordinate(purl: &str) -> String {
    let Some(parts) = purl_parts(purl) else {
        return purl.to_string();
    };
    let mut coordinate = format!("{}:{}:{}", parts.group, parts.artifact, parts.version);
    if parts.kind.is_some() || parts.classifier.is_some() {
        coordinate.push(':');
        coordinate.push_str(parts.kind.unwrap_or("jar"));
        if let Some(classifier) = parts.classifier {
            coordinate.push(':');
            coordinate.push_str(classifier);
        }
    }
    coordinate
}

/// The nearest version of the dependency `purl` that `vulnerability` names
/// as fixed.
fn fixed_version(vulnerability: &Vulnerability, purl: &str) -> Option<String> {
    let (name, version) = rv_maven_types::maven_purl_name_version(purl)?;
    vulnerability.fixed_version(&name, &version)
}

/// `raeva vuln triage`: scan, find the one finding the arguments name, and
/// record it as not_affected.
async fn triage(args: &TriageArgs, session: &Session) -> Result<Report> {
    session.require_network("vuln", "queries the OSV vulnerability database")?;
    if !args.vex.try_exists().map_err(CliError::io_at(&args.vex))? {
        crate::commands::vex::new_file_author(&args.vex, args.author.as_deref())?;
    }
    let id = args.id.trim();
    let scan = (scan(
        session,
        &args.module,
        &args.targets,
        args.include_test,
        None,
    )
    .await)
        .map_err(|cause| CliError::VulnerabilityScan(Box::new(cause)))?;
    if !scan.report.is_complete() {
        return Err(CliError::VulnerabilityScan(Box::new(
            CliError::VulnRecordsUnfetched {
                failures: scan.report.failed_fetches.clone(),
            },
        )));
    }
    let component = args.component.as_deref().map(str::trim);
    // Each (module, dependency) the advisory affects, with every name the
    // matching records give it.
    let mut targets = BTreeMap::<(String, String, String), BTreeSet<&str>>::new();
    for result in &scan.report.vulnerabilities {
        let purl = result.purl.as_str();
        if component
            .is_some_and(|component| component != purl && component != purl_coordinate(purl))
        {
            continue;
        }
        for vulnerability in &result.vulnerabilities {
            let ids = names(vulnerability);
            if !ids.contains(&id) {
                continue;
            }
            for (module, product) in scan.products.get(purl).into_iter().flatten() {
                let product = if args.product_version {
                    product.clone()
                } else {
                    versionless_purl(product).unwrap_or_else(|| product.clone())
                };
                targets
                    .entry((module.clone(), product, purl.to_string()))
                    .or_default()
                    .extend(ids.iter().copied());
            }
        }
    }
    let ((module, product, purl), ids) = match targets.len() {
        1 => targets.pop_first().expect("one target"),
        0 => {
            return Err(CliError::Usage(format!(
                "{id} is not a finding of {} in the scanned modules",
                component.unwrap_or("any dependency")
            )));
        }
        _ => {
            let candidates = targets
                .keys()
                .map(|(module, product, purl)| format!("{purl} in {module} ({product})"))
                .collect::<Vec<_>>();
            return Err(CliError::Usage(format!(
                "{id} affects {}: {}; pass --module and --component, or --platform and --jdk, to pick one",
                plural(candidates.len(), "finding", "findings"),
                candidates.join(", ")
            )));
        }
    };
    let module_purl = scan.products[&purl]
        .iter()
        .find(|(path, candidate)| {
            path == &module
                && (candidate == &product || versionless_purl(candidate).as_ref() == Some(&product))
        })
        .map(|(_, product)| product)
        .expect("selected product");
    let ids = ids.into_iter().collect::<Vec<_>>();
    let statement = NewStatement {
        name: id,
        module: module_purl,
        product: &product,
        subcomponent: &purl,
        justification: args.justification,
        impact_statement: args.impact_statement.as_deref(),
    };
    let recorded =
        crate::commands::vex::record(&args.vex, &statement, &ids, args.author.as_deref())?;
    Ok(Report::data(Triaged {
        path: args.vex.clone(),
        written: recorded.written,
        version: recorded.version,
        vulnerability: id.to_string(),
        module: module.to_string(),
        product,
        subcomponent: purl.to_string(),
        justification: args.justification,
    }))
}

struct Triaged {
    path: PathBuf,
    written: bool,
    version: u64,
    vulnerability: String,
    module: String,
    product: String,
    subcomponent: String,
    justification: Justification,
}

impl CommandOutput for Triaged {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "path": crate::commands::path_to_forward_slashes(&self.path),
            "written": self.written,
            "version": self.version,
            "vulnerability": self.vulnerability,
            "module": self.module,
            "product": self.product,
            "subcomponent": self.subcomponent,
            "justification": self.justification,
        }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        let versions = if versionless_purl(&self.product).is_none() {
            "every version of "
        } else {
            ""
        };
        let what = format!(
            "{} not_affected ({}) for {} in {versions}the {} module",
            self.vulnerability,
            self.justification.as_str(),
            purl_coordinate(&self.subcomponent),
            self.module
        );
        if self.written {
            human.done(
                "Recorded",
                format!(
                    "{what} in {} (version {})",
                    self.path.display(),
                    self.version
                ),
            )
        } else {
            human.line(format!("{} already records {what}.", self.path.display()))
        }
    }
}

fn scan_metadata(query_timestamp: &str) -> serde_json::Value {
    serde_json::json!({
        "tool": {
            "name": "raeva",
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
    use rv_vuln::Vulnerability;

    use super::{SeverityThreshold, fixed_version, sarif_level};

    /// The purl's version is percent-encoded; the fix is chosen against the
    /// version itself.
    #[test]
    fn the_fixed_version_compares_the_decoded_version() {
        let record: Vulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-1",
            "summary": "",
            "affected": [{
                "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "1.0+1"}, {"introduced": "1.0+2"}, {"fixed": "1.0+3"},
                ]}],
            }],
        }))
        .expect("record");
        let purl = rv_maven_types::maven_purl("org.example", "lib", "1.0+2").expect("purl");
        assert!(purl.contains("%2B"), "{purl}");
        assert_eq!(fixed_version(&record, &purl).as_deref(), Some("1.0+3"));
    }

    fn vulnerability(score: Option<&str>) -> Vulnerability {
        serde_json::from_value(serde_json::json!({
            "id": "OSV-TEST",
            "summary": "test",
            "severity": score.map(|score| serde_json::json!({ "type": "CVSS_V3", "score": score })),
        }))
        .expect("vulnerability")
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

        // CVSS rates 0.0 None, which only `any` meets.
        let none = vulnerability(Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"));
        assert!(SeverityThreshold::Any.matches(&none));
        assert!(!SeverityThreshold::Low.matches(&none));
        assert_eq!(sarif_level(&none), "note");
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
    fn vex_checks_every_product_identity_that_reaches_a_dependency() {
        use super::{ScanData, assess};
        use crate::commands::vex::VexSet;
        use std::collections::{BTreeMap, BTreeSet};
        let purl = "pkg:maven/org.example/lib@1";
        let result = serde_json::from_value(serde_json::json!({
            "purl": purl, "vulnerabilities": [vulnerability(Some("9.8"))]
        }))
        .unwrap();
        let scan = ScanData {
            baseline: None,
            report: rv_vuln::ScanReport {
                total_dependencies: 1,
                vulnerabilities: vec![result],
                failed_fetches: Vec::new(),
            },
            targets: Vec::new(),
            reachability: BTreeMap::from([(purl.to_string(), vec!["pom.xml".to_string()])]),
            module_purls: BTreeSet::from([
                "pkg:maven/com.example/app@1".to_string(),
                "pkg:maven/com.example/app@2".to_string(),
            ]),
            products: BTreeMap::from([(
                purl.to_string(),
                vec![
                    (
                        "pom.xml".to_string(),
                        "pkg:maven/com.example/app@1".to_string(),
                    ),
                    (
                        "pom.xml".to_string(),
                        "pkg:maven/com.example/app@2".to_string(),
                    ),
                ],
            )]),
            test_only: 0,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vex.json");
        for (product, suppressed) in [
            ("pkg:maven/com.example/app@1", false),
            ("pkg:maven/com.example/app", true),
        ] {
            std::fs::write(
                &path,
                serde_json::json!({
                    "@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:uuid:product-variants",
                    "author": "Fixture", "timestamp": "2026-10-01T00:00:00Z", "version": 1,
                    "statements": [{"vulnerability": {"name": "OSV-TEST"},
                        "products": [{"@id": product, "subcomponents": [{"@id": purl}]}],
                        "status": "not_affected", "justification": "component_not_present"}]
                })
                .to_string(),
            )
            .unwrap();
            let vex = VexSet::load(std::slice::from_ref(&path)).unwrap();
            let finding = assess(&scan, &vex).unwrap().pop().unwrap();
            assert_eq!(finding.suppressed(), suppressed);
            assert_eq!(finding.vex.len(), 1);
            if !suppressed {
                assert_eq!(finding.active, ["pom.xml"]);
            }
        }
    }
}
