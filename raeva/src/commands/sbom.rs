use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Args;
use rv_sbom::{
    AnalysisJustification, AnalysisState, Component, CycloneDxGenerator, VulnerabilityAnalysis,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::commands::module_selector::ModuleSelector;
use crate::commands::report_selector::{ReportSelector, ReportTarget};
use crate::commands::vex::{Assessment, Justification, Status, VexSet};
use crate::error::{CliError, Result};
use crate::output::{CommandOutput, Human, Report};
use crate::session::Session;

#[derive(Debug, Args)]
#[command(
    after_long_help = format!(
        "\
Output:
  Writes a CycloneDX 1.5 JSON document to stdout unless -o/--output is
  provided. By default, it covers all recorded platforms and JDKs when
  their selected module graphs and evidence agree. Otherwise, select a
  target with --platform and --jdk.

  --vex adds the statements an OpenVEX file makes about the selected
  modules' dependencies as vulnerabilities with an analysis. It does not
  query OSV. Analyses combine all selected modules: an affected module
  takes precedence, and a missing assessment keeps the result in triage.

{}",
        crate::commands::util::help_examples(&[
            ("sbom", ""),
            ("sbom --platform linux-x86_64 --jdk 21", ""),
            ("sbom --module app/pom.xml", ""),
            ("sbom --module com.acme:app", ""),
            ("sbom -o bom.json", ""),
            ("sbom --module app/pom.xml --vex vex.json", ""),
        ])
    )
)]
pub(crate) struct SbomArgs {
    #[command(flatten)]
    module: ModuleSelector,
    #[command(flatten)]
    targets: ReportSelector,
    #[arg(
        short = 'o',
        long,
        value_name = "FILE",
        help = "Write the SBOM to a file instead of stdout"
    )]
    output: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Add the analyses an OpenVEX file records (repeatable)"
    )]
    vex: Vec<PathBuf>,
}

pub(crate) fn run(args: &SbomArgs, session: &Session) -> Result<Report> {
    let vex = VexSet::load(&args.vex)?;
    let config = session.config()?;
    let output = session.output();
    // The freshness check's reactor models also give the license evidence.
    let (lock, models, _) = session.fresh_lockfile(&config)?;
    let selected_targets = args.targets.select(&lock)?;
    let targets = selected_targets.targets();
    let platform = selected_targets.sbom_platform(&args.module)?;
    let selection = args.module.select(&platform)?;
    output.note(&format!(
        "SBOM of raeva.lock for {}",
        targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let adapted = crate::commands::lock_adapter::adapt_sbom_modules(&platform, selection.modules())
        .map_err(|err| CliError::LockfileDefect {
            details: err.to_string(),
        })?;
    let vulnerabilities = vulnerability_analyses(&vex, &adapted.modules)?;
    vex.warn_unused(output, |product| {
        (adapted.modules.iter())
            .any(|(_, module, _)| crate::commands::vex::same_module(product, module))
    });
    let mut root = adapted.root;
    let mut components = adapted.components;
    let paths: BTreeSet<_> = selection
        .modules()
        .iter()
        .map(|m| m.path.as_str())
        .collect();
    let mut licenses = std::collections::BTreeMap::new();
    for original in &selected_targets.platforms {
        let modules: Vec<_> = original
            .modules
            .iter()
            .filter(|m| paths.contains(m.path.as_str()))
            .collect();
        if modules.is_empty() {
            continue;
        }
        let model = (models.iter())
            .find(|model| model.platform == original.platform)
            .expect("a model for every locked target");
        crate::commands::sbom_licenses::populate(
            &config,
            original,
            &model.workspace,
            &modules,
            &mut licenses,
        )?;
    }

    for component in std::iter::once(&mut root).chain(&mut components) {
        component.licenses = licenses
            .remove(&component.purl)
            .expect("every merged component has original target evidence");
    }
    let identity = document_identity(&targets, &root, &components, &vulnerabilities)?;
    let document = CycloneDxGenerator {
        tool_name: "raeva".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        root_component: root,
        serial_number: format!("urn:uuid:{identity}"),
        vulnerabilities,
    }
    .generate_with_properties(
        &components,
        &targets
            .iter()
            .map(|target| ("raeva:target".to_string(), target.to_string()))
            .collect::<Vec<_>>(),
    )?;

    let Some(path) = &args.output else {
        return Ok(Report::document(document));
    };
    crate::commands::write_atomic(path, format!("{document}\n").as_bytes())?;
    Ok(Report::data(SbomWritten {
        path: path.clone(),
        targets,
    }))
}

/// `raeva sbom -o FILE`: the document went to a file.
struct SbomWritten {
    path: PathBuf,
    targets: Vec<ReportTarget>,
}

impl CommandOutput for SbomWritten {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "format": "cyclonedx",
            "targets": self.targets,
            "path": crate::commands::path_to_forward_slashes(&self.path),
        }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> std::io::Result<()> {
        human.done("Wrote", self.path.display().to_string())
    }
}

/// The `--vex` statements about the selected modules' packages, one entry
/// per vulnerability and package. Statements whose names or aliases
/// overlap, directly or through another statement, are about one
/// vulnerability. A combined analysis never treats an unassessed module
/// as unaffected. Conflicting statements within one module remain errors.
fn vulnerability_analyses(
    vex: &VexSet,
    modules: &[(String, String, BTreeSet<String>)],
) -> Result<Vec<VulnerabilityAnalysis>> {
    let packages: BTreeSet<&str> = (modules.iter())
        .flat_map(|(_, _, packages)| packages.iter().map(String::as_str))
        .collect();
    let mut analyses = Vec::new();
    for package in packages {
        let holders: Vec<(&str, &str)> = (modules.iter())
            .filter(|(_, _, packages)| packages.contains(package))
            .map(|(path, product, _)| (path.as_str(), product.as_str()))
            .collect();
        let statements: Vec<(usize, &[String], &Assessment)> = (holders.iter().enumerate())
            .flat_map(|(holder, &(_, product))| {
                (vex.statements(product, package))
                    .map(move |(names, assessment)| (holder, names, assessment))
            })
            .collect();
        let mut group: Vec<usize> = (0..statements.len()).collect();
        for later in 0..statements.len() {
            for earlier in 0..later {
                let (from, to) = (group[later], group[earlier]);
                let overlap = statements[later]
                    .1
                    .iter()
                    .any(|name| statements[earlier].1.contains(name));
                if overlap && from != to {
                    group
                        .iter_mut()
                        .filter(|g| **g == from)
                        .for_each(|g| *g = to);
                }
            }
        }
        for label in group.iter().copied().collect::<BTreeSet<_>>() {
            let members: Vec<_> = (statements.iter().zip(&group))
                .filter(|(_, g)| **g == label)
                .map(|(statement, _)| statement)
                .collect();
            let id = members
                .iter()
                .map(|(_, names, _)| names[0].as_str())
                .min()
                .expect("a member");
            let differ = |detail: String| {
                CliError::Usage(format!(
                    "the --vex statements on {id} for {package} differ: {detail}; pass --module \
                     to write one module's SBOM"
                ))
            };
            let mut assessments = Vec::new();
            for (holder, &(path, _)) in holders.iter().enumerate() {
                let mut distinct = Vec::<&Assessment>::new();
                for (_, _, assessment) in members.iter().filter(|(h, _, _)| *h == holder) {
                    if !distinct.contains(assessment) {
                        distinct.push(assessment);
                    }
                }
                if distinct.len() > 1 {
                    let said: BTreeSet<String> = distinct
                        .iter()
                        .map(|assessment| describe(Some(assessment)))
                        .collect();
                    let said = said.into_iter().collect::<Vec<_>>().join(" and ");
                    return Err(differ(format!("{path} says {said}")));
                }
                assessments.push((path, distinct.first().copied()));
            }
            analyses.push(combined_analysis(id, package, &assessments));
        }
    }
    Ok(analyses)
}

fn combined_analysis(
    id: &str,
    package: &str,
    assessments: &[(&str, Option<&Assessment>)],
) -> VulnerabilityAnalysis {
    let first = assessments[0].1;
    if let Some(first) = first
        && assessments.iter().all(|(_, value)| *value == Some(first))
    {
        return analysis(id, package, first);
    }
    let has_status = |status| {
        assessments
            .iter()
            .any(|(_, value)| value.is_some_and(|a| a.status == status))
    };
    let state = if has_status(Status::Affected) {
        AnalysisState::Exploitable
    } else if has_status(Status::UnderInvestigation)
        || assessments.iter().any(|(_, value)| value.is_none())
    {
        AnalysisState::InTriage
    } else if assessments
        .iter()
        .all(|(_, value)| value.is_some_and(|a| a.status == Status::Fixed))
    {
        AnalysisState::Resolved
    } else if assessments
        .iter()
        .all(|(_, value)| value.is_some_and(|a| a.status == Status::NotAffected))
    {
        AnalysisState::NotAffected
    } else {
        // Fixed and not_affected describe different conclusions. Keep both
        // as evidence without choosing one for the combined component.
        AnalysisState::InTriage
    };
    let justification = first.and_then(|first| {
        assessments
            .iter()
            .all(|(_, value)| {
                value.is_some_and(|a| {
                    a.status == first.status && a.justification == first.justification
                })
            })
            .then(|| analysis(id, package, first).justification)
            .flatten()
    });
    let detail = assessments
        .iter()
        .map(|(path, value)| {
            let mut text = format!("{path}: {}", describe(*value));
            if let Some(impact) = value.and_then(|a| a.impact_statement.as_deref()) {
                text.push_str(". ");
                text.push_str(impact);
            }
            text
        })
        .collect::<Vec<_>>()
        .join("\n");
    VulnerabilityAnalysis {
        id: id.to_string(),
        state,
        justification,
        detail: Some(detail),
        affects: vec![package.to_string()],
    }
}

fn describe(assessment: Option<&Assessment>) -> String {
    assessment.map_or_else(|| "nothing".to_string(), crate::commands::vex::describe)
}

fn analysis(id: &str, package: &str, assessment: &Assessment) -> VulnerabilityAnalysis {
    VulnerabilityAnalysis {
        id: id.to_string(),
        state: match assessment.status {
            Status::NotAffected => AnalysisState::NotAffected,
            Status::Affected => AnalysisState::Exploitable,
            Status::Fixed => AnalysisState::Resolved,
            Status::UnderInvestigation => AnalysisState::InTriage,
        },
        justification: assessment
            .justification
            .map(|justification| match justification {
                Justification::ComponentNotPresent | Justification::VulnerableCodeNotPresent => {
                    AnalysisJustification::CodeNotPresent
                }
                Justification::VulnerableCodeNotInExecutePath => {
                    AnalysisJustification::CodeNotReachable
                }
                Justification::VulnerableCodeCannotBeControlledByAdversary => {
                    AnalysisJustification::RequiresEnvironment
                }
                Justification::InlineMitigationsAlreadyExist => {
                    AnalysisJustification::ProtectedByMitigatingControl
                }
            }),
        detail: assessment.impact_statement.clone(),
        affects: vec![package.to_string()],
    }
}

fn document_identity(
    targets: &[ReportTarget],
    root: &Component,
    components: &[Component],
    vulnerabilities: &[VulnerabilityAnalysis],
) -> Result<String> {
    #[derive(Serialize)]
    struct IdentityInput<'a> {
        tool_version: &'static str,
        targets: &'a [ReportTarget],
        root: &'a Component,
        components: &'a [Component],
        #[serde(skip_serializing_if = "Vec::is_empty")]
        vulnerabilities: Vec<(&'a str, &'a [String], String)>,
    }

    let input = serde_json::to_vec(&IdentityInput {
        tool_version: env!("CARGO_PKG_VERSION"),
        targets,
        root,
        components,
        vulnerabilities: vulnerabilities
            .iter()
            .map(|vulnerability| {
                let analysis = format!(
                    "{:?} {:?} {:?}",
                    vulnerability.state, vulnerability.justification, vulnerability.detail
                );
                (
                    vulnerability.id.as_str(),
                    vulnerability.affects.as_slice(),
                    analysis,
                )
            })
            .collect(),
    })?;
    Ok(crate::commands::util::uuid_v8(&Sha256::digest(input)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use tempfile::TempDir;

    use rv_sbom::Component;

    use super::document_identity;

    fn target(platform: &str, jdk: Option<&str>) -> super::ReportTarget {
        super::ReportTarget {
            platform: platform.into(),
            jdk: jdk.map(str::to_string),
        }
    }

    #[test]
    fn document_identity_is_stable_and_uses_uuid_v8() {
        let root = Component {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            group: Some("com.example".to_string()),
            purl: "pkg:maven/com.example/demo@1.0.0".to_string(),
            hashes: Vec::new(),
            licenses: Vec::new(),
            dependencies: Vec::new(),
        };

        let first =
            document_identity(&[target("linux-x86_64", None)], &root, &[], &[]).expect("identity");
        let second =
            document_identity(&[target("linux-x86_64", None)], &root, &[], &[]).expect("identity");
        assert_eq!(first, second);
        assert_eq!(first.as_bytes()[14], b'8');

        let other =
            document_identity(&[target("macos-aarch64", None)], &root, &[], &[]).expect("identity");
        assert_ne!(first, other);

        let jdk_other = document_identity(&[target("linux-x86_64", Some("21"))], &root, &[], &[])
            .expect("identity");
        assert_ne!(first, jdk_other);
        let targets = [target("linux-x86_64", None)];
        let mut licensed = root.clone();
        licensed.licenses.push(rv_sbom::License::Id("MIT".into()));
        assert_ne!(
            first,
            document_identity(&targets, &licensed, &[], &[]).unwrap()
        );
        assert_ne!(
            first,
            document_identity(&targets, &root, &[licensed], &[]).unwrap()
        );
        let analysis = super::VulnerabilityAnalysis {
            id: "CVE-X".into(),
            state: rv_sbom::AnalysisState::InTriage,
            justification: None,
            detail: Some("app/pom.xml: nothing".into()),
            affects: vec![root.purl.clone()],
        };
        let with_vex =
            document_identity(&targets, &root, &[], std::slice::from_ref(&analysis)).unwrap();
        assert_ne!(first, with_vex);
        let mut changed = analysis;
        changed.detail = Some("other/pom.xml: nothing".into());
        assert_ne!(
            with_vex,
            document_identity(&targets, &root, &[], &[changed]).unwrap()
        );
    }

    #[test]
    fn combined_analysis_keeps_affected_and_unassessed_modules_visible() {
        use crate::commands::vex::{Assessment, Justification, Status};
        use rv_sbom::AnalysisState;
        let assessment = |status| Assessment {
            status,
            justification: (status == Status::NotAffected)
                .then_some(Justification::ComponentNotPresent),
            impact_statement: None,
        };
        let unaffected = assessment(Status::NotAffected);
        let affected = assessment(Status::Affected);
        let fixed = assessment(Status::Fixed);
        let pending = assessment(Status::UnderInvestigation);
        for (left, right, expected) in [
            (
                Some(&unaffected),
                Some(&affected),
                AnalysisState::Exploitable,
            ),
            (None, Some(&affected), AnalysisState::Exploitable),
            (Some(&unaffected), None, AnalysisState::InTriage),
            (Some(&fixed), None, AnalysisState::InTriage),
            (Some(&unaffected), Some(&pending), AnalysisState::InTriage),
            (Some(&fixed), Some(&unaffected), AnalysisState::InTriage),
            (Some(&fixed), Some(&fixed), AnalysisState::Resolved),
            (
                Some(&unaffected),
                Some(&unaffected),
                AnalysisState::NotAffected,
            ),
        ] {
            for assessments in [[("a", left), ("b", right)], [("b", right), ("a", left)]] {
                let combined = super::combined_analysis("CVE-X", UTIL, &assessments);
                assert_eq!(combined.state, expected);
                if expected != AnalysisState::NotAffected {
                    assert_eq!(combined.justification, None);
                }
            }
        }
        let mut other_reason = unaffected.clone();
        other_reason.justification = Some(Justification::InlineMitigationsAlreadyExist);
        let combined = super::combined_analysis(
            "CVE-X",
            UTIL,
            &[("a", Some(&unaffected)), ("b", Some(&other_reason))],
        );
        assert_eq!(combined.state, AnalysisState::NotAffected);
        assert_eq!(combined.justification, None);
        assert!(
            combined
                .detail
                .unwrap()
                .contains("inline_mitigations_already_exist")
        );
    }

    #[test]
    fn root_component_rejects_oversized_pom() {
        let temp = TempDir::new().expect("tempdir");
        let pom_path = temp.path().join("pom.xml");
        fs::write(&pom_path, vec![b'x'; rv_config::MAX_PROJECT_INPUT_SIZE + 1])
            .expect("write oversized pom");

        let error =
            rv_config::read_project_input_string(&pom_path).expect_err("oversized POM must fail");
        assert!(matches!(
            error,
            rv_config::ConfigError::ProjectInputTooLarge { .. }
        ));
    }

    const APP: &str = "pkg:maven/com.example/app@1";
    const LIB: &str = "pkg:maven/com.example/lib@1";
    const UTIL: &str = "pkg:maven/org.example/util@1";

    fn statement(product: &str, names: &[&str], status: &str) -> serde_json::Value {
        let mut statement = serde_json::json!({
            "vulnerability": {"name": names[0], "aliases": &names[1..]},
            "products": [{"@id": product, "subcomponents": [{"@id": UTIL}]}],
            "status": status,
        });
        if status == "not_affected" {
            statement["justification"] = "component_not_present".into();
        }
        statement
    }

    /// The analyses for `statements` on util, which both modules have.
    fn analyses(statements: Vec<serde_json::Value>) -> Result<Vec<String>, String> {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("vex.json");
        let document = serde_json::json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:uuid:test",
            "author": "Example",
            "timestamp": "2026-10-01T00:00:00Z",
            "version": 1,
            "statements": statements,
        });
        fs::write(&path, document.to_string()).expect("write");
        let vex = crate::commands::vex::VexSet::load(&[path]).map_err(|err| err.to_string())?;
        let packages = BTreeSet::from([UTIL.to_string()]);
        let modules = [
            ("app/pom.xml".to_string(), APP.to_string(), packages.clone()),
            ("lib/pom.xml".to_string(), LIB.to_string(), packages),
        ];
        let analyses =
            super::vulnerability_analyses(&vex, &modules).map_err(|err| err.to_string())?;
        Ok(analyses.into_iter().map(|analysis| analysis.id).collect())
    }

    /// Statements about one vulnerability are grouped through any chain of
    /// shared names, whatever their order, and a module may not say two
    /// things about it.
    #[test]
    fn sbom_analyses_group_aliases_transitively() {
        let bridge = |product| statement(product, &["CVE-X", "GHSA-Y"], "not_affected");
        let cve = |product| statement(product, &["CVE-X"], "not_affected");
        let ghsa = |product| statement(product, &["GHSA-Y"], "not_affected");
        for order in [
            vec![cve(APP), ghsa(APP), bridge(APP), bridge(LIB)],
            vec![bridge(APP), cve(APP), ghsa(APP), bridge(LIB)],
            vec![cve(APP), bridge(LIB), ghsa(APP)],
        ] {
            assert_eq!(analyses(order), Ok(vec!["CVE-X".to_string()]));
        }
        let affected = statement(APP, &["GHSA-Y"], "affected");
        for order in [
            vec![bridge(LIB), cve(APP), affected.clone()],
            vec![bridge(LIB), affected.clone(), cve(APP)],
        ] {
            let error = analyses(order).expect_err("app says two things");
            assert!(
                error.contains("app/pom.xml says affected and not_affected"),
                "{error}"
            );
        }
    }
}
