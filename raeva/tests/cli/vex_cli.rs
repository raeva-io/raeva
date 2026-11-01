//! `raeva vuln` scope filtering and OpenVEX: `--vex`, `vuln triage`, and
//! `sbom --vex`, on the lock-golden projects against a stub OSV server.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use rv_test_support::fixtures;
use rv_test_support::http::{Response, StubServer};
use rv_test_support::net::RefusingPort;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::common::{assert_status, assert_success, raeva_command};
use crate::schemas::{assert_schema_valid, cyclonedx_validator};

const UTIL: &str = "pkg:maven/org.golden/util@2.0";
const API: &str = "pkg:maven/org.golden.reactor/api@2.0";
const APP: &str = "pkg:maven/org.golden.reactor/app@2.0";

/// A lock-golden project, synced offline from the file repository each
/// module basedir declares.
fn golden_project(name: &str) -> (TempDir, TempDir) {
    let project = TempDir::new().expect("project");
    let home = TempDir::new().expect("home");
    let fixture = fixtures::path("lock-golden");
    fixtures::copy_tree_lf(&fixture.join(name).join("project"), project.path());
    let modules: &[&str] = if name == "reactor" {
        &[".", "api", "app"]
    } else {
        &["."]
    };
    for module in modules {
        fixtures::copy_tree_lf(
            &fixture.join("repository"),
            &project.path().join(module).join("repository"),
        );
    }
    let sync = raeva_command(project.path(), home.path())
        .args(["--quiet", "sync", "--offline"])
        .output()
        .expect("run raeva sync");
    assert_success(&sync, "fixture sync");
    (project, home)
}

fn advisory(id: &str) -> Value {
    json!({
        "id": id,
        "aliases": ["CVE-2024-0001"],
        "summary": format!("{id} summary"),
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "affected": [],
    })
}

/// OSV with `OSV-UTIL-1` (alias `CVE-2024-0001`) on every util version and
/// `OSV-TESTLIB-1` on testlib. With `missing`, util also names a record
/// OSV does not serve.
fn osv(missing: bool) -> (String, StubServer) {
    let server = StubServer::start(move |request| {
        let ok = |body: Value| {
            Response::new(200, body.to_string()).header("Content-Type", "application/json")
        };
        let ids = |purl: &str| {
            if purl.starts_with("pkg:maven/org.golden/util@") {
                let mut ids = vec![json!({"id": "OSV-UTIL-1"})];
                if missing {
                    ids.push(json!({"id": "OSV-MISSING"}));
                }
                json!({"vulns": ids})
            } else if purl.starts_with("pkg:maven/org.golden/testlib@") {
                json!({"vulns": [{"id": "OSV-TESTLIB-1"}]})
            } else {
                json!({})
            }
        };
        match request.path.as_str() {
            "/v1/querybatch" => {
                let body: Value = serde_json::from_slice(&request.body).expect("body");
                let results: Vec<Value> = (body["queries"].as_array().expect("queries").iter())
                    .map(|query| ids(query["package"]["purl"].as_str().unwrap_or_default()))
                    .collect();
                ok(json!({ "results": results }))
            }
            "/v1/query" => {
                let body: Value = serde_json::from_slice(&request.body).expect("body");
                let purl = body["package"]["purl"].as_str().unwrap_or_default();
                let records: Vec<Value> = (ids(purl)["vulns"].as_array().into_iter().flatten())
                    .map(|id| advisory(id["id"].as_str().expect("id")))
                    .collect();
                ok(json!({ "vulns": records }))
            }
            "/v1/vulns/OSV-UTIL-1" => ok(advisory("OSV-UTIL-1")),
            "/v1/vulns/OSV-TESTLIB-1" => ok(advisory("OSV-TESTLIB-1")),
            _ => Response::new(404, "{}"),
        }
    });
    (format!("http://{}/v1", server.addr()), server)
}

fn vex_document(statements: Vec<Value>) -> String {
    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:uuid:fixture",
        "author": "Fixture",
        "timestamp": "2026-10-01T00:00:00Z",
        "version": 1,
        "statements": statements,
    })
    .to_string()
}

fn vex_statement(name: &str, product: &str, status: &str, justification: Option<&str>) -> Value {
    let mut statement = json!({
        "vulnerability": {"name": name},
        "products": [{"@id": product, "subcomponents": [{"@id": UTIL}]}],
        "status": status,
    });
    if let Some(justification) = justification {
        statement["justification"] = justification.into();
    }
    statement
}

fn write_vex(project: &Path, name: &str, statements: Vec<Value>) -> PathBuf {
    let path = project.join(name);
    fs::write(&path, vex_document(statements)).expect("write VEX");
    path
}

fn vuln(project: &Path, home: &Path, osv: &str, args: &[&str]) -> Output {
    raeva_command(project, home)
        .env("RAEVA_OSV_BASE_URL", osv)
        .args(args)
        .output()
        .expect("run raeva vuln")
}

fn json_vuln(project: &Path, home: &Path, osv: &str, args: &[&str]) -> (i32, Value) {
    let output = vuln(project, home, osv, &[&["--json", "vuln"], args].concat());
    let envelope = serde_json::from_slice(&output.stdout).expect("JSON envelope");
    (output.status.code().expect("exit code"), envelope)
}

fn sarif_vuln(project: &Path, home: &Path, osv: &str, args: &[&str]) -> Value {
    let output = vuln(
        project,
        home,
        osv,
        &[&["vuln", "--format", "sarif"], args].concat(),
    );
    serde_json::from_slice(&output.stdout).expect("SARIF")
}

/// Only what the test classpath alone reaches is left out: testlib and the
/// test-jar. util, which core brings in at compile scope and testlib at
/// test scope, is scanned. JSON and SARIF count the same findings.
#[test]
fn vuln_skips_dependencies_only_the_test_classpath_reaches() {
    let (project, home) = golden_project("single-module");
    let (osv, server) = osv(false);
    let (code, envelope) = json_vuln(project.path(), home.path(), &osv, &[]);
    assert_eq!(code, 1, "{envelope}");
    let requests: String = server.requests().into_iter().map(|r| r.raw).collect();
    assert!(!requests.contains("testlib"), "{requests}");
    assert!(!requests.contains("classifier=tests"), "{requests}");
    assert!(
        requests.contains("pkg:maven/org.golden/util@1.0"),
        "{requests}"
    );
    assert!(
        requests.contains("pkg:maven/org.golden/api-spec@1.0"),
        "provided"
    );
    assert!(
        requests.contains("pkg:maven/org.golden/runtime-only@1.0"),
        "runtime"
    );
    assert!(
        requests.contains("pkg:maven/org.golden/vendored@0.9"),
        "system"
    );

    let summary = &envelope["data"]["summary"];
    assert_eq!(summary["total_dependencies"], 7, "{summary}");
    assert_eq!(summary["test_only_dependencies"], 2, "{summary}");
    assert_eq!(summary["total_vulnerabilities"], 1, "{summary}");
    assert_eq!(summary["critical"], 1, "{summary}");
    let sarif = sarif_vuln(project.path(), home.path(), &osv, &[]);
    assert_eq!(
        sarif["runs"][0]["results"].as_array().map(Vec::len),
        Some(1)
    );

    let human = vuln(project.path(), home.path(), &osv, &["vuln"]);
    let table = String::from_utf8_lossy(&human.stdout);
    assert!(
        table.contains("Not scanned: 2 dependencies only on the test classpath."),
        "{table}"
    );
    server.stop();
}

/// A statement for one module leaves the finding active in the other; a
/// statement for each suppresses it. Only active findings meet --fail-on.
#[test]
fn vex_suppresses_per_module_before_the_modules_combine() {
    let (project, home) = golden_project("reactor");
    let (osv, server) = osv(false);
    let justification = "vulnerable_code_not_in_execute_path";
    let api = write_vex(
        project.path(),
        "api.vex.json",
        vec![vex_statement(
            "CVE-2024-0001",
            API,
            "not_affected",
            Some(justification),
        )],
    );
    let api = api.to_str().expect("path");
    let (code, envelope) = json_vuln(project.path(), home.path(), &osv, &["--vex", api]);
    assert_eq!(code, 1, "{envelope}");
    let data = &envelope["data"];
    assert_eq!(data["summary"]["suppressed"], 0);
    assert_eq!(data["summary"]["findings_at_or_above_threshold"], 1);
    let result = &data["results"][0];
    assert_eq!(result["purl"], UTIL);
    assert_eq!(
        result["affected_modules"],
        json!(["api/pom.xml", "app/pom.xml"])
    );
    assert_eq!(result["suppressed"], json!([]));
    assert_eq!(
        result["vex"],
        json!([{
            "id": "OSV-UTIL-1",
            "module": "api/pom.xml",
            "status": "not_affected",
            "justification": justification,
            "impact_statement": null,
        }])
    );
    let sarif = sarif_vuln(project.path(), home.path(), &osv, &["--vex", api]);
    let finding = &sarif["runs"][0]["results"][0];
    assert!(finding.get("suppressions").is_none(), "{finding}");
    assert_eq!(
        finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "app/pom.xml"
    );
    assert_eq!(finding["locations"].as_array().map(Vec::len), Some(1));
    let table = vuln(project.path(), home.path(), &osv, &["vuln", "--vex", api]);
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(table.contains("In app: OSV-UTIL-1 summary"), "{table}");
    assert!(
        table.contains("Suppressed by VEX: 1 finding in some modules only"),
        "{table}"
    );
    assert!(
        table.contains(&format!("In api: {justification}")),
        "{table}"
    );

    let app = write_vex(
        project.path(),
        "app.vex.json",
        vec![vex_statement(
            "OSV-UTIL-1",
            APP,
            "not_affected",
            Some("component_not_present"),
        )],
    );
    let app = app.to_str().expect("path");
    let both = ["--vex", api, "--vex", app];
    let (code, envelope) = json_vuln(project.path(), home.path(), &osv, &both);
    assert_eq!(code, 0, "{envelope}");
    let summary = &envelope["data"]["summary"];
    assert_eq!(summary["total_vulnerabilities"], 1);
    assert_eq!(summary["suppressed"], 1);
    assert_eq!(summary["critical"], 0);
    assert_eq!(summary["findings_at_or_above_threshold"], 0);
    assert_eq!(envelope["data"]["threshold_exceeded"], false);
    assert_eq!(
        envelope["data"]["results"][0]["suppressed"],
        json!(["OSV-UTIL-1"])
    );
    let sarif = sarif_vuln(project.path(), home.path(), &osv, &both);
    let finding = &sarif["runs"][0]["results"][0];
    assert_eq!(
        finding["suppressions"],
        json!([{
            "kind": "external",
            "status": "accepted",
            "justification": format!("OpenVEX not_affected: component_not_present, {justification}"),
        }])
    );
    assert_eq!(finding["locations"].as_array().map(Vec::len), Some(2));
    let table = vuln(
        project.path(),
        home.path(),
        &osv,
        &[&["vuln"][..], &both].concat(),
    );
    assert_status(&table, 0, "every module suppressed");
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(table.contains("Suppressed by VEX: 1 finding\n"), "{table}");
    assert!(
        table.contains("No unsuppressed finding is at high severity or above"),
        "{table}"
    );

    // Other statuses are shown and suppress nothing.
    let investigating = write_vex(
        project.path(),
        "investigating.vex.json",
        vec![vex_statement(
            "CVE-2024-0001",
            APP,
            "under_investigation",
            None,
        )],
    );
    let investigating = investigating.to_str().expect("path");
    let args = [
        "--vex",
        api,
        "--vex",
        investigating,
        "--fail-on",
        "critical",
    ];
    let (code, envelope) = json_vuln(project.path(), home.path(), &osv, &args);
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(
        envelope["data"]["summary"]["findings_at_or_above_threshold"],
        1
    );
    let table = vuln(
        project.path(),
        home.path(),
        &osv,
        &[&["vuln"][..], &args].concat(),
    );
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(
        table.contains("In app: (VEX under_investigation) OSV-UTIL-1"),
        "{table}"
    );
    server.stop();
}

/// Two statements that disagree fail before OSV is asked anything.
#[test]
fn conflicting_vex_statements_fail_before_the_scan() {
    let (project, home) = golden_project("reactor");
    let (osv, server) = osv(false);
    let first = write_vex(
        project.path(),
        "a.vex.json",
        vec![vex_statement(
            "CVE-2024-0001",
            API,
            "not_affected",
            Some("component_not_present"),
        )],
    );
    let second = write_vex(
        project.path(),
        "b.vex.json",
        vec![vex_statement("CVE-2024-0001", API, "affected", None)],
    );
    let args = [
        "--vex",
        first.to_str().expect("path"),
        "--vex",
        second.to_str().expect("path"),
    ];
    let (code, envelope) = json_vuln(project.path(), home.path(), &osv, &args);
    assert_eq!(code, 3, "{envelope}");
    assert_eq!(envelope["code"], "INVALID_PROJECT_INPUT");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("say different things")),
        "{envelope}"
    );
    assert_eq!(server.answered(), 0);
    server.stop();
}

/// Suppression does not make an incomplete scan pass.
#[test]
fn an_incomplete_scan_fails_even_when_vex_suppresses_its_findings() {
    let (project, home) = golden_project("single-module");
    let (osv, server) = osv(true);
    let vex = write_vex(
        project.path(),
        "vex.json",
        vec![{
            let mut statement = vex_statement(
                "OSV-UTIL-1",
                "pkg:maven/org.golden.app/single@1.0",
                "not_affected",
                Some("component_not_present"),
            );
            statement["products"][0]["subcomponents"][0]["@id"] =
                "pkg:maven/org.golden/util@1.0".into();
            statement
        }],
    );
    let (code, envelope) = json_vuln(
        project.path(),
        home.path(),
        &osv,
        &["--vex", vex.to_str().expect("path")],
    );
    assert!(code > 1, "{envelope}");
    assert_eq!(envelope["data"]["complete"], false);
    assert_eq!(envelope["data"]["summary"]["suppressed"], 1);
    server.stop();
}

/// A versionless product covers every module version, and a statement that
/// matches nothing in scope is reported so it can be removed.
#[test]
fn unused_vex_statements_are_reported() {
    let (project, home) = golden_project("reactor");
    let (osv, server) = osv(false);
    let justification = Some("vulnerable_code_not_in_execute_path");
    let vex = write_vex(
        project.path(),
        "vex.json",
        vec![
            vex_statement(
                "CVE-2024-0001",
                "pkg:maven/org.golden.reactor/api",
                "not_affected",
                justification,
            ),
            vex_statement("CVE-2099-0001", API, "not_affected", justification),
            {
                let mut gone = vex_statement("CVE-2099-0002", API, "not_affected", justification);
                gone["products"][0]["subcomponents"][0]["@id"] =
                    "pkg:maven/org.golden/util@0.9".into();
                gone
            },
        ],
    );
    let vex = vex.to_str().expect("path");
    let unused = |envelope: &Value| -> Vec<String> {
        (envelope["data"]["warnings"]
            .as_array()
            .into_iter()
            .flatten())
        .filter(|warning| warning["code"] == "VEX_STATEMENT_UNUSED")
        .map(|warning| {
            warning["context"]["vulnerability"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
    };

    let (_, envelope) = json_vuln(
        project.path(),
        home.path(),
        &osv,
        &["--vex", vex, "--module", "api/pom.xml"],
    );
    assert_eq!(envelope["data"]["summary"]["suppressed"], 1, "{envelope}");
    assert_eq!(
        unused(&envelope),
        ["CVE-2099-0001", "CVE-2099-0002"],
        "{envelope}"
    );

    let (_, envelope) = json_vuln(
        project.path(),
        home.path(),
        &osv,
        &["--vex", vex, "--module", "app/pom.xml"],
    );
    assert!(unused(&envelope).is_empty(), "{envelope}");

    let output = sbom(
        project.path(),
        home.path(),
        &["--vex", vex, "--module", "api/pom.xml"],
    );
    assert_success(&output, "sbom --vex");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("about CVE-2099-0002 matched nothing"),
        "{stderr}"
    );
    assert!(!stderr.contains("CVE-2099-0001"), "{stderr}");
    assert!(stderr.contains("SBOM of raeva.lock for "), "{stderr}");

    // The SBOM on stdout has no envelope, so the count names one that does.
    let gone = |id: &str| {
        let mut gone = vex_statement(id, API, "not_affected", justification);
        gone["products"][0]["subcomponents"][0]["@id"] = "pkg:maven/org.golden/util@0.9".into();
        gone
    };
    let two = write_vex(
        project.path(),
        "two.json",
        vec![gone("CVE-2099-0002"), gone("CVE-2099-0003")],
    );
    let two = two.to_str().expect("path");
    let args = ["--vex", two, "--module", "api/pom.xml"];
    let output = sbom(project.path(), home.path(), &args);
    assert_success(&output, "sbom --vex with two unused statements");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("and 1 more ('raeva --json sbom -o FILE' lists them)"),
        "{stderr}"
    );
    let file = project.path().join("sbom.json");
    let output = raeva_command(project.path(), home.path())
        .args(["--json", "sbom", "-o", file.to_str().unwrap()])
        .args(args)
        .output()
        .unwrap();
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(unused(&envelope).len(), 2, "{envelope}");
    server.stop();
}

fn triage(project: &Path, home: &Path, osv: &str, args: &[&str]) -> (i32, Value) {
    let output = vuln(
        project,
        home,
        osv,
        &[&["--json", "vuln", "triage"], args].concat(),
    );
    let envelope = serde_json::from_slice(&output.stdout).expect("JSON envelope");
    (output.status.code().expect("exit code"), envelope)
}

/// Triage writes only for one unambiguous finding, keeps an identical
/// statement once, and refuses a contradiction without touching the file.
#[test]
fn triage_records_one_unambiguous_finding() {
    let (project, home) = golden_project("reactor");
    let (osv, server) = osv(false);
    let path = project.path().join("vex.json");
    let vex = path.to_str().expect("path");
    let base = [
        "CVE-2024-0001",
        "--justification",
        "vulnerable_code_not_in_execute_path",
        "--vex",
        vex,
        "--author",
        "Example",
    ];
    let (code, envelope) = triage(project.path(), home.path(), &osv, &base);
    assert_eq!(code, 2, "{envelope}");
    let error = envelope["error"].as_str().expect("error");
    assert!(error.contains("affects 2 findings"), "{error}");
    assert!(error.contains(&format!("{UTIL} in api/pom.xml")), "{error}");
    assert!(!path.exists());

    let api = [&base[..], &["--module", "api/pom.xml"]].concat();
    let (code, envelope) = triage(project.path(), home.path(), &osv, &api);
    assert_eq!(code, 0, "{envelope}");
    let data = &envelope["data"];
    assert_eq!(data["written"], true);
    assert_eq!(data["version"], 1);
    assert_eq!(data["product"], "pkg:maven/org.golden.reactor/api");
    assert_eq!(data["subcomponent"], UTIL);
    let written = fs::read(&path).expect("VEX");

    let (code, envelope) = triage(project.path(), home.path(), &osv, &api);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["written"], false);
    assert_eq!(fs::read(&path).expect("VEX"), written);

    let mut contradicting = api.clone();
    contradicting[2] = "component_not_present";
    let (code, envelope) = triage(project.path(), home.path(), &osv, &contradicting);
    assert_eq!(code, 2, "{envelope}");
    assert_eq!(fs::read(&path).expect("VEX"), written);

    let narrow = [&api[..], &["--product-version"]].concat();
    let (code, envelope) = triage(project.path(), home.path(), &osv, &narrow);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["written"], true);
    assert_eq!(envelope["data"]["product"], API);

    let unknown = [&base[..], &["--component", "org.golden:core:1.0"]].concat();
    let (code, envelope) = triage(project.path(), home.path(), &osv, &unknown);
    assert_eq!(code, 2, "{envelope}");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|e| e.contains("is not a finding"))
    );

    let app = [
        &base[..],
        &[
            "--module",
            "app/pom.xml",
            "--component",
            "org.golden:util:2.0",
        ],
    ]
    .concat();
    let (code, envelope) = triage(project.path(), home.path(), &osv, &app);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["version"], 3);

    let (code, envelope) = json_vuln(project.path(), home.path(), &osv, &["--vex", vex]);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["data"]["summary"]["suppressed"], 1);
    server.stop();
}

/// A `--vex` file that cannot be read fails as a `--baseline` one does.
#[test]
fn a_missing_vex_file_is_invalid_project_input() {
    let (project, home) = golden_project("reactor");
    let output = sbom(project.path(), home.path(), &["--vex", "missing.json"]);
    assert_eq!(output.status.code(), Some(3));
    let output = raeva_command(project.path(), home.path())
        .args(["--json", "sbom", "--vex", "missing.json"])
        .output()
        .unwrap();
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["code"], "INVALID_PROJECT_INPUT", "{envelope}");
    let error = envelope["error"].as_str().unwrap();
    assert!(error.contains("cannot read --vex file"), "{error}");
}

fn sbom(project: &Path, home: &Path, args: &[&str]) -> Output {
    // A port that refuses connections: sbom must not query OSV.
    let refusing = RefusingPort::bind();
    raeva_command(project, home)
        .env(
            "RAEVA_OSV_BASE_URL",
            format!("http://{}/v1", refusing.addr()),
        )
        .args([&["sbom"], args].concat())
        .output()
        .expect("run raeva sbom")
}

/// The SBOM lists a component once for all modules, so `sbom --vex`
/// combines assessments conservatively and keeps each module's evidence.
#[test]
fn sbom_vex_exports_module_scoped_analyses() {
    let (project, home) = golden_project("reactor");
    let plain = sbom(project.path(), home.path(), &[]);
    assert_success(&plain, "plain sbom");
    let plain: Value = serde_json::from_slice(&plain.stdout).expect("CycloneDX");
    assert!(plain.get("vulnerabilities").is_none());

    let vex = write_vex(
        project.path(),
        "vex.json",
        vec![{
            let mut statement = vex_statement(
                "CVE-2024-0001",
                API,
                "not_affected",
                Some("vulnerable_code_not_in_execute_path"),
            );
            statement["impact_statement"] = "the parser is never called".into();
            statement
        }],
    );
    let vex = vex.to_str().expect("path");
    let aggregate = sbom(project.path(), home.path(), &["--vex", vex]);
    assert_success(&aggregate, "combined modules");
    let combined: Value = serde_json::from_slice(&aggregate.stdout).expect("CycloneDX");
    assert_schema_valid(&cyclonedx_validator(), &combined);
    let analysis = &combined["vulnerabilities"][0]["analysis"];
    assert_eq!(analysis["state"], "in_triage");
    let detail = analysis["detail"].as_str().expect("module details");
    assert!(detail.contains("api/pom.xml: not_affected"), "{detail}");
    assert!(detail.contains("app/pom.xml: nothing"), "{detail}");
    assert!(analysis.get("justification").is_none());

    let api = sbom(
        project.path(),
        home.path(),
        &["--module", "api/pom.xml", "--vex", vex],
    );
    assert_success(&api, "module sbom");
    let document: Value = serde_json::from_slice(&api.stdout).expect("CycloneDX");
    assert_schema_valid(&cyclonedx_validator(), &document);
    assert_eq!(
        document["vulnerabilities"],
        json!([{
            "id": "CVE-2024-0001",
            "analysis": {
                "state": "not_affected",
                "justification": "code_not_reachable",
                "detail": "the parser is never called",
            },
            "affects": [{"ref": UTIL}],
        }])
    );

    // The same statement for both modules, under an alias in one, exports
    // once; distinct impact statements retain their module names.
    let both = |app_impact: &str| {
        let mut api = vex_statement(
            "CVE-2024-0001",
            API,
            "not_affected",
            Some("vulnerable_code_not_in_execute_path"),
        );
        api["vulnerability"]["aliases"] = json!(["OSV-UTIL-1"]);
        api["impact_statement"] = "the parser is never called".into();
        let mut app = vex_statement(
            "OSV-UTIL-1",
            APP,
            "not_affected",
            Some("vulnerable_code_not_in_execute_path"),
        );
        app["impact_statement"] = app_impact.into();
        write_vex(project.path(), "both.vex.json", vec![api, app])
    };
    let agreeing = both("the parser is never called");
    let aggregate = sbom(
        project.path(),
        home.path(),
        &["--vex", agreeing.to_str().expect("path")],
    );
    assert_success(&aggregate, "modules agree");
    let aggregate: Value = serde_json::from_slice(&aggregate.stdout).expect("CycloneDX");
    assert_eq!(aggregate["vulnerabilities"], document["vulnerabilities"]);
    let differing = both("only tests call the parser");
    let aggregate = sbom(
        project.path(),
        home.path(),
        &["--vex", differing.to_str().expect("path")],
    );
    assert_success(&aggregate, "distinct impact statements");
    let aggregate: Value = serde_json::from_slice(&aggregate.stdout).expect("CycloneDX");
    assert_schema_valid(&cyclonedx_validator(), &aggregate);
    let analysis = &aggregate["vulnerabilities"][0]["analysis"];
    assert_eq!(analysis["state"], "not_affected");
    assert_eq!(analysis["justification"], "code_not_reachable");
    let detail = analysis["detail"].as_str().expect("module details");
    assert!(detail.contains("the parser is never called"), "{detail}");
    assert!(detail.contains("only tests call the parser"), "{detail}");

    let module_plain = sbom(project.path(), home.path(), &["--module", "api/pom.xml"]);
    let module_plain: Value = serde_json::from_slice(&module_plain.stdout).expect("CycloneDX");
    assert_ne!(module_plain["serialNumber"], document["serialNumber"]);
}
