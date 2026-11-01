use rv_test_support::net::RefusingPort;

use crate::common::{
    assert_status, closing_server, raeva_command, spawn_osv, temp_project, write_demo_lock,
};
use rv_lock::Scope;

const DEMO: &[(&str, &str, Option<&str>, Scope)] =
    &[("demo-lib", "test-jar", Some("tests"), Scope::Compile)];

#[test]
fn vuln_json_reports_findings_and_preserves_qualified_purl() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let body = r#"{
        "vulns": [{
            "id": "OSV-TEST-1",
            "summary": "test vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [{
                "package": {"ecosystem": "Maven", "name": "org.example:demo-lib"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "2.1.0"}, {"introduced": "3.0"}, {"fixed": "3.2"}
                ]}]
            }]
        }]
    }"#;
    let (base_url, server) = spawn_osv(200, body);

    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &base_url)
        .args(["--json", "vuln"])
        .output()
        .expect("run raeva vuln");

    assert_status(&output, 1, "vuln findings");
    assert!(
        output.stderr.is_empty(),
        "stderr must be empty in JSON mode"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["success"], false);
    assert_eq!(envelope["exit_code"], 1);
    assert_eq!(envelope["code"], "VULNERABILITIES_FOUND");
    assert_eq!(
        envelope["error"],
        "found 1 known vulnerability at high severity or above"
    );
    assert_eq!(
        envelope["data"]["results"][0]["findings"],
        serde_json::json!([{"id": "OSV-TEST-1", "severity": "Critical", "fixed": "2.1.0"}])
    );
    assert_eq!(envelope["data"]["metadata"]["tool"]["name"], "raeva");
    assert_eq!(
        envelope["data"]["metadata"]["tool"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        envelope["data"]["metadata"]["scanner"]["provider"],
        "osv.dev"
    );
    assert!(envelope["data"]["metadata"]["scanner"]["database_snapshot"].is_null());
    assert!(
        envelope["data"]["metadata"]["query_timestamp"].is_string(),
        "envelope={envelope}"
    );
    assert_eq!(envelope["data"]["threshold_exceeded"], true);
    assert_eq!(
        envelope["data"]["summary"]["findings_at_or_above_threshold"],
        1
    );

    let request = server.requests()[0].raw.clone();
    assert!(
        request.contains("pkg:maven/org.example/demo-lib@2.0.0?classifier=tests&type=test-jar"),
        "request={request}"
    );

    let human = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &base_url)
        .arg("vuln")
        .output()
        .expect("run raeva vuln");
    assert_status(&human, 1, "vuln table");
    let table = String::from_utf8_lossy(&human.stdout);
    for cell in [
        "Critical   9.8",
        "OSV-TEST-1",
        "2.1.0",
        "org.example:demo-lib:2.0.0:test-jar:tests",
    ] {
        assert!(table.contains(cell), "{cell}: {table}");
    }
    let notes = String::from_utf8_lossy(&human.stderr);
    for note in [
        "Scanned raeva.lock for ",
        "'raeva why org.example:demo-lib' shows what brings a dependency in",
    ] {
        assert!(notes.contains(note), "{note}: {notes}");
    }

    let sarif = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &base_url)
        .args(["vuln", "--format", "sarif"])
        .output()
        .expect("run raeva vuln --format sarif");
    assert_status(&sarif, 1, "vuln sarif");
    let report: serde_json::Value = serde_json::from_slice(&sarif.stdout).expect("SARIF");
    let result = &report["runs"][0]["results"][0];
    assert!(
        result["message"]["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("OSV-TEST-1 (Critical) affects ")
                && text.ends_with("; fixed in 2.1.0")),
        "{result}"
    );
    assert_eq!(result["properties"]["severity"], "Critical");
    assert_eq!(result["properties"]["fixedVersion"], "2.1.0");
    assert_eq!(server.answered(), 3);
    server.stop();
}

#[test]
fn vuln_returns_two_when_osv_rejects_the_query() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let (base_url, server) = spawn_osv(400, "{\"message\":\"bad\u{1b}[31m\\r\\nquery\"}");

    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["--json", "vuln"])
        .output()
        .expect("run raeva vuln");

    assert_status(&output, 2, "OSV rejected query");
    assert!(
        output.stderr.is_empty(),
        "stderr must be empty in JSON mode"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["success"], false);
    assert_eq!(envelope["exit_code"], 2);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| { error.contains("unexpected OSV status 400") })
    );
    assert!(!envelope["error"].as_str().unwrap().contains('\u{1b}'));
    assert!(!envelope["error"].as_str().unwrap().contains("bad"));
    assert_eq!(
        envelope["data"]["metadata"]["scanner"]["provider"],
        "osv.dev"
    );
    assert_eq!(server.answered(), 1);
    server.stop();
}

#[test]
fn vuln_returns_four_when_osv_is_unavailable() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let (busy_url, server) = spawn_osv(503, "{}");
    let refusing = RefusingPort::bind();
    let closed_url = format!("http://{}/v1", refusing.addr());

    for base_url in [busy_url, closed_url.clone()] {
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", &base_url)
            .env("RAEVA_RETRIES", "0")
            .args(["--json", "vuln"])
            .output()
            .expect("run raeva vuln");

        assert_status(&output, 4, &base_url);
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON envelope");
        assert_eq!(envelope["exit_code"], 4, "{base_url}");
        assert_eq!(envelope["code"], "NETWORK", "{base_url}");
        if base_url == closed_url {
            let error = envelope["error"].as_str().expect("error");
            assert!(error.contains(": connection refused"), "{error}");
        }
    }
    assert!(server.answered() >= 1);
    server.stop();
}

/// Each wait before a retry of an OSV request prints a line on stderr.
#[test]
fn vuln_prints_each_retry_wait() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", format!("{}/v1", closing_server()))
        .env("RAEVA_RETRIES", "1")
        .arg("vuln")
        .output()
        .expect("run raeva vuln");
    assert_status(&output, 4, "OSV closing connections");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("Retrying OSV query")
                && line.contains(" s (attempt 2 of 2): OSV HTTP request failed: ")),
        "{stderr}"
    );
}

#[test]
fn vuln_refuses_a_base_url_that_is_not_http() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    for base_url in ["notaurl", "ftp://osv.example/v1", "http://exa mple/v1"] {
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", base_url)
            .args(["--json", "vuln"])
            .output()
            .expect("run raeva vuln");
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON envelope");
        assert_status(&output, 2, &format!("{base_url}: {envelope}"));
        assert_eq!(envelope["code"], "USAGE", "{base_url}: {envelope}");
        let error = envelope["error"].as_str().expect("error");
        assert!(error.contains("RAEVA_OSV_BASE_URL"), "{error}");
        assert!(!error.contains(base_url), "{error}");
    }
}

#[test]
fn unknown_severity_is_labelled_and_never_only_reports() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let body = r#"{"vulns": [{"id": "OSV-TEST-2", "summary": "no score", "affected": []}]}"#;
    let (base_url, server) = spawn_osv(200, body);

    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &base_url)
        .args(["--json", "vuln"])
        .output()
        .expect("run raeva vuln");
    assert_status(&output, 1, "unknown meets the default threshold");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    let finding = &envelope["data"]["results"][0]["findings"][0];
    assert_eq!(finding["severity"], "Unknown (no CVSS score)");
    assert!(finding["fixed"].is_null(), "{finding}");

    let never = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &base_url)
        .args(["vuln", "--fail-on", "never"])
        .output()
        .expect("run raeva vuln --fail-on never");
    assert_status(&never, 0, "--fail-on never");
    let table = String::from_utf8_lossy(&never.stdout);
    for cell in [
        "Unknown (no CVSS score)",
        "--fail-on never reports these findings and passes.",
    ] {
        assert!(table.contains(cell), "{cell}: {table}");
    }

    let sarif = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &base_url)
        .args(["vuln", "--format", "sarif", "--fail-on", "never"])
        .output()
        .expect("run raeva vuln --format sarif");
    assert_status(&sarif, 0, "sarif with --fail-on never");
    let report: serde_json::Value = serde_json::from_slice(&sarif.stdout).expect("SARIF");
    let result = &report["runs"][0]["results"][0];
    assert_eq!(result["properties"]["severity"], "Unknown (no CVSS score)");
    assert!(result["properties"]["fixedVersion"].is_null(), "{result}");
    server.stop();
}

#[test]
fn never_still_fails_an_incomplete_scan() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let (base_url, server) = spawn_osv(503, "{}");
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &base_url)
        .env("RAEVA_RETRIES", "0")
        .args(["--json", "vuln", "--fail-on", "never"])
        .output()
        .expect("run raeva vuln");
    assert_status(&output, 4, "incomplete scan under --fail-on never");
    server.stop();
}

#[test]
fn triage_checks_the_author_before_scanning() {
    let (project, home) = temp_project();
    let refusing = RefusingPort::bind();
    let output = raeva_command(project.path(), home.path())
        .env(
            "RAEVA_OSV_BASE_URL",
            format!("http://{}/v1", refusing.addr()),
        )
        .args([
            "--json",
            "vuln",
            "triage",
            "OSV-TEST-1",
            "--justification",
            "vulnerable_code_not_in_execute_path",
            "--vex",
            "raeva.vex.json",
        ])
        .output()
        .expect("run raeva vuln triage");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_status(&output, 2, &envelope.to_string());
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("--author")),
        "{envelope}"
    );
    assert!(!project.path().join("raeva.vex.json").exists());
}

fn baseline_lock(
    project: &std::path::Path,
    change: impl FnOnce(&mut rv_lock::Lockfile),
) -> std::path::PathBuf {
    let mut lock = rv_lock::Lockfile::read(&project.join("raeva.lock")).expect("read lock");
    change(&mut lock);
    let path = project.join("base.lock");
    lock.write_atomic(&path).expect("write baseline");
    path
}

fn remove_dependency(lock: &mut rv_lock::Lockfile, artifact: &str) {
    for platform in &mut lock.platforms {
        platform
            .artifacts
            .retain(|a| a.coordinate.artifact_id() != artifact);
        for module in &mut platform.modules {
            module
                .packages
                .retain(|p| p.coordinate.artifact_id() != artifact);
        }
    }
}

#[test]
fn baseline_shared_findings_use_current_osv_data_and_are_reported_as_existing() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let baseline = baseline_lock(project.path(), |_| {});
    // The baseline is an inventory, so neither its POMs nor their current
    // hashes are required. OSV learns both advisories after it was written.
    let detached = tempfile::TempDir::new().expect("baseline directory");
    let detached_baseline = detached.path().join("base.lock");
    std::fs::rename(baseline, &detached_baseline).expect("move baseline");
    let baseline = detached_baseline.to_str().expect("path");
    let (url, server) = spawn_osv(
        200,
        r#"{"vulns":[{"id":"OSV-SHARED","summary":"shared"},{"id":"OSV-RECENT","summary":"recent"}]}"#,
    );
    for format in ["json", "table", "sarif"] {
        let mut command = raeva_command(project.path(), home.path());
        command.env("RAEVA_OSV_BASE_URL", &url);
        if format == "json" {
            command.arg("--json");
        }
        command.args(["vuln", "--baseline", baseline]);
        if format == "sarif" {
            command.args(["--format", "sarif"]);
        }
        let output = command.output().expect("scan baseline");
        assert_status(&output, 0, format);
        if format == "json" {
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let data = &envelope["data"];
            assert_eq!(data["baseline"], baseline);
            assert_eq!(data["threshold_exceeded"], false);
            assert_eq!(data["summary"]["total_vulnerabilities"], 2);
            assert_eq!(data["summary"]["findings_at_or_above_threshold"], 0);
            assert!(
                data["results"][0]["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|f| f["new"] == false)
            );
        } else if format == "sarif" {
            let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let results = sarif["runs"][0]["results"].as_array().unwrap();
            assert_eq!(results.len(), 2);
            assert!(results.iter().all(|r| r["baselineState"] == "unchanged"));
            crate::schemas::assert_schema_valid(
                &crate::schemas::validator(crate::schemas::SARIF_SCHEMA),
                &sarif,
            );
        } else {
            let table = String::from_utf8_lossy(&output.stdout);
            for label in [
                "Baseline",
                "Existing",
                "OSV-SHARED",
                "OSV-RECENT",
                "No new finding",
            ] {
                assert!(table.contains(label), "{label}: {table}");
            }
        }
    }
    assert_eq!(
        server.answered(),
        3,
        "one query per scan for the shared purl"
    );
    server.stop();
}

fn baseline_osv(missing: Option<&'static str>) -> (String, rv_test_support::http::StubServer) {
    use rv_test_support::http::{Response, StubServer};
    use serde_json::{Value, json};
    let server = StubServer::start(move |request| {
        let ok = |value: Value| {
            Response::new(200, value.to_string()).header("Content-Type", "application/json")
        };
        let ids = |purl: &str| {
            let mut ids = vec!["OSV-SHARED"];
            if purl.contains("/new-lib@") {
                ids.push("OSV-NEW");
            }
            if missing.is_some_and(|name| purl.contains(name)) {
                ids.push("OSV-MISSING");
            }
            ids
        };
        let record = |id| json!({"id": id, "summary": "test advisory", "severity": [{"type": "CVSS_V3", "score": "9.8"}]});
        match request.path.as_str() {
            "/v1/querybatch" => {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let results: Vec<_> = body["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| {
                        let vulns: Vec<_> = ids(q["package"]["purl"].as_str().unwrap())
                            .into_iter()
                            .map(|id| json!({"id": id}))
                            .collect();
                        json!({"vulns": vulns})
                    })
                    .collect();
                ok(json!({"results": results}))
            }
            "/v1/query" => {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let vulns: Vec<_> = ids(body["package"]["purl"].as_str().unwrap())
                    .into_iter()
                    .map(record)
                    .collect();
                ok(json!({"vulns": vulns}))
            }
            "/v1/vulns/OSV-SHARED" => ok(record("OSV-SHARED")),
            "/v1/vulns/OSV-NEW" => ok(record("OSV-NEW")),
            _ => Response::new(404, "{}"),
        }
    });
    (format!("http://{}/v1", server.addr()), server)
}

#[test]
fn baseline_gates_new_dependency_advisories_and_queries_only_the_current_inventory() {
    let (project, home) = temp_project();
    write_demo_lock(
        project.path(),
        home.path(),
        &[
            ("demo-lib", "jar", None, Scope::Compile),
            ("new-lib", "jar", None, Scope::Compile),
            ("removed-lib", "jar", None, Scope::Compile),
        ],
        Vec::new(),
    );
    let baseline = baseline_lock(project.path(), |lock| remove_dependency(lock, "new-lib"));
    let current = project.path().join("raeva.lock");
    let mut lock = rv_lock::Lockfile::read(&current).unwrap();
    remove_dependency(&mut lock, "removed-lib");
    lock.write_atomic(&current).unwrap();
    let (url, server) = baseline_osv(None);
    for format in ["json", "table", "sarif"] {
        let mut command = raeva_command(project.path(), home.path());
        command.env("RAEVA_OSV_BASE_URL", &url);
        if format == "json" {
            command.arg("--json");
        }
        command.arg("vuln").arg("--baseline").arg(&baseline);
        if format == "sarif" {
            command.args(["--format", "sarif"]);
        }
        let output = command.output().expect("scan baseline");
        assert_status(&output, 1, format);
        if format == "json" {
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let data = &envelope["data"];
            assert_eq!(data["complete"], true);
            assert_eq!(data["summary"]["total_dependencies"], 2);
            assert_eq!(data["summary"]["vulnerable_dependencies"], 2);
            assert_eq!(data["summary"]["total_vulnerabilities"], 3);
            assert_eq!(data["summary"]["critical"], 3);
            assert_eq!(data["summary"]["findings_at_or_above_threshold"], 2);
            let results = data["results"].as_array().unwrap();
            assert_eq!(results[0]["findings"][0]["new"], false);
            assert!(
                results[1]["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|f| f["new"] == true)
            );
        } else if format == "sarif" {
            let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let results = sarif["runs"][0]["results"].as_array().unwrap();
            assert_eq!(
                results
                    .iter()
                    .filter(|r| r["baselineState"] == "new")
                    .count(),
                2
            );
            assert_eq!(
                results
                    .iter()
                    .filter(|r| r["baselineState"] == "unchanged")
                    .count(),
                1
            );
        } else {
            let table = String::from_utf8_lossy(&output.stdout);
            for label in ["New", "Existing", "OSV-NEW", "new-lib"] {
                assert!(table.contains(label), "{label}: {table}");
            }
            assert!(!table.contains("removed-lib"), "{table}");
        }
    }
    let requests = server.requests();
    for batch in requests.iter().filter(|r| r.path == "/v1/querybatch") {
        let body: serde_json::Value = serde_json::from_slice(&batch.body).unwrap();
        let purls: Vec<_> = body["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| q["package"]["purl"].as_str().unwrap())
            .collect();
        assert_eq!(purls.len(), 2);
        assert!(!purls.iter().any(|purl| purl.contains("removed-lib")));
    }
    assert_eq!(
        requests.len(),
        9,
        "one batch and two advisory fetches per scan"
    );
    server.stop();
}

#[test]
fn baseline_comparison_keeps_versions_and_qualifiers_exact() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let (url, server) = baseline_osv(None);
    for (version, packaging, classifier) in [
        ("1.0.0", "test-jar", Some("tests")),
        ("2.0.0", "jar", Some("tests")),
        ("2.0.0", "test-jar", Some("other")),
    ] {
        let baseline = baseline_lock(project.path(), |lock| {
            let coordinate = rv_maven_types::ArtifactCoord::new(
                "org.example",
                "demo-lib",
                version,
                packaging,
                classifier,
            );
            let platform = &mut lock.platforms[0];
            platform.artifacts[0].coordinate = coordinate.clone();
            platform.modules[0].packages[0].coordinate = coordinate;
        });
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", &url)
            .args(["--json", "vuln", "--baseline"])
            .arg(&baseline)
            .output()
            .unwrap();
        assert_status(
            &output,
            1,
            "changed purl remains affected by the same advisory",
        );
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["data"]["results"][0]["findings"][0]["new"], true);
    }
    assert_eq!(server.requests().len(), 3, "one query per scan");
    server.stop();
}

#[test]
fn baseline_errors_are_explicit_before_any_osv_query() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let baseline = project.path().join("base.lock");
    for invalid in ["missing", "malformed", "empty", "directory"] {
        match invalid {
            "malformed" => std::fs::write(&baseline, "[broken").unwrap(),
            "empty" => std::fs::write(&baseline, "").unwrap(),
            "directory" => {
                std::fs::remove_file(&baseline).unwrap();
                std::fs::create_dir(&baseline).unwrap();
            }
            _ => {}
        }
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", "invalid-url-before-any-request")
            .args(["--json", "vuln", "--fail-on", "never", "--baseline"])
            .arg(&baseline)
            .output()
            .unwrap();
        assert_status(&output, 3, invalid);
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["code"], "INVALID_PROJECT_INPUT");
        let error = envelope["error"].as_str().unwrap();
        assert!(
            error.contains("base.lock") && error.contains("--baseline"),
            "{error}"
        );
    }
}

#[test]
fn only_current_record_failures_make_a_baseline_scan_incomplete() {
    let (project, home) = temp_project();
    write_demo_lock(
        project.path(),
        home.path(),
        &[
            ("demo-lib", "jar", None, Scope::Compile),
            ("kept-lib", "jar", None, Scope::Compile),
            ("removed-lib", "jar", None, Scope::Compile),
        ],
        Vec::new(),
    );
    let baseline = baseline_lock(project.path(), |_| {});
    let current = project.path().join("raeva.lock");
    let mut lock = rv_lock::Lockfile::read(&current).unwrap();
    remove_dependency(&mut lock, "removed-lib");
    lock.write_atomic(&current).unwrap();
    for missing in ["demo-lib", "removed-lib"] {
        let (url, server) = baseline_osv(Some(missing));
        let current = missing == "demo-lib";
        for format in ["json", "sarif"] {
            let mut command = raeva_command(project.path(), home.path());
            command.env("RAEVA_OSV_BASE_URL", &url);
            if format == "json" {
                command.arg("--json");
            }
            command
                .args(["vuln", "--fail-on", "never", "--baseline"])
                .arg(&baseline);
            if format == "sarif" {
                command.args(["--format", "sarif"]);
            }
            let output = command.output().unwrap();
            assert_status(&output, if current { 2 } else { 0 }, missing);
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            if format == "json" {
                assert_eq!(value["data"]["complete"], !current);
                assert_eq!(value["data"]["threshold_exceeded"], false);
                assert_eq!(value["data"]["results"][0]["findings"][0]["new"], false);
                if current {
                    assert_eq!(value["data"]["failed_records"][0]["id"], "OSV-MISSING");
                }
            } else {
                let failed = &value["runs"][0]["invocations"][0]["executionSuccessful"];
                assert_eq!(failed == false, current);
                assert_eq!(value["runs"][0]["results"][0]["baselineState"], "unchanged");
            }
        }
        assert!(
            !(server.requests().iter())
                .any(|request| String::from_utf8_lossy(&request.body).contains("removed-lib")),
            "a dependency only the baseline has is not queried"
        );
        server.stop();
    }
}

#[test]
fn baseline_new_findings_keep_vex_suppression_and_labels() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let baseline = baseline_lock(project.path(), |lock| remove_dependency(lock, "demo-lib"));
    let vex = project.path().join("vex.json");
    std::fs::write(
        &vex,
        serde_json::json!({
            "@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:uuid:baseline-test",
            "author": "Fixture", "timestamp": "2026-10-01T00:00:00Z", "version": 1,
            "statements": [{
                "vulnerability": {"name": "OSV-SHARED"},
                "products": [{"@id": "pkg:maven/com.example/demo", "subcomponents": [{
                    "@id": "pkg:maven/org.example/demo-lib@2.0.0?classifier=tests&type=test-jar"
                }]}],
                "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"
            }]
        })
        .to_string(),
    )
    .unwrap();
    let (url, server) = baseline_osv(None);
    for format in ["json", "sarif", "table"] {
        let mut command = raeva_command(project.path(), home.path());
        command.env("RAEVA_OSV_BASE_URL", &url);
        if format == "json" {
            command.arg("--json");
        }
        command
            .arg("vuln")
            .arg("--baseline")
            .arg(&baseline)
            .arg("--vex")
            .arg(&vex);
        if format == "sarif" {
            command.args(["--format", "sarif"]);
        }
        let output = command.output().unwrap();
        assert_status(&output, 0, "VEX suppresses a new finding");
        if format == "table" {
            let text = String::from_utf8_lossy(&output.stdout);
            for label in ["Suppressed by VEX", "Baseline", "New", "OSV-SHARED"] {
                assert!(text.contains(label), "{label}: {text}");
            }
        } else {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            if format == "json" {
                assert_eq!(value["data"]["results"][0]["findings"][0]["new"], true);
                assert_eq!(value["data"]["summary"]["suppressed"], 1);
                assert_eq!(
                    value["data"]["summary"]["findings_at_or_above_threshold"],
                    0
                );
            } else {
                let result = &value["runs"][0]["results"][0];
                assert_eq!(result["baselineState"], "new");
                assert_eq!(result["suppressions"][0]["status"], "accepted");
            }
        }
    }
    server.stop();
}

#[test]
fn baseline_ignores_module_paths_but_keeps_scope_filtering() {
    let (project, home) = temp_project();
    write_demo_lock(project.path(), home.path(), DEMO, Vec::new());
    let (url, server) = baseline_osv(None);
    for test_only in [false, true] {
        let baseline = baseline_lock(project.path(), |lock| {
            let module = &mut lock.platforms[0].modules[0];
            module.path = "old/pom.xml".to_string();
            if test_only {
                module.packages[0].scope = Scope::Test;
                module.packages[0].direct_scope = Some(Scope::Test);
            }
        });
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", &url)
            .args(["--json", "vuln", "--module", "pom.xml", "--baseline"])
            .arg(&baseline)
            .output()
            .unwrap();
        assert_status(&output, i32::from(test_only), "baseline module inventory");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            envelope["data"]["results"][0]["findings"][0]["new"],
            test_only
        );
    }
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &url)
        .args(["--json", "vuln", "--include-test", "--baseline"])
        .arg(project.path().join("base.lock"))
        .output()
        .unwrap();
    assert_status(&output, 0, "test scope is included in the baseline too");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["results"][0]["findings"][0]["new"], false);
    assert_eq!(server.answered(), 3);
    server.stop();
}

fn report_matrix(project: &std::path::Path, home: &std::path::Path) {
    std::fs::write(
        project.join("raeva.toml"),
        "[lock]\njdks = [\"17\", \"21\"]\n",
    )
    .unwrap();
    write_demo_lock(
        project,
        home,
        &[
            ("demo-lib", "jar", None, Scope::Compile),
            ("new-lib", "jar", None, Scope::Runtime),
            ("test-lib", "jar", None, Scope::Test),
        ],
        Vec::new(),
    );
    let path = project.join("raeva.lock");
    let mut lock = rv_lock::Lockfile::read(&path).unwrap();
    // Every target reads the same empty POM and profiles. Only its recorded
    // inventory differs, as in write_demo_lock.
    let original = lock.platforms.clone();
    let inventory = original.iter().find(|p| !p.artifacts.is_empty()).unwrap();
    lock.platforms.clear();
    for os in ["windows", "linux"] {
        for jdk in ["21", "17"] {
            let mut target = original
                .iter()
                .find(|p| p.platform.jdk() == Some(jdk))
                .unwrap()
                .clone();
            target.artifacts.clone_from(&inventory.artifacts);
            target.modules.clone_from(&inventory.modules);
            target.platform = rv_lock::Platform::new(os, "x86_64").unwrap().with_jdk(jdk);
            if os != "linux" || jdk != "21" {
                target
                    .artifacts
                    .retain(|a| a.coordinate.artifact_id() != "new-lib");
                target.modules[0]
                    .packages
                    .retain(|p| p.coordinate.artifact_id() != "new-lib");
            }
            lock.platforms.push(target);
        }
    }
    lock.write_atomic(&path).unwrap();
}

#[test]
fn vuln_selects_platforms_and_jdks_or_scans_the_whole_lock_once() {
    let (project, home) = temp_project();
    report_matrix(project.path(), home.path());
    let (url, server) = baseline_osv(None);
    for (args, targets, dependencies, findings) in [
        (vec![], 4, 2, 3),
        (vec!["--platform", "windows-x86_64"], 2, 1, 1),
        (vec!["--jdk", "17"], 2, 1, 1),
        (vec!["--platform", "linux-x86_64", "--jdk", "21"], 1, 2, 3),
        (vec!["--include-test"], 4, 3, 4),
    ] {
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", &url)
            .args(["--json", "vuln"])
            .args(&args)
            .output()
            .unwrap();
        assert_status(&output, 1, &format!("{args:?}"));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let data = &value["data"];
        assert_eq!(data["targets"].as_array().unwrap().len(), targets);
        assert_eq!(data["summary"]["total_dependencies"], dependencies);
        assert_eq!(data["summary"]["total_vulnerabilities"], findings);
        assert_eq!(
            data["summary"]["test_only_dependencies"],
            if args.contains(&"--include-test") {
                0
            } else {
                1
            }
        );
        if targets > 1 {
            assert!(data.get("platform").is_none() && data.get("jdk").is_none());
        } else {
            assert_eq!(data["platform"], "linux-x86_64");
            assert_eq!(data["jdk"], "21");
        }
    }
    let requests = server.requests();
    let batch: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        batch["queries"].as_array().unwrap().len(),
        2,
        "shared dependencies queried once across four targets"
    );
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &url)
        .args(["vuln", "--format", "sarif"])
        .output()
        .unwrap();
    assert_status(&output, 1, "whole-lock SARIF");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["runs"][0]["properties"]["targets"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &url)
        .arg("vuln")
        .output()
        .unwrap();
    let notes = String::from_utf8_lossy(&output.stderr);
    for target in [
        "linux-x86_64 and JDK 17",
        "linux-x86_64 and JDK 21",
        "windows-x86_64 and JDK 17",
        "windows-x86_64 and JDK 21",
    ] {
        assert!(notes.contains(target), "{notes}");
    }
    server.stop();
}

#[test]
fn vuln_missing_target_selectors_fail_without_osv_queries() {
    let (project, home) = temp_project();
    report_matrix(project.path(), home.path());
    for (args, asked) in [
        (
            vec!["--platform", "macos-aarch64"],
            "--platform macos-aarch64",
        ),
        (vec!["--jdk", "99"], "--jdk 99"),
        (
            vec!["--platform", "linux-x86_64", "--jdk", "99"],
            "--platform linux-x86_64 and --jdk 99",
        ),
    ] {
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", "invalid-url-before-any-request")
            .args(["--json", "vuln"])
            .args(&args)
            .output()
            .unwrap();
        assert_status(&output, 2, &format!("{args:?}"));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["code"], "USAGE");
        let error = value["error"].as_str().unwrap();
        assert!(
            error.contains(&format!(
                "no recorded target matches {asked}; available targets: "
            )),
            "{error}"
        );
    }
}

#[test]
fn baseline_uses_every_target_and_the_include_test_scope() {
    let (project, home) = temp_project();
    report_matrix(project.path(), home.path());
    let baseline = baseline_lock(project.path(), |lock| {
        let new_lib = lock
            .platforms
            .iter()
            .find(|p| p.platform.os() == "linux" && p.platform.jdk() == Some("21"))
            .unwrap()
            .clone();
        remove_dependency(lock, "new-lib");
        let windows = lock
            .platforms
            .iter_mut()
            .find(|p| p.platform.os() == "windows" && p.platform.jdk() == Some("21"))
            .unwrap();
        windows.artifacts.push(
            new_lib
                .artifacts
                .iter()
                .find(|a| a.coordinate.artifact_id() == "new-lib")
                .unwrap()
                .clone(),
        );
        windows.modules[0].packages.push(
            new_lib.modules[0]
                .packages
                .iter()
                .find(|p| p.coordinate.artifact_id() == "new-lib")
                .unwrap()
                .clone(),
        );
    });
    let (url, server) = baseline_osv(None);
    for (args, status, new) in [
        (vec![], 0, false),
        (vec!["--include-test"], 0, false),
        // new-lib is in the baseline's Windows section only.
        (vec!["--platform", "linux-x86_64", "--jdk", "21"], 0, false),
    ] {
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", &url)
            .args(["--json", "vuln", "--baseline"])
            .arg(&baseline)
            .args(&args)
            .output()
            .unwrap();
        assert_status(&output, status, &format!("{args:?}"));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for result in value["data"]["results"].as_array().unwrap() {
            let purl = result["purl"].as_str().unwrap();
            for finding in result["findings"].as_array().unwrap() {
                assert_eq!(finding["new"], new && purl.contains("/new-lib@"));
            }
        }
    }
    server.stop();
}

#[test]
fn a_baseline_without_the_added_targets_still_compares() {
    let (project, home) = temp_project();
    report_matrix(project.path(), home.path());
    let (url, server) = baseline_osv(None);
    // The pull request adds targets: the baseline has one of them, with or
    // without new-lib.
    for (keep, status, new_lib_is_new) in [("windows", 1, true), ("linux", 0, false)] {
        let baseline = baseline_lock(project.path(), |lock| {
            lock.platforms
                .retain(|p| p.platform.os() == keep && p.platform.jdk() == Some("21"));
            for platform in &mut lock.platforms {
                platform.platform = rv_lock::Platform::new(keep, "aarch64").unwrap();
            }
        });
        let output = raeva_command(project.path(), home.path())
            .env("RAEVA_OSV_BASE_URL", &url)
            .args(["--json", "vuln", "--baseline"])
            .arg(&baseline)
            .output()
            .unwrap();
        assert_status(&output, status, keep);
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for result in value["data"]["results"].as_array().unwrap() {
            let new_lib = result["purl"].as_str().unwrap().contains("/new-lib@");
            for finding in result["findings"].as_array().unwrap() {
                assert_eq!(
                    finding["new"],
                    new_lib && new_lib_is_new,
                    "{keep}: {result}"
                );
            }
        }
    }
    server.stop();
}

#[test]
fn include_test_applies_vex_to_test_dependencies_across_targets() {
    let (project, home) = temp_project();
    report_matrix(project.path(), home.path());
    let baseline = baseline_lock(project.path(), |lock| remove_dependency(lock, "test-lib"));
    let vex = project.path().join("test.vex.json");
    std::fs::write(&vex, serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:uuid:test-scope",
        "author": "Fixture", "timestamp": "2026-10-01T00:00:00Z", "version": 1,
        "statements": [{"vulnerability": {"name": "OSV-SHARED"},
            "products": [{"@id": "pkg:maven/com.example/demo", "subcomponents": [{"@id": "pkg:maven/org.example/test-lib@2.0.0"}]}],
            "status": "not_affected", "justification": "component_not_present"}]
    }).to_string()).unwrap();
    let (url, server) = baseline_osv(None);
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", &url)
        .args(["--json", "vuln", "--include-test", "--baseline"])
        .arg(&baseline)
        .arg("--vex")
        .arg(&vex)
        .output()
        .unwrap();
    assert_status(&output, 0, "only the new test dependency is suppressed");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["summary"]["suppressed"], 1);
    let test = value["data"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["purl"].as_str().unwrap().contains("/test-lib@"))
        .unwrap();
    assert_eq!(test["findings"][0]["new"], true);
    assert_eq!(test["affected_modules"], serde_json::json!(["pom.xml"]));
    assert_eq!(
        test["vex"].as_array().unwrap().len(),
        1,
        "repeated module identity is assessed once"
    );
    server.stop();
}

/// Without raeva.lock there is no scan to fail: the error is the missing
/// lock alone.
#[test]
fn vuln_without_a_lock_says_only_that_it_is_missing() {
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let output = crate::common::run_raeva(project.path(), home.path(), &["vuln"]);
    assert_status(&output, 3, "vuln without a lock");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("error: lockfile not found: "),
        "{stderr}"
    );
}
