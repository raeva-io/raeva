mod common;

use std::collections::BTreeMap;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;

use common::{rv_command, temp_project};
use rv_config::{Checksum, LockPackage, LockPlatform, Lockfile};

fn push_package(platform: &mut LockPlatform, package: LockPackage) {
    let module = platform.modules.first().expect("generated module");
    let mut converted = LockPlatform::single_module(
        platform.platform.clone(),
        platform.model_hash.clone(),
        &module.path,
        module.gav.clone(),
        &module.packaging,
        vec![package],
        Vec::new(),
    );
    platform.modules[0]
        .packages
        .append(&mut converted.modules[0].packages);
    platform.artifacts.append(&mut converted.artifacts);
}

fn write_pom(project_root: &Path, version: &str) {
    fs::write(
        project_root.join("pom.xml"),
        format!(
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>{version}</version>
</project>
"#
        ),
    )
    .expect("write pom.xml");
}

fn write_fresh_lock(project_root: &Path, home: &Path) {
    write_pom(project_root, "1.0.0");
    let output = rv_command(project_root, home)
        .args(["--quiet", "sync", "--offline"])
        .output()
        .expect("run rv sync");
    assert!(
        output.status.success(),
        "sync failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = project_root.join("rv.lock");
    let mut lock = Lockfile::read(&lock_path).expect("read generated lock");
    let platform = lock.platforms.first_mut().expect("generated platform");
    push_package(
        platform,
        LockPackage {
            group_id: "org.example".to_string(),
            artifact_id: "demo-lib".to_string(),
            version: "2.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "test-jar".to_string(),
            classifier: Some("tests".to_string()),
            repo_url: "https://repo.example/maven2".to_string(),
            checksum: Some(Checksum::new(
                "sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
            system_path: None,
            direct_scope: Some("test".to_string()),
            extra: BTreeMap::new(),
        },
    );
    lock.write_atomic(&lock_path).expect("write fixture lock");
}

fn add_locked_dependency(project_root: &Path, artifact_id: &str) {
    let lock_path = project_root.join("rv.lock");
    let mut lock = Lockfile::read(&lock_path).expect("read fixture lock");
    push_package(
        lock.platforms.first_mut().expect("fixture platform"),
        LockPackage {
            group_id: "org.example".to_string(),
            artifact_id: artifact_id.to_string(),
            version: "1.0.0".to_string(),
            snapshot_timestamp: None,
            packaging: "jar".to_string(),
            classifier: None,
            repo_url: "https://repo.example/maven2".to_string(),
            checksum: None,
            system_path: None,
            direct_scope: Some("compile".to_string()),
            extra: BTreeMap::new(),
        },
    );
    lock.write_atomic(&lock_path).expect("write fixture lock");
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    let mut expected_length = None;
    loop {
        let size = stream.read(&mut buffer).expect("read OSV request");
        assert_ne!(size, 0, "OSV request ended before its body was complete");
        request.extend_from_slice(&buffer[..size]);
        if expected_length.is_none()
            && let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("Content-Length"))
                    })
                })
                .unwrap_or(0);
            expected_length = Some(header_end + 4 + content_length);
        }
        if expected_length.is_some_and(|length| request.len() >= length) {
            break;
        }
    }
    String::from_utf8(request).expect("OSV request UTF-8")
}

fn spawn_osv(status: &str, response_body: &'static str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OSV mock");
    let address = listener.local_addr().expect("mock address");
    let status = status.to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept OSV request");
        let request = read_request(&mut stream);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{response_body}",
            response_body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write OSV response");
        request
    });
    (format!("http://{address}/v1"), handle)
}

fn spawn_osv_routes(
    routes: Vec<(&'static str, &'static str)>,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OSV mock");
    let address = listener.local_addr().expect("mock address");
    let total = routes.len();
    let mut routes: HashMap<String, VecDeque<&'static str>> =
        routes
            .into_iter()
            .fold(HashMap::new(), |mut routes, (path, body)| {
                routes.entry(path.to_string()).or_default().push_back(body);
                routes
            });
    let handle = thread::spawn(move || {
        let mut requests = Vec::with_capacity(total);
        for _ in 0..total {
            let (mut stream, _) = listener.accept().expect("accept OSV request");
            let request = read_request(&mut stream);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .expect("request path");
            let body = routes
                .get_mut(path)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| panic!("unexpected OSV path {path}"));
            requests.push(request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write OSV response");
        }
        requests
    });
    (format!("http://{address}/v1"), handle)
}

#[test]
fn vuln_returns_zero_when_scan_has_no_findings() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());
    let (base_url, server) = spawn_osv("200 OK", "{}");

    let output = rv_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .arg("vuln")
        .output()
        .expect("run rv vuln");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("No vulnerabilities found"),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    server.join().expect("OSV server");
}

#[test]
fn vuln_json_reports_findings_and_preserves_qualified_purl() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());
    let body = r#"{
        "vulns": [{
            "id": "OSV-TEST-1",
            "summary": "test vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": []
        }]
    }"#;
    let (base_url, server) = spawn_osv("200 OK", body);

    let output = rv_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["vuln", "--format", "json"])
        .output()
        .expect("run rv vuln");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "stderr must be empty in JSON mode"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["success"], true);
    assert_eq!(envelope["data"]["metadata"]["tool"]["name"], "rv");
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

    let request = server.join().expect("OSV server");
    assert!(
        request.contains("pkg:maven/org.example/demo-lib@2.0.0?classifier=tests&type=test-jar"),
        "request={request}"
    );
}

#[test]
fn vuln_sarif_reports_rules_levels_and_pom_locations() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());
    let body = r#"{
        "vulns": [
            {
                "id": "OSV-CRITICAL",
                "summary": "critical vulnerability",
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                "references": [{"type": "ADVISORY", "url": "https://example.com/critical"}],
                "affected": []
            },
            {
                "id": "OSV-MEDIUM",
                "summary": "medium vulnerability",
                "severity": [{"type": "CVSS_V3", "score": "5.0"}],
                "affected": []
            }
        ]
    }"#;
    let (base_url, server) = spawn_osv("200 OK", body);

    let output = rv_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["vuln", "--format", "sarif"])
        .output()
        .expect("run SARIF scan");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).expect("SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"].as_array().expect("runs").len(), 1);
    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "rv");
    assert_eq!(run["tool"]["driver"]["version"], env!("CARGO_PKG_VERSION"));
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["id"], "OSV-CRITICAL");
    assert_eq!(rules[0]["helpUri"], "https://example.com/critical");
    assert_eq!(rules[1]["id"], "OSV-MEDIUM");
    assert_eq!(
        rules[1]["helpUri"],
        "https://osv.dev/vulnerability/OSV-MEDIUM"
    );

    let results = run["results"].as_array().expect("results");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[1]["level"], "warning");
    for result in results {
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "pom.xml"
        );
        assert!(
            result["locations"][0]["physicalLocation"]
                .get("region")
                .is_none()
        );
        assert_eq!(
            result["properties"]["dependencyPurl"],
            "pkg:maven/org.example/demo-lib@2.0.0?classifier=tests&type=test-jar"
        );
    }
    server.join().expect("OSV server");
}

#[test]
fn vuln_returns_two_when_osv_rejects_the_query() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());
    let (base_url, server) = spawn_osv(
        "400 Bad Request",
        "{\"message\":\"bad\u{1b}[31m\\r\\nquery\"}",
    );

    let output = rv_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["vuln", "--format", "json"])
        .output()
        .expect("run rv vuln");

    assert_eq!(output.status.code(), Some(2));
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
    assert_eq!(
        envelope["data"]["metadata"]["scanner"]["provider"],
        "osv.dev"
    );
    server.join().expect("OSV server");
}

#[test]
fn vuln_returns_two_when_osv_detail_id_does_not_match() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());
    add_locked_dependency(project.path(), "second-lib");
    let batch = r#"{"results":[{"vulns":[{"id":"OSV-A"}]},{"vulns":[]}]}"#;
    let mismatched = r#"{"id":"OSV-B"}"#;
    let (base_url, server) = spawn_osv_routes(vec![
        ("/v1/querybatch", batch),
        ("/v1/vulns/OSV-A", mismatched),
    ]);

    let output = rv_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["vuln", "--format", "json"])
        .output()
        .expect("run rv vuln");

    assert_eq!(output.status.code(), Some(2));
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["success"], false);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|message| message.contains("OSV-A"))
    );
    server.join().expect("OSV server");
}

#[test]
fn vuln_fail_on_threshold_controls_exit_one() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());
    let body = r#"{
        "vulns": [{
            "id": "OSV-MEDIUM",
            "summary": "medium vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "5.0"}],
            "affected": []
        }]
    }"#;
    let (base_url, server) = spawn_osv("200 OK", body);

    let output = rv_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["vuln", "--fail-on", "high"])
        .output()
        .expect("run rv vuln");

    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("0 finding(s) at or above the high"));
    server.join().expect("OSV server");
}

#[test]
fn vuln_unknown_severity_meets_every_fail_on_threshold() {
    let (project, home) = temp_project();
    write_fresh_lock(project.path(), home.path());
    let body = r#"{
        "vulns": [{
            "id": "OSV-UNKNOWN",
            "summary": "unscored vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "not-a-score"}],
            "affected": []
        }]
    }"#;
    let (base_url, server) = spawn_osv("200 OK", body);

    let output = rv_command(project.path(), home.path())
        .env("RAEVA_OSV_BASE_URL", base_url)
        .args(["vuln", "--format", "json", "--fail-on", "critical"])
        .output()
        .expect("run rv vuln");

    assert_eq!(output.status.code(), Some(1));
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["data"]["threshold_exceeded"], true);
    assert_eq!(envelope["data"]["summary"]["unknown"], 1);
    server.join().expect("OSV server");
}

#[test]
fn vuln_maps_missing_and_stale_lockfiles_to_exit_two() {
    let (missing_project, missing_home) = temp_project();
    write_pom(missing_project.path(), "1.0.0");
    let missing = rv_command(missing_project.path(), missing_home.path())
        .arg("vuln")
        .output()
        .expect("run missing-lock scan");
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("lockfile not found"));

    let (stale_project, stale_home) = temp_project();
    write_fresh_lock(stale_project.path(), stale_home.path());
    write_pom(stale_project.path(), "2.0.0");
    let stale = rv_command(stale_project.path(), stale_home.path())
        .arg("vuln")
        .output()
        .expect("run stale-lock scan");
    assert_eq!(stale.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&stale.stderr).contains("out of date"));
}
