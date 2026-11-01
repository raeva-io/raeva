//! JSON payload snapshots: the `--json` output of every command, for one
//! success and one representative failure each, compared with the committed
//! files under `test-fixtures/json-payloads/`.
//!
//! Each snapshot holds the exit code and the stdout JSON value after
//! [`normalize`] replaced volatile values (durations, timestamps, temporary
//! paths, the raeva version, the host platform, stub server ports) with
//! placeholders, and sorted the lists whose order varies. Object keys are
//! compared in sorted order, not in the order raeva prints them. stdout must
//! hold exactly one JSON value and stderr must be empty. A payload change is a
//! deliberate act: regenerate with `RAEVA_TEST_BLESS=1 cargo test -p raeva
//! --test cli -- json_payloads` and commit the reviewed diff with the change
//! that caused it.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use rv_test_support::http::{Response, StubServer};
use rv_test_support::net::RefusingPort;
use rv_test_support::{fixtures, golden};
use serde_json::Value;
use tempfile::TempDir;

use crate::common::{
    assert_success, cli_command_dirs, raeva_command, sha256_hex, write_empty_pom, write_repo_toml,
};

/// Snapshot names a case below writes, from each `Env::check` call in this file.
fn snapshot_names() -> Vec<String> {
    let mut names =
        fixtures::quoted_after(include_str!("json_payloads.rs"), concat!(".check", "("));
    names.sort();
    names
}

fn snapshot_path(name: &str) -> PathBuf {
    fixtures::path("json-payloads").join(format!("{name}.json"))
}

/// One temporary directory holding the project, the Raeva home and every
/// other path a command may print, so [`normalize`] replaces a single root.
struct Env {
    base: TempDir,
    ports: Vec<u16>,
}

impl Env {
    fn new() -> Self {
        let base = TempDir::new().expect("temp base");
        fs::create_dir_all(base.path().join("home")).expect("create home");
        fs::create_dir_all(base.path().join("project")).expect("create project");
        Self {
            base,
            ports: Vec::new(),
        }
    }

    fn project(&self) -> PathBuf {
        self.base.path().join("project")
    }

    fn home(&self) -> PathBuf {
        self.base.path().join("home")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = raeva_command(&self.project(), &self.home());
        cmd.arg("--json").args(args);
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run raeva")
    }

    fn single_module_project(&self) {
        let fixture = fixtures::path("lock-golden");
        fixtures::copy_tree_lf(&fixture.join("single-module/project"), &self.project());
        fixtures::copy_tree_lf(
            &fixture.join("repository"),
            &self.project().join("repository"),
        );
    }

    fn synced_project(&self) {
        self.single_module_project();
        assert_success(
            &self.run(&["sync", "--offline", "--platforms", &host_platform()]),
            "fixture sync",
        );
    }

    fn stub(
        &mut self,
        handler: impl Fn(&rv_test_support::http::Request) -> Response + Send + Sync + 'static,
    ) -> StubServer {
        let server = StubServer::start(handler);
        self.ports.push(server.addr().port());
        server
    }

    fn refusing_port(&mut self) -> RefusingPort {
        let port = RefusingPort::bind();
        self.ports.push(port.addr().port());
        port
    }

    /// Compare `output` with the snapshot `name`.
    fn check(&self, name: &str, output: &Output) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.is_empty(),
            "{name}: stderr must be empty under --json, got:\n{stderr}"
        );
        let value: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
            panic!("{name}: stdout is not exactly one JSON value ({err}):\n{stdout}")
        });
        let snapshot = serde_json::json!({
            "exit_code": output.status.code(),
            "stdout": normalize(value, &self.replacements()),
        });
        let mut text = serde_json::to_string_pretty(&snapshot).expect("serialize snapshot");
        text.push('\n');
        golden::assert_golden(&snapshot_path(name), &text);
    }

    /// Literal text to replace in every string, longest first.
    fn replacements(&self) -> Vec<(String, String)> {
        let mut roots = vec![self.base.path().to_path_buf()];
        if let Ok(canonical) = dunce::canonicalize(self.base.path()) {
            roots.push(canonical);
        }
        if let Ok(canonical) = fs::canonicalize(self.base.path()) {
            roots.push(canonical);
        }
        let mut replacements = Vec::new();
        for root in roots {
            let text = root.to_string_lossy().into_owned();
            replacements.push((text.replace('\\', "/"), "<tmp>".to_string()));
            replacements.push((text, "<tmp>".to_string()));
        }
        for port in &self.ports {
            replacements.push((format!("127.0.0.1:{port}"), "127.0.0.1:<port>".to_string()));
        }
        replacements.push((
            format!("on platform {}", host_platform()),
            "on platform <host-platform>".to_string(),
        ));
        replacements.sort_by(|left, right| right.0.len().cmp(&left.0.len()));
        replacements.dedup();
        replacements
    }
}

fn host_platform() -> String {
    rv_lock::Platform::current()
        .expect("host platform")
        .to_string()
}

/// Keys whose values change from run to run, replaced by a placeholder that
/// still records the value's JSON type.
const VOLATILE_KEYS: &[&str] = &["duration_ms", "last_modified", "query_timestamp"];

/// The SBOM serial number: a UUID derived from the raeva version and the
/// platform as well as the content, so it changes with every release and
/// differs between hosts. The text around the UUID is kept.
const IDENTITY_KEYS: &[&str] = &["serialNumber"];

fn replace_trailing_uuid(value: Value) -> Value {
    let Value::String(text) = value else {
        return value;
    };
    let split = text.len().saturating_sub(36);
    let (prefix, uuid) = text.split_at(split);
    let is_uuid = uuid.len() == 36
        && uuid.char_indices().all(|(index, c)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    Value::String(if is_uuid {
        format!("{prefix}<document-identity>")
    } else {
        text
    })
}

/// Lists whose order is not stable from run to run, sorted before
/// comparison. Warnings are collected from concurrent work, and `raeva lock
/// verify` lists failures in the order its unordered parallel checks finish.
const UNORDERED_KEYS: &[&str] = &[
    "corrupt_artifacts",
    "missing_artifacts",
    "no_checksum_artifacts",
    "pin_mismatch_artifacts",
    "untrusted_origin_artifacts",
    "warnings",
];

fn placeholder(value: &Value) -> Value {
    Value::String(
        match value {
            Value::Null => "<null>",
            Value::Bool(_) => "<bool>",
            Value::Number(_) => "<number>",
            Value::String(_) => "<string>",
            Value::Array(_) => "<array>",
            Value::Object(_) => "<object>",
        }
        .to_string(),
    )
}

fn normalize(value: Value, replacements: &[(String, String)]) -> Value {
    match value {
        Value::String(text) => Value::String(normalize_string(text, replacements)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| normalize(item, replacements))
                .collect(),
        ),
        Value::Object(map) => {
            // An SBOM names the platform as the value of its `raeva:target`
            // property.
            let target = map.get("name").and_then(Value::as_str) == Some("raeva:target");
            Value::Object(
                map.into_iter()
                    .map(|(key, value)| {
                        let value = if VOLATILE_KEYS.contains(&key.as_str()) {
                            placeholder(&value)
                        } else if (key == "platform" || (target && key == "value"))
                            && value.as_str() == Some(&host_platform())
                        {
                            Value::String("<host-platform>".to_string())
                        } else if IDENTITY_KEYS.contains(&key.as_str()) {
                            replace_trailing_uuid(value)
                        } else if UNORDERED_KEYS.contains(&key.as_str()) {
                            sort_array(normalize(value, replacements))
                        } else {
                            normalize(value, replacements)
                        };
                        (key, value)
                    })
                    .collect(),
            )
        }
        other => other,
    }
}

fn normalize_string(text: String, replacements: &[(String, String)]) -> String {
    if text == env!("CARGO_PKG_VERSION") {
        return "<raeva-version>".to_string();
    }
    let mut out = text;
    for (from, to) in replacements {
        out = out.replace(from.as_str(), to);
    }
    slash_tmp_paths(&out)
}

/// Turn `\` into `/` in each path under the temporary root, which uses the
/// host's separators. A path ends at whitespace or at a quote, bracket or
/// comma; separators elsewhere in the text are kept.
fn slash_tmp_paths(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("<tmp>") {
        out.push_str(&rest[..start]);
        let path = &rest[start..];
        let end = path
            .find(|c: char| c.is_whitespace() || "'\"`()[],".contains(c))
            .unwrap_or(path.len());
        out.push_str(&path[..end].replace('\\', "/"));
        rest = &path[end..];
    }
    out.push_str(rest);
    out
}

fn sort_array(value: Value) -> Value {
    match value {
        Value::Array(mut items) => {
            items.sort_by_key(|item| item.to_string());
            Value::Array(items)
        }
        other => other,
    }
}

/// Deleting or adding a snapshot file, including one nested deeper or at the
/// root, must fail here until a case writes it. `.gitattributes` is required
/// so Git keeps LF.
#[test]
fn every_snapshot_file_has_a_case() {
    let root = fixtures::path("json-payloads");
    let mut found = Vec::new();
    let mut has_gitattributes = false;
    for rel in fixtures::sorted_relative_files(&root) {
        if rel == ".gitattributes" {
            has_gitattributes = true;
            continue;
        }
        if let Some(stem) = rel.strip_suffix(".json") {
            found.push(stem.to_string());
        } else {
            panic!("unexpected file in json-payloads: {rel}");
        }
    }
    assert!(
        has_gitattributes,
        "json-payloads needs .gitattributes so Git keeps LF"
    );
    assert_eq!(
        found,
        snapshot_names(),
        "snapshot files and Env::check names differ"
    );
}

/// Adding a command must fail here until it has a `json-payloads/` directory
/// with a success snapshot and a failure snapshot. An empty directory, a
/// single file, or a nested directory does not count.
#[test]
fn every_command_has_json_payload_snapshots() {
    let root = fixtures::path("json-payloads");
    let found = fixtures::sorted_child_names(&root, |path| path.is_dir());
    assert_eq!(
        found,
        cli_command_dirs(),
        "json-payloads dirs and CLI commands differ"
    );
    for command in &found {
        let dir = root.join(command);
        let files = fixtures::sorted_child_names(&dir, |path| path.is_file());
        assert!(
            files.len() >= 2,
            "{command} needs a success snapshot and a failure snapshot"
        );
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        fixtures::assert_children(&dir, &[], &files);
    }
}

/// `##` heading in docs/json-output.md that names this command. `lock-info`
/// is `raeva lock info`; hyphenated commands keep the hyphen. Tree and why
/// share a heading.
fn command_json_heading<'a>(docs: &'a str, command: &str) -> Option<&'a str> {
    let needles = [
        format!("`raeva {command}`"),
        format!("`raeva {}`", command.replace('-', " ")),
    ];
    fixtures::markdown_prose_lines(docs)
        .into_iter()
        .find(|line| line.starts_with("## ") && needles.iter().any(|needle| line.contains(needle)))
}

/// `json!({ "field": ... })` keys in the command's `to_json` source, so a
/// field that only appears when a list is non-empty still counts. Files are
/// `raeva/src/commands/<command>.rs` and every `.rs` file under
/// `<command>/` that implements `to_json`, with hyphens turned into
/// underscores, so a new command file is included. Tree and why serialize
/// structs; their skip_serializing_if fields are checked next to those
/// structs. SARIF is a document, not the envelope.
fn command_json_source(command: &str) -> Option<String> {
    let stem = command.replace('-', "_");
    let file = format!("raeva/src/commands/{stem}.rs");
    let dir = format!("raeva/src/commands/{stem}/");
    let mut source = String::new();
    for (rel, text) in fixtures::workspace_production_sources() {
        if rel != file && !rel.starts_with(&dir) {
            continue;
        }
        let kept = fixtures::without_inline_test_module(&text);
        if kept.contains("fn to_json") {
            source.push_str(&kept);
            source.push('\n');
        }
    }
    if source.is_empty() {
        return None;
    }
    Some(
        source
            .split("fn sarif_report")
            .next()
            .unwrap_or(&source)
            .to_string(),
    )
}

/// docs/json-output.md names every `data` key each command prints, including
/// nested objects. `warnings` is the envelope list, checked separately.
/// `vulnerabilities` holds OSV records. A command whose snapshots print a
/// document, and whose source has no envelope `json!`, is skipped.
#[test]
fn the_docs_name_each_command_json_fields() {
    let docs = fixtures::workspace_file("docs/json-output.md");
    for command in cli_command_dirs() {
        let mut keys = std::collections::BTreeSet::new();
        let dir = fixtures::path("json-payloads").join(&command);
        for name in fixtures::sorted_child_names(&dir, |path| {
            path.extension().is_some_and(|ext| ext == "json")
        }) {
            let snapshot: Value =
                serde_json::from_str(&std::fs::read_to_string(dir.join(&name)).expect("snapshot"))
                    .expect("parse snapshot");
            collect_payload_keys(&snapshot["stdout"]["data"], &mut keys);
        }
        if let Some(source) = command_json_source(&command) {
            keys.extend(fixtures::json_macro_keys(&source));
        }
        keys.remove("warnings");
        if keys.is_empty() {
            continue;
        }
        let heading = command_json_heading(&docs, &command)
            .unwrap_or_else(|| panic!("docs/json-output.md has no section for {command}"));
        let section = fixtures::markdown_section(&docs, heading);
        fixtures::assert_markdown_names(section, &format!("docs/json-output.md {heading}"), &keys);
    }
}

fn collect_payload_keys(value: &Value, keys: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                keys.insert(key.clone());
                if key != "warnings" && key != "vulnerabilities" {
                    collect_payload_keys(child, keys);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_payload_keys(item, keys);
            }
        }
        _ => {}
    }
}

#[test]
fn normalize_replaces_volatile_values() {
    let replacements = vec![("/tmp/x".to_string(), "<tmp>".to_string())];
    let value = serde_json::json!({
        "duration_ms": 12,
        "error": "cannot read /tmp/x\\project\\raeva.lock (a\\b)",
        "path": "/tmp/x/project/raeva.lock",
        "platform": host_platform(),
        "target": host_platform(),
        "warnings": [{"code": "B"}, {"code": "A"}],
        "version": env!("CARGO_PKG_VERSION"),
    });
    assert_eq!(
        normalize(value, &replacements),
        serde_json::json!({
            "duration_ms": "<number>",
            "error": "cannot read <tmp>/project/raeva.lock (a\\b)",
            "path": "<tmp>/project/raeva.lock",
            "platform": "<host-platform>",
            "target": host_platform(),
            "warnings": [{"code": "A"}, {"code": "B"}],
            "version": "<raeva-version>",
        })
    );
}

// sync

#[test]
fn sync_success() {
    let env = Env::new();
    env.single_module_project();
    let output = env.run(&["sync", "--offline", "--platforms", "linux-x86_64"]);
    env.check("sync/success", &output);
}

#[test]
fn sync_frozen_mismatch() {
    let env = Env::new();
    env.synced_project();
    let pom = env.project().join("pom.xml");
    let text = fs::read_to_string(&pom).expect("read pom.xml");
    fs::write(
        &pom,
        text.replace("<scope>runtime</scope>", "<scope>compile</scope>"),
    )
    .expect("write pom.xml");
    let output = env.run(&["sync", "--frozen", "--offline"]);
    env.check("sync/frozen-mismatch", &output);
}

// tree and why

#[test]
fn tree_success() {
    let env = Env::new();
    env.synced_project();
    env.check("tree/success", &env.run(&["tree"]));
}

#[test]
fn tree_unknown_module() {
    let env = Env::new();
    env.synced_project();
    env.check(
        "tree/unknown-module",
        &env.run(&["tree", "--module", "org.golden:missing"]),
    );
}

#[test]
fn why_success() {
    let env = Env::new();
    env.synced_project();
    env.check("why/success", &env.run(&["why", "org.golden:util"]));
}

#[test]
fn why_not_found() {
    let env = Env::new();
    env.synced_project();
    env.check("why/not-found", &env.run(&["why", "org.golden:absent"]));
}

// lock verify and lock info

#[test]
fn lock_verify_success() {
    let env = Env::new();
    env.synced_project();
    env.check("lock-verify/success", &env.run(&["lock", "verify"]));
}

#[test]
fn lock_verify_missing_blobs() {
    let env = Env::new();
    env.synced_project();
    fs::remove_dir_all(env.home()).expect("remove the store");
    fs::create_dir_all(env.home()).expect("recreate home");
    env.check("lock-verify/missing-blobs", &env.run(&["lock", "verify"]));
}

#[test]
fn lock_info_success() {
    let env = Env::new();
    env.synced_project();
    env.check("lock-info/success", &env.run(&["lock", "info"]));
}

#[test]
fn lock_info_no_lock() {
    let env = Env::new();
    write_empty_pom(&env.project().join("pom.xml"));
    env.check("lock-info/no-lock", &env.run(&["lock", "info"]));
}

#[test]
fn lock_diff_success() {
    let env = Env::new();
    let old = env.project().join("old.lock");
    for (fixture, destination) in [
        ("lock-golden/snapshot/raeva.lock", old.clone()),
        ("lock-diff/snapshot.lock", env.project().join("raeva.lock")),
    ] {
        let text = fs::read_to_string(fixtures::path(fixture)).unwrap();
        fs::write(destination, text.replace("linux-x86_64", &host_platform())).unwrap();
    }
    env.check(
        "lock-diff/success",
        &env.run(&["lock", "diff", old.to_str().unwrap()]),
    );
}

#[test]
fn lock_diff_invalid() {
    let env = Env::new();
    let old = env.project().join("old.lock");
    fs::copy(fixtures::path("lock-golden/snapshot/raeva.lock"), &old).unwrap();
    fs::write(env.project().join("raeva.lock"), "not valid TOML").unwrap();
    env.check(
        "lock-diff/invalid",
        &env.run(&["lock", "diff", old.to_str().unwrap()]),
    );
}

// export-m2 and export-checksums

#[test]
fn export_m2_dry_run() {
    let env = Env::new();
    env.synced_project();
    let m2 = env.base.path().join("m2");
    let output = env.run(&[
        "export-m2",
        "--dry-run",
        "--m2-path",
        m2.to_str().expect("utf-8"),
    ]);
    env.check("export-m2/dry-run", &output);
    assert!(!m2.exists(), "a dry run must not create the repository");
}

#[test]
fn export_m2_no_lock() {
    let env = Env::new();
    write_empty_pom(&env.project().join("pom.xml"));
    let m2 = env.base.path().join("m2");
    let output = env.run(&[
        "export-m2",
        "--dry-run",
        "--m2-path",
        m2.to_str().expect("utf-8"),
    ]);
    env.check("export-m2/no-lock", &output);
}

#[test]
fn export_checksums_success() {
    let env = Env::new();
    env.synced_project();
    env.check("export-checksums/success", &env.run(&["export-checksums"]));
}

#[test]
fn export_checksums_no_lock() {
    let env = Env::new();
    write_empty_pom(&env.project().join("pom.xml"));
    env.check("export-checksums/no-lock", &env.run(&["export-checksums"]));
}

// sbom

#[test]
fn sbom_cyclonedx() {
    let env = Env::new();
    env.synced_project();
    env.check("sbom/cyclonedx", &env.run(&["sbom"]));
}

#[test]
fn sbom_no_lock() {
    let env = Env::new();
    write_empty_pom(&env.project().join("pom.xml"));
    env.check("sbom/no-lock", &env.run(&["sbom"]));
}

// vuln against a stub OSV server

/// OSV answers that report one advisory for `org.golden:util:1.0` and none
/// for any other package, whatever order the batch lists them in.
fn osv_handler(request: &rv_test_support::http::Request) -> Response {
    let json = |body: String| Response::new(200, body).header("Content-Type", "application/json");
    match request.path.as_str() {
        "/v1/querybatch" => {
            let body: Value = serde_json::from_slice(&request.body).expect("querybatch body");
            let results: Vec<Value> = body["queries"]
                .as_array()
                .expect("queries")
                .iter()
                .map(|query| {
                    let purl = query["package"]["purl"].as_str().unwrap_or_default();
                    if purl.starts_with("pkg:maven/org.golden/util@1.0") {
                        serde_json::json!({"vulns": [{"id": "GOLDEN-2024-1"}]})
                    } else {
                        serde_json::json!({})
                    }
                })
                .collect();
            json(serde_json::json!({ "results": results }).to_string())
        }
        "/v1/query" => {
            let body: Value = serde_json::from_slice(&request.body).expect("query body");
            let purl = body["package"]["purl"].as_str().unwrap_or_default();
            if purl.starts_with("pkg:maven/org.golden/util@1.0") {
                json(serde_json::json!({"vulns": [golden_advisory()]}).to_string())
            } else {
                json("{}".to_string())
            }
        }
        "/v1/vulns/GOLDEN-2024-1" => json(golden_advisory().to_string()),
        _ => Response::new(404, ""),
    }
}

fn golden_advisory() -> Value {
    serde_json::json!({
        "id": "GOLDEN-2024-1",
        "summary": "fixture advisory for org.golden:util",
        "modified": "2024-01-01T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"ecosystem": "Maven", "name": "org.golden:util"},
            "versions": ["1.0"]
        }],
        "references": [{"type": "ADVISORY", "url": "https://example.com/GOLDEN-2024-1"}]
    })
}

#[test]
fn vuln_findings() {
    let mut env = Env::new();
    env.synced_project();
    let server = env.stub(osv_handler);
    let output = env
        .command(&["vuln"])
        .env("RAEVA_OSV_BASE_URL", format!("http://{}/v1", server.addr()))
        .output()
        .expect("run raeva vuln");
    env.check("vuln/findings", &output);
    server.stop();
}

/// util, suppressed by a `--vex` statement for the module.
#[test]
fn vuln_vex_suppressed() {
    let mut env = Env::new();
    env.synced_project();
    let vex = env.project().join("vex.json");
    let statement = serde_json::json!({
        "vulnerability": {"name": "GOLDEN-2024-1"},
        "products": [{
            "@id": "pkg:maven/org.golden.app/single@1.0",
            "subcomponents": [{"@id": "pkg:maven/org.golden/util@1.0"}],
        }],
        "status": "not_affected",
        "justification": "inline_mitigations_already_exist",
        "impact_statement": "input is validated before it reaches util",
    });
    let document = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:uuid:fixture",
        "author": "Fixture",
        "timestamp": "2026-10-01T00:00:00Z",
        "version": 1,
        "statements": [statement],
    });
    fs::write(&vex, document.to_string()).expect("write VEX");
    let server = env.stub(osv_handler);
    let output = env
        .command(&["vuln", "--vex", vex.to_str().expect("path")])
        .env("RAEVA_OSV_BASE_URL", format!("http://{}/v1", server.addr()))
        .output()
        .expect("run raeva vuln");
    env.check("vuln/vex-suppressed", &output);
    server.stop();
}

#[test]
fn vuln_triage() {
    let mut env = Env::new();
    env.synced_project();
    let vex = env.project().join("vex.json");
    let server = env.stub(osv_handler);
    let output = env
        .command(&[
            "vuln",
            "triage",
            "GOLDEN-2024-1",
            "--justification",
            "vulnerable_code_not_present",
            "--vex",
            vex.to_str().expect("path"),
            "--author",
            "Fixture",
        ])
        .env("RAEVA_OSV_BASE_URL", format!("http://{}/v1", server.addr()))
        .output()
        .expect("run raeva vuln triage");
    env.check("vuln/triage", &output);
    server.stop();
}

#[test]
fn vuln_osv_error() {
    let mut env = Env::new();
    env.synced_project();
    let server = env.stub(|_| Response::new(400, "bad request"));
    let output = env
        .command(&["vuln"])
        .env("RAEVA_OSV_BASE_URL", format!("http://{}/v1", server.addr()))
        .output()
        .expect("run raeva vuln");
    env.check("vuln/osv-error", &output);
    server.stop();
}

// doctor against stub repositories

#[test]
fn doctor_reachable() {
    let mut env = Env::new();
    write_empty_pom(&env.project().join("pom.xml"));
    let metadata = "<metadata><groupId>org.apache</groupId><artifactId>maven</artifactId>\
                    <versioning><versions><version>1.0</version></versions></versioning></metadata>";
    let server = env.stub(move |request| match request.path.as_str() {
        "/maven2/org/apache/maven/maven-metadata.xml" => Response::new(200, metadata),
        "/maven2/org/apache/maven/maven-metadata.xml.sha256" => {
            Response::new(200, sha256_hex(metadata.as_bytes()))
        }
        _ => Response::new(404, ""),
    });
    write_repo_toml(
        &env.project(),
        "stub",
        &format!("http://{}/maven2/", server.addr()),
    );
    env.check("doctor/reachable", &env.run(&["doctor"]));
    server.stop();
}

#[test]
fn doctor_unreachable() {
    let mut env = Env::new();
    let refusing = env.refusing_port();
    write_repo_toml(
        &env.project(),
        "unreachable",
        &format!("http://{}/maven2/", refusing.addr()),
    );
    let output = env.run(&["doctor"]);
    env.check("doctor/unreachable", &output);
}
