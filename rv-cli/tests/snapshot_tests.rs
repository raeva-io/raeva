//! Snapshot tests for --json output of rv commands.
//!
//! These tests verify that the JSON output format of commands like `rv tree --json`
//! and `rv why --json` matches the expected snapshot. They use pre-written lockfiles
//! so no network access is required.

mod common;

use std::fs;

use common::*;

/// Write a minimal rv.lock file with a single dependency for testing.
fn write_minimal_lock(project_root: &std::path::Path) {
    // Use the current platform so `rv tree` can find packages
    let platform = rv_config::Platform::current()
        .map(|p| p.to_string())
        .unwrap_or_else(|_| "linux-x86_64".to_string());

    let lock_content = format!(
        r#"schema_version = 3

[[platforms]]
platform = "{platform}"

[[platforms.packages]]
group_id = "org.slf4j"
artifact_id = "slf4j-api"
version = "2.0.9"
packaging = "jar"
repo_url = "https://repo1.maven.org/maven2"
checksum = {{ algorithm = "sha256", digest = "7cf2726cb3b3cc28c34c8f40fb66e8b3b90e1a04f0490a16df38e49f2b8b6148" }}
direct_scope = "compile"
"#,
    );
    fs::write(project_root.join("rv.lock"), lock_content).expect("write rv.lock");
}

/// Write a minimal rv.toml with a dependency.
fn write_minimal_toml(project_root: &std::path::Path) {
    let toml_content = r#"[project]
group = "com.example"
artifact = "demo"
version = "1.0.0"

[dependencies]
compile = ["org.slf4j:slf4j-api:2.0.9"]
"#;
    fs::write(project_root.join("rv.toml"), toml_content).expect("write rv.toml");
}

/// Parse an envelope `{success: bool, data: ...}` from raw stdout bytes,
/// returning the inner `data` payload.
fn parse_envelope(stdout: &[u8]) -> serde_json::Value {
    let text = std::str::from_utf8(stdout).expect("rv JSON output should be UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(text.trim()).expect("rv JSON output should be valid JSON");
    assert_eq!(
        parsed.get("success").and_then(|v| v.as_bool()),
        Some(true),
        "envelope.success should be true; payload: {text}"
    );
    parsed
        .get("data")
        .cloned()
        .expect("envelope should have a 'data' field")
}

// The earlier `test_tree_json_is_valid_json` and `test_why_json_is_valid_json`
// tests only asserted that `data.get("dependencies").is_some()` and the same
// for `paths`/`found`, which trivially passed on an empty dependency tree or
// `found = false`. They have been folded into the snapshot tests below, which
// pin exact-value shapes so a regression that drops the dependency or breaks
// `why`'s graph walk no longer slips through.

/// `tree --json` against the minimal lockfile must list slf4j-api as the
/// sole top-level dependency with no children.
#[test]
fn test_tree_json_snapshot() {
    let (project, home) = temp_project();
    write_minimal_toml(project.path());
    write_minimal_lock(project.path());

    let output = rv_command(project.path(), home.path())
        .args(["--json", "tree"])
        .output()
        .expect("spawn rv tree");

    assert!(
        output.status.success(),
        "rv tree failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let data = parse_envelope(&output.stdout);

    // `project` is the project directory name (a tempdir); just require a
    // non-empty string. `platform` is the resolved current platform.
    assert!(
        data.get("project")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "project should be a non-empty string, payload: {data}"
    );
    assert!(
        data.get("platform")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "platform should be a non-empty string, payload: {data}"
    );

    let deps = data
        .get("dependencies")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("dependencies should be an array, payload: {data}"));
    assert_eq!(
        deps.len(),
        1,
        "expected exactly one top-level dependency (slf4j-api); payload: {data}"
    );
    let root = &deps[0];
    let coord = root
        .get("coordinate")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("root dep missing coordinate string, root: {root}"));
    assert!(
        coord.starts_with("org.slf4j:slf4j-api:2.0.9"),
        "expected root dep org.slf4j:slf4j-api:2.0.9, got: {coord}"
    );
    let children = root
        .get("children")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("root dep missing children array, root: {root}"));
    assert!(
        children.is_empty(),
        "slf4j-api has no transitives in this lockfile; got: {children:?}"
    );
}

/// `why --json slf4j-api` against the minimal lockfile must find the dep
/// and emit at least one path whose terminal segment names slf4j-api.
#[test]
fn test_why_json_snapshot() {
    let (project, home) = temp_project();
    write_minimal_toml(project.path());
    write_minimal_lock(project.path());

    let output = rv_command(project.path(), home.path())
        .args(["--json", "why", "slf4j-api"])
        .output()
        .expect("spawn rv why");

    assert!(
        output.status.success(),
        "rv why failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let data = parse_envelope(&output.stdout);
    assert_eq!(
        data.get("found").and_then(|v| v.as_bool()),
        Some(true),
        "why must find slf4j-api (the only dep in the minimal lockfile); payload: {data}"
    );
    let target = data
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("target should be a string, payload: {data}"));
    assert!(
        target.contains("slf4j-api"),
        "target should reference slf4j-api, got: {target}"
    );
    let paths = data
        .get("paths")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("paths should be an array, payload: {data}"));
    assert!(
        !paths.is_empty(),
        "paths must be non-empty when found = true; payload: {data}"
    );
    let first_path = paths[0]
        .as_array()
        .unwrap_or_else(|| panic!("first path should be an array, payload: {data}"));
    let last = first_path
        .last()
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("last segment should be a string, path: {first_path:?}"));
    assert!(
        last.contains("slf4j-api"),
        "last path segment must reference slf4j-api, got: {last}"
    );
}
