//! Tests for `--json` output discipline.
//!
//! The contract: when `--json` is active, stdout contains exactly one root
//! JSON value (the envelope) and stderr contains no chatter. Direct
//! `eprintln!` sites and tracing output must be suppressed so machine-readable
//! consumers see a single parseable result.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

fn rv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rv")
}

fn run_rv(args: &[&str], dir: &Path) -> Output {
    let mut cmd = Command::new(rv_bin());
    cmd.args(args).current_dir(dir);
    // Isolate from the developer's environment so a `RUST_LOG` export in the
    // host shell can't flip the suppression we are trying to test.
    cmd.env_remove("RUST_LOG");
    // Force HOME to a temp dir so any future "user config" surface can't read
    // from the developer profile.
    cmd.env("HOME", dir);
    cmd.env("USERPROFILE", dir);
    cmd.output().expect("spawn rv")
}

fn write_minimal_pom(dir: &Path) {
    fs::write(
        dir.join("pom.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>test</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
</project>
"#,
    )
    .expect("write pom.xml");
}

/// `rv --json sync --frozen` against a stale lockfile fails fast without any
/// network call. We use this as the controllable failure path to assert the
/// stdout/stderr discipline.
#[test]
fn json_sync_frozen_mismatch_emits_clean_streams() {
    let dir = tempdir().unwrap();
    write_minimal_pom(dir.path());

    fs::write(
        dir.path().join("rv.lock"),
        r#"schema_version = 1

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.old"
artifact_id = "stale"
version = "1.0"
"#,
    )
    .unwrap();

    let output = run_rv(&["--json", "sync", "--frozen"], dir.path());
    assert!(
        !output.status.success(),
        "sync --frozen should fail when the lockfile is stale"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");

    // Stderr must be empty: every direct eprintln! site is gated and the
    // tracing subscriber is installed at `off` in JSON mode.
    assert!(
        stderr.is_empty(),
        "stderr should be empty in --json mode, got: {stderr:?}"
    );

    // Stdout must be exactly one JSON value (the error envelope from the
    // top-level handler).
    let trimmed = stdout.trim();
    assert!(!trimmed.is_empty(), "expected one JSON envelope on stdout");
    let parsed: serde_json::Value = serde_json::from_str(trimmed)
        .unwrap_or_else(|err| panic!("stdout is not a single JSON value: {err}\nstdout: {stdout}"));
    assert_eq!(parsed["success"], serde_json::Value::Bool(false));
    // `exit_code` and `error` are top-level envelope fields, not
    // buried inside `data`.
    assert!(
        parsed["exit_code"].is_number(),
        "expected top-level exit_code, got: {parsed}"
    );
    assert!(
        parsed["error"].is_string(),
        "expected top-level error string, got: {parsed}"
    );
    assert!(
        parsed["data"]["exit_code"].is_null(),
        "exit_code must not be nested inside data: {parsed}"
    );
    assert!(
        parsed["data"]["error"].is_null(),
        "error must not be nested inside data: {parsed}"
    );
    assert!(
        parsed["data"]["warnings"].is_array(),
        "data.warnings array should remain: {parsed}"
    );
}

/// `rv --json doctor` against an unreachable repository must emit exactly one
/// root JSON object. Previously the command printed its own envelope and the
/// top-level error handler printed a second one, giving JSON consumers two
/// values on stdout.
#[test]
fn json_doctor_failure_emits_single_envelope() {
    let dir = tempdir().unwrap();
    // RFC 5737 TEST-NET-1 (192.0.2.0/24) is reserved for documentation; the
    // doctor probe will fail to connect locally without real network egress.
    fs::write(
        dir.path().join("rv.toml"),
        r#"
[[repositories]]
id = "unreachable"
url = "http://192.0.2.1/maven2"
"#,
    )
    .expect("write rv.toml");

    let output = run_rv(&["--json", "doctor"], dir.path());

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");

    assert!(
        !output.status.success(),
        "doctor should fail against an unreachable repository\nstdout: {stdout}\nstderr: {stderr}"
    );

    assert!(
        stderr.is_empty(),
        "stderr should be empty in --json mode, got: {stderr:?}"
    );

    // serde_json::from_str is strict about trailing input: if doctor emits a
    // second envelope this parse fails with "trailing characters", which is
    // exactly the regression we're guarding against.
    let trimmed = stdout.trim();
    let parsed: serde_json::Value = serde_json::from_str(trimmed).unwrap_or_else(|err| {
        panic!("stdout must contain exactly one JSON value, got: {err}\nstdout: {stdout}")
    });
    assert_eq!(
        parsed["success"],
        serde_json::Value::Bool(false),
        "doctor envelope should report success=false on failure"
    );
    // Ensure the surviving envelope is the structured doctor payload (with
    // `checks` and `issues`), not the generic error envelope from the
    // top-level handler.
    assert!(
        parsed["data"]["checks"].is_array(),
        "expected the doctor envelope to win, got: {parsed}"
    );
    assert!(
        parsed["data"]["issues"].is_number(),
        "expected the doctor envelope to win, got: {parsed}"
    );
    // The doctor *failure* envelope must carry the same top-level
    // `exit_code` and `error` fields the generic error envelope provides, so
    // JSON consumers don't have to special-case doctor output.
    assert!(
        parsed["exit_code"].is_number(),
        "doctor failure envelope must hoist exit_code to the top level, got: {parsed}"
    );
    assert!(
        parsed["error"].is_string(),
        "doctor failure envelope must hoist an error string to the top level, got: {parsed}"
    );
    // And those keys must not also linger inside `data` (they were hoisted).
    assert!(
        parsed["data"]["exit_code"].is_null(),
        "exit_code must not remain nested inside data: {parsed}"
    );
    assert!(
        parsed["data"]["error"].is_null(),
        "error must not remain nested inside data: {parsed}"
    );
}

/// `rv --json lock info` is a happy-path command that prints a human table
/// in non-JSON mode. Under `--json` no decorative chatter (heading, table)
/// may bleed onto stderr/stdout: exactly one structured envelope on stdout,
/// nothing on stderr.
#[test]
fn json_lock_info_emits_single_envelope() {
    let dir = tempdir().unwrap();
    write_minimal_pom(dir.path());
    // Minimal valid lockfile that `lock info` can read.
    fs::write(
        dir.path().join("rv.lock"),
        r#"schema_version = 1

[[platforms]]
platform = "linux-x86_64"
"#,
    )
    .unwrap();

    let output = run_rv(&["--json", "lock", "info"], dir.path());

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");

    assert!(
        output.status.success(),
        "lock info should succeed\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.is_empty(),
        "stderr must be empty in --json mode, got: {stderr:?}"
    );

    let trimmed = stdout.trim();
    let parsed: serde_json::Value = serde_json::from_str(trimmed)
        .unwrap_or_else(|err| panic!("stdout is not a single JSON value: {err}\nstdout: {stdout}"));
    assert_eq!(parsed["success"], serde_json::Value::Bool(true));
    assert!(
        parsed["data"]["schema_version"].is_number(),
        "missing schema_version: {parsed}"
    );
}

/// `rv --json lock verify` happy path against a lockfile whose packages list
/// is empty: nothing to verify, success envelope on stdout, clean stderr.
#[test]
fn json_lock_verify_emits_single_envelope() {
    let dir = tempdir().unwrap();
    write_minimal_pom(dir.path());
    fs::write(
        dir.path().join("rv.lock"),
        r#"schema_version = 1

[[platforms]]
platform = "linux-x86_64"
"#,
    )
    .unwrap();

    let output = run_rv(&["--json", "lock", "verify"], dir.path());

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");

    assert!(
        output.status.success(),
        "lock verify should succeed on empty lock\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.is_empty(),
        "stderr must be empty in --json mode, got: {stderr:?}"
    );

    let trimmed = stdout.trim();
    let parsed: serde_json::Value = serde_json::from_str(trimmed)
        .unwrap_or_else(|err| panic!("stdout is not a single JSON value: {err}\nstdout: {stdout}"));
    assert_eq!(parsed["success"], serde_json::Value::Bool(true));
    assert_eq!(parsed["data"]["verified"], serde_json::json!(0));
    // The envelope's `data.warnings` channel must always be an array,
    // even when no warning fired. Consumers rely on the field's
    // presence to skip a probe-and-default. The captured warnings
    // (`WEAK_HASH_FALLBACK`, `CROSS_HOST_MIRROR`, `TRANSITIVE_REPO_DROPPED`)
    // are routed here by `WarningCollectorLayer`; this test guards the
    // baseline (empty) shape end to end.
    assert!(
        parsed["data"]["warnings"].is_array(),
        "data.warnings must be present and an array, envelope: {parsed}"
    );
}

/// `rv --json export-checksums` happy path: writes the checksum file, emits
/// one envelope on stdout, nothing on stderr.
#[test]
fn json_export_checksums_emits_single_envelope() {
    let dir = tempdir().unwrap();
    write_minimal_pom(dir.path());
    fs::write(
        dir.path().join("rv.lock"),
        r#"schema_version = 1

[[platforms]]
platform = "linux-x86_64"
"#,
    )
    .unwrap();

    let output = run_rv(&["--json", "export-checksums"], dir.path());

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");

    assert!(
        output.status.success(),
        "export-checksums should succeed\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.is_empty(),
        "stderr must be empty in --json mode, got: {stderr:?}"
    );

    let trimmed = stdout.trim();
    let parsed: serde_json::Value = serde_json::from_str(trimmed)
        .unwrap_or_else(|err| panic!("stdout is not a single JSON value: {err}\nstdout: {stdout}"));
    assert_eq!(parsed["success"], serde_json::Value::Bool(true));
    assert!(parsed["data"]["path"].is_string(), "missing path: {parsed}");
}
