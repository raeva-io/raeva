//! Regression for the v0.1 fix that `rv doctor` redacts user-info and query
//! parameters from URLs in its connection-error output. Concrete failure
//! shape: a `<repository>` URL with embedded `user:password@host?api_key=...`
//! must not leak the password or the `api_key` value into doctor's report.
//!
//! Strategy: point doctor at an unroutable, credential-bearing URL and parse
//! the structured `--json` envelope. The doctor probe fails to connect; the
//! `format_connection_error` path is what runs. Assert the sensitive tokens
//! never appear anywhere in the JSON payload.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

fn rv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rv")
}

fn run_doctor(dir: &Path) -> Output {
    let mut cmd = Command::new(rv_bin());
    cmd.arg("-C").arg(dir).arg("--json").arg("doctor");
    cmd.env_remove("RUST_LOG");
    cmd.env("RAEVA_HOME", dir);
    cmd.env("HOME", dir);
    cmd.env("USERPROFILE", dir);
    cmd.output().expect("spawn rv doctor")
}

#[test]
fn doctor_redacts_userinfo_and_query_params_on_failure() {
    let dir = tempdir().expect("tempdir");
    // RFC 5737 TEST-NET-1 (192.0.2.0/24) is reserved for documentation.
    // The connection will fail locally without real network egress, which
    // is exactly the failure path that exercises `format_connection_error`.
    //
    // The URL embeds:
    //   * basic-auth userinfo:  alice:hunter2
    //   * a query parameter:    api_key=topsecretvalue
    // Both must be stripped from the reported error.
    std::fs::write(
        dir.path().join("rv.toml"),
        r#"
[[repositories]]
id = "leaky"
url = "http://alice:hunter2@192.0.2.1/maven2?api_key=topsecretvalue"
"#,
    )
    .expect("write rv.toml");

    let output = run_doctor(dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Doctor exits non-zero against an unreachable repository.
    assert!(
        !output.status.success(),
        "doctor should fail against the unroutable repo\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The entire wire output (stdout JSON envelope + stderr chatter) must
    // be free of the secrets. `format_connection_error` calls
    // `reqwest::Error::without_url`, so the URL is stripped from the error
    // string itself; we belt-and-braces by sweeping both streams.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        !combined.contains("hunter2"),
        "password leaked into doctor output:\n{combined}"
    );
    assert!(
        !combined.contains("topsecretvalue"),
        "query-string secret leaked into doctor output:\n{combined}"
    );
}
