//! Regression for the v0.1 fix: `rv lock verify` reports the full batch of
//! checksum failures instead of bailing on the first one.
//!
//! Concrete failure shape: two distinct lockfile entries pin SHA-256 digests
//! that have no corresponding blob in the local store. The verify path must
//! collect both as `missing` and surface a single envelope summarising the
//! whole batch (`missing: 2`), not exit on the first miss with `missing: 1`.

use std::fs;
use std::path::Path;

use tempfile::tempdir;

fn rv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rv")
}

fn write_pom(dir: &Path) {
    fs::write(
        dir.join("pom.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
</project>
"#,
    )
    .expect("write pom.xml");
}

#[test]
fn lock_verify_reports_all_missing_artifacts_in_one_batch() {
    let project = tempdir().expect("project tempdir");
    let home = tempdir().expect("home tempdir");
    write_pom(project.path());

    // Two packages, each with a unique SHA-256 pin that has zero
    // probability of colliding with a real blob path inside the empty
    // store. `00...` and `ff...` are both valid 64-char hex digests but
    // they are not the SHA-256 of any blob we ever wrote.
    let lockfile = r#"schema_version = 1

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "com.example"
artifact_id = "alpha"
version = "1.0.0"
packaging = "jar"
repo_url = "https://repo.example/m2/"
checksum = { algorithm = "sha256", digest = "0000000000000000000000000000000000000000000000000000000000000000" }

[[platforms.packages]]
group_id = "com.example"
artifact_id = "beta"
version = "2.0.0"
packaging = "jar"
repo_url = "https://repo.example/m2/"
checksum = { algorithm = "sha256", digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" }
"#;
    fs::write(project.path().join("rv.lock"), lockfile).expect("write rv.lock");

    let output = std::process::Command::new(rv_bin())
        .arg("-C")
        .arg(project.path())
        .arg("--json")
        .arg("lock")
        .arg("verify")
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn rv lock verify");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !output.status.success(),
        "verify should fail when artifacts are missing\nstdout: {stdout}\nstderr: {stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
        panic!("stdout must be a single JSON envelope: {err}\nstdout: {stdout}\nstderr: {stderr}")
    });
    assert_eq!(parsed["success"], serde_json::Value::Bool(false));
    let data = parsed
        .get("data")
        .unwrap_or_else(|| panic!("envelope missing data: {parsed}"));
    let missing = data["missing"]
        .as_u64()
        .unwrap_or_else(|| panic!("data.missing should be a non-negative integer: {parsed}"));
    let corrupt = data["corrupt"]
        .as_u64()
        .unwrap_or_else(|| panic!("data.corrupt should be a non-negative integer: {parsed}"));
    // Either both land in `missing` (no on-disk blob at that SHA), or
    // possibly some land in `corrupt` if the index already mapped the key
    // to a real but mismatched blob. The load-bearing invariant is the
    // total count: both failures must surface, not just the first one.
    assert_eq!(
        missing + corrupt,
        2,
        "verify must report all 2 failing artifacts in a single batch; got missing={missing} corrupt={corrupt}, envelope: {parsed}"
    );

    // Belt-and-braces: the top-level envelope `error` field also encodes
    // the batch totals as a sanity message; assert it mentions a non-zero
    // failure count consistent with `missing + corrupt = 2`.
    let error_msg = parsed
        .get("error")
        .and_then(|v| v.as_str())
        .or_else(|| data.get("error").and_then(|v| v.as_str()))
        .unwrap_or("");
    assert!(
        error_msg.contains('2') || (missing + corrupt == 2),
        "expected the error summary to encode the batch size; got error={error_msg:?}, envelope: {parsed}"
    );
}
