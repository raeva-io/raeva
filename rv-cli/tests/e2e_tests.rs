//! End-to-end tests for rv CLI commands.
//! These tests use real Maven Central and require network access.

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn rv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rv")
}

fn run_rv(args: &[&str], dir: &Path) -> std::process::Output {
    Command::new(rv_bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run rv")
}

// `test_init_creates_rv_toml` was removed: `rv init` is not in v0.1 scope
// (per CHANGELOG). Re-add the test alongside the command if/when init lands
// in a future release.

#[test]
#[ignore] // Requires network access to Maven Central
fn test_sync_creates_lockfile() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("pom.xml"),
        r"
        <project>
            <modelVersion>4.0.0</modelVersion>
            <groupId>test</groupId>
            <artifactId>test</artifactId>
            <version>1.0</version>
            <dependencies>
                <dependency>
                    <groupId>org.slf4j</groupId>
                    <artifactId>slf4j-api</artifactId>
                    <version>2.0.9</version>
                </dependency>
            </dependencies>
        </project>
    ",
    )
    .unwrap();

    let output = run_rv(&["sync"], dir.path());
    assert!(
        output.status.success(),
        "sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("rv.lock").exists());
}

#[test]
fn test_sync_frozen_fails_on_mismatch() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("pom.xml"),
        r"
        <project>
            <modelVersion>4.0.0</modelVersion>
            <groupId>test</groupId>
            <artifactId>test</artifactId>
            <version>1.0</version>
        </project>
    ",
    )
    .unwrap();

    // Create a stale lockfile
    fs::write(
        dir.path().join("rv.lock"),
        r#"
schema_version = 1
config_hash = "0000000000000000000000000000000000000000000000000000000000000000"

[[platforms]]
platform = "linux-x86_64"

[[platforms.packages]]
group_id = "org.old"
artifact_id = "stale"
version = "1.0"
packaging = "jar"
"#,
    )
    .unwrap();

    let output = run_rv(&["sync", "--frozen"], dir.path());
    assert!(
        !output.status.success(),
        "sync --frozen should fail against a stale lockfile"
    );
    // Strengthen the assertion: it must fail for the *right* reason — a
    // lockfile mismatch — not, say, a config-load or network error. The
    // stable contract is exit code 7 (LOCKFILE_MISMATCH) plus a message that
    // names the mismatch.
    assert_eq!(
        output.status.code(),
        Some(7),
        "expected LOCKFILE_MISMATCH (exit 7); stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lockfile mismatch") || stderr.contains("rv sync"),
        "expected a lockfile-mismatch message, got stderr: {stderr}"
    );
}

#[test]
fn frozen_accepts_v3_lock_without_rewriting() {
    let project = tempdir().unwrap();
    let home = tempdir().unwrap();
    fs::write(
        project.path().join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId>
  <artifactId>legacy-frozen</artifactId>
  <version>1.0</version>
</project>
"#,
    )
    .unwrap();

    let initial = Command::new(rv_bin())
        .args(["-C", project.path().to_str().unwrap(), "sync", "--offline"])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .expect("initial sync");
    assert!(
        initial.status.success(),
        "initial sync failed: {}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let generated =
        rv_config::Lockfile::read(&project.path().join("rv.lock")).expect("read generated lock");
    let config_hash = generated.config_hash.as_deref().expect("config hash");
    let platform = generated.platforms[0].platform.to_string();
    let v3 = format!(
        "schema_version = 3\nconfig_hash = \"{config_hash}\"\n\n\
         [[platforms]]\nplatform = \"{platform}\"\n"
    );
    fs::write(project.path().join("rv.lock"), &v3).expect("write v3 lock");

    let frozen = Command::new(rv_bin())
        .args([
            "-C",
            project.path().to_str().unwrap(),
            "sync",
            "--frozen",
            "--offline",
        ])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .expect("frozen sync");
    assert!(
        frozen.status.success(),
        "frozen v3 validation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );
    assert_eq!(
        fs::read_to_string(project.path().join("rv.lock")).expect("read v3 after frozen"),
        v3,
        "--frozen must not rewrite a valid schema-3 lock"
    );

    // Online --frozen resolves schema-4 locks afresh, but a schema 1-3 lock has
    // no reactor identity to resolve against, so it keeps the local-inputs-only
    // check rather than reporting drift for every valid legacy lock.
    let frozen_online = Command::new(rv_bin())
        .args(["-C", project.path().to_str().unwrap(), "sync", "--frozen"])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .expect("online frozen sync");
    assert!(
        frozen_online.status.success(),
        "online frozen v3 validation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&frozen_online.stdout),
        String::from_utf8_lossy(&frozen_online.stderr)
    );
    assert_eq!(
        fs::read_to_string(project.path().join("rv.lock")).expect("read v3 after online frozen"),
        v3,
        "--frozen must not rewrite a valid schema-3 lock"
    );

    let upgrade = Command::new(rv_bin())
        .args(["-C", project.path().to_str().unwrap(), "sync", "--offline"])
        .env("RAEVA_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .expect("normal sync upgrade");
    assert!(
        upgrade.status.success(),
        "normal v3 upgrade failed: {}",
        String::from_utf8_lossy(&upgrade.stderr)
    );
    assert_eq!(
        rv_config::Lockfile::read(&project.path().join("rv.lock"))
            .expect("read upgraded lock")
            .schema_version,
        rv_config::LOCKFILE_SCHEMA_VERSION
    );
}

#[test]
fn test_lock_info_rejects_non_file_lockfile() {
    // Regression for the `lock info` not-a-file diagnostic: a directory (or
    // any non-regular file) at the rv.lock path must be reported as
    // "not a regular file", not collapsed into the generic "missing" message.
    // No network access required.
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("rv.lock")).expect("create rv.lock directory");

    let output = run_rv(&["lock", "info"], dir.path());
    assert!(
        !output.status.success(),
        "lock info against a directory rv.lock must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a regular file"),
        "expected a not-a-regular-file diagnostic, got stderr: {stderr}"
    );
    // It must NOT misreport the non-file as a missing lockfile.
    assert!(
        !stderr.contains("lockfile not found"),
        "non-file lockfile must not be reported as missing, got stderr: {stderr}"
    );
}

#[test]
#[ignore] // Requires network access to Maven Central
fn test_tree_shows_dependencies() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("pom.xml"),
        r"
        <project>
            <modelVersion>4.0.0</modelVersion>
            <groupId>test</groupId>
            <artifactId>test</artifactId>
            <version>1.0</version>
            <dependencies>
                <dependency>
                    <groupId>junit</groupId>
                    <artifactId>junit</artifactId>
                    <version>4.13.2</version>
                    <scope>test</scope>
                </dependency>
            </dependencies>
        </project>
    ",
    )
    .unwrap();

    run_rv(&["sync"], dir.path());
    let output = run_rv(&["tree"], dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("junit"));
    assert!(stdout.contains("hamcrest"));
}

#[test]
#[ignore] // Requires network access to Maven Central
fn test_why_explains_dependency() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("pom.xml"),
        r"
        <project>
            <modelVersion>4.0.0</modelVersion>
            <groupId>test</groupId>
            <artifactId>test</artifactId>
            <version>1.0</version>
            <dependencies>
                <dependency>
                    <groupId>junit</groupId>
                    <artifactId>junit</artifactId>
                    <version>4.13.2</version>
                </dependency>
            </dependencies>
        </project>
    ",
    )
    .unwrap();

    run_rv(&["sync"], dir.path());
    let output = run_rv(&["why", "org.hamcrest:hamcrest-core"], dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("junit") || stdout.contains("hamcrest"));
}
