//! Tests for `--json` output discipline.
//!
//! The contract: when `--json` is active, stdout contains exactly one root
//! JSON value (the envelope). Tracing goes to stderr, and `--json` turns it
//! off unless `-v`/`-vv` or `RUST_LOG` is set, so `raeva --json … | jq`
//! still sees one JSON value.

use crate::common::{
    self, assert_status, assert_success, raeva_command, run_raeva, temp_project, write_empty_pom,
};

use std::fs;
#[cfg(unix)]
use tempfile::tempdir;

/// `raeva --json sync --frozen` against a stale lockfile fails fast without any
/// network call. We use this as the controllable failure path to assert the
/// stdout/stderr discipline.
#[test]
fn json_sync_frozen_mismatch_emits_clean_streams() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));

    // No config_hash: --frozen cannot tie the lock to the project.
    fs::write(
        project.path().join("raeva.lock"),
        common::lock_text(
            "linux-x86_64",
            None,
            vec![common::package("org.old", "stale", "1.0")],
        ),
    )
    .unwrap();

    let output = run_raeva(
        project.path(),
        home.path(),
        &["--json", "sync", "--frozen", "--platforms", "linux-x86_64"],
    );
    assert_status(&output, 7, "sync --frozen against a stale lock");

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
    assert_eq!(parsed["code"], "LOCKFILE_MISMATCH");
    assert_eq!(parsed["exit_code"], 7);
    // `exit_code` and `error` are top-level envelope fields, not
    // buried inside `data`.
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

/// The path `export-checksums` prints comes from the project directory, which
/// can carry a terminal control sequence in its name.
#[cfg(unix)]
#[test]
fn export_checksums_escapes_controls_in_the_printed_path() {
    let parent = tempdir().unwrap();
    let dir = parent.path().join("proj\u{1b}[31mred");
    fs::create_dir(&dir).unwrap();
    write_empty_pom(&dir.join("pom.xml"));
    let home = tempdir().unwrap();
    let synced = run_raeva(&dir, home.path(), &["--quiet", "sync", "--offline"]);
    assert_success(&synced, "sync");

    let output = run_raeva(&dir, home.path(), &["export-checksums"]);
    assert_success(&output, "export-checksums");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(
        !stdout.contains('\u{1b}'),
        "stdout must not carry a raw escape: {stdout:?}"
    );
    assert!(stdout.contains("\\u{1b}[31mred"), "{stdout:?}");
}

/// A path, coordinate or repository id with terminal controls in it is
/// printed escaped, so it cannot rewrite the screen or reorder what a reader
/// sees. JSON keeps the value and writes the controls as `\u` escapes.
#[cfg(unix)]
#[test]
fn control_characters_in_printed_values_are_escaped() {
    let parent = tempdir().unwrap();
    let home = tempdir().unwrap();
    let hostile = "n-\u{1b}[31mred\u{202e}\u{7f}";
    let root = parent.path().join(hostile);

    let human = raeva_command(&root, home.path())
        .arg("tree")
        .output()
        .expect("run raeva");
    assert_status(&human, 3, "tree with controls in the path");
    let stderr = String::from_utf8(human.stderr).expect("UTF-8 stderr");
    assert!(
        stderr.contains("n-\\u{1b}[31mred\\u{202e}\\u{7f}"),
        "{stderr:?}"
    );
    for raw in ['\u{1b}', '\u{202e}', '\u{7f}'] {
        assert!(!stderr.contains(raw), "{raw:?} printed raw: {stderr:?}");
    }

    let json = raeva_command(&root, home.path())
        .args(["--json", "tree"])
        .output()
        .expect("run raeva");
    let stdout = String::from_utf8(json.stdout).expect("UTF-8 stdout");
    for raw in ['\u{1b}', '\u{202e}', '\u{7f}'] {
        assert!(!stdout.contains(raw), "{raw:?} printed raw: {stdout:?}");
    }
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one envelope");
    let error = envelope["error"].as_str().expect("error text");
    assert!(error.contains(hostile), "{error:?}");
}

#[test]
fn library_warnings_reach_the_json_envelope() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_MAX_ARTIFACT_SIZE", "big")
        .args(["--json", "sync", "--offline"])
        .output()
        .expect("spawn raeva");
    assert_success(&output, "sync");
    assert!(
        output.stderr.is_empty(),
        "stderr must be empty in --json mode, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON envelope");
    let warnings = parsed["data"]["warnings"].as_array().expect("warnings");
    assert!(
        warnings
            .iter()
            .any(|warning| warning["code"] == "SETTING_IGNORED"
                && warning["context"]["env"] == "RAEVA_MAX_ARTIFACT_SIZE"),
        "{parsed}"
    );
}

/// Tracing goes to stderr, never stdout: a pipeline like
/// `raeva --json -vv sync | jq` would otherwise get log lines in its payload.
/// `-vv` still traces in `--json` mode; the envelope stays one JSON value.
#[test]
fn verbose_tracing_does_not_leak_to_stdout() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let output = run_raeva(
        project.path(),
        home.path(),
        &["-vv", "--json", "sync", "--offline"],
    );
    assert_success(&output, "sync");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    for level in ["INFO", "DEBUG", "TRACE", "WARN"] {
        assert!(!stdout.contains(level), "{level} on stdout: {stdout:?}");
    }
    serde_json::from_str::<serde_json::Value>(stdout.trim()).expect("one JSON envelope");
    // The tracing did reach stderr, so the check above is not vacuous.
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("DEBUG"),
        "no -vv tracing on stderr: {stderr:?}"
    );
}

/// A reactor's tree ends with a note on stderr on how to show less, and the
/// tree itself stays on stdout. A host the lock has no section for warns
/// after the note.
#[test]
fn a_reactor_tree_says_how_to_show_one_module() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::copy(
        rv_test_support::fixtures::path("lock-golden/reactor/raeva.lock"),
        project.path().join("raeva.lock"),
    )
    .unwrap();
    let output = raeva_command(project.path(), home.path())
        .arg("tree")
        .output()
        .expect("run raeva");
    assert_status(&output, 0, "reactor tree");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let last_note = |stderr: &str| {
        (stderr.lines().rev())
            .find(|line| !line.starts_with("warning: PLATFORM_FALLBACK"))
            .map(str::to_owned)
    };
    assert_eq!(
        last_note(&stderr).as_deref(),
        Some("3 modules; --module <path> shows one, --depth 1 the direct dependencies"),
        "{stderr}"
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("Module: ")
    );
    let shallow = raeva_command(project.path(), home.path())
        .args(["tree", "--depth", "1"])
        .output()
        .expect("run raeva");
    let stderr = String::from_utf8(shallow.stderr).unwrap();
    assert_eq!(
        last_note(&stderr).as_deref(),
        Some("3 modules; --module <path> shows one"),
        "{stderr}"
    );
}

/// A full stderr loses the error line but keeps the exit status, instead
/// of panicking with 101.
#[cfg(target_os = "linux")]
#[test]
fn a_full_stderr_keeps_the_exit_status() {
    let (project, home) = temp_project();
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let run = |args: &[&str]| {
        raeva_command(project.path(), home.path())
            .args(args)
            .stderr(full.try_clone().expect("clone /dev/full"))
            .output()
            .expect("run raeva")
    };
    assert_status(&run(&["sync", "--offline"]), 3, "sync without pom.xml");
    write_empty_pom(&project.path().join("pom.xml"));
    assert_status(&run(&["sync", "--offline"]), 0, "sync, stderr full");
    let info = run(&["lock", "info"]);
    assert_status(&info, 0, "lock info, stderr full");
    assert!(!info.stdout.is_empty());
}
