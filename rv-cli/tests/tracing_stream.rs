//! Regression test: tracing must write to stderr, never stdout.
//!
//! A pipeline like `rv -v sync | jq` is broken if tracing INFO/DEBUG lines
//! land on stdout because they corrupt the structured payload downstream
//! consumers expect. The CLI installs the tracing subscriber with
//! `with_writer(std::io::stderr)` specifically to keep stdout clean.

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
    cmd.env_remove("RUST_LOG");
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

/// With `-vv` the tracing filter is set to `debug`, which emits a high volume
/// of structured log lines. None of them may land on stdout.
#[test]
fn verbose_tracing_does_not_leak_to_stdout() {
    let dir = tempdir().unwrap();
    write_minimal_pom(dir.path());

    // `lock info` against a missing lockfile is a fast, deterministic failure
    // path that still exercises the tracing subscriber install.
    let output = run_rv(&["-vv", "lock", "info"], dir.path());

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    // tracing_subscriber::fmt emits level names verbatim. If any leaked to
    // stdout the pipeline would be corrupted.
    for level in ["INFO", "DEBUG", "TRACE", "WARN"] {
        assert!(
            !stdout.contains(level),
            "tracing level {level} leaked onto stdout: {stdout:?}"
        );
    }

    // Positive counterpart: confirm the `-vv` tracing actually reached stderr.
    // Without this, a regression that silenced all logs (or moved the early
    // exit ahead of subscriber install) would pass the stdout checks above
    // while emitting nothing at all.
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("DEBUG") || stderr.contains("config loaded"),
        "expected -vv tracing output on stderr, got: {stderr:?}"
    );
}
