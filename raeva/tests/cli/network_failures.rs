//! What a sync that cannot reach its repository tells the user: the cause
//! of the failure, each wait before a retry, and how many attempts it made.

use std::time::{Duration, Instant};

use crate::common::{assert_status, closing_server, raeva_command, write_repo_toml};
use rv_test_support::http::{Response, StubServer};
use rv_test_support::net::RefusingPort;
use tempfile::TempDir;

/// A project with one dependency, `org.example:lib:1.0`, from the repository
/// at `url`.
fn project(url: &str) -> TempDir {
    let dir = tempfile::tempdir().expect("project dir");
    std::fs::write(
        dir.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId>\
<artifactId>app</artifactId><version>1.0</version><dependencies><dependency>\
<groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version>\
</dependency></dependencies></project>",
    )
    .expect("write pom.xml");
    write_repo_toml(dir.path(), "fixture", url);
    dir
}

#[test]
fn a_refused_connection_names_its_cause() {
    let refusing = RefusingPort::bind();
    let project = project(&format!("http://{}/maven/", refusing.addr()));
    let home = TempDir::new().expect("home");
    let output = raeva_command(project.path(), home.path())
        .arg("sync")
        .output()
        .expect("run raeva sync");
    assert_status(&output, 4, "refused connection");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(": connection refused"), "{stderr}");
}

/// A `Retry-After` longer than raeva waits fails the sync at once, and the
/// error says why it did not ask again.
#[test]
fn a_retry_after_past_the_cap_is_not_waited_for() {
    let server = StubServer::start(|_| Response::new(429, "").header("Retry-After", "120"));
    let project = project(&format!("http://{}/maven/", server.addr()));
    let home = TempDir::new().expect("home");
    let start = Instant::now();
    let output = raeva_command(project.path(), home.path())
        .env("RAEVA_RETRIES", "1")
        .arg("sync")
        .output()
        .expect("run raeva sync");
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "{:?}",
        start.elapsed()
    );
    assert_status(&output, 4, "rate limited");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("asked for 120 s"), "{stderr}");
    let paths: Vec<String> = server.requests().into_iter().map(|r| r.path).collect();
    let poms = paths.iter().filter(|path| path.ends_with("/lib-1.0.pom"));
    assert_eq!(poms.count(), 1, "{paths:?}");
}

/// Each wait before a retry prints a line on stderr, outside `--json`, and
/// the final error says how many attempts were made.
#[test]
fn retries_print_their_waits_and_the_error_counts_the_attempts() {
    let project = project(&format!("{}/maven/", closing_server()));
    let home = TempDir::new().expect("home");
    let sync = |args: &[&str]| {
        raeva_command(project.path(), home.path())
            .env("RAEVA_RETRIES", "1")
            .args(args)
            .output()
            .expect("run raeva sync")
    };

    let output = sync(&["sync"]);
    assert_status(&output, 4, "server closing connections");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let retry = stderr
        .lines()
        .find(|line| line.starts_with("Retrying in ") && line.contains("/lib-1.0.pom): "))
        .unwrap_or_else(|| panic!("no retry line:\n{stderr}"));
    assert!(retry.contains(" s (attempt 2 of 2): "), "{retry}");
    assert!(stderr.contains("(after 2 attempts)"), "{stderr}");

    let output = sync(&["--json", "sync"]);
    assert_status(&output, 4, "server closing connections, --json");
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let error = envelope["error"].as_str().expect("error");
    assert!(error.contains("(after 2 attempts)"), "{error}");
}
