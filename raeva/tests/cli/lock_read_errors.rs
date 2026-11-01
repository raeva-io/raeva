//! Exit codes when raeva.lock cannot be read as a file.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::common::{assert_status, raeva_command, temp_project, write_empty_pom};

/// An unreadable raeva.lock is a local IO failure (exit 1, code IO), not a
/// configuration problem. Scripts that treat CONFIG as "edit raeva.toml" must
/// not see permission errors there.
#[test]
fn an_unreadable_lockfile_exits_1_with_io() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let synced = raeva_command(project.path(), home.path())
        .args(["--quiet", "sync", "--offline"])
        .output()
        .expect("sync");
    assert_status(&synced, 0, "sync");

    let lock = project.path().join("raeva.lock");
    let mut perms = fs::metadata(&lock).expect("meta").permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&lock, perms).expect("chmod");

    let output = raeva_command(project.path(), home.path())
        .args(["--json", "tree"])
        .output()
        .expect("tree");

    let mut perms = fs::metadata(&lock).expect("meta").permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&lock, perms).expect("restore");

    assert_status(&output, 1, "tree with unreadable lock");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["exit_code"], 1, "{envelope}");
    assert_eq!(envelope["code"], "IO", "{envelope}");
    assert_eq!(envelope["success"], false);
}

/// A raeva.lock cut off mid-entry names the line and says it may be cut
/// off, and the advice is a hint. One a sync cannot read at all, such as a
/// binary file, says to delete it, since a plain sync refuses it too.
#[test]
fn an_unusable_lockfile_says_where_and_what_fixes_it() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let lock = project.path().join("raeva.lock");
    let frozen = || {
        let output = raeva_command(project.path(), home.path())
            .args(["--json", "sync", "--frozen", "--offline"])
            .output()
            .expect("sync --frozen");
        assert_status(&output, 3, "sync --frozen with an unusable lock");
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON envelope");
        assert_eq!(envelope["code"], "LOCKFILE_INVALID", "{envelope}");
        envelope
    };

    fs::write(&lock, "schema_version = 2\n\n[[platforms]]\nos").expect("write lock");
    let envelope = frozen();
    let error = envelope["error"].as_str().expect("error");
    assert!(
        error.contains("(line 4, column 3); the file ends there, so it may be cut off"),
        "{error}"
    );
    assert_eq!(
        envelope["hints"],
        serde_json::json!(["Run 'raeva sync' without --frozen to regenerate it"])
    );

    fs::write(&lock, b"\x00\x01\xff").expect("write lock");
    let hints = frozen()["hints"].to_string();
    assert!(
        hints.contains("Delete raeva.lock and run 'raeva sync'"),
        "{hints}"
    );
}

/// A missing raeva.lock is named from the working directory, which in CI is
/// the checkout, and the hint says to create and commit it.
#[test]
fn a_missing_lockfile_is_named_from_the_working_directory() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let output = raeva_command(project.path(), home.path())
        .current_dir(project.path())
        .args(["--json", "sync", "--frozen"])
        .output()
        .expect("frozen");
    assert_status(&output, 3, "frozen without a lock");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["code"], "LOCKFILE_MISSING", "{envelope}");
    assert_eq!(envelope["error"], "lockfile not found: raeva.lock");
    assert!(
        envelope["hints"][0]
            .as_str()
            .is_some_and(|hint| hint.starts_with("Run 'raeva sync' to create it")),
        "{envelope}"
    );

    // A working directory reached through a link, as macOS's /var is.
    #[cfg(unix)]
    {
        let link = home.path().join("checkout");
        std::os::unix::fs::symlink(project.path(), &link).expect("symlink");
        let output = raeva_command(&link, home.path())
            .current_dir(&link)
            .args(["--json", "sync", "--frozen"])
            .output()
            .expect("frozen");
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON envelope");
        assert_eq!(envelope["error"], "lockfile not found: raeva.lock");
    }
}

/// `--frozen` beside a raeva.lock but no pom.xml is the wrong directory, as
/// for every other command, not a stale lock.
#[test]
fn frozen_without_a_pom_names_the_missing_project_file() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let synced = raeva_command(project.path(), home.path())
        .args(["--quiet", "sync", "--offline"])
        .output()
        .expect("sync");
    assert_status(&synced, 0, "sync");
    fs::remove_file(project.path().join("pom.xml")).expect("remove pom");
    let output = raeva_command(project.path(), home.path())
        .args(["--json", "sync", "--frozen", "--offline"])
        .output()
        .expect("frozen");
    assert_status(&output, 3, "frozen without pom.xml");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["code"], "PROJECT_FILE_MISSING", "{envelope}");
    assert!(
        envelope["hints"].to_string().contains("-C <dir>"),
        "{envelope}"
    );

    // Before the platform checks: a lock for other machines only.
    let lock_path = project.path().join("raeva.lock");
    let host = rv_lock::Platform::current().expect("host").os_arch();
    let other = if host == "linux-x86_64" {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    };
    let text = fs::read_to_string(&lock_path).expect("read lock");
    fs::write(&lock_path, text.replace(&host, other)).expect("write lock");
    let output = raeva_command(project.path(), home.path())
        .args(["--json", "sync", "--frozen", "--offline"])
        .output()
        .expect("frozen");
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["code"], "PROJECT_FILE_MISSING", "{envelope}");
}
