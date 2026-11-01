use std::fs;
use std::path::Path;
use std::process::Output;

use rv_test_support::fixtures;
use serde_json::{Value, json};

use crate::common::{assert_status, assert_success, raeva_command, temp_project};

fn diff(project: &Path, home: &Path, old: &str, new: Option<&str>) -> Output {
    let mut command = raeva_command(project, home);
    command
        .current_dir(project)
        .args(["--json", "--offline", "lock", "diff", old]);
    if let Some(new) = new {
        command.arg(new);
    }
    command.output().expect("lock diff")
}

fn data(output: &Output) -> Value {
    assert_success(output, "lock diff");
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["success"], true);
    envelope["data"].clone()
}

fn stage(project: &Path, fixture: &str, name: &str) {
    fs::copy(fixtures::path(fixture), project.join(name)).unwrap();
}

#[test]
fn identical_locks_exit_zero_and_keep_supplied_paths() {
    let (project, home) = temp_project();
    stage(
        project.path(),
        "lock-golden/round-trip/raeva.lock",
        "old.lock",
    );
    stage(
        project.path(),
        "lock-golden/round-trip/raeva.lock",
        "new.lock",
    );
    let data = data(&diff(
        project.path(),
        home.path(),
        "old.lock",
        Some("./new.lock"),
    ));
    assert_eq!(
        data,
        json!({
            "old": "old.lock", "new": "./new.lock", "changed": false,
            "changes": [], "edge_changes": [], "pom_changes": [], "changed_inputs": [],
            "platforms_added": [], "platforms_removed": [],
            "module_changes": [], "profile_changes": [],
            "via_limited": false, "warnings": [],
        })
    );
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn fixture_version_change_has_a_new_lock_path_and_grouped_text() {
    let (project, home) = temp_project();
    stage(
        project.path(),
        "lock-golden/round-trip/raeva.lock",
        "old.lock",
    );
    stage(project.path(), "lock-diff/round-trip.lock", "new.lock");
    let data = data(&diff(
        project.path(),
        home.path(),
        "old.lock",
        Some("new.lock"),
    ));
    assert_eq!(data["changed"], true);
    let version = data["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["change"] == "version")
        .unwrap();
    assert_eq!(version["old_version"], "1.1");
    assert_eq!(version["new_version"], "1.2");
    assert_eq!(version["via"], json!([["org.golden:core:1.2:jar"]]));
    assert_eq!(data["pom_changes"].as_array().unwrap().len(), 4);
    let text = raeva_command(project.path(), home.path())
        .current_dir(project.path())
        .args(["lock", "diff", "old.lock", "new.lock"])
        .output()
        .unwrap();
    assert_success(&text, "text lock diff");
    let stdout = String::from_utf8(text.stdout).unwrap();
    // core is a direct dependency, so the text shows no path for it.
    assert!(
        stdout.contains("  core  1.1 -> 1.2 (in app, on linux-x86_64)\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("via org.golden:core"), "{stdout}");
    assert_eq!(stdout.matches("checksum changed").count(), 1);
    assert!(
        String::from_utf8(text.stderr)
            .unwrap()
            .contains("Lockfile diff")
    );
}

#[test]
fn added_removed_and_added_platform_are_structured() {
    let (project, home) = temp_project();
    stage(
        project.path(),
        "lock-golden/single-module/raeva.lock",
        "old.lock",
    );
    stage(
        project.path(),
        "lock-golden/round-trip/raeva.lock",
        "new.lock",
    );
    let data = data(&diff(
        project.path(),
        home.path(),
        "old.lock",
        Some("new.lock"),
    ));
    assert_eq!(data["platforms_added"], json!(["windows-x86_64"]));
    let changes = data["changes"].as_array().unwrap();
    assert!(changes.iter().all(|row| row["platform"] == "linux-x86_64"));
    for kind in ["external", "workspace", "system"] {
        assert!(changes.iter().any(|row| row["kind"] == kind), "{data}");
    }
    assert!(
        changes
            .iter()
            .any(|row| row["coordinate"] == "org.golden:lib:jar:tests")
    );
    let added = changes.iter().find(|row| row["change"] == "added").unwrap();
    assert!(added["old_version"].is_null());
    assert!(!added["via"].as_array().unwrap().is_empty());
    let removed = changes
        .iter()
        .find(|row| row["change"] == "removed")
        .unwrap();
    assert!(removed["new_version"].is_null());
    assert!(!removed["via"].as_array().unwrap().is_empty());
}

#[test]
fn malformed_or_conflicted_second_lock_uses_the_strict_reader() {
    let (project, home) = temp_project();
    stage(
        project.path(),
        "lock-golden/round-trip/raeva.lock",
        "old.lock",
    );
    for text in [
        "not valid TOML",
        "<<<<<<< HEAD\nschema_version = 6\n=======\n>>>>>>> branch\n",
    ] {
        fs::write(project.path().join("bad.lock"), text).unwrap();
        let output = diff(project.path(), home.path(), "old.lock", Some("bad.lock"));
        assert_status(&output, 3, "invalid second lock");
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["success"], false);
        assert_eq!(json["code"], "LOCKFILE_INVALID");
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn omitted_new_uses_the_project_lock_selected_by_c() {
    let (project, home) = temp_project();
    stage(
        project.path(),
        "lock-golden/snapshot/raeva.lock",
        "old.lock",
    );
    stage(project.path(), "lock-diff/snapshot.lock", "raeva.lock");
    // A separate cwd proves -C chooses NEW without rebasing the explicit OLD.
    let output = raeva_command(project.path(), home.path())
        .current_dir(home.path())
        .args(["--json", "lock", "diff"])
        .arg(project.path().join("old.lock"))
        .output()
        .unwrap();
    let data = data(&output);
    assert_eq!(
        data["new"],
        project
            .path()
            .join("raeva.lock")
            .to_string_lossy()
            .replace('\\', "/")
    );
    assert_eq!(data["changed"], true);
    assert_eq!(data["changes"][0]["old_version"], "1.0-20240101.010101-7");
    assert_eq!(data["changes"][0]["new_version"], "1.0-20240202.020202-9");
    assert_eq!(
        data["changes"][0]["via"],
        json!([["org.golden:snap:1.0-SNAPSHOT:jar"]])
    );
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn snapshot_origin_lists_change_the_json_and_text_diff() {
    use rv_lock::{LockArtifact, LockPlatform, Lockfile};
    use rv_maven_types::{ArtifactCoord, BlobId, Digest, Gav, SnapshotStamp};

    let (project, home) = temp_project();
    let mut row = LockArtifact::new(
        ArtifactCoord::new("g", "demo", "1-SNAPSHOT", "jar", None),
        "https://files.example/",
    );
    row.snapshot = SnapshotStamp::new("20261025.010101", 1);
    row.checksums = vec![Digest::Sha256(BlobId::from_bytes(b"jar"))];
    row.pom_sha256 = Some(BlobId::from_bytes(b"pom"));
    row.other_repo_urls = vec!["https://other.example/".into()];
    row.pom_repo_urls = vec!["https://poms.example/".into()];
    let mut old = Lockfile::new();
    old.platforms.push(LockPlatform::single_module(
        "linux-x86_64".parse().unwrap(),
        Gav::new("g", "root", "1"),
        "pom",
        vec![row],
    ));
    for id in ["files", "other", "poms", "moved"] {
        old.repo_ids
            .insert(format!("https://{id}.example/"), [id.into()].into());
    }
    fs::write(project.path().join("old.lock"), old.to_toml().unwrap()).unwrap();
    for pom in [false, true] {
        let mut new = old.clone();
        let row = &mut new.platforms[0].artifacts[0];
        let origins = if pom {
            &mut row.pom_repo_urls
        } else {
            &mut row.other_repo_urls
        };
        *origins = vec!["https://moved.example/".into()];
        fs::write(project.path().join("new.lock"), new.to_toml().unwrap()).unwrap();
        let json = data(&diff(
            project.path(),
            home.path(),
            "old.lock",
            Some("new.lock"),
        ));
        assert_eq!(json["changed"], true, "POM origins: {pom}");
        assert_eq!(json["changes"][0]["change"], "origin");
        let text = raeva_command(project.path(), home.path())
            .current_dir(project.path())
            .args(["--offline", "lock", "diff", "old.lock", "new.lock"])
            .output()
            .unwrap();
        assert_success(&text, "origin diff");
        for output in [json.to_string(), String::from_utf8(text.stdout).unwrap()] {
            let before = if pom {
                "https://poms.example/"
            } else {
                "https://other.example/"
            };
            assert!(output.contains(before), "{output}");
            assert!(output.contains("https://moved.example/"), "{output}");
            assert!(output.contains("pom:"), "{output}");
        }
    }
}
