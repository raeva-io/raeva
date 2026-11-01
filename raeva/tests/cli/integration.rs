// CLI integration tests. Each case is a plain `#[test]`, runs with
// `--offline`, and does not need a live Maven repository.

use std::fs;
use std::io::Read;
use std::process::{Child, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use rv_lock::{Lockfile, LockfileGuard, Platform};

use crate::common::{
    assert_status, assert_success, raeva_command, run_raeva, temp_project, write_empty_pom,
};

fn collect_output(mut child: Child, status: ExitStatus) -> Output {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_end(&mut stdout).expect("read stdout");
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_end(&mut stderr).expect("read stderr");
    }
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Network settings decide only whether a fetch succeeds, so changing one
/// after `raeva sync` leaves `raeva sync --frozen` passing. A setting that changes
/// resolution makes it fail with a message that names the configuration
/// and gives the fix once. No network required.
#[test]
fn frozen_ignores_transport_settings_and_names_configuration_drift() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let raeva = |envs: &[(&str, &str)]| {
        let mut cmd = raeva_command(project.path(), home.path());
        cmd.args(["sync", "--frozen", "--offline"]);
        for (name, value) in envs {
            cmd.env(name, value);
        }
        cmd.output().expect("run raeva")
    };
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--offline"]),
        "sync",
    );

    for env in [
        ("RAEVA_TIMEOUT", "90"),
        ("RAEVA_RETRIES", "3"),
        ("RAEVA_LOW_SPEED_LIMIT", "0"),
        ("RAEVA_LOW_SPEED_TIME", "120"),
        ("RAEVA_MAX_ARTIFACT_SIZE", "1048576"),
    ] {
        assert_success(&raeva(&[env]), &format!("frozen with {}", env.0));
    }
    fs::write(
        project.path().join("raeva.toml"),
        "[network]\ntimeout = 90\nretries = 7\nconcurrency = 2\n\
         low_speed_limit = 0\nlow_speed_time = 120\n",
    )
    .expect("write raeva.toml");
    assert_success(&raeva(&[]), "frozen after transport raeva.toml");

    fs::write(
        project.path().join("raeva.toml"),
        "inactive_profiles = [\"ci\"]\n",
    )
    .expect("write raeva.toml");
    let output = raeva(&[]);
    assert_status(&output, 7, "frozen after profile drift");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("the configuration changed since raeva.lock was written"),
        "{stderr}"
    );
    assert!(!stderr.contains("pom.xml changed"), "{stderr}");
    assert_eq!(stderr.matches(" sync").count(), 1, "one hint: {stderr}");

    // Commands that require a Fresh lock report the same drift.
    let output = run_raeva(project.path(), home.path(), &["sbom"]);
    assert_status(&output, 7, "sbom after profile drift");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("configuration changed"), "{stderr}");
    assert_eq!(stderr.matches(" sync").count(), 1, "one hint: {stderr}");
}

/// A settings.xml profile activates on the platform being locked, not on
/// the host, and the lock covers its definition rather than the host's
/// outcome. Its id selects no POM profile, so it is not among the model's.
#[test]
fn settings_profiles_activate_per_locked_platform() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let settings = |family: &str| {
        let m2 = home.path().join(".m2");
        fs::create_dir_all(&m2).expect("create .m2");
        fs::write(
            m2.join("settings.xml"),
            format!(
                "<settings><profiles><profile><id>on-{family}</id><activation><os>\
                 <family>{family}</family></os></activation></profile></profiles></settings>"
            ),
        )
        .expect("write settings.xml");
    };
    let sync = |args: &[&str]| {
        let mut cmd = raeva_command(project.path(), home.path());
        cmd.args([
            "sync",
            "--offline",
            "--platforms",
            "linux-x86_64,windows-x86_64",
        ])
        .args(args);
        cmd.output().expect("run raeva")
    };
    settings("windows");
    assert_success(&sync(&[]), "sync");
    let lock = Lockfile::read(&project.path().join("raeva.lock")).expect("read raeva.lock");
    let profiles = |name: &str| {
        let platform: Platform = name.parse().unwrap();
        lock.platforms
            .iter()
            .find(|entry| entry.platform == platform)
            .expect("platform")
            .model_inputs
            .as_ref()
            .expect("profiles")
            .profiles
            .clone()
    };
    assert!(profiles("windows-x86_64").is_empty());
    assert!(profiles("linux-x86_64").is_empty());
    assert_success(&sync(&["--frozen"]), "frozen");

    settings("mac");
    let output = sync(&["--frozen"]);
    assert_status(&output, 7, "frozen after settings family change");
}

/// `sync --frozen` must read `raeva.lock` only after it holds the project
/// lockfile guard. Otherwise a concurrent writer can replace the lock between
/// the local frozen checks and the rest of the run, and frozen keeps a stale
/// snapshot. Hold the guard, start frozen, rewrite the lock to a failing
/// config hash, then release: frozen must see the rewrite and exit 7.
#[test]
fn frozen_sees_lock_rewritten_while_waiting_for_the_guard() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync", "--offline"]),
        "sync",
    );

    let held = LockfileGuard::acquire(
        &home.path().join("cache"),
        project.path(),
        Duration::from_secs(1),
        || {},
    )
    .expect("hold lockfile guard");

    let mut child = raeva_command(project.path(), home.path())
        .args(["sync", "--frozen", "--offline"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn frozen sync");
    // Give the child time to block on the held guard before we rewrite the lock.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        child.try_wait().expect("poll frozen sync").is_none(),
        "frozen sync should still be waiting on the held guard"
    );

    let lock_path = project.path().join("raeva.lock");
    let mut lock = Lockfile::read(&lock_path).expect("read raeva.lock");
    lock.config_hash = Some("0".repeat(64));
    lock.write_atomic(&lock_path).expect("rewrite raeva.lock");
    drop(held);

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll frozen sync") {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(30) {
            let _ = child.kill();
            let status = child.wait().expect("wait for frozen sync");
            let output = collect_output(child, status);
            panic!(
                "frozen sync timed out\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let output = collect_output(child, status);
    assert_status(&output, 7, "frozen must observe the rewritten lock");
}

/// A project directory raeva cannot write fails the sync as an I/O error on
/// raeva.lock, without the name of the temporary file it tried to create.
#[cfg(unix)]
#[test]
fn a_read_only_project_fails_on_raeva_lock() {
    use std::os::unix::fs::PermissionsExt;
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    fs::set_permissions(project.path(), fs::Permissions::from_mode(0o555)).unwrap();
    // Root writes anyway.
    let writable = fs::write(project.path().join("probe"), b"").is_ok();
    let output = run_raeva(project.path(), home.path(), &["sync", "--offline"]);
    fs::set_permissions(project.path(), fs::Permissions::from_mode(0o755)).unwrap();
    if writable {
        return;
    }
    assert_status(&output, 1, "sync in a read-only project");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("raeva.lock: Permission denied"), "{stderr}");
    assert!(stderr.contains("Check the permissions of"), "{stderr}");
    assert!(
        !stderr.contains(" at path ") && !stderr.contains("configuration error"),
        "{stderr}"
    );
}

/// SIGTERM, which CI runners send to cancel a job, stops a sync the way
/// Ctrl-C does: its cleanup runs and it exits 143 rather than dying.
#[cfg(unix)]
#[test]
fn sigterm_stops_a_sync_like_ctrl_c() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let _held = LockfileGuard::acquire(
        &home.path().join("cache"),
        project.path(),
        Duration::from_secs(1),
        || {},
    )
    .expect("hold lockfile guard");
    let child = raeva_command(project.path(), home.path())
        .args(["sync", "--offline"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sync");
    std::thread::sleep(Duration::from_millis(500));
    let kill = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success());
    let output = child.wait_with_output().expect("wait for sync");
    assert_status(&output, 143, "sync stopped by SIGTERM");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Terminated."));
}

/// The headline compares the lockfile's bytes, so a sync that leaves them as
/// they were reports raeva.lock as up to date even when it had to replace
/// the file, as it does a symlink.
#[cfg(unix)]
#[test]
fn identical_bytes_written_through_a_symlink_are_up_to_date() {
    let (project, home) = temp_project();
    write_empty_pom(&project.path().join("pom.xml"));
    let lock_path = project.path().join("raeva.lock");
    assert_success(
        &run_raeva(project.path(), home.path(), &["sync"]),
        "first sync",
    );
    let target = project.path().join("target.lock");
    fs::rename(&lock_path, &target).expect("move raeva.lock");
    std::os::unix::fs::symlink(&target, &lock_path).expect("symlink raeva.lock");

    let output = run_raeva(project.path(), home.path(), &["sync", "--update"]);
    assert_success(&output, "update sync");
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("raeva.lock is up to date"), "{text}");
}

/// A version changed in the POM is resolved, recorded and stored by the next
/// sync, and the stored file matches the new pin.
#[test]
fn a_version_changed_in_the_pom_is_downloaded_and_locked() {
    let project = crate::offline_project::Project::synced();
    let dir = project.root().join("repository/org/test/lib/2.0");
    fs::create_dir_all(&dir).expect("create lib 2.0");
    let files: [(&str, &[u8]); 2] = [
        (
            "lib-2.0.pom",
            b"<project><modelVersion>4.0.0</modelVersion>\
<groupId>org.test</groupId><artifactId>lib</artifactId><version>2.0</version></project>",
        ),
        ("lib-2.0.jar", b"lib 2.0 jar bytes"),
    ];
    for (name, bytes) in files {
        fs::write(dir.join(name), bytes).expect("write file");
        fs::write(
            dir.join(format!("{name}.sha256")),
            crate::common::sha256_hex(bytes),
        )
        .expect("write sidecar");
    }
    let pom = project.root().join("pom.xml");
    let text = fs::read_to_string(&pom).expect("read pom.xml");
    fs::write(
        &pom,
        text.replace("<version>1.0</version>", "<version>2.0</version>"),
    )
    .expect("write pom.xml");

    assert_success(
        &project.raeva(&["sync", "--offline"]),
        "sync after the change",
    );
    let lock = Lockfile::read(&project.root().join("raeva.lock")).expect("read raeva.lock");
    let versions: Vec<_> = lock.platforms[0]
        .artifacts
        .iter()
        .map(|row| row.coordinate.version().to_string())
        .collect();
    assert_eq!(versions, ["2.0"]);
    assert_success(&project.raeva(&["lock", "verify", "--offline"]), "verify");
}
