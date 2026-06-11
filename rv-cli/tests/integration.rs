// Integration tests are opt-in via `cargo test -- --ignored` (each test
// carries `#[ignore]`). They require live network access to a Maven repository.
// Allow dead code since not all helpers are used in every test configuration.
#![allow(dead_code)]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use rv_config::{LockPlatform, Lockfile, Platform};
use serde::Deserialize;
use tempfile::TempDir;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(120);

const SIMPLE_GROUP: &str = "org.slf4j";
const SIMPLE_ARTIFACT: &str = "slf4j-api";
const SIMPLE_VERSION: &str = "2.0.9";

const JUNIT_GROUP: &str = "junit";
const JUNIT_ARTIFACT: &str = "junit";
const JUNIT_VERSION: &str = "4.13.2";

const HAMCREST_GROUP: &str = "org.hamcrest";
const HAMCREST_ARTIFACT: &str = "hamcrest-core";
const HAMCREST_VERSION: &str = "1.3";

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    data: T,
}

#[derive(Deserialize)]
struct TreeOutput {
    dependencies: Vec<TreeNode>,
}

#[derive(Deserialize)]
struct TreeNode {
    coordinate: String,
    children: Vec<TreeNode>,
}

#[derive(Deserialize)]
struct WhyOutput {
    found: bool,
    paths: Vec<Vec<String>>,
}

fn rv_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rv"))
}

fn temp_project() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("temp project dir");
    let home = TempDir::new().expect("temp raeva home");
    (project, home)
}

fn rv_command(project_root: &Path, home: &Path) -> Command {
    let mut cmd = Command::new(rv_bin());
    cmd.arg("-C").arg(project_root);
    cmd.env("RAEVA_HOME", home);
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd
}

fn run_cmd(mut cmd: Command) -> Output {
    cmd.output().expect("spawn rv command")
}

fn run_cmd_with_timeout(cmd: &mut Command, timeout: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn rv command");
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll rv command") {
            return collect_output(child, status);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let status = child.wait().expect("wait for rv command");
            let output = collect_output(child, status);
            let (stdout, stderr) = output_strings(&output);
            panic!("rv command timed out after {timeout:?}\nstdout: {stdout}\nstderr: {stderr}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

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

fn output_strings(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn assert_success(output: &Output) {
    if output.status.success() {
        return;
    }
    let (stdout, stderr) = output_strings(output);
    panic!(
        "rv command failed: {status}\nstdout: {stdout}\nstderr: {stderr}",
        status = output.status
    );
}

fn write_pom(path: &Path, deps: &[(&str, &str, &str)]) {
    let deps_xml = deps
        .iter()
        .map(|(group, artifact, version)| {
            format!(
                "        <dependency>\n            <groupId>{group}</groupId>\n            \
                 <artifactId>{artifact}</artifactId>\n            <version>{version}</version>\n        </dependency>"
            )
        })
        .collect::<Vec<String>>()
        .join("\n");

    let contents = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>

    <dependencies>
{deps_xml}
    </dependencies>
</project>
"#
    );

    fs::write(path, contents).expect("write pom.xml");
}

fn read_lock(project_root: &Path) -> Lockfile {
    Lockfile::read(&project_root.join("rv.lock")).expect("read rv.lock")
}

fn select_platform(lock: &Lockfile) -> &LockPlatform {
    let current = Platform::current().ok();
    if let Some(current) = current
        && let Some(platform) = lock
            .platforms
            .iter()
            .find(|entry| entry.platform == current)
    {
        return platform;
    }
    lock.platforms.first().expect("lockfile has platform data")
}

fn package_index(
    platform: &LockPlatform,
    group: &str,
    artifact: &str,
    version: &str,
) -> Option<usize> {
    platform.packages.iter().position(|pkg| {
        pkg.group_id == group && pkg.artifact_id == artifact && pkg.version == version
    })
}

fn coord(group: &str, artifact: &str, version: &str) -> String {
    format!("{group}:{artifact}:{version}")
}

fn tree_contains(nodes: &[TreeNode], target: &str) -> bool {
    nodes
        .iter()
        .any(|node| node.coordinate.starts_with(target) || tree_contains(&node.children, target))
}

#[test]
#[ignore]
fn test_sync_simple_project() {
    let (project, home) = temp_project();
    let pom_path = project.path().join("pom.xml");
    write_pom(
        &pom_path,
        &[(SIMPLE_GROUP, SIMPLE_ARTIFACT, SIMPLE_VERSION)],
    );

    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    let lock_path = project.path().join("rv.lock");
    assert!(lock_path.is_file(), "rv.lock should be created");

    let lock = read_lock(project.path());
    let platform = select_platform(&lock);
    assert!(
        package_index(platform, SIMPLE_GROUP, SIMPLE_ARTIFACT, SIMPLE_VERSION).is_some(),
        "lockfile should include {SIMPLE_GROUP}:{SIMPLE_ARTIFACT}:{SIMPLE_VERSION}"
    );
}

#[test]
#[ignore]
fn test_sync_with_transitives() {
    let (project, home) = temp_project();
    let pom_path = project.path().join("pom.xml");
    write_pom(&pom_path, &[(JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION)]);

    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    let lock = read_lock(project.path());
    let platform = select_platform(&lock);
    let junit_idx = package_index(platform, JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION)
        .expect("junit should be in lockfile");
    let hamcrest_idx = package_index(
        platform,
        HAMCREST_GROUP,
        HAMCREST_ARTIFACT,
        HAMCREST_VERSION,
    )
    .expect("hamcrest-core should be in lockfile");

    assert!(
        platform
            .edges
            .iter()
            .any(|edge| edge.from == junit_idx && edge.to == hamcrest_idx),
        "lockfile should include an edge from junit to hamcrest-core"
    );
}

#[test]
#[ignore]
fn test_sync_frozen_mode() {
    let (project, home) = temp_project();
    let pom_path = project.path().join("pom.xml");
    write_pom(
        &pom_path,
        &[(SIMPLE_GROUP, SIMPLE_ARTIFACT, SIMPLE_VERSION)],
    );

    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    write_pom(
        &pom_path,
        &[
            (SIMPLE_GROUP, SIMPLE_ARTIFACT, SIMPLE_VERSION),
            (JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION),
        ],
    );

    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path())
            .arg("sync")
            .arg("--frozen"),
        NETWORK_TIMEOUT,
    );

    assert!(
        !output.status.success(),
        "sync --frozen should fail when the lockfile is stale"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lockfile mismatch"),
        "expected lockfile mismatch error, got: {stderr}"
    );
}

/// `rv sync --frozen` against a lockfile whose `config_hash` is set must
/// not silently re-resolve when the project's manifest is missing —
/// frozen means "do not touch the network for a fresh resolve". The
/// fix surfaces this as a `LockfileMismatch` error, which exits with
/// the lockfile-mismatch code (not zero). No network required.
#[test]
fn frozen_without_manifest_errors_when_lock_has_config_hash() {
    use rv_config::{LockPlatform, Lockfile, Platform};

    let (project, home) = temp_project();
    // No pom.xml, no rv.toml — but a lockfile that was clearly produced
    // against some prior manifest.
    let mut lock = Lockfile::new();
    lock.platforms.push(LockPlatform {
        platform: Platform::current().expect("current platform"),
        packages: Vec::new(),
        edges: Vec::new(),
        extra: std::collections::BTreeMap::new(),
    });
    lock.config_hash = Some("deadbeef".to_string());
    lock.write_atomic(&project.path().join("rv.lock"))
        .expect("write rv.lock");

    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path())
            .arg("sync")
            .arg("--frozen")
            .arg("--offline"),
        Duration::from_secs(30),
    );

    assert!(
        !output.status.success(),
        "sync --frozen with stale lockfile must fail; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lockfile") || stderr.contains("rv.lock"),
        "expected lockfile mismatch message, got: {stderr}"
    );
}

#[test]
#[ignore]
fn test_tree_output() {
    let (project, home) = temp_project();
    let pom_path = project.path().join("pom.xml");
    write_pom(&pom_path, &[(JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION)]);

    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path())
            .arg("--json")
            .arg("tree"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    let envelope: Envelope<TreeOutput> =
        serde_json::from_slice(&output.stdout).expect("parse tree output");
    assert!(
        envelope.success,
        "tree --json envelope.success should be true"
    );
    let target = coord(JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION);
    assert!(
        tree_contains(&envelope.data.dependencies, &target),
        "tree output should include {target}"
    );
}

#[test]
#[ignore]
fn test_why_command() {
    let (project, home) = temp_project();
    let pom_path = project.path().join("pom.xml");
    write_pom(&pom_path, &[(JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION)]);

    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    let target = coord(HAMCREST_GROUP, HAMCREST_ARTIFACT, HAMCREST_VERSION);
    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path())
            .arg("--json")
            .arg("why")
            .arg(&target),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    let envelope: Envelope<WhyOutput> =
        serde_json::from_slice(&output.stdout).expect("parse why output");
    assert!(
        envelope.success,
        "why --json envelope.success should be true"
    );
    let why = envelope.data;
    assert!(why.found, "why should report paths for {target}");
    let direct = coord(JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION);
    assert!(
        why.paths.iter().any(|path| {
            path.iter().any(|p| p.starts_with(&direct))
                && path.last().is_some_and(|p| p.starts_with(&target))
        }),
        "why output should include a path from junit to hamcrest-core"
    );
}

/// End-to-end test: sync a project with transitive deps, verify lockfile, then export to ~/.m2.
#[test]
#[ignore]
fn test_e2e_sync_and_export_m2() {
    let (project, home) = temp_project();
    let pom_path = project.path().join("pom.xml");

    // Use junit (which pulls hamcrest-core transitively)
    write_pom(&pom_path, &[(JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION)]);

    // Step 1: rv sync
    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    // Step 2: Verify lockfile
    let lock_path = project.path().join("rv.lock");
    assert!(lock_path.is_file(), "rv.lock should be created");

    let lock = read_lock(project.path());
    let platform = select_platform(&lock);
    assert!(
        package_index(platform, JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION).is_some(),
        "lockfile should contain junit"
    );
    assert!(
        package_index(
            platform,
            HAMCREST_GROUP,
            HAMCREST_ARTIFACT,
            HAMCREST_VERSION
        )
        .is_some(),
        "lockfile should contain transitive hamcrest-core"
    );

    // Step 3: rv export-m2
    let m2_dir = home.path().join("m2-export");
    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path())
            .arg("export-m2")
            .arg("--m2-path")
            .arg(&m2_dir),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    // Step 4: Verify the exported directory has expected structure
    let junit_jar_path = m2_dir
        .join("junit")
        .join("junit")
        .join(JUNIT_VERSION)
        .join(format!("junit-{JUNIT_VERSION}.jar"));
    assert!(
        junit_jar_path.exists(),
        "exported m2 should contain junit jar at {}",
        junit_jar_path.display()
    );

    // Verify transitive dependency was also exported
    let hamcrest_jar_path = m2_dir
        .join("org")
        .join("hamcrest")
        .join("hamcrest-core")
        .join(HAMCREST_VERSION)
        .join(format!("hamcrest-core-{HAMCREST_VERSION}.jar"));
    assert!(
        hamcrest_jar_path.exists(),
        "exported m2 should contain transitive hamcrest-core jar at {}",
        hamcrest_jar_path.display()
    );
}

/// End-to-end test: verify `rv sync` is idempotent (re-running produces same lockfile).
#[test]
#[ignore]
fn test_e2e_sync_idempotent() {
    let (project, home) = temp_project();
    let pom_path = project.path().join("pom.xml");
    write_pom(
        &pom_path,
        &[(SIMPLE_GROUP, SIMPLE_ARTIFACT, SIMPLE_VERSION)],
    );

    // First sync
    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    let lock_content_1 = fs::read_to_string(project.path().join("rv.lock")).unwrap();

    // Second sync (should produce identical lockfile)
    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    let lock_content_2 = fs::read_to_string(project.path().join("rv.lock")).unwrap();
    assert_eq!(
        lock_content_1, lock_content_2,
        "lockfile should be stable across re-syncs"
    );
}

/// Integration test: workspace sync across a multi-module Maven project.
///
/// Creates a parent POM with two modules (module-a depending on slf4j-api,
/// module-b depending on junit) and verifies that `rv sync` resolves both
/// modules and produces a lockfile at the project root.
#[test]
#[ignore]
fn test_workspace_sync_multi_module() {
    let (project, home) = temp_project();

    // Parent POM with two modules
    let parent_pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>

    <modules>
        <module>module-a</module>
        <module>module-b</module>
    </modules>
</project>
"#;
    fs::write(project.path().join("pom.xml"), parent_pom).expect("write parent pom.xml");

    // module-a: depends on slf4j-api
    let module_a_dir = project.path().join("module-a");
    fs::create_dir_all(&module_a_dir).expect("create module-a dir");
    let module_a_pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
        <relativePath>..</relativePath>
    </parent>

    <artifactId>module-a</artifactId>

    <dependencies>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>2.0.9</version>
        </dependency>
    </dependencies>
</project>
"#;
    fs::write(module_a_dir.join("pom.xml"), module_a_pom).expect("write module-a pom.xml");

    // module-b: depends on junit
    let module_b_dir = project.path().join("module-b");
    fs::create_dir_all(&module_b_dir).expect("create module-b dir");
    let module_b_pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
        <relativePath>..</relativePath>
    </parent>

    <artifactId>module-b</artifactId>

    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
        </dependency>
    </dependencies>
</project>
"#;
    fs::write(module_b_dir.join("pom.xml"), module_b_pom).expect("write module-b pom.xml");

    // Run rv sync at the project root
    let output = run_cmd_with_timeout(
        rv_command(project.path(), home.path()).arg("sync"),
        NETWORK_TIMEOUT,
    );
    assert_success(&output);

    // Verify rv.lock exists at the project root
    let lock_path = project.path().join("rv.lock");
    assert!(
        lock_path.is_file(),
        "rv.lock should be created at the project root after workspace sync"
    );

    // Both modules must contribute their direct deps to the lockfile.
    // Earlier this test only checked file existence, which would pass even
    // if the workspace walk skipped one module entirely.
    let lock = read_lock(project.path());
    let platform = select_platform(&lock);
    assert!(
        package_index(platform, SIMPLE_GROUP, SIMPLE_ARTIFACT, SIMPLE_VERSION).is_some(),
        "workspace sync should resolve module-a's dependency on \
         {SIMPLE_GROUP}:{SIMPLE_ARTIFACT}:{SIMPLE_VERSION}"
    );
    assert!(
        package_index(platform, JUNIT_GROUP, JUNIT_ARTIFACT, JUNIT_VERSION).is_some(),
        "workspace sync should resolve module-b's dependency on \
         {JUNIT_GROUP}:{JUNIT_ARTIFACT}:{JUNIT_VERSION}"
    );
}
